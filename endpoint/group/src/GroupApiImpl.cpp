#include <algorithm>
#include <cctype>

#include <privmx/crypto/Crypto.hpp>
#include <privmx/crypto/ecc/PrivateKey.hpp>
#include <privmx/endpoint/core/CoreException.hpp>
#include <privmx/endpoint/core/LocalSeal.hpp>
#include <privmx/utils/JsonHelper.hpp>
#include <privmx/utils/Utils.hpp>

#include <privmx/endpoint/core/CoreConstants.hpp>
#include <privmx/endpoint/core/EndpointUtils.hpp>
#include <privmx/endpoint/core/EventMiddleware.hpp>
#include <privmx/endpoint/core/TimestampValidator.hpp>
#include <privmx/endpoint/core/Types.hpp>
#include <privmx/endpoint/core/Utils.hpp>

#include "privmx/endpoint/core/EventBuilder.hpp"
#include "privmx/endpoint/core/ListQueryMapper.hpp"
#include "privmx/endpoint/core/Mapper.hpp"
#include "privmx/endpoint/core/Validator.hpp"
#include "privmx/endpoint/group/Constants.hpp"
#include "privmx/endpoint/group/GroupApiImpl.hpp"
#include "privmx/endpoint/group/GroupException.hpp"
#include "privmx/endpoint/group/Mapper.hpp"
#include "privmx/endpoint/group/ServerTypes.hpp"
#include "privmx/endpoint/group/keytree/PinBlob.hpp"
#include "privmx/endpoint/group/keytree/TreeCommits.hpp"
#include "privmx/utils/Logger.hpp"
#include <privmx/endpoint/core/ConvertedExceptions.hpp>

using namespace privmx::endpoint;
using namespace group;

// A Group whose served history does not verify: the answer, never a reason to fall back to another read.
bool GroupApiImpl::isForgedHistory(const core::Exception& e) {
    const auto code = e.getCode();
    return code == GroupHistoryForkException::FULL_CODE ||
        code == GroupDataIntegrityException::FULL_CODE ||
        code == GroupChainBrokenException::FULL_CODE ||
        code == GroupUnauthorizedSignerException::FULL_CODE ||
        code == GroupMembershipMismatchException::FULL_CODE ||
        code == GroupPublicDataMismatchException::FULL_CODE;
}

GroupApiImpl::GroupApiImpl(
    const privfs::RpcGateway::Ptr& gateway,
    const privmx::crypto::PrivateKey& userPrivKey,
    const std::shared_ptr<core::KeyProvider>& keyProvider,
    const std::string& host,
    const std::shared_ptr<core::EventMiddleware>& eventMiddleware,
    const core::Connection& connection
)
    : ContainerBaseApi(userPrivKey, keyProvider, host, eventMiddleware, connection), _serverApi(ServerApi(gateway)),
      _subscriber(gateway), _groupDataSchemaMapper(std::make_shared<GroupDataSchemaMapper>(userPrivKey, connection)) {
    // A group opens its own metadata key by climbing its own tree, so it resolves its grant key for itself.
    initGroupPrivKeyResolver(_keys.resolverOver(nullptr));
    initModuleDataSchemaMapper(_groupDataSchemaMapper);
    _pinnedGroupEpoch = [this](const std::string& groupId) { return pinnedKeyVersion(groupId); };
    // The pins this identity saved on this Bridge (any instance, any session) before anything reads a group.
    // Loaded once; instances running side by side meet again in the slot at each save (`PinBlob::higher`).
    const auto connectionImpl = connection.getImpl();
    _pinStore = connectionImpl->getPinStore();
    if (_pinStore) {
        _pinStoreKey = connectionImpl->localStateSlot(core::LocalSeal::GROUP_PINS, userPrivKey.getPublicKey());
        // Unreadable, corrupted or deleted: this instance starts as a first contact for every group (as without a store).
        loadPins();
        for (const auto& [previousPub, body] : connectionImpl->getStagedPinBodies()) {
            const auto adopted = keytree::PinBlob::decode(body);
            if (!adopted.has_value()) {
                LOG_WARN("[pins] the previous identity's pins do not parse; not adopted")
                continue;
            }
            try {
                adoptBody(adopted.value());
            } catch (const std::exception& e) {
                LOG_WARN("[pins] the previous identity's pins not adopted: ", e.what())
                continue;
            }
            std::lock_guard<std::mutex> lock(_pinSaveMutex);
            _adoptedIdentities.insert(previousPub);
        }
    }
    _treeVerifier.onPinsMoved([this](bool major) { pinsMoved(major); });
    _groupDataSchemaMapper->onPinsMoved([this](bool major) { pinsMoved(major); });
    _notificationListenerId = _eventMiddleware->addNotificationEventListener(
        std::bind(&GroupApiImpl::processNotificationEvent, this, std::placeholders::_1, std::placeholders::_2)
    );
    _connectedListenerId = _eventMiddleware->addConnectedEventListener(
        std::bind(&GroupApiImpl::processConnectedEvent, this)
    );
    _disconnectedListenerId = _eventMiddleware->addDisconnectedEventListener(
        std::bind(&GroupApiImpl::processDisconnectedEvent, this)
    );
}

GroupApiImpl::~GroupApiImpl() {
    _eventMiddleware->removeNotificationEventListener(_notificationListenerId);
    _eventMiddleware->removeConnectedEventListener(_connectedListenerId);
    _eventMiddleware->removeDisconnectedEventListener(_disconnectedListenerId);
    _guardedExecutor.reset();
    // Last: notification tasks may move pins until the executor is gone.
    if (_pinStore) {
        savePins();
    }
}

// Public keys for exactly these members, from the Context user list. One listing round trip per 100 of them.
std::map<std::string, std::string> GroupApiImpl::resolveMemberKeys(
    const std::string& contextId,
    const std::vector<std::string>& userIds
) {
    if (userIds.empty()) {
        return {};
    }
    const ContainerRoster resolved = resolveRosterPubKeys(contextId, userIds, {});
    assertUserKeysVerified(contextId, resolved.users);
    std::map<std::string, std::string> keys;
    for (const core::UserWithPubKey& user : resolved.users) {
        keys.emplace(user.userId, user.pubKey);
    }
    return keys;
}

std::string GroupApiImpl::createGroup(
    const std::string& contextId,
    const std::vector<core::UserWithPubKey>& users,
    const std::vector<core::UserWithPubKey>& managers,
    const core::Buffer& publicMeta,
    const core::Buffer& privateMeta,
    const std::optional<GroupRulesUpdate>& rules,
    const std::optional<core::Buffer>& idSeed,
    const std::string& visibleTo
) {
    if (visibleTo != "members" && visibleTo != "context") {
        throw core::InvalidParamsException("visibleTo is \"members\" or \"context\"");
    }
    return _ops.create(
        contextId, users, managers, publicMeta, privateMeta, rules.value_or(GroupRulesUpdate{}),
        idSeed.has_value() ? std::optional<std::string>(resourceIdOfSeed(idSeed.value())) : std::nullopt,
        visibleTo == "members" ? std::nullopt : std::optional<std::string>(visibleTo)
    );
}

std::string GroupApiImpl::resourceIdOfSeed(const core::Buffer& idSeed) {
    if (idSeed.size() == 0) {
        throw core::InvalidParamsException("an id seed cannot be empty");
    }
    return privmx::utils::Hex::from(privmx::crypto::Crypto::sha256("privmx/group/id-seed" + idSeed.stdString()));
}

std::string GroupApiImpl::deriveGroupId(const std::string& contextId, const core::Buffer& idSeed) {
    return keytree::TreeCommits::groupId(contextId, resourceIdOfSeed(idSeed));
}

std::vector<GroupResult> GroupApiImpl::getGroups(const std::vector<std::string>& groupIds) {
    // One request for all of them (`groupGetMany`), then each answer through everything `getGroup` checks: the
    // answers are what `groupGet` would have served, so nothing is verified any less. A Bridge without the call, or
    // one that fails it, costs a request per group instead.
    try {
        _serverApi.prefetchGroups(groupIds);
    } catch (const std::exception& e) { LOG_WARN("[groups] reading several at once failed: ", e.what()) }
    struct DropPrefetched {
        ServerApi& serverApi;
        ~DropPrefetched() { serverApi.dropPrefetched(); }
    } drop{_serverApi};
    std::vector<GroupResult> results;
    results.reserve(groupIds.size());
    for (const std::string& groupId : groupIds) {
        GroupResult result{};
        try {
            result.group = getGroup(groupId);
            result.statusCode = result.group.statusCode;
        } catch (const core::Exception& e) { result.statusCode = e.getCode(); } catch (...) {
            result.statusCode = ENDPOINT_CORE_EXCEPTION_CODE;
        }
        results.push_back(std::move(result));
    }
    return results;
}

GroupPublicKey GroupApiImpl::getGroupPublicKey(const std::string& contextId, const std::string& groupId) {
    const auto epochs = fetchGroupEpochs(contextId, {groupId});
    const auto epoch = epochs.find(groupId);
    if (epoch == epochs.end()) {
        throw GroupDataIntegrityException("group " + groupId + " has no verifiable key");
    }
    // The creator, from a read held to the latest signed statement (the policy it signs names the creator): the
    // caller's own read when it verified (statusCode 0: getGroup reports an unattested answer instead of throwing,
    // creator still copied from the Bridge), the public one otherwise. A history that does not verify is the
    // answer, never a reason to try the other read.
    std::optional<std::string> creator;
    try {
        const Group group = getGroup(groupId);
        if (group.statusCode == 0 && group.contextId == contextId) {
            creator = group.creator;
        }
    } catch (const core::Exception& e) {
        if (isForgedHistory(e)) {
            throw;
        }
    }
    if (!creator.has_value()) {
        server::GroupGetPublicKeyModel model;
        model.groupId = groupId;
        const server::GroupInfo group = listedFrom(_serverApi.groupGetPublicKey(model).group);
        _treeVerifier.preverifyListed({group}, VerifiedGroup::treeEnvironment(_serverApi, _connection, std::string()));
        _treeVerifier.verifyListed(group, VerifiedGroup::treeEnvironment(_serverApi, _connection, group.id));
        if (group.contextId != contextId) {
            throw GroupDataIntegrityException("group " + groupId + " is of another Context");
        }
        creator = group.creator;
    }
    return GroupPublicKey{
        .groupId = groupId,
        .keyVersion = epoch->second.keyVersion,
        .pubKey = epoch->second.groupPubKey,
        .creator = creator.value()
    };
}

void GroupApiImpl::setGroupVisibility(const std::string& groupId, const std::string& visibleTo) {
    if (visibleTo != "members" && visibleTo != "context") {
        throw core::InvalidParamsException("visibleTo is \"members\" or \"context\"");
    }
    _ops.assertMayChangeVisibility(groupId);
    server::GroupSetVisibilityModel model;
    model.groupId = groupId;
    model.visibleTo = visibleTo;
    _serverApi.groupSetVisibility(model);
}

void GroupApiImpl::addGroupMembers(const std::string& groupId, const std::vector<GroupMemberToAdd>& newMembers) {
    // The op-effect table's add row names each newcomer once: refused here, before anything is read or signed.
    std::set<std::string> named;
    for (const GroupMemberToAdd& newMember : newMembers) {
        if (!named.insert(newMember.user.userId).second) {
            throw core::InvalidParamsException("user '" + newMember.user.userId + "' is listed twice");
        }
    }
    CommitEngine::commitWithRetry([&] { _ops.add(groupId, newMembers); });
    runDueWork(groupId);
}

int64_t GroupApiImpl::removeGroupMembers(const std::string& groupId, const std::vector<std::string>& userIds) {
    // A narrowing's carry still to do runs first: after the removal its plane would be judged under the new rules.
    _metadata.retryPendingCarry(groupId);
    std::optional<bool> historyAbandoned;
    PriorRole prior;
    CommitEngine::commitWithRetry([&] { historyAbandoned = _ops.remove(groupId, userIds, prior); });
    // The removal is committed; the metadata entry is now one epoch behind, under a key the departed member
    // still holds. Move it up. Outside the write above on purpose — see the header. Already done when an earlier
    // call's removal turned out to have landed (`settle`).
    if (historyAbandoned.has_value()) {
        _metadata.carryMetadataForward(groupId, CarryScope::NewEpoch, historyAbandoned.value(), prior);
    }
    runDueWork(groupId);
    // The epoch this client committed, or verified when an earlier call's removal turned out to have landed.
    return static_cast<int64_t>(pinnedKeyVersion(groupId));
}

int64_t GroupApiImpl::rotateGroupKey(const std::string& groupId) {
    _metadata.retryPendingCarry(groupId);
    bool committedHere = true;
    PriorRole prior;
    CommitEngine::commitWithRetry([&] { committedHere = _ops.rotate(groupId, prior); });
    // As after a removal: the metadata planes sit one epoch behind, under the key the rotation replaces. Nobody left,
    // so nobody is accepted as an author beyond the members. Already done when an earlier call's rotation turned out
    // to have landed (`settle`).
    if (committedHere) {
        _metadata.carryMetadataForward(groupId, CarryScope::NewEpoch, false, prior);
    }
    runDueWork(groupId);
    return static_cast<int64_t>(pinnedKeyVersion(groupId));
}

int64_t GroupApiImpl::cutHistory(const std::string& groupId) {
    _metadata.retryPendingCarry(groupId);
    bool committedHere = true;
    PriorRole prior;
    try {
        CommitEngine::commitWithRetry([&] { committedHere = _ops.rotate(groupId, prior, true); });
    } catch (const core::Exception& e) {
        if (e.getCode() == privmx::endpoint::server::GroupInUseException().getCode()) {
            throw GroupHistoryInUseException(e);
        }
        throw;
    }
    // As after a rotation. The cutter still holds the cut epoch's key, so the planes are carried with what they say.
    if (committedHere) {
        _metadata.carryMetadataForward(groupId, CarryScope::NewEpoch, false, prior);
    }
    runDueWork(groupId);
    return static_cast<int64_t>(pinnedKeyVersion(groupId));
}

int64_t GroupApiImpl::replaceGroupMemberKeys(const std::string& groupId, const std::vector<std::string>& userIds) {
    _metadata.retryPendingCarry(groupId);
    std::optional<bool> historyAbandoned;
    PriorRole prior;
    CommitEngine::commitWithRetry([&] { historyAbandoned = _ops.remove(groupId, userIds, prior, true); });
    // As after a rotation: the planes sit one epoch behind, and nobody left, so nobody beyond the members is accepted
    // as an author.
    if (historyAbandoned.has_value()) {
        _metadata.carryMetadataForward(groupId, CarryScope::NewEpoch, historyAbandoned.value(), prior);
    }
    runDueWork(groupId);
    return static_cast<int64_t>(pinnedKeyVersion(groupId));
}

void GroupApiImpl::setGroupRoles(const std::string& groupId, const std::vector<GroupRoleChange>& changes) {
    if (changes.empty()) {
        throw core::InvalidParamsException("no member to change the role of");
    }
    std::set<std::string> named;
    for (const GroupRoleChange& change : changes) {
        if (!named.insert(change.userId).second) {
            throw core::InvalidParamsException("user '" + change.userId + "' is listed twice");
        }
    }
    _metadata.retryPendingCarry(groupId);
    std::optional<PendingCarry> carry;
    CommitEngine::commitWithRetry([&] {
        carry.reset();
        _ops.setRoles(groupId, changes, carry);
    });
    // A plane whose author lost its rule with its role is refused from now on; carry it under the caller's name.
    if (carry.has_value()) {
        _metadata.runPolicyCarry(groupId, carry.value());
    }
    runDueWork(groupId);
}

void GroupApiImpl::updateGroupRules(const std::string& groupId, const GroupRulesUpdate& rules) {
    _metadata.retryPendingCarry(groupId);
    std::optional<PendingCarry> carry;
    CommitEngine::commitWithRetry([&] {
        carry.reset();
        _ops.updateRules(groupId, rules, carry);
    });
    // A plane whose author lost its rule is refused from now on; carry it under the caller's name.
    if (carry.has_value()) {
        _metadata.runPolicyCarry(groupId, carry.value());
    }
    runDueWork(groupId);
}

core::PagingList<GroupLogEntry> GroupApiImpl::getGroupLog(
    const std::string& groupId,
    const core::PagingQuery& pagingQuery
) {
    if (pagingQuery.skip < 0 ||
        pagingQuery.limit < 1 ||
        (pagingQuery.sortOrder != "asc" && pagingQuery.sortOrder != "desc")) {
        throw core::InvalidParamsException("skip >= 0, limit >= 1 and sortOrder \"asc\" or \"desc\" are required");
    }
    // The latest state first, verified and pinned: the history is replayed up to exactly that statement.
    const GroupRead read = _hooks.read(VerifiedGroup::pathRead(groupId), keytree::TreeVerifier::Scope::Path);
    if (!read.verified.has_value()) {
        throw core::InvalidParamsException("only a member of a group can read its history");
    }
    const std::string contextId = read.group().contextId;
    std::vector<keytree::CommitStatement> statements = _treeVerifier.history(
        groupId, contextId, VerifiedGroup::treeEnvironment(_serverApi, _connection, groupId)
    );
    if (pagingQuery.sortOrder == "desc") {
        std::reverse(statements.begin(), statements.end());
    }
    core::PagingList<GroupLogEntry> result{.totalAvailable = static_cast<int64_t>(statements.size()), .readItems = {}};
    for (std::size_t i = static_cast<std::size_t>(pagingQuery.skip);
         i < statements.size() && result.readItems.size() < static_cast<std::size_t>(pagingQuery.limit); ++i) {
        const keytree::CommitStatement& statement = statements[i];
        result.readItems.push_back(
            GroupLogEntry{
                .seq = static_cast<int64_t>(statement.seq),
                .kind = keytree::TreeCommits::toWire(statement).op,
                .author = statement.committer,
                .authorPubKey = statement.committerPubKey,
                .date = static_cast<int64_t>(statement.date),
                .keyVersion = static_cast<int64_t>(statement.keyVersion),
                .rosterVersion = static_cast<int64_t>(statement.rosterVersion),
                .addedUsers = statement.addedUsers,
                .addedManagers = statement.addedManagers,
                .removed = statement.removed
            }
        );
    }
    runDueWork(groupId);
    return result;
}

void GroupApiImpl::runDueWork(const std::string& groupId) {
    if (_dueWorkOff) {
        return;
    }
    _deferred.run(groupId, [&] { selfUpdate(groupId); });
    savePinsIfDue();
}

void GroupApiImpl::savePinsIfDue() noexcept {
    try {
        {
            std::unique_lock<std::mutex> lock(_pinsMovedMutex);
            if (!_pinsMovedMajor &&
                !(_pinsMoved && std::chrono::steady_clock::now() - _lastPinSave >= PIN_SAVE_IDLE_INTERVAL)) {
                return;
            }
        }
        savePins();
    } catch (const std::exception& e) { LOG_WARN("[pins] save dropped: ", e.what()) } catch (...) {
        LOG_WARN("[pins] save dropped")
    }
}

void GroupApiImpl::selfUpdate(const std::string& groupId) {
    _ops.selfUpdate(groupId, nullptr, CommitEngine::SELF_UPDATE_OP, false);
}

bool GroupApiImpl::renewLeaf(const std::string& groupId, const std::string& previousUserPrivKey) {
    std::optional<privmx::crypto::PrivateKey> previous;
    try {
        previous = privmx::crypto::PrivateKey::fromWIF(previousUserPrivKey);
    } catch (...) { throw core::InvalidParamsException("the previous key is not a private key in WIF"); }
    if (previous->getPublicKey() == _userPrivKey.getPublicKey()) {
        throw core::InvalidParamsException("the previous key is the current key");
    }
    // The previous key's pins first, so the read the renewal plans on continues them (the app is meant to have
    // done this at connect with Connection::adoptPreviousIdentity; a second adoption is a no-op).
    adoptPreviousIdentity(previous.value());
    bool renewed = false;
    CommitEngine::commitWithRetry([&] { renewed = _ops.selfUpdate(groupId, &previous.value(), RENEW_LEAF_OP, true); });
    runDueWork(groupId);
    return renewed;
}

void GroupApiImpl::renewOwnLeafOnce(const std::string& groupId) {
    const auto connection = _connection.getImpl();
    if (!connection->renewsLeaves()) {
        return;
    }
    {
        std::lock_guard<std::mutex> lock(_leafRenewalMutex);
        if (!_leafRenewalTried.insert(groupId).second) {
            return;
        }
    }
    for (const privmx::crypto::PrivateKey& previous : connection->previousIdentities()) {
        try {
            adoptPreviousIdentity(previous);
            bool renewed = false;
            CommitEngine::commitWithRetry([&] { renewed = _ops.selfUpdate(groupId, &previous, RENEW_LEAF_OP, true); });
            if (renewed) {
                return;
            }
        } catch (const std::exception& e) { LOG_WARN("[groups] leaf renewal of ", groupId, " failed: ", e.what()) }
    }
}

void GroupApiImpl::updateGroupPublicMeta(
    const std::string& groupId,
    const core::Buffer& publicMeta,
    const int64_t version
) {
    // The default path view is enough: this submits no tree and does not touch the roster at all.
    _metadata.writeMeta(readGroupForKeys(groupId), true, publicMeta, version);
    // After, not before: the carry would move the counter this write is checked against. It skips a plane this
    // write replaced (no longer the entry it read).
    _metadata.retryPendingCarry(groupId);
    runDueWork(groupId);
}

void GroupApiImpl::updateGroupPrivateMeta(
    const std::string& groupId,
    const core::Buffer& privateMeta,
    const int64_t version
) {
    _metadata.writeMeta(readGroupForKeys(groupId), false, privateMeta, version);
    _metadata.retryPendingCarry(groupId);
    runDueWork(groupId);
}

void GroupApiImpl::deleteGroup(const std::string& groupId) {
    server::GroupDeleteModel model{.groupId = groupId};
    _serverApi.groupDelete(model);
    _sessions.forget(groupId);
    dropCachedGroup(groupId);
}

Group GroupApiImpl::getGroup(const std::string& groupId) {
    renewOwnLeafOnce(groupId);
    _metadata.retryPendingCarry(groupId);
    const server::GroupGetModel params = VerifiedGroup::pathRead(groupId);
    // The head roster entry and the current metadata entry — two entries, whatever the group's age. The cache is
    // keyed on the roster version, because that is the plane key material moves with.
    // The tree first, on this same answer: only the verified latest statement says which epoch is current. A caller
    // without a seat gets the group as before, with nothing cached.
    const GroupRead read = _hooks.read(params, keytree::TreeVerifier::Scope::Path);
    const server::GroupInfo& group = read.group();
    const bool seated = read.verified.has_value();
    // An unseated answer is bound to the chain (`verifyListed`: describes() binds policy, creator and roster; replay
    // from the pin when this process has one) before the mapper reads any of it; a rollback below the pin counts as
    // not attested.
    const bool attested = seated || hasVerifiedGrantKey(group);
    // An answer refused below as not attested must not move the version pins either, or the next honest answer
    // would look like a rollback.
    Group result = _groupDataSchemaMapper->validateDecryptAndConvertGroup(
        group, _keyProvider, seated ? _keys.resolverOver(&read.verified.value()) : _groupPrivKeyResolver, std::nullopt,
        attested
    );
    if (!attested) {
        // Outsiders seal anonymous envelopes to it: only as the latest statement vouches for it.
        result.groupPubKey.clear();
        if (result.statusCode == 0) {
            // Planes opened under keys the resolver found, on a policy and roster nobody signed: not handed out.
            result.statusCode = GroupDataIntegrityException().getCode();
            result.publicMeta = core::Buffer();
            result.privateMeta = core::Buffer();
        }
    }
    // Writes take their key from this cache, so only an answer that passed everything may fill it.
    if (seated && result.statusCode == 0) {
        assertHeadKeyAtEpoch(group);
        // The roster with the keys, never one without the other: an author is checked against the roster of the
        // same answer the cached keys came from.
        rememberRoster(group);
        setNewModuleKeysInCache(group.id, groupToModuleKeys(group), group.rosterVersion);
    }
    runDueWork(groupId);
    return result;
}

core::PagingList<GroupSummary> GroupApiImpl::listGroups(
    const std::string& contextId,
    const core::PagingQuery& pagingQuery
) {
    server::GroupListModel model;
    model.contextId = contextId;
    core::ListQueryMapper::map(model, pagingQuery);
    auto groupsList = _serverApi.groupList(model);
    std::vector<GroupSummary> groups;
    groups.reserve(groupsList.groups.size());
    for (const auto& group : groupsList.groups) {
        groups.push_back(GroupDataSchemaMapper::toLibGroupSummary(group));
        // What an outsider would seal anonymous envelopes to. A listing carries no statement to vouch for it, so only
        // the key of a state this process has verified is handed out; `getGroup` verifies the rest.
        // The point the pin holds, in its one spelling: the bridge's may be another string for it.
        groups.back().groupPubKey = _treeVerifier.pinnedAt(group.id, contextId, group.keyVersion, group.groupPubKey) ?
            keytree::TreeVerifier::canonicalKey(group.groupPubKey) :
            std::string();
    }
    return core::PagingList<GroupSummary>({.totalAvailable = groupsList.count, .readItems = groups});
}

bool GroupApiImpl::hasVerifiedGrantKey(const server::GroupInfo& group) {
    const SaveDuePins saveAfter{*this};
    try {
        _treeVerifier.verifyListed(group, VerifiedGroup::treeEnvironment(_serverApi, _connection, group.id));
    } catch (const std::exception& e) {
        LOG_WARN("[hasVerifiedGrantKey] group ", group.id, " failed verification: ", e.what())
        return false;
    }
    return group.treeCommit->seq >= static_cast<std::int64_t>(_treeVerifier.pinnedSeq(group.id));
}

// What `groupGetPublicKey` serves, in the shape the listing checks take.
group::server::GroupInfo GroupApiImpl::listedFrom(const group::server::GroupPublicInfo& info) {
    server::GroupInfo asListed;
    asListed.id = info.id;
    asListed.contextId = info.contextId;
    asListed.resourceId = info.resourceId;
    asListed.creator = info.creator;
    asListed.users = info.users;
    asListed.managers = info.managers;
    asListed.rosterVersion = info.rosterVersion;
    asListed.keyVersion = info.keyVersion;
    asListed.groupPubKey = info.groupPubKey;
    asListed.policy = info.policy;
    asListed.treeCommit = info.treeCommit;
    return asListed;
}

// The roster of a group the caller is not in, when the group is visible to the Context. Read now, and held to the
// group's latest signed statement exactly as a key read off it is: the roster is hashed into that statement.
std::optional<GroupApiImpl::RosterView> GroupApiImpl::publicRosterOf(
    const std::string& contextId,
    const std::string& groupId
) {
    try {
        server::GroupGetPublicKeyModel model;
        model.groupId = groupId;
        const server::GroupInfo group = listedFrom(_serverApi.groupGetPublicKey(model).group);
        if (group.contextId != contextId) {
            return std::nullopt;
        }
        _treeVerifier.preverifyListed({group}, VerifiedGroup::treeEnvironment(_serverApi, _connection, std::string()));
        _treeVerifier.verifyListed(group, VerifiedGroup::treeEnvironment(_serverApi, _connection, group.id));
        if (group.treeCommit->seq < static_cast<std::int64_t>(_treeVerifier.pinnedSeq(group.id))) {
            return std::nullopt;
        }
        return RosterView{
            .contextId = group.contextId,
            .keyVersion = group.keyVersion,
            .rosterVersion = group.rosterVersion,
            .users = group.users,
            .managers = group.managers,
        };
    } catch (const std::exception& e) {
        LOG_WARN("[publicRosterOf] group ", groupId, " shows no roster to this caller: ", e.what())
        return std::nullopt;
    }
}

std::unordered_map<std::string, core::GroupEpochInfo> GroupApiImpl::fetchGroupEpochs(
    const std::string& contextId,
    const std::vector<std::string>& groupIds
) {
    const SaveDuePins saveAfter{*this};
    std::unordered_map<std::string, core::GroupEpochInfo> epochs;
    // A container key is about to be wrapped to these grant keys, so each comes off the group's latest statement.
    // A writer outside the group trusts that the signer, vouched by the UserVerifier, is a member (TOFU on membership).
    // The listing (constant size) says which epoch is current; one this process has pinned is taken from the pin,
    // anything else is read with `groupGet` (roster and statement, which grow) and verified. Returns the ids served
    // behind the state this process has verified for them.
    const auto take = [&](const std::vector<std::string>& ids) {
        server::GroupListModel model;
        model.contextId = contextId;
        core::ListQueryMapper::map(model, pageOfIds("#id", ids));
        std::vector<std::string> behind;
        std::vector<server::GroupSummary> listed;
        try {
            listed = _serverApi.groupList(model).groups;
        } catch (const std::exception& e) { LOG_WARN("[fetchGroupEpochs] groupList by id unavailable: ", e.what()) }
        std::vector<server::GroupInfo> read;
        std::set<std::string> listedIds; // read in full below
        for (const auto& summary : listed) {
            // A listing for another context would have the UserVerifier vouch for the committer there.
            if (summary.contextId != contextId) {
                continue;
            }
            if (_treeVerifier.pinnedAt(summary.id, contextId, summary.keyVersion, summary.groupPubKey)) {
                epochs[summary.id] = core::GroupEpochInfo{
                    .keyVersion = summary.keyVersion,
                    .groupPubKey = keytree::TreeVerifier::canonicalKey(summary.groupPubKey)
                };
                continue;
            }
            // Limit: one `groupGet` per unpinned group, the whole tree for a caller without a seat; a statement-and-
            // roster read would do if non-member writes to new or rotated groups get hot.
            try {
                read.push_back(_serverApi.groupGet(VerifiedGroup::pathRead(summary.id)).group);
                listedIds.insert(summary.id);
            } catch (const std::exception& e) {
                LOG_WARN("[fetchGroupEpochs] group ", summary.id, " unreadable: ", e.what())
            }
        }
        // What neither the listing nor `groupGet` serves this caller: a group it is not in. The Bridge hands the
        // identity key, the roster and the latest statement of a group visible to the context to anybody in it,
        // and that is all `verifyListed` reads.
        for (const std::string& id : ids) {
            if (listedIds.count(id) != 0 || epochs.count(id) != 0) {
                continue;
            }
            try {
                server::GroupGetPublicKeyModel publicKeyModel;
                publicKeyModel.groupId = id;
                const server::GroupPublicInfo info = _serverApi.groupGetPublicKey(publicKeyModel).group;
                server::GroupInfo asListed = listedFrom(info);
                read.push_back(std::move(asListed));
            } catch (const std::exception& e) {
                LOG_WARN("[fetchGroupEpochs] group ", id, " serves no key to this caller: ", e.what())
            }
        }
        _treeVerifier.preverifyListed(read, VerifiedGroup::treeEnvironment(_serverApi, _connection, std::string()));
        for (const auto& group : read) {
            // A group that fails verification gets no key at all, never the unverified one.
            if (group.contextId != contextId) {
                continue;
            }
            try {
                _treeVerifier.verifyListed(group, VerifiedGroup::treeEnvironment(_serverApi, _connection, group.id));
            } catch (const std::exception& e) {
                LOG_WARN("[fetchGroupEpochs] group ", group.id, " failed verification: ", e.what())
                continue;
            }
            if (group.treeCommit->seq < static_cast<std::int64_t>(_treeVerifier.pinnedSeq(group.id))) {
                behind.push_back(group.id);
                continue;
            }
            epochs[group.id] = core::GroupEpochInfo{
                .keyVersion = group.keyVersion, .groupPubKey = keytree::TreeVerifier::canonicalKey(group.groupPubKey)
            };
        }
        return behind;
    };
    for (size_t offset = 0; offset < groupIds.size(); offset += BRIDGE_MAX_BATCH_SIZE) {
        const std::vector<std::string> behind = take(
            std::vector<std::string>(
                groupIds.begin() + offset, groupIds.begin() + std::min(offset + BRIDGE_MAX_BATCH_SIZE, groupIds.size())
            )
        );
        // Behind may be a read that lagged a concurrent one; read once more, and still behind gets no key.
        if (!behind.empty()) {
            take(behind);
        }
    }
    return epochs;
}

void GroupApiImpl::processNotificationEvent(const std::string& type, const core::NotificationEvent& notification) {
    auto subscriptionQuery = _subscriber.getSubscriptionQuery(notification.subscriptions);
    if (!subscriptionQuery.has_value()) {
        return;
    }
    _guardedExecutor->exec([&, type, notification, subscriptionQuery]() {
        if (type == "custom") {
            // The channel name is not in the notification — it is the fourth element of the query that matched.
            const std::string channelName = SubscriberImpl::channelNameFromQuery(subscriptionQuery.value());
            if (channelName.empty()) {
                return; // matched on a change-event subscription, so not ours to open
            }
            auto raw = server::GroupCustomEventData::fromJSON(notification.data);
            GroupCustomEventData data{
                .groupId = raw.id,
                .channelName = channelName,
                .userId = raw.author.id,
                .authorPubKey = {},
                .payload = {},
                .statusCode = 0
            };
            // A failure here is reported, never thrown: the event loop has nobody to throw to, and one
            // unreadable notification must not cost the caller the readable ones behind it.
            try {
                const core::Buffer envelope = core::Buffer::from(privmx::utils::Base64::toString(raw.eventData));
                // A member's event, for the group the bridge labels it with, under the current epoch's key: a removed
                // member holds only the earlier ones. The channel it was sealed for is checked once it is open.
                const auto routing = _envelopeEncryptor.peek(envelope);
                // A cached head behind the pinned epoch is no current key (as in `currentEncKey`).
                core::ModuleKeys keys = getModuleKeys(raw.id);
                if (routing.keyId != keys.currentKeyId || isRekeyNeeded(keys)) {
                    keys = getNewModuleKeysAndUpdateCache(raw.id);
                }
                if (routing.type != ENVELOPE_FROM_MEMBER ||
                    routing.groupId != raw.id ||
                    routing.keyId != keys.currentKeyId) {
                    throw InvalidEnvelopeFormatException(
                        "a custom event must be sealed by a member under the current key"
                    );
                }
                const OpenedEnvelope decrypted = _envelopeEncryptor.openMemberEnvelope(
                    envelope, encKeyById(raw.id, routing.keyId).key, EnvelopeBinding{}
                );
                // The bridge names the sender; the application vouches that the key which signed is that user's.
                assertUserKeysVerified(
                    getModuleKeys(decrypted.groupId).contextId,
                    {core::UserWithPubKey{.userId = raw.author.id, .pubKey = decrypted.authorPubKey}}
                );
                const auto payload = SubscriberImpl::openOnChannel(channelName, decrypted.data.stdString());
                if (!payload.has_value()) {
                    throw InvalidEnvelopeFormatException("a custom event sealed for another channel");
                }
                data.payload = core::Buffer::from(payload.value());
                data.authorPubKey = decrypted.authorPubKey;
            } catch (const core::Exception& e) { data.statusCode = e.getCode(); } catch (...) {
                data.statusCode = ENDPOINT_CORE_EXCEPTION_CODE;
            }
            auto event = core::EventBuilder::buildEvent<GroupCustomEvent>(
                "group/" + raw.id + "/" + channelName, data, notification
            );
            _eventMiddleware->emitApiEvent(event);
        } else if (type == "groupCreated") {
            auto raw = server::GroupChangedEventData::fromJSON(notification.data);
            auto data = Mapper::mapToGroupChangedEventData(raw);
            auto event = core::EventBuilder::buildEvent<GroupCreatedEvent>("context", data, notification);
            _eventMiddleware->emitApiEvent(event);
        } else if (type == "groupUpdated") {
            auto raw = server::GroupChangedEventData::fromJSON(notification.data);
            dropCachedGroup(raw.groupId);
            auto data = Mapper::mapToGroupChangedEventData(raw);
            auto event = core::EventBuilder::buildEvent<GroupUpdatedEvent>("context", data, notification);
            _eventMiddleware->emitApiEvent(event);
        } else if (type == "groupDeleted") {
            auto raw = server::GroupDeletedEventData::fromJSON(notification.data);
            // Key caches only. The pins stay as tombstones: the event is the bridge's word alone, and dropping them
            // would make the next read of the group a first contact the bridge could answer with any old state.
            _sessions.forget(raw.groupId);
            dropCachedGroup(raw.groupId);
            auto data = Mapper::mapToGroupDeletedEventData(raw);
            auto event = core::EventBuilder::buildEvent<GroupDeletedEvent>("context", data, notification);
            _eventMiddleware->emitApiEvent(event);
        } else if (type == "spaceCreated" || type == "spaceUpdated" || type == "spaceDeleted") {
            auto raw = server::SpaceChangedEventData::fromJSON(notification.data);
            // The cached read only. The pinned history stays: the event is the bridge's word alone, and the next
            // read of the Space verifies whatever it says against that pin.
            _spaces.erase(raw.spaceId);
            SpaceChangedEventData data{
                .spaceId = raw.spaceId,
                .contextId = raw.contextId,
                .keyVersion = raw.keyVersion.value_or(0),
                .publicMetaVersion = raw.publicMetaVersion.value_or(0),
                .privateMetaVersion = raw.privateMetaVersion.value_or(0),
                .changeKind = type == "spaceDeleted" ? "deleted" : raw.changeKind.value_or("")
            };
            auto event = core::EventBuilder::buildEvent<SpaceChangedEvent>("context", data, notification);
            _eventMiddleware->emitApiEvent(event);
        } else {
            LOG_ERROR("UNRESOLVED EVENT in CPP layer: '", type, "'");
        }
    });
}

// The tree and version pins stay across reconnects: they only ever move forward, and a new session is no reason
// to accept a state older than one this process has already verified.
void GroupApiImpl::processConnectedEvent() {
    _deferred.forgetChecked();
    _sessions.dropKeys(true); // the epoch keys stay for the connection
    // Open file handles too. A handle used after this reports "not an open encrypted-file handle", which a reconnect
    // made true.
    _envelopeFiles.clear();
    dropSequences();
    _spaces.clear();
    _spaceKeys.clear();
    dropCachedGroup();
}

// The sessions' unresolved commits are kept on purpose: a dropped connection is the commonest unknown outcome of a
// commit, and the same call retried on the next connection must resend that statement, not be held back by it. So
// are the pending carries: the next mutating call retries them, and dropping them would leave the planes refused to
// readers.
void GroupApiImpl::processDisconnectedEvent() {
    _deferred.dropAll();
    savePins();
    _sessions.dropKeys();
    _envelopeFiles.clear();
    dropSequences();
    _spaces.clear();
    _spaceKeys.clear();
    dropCachedGroup();
}

std::pair<core::ModuleKeys, int64_t> GroupApiImpl::getModuleKeysAndVersionFromServer(std::string moduleId) {
    const VerifiedGroup group = readGroupForKeys(moduleId);
    // The attested roster of the same read the keys come from: who an envelope's author is checked against.
    rememberRoster(group);
    // Roster version: key material moves with that plane, so a metadata-only write must not stale the cache.
    return std::make_pair(groupToModuleKeys(group), group->rosterVersion);
}

VerifiedGroup GroupApiImpl::readGroupForKeys(const std::string& groupId) {
    renewOwnLeafOnce(groupId);
    // On return, after the roster attestation below has moved the version pins too, not only the tree's.
    const SaveDuePins saveAfter{*this};
    // The tree pins `keyVersion` (never below what this client verified or committed itself); the head entry's
    // grant must be at exactly that epoch; the roster attestation binds the head to it and moves the version pins.
    GroupRead read = _hooks.read(VerifiedGroup::pathRead(groupId), keytree::TreeVerifier::Scope::Path);
    if (!read.verified.has_value()) {
        throw core::EncryptionKeyValidationException("caller holds no verifiable seat in this group's key tree");
    }
    VerifiedGroup group = std::move(read.verified.value());
    assertHeadKeyAtEpoch(group);
    _groupDataSchemaMapper->validateAndGetAttestedRoster(group, _keyProvider, _keys.resolverOver(&group));
    return group;
}

void GroupApiImpl::assertHeadKeyAtEpoch(const server::GroupInfo& group) {
    if (group.data.empty()) {
        throw GroupDataIntegrityException("group has no head entry");
    }
    bool found = false;
    for (const auto& entry : group.groupKeys.value_or(std::vector<core::server::GroupKeysEntry>{})) {
        for (const auto& key : entry.keys) {
            if (entry.group != group.id || key.keyId != group.data.back().keyId) {
                continue;
            }
            if (key.groupEpoch.value_or(0) != group.keyVersion) {
                throw GroupDataIntegrityException("the head entry's key is not the current epoch's");
            }
            found = true;
        }
    }
    if (!found) {
        throw GroupDataIntegrityException("the head entry's key is not published to the group");
    }
}

std::uint64_t GroupApiImpl::pinnedKeyVersion(const std::string& groupId) {
    return _treeVerifier.pinnedKeyVersion(groupId);
}

bool GroupApiImpl::agreesWithPin(
    const std::string& groupId,
    const std::string& contextId,
    std::int64_t keyVersion,
    const std::string& groupPubKey
) {
    return _treeVerifier.agreesWithPin(groupId, contextId, keyVersion, groupPubKey);
}

core::ModuleKeys GroupApiImpl::groupToModuleKeys(const server::GroupInfo& group) {
    return core::ModuleKeys{
        .keys = {},
        .groupKeys = group.groupKeys.value_or(std::vector<core::server::GroupKeysEntry>{}),
        .staleGroups = {},
        .currentKeyId = group.data.back().keyId,
        .moduleSchemaVersion = _groupDataSchemaMapper->getDataStructureVersion(group.data.back()),
        .moduleResourceId = group.resourceId.value_or(""),
        .contextId = group.contextId
    };
}

std::vector<std::string> GroupApiImpl::subscribeFor(const std::vector<std::string>& subscriptionQueries) {
    auto result = _subscriber.subscribeFor(subscriptionQueries);
    _eventMiddleware->notificationEventListenerAddSubscriptionIds(_notificationListenerId, result);
    return result;
}

void GroupApiImpl::unsubscribeFrom(const std::vector<std::string>& subscriptionIds) {
    _subscriber.unsubscribeFrom(subscriptionIds);
    _eventMiddleware->notificationEventListenerRemoveSubscriptionIds(_notificationListenerId, subscriptionIds);
}

std::string GroupApiImpl::buildSubscriptionQuery(
    EventType eventType,
    EventSelectorType selectorType,
    const std::string& selectorId
) {
    return SubscriberImpl::buildQuery(eventType, selectorType, selectorId);
}

std::string GroupApiImpl::buildCustomEventSubscriptionQuery(
    const std::string& channelName,
    EventSelectorType selectorType,
    const std::string& selectorId
) {
    return SubscriberImpl::buildCustomEventQuery(channelName, selectorType, selectorId);
}

privmx::crypto::PrivateKey GroupApiImpl::resolveGroupPrivKey(
    const std::string& groupId,
    int64_t epoch,
    const VerifiedGroup* seatedRead,
    const ClimbWith* with
) {
    return _keys.resolveGroupPrivKey(groupId, epoch, seatedRead, with);
}

GroupApiHooks GroupApiImpl::bindHooks() {
    return GroupApiHooks{
        .read =
            [this](const server::GroupGetModel& model, keytree::TreeVerifier::Scope scope) {
                return VerifiedGroup::read(_serverApi, _treeVerifier, _connection, model, scope, [this] {
                    savePinsIfDue();
                });
            },
        .readForKeys = [this](const std::string& groupId) { return readGroupForKeys(groupId); },
        .savePins = [this] { savePins(); },
        .prepareCreate = [this](const std::string& contextId) { return prepareContainerCreate(contextId, {}, {}); },
        .prepareUpdate =
            [this](
                const server::GroupInfo& group, const std::string& resourceId, const RosterAfterChange& roster,
                bool newKey
            ) {
                return prepareContainerUpdateWithoutKeyEntries(
                    group, group.data.back(), resourceId, roster.users, roster.managers, newKey
                );
            },
        .buildGroupKeyEntries =
            [this](
                const std::vector<core::GroupGrantWithKey>& groups, const core::EncKey& key,
                const core::DataIntegrityObject& dio, const std::string& contextId, const std::string& resourceId,
                const std::string& containerSecret
            ) { return buildGroupKeyEntries(groups, key, dio, contextId, resourceId, containerSecret); },
        .assertUserKeysVerified = [this](
                                      const std::string& contextId, const std::vector<core::UserWithPubKey>& users
                                  ) { assertUserKeysVerified(contextId, users); },
        .resolveMemberKeys = [this](
                                 const std::string& contextId, const std::vector<std::string>& userIds
                             ) { return resolveMemberKeys(contextId, userIds); },
        .invalidateModuleKeys = [this](const std::string& groupId) { dropCachedGroup(groupId); },
    };
}

// -- envelopes -------------------------------------------------------------------------------------------

core::DecryptedEncKeyV2 GroupApiImpl::encKeyById(
    const std::string& groupId,
    const std::string& keyId,
    std::int64_t* epochOut
) {
    return _keys.encKeyById(
        groupId, keyId,
        [&](bool fresh) { return fresh ? getNewModuleKeysAndUpdateCache(groupId) : getModuleKeys(groupId); },
        *_keyProvider, _groupPrivKeyResolver, epochOut
    );
}

core::DecryptedEncKeyV2 GroupApiImpl::currentEncKey(const std::string& groupId) {
    core::ModuleKeys keys = getModuleKeys(groupId);
    // A cached head behind the epoch verified since (a read for a key, a commit of our own, a sibling instance's
    // save) is re-read, not refused.
    if (isRekeyNeeded(keys)) {
        keys = getNewModuleKeysAndUpdateCache(groupId);
    }
    return getAndValidateModuleCurrentEncKey(keys);
}

// -- envelopes: what is checked, in one place -------------------------------------------------------------

Path GroupApiImpl::noLocation() {
    return Path{PathSegment{.isId = true, .value = core::Buffer()}};
}

core::Buffer GroupApiImpl::idFromString(const std::string& identifier) {
    if (identifier.empty()) {
        throw core::InvalidParamsException("an identifier cannot be empty");
    }
    // A UUID is the one identifier that commonly travels in several spellings (case, dashes, braces): two clients
    // that spelled it differently would bind to different paths. Only its exact forms count - 32 hex digits,
    // 8-4-4-4-12, or that in one pair of braces - so nothing else is ever reinterpreted.
    std::string body = identifier;
    if (body.size() == 38 && body.front() == '{' && body.back() == '}') {
        body = body.substr(1, 36);
    }
    bool uuid = body.size() == 32 || body.size() == 36;
    std::string hex;
    for (std::size_t i = 0; uuid && i < body.size(); ++i) {
        const bool dashExpected = body.size() == 36 && (i == 8 || i == 13 || i == 18 || i == 23);
        if (dashExpected) {
            uuid = body[i] == '-';
        } else if (std::isxdigit(static_cast<unsigned char>(body[i]))) {
            hex.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(body[i]))));
        } else {
            uuid = false;
        }
    }
    // The first byte says which of the two it is, so the 16 bytes of a UUID are never the bytes of some other
    // identifier written as text.
    if (!uuid) {
        return core::Buffer::from(std::string(1, '\x00') + identifier);
    }
    std::string bytes(1, '\x01');
    for (std::size_t i = 0; i < hex.size(); i += 2) {
        bytes.push_back(static_cast<char>(std::stoi(hex.substr(i, 2), nullptr, 16)));
    }
    return core::Buffer::from(bytes);
}

EnvelopeBinding GroupApiImpl::bindingOf(const Path& location, EnvelopeContent content) {
    if (location.size() == 1 && location.front().isId && location.front().value.size() == 0) {
        return EnvelopeBinding{.content = content};
    }
    if (location.empty()) {
        throw core::InvalidParamsException("a location needs at least one segment; say noLocation() to bind to none");
    }
    for (const PathSegment& segment : location) {
        if (segment.value.size() == 0) {
            throw core::InvalidParamsException("a location segment cannot be empty");
        }
    }
    EnvelopeBinding binding = GroupEnvelopeEncryptor::bindLocation(location);
    binding.content = content;
    return binding;
}

std::string GroupApiImpl::kindOf(const EnvelopeRouting& routing) {
    if (!routing.spaceId.empty()) {
        return "space";
    }
    switch (routing.type) {
    case ENVELOPE_FROM_MEMBER:
        return "member";
    case ENVELOPE_FROM_OUTSIDER:
        return "outsider";
    default:
        return "anonymous";
    }
}

EnvelopeAudience GroupApiImpl::audienceOf(const std::vector<WireRecipient>& recipients) {
    EnvelopeAudience audience;
    for (const WireRecipient& recipient : recipients) {
        (recipient.isGroup ? audience.groups : audience.users).push_back(recipient.id);
    }
    return audience;
}

EnvelopeHeader GroupApiImpl::peekEnvelope(const core::Buffer& envelope) {
    const EnvelopeRouting routing = GroupEnvelopeEncryptor::peekAny(envelope);
    EnvelopeHeader header{
        .version = GroupEnvelopeEncryptor::VERSION,
        .groupId = routing.groupId,
        .keyVersion = routing.keyVersion,
        .fromOutsider = routing.type != ENVELOPE_FROM_MEMBER && routing.spaceId.empty(),
        .isSigned = routing.type != ENVELOPE_ANONYMOUS,
        .isFile = routing.content == EnvelopeContent::File,
        .hasLocation = routing.hasLocation,
        .authorUserId = routing.authorUserId,
        .sequenceId = routing.content == EnvelopeContent::Sequence ?
            privmx::utils::Hex::from(GroupEnvelopeEncryptor::sequenceIdOf(envelope)) :
            std::string(),
        .spaceId = routing.spaceId,
        .alsoForGroups = {},
        .alsoForUsers = {},
    };
    for (const WireRecipient& recipient : routing.recipients) {
        if (recipient.isGroup) {
            header.alsoForGroups.push_back(GroupEpochRef{.groupId = recipient.id, .keyVersion = recipient.keyVersion});
        } else {
            header.alsoForUsers.push_back(recipient.id);
        }
    }
    return header;
}

std::string GroupApiImpl::RosterView::roleOf(const std::string& userId) const {
    if (std::find(managers.begin(), managers.end(), userId) != managers.end()) {
        return "manager";
    }
    if (std::find(users.begin(), users.end(), userId) != users.end()) {
        return "user";
    }
    return std::string();
}

void GroupApiImpl::rememberRoster(const server::GroupInfo& group) {
    _rosters.set(
        group.id,
        RosterView{
            .contextId = group.contextId,
            .keyVersion = group.keyVersion,
            .rosterVersion = group.rosterVersion,
            .users = group.users,
            .managers = group.managers,
        }
    );
}

void GroupApiImpl::dropCachedGroup(const std::optional<std::string>& groupId) {
    // Before the keys: a reader between the two finds no roster and re-reads, rather than a roster without keys.
    if (groupId.has_value()) {
        _rosters.erase(groupId.value());
    } else {
        _rosters.clear();
    }
    // A change in a group can make a Space's key stale; the next write reads the Space again.
    _spaces.clear();
    invalidateModuleKeysInCache(groupId);
}

GroupApiImpl::RosterView GroupApiImpl::rosterOf(const std::string& groupId) {
    // The module keys first: a cache the group's own events invalidated is re-read here, and that read is the
    // one that refreshes the roster beside it.
    core::ModuleKeys keys = getModuleKeys(groupId);
    if (isRekeyNeeded(keys)) {
        getNewModuleKeysAndUpdateCache(groupId);
    }
    auto roster = _rosters.get(groupId);
    if (!roster.has_value()) {
        getNewModuleKeysAndUpdateCache(groupId);
        roster = _rosters.get(groupId);
    }
    if (!roster.has_value()) {
        throw core::EncryptionKeyValidationException("caller holds no verifiable seat in this group's key tree");
    }
    return roster.value();
}

void GroupApiImpl::requireAuthorStated(const DecryptOptions& options) {
    if (options.anyAuthor == !options.expectedAuthor.empty()) {
        throw EnvelopeAuthorNotStatedException(
            options.anyAuthor ? "both expectedAuthor and anyAuthor are set" :
                                "neither expectedAuthor nor anyAuthor is set"
        );
    }
}

void GroupApiImpl::requireFor(const EnvelopeRouting& routing, const std::string& groupId, EnvelopeType kind) {
    if (routing.groupId != groupId) {
        throw EnvelopeWrongGroupException();
    }
    // An envelope of a Space parses as a member's; it is read with the Space, never with a group.
    if (routing.type != kind || !routing.spaceId.empty()) {
        throw EnvelopeWrongKindException(kindOf(routing));
    }
}

void GroupApiImpl::requireVerifiedWriter(
    const std::string& contextId,
    const OpenedEnvelope& opened,
    const DecryptOptions& options
) {
    if (!options.anyAuthor && opened.authorUserId != options.expectedAuthor) {
        throw EnvelopeWrongAuthorException("signed by " + opened.authorUserId);
    }
    // The id is the writer's own claim, like the key: the application's UserVerifier says whether that user
    // holds that key. Without this anyone could sign as anyone.
    try {
        assertUserKeysVerified(
            contextId, {core::UserWithPubKey{.userId = opened.authorUserId, .pubKey = opened.authorPubKey}}
        );
    } catch (const core::Exception& e) {
        throw EnvelopeUnverifiedAuthorException(opened.authorUserId + " " + opened.authorPubKey, e);
    }
}

void GroupApiImpl::requireCurrentKey(const std::string& groupId, const std::string& keyId) {
    // A cached head behind the pinned epoch is no current key (as in `currentEncKey`).
    core::ModuleKeys keys = getModuleKeys(groupId);
    if (keyId != keys.currentKeyId || isRekeyNeeded(keys)) {
        keys = getNewModuleKeysAndUpdateCache(groupId);
    }
    if (keyId != keys.currentKeyId) {
        throw EnvelopeStaleEpochException();
    }
}

std::vector<WireRecipient> GroupApiImpl::wireRecipients(
    const std::string& contextId,
    const std::string& homeGroupId,
    const std::vector<EnvelopeRecipient>& alsoFor
) {
    std::vector<WireRecipient> recipients;
    std::vector<std::string> groupIds;
    for (const EnvelopeRecipient& recipient : alsoFor) {
        if (recipient.groupId.empty() == !recipient.user.has_value()) {
            throw core::InvalidParamsException("a recipient is one group, by its ID, or one user");
        }
        if (!recipient.groupId.empty()) {
            core::Validator::validateId(recipient.groupId, "field:alsoFor.groupId ");
            if (recipient.groupId == homeGroupId) {
                throw core::InvalidParamsException("the group an envelope is written in is not a further recipient");
            }
            groupIds.push_back(recipient.groupId);
        }
    }
    // Each group's key is its current one, read and verified now: one from before a removal cannot be passed in.
    const auto epochs = groupIds.empty() ? std::unordered_map<std::string, core::GroupEpochInfo>{} :
                                           fetchGroupEpochs(contextId, groupIds);
    for (const EnvelopeRecipient& recipient : alsoFor) {
        if (!recipient.groupId.empty()) {
            const auto epoch = epochs.find(recipient.groupId);
            if (epoch == epochs.end()) {
                throw core::InvalidParamsException("recipient group " + recipient.groupId + " has no verifiable key");
            }
            recipients.push_back(
                WireRecipient{
                    .isGroup = true,
                    .id = recipient.groupId,
                    .pubKey = privmx::crypto::PublicKey::fromBase58DER(epoch->second.groupPubKey).toBase58DER(),
                    .keyVersion = epoch->second.keyVersion,
                }
            );
        } else {
            assertUserKeysVerified(contextId, {recipient.user.value()});
            recipients.push_back(
                WireRecipient{
                    .isGroup = false,
                    .id = recipient.user->userId,
                    .pubKey = privmx::crypto::PublicKey::fromBase58DER(recipient.user->pubKey).toBase58DER(),
                    .keyVersion = 0,
                }
            );
        }
    }
    return recipients;
}

Envelope GroupApiImpl::sealAsMember(
    const std::string& groupId,
    const EnvelopeBinding& binding,
    const core::Buffer& content,
    const std::vector<EnvelopeRecipient>& alsoFor
) {
    const std::string keyId = currentEncKey(groupId).id;
    // The epoch of the key used, looked up by its id as `decrypt` does: the roster is a second lookup, and a rotation
    // between the two would label K_n's envelope n+1, which nobody could open. The roster gives only who it is for.
    std::int64_t epoch = 0;
    const core::DecryptedEncKeyV2 key = encKeyById(groupId, keyId, &epoch);
    const RosterView roster = rosterOf(groupId);
    const EnvelopeSeal seal{
        .binding = binding,
        .keyVersion = epoch,
        .encryptedAt = privmx::utils::Utils::getNowTimestamp(),
        .authorUserId = _connection.getImpl()->getMyUserId(roster.contextId),
    };
    return _envelopeEncryptor.packMemberEnvelope(
        groupId, key.id, content, _userPrivKey, key.key, seal, wireRecipients(roster.contextId, groupId, alsoFor)
    );
}

Envelope GroupApiImpl::encrypt(
    const std::string& groupId,
    const Path& location,
    const core::Buffer& content,
    const EncryptOptions& options
) {
    return sealAsMember(groupId, bindingOf(location), content, options.alsoFor);
}

// The notification is an ordinary member envelope: one `encrypt` under the group's current key, one request
// whatever the group's size. The recipients already hold the key, so there is no key list to build.
void GroupApiImpl::sendCustomEvent(
    const std::string& groupId,
    const std::string& channelName,
    const core::Buffer& eventData,
    const std::vector<std::string>& users
) {
    server::GroupSendCustomEventModel model;
    model.groupId = groupId;
    model.channel = channelName;
    // Bound to its channel inside the content (`sealOnChannel`), not by a location: an event has no place in the
    // application's data.
    model.data = privmx::utils::Base64::from(
        sealAsMember(
            groupId, EnvelopeBinding{},
            core::Buffer::from(SubscriberImpl::sealOnChannel(channelName, eventData.stdString())), {}
        )
            .stdString()
    );
    if (!users.empty()) {
        model.users = users;
    }
    _serverApi.groupSendCustomEvent(model);
}

DecryptedEnvelope GroupApiImpl::decrypt(
    const std::string& groupId,
    const Path& location,
    const Envelope& envelope,
    const DecryptOptions& options,
    EnvelopeContent content
) {
    requireAuthorStated(options);
    const EnvelopeBinding binding = bindingOf(location, content);
    const EnvelopeRouting routing = _envelopeEncryptor.peek(envelope, content);
    // Before any key is looked up: the caller names the group, so an envelope cannot steer the read to another.
    requireFor(routing, groupId, ENVELOPE_FROM_MEMBER);

    std::int64_t epoch = 0;
    const core::DecryptedEncKeyV2 key = encKeyById(groupId, routing.keyId, &epoch);
    const OpenedEnvelope opened = _envelopeEncryptor.openMemberEnvelope(envelope, key.key, binding);
    // The epoch in the header is what a server without keys gates writes on. It has to be the epoch of the key
    // that actually opened the envelope, or a removed member would label an old key's envelope as current.
    if (opened.keyVersion != epoch) {
        throw InvalidEnvelopeFormatException("envelope claims an epoch other than its key's");
    }
    if (options.currentEpochOnly) {
        requireCurrentKey(groupId, routing.keyId);
    }
    const RosterView roster = rosterOf(groupId);
    requireVerifiedWriter(roster.contextId, opened, options);
    const std::string role = roster.roleOf(opened.authorUserId);
    if (role.empty()) {
        throw EnvelopeAuthorNotMemberException(opened.authorUserId);
    }
    return DecryptedEnvelope{
        .data = opened.data,
        .author = EnvelopeAuthor{.userId = opened.authorUserId, .pubKey = opened.authorPubKey, .role = role},
        .keyVersion = epoch,
        .encryptedAt = opened.encryptedAt,
        .sharedWith = audienceOf(opened.recipients),
    };
}

std::vector<DecryptResult> GroupApiImpl::decryptMany(
    const std::string& groupId,
    const std::vector<DecryptItem>& items
) {
    std::vector<DecryptResult> results;
    results.reserve(items.size());
    for (const DecryptItem& item : items) {
        DecryptResult result{};
        try {
            result.envelope = decrypt(groupId, item.location, item.envelope, item.options);
        } catch (const core::Exception& e) {
            result.statusCode = e.getCode();
            // What the failure is about, read off the plain header: enough to name it in a warning, and
            // unauthenticated, so never shown as fact.
            try {
                const EnvelopeRouting routing = GroupEnvelopeEncryptor::peekAny(item.envelope);
                if (e.getCode() == EnvelopeWrongKindException::FULL_CODE) {
                    result.details.envelopeKind = kindOf(routing);
                } else if (e.getCode() == EnvelopeWrongAuthorException::FULL_CODE ||
                           e.getCode() == EnvelopeUnverifiedAuthorException::FULL_CODE ||
                           e.getCode() == EnvelopeAuthorNotMemberException::FULL_CODE) {
                    result.details.userId = routing.authorUserId;
                    result.details.pubKey = routing.authorPubKey;
                }
            } catch (...) {}
        } catch (...) { result.statusCode = ENDPOINT_CORE_EXCEPTION_CODE; }
        results.push_back(std::move(result));
    }
    return results;
}

Envelope GroupApiImpl::encryptAsOutsider(
    const std::string& contextId,
    const std::string& groupId,
    const Path& location,
    const core::Buffer& content,
    const EncryptOptions& options
) {
    return sealAsOutsider(contextId, groupId, bindingOf(location), content, options.alsoFor);
}

Envelope GroupApiImpl::sealAsOutsider(
    const std::string& contextId,
    const std::string& groupId,
    const EnvelopeBinding& binding,
    const core::Buffer& content,
    const std::vector<EnvelopeRecipient>& alsoFor
) {
    // The group's current key, off its latest verified statement: the same read a container's grant uses.
    const auto epochs = fetchGroupEpochs(contextId, {groupId});
    const auto epoch = epochs.find(groupId);
    if (epoch == epochs.end()) {
        throw core::InvalidParamsException("group " + groupId + " has no verifiable key");
    }
    const EnvelopeSeal seal{
        .binding = binding,
        .keyVersion = 0,
        .encryptedAt = privmx::utils::Utils::getNowTimestamp(),
        .authorUserId = _connection.getImpl()->getMyUserId(contextId),
    };
    return _envelopeEncryptor.packOutsiderEnvelope(
        groupId, privmx::crypto::PublicKey::fromBase58DER(epoch->second.groupPubKey), content, _userPrivKey, seal,
        wireRecipients(contextId, groupId, alsoFor)
    );
}

DecryptedOutsiderEnvelope GroupApiImpl::decryptFromOutsider(
    const std::string& groupId,
    const Path& location,
    const Envelope& envelope,
    const DecryptOptions& options,
    EnvelopeContent content
) {
    requireAuthorStated(options);
    const EnvelopeBinding binding = bindingOf(location, content);
    const EnvelopeRouting routing = _envelopeEncryptor.peek(envelope, content);
    requireFor(routing, groupId, ENVELOPE_FROM_OUTSIDER);

    const OpenedEnvelope opened = _envelopeEncryptor.openOutsiderEnvelope(
        envelope, _keys.grantKeyForPubKey(groupId, routing.groupPubKey), binding
    );
    const std::int64_t epoch = _keys.grantEpochOf(groupId, routing.groupPubKey);
    RosterView roster = rosterOf(groupId);
    if (options.currentEpochOnly && epoch != roster.keyVersion) {
        // The epoch was just looked up, the roster may be a cached one behind it: read again before refusing (as
        // `requireCurrentKey` does).
        getNewModuleKeysAndUpdateCache(groupId);
        roster = rosterOf(groupId);
        if (epoch != roster.keyVersion) {
            throw EnvelopeStaleEpochException();
        }
    }
    requireVerifiedWriter(roster.contextId, opened, options);
    return DecryptedOutsiderEnvelope{
        .data = opened.data,
        .keyVersion = epoch,
        .sender = EnvelopeSender{.userId = opened.authorUserId, .pubKey = opened.authorPubKey},
        .encryptedAt = opened.encryptedAt,
        .sharedWith = audienceOf(opened.recipients),
    };
}

DecryptedAnonymousEnvelope GroupApiImpl::decryptAnonymous(
    const std::string& groupId,
    const Path& location,
    const Envelope& envelope,
    EnvelopeContent content
) {
    const EnvelopeBinding binding = bindingOf(location, content);
    const EnvelopeRouting routing = _envelopeEncryptor.peek(envelope, content);
    requireFor(routing, groupId, ENVELOPE_ANONYMOUS);
    const OpenedEnvelope opened = _envelopeEncryptor.openAnonymousEnvelope(
        envelope, _keys.grantKeyForPubKey(groupId, routing.groupPubKey), binding
    );
    return DecryptedAnonymousEnvelope{
        .data = opened.data, .keyVersion = _keys.grantEpochOf(groupId, routing.groupPubKey)
    };
}

DecryptedSharedEnvelope GroupApiImpl::decryptShared(
    const std::string& contextId,
    const Path& location,
    const Envelope& envelope,
    const DecryptOptions& options,
    EnvelopeContent content
) {
    requireAuthorStated(options);
    if (options.currentEpochOnly) {
        // A recipient holds no epoch of the author's Group to compare with: refused, never silently ignored.
        throw core::InvalidParamsException("currentEpochOnly does not apply to a shared envelope");
    }
    const EnvelopeBinding binding = bindingOf(location, content);
    const EnvelopeRouting routing = _envelopeEncryptor.peek(envelope, content);
    if (!routing.spaceId.empty()) {
        throw EnvelopeWrongKindException(kindOf(routing));
    }
    core::Validator::validateId(routing.groupId, "field:envelope.groupId ");
    if (routing.type == ENVELOPE_ANONYMOUS || routing.recipients.empty()) {
        // Not shared with anybody: a plain member's or outsider's envelope is read with the group it names.
        throw EnvelopeWrongKindException(kindOf(routing));
    }

    // The caller among the recipients: as a user first (no request), then through a recipient group they are in.
    const std::string ownPubKey = _userPrivKey.getPublicKey().toBase58DER();
    std::optional<OpenedEnvelope> opened;
    std::string via;
    for (std::size_t i = 0; i < routing.recipients.size() && !opened.has_value(); ++i) {
        const WireRecipient& recipient = routing.recipients[i];
        if (!recipient.isGroup &&
            privmx::crypto::PublicKey::fromBase58DER(recipient.pubKey).toBase58DER() == ownPubKey) {
            opened = _envelopeEncryptor.openSharedEnvelope(envelope, i, _userPrivKey, binding);
            via = "user";
        }
    }
    for (std::size_t i = 0; i < routing.recipients.size() && !opened.has_value(); ++i) {
        const WireRecipient& recipient = routing.recipients[i];
        if (!recipient.isGroup) {
            continue;
        }
        std::optional<privmx::crypto::PrivateKey> groupKey;
        try {
            core::Validator::validateId(recipient.id, "field:envelope.recipient ");
            groupKey = _keys.grantKeyForPubKey(recipient.id, recipient.pubKey);
        } catch (const core::Exception&) {
            continue; // not a group of the caller's, or not a key of that group
        }
        // From here a failure is about the envelope, not about who the caller is: it is reported.
        opened = _envelopeEncryptor.openSharedEnvelope(envelope, i, groupKey.value(), binding);
        via = recipient.id;
    }
    if (!opened.has_value()) {
        throw EnvelopeNotARecipientException();
    }
    requireVerifiedWriter(contextId, opened.value(), options);

    // Whether the writer is inside the group the envelope names is not something a recipient's key can show
    // (`homeGroupUnverified`). The group's roster can, for a caller who is in that group too.
    std::string membership = "unknown";
    if (opened->type == ENVELOPE_FROM_OUTSIDER) {
        membership = "notMember";
    } else {
        try {
            // A roster of another Context says nothing about a group of this one: "unknown".
            const RosterView roster = rosterOf(opened->groupId);
            if (roster.contextId == contextId) {
                membership = roster.roleOf(opened->authorUserId).empty() ? "notMember" : "member";
            }
        } catch (const core::Exception& e) {
            if (isForgedHistory(e)) {
                throw;
            }
            // Not a group of the caller's. One visible to the Context still shows its signed roster.
            if (const auto roster = publicRosterOf(contextId, opened->groupId); roster.has_value()) {
                membership = roster->roleOf(opened->authorUserId).empty() ? "notMember" : "member";
            }
        }
    }
    return DecryptedSharedEnvelope{
        .data = opened->data,
        .sender = EnvelopeSender{.userId = opened->authorUserId, .pubKey = opened->authorPubKey},
        .homeGroupId = opened->groupId,
        .senderMembership = membership,
        .via = via,
        .encryptedAt = opened->encryptedAt,
        .sharedWith = audienceOf(opened->recipients),
    };
}

Envelope GroupApiImpl::encryptAnonymously(
    const std::string& groupId,
    const std::string& groupPubKey,
    const Path& location,
    const core::Buffer& content
) {
    // Public information only: no membership, no server call. That is the whole point: the sender is outside
    // the group and must stay able to write into it knowing nothing but its id and its identity key.
    return _envelopeEncryptor.packAnonymousEnvelope(
        groupId, privmx::crypto::PublicKey::fromBase58DER(groupPubKey), content, bindingOf(location)
    );
}

// -- envelope files --------------------------------------------------------------------------------------
//
// A file's envelope is an ordinary envelope whose content is the file's manifest. So a file is written and read
// through the same four doors as a message, with the same checks, and only the bytes go another way.

FileHandle GroupApiImpl::beginFileWrite(std::function<core::Buffer(const core::Buffer&)> seal) {
    EnvelopeFileState state{};
    // Per file, so a chunk lifted from one file is useless in any other.
    state.fileKey = privmx::crypto::Crypto::randomBytes(32);
    state.seal = std::move(seal);
    return _envelopeFiles.open("GroupEnvelope:Encrypt", std::move(state));
}

FileHandle GroupApiImpl::beginFileRead(const core::Buffer& manifest, DecryptedFileInfo info) {
    EnvelopeFileState state{};
    state.reading = true;
    state.chunks = GroupEnvelopeEncryptor::readFileManifest(manifest, state.fileKey);
    info.size = static_cast<int64_t>(GroupEnvelopeFiles::plainSizeOf(state));
    state.info = std::move(info);
    return _envelopeFiles.open("GroupEnvelope:Decrypt", std::move(state));
}

FileHandle GroupApiImpl::beginFileEncryption(
    const std::string& groupId,
    const Path& location,
    const EncryptOptions& options
) {
    const EnvelopeBinding binding = bindingOf(location, EnvelopeContent::File);
    // Now, so that a caller who cannot write to the group learns it before the upload and not after. The
    // envelope is sealed at the finish, under the key that is current then.
    currentEncKey(groupId);
    return beginFileWrite([this, groupId, binding, alsoFor = options.alsoFor](const core::Buffer& manifest) {
        return sealAsMember(groupId, binding, manifest, alsoFor);
    });
}

FileHandle GroupApiImpl::beginFileEncryptionAsOutsider(
    const std::string& contextId,
    const std::string& groupId,
    const Path& location,
    const EncryptOptions& options
) {
    const EnvelopeBinding binding = bindingOf(location, EnvelopeContent::File);
    if (fetchGroupEpochs(contextId, {groupId}).count(groupId) == 0) {
        throw core::InvalidParamsException("group " + groupId + " has no verifiable key");
    }
    return beginFileWrite([this, contextId, groupId, binding, alsoFor = options.alsoFor](const core::Buffer& manifest) {
        return sealAsOutsider(contextId, groupId, binding, manifest, alsoFor);
    });
}

FileHandle GroupApiImpl::beginFileEncryptionAnonymously(
    const std::string& groupId,
    const std::string& groupPubKey,
    const Path& location
) {
    const EnvelopeBinding binding = bindingOf(location, EnvelopeContent::File);
    // No server call and no membership, exactly like `encryptAnonymously`.
    const privmx::crypto::PublicKey pubKey = privmx::crypto::PublicKey::fromBase58DER(groupPubKey);
    return beginFileWrite([this, groupId, pubKey, binding](const core::Buffer& manifest) {
        return _envelopeEncryptor.packAnonymousEnvelope(groupId, pubKey, manifest, binding);
    });
}

core::Buffer GroupApiImpl::encryptFileChunk(FileHandle fileHandle, const core::Buffer& plainChunk) {
    return _envelopeFiles.encryptChunk(fileHandle, plainChunk);
}

Envelope GroupApiImpl::finishFileEncryption(FileHandle fileHandle) {
    return _envelopeFiles.finishWrite(fileHandle, [](const EnvelopeFileState& state) {
        return state.seal(GroupEnvelopeEncryptor::packFileManifest(state.fileKey, state.chunks));
    });
}

void GroupApiImpl::abortFile(FileHandle fileHandle) {
    _envelopeFiles.abort(fileHandle);
}

FileHandle GroupApiImpl::beginFileDecryption(
    const std::string& groupId,
    const Path& location,
    const Envelope& envelope,
    const DecryptOptions& options
) {
    const DecryptedEnvelope opened = decrypt(groupId, location, envelope, options, EnvelopeContent::File);
    return beginFileRead(
        opened.data,
        DecryptedFileInfo{
            .author = opened.author,
            .sender = std::nullopt,
            .homeGroupId = {},
            .senderMembership = {},
            .via = {},
            .sharedWith = opened.sharedWith,
            .keyVersion = opened.keyVersion,
            .size = 0,
            .complete = false,
        }
    );
}

FileHandle GroupApiImpl::beginFileDecryptionFromOutsider(
    const std::string& groupId,
    const Path& location,
    const Envelope& envelope,
    const DecryptOptions& options
) {
    const DecryptedOutsiderEnvelope opened = decryptFromOutsider(
        groupId, location, envelope, options, EnvelopeContent::File
    );
    return beginFileRead(
        opened.data,
        DecryptedFileInfo{
            .author = std::nullopt,
            .sender = opened.sender,
            .homeGroupId = {},
            .senderMembership = {},
            .via = {},
            .sharedWith = opened.sharedWith,
            .keyVersion = opened.keyVersion,
            .size = 0,
            .complete = false,
        }
    );
}

FileHandle GroupApiImpl::beginAnonymousFileDecryption(
    const std::string& groupId,
    const Path& location,
    const Envelope& envelope
) {
    const DecryptedAnonymousEnvelope opened = decryptAnonymous(groupId, location, envelope, EnvelopeContent::File);
    return beginFileRead(
        opened.data,
        DecryptedFileInfo{
            .author = std::nullopt,
            .sender = std::nullopt,
            .homeGroupId = {},
            .senderMembership = {},
            .via = {},
            .sharedWith = {},
            .keyVersion = opened.keyVersion,
            .size = 0,
            .complete = false,
        }
    );
}

FileHandle GroupApiImpl::beginSharedFileDecryption(
    const std::string& contextId,
    const Path& location,
    const Envelope& envelope,
    const DecryptOptions& options
) {
    const DecryptedSharedEnvelope opened = decryptShared(contextId, location, envelope, options, EnvelopeContent::File);
    return beginFileRead(
        opened.data,
        DecryptedFileInfo{
            .author = std::nullopt,
            .sender = opened.sender,
            .homeGroupId = opened.homeGroupId,
            .senderMembership = opened.senderMembership,
            .via = opened.via,
            .sharedWith = opened.sharedWith,
            .keyVersion = 0,
            .size = 0,
            .complete = false,
        }
    );
}

core::Buffer GroupApiImpl::decryptFileChunk(FileHandle fileHandle, const core::Buffer& cipherChunk) {
    return _envelopeFiles.decryptChunk(fileHandle, cipherChunk);
}

CipherRange GroupApiImpl::getFileCipherRange(FileHandle fileHandle, FilePosition from, FilePosition to) {
    return _envelopeFiles.cipherRange(fileHandle, from, to);
}

CipherOffset GroupApiImpl::seekInEncryptedFile(FileHandle fileHandle, FilePosition position) {
    return _envelopeFiles.seek(fileHandle, position);
}

DecryptedFileInfo GroupApiImpl::finishFileDecryption(FileHandle fileHandle) {
    EnvelopeFileState state = _envelopeFiles.finish(fileHandle, true);
    state.info.complete = !state.seeked;
    return state.info;
}

// -- sequences -------------------------------------------------------------------------------------------

SequenceHandle GroupApiImpl::openSequenceHandle(const std::string& label, std::shared_ptr<Sequence> sequence) {
    const SequenceHandle handle = _connection.getImpl()->getHandleManager()->createHandle(label);
    _sequences.set(handle, std::move(sequence));
    return handle;
}

std::shared_ptr<GroupApiImpl::Sequence> GroupApiImpl::sequenceOf(SequenceHandle handle, bool wantReading) {
    const auto sequence = _sequences.get(handle);
    if (!sequence.has_value()) {
        throw core::InvalidParamsException("field:sequence is not an open sequence handle");
    }
    if (sequence.value()->reading != wantReading) {
        throw core::InvalidParamsException(
            wantReading ? "field:sequence came from beginSequence, not openSequence" :
                          "field:sequence came from openSequence, not beginSequence"
        );
    }
    return sequence.value();
}

// Every open sequence, out of the HandleManager too: a handle used after this is "not an open sequence handle".
void GroupApiImpl::dropSequences() {
    std::vector<SequenceHandle> handles;
    _sequences.forAll([&](const SequenceHandle& handle, const std::shared_ptr<Sequence>&) {
        handles.push_back(handle);
    });
    for (const SequenceHandle handle : handles) {
        _sequences.erase(handle);
        try {
            _connection.getImpl()->getHandleManager()->removeHandle(handle);
        } catch (...) {}
    }
}

void GroupApiImpl::closeSequence(SequenceHandle handle) {
    if (!_sequences.get(handle).has_value()) {
        throw core::InvalidParamsException("field:sequence is not an open sequence handle");
    }
    _sequences.erase(handle);
    _connection.getImpl()->getHandleManager()->removeHandle(handle);
}

SequenceHandle GroupApiImpl::beginSequenceOver(
    const std::function<core::Buffer(const core::Buffer& key)>& sealHeader,
    const std::function<std::function<void()>(const core::Buffer& header)>& epochGuard,
    int64_t checkpointEvery
) {
    if (checkpointEvery < 0) {
        throw core::InvalidParamsException("field:checkpointEvery cannot be negative");
    }
    auto sequence = std::make_shared<Sequence>();
    sequence->key = privmx::crypto::Crypto::randomBytes(32);
    sequence->header = sealHeader(core::Buffer::from(sequence->key));
    sequence->id = GroupEnvelopeEncryptor::sequenceIdOf(sequence->header);
    sequence->transcript = GroupEnvelopeEncryptor::sequenceTranscriptStart(sequence->id);
    sequence->checkpointEvery = checkpointEvery;
    sequence->requireCurrentEpoch = epochGuard(sequence->header);
    return openSequenceHandle("GroupSequence:Write", std::move(sequence));
}

SequenceHandle GroupApiImpl::beginSequence(const std::string& groupId, const Path& location, int64_t checkpointEvery) {
    const EnvelopeBinding binding = bindingOf(location, EnvelopeContent::Sequence);
    return beginSequenceOver(
        // The header is a member's envelope like any other: signed, bound to the location, sealed to the epoch.
        [&](const core::Buffer& key) { return sealAsMember(groupId, binding, key, {}); },
        // Whoever was removed since still knows this sequence's key: it must not go on.
        [&](const core::Buffer& header) -> std::function<void()> {
            return [this, groupId, keyId = GroupEnvelopeEncryptor::peekAny(header).keyId]() {
                requireCurrentKey(groupId, keyId);
            };
        },
        checkpointEvery
    );
}

core::Buffer GroupApiImpl::getSequenceHeader(SequenceHandle handle) {
    return sequenceOf(handle, false)->header;
}

core::Buffer GroupApiImpl::markSequence(Sequence& sequence, bool closed) {
    sequence.sinceMark = 0;
    return _envelopeEncryptor.packSequenceMark(
        sequence.id, sequence.key,
        GroupEnvelopeEncryptor::SequenceMark{
            .count = sequence.next, .closed = closed, .transcript = sequence.transcript
        },
        _userPrivKey
    );
}

SequenceAppendResult GroupApiImpl::appendToSequence(SequenceHandle handle, const core::Buffer& data) {
    const auto sequence = sequenceOf(handle, false);
    std::lock_guard lock(sequence->mutex);
    if (sequence->closed) {
        throw core::InvalidParamsException("field:sequence is finished");
    }
    sequence->requireCurrentEpoch();
    SequenceAppendResult result{
        .item = _envelopeEncryptor.packSequenceItem(sequence->id, sequence->key, sequence->next, data),
        .mark = std::nullopt,
    };
    sequence->transcript = GroupEnvelopeEncryptor::sequenceTranscriptNext(sequence->transcript, result.item);
    sequence->next++;
    if (++sequence->sinceMark >= sequence->checkpointEvery && sequence->checkpointEvery > 0) {
        result.mark = markSequence(*sequence, false);
    }
    return result;
}

core::Buffer GroupApiImpl::checkpointSequence(SequenceHandle handle) {
    const auto sequence = sequenceOf(handle, false);
    std::lock_guard lock(sequence->mutex);
    if (sequence->closed) {
        throw core::InvalidParamsException("field:sequence is finished");
    }
    return markSequence(*sequence, false);
}

core::Buffer GroupApiImpl::finishSequence(SequenceHandle handle) {
    const auto sequence = sequenceOf(handle, false);
    core::Buffer mark;
    {
        std::lock_guard lock(sequence->mutex);
        if (sequence->closed) {
            throw core::InvalidParamsException("field:sequence is finished");
        }
        sequence->closed = true;
        mark = markSequence(*sequence, true);
    }
    closeSequence(handle);
    return mark;
}

SequenceHandle GroupApiImpl::openSequence(
    const std::string& groupId,
    const Path& location,
    const core::Buffer& header,
    const DecryptOptions& options,
    const std::optional<core::Buffer>& resumeFrom
) {
    const DecryptedEnvelope opened = decrypt(groupId, location, header, options, EnvelopeContent::Sequence);
    return openSequenceOver(header, opened.data, opened.author.pubKey, resumeFrom);
}

SequenceHandle GroupApiImpl::openSequenceOver(
    const core::Buffer& header,
    const core::Buffer& key,
    const std::string& authorPubKey,
    const std::optional<core::Buffer>& resumeFrom,
    std::optional<SpaceOrigin> spaceOrigin
) {
    if (key.size() != 32) {
        throw InvalidEnvelopeFormatException("sequence header carries a malformed key");
    }
    auto sequence = std::make_shared<Sequence>();
    sequence->reading = true;
    sequence->key = key.stdString();
    sequence->id = GroupEnvelopeEncryptor::sequenceIdOf(header);
    sequence->transcript = GroupEnvelopeEncryptor::sequenceTranscriptStart(sequence->id);
    sequence->authorPubKey = authorPubKey;
    sequence->spaceOrigin = std::move(spaceOrigin);
    if (resumeFrom.has_value()) {
        const auto wire = GroupEnvelopeEncryptor::parseSequenceWire(resumeFrom.value());
        if (!wire.isMark || wire.sequenceId != sequence->id) {
            throw core::InvalidParamsException("field:resumeFrom is not a checkpoint of this sequence");
        }
        // The author's signature is all a late reader has for what came before; it is enough.
        const auto mark = _envelopeEncryptor.openSequenceMark(wire, sequence->key, sequence->authorPubKey);
        sequence->next = sequence->attested = sequence->inOrder = sequence->segmentStart = mark.count;
        sequence->transcript = mark.transcript;
        sequence->closed = mark.closed;
    }
    return openSequenceHandle("GroupSequence:Read", std::move(sequence));
}

SequenceItem GroupApiImpl::readSequenceItem(SequenceHandle handle, const core::Buffer& item) {
    const auto sequence = sequenceOf(handle, true);
    std::lock_guard lock(sequence->mutex);
    const auto wire = GroupEnvelopeEncryptor::parseSequenceWire(item);
    if (wire.isMark) {
        throw core::InvalidParamsException("field:item is a mark; give it to verifySequenceMark");
    }
    if (wire.sequenceId != sequence->id) {
        throw InvalidEnvelopeFormatException("item of another sequence");
    }
    if (sequence->closed) {
        throw EnvelopeSequenceOrderException("the author closed the sequence before this item");
    }
    if (wire.index < sequence->next) {
        throw EnvelopeSequenceOrderException(
            "item " + std::to_string(wire.index) + " is earlier than, or repeats, one already read"
        );
    }
    // The index is plain and an item is sealed by whoever holds the sequence key, so every member can name any
    // position. One that the arithmetic below cannot hold is nobody's item.
    if (wire.index >= static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max())) {
        throw InvalidEnvelopeFormatException("sequence item at an impossible position");
    }
    SequenceItem result{
        .data = _envelopeEncryptor.openSequenceItem(wire, sequence->key),
        .index = static_cast<int64_t>(wire.index),
        .missing = static_cast<int64_t>(wire.index - sequence->next),
    };
    if (result.missing > 0) {
        sequence->gap = true;
    } else if (!sequence->gap) {
        sequence->transcript = GroupEnvelopeEncryptor::sequenceTranscriptNext(sequence->transcript, item);
    }
    sequence->next = wire.index + 1;
    if (!sequence->gap) {
        sequence->inOrder = sequence->next;
    }
    return result;
}

SequenceMarkInfo GroupApiImpl::verifySequenceMark(SequenceHandle handle, const core::Buffer& markBytes) {
    const auto sequence = sequenceOf(handle, true);
    std::lock_guard lock(sequence->mutex);
    const auto wire = GroupEnvelopeEncryptor::parseSequenceWire(markBytes);
    if (!wire.isMark) {
        throw core::InvalidParamsException("field:mark is an item; give it to readSequenceItem");
    }
    if (wire.sequenceId != sequence->id) {
        throw InvalidEnvelopeFormatException("mark of another sequence");
    }
    const auto mark = _envelopeEncryptor.openSequenceMark(wire, sequence->key, sequence->authorPubKey);
    // After a gap the position is only what an unsigned item claimed - any member can seal one far ahead and
    // have the real items refused as "earlier". The author's mark is signed: it puts the reader back, also behind
    // that claim - but never behind an item that was read in order, or that item could be replayed.
    if (mark.count < sequence->attested || mark.count < (sequence->gap ? sequence->inOrder : sequence->next)) {
        throw EnvelopeSequenceOrderException("mark covers fewer items than were read");
    }
    const bool agrees = !sequence->gap && mark.count == sequence->next && mark.transcript == sequence->transcript;
    // The mark is the author's either way, so reading goes on from it: what follows can be attested again.
    sequence->next = mark.count;
    sequence->transcript = mark.transcript;
    sequence->gap = false;
    sequence->inOrder = mark.count;
    sequence->closed = mark.closed;
    if (!agrees) {
        // SECURITY: what came before this mark is not attested by the next one that agrees: that one proves only
        // the items since this mark.
        sequence->segmentStart = mark.count;
        throw EnvelopeSequenceOrderException(
            "items " +
            std::to_string(sequence->attested) +
            ".." +
            std::to_string(mark.count) +
            " were missing or are not what the author wrote"
        );
    }
    const SequenceMarkInfo info{
        .attestedFrom = static_cast<int64_t>(sequence->segmentStart),
        .attestedItems = static_cast<int64_t>(mark.count),
        .closed = mark.closed,
    };
    sequence->segmentStart = sequence->attested = mark.count;
    return info;
}

SequenceItemHeader GroupApiImpl::peekSequenceItem(const core::Buffer& itemOrMark) {
    const auto wire = GroupEnvelopeEncryptor::parseSequenceWire(itemOrMark);
    return SequenceItemHeader{
        .sequenceId = privmx::utils::Hex::from(wire.sequenceId),
        .index = static_cast<int64_t>(wire.index),
        .isMark = wire.isMark,
    };
}

core::LocalSeal GroupApiImpl::pinSeal() const {
    return core::LocalSeal(_userPrivKey, keytree::PinBlob::LABEL, keytree::PinBlob::VERSION, _pinStoreKey);
}

void GroupApiImpl::loadPins() {
    std::string blob;
    try {
        blob = _pinStore->load(_pinStoreKey).stdString();
    } catch (const std::exception& e) {
        LOG_WARN("[pins] the pin store does not load: ", e.what())
        return;
    } catch (...) {
        LOG_WARN("[pins] the pin store does not load")
        return;
    }
    if (blob.empty()) {
        return;
    }
    const auto body = pinSeal().open(blob);
    const auto stored = body.has_value() ? keytree::PinBlob::decode(body.value()) : std::nullopt;
    if (!stored.has_value()) {
        // The same as a deleted blob: first contact for what it held (it is overwritten by the next save).
        LOG_WARN("[pins] the stored pins fail their integrity check; ignored")
        return;
    }
    _treeVerifier.mergeStored(stored->tree);
    _groupDataSchemaMapper->importVersionPins(stored->planes);
}

void GroupApiImpl::pinsMoved(bool major) {
    if (!_pinStore) {
        return;
    }
    std::unique_lock<std::mutex> lock(_pinsMovedMutex);
    _pinsMoved = true;
    _pinsMovedMajor = _pinsMovedMajor || major;
}

bool GroupApiImpl::savePins(bool all) {
    if (!_pinStore) {
        return true;
    }
    bool saved = false;
    {
        std::lock_guard<std::mutex> lock(_pinSaveMutex);
        {
            // Before the export: a move after it marks the pins again.
            std::unique_lock<std::mutex> movedLock(_pinsMovedMutex);
            _pinsMoved = _pinsMovedMajor = false;
        }
        keytree::TreeVerifier::PinSet mine;
        mine.tree = _treeVerifier.exportPins(all || _pinSaveFull);
        mine.planes = _groupDataSchemaMapper->exportVersionPins();
        std::optional<keytree::TreeVerifier::PinSet> stored;
        try {
            saved = pinSeal().update(*_pinStore, [&](const std::optional<std::string>& body) {
                stored = body.has_value() ? keytree::PinBlob::decode(body.value()) : std::nullopt;
                if (stored.has_value()) {
                    return keytree::PinBlob::encode(keytree::PinBlob::mergeForSave(mine, stored.value()));
                }
                // Nothing stored, another version or a bad tag: overwritten with every pin in full.
                if (body.has_value()) {
                    LOG_WARN("[pins] the stored pins do not parse; overwritten")
                }
                return keytree::PinBlob::encode(
                    all || _pinSaveFull ? mine :
                                          keytree::TreeVerifier::PinSet{_treeVerifier.exportPins(true), mine.planes}
                );
            });
        } catch (const std::exception& e) { LOG_WARN("[pins] the pin store does not save: ", e.what()) } catch (...) {
            LOG_WARN("[pins] the pin store does not save")
        }
        if (saved) {
            // What another instance of this device saved meanwhile comes in too (`PinBlob::higher`).
            if (stored.has_value()) {
                _treeVerifier.mergeStored(stored->tree);
                _groupDataSchemaMapper->importVersionPins(stored->planes);
            }
            _pinSaveFull = false;
        } else {
            // Not fail-closed: the pins in memory still protect this instance; the slot is retried in full.
            _pinSaveFull = true;
        }
    }
    std::unique_lock<std::mutex> lock(_pinsMovedMutex);
    // A failure is retried as a minor move: once PIN_SAVE_IDLE_INTERVAL has passed, or at the next major move, own
    // commit, disconnect or destruction; not at every verification against a store that keeps refusing.
    _lastPinSave = std::chrono::steady_clock::now();
    _pinsMoved = _pinsMoved || !saved;
    return saved;
}

void GroupApiImpl::adoptPreviousIdentity(const privmx::crypto::PrivateKey& previous) {
    const std::string previousPub = previous.getPublicKey().toBase58DER();
    {
        std::lock_guard<std::mutex> lock(_pinSaveMutex);
        if (_adoptedIdentities.count(previousPub) > 0) {
            return;
        }
    }
    // The connection records the key (for `climbsWithPreviousIdentity`) and stages what its slot holds; it throws
    // when the slot does not open. The current key, or no store: nothing staged, nothing to adopt.
    const auto connectionImpl = _connection.getImpl();
    connectionImpl->adoptPreviousIdentity(previous);
    if (!_pinStore || previousPub == _userPrivKey.getPublicKey().toBase58DER()) {
        return;
    }
    const auto staged = connectionImpl->getStagedPinBodies();
    if (const auto it = staged.find(previousPub); it != staged.end()) {
        const auto adopted = keytree::PinBlob::decode(it->second);
        if (!adopted.has_value()) {
            // Never ignored: corrupting the slot must not be a way to turn adoption off.
            throw core::LocalStateIntegrityException("the previous identity's group pins do not open");
        }
        adoptBody(adopted.value());
    }
    std::lock_guard<std::mutex> lock(_pinSaveMutex);
    _adoptedIdentities.insert(previousPub);
}

void GroupApiImpl::adoptBody(const keytree::TreeVerifier::PinSet& adopted) {
    // Only for groups with no pin under the current key, and only as hints: whoever holds the previous key can write
    // its slot, so its records never replace or raise a pin, and are saved only once a read has verified them. Its
    // version pins are not taken at all: raised by such a record, they would refuse honest answers as rollbacks.
    _treeVerifier.mergeStored(adopted.tree, true);
}
