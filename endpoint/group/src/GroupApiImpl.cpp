#include <algorithm>

#include <privmx/crypto/Crypto.hpp>
#include <privmx/crypto/ecc/PrivateKey.hpp>
#include <privmx/endpoint/core/CoreException.hpp>
#include <privmx/endpoint/core/LocalSeal.hpp>
#include <privmx/utils/JsonHelper.hpp>
#include <privmx/utils/Utils.hpp>

#include <privmx/endpoint/core/CoreConstants.hpp>
#include <privmx/endpoint/core/EndpointUtils.hpp>
#include <privmx/endpoint/core/EventMiddleware.hpp>
#include <privmx/endpoint/core/ExceptionConverter.hpp>
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
        _pinStoreKey = connectionImpl->localStateSlot(core::localstate::GROUP_PINS, userPrivKey.getPublicKey());
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
    const std::optional<core::ContainerPolicy>& policies
) {
    return _ops.create(contextId, users, managers, publicMeta, privateMeta, policies);
}

void GroupApiImpl::addGroupMembers(const std::string& groupId, const std::vector<GroupMemberToAdd>& newMembers) {
    // The op-effect table's add row names each newcomer once: refused here, before anything is read or signed.
    std::set<std::string> named;
    for (const GroupMemberToAdd& newMember : newMembers) {
        if (!named.insert(newMember.user.userId).second) {
            throw core::InvalidParamsException("user '" + newMember.user.userId + "' is listed twice");
        }
    }
    commitWithRetry([&] { _ops.add(groupId, newMembers); });
    runDueWork(groupId);
}

void GroupApiImpl::removeGroupMembers(const std::string& groupId, const std::vector<std::string>& userIds) {
    // A narrowing's carry still to do runs first: after the removal its plane would be judged under the new rules.
    _metadata.retryPendingCarry(groupId);
    std::optional<bool> historyAbandoned;
    PriorRole prior;
    commitWithRetry([&] { historyAbandoned = _ops.remove(groupId, userIds, prior); });
    // The removal is committed; the metadata entry is now one epoch behind, under a key the departed member
    // still holds. Move it up. Outside the write above on purpose — see the header. Already done when an earlier
    // call's removal turned out to have landed (`settle`).
    if (historyAbandoned.has_value()) {
        _metadata.carryMetadataForward(groupId, CarryScope::NewEpoch, historyAbandoned.value(), userIds, prior);
    }
    runDueWork(groupId);
}

void GroupApiImpl::rotateGroupKey(const std::string& groupId) {
    _metadata.retryPendingCarry(groupId);
    bool committedHere = true;
    PriorRole prior;
    commitWithRetry([&] { committedHere = _ops.rotate(groupId, prior); });
    // As after a removal: the metadata planes sit one epoch behind, under the key the rotation replaces. Nobody left,
    // so nobody is accepted as an author beyond the members. Already done when an earlier call's rotation turned out
    // to have landed (`settle`).
    if (committedHere) {
        _metadata.carryMetadataForward(groupId, CarryScope::NewEpoch, false, {}, prior);
    }
    runDueWork(groupId);
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
    } catch (const std::exception& e) {
        LOG_WARN("[pins] save dropped: ", e.what())
    } catch (...) { LOG_WARN("[pins] save dropped") }
}

void GroupApiImpl::selfUpdate(const std::string& groupId) {
    _ops.selfUpdate(groupId, nullptr, SELF_UPDATE_OP, false);
}

bool GroupApiImpl::renewLeaf(const std::string& groupId, const std::string& previousUserPrivKey) {
    std::optional<privmx::crypto::PrivateKey> previous;
    try {
        previous = privmx::crypto::PrivateKey::fromWIF(previousUserPrivKey);
    } catch (...) {
        throw core::InvalidParamsException("the previous key is not a private key in WIF");
    }
    if (previous->getPublicKey() == _userPrivKey.getPublicKey()) {
        throw core::InvalidParamsException("the previous key is the current key");
    }
    // The previous key's pins first, so the read the renewal plans on continues them (the app is meant to have
    // done this at connect with Connection::adoptPreviousIdentity; a second adoption is a no-op).
    adoptPreviousIdentity(previous.value());
    bool renewed = false;
    commitWithRetry([&] { renewed = _ops.selfUpdate(groupId, &previous.value(), RENEW_LEAF_OP, true); });
    runDueWork(groupId);
    return renewed;
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

void GroupApiImpl::updateGroupPolicy(const std::string& groupId, const core::ContainerPolicy& policies) {
    _metadata.retryPendingCarry(groupId);
    std::optional<PendingCarry> carry;
    commitWithRetry([&] {
        carry.reset();
        _ops.updatePolicy(groupId, policies, carry);
    });
    // A plane whose author lost `update` is refused from now on; carry it under the caller's name.
    if (carry.has_value()) {
        _metadata.runPolicyCarry(groupId, carry.value());
    }
    runDueWork(groupId);
}

void GroupApiImpl::deleteGroup(const std::string& groupId) {
    server::GroupDeleteModel model{.groupId = groupId};
    _serverApi.groupDelete(model);
    _sessions.forget(groupId);
    invalidateModuleKeysInCache(groupId);
}

Group GroupApiImpl::getGroup(const std::string& groupId) {
    _metadata.retryPendingCarry(groupId);
    const server::GroupGetModel params = pathRead(groupId);
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
        _treeVerifier.verifyListed(group, treeEnvironment(_serverApi, _connection, group.id));
    } catch (const std::exception& e) {
        LOG_WARN("[hasVerifiedGrantKey] group ", group.id, " failed verification: ", e.what())
        return false;
    }
    return group.treeCommit->seq >= static_cast<std::int64_t>(_treeVerifier.pinnedSeq(group.id));
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
                read.push_back(_serverApi.groupGet(pathRead(summary.id)).group);
            } catch (const std::exception& e) {
                LOG_WARN("[fetchGroupEpochs] group ", summary.id, " unreadable: ", e.what())
            }
        }
        _treeVerifier.preverifyListed(read, treeEnvironment(_serverApi, _connection, std::string()));
        for (const auto& group : read) {
            // A group that fails verification gets no key at all, never the unverified one.
            if (group.contextId != contextId) {
                continue;
            }
            try {
                _treeVerifier.verifyListed(group, treeEnvironment(_serverApi, _connection, group.id));
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
        const std::vector<std::string> behind = take(std::vector<std::string>(
            groupIds.begin() + offset, groupIds.begin() + std::min(offset + BRIDGE_MAX_BATCH_SIZE, groupIds.size())
        ));
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
                if (routing.type != ENVELOPE_FROM_MEMBER || routing.groupId != raw.id ||
                    routing.keyId != keys.currentKeyId) {
                    throw InvalidEnvelopeFormatException("a custom event must be sealed by a member under the current key");
                }
                auto decrypted = decrypt(envelope);
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
            } catch (const core::Exception& e) {
                data.statusCode = e.getCode();
            } catch (const privmx::utils::PrivmxException& e) {
                data.statusCode = core::ExceptionConverter::convert(e).getCode();
            } catch (...) { data.statusCode = ENDPOINT_CORE_EXCEPTION_CODE; }
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
            invalidateModuleKeysInCache(raw.groupId);
            auto data = Mapper::mapToGroupChangedEventData(raw);
            auto event = core::EventBuilder::buildEvent<GroupUpdatedEvent>("context", data, notification);
            _eventMiddleware->emitApiEvent(event);
        } else if (type == "groupDeleted") {
            auto raw = server::GroupDeletedEventData::fromJSON(notification.data);
            // Key caches only. The pins stay as tombstones: the event is the bridge's word alone, and dropping them
            // would make the next read of the group a first contact the bridge could answer with any old state.
            _sessions.forget(raw.groupId);
            invalidateModuleKeysInCache(raw.groupId);
            auto data = Mapper::mapToGroupDeletedEventData(raw);
            auto event = core::EventBuilder::buildEvent<GroupDeletedEvent>("context", data, notification);
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
    invalidateModuleKeysInCache();
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
    invalidateModuleKeysInCache();
}

std::pair<core::ModuleKeys, int64_t> GroupApiImpl::getModuleKeysAndVersionFromServer(std::string moduleId) {
    const VerifiedGroup group = readGroupForKeys(moduleId);
    // Roster version: key material moves with that plane, so a metadata-only write must not stale the cache.
    return std::make_pair(groupToModuleKeys(group), group->rosterVersion);
}

VerifiedGroup GroupApiImpl::readGroupForKeys(const std::string& groupId) {
    // On return, after the roster attestation below has moved the version pins too, not only the tree's.
    const SaveDuePins saveAfter{*this};
    // The tree pins `keyVersion` (never below what this client verified or committed itself); the head entry's
    // grant must be at exactly that epoch; the roster attestation binds the head to it and moves the version pins.
    GroupRead read = _hooks.read(pathRead(groupId), keytree::TreeVerifier::Scope::Path);
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
                return readGroup(_serverApi, _treeVerifier, _connection, model, scope, [this] { savePinsIfDue(); });
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
        .invalidateModuleKeys = [this](const std::string& groupId) { invalidateModuleKeysInCache(groupId); },
    };
}

// -- envelopes -------------------------------------------------------------------------------------------

core::DecryptedEncKeyV2 GroupApiImpl::encKeyById(const std::string& groupId, const std::string& keyId) {
    return _keys.encKeyById(
        groupId, keyId,
        [&](bool fresh) { return fresh ? getNewModuleKeysAndUpdateCache(groupId) : getModuleKeys(groupId); },
        *_keyProvider, _groupPrivKeyResolver
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

Envelope GroupApiImpl::encrypt(const std::string& groupId, const core::Buffer& content) {
    auto key = currentEncKey(groupId);
    return _envelopeEncryptor.packGroupKeyEnvelope(groupId, key.id, content, _userPrivKey, key.key);
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
    model.data = privmx::utils::Base64::from(
        encrypt(groupId, core::Buffer::from(SubscriberImpl::sealOnChannel(channelName, eventData.stdString())))
            .stdString()
    );
    if (!users.empty()) {
        model.users = users;
    }
    _serverApi.groupSendCustomEvent(model);
}

DecryptedEnvelope GroupApiImpl::decrypt(const Envelope& envelope) {
    auto routing = _envelopeEncryptor.peek(envelope);
    // The group id comes off an envelope we have not authenticated yet. Validating it here keeps a hostile one
    // from steering us into a `groupGet` and a tree climb against an id of its choosing.
    core::Validator::validateId(routing.groupId, "field:envelope.groupId ");
    if (routing.type == ENVELOPE_FROM_MEMBER) {
        return _envelopeEncryptor.openGroupKeyEnvelope(envelope, encKeyById(routing.groupId, routing.keyId).key);
    }

    return _envelopeEncryptor.openAnonymousEnvelope(
        envelope, _keys.grantKeyForPubKey(routing.groupId, routing.groupPubKey)
    );
}

Envelope GroupApiImpl::encryptAnonymously(
    const std::string& groupId,
    const std::string& groupPubKey,
    const core::Buffer& content
) {
    // Public information only — no membership, no server call. That is the whole point: the sender is outside
    // the group and must stay able to write into it knowing nothing but its id and its identity key.
    return _envelopeEncryptor.packAnonymousEnvelope(
        groupId, privmx::crypto::PublicKey::fromBase58DER(groupPubKey), content
    );
}

// -- envelope files --------------------------------------------------------------------------------------

FileHandle GroupApiImpl::beginFileEncryption(const std::string& groupId, FileSize size) {
    auto key = currentEncKey(groupId);
    return _envelopeFiles.open(
        "GroupEnvelope:Encrypt",
        EnvelopeFileState{
            .reading = false,
            .type = ENVELOPE_FROM_MEMBER,
            .groupId = groupId,
            .keyId = key.id,
            .groupKey = key.key,
            // Per file, so a chunk lifted from one file is useless in any other.
            .fileKey = privmx::crypto::Crypto::randomBytes(32),
            .index = 0,
            .plainSize = static_cast<ByteCount>(size),
        }
    );
}

FileHandle GroupApiImpl::beginFileEncryptionAnonymously(
    const std::string& groupId,
    const std::string& groupPubKey,
    FileSize size
) {
    // No server call and no membership, exactly like `encryptAnonymously`. The public key is enough to seal
    // to, and the envelope is not built until the finish, so nothing here needs the group's own key.
    privmx::crypto::PublicKey::fromBase58DER(groupPubKey); // reject a malformed key now, not at the finish
    return _envelopeFiles.open(
        "GroupEnvelope:EncryptAnonymous",
        EnvelopeFileState{
            .reading = false,
            .type = ENVELOPE_ANONYMOUS,
            .groupId = groupId,
            .groupPubKey = groupPubKey,
            .fileKey = privmx::crypto::Crypto::randomBytes(32),
            .index = 0,
            .plainSize = static_cast<ByteCount>(size),
        }
    );
}

core::Buffer GroupApiImpl::encryptFileChunk(FileHandle fileHandle, const core::Buffer& plainChunk) {
    return _envelopeFiles.encryptChunk(fileHandle, plainChunk);
}

FileHandle GroupApiImpl::beginFileDecryption(const Envelope& envelope) {
    auto routing = _envelopeEncryptor.peekFile(envelope);
    core::Validator::validateId(routing.groupId, "field:envelope.groupId ");

    // Both kinds open into the same reader: only the header is wrapped differently, the body is not.
    EnvelopeFileHeader header;
    std::string groupKey;
    if (routing.type == ENVELOPE_FROM_MEMBER) {
        groupKey = encKeyById(routing.groupId, routing.keyId).key;
        header = _envelopeEncryptor.unpackFileEnvelope(envelope, groupKey);
    } else {
        header = _envelopeEncryptor.unpackAnonymousFileEnvelope(
            envelope, _keys.grantKeyForPubKey(routing.groupId, routing.groupPubKey)
        );
    }

    return _envelopeFiles.open(
        "GroupEnvelope:Decrypt",
        EnvelopeFileState{
            .reading = true,
            .type = header.type,
            .groupId = header.groupId,
            .keyId = header.keyId,
            .groupKey = groupKey,
            .groupPubKey = routing.groupPubKey,
            .authorPubKey = header.authorPubKey,
            .fileKey = header.fileKey,
            .index = 0,
            .plainSize = header.plainSize,
        }
    );
}

core::Buffer GroupApiImpl::decryptFileChunk(FileHandle fileHandle, const core::Buffer& cipherChunk) {
    return _envelopeFiles.decryptChunk(fileHandle, cipherChunk);
}

CipherOffset GroupApiImpl::seekInEncryptedFile(FileHandle fileHandle, FilePosition position) {
    return _envelopeFiles.seek(fileHandle, position);
}

Envelope GroupApiImpl::finishFileEncryption(FileHandle fileHandle) {
    auto state = _envelopeFiles.finish(fileHandle, false);
    if (state.type == ENVELOPE_ANONYMOUS) {
        return _envelopeEncryptor.packAnonymousFileEnvelope(
            state.groupId, privmx::crypto::PublicKey::fromBase58DER(state.groupPubKey), state.plainSize,
            state.fileKey
        );
    }
    return _envelopeEncryptor.packFileEnvelope(
        state.groupId, state.keyId, state.plainSize, state.fileKey, _userPrivKey, state.groupKey
    );
}

DecryptedFileInfo GroupApiImpl::finishFileDecryption(FileHandle fileHandle) {
    auto state = _envelopeFiles.finish(fileHandle, true);
    return DecryptedFileInfo{
        .groupId = state.groupId,
        .authorPubKey = state.authorPubKey,
        .type = state.type,
        .complete = !state.seeked,
    };
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
    const auto body =
        core::openLocal(_userPrivKey, keytree::PinBlob::LABEL, keytree::PinBlob::VERSION, _pinStoreKey, blob);
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
            saved = core::updateSealed(
                *_pinStore, _userPrivKey, _pinStoreKey, keytree::PinBlob::LABEL, keytree::PinBlob::VERSION,
                [&](const std::optional<std::string>& body) {
                    stored = body.has_value() ? keytree::PinBlob::decode(body.value()) : std::nullopt;
                    if (stored.has_value()) {
                        return keytree::PinBlob::encode(keytree::PinBlob::mergeForSave(mine, stored.value()));
                    }
                    // Nothing stored, another version or a bad tag: overwritten with every pin in full.
                    if (body.has_value()) {
                        LOG_WARN("[pins] the stored pins do not parse; overwritten")
                    }
                    return keytree::PinBlob::encode(
                        all || _pinSaveFull ? mine
                                            : keytree::TreeVerifier::PinSet{_treeVerifier.exportPins(true), mine.planes}
                    );
                }
            );
        } catch (const std::exception& e) {
            LOG_WARN("[pins] the pin store does not save: ", e.what())
        } catch (...) { LOG_WARN("[pins] the pin store does not save") }
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
