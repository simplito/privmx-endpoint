#include <algorithm>
#include <random>

#include <privmx/crypto/Crypto.hpp>
#include <privmx/crypto/ecc/PrivateKey.hpp>
#include <privmx/endpoint/core/CoreException.hpp>
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
#include "privmx/endpoint/group/keytree/LadderKeys.hpp"
#include "privmx/endpoint/group/keytree/TreeCommits.hpp"
#include "privmx/endpoint/group/keytree/TreeMath.hpp"
#include "privmx/endpoint/group/keytree/TreeWire.hpp"
#include "privmx/utils/Logger.hpp"
#include <privmx/endpoint/core/ConvertedExceptions.hpp>

using namespace privmx::endpoint;
using namespace group;

namespace {

// `groupGet` in the default "path" scope, with nothing for anybody else.
group::server::GroupGetModel pathRead(const std::string& groupId) {
    return group::server::GroupGetModel{
        .groupId = groupId, .type = {}, .scope = {}, .forUserIds = {}, .forNewMembers = {}, .fromRosterVersion = {}
    };
}

} // namespace

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
    initGroupPrivKeyResolver(resolverOver(nullptr));
    initModuleDataSchemaMapper(_groupDataSchemaMapper);
    _pinnedGroupEpoch = [this](const std::string& groupId) { return pinnedKeyVersion(groupId); };
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
    {
        std::unique_lock<std::mutex> lock(_selfUpdateMutex);
        _selfUpdateStopping = true;
        _selfUpdatePending.clear();
    }
    _selfUpdateWake.notify_all();
    if (_selfUpdateWorker.joinable()) {
        _selfUpdateWorker.join();
    }
    _eventMiddleware->removeNotificationEventListener(_notificationListenerId);
    _eventMiddleware->removeConnectedEventListener(_connectedListenerId);
    _eventMiddleware->removeDisconnectedEventListener(_disconnectedListenerId);
    _guardedExecutor.reset();
}

static void rejectConflictingRosterKey(const std::string& userId) {
    throw core::InvalidParamsException("user '" + userId + "' is listed with two different public keys");
}

dynamic::MembershipBlock GroupApiImpl::buildMembershipBlock(
    const core::EncKey& key,
    const std::string& groupPubKey,
    int64_t keyVersion,
    int64_t rosterVersion,
    const std::vector<core::UserWithPubKey>& users,
    const std::vector<core::UserWithPubKey>& managers
) {
    return dynamic::MembershipBlock{
        .rosterTag = GroupDataSchemaMapper::rosterTag(
            key.key, keyVersion, rosterVersion, core::EndpointUtils::usersWithPubKeyToIds(users),
            core::EndpointUtils::usersWithPubKeyToIds(managers)
        ),
        .groupPubKey = groupPubKey,
        .keyId = key.id,
        .keyVersion = keyVersion,
        .rosterVersion = rosterVersion
    };
}

std::vector<keytree::TreeMember> GroupApiImpl::toTreeMembers(
    const std::vector<core::UserWithPubKey>& users,
    const std::vector<core::UserWithPubKey>& managers
) {
    std::vector<keytree::TreeMember> members;
    std::map<std::string, std::string> seen; // user id -> the key that took their leaf

    std::vector<core::UserWithPubKey> all;
    all.insert(all.end(), users.begin(), users.end());
    all.insert(all.end(), managers.begin(), managers.end());
    std::sort(all.begin(), all.end(), [](const core::UserWithPubKey& a, const core::UserWithPubKey& b) {
        return a.userId < b.userId;
    });
    for (const core::UserWithPubKey& user : all) {
        const auto inserted = seen.emplace(user.userId, user.pubKey);
        if (!inserted.second) {
            if (inserted.first->second != user.pubKey) {
                rejectConflictingRosterKey(user.userId);
            }
            continue; // a manager listed as a user too gets one leaf, not two
        }
        members.push_back(keytree::TreeMember{user.userId, privmx::crypto::PublicKey::fromBase58DER(user.pubKey)});
    }
    return members;
}

// The attested roster, as bare ids — the update preparation diffs names, it does not wrap to them.
RosterAfterChange GroupApiImpl::rosterFromUserIds(
    const std::vector<std::string>& users,
    const std::vector<std::string>& managers
) {
    RosterAfterChange roster;
    for (const std::string& userId : users) {
        roster.users.push_back(core::UserWithPubKey{.userId = userId, .pubKey = std::string()});
    }
    for (const std::string& managerId : managers) {
        roster.managers.push_back(core::UserWithPubKey{.userId = managerId, .pubKey = std::string()});
    }
    return roster;
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
    std::map<std::string, std::string> keys;
    for (const core::UserWithPubKey& user : resolved.users) {
        keys.emplace(user.userId, user.pubKey);
    }
    return keys;
}

std::map<std::string, std::string> GroupApiImpl::commitRecipientKeys(
    const server::GroupInfo& group,
    const std::vector<std::string>& recipients,
    const std::string& ownUserId,
    const std::set<std::string>& newcomers
) {
    std::vector<std::string> toResolve;
    for (const std::string& userId : recipients) {
        if (userId != ownUserId && newcomers.count(userId) == 0) {
            toResolve.push_back(userId);
        }
    }
    std::map<std::string, std::string> keys = resolveMemberKeys(group.contextId, toResolve);
    keys[ownUserId] = _userPrivKey.getPublicKey().toBase58DER();
    return keys;
}

// The keytree module reports impossible requests as `std::invalid_argument`, having no dependency on the endpoint's
// exception hierarchy. Letting one escape the SDK boundary would `std::terminate` a caller catching core::Exception.
template<typename TPlan>
static TPlan planOrThrow(const std::function<TPlan()>& build) {
    try {
        return build();
    } catch (const std::invalid_argument& e) {
        throw core::EncryptionKeyValidationException(std::string("key tree operation is not possible: ") + e.what());
    }
}

keytree::TreeGroupState GroupApiImpl::climbForPlanning(
    const server::GroupInfo& group,
    const std::shared_ptr<keytree::TreeKeyCache>& cache,
    bool tolerateBrokenClimb
) {
    if (!keytree::GroupKeyResolver::hasTree(group)) {
        throw core::EncryptionKeyValidationException("this group is not backed by a key tree");
    }
    if (!keytree::GroupKeyResolver::hasSupportedTree(group)) {
        keytree::ResolveResult asResolve;
        asResolve.failure = keytree::ResolveFailure::UnsupportedTreeVersion;
        throw core::EncryptionKeyValidationException(describeResolveFailure(asResolve));
    }
    const auto identity = keytree::GroupKeyResolver::ownUserId(group);
    if (!identity.has_value()) {
        throw core::EncryptionKeyValidationException("caller holds no leaf in this group's key tree");
    }
    const keytree::TreeGroupState state = keytree::GroupKeyResolver::toTreeState(group);
    keytree::TreeKeys tree(*cache);
    // Walk even when the grant key is already cached: a plan needs the node keys along the path, and the cache
    // would otherwise satisfy the request without ever recovering them.
    const keytree::ClimbResult climb = tree.climbToGrantKey(state, identity.value(), _userPrivKey, false);
    if (climb.failure != keytree::ClimbFailure::None || !climb.grantKey.has_value()) {
        keytree::ResolveResult asResolve;
        asResolve.failure = keytree::ResolveFailure::ClimbFailed;
        asResolve.climb = climb.failure;
        if (climb.failure == keytree::ClimbFailure::Tampered || climb.failure == keytree::ClimbFailure::DecryptFailed) {
            asResolve.blame = keytree::GroupKeyResolver::tamperedBy(group, climb.tamperedNode);
        }
        // Garbled wraps must not let whoever garbled them block their own removal: the state is verified, and a
        // removal wraps only fresh keys to public ones.
        if (tolerateBrokenClimb && climb.failure != keytree::ClimbFailure::NotAMember) {
            LOG_WARN("[climbForPlanning] planning without the climb: ", describeResolveFailure(asResolve))
            return state;
        }
        throw core::EncryptionKeyValidationException(describeResolveFailure(asResolve));
    }
    scheduleSelfUpdateIfNeeded(group.id, group);
    return state;
}

std::string GroupApiImpl::createGroup(
    const std::string& contextId,
    const std::vector<core::UserWithPubKey>& users,
    const std::vector<core::UserWithPubKey>& managers,
    const core::Buffer& publicMeta,
    const core::Buffer& privateMeta,
    const std::optional<core::ContainerPolicy>& policies
) {
    // The creator commits from a seat of its own, like any committer. Checked by
    // key first, which needs no request; the id the seat is planned under is checked again once it is known.
    const std::vector<keytree::TreeMember> members = toTreeMembers(users, managers);
    const privmx::crypto::PublicKey ownKey = _userPrivKey.getPublicKey();
    if (std::none_of(members.begin(), members.end(), [&](const keytree::TreeMember& m) {
            return m.publicKey == ownKey;
        })) {
        throw core::InvalidParamsException("the creator of a group must be one of its users or managers");
    }

    // Empty rosters: the metadata key is wrapped once to the group's own grant key, and members open it by climbing.
    auto ctx = prepareContainerCreate(contextId, {}, {});
    const std::string creatorId = ctx.dio.creatorUserId;
    if (std::none_of(members.begin(), members.end(), [&](const keytree::TreeMember& m) {
            return m.userId == creatorId && m.publicKey == ownKey;
        })) {
        throw core::InvalidParamsException("the creator of a group must be one of its users or managers");
    }
    // Each seat is filled to the key given for it, and those keys are as good as the listing they came from.
    assertUserKeysVerified(contextId, core::EndpointUtils::uniqueListUserWithPubKey(users, managers));
    keytree::TreeKeyCache scratch; // the group has no id yet
    keytree::TreeKeys builder(scratch);
    const keytree::CommitPlan plan = planOrThrow<keytree::CommitPlan>([&] {
        return builder.planCreate(members, creatorId, _userPrivKey);
    });
    const std::string groupPubKeyStr = plan.grantKey.getPublicKey().toBase58DER();

    // All three planes start at 1 under the same epoch-1 content key, with `internalMeta` on the roster only.
    // The three DIOs must not share a `randomId`, or a replay check sees them as one entry served three times.
    const core::ModuleInternalMetaV5 internalMeta{
        .secret = ctx.secret, .resourceId = ctx.resourceId, .randomId = ctx.dio.randomId
    };
    core::DataIntegrityObject publicMetaDio = ctx.dio;
    publicMetaDio.randomId = core::EndpointUtils::generateDIORandomId();
    core::DataIntegrityObject privateMetaDio = ctx.dio;
    privateMetaDio.randomId = core::EndpointUtils::generateDIORandomId();
    GroupRosterToEncryptV5 rosterToEncrypt{
        .internalMeta = internalMeta,
        .dio = ctx.dio,
        .membership = buildMembershipBlock(ctx.key, groupPubKeyStr, 1, 1, users, managers)
    };
    GroupPublicMetaToEncryptV5 publicMetaToEncrypt{
        .publicMeta = publicMeta,
        .dio = publicMetaDio,
        .meta = dynamic::MetaBlock{
            .metaTag = GroupDataSchemaMapper::publicMetaTag(ctx.key.key, 1, 1),
            .keyId = ctx.key.id,
            .keyVersion = 1,
            .metaVersion = 1
        }
    };
    GroupPrivateMetaToEncryptV5 privateMetaToEncrypt{
        .privateMeta = privateMeta,
        .dio = privateMetaDio,
        .meta = dynamic::MetaBlock{
            .metaTag = GroupDataSchemaMapper::privateMetaTag(ctx.key.key, 1, 1),
            .keyId = ctx.key.id,
            .keyVersion = 1,
            .metaVersion = 1
        }
    };

    server::GroupCreateModel model;
    model.resourceId = ctx.resourceId;
    model.contextId = contextId;
    model.keyId = ctx.key.id;
    model.data = _groupDataSchemaMapper->encryptRoster(rosterToEncrypt, ctx.key.key);
    model.publicMeta = _groupDataSchemaMapper->encryptPublicMeta(publicMetaToEncrypt);
    model.privateMeta = _groupDataSchemaMapper->encryptPrivateMeta(privateMetaToEncrypt, ctx.key.key);
    model.users = core::EndpointUtils::usersWithPubKeyToIds(users);
    model.managers = core::EndpointUtils::usersWithPubKeyToIds(managers);
    model.groupPubKey = groupPubKeyStr;
    model.type = GROUP_TYPE_FILTER_FLAG;
    const auto selfAddressed = buildGroupKeyEntries(
        {core::GroupGrantWithKey{
            .groupId = std::string(),
            .role = "manager",
            .groupPubKey = groupPubKeyStr,
            .groupEpoch = 1,
        }},
        ctx.key, ctx.dio, contextId, ctx.resourceId, ctx.secret
    );
    model.groupKeys = server::GroupKeyEntrySetForNewGroup{
        .keyId = selfAddressed.at(0).keyId, .groupEpoch = 1, .data = selfAddressed.at(0).data
    };
    model.tree = keytree::TreeWire::toCreateTree(plan);
    // The group has no id until the bridge stores it, so the first statement names the resourceId instead.
    keytree::CommitStatement statement = keytree::TreeCommits::statementFor(
        plan, keytree::CommitOp::Create, ctx.resourceId, commitDate(), 1, groupPubKeyStr, 1,
        core::EndpointUtils::usersWithPubKeyToIds(users), core::EndpointUtils::usersWithPubKeyToIds(managers),
        creatorId, {}, {}, {} // the genesis roster is bound by rosterHash; the bridge serves it beside the chain (I-1)
    );
    keytree::TreeCommits::sign(statement, _userPrivKey);
    model.commit = keytree::TreeCommits::toWire(statement);
    if (policies.has_value()) {
        model.policy = core::Factory::createPolicyServerObject(policies.value());
    }

    auto result = _serverApi.groupCreate(model);
    // The bridge derives the id from the signed resourceId; any other id is not the group this statement created.
    if (result.groupId != keytree::TreeCommits::groupId(contextId, ctx.resourceId)) {
        throw GroupDataIntegrityException("the new group's id does not follow from its resourceId");
    }
    _treeVerifier.pinCommitted(
        result.groupId, contextId, statement, core::EndpointUtils::usersWithPubKeyToIds(users),
        core::EndpointUtils::usersWithPubKeyToIds(managers)
    );
    const auto cache = _treeKeyCaches.get(result.groupId);
    cache->putGrantKey(1, plan.grantKey);
    return result.groupId;
}

void GroupApiImpl::addGroupMembers(const std::string& groupId, const std::vector<GroupMemberToAdd>& newMembers) {
    commitWithRetry([&] { addGroupMembersOnce(groupId, newMembers); });
}

void GroupApiImpl::addGroupMembersOnce(const std::string& groupId, const std::vector<GroupMemberToAdd>& newMembers) {
    // One read, not two: the bridge holds the roster, so it allocates the seats and serves every node record the
    // plan resolves through in the same answer.
    server::GroupGetModel getModel{
        .groupId = groupId,
        .type = {},
        .scope = std::string("plan"),
        .forUserIds = {},
        .forNewMembers = static_cast<std::int64_t>(newMembers.size()),
        .fromRosterVersion = {}
    };
    auto currentGroup = _serverApi.groupGet(getModel).group;
    // Every record a plan reads and every node it wraps to, checked against the statements members signed.
    verifyTree(currentGroup, getModel, keytree::TreeVerifier::Scope::Plan);
    const auto& currentEntry = currentGroup.data.back();
    const auto resourceId = currentGroup.resourceId.value_or(core::EndpointUtils::generateId());
    const int64_t currentEpoch = currentGroup.keyVersion;
    // The bridge pins this in its compare-and-swap, so the entry lands here or the call is refused — which is
    // what lets the tag below commit to it.
    const int64_t newRosterVersion = currentGroup.rosterVersion + 1;

    // The roster this call signs has to be the one the head attests to, not one the caller restated or the bridge
    // asserted. Roster plane only — seating a member is not a metadata edit, so it does not open that entry.
    const auto [attestedUsers, attestedManagers] = _groupDataSchemaMapper->validateAndGetAttestedRoster(
        currentGroup, _keyProvider, _groupPrivKeyResolver
    );
    keytree::TreeVerifier::assertSeatsMatchRoster(currentGroup, attestedUsers, attestedManagers);

    const auto& allocated = currentGroup.nextFreeSeats;
    if (!allocated.has_value() || allocated.value().size() != newMembers.size()) {
        throw core::Exception("bridge did not allocate a seat for every newcomer");
    }
    std::vector<std::uint32_t> positions;
    for (const std::int64_t seat : allocated.value()) {
        positions.push_back(static_cast<std::uint32_t>(seat));
    }

    // Handle for the whole operation
    const auto cache = _treeKeyCaches.get(groupId);
    const keytree::TreeGroupState state = climbForPlanning(currentGroup, cache);
    const std::string adderId = keytree::GroupKeyResolver::ownUserId(currentGroup).value();

    std::vector<core::UserWithPubKey> newcomerKeys;
    std::vector<keytree::TreeMember> treeNewcomers;
    std::vector<std::string> newcomerIds;
    for (const GroupMemberToAdd& newMember : newMembers) {
        newcomerKeys.push_back(newMember.user);
        treeNewcomers.push_back(
            keytree::TreeMember{newMember.user.userId, privmx::crypto::PublicKey::fromBase58DER(newMember.user.pubKey)}
        );
        newcomerIds.push_back(newMember.user.userId);
    }
    // The newcomers' paths are filled to these keys, as the caller's word for them; existing members' keys go through
    // the same check in `commitRecipientKeys`.
    assertUserKeysVerified(currentGroup.contextId, newcomerKeys);
    keytree::TreeKeys tree(*cache);
    // Only the members the minted nodes wrap to, which the buckets keep to a handful per node.
    tree.setMemberKeyStrings(commitRecipientKeys(
        currentGroup, planOrThrow<std::vector<std::string>>([&] {
            return keytree::TreeKeys::recipients(
                state, keytree::TreeKeys::shapeAddition(state, newcomerIds, positions, adderId)
            );
        }),
        adderId, std::set<std::string>(newcomerIds.begin(), newcomerIds.end())
    ));
    const keytree::CommitPlan plan = planOrThrow<keytree::CommitPlan>([&] {
        return tree.planAddition(state, treeNewcomers, positions, adderId, _userPrivKey);
    });

    // The roster after the change, derived rather than restated. Bare ids: nothing here wraps a key to them,
    // so the public keys the caller used to supply were never read.
    RosterAfterChange roster = rosterFromUserIds(attestedUsers, attestedManagers);
    for (const GroupMemberToAdd& newMember : newMembers) {
        (newMember.role == "manager" ? roster.managers : roster.users)
            .push_back(core::UserWithPubKey{.userId = newMember.user.userId, .pubKey = std::string()});
    }

    // No new epoch
    auto ctx = prepareContainerUpdateWithoutKeyEntries(
        currentGroup, currentEntry, resourceId, roster.users, roster.managers, false
    );
    // Roster only. The metadata entry is not read, not re-encrypted and not re-signed — that is the separation
    // that stops a concurrent metadata write from stranding this write at a version it never committed to.
    GroupRosterToEncryptV5 rosterToEncrypt{
        .internalMeta = core::
            ModuleInternalMetaV5{.secret = ctx.secret, .resourceId = resourceId, .randomId = ctx.dio.randomId},
        .dio = ctx.dio,
        .membership = buildMembershipBlock(
            ctx.key, currentGroup.groupPubKey, currentEpoch, newRosterVersion, roster.users, roster.managers
        )
    };

    server::GroupAddMembersModel model;
    model.id = groupId;
    for (const GroupMemberToAdd& newMember : newMembers) {
        model.members.push_back(server::GroupAddMemberEntry{.userId = newMember.user.userId, .role = newMember.role});
    }
    model.keyId = ctx.key.id;
    model.data = _groupDataSchemaMapper->encryptRoster(rosterToEncrypt, ctx.key.key);
    model.transition = keytree::TreeWire::toAdditionTransition(plan, currentEpoch);
    std::vector<std::string> addedUsers;
    std::vector<std::string> addedManagers;
    for (const GroupMemberToAdd& newMember : newMembers) {
        (newMember.role == "manager" ? addedManagers : addedUsers).push_back(newMember.user.userId);
    }
    keytree::CommitStatement statement = keytree::TreeCommits::statementFor(
        plan, keytree::CommitOp::Add, groupId, commitDate(), static_cast<std::uint64_t>(currentEpoch),
        currentGroup.groupPubKey, static_cast<std::uint64_t>(newRosterVersion),
        core::EndpointUtils::usersWithPubKeyToIds(roster.users),
        core::EndpointUtils::usersWithPubKeyToIds(roster.managers), adderId, addedUsers, addedManagers, {}
    );
    chainTo(statement, currentGroup);
    keytree::TreeCommits::sign(statement, _userPrivKey);
    model.commit = keytree::TreeCommits::toWire(statement);
    model.expectedKeyVersion = currentEpoch;
    model.expectedRosterVersion = currentGroup.rosterVersion;

    submit(groupId, statement, [&] { _serverApi.groupAddMembers(model); });
    _treeVerifier.pinCommitted(
        groupId, currentGroup.contextId, statement, core::EndpointUtils::usersWithPubKeyToIds(roster.users),
        core::EndpointUtils::usersWithPubKeyToIds(roster.managers)
    );
    invalidateModuleKeysInCache(groupId);
}

std::vector<keytree::ArchiveRung> GroupApiImpl::buildRotationRungs(
    const server::GroupInfo& group,
    std::uint32_t newEpoch,
    const privmx::crypto::PublicKey& newGrantPublicKey,
    const std::optional<privmx::crypto::PrivateKey>& previousEpochKey,
    const std::string& author,
    keytree::TreeKeyCache& cache
) {
    const auto asEpoch = [](const std::optional<int64_t>& value) -> std::optional<std::uint32_t> {
        return value.has_value() ? std::optional<std::uint32_t>(static_cast<std::uint32_t>(value.value())) :
                                   std::nullopt;
    };
    keytree::LadderKeys ladder(cache);

    const std::vector<std::uint32_t> targets = keytree::LadderKeys::requiredSkipTargets(
        newEpoch, static_cast<std::uint32_t>(group.eraFloor.value_or(1)), asEpoch(group.archivePrunedBelow)
    );
    if (targets.empty()) {
        // Nothing to fetch and nothing to walk.
        return planOrThrow<std::vector<keytree::ArchiveRung>>([&] {
            return ladder.buildRungs(
                newEpoch, newGrantPublicKey, previousEpochKey, static_cast<std::uint32_t>(group.eraFloor.value_or(1)),
                author, _userPrivKey, true, asEpoch(group.archivePrunedBelow)
            );
        });
    }
    const server::GroupGetKeyArchiveResult archive = fetchKeyArchive(
        group, static_cast<int64_t>(targets.back()), static_cast<int64_t>(newEpoch - 1)
    );
    const std::uint32_t eraFloor = static_cast<std::uint32_t>(archive.eraFloor);
    const std::optional<std::uint32_t> prunedBelow = asEpoch(archive.archivePrunedBelow);

    const keytree::RungKeyGathering gathered = ladder.gatherRungKeys(
        newEpoch, keytree::GroupKeyResolver::toDownwardRungs(archive),
        keytree::GroupKeyResolver::registryFromArchive(group, archive), eraFloor, prunedBelow
    );
    LOG_DEBUG(
        "ladder gather for epoch ",
        std::to_string(newEpoch) +
            ": " +
            std::to_string(gathered.unwraps) +
            " unwraps for " +
            std::to_string(targets.size()) +
            " skip target(s)"
    )
    if (!gathered.complete) {
        throw IncompleteEpochLadderException();
    }
    return planOrThrow<std::vector<keytree::ArchiveRung>>([&] {
        return ladder.buildRungs(
            newEpoch, newGrantPublicKey, previousEpochKey, eraFloor, author, _userPrivKey, true, prunedBelow
        );
    });
}

void GroupApiImpl::removeGroupMembers(const std::string& groupId, const std::vector<std::string>& userIds) {
    bool historyAbandoned = false;
    MetaPlanes planesBefore;
    commitWithRetry([&] { historyAbandoned = removeGroupMembersOnce(groupId, userIds, planesBefore); });
    // The removal is committed; the metadata entry is now one epoch behind, under a key the departed member
    // still holds. Move it up. Outside the write above on purpose — see the header.
    refreshMetadataEpochAfterRemoval(groupId, historyAbandoned, userIds, planesBefore);
}

bool GroupApiImpl::removeGroupMembersOnce(
    const std::string& groupId,
    const std::vector<std::string>& userIds,
    MetaPlanes& planesBefore
) {
    // Every departing member's path, because one commit covers their union — and one epoch covers the batch, where
    // removing them one at a time would stale every container the group can read once per member.
    server::GroupGetModel getModel{
        .groupId = groupId,
        .type = {},
        .scope = std::string("plan"),
        .forUserIds = userIds,
        .forNewMembers = {},
        .fromRosterVersion = {}
    };
    auto currentGroup = _serverApi.groupGet(getModel).group;
    verifyTree(currentGroup, getModel, keytree::TreeVerifier::Scope::Plan);
    planesBefore = MetaPlanes{currentGroup.publicMeta, currentGroup.privateMeta};
    // Refused before anything is planned: the remover mints the next epoch's grant key, so a member removing itself
    // would walk out holding the key meant to lock it out. The bridge refuses it too.
    const std::string self = _connection.getImpl()->getMyUserId(currentGroup.contextId);
    if (std::find(userIds.begin(), userIds.end(), self) != userIds.end()) {
        throw core::InvalidParamsException("a member cannot remove themselves from a group");
    }
    const int64_t currentEpoch = currentGroup.keyVersion;
    const int64_t newEpoch = currentEpoch + 1;
    const int64_t newRosterVersion = currentGroup.rosterVersion + 1;

    const auto cache = _treeKeyCaches.get(groupId);
    const keytree::TreeGroupState state = climbForPlanning(currentGroup, cache, true);
    // Without the current grant key (a broken climb and nothing cached) the removal still goes through, and the
    // epochs before it become unreachable. A malicious bridge can force this by garbling edges (edges are not in
    // the tree hash) — it could destroy history anyway.
    auto currentGrantKey = cache->getGrantKey(static_cast<std::uint32_t>(currentEpoch));
    if (currentGrantKey.has_value() && currentGrantKey->getPublicKey().toBase58DER() != currentGroup.groupPubKey) {
        currentGrantKey.reset(); // not the epoch's key: wrapped into the unit rung it would cut history off anyway
    }
    const bool abandonHistory = !currentGrantKey.has_value();
    // Roster plane only: a removal must not wait on a metadata entry that may sit at an older epoch. With history
    // abandoned the entry cannot be opened; the served roster, bound to the signed latest statement by
    // `verifyTree`'s roster hash, stands in for it.
    const auto [attestedUsers, attestedManagers] = abandonHistory ?
        std::make_pair(currentGroup.users, currentGroup.managers) :
        _groupDataSchemaMapper->validateAndGetAttestedRoster(currentGroup, _keyProvider, _groupPrivKeyResolver);
    keytree::TreeVerifier::assertSeatsMatchRoster(currentGroup, attestedUsers, attestedManagers);
    const std::string removerId = keytree::GroupKeyResolver::ownUserId(currentGroup).value();

    // Handle for the whole operation
    keytree::TreeKeys tree(*cache);
    // Only the members the remover's path wraps to — never the departing ones, whose seats resolve to nobody.
    tree.setMemberKeyStrings(commitRecipientKeys(
        currentGroup, planOrThrow<std::vector<std::string>>([&] {
            return keytree::TreeKeys::recipients(state, keytree::TreeKeys::shapeRemoval(state, userIds, removerId));
        }),
        removerId
    ));
    const keytree::CommitPlan plan = planOrThrow<keytree::CommitPlan>([&] {
        return tree.planRemoval(state, userIds, removerId, _userPrivKey);
    });
    const std::vector<keytree::ArchiveRung> rungs = abandonHistory ?
        std::vector<keytree::ArchiveRung>{} :
        buildRotationRungs(
            currentGroup, static_cast<std::uint32_t>(newEpoch), plan.grantKey.getPublicKey(), currentGrantKey,
            removerId, *cache
        );
    // The roster that remains, derived from the verified head rather than restated by the caller.
    const std::set<std::string> leaving(userIds.begin(), userIds.end());
    RosterAfterChange roster = rosterFromUserIds(attestedUsers, attestedManagers);
    const auto drop = [&](std::vector<core::UserWithPubKey>& list) {
        list.erase(
            std::remove_if(
                list.begin(), list.end(), [&](const core::UserWithPubKey& u) { return leaving.count(u.userId) > 0; }
            ),
            list.end()
        );
    };
    drop(roster.users);
    drop(roster.managers);

    const std::string newGroupPubKeyStr = plan.grantKey.getPublicKey().toBase58DER();
    const NewEpochRoster sealed = sealRosterForNewEpoch(
        currentGroup, roster, newGroupPubKeyStr, newEpoch, newRosterVersion, abandonHistory
    );

    // Seats come from the plan, which resolved them from the roster the bridge served. `subjectLeafPositions`
    // carries the same answer; keeping the plan as the single source stops the two from ever disagreeing.
    server::GroupRemoveMembersModel model;
    model.id = groupId;
    model.userIds = userIds;
    model.groupPubKey = newGroupPubKeyStr;
    model.keyId = sealed.keyId;
    model.data = sealed.data;
    model.transition = keytree::TreeWire::toRemovalTransition(plan, currentEpoch);
    keytree::CommitStatement statement = keytree::TreeCommits::statementFor(
        plan, keytree::CommitOp::Remove, groupId, commitDate(), static_cast<std::uint64_t>(newEpoch), newGroupPubKeyStr,
        static_cast<std::uint64_t>(newRosterVersion), core::EndpointUtils::usersWithPubKeyToIds(roster.users),
        core::EndpointUtils::usersWithPubKeyToIds(roster.managers), removerId, {}, {}, userIds
    );
    chainTo(statement, currentGroup);
    keytree::TreeCommits::sign(statement, _userPrivKey);
    model.commit = keytree::TreeCommits::toWire(statement);
    model.rungs = keytree::TreeWire::toWire(rungs);
    if (abandonHistory) {
        model.abandonHistory = true;
    }
    model.groupKeys = sealed.groupKeys;
    model.expectedKeyVersion = currentEpoch;
    model.expectedRosterVersion = currentGroup.rosterVersion;

    submit(groupId, statement, [&] { _serverApi.groupRemoveMembers(model); });
    // Pinned before anything reads the group again, or the next read could be the state with the leaver still in.
    adoptCommittedEpoch(currentGroup, statement, roster, plan.grantKey, *cache);
    return abandonHistory;
}

GroupApiImpl::NewEpochRoster GroupApiImpl::sealRosterForNewEpoch(
    const server::GroupInfo& currentGroup,
    const RosterAfterChange& roster,
    const std::string& newGroupPubKeyStr,
    int64_t newEpoch,
    int64_t newRosterVersion,
    bool abandonHistory
) {
    const std::string& groupId = currentGroup.id;
    const auto& currentEntry = currentGroup.data.back();
    const auto resourceId = currentGroup.resourceId.value_or(core::EndpointUtils::generateId());
    // Nothing old may stay readable once history is abandoned, and the old key and secret cannot be opened anyway:
    // both start fresh, as at creation.
    auto ctx = abandonHistory ?
        core::ContainerUpdateContext{
            .location = {.contextId = currentGroup.contextId, .resourceId = resourceId},
            .key = _keyProvider->generateKey(),
            .dio = _connection.getImpl()->createDIO(currentGroup.contextId, resourceId),
            .secret = _keyProvider->generateSecret(),
            .keyEntries = {}
        } :
        prepareContainerUpdateWithoutKeyEntries(
            currentGroup, currentEntry, resourceId, roster.users, roster.managers, true
        );
    const auto selfAddressedKey = buildGroupKeyEntries(
        {core::GroupGrantWithKey{
            .groupId = groupId,
            .role = "manager",
            .groupPubKey = newGroupPubKeyStr,
            .groupEpoch = newEpoch,
        }},
        ctx.key, ctx.dio, currentGroup.contextId, resourceId, ctx.secret
    );

    // Roster plane only — the metadata entry is not part of this write. `refreshMetadataEpochAfterRemoval`
    // carries it up to the new epoch once this has committed; see its header for why that is a second call.
    GroupRosterToEncryptV5 rosterToEncrypt{
        .internalMeta = core::
            ModuleInternalMetaV5{.secret = ctx.secret, .resourceId = resourceId, .randomId = ctx.dio.randomId},
        .dio = ctx.dio,
        .membership = buildMembershipBlock(
            ctx.key, newGroupPubKeyStr, newEpoch, newRosterVersion, roster.users, roster.managers
        )
    };

    return NewEpochRoster{
        .keyId = ctx.key.id,
        .data = _groupDataSchemaMapper->encryptRoster(rosterToEncrypt, ctx.key.key),
        .groupKeys = selfAddressedKey.at(0)
    };
}

void GroupApiImpl::adoptCommittedEpoch(
    const server::GroupInfo& currentGroup,
    const keytree::CommitStatement& statement,
    const RosterAfterChange& roster,
    const privmx::crypto::PrivateKey& grantKey,
    keytree::TreeKeyCache& cache
) {
    _treeVerifier.pinCommitted(
        currentGroup.id, currentGroup.contextId, statement, core::EndpointUtils::usersWithPubKeyToIds(roster.users),
        core::EndpointUtils::usersWithPubKeyToIds(roster.managers)
    );
    cache.putGrantKey(static_cast<std::uint32_t>(statement.keyVersion), grantKey);
    // Minted here and accepted at exactly this epoch (the CAS), so it is the epoch's published key: the metadata
    // refresh that follows opens it without a read.
    _epochKeys.set(memoKeyFor(currentGroup.id, std::to_string(statement.keyVersion)), grantKey);
    invalidateModuleKeysInCache(currentGroup.id);
}

void GroupApiImpl::rotateGroupKey(const std::string& groupId) {
    MetaPlanes planesBefore;
    commitWithRetry([&] { rotateGroupKeyOnce(groupId, planesBefore); });
    // As after a removal: the metadata planes sit one epoch behind, under the key the rotation replaces. Nobody left,
    // so nobody is accepted as an author beyond the members.
    refreshMetadataEpochAfterRemoval(groupId, false, {}, planesBefore);
}

void GroupApiImpl::rotateGroupKeyOnce(const std::string& groupId, MetaPlanes& planesBefore) {
    // Every record, because the statement signs the tree hash, which a rotation leaves as it is.
    server::GroupGetModel getModel{
        .groupId = groupId,
        .type = {},
        .scope = std::string("plan"),
        .forUserIds = {},
        .forNewMembers = {},
        .fromRosterVersion = {}
    };
    auto currentGroup = _serverApi.groupGet(getModel).group;
    verifyTree(currentGroup, getModel, keytree::TreeVerifier::Scope::Plan);
    planesBefore = MetaPlanes{currentGroup.publicMeta, currentGroup.privateMeta};
    const int64_t currentEpoch = currentGroup.keyVersion;
    const int64_t newEpoch = currentEpoch + 1;
    const int64_t newRosterVersion = currentGroup.rosterVersion + 1;

    // Unlike a removal, a rotation never abandons history: the point is a new key for the same members, and the
    // climb (a verified root key and the current grant key) is what the rungs down to the old epochs are made from.
    const auto cache = _treeKeyCaches.get(groupId);
    const keytree::TreeGroupState state = climbForPlanning(currentGroup, cache);
    const auto currentGrantKey = cache->getGrantKey(static_cast<std::uint32_t>(currentEpoch));
    if (!currentGrantKey.has_value() || currentGrantKey->getPublicKey().toBase58DER() != currentGroup.groupPubKey) {
        throw core::EncryptionKeyValidationException("rotating the group key needs the current grant key");
    }
    const auto [attestedUsers, attestedManagers] =
        _groupDataSchemaMapper->validateAndGetAttestedRoster(currentGroup, _keyProvider, _groupPrivKeyResolver);
    keytree::TreeVerifier::assertSeatsMatchRoster(currentGroup, attestedUsers, attestedManagers);
    const std::string rotatorId = keytree::GroupKeyResolver::ownUserId(currentGroup).value();

    keytree::TreeKeys tree(*cache);
    const keytree::CommitPlan plan = planOrThrow<keytree::CommitPlan>([&] {
        return tree.planRotation(state, rotatorId, _userPrivKey);
    });
    const std::vector<keytree::ArchiveRung> rungs = buildRotationRungs(
        currentGroup, static_cast<std::uint32_t>(newEpoch), plan.grantKey.getPublicKey(), currentGrantKey, rotatorId,
        *cache
    );
    const RosterAfterChange roster = rosterFromUserIds(attestedUsers, attestedManagers);
    const std::string newGroupPubKeyStr = plan.grantKey.getPublicKey().toBase58DER();
    const NewEpochRoster sealed = sealRosterForNewEpoch(
        currentGroup, roster, newGroupPubKeyStr, newEpoch, newRosterVersion, false
    );

    server::GroupGenerateNewKeyModel model;
    model.id = groupId;
    model.groupPubKey = newGroupPubKeyStr;
    model.keyId = sealed.keyId;
    model.data = sealed.data;
    model.grantEdge = keytree::TreeWire::toWire(plan.edges.at(0));
    keytree::CommitStatement statement = keytree::TreeCommits::statementFor(
        plan, keytree::CommitOp::Rotate, groupId, commitDate(), static_cast<std::uint64_t>(newEpoch), newGroupPubKeyStr,
        static_cast<std::uint64_t>(newRosterVersion), attestedUsers, attestedManagers, rotatorId, {}, {}, {}
    );
    chainTo(statement, currentGroup);
    keytree::TreeCommits::sign(statement, _userPrivKey);
    model.commit = keytree::TreeCommits::toWire(statement);
    model.rungs = keytree::TreeWire::toWire(rungs);
    model.groupKeys = sealed.groupKeys;
    model.expectedKeyVersion = currentEpoch;
    model.expectedRosterVersion = currentGroup.rosterVersion;

    submit(groupId, statement, [&] { _serverApi.groupGenerateNewKey(model); });
    // Pinned before anything reads the group again: the state under the replaced key is refused from here on.
    adoptCommittedEpoch(currentGroup, statement, roster, plan.grantKey, *cache);
}

void GroupApiImpl::commitWithRetry(const std::function<void()>& attempt) {
    constexpr int MAX_ATTEMPTS = 3;
    for (int attemptNo = 1;; ++attemptNo) {
        try {
            attempt();
            return;
        } catch (const privmx::utils::PrivmxException& e) {
            if (attemptNo < MAX_ATTEMPTS && isRetryableCommitRejection(e)) {
                LOG_DEBUG("group commit planned against a moved base, re-planning: ", e.what())
                continue;
            }
            core::ExceptionConverter::rethrowAsCoreException(e);
            throw core::Exception("ExceptionConverter rethrow error");
        }
    }
}

// A concurrent commit — most often a self-update, which every member under a blanked node runs on its own — moved
// the generations or versions this one was planned against. Nothing about the request was wrong, so a fresh read
// and a fresh plan are all it takes; anything else the bridge refuses is reported as it is.
bool GroupApiImpl::isRetryableCommitRejection(const privmx::utils::PrivmxException& e) {
    const unsigned int code = e.getCode();
    if ((code & 0xFFFF0000) != 0) {
        return false; // not a bridge application error
    }
    switch (code & 0x0000FFFF) {
    case 0x621C: // ROTATED_ALREADY
    case 0x6224: // GROUP_ROSTER_VERSION_MISMATCH
        return true;
    case 0x621E: // GROUP_TREE_INVALID, whose data lists the problems found
        return e.getData().find("\"STALE_BASE_GENERATION\"") != std::string::npos;
    default:
        return false;
    }
}

void GroupApiImpl::scheduleSelfUpdateIfNeeded(const std::string& groupId, const server::GroupInfo& group) {
    const auto node = keytree::GroupKeyResolver::nodeNeedingSelfUpdate(group);
    if (!node.has_value()) {
        return;
    }
    // ponytail: 8 ms per seat, 1-120 s. One window holds the first healers of a fresh 16k group (~n/32 commits) at
    // the bridge's ~5-10 commits/s only with retries; a per-group rate limit on the bridge is the upgrade path.
    const std::int64_t windowMs = std::clamp<std::int64_t>(group.numLeaves.value_or(1) * 8, 1000, 120000);
    scheduleSelfUpdate(groupId, windowMs, keytree::GroupKeyResolver::healsFirst(group, node.value()));
}

void GroupApiImpl::scheduleSelfUpdate(
    const std::string& groupId,
    std::int64_t windowMs,
    bool healsFirst,
    int attempts
) {
    std::unique_lock<std::mutex> lock(_selfUpdateMutex);
    if (_selfUpdateStopping || _selfUpdatePending.count(groupId) > 0 || _selfUpdateRunning == groupId) {
        return;
    }
    // The healer of a node commits within the window; everybody else under it waits the window out first and then
    // finds (on a path read) the node already refilled, unless that healer is gone. Jitter keeps the healers of
    // different nodes, and the stand-ins, from colliding on the generations they all refresh.
    static thread_local std::mt19937_64 random{std::random_device{}()};
    const auto delay = std::chrono::milliseconds(
        (healsFirst ? 0 : windowMs) + std::uniform_int_distribution<std::int64_t>(0, windowMs)(random)
    );
    _selfUpdatePending[groupId] = {std::chrono::steady_clock::now() + delay, windowMs, attempts};
    if (!_selfUpdateWorker.joinable()) {
        _selfUpdateWorker = std::thread([this] { runSelfUpdates(); });
    }
    _selfUpdateWake.notify_all();
}

void GroupApiImpl::runSelfUpdates() {
    std::unique_lock<std::mutex> lock(_selfUpdateMutex);
    while (!_selfUpdateStopping) {
        const auto next = std::min_element(
            _selfUpdatePending.begin(), _selfUpdatePending.end(),
            [](const auto& a, const auto& b) { return a.second.due < b.second.due; }
        );
        if (next == _selfUpdatePending.end()) {
            _selfUpdateWake.wait(lock);
            continue;
        }
        if (next->second.due > std::chrono::steady_clock::now()) {
            _selfUpdateWake.wait_until(lock, next->second.due);
            continue;
        }
        const std::string groupId = next->first;
        const PendingSelfUpdate pending = next->second;
        _selfUpdateRunning = groupId;
        _selfUpdatePending.erase(next);
        lock.unlock();
        bool lostRace = false;
        try {
            selfUpdate(groupId);
        } catch (const privmx::utils::PrivmxException& e) {
            lostRace = isRetryableCommitRejection(e);
            if (!lostRace) {
                LOG_WARN("[selfUpdate] group key tree self-update dropped: ", e.what())
            }
        } catch (const std::exception& e) {
            LOG_WARN("[selfUpdate] group key tree self-update dropped: ", e.what())
        } catch (...) { LOG_WARN("[selfUpdate] group key tree self-update dropped") }
        lock.lock();
        _selfUpdateRunning.reset();
        // A lost race goes back in the queue with a fresh random delay, so the members that collided spread out
        // instead of colliding again on an immediate re-plan.
        if (lostRace && pending.attempts + 1 < MAX_SELF_UPDATE_ATTEMPTS) {
            lock.unlock();
            // It already waited its turn once.
            scheduleSelfUpdate(groupId, pending.windowMs, true, pending.attempts + 1);
            lock.lock();
        } else if (lostRace) {
            LOG_WARN("[selfUpdate] group key tree self-update dropped after repeated concurrent commits")
        }
    }
}

void GroupApiImpl::selfUpdate(const std::string& groupId) {
    // The need first, on the small path view: by now the node's healer, or anybody's commit through it, has most
    // likely refilled it, and the plan view carries every node record of the tree.
    const server::GroupGetModel pathModel = pathRead(groupId);
    auto pathView = _serverApi.groupGet(pathModel).group;
    if (!verifyTree(pathView, pathModel, keytree::TreeVerifier::Scope::Path) ||
        !keytree::GroupKeyResolver::nodeNeedingSelfUpdate(pathView).has_value()) {
        return;
    }
    server::GroupGetModel getModel{
        .groupId = groupId,
        .type = {},
        .scope = std::string("plan"),
        .forUserIds = {},
        .forNewMembers = {},
        .fromRosterVersion = {}
    };
    auto group = _serverApi.groupGet(getModel).group;
    verifyTree(group, getModel, keytree::TreeVerifier::Scope::Plan);
    // Re-checked on a fresh read: somebody's commit through the same nodes may have refilled them meanwhile.
    if (!keytree::GroupKeyResolver::hasTree(group) ||
        !keytree::GroupKeyResolver::hasSupportedTree(group) ||
        !keytree::GroupKeyResolver::nodeNeedingSelfUpdate(group).has_value()) {
        return;
    }
    // A self-update wraps to whoever is seated, so it needs the seats proven against the roster like any commit.
    const auto [attestedUsers, attestedManagers] = _groupDataSchemaMapper->validateAndGetAttestedRoster(
        group, _keyProvider, _groupPrivKeyResolver
    );
    keytree::TreeVerifier::assertSeatsMatchRoster(group, attestedUsers, attestedManagers);
    const auto cache = _treeKeyCaches.get(groupId);
    const keytree::TreeGroupState state = climbForPlanning(group, cache);
    const std::string memberId = keytree::GroupKeyResolver::ownUserId(group).value();

    keytree::TreeKeys tree(*cache);
    tree.setMemberKeyStrings(commitRecipientKeys(
        group, keytree::TreeKeys::recipients(state, keytree::TreeKeys::shapeSelfUpdate(state, memberId)), memberId
    ));
    const keytree::CommitPlan plan = tree.planSelfUpdate(state, memberId, _userPrivKey);

    server::GroupSelfUpdateModel model;
    model.id = groupId;
    model.expectedKeyVersion = group.keyVersion;
    model.transition = keytree::TreeWire::toSelfUpdateTransition(plan, group.keyVersion);
    keytree::CommitStatement statement = keytree::TreeCommits::statementFor(
        plan, keytree::CommitOp::SelfUpdate, groupId, commitDate(), static_cast<std::uint64_t>(group.keyVersion),
        group.groupPubKey, static_cast<std::uint64_t>(group.rosterVersion), attestedUsers, attestedManagers, memberId,
        {}, {}, {}
    );
    chainTo(statement, group);
    keytree::TreeCommits::sign(statement, _userPrivKey);
    model.commit = keytree::TreeCommits::toWire(statement);
    submit(groupId, statement, [&] { _serverApi.groupSelfUpdate(model); });
    _treeVerifier.pinCommitted(groupId, group.contextId, statement, attestedUsers, attestedManagers);
}

void GroupApiImpl::refreshMetadataEpochAfterRemoval(
    const std::string& groupId,
    bool historyAbandoned,
    const std::vector<std::string>& removed,
    const MetaPlanes& planesBefore
) {
    try {
        // One verified answer decides both whether a plane is behind and what it says: re-signing metadata this
        // client has not attested would launder whatever the bridge served into an entry under the new epoch's key,
        // and an unverified epoch would let the bridge talk this out of running.
        const server::GroupInfo group = readGroupForKeys(groupId);
        // Per plane, because the two sit at epochs of their own: one may already have been carried up by a
        // concurrent write while the other is still behind.
        const bool publicBehind = group.publicMeta.keyVersion < group.keyVersion;
        const bool privateBehind = group.privateMeta.keyVersion < group.keyVersion;
        if (historyAbandoned) {
            // A plane behind sits under a key nobody can reach any more, and what it says cannot be attested: start
            // it over, empty, in the new epoch rather than leave it unreadable for good.
            if (publicBehind) {
                writePublicMeta(group, core::Buffer(), group.publicMetaVersion);
            }
            if (privateBehind) {
                writePrivateMeta(group, core::Buffer(), group.privateMetaVersion);
            }
            return;
        }
        // The removed count as authors only of the very entries served before the removal, written while they were
        // members: one tagged since under the key they still hold must not be re-signed in the remover's name.
        const auto asBefore = [](const server::GroupMetaEntry& now, const server::GroupMetaEntry& then) {
            return now.version == then.version && now.author == then.author && now.keyId == then.keyId &&
                privmx::utils::Utils::stringifyVar(now.data) == privmx::utils::Utils::stringifyVar(then.data);
        };
        const bool unchanged = (!publicBehind || asBefore(group.publicMeta, planesBefore.publicMeta)) &&
            (!privateBehind || asBefore(group.privateMeta, planesBefore.privateMeta));
        const Group verified = _groupDataSchemaMapper->validateDecryptAndConvertGroup(
            group, _keyProvider, resolverOver(&group), unchanged ? removed : std::vector<std::string>{}
        );
        if (verified.statusCode != 0) {
            return;
        }
        if (!publicBehind && !privateBehind) {
            // Already current — a concurrent metadata write got there first, which is the same outcome.
            return;
        }
        // One write per plane that is behind. A plane already at the current epoch is left alone, so a concurrent
        // writer keeps its entry.
        // Both off the one verified read: a metadata write moves neither the head nor the epoch it is checked against.
        if (publicBehind) {
            writePublicMeta(group, verified.publicMeta, verified.publicMetaVersion);
        }
        if (privateBehind) {
            writePrivateMeta(group, verified.privateMeta, verified.privateMetaVersion);
        }
    } catch (...) {
        // Best-effort by design. A failure leaves the group where a removal used to leave it, and the next
        // metadata write closes the window; throwing here would fail a removal that has already happened.
    }
}

MetaWriteContext GroupApiImpl::prepareMetaWrite(const server::GroupInfo& currentGroup) {
    const auto& currentEntry = currentGroup.data.back();
    const auto resourceId = currentGroup.resourceId.value_or(core::EndpointUtils::generateId());
    const int64_t currentEpoch = currentGroup.keyVersion;

    // Names no diff, so `UsersKeysResolver` sees no reason to mint a key: the pub keys are deliberately empty
    // because nothing here is wrapped to anybody.
    const auto roster = rosterFromUserIds(currentGroup.users, currentGroup.managers);
    auto ctx = prepareContainerUpdateWithoutKeyEntries(
        currentGroup, currentEntry, resourceId, roster.users, roster.managers, false
    );

    // The roster head always sits at the current epoch, so the key selected off it is the current epoch's.
    // Were that to stop holding, metadata would be written under a key a removed member still holds.
    if (ctx.key.id != currentEntry.keyId) {
        throw GroupDataIntegrityException("metadata write resolved a key that is not the current epoch's");
    }
    return MetaWriteContext{.resourceId = resourceId, .currentEpoch = currentEpoch, .ctx = ctx};
}

void GroupApiImpl::updateGroupPublicMeta(
    const std::string& groupId,
    const core::Buffer& publicMeta,
    const int64_t version
) {
    // The default path view is enough: this submits no tree and does not touch the roster at all.
    writePublicMeta(readGroupForKeys(groupId), publicMeta, version);
}

void GroupApiImpl::writePublicMeta(
    const server::GroupInfo& currentGroup,
    const core::Buffer& publicMeta,
    const int64_t version
) {
    const std::string& groupId = currentGroup.id;
    auto w = prepareMetaWrite(currentGroup);
    GroupPublicMetaToEncryptV5 toEncrypt{
        .publicMeta = publicMeta,
        .dio = w.ctx.dio,
        .meta = dynamic::MetaBlock{
            // The same `version` feeds the CAS field below, so the version this commits to and the version
            // the bridge checks cannot disagree.
            .metaTag = GroupDataSchemaMapper::publicMetaTag(w.ctx.key.key, w.currentEpoch, version + 1),
            .keyId = w.ctx.key.id,
            .keyVersion = w.currentEpoch,
            .metaVersion = version + 1
        }
    };

    server::GroupUpdatePublicMetaModel model;
    model.id = groupId;
    model.resourceId = w.resourceId;
    model.keyId = w.ctx.key.id;
    // No force field, unlike the other containers: the entry commits the version it lands at, so a write that
    // skipped the version check could only land a tag no reader will accept.
    model.version = version;
    model.data = _groupDataSchemaMapper->encryptPublicMeta(toEncrypt);

    // A metadata write is never answered with `ROTATED_ALREADY` (that is the commits'); a version conflict is the
    // caller's to re-read, like any other.
    _serverApi.groupUpdatePublicMeta(model);
    // Rotates nothing — not the content key, not the grant key, not the tree. Only the cached view is stale.
    invalidateModuleKeysInCache(groupId);
}

void GroupApiImpl::updateGroupPrivateMeta(
    const std::string& groupId,
    const core::Buffer& privateMeta,
    const int64_t version
) {
    writePrivateMeta(readGroupForKeys(groupId), privateMeta, version);
}

void GroupApiImpl::writePrivateMeta(
    const server::GroupInfo& currentGroup,
    const core::Buffer& privateMeta,
    const int64_t version
) {
    const std::string& groupId = currentGroup.id;
    auto w = prepareMetaWrite(currentGroup);
    GroupPrivateMetaToEncryptV5 toEncrypt{
        .privateMeta = privateMeta,
        .dio = w.ctx.dio,
        .meta = dynamic::MetaBlock{
            .metaTag = GroupDataSchemaMapper::privateMetaTag(w.ctx.key.key, w.currentEpoch, version + 1),
            .keyId = w.ctx.key.id,
            .keyVersion = w.currentEpoch,
            .metaVersion = version + 1
        }
    };

    server::GroupUpdatePrivateMetaModel model;
    model.id = groupId;
    model.resourceId = w.resourceId;
    model.keyId = w.ctx.key.id;
    model.version = version;
    model.data = _groupDataSchemaMapper->encryptPrivateMeta(toEncrypt, w.ctx.key.key);

    _serverApi.groupUpdatePrivateMeta(model);
    invalidateModuleKeysInCache(groupId);
}

void GroupApiImpl::updateGroupPolicy(const std::string& groupId, const core::ContainerPolicy& policies) {
    // No read, no key, no envelope: the policy is a bare bridge-held field, so there is nothing to tag or
    // encrypt. No cache invalidation either — no counter moves and the module key cache keys on `rosterVersion`.
    _serverApi.groupUpdatePolicy(
        server::GroupUpdatePolicyModel{.id = groupId, .policy = core::Factory::createPolicyServerObject(policies)}
    );
}

void GroupApiImpl::deleteGroup(const std::string& groupId) {
    server::GroupDeleteModel model{.groupId = groupId};
    _serverApi.groupDelete(model);
    forgetGroupKeys(groupId);
    invalidateModuleKeysInCache(groupId);
}

Group GroupApiImpl::getGroup(const std::string& groupId) {
    const server::GroupGetModel params = pathRead(groupId);
    // The head roster entry and the current metadata entry — two entries, whatever the group's age. The cache is
    // keyed on the roster version, because that is the plane key material moves with.
    auto group = _serverApi.groupGet(params).group;
    // The tree first, on this same answer: only the verified latest statement says which epoch is current. A caller
    // without a seat gets the group as before, with nothing cached.
    const bool seated = verifyTree(group, params, keytree::TreeVerifier::Scope::Path);
    Group result = _groupDataSchemaMapper->validateDecryptAndConvertGroup(
        group, _keyProvider, seated ? resolverOver(&group) : _groupPrivKeyResolver
    );
    // Outsiders seal anonymous envelopes to it: only as the latest statement vouches for it, which `verifyTree`
    // checked for a seated caller.
    if (!seated && !hasVerifiedGrantKey(group)) {
        result.groupPubKey.clear();
    }
    // Writes take their key from this cache, so only an answer that passed everything may fill it.
    if (seated && result.statusCode == 0) {
        assertHeadKeyAtEpoch(group);
        setNewModuleKeysInCache(group.id, groupToModuleKeys(group), group.rosterVersion);
    }
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
        if (!_treeVerifier.pinnedAt(group.id, contextId, group.keyVersion, group.groupPubKey)) {
            groups.back().groupPubKey.clear();
        }
    }
    return core::PagingList<GroupSummary>({.totalAvailable = groupsList.count, .readItems = groups});
}

bool GroupApiImpl::hasVerifiedGrantKey(const server::GroupInfo& group) {
    try {
        _treeVerifier.verifyListed(group, treeEnvironment(group.id));
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
    std::unordered_map<std::string, core::GroupEpochInfo> epochs;
    // A container key is about to be wrapped to these grant keys, so each comes off the group's latest statement.
    // A writer outside the group trusts that the signer, vouched by the UserVerifier, is a member (TOFU on membership).
    // The listing (constant size) says which epoch is current; one this process has pinned is taken from the pin,
    // anything else is read with `groupGet` (roster and statement, which grow) and verified. Returns the ids served
    // behind the state this process has verified for them.
    const auto take = [&](const std::vector<std::string>& ids) {
        Poco::JSON::Array::Ptr idArray = new Poco::JSON::Array();
        for (const auto& id : ids) {
            idArray->add(id);
        }
        Poco::JSON::Object::Ptr in = new Poco::JSON::Object();
        in->set("$in", idArray);
        Poco::JSON::Object::Ptr query = new Poco::JSON::Object();
        query->set("#id", in);
        server::GroupListModel model;
        model.contextId = contextId;
        core::ListQueryMapper::map(
            model,
            core::PagingQuery{
                .skip = 0,
                .limit = static_cast<int64_t>(ids.size()),
                .sortOrder = "asc",
                .lastId = std::nullopt,
                .sortBy = std::nullopt,
                .queryAsJson = privmx::utils::Utils::stringify(query)
            }
        );
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
                epochs[summary.id] =
                    core::GroupEpochInfo{.keyVersion = summary.keyVersion, .groupPubKey = summary.groupPubKey};
                continue;
            }
            // ponytail: one `groupGet` per unpinned group, the whole tree for a caller without a seat; a statement-and-
            // roster read would do if non-member writes to new or rotated groups get hot.
            try {
                read.push_back(_serverApi.groupGet(pathRead(summary.id)).group);
            } catch (const std::exception& e) {
                LOG_WARN("[fetchGroupEpochs] group ", summary.id, " unreadable: ", e.what())
            }
        }
        _treeVerifier.preverifyListed(read, treeEnvironment(std::string()));
        for (const auto& group : read) {
            // A group that fails verification gets no key at all, never the unverified one.
            if (group.contextId != contextId) {
                continue;
            }
            try {
                _treeVerifier.verifyListed(group, treeEnvironment(group.id));
            } catch (const std::exception& e) {
                LOG_WARN("[fetchGroupEpochs] group ", group.id, " failed verification: ", e.what())
                continue;
            }
            if (group.treeCommit->seq < static_cast<std::int64_t>(_treeVerifier.pinnedSeq(group.id))) {
                behind.push_back(group.id);
                continue;
            }
            epochs[group.id] = core::GroupEpochInfo{.keyVersion = group.keyVersion, .groupPubKey = group.groupPubKey};
        }
        return behind;
    };
    constexpr size_t BATCH = 100; // The bridge listing caps at 100
    for (size_t offset = 0; offset < groupIds.size(); offset += BATCH) {
        const std::vector<std::string> behind = take(std::vector<std::string>(
            groupIds.begin() + offset, groupIds.begin() + std::min(offset + BATCH, groupIds.size())
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
                if (routing.type != ENVELOPE_FROM_MEMBER || routing.groupId != raw.id ||
                    (routing.keyId != getModuleKeys(raw.id).currentKeyId &&
                     routing.keyId != getNewModuleKeysAndUpdateCache(raw.id).currentKeyId)) {
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
            forgetGroupKeys(raw.groupId);
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
    _treeKeyCaches.dropAll();
    dropEnvelopeState();
    invalidateModuleKeysInCache();
}

void GroupApiImpl::processDisconnectedEvent() {
    {
        std::unique_lock<std::mutex> lock(_selfUpdateMutex);
        _selfUpdatePending.clear();
    }
    _epochKeys.clear();
    _treeKeyCaches.dropAll();
    dropEnvelopeState();
    invalidateModuleKeysInCache();
}

void GroupApiImpl::dropEnvelopeState() {
    _envelopeKeys.clear();
    _envelopeGrantEpochs.clear();
    // Open file handles too: an `EnvelopeFileState` holds the group and file keys as plainly as `_envelopeKeys`
    // does. A handle used after this reports "not an open encrypted-file handle", which a reconnect made true.
    _envelopeFiles.clear();
}

void GroupApiImpl::forgetGroupKeys(const std::string& groupId) {
    _treeKeyCaches.drop(groupId);
    const std::string prefix = memoKeyFor(groupId, "");
    const auto erase = [&](auto& memo) {
        std::vector<std::string> stale;
        memo.forAllLockSave([&](const std::string& key, const auto&) {
            if (key.compare(0, prefix.size(), prefix) == 0) {
                stale.push_back(key);
            }
        });
        for (const std::string& key : stale) {
            memo.erase(key);
        }
    };
    erase(_epochKeys);
    erase(_envelopeKeys);
    erase(_envelopeGrantEpochs);
}

std::pair<core::ModuleKeys, int64_t> GroupApiImpl::getModuleKeysAndVersionFromServer(std::string moduleId) {
    const server::GroupInfo group = readGroupForKeys(moduleId);
    // Roster version: key material moves with that plane, so a metadata-only write must not stale the cache.
    return std::make_pair(groupToModuleKeys(group), group.rosterVersion);
}

group::server::GroupInfo GroupApiImpl::readGroupForKeys(const std::string& groupId) {
    const server::GroupGetModel params = pathRead(groupId);
    auto group = _serverApi.groupGet(params).group;
    // The tree pins `keyVersion` (never below what this client verified or committed itself); the head entry's
    // grant must be at exactly that epoch; the roster attestation binds the head to it and moves the version pins.
    if (!verifyTree(group, params, keytree::TreeVerifier::Scope::Path)) {
        throw core::EncryptionKeyValidationException("caller holds no verifiable seat in this group's key tree");
    }
    assertHeadKeyAtEpoch(group);
    _groupDataSchemaMapper->validateAndGetAttestedRoster(group, _keyProvider, resolverOver(&group));
    return group;
}

core::KeyProvider::GroupPrivKeyResolver GroupApiImpl::resolverOver(const server::GroupInfo* seatedRead) {
    return [this, seatedRead](const std::string& groupId, int64_t epoch) -> std::optional<privmx::crypto::PrivateKey> {
        try {
            return resolveGroupPrivKey(groupId, epoch, seatedRead);
        } catch (const GroupHistoryForkException&) {
            throw; // a rollback is not "no key": it must reach the caller as itself
        } catch (...) {
            // caller holds no leaf in this group's tree at this epoch — skip
            return std::nullopt;
        }
    };
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
    const server::GroupInfo* seatedRead
) {
    // An epoch's key never changes: once resolved and matched to its published public key it is served from here,
    // with no read, no tree check, no climb and no ladder. 0 ("current") names no fixed epoch, so it always reads.
    if (epoch > 0) {
        if (auto cached = _epochKeys.get(memoKeyFor(groupId, std::to_string(epoch))); cached.has_value()) {
            return cached.value();
        }
    }
    // Only its own current epoch: any other one needs the archive, which this read decides nothing about.
    const bool reuse = seatedRead != nullptr && seatedRead->id == groupId && epoch == seatedRead->keyVersion;
    const server::GroupGetModel params = pathRead(groupId);
    std::optional<server::GroupInfo> fresh;
    if (!reuse) {
        fresh = _serverApi.groupGet(params).group;
    }
    // The served path checked against the latest statement before any key off it is used. A group without a
    // supported tree, or a caller without a seat, is left to the resolver, which refuses both without a key.
    const bool seated = reuse || verifyTree(fresh.value(), params, keytree::TreeVerifier::Scope::Path);
    const server::GroupInfo& group = reuse ? *seatedRead : fresh.value();

    const int64_t currentEpoch = group.keyVersion;
    const auto cache = _treeKeyCaches.get(groupId);
    keytree::GroupKeyResolver resolver(*cache);
    const bool needsDescent = seated && epoch > 0 && epoch < currentEpoch;
    const keytree::ResolveResult resolved = resolver.resolve(
        group, epoch, _userPrivKey,
        needsDescent ? fetchKeyArchive(group, epoch, currentEpoch) : server::GroupGetKeyArchiveResult{}
    );
    if (resolved.key.has_value()) {
        // The climb to the current epoch went through, so the served path is the caller's to vouch for: refill
        // whatever blanks a removal left on it, and re-key what somebody outside it set, in the background.
        scheduleSelfUpdateIfNeeded(groupId, group);
        // The resolver has checked the key against the epoch's published public key on the way here.
        _epochKeys.set(memoKeyFor(groupId, std::to_string(epoch == 0 ? currentEpoch : epoch)), resolved.key.value());
        return resolved.key.value();
    }
    if (resolved.failure == keytree::ResolveFailure::ClimbFailed &&
        resolved.climb == keytree::ClimbFailure::NotAMember) {
        _treeKeyCaches.drop(groupId);
    }
    throw core::EncryptionKeyValidationException(describeResolveFailure(resolved));
}

bool GroupApiImpl::verifyTree(
    server::GroupInfo& group,
    const server::GroupGetModel& model,
    keytree::TreeVerifier::Scope scope
) {
    if (!keytree::GroupKeyResolver::hasTree(group) ||
        !keytree::GroupKeyResolver::hasSupportedTree(group) ||
        !keytree::GroupKeyResolver::ownUserId(group).has_value()) {
        return false;
    }
    const keytree::TreeVerifier::Environment environment = treeEnvironment(group.id);
    try {
        _treeVerifier.verify(group, scope, environment);
    } catch (const EndpointGroupException&) {
        // A torn read, or a concurrent read that pinned a newer state while this answer was in flight: a fresh read
        // settles both, and a real attack fails the second check too.
        group = _serverApi.groupGet(model).group;
        _treeVerifier.verify(group, scope, environment);
    }
    // The hash binds the seat to a user id, not to this caller: every climb starts there and every commit signs as it.
    if (keytree::GroupKeyResolver::ownUserId(group) != _connection.getImpl()->getMyUserId(group.contextId)) {
        throw GroupDataIntegrityException("the caller was served somebody else's seat");
    }
    return true;
}

keytree::TreeVerifier::Environment GroupApiImpl::treeEnvironment(const std::string& groupId) {
    keytree::TreeVerifier::Environment environment;
    environment.verifyUsers = [this](const std::vector<core::VerificationRequest>& requests) {
        return _connection.getImpl()->getUserVerifier()->verify(requests);
    };
    // One page: the bridge answers at most 256 statements a call, and the verifier asks again from where it stopped.
    environment.commitsBetween = [this, groupId](std::uint64_t fromSeq, std::uint64_t toSeq) {
        return _serverApi
            .groupGetTreeCommits(
                server::GroupGetTreeCommitsModel{
                    .groupId = groupId,
                    .fromSeq = static_cast<std::int64_t>(fromSeq),
                    .toSeq = static_cast<std::int64_t>(toSeq)
                }
            );
    };
    return environment;
}

std::uint64_t GroupApiImpl::commitDate() {
    return static_cast<std::uint64_t>(privmx::utils::Utils::getNowTimestamp());
}

void GroupApiImpl::chainTo(keytree::CommitStatement& statement, const server::GroupInfo& group) {
    _treeVerifier.assertMaySignAt(group.id, statement.seq);
    const keytree::CommitStatement previous = keytree::TreeCommits::fromWire(group.treeCommit.value());
    statement.prevDigest = keytree::TreeCommits::digest(previous);
    // A clock behind the last committer's signs its date. The bridge takes a date equal to the previous one even
    // past its tolerance, so this never freezes (N-1); keep the max: the exception is equality, not "anything later".
    statement.date = std::max(statement.date, previous.date);
}

void GroupApiImpl::submit(
    const std::string& groupId,
    const keytree::CommitStatement& statement,
    const std::function<void()>& send
) {
    try {
        send();
    } catch (const privmx::utils::PrivmxException& e) {
        // The bridge's word that a concurrent commit took this seq; it may have applied ours all the same.
        if (isRetryableCommitRejection(e)) {
            _treeVerifier.refusedAsLostRace(groupId, statement.seq);
        }
        throw;
    }
}

privmx::endpoint::group::server::GroupGetKeyArchiveResult GroupApiImpl::fetchKeyArchive(
    const server::GroupInfo& group,
    int64_t targetEpoch,
    int64_t currentEpoch
) {
    server::GroupGetKeyArchiveModel params;
    params.id = group.id;
    params.fromKeyVersion = targetEpoch;
    params.toKeyVersion = currentEpoch;
    // `keyHistory` and a rung's `author` are the bridge's word; the statements are the members'.
    return keytree::GroupKeyResolver::authenticated(
        _serverApi.groupGetKeyArchive(params),
        _treeVerifier.epochOpeners(group.id, group.contextId, treeEnvironment(group.id))
    );
}

std::string GroupApiImpl::describeResolveFailure(const keytree::ResolveResult& resolved) {
    switch (resolved.failure) {
    case keytree::ResolveFailure::NoTree:
        return "Group key unavailable: group has no key tree";
    case keytree::ResolveFailure::UnsupportedTreeVersion:
        return "Group key unavailable: the group's key tree has a version this client does not support";
    case keytree::ResolveFailure::FutureEpoch:
        return "Group key unavailable: the requested epoch has not happened yet";
    case keytree::ResolveFailure::InvalidEpoch:
        return "Group key unavailable: the requested epoch is out of range";
    case keytree::ResolveFailure::ClimbFailed:
        if (resolved.climb == keytree::ClimbFailure::Tampered) {
            return "Group key tree verification failed: a node key does not match the published public key" +
                (resolved.blame.has_value() ? " (wrapped by " + resolved.blame.value() + ")" : "");
        }
        if (resolved.climb == keytree::ClimbFailure::NotAMember) {
            return "Group key unavailable: caller holds no leaf in the key tree";
        }
        if (resolved.climb == keytree::ClimbFailure::DecryptFailed) {
            return "Group key unavailable: a key tree edge does not open" +
                (resolved.blame.has_value() ? " (wrapped by " + resolved.blame.value() + ")" : "");
        }
        return "Group key unavailable: the key tree could not be climbed";
    case keytree::ResolveFailure::DescentFailed:
        switch (resolved.descent) {
        case keytree::DescentFailure::EraBoundary:
            return "History before this era is not available to you";
        case keytree::DescentFailure::Pruned:
            return "History this old has been pruned and is no longer recoverable";
        case keytree::DescentFailure::Tampered:
            return "Epoch ladder verification failed" +
                (resolved.blame.has_value() ? " (rung published by " + resolved.blame.value() + ")" : "");
        default:
            return "Group key unavailable: the epoch ladder could not be descended";
        }
    default:
        return "Group key unavailable";
    }
}

// -- envelopes -------------------------------------------------------------------------------------------

std::vector<core::server::GroupKeysEntry> GroupApiImpl::filterToKeyId(
    const std::vector<core::server::GroupKeysEntry>& all,
    const std::string& groupId,
    const std::string& keyId
) {
    std::vector<core::server::GroupKeysEntry> filtered;
    for (const auto& entry : all) {
        if (entry.group != groupId) {
            continue;
        }
        core::server::GroupKeysEntry kept;
        kept.group = entry.group;
        for (const auto& key : entry.keys) {
            if (key.keyId == keyId) {
                kept.keys.push_back(key);
            }
        }
        if (!kept.keys.empty()) {
            filtered.push_back(kept);
        }
    }
    return filtered;
}

bool GroupApiImpl::wrappedByEpochOpener(
    const std::vector<core::server::GroupKeysEntry>& routes,
    const std::string& wrappedBy,
    const std::map<std::uint64_t, keytree::CommitStatement>& openers
) {
    for (const auto& route : routes) {
        for (const auto& key : route.keys) {
            const auto opener = openers.find(static_cast<std::uint64_t>(key.groupEpoch.value_or(0)));
            if (opener != openers.end() && opener->second.committer == wrappedBy) {
                return true;
            }
        }
    }
    return false;
}

std::string GroupApiImpl::memoKeyFor(const std::string& groupId, const std::string& suffix) {
    // Length-prefixed rather than joined by a separator: `validateId` bounds a groupId's length but not its
    // characters, so a plain join would let one pair collide with another under a different split.
    return std::to_string(groupId.size()) + ":" + groupId + suffix;
}

core::DecryptedEncKeyV2 GroupApiImpl::encKeyById(const std::string& groupId, const std::string& keyId) {
    const std::string memoKey = memoKeyFor(groupId, keyId);
    if (auto cached = _envelopeKeys.get(memoKey); cached.has_value()) {
        return cached.value();
    }

    // Whatever an earlier `getGroup` or `encrypt` on this group already put in the key cache. Reading it
    // costs nothing; only a keyId we have never seen forces a fetch.
    core::ModuleKeys moduleKeys = getModuleKeys(groupId);
    auto candidates = filterToKeyId(moduleKeys.groupKeys, groupId, keyId);
    if (candidates.empty()) {
        moduleKeys = getNewModuleKeysAndUpdateCache(groupId);
        candidates = filterToKeyId(moduleKeys.groupKeys, groupId, keyId);
    }
    if (candidates.empty()) {
        throw core::EncryptionKeyValidationException("Group " + groupId + " publishes no key " + keyId);
    }

    core::KeyDecryptionAndVerificationRequest request;
    const auto location = core::EncKeyLocation{
        .contextId = moduleKeys.contextId, .resourceId = moduleKeys.moduleResourceId
    };
    request.addGroupKeys(candidates, location);
    const auto byLocation = _keyProvider->getKeysAndVerify(request, _groupPrivKeyResolver);

    const auto atLocation = byLocation.find(location);
    if (atLocation == byLocation.end() || atLocation->second.count(keyId) == 0) {
        throw core::EncryptionKeyValidationException("Group key " + keyId + " could not be resolved");
    }
    const core::DecryptedEncKeyV2 found = atLocation->second.at(keyId);
    if (found.statusCode != 0) {
        // `findEncKeyByKeyId` and friends hand back entries whose decryption failed; unchecked, the empty key
        // surfaces as a cipher length complaint instead of the real cause, usually an era boundary.
        throw core::EncryptionKeyValidationException(
            "Group key " + keyId + " could not be decrypted (status " + std::to_string(found.statusCode) + ")"
        );
    }
    // The head key's wrapper was checked against the roster by the verified read the module keys came from; an
    // earlier epoch's against who opened it, or a member envelope could come from anybody in the context.
    if (keyId != moduleKeys.currentKeyId &&
        !wrappedByEpochOpener(
            candidates, found.dio.creatorUserId,
            _treeVerifier.epochOpeners(groupId, moduleKeys.contextId, treeEnvironment(groupId))
        )) {
        throw core::EncryptionKeyValidationException("Group key " + keyId + " was not wrapped by its epoch's opener");
    }
    _envelopeKeys.set(memoKey, found);
    return found;
}

core::DecryptedEncKeyV2 GroupApiImpl::currentEncKey(const std::string& groupId) {
    core::ModuleKeys keys = getModuleKeys(groupId);
    // A cached head behind the epoch verified since (a read for a key, a commit of our own) is re-read, not refused.
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

    return _envelopeEncryptor.openAnonymousEnvelope(envelope, grantKeyForPubKey(routing.groupId, routing.groupPubKey));
}

privmx::crypto::PrivateKey GroupApiImpl::grantKeyForPubKey(
    const std::string& groupId,
    const std::string& groupPubKeyBase58
) {
    // A published grant public key's epoch is immutable, so the lookup is memoized like `_envelopeKeys`.
    // Without it every anonymous envelope pays a `groupGet` here on top of `resolveGroupPrivKey`'s.
    const std::string memoKey = memoKeyFor(groupId, groupPubKeyBase58);
    if (auto cached = _envelopeGrantEpochs.get(memoKey); cached.has_value()) {
        return resolveGroupPrivKey(groupId, cached.value());
    }

    auto group = _serverApi.groupGet(pathRead(groupId)).group;
    auto target = privmx::crypto::PublicKey::fromBase58DER(groupPubKeyBase58);
    // `keyHistory` is the bridge's word: only an epoch whose own key turns out to be the target is remembered.
    for (const auto& entry : keytree::GroupKeyResolver::registryFromGroupHistory(group)) {
        if (entry.grantPublicKey == target) {
            const privmx::crypto::PrivateKey key = resolveGroupPrivKey(groupId, entry.epoch);
            if (key.getPublicKey() == target) {
                _envelopeGrantEpochs.set(memoKey, entry.epoch);
                return key;
            }
        }
    }
    throw InvalidEnvelopeFormatException("envelope names a group key that is not in this group's history");
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

namespace {
constexpr const char* NOT_AN_OPEN_FILE_HANDLE = "field:fileHandle is not an open encrypted-file handle";

// For a call holding the handle's lock: a finish that won the lock first has closed it.
EnvelopeFileState& openState(EnvelopeFile& file) {
    if (file.state.closed) {
        throw core::InvalidParamsException(NOT_AN_OPEN_FILE_HANDLE);
    }
    return file.state;
}
} // namespace

// `reading` never changes after construction, so it is checked here without the handle's lock.
std::shared_ptr<EnvelopeFile> GroupApiImpl::getFileState(FileHandle fileHandle, bool wantReading) {
    auto file = _envelopeFiles.get(fileHandle);
    if (!file.has_value()) {
        throw core::InvalidParamsException(NOT_AN_OPEN_FILE_HANDLE);
    }
    if (file.value()->state.reading != wantReading) {
        throw core::InvalidParamsException(
            wantReading ? "field:fileHandle came from beginFileEncryption, not beginFileDecryption" :
                          "field:fileHandle came from beginFileDecryption, not beginFileEncryption"
        );
    }
    return file.value();
}

void GroupApiImpl::releaseFileHandle(FileHandle fileHandle) {
    _envelopeFiles.erase(fileHandle);
    // Both, always. Dropping only the local entry leaks the id in HandleManager's map for the process
    // lifetime — the pair Store's FileHandleManager keeps together for the same reason.
    _connection.getImpl()->getHandleManager()->removeHandle(fileHandle);
}

// A chunk's sealed length follows from the declared size, so both directions work at arbitrary caller-chosen
// block sizes. Declaring the size up front is what distinguishes a short final chunk from one still arriving.
core::Buffer GroupApiImpl::drainChunks(EnvelopeFileState& state) {
    const ByteCount chunks = GroupEnvelopeEncryptor::chunkCount(state.plainSize);
    std::string out;
    while (state.index < chunks) {
        const ByteCount plainLen = GroupEnvelopeEncryptor::plainChunkSizeAt(state.plainSize, state.index);
        const ByteCount need = state.reading ? encryptedChunkSizeFor(plainLen) : plainLen;
        if (state.buffer.size() < need) {
            break;
        }
        core::Buffer piece = core::Buffer::from(state.buffer.substr(0, need));
        std::string produced = (state.reading ? _envelopeEncryptor.decryptChunk(piece, state.fileKey, state.index) :
                                                _envelopeEncryptor.encryptChunk(piece, state.fileKey, state.index))
                                   .stdString();
        if (state.skipInChunk > 0) {
            // A seek can land mid-chunk, but a chunk only opens whole. Drop the head the caller did not ask
            // for, once, on the first chunk after the seek.
            produced.erase(0, std::min<std::size_t>(state.skipInChunk, produced.size()));
            state.skipInChunk = 0;
        }
        out.append(produced);
        state.buffer.erase(0, need);
        state.index++;
    }
    // Past the last chunk nothing drains, so leftovers only grow. Refused here rather than at the close, or a
    // long ciphertext against a short declared size buffers the whole remainder first. Seeked readers included.
    if (state.reading && state.index >= chunks && !state.buffer.empty()) {
        throw InvalidEnvelopeFormatException("more file data than the declared size accounts for");
    }
    return core::Buffer::from(out);
}

FileHandle GroupApiImpl::beginFileEncryption(const std::string& groupId, FileSize size) {
    auto key = currentEncKey(groupId);
    FileHandle handle = _connection.getImpl()->getHandleManager()->createHandle("GroupEnvelope:Encrypt");
    auto file = std::make_shared<EnvelopeFile>();
    file->state = EnvelopeFileState{
        .reading = false,
        .type = ENVELOPE_FROM_MEMBER,
        .groupId = groupId,
        .keyId = key.id,
        .groupKey = key.key,
        // Per file, so a chunk lifted from one file is useless in any other.
        .fileKey = privmx::crypto::Crypto::randomBytes(32),
        .index = 0,
        .plainSize = static_cast<ByteCount>(size),
    };
    _envelopeFiles.set(handle, file);
    return handle;
}

FileHandle GroupApiImpl::beginFileEncryptionAnonymously(
    const std::string& groupId,
    const std::string& groupPubKey,
    FileSize size
) {
    // No server call and no membership, exactly like `encryptAnonymously`. The public key is enough to seal
    // to, and the envelope is not built until the finish, so nothing here needs the group's own key.
    privmx::crypto::PublicKey::fromBase58DER(groupPubKey); // reject a malformed key now, not at the finish
    FileHandle handle = _connection.getImpl()->getHandleManager()->createHandle("GroupEnvelope:EncryptAnonymous");
    auto file = std::make_shared<EnvelopeFile>();
    file->state = EnvelopeFileState{
        .reading = false,
        .type = ENVELOPE_ANONYMOUS,
        .groupId = groupId,
        .groupPubKey = groupPubKey,
        .fileKey = privmx::crypto::Crypto::randomBytes(32),
        .index = 0,
        .plainSize = static_cast<ByteCount>(size),
    };
    _envelopeFiles.set(handle, file);
    return handle;
}

core::Buffer GroupApiImpl::encryptFileChunk(FileHandle fileHandle, const core::Buffer& plainChunk) {
    auto file = getFileState(fileHandle, false);
    std::lock_guard lock(file->mutex);
    EnvelopeFileState& state = openState(*file);
    if (state.written + plainChunk.size() > state.plainSize) {
        throw core::InvalidParamsException("field:plainChunk would exceed the declared file size");
    }
    state.written += plainChunk.size();
    state.buffer.append(plainChunk.stdString());
    return drainChunks(state);
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
            envelope, grantKeyForPubKey(routing.groupId, routing.groupPubKey)
        );
    }

    FileHandle handle = _connection.getImpl()->getHandleManager()->createHandle("GroupEnvelope:Decrypt");
    auto file = std::make_shared<EnvelopeFile>();
    file->state = EnvelopeFileState{
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
    };
    _envelopeFiles.set(handle, file);
    return handle;
}

core::Buffer GroupApiImpl::decryptFileChunk(FileHandle fileHandle, const core::Buffer& cipherChunk) {
    auto file = getFileState(fileHandle, true);
    std::lock_guard lock(file->mutex);
    EnvelopeFileState& state = openState(*file);
    state.buffer.append(cipherChunk.stdString());
    return drainChunks(state);
}

CipherOffset GroupApiImpl::seekInEncryptedFile(FileHandle fileHandle, FilePosition position) {
    auto file = getFileState(fileHandle, true);
    std::lock_guard lock(file->mutex);
    EnvelopeFileState& state = openState(*file);
    if (position < 0 || static_cast<ByteCount>(position) > state.plainSize) {
        throw core::InvalidParamsException("field:position is outside the file");
    }
    const ByteCount target = static_cast<ByteCount>(position);
    state.index = static_cast<ChunkIndex>(target / GroupEnvelopeEncryptor::CHUNK_SIZE);
    state.skipInChunk = target % GroupEnvelopeEncryptor::CHUNK_SIZE;
    // Whatever was half-collected belonged to the old position.
    state.buffer.clear();
    // From here on the caller decides what to read, so "did all of it arrive" is a question this handle can
    // no longer answer. `finishFileDecryption` reports that rather than pretending otherwise.
    state.seeked = true;
    return static_cast<int64_t>(GroupEnvelopeEncryptor::cipherOffsetOfChunk(state.index));
}

EnvelopeFileState GroupApiImpl::finishFile(FileHandle fileHandle, bool wantReading) {
    auto file = getFileState(fileHandle, wantReading);
    std::lock_guard lock(file->mutex);
    EnvelopeFileState& state = openState(*file);
    // Closed whatever the outcome, so neither a second finish nor a chunk call still waiting for the lock
    // touches the state after this one.
    state.closed = true;
    // Free the handle however this ends, rather than hold a key resident because a file turned out short.
    // `Release` takes only the map and HandleManager locks; nothing takes those and then a file lock.
    struct Release {
        GroupApiImpl* self;
        int64_t handle;
        // This destructor exists to run during exception unwinding, so it must not throw out of one.
        ~Release() {
            try {
                self->releaseFileHandle(handle);
            } catch (...) {}
        }
    } release{this, fileHandle};

    switch (GroupEnvelopeEncryptor::classifyRead(
        state.seeked, state.index, GroupEnvelopeEncryptor::chunkCount(state.plainSize), state.buffer.empty()
    )) {
    case GroupEnvelopeEncryptor::ReadOutcome::Truncated:
        // Every chunk authenticates itself, but nothing in chunk N says how many were meant to follow. The
        // declared size is the only place a dropped tail — or an unfinished write — shows up.
        throw EnvelopeTruncatedFileException();
    case GroupEnvelopeEncryptor::ReadOutcome::Overrun:
        // Every chunk the declared size called for arrived, and then more followed. `drainChunks` refuses
        // those as they arrive; this catches the caller who swallowed that and closed anyway.
        throw InvalidEnvelopeFormatException("more file data than the declared size accounts for");
    case GroupEnvelopeEncryptor::ReadOutcome::PartialRange:
    case GroupEnvelopeEncryptor::ReadOutcome::Complete:
        break;
    }
    // Moved, not copied, so the keys are not duplicated; `closed` (a bool, copied) stays set for anyone still
    // holding `file`.
    return std::move(state);
}

Envelope GroupApiImpl::finishFileEncryption(FileHandle fileHandle) {
    auto state = finishFile(fileHandle, false);
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
    auto state = finishFile(fileHandle, true);
    return DecryptedFileInfo{
        .groupId = state.groupId,
        .authorPubKey = state.authorPubKey,
        .type = state.type,
        .complete = !state.seeked,
    };
}
