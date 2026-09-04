#include <algorithm>

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
#include "privmx/endpoint/group/GroupApiImpl.hpp"
#include "privmx/endpoint/group/GroupException.hpp"
#include "privmx/endpoint/group/Mapper.hpp"
#include "privmx/endpoint/group/ServerTypes.hpp"
#include "privmx/endpoint/group/keytree/LadderKeys.hpp"
#include "privmx/endpoint/group/keytree/TreeMath.hpp"
#include "privmx/endpoint/group/keytree/TreeWire.hpp"
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
    : ModuleBaseApi(userPrivKey, keyProvider, host, eventMiddleware, connection), _gateway(gateway),
      _userPrivKey(userPrivKey), _keyProvider(keyProvider), _host(host), _eventMiddleware(eventMiddleware),
      _connection(connection), _serverApi(ServerApi(gateway)), _subscriber(gateway),
      _groupDataSchemaMapper(std::make_shared<GroupDataSchemaMapper>(userPrivKey, connection)) {
    initGroupResolvers(
        core::ModuleBaseApi::GroupResolvers{
            // Resolves a group's own grant key by climbing its own tree — swallows a failed climb to nullopt.
            .groupPrivKey =
                [this](const std::string& groupId, int64_t epoch) -> std::optional<privmx::crypto::PrivateKey> {
                try {
                    return resolveGroupPrivKey(groupId, epoch);
                } catch (...) {
                    // caller holds no leaf in this group's tree at this epoch — skip
                    return std::nullopt;
                }
            },
            .groupEpochs = [this](
                               const std::string& contextId, const std::vector<std::string>& groupIds
                           ) { return fetchGroupEpochs(contextId, groupIds); }
        }
    );
    initModuleDataSchemaMapper(_groupDataSchemaMapper);
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
}

static void rejectConflictingRosterKey(const std::string& userId) {
    throw core::InvalidParamsException("user '" + userId + "' is listed with two different public keys");
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

/** The verified head's roster, as bare ids — `prepareContainerUpdate` diffs names, it does not wrap to them. */
GroupApiImpl::RosterAfterChange GroupApiImpl::rosterOf(const Group& verified) {
    RosterAfterChange roster;
    for (const std::string& userId : verified.users) {
        roster.users.push_back(core::UserWithPubKey{.userId = userId, .pubKey = std::string()});
    }
    for (const std::string& managerId : verified.managers) {
        roster.managers.push_back(core::UserWithPubKey{.userId = managerId, .pubKey = std::string()});
    }
    return roster;
}

/** Public keys for exactly these members, from the Context user list. One listing round trip per 100 of them. */
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
    const std::shared_ptr<keytree::TreeKeyCache>& cache
) {
    if (!keytree::GroupKeyResolver::hasTree(group)) {
        throw core::EncryptionKeyValidationException("this group is not backed by a key tree");
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
        throw core::EncryptionKeyValidationException(describeResolveFailure(asResolve));
    }
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
    // Empty rosters: the metadata key is wrapped once to the group's own grant key, and members open it by climbing.
    auto ctx = prepareContainerCreate(contextId, {}, {});

    const std::vector<keytree::TreeMember> members = toTreeMembers(users, managers);
    keytree::TreeKeyCache scratch; // the group has no id yet
    keytree::TreeKeys builder(scratch);
    const keytree::BuildPlan plan = builder.build(members, _userPrivKey);
    const std::string groupPubKeyStr = plan.grantKey.getPublicKey().toBase58DER();

    dynamic::MembershipBlock membership{
        .rosterTag = GroupDataSchemaMapper::rosterTag(
            ctx.key.key, 1, 1, core::EndpointUtils::usersWithPubKeyToIds(users),
            core::EndpointUtils::usersWithPubKeyToIds(managers)
        ),
        .groupPubKey = groupPubKeyStr,
        .keyId = ctx.key.id,
        .keyVersion = 1
    };

    GroupDataToEncryptV5 dataToEncrypt{
        .publicMeta = publicMeta,
        .privateMeta = privateMeta,
        .internalMeta = core::
            ModuleInternalMetaV5{.secret = ctx.secret, .resourceId = ctx.resourceId, .randomId = ctx.dio.randomId},
        .dio = ctx.dio,
        .groupPrivKey = std::string(),
        .membership = membership
    };

    server::GroupCreateModel model;
    model.resourceId = ctx.resourceId;
    model.contextId = contextId;
    model.keyId = ctx.key.id;
    model.data = _groupDataSchemaMapper->encrypt(dataToEncrypt, ctx.key.key);
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
    model.tree = keytree::TreeWire::fromBuildPlan(plan, members);
    if (policies.has_value()) {
        model.policy = core::Factory::createPolicyServerObject(policies.value());
    }

    auto result = _serverApi.groupCreate(model);
    const auto cache = _treeKeyCaches.get(result.groupId);
    cache->putGrantKey(1, plan.grantKey);
    for (const auto& minted : plan.nodeKeys) {
        cache->putNodeKey(minted.first, 0, minted.second);
    }
    return result.groupId;
}

void GroupApiImpl::addGroupMembers(const std::string& groupId, const std::vector<GroupMemberToAdd>& newMembers) {
    // One read, not two. The bridge holds the roster, so it allocates the seats and serves the nodes seating them
    // needs in the same answer — where this used to fetch `leafAssignment` only to work out where a newcomer may
    // sit, then come back for the window around that seat.
    server::GroupGetModel getModel{
        .groupId = groupId,
        .type = {},
        .scope = {},
        .forUserIds = {},
        .forNewMembers = static_cast<std::int64_t>(newMembers.size()),
        .fromVersion = {}
    };
    auto currentGroup = _serverApi.groupGet(getModel).group;
    const auto& currentEntry = currentGroup.data.back();
    const auto resourceId = currentGroup.resourceId.value_or(core::EndpointUtils::generateId());
    const int64_t currentEpoch = currentGroup.keyVersion.value_or(1);

    // Verifies the chain and decrypts the head in one pass. Both halves are needed: the roster this call signs
    // has to be the one the signed history proves, not one the caller restated or the bridge asserted; and the
    // metadata carries through untouched, because seating a member is not a metadata edit.
    const Group verified = _groupDataSchemaMapper->validateDecryptAndConvertGroup(
        currentGroup, _keyProvider, _groupPrivKeyResolver
    );

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
    std::map<std::uint32_t, std::uint32_t> previousGenerations;
    for (const keytree::TreeNodeState& node : state.nodes) {
        previousGenerations[node.nodeIndex] = node.generation;
    }

    keytree::TreeKeys tree(*cache);
    // Only the leaves the re-keying actually wraps to — `O(k log n)` of the roster, one listing round trip.
    const std::uint32_t grown = keytree::TreeMath::numLeavesToSeatAll(positions, state.numLeaves);
    tree.setMemberKeyStrings(
        resolveMemberKeys(currentGroup.contextId, keytree::TreeKeys::membersToWrapTo(state, positions, grown))
    );
    std::vector<keytree::TreeMember> treeNewcomers;
    for (const GroupMemberToAdd& newMember : newMembers) {
        treeNewcomers.push_back(
            keytree::TreeMember{newMember.user.userId, privmx::crypto::PublicKey::fromBase58DER(newMember.user.pubKey)}
        );
    }
    const keytree::AdditionPlan plan = planOrThrow<keytree::AdditionPlan>([&] {
        return tree.planAddition(state, treeNewcomers, positions, _userPrivKey);
    });
    for (const auto& [nodeIndex, nodeKey] : plan.nodeKeys) {
        const auto minted = std::find_if(plan.nodes.begin(), plan.nodes.end(), [&](const keytree::TreeNodeState& n) {
            return n.nodeIndex == nodeIndex;
        });
        if (minted != plan.nodes.end()) {
            cache->putNodeKey(nodeIndex, minted->generation, nodeKey);
        }
    }

    // The roster after the change, derived rather than restated. Bare ids: with `distributeToUsers = false`
    // nothing here wraps a key to them, so the public keys the caller used to supply were never read.
    RosterAfterChange roster = rosterOf(verified);
    for (const GroupMemberToAdd& newMember : newMembers) {
        (newMember.role == "manager" ? roster.managers : roster.users)
            .push_back(core::UserWithPubKey{.userId = newMember.user.userId, .pubKey = std::string()});
    }

    // No new epoch, `distributeToUsers = false`
    auto ctx = prepareContainerUpdate(
        currentGroup, currentEntry, resourceId, roster.users, roster.managers, false, false, _groupPrivKeyResolver
    );
    dynamic::MembershipBlock membership{
        .rosterTag = GroupDataSchemaMapper::rosterTag(
            ctx.key.key, currentEpoch, currentGroup.version + 1,
            core::EndpointUtils::usersWithPubKeyToIds(roster.users),
            core::EndpointUtils::usersWithPubKeyToIds(roster.managers)
        ),
        .groupPubKey = currentGroup.groupPubKey,
        .keyId = ctx.key.id,
        .keyVersion = currentEpoch
    };

    GroupDataToEncryptV5 dataToEncrypt{
        // Carried through, not taken as a parameter: a membership change must not silently rewrite the group's
        // metadata. `updateGroup` is where that happens.
        .publicMeta = verified.publicMeta,
        .privateMeta = verified.privateMeta,
        .internalMeta = core::
            ModuleInternalMetaV5{.secret = ctx.secret, .resourceId = resourceId, .randomId = ctx.dio.randomId},
        .dio = ctx.dio,
        .groupPrivKey = std::string(),
        .membership = membership
    };

    server::GroupAddMembersModel model;
    model.id = groupId;
    for (const GroupMemberToAdd& newMember : newMembers) {
        model.members.push_back(server::GroupAddMemberEntry{.userId = newMember.user.userId, .role = newMember.role});
    }
    model.keyId = ctx.key.id;
    model.data = _groupDataSchemaMapper->encrypt(dataToEncrypt, ctx.key.key);
    model.transition = keytree::TreeWire::toAdditionTransition(plan, previousGenerations, currentEpoch);
    model.expectedKeyVersion = currentEpoch;

    try {
        _serverApi.groupAddMembers(model);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
    // No tree-key invalidation and the epoch and grant keypair did not move.
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
        group.id, static_cast<int64_t>(targets.back()), static_cast<int64_t>(newEpoch - 1)
    );
    const std::uint32_t eraFloor = static_cast<std::uint32_t>(archive.eraFloor);
    const std::optional<std::uint32_t> prunedBelow = asEpoch(archive.archivePrunedBelow);

    const keytree::RungKeyGathering gathered = ladder.gatherRungKeys(
        newEpoch, keytree::GroupKeyResolver::toDownwardRungs(archive),
        keytree::GroupKeyResolver::toRegistry(group, archive), eraFloor, prunedBelow
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
    // Every departing member's path, because one delta covers their union — and one epoch covers the batch, where
    // removing them one at a time would stale every container the group can read once per member.
    server::GroupGetModel getModel{
        .groupId = groupId, .type = {}, .scope = {}, .forUserIds = userIds, .forNewMembers = {}, .fromVersion = {}
    };
    auto currentGroup = _serverApi.groupGet(getModel).group;
    const auto& currentEntry = currentGroup.data.back();
    const auto resourceId = currentGroup.resourceId.value_or(core::EndpointUtils::generateId());
    const int64_t currentEpoch = currentGroup.keyVersion.value_or(1);
    const int64_t newEpoch = currentEpoch + 1;
    const Group verified = _groupDataSchemaMapper->validateDecryptAndConvertGroup(
        currentGroup, _keyProvider, _groupPrivKeyResolver
    );

    const auto cache = _treeKeyCaches.get(groupId);
    const keytree::TreeGroupState state = climbForPlanning(currentGroup, cache);
    const auto currentGrantKey = cache->getGrantKey(static_cast<std::uint32_t>(currentEpoch));

    // Handle for the whole operation
    keytree::TreeKeys tree(*cache);
    // The surviving siblings' public keys: not part of the tree state, and a refresh that skipped one would
    // silently lock that member out. Only the leaves beside the refreshed frontier, and never the departing
    // members — nobody wraps to them, and looking them up would fail if they have already left the context.
    std::vector<std::uint32_t> leavingSeats;
    std::set<std::uint32_t> leavingSeatSet;
    for (const std::string& gone : userIds) {
        const auto seat = keytree::TreeKeys::positionOf(state, gone);
        if (!seat.has_value()) {
            throw core::EncryptionKeyValidationException("member " + gone + " holds no leaf in this group");
        }
        leavingSeats.push_back(seat.value());
        leavingSeatSet.insert(seat.value());
    }
    tree.setMemberKeyStrings(resolveMemberKeys(
        currentGroup.contextId, keytree::TreeKeys::membersToWrapTo(state, leavingSeats, state.numLeaves, leavingSeatSet)
    ));
    const keytree::RemovalPlan plan = planOrThrow<keytree::RemovalPlan>([&] {
        return tree.planRemoval(state, userIds, _userPrivKey);
    });
    const std::vector<keytree::ArchiveRung> rungs = buildRotationRungs(
        currentGroup, static_cast<std::uint32_t>(newEpoch), plan.newGrantKey.getPublicKey(), currentGrantKey,
        keytree::GroupKeyResolver::ownUserId(currentGroup).value_or(std::string()), *cache
    );
    // The roster that remains, derived from the verified head rather than restated by the caller.
    const std::set<std::string> leaving(userIds.begin(), userIds.end());
    RosterAfterChange roster = rosterOf(verified);
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

    auto ctx = prepareContainerUpdate(
        currentGroup, currentEntry, resourceId, roster.users, roster.managers, true, false, _groupPrivKeyResolver
    );
    const auto selfAddressedKey = buildGroupKeyEntries(
        {core::GroupGrantWithKey{
            .groupId = groupId,
            .role = "manager",
            .groupPubKey = plan.newGrantKey.getPublicKey().toBase58DER(),
            .groupEpoch = newEpoch,
        }},
        ctx.key, ctx.dio, currentGroup.contextId, resourceId, ctx.secret
    );

    const std::string newGroupPubKeyStr = plan.newGrantKey.getPublicKey().toBase58DER();
    dynamic::MembershipBlock membership{
        .rosterTag = GroupDataSchemaMapper::rosterTag(
            ctx.key.key, newEpoch, currentGroup.version + 1, core::EndpointUtils::usersWithPubKeyToIds(roster.users),
            core::EndpointUtils::usersWithPubKeyToIds(roster.managers)
        ),
        .groupPubKey = newGroupPubKeyStr,
        .keyId = ctx.key.id,
        .keyVersion = newEpoch
    };

    GroupDataToEncryptV5 dataToEncrypt{
        // Carried through: removing a member is not a metadata edit either.
        .publicMeta = verified.publicMeta,
        .privateMeta = verified.privateMeta,
        .internalMeta = core::
            ModuleInternalMetaV5{.secret = ctx.secret, .resourceId = resourceId, .randomId = ctx.dio.randomId},
        .dio = ctx.dio,
        .groupPrivKey = std::string(),
        .membership = membership
    };

    // Seats come from the plan, which resolved them from the roster the bridge served. `subjectLeafPositions`
    // carries the same answer; keeping the plan as the single source stops the two from ever disagreeing.
    server::GroupRemoveMembersModel model;
    model.id = groupId;
    model.userIds = userIds;
    model.groupPubKey = newGroupPubKeyStr;
    model.keyId = ctx.key.id;
    model.data = _groupDataSchemaMapper->encrypt(dataToEncrypt, ctx.key.key);
    model.transition = keytree::TreeWire::toRemovalTransition(
        keytree::TreeWire::fromGroupInfo(currentGroup), plan, currentEpoch
    );
    model.rungs = keytree::TreeWire::toWire(rungs);
    model.groupKeys = selfAddressedKey.at(0);
    model.expectedKeyVersion = currentEpoch;
    const auto confInput = std::string("confirm") + groupId + std::to_string(newEpoch) + ctx.key.id;
    model.confirmationTag = privmx::utils::Hex::from(privmx::crypto::Crypto::hmacSha256(ctx.key.key, confInput));

    try {
        _serverApi.groupRemoveMembers(model);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
    cache->clearNodeKeys();
    cache->putGrantKey(static_cast<std::uint32_t>(newEpoch), plan.newGrantKey);
    invalidateModuleKeysInCache(groupId);
}

static constexpr unsigned int BRIDGE_GROUP_ROTATED_ALREADY = 0x621C;

void GroupApiImpl::updateGroup(
    const std::string& groupId,
    const core::Buffer& publicMeta,
    const core::Buffer& privateMeta,
    const int64_t version,
    const bool force,
    const std::optional<core::ContainerPolicy>& policies,
    bool allowRotationRetry
) {
    // The default path view is enough: this submits no tree, and the roster it re-signs is the one it reads back.
    server::GroupGetModel getModel{
        .groupId = groupId, .type = {}, .scope = {}, .forUserIds = {}, .forNewMembers = {}, .fromVersion = {}
    };
    auto currentGroup = _serverApi.groupGet(getModel).group;
    const auto& currentEntry = currentGroup.data.back();
    const auto resourceId = currentGroup.resourceId.value_or(core::EndpointUtils::generateId());
    int64_t currentEpoch = currentGroup.keyVersion.value_or(0);

    auto currentDecryptedEncKey = getAndValidateModuleCurrentEncKey(currentGroup, _groupPrivKeyResolver);
    std::vector<core::UserWithPubKey> unchangedUsers;
    for (const auto& userId : currentGroup.users) {
        unchangedUsers.push_back(core::UserWithPubKey{.userId = userId, .pubKey = std::string()});
    }
    std::vector<core::UserWithPubKey> unchangedManagers;
    for (const auto& userId : currentGroup.managers) {
        unchangedManagers.push_back(core::UserWithPubKey{.userId = userId, .pubKey = std::string()});
    }
    auto ctx = prepareContainerUpdate(
        currentGroup, currentEntry, resourceId, unchangedUsers, unchangedManagers, false, false, _groupPrivKeyResolver
    );
    LOG_DEBUG("ctx.secret - ", ctx.secret)

    std::string newGroupPrivKeyStr;
    if (currentDecryptedEncKey.statusCode == 0) {
        newGroupPrivKeyStr = _groupDataSchemaMapper->getGroupPrivKey(currentGroup, currentDecryptedEncKey);
    }
    std::string newGroupPubKeyStr = currentGroup.groupPubKey;
    int64_t newEpoch = currentEpoch;

    dynamic::MembershipBlock membership{
        // Metadata only — but the tag still has to be re-issued, because it commits to the version and every
        // write moves it.
        .rosterTag = GroupDataSchemaMapper::rosterTag(
            ctx.key.key, newEpoch, currentGroup.version + 1, currentGroup.users, currentGroup.managers
        ),
        .groupPubKey = newGroupPubKeyStr,
        .keyId = ctx.key.id,
        .keyVersion = newEpoch
    };

    GroupDataToEncryptV5 dataToEncrypt{
        .publicMeta = publicMeta,
        .privateMeta = privateMeta,
        .internalMeta = core::
            ModuleInternalMetaV5{.secret = ctx.secret, .resourceId = resourceId, .randomId = ctx.dio.randomId},
        .dio = ctx.dio,
        .groupPrivKey = newGroupPrivKeyStr,
        .membership = membership
    };
    // Metadata only
    server::GroupUpdateModel model;
    model.id = groupId;
    model.resourceId = resourceId;
    model.keyId = ctx.key.id;
    model.version = version;
    model.force = force;
    model.data = _groupDataSchemaMapper->encrypt(dataToEncrypt, ctx.key.key);
    if (policies.has_value()) {
        model.policy = core::Factory::createPolicyServerObject(policies.value());
    }

    try {
        _serverApi.groupUpdate(model);
    } catch (const privmx::utils::PrivmxException& e) {
        if (allowRotationRetry && (e.getCode() & 0x0000FFFF) == BRIDGE_GROUP_ROTATED_ALREADY) {
            auto payload = server::RotatedAlreadyPayload::fromJSON(privmx::utils::Utils::parseJsonObject(e.getData()));
            adoptRotatedAlready(groupId, payload);
            updateGroup(groupId, publicMeta, privateMeta, version, force, policies, false);
            return;
        }
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
    // Rotates the metadata key but never the grant key or the tree.
    invalidateModuleKeysInCache(groupId);
}

void GroupApiImpl::deleteGroup(const std::string& groupId) {
    server::GroupDeleteModel model{.groupId = groupId};
    _serverApi.groupDelete(model);
    _treeKeyCaches.drop(groupId);
    invalidateModuleKeysInCache(groupId);
}

void GroupApiImpl::adoptRotatedAlready(const std::string& groupId, const server::RotatedAlreadyPayload& payload) {
    // Verifies the winner's key entry and nothing else — no tree is submitted, so the default path view is enough.
    server::GroupGetModel getModel{
        .groupId = groupId, .type = {}, .scope = {}, .forUserIds = {}, .forNewMembers = {}, .fromVersion = {}
    };
    auto updatedGroup = _serverApi.groupGet(getModel).group;

    std::vector<core::server::KeyEntry> winnerKeyVec{payload.winnerKeyEntry};
    core::KeyDecryptionAndVerificationRequest request;
    auto location = getModuleEncKeyLocation(updatedGroup, updatedGroup.resourceId);
    request.addOne(winnerKeyVec, payload.winnerKeyEntry.keyId, location);
    auto decrypted = _keyProvider->getKeysAndVerify(request);
    const auto& winnerGk = decrypted.at(location).at(payload.winnerKeyEntry.keyId);
    if (winnerGk.statusCode != 0) {
        throw GroupDataIntegrityException("RotatedAlready: winner's key entry failed verification");
    }

    // Without a tag there is nothing tying this epoch to a member: adopting it would mean re-wrapping against
    // whatever key the answer named. Refusing is the only safe direction — an epoch that cannot be checked is
    // not a smaller answer than one that can.
    if (!payload.confirmationTag.has_value()) {
        throw GroupDataIntegrityException("RotatedAlready: winner carries no confirmation tag to check");
    }
    auto confInput = std::string("confirm") +
        groupId +
        std::to_string(payload.keyVersion) +
        payload.winnerKeyEntry.keyId;
    auto expectedTag = privmx::utils::Hex::from(privmx::crypto::Crypto::hmacSha256(winnerGk.key, confInput));
    if (expectedTag != payload.confirmationTag.value()) {
        throw GroupDataIntegrityException("RotatedAlready: confirmation tag mismatch");
    }

    dropNodeKeysIfEpochAdvanced(groupId, static_cast<std::uint32_t>(payload.keyVersion));
    invalidateModuleKeysInCache(groupId);
}

Group GroupApiImpl::getGroup(const std::string& groupId) {
    server::GroupGetModel params{
        .groupId = groupId, .type = {}, .scope = {}, .forUserIds = {}, .forNewMembers = {}, .fromVersion = {}
    };
    // Only the part of the chain this client has not verified yet — each entry carries its whole roster, so
    // re-sending proved versions is the bulk of a read. `assertDataIntegrity` insists the window chains in.
    auto group = _serverApi.groupGet(params).group;
    setNewModuleKeysInCache(group.id, groupToModuleKeys(group), group.version);
    return _groupDataSchemaMapper->validateDecryptAndConvertGroup(group, _keyProvider, _groupPrivKeyResolver);
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
    }
    return core::PagingList<GroupSummary>({.totalAvailable = groupsList.count, .readItems = groups});
}

std::unordered_map<std::string, core::GroupEpochInfo> GroupApiImpl::fetchGroupEpochs(
    const std::string& contextId,
    const std::vector<std::string>& groupIds
) {
    std::unordered_map<std::string, core::GroupEpochInfo> epochs;
    constexpr size_t BATCH = 100; // The bridge listing caps at 100
    for (size_t offset = 0; offset < groupIds.size(); offset += BATCH) {
        std::vector<std::string> batch(
            groupIds.begin() + offset, groupIds.begin() + std::min(offset + BATCH, groupIds.size())
        );
        Poco::JSON::Array::Ptr ids = new Poco::JSON::Array();
        for (const auto& id : batch) {
            ids->add(id);
        }
        Poco::JSON::Object::Ptr in = new Poco::JSON::Object();
        in->set("$in", ids);
        Poco::JSON::Object::Ptr query = new Poco::JSON::Object();
        query->set("#id", in);
        core::PagingQuery pagingQuery{
            .skip = 0,
            .limit = static_cast<int64_t>(batch.size()),
            .sortOrder = "asc",
            .lastId = std::nullopt,
            .sortBy = std::nullopt,
            .queryAsJson = privmx::utils::Utils::stringify(query)
        };
        try {
            auto listed = listGroups(contextId, pagingQuery);
            for (const auto& summary : listed.readItems) {
                epochs[summary.groupId] = core::GroupEpochInfo{
                    .keyVersion = summary.keyVersion, .groupPubKey = summary.groupPubKey
                };
            }
        } catch (const std::exception& e) { LOG_WARN("[fetchGroupEpochs] groupList by id unavailable: ", e.what()) }
    }
    for (const auto& id : groupIds) {
        if (epochs.find(id) != epochs.end())
            continue;
        try {
            auto fetched = getGroup(id);
            epochs[id] = core::GroupEpochInfo{.keyVersion = fetched.keyVersion, .groupPubKey = fetched.groupPubKey};
        } catch (const std::exception& e) { LOG_WARN("[fetchGroupEpochs] cannot read group ", id, ": ", e.what()) }
    }
    return epochs;
}

core::ModuleBaseApi::GroupResolvers GroupApiImpl::makeGroupResolvers(
    const std::shared_ptr<GroupApiImpl>& groupApiImpl
) {
    return core::ModuleBaseApi::GroupResolvers{
        .groupPrivKey =
            [groupApiImpl](const std::string& groupId, int64_t epoch) -> std::optional<privmx::crypto::PrivateKey> {
            try {
                return groupApiImpl->resolveGroupPrivKey(groupId, epoch);
            } catch (...) {
                // not a member of this group at this epoch — skip
                return std::nullopt;
            }
        },
        .groupEpochs = [groupApiImpl](
                           const std::string& contextId, const std::vector<std::string>& groupIds
                       ) { return groupApiImpl->fetchGroupEpochs(contextId, groupIds); }
    };
}

std::optional<core::ModuleBaseApi::GroupResolvers> GroupApiImpl::makeGroupResolvers(
    const std::optional<GroupApi>& groupApi
) {
    if (!groupApi.has_value()) {
        return std::nullopt;
    }
    return makeGroupResolvers(groupApi->getImpl());
}

void GroupApiImpl::processNotificationEvent(const std::string& type, const core::NotificationEvent& notification) {
    auto subscriptionQuery = _subscriber.getSubscriptionQuery(notification.subscriptions);
    if (!subscriptionQuery.has_value()) {
        return;
    }
    _guardedExecutor->exec([&, type, notification]() {
        if (type == "groupCreated") {
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
            _treeKeyCaches.drop(raw.groupId);
            _groupDataSchemaMapper->dropVersionPin(raw.groupId);
            invalidateModuleKeysInCache(raw.groupId);
            auto data = Mapper::mapToGroupDeletedEventData(raw);
            auto event = core::EventBuilder::buildEvent<GroupDeletedEvent>("context", data, notification);
            _eventMiddleware->emitApiEvent(event);
        } else {
            LOG_ERROR("UNRESOLVED EVENT in CPP layer: '", type, "'");
        }
    });
}

void GroupApiImpl::processConnectedEvent() {
    _treeKeyCaches.dropAll();
    _groupDataSchemaMapper->dropAllVersionPins();
    invalidateModuleKeysInCache();
}

void GroupApiImpl::processDisconnectedEvent() {
    _treeKeyCaches.dropAll();
    _groupDataSchemaMapper->dropAllVersionPins();
    invalidateModuleKeysInCache();
    privmx::utils::ManualManagedClass<GroupApiImpl>::cleanup();
}

std::pair<core::ModuleKeys, int64_t> GroupApiImpl::getModuleKeysAndVersionFromServer(std::string moduleId) {
    server::GroupGetModel params{
        .groupId = moduleId, .type = {}, .scope = {}, .forUserIds = {}, .forNewMembers = {}, .fromVersion = {}
    };
    auto group = _serverApi.groupGet(params).group;
    _groupDataSchemaMapper->assertDataIntegrity(group);
    return std::make_pair(groupToModuleKeys(group), group.version);
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

privmx::crypto::PrivateKey GroupApiImpl::resolveGroupPrivKey(const std::string& groupId, int64_t epoch) {
    server::GroupGetModel params{
        .groupId = groupId, .type = {}, .scope = {}, .forUserIds = {}, .forNewMembers = {}, .fromVersion = {}
    };
    auto group = _serverApi.groupGet(params).group;

    const int64_t currentEpoch = group.keyVersion.value_or(1);
    // Every read learns the epoch here, so a client that missed the `groupUpdated` event still converges.
    dropNodeKeysIfEpochAdvanced(groupId, static_cast<std::uint32_t>(currentEpoch));
    const auto cache = _treeKeyCaches.get(groupId);
    keytree::GroupKeyResolver resolver(*cache);
    const bool needsDescent = epoch > 0 && epoch < currentEpoch;
    const keytree::ResolveResult resolved = resolver.resolve(
        group, epoch, _userPrivKey,
        needsDescent ? fetchKeyArchive(groupId, epoch, currentEpoch) : server::GroupGetKeyArchiveResult{}
    );
    if (resolved.key.has_value()) {
        return resolved.key.value();
    }
    if (resolved.failure == keytree::ResolveFailure::ClimbFailed &&
        resolved.climb == keytree::ClimbFailure::NotAMember) {
        _treeKeyCaches.drop(groupId);
    }
    throw core::EncryptionKeyValidationException(describeResolveFailure(resolved));
}

void GroupApiImpl::dropNodeKeysIfEpochAdvanced(const std::string& groupId, std::uint32_t epoch) {
    const auto cache = _treeKeyCaches.get(groupId);
    const auto known = cache->highestGrantEpoch();
    if (!known.has_value() || epoch > known.value()) {
        cache->clearNodeKeys();
    }
}

privmx::endpoint::group::server::GroupGetKeyArchiveResult GroupApiImpl::fetchKeyArchive(
    const std::string& groupId,
    int64_t targetEpoch,
    int64_t currentEpoch
) {
    server::GroupGetKeyArchiveModel params;
    params.id = groupId;
    params.fromKeyVersion = targetEpoch;
    params.toKeyVersion = currentEpoch;
    return _serverApi.groupGetKeyArchive(params);
}

std::string GroupApiImpl::describeResolveFailure(const keytree::ResolveResult& resolved) {
    switch (resolved.failure) {
    case keytree::ResolveFailure::NoTree:
        return "Group key unavailable: group has no key tree";
    case keytree::ResolveFailure::ClimbFailed:
        if (resolved.climb == keytree::ClimbFailure::Tampered) {
            return "Group key tree verification failed: a node key does not match the published public key";
        }
        if (resolved.climb == keytree::ClimbFailure::NotAMember) {
            return "Group key unavailable: caller holds no leaf in the key tree";
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
