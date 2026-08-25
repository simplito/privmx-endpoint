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
#include "privmx/endpoint/group/keytree/TreeWire.hpp"
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
    _groupPrivKeyResolver =
        [this](const std::string& groupId, int64_t epoch) -> std::optional<privmx::crypto::PrivateKey> {
        try {
            return resolveGroupPrivKey(groupId, epoch);
        } catch (...) {
            // caller holds no leaf in this group's tree at this epoch — skip
            return std::nullopt;
        }
    };
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

// ─────────────────────────────────────────────────────────────────────────────
// Tree-backed membership (documents/nested_groups/09-hidden-key-tree.md)
// ─────────────────────────────────────────────────────────────────────────────

std::vector<keytree::TreeMember> GroupApiImpl::toTreeMembers(
    const std::vector<core::UserWithPubKey>& users,
    const std::vector<core::UserWithPubKey>& managers
) {
    std::vector<keytree::TreeMember> members;
    std::set<std::string> seen;
    // Sorted by user id so two clients computing the same tree independently agree on the seating. Managers and
    // users share one leaf space: the tree carries reachability, not authority.
    std::vector<core::UserWithPubKey> all;
    all.insert(all.end(), users.begin(), users.end());
    all.insert(all.end(), managers.begin(), managers.end());
    std::sort(all.begin(), all.end(), [](const core::UserWithPubKey& a, const core::UserWithPubKey& b) {
        return a.userId < b.userId;
    });
    for (const core::UserWithPubKey& user : all) {
        if (!seen.insert(user.userId).second) {
            continue; // a manager listed as a user too gets one leaf, not two
        }
        members.push_back(keytree::TreeMember{user.userId, privmx::crypto::PublicKey::fromBase58DER(user.pubKey)});
    }
    return members;
}

std::map<std::string, std::string> GroupApiImpl::rosterKeyStrings(
    const std::vector<core::UserWithPubKey>& users,
    const std::vector<core::UserWithPubKey>& managers
) {
    std::map<std::string, std::string> result;
    for (const core::UserWithPubKey& user : users) {
        result[user.userId] = user.pubKey;
    }
    for (const core::UserWithPubKey& manager : managers) {
        result[manager.userId] = manager.pubKey;
    }
    return result;
}

/**
 * Runs a plan builder, converting its argument errors into an endpoint exception.
 *
 * The keytree module reports impossible requests — removing somebody who holds no leaf, growing without the
 * roster — as `std::invalid_argument`, which is right for a library with no dependency on the endpoint's
 * exception hierarchy. It is wrong to let one escape the SDK boundary: a caller catching `core::Exception`
 * would get a `std::terminate` instead of an error.
 */
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

std::string GroupApiImpl::createGroupWithKeyTree(
    const std::string& contextId,
    const std::vector<core::UserWithPubKey>& users,
    const std::vector<core::UserWithPubKey>& managers,
    const core::Buffer& publicMeta,
    const core::Buffer& privateMeta,
    const std::optional<core::ContainerPolicy>& policies
) {
    // Empty rosters: no per-member key entries. The metadata key is wrapped once, to the group's own grant public
    // key, and every member opens it by climbing — see `GROUP_CREATE_MODEL_EXTRA_FIELDS` for what one wrap each cost.
    auto ctx = prepareContainerCreate(contextId, {}, {});

    const std::vector<keytree::TreeMember> members = toTreeMembers(users, managers);
    // A scratch cache: the group has no id yet, so it has no cache in the registry to write to. `build()` writes
    // nothing anyway — the keys it mints come back in the plan, and are seeded below once the id exists.
    keytree::TreeKeyCache scratch;
    keytree::TreeKeys builder(scratch);
    const keytree::BuildPlan plan = builder.build(members, _userPrivKey);
    const std::string groupPubKeyStr = plan.grantKey.getPublicKey().toBase58DER();

    std::vector<std::string> sortedUsers = core::EndpointUtils::usersWithPubKeyToIds(users);
    std::vector<std::string> sortedManagers = core::EndpointUtils::usersWithPubKeyToIds(managers);
    std::sort(sortedUsers.begin(), sortedUsers.end());
    std::sort(sortedManagers.begin(), sortedManagers.end());

    dynamic::MembershipBlock membership{
        .users = sortedUsers,
        .managers = sortedManagers,
        .groupPubKey = groupPubKeyStr,
        .keyId = ctx.key.id,
        .keyVersion = 1,
        .prevEntryHash = std::nullopt
    };

    GroupDataToEncryptV5 dataToEncrypt{
        .publicMeta = publicMeta,
        .privateMeta = privateMeta,
        .internalMeta = core::
            ModuleInternalMetaV5{.secret = ctx.secret, .resourceId = ctx.resourceId, .randomId = ctx.dio.randomId},
        .dio = ctx.dio,
        // Empty on purpose: the grant private key is reached by climbing. Carrying it here would deliver it to
        // every member through the metadata key, and that key would then need re-wrapping for everyone on each
        // removal — the very cost the tree removes.
        .groupPrivKey = std::string(),
        .membership = membership
    };

    // Filled field by field rather than through `fillContainerCreateModel`: that helper also sets `keys`, and a
    // group carries none — the bridge refuses a create that names the field at all.
    server::GroupCreateModel model;
    model.resourceId = ctx.resourceId;
    model.contextId = contextId;
    model.keyId = ctx.key.id;
    model.data = _groupDataSchemaMapper->encrypt(dataToEncrypt, ctx.key.key);
    model.users = core::EndpointUtils::usersWithPubKeyToIds(users);
    model.managers = core::EndpointUtils::usersWithPubKeyToIds(managers);
    model.groupPubKey = groupPubKeyStr;
    model.type = GROUP_TYPE_FILTER_FLAG;
    // The group is a grantee of itself, at epoch 1. The entry names no group: the id does not exist yet, and the
    // server files it against the group it is creating; nothing inside the ciphertext depends on it.
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
    // The creator already holds everything a climb would recover, so seeding saves it a log2(N) walk on its very
    // next read. Safe only because a cached grant key is now re-checked against the tree the server serves back:
    // if the bridge committed anything other than what we submitted, the next read evicts this and re-climbs.
    const auto cache = _treeKeyCaches.get(result.groupId);
    cache->putGrantKey(1, plan.grantKey); // a new group starts at epoch 1
    for (const auto& minted : plan.nodeKeys) {
        cache->putNodeKey(minted.first, 0, minted.second); // every node in a fresh build is at generation 0
    }
    return result.groupId;
}

void GroupApiImpl::addGroupMember(
    const std::string& groupId,
    const core::UserWithPubKey& newMember,
    bool asManager,
    const std::vector<core::UserWithPubKey>& users,
    const std::vector<core::UserWithPubKey>& managers,
    const core::Buffer& publicMeta,
    const core::Buffer& privateMeta
) {
    // Two `O(log n)` reads rather than one `O(n)` one. Which seat the newcomer takes follows from `leafAssignment`,
    // which every scope carries, so the first read is the caller's own path view; the second asks for what seating
    // that position needs — the nodes beside the new leaf, whose public keys the re-keying wraps to. The seat has
    // no holder yet, so `forUserId` cannot name it, which is what `forPosition` is for.
    server::GroupGetModel seatModel{.groupId = groupId, .type = {}};
    withHistoryFrom(seatModel, groupId);
    const auto seating = _serverApi.groupGet(seatModel).group;
    const std::uint32_t position = keytree::TreeKeys::choosePosition(
        keytree::TreeWire::toRuntime(keytree::TreeWire::fromGroupInfo(seating), 0, _userPrivKey.getPublicKey())
    );

    server::GroupGetModel getModel{.groupId = groupId, .type = {}};
    getModel.forPosition = static_cast<std::int64_t>(position);
    withHistoryFrom(getModel, groupId);
    auto currentGroup = _serverApi.groupGet(getModel).group;
    const auto& currentEntry = currentGroup.data.back();
    const auto resourceId = currentGroup.resourceId.value_or(core::EndpointUtils::generateId());
    const int64_t currentEpoch = currentGroup.keyVersion.value_or(1);

    // One handle for the whole operation: the climb populates the node keys the plan then reads, so re-looking it
    // up in between would let a concurrent invalidation leave `planAddition` with nothing to work from.
    const auto cache = _treeKeyCaches.get(groupId);
    const keytree::TreeGroupState state = climbForPlanning(currentGroup, cache);
    // What the server already holds for the nodes on that path: a node it has advances a generation, a node it
    // does not is one growth mints, and the delta has to say which is which.
    std::map<std::uint32_t, std::uint32_t> previousGenerations;
    for (const keytree::TreeNodeState& node : state.nodes) {
        previousGenerations[node.nodeIndex] = node.generation;
    }

    keytree::TreeKeys tree(*cache);
    tree.setMemberKeyStrings(rosterKeyStrings(users, managers));
    const keytree::AdditionPlan plan = planOrThrow<keytree::AdditionPlan>([&] {
        return tree.planAddition(
            state, keytree::TreeMember{newMember.userId, privmx::crypto::PublicKey::fromBase58DER(newMember.pubKey)},
            _userPrivKey
        );
    });
    // The path this caller just re-keyed includes their own ancestors, so their cached keys for those nodes now
    // name a generation the tree no longer has. Keeping the minted ones spares the next operation a re-climb.
    for (const auto& [nodeIndex, nodeKey] : plan.nodeKeys) {
        const auto minted = std::find_if(plan.nodes.begin(), plan.nodes.end(), [&](const keytree::TreeNodeState& n) {
            return n.nodeIndex == nodeIndex;
        });
        if (minted != plan.nodes.end()) {
            cache->putNodeKey(nodeIndex, minted->generation, nodeKey);
        }
    }

    // No new epoch: `forceGenerateNewKey` stays false so the metadata key is untouched and every container the
    // group can read stays valid. The newcomer simply gets an entry for the key that already exists.
    //
    // `distributeToUsers = false`, and the one entry is built below instead: the shared path would wrap *every*
    // metadata key this client can open — the whole history — to the newcomer, and a tree-backed group holds at
    // most one key entry per member. Older epochs are not wrapped on purpose. They are reached by descending the
    // ladder, which is what the tree exists for; handing them over per member would put `members × epochs`
    // wraps back on the group document, and the bridge refuses the request outright.
    auto ctx = prepareContainerUpdate(
        currentGroup, currentEntry, resourceId, users, managers, false, false, _groupPrivKeyResolver
    );
    std::vector<std::string> sortedUsers = currentGroup.users;
    std::vector<std::string> sortedManagers = currentGroup.managers;
    std::sort(sortedUsers.begin(), sortedUsers.end());
    std::sort(sortedManagers.begin(), sortedManagers.end());

    auto prevEncData = dynamic::EncryptedGroupDataV5::fromJSON(currentEntry.data);
    dynamic::MembershipBlock membership{
        .users = sortedUsers,
        .managers = sortedManagers,
        .groupPubKey = currentGroup.groupPubKey,
        .keyId = ctx.key.id,
        .keyVersion = currentEpoch,
        .prevEntryHash = privmx::utils::Hex::from(privmx::crypto::Crypto::sha256(prevEncData.dio))
    };

    GroupDataToEncryptV5 dataToEncrypt{
        .publicMeta = publicMeta,
        .privateMeta = privateMeta,
        .internalMeta = core::
            ModuleInternalMetaV5{.secret = ctx.secret, .resourceId = resourceId, .randomId = ctx.dio.randomId},
        .dio = ctx.dio,
        .groupPrivKey = std::string(),
        .membership = membership
    };

    server::GroupAddMemberModel model;
    model.id = groupId;
    model.userId = newMember.userId;
    model.role = asManager ? "manager" : "user";
    model.position = static_cast<std::int64_t>(plan.position);
    model.keyId = ctx.key.id;
    model.data = _groupDataSchemaMapper->encrypt(dataToEncrypt, ctx.key.key);
    // The delta, not the state: the server holds everything else and checks this against it.
    model.transition = keytree::TreeWire::toAdditionTransition(plan, previousGenerations, currentEpoch);
    // There is no key entry to send: the newcomer climbs to the grant key and opens the group's single
    // self-addressed metadata entry, like everybody else.
    model.expectedKeyVersion = currentEpoch;

    try {
        _serverApi.groupAddMember(model);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
    // Deliberately no tree-key invalidation: seating re-keys the new leaf's path, and the minted keys went into
    // the cache above under the generation they were minted at. Cache entries are keyed by (node, generation), so
    // the superseded ones cannot be mistaken for current — they are dead weight, not a correctness problem. The
    // epoch does not move and the grant keypair is untouched, so nothing else cached goes stale.
    invalidateModuleKeysInCache(groupId);
}

void GroupApiImpl::removeGroupMember(
    const std::string& groupId,
    const std::string& userId,
    const std::vector<core::UserWithPubKey>& users,
    const std::vector<core::UserWithPubKey>& managers,
    const core::Buffer& publicMeta,
    const core::Buffer& privateMeta
) {
    // The path view is enough for both halves of a removal: climbing runs on the caller's own path, and planning
    // needs the subject's path and copath — which `forUserId` asks the server to include. What used to be a
    // ~13 MB download at 16 384 members is `O(log n)`.
    server::GroupGetModel getModel{.groupId = groupId, .type = {}};
    getModel.forUserId = userId;
    withHistoryFrom(getModel, groupId);
    auto currentGroup = _serverApi.groupGet(getModel).group;
    const auto& currentEntry = currentGroup.data.back();
    const auto resourceId = currentGroup.resourceId.value_or(core::EndpointUtils::generateId());
    const int64_t currentEpoch = currentGroup.keyVersion.value_or(1);
    const int64_t newEpoch = currentEpoch + 1;

    // One handle for the whole removal — the climb, the plan, the rungs and the post-commit seed all have to see
    // the same cache, or the plan reads node keys the climb never wrote.
    const auto cache = _treeKeyCaches.get(groupId);
    const keytree::TreeGroupState state = climbForPlanning(currentGroup, cache);
    const auto currentGrantKey = cache->getGrantKey(static_cast<std::uint32_t>(currentEpoch));

    keytree::TreeKeys tree(*cache);
    // The surviving siblings' public keys come from the roster: they are not part of the tree state, and a
    // refresh that skipped one would silently lock that member out.
    tree.setMemberKeyStrings(rosterKeyStrings(users, managers));
    const keytree::RemovalPlan plan = planOrThrow<keytree::RemovalPlan>([&] {
        return tree.planRemoval(state, userId, _userPrivKey);
    });

    // Rungs for the new epoch. The unit rung is mandatory — without it the group's own history is orphaned at
    // the moment of the removal. Skip rungs are added when this client happens to hold the older epoch keys,
    // and are a shortcut for future descents rather than a correctness requirement.
    keytree::LadderKeys ladder(*cache);
    const std::vector<keytree::ArchiveRung> rungs = ladder.buildRungs(
        static_cast<std::uint32_t>(newEpoch), plan.newGrantKey.getPublicKey(), currentGrantKey,
        static_cast<std::uint32_t>(currentGroup.eraFloor.value_or(1)),
        keytree::GroupKeyResolver::ownUserId(currentGroup).value_or(std::string()), _userPrivKey
    );

    // A removal DOES rotate the metadata key: otherwise the departing member keeps reading the group's name and
    // description, even though the grant key is beyond their reach.
    //
    // But it rotates it with **one** wrap, not one per remaining member. The new key is wrapped to the group's
    // own new grant public key — the group is a grantee of itself, using the same mechanism a thread or store
    // uses when it grants access to a group — and every remaining member opens it by climbing to a key they can
    // already reach. Distributing it per member would put the O(n) cost back into the one operation the tree
    // exists to keep cheap. See documents/nested_groups/09-hidden-key-tree.md §9.1.
    // `distributeToUsers = false`: a new metadata key is generated, but not wrapped to anyone individually. Doing
    // that would cost one ECIES operation per remaining member in this client's own CPU even though none of the
    // results would be sent.
    auto ctx = prepareContainerUpdate(
        currentGroup, currentEntry, resourceId, users, managers, true, false, _groupPrivKeyResolver
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

    std::vector<std::string> sortedUsers = core::EndpointUtils::usersWithPubKeyToIds(users);
    std::vector<std::string> sortedManagers = core::EndpointUtils::usersWithPubKeyToIds(managers);
    std::sort(sortedUsers.begin(), sortedUsers.end());
    std::sort(sortedManagers.begin(), sortedManagers.end());

    const std::string newGroupPubKeyStr = plan.newGrantKey.getPublicKey().toBase58DER();
    auto prevEncData = dynamic::EncryptedGroupDataV5::fromJSON(currentEntry.data);
    dynamic::MembershipBlock membership{
        .users = sortedUsers,
        .managers = sortedManagers,
        .groupPubKey = newGroupPubKeyStr,
        .keyId = ctx.key.id,
        .keyVersion = newEpoch,
        .prevEntryHash = privmx::utils::Hex::from(privmx::crypto::Crypto::sha256(prevEncData.dio))
    };

    GroupDataToEncryptV5 dataToEncrypt{
        .publicMeta = publicMeta,
        .privateMeta = privateMeta,
        .internalMeta = core::
            ModuleInternalMetaV5{.secret = ctx.secret, .resourceId = resourceId, .randomId = ctx.dio.randomId},
        .dio = ctx.dio,
        .groupPrivKey = std::string(),
        .membership = membership
    };

    const auto position = keytree::TreeKeys::positionOf(state, userId);
    if (!position.has_value()) {
        throw core::EncryptionKeyValidationException("member " + userId + " holds no leaf in this group");
    }

    server::GroupRemoveMemberModel model;
    model.id = groupId;
    model.userId = userId;
    model.groupPubKey = newGroupPubKeyStr;
    model.keyId = ctx.key.id;
    model.data = _groupDataSchemaMapper->encrypt(dataToEncrypt, ctx.key.key);
    // The delta, not the state: the server holds everything else and checks this against it.
    model.transition = keytree::TreeWire::toTransition(
        keytree::TreeWire::fromGroupInfo(currentGroup), plan, position.value(), currentEpoch
    );
    model.rungs = keytree::TreeWire::toWire(rungs);
    // One ciphertext, whatever the group's size — the O(1) replacement for one wrap per survivor.
    model.groupKeys = selfAddressedKey.at(0);
    model.expectedKeyVersion = currentEpoch;
    const auto confInput = std::string("confirm") + groupId + std::to_string(newEpoch) + ctx.key.id;
    model.confirmationTag = privmx::utils::Hex::from(privmx::crypto::Crypto::hmacSha256(ctx.key.key, confInput));

    try {
        _serverApi.groupRemoveMember(model);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
    // Node keys only. The removal refreshed every generation on the departing leaf's path, so those are dead —
    // but the grant keys are not: within one group `epoch -> key` is immutable, and `buildRungs` reads the older
    // ones to publish skip rungs at the next removal. Dropping them would quietly degrade future descents to
    // walking one rung at a time.
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
    const bool forceGenerateNewKey,
    const std::optional<core::ContainerPolicy>& policies,
    bool allowRotationRetry
) {
    // The default path view is enough: this submits no tree, and the roster it re-signs is the one it reads back.
    server::GroupGetModel getModel{.groupId = groupId, .type = {}};
    withHistoryFrom(getModel, groupId);
    auto currentGroup = _serverApi.groupGet(getModel).group;
    const auto& currentEntry = currentGroup.data.back();
    const auto resourceId = currentGroup.resourceId.value_or(core::EndpointUtils::generateId());
    int64_t currentEpoch = currentGroup.keyVersion.value_or(0);

    auto currentDecryptedEncKey = getAndValidateModuleCurrentEncKey(currentGroup, _groupPrivKeyResolver);

    // The roster is unchanged by definition — moving a member goes through addGroupMember/removeGroupMember —
    // so the resolver is handed the group's own roster back. That leaves `doNeedNewKey()` driven by
    // `forceGenerateNewKey` alone; an empty roster here would read as "everybody was removed" and rotate.
    // Public keys are not needed: `distributeToUsers = false` discards everything they would be used for.
    std::vector<core::UserWithPubKey> unchangedUsers;
    for (const auto& userId : currentGroup.users) {
        unchangedUsers.push_back(core::UserWithPubKey{.userId = userId, .pubKey = std::string()});
    }
    std::vector<core::UserWithPubKey> unchangedManagers;
    for (const auto& userId : currentGroup.managers) {
        unchangedManagers.push_back(core::UserWithPubKey{.userId = userId, .pubKey = std::string()});
    }
    auto ctx = prepareContainerUpdate(
        currentGroup, currentEntry, resourceId, unchangedUsers, unchangedManagers, forceGenerateNewKey, false,
        _groupPrivKeyResolver
    );
    LOG_DEBUG("ctx.secret - ", ctx.secret)

    std::string newGroupPrivKeyStr;
    if (currentDecryptedEncKey.statusCode == 0) {
        newGroupPrivKeyStr = _groupDataSchemaMapper->getGroupPrivKey(currentGroup, currentDecryptedEncKey);
    }
    std::string newGroupPubKeyStr = currentGroup.groupPubKey;
    int64_t newEpoch = currentEpoch;

    std::vector<std::string> sortedUsers = currentGroup.users;
    std::vector<std::string> sortedManagers = currentGroup.managers;
    std::sort(sortedUsers.begin(), sortedUsers.end());
    std::sort(sortedManagers.begin(), sortedManagers.end());

    auto prevEncData = dynamic::EncryptedGroupDataV5::fromJSON(currentEntry.data);
    dynamic::MembershipBlock membership{
        .users = sortedUsers,
        .managers = sortedManagers,
        .groupPubKey = newGroupPubKeyStr,
        .keyId = ctx.key.id,
        .keyVersion = newEpoch,
        .prevEntryHash = privmx::utils::Hex::from(privmx::crypto::Crypto::sha256(prevEncData.dio))
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

    // Metadata only: no roster, no `keys`, no grant key. The bridge refuses a groupUpdate that names any of them.
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
            updateGroup(groupId, publicMeta, privateMeta, version, force, forceGenerateNewKey, policies, false);
            return;
        }
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
    // Deliberately no tree-key invalidation: `newEpoch == currentEpoch` here — this path rotates the metadata key
    // but never the grant key, and never touches the tree. The `groupUpdated` event and `resolveGroupPrivKey`
    // both re-check the epoch anyway, so a rotation that did advance it is still caught.
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
    server::GroupGetModel getModel{.groupId = groupId, .type = {}};
    withHistoryFrom(getModel, groupId);
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

    auto confInput = std::string("confirm") +
        groupId +
        std::to_string(payload.keyVersion) +
        payload.winnerKeyEntry.keyId;
    auto expectedTag = privmx::utils::Hex::from(privmx::crypto::Crypto::hmacSha256(winnerGk.key, confInput));
    if (expectedTag != payload.confirmationTag) {
        throw GroupDataIntegrityException("RotatedAlready: confirmation tag mismatch");
    }

    noteGroupEpoch(groupId, static_cast<std::uint32_t>(payload.keyVersion));
    invalidateModuleKeysInCache(groupId);
}

void GroupApiImpl::withHistoryFrom(server::GroupGetModel& params, const std::string& groupId) {
    const int64_t verified = _groupDataSchemaMapper->verifiedVersion(groupId);
    if (verified > 0) {
        params.fromVersion = verified + 1;
    }
}

Group GroupApiImpl::getGroup(const std::string& groupId) {
    server::GroupGetModel params{.groupId = groupId, .type = {}};
    // Only the part of the chain this client has not verified yet. Each entry carries the roster it was written
    // with — ~40 B per member — so a group of 16 384 ships ~650 KB per version, and re-sending versions we have
    // already proved is the bulk of what a read costs. The window has to chain into our checkpoint, which
    // `assertDataIntegrity` insists on rather than assumes.
    withHistoryFrom(params, groupId);
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
    // A straight mapping, and no cache warming: the listing carries no key entries, so there is nothing to put
    // in the module-key cache. Any later per-group operation fetches full state through
    // `getModuleKeysAndVersionFromServer` on the cache miss.
    std::vector<GroupSummary> groups;
    groups.reserve(groupsList.groups.size());
    for (const auto& group : groupsList.groups) {
        groups.push_back(GroupDataSchemaMapper::toLibGroupSummary(group));
    }
    return core::PagingList<GroupSummary>({.totalAvailable = groupsList.count, .readItems = groups});
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
            _groupDataSchemaMapper->dropChainCheckpoint(raw.groupId);
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
    _groupDataSchemaMapper->dropAllChainCheckpoints();
    invalidateModuleKeysInCache();
}

void GroupApiImpl::processDisconnectedEvent() {
    // Not redundant with the destructor: `cleanup()` only drops this object's self-reference, and `ThreadApiImpl`
    // holds a `shared_ptr` to it, so the group keys would otherwise outlive the session that earned them.
    _treeKeyCaches.dropAll();
    _groupDataSchemaMapper->dropAllChainCheckpoints();
    invalidateModuleKeysInCache();
    privmx::utils::ManualManagedClass<GroupApiImpl>::cleanup();
}

std::pair<core::ModuleKeys, int64_t> GroupApiImpl::getModuleKeysAndVersionFromServer(std::string moduleId) {
    server::GroupGetModel params{.groupId = moduleId, .type = {}};
    withHistoryFrom(params, moduleId);
    auto group = _serverApi.groupGet(params).group;
    _groupDataSchemaMapper->assertDataIntegrity(group);
    return std::make_pair(groupToModuleKeys(group), group.version);
}

core::ModuleKeys GroupApiImpl::groupToModuleKeys(const server::GroupInfo& group) {
    return core::ModuleKeys{
        // Always empty: a group distributes its metadata key through `groupKeys`, opened by climbing.
        .keys = {},
        .groupKeys = group.groupKeys.value_or(std::vector<core::server::GroupKeysEntry>{}),
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
    server::GroupGetModel params{.groupId = groupId, .type = {}};
    withHistoryFrom(params, groupId);
    auto group = _serverApi.groupGet(params).group;

    const int64_t currentEpoch = group.keyVersion.value_or(1);
    // The invalidation hook that needs no event and no subscription: every read learns the group's current epoch
    // from the server, so a client that missed `groupUpdated` still drops its stale node keys here.
    noteGroupEpoch(groupId, static_cast<std::uint32_t>(currentEpoch));

    // Named local, not `*_treeKeyCaches.get(groupId)`: the resolver holds a reference into the cache, and a
    // temporary shared_ptr would release the last owner at the end of this statement.
    const auto cache = _treeKeyCaches.get(groupId);
    keytree::GroupKeyResolver resolver(*cache);
    const keytree::ResolveResult resolved = resolver.resolve(
        group, epoch, _userPrivKey, fetchKeyArchive(groupId, epoch, currentEpoch)
    );
    if (resolved.key.has_value()) {
        return resolved.key.value();
    }
    if (resolved.failure == keytree::ResolveFailure::ClimbFailed &&
        resolved.climb == keytree::ClimbFailure::NotAMember) {
        // The server no longer seats us in this group. This is the backstop for a client that never saw the
        // `groupUpdated` — unsubscribed, or offline when it fired. Dropping a local cache is hygiene, not a
        // revocation control: revocation is enforced by the refreshed tree and by the bridge.
        _treeKeyCaches.drop(groupId);
    }
    throw core::EncryptionKeyValidationException(describeResolveFailure(resolved));
}

void GroupApiImpl::noteGroupEpoch(const std::string& groupId, std::uint32_t epoch) {
    const auto cache = _treeKeyCaches.get(groupId);
    const auto known = cache->highestGrantEpoch();
    if (!known.has_value() || epoch > known.value()) {
        // Two threads can both decide to clear here. Harmless: clearing twice costs one re-climb at worst.
        cache->clearNodeKeys();
    }
}

/**
 * Fetches the rungs needed to get from `currentEpoch` down to `targetEpoch`.
 *
 * The bridge serves the archive separately from the group because it grows with the group's entire history. The
 * window here is the descent's own range: every rung used along the way is addressed to an epoch inside it.
 */
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

/** Turns a resolver failure into a message that distinguishes policy from attack. */
std::string GroupApiImpl::describeResolveFailure(const keytree::ResolveResult& resolved) {
    switch (resolved.failure) {
    case keytree::ResolveFailure::NoTree:
        return "Group key unavailable: group has no key tree";
    case keytree::ResolveFailure::ClimbFailed:
        if (resolved.climb == keytree::ClimbFailure::Tampered) {
            // A security event, not a transient failure. Deterministic and adversarial — do not retry.
            return "Group key tree verification failed: a node key does not match the published public key";
        }
        if (resolved.climb == keytree::ClimbFailure::NotAMember) {
            return "Group key unavailable: caller holds no leaf in the key tree";
        }
        return "Group key unavailable: the key tree could not be climbed";
    case keytree::ResolveFailure::DescentFailed:
        switch (resolved.descent) {
        case keytree::DescentFailure::EraBoundary:
            // Normal policy: history before the caller's era is simply not theirs to read.
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
