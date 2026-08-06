#include <algorithm>

#include <privmx/crypto/Crypto.hpp>
#include <privmx/crypto/ecc/PrivateKey.hpp>
#include <privmx/endpoint/core/CoreException.hpp>
#include <privmx/utils/Debug.hpp>
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

std::string GroupApiImpl::createGroup(
    const std::string& contextId,
    const std::vector<core::UserWithPubKey>& users,
    const std::vector<core::UserWithPubKey>& managers,
    const core::Buffer& publicMeta,
    const core::Buffer& privateMeta,
    const std::optional<core::ContainerPolicy>& policies
) {
    auto ctx = prepareContainerCreate(contextId, users, managers);

    auto groupIdentityKey = privmx::crypto::PrivateKey::generateRandom();
    std::string groupPubKeyStr = groupIdentityKey.getPublicKey().toBase58DER();
    std::string groupPrivKeyStr = groupIdentityKey.toWIF();

    std::vector<std::string> sortedUsers = core::EndpointUtils::usersWithPubKeyToIds(users);
    std::vector<std::string> sortedManagers = core::EndpointUtils::usersWithPubKeyToIds(managers);
    std::sort(sortedUsers.begin(), sortedUsers.end());
    std::sort(sortedManagers.begin(), sortedManagers.end());

    dynamic::MembershipBlock membership{
        .users = sortedUsers,
        .managers = sortedManagers,
        .groupPubKey = groupPubKeyStr,
        .keyId = ctx.key.id,
        .keyVersion = 0,
        .prevEntryHash = std::nullopt
    };

    GroupDataToEncryptV5 dataToEncrypt{
        .publicMeta = publicMeta,
        .privateMeta = privateMeta,
        .internalMeta = core::ModuleInternalMetaV5{
            .secret = ctx.secret, .resourceId = ctx.resourceId, .randomId = ctx.dio.randomId
        },
        .dio = ctx.dio,
        .groupPrivKey = groupPrivKeyStr,
        .membership = membership
    };

    server::GroupCreateModel model;
    fillContainerCreateModel(
        model, contextId, users, managers, ctx,
        _groupDataSchemaMapper->encrypt(dataToEncrypt, ctx.key.key)
    );
    model.groupPubKey = groupPubKeyStr;
    model.type = GROUP_TYPE_FILTER_FLAG;
    if (policies.has_value()) {
        model.policy = core::Factory::createPolicyServerObject(policies.value());
    }

    auto result = _serverApi.groupCreate(model);
    return result.groupId;
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
        members.push_back(keytree::TreeMember{
            user.userId, privmx::crypto::PublicKey::fromBase58DER(user.pubKey)
        });
    }
    return members;
}

keytree::TreeGroupState GroupApiImpl::climbForPlanning(const server::GroupInfo& group) {
    if (!keytree::GroupKeyResolver::hasTree(group)) {
        throw core::EncryptionKeyValidationException("this group is not backed by a key tree");
    }
    const auto identity = keytree::GroupKeyResolver::ownUserId(group);
    if (!identity.has_value()) {
        throw core::EncryptionKeyValidationException("caller holds no leaf in this group's key tree");
    }
    const keytree::TreeGroupState state = keytree::GroupKeyResolver::toTreeState(group);
    keytree::TreeKeys tree(_treeKeyStore);
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
    auto ctx = prepareContainerCreate(contextId, users, managers);

    const std::vector<keytree::TreeMember> members = toTreeMembers(users, managers);
    keytree::TreeKeys builder(_treeKeyStore);
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
        .internalMeta = core::ModuleInternalMetaV5{
            .secret = ctx.secret, .resourceId = ctx.resourceId, .randomId = ctx.dio.randomId
        },
        .dio = ctx.dio,
        // Empty on purpose: the grant private key is reached by climbing. Carrying it here would deliver it to
        // every member through the metadata key, and that key would then need re-wrapping for everyone on each
        // removal — the very cost the tree removes.
        .groupPrivKey = std::string(),
        .membership = membership
    };

    server::GroupCreateModel model;
    fillContainerCreateModel(
        model, contextId, users, managers, ctx,
        _groupDataSchemaMapper->encrypt(dataToEncrypt, ctx.key.key)
    );
    model.groupPubKey = groupPubKeyStr;
    model.type = GROUP_TYPE_FILTER_FLAG;
    model.tree = keytree::TreeWire::fromBuildPlan(plan, members);
    if (policies.has_value()) {
        model.policy = core::Factory::createPolicyServerObject(policies.value());
    }

    auto result = _serverApi.groupCreate(model);
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
    server::GroupGetModel getModel{.groupId = groupId, .type = {}};
    auto currentGroup = _serverApi.groupGet(getModel).group;
    const auto& currentEntry = currentGroup.data.back();
    const auto resourceId = currentGroup.resourceId.value_or(core::EndpointUtils::generateId());
    const int64_t currentEpoch = currentGroup.keyVersion.value_or(1);

    const keytree::TreeGroupState state = climbForPlanning(currentGroup);

    keytree::TreeKeys tree(_treeKeyStore);
    tree.setMemberKeys(toTreeMembers(users, managers));
    const keytree::AdditionPlan plan = tree.planAddition(
        state,
        keytree::TreeMember{newMember.userId, privmx::crypto::PublicKey::fromBase58DER(newMember.pubKey)},
        _userPrivKey
    );

    // No new epoch: `forceGenerateNewKey` stays false so the metadata key is untouched and every container the
    // group can read stays valid. The newcomer simply gets an entry for the key that already exists.
    auto ctx = prepareContainerUpdate(currentGroup, currentEntry, resourceId, users, managers, false);

    std::vector<std::string> sortedUsers = core::EndpointUtils::usersWithPubKeyToIds(users);
    std::vector<std::string> sortedManagers = core::EndpointUtils::usersWithPubKeyToIds(managers);
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
        .internalMeta = core::ModuleInternalMetaV5{
            .secret = ctx.secret, .resourceId = resourceId, .randomId = ctx.dio.randomId
        },
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
    model.tree = keytree::TreeWire::afterAddition(
        keytree::TreeWire::fromGroupInfo(currentGroup), plan, newMember.userId
    );
    model.keys = ctx.keyEntries;
    model.expectedKeyVersion = currentEpoch;

    try {
        _serverApi.groupAddMember(model);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
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
    server::GroupGetModel getModel{.groupId = groupId, .type = {}};
    auto currentGroup = _serverApi.groupGet(getModel).group;
    const auto& currentEntry = currentGroup.data.back();
    const auto resourceId = currentGroup.resourceId.value_or(core::EndpointUtils::generateId());
    const int64_t currentEpoch = currentGroup.keyVersion.value_or(1);
    const int64_t newEpoch = currentEpoch + 1;

    const keytree::TreeGroupState state = climbForPlanning(currentGroup);
    const auto currentGrantKey = _treeKeyStore.getGrantKey(static_cast<std::uint32_t>(currentEpoch));

    keytree::TreeKeys tree(_treeKeyStore);
    // The surviving siblings' public keys come from the roster: they are not part of the tree state, and a
    // refresh that skipped one would silently lock that member out.
    tree.setMemberKeys(toTreeMembers(users, managers));
    const keytree::RemovalPlan plan = tree.planRemoval(state, userId, _userPrivKey);

    // Rungs for the new epoch. The unit rung is mandatory — without it the group's own history is orphaned at
    // the moment of the removal. Skip rungs are added when this client happens to hold the older epoch keys,
    // and are a shortcut for future descents rather than a correctness requirement.
    keytree::LadderKeys ladder(_treeKeyStore);
    const std::vector<keytree::ArchiveRung> rungs = ladder.buildRungs(
        static_cast<std::uint32_t>(newEpoch),
        plan.newGrantKey.getPublicKey(),
        currentGrantKey,
        static_cast<std::uint32_t>(currentGroup.eraFloor.value_or(1)),
        keytree::GroupKeyResolver::ownUserId(currentGroup).value_or(std::string()),
        _userPrivKey
    );

    // A removal DOES rotate the metadata key: otherwise the departing member keeps reading the group's name and
    // description, even though the grant key is beyond their reach.
    auto ctx = prepareContainerUpdate(currentGroup, currentEntry, resourceId, users, managers, true);

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
        .internalMeta = core::ModuleInternalMetaV5{
            .secret = ctx.secret, .resourceId = resourceId, .randomId = ctx.dio.randomId
        },
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
    model.tree = keytree::TreeWire::afterRemoval(
        keytree::TreeWire::fromGroupInfo(currentGroup), plan, position.value()
    );
    model.rungs = keytree::TreeWire::toWire(rungs);
    model.keys = ctx.keyEntries;
    model.expectedKeyVersion = currentEpoch;
    const auto confInput = std::string("confirm") + groupId + std::to_string(newEpoch) + ctx.key.id;
    model.confirmationTag = privmx::utils::Hex::from(privmx::crypto::Crypto::hmacSha256(ctx.key.key, confInput));

    try {
        _serverApi.groupRemoveMember(model);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
    _treeKeyStore.putGrantKey(static_cast<std::uint32_t>(newEpoch), plan.newGrantKey);
    invalidateModuleKeysInCache(groupId);
}

static constexpr unsigned int BRIDGE_GROUP_ROTATED_ALREADY = 0x621C;

void GroupApiImpl::updateGroup(
    const std::string& groupId,
    const std::vector<core::UserWithPubKey>& users,
    const std::vector<core::UserWithPubKey>& managers,
    const core::Buffer& publicMeta,
    const core::Buffer& privateMeta,
    const int64_t version,
    const bool force,
    const bool forceGenerateNewKey,
    const std::optional<core::ContainerPolicy>& policies,
    bool allowRotationRetry
) {
    server::GroupGetModel getModel{.groupId = groupId, .type = {}};
    auto currentGroup = _serverApi.groupGet(getModel).group;
    const auto& currentEntry = currentGroup.data.back();
    const auto resourceId = currentGroup.resourceId.value_or(core::EndpointUtils::generateId());
    int64_t currentEpoch = currentGroup.keyVersion.value_or(0);

    std::set<std::string> newMemberIds;
    for (const auto& u : users) newMemberIds.insert(u.userId);
    for (const auto& m : managers) newMemberIds.insert(m.userId);
    bool removalDetected = false;
    for (const auto& u : currentGroup.users) {
        if (!newMemberIds.count(u)) { removalDetected = true; break; }
    }
    if (!removalDetected) {
        for (const auto& m : currentGroup.managers) {
            if (!newMemberIds.count(m)) { removalDetected = true; break; }
        }
    }

    auto currentDecryptedEncKey = getAndValidateModuleCurrentEncKey(currentGroup);

    auto ctx = prepareContainerUpdate(
        currentGroup, currentEntry, resourceId, users, managers, forceGenerateNewKey || removalDetected
    );
    LOG_DEBUG("ctx.secret - ", ctx.secret)

    std::string newGroupPrivKeyStr;
    if (currentDecryptedEncKey.statusCode == 0) {
        newGroupPrivKeyStr = _groupDataSchemaMapper->getGroupPrivKey(currentGroup, currentDecryptedEncKey);
    }
    std::string newGroupPubKeyStr = currentGroup.groupPubKey;
    int64_t newEpoch = currentEpoch;

    std::vector<std::string> sortedUsers = core::EndpointUtils::usersWithPubKeyToIds(users);
    std::vector<std::string> sortedManagers = core::EndpointUtils::usersWithPubKeyToIds(managers);
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
        .internalMeta = core::ModuleInternalMetaV5{
            .secret = ctx.secret, .resourceId = resourceId, .randomId = ctx.dio.randomId
        },
        .dio = ctx.dio,
        .groupPrivKey = newGroupPrivKeyStr,
        .membership = membership
    };

    server::GroupUpdateModel model;
    fillContainerUpdateModel(model, groupId, resourceId, users, managers, ctx, version, force);
    model.groupPubKey = newGroupPubKeyStr;
    model.data = _groupDataSchemaMapper->encrypt(dataToEncrypt, ctx.key.key);
    if (policies.has_value()) {
        model.policy = core::Factory::createPolicyServerObject(policies.value());
    }

    try {
        _serverApi.groupUpdate(model);
    } catch (const privmx::utils::PrivmxException& e) {
        if (allowRotationRetry && (e.getCode() & 0x0000FFFF) == BRIDGE_GROUP_ROTATED_ALREADY) {
            auto payload = server::RotatedAlreadyPayload::fromJSON(
                privmx::utils::Utils::parseJsonObject(e.getData())
            );
            adoptRotatedAlready(groupId, payload);
            updateGroup(groupId, users, managers, publicMeta, privateMeta, version, force,
                        forceGenerateNewKey, policies, false);
            return;
        }
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
    invalidateModuleKeysInCache(groupId);
}

void GroupApiImpl::deleteGroup(const std::string& groupId) {
    server::GroupDeleteModel model{.groupId = groupId};
    _serverApi.groupDelete(model);
    invalidateModuleKeysInCache(groupId);
}

void GroupApiImpl::generateNewGroupKey(
    const std::string& groupId,
    const std::vector<core::UserWithPubKey>& users,
    const std::vector<core::UserWithPubKey>& managers,
    bool allowRotationRetry
) {
    server::GroupGetModel getModel{.groupId = groupId, .type = {}};
    auto currentGroup = _serverApi.groupGet(getModel).group;
    const auto& currentEntry = currentGroup.data.back();
    const auto resourceId = currentGroup.resourceId.value_or(core::EndpointUtils::generateId());
    int64_t currentEpoch = currentGroup.keyVersion.value_or(0);
    int64_t newEpoch = currentEpoch + 1;

    auto currentDecryptedEncKey = getAndValidateModuleCurrentEncKey(currentGroup);

    auto ctx = prepareContainerUpdate(currentGroup, currentEntry, resourceId, users, managers, true);

    auto newGroupKey = privmx::crypto::PrivateKey::generateRandom();
    std::string newGroupPrivKeyStr = newGroupKey.toWIF();
    std::string newGroupPubKeyStr = newGroupKey.getPublicKey().toBase58DER();

    std::vector<std::string> sortedUsers = core::EndpointUtils::usersWithPubKeyToIds(users);
    std::vector<std::string> sortedManagers = core::EndpointUtils::usersWithPubKeyToIds(managers);
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

    core::Buffer publicMeta;
    core::Buffer privateMeta;
    if (currentDecryptedEncKey.statusCode == 0) {
        auto [grp, _dio] = _groupDataSchemaMapper->decrypt(currentGroup, currentDecryptedEncKey);
        publicMeta = grp.publicMeta;
        privateMeta = grp.privateMeta;
    }

    GroupDataToEncryptV5 dataToEncrypt{
        .publicMeta = publicMeta,
        .privateMeta = privateMeta,
        .internalMeta = core::ModuleInternalMetaV5{
            .secret = ctx.secret, .resourceId = resourceId, .randomId = ctx.dio.randomId
        },
        .dio = ctx.dio,
        .groupPrivKey = newGroupPrivKeyStr,
        .membership = membership
    };

    server::GenerateNewGroupKeyModel model;
    model.id = groupId;
    model.keyId = ctx.key.id;
    model.expectedKeyVersion = currentEpoch;
    model.groupPubKey = newGroupPubKeyStr;
    model.data = _groupDataSchemaMapper->encrypt(dataToEncrypt, ctx.key.key);
    model.keys = ctx.keyEntries;
    auto confInput = std::string("confirm") + groupId + std::to_string(newEpoch) + ctx.key.id;
    model.confirmationTag = privmx::utils::Hex::from(
        privmx::crypto::Crypto::hmacSha256(ctx.key.key, confInput)
    );

    try {
        _serverApi.generateNewGroupKey(model);
    } catch (const privmx::utils::PrivmxException& e) {
        if (allowRotationRetry && (e.getCode() & 0x0000FFFF) == BRIDGE_GROUP_ROTATED_ALREADY) {
            auto payload = server::RotatedAlreadyPayload::fromJSON(
                privmx::utils::Utils::parseJsonObject(e.getData())
            );
            adoptRotatedAlready(groupId, payload);
            generateNewGroupKey(groupId, users, managers, false);
            return;
        }
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
    invalidateModuleKeysInCache(groupId);
}

void GroupApiImpl::adoptRotatedAlready(
    const std::string& groupId,
    const server::RotatedAlreadyPayload& payload
) {
    server::GroupGetModel getModel{.groupId = groupId, .type = {}};
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

    auto confInput = std::string("confirm") + groupId +
                     std::to_string(payload.keyVersion) + payload.winnerKeyEntry.keyId;
    auto expectedTag = privmx::utils::Hex::from(
        privmx::crypto::Crypto::hmacSha256(winnerGk.key, confInput)
    );
    if (expectedTag != payload.confirmationTag) {
        throw GroupDataIntegrityException("RotatedAlready: confirmation tag mismatch");
    }

    auto winnerPrivKeyWif = _groupDataSchemaMapper->getGroupPrivKey(updatedGroup, winnerGk);
    auto winnerPrivKey = privmx::crypto::PrivateKey::fromWIF(winnerPrivKeyWif);
    _keyProvider->registerGroupPrivKey(groupId, payload.keyVersion, winnerPrivKey);

    invalidateModuleKeysInCache(groupId);
}

Group GroupApiImpl::getGroup(const std::string& groupId) {
    server::GroupGetModel params{.groupId = groupId, .type = {}};
    auto group = _serverApi.groupGet(params).group;
    setNewModuleKeysInCache(group.id, groupToModuleKeys(group), group.version);
    return _groupDataSchemaMapper->validateDecryptAndConvertGroup(group, _keyProvider);
}

core::PagingList<Group> GroupApiImpl::listGroups(
    const std::string& contextId,
    const core::PagingQuery& pagingQuery
) {
    server::GroupListModel model;
    model.contextId = contextId;
    core::ListQueryMapper::map(model, pagingQuery);
    auto groupsList = _serverApi.groupList(model);
    for (const auto& group : groupsList.groups) {
        setNewModuleKeysInCache(group.id, groupToModuleKeys(group), group.version);
    }
    std::vector<Group> groups = _groupDataSchemaMapper->validateDecryptAndConvertGroups(
        groupsList.groups, _keyProvider
    );
    return core::PagingList<Group>({.totalAvailable = groupsList.count, .readItems = groups});
}

void GroupApiImpl::processNotificationEvent(
    const std::string& type,
    const core::NotificationEvent& notification
) {
    auto subscriptionQuery = _subscriber.getSubscriptionQuery(notification.subscriptions);
    if (!subscriptionQuery.has_value()) {
        return;
    }
    _guardedExecutor->exec([&, type, notification]() {
        if (type == "groupCreated") {
            auto raw = server::GroupInfo::fromJSON(notification.data);
            setNewModuleKeysInCache(raw.id, groupToModuleKeys(raw), raw.version);
            auto data = _groupDataSchemaMapper->validateDecryptAndConvertGroup(raw, _keyProvider);
            auto event = core::EventBuilder::buildEvent<GroupCreatedEvent>("context", data, notification);
            _eventMiddleware->emitApiEvent(event);
        } else if (type == "groupUpdated") {
            auto raw = server::GroupInfo::fromJSON(notification.data);
            setNewModuleKeysInCache(raw.id, groupToModuleKeys(raw), raw.version);
            invalidateModuleKeysInCache(raw.id);
            auto data = _groupDataSchemaMapper->validateDecryptAndConvertGroup(raw, _keyProvider);
            auto event = core::EventBuilder::buildEvent<GroupUpdatedEvent>("context", data, notification);
            _eventMiddleware->emitApiEvent(event);
        } else if (type == "groupDeleted") {
            auto raw = server::GroupDeletedEventData::fromJSON(notification.data);
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
    invalidateModuleKeysInCache();
}

void GroupApiImpl::processDisconnectedEvent() {
    invalidateModuleKeysInCache();
    privmx::utils::ManualManagedClass<GroupApiImpl>::cleanup();
}

std::pair<core::ModuleKeys, int64_t> GroupApiImpl::getModuleKeysAndVersionFromServer(std::string moduleId) {
    server::GroupGetModel params{.groupId = moduleId, .type = {}};
    auto group = _serverApi.groupGet(params).group;
    _groupDataSchemaMapper->assertDataIntegrity(group);
    return std::make_pair(groupToModuleKeys(group), group.version);
}

core::ModuleKeys GroupApiImpl::groupToModuleKeys(const server::GroupInfo& group) {
    return core::ModuleKeys{
        .keys = group.keys,
        .groupKeys = {},
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
    auto group = _serverApi.groupGet(params).group;

    // Flat path first: it is how every group worked before the hidden key tree, and groups that carry per-member
    // key entries must keep behaving identically.
    try {
        return resolveGroupPrivKeyFlat(group, epoch);
    } catch (const core::Exception&) {
        // Fall through to the tree. A flat miss is the normal case for a tree-backed group, which has no
        // per-member entry at all.
    }

    keytree::GroupKeyResolver resolver(_treeKeyStore);
    const int64_t currentEpoch = group.keyVersion.value_or(1);
    const keytree::ResolveResult resolved = (epoch > 0 && epoch < currentEpoch)
        // Only a descent needs the ladder, so only a descent pays for fetching it. The window is bounded by the
        // two epochs involved, which keeps the request proportional to the hop rather than to the group's age.
        ? resolver.resolve(group, epoch, _userPrivKey, fetchKeyArchive(groupId, epoch, currentEpoch))
        : resolver.resolve(group, epoch, _userPrivKey);
    if (resolved.key.has_value()) {
        return resolved.key.value();
    }
    throw core::EncryptionKeyValidationException(describeResolveFailure(resolved));
}

/**
 * Fetches the rungs needed to get from `currentEpoch` down to `targetEpoch`.
 *
 * The bridge serves the archive separately from the group because it grows with the group's entire history. The
 * window here is the descent's own range: every rung used along the way is addressed to an epoch inside it.
 */
privmx::endpoint::group::server::GroupGetKeyArchiveResult
GroupApiImpl::fetchKeyArchive(const std::string& groupId, int64_t targetEpoch, int64_t currentEpoch) {
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
            return "Group key unavailable: no per-member key entry and no key tree";
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
                    return "Epoch ladder verification failed"
                        + (resolved.blame.has_value() ? " (rung published by " + resolved.blame.value() + ")" : "");
                default:
                    return "Group key unavailable: the epoch ladder could not be descended";
            }
        default:
            return "Group key unavailable";
    }
}

privmx::crypto::PrivateKey GroupApiImpl::resolveGroupPrivKeyFlat(const server::GroupInfo& group, int64_t epoch) {
    int64_t currentEpoch = group.keyVersion.value_or(0);

    std::string targetKeyId;
    if (epoch == 0 || epoch == currentEpoch) {
        targetKeyId = group.data.back().keyId;
    } else if (group.keyHistory.has_value()) {
        std::string epochPubKey;
        for (const auto& kh : group.keyHistory.value()) {
            if (kh.keyVersion == epoch) {
                epochPubKey = kh.groupPubKey;
                break;
            }
        }
        if (!epochPubKey.empty()) {
            for (const auto& h : group.history) {
                if (h.groupPubKey == epochPubKey) {
                    targetKeyId = h.keyId;
                    break;
                }
            }
        }
    }
    if (targetKeyId.empty()) {
        targetKeyId = group.data.back().keyId;
    }

    core::KeyDecryptionAndVerificationRequest request;
    auto location = getModuleEncKeyLocation(group, group.resourceId);
    request.addOne(group.keys, targetKeyId, location);
    auto decrypted = _keyProvider->getKeysAndVerify(request);
    auto& encKey = decrypted.at(location).at(targetKeyId);
    if (encKey.statusCode != 0) {
        throw core::EncryptionKeyValidationException(
            "Group key statusCode: " + std::to_string(encKey.statusCode)
        );
    }
    auto privKeyWif = _groupDataSchemaMapper->getGroupPrivKey(group, encKey);
    if (privKeyWif.empty()) {
        // A tree-backed group carries no grant key in its metadata on purpose. Saying so explicitly keeps the
        // caller on the intended path instead of letting a WIF parse failure surface as something else.
        throw core::EncryptionKeyValidationException("group carries no per-member grant key; use the key tree");
    }
    return privmx::crypto::PrivateKey::fromWIF(privKeyWif);
}
