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
    return privmx::crypto::PrivateKey::fromWIF(privKeyWif);
}
