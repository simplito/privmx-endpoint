/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include <privmx/utils/Debug.hpp>
#include <privmx/utils/Utils.hpp>

#include <privmx/endpoint/core/Types.hpp>
#include <privmx/endpoint/core/EndpointUtils.hpp>
#include <privmx/endpoint/core/Utils.hpp>
#include <privmx/endpoint/core/EventMiddleware.hpp>
#include <privmx/endpoint/core/VarDeserializer.hpp>
#include <privmx/endpoint/core/VarSerializer.hpp>
#include <privmx/endpoint/core/ExceptionConverter.hpp>
#include <privmx/endpoint/core/TimestampValidator.hpp>
#include <privmx/endpoint/core/CoreConstants.hpp>

#include "privmx/endpoint/group/DynamicTypes.hpp"
#include "privmx/endpoint/group/GroupApiImpl.hpp"
#include "privmx/endpoint/group/ServerTypes.hpp"
#include "privmx/endpoint/group/GroupException.hpp"
#include "privmx/endpoint/core/ListQueryMapper.hpp"
#include "privmx/endpoint/core/UsersKeysResolver.hpp"
#include <privmx/endpoint/core/ConvertedExceptions.hpp>
#include "privmx/endpoint/core/Mapper.hpp"
#include "privmx/endpoint/core/EventBuilder.hpp"
#include <privmx/crypto/ecc/PrivateKey.hpp>

using namespace privmx::endpoint;
using namespace group;

GroupApiImpl::GroupApiImpl(
    const privfs::RpcGateway::Ptr& gateway,
    const privmx::crypto::PrivateKey& userPrivKey,
    const std::shared_ptr<core::KeyProvider>& keyProvider,
    const std::string& host,
    const std::shared_ptr<core::EventMiddleware>& eventMiddleware,
    const core::Connection& connection
) : ModuleBaseApi(userPrivKey, keyProvider, host, eventMiddleware, connection), 
    _gateway(gateway),
    _userPrivKey(userPrivKey),
    _keyProvider(keyProvider),
    _host(host),
    _eventMiddleware(eventMiddleware),
    _connection(connection),
    _serverApi(ServerApi(gateway)),
    _dataEncryptorGroup(core::DataEncryptor<dynamic::GroupDataV1>()),
    // _messageDataV2Encryptor(MessageDataV2Encryptor()),
    // _messageDataV3Encryptor(MessageDataV3Encryptor()),
    // _messageKeyIdFormatValidator(MessageKeyIdFormatValidator()),
    // _subscriber(gateway, GROUP_TYPE_FILTER_FLAG),
    _forbiddenChannelsNames({INTERNAL_EVENT_CHANNEL_NAME, "group", "messages"}) 
{
    _notificationListenerId = _eventMiddleware->addNotificationEventListener(std::bind(&GroupApiImpl::processNotificationEvent, this, std::placeholders::_1, std::placeholders::_2));
    _connectedListenerId = _eventMiddleware->addConnectedEventListener(std::bind(&GroupApiImpl::processConnectedEvent, this));
    _disconnectedListenerId = _eventMiddleware->addDisconnectedEventListener(std::bind(&GroupApiImpl::processDisconnectedEvent, this));
}

GroupApiImpl::~GroupApiImpl() {
    _eventMiddleware->removeNotificationEventListener(_notificationListenerId);
    _eventMiddleware->removeConnectedEventListener(_connectedListenerId);
    _eventMiddleware->removeDisconnectedEventListener(_disconnectedListenerId);
    _guardedExecutor.reset();
    LOG_TRACE("~GroupApiImpl Done");
}

std::string GroupApiImpl::createGroup(
    const std::string& contextId, 
    const std::vector<core::UserWithPubKey>& users, 
    const std::vector<core::UserWithPubKey>& managers, 
    const core::Buffer& publicMeta, 
    const core::Buffer& privateMeta
) {
    return _createGroupEx(contextId, users, managers, publicMeta, privateMeta);
}

std::string GroupApiImpl::createGroupEx(
    const std::string& contextId, 
    const std::vector<core::UserWithPubKey>& users, 
    const std::vector<core::UserWithPubKey>& managers, 
    const core::Buffer& publicMeta, 
    const core::Buffer& privateMeta
) {
    return _createGroupEx(contextId, users, managers, publicMeta, privateMeta);
}

std::string GroupApiImpl::_createGroupEx(
    const std::string& contextId, 
    const std::vector<core::UserWithPubKey>& users, 
    const std::vector<core::UserWithPubKey>& managers, 
    const core::Buffer& publicMeta, 
    const core::Buffer& privateMeta
) {
    PRIVMX_DEBUG_TIME_START(PlatformGroup, _createGroupEx)
    auto groupKey = privmx::crypto::PrivateKey::generateRandom();
    core::EncKey groupEncKey = {
        .id = groupKey.getPublicKey().toBase58DER(),
        .key = groupKey.toWIF()
    };
    // auto groupKey = _keyProvider->generateKey();
    std::string resourceId = core::EndpointUtils::generateId();
    auto groupDIO = _connection.getImpl()->createDIO(
        contextId,
        resourceId
    );
    auto groupSecret = _keyProvider->generateSecret();

    core::ModuleDataToEncryptV5 groupDataToEncrypt {
        .publicMeta = publicMeta,
        .privateMeta = privateMeta,
        .internalMeta = core::ModuleInternalMetaV5{.secret=groupSecret, .resourceId=resourceId, .randomId=groupDIO.randomId},
        .dio = groupDIO
    };
    auto create_group_model = utils::TypedObjectFactory::createNewObject<server::GroupCreateModel>();
    create_group_model.resourceId(resourceId);
    create_group_model.contextId(contextId);
    create_group_model.groupPubKey(groupEncKey.id);
    create_group_model.data(_groupDataEncryptorV5.encrypt(groupDataToEncrypt, _userPrivKey, groupKey.getPrivateEncKey()).asVar());
    auto allUsers = core::EndpointUtils::uniqueListUserWithPubKey(users, managers);
    // create_group_model.keys(
    //     _keyProvider->prepareKeysList(
    //         allUsers, 
    //         groupEncKey, 
    //         groupDIO,
    //         {.contextId=contextId, .resourceId=resourceId},
    //         groupSecret
    //     )
    // );

    create_group_model.users(mapUsers(users));
    create_group_model.managers(mapUsers(managers));
    PRIVMX_DEBUG_TIME_CHECKPOINT(PlatformGroup, _createGroupEx, data encrypted)
    auto result = _serverApi.groupCreate(create_group_model);
    PRIVMX_DEBUG_TIME_STOP(PlatformGroup, _createGroupEx, data send)
    return result.groupId();
}

void GroupApiImpl::updateGroup(
    const std::string& groupId,
    const core::Buffer& publicMeta,
    const core::Buffer& privateMeta,
    const int64_t version,
    const bool force
) {
    PRIVMX_DEBUG_TIME_START(PlatformGroup, updateGroup)

    // get current group

    auto getModel = utils::TypedObjectFactory::createNewObject<server::GroupGetModel>();
    getModel.groupId(groupId);
    auto currentGroup = _serverApi.groupGet(getModel).group();
    auto currentGroupEntry = currentGroup.data().get(currentGroup.data().size()-1);
    auto currentGroupResourceId = currentGroup.resourceIdOpt(core::EndpointUtils::generateId());
    auto location {getModuleEncKeyLocation(currentGroup, currentGroupResourceId)};
    // auto groupKeys {getAndValidateModuleKeys(currentGroup, currentGroupResourceId)};
    // auto currentGroupKey {findEncKeyByKeyId(groupKeys, currentGroupEntry.keyId())};
    // auto groupInternalMeta = extractAndDecryptModuleInternalMeta(currentGroupEntry, currentGroupKey);

    // auto usersKeysResolver {core::UsersKeysResolver::create(currentGroup, users, managers, forceGenerateNewKey, currentGroupKey)};

    // if(!_keyProvider->verifyKeysSecret(groupKeys, location, groupInternalMeta.secret)) {
    //     throw GroupEncryptionKeyValidationException();
    // }
    // setting group Key adding new users
    // core::EncKey groupKey = currentGroupKey;
    core::DataIntegrityObject updateGroupDio = _connection.getImpl()->createDIO(currentGroup.contextId(), currentGroupResourceId);
    
    privmx::utils::List<core::server::KeyEntrySet> keys = utils::TypedObjectFactory::createNewList<core::server::KeyEntrySet>();
    // if(usersKeysResolver->doNeedNewKey()) {
    //     groupKey = _keyProvider->generateKey();
    //     keys = _keyProvider->prepareKeysList(
    //         usersKeysResolver->getNewUsers(), 
    //         groupKey, 
    //         updateGroupDio,
    //         location,
    //         groupInternalMeta.secret
    //     );
    // }

    // auto usersToAddMissingKey {usersKeysResolver->getUsersToAddKey()};
    // if(usersToAddMissingKey.size() > 0) {
    //     auto tmp = _keyProvider->prepareMissingKeysForNewUsers(
    //         groupKeys,
    //         usersToAddMissingKey,
    //         updateGroupDio, 
    //         location,
    //         groupInternalMeta.secret
    //     );
    //     for(auto t: tmp) keys.add(t);
    // }
    auto model = utils::TypedObjectFactory::createNewObject<server::GroupUpdateModel>();
    // auto usersList = utils::TypedObjectFactory::createNewList<std::string>();
    // for (auto user: users) {
    //     usersList.add(user.userId);
    // }
    // auto managersList = utils::TypedObjectFactory::createNewList<std::string>();
    // for (auto x: managers) {
    //     managersList.add(x.userId);
    // }
    model.id(groupId);
    model.resourceId(currentGroupResourceId);
    model.groupPubKey(currentGroup.pubKey());
    // model.keys(keys);
    // model.users(usersList);
    // model.managers(managersList);
    model.version(version);
    model.force(force);
    // core::ModuleDataToEncryptV5 groupDataToEncrypt {
    //     .publicMeta = publicMeta,
    //     .privateMeta = privateMeta,
    //     .internalMeta = core::ModuleInternalMetaV5{.secret=groupInternalMeta.secret, .resourceId=currentGroupResourceId, .randomId=updateGroupDio.randomId},
    //     .dio = updateGroupDio
    // };
    // model.data(_groupDataEncryptorV5.encrypt(groupDataToEncrypt, _userPrivKey, groupKey.key).asVar());

    PRIVMX_DEBUG_TIME_CHECKPOINT(PlatformGroup, updateGroup, data encrypted)
    _serverApi.groupUpdate(model);
    invalidateModuleKeysInCache(groupId);
    PRIVMX_DEBUG_TIME_STOP(PlatformGroup, updateGroup, data send)
}

void GroupApiImpl::modifyGroupMembers(const std::string& groupId,
        const std::vector<core::UserWithPubKey>& usersToAddOrUpdate, const std::vector<std::string>& usersToRemove,
        const std::vector<core::UserWithPubKey>& managersToAddOrUpdate, const std::vector<std::string>& managersToRemove
) {
    
}

void GroupApiImpl::deleteGroup(const std::string& groupId) {
    auto model = utils::TypedObjectFactory::createNewObject<server::GroupDeleteModel>();
    model.groupId(groupId);
    _serverApi.groupDelete(model);
    invalidateModuleKeysInCache(groupId);
}

Group GroupApiImpl::getGroup(const std::string& groupId) {
    return _getGroupEx(groupId);
}

Group GroupApiImpl::getGroupEx(const std::string& groupId) {
    return _getGroupEx(groupId);
}

Group GroupApiImpl::_getGroupEx(const std::string& groupId) {
    PRIVMX_DEBUG_TIME_START(PlatformGroup, _getGroupEx)
    Poco::JSON::Object::Ptr params = new Poco::JSON::Object();
    params->set("groupId", groupId);
    PRIVMX_DEBUG_TIME_CHECKPOINT(PlatformGroup, _getGroupEx, getting group)
    auto group = _serverApi.groupGet(params).group();
    PRIVMX_DEBUG_TIME_CHECKPOINT(PlatformGroup, _getGroupEx, data send)
     // Add to cache
    setNewModuleKeysInCache(group.id(), groupToModuleKeys(group), group.version());
    // decrypt
    auto result = validateDecryptAndConvertGroupDataToGroup(group);
    PRIVMX_DEBUG_TIME_CHECKPOINT(PlatformGroup, _getGroupEx, data decrypted)
    return result;
}

core::PagingList<Group> GroupApiImpl::listGroups(const std::string& contextId, const core::PagingQuery& pagingQuery) {
    return _listGroupsEx(contextId, pagingQuery);
}

core::PagingList<Group> GroupApiImpl::listGroupsEx(const std::string& contextId, const core::PagingQuery& pagingQuery) {
    return _listGroupsEx(contextId, pagingQuery);
}

core::PagingList<Group> GroupApiImpl::_listGroupsEx(const std::string& contextId, const core::PagingQuery& pagingQuery) {
    PRIVMX_DEBUG_TIME_START(PlatformGroup, _listGroupsEx)
    auto model = utils::TypedObjectFactory::createNewObject<server::GroupListModel>();
    model.contextId(contextId);
    core::ListQueryMapper::map(model, pagingQuery);
    PRIVMX_DEBUG_TIME_CHECKPOINT(PlatformGroup, _listGroupsEx, getting groupList)
    auto groupsList = _serverApi.groupList(model);
    PRIVMX_DEBUG_TIME_CHECKPOINT(PlatformGroup, _listGroupsEx, data send)
    for (auto group : groupsList.groups()) {
        setNewModuleKeysInCache(group.id(), groupToModuleKeys(group), group.version());
    }
    std::vector<Group> groups = validateDecryptAndConvertGroupsDataToGroups(groupsList.groups());
    PRIVMX_DEBUG_TIME_STOP(PlatformGroup, _listGroupsEx, data decrypted)
    return core::PagingList<Group>({
        .totalAvailable = groupsList.count(),
        .readItems = groups
    });
}


void GroupApiImpl::processConnectedEvent() {
    invalidateModuleKeysInCache();
}

void GroupApiImpl::processDisconnectedEvent() {
    LOG_TRACE("GroupApiImpl recived DisconnectedEvent");
    invalidateModuleKeysInCache();
    privmx::utils::ManualManagedClass<GroupApiImpl>::cleanup();
}

privmx::utils::List<std::string> GroupApiImpl::mapUsers(const std::vector<core::UserWithPubKey>& users) {
    auto result = privmx::utils::TypedObjectFactory::createNewList<std::string>();
    for (auto user : users) {
        result.add(user.userId);
    }
    return result;
}

dynamic::GroupDataV1 GroupApiImpl::decryptGroupV1(server::GroupDataEntry groupEntry, const core::DecryptedEncKey& encKey) {
    try {
        return _dataEncryptorGroup.decrypt(groupEntry.data(), encKey);
    } catch (const core::Exception& e) {
        dynamic::GroupDataV1 result = utils::TypedObjectFactory::createNewObject<dynamic::GroupDataV1>();
        result.title(std::string());
        result.statusCode(e.getCode());
        return result;
    } catch (const privmx::utils::PrivmxException& e) {
        dynamic::GroupDataV1 result = utils::TypedObjectFactory::createNewObject<dynamic::GroupDataV1>();
        result.title(std::string());
        result.statusCode(core::ExceptionConverter::convert(e).getCode());
        return result;
    } catch (...) {
        dynamic::GroupDataV1 result = utils::TypedObjectFactory::createNewObject<dynamic::GroupDataV1>();
        result.title(std::string());
        result.statusCode(ENDPOINT_CORE_EXCEPTION_CODE);
        return result;
    }
}

Group GroupApiImpl::convertServerGroupToLibGroup(
    server::GroupInfo groupInfo,
    const core::Buffer& publicMeta,
    const core::Buffer& privateMeta,
    const int64_t& statusCode,
    const int64_t& schemaVersion
) {
    std::vector<std::string> users;
    std::vector<std::string> managers;
    if(!groupInfo.usersEmpty()) {
        for (auto x : groupInfo.users()) {
            users.push_back(x);
        }
    }
    if(!groupInfo.managersEmpty()) {
        for (auto x : groupInfo.managers()) {
            managers.push_back(x);
        }
    }
    return Group{
        .contextId = groupInfo.contextIdOpt(""),
        .groupId = groupInfo.idOpt(""),
        .pubKey = groupInfo.pubKey(),
        .createDate = groupInfo.createDateOpt(0),
        .creator = groupInfo.creatorOpt(""),
        .lastModificationDate = groupInfo.lastModificationDateOpt(0),
        .lastModifier = groupInfo.lastModifierOpt(""),
        .users = users,
        .managers = managers,
        .version = groupInfo.versionOpt(0),
        .publicMeta = publicMeta,
        .privateMeta = privateMeta,
        .statusCode = statusCode,
        .schemaVersion = schemaVersion
    };
}

Group GroupApiImpl::convertGroupDataV1ToGroup(server::GroupInfo groupInfo, dynamic::GroupDataV1 groupData) {
    Poco::JSON::Object::Ptr privateMeta = Poco::JSON::Object::Ptr(new Poco::JSON::Object());
    privateMeta->set("title", groupData.title());
    return convertServerGroupToLibGroup(
        groupInfo, 
        core::Buffer::from(""), 
        core::Buffer::from(utils::Utils::stringify(privateMeta)), 
        groupData.statusCodeOpt(0), 
        GroupDataSchema::Version::VERSION_5
    );
}

// Group GroupApiImpl::convertDecryptedGroupDataV4ToGroup(server::GroupInfo groupInfo, const core::DecryptedModuleDataV4& groupData) {
//     return convertServerGroupToLibGroup(
//         groupInfo, 
//         groupData.publicMeta, 
//         groupData.privateMeta, 
//         groupData.statusCode, 
//         GroupDataSchema::Version::VERSION_4
//     );
// }

// Group GroupApiImpl::convertDecryptedGroupDataV5ToGroup(server::GroupInfo groupInfo, const core::DecryptedModuleDataV5& groupData) {  
//     return convertServerGroupToLibGroup(
//         groupInfo, 
//         groupData.publicMeta, 
//         groupData.privateMeta, 
//         groupData.statusCode, 
//         // GroupDataSchema::Version::VERSION_5
//     );
// }

GroupDataSchema::Version GroupApiImpl::getGroupEntryDataStructureVersion(server::GroupDataEntry groupEntry) {
    if (groupEntry.data().type() == typeid(Poco::JSON::Object::Ptr)) {
        auto versioned = utils::TypedObjectFactory::createObjectFromVar<core::dynamic::VersionedData>(groupEntry.data());
        auto version = versioned.versionOpt(core::ModuleDataSchema::Version::UNKNOWN);
        switch (version) {
            case core::ModuleDataSchema::Version::VERSION_5:
                return GroupDataSchema::Version::VERSION_5;
            default:
                return GroupDataSchema::Version::UNKNOWN;
        }
    } else if (groupEntry.data().isString()) {
        return GroupDataSchema::Version::VERSION_5;
    }
    return GroupDataSchema::Version::UNKNOWN;
}

std::tuple<Group, core::DataIntegrityObject> GroupApiImpl::decryptAndConvertGroupDataToGroup(server::GroupInfo group, server::GroupDataEntry groupEntry, const core::DecryptedEncKey& encKey) {
    // switch (getGroupEntryDataStructureVersion(groupEntry)) {
    //     case GroupDataSchema::Version::UNKNOWN: {
    //         auto e = UnknowGroupFormatException();
    //         return std::make_tuple(convertServerGroupToLibGroup(group, {}, {}, e.getCode()), core::DataIntegrityObject());
    //     }
    //     case GroupDataSchema::Version::VERSION_5: {
    //         auto decryptedGroupData = decryptModuleDataV5(groupEntry, encKey);
    //         return std::make_tuple(convertDecryptedGroupDataV5ToGroup(group, decryptedGroupData), decryptedGroupData.dio);
    //     }            
    // }
    auto e = UnknowGroupFormatException();
    return std::make_tuple(convertServerGroupToLibGroup(group, {}, {}, e.getCode()), core::DataIntegrityObject());
}


std::vector<Group> GroupApiImpl::validateDecryptAndConvertGroupsDataToGroups(privmx::utils::List<server::GroupInfo> groups) {
    // Create Result Array
    std::vector<Group> result(groups.size());
    // Validate data Integrity
    for (size_t i = 0; i < groups.size(); i++) {
        auto group = groups.get(i);
        result[i].statusCode = validateGroupDataIntegrity(group);
        if(result[i].statusCode != 0) {
            result[i] = convertServerGroupToLibGroup(group, {}, {}, result[i].statusCode);
        }
    }
    core::KeyDecryptionAndVerificationRequest keyProviderRequest;
    // Create request to KeyProvider for keys
    for (size_t i = 0; i < groups.size(); i++) {
        auto group = groups.get(i);
        core::EncKeyLocation location{.contextId=group.contextId(), .resourceId=group.resourceIdOpt("")};
        auto group_data_entry = group.data().get(group.data().size()-1);
        // keyProviderRequest.addOne(group.keys(), group_data_entry.keyId(), location);
    }
    // Send request to KeyProvider
    auto groupsKeys {_keyProvider->getKeysAndVerify(keyProviderRequest)};
    std::vector<core::DataIntegrityObject> groupsDIO(groups.size());
    std::map<std::string, bool> duplication_check;
    for (size_t i = 0; i < groups.size(); i++) {
        if(result[i].statusCode != 0) {
            groupsDIO.push_back(core::DataIntegrityObject{});
        } else {
            auto group = groups.get(i);
            try {
                // auto tmp = decryptAndConvertGroupDataToGroup(
                //     group, 
                //     group.data().get(group.data().size()-1), 
                //     groupsKeys.at(core::EncKeyLocation{.contextId=group.contextId(), .resourceId=group.resourceIdOpt("")}).at(group.data().get(group.data().size()-1).keyId())
                // );
                // result[i] = std::get<0>(tmp);
                // auto groupDIO = std::get<1>(tmp);
                // groupsDIO[i] = groupDIO;
                // //find duplication
                // std::string fullRandomId = groupDIO.randomId + "-" + std::to_string(groupDIO.timestamp);
                // if(duplication_check.find(fullRandomId) == duplication_check.end()) {
                //     duplication_check.insert(std::make_pair(fullRandomId, true));
                // } else {
                //     result[i].statusCode = core::DataIntegrityObjectDuplicatedException().getCode();
                // }
            } catch (const core::Exception& e) {
                result[i] = convertServerGroupToLibGroup(group, {}, {}, e.getCode());
                groupsDIO[i] = core::DataIntegrityObject{};
            }
        }
    }
    std::vector<core::VerificationRequest> verifierInput {};
    for (size_t i = 0; i < result.size(); i++) {
        if(result[i].statusCode == 0) {
            verifierInput.push_back(core::VerificationRequest{
                .contextId = result[i].contextId,
                .senderId = result[i].lastModifier,
                .senderPubKey = groupsDIO[i].creatorPubKey,
                .date = result[i].lastModificationDate,
                .bridgeIdentity = groupsDIO[i].bridgeIdentity
            });
        }
    }
    std::vector<bool> verified;
    verified =_connection.getImpl()->getUserVerifier()->verify(verifierInput);
    for (size_t j = 0, i = 0; i < result.size(); i++) {
        if(result[i].statusCode == 0) {
            result[i].statusCode = verified[j] ? 0 : core::ExceptionConverter::getCodeOfUserVerificationFailureException();
            j++;
        }
    }
    return result;
}

Group GroupApiImpl::validateDecryptAndConvertGroupDataToGroup(server::GroupInfo group) {
    // Validate data Integrity
    auto statusCode = validateGroupDataIntegrity(group);
    if(statusCode != 0) {
        return convertServerGroupToLibGroup(group, {}, {}, statusCode);
    }
    // Get current GroupEntry and Key
    auto group_data_entry = group.data().get(group.data().size()-1);
    // Create request to KeyProvider for keys
    core::KeyDecryptionAndVerificationRequest keyProviderRequest;
    core::EncKeyLocation location{.contextId=group.contextId(), .resourceId=group.resourceIdOpt("")};
    // keyProviderRequest.addOne(group.keys(), group_data_entry.keyId(), location);
    //Send request to KeyProvider
    // auto key = _keyProvider->getKeysAndVerify(keyProviderRequest).at(location).at(group_data_entry.keyId());
    Group result;
    core::DataIntegrityObject groupDIO;
    // Decrypt
    // std::tie(result, groupDIO) = decryptAndConvertGroupDataToGroup(group, group_data_entry, key);
    // Validate with UserVerifier
    if(result.statusCode != 0) return result;
    std::vector<core::VerificationRequest> verifierInput {};
    verifierInput.push_back(core::VerificationRequest{
        .contextId = result.contextId,
        .senderId = result.lastModifier,
        .senderPubKey = groupDIO.creatorPubKey,
        .date = result.lastModificationDate,
        .bridgeIdentity = groupDIO.bridgeIdentity
    });
    std::vector<bool> verified;
    verified =_connection.getImpl()->getUserVerifier()->verify(verifierInput);
    result.statusCode = verified[0] ? 0 : core::ExceptionConverter::getCodeOfUserVerificationFailureException();
    return result;
}

void GroupApiImpl::assertGroupExist(const std::string& groupId) {
    auto params = privmx::utils::TypedObjectFactory::createNewObject<group::server::GroupGetModel>();
    params.groupId(groupId);
    _serverApi.groupGet(params).group();
}

std::pair<core::ModuleKeys, int64_t> GroupApiImpl::getModuleKeysAndVersionFromServer(std::string moduleId) {
    auto params = privmx::utils::TypedObjectFactory::createNewObject<group::server::GroupGetModel>();
    params.groupId(moduleId);
    auto group = _serverApi.groupGet(params).group();
    // validate group Data before returning data
    assertGroupDataIntegrity(group);
    return std::make_pair(groupToModuleKeys(group), group.version());
}

core::ModuleKeys GroupApiImpl::groupToModuleKeys(server::GroupInfo group) {
    return core::ModuleKeys{
        // .keys=group.keys(),
        // .currentKeyId=group.keyId(),
        .moduleSchemaVersion=getGroupEntryDataStructureVersion(group.data().get(group.data().size()-1)),
        .moduleResourceId=group.resourceIdOpt(""),
        .contextId = group.contextId()
    };
}

void GroupApiImpl::assertGroupDataIntegrity(server::GroupInfo group) {
    auto group_data_entry = group.data().get(group.data().size()-1);
        switch (getGroupEntryDataStructureVersion(group_data_entry)) {
            case GroupDataSchema::Version::UNKNOWN:
                throw UnknowGroupFormatException();
            case GroupDataSchema::Version::VERSION_5: {
                auto group_data = utils::TypedObjectFactory::createObjectFromVar<core::dynamic::EncryptedModuleDataV5>(group_data_entry.data());
                auto dio = _groupDataEncryptorV5.getDIOAndAssertIntegrity(group_data);
                if(
                    dio.contextId != group.contextId() ||
                    dio.resourceId != group.resourceIdOpt("") ||
                    dio.creatorUserId != group.lastModifier() ||
                    !core::TimestampValidator::validate(dio.timestamp, group.lastModificationDate())
                ) {
                    throw GroupDataIntegrityException();
                }
                return;
            }
        }
    throw UnknowGroupFormatException();
}

uint32_t GroupApiImpl::validateGroupDataIntegrity(server::GroupInfo group) {
    try {
        assertGroupDataIntegrity(group);
        return 0;
    } catch (const core::Exception& e) {
        return e.getCode();
    } catch (const privmx::utils::PrivmxException& e) {
        return e.getCode();
    } catch (...) {
        return ENDPOINT_CORE_EXCEPTION_CODE;
    } 
}
