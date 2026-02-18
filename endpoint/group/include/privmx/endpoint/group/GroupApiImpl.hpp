/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_ENDPOINT_GROUP_GROUPAPIIMPL_HPP_
#define _PRIVMXLIB_ENDPOINT_GROUP_GROUPAPIIMPL_HPP_

#include <memory>
#include <optional>
#include <string>
#include <atomic>

#include <privmx/endpoint/core/ConnectionImpl.hpp>
#include <privmx/endpoint/core/encryptors/DataEncryptorV4.hpp>
#include <privmx/endpoint/core/KeyProvider.hpp>
#include <privmx/utils/ThreadSaveMap.hpp>
#include <privmx/endpoint/core/EventMiddleware.hpp>
#include <privmx/endpoint/core/encryptors/module/ModuleDataEncryptorV4.hpp>
#include <privmx/endpoint/core/encryptors/module/ModuleDataEncryptorV5.hpp>

#include "privmx/endpoint/group/ServerApi.hpp"
#include "privmx/endpoint/group/DynamicTypes.hpp"
#include "privmx/endpoint/group/GroupApi.hpp"
#include "privmx/endpoint/core/Factory.hpp"
#include "privmx/endpoint/group/Constants.hpp"
#include "privmx/endpoint/core/ModuleBaseApi.hpp"
#include "privmx/endpoint/core/ContainerKeyCache.hpp"
#include <privmx/utils/ManualManagedClass.hpp>
#include <privmx/endpoint/core/encryptors/DataEncryptor.hpp>

namespace privmx {
namespace endpoint {
namespace group {

class GroupApiImpl : public privmx::utils::ManualManagedClass<GroupApiImpl>, protected core::ModuleBaseApi
{
public:
    GroupApiImpl(
        const privfs::RpcGateway::Ptr& gateway,
        const privmx::crypto::PrivateKey& userPrivKey,
        const std::shared_ptr<core::KeyProvider>& keyProvider,
        const std::string& host,
        const std::shared_ptr<core::EventMiddleware>& eventMiddleware,
        const core::Connection& connection
    );
    ~GroupApiImpl();
    std::string createGroup(const std::string& contextId, const std::vector<core::UserWithPubKey>& users,
                             const std::vector<core::UserWithPubKey>& managers, const core::Buffer& publicMeta, const core::Buffer& privateMeta);
    std::string createGroupEx(const std::string& contextId, const std::vector<core::UserWithPubKey>& users,
                             const std::vector<core::UserWithPubKey>& managers, const core::Buffer& publicMeta, const core::Buffer& privateMeta);

    void updateGroup(const std::string& groupId, const core::Buffer& publicMeta, const core::Buffer& privateMeta,
                      const int64_t version, const bool force);

    void modifyGroupMembers(const std::string& groupId,
        const std::vector<core::UserWithPubKey>& usersToAddOrUpdate, const std::vector<std::string>& usersToRemove,
        const std::vector<core::UserWithPubKey>& managersToAddOrUpdate, const std::vector<std::string>& managersToRemove);

    void deleteGroup(const std::string& groupId);

    Group getGroup(const std::string& groupId);
    Group getGroupEx(const std::string& groupId);
    core::PagingList<Group> listGroups(const std::string& contextId, const core::PagingQuery& pagingQuery);
    core::PagingList<Group> listGroupsEx(const std::string& contextId, const core::PagingQuery& pagingQuery);

private:
    std::string _createGroupEx(
        const std::string& contextId, 
        const std::vector<core::UserWithPubKey>& users, 
        const std::vector<core::UserWithPubKey>& managers,
        const core::Buffer& publicMeta,
        const core::Buffer& privateMeta
    );
    
    Group _getGroupEx(const std::string& groupId);
    core::PagingList<Group> _listGroupsEx(const std::string& contextId, const core::PagingQuery& pagingQuery);

    void processNotificationEvent(const std::string& type, const core::NotificationEvent& notification);
    void processConnectedEvent();
    void processDisconnectedEvent();
    utils::List<std::string> mapUsers(const std::vector<core::UserWithPubKey>& users);
    dynamic::GroupDataV1 decryptGroupV1(server::GroupDataEntry groupEntry, const core::DecryptedEncKey& encKey);
    Group convertServerGroupToLibGroup(
        server::GroupInfo groupInfo,
        const core::Buffer& publicMeta = core::Buffer(),
        const core::Buffer& privateMeta = core::Buffer(),
        const int64_t& statusCode = 0,
        const int64_t& schemaVersion = GroupDataSchema::Version::UNKNOWN
    );
    Group convertGroupDataV1ToGroup(server::GroupInfo groupInfo, dynamic::GroupDataV1 groupData);
    Group convertDecryptedGroupDataV4ToGroup(server::GroupInfo groupInfo, const core::DecryptedModuleDataV4& groupData);
    Group convertDecryptedGroupDataV5ToGroup(server::GroupInfo groupInfo, const core::DecryptedModuleDataV5& groupData);
    GroupDataSchema::Version getGroupEntryDataStructureVersion(server::GroupDataEntry groupEntry);
    std::tuple<Group, core::DataIntegrityObject> decryptAndConvertGroupDataToGroup(server::GroupInfo group, server::GroupDataEntry groupEntry, const core::DecryptedEncKey& encKey);
    std::vector<Group> validateDecryptAndConvertGroupsDataToGroups(utils::List<server::GroupInfo> groups);
    Group validateDecryptAndConvertGroupDataToGroup(server::GroupInfo group);
    void assertGroupDataIntegrity(server::GroupInfo group);
    uint32_t validateGroupDataIntegrity(server::GroupInfo group);
    virtual std::pair<core::ModuleKeys, int64_t> getModuleKeysAndVersionFromServer(std::string moduleId) override;
    core::ModuleKeys groupToModuleKeys(server::GroupInfo group);



    

    void assertGroupExist(const std::string& groupId);

    privfs::RpcGateway::Ptr _gateway;
    privmx::crypto::PrivateKey _userPrivKey;
    std::shared_ptr<core::KeyProvider> _keyProvider;
    std::string _host;
    std::shared_ptr<core::EventMiddleware> _eventMiddleware;
    core::Connection _connection;
    ServerApi _serverApi;
    core::DataEncryptor<dynamic::GroupDataV1> _dataEncryptorGroup;

    int _notificationListenerId, _connectedListenerId, _disconnectedListenerId;
    std::string _messageDecryptorId, _messageDeleterId;
    core::ModuleDataEncryptorV4 _groupDataEncryptorV4;
    core::ModuleDataEncryptorV5 _groupDataEncryptorV5;
    core::DataEncryptorV4 _eventDataEncryptorV4;
    std::vector<std::string> _forbiddenChannelsNames;
};

} // group
} // endpoint
} // privmx

#endif // _PRIVMXLIB_ENDPOINT_GROUP_GROUPAPIIMPL_HPP_
