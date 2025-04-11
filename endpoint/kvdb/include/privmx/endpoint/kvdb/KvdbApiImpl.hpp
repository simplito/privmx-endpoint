/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_ENDPOINT_KVDB_KVDBAPIIMPL_HPP_
#define _PRIVMXLIB_ENDPOINT_KVDB_KVDBAPIIMPL_HPP_

#include <memory>
#include <optional>
#include <string>

#include <privmx/endpoint/core/ConnectionImpl.hpp>
#include <privmx/endpoint/core/KeyProvider.hpp>
#include <privmx/utils/ThreadSaveMap.hpp>
#include <privmx/endpoint/core/EventMiddleware.hpp>
#include <privmx/endpoint/core/EventChannelManager.hpp>
#include <privmx/endpoint/core/SubscriptionHelper.hpp>

#include "privmx/endpoint/kvdb/ServerApi.hpp"
#include "privmx/endpoint/kvdb/KvdbApi.hpp"
#include "privmx/endpoint/kvdb/encryptors/kvdb/KvdbDataEncryptorV5.hpp"
#include "privmx/endpoint/kvdb/encryptors/item/ItemDataEncryptorV5.hpp"
#include "privmx/endpoint/kvdb/Events.hpp"
#include "privmx/endpoint/core/Factory.hpp"
#include "privmx/endpoint/kvdb/KvdbProvider.hpp"

namespace privmx {
namespace endpoint {
namespace kvdb {

class KvdbApiImpl
{
public:
    KvdbApiImpl(
        const privfs::RpcGateway::Ptr& gateway,
        const privmx::crypto::PrivateKey& userPrivKey,
        const std::shared_ptr<core::KeyProvider>& keyProvider,
        const std::string& host,
        const std::shared_ptr<core::EventMiddleware>& eventMiddleware,
        const std::shared_ptr<core::EventChannelManager>& eventChannelManager,
        const core::Connection& connection
    );
    ~KvdbApiImpl();
    std::string createKvdb(const std::string& contextId, 
        const std::vector<core::UserWithPubKey>& users,
        const std::vector<core::UserWithPubKey>& managers, 
        const core::Buffer& publicMeta, 
        const core::Buffer& privateMeta, 
        const std::optional<core::ContainerPolicy>& policies = std::nullopt
    );
    void updateKvdb(const std::string& kvdbId, 
        const std::vector<core::UserWithPubKey>& users,
        const std::vector<core::UserWithPubKey>& managers, 
        const core::Buffer& publicMeta, 
        const core::Buffer& privateMeta,
        const int64_t version, 
        const bool force, 
        const bool forceGenerateNewKey, 
        const std::optional<core::ContainerPolicy>& policies = std::nullopt
    );
    void deleteKvdb(const std::string& kvdbId);
    Kvdb getKvdb(const std::string& kvdbId);
    Kvdb getKvdbEx(const std::string& kvdbId, const std::string& type);
    core::PagingList<Kvdb> listKvdbs(const std::string& contextId, const core::PagingQuery& pagingQuery);
    core::PagingList<Kvdb> listKvdbsEx(const std::string& contextId, const core::PagingQuery& pagingQuery, const std::string& type);

    Item getItem(const std::string& kvdbId, const std::string& key);
    core::PagingList<std::string> listItemKeys(const std::string& kvdbId, const kvdb::KeysPagingQuery& pagingQuery);
    core::PagingList<Item> listItem(const std::string& kvdbId, const kvdb::ItemsPagingQuery& pagingQuery);
    void setItem(const std::string& kvdbId, const std::string& key, const core::Buffer& publicMeta, const core::Buffer& privateMeta, const core::Buffer& data, int64_t version);
    void deleteItem(const std::string& kvdbId, const std::string& key);
    std::map<std::string, bool> deleteItems(const std::string& kvdbId, const std::vector<std::string>& keys);

    void subscribeForKvdbEvents();
    void unsubscribeFromKvdbEvents();
    void subscribeForItemEvents(std::string kvdbId);
    void unsubscribeFromItemEvents(std::string kvdbId);
private:
    std::string createKvdbEx(
        const std::string& contextId, 
        const std::vector<core::UserWithPubKey>& users, 
        const std::vector<core::UserWithPubKey>& managers,
        const core::Buffer& publicMeta,
        const core::Buffer& privateMeta,
        const std::string& type,
        const std::optional<core::ContainerPolicy>& policies
    );
    server::KvdbInfo getRawKvdbFromCacheOrBridge(const std::string& kvdbId);

    void processNotificationEvent(const std::string& type, const std::string& channel, const Poco::JSON::Object::Ptr& data);
    void processConnectedEvent();
    void processDisconnectedEvent();
    utils::List<std::string> mapUsers(const std::vector<core::UserWithPubKey>& users);

    DecryptedKvdbDataV5 decryptKvdbV5(server::KvdbDataEntry kvdbEntry, const core::DecryptedEncKey& encKey);
    Kvdb convertDecryptedKvdbDataV5ToKvdb(server::KvdbInfo kvdbInfo, const DecryptedKvdbDataV5& kvdbData);
    std::tuple<Kvdb, core::DataIntegrityObject> decryptAndConvertKvdbDataToKvdb(server::KvdbInfo kvdb, server::KvdbDataEntry kvdbEntry, const core::DecryptedEncKey& encKey);
    std::vector<Kvdb> decryptAndConvertKvdbsDataToKvdbs(utils::List<server::KvdbInfo> kvdbs);
    Kvdb decryptAndConvertKvdbDataToKvdb(server::KvdbInfo kvdb);
    std::string decryptKvdbInternalMeta(server::KvdbDataEntry kvdbEntry, const core::DecryptedEncKey& encKey);
    uint32_t validateKvdbDataIntegrity(server::KvdbInfo kvdb);
    core::DecryptedEncKey getKvdbCurrentEncKey(server::KvdbInfo kvdb);

    DecryptedItemDataV5 decryptItemDataV5(server::KvdbItemInfo item, const core::DecryptedEncKey& encKey);
    Item convertDecryptedItemDataV5ToItem(server::KvdbItemInfo item, DecryptedItemDataV5 itemData);
    std::tuple<Item, core::DataIntegrityObject> decryptAndConvertItemDataToItem(server::KvdbItemInfo item, const core::DecryptedEncKey& encKey);
    std::vector<Item> decryptAndConvertItemsDataToItems(server::KvdbInfo kvdb, utils::List<server::KvdbItemInfo> items);
    Item decryptAndConvertItemDataToItem(server::KvdbInfo kvdb, server::KvdbItemInfo item);
    Item decryptAndConvertItemDataToItem(server::KvdbItemInfo item);
    uint32_t validateItemDataIntegrity(server::KvdbItemInfo item);
    
    void assertKvdbExist(const std::string& kvdbId);
    privfs::RpcGateway::Ptr _gateway;
    privmx::crypto::PrivateKey _userPrivKey;
    std::shared_ptr<core::KeyProvider> _keyProvider;
    std::string _host;
    std::shared_ptr<core::EventMiddleware> _eventMiddleware;
    core::Connection _connection;
    ServerApi _serverApi;
    KvdbProvider _kvdbProvider;
    bool _subscribeForKvdb;
    core::SubscriptionHelper _kvdbSubscriptionHelper;
    KvdbDataEncryptorV5 _kvdbDataEncryptorV5;
    ItemDataEncryptorV5 _itemDataEncryptorV5;
    int _notificationListenerId, _connectedListenerId, _disconnectedListenerId;
    inline static const std::string KVDB_TYPE_FILTER_FLAG = "kvdb";
};

} // kvdb
} // endpoint
} // privmx

#endif // _PRIVMXLIB_ENDPOINT_KVDB_KVDBAPIIMPL_HPP_
