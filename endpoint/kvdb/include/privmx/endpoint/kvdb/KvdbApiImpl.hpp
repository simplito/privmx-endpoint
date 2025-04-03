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
#include <privmx/endpoint/core/DataEncryptor.hpp>
#include <privmx/endpoint/core/KeyProvider.hpp>
#include <privmx/utils/ThreadSaveMap.hpp>
#include <privmx/endpoint/core/EventMiddleware.hpp>
#include <privmx/endpoint/core/EventChannelManager.hpp>
#include <privmx/endpoint/core/SubscriptionHelper.hpp>

#include "privmx/endpoint/kvdb/ServerApi.hpp"
#include "privmx/endpoint/kvdb/KvdbApi.hpp"
#include "privmx/endpoint/kvdb/KvdbItemDataEncryptorV4.hpp"
#include "privmx/endpoint/kvdb/KvdbDataEncryptorV4.hpp"
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
        const std::optional<core::ContainerPolicy>& policies
    );
    void updateKvdb(const std::string& kvdbId, 
        const std::vector<core::UserWithPubKey>& users,
        const std::vector<core::UserWithPubKey>& managers, 
        const core::Buffer& publicMeta, 
        const core::Buffer& privateMeta,
        const int64_t version, 
        const bool force, 
        const bool forceGenerateNewKey, 
        const std::optional<core::ContainerPolicy>& policies
    );
    void deleteKvdb(const std::string& kvdbId);
    Kvdb getKvdb(const std::string& kvdbId);
    Kvdb getKvdbEx(const std::string& kvdbId, const std::string& type);
    core::PagingList<Kvdb> listKvdbs(const std::string& contextId, const core::PagingQuery& pagingQuery);
    core::PagingList<Kvdb> listKvdbsEx(const std::string& contextId, const core::PagingQuery& pagingQuery, const std::string& type);

    Item getItem(const std::string& kvdbId, const std::string& key);
    core::PagingList<std::string> listItemKeys(const std::string& kvdbId, const kvdb::PagingQuery& pagingQuery);
    void setItem(const std::string& kvdbId, const std::string& key, const core::Buffer& data, int64_t version);
    void deleteItem(const std::string& kvdbId, const std::string& key);
    void deleteItems(const std::string& kvdbId, const std::vector<std::string>& keys);


    void subscribeForKvdbEvents();
    void unsubscribeFromKvdbEvents();
    void subscribeForItemEvents(std::string kvdbId);
    void unsubscribeFromItemEvents(std::string kvdbId);
private:
    
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
    int _notificationListenerId, _connectedListenerId, _disconnectedListenerId;
    inline static const std::string KVDB_TYPE_FILTER_FLAG = "kvdb";
};

} // kvdb
} // endpoint
} // privmx

#endif // _PRIVMXLIB_ENDPOINT_KVDB_KVDBAPIIMPL_HPP_
