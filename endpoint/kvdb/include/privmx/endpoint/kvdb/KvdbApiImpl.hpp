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
#include <atomic>

#include <privmx/endpoint/core/ConnectionImpl.hpp>
#include <privmx/endpoint/core/KeyProvider.hpp>
#include <privmx/utils/ThreadSaveMap.hpp>
#include <privmx/endpoint/core/EventMiddleware.hpp>
#include <privmx/endpoint/core/encryptors/module/ModuleDataEncryptorV5.hpp>
#include <privmx/endpoint/core/ModuleBaseApi.hpp>
#include <privmx/endpoint/core/ContainerKeyCache.hpp>

#include "privmx/endpoint/kvdb/ServerApi.hpp"
#include "privmx/endpoint/kvdb/KvdbApi.hpp"
#include "privmx/endpoint/kvdb/encryptors/entry/EntryDataEncryptorV5.hpp"
#include "privmx/endpoint/kvdb/Events.hpp"
#include "privmx/endpoint/core/Factory.hpp"
#include "privmx/endpoint/kvdb/Constants.hpp"
#include "privmx/endpoint/kvdb/SubscriberImpl.hpp"


namespace privmx {
namespace endpoint {
namespace kvdb {

class KvdbApiImpl : protected core::ModuleBaseApi
{
public:
    KvdbApiImpl(
        const privfs::RpcGateway::Ptr& gateway,
        const privmx::crypto::PrivateKey& userPrivKey,
        const std::shared_ptr<core::KeyProvider>& keyProvider,
        const std::string& host,
        const std::shared_ptr<core::EventMiddleware>& eventMiddleware,
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

    KvdbEntry getEntry(const std::string& kvdbId, const std::string& key);
    bool hasEntry(const std::string& kvdbId, const std::string& key);
    core::PagingList<std::string> listEntriesKeys(const std::string& kvdbId, const core::PagingQuery& pagingQuery);
    core::PagingList<KvdbEntry> listEntries(const std::string& kvdbId, const core::PagingQuery& pagingQuery);
    void setEntry(const std::string& kvdbId, const std::string& key, const core::Buffer& publicMeta, const core::Buffer& privateMeta, const core::Buffer& data, int64_t version);
    void deleteEntry(const std::string& kvdbId, const std::string& key);
    std::map<std::string, bool> deleteEntries(const std::string& kvdbId, const std::vector<std::string>& keys);

    std::vector<std::string> subscribeFor(const std::vector<std::string>& subscriptionQueries);
    void unsubscribeFrom(const std::vector<std::string>& subscriptionIds);
    std::string buildSubscriptionQuery(EventType eventType, EventSelectorType selectorType, const std::string& selectorId);
    std::string buildSubscriptionQueryForSelectedEntry(EventType eventType, const std::string& kvdbId, const std::string& kvdbEntryKey);
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

    void processNotificationEvent(const std::string& type, const core::NotificationEvent& notification);
    void processConnectedEvent();
    void processDisconnectedEvent();
    utils::List<std::string> mapUsers(const std::vector<core::UserWithPubKey>& users);

    Kvdb convertServerKvdbToLibKvdb(
        server::KvdbInfo kvdb,
        const core::Buffer& publicMeta = core::Buffer(),
        const core::Buffer& privateMeta = core::Buffer(),
        const int64_t& statusCode = 0,
        const int64_t& schemaVersion = KvdbDataSchema::Version::UNKNOWN
    );
    Kvdb convertDecryptedKvdbDataV5ToKvdb(server::KvdbInfo kvdbInfo, const core::DecryptedModuleDataV5& kvdbData);
    KvdbDataSchema::Version getKvdbDataEntryStructureVersion(server::KvdbDataEntry kvdbEntry);
    std::tuple<Kvdb, core::DataIntegrityObject> decryptAndConvertKvdbDataToKvdb(server::KvdbInfo kvdb, server::KvdbDataEntry kvdbEntry, const core::DecryptedEncKey& encKey);
    std::vector<Kvdb> validateDecryptAndConvertKvdbsDataToKvdbs(utils::List<server::KvdbInfo> kvdbs);
    Kvdb validateDecryptAndConvertKvdbDataToKvdb(server::KvdbInfo kvdb);
    void assertKvdbDataIntegrity(server::KvdbInfo kvdb);
    uint32_t validateKvdbDataIntegrity(server::KvdbInfo kvdb);
    virtual std::pair<core::ModuleKeys, int64_t> getModuleKeysAndVersionFromServer(std::string moduleId) override;
    core::ModuleKeys kvdbToModuleKeys(server::KvdbInfo kvdb);


    DecryptedKvdbEntryDataV5 decryptKvdbEntryDataV5(server::KvdbEntryInfo entry, const core::DecryptedEncKey& encKey);
    KvdbEntry convertDecryptedKvdbEntryDataV5ToKvdbEntry(server::KvdbEntryInfo entry, DecryptedKvdbEntryDataV5 entryData);
    KvdbEntry convertServerKvdbEntryToLibKvdbEntry(
        server::KvdbEntryInfo entry,
        const core::Buffer& publicMeta = core::Buffer(),
        const core::Buffer& privateMeta = core::Buffer(),
        const core::Buffer& data = core::Buffer(),
        const std::string& authorPubKey = std::string(),
        const int64_t& statusCode = 0,
        const int64_t& schemaVersion = KvdbEntryDataSchema::Version::UNKNOWN
    );
    KvdbEntryDataSchema::Version getEntryDataStructureVersion(server::KvdbEntryInfo entry);
    std::tuple<KvdbEntry, core::DataIntegrityObject> decryptAndConvertEntryDataToEntry(server::KvdbEntryInfo entry, const core::DecryptedEncKey& encKey);
    std::vector<KvdbEntry> validateDecryptAndConvertKvdbEntriesDataToKvdbEntries(utils::List<server::KvdbEntryInfo> entries, const core::ModuleKeys& kvdbKeys);
    KvdbEntry validateDecryptAndConvertEntryDataToEntry(server::KvdbEntryInfo entry, const core::ModuleKeys& kvdbKeys);
    core::ModuleKeys getEntryDecryptionKeys(server::KvdbEntryInfo entry);
    uint32_t validateEntryDataIntegrity(server::KvdbEntryInfo entry, const std::string& kvdbResourceId);
    Poco::Dynamic::Var encryptEntryData(
        const std::string& kvdbId, 
        const std::string& resourceId, 
        const core::Buffer& publicMeta, 
        const core::Buffer& privateMeta, 
        const core::Buffer& data, 
        const core::ModuleKeys& kvdbKeys
    );
    void setEntryRequest(
        const std::string& kvdbId, 
        const std::string& key, 
        const core::Buffer& publicMeta, 
        const core::Buffer& privateMeta, 
        const core::Buffer& data, 
        int64_t version,
        const core::ModuleKeys& keys
    );

    void assertKvdbExist(const std::string& kvdbId);
    privfs::RpcGateway::Ptr _gateway;
    privmx::crypto::PrivateKey _userPrivKey;
    std::shared_ptr<core::KeyProvider> _keyProvider;
    std::string _host;
    std::shared_ptr<core::EventMiddleware> _eventMiddleware;
    core::Connection _connection;
    ServerApi _serverApi;
    SubscriberImpl _subscriber;
    core::ModuleDataEncryptorV5 _kvdbDataEncryptorV5;
    EntryDataEncryptorV5 _entryDataEncryptorV5;
    int _notificationListenerId, _connectedListenerId, _disconnectedListenerId;
    inline static const std::string KVDB_TYPE_FILTER_FLAG = "kvdb";
};

} // kvdb
} // endpoint
} // privmx

#endif // _PRIVMXLIB_ENDPOINT_KVDB_KVDBAPIIMPL_HPP_
