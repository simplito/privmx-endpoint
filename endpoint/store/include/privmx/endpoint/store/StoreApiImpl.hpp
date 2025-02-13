/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_ENDPOINT_STORE_STOREAPIIMPL_HPP_
#define _PRIVMXLIB_ENDPOINT_STORE_STOREAPIIMPL_HPP_

#include <memory>
#include <optional>
#include <string>
#include <vector>

#include <privmx/utils/ThreadSaveMap.hpp>

#include <privmx/endpoint/core/Connection.hpp>
#include <privmx/endpoint/core/DataEncryptor.hpp>
#include <privmx/endpoint/core/KeyProvider.hpp>
#include <privmx/endpoint/core/EventMiddleware.hpp>
#include <privmx/endpoint/core/EventChannelManager.hpp>
#include <privmx/endpoint/core/SubscriptionHelper.hpp>

#include "privmx/endpoint/store/DynamicTypes.hpp"
#include "privmx/endpoint/store/FileDataProvider.hpp"
#include "privmx/endpoint/store/FileMetaEncryptor.hpp"
#include "privmx/endpoint/store/RequestApi.hpp"
#include "privmx/endpoint/store/ServerApi.hpp"
#include "privmx/endpoint/store/StoreApi.hpp"
#include "privmx/endpoint/store/FileHandle.hpp"
#include "privmx/endpoint/store/FileKeyIdFormatValidator.hpp"
#include "privmx/endpoint/store/FileMetaEncryptorV4.hpp"
#include "privmx/endpoint/store/StoreDataEncryptorV4.hpp"
#include "privmx/endpoint/store/Events.hpp"
#include "privmx/endpoint/core/Factory.hpp"
#include "privmx/endpoint/store/StoreCache.hpp"

namespace privmx {
namespace endpoint {
namespace store {

class StoreApiImpl
{
public:
    StoreApiImpl(
        const std::shared_ptr<core::KeyProvider>& keyProvider,
        const std::shared_ptr<ServerApi>& serverApi,
        const std::string& host,
        const privmx::crypto::PrivateKey& userPrivKey,
        const std::shared_ptr<RequestApi>& requestApi,
        const std::shared_ptr<FileDataProvider>& fileDataProvider,
        const std::shared_ptr<core::EventMiddleware>& eventMiddleware,
        const std::shared_ptr<core::EventChannelManager>& eventChannelManager,
        const std::shared_ptr<core::HandleManager>& handleManager,
        const core::Connection& connection,
        size_t serverRequestChunkSize
    );
    ~StoreApiImpl();
    std::string createStore(const std::string& contextId, const std::vector<core::UserWithPubKey>& users, const std::vector<core::UserWithPubKey>& managers, 
                const core::Buffer& publicMeta, const core::Buffer& privateMeta,
                const std::optional<core::ContainerPolicy>& policies);
    std::string createStoreEx(const std::string& contextId, const std::vector<core::UserWithPubKey>& users, const std::vector<core::UserWithPubKey>& managers, 
                const core::Buffer& publicMeta, const core::Buffer& privateMeta, const std::string& type,
                const std::optional<core::ContainerPolicy>& policies);
    void updateStore(
        const std::string& storeId, 
        const std::vector<core::UserWithPubKey>& users, 
        const std::vector<core::UserWithPubKey>& managers, 
        const core::Buffer& publicMeta,
        const core::Buffer& privateMeta,
        const int64_t version, 
        const bool force, 
        const bool forceGenerateNewKey,
        const std::optional<core::ContainerPolicy>& policies
    );
    void deleteStore(const std::string& storeId);
    Store getStore(const std::string& storeId);
    Store getStoreEx(const std::string& storeId, const std::string& type);
    core::PagingList<Store> listStores(const std::string& contextId, const core::PagingQuery& query);
    core::PagingList<Store> listStoresEx(const std::string& contextId, const core::PagingQuery& query, const std::string& type);
    File getFile(const std::string& fileId);
    core::PagingList<store::File> listFiles(const std::string& storeId, const core::PagingQuery& query);
    void deleteFile(const std::string& fileId);
    int64_t createFile(const std::string& storeId, const core::Buffer& publicMeta, const core::Buffer& privateMeta, const int64_t size);
    int64_t updateFile(const std::string& fileId, const core::Buffer& publicMeta, const core::Buffer& privateMeta, const int64_t size);
    void updateFileMeta(const std::string& fileId, const core::Buffer& publicMeta, const core::Buffer& privateMeta);
    int64_t openFile(const std::string& fileId);
    void writeToFile(const int64_t handle, const core::Buffer& dataChunk);
    core::Buffer readFromFile(const int64_t handle, const int64_t length);
    void seekInFile(const int64_t handle, const int64_t pos);
    std::string closeFile(const int64_t handle);

    void subscribeForStoreEvents();
    void unsubscribeFromStoreEvents();
    void subscribeForFileEvents(const std::string& storeId);
    void unsubscribeFromFileEvents(const std::string& storeId);
private:
    struct StoreFileDecryptionParams {
        std::string fileId;
        uint64_t sizeOnServer;
        uint64_t originalSize;
        int64_t cipherType;
        size_t chunkSize;
        std::string key;
        std::string hmac;
        int64_t version;
    };
    std::string _storeCreateEx(const std::string& contextId, const std::vector<core::UserWithPubKey>& users, const std::vector<core::UserWithPubKey>& managers, 
                const core::Buffer& publicMeta, const core::Buffer& privateMeta, const std::string& type,
                const std::optional<core::ContainerPolicy>& policies);
    Store _storeGetEx(const std::string& storeId, const std::string& type);
    core::PagingList<Store> _storeListEx(const std::string& contextId, const core::PagingQuery& query, const std::string& type);

    std::vector<std::string> usersWithPubKeyToIds(std::vector<core::UserWithPubKey> &users);
    void processNotificationEvent(const std::string& type, const std::string& channel, const Poco::JSON::Object::Ptr& data);
    void processConnectedEvent();
    void processDisconnectedEvent();
    dynamic::compat_v1::StoreData decryptStoreV1(const server::Store& storeRaw);
    DecryptedStoreData decryptStoreV4(const server::Store& storeRaw);
    Store convertStoreDataV1ToStore(const server::Store& storeRaw, dynamic::compat_v1::StoreData storeData);
    Store convertDecryptedStoreDataToStore(const server::Store& storeRaw, const DecryptedStoreData& storeData);
    Store decryptAndConvertStoreDataToStore(const server::Store& storeRaw);


    // OLD CODE    
    StoreFile decryptStoreFileV1(const server::Store& store, const server::File& storeFile);
    // OLD CODE   
    std::string verifyFileV1Signature(FileMetaSigned meta, server::File raw, std::string& serverId);
    // OLD CODE   
    StoreFile decryptAndVerifyFileV1(const std::string &filesKey, server::File x);
    DecryptedFileMeta decryptFileMetaV4(const server::Store& store, const server::File& file);
    File convertStoreFileMetaV1ToFile(server::File file, dynamic::compat_v1::StoreFileMeta fileData);
    File convertDecryptedFileMetaToFile(server::File file, DecryptedFileMeta fileData);
    File decryptAndConvertFileDataToFileInfo(server::Store store, server::File file);

    std::string storeFileFinalizeWrite(const std::shared_ptr<FileWriteHandle>& handle);
    
    StoreFileDecryptionParams getStoreFileDecryptionParams(const server::File& file, const core::EncKey& encKey);
    int64_t createFileReadHandle(const StoreFileDecryptionParams& storeFileDecryptionParams);
    static const size_t _CHUNK_SIZE;
    
    std::shared_ptr<core::KeyProvider> _keyProvider;
    std::shared_ptr<ServerApi> _serverApi;
    std::string _host;
    privmx::crypto::PrivateKey _userPrivKey;
    std::shared_ptr<RequestApi> _requestApi;
    std::shared_ptr<FileDataProvider> _fileDataProvider;
    std::shared_ptr<core::EventMiddleware> _eventMiddleware;
    std::shared_ptr<core::EventChannelManager> _eventChannelManager;
    std::shared_ptr<core::HandleManager> _handleManager;
    core::Connection _connection;
    size_t _serverRequestChunkSize;
    
    
    FileHandleManager _fileHandleManager;
    core::DataEncryptor<dynamic::compat_v1::StoreData> _dataEncryptorCompatV1;
    FileMetaEncryptor _fileMetaEncryptor;
    FileKeyIdFormatValidator _fileKeyIdFormatValidator;
    StoreCache _storeCache;
    bool _subscribeForStore;
    core::SubscriptionHelper _storeSubscriptionHelper;
    int _notificationListenerId, _connectedListenerId, _disconnectedListenerId;
    std::string _fileDecryptorId, _fileOpenerId, _fileSeekerId, _fileReaderId, _fileCloserId; 

    FileMetaEncryptorV4 _fileMetaEncryptorV4;
    StoreDataEncryptorV4 _storeDataEncryptorV4;
    

    inline static const std::string STORE_TYPE_FILTER_FLAG = "store";
};

} // store
} // endpoint
} // privmx

#endif // _PRIVMXLIB_ENDPOINT_STORE_STOREAPIIMPL_HPP_
