/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include <Poco/ByteOrder.h>
#include <privmx/crypto/Crypto.hpp>
#include <privmx/utils/Debug.hpp>

#include <privmx/endpoint/core/EndpointUtils.hpp>
#include <privmx/endpoint/core/VarDeserializer.hpp>
#include <privmx/endpoint/core/VarSerializer.hpp>
#include <privmx/endpoint/core/ExceptionConverter.hpp>

#include <privmx/endpoint/store/StoreException.hpp>
#include "privmx/endpoint/store/DynamicTypes.hpp"
#include "privmx/endpoint/store/ServerTypes.hpp"
#include "privmx/endpoint/store/StoreApiImpl.hpp"
#include "privmx/endpoint/store/Mapper.hpp"
#include "privmx/endpoint/store/StoreVarSerializer.hpp"
#include "privmx/endpoint/core/ListQueryMapper.hpp"

using namespace privmx::endpoint;
using namespace privmx::endpoint::store;

const size_t StoreApiImpl::_CHUNK_SIZE = 128 * 1024;

StoreApiImpl::StoreApiImpl(
    const std::shared_ptr<core::KeyProvider>& keyProvider,
    const std::shared_ptr<ServerApi>& serverApi,
    const std::string& host,
    const privmx::crypto::PrivateKey& userPrivKey,
    const std::shared_ptr<RequestApi>& requestApi,
    const std::shared_ptr<store::FileDataProvider>& fileDataProvider,
    const std::shared_ptr<core::EventMiddleware>& eventMiddleware,
    const std::shared_ptr<core::EventChannelManager>& eventChannelManager,
    const std::shared_ptr<core::HandleManager>& handleManager,
    const core::Connection& connection,
    size_t serverRequestChunkSize
) : _keyProvider(keyProvider),
    _serverApi(serverApi),
    _host(host),
    _userPrivKey(userPrivKey),
    _requestApi(requestApi),
    _fileDataProvider(fileDataProvider),
    _eventMiddleware(eventMiddleware),
    _eventChannelManager(eventChannelManager),
    _handleManager(handleManager),
    _connection(connection),
    _serverRequestChunkSize(serverRequestChunkSize),

    _fileHandleManager(FileHandleManager(handleManager, "Store")),
    _dataEncryptorCompatV1(core::DataEncryptor<dynamic::compat_v1::StoreData>()),
    _fileMetaEncryptor(FileMetaEncryptor()),
    _fileKeyIdFormatValidator(FileKeyIdFormatValidator()),
    _storeProvider(StoreProvider([&](const std::string& id) {
        auto model = privmx::utils::TypedObjectFactory::createNewObject<server::StoreGetModel>();
        model.storeId(id);
        model.type(STORE_TYPE_FILTER_FLAG);
        return _serverApi->storeGet(model).store();
    })),
    _subscribeForStore(false),
    _storeSubscriptionHelper(core::SubscriptionHelper(eventChannelManager, "store", "files")),
    _fileMetaEncryptorV4(FileMetaEncryptorV4()),
    _storeDataEncryptorV4(StoreDataEncryptorV4()),
    _unallowedChannelsNames({INTERNAL_EVENT_CHANNEL_NAME, "store", "files"}) 
{
    _notificationListenerId = _eventMiddleware->addNotificationEventListener(std::bind(&StoreApiImpl::processNotificationEvent, this, std::placeholders::_1, std::placeholders::_2, std::placeholders::_3));
    _connectedListenerId = _eventMiddleware->addConnectedEventListener(std::bind(&StoreApiImpl::processConnectedEvent, this));
    _disconnectedListenerId = _eventMiddleware->addDisconnectedEventListener(std::bind(&StoreApiImpl::processDisconnectedEvent, this));
}

StoreApiImpl::~StoreApiImpl() {
    _eventMiddleware->removeNotificationEventListener(_notificationListenerId);
    _eventMiddleware->removeConnectedEventListener(_connectedListenerId);
    _eventMiddleware->removeDisconnectedEventListener(_disconnectedListenerId);
}

std::string StoreApiImpl::createStore(const std::string& contextId, const std::vector<core::UserWithPubKey>& users, const std::vector<core::UserWithPubKey>& managers, 
            const core::Buffer& publicMeta, const core::Buffer& privateMeta,
            const std::optional<core::ContainerPolicy>& policies) {
    return _storeCreateEx(contextId, users, managers, publicMeta, privateMeta, STORE_TYPE_FILTER_FLAG, policies);
}

std::string StoreApiImpl::createStoreEx(const std::string& contextId, const std::vector<core::UserWithPubKey>& users, const std::vector<core::UserWithPubKey>& managers, 
            const core::Buffer& publicMeta, const core::Buffer& privateMeta,
            const std::string& type, const std::optional<core::ContainerPolicy>& policies) {
    return _storeCreateEx(contextId, users, managers, publicMeta, privateMeta, type, policies);
}

std::string StoreApiImpl::_storeCreateEx(const std::string& contextId, const std::vector<core::UserWithPubKey>& users, const std::vector<core::UserWithPubKey>& managers, 
            const core::Buffer& publicMeta, const core::Buffer& privateMeta, const std::string& type,
            const std::optional<core::ContainerPolicy>& policies) {
    PRIVMX_DEBUG_TIME_START(PlatformStore, _storeCreateEx)
    auto storeKey = _keyProvider->generateKey();
    StoreDataToEncrypt storeDataToEncrypt {
        .publicMeta = publicMeta,
        .privateMeta = privateMeta,
        .internalMeta = std::nullopt
    };
    // auto new_store_data = utils::TypedObjectFactory::createNewObject<dynamic::StoreData>();
    // new_store_data.name(name);
    auto storeCreateModel = utils::TypedObjectFactory::createNewObject<server::StoreCreateModel>();
    storeCreateModel.contextId(contextId);
    storeCreateModel.keyId(storeKey.id);
    storeCreateModel.data(_storeDataEncryptorV4.encrypt(storeDataToEncrypt, _userPrivKey, storeKey.key).asVar());
    if (type.length() > 0) {
        storeCreateModel.type(type);
    }
    if (policies.has_value()) {
        storeCreateModel.policy(privmx::endpoint::core::Factory::createPolicyServerObject(policies.value()));
    }
    auto all_users = core::EndpointUtils::uniqueListUserWithPubKey(users, managers);
    storeCreateModel.keys(_keyProvider->prepareKeysList(all_users, storeKey));

    auto usersList = utils::TypedObjectFactory::createNewList<std::string>();
    for (auto user: users) {
        usersList.add(user.userId);
    }
    auto managersList = utils::TypedObjectFactory::createNewList<std::string>();
    for (auto x: managers) {
        managersList.add(x.userId);
    }
    storeCreateModel.users(usersList);
    storeCreateModel.managers(managersList);
    PRIVMX_DEBUG_TIME_CHECKPOINT(PlatformStore, _storeCreateEx, data encrypted)
    auto storeId = _serverApi->storeCreate(storeCreateModel).storeId();
    PRIVMX_DEBUG_TIME_STOP(PlatformStore, storeCreate, data send)
    return storeId;

}

std::vector<std::string> StoreApiImpl::usersWithPubKeyToIds(std::vector<core::UserWithPubKey>& users) {
    std::vector<std::string> ids{};
    for (auto & user : users) {
        ids.push_back(user.userId);
    }
    return ids;
}

void StoreApiImpl::updateStore(
        const std::string& storeId,
        const std::vector<core::UserWithPubKey>& users,
        const std::vector<core::UserWithPubKey>& managers,
        const core::Buffer& publicMeta,
        const core::Buffer& privateMeta,
        const int64_t version,
        const bool force,
        const bool forceGenerateNewKey,
        const std::optional<core::ContainerPolicy>& policies
) {
    PRIVMX_DEBUG_TIME_START(PlatformStore, storeUpdate)

    // get current store
    auto getModel = utils::TypedObjectFactory::createNewObject<server::StoreGetModel>();
    getModel.storeId(storeId);
    auto currentStore {_serverApi->storeGet(getModel).store()};

    // std::cout << "STORE RAW on get" << std::endl;
    // std::cout << utils::Utils::stringify(currentStore, true) << std::endl;

    // extract current users info
    auto usersVec {core::EndpointUtils::listToVector<std::string>(currentStore.users())};
    auto managersVec {core::EndpointUtils::listToVector<std::string>(currentStore.managers())};
    auto oldUsersAll {core::EndpointUtils::uniqueList(usersVec, managersVec)};

    auto new_users = core::EndpointUtils::uniqueListUserWithPubKey(users, managers);

    // adjust key
    std::vector<std::string> usersDiff {core::EndpointUtils::getDifference(oldUsersAll, usersWithPubKeyToIds(new_users))};

    bool needNewKey = usersDiff.size() > 0;

    auto currentKey {_keyProvider->getKey(currentStore.keys(), currentStore.keyId())};
    auto storeKey = forceGenerateNewKey || needNewKey ? _keyProvider->generateKey() : currentKey; 

    auto model = utils::TypedObjectFactory::createNewObject<server::StoreUpdateModel>();


    auto usersList = utils::TypedObjectFactory::createNewList<std::string>();
    for (auto user: users) {
        usersList.add(user.userId);
    }
    auto managersList = utils::TypedObjectFactory::createNewList<std::string>();
    for (auto x: managers) {
        managersList.add(x.userId);
    }

    model.id(storeId);
    model.keyId(storeKey.id);
    model.keys(_keyProvider->prepareKeysList(new_users, storeKey));
    model.users(usersList);
    model.managers(managersList);
    model.version(version);
    model.force(force);
    if (policies.has_value()) {
        model.policy(privmx::endpoint::core::Factory::createPolicyServerObject(policies.value()));
    }
    StoreDataToEncrypt storeDataToEncrypt {
        .publicMeta = publicMeta,
        .privateMeta = privateMeta,
        .internalMeta = std::nullopt
    };
    model.data(_storeDataEncryptorV4.encrypt(storeDataToEncrypt, _userPrivKey, storeKey.key).asVar());

    PRIVMX_DEBUG_TIME_CHECKPOINT(PlatformStore, storeUpdate, data encrypted)
    _serverApi->storeUpdate(model);
    PRIVMX_DEBUG_TIME_STOP(PlatformStore, storeUpdate, data send)
}

void StoreApiImpl::deleteStore(const std::string& storeId) {
    auto model = utils::TypedObjectFactory::createNewObject<server::StoreDeleteModel>();
    model.storeId(storeId);
    _serverApi->storeDelete(model);
}

Store StoreApiImpl::getStore(const std::string& storeId) {
    return _storeGetEx(storeId, STORE_TYPE_FILTER_FLAG);
}

Store StoreApiImpl::getStoreEx(const std::string& storeId, const std::string& type) {
    return _storeGetEx(storeId, type);
}

Store StoreApiImpl::_storeGetEx(const std::string& storeId, const std::string& type) {
    PRIVMX_DEBUG_TIME_START(PlatformStore, _storeGetEx)
    auto model = privmx::utils::TypedObjectFactory::createNewObject<server::StoreGetModel>();
    model.storeId(storeId);
    if (type.length() > 0) {
        model.type(type);
    }
    PRIVMX_DEBUG_TIME_CHECKPOINT(PlatformStore, _storeGetEx, getting store)
    auto store = _serverApi->storeGet(model).store();
    PRIVMX_DEBUG_TIME_CHECKPOINT(PlatformStore, _storeGetEx, data send)
    _storeProvider.updateCache(store.id(), store);
    auto result = decryptAndConvertStoreDataToStore(store);
    PRIVMX_DEBUG_TIME_STOP(PlatformStore, _storeGetEx, data decrypted)
    return result;
}

core::PagingList<Store> StoreApiImpl::listStores(const std::string& contextId, const core::PagingQuery& query) {
    return _storeListEx(contextId, query, STORE_TYPE_FILTER_FLAG);
}

core::PagingList<Store> StoreApiImpl::listStoresEx(const std::string& contextId, const core::PagingQuery& query, const std::string& type) {
    return _storeListEx(contextId, query, type);
}

core::PagingList<Store> StoreApiImpl::_storeListEx(const std::string& contextId, const core::PagingQuery& query, const std::string& type) {
    PRIVMX_DEBUG_TIME_START(PlatformStore, storeList)
    std::vector<Store> stores;
    auto storeListModel = utils::TypedObjectFactory::createNewObject<server::StoreListModel>();
    storeListModel.contextId(contextId);
    if (type.length() > 0) {
        storeListModel.type(type);
    }
    core::ListQueryMapper::map(storeListModel, query);
    PRIVMX_DEBUG_TIME_CHECKPOINT(PlatformStore, storeList)
    auto storesResult = _serverApi->storeList(storeListModel);
    PRIVMX_DEBUG_TIME_CHECKPOINT(PlatformStore, storeList, data send)
    for(auto store : storesResult.stores()) {
        _storeProvider.updateCache(store.id(), store);
        stores.push_back(decryptAndConvertStoreDataToStore(store));
    }
    core::PagingList<Store> result = {
        .totalAvailable = storesResult.count(),
        .readItems = stores
    };
    PRIVMX_DEBUG_TIME_STOP(PlatformStore, storeList, data decrypted)
    return result;
}

File StoreApiImpl::getFile(const std::string& fileId) {
    PRIVMX_DEBUG_TIME_START(PlatformStore, storeFileGet)
    auto storeFileGetModel = utils::TypedObjectFactory::createNewObject<server::StoreFileGetModel>();
    storeFileGetModel.fileId(fileId);
    PRIVMX_DEBUG_TIME_CHECKPOINT(PlatformStore, storeFileGet)
    auto serverFileResult = _serverApi->storeFileGet(storeFileGetModel);
    PRIVMX_DEBUG_TIME_CHECKPOINT(PlatformStore, storeFileGet, data send)
    // auto ret {convertStoreFile(file_raw.file(), decryptStoreFile(file_raw.store(), file_raw.file()).meta)};
    auto ret {decryptAndConvertFileDataToFileInfo(serverFileResult.store(), serverFileResult.file())};
    PRIVMX_DEBUG_TIME_STOP(PlatformStore, storeFileGet, data decrypted)
    return ret;
}

core::PagingList<File> StoreApiImpl::listFiles(const std::string& storeId, const core::PagingQuery& query) {
    PRIVMX_DEBUG_TIME_START(PlatformStore, storeFileList)
    auto model = utils::TypedObjectFactory::createNewObject<server::StoreFileListModel>();
    model.storeId(storeId);
    core::ListQueryMapper::map(model, query);

    PRIVMX_DEBUG_TIME_CHECKPOINT(PlatformStore, storeFileList)
    auto serverFilesResult = _serverApi->storeFileList(model);
    PRIVMX_DEBUG_TIME_CHECKPOINT(PlatformStore, storeFileList, data send)

    std::vector<File> filesList;
    // auto store {convertStore(files_raw.store(), decryptStore(files_raw.store()))};
    for(auto rawFile: serverFilesResult.files()) {
        // auto file {convertStoreFile(file_raw, decryptStoreFile(files_raw.store(), file_raw).meta)};
        auto file {decryptAndConvertFileDataToFileInfo(serverFilesResult.store(), rawFile)};
        filesList.push_back(file);
    }
    core::PagingList<File> ret({
        .totalAvailable = serverFilesResult.count(),
        .readItems = filesList
    });
    PRIVMX_DEBUG_TIME_STOP(PlatformStore, storeFileList, data decrypted)
    return ret;
}

void StoreApiImpl::deleteFile(const std::string& fileId) {
    PRIVMX_DEBUG_TIME_START(PlatformStore, storeFileDelete)
    auto model{utils::TypedObjectFactory::createNewObject<server::StoreFileDeleteModel>()};
    model.fileId(fileId);
    PRIVMX_DEBUG_TIME_CHECKPOINT(PlatformStore, storeFileWrite)
    _serverApi->storeFileDelete(model);
    PRIVMX_DEBUG_TIME_STOP(PlatformStore, storeFileDelete, data send)
}

int64_t StoreApiImpl::createFile(const std::string& storeId, const core::Buffer& publicMeta, const core::Buffer& privateMeta, const int64_t size) {
    //check if store exist
    auto store = _storeProvider.get(storeId, !_subscribeForStore);

    std::shared_ptr<FileWriteHandle> handle = _fileHandleManager.createFileWriteHandle(
        storeId,
        std::string(),
        (uint64_t)size,
        publicMeta,
        privateMeta,
        _CHUNK_SIZE,
        _serverRequestChunkSize,
        _requestApi
    );
    handle->createRequestData();
    return handle->getId();
}

int64_t StoreApiImpl::updateFile(const std::string& fileId, const core::Buffer& publicMeta, const core::Buffer& privateMeta, const int64_t size) {
    //check if file exist
    auto storeFileGetModel = utils::TypedObjectFactory::createNewObject<server::StoreFileGetModel>();
    storeFileGetModel.fileId(fileId);
    auto file_raw = _serverApi->storeFileGet(storeFileGetModel);

   std::shared_ptr<FileWriteHandle> handle = _fileHandleManager.createFileWriteHandle(
        std::string(),
        fileId,
        (uint64_t)size,
        publicMeta,
        privateMeta,
        _CHUNK_SIZE,
        _serverRequestChunkSize,
        _requestApi
    );
    handle->createRequestData();
    return handle->getId();
}

int64_t StoreApiImpl::openFile(const std::string& fileId) {
    auto storeFileGetModel = utils::TypedObjectFactory::createNewObject<server::StoreFileGetModel>();
    storeFileGetModel.fileId(fileId);
    auto file_raw = _serverApi->storeFileGet(storeFileGetModel);
    auto key = _keyProvider->getKey(file_raw.store().keys(), file_raw.store().keyId());
    auto decryptionParams = getStoreFileDecryptionParams(file_raw.file(), key);
    return createFileReadHandle(decryptionParams);
}

StoreApiImpl::StoreFileDecryptionParams StoreApiImpl::getStoreFileDecryptionParams(const server::File& file, const core::EncKey& encKey) {
    if (!file.meta().isString()) {
        // When meta is not string, then is new V4 format as object
        auto encryptedFileMeta = utils::TypedObjectFactory::createObjectFromVar<server::EncryptedFileMetaV4>(file.meta());
        auto fileMeta = _fileMetaEncryptorV4.decrypt(encryptedFileMeta, encKey.key);
        auto internalMeta = utils::TypedObjectFactory::createObjectFromVar<dynamic::InternalStoreFileMeta>(utils::Utils::parseJson(fileMeta.internalMeta.stdString()));
        if ((uint64_t)internalMeta.chunkSize() > SIZE_MAX) {
            throw NumberToBigForCPUArchitectureException("chunkSize to big for this CPU architecture");
        }
        return StoreFileDecryptionParams {
            .fileId = file.id(),
            .sizeOnServer = (uint64_t)file.size(),
            .originalSize = (uint64_t)internalMeta.size(),
            .cipherType = internalMeta.cipherType(),
            .chunkSize = (size_t)internalMeta.chunkSize(),
            .key = privmx::utils::Base64::toString(internalMeta.key()),
            .hmac = privmx::utils::Base64::toString(internalMeta.hmac()),
            .version = file.version()
        };
    } else {
        // When meta is string, then old version
        auto decryptedFile = decryptAndVerifyFileV1(encKey.key, file);
        if ((uint64_t)decryptedFile.meta.chunkSize() > SIZE_MAX) {
            throw NumberToBigForCPUArchitectureException("chunkSize to big for this CPU architecture");
        }
        return StoreFileDecryptionParams {
            .fileId = file.id(),
            .sizeOnServer = (uint64_t)file.size(),
            .originalSize = (uint64_t)decryptedFile.meta.size(),
            .cipherType = decryptedFile.meta.cipherType(),
            .chunkSize = (size_t)decryptedFile.meta.chunkSize(),
            .key = privmx::utils::Base64::toString(decryptedFile.meta.key()),
            .hmac = privmx::utils::Base64::toString(decryptedFile.meta.hmac()),
            .version = file.version()
        };
    }
}

int64_t StoreApiImpl::createFileReadHandle(const StoreFileDecryptionParams& storeFileDecryptionParams) {
    if (storeFileDecryptionParams.cipherType != 1) {
        throw UnsupportedCipherTypeException(std::to_string(storeFileDecryptionParams.cipherType) + " expected type: 1");
    }
    std::shared_ptr<FileReadHandle> handle = _fileHandleManager.createFileReadHandle(
        storeFileDecryptionParams.fileId, 
        storeFileDecryptionParams.originalSize,
        storeFileDecryptionParams.sizeOnServer,
        storeFileDecryptionParams.chunkSize,
        _serverRequestChunkSize,
        storeFileDecryptionParams.version,
        storeFileDecryptionParams.key,
        storeFileDecryptionParams.hmac,
        _serverApi
    );
    return handle->getId();
}

void StoreApiImpl::writeToFile(const int64_t handleId, const core::Buffer& dataChunk) {
    std::shared_ptr<FileWriteHandle> handle = _fileHandleManager.getFileWriteHandle(handleId);
    handle->write(dataChunk.stdString());
}

core::Buffer StoreApiImpl::readFromFile(const int64_t handle, const int64_t length) {
    std::shared_ptr<FileReadHandle> handlePtr = _fileHandleManager.getFileReadHandle(handle);
    try {
        return core::Buffer::from(handlePtr->read(length));
    } catch(const store::FileVersionMismatchException& e) {
        closeFile(handle);
        throw FileVersionMismatchHandleClosedException();
    }

}

void StoreApiImpl::seekInFile(const int64_t handle, const int64_t pos) {
    std::shared_ptr<FileReadHandle> handlePtr = _fileHandleManager.getFileReadHandle(handle);
    handlePtr->seek(pos);
}

std::string StoreApiImpl::closeFile(const int64_t handle) {
    std::shared_ptr<FileHandle> handlePtr = _fileHandleManager.getFileHandle(handle);
    _fileHandleManager.removeHandle(handle);
    if (handlePtr->isWriteHandle()) {
        try {
            return storeFileFinalizeWrite(std::dynamic_pointer_cast<FileWriteHandle>(handlePtr));
        } catch (const core::DataDifferentThanDeclaredException& e) {
            throw WritingToFileInteruptedWrittenDataSmallerThenDeclaredException();
        }
    }
    return handlePtr->getFileId();
}

std::string StoreApiImpl::storeFileFinalizeWrite(const std::shared_ptr<FileWriteHandle>& handle) {
    auto data = handle->finalize();
    auto serverId = _host;
    
    server::Store store;
    if (handle->getFileId().empty()) {
        store = _storeProvider.get(handle->getStoreId(), !_subscribeForStore);
    } else {
        auto storeFileGetModel = utils::TypedObjectFactory::createNewObject<server::StoreFileGetModel>();
        storeFileGetModel.fileId(handle->getFileId());
        store = _serverApi->storeFileGet(storeFileGetModel).store();
    }
    auto key = _keyProvider->getKey(store.keys(), store.keyId());

    auto internalFileMeta = utils::TypedObjectFactory::createNewObject<dynamic::InternalStoreFileMeta>();
    internalFileMeta.version(4);
    internalFileMeta.size(handle->getSize());
    internalFileMeta.cipherType(data.cipherType);
    internalFileMeta.chunkSize(data.chunkSize);
    internalFileMeta.key(utils::Base64::from(data.key));
    internalFileMeta.hmac(utils::Base64::from(data.hmac));

    store::FileMetaToEncrypt fileMeta {
        .publicMeta = handle->getPublicMeta(),
        .privateMeta = handle->getPrivateMeta(),
        .fileSize = handle->getSize(),
        .internalMeta = core::Buffer::from(utils::Utils::stringifyVar(internalFileMeta.asVar()))
    };

    auto encryptedMeta = _fileMetaEncryptorV4.encrypt(fileMeta, _userPrivKey, key.key);

    if (handle->getFileId().empty()) {
        // create file
        auto storeFileCreateModel = utils::TypedObjectFactory::createNewObject<server::StoreFileCreateModel>();
        storeFileCreateModel.fileIndex(0);
        storeFileCreateModel.storeId(handle->getStoreId());
        storeFileCreateModel.meta(encryptedMeta.asVar());
        storeFileCreateModel.keyId(key.id);
        storeFileCreateModel.requestId(data.requestId);
        return _serverApi->storeFileCreate(storeFileCreateModel).fileId();
    } else {
        // update file
        auto storeFileWriteModel = utils::TypedObjectFactory::createNewObject<server::StoreFileWriteModel>();
        storeFileWriteModel.fileIndex(0);
        storeFileWriteModel.fileId(handle->getFileId());
        storeFileWriteModel.meta(encryptedMeta.asVar());
        storeFileWriteModel.keyId(key.id);
        storeFileWriteModel.requestId(data.requestId);
        _serverApi->storeFileWrite(storeFileWriteModel);
        return handle->getFileId();
    }
}

void StoreApiImpl::processNotificationEvent(const std::string& type, const std::string& channel, const Poco::JSON::Object::Ptr& data) {
    if(!_storeSubscriptionHelper.hasSubscriptionForChannel(channel) && channel != INTERNAL_EVENT_CHANNEL_NAME) {
        return;
    }
    if (type == "storeCreated") {
        auto raw = utils::TypedObjectFactory::createObjectFromVar<server::Store>(data);
        if(raw.typeOpt(std::string(STORE_TYPE_FILTER_FLAG)) == STORE_TYPE_FILTER_FLAG) {
            _storeProvider.updateCache(raw.id(), raw);
            auto data = decryptAndConvertStoreDataToStore(raw);
            std::shared_ptr<StoreCreatedEvent> event(new StoreCreatedEvent());
            event->channel = channel;
            event->data = data;
            _eventMiddleware->emitApiEvent(event);
        }
    } else if (type == "storeUpdated") {
        auto raw = utils::TypedObjectFactory::createObjectFromVar<server::Store>(data);
        if(raw.typeOpt(std::string(STORE_TYPE_FILTER_FLAG)) == STORE_TYPE_FILTER_FLAG) {
            _storeProvider.updateCache(raw.id(), raw);
            auto data = decryptAndConvertStoreDataToStore(raw);
            std::shared_ptr<StoreUpdatedEvent> event(new StoreUpdatedEvent());
            event->channel = channel;
            event->data = data;
            _eventMiddleware->emitApiEvent(event);
        }
    } else if (type == "storeDeleted") {
        auto raw = utils::TypedObjectFactory::createObjectFromVar<server::StoreDeletedEventData>(data);
        if(raw.typeOpt(std::string(STORE_TYPE_FILTER_FLAG)) == STORE_TYPE_FILTER_FLAG) {
            _storeProvider.remove(raw.storeId());
            auto data = Mapper::mapToStoreDeletedEventData(raw);
            std::shared_ptr<StoreDeletedEvent> event(new StoreDeletedEvent());
            event->channel = channel;
            event->data = data;
            _eventMiddleware->emitApiEvent(event);
        }
    } else if (type == "storeStatsChanged") {
        auto raw = utils::TypedObjectFactory::createObjectFromVar<server::StoreStatsChangedEventData>(data);
        if(raw.typeOpt(std::string(STORE_TYPE_FILTER_FLAG)) == STORE_TYPE_FILTER_FLAG) {
            auto data = Mapper::mapToStoreStatsChangedEventData(raw);
            std::shared_ptr<StoreStatsChangedEvent> event(new StoreStatsChangedEvent());
            event->channel = channel;
            event->data = data;
            _eventMiddleware->emitApiEvent(event);
        }
    
    } else if (type == "storeFileCreated") {
        auto raw = utils::TypedObjectFactory::createObjectFromVar<server::File>(data);
        auto store {_storeProvider.get(raw.storeId(), !_subscribeForStore)};
        auto file = decryptAndConvertFileDataToFileInfo(store, raw);

        // auto data = _dataResolver->decrypt(std::vector<server::File>{raw})[0];
        std::shared_ptr<StoreFileCreatedEvent> event(new StoreFileCreatedEvent());
        event->channel = channel;
        event->data = file;
        _eventMiddleware->emitApiEvent(event);
    } else if (type == "storeFileUpdated") {
        auto raw = utils::TypedObjectFactory::createObjectFromVar<server::File>(data);
        auto store {_storeProvider.get(raw.storeId(), !_subscribeForStore)};
        auto file = decryptAndConvertFileDataToFileInfo(store, raw);
        std::shared_ptr<StoreFileUpdatedEvent> event(new StoreFileUpdatedEvent());
        event->channel = channel;
        event->data = file;
        _eventMiddleware->emitApiEvent(event);
    } else if (type == "storeFileDeleted") {
        auto raw = utils::TypedObjectFactory::createObjectFromVar<server::StoreFileDeletedEventData>(data);
        auto data = Mapper::mapToStoreFileDeletedEventData(raw);
        std::shared_ptr<StoreFileDeletedEvent> event(new StoreFileDeletedEvent());
        event->channel = channel;
        event->data = data;
        _eventMiddleware->emitApiEvent(event);
    } else if (type == "custom") {
        auto raw = utils::TypedObjectFactory::createObjectFromVar<server::StoreCustomEventData>(data);
        auto store = _storeProvider.get(raw.id());
        auto key = _keyProvider->getKey(store.keys(), raw.keyId());
        auto data = _eventDataEncryptorV4.decodeAndDecryptAndVerify(raw.eventData(), crypto::PublicKey::fromBase58DER(raw.author().pub()), key.key);
        std::shared_ptr<StoreCustomEvent> event(new StoreCustomEvent());
        event->channel = channel;
        event->data = data;
        event->userId = raw.author().id();
        event->storeId = raw.id();
        _eventMiddleware->emitApiEvent(event);
    } else if (type == "subscribe") {
        std::string channel = data->has("channel") ? data->get("channel") : "";
        if(channel == "store") {
            PRIVMX_DEBUG("StoreApi", "Cache", "Enabled")
            _subscribeForStore = true;
        }
    } else if (type == "unsubscribe") {
        std::string channel = data->has("channel") ? data->get("channel") : "";
        if(channel == "store") {
            PRIVMX_DEBUG("StoreApi", "Cache", "Disabled")
            _subscribeForStore = false;
            _storeProvider.reset();
        }
    } 
}

void StoreApiImpl::subscribeForStoreEvents() {
    if(_storeSubscriptionHelper.hasSubscriptionForModule()) {
        throw AlreadySubscribedException();
    }
    _storeSubscriptionHelper.subscribeForModule();
}

void StoreApiImpl::unsubscribeFromStoreEvents() {
    if(!_storeSubscriptionHelper.hasSubscriptionForModule()) {
        throw NotSubscribedException();
    }
    _storeSubscriptionHelper.unsubscribeFromModule();
}

void StoreApiImpl::subscribeForFileEvents(const std::string& storeId) {
    auto store {_storeProvider.get(storeId, !_subscribeForStore)};
    if(_storeSubscriptionHelper.hasSubscriptionForElement(storeId)) {
        throw AlreadySubscribedException(storeId);
    }
    _storeSubscriptionHelper.subscribeForElement(storeId);
}

void StoreApiImpl::unsubscribeFromFileEvents(const std::string& storeId) {
    auto store {_storeProvider.get(storeId, !_subscribeForStore)};
    if(!_storeSubscriptionHelper.hasSubscriptionForElement(storeId)) {
        throw NotSubscribedException(storeId);
    }
    _storeSubscriptionHelper.unsubscribeFromElement(storeId);
}

void StoreApiImpl::processConnectedEvent() {
    _storeProvider.reset();
}

void StoreApiImpl::processDisconnectedEvent() {
    _storeProvider.reset();
}

dynamic::compat_v1::StoreData StoreApiImpl::decryptStoreV1(const server::Store& storeRaw) {
    try {
        auto encryptedDataEntry = storeRaw.data().get(storeRaw.data().size()-1);
        auto key = _keyProvider->getKey(storeRaw.keys(), encryptedDataEntry.keyId());
        return _dataEncryptorCompatV1.decrypt(encryptedDataEntry.data(), key);
    } catch (const core::Exception& e) {
        dynamic::compat_v1::StoreData result = utils::TypedObjectFactory::createNewObject<dynamic::compat_v1::StoreData>();
        result.name(std::string());
        result.statusCode(e.getCode());
        return result;
    } catch (const privmx::utils::PrivmxException& e) {
        dynamic::compat_v1::StoreData result = utils::TypedObjectFactory::createNewObject<dynamic::compat_v1::StoreData>();
        result.name(std::string());
        result.statusCode(core::ExceptionConverter::convert(e).getCode());
        return result;
    } catch (...) {
        dynamic::compat_v1::StoreData result = utils::TypedObjectFactory::createNewObject<dynamic::compat_v1::StoreData>();
        result.name(std::string());
        result.statusCode(ENDPOINT_CORE_EXCEPTION_CODE);
        return result;
    }
}

DecryptedStoreData StoreApiImpl::decryptStoreV4(const server::Store& storeRaw) {
    try {
        auto encryptedDataEntry = storeRaw.data().get(storeRaw.data().size()-1);
        auto key = _keyProvider->getKey(storeRaw.keys(), encryptedDataEntry.keyId());
        auto encryptedDataEntryVar = utils::TypedObjectFactory::createObjectFromVar<server::EncryptedStoreDataV4>(encryptedDataEntry.data());
        return _storeDataEncryptorV4.decrypt(encryptedDataEntryVar, key.key);
    } catch (const core::Exception& e) {
        return DecryptedStoreData({{},{},{},{},.statusCode = e.getCode()});
    } catch (const privmx::utils::PrivmxException& e) {
        return DecryptedStoreData({{},{},{},{},.statusCode = core::ExceptionConverter::convert(e).getCode()});
    } catch (...) {
        return DecryptedStoreData({{},{},{},{},.statusCode = ENDPOINT_CORE_EXCEPTION_CODE});
    }
}

Store StoreApiImpl::convertStoreDataV1ToStore(const server::Store& storeRaw, dynamic::compat_v1::StoreData storeData) {
    std::vector<std::string> users;
    std::vector<std::string> managers;
    for (auto x : storeRaw.users()) {
        users.push_back(x);
    }
    for (auto x : storeRaw.managers()) {
        managers.push_back(x);
    }
    Poco::JSON::Object::Ptr privateMeta = Poco::JSON::Object::Ptr(new Poco::JSON::Object());
    privateMeta->set("title", storeData.name());
    int64_t statusCode = storeData.statusCodeOpt(0);
    return {
        .storeId = storeRaw.id(),
        .contextId = storeRaw.contextId(),
        .createDate = storeRaw.createDate(),
        .creator = storeRaw.creator(),
        .lastModificationDate = storeRaw.lastModificationDate(),
        .lastFileDate = storeRaw.lastFileDate(),
        .lastModifier = storeRaw.lastModifier(),
        .users = users,
        .managers = managers,
        .version = storeRaw.version(),
        .publicMeta = core::Buffer::from(""),
        .privateMeta = core::Buffer::from(utils::Utils::stringify(privateMeta)),
        .policy = {},
        .filesCount = storeRaw.files(),
        .statusCode = statusCode
    };
}

Store StoreApiImpl::convertDecryptedStoreDataToStore(const server::Store& storeRaw, const DecryptedStoreData& storeData) {
    std::vector<std::string> users;
    std::vector<std::string> managers;
    for (auto x : storeRaw.users()) {
        users.push_back(x);
    }
    for (auto x : storeRaw.managers()) {
        managers.push_back(x);
    }
    Store result {
        .storeId = storeRaw.id(),
        .contextId = storeRaw.contextId(), 
        .createDate = storeRaw.createDate(),
        .creator = storeRaw.creator(),
        .lastModificationDate = storeRaw.lastModificationDate(),
        .lastFileDate = storeRaw.lastFileDate(),
        .lastModifier = storeRaw.lastModifier(),
        .users = users,
        .managers = managers,
        .version = storeRaw.version(),
        .publicMeta = storeData.publicMeta,
        .privateMeta = storeData.privateMeta,
        .policy = core::Factory::parsePolicyServerObject(storeRaw.policy()), 
        .filesCount = storeRaw.files(),
        .statusCode = storeData.statusCode
    };
    return result;
}

Store StoreApiImpl::decryptAndConvertStoreDataToStore(const server::Store& storeRaw) {
    auto store_data_entry = storeRaw.data().get(storeRaw.data().size()-1);
    if (store_data_entry.data().isString()) {
        return convertStoreDataV1ToStore(storeRaw, decryptStoreV1(storeRaw));
    }
    auto versioned = utils::TypedObjectFactory::createObjectFromVar<dynamic::VersionedData>(store_data_entry.data());
    if (!versioned.versionEmpty() && versioned.version() == 4) {
        return convertDecryptedStoreDataToStore(storeRaw, decryptStoreV4(storeRaw));
    }
    auto e = UnknowStoreFormatException();
    return Store{{},{},{},{},{},{},{},{},{},{},{},{},{},{}, .statusCode = e.getCode()};
}

// OLD CODE
StoreFile StoreApiImpl::decryptStoreFileV1(const server::Store& store, const server::File& storeFile) {
    try {
        std::string keyId = storeFile.keyId();
        _fileKeyIdFormatValidator.assertKeyIdFormat(keyId);
        auto key = _keyProvider->getKey(store.keys(), keyId).key;
        auto file = decryptAndVerifyFileV1(key, storeFile);
        return file;
    } catch (const privmx::endpoint::core::Exception& e) {
        StoreFile result = {.raw=storeFile, .meta=privmx::utils::TypedObjectFactory::createNewObject<dynamic::compat_v1::StoreFileMeta>(), .verified="invalid"};
        result.meta.statusCode(e.getCode());
        return result;
    } catch (const privmx::utils::PrivmxException& e) {
        StoreFile result = {.raw=storeFile, .meta=privmx::utils::TypedObjectFactory::createNewObject<dynamic::compat_v1::StoreFileMeta>(), .verified="invalid"};
        result.meta.statusCode(core::ExceptionConverter::convert(e).getCode());
        return result;
    } catch (...) {
        StoreFile result = {.raw=storeFile, .meta=privmx::utils::TypedObjectFactory::createNewObject<dynamic::compat_v1::StoreFileMeta>(), .verified="invalid"};
        result.meta.statusCode(ENDPOINT_CORE_EXCEPTION_CODE);
        return result;
    }
}
// OLD CODE
std::string StoreApiImpl::verifyFileV1Signature(FileMetaSigned meta, server::File raw, std::string& serverId) {
    try {
        if (meta.signature.length() == 0 || meta.meta.authorEmpty() || meta.meta.destinationEmpty()) {
            return std::string("no-signature");
        }
        if (meta.meta.destination().server() != serverId) {
            return std::string("invalid");
        }
        if (meta.meta.destination().storeIdOpt(meta.meta.destination().storeOpt("")) != raw.id()) {  // backward compatibility
            return std::string("invalid");
        }
        auto author = meta.meta.author();
        auto pubKey = privmx::crypto::PublicKey::fromBase58DER(author.pubKey());
        auto result = pubKey.verifyCompactSignatureWithHash(meta.metaBuf, meta.signature);
        return result ? std::string("verified") : std::string("invalid");        
    } catch (...) {
        return std::string("invalid");
    }
}
// OLD CODE
StoreFile StoreApiImpl::decryptAndVerifyFileV1(const std::string &filesKey, server::File x) {
    StoreFile odp;
    auto fileMetaSigned = _fileMetaEncryptor.decrypt(x.meta(), filesKey);
    odp.raw = x;
    odp.meta = fileMetaSigned.meta;
    odp.verified = verifyFileV1Signature(fileMetaSigned, x, _host);
    return odp;
}

DecryptedFileMeta StoreApiImpl::decryptFileMetaV4(const server::Store& store, const server::File& file) {
    try {
        auto keyId = file.keyId();
        auto encKey = _keyProvider->getKey(store.keys(), keyId);
        _fileKeyIdFormatValidator.assertKeyIdFormat(keyId);
        auto encryptionKey = encKey.key;
        auto encryptedFileMeta = utils::TypedObjectFactory::createObjectFromVar<server::EncryptedFileMetaV4>(file.meta());
        return _fileMetaEncryptorV4.decrypt(encryptedFileMeta, encryptionKey);
    } catch (const core::Exception& e) {
        return DecryptedFileMeta({{},{},{},{},{},.statusCode = e.getCode()});
    } catch (const privmx::utils::PrivmxException& e) {
        return DecryptedFileMeta({{},{},{},{},{},.statusCode = core::ExceptionConverter::convert(e).getCode()});
    } catch (...) {
        return DecryptedFileMeta({{},{},{},{},{},.statusCode = ENDPOINT_CORE_EXCEPTION_CODE});
    }
}

File StoreApiImpl::convertStoreFileMetaV1ToFile(server::File file, dynamic::compat_v1::StoreFileMeta storeFileMeta) {
    File result = {
        .info = {
            .storeId = file.storeId(),
            .fileId = file.id(),
            .createDate = file.created(),
            .author = file.creator(),
        },
        .publicMeta = core::Buffer(),
        .privateMeta = core::Buffer::from(utils::Utils::stringifyVar(storeFileMeta)),
        .size = storeFileMeta.sizeOpt(0),
        .authorPubKey = storeFileMeta.authorEmpty() ? "" : storeFileMeta.author().pubKeyOpt(""),
        .statusCode = storeFileMeta.statusCodeOpt(0)
    };
    return result;
}

File StoreApiImpl::convertDecryptedFileMetaToFile(server::File file, DecryptedFileMeta fileData) {
    store::ServerFileInfo fileInfo = {
        .storeId = file.storeId(),
        .fileId = file.id(),
        .createDate = file.created(),
        .author = file.creator(),
    };
    return store::File {
        .info = fileInfo,
        .publicMeta = fileData.publicMeta,
        .privateMeta = fileData.privateMeta,
        .size = fileData.fileSize,
        .authorPubKey = fileData.authorPubKey,
        .statusCode = fileData.statusCode
    };
}

File StoreApiImpl::decryptAndConvertFileDataToFileInfo(server::Store store, server::File file) {
    if (file.meta().isString()) {
        return convertStoreFileMetaV1ToFile(file, decryptStoreFileV1(store, file).meta);
    }
    auto versioned = utils::TypedObjectFactory::createObjectFromVar<dynamic::VersionedData>(file.meta());
    if (!versioned.versionEmpty() && versioned.version() == 4) {
        return convertDecryptedFileMetaToFile(file, decryptFileMetaV4(store, file));
    }
    auto e = UnknowFileFormatException();
    return File{{},{},{},{},{},.statusCode = e.getCode()};
}

void StoreApiImpl::updateFileMeta(const std::string& fileId, const core::Buffer& publicMeta, const core::Buffer& privateMeta) {
    auto storeFileGetModel = utils::TypedObjectFactory::createNewObject<server::StoreFileGetModel>();
    storeFileGetModel.fileId(fileId);

    auto storeFileGetResult = _serverApi->storeFileGet(storeFileGetModel);
    server::Store store = storeFileGetResult.store();
    server::File file = storeFileGetResult.file();
    core::EncKey key = _keyProvider->getKey(store.keys(), store.keyId());
    DecryptedFileMeta decryptedFile = decryptFileMetaV4(store, file);

    store::FileMetaToEncrypt fileMeta {
        .publicMeta = publicMeta,
        .privateMeta = privateMeta,
        .fileSize = decryptedFile.fileSize,
        .internalMeta = decryptedFile.internalMeta
    };

    auto encryptedMeta = _fileMetaEncryptorV4.encrypt(fileMeta, _userPrivKey, key.key);

    auto storeFileUpdateModel = utils::TypedObjectFactory::createNewObject<server::StoreFileUpdateModel>();
    storeFileUpdateModel.fileId(fileId);
    storeFileUpdateModel.meta(encryptedMeta.asVar());
    storeFileUpdateModel.keyId(key.id);
    _serverApi->storeFileUpdate(storeFileUpdateModel);
}

void StoreApiImpl::validateChannelName(const std::string& channelName) {
    if(std::find(_unallowedChannelsNames.begin(), _unallowedChannelsNames.end(), channelName) != _unallowedChannelsNames.end()) {
        throw UnallowedChannelNameException();
    }
}

void StoreApiImpl::emitEvent(const std::string& storeId, const std::string& channelName, const core::Buffer& eventData, const std::vector<std::string>& usersIds) {
    validateChannelName(channelName);
    auto store = _storeProvider.get(storeId);
    auto key = _keyProvider->getKey(store.keys(), store.keyId());
    auto usersIdList = privmx::utils::TypedObjectFactory::createNewList<std::string>();
    for(auto userId: usersIds) {
        usersIdList.add(userId);
    }
    server::StoreEmitCustomEventModel model = privmx::utils::TypedObjectFactory::createNewObject<server::StoreEmitCustomEventModel>();
    model.storeId(storeId);
    model.data(_eventDataEncryptorV4.signAndEncryptAndEncode(eventData, _userPrivKey, key.key));
    model.channel(channelName);
    model.users(usersIdList);
    model.keyId(key.id);
    _serverApi->storeSendCustomEvent(model);
}

void StoreApiImpl::subscribeForStoreCustomEvents(const std::string& storeId, const std::string& channelName) {
    validateChannelName(channelName);
    auto store = _storeProvider.get(storeId);
    if(_storeSubscriptionHelper.hasSubscriptionForElementCustom(storeId, channelName)) {
        throw AlreadySubscribedException(storeId);
    }
    _storeSubscriptionHelper.subscribeForElementCustom(storeId, channelName);
}

void StoreApiImpl::unsubscribeFromStoreCustomEvents(const std::string& storeId, const std::string& channelName) {
    validateChannelName(channelName);
    auto store = _storeProvider.get(storeId);
    if(!_storeSubscriptionHelper.hasSubscriptionForElementCustom(storeId, channelName)) {
        throw NotSubscribedException(storeId);
    }
    _storeSubscriptionHelper.unsubscribeFromElementCustom(storeId, channelName);
}