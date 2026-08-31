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

#include <privmx/utils/Utils.hpp>

#include <privmx/endpoint/core/EndpointUtils.hpp>
#include <privmx/endpoint/core/ExceptionConverter.hpp>
#include <privmx/endpoint/core/TimestampValidator.hpp>
#include <privmx/endpoint/core/VarDeserializer.hpp>

#include "privmx/endpoint/core/ListQueryMapper.hpp"
#include "privmx/endpoint/core/UsersKeysResolver.hpp"
#include "privmx/endpoint/core/Validator.hpp"
#include "privmx/endpoint/store/DynamicTypes.hpp"
#include "privmx/endpoint/store/Mapper.hpp"
#include "privmx/endpoint/store/ServerTypes.hpp"
#include "privmx/endpoint/store/StoreApiImpl.hpp"
#include <privmx/endpoint/store/StoreException.hpp>

#include "privmx/endpoint/core/EventBuilder.hpp"
#include "privmx/endpoint/core/Mapper.hpp"
#include "privmx/endpoint/group/GroupApiImpl.hpp"
#include "privmx/endpoint/store/ChunkDataProvider.hpp"
#include "privmx/endpoint/store/ChunkReader.hpp"
#include "privmx/endpoint/store/FileHandler.hpp"
#include "privmx/endpoint/store/cache/CacheScopedNamespace.hpp"
#include "privmx/endpoint/store/cache/GlobalCache.hpp"
#include "privmx/endpoint/store/encryptors/fileData/ChunkEncryptor.hpp"
#include "privmx/endpoint/store/encryptors/fileData/HmacList.hpp"
#include "privmx/endpoint/store/interfaces/IChunkDataProvider.hpp"
#include "privmx/endpoint/store/interfaces/IFileHandler.hpp"
#include <privmx/endpoint/core/ConvertedExceptions.hpp>

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
    const std::shared_ptr<core::HandleManager>& handleManager,
    const core::Connection& connection,
    size_t serverRequestChunkSize,
    const std::optional<group::GroupApi>& groupApi
)
    : ModuleBaseApi(userPrivKey, keyProvider, host, eventMiddleware, connection), _keyProvider(keyProvider),
      _serverApi(serverApi), _host(host), _userPrivKey(userPrivKey), _requestApi(requestApi),
      _fileDataProvider(fileDataProvider), _eventMiddleware(eventMiddleware), _handleManager(handleManager),
      _connection(connection), _serverRequestChunkSize(serverRequestChunkSize),
      _chunksCache(
          std::make_shared<CacheScopedNamespace>(
              host + ";" + userPrivKey.getPublicKey().toBase58DER() + ";",
              GlobalCache::getChunksCacheInstance()
          )
      ),

      _fileHandleManager(FileHandleManager(handleManager, "Store")),
      _subscriber(connection.getImpl()->getGateway(), STORE_TYPE_FILTER_FLAG),
      _storeDataSchemaMapper(std::make_shared<StoreDataSchemaMapper>(userPrivKey, connection)),
      _fileMetaDataSchemaMapper(userPrivKey, connection) {
    initGroupResolvers(group::GroupApiImpl::makeGroupResolvers(groupApi));
    initModuleDataSchemaMapper(_storeDataSchemaMapper);
    _notificationListenerId = _eventMiddleware->addNotificationEventListener(
        std::bind(&StoreApiImpl::processNotificationEvent, this, std::placeholders::_1, std::placeholders::_2)
    );
    _connectedListenerId = _eventMiddleware->addConnectedEventListener(
        std::bind(&StoreApiImpl::processConnectedEvent, this)
    );
    _disconnectedListenerId = _eventMiddleware->addDisconnectedEventListener(
        std::bind(&StoreApiImpl::processDisconnectedEvent, this)
    );
}

StoreApiImpl::~StoreApiImpl() {
    _eventMiddleware->removeNotificationEventListener(_notificationListenerId);
    _eventMiddleware->removeConnectedEventListener(_connectedListenerId);
    _eventMiddleware->removeDisconnectedEventListener(_disconnectedListenerId);
    _guardedExecutor.reset();
    LOG_TRACE("~StoreApiImpl Done");
}

std::string StoreApiImpl::createStore(
    const std::string& contextId,
    const std::vector<core::UserWithPubKey>& users,
    const std::vector<core::UserWithPubKey>& managers,
    const core::Buffer& publicMeta,
    const core::Buffer& privateMeta,
    const std::optional<core::ContainerPolicy>& policies,
    const std::string& type,
    const std::vector<core::GroupGrantWithKey>& groups
) {
    auto ctx = prepareContainerCreate(contextId, users, managers);
    core::ModuleDataToEncryptV5 storeDataToEncrypt{
        .publicMeta = publicMeta,
        .privateMeta = privateMeta,
        .internalMeta = core::
            ModuleInternalMetaV5{.secret = ctx.secret, .resourceId = ctx.resourceId, .randomId = ctx.dio.randomId},
        .dio = ctx.dio
    };
    server::StoreCreateModel storeCreateModel;
    fillContainerCreateModel(
        storeCreateModel, contextId, users, managers, ctx,
        _storeDataSchemaMapper->encrypt(storeDataToEncrypt, ctx.key.key), groups
    );
    if (type.length() > 0) {
        storeCreateModel.type = type;
    }
    if (policies.has_value()) {
        storeCreateModel.policy = privmx::endpoint::core::Factory::createPolicyServerObject(policies.value());
    }
    auto result = _serverApi->storeCreate(storeCreateModel);
    return result.storeId;
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
    const std::optional<core::ContainerPolicy>& policies,
    const std::vector<core::GroupGrantWithKey>& groups
) {

    server::StoreGetModel getModel;
    getModel.storeId = storeId;
    auto currentStore{_serverApi->storeGet(getModel).store};
    auto currentStoreEntry = currentStore.data.back();
    auto currentStoreResourceId = currentStore.resourceId.has_value() ? currentStore.resourceId.value() :
                                                                        core::EndpointUtils::generateId();
    auto ctx = prepareContainerUpdate(
        currentStore, currentStoreEntry, currentStoreResourceId, users, managers,
        forceGenerateNewKey || doesGroupStateForceNewKey(currentStore, groups), true, _groupPrivKeyResolver
    );
    server::StoreUpdateModel model;
    // The grant list is the caller's: this is the call that adds and removes group grantees, so an empty list
    // revokes every grant the Store had.
    fillContainerUpdateModel(model, storeId, currentStoreResourceId, users, managers, ctx, version, force, groups);
    if (policies.has_value()) {
        model.policy = privmx::endpoint::core::Factory::createPolicyServerObject(policies.value());
    }
    core::ModuleDataToEncryptV5 storeDataToEncrypt{
        .publicMeta = publicMeta,
        .privateMeta = privateMeta,
        .internalMeta =
            core::ModuleInternalMetaV5{
                .secret = ctx.secret, .resourceId = currentStoreResourceId, .randomId = ctx.dio.randomId
            },
        .dio = ctx.dio
    };
    model.data = _storeDataSchemaMapper->encrypt(storeDataToEncrypt, ctx.key.key);
    _serverApi->storeUpdate(model);
    invalidateModuleKeysInCache(storeId);
}

void StoreApiImpl::rotateStoreKeys(
    const std::string& storeId,
    const std::vector<core::UserWithPubKey>& users,
    const std::vector<core::UserWithPubKey>& managers,
    const int64_t version,
    const bool force,
    const std::vector<core::GroupGrantWithKey>& groups
) {
    server::StoreGetModel getModel;
    getModel.storeId = storeId;
    auto currentStore = _serverApi->storeGet(getModel).store;
    rotateContainerKeys<server::StoreRotateKeysModel>(
        storeId, currentStore, users, managers, version, force, groups,
        [&](const server::StoreRotateKeysModel& model) { _serverApi->storeRotateKeys(model); }
    );
}

void StoreApiImpl::autoRotateStoreKeys(const std::string& storeId) {
    // A fresh read, not the cached keys: whatever triggered this may have been a stale snapshot, and the roster
    // and version this re-key is built on have to be the ones the bridge will check it against.
    server::StoreGetModel getModel;
    getModel.storeId = storeId;
    auto currentStore = _serverApi->storeGet(getModel).store;
    if (!isRekeyNeeded(currentStore)) {
        // Someone else already re-keyed it. The caller refetches the keys either way, so there is nothing to do.
        return;
    }
    auto roster = resolveRosterPubKeys(currentStore.contextId, currentStore.users, currentStore.managers);
    runAutoRekey(storeId, [&] {
        rotateContainerKeys<server::StoreRotateKeysModel>(
            storeId, currentStore, roster.users, roster.managers, currentStore.version, false, {},
            [&](const server::StoreRotateKeysModel& model) { _serverApi->storeRotateKeys(model); }
        );
    });
}

void StoreApiImpl::deleteStore(const std::string& storeId) {
    server::StoreDeleteModel model;
    model.storeId = storeId;
    _serverApi->storeDelete(model);
    invalidateModuleKeysInCache(storeId);
}

Store StoreApiImpl::getStore(const std::string& storeId, const std::string& type) {
    server::StoreGetModel model;
    model.storeId = storeId;
    if (type.length() > 0) {
        model.type = type;
    }
    auto store = _serverApi->storeGet(model).store;
    setNewModuleKeysInCache(store.id, storeToModuleKeys(store), store.version);
    auto result = _storeDataSchemaMapper->validateDecryptAndConvertStore(store, _keyProvider, _groupPrivKeyResolver);
    return result;
}

core::PagingList<Store> StoreApiImpl::listStores(
    const std::string& contextId,
    const core::PagingQuery& query,
    const std::string& type
) {
    server::StoreListModel storeListModel;
    storeListModel.contextId = contextId;
    if (type.length() > 0) {
        storeListModel.type = type;
    }
    core::ListQueryMapper::map(storeListModel, query);
    auto storesList = _serverApi->storeList(storeListModel);
    for (auto store : storesList.stores) {
        setNewModuleKeysInCache(store.id, storeToModuleKeys(store), store.version);
    }
    auto stores = _storeDataSchemaMapper->validateDecryptAndConvertStores(
        storesList.stores, _keyProvider, _groupPrivKeyResolver
    );
    return core::PagingList<Store>({.totalAvailable = storesList.count, .readItems = stores});
}

File StoreApiImpl::getFile(const std::string& fileId) {
    server::StoreFileGetModel storeFileGetModel;
    storeFileGetModel.fileId = fileId;
    auto serverFileResult = _serverApi->storeFileGet(storeFileGetModel);
    auto store = serverFileResult.store;
    _storeDataSchemaMapper->assertDataIntegrity(store);
    setNewModuleKeysInCache(store.id, storeToModuleKeys(store), store.version);
    auto statusCode = _fileMetaDataSchemaMapper.validateDataIntegrity(
        serverFileResult.file, store.resourceId.value_or("")
    );
    if (statusCode != 0) {
        File result;
        result.statusCode = statusCode;
        return result;
    }
    auto ret{_fileMetaDataSchemaMapper.validateDecryptAndConvertFile(
        serverFileResult.file, storeToModuleKeys(store), _keyProvider, _groupPrivKeyResolver
    )};
    return ret;
}

core::PagingList<File> StoreApiImpl::listFiles(const std::string& storeId, const core::PagingQuery& query) {
    server::StoreFileListModel model;
    model.storeId = storeId;
    core::ListQueryMapper::map(model, query);
    auto serverFilesResult = _serverApi->storeFileList(model);
    auto store = serverFilesResult.store;
    _storeDataSchemaMapper->assertDataIntegrity(store);
    setNewModuleKeysInCache(store.id, storeToModuleKeys(store), store.version);
    auto files = _fileMetaDataSchemaMapper.validateDecryptAndConvertFiles(
        serverFilesResult.files, storeToModuleKeys(store), _keyProvider, _groupPrivKeyResolver
    );
    return core::PagingList<File>({.totalAvailable = serverFilesResult.count, .readItems = files});
}

void StoreApiImpl::deleteFile(const std::string& fileId) {
    server::StoreFileDeleteModel model;
    model.fileId = fileId;
    _serverApi->storeFileDelete(model);
}

int64_t StoreApiImpl::createFile(
    const std::string& storeId,
    const core::Buffer& publicMeta,
    const core::Buffer& privateMeta,
    const int64_t size,
    bool randomWriteSupport
) {
    assertStoreExist(storeId);
    std::shared_ptr<FileWriteHandle> handle = _fileHandleManager.createFileWriteHandle(
        storeId, std::string(), core::EndpointUtils::generateId(), (uint64_t)size, publicMeta, privateMeta, _CHUNK_SIZE,
        _serverRequestChunkSize, _requestApi, randomWriteSupport
    );
    handle->createRequestData();
    return handle->getId();
}

int64_t StoreApiImpl::updateFile(
    const std::string& fileId,
    const core::Buffer& publicMeta,
    const core::Buffer& privateMeta,
    const int64_t size
) {
    server::StoreFileGetModel storeFileGetModel;
    storeFileGetModel.fileId = fileId;
    auto result = _serverApi->storeFileGet(storeFileGetModel);
    auto internalMeta = _fileMetaDataSchemaMapper.validateDecryptFileInternalMeta(
        result.file, storeToModuleKeys(result.store), _keyProvider, _groupPrivKeyResolver
    );
    std::shared_ptr<FileWriteHandle> handle = _fileHandleManager.createFileWriteHandle(
        result.store.id, fileId, result.file.resourceId, (uint64_t)size, publicMeta, privateMeta, _CHUNK_SIZE,
        _serverRequestChunkSize, _requestApi, internalMeta.randomWrite.value_or(false)
    );
    handle->createRequestData();
    return handle->getId();
}

int64_t StoreApiImpl::openFile(const std::string& fileId) {
    server::StoreFileGetModel storeFileGetModel;
    storeFileGetModel.fileId = fileId;
    auto file_raw = _serverApi->storeFileGet(storeFileGetModel);
    auto encryptionParams = getFileEncryptionParams(file_raw.file, file_raw.store);
    if (encryptionParams.fileMeta.internalFileMeta.randomWrite.value_or(false)) {
        std::shared_ptr<FileReadWriteHandle> handle = _fileHandleManager.createFileReadWriteHandle(
            privmx::endpoint::store::FileInfo{
                .contextId = file_raw.file.contextId,
                .storeId = file_raw.file.storeId,
                .storeResourceId = file_raw.store.resourceId.value_or(""),
                .fileId = file_raw.file.id,
                .resourceId = file_raw.file.resourceId
            },
            encryptionParams, _serverRequestChunkSize, _userPrivKey, _connection, _serverApi, _chunksCache
        );
        return handle->getId();
    }
    return createFileReadHandle(encryptionParams.fileDecryptionParams);
}

FileDecryptionParams StoreApiImpl::getFileDecryptionParams(server::File file, const core::DecryptedEncKey& encKey) {
    auto internalMeta = _fileMetaDataSchemaMapper.decryptFileInternalMeta(file, core::DecryptedEncKey(encKey));
    return getFileDecryptionParams(file, internalMeta);
}

FileDecryptionParams StoreApiImpl::getFileDecryptionParams(
    server::File file,
    dynamic::InternalStoreFileMeta internalMeta
) {
    if ((uint64_t)internalMeta.chunkSize > SIZE_MAX) {
        throw NumberToBigForCPUArchitectureException("chunkSize to big for this CPU architecture");
    }
    return FileDecryptionParams{
        .fileId = file.id,
        .resourceId = file.resourceId,
        .sizeOnServer = (uint64_t)file.size,
        .originalSize = (uint64_t)internalMeta.size,
        .cipherType = internalMeta.cipherType,
        .chunkSize = (size_t)internalMeta.chunkSize,
        .key = privmx::utils::Base64::toString(internalMeta.key),
        .hmac = privmx::utils::Base64::toString(internalMeta.hmac),
        .version = file.version
    };
}

int64_t StoreApiImpl::createFileReadHandle(const FileDecryptionParams& storeFileDecryptionParams) {
    if (storeFileDecryptionParams.cipherType != 1) {
        throw UnsupportedCipherTypeException(
            std::to_string(storeFileDecryptionParams.cipherType) + " expected type: 1"
        );
    }
    std::shared_ptr<FileReadHandle> handle = _fileHandleManager.createFileReadHandle(
        storeFileDecryptionParams, _serverRequestChunkSize, _serverApi, _chunksCache
    );
    return handle->getId();
}

void StoreApiImpl::writeToFile(const int64_t handleId, const core::Buffer& dataChunk, bool truncate) {
    std::shared_ptr<FileReadWriteHandle> rw_handle = _fileHandleManager.tryGetFileReadWriteHandle(handleId);
    if (rw_handle) {
        core::Validator::validateBufferSize(dataChunk, 0, 512 * 1024, "field:dataChunk");
        rw_handle->file->write(dataChunk, truncate);
        return;
    }
    std::shared_ptr<FileWriteHandle> handle = _fileHandleManager.getFileWriteHandle(handleId);
    handle->write(dataChunk.stdString());
}

core::Buffer StoreApiImpl::readFromFile(const int64_t handle, const int64_t length) {
    std::shared_ptr<FileReadWriteHandle> rw_handle = _fileHandleManager.tryGetFileReadWriteHandle(handle);
    if (rw_handle) {
        return rw_handle->file->read(length);
    }
    std::shared_ptr<FileReadHandle> handlePtr = _fileHandleManager.getFileReadHandle(handle);
    return core::Buffer::from(handlePtr->read(length));
}

void StoreApiImpl::seekInFile(const int64_t handle, const int64_t pos) {
    std::shared_ptr<FileReadWriteHandle> rw_handle = _fileHandleManager.tryGetFileReadWriteHandle(handle);
    if (rw_handle) {
        rw_handle->file->seekg(pos);
        rw_handle->file->seekp(pos);
        return;
    }
    std::shared_ptr<FileReadHandle> handlePtr = _fileHandleManager.getFileReadHandle(handle);
    handlePtr->seek(pos);
}

void StoreApiImpl::syncFile(const int64_t handle) {
    std::shared_ptr<FileHandle> fileHandle = _fileHandleManager.getFileHandle(handle);
    server::StoreFileGetModel storeFileGetModel;
    storeFileGetModel.fileId = fileHandle->getFileId();
    auto file_raw = _serverApi->storeFileGet(storeFileGetModel);
    auto encryptionParams = getFileEncryptionParams(file_raw.file, file_raw.store);

    std::shared_ptr<FileReadWriteHandle> rw_handle = _fileHandleManager.tryGetFileReadWriteHandle(handle);
    if (rw_handle) {
        rw_handle->file->sync(
            encryptionParams.fileMeta, encryptionParams.fileDecryptionParams, encryptionParams.encKey
        );
        return;
    }
    std::shared_ptr<FileReadHandle> handlePtr = _fileHandleManager.getFileReadHandle(handle);
    try {
        handlePtr->sync(encryptionParams.fileDecryptionParams);
    } catch (const store::FileCorruptedException& e) {
        _fileHandleManager.removeHandle(handle);
        FileSyncFailedHandleCloseException ex("in file read handle");
        ex.setCause(e);
        throw ex;
    }
}

void StoreApiImpl::flushFile(const int64_t handle) {
    std::shared_ptr<FileReadWriteHandle> rw_handle = _fileHandleManager.tryGetFileReadWriteHandle(handle);
    if (!rw_handle) {
        throw InvalidFileReadWriteHandleException();
    }
    rw_handle->file->flush();
}

uint64_t StoreApiImpl::getFileSize(const int64_t handle) {
    std::shared_ptr<FileReadWriteHandle> rw_handle = _fileHandleManager.tryGetFileReadWriteHandle(handle);
    if (!rw_handle) {
        throw InvalidFileReadWriteHandleException();
    }
    return rw_handle->file->size();
}

std::string StoreApiImpl::closeFile(const int64_t handle) {
    std::shared_ptr<FileReadWriteHandle> rw_handle = _fileHandleManager.tryGetFileReadWriteHandle(handle);
    if (rw_handle) {
        rw_handle->file->close();
        _fileHandleManager.removeHandle(handle);
        return rw_handle->getFileId();
    }
    std::shared_ptr<FileHandle> handlePtr = _fileHandleManager.getFileHandle(handle);
    _fileHandleManager.removeHandle(handle);
    if (handlePtr->isWriteHandle()) {
        try {
            return storeFileFinalizeWrite(std::dynamic_pointer_cast<FileWriteHandle>(handlePtr));
        } catch (const core::DataDifferentThanDeclaredException& e) {
            WritingToFileInteruptedWrittenDataSmallerThenDeclaredException ex;
            ex.setCause(e);
            throw ex;
        }
    }
    return handlePtr->getFileId();
}

std::string StoreApiImpl::storeFileFinalizeWrite(const std::shared_ptr<FileWriteHandle>& handle) {
    auto data = handle->finalize();
    if (handle->getFileId().empty()) {
        return withKeyRefresh<std::string>(
            handle->getStoreId(), privmx::endpoint::server::InvalidKeyException().getCode(),
            [&](const core::ModuleKeys& keys) { return storeFileFinalizeWriteRequest(handle, data, keys); },
            [&] { autoRotateStoreKeys(handle->getStoreId()); }
        );
    }
    server::StoreFileGetModel storeFileGetModel;
    storeFileGetModel.fileId = handle->getFileId();
    auto store = _serverApi->storeFileGet(storeFileGetModel).store;
    // Overwriting an existing file reaches the Store through the file rather than through `withKeyRefresh`, so
    // the stale key has to be caught by hand. Re-keying invalidates what was just cached, hence the re-read.
    if (isRekeyNeeded(store)) {
        autoRotateStoreKeys(store.id);
        store = _serverApi->storeFileGet(storeFileGetModel).store;
    }
    auto storeKey = storeToModuleKeys(store);
    setNewModuleKeysInCache(store.id, storeKey, store.version);
    return storeFileFinalizeWriteRequest(handle, data, storeKey);
}

std::string StoreApiImpl::storeFileFinalizeWriteRequest(
    const std::shared_ptr<FileWriteHandle>& handle,
    const ChunksSentInfo& data,
    const core::ModuleKeys& storeKey
) {
    auto serverId = _host;
    auto key = getAndValidateModuleCurrentEncKey(storeKey, _groupPrivKeyResolver);
    if (key.statusCode != 0) {
        throw core::EncryptionKeyValidationException(
            "Current encryption key statusCode: " + std::to_string(key.statusCode)
        );
    }
    dynamic::InternalStoreFileMeta internalFileMeta;
    internalFileMeta.version = 4;
    internalFileMeta.size = handle->getSize();
    internalFileMeta.cipherType = data.cipherType;
    internalFileMeta.chunkSize = data.chunkSize;
    internalFileMeta.key = utils::Base64::from(data.key);
    internalFileMeta.hmac = utils::Base64::from(data.hmac);
    internalFileMeta.randomWrite = handle->getRandomWriteSupport();
    auto encryptedMetaVar = _fileMetaDataSchemaMapper.encrypt(
        handle->getStoreId(), handle->getResourceId(), storeKey.contextId, storeKey.moduleResourceId,
        handle->getPublicMeta(), handle->getPrivateMeta(), core::Buffer::from(internalFileMeta.serialize()), key
    );
    if (handle->getFileId().empty()) {
        server::StoreFileCreateModel storeFileCreateModel;
        storeFileCreateModel.fileIndex = 0;
        storeFileCreateModel.resourceId = handle->getResourceId();
        storeFileCreateModel.storeId = handle->getStoreId();
        storeFileCreateModel.meta = encryptedMetaVar;
        storeFileCreateModel.keyId = key.id;
        storeFileCreateModel.requestId = data.requestId;
        return _serverApi->storeFileCreate(storeFileCreateModel).fileId;
    } else {
        server::StoreFileWriteModel storeFileWriteModel;
        storeFileWriteModel.fileIndex = 0;
        storeFileWriteModel.fileId = handle->getFileId();
        storeFileWriteModel.meta = encryptedMetaVar;
        storeFileWriteModel.keyId = key.id;
        storeFileWriteModel.requestId = data.requestId;
        _serverApi->storeFileWrite(storeFileWriteModel);
        return handle->getFileId();
    }
}

void StoreApiImpl::processNotificationEvent(const std::string& type, const core::NotificationEvent& notification) {
    auto subscriptionQuery = _subscriber.getSubscriptionQuery(notification.subscriptions);
    if (!subscriptionQuery.has_value()) {
        return;
    }
    _guardedExecutor->exec([&, type, notification]() {
        if (type == "storeCreated") {
            auto raw = server::Store::fromJSON(notification.data);
            if (raw.type.value_or(std::string(STORE_TYPE_FILTER_FLAG)) == STORE_TYPE_FILTER_FLAG) {
                setNewModuleKeysInCache(raw.id, storeToModuleKeys(raw), raw.version);
                auto data = _storeDataSchemaMapper->validateDecryptAndConvertStore(
                    raw, _keyProvider, _groupPrivKeyResolver
                );
                auto event = core::EventBuilder::buildEvent<StoreCreatedEvent>("store", data, notification);
                _eventMiddleware->emitApiEvent(event);
            }
        } else if (type == "storeUpdated") {
            auto raw = server::Store::fromJSON(notification.data);
            if (raw.type.value_or(std::string(STORE_TYPE_FILTER_FLAG)) == STORE_TYPE_FILTER_FLAG) {
                setNewModuleKeysInCache(raw.id, storeToModuleKeys(raw), raw.version);
                auto data = _storeDataSchemaMapper->validateDecryptAndConvertStore(
                    raw, _keyProvider, _groupPrivKeyResolver
                );
                auto event = core::EventBuilder::buildEvent<StoreUpdatedEvent>("store", data, notification);
                _eventMiddleware->emitApiEvent(event);
            }
        } else if (type == "storeDeleted") {
            auto raw = server::StoreDeletedEventData::fromJSON(notification.data);
            if (raw.type.value_or(std::string(STORE_TYPE_FILTER_FLAG)) == STORE_TYPE_FILTER_FLAG) {
                invalidateModuleKeysInCache(raw.storeId);
                auto data = Mapper::mapToStoreDeletedEventData(raw);
                auto event = core::EventBuilder::buildEvent<StoreDeletedEvent>("store", data, notification);
                _eventMiddleware->emitApiEvent(event);
            }
        } else if (type == "storeStatsChanged") {
            auto raw = server::StoreStatsChangedEventData::fromJSON(notification.data);
            if (raw.type.value_or(std::string(STORE_TYPE_FILTER_FLAG)) == STORE_TYPE_FILTER_FLAG) {
                auto data = Mapper::mapToStoreStatsChangedEventData(raw);
                auto event = core::EventBuilder::buildEvent<StoreStatsChangedEvent>("store", data, notification);
                _eventMiddleware->emitApiEvent(event);
            }
        } else if (type == "storeFileCreated") {
            auto raw = server::StoreFileEventData::fromJSON(notification.data);
            if (raw.containerType.value_or(std::string(STORE_TYPE_FILTER_FLAG)) == STORE_TYPE_FILTER_FLAG) {
                auto file = _fileMetaDataSchemaMapper.validateDecryptAndConvertFile(
                    raw, getFileDecryptionKeys(raw), _keyProvider, _groupPrivKeyResolver
                );
                auto event = core::EventBuilder::buildEvent<StoreFileCreatedEvent>(
                    "store/" + raw.storeId + "/files", file, notification
                );
                _eventMiddleware->emitApiEvent(event);
            }
        } else if (type == "storeFileUpdated") {
            auto raw = server::StoreFileUpdatedEventData::fromJSON(notification.data);
            if (raw.containerType.value_or(std::string(STORE_TYPE_FILTER_FLAG)) == STORE_TYPE_FILTER_FLAG) {
                auto storeKeys = getFileDecryptionKeys(raw);
                auto file = _fileMetaDataSchemaMapper.validateDecryptAndConvertFile(
                    raw, storeKeys, _keyProvider, _groupPrivKeyResolver
                );
                auto internalMeta = _fileMetaDataSchemaMapper.validateDecryptFileInternalMeta(
                    raw, storeKeys, _keyProvider, _groupPrivKeyResolver
                );
                auto fileDecryptionParams = getFileDecryptionParams(raw, internalMeta);
                auto data = Mapper::mapToStoreFileUpdatedEventData(raw, file, fileDecryptionParams);
                auto event = core::EventBuilder::buildEvent<StoreFileUpdatedEvent>(
                    "store/" + raw.storeId + "/files", data, notification
                );
                _eventMiddleware->emitApiEvent(event);
            }
        } else if (type == "storeFileDeleted") {
            auto raw = server::StoreFileDeletedEventData::fromJSON(notification.data);
            if (raw.containerType.value_or(std::string(STORE_TYPE_FILTER_FLAG)) == STORE_TYPE_FILTER_FLAG) {
                auto data = Mapper::mapToStoreFileDeletedEventData(raw);
                auto event = core::EventBuilder::buildEvent<StoreFileDeletedEvent>(
                    "store/" + raw.storeId + "/files", data, notification
                );
                _eventMiddleware->emitApiEvent(event);
            }
        } else if (type == "storeCollectionChanged") {
            auto raw = core::server::CollectionChangedEventData::fromJSON(notification.data);
            if (raw.containerType.value_or(std::string(STORE_TYPE_FILTER_FLAG)) == STORE_TYPE_FILTER_FLAG) {
                auto data = core::Mapper::mapToCollectionChangedEventData(STORE_TYPE_FILTER_FLAG, raw);
                auto event = core::EventBuilder::buildEvent<core::CollectionChangedEvent>(
                    "store/collectionChanged", data, notification
                );
                _eventMiddleware->emitApiEvent(event);
            }
        } else {
            LOG_ERROR("UNRESOLVED EVENT in CPP layer: '", type, "'");
        }
    });
}

void StoreApiImpl::processConnectedEvent() {
    invalidateModuleKeysInCache();
}

void StoreApiImpl::processDisconnectedEvent() {
    LOG_TRACE("StoreApiImpl recived DisconnectedEvent");
    invalidateModuleKeysInCache();
    privmx::utils::ManualManagedClass<StoreApiImpl>::cleanup();
}

FileEncryptionParams StoreApiImpl::getFileEncryptionParams(server::File file, const core::DecryptedEncKey& encKey) {
    File decryptedFile;
    core::DataIntegrityObject fileDIO;
    std::tie(decryptedFile, fileDIO) = _fileMetaDataSchemaMapper.decrypt(file, core::DecryptedEncKey(encKey));
    auto internalMeta = _fileMetaDataSchemaMapper.decryptFileInternalMeta(file, core::DecryptedEncKey(encKey));
    return FileEncryptionParams{
        FileMeta{
            .publicMeta = decryptedFile.publicMeta,
            .privateMeta = decryptedFile.privateMeta,
            .internalFileMeta = internalMeta
        },
        getFileDecryptionParams(file, internalMeta), encKey
    };
}

FileEncryptionParams StoreApiImpl::getFileEncryptionParams(server::File file, server::Store store) {
    core::KeyDecryptionAndVerificationRequest keyProviderRequest;
    core::EncKeyLocation location{.contextId = store.contextId, .resourceId = store.resourceId.value_or("")};
    keyProviderRequest.addOne(store.keys, file.keyId, location);
    keyProviderRequest.addGroupKeys(store.groupKeys, location);
    auto key = _keyProvider->getKeysAndVerify(keyProviderRequest, _groupPrivKeyResolver).at(location).at(file.keyId);
    return getFileEncryptionParams(file, key);
}

core::ModuleKeys StoreApiImpl::getFileDecryptionKeys(server::File file) {
    return getModuleKeysForItem(file.storeId, file.keyId, _fileMetaDataSchemaMapper.getMinimumStoreSchemaVersion(file));
}

void StoreApiImpl::updateFileMeta(
    const std::string& fileId,
    const core::Buffer& publicMeta,
    const core::Buffer& privateMeta
) {
    server::StoreFileGetModel storeFileGetModel;
    storeFileGetModel.fileId = fileId;

    auto storeFileGetResult = _serverApi->storeFileGet(storeFileGetModel);
    server::Store store = storeFileGetResult.store;
    // Like the overwrite path in `storeFileFinalizeWrite`: this reaches the Store through the file, so the stale
    // key is caught by hand rather than by `withKeyRefresh`, and the re-key means the fetch has to be redone.
    if (isRekeyNeeded(store)) {
        autoRotateStoreKeys(store.id);
        storeFileGetResult = _serverApi->storeFileGet(storeFileGetModel);
        store = storeFileGetResult.store;
    }
    auto storeKey = storeToModuleKeys(store);
    setNewModuleKeysInCache(store.id, storeKey, store.version);
    server::File file = storeFileGetResult.file;
    auto statusCode = _fileMetaDataSchemaMapper.validateDataIntegrity(file, store.resourceId.value_or(""));
    if (statusCode != 0) {
        throw FileDataIntegrityException("statusCode=" + std::to_string(statusCode));
    }
    // Still guarded: the server-struct key fetch, unlike the `ModuleKeys` one, does not assert, and the re-key
    // above is not guaranteed to have happened — a caller who may not re-key never gets here.
    assertRekeyNotNeeded(store);
    auto key = getAndValidateModuleCurrentEncKey(store, _groupPrivKeyResolver);
    if (key.statusCode != 0) {
        throw core::EncryptionKeyValidationException(
            "Current encryption key statusCode: " + std::to_string(key.statusCode)
        );
    }
    auto fileInternalMeta = _fileMetaDataSchemaMapper.validateDecryptFileInternalMeta(
        file, storeKey, _keyProvider, _groupPrivKeyResolver
    );
    auto internalMeta = core::Buffer::from(fileInternalMeta.serialize());
    auto encryptedMetaVar = _fileMetaDataSchemaMapper.encrypt(
        file.storeId, file.resourceId.empty() ? core::EndpointUtils::generateId() : file.resourceId, file.contextId,
        store.resourceId.value_or(""), publicMeta, privateMeta, internalMeta, key
    );
    server::StoreFileUpdateModel storeFileUpdateModel;
    storeFileUpdateModel.fileId = fileId;
    storeFileUpdateModel.meta = encryptedMetaVar;
    storeFileUpdateModel.keyId = key.id;
    _serverApi->storeFileUpdate(storeFileUpdateModel);
}

void StoreApiImpl::assertStoreExist(const std::string& storeId) {
    store::server::StoreGetModel params{.storeId = storeId, .type = std::nullopt};
    _serverApi->storeGet(params);
}

void StoreApiImpl::assertFileExist(const std::string& fileId) {
    server::StoreFileGetModel storeFileGetModel{.fileId = fileId};
    _serverApi->storeFileGet(storeFileGetModel).file;
}

std::pair<core::ModuleKeys, int64_t> StoreApiImpl::getModuleKeysAndVersionFromServer(std::string moduleId) {
    store::server::StoreGetModel params{.storeId = moduleId, .type = std::nullopt};
    auto store = _serverApi->storeGet(params).store;
    _storeDataSchemaMapper->assertDataIntegrity(store);
    return std::make_pair(storeToModuleKeys(store), store.version);
}

core::ModuleKeys StoreApiImpl::storeToModuleKeys(server::Store store) {
    return containerToModuleKeys(store);
}

std::vector<std::string> StoreApiImpl::subscribeFor(const std::vector<std::string>& subscriptionQueries) {
    auto result = _subscriber.subscribeFor(subscriptionQueries);
    _eventMiddleware->notificationEventListenerAddSubscriptionIds(_notificationListenerId, result);
    return result;
}

void StoreApiImpl::unsubscribeFrom(const std::vector<std::string>& subscriptionIds) {
    _subscriber.unsubscribeFrom(subscriptionIds);
    _eventMiddleware->notificationEventListenerRemoveSubscriptionIds(_notificationListenerId, subscriptionIds);
}

std::string StoreApiImpl::buildSubscriptionQuery(
    EventType eventType,
    EventSelectorType selectorType,
    const std::string& selectorId
) {
    return SubscriberImpl::buildQuery(eventType, selectorType, selectorId);
}
