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
#include "privmx/endpoint/store/ChunkDataProvider.hpp"
#include "privmx/endpoint/store/ChunkReader.hpp"
#include "privmx/endpoint/store/FileHandler.hpp"
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
    size_t serverRequestChunkSize
)
    : ModuleBaseApi(userPrivKey, keyProvider, host, eventMiddleware, connection), _keyProvider(keyProvider),
      _serverApi(serverApi), _host(host), _userPrivKey(userPrivKey), _requestApi(requestApi),
      _fileDataProvider(fileDataProvider), _eventMiddleware(eventMiddleware), _handleManager(handleManager),
      _connection(connection), _serverRequestChunkSize(serverRequestChunkSize),

      _fileHandleManager(FileHandleManager(handleManager, "Store")),
      _subscriber(connection.getImpl()->getGateway(), STORE_TYPE_FILTER_FLAG),
      _storeDataSchemaMapper(userPrivKey, connection), _fileMetaDataSchemaMapper(userPrivKey, connection) {
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
    const std::optional<core::ContainerPolicy>& policies
) {
    return _storeCreateEx(contextId, users, managers, publicMeta, privateMeta, STORE_TYPE_FILTER_FLAG, policies);
}

std::string StoreApiImpl::createStoreEx(
    const std::string& contextId,
    const std::vector<core::UserWithPubKey>& users,
    const std::vector<core::UserWithPubKey>& managers,
    const core::Buffer& publicMeta,
    const core::Buffer& privateMeta,
    const std::string& type,
    const std::optional<core::ContainerPolicy>& policies
) {
    return _storeCreateEx(contextId, users, managers, publicMeta, privateMeta, type, policies);
}

std::string StoreApiImpl::_storeCreateEx(
    const std::string& contextId,
    const std::vector<core::UserWithPubKey>& users,
    const std::vector<core::UserWithPubKey>& managers,
    const core::Buffer& publicMeta,
    const core::Buffer& privateMeta,
    const std::string& type,
    const std::optional<core::ContainerPolicy>& policies
) {
    PRIVMX_DEBUG_TIME_START(PlatformStore, _storeCreateEx)
    auto storeKey = _keyProvider->generateKey();
    std::string resourceId = core::EndpointUtils::generateId();
    auto storeDIO = _connection.getImpl()->createDIO(contextId, resourceId);
    auto storeSecret = _keyProvider->generateSecret();
    core::ModuleDataToEncryptV5 storeDataToEncrypt{
        .publicMeta = publicMeta,
        .privateMeta = privateMeta,
        .internalMeta = core::
            ModuleInternalMetaV5{.secret = storeSecret, .resourceId = resourceId, .randomId = storeDIO.randomId},
        .dio = storeDIO
    };
    server::StoreCreateModel storeCreateModel;
    storeCreateModel.resourceId = resourceId;
    storeCreateModel.contextId = contextId;
    storeCreateModel.keyId = storeKey.id;
    storeCreateModel.data = _storeDataSchemaMapper.encrypt(storeDataToEncrypt, storeKey.key);
    if (type.length() > 0) {
        storeCreateModel.type = type;
    }
    if (policies.has_value()) {
        storeCreateModel.policy = privmx::endpoint::core::Factory::createPolicyServerObject(policies.value());
    }
    auto all_users = core::EndpointUtils::uniqueListUserWithPubKey(users, managers);
    storeCreateModel.keys = _keyProvider->prepareKeysList(
        all_users, storeKey, storeDIO, {.contextId = contextId, .resourceId = resourceId}, storeSecret
    );
    std::vector<std::string> usersList;
    for (auto user : users) {
        usersList.push_back(user.userId);
    }
    std::vector<std::string> managersList;
    for (auto x : managers) {
        managersList.push_back(x.userId);
    }
    storeCreateModel.users = usersList;
    storeCreateModel.managers = managersList;
    PRIVMX_DEBUG_TIME_CHECKPOINT(PlatformStore, _storeCreateEx, data encrypted)
    auto result = _serverApi->storeCreate(storeCreateModel);
    PRIVMX_DEBUG_TIME_STOP(PlatformStore, storeCreate, data send)
    return result.storeId;
}

std::vector<std::string> StoreApiImpl::usersWithPubKeyToIds(std::vector<core::UserWithPubKey>& users) {
    std::vector<std::string> ids{};
    for (auto& user : users) {
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

    server::StoreGetModel getModel;
    getModel.storeId = storeId;
    auto currentStore{_serverApi->storeGet(getModel).store};
    auto currentStoreEntry = currentStore.data.back();
    auto currentStoreResourceId = currentStore.resourceId.has_value() ? currentStore.resourceId.value() :
                                                                        core::EndpointUtils::generateId();
    auto location{getModuleEncKeyLocation(currentStore, currentStoreResourceId)};
    auto storeKeys{getAndValidateModuleKeys(currentStore, currentStoreResourceId)};
    auto currentStoreKey{findEncKeyByKeyId(storeKeys, currentStoreEntry.keyId)};
    auto storeInternalMeta = extractAndDecryptModuleInternalMeta(currentStoreEntry, currentStoreKey);

    auto usersKeysResolver{
        core::UsersKeysResolver::create(currentStore, users, managers, forceGenerateNewKey, currentStoreKey)
    };

    if (!_keyProvider->verifyKeysSecret(storeKeys, location, storeInternalMeta.secret)) {
        throw StoreEncryptionKeyValidationException();
    }
    core::EncKey storeKey = currentStoreKey;
    core::DataIntegrityObject updateStoreDio = _connection.getImpl()->createDIO(
        currentStore.contextId, currentStoreResourceId
    );

    std::vector<core::server::KeyEntrySet> keys;
    if (usersKeysResolver->doNeedNewKey()) {
        storeKey = _keyProvider->generateKey();
        keys = _keyProvider->prepareKeysList(
            usersKeysResolver->getNewUsers(), storeKey, updateStoreDio, location, storeInternalMeta.secret
        );
    }

    auto usersToAddMissingKey{usersKeysResolver->getUsersToAddKey()};
    if (usersToAddMissingKey.size() > 0) {
        auto tmp = _keyProvider->prepareMissingKeysForNewUsers(
            storeKeys, usersToAddMissingKey, updateStoreDio, location, storeInternalMeta.secret
        );
        for (auto t : tmp)
            keys.push_back(t);
    }

    server::StoreUpdateModel model;
    std::vector<std::string> usersList;
    for (auto user : users) {
        usersList.push_back(user.userId);
    }
    std::vector<std::string> managersList;
    for (auto x : managers) {
        managersList.push_back(x.userId);
    }
    model.id = storeId;
    model.resourceId = currentStoreResourceId;
    model.keyId = storeKey.id;
    model.keys = keys;
    model.users = usersList;
    model.managers = managersList;
    model.version = version;
    model.force = force;
    if (policies.has_value()) {
        model.policy = privmx::endpoint::core::Factory::createPolicyServerObject(policies.value());
    }
    core::ModuleDataToEncryptV5 storeDataToEncrypt{
        .publicMeta = publicMeta,
        .privateMeta = privateMeta,
        .internalMeta =
            core::ModuleInternalMetaV5{
                .secret = storeInternalMeta.secret,
                .resourceId = currentStoreResourceId,
                .randomId = updateStoreDio.randomId
            },
        .dio = updateStoreDio
    };
    model.data = _storeDataSchemaMapper.encrypt(storeDataToEncrypt, storeKey.key);

    PRIVMX_DEBUG_TIME_CHECKPOINT(PlatformStore, storeUpdate, data encrypted)
    _serverApi->storeUpdate(model);
    invalidateModuleKeysInCache(storeId);
    PRIVMX_DEBUG_TIME_STOP(PlatformStore, storeUpdate, data send)
}

void StoreApiImpl::deleteStore(const std::string& storeId) {
    server::StoreDeleteModel model;
    model.storeId = storeId;
    _serverApi->storeDelete(model);
    invalidateModuleKeysInCache(storeId);
}

Store StoreApiImpl::getStore(const std::string& storeId) {
    return _storeGetEx(storeId, STORE_TYPE_FILTER_FLAG);
}

Store StoreApiImpl::getStoreEx(const std::string& storeId, const std::string& type) {
    return _storeGetEx(storeId, type);
}

Store StoreApiImpl::_storeGetEx(const std::string& storeId, const std::string& type) {
    PRIVMX_DEBUG_TIME_START(PlatformStore, _storeGetEx)
    server::StoreGetModel model;
    model.storeId = storeId;
    if (type.length() > 0) {
        model.type = type;
    }
    PRIVMX_DEBUG_TIME_CHECKPOINT(PlatformStore, _storeGetEx, getting store)
    auto store = _serverApi->storeGet(model).store;
    setNewModuleKeysInCache(store.id, storeToModuleKeys(store), store.version);
    PRIVMX_DEBUG_TIME_CHECKPOINT(PlatformStore, _storeGetEx, data send)
    auto result = _storeDataSchemaMapper.validateDecryptAndConvertStore(store, _keyProvider);
    PRIVMX_DEBUG_TIME_STOP(PlatformStore, _getStoreEx, data decrypted)
    return result;
}

core::PagingList<Store> StoreApiImpl::listStores(const std::string& contextId, const core::PagingQuery& query) {
    return _storeListEx(contextId, query, STORE_TYPE_FILTER_FLAG);
}

core::PagingList<Store> StoreApiImpl::listStoresEx(
    const std::string& contextId,
    const core::PagingQuery& query,
    const std::string& type
) {
    return _storeListEx(contextId, query, type);
}

core::PagingList<Store> StoreApiImpl::_storeListEx(
    const std::string& contextId,
    const core::PagingQuery& query,
    const std::string& type
) {
    PRIVMX_DEBUG_TIME_START(PlatformStore, _listStoresEx)
    server::StoreListModel storeListModel;
    storeListModel.contextId = contextId;
    if (type.length() > 0) {
        storeListModel.type = type;
    }
    core::ListQueryMapper::map(storeListModel, query);
    PRIVMX_DEBUG_TIME_CHECKPOINT(PlatformStore, _listStoresEx)
    auto storesList = _serverApi->storeList(storeListModel);
    PRIVMX_DEBUG_TIME_CHECKPOINT(PlatformStore, storeList, data send)
    for (auto store : storesList.stores) {
        setNewModuleKeysInCache(store.id, storeToModuleKeys(store), store.version);
    }
    auto stores = _storeDataSchemaMapper.validateDecryptAndConvertStores(storesList.stores, _keyProvider);
    PRIVMX_DEBUG_TIME_STOP(PlatformStore, _listStoresEx, data decrypted)
    return core::PagingList<Store>({.totalAvailable = storesList.count, .readItems = stores});
}

File StoreApiImpl::getFile(const std::string& fileId) {
    PRIVMX_DEBUG_TIME_START(PlatformStore, getFile)
    server::StoreFileGetModel storeFileGetModel;
    storeFileGetModel.fileId = fileId;
    PRIVMX_DEBUG_TIME_CHECKPOINT(PlatformStore, getFile)
    auto serverFileResult = _serverApi->storeFileGet(storeFileGetModel);
    PRIVMX_DEBUG_TIME_CHECKPOINT(PlatformStore, getFile, data send)
    auto store = serverFileResult.store;
    _storeDataSchemaMapper.assertDataIntegrity(store);
    setNewModuleKeysInCache(store.id, storeToModuleKeys(store), store.version);
    auto statusCode = _fileMetaDataSchemaMapper.validateDataIntegrity(
        serverFileResult.file, store.resourceId.value_or("")
    );
    if (statusCode != 0) {
        PRIVMX_DEBUG_TIME_STOP(PlatformStore, getFile, data integrity validation failed)
        File result;
        result.statusCode = statusCode;
        return result;
    }
    auto ret{_fileMetaDataSchemaMapper.validateDecryptAndConvertFile(
        serverFileResult.file, storeToModuleKeys(store), _keyProvider
    )};
    PRIVMX_DEBUG_TIME_STOP(PlatformStore, getFile, data decrypted)
    return ret;
}

core::PagingList<File> StoreApiImpl::listFiles(const std::string& storeId, const core::PagingQuery& query) {
    PRIVMX_DEBUG_TIME_START(PlatformStore, storeFileList)
    server::StoreFileListModel model;
    model.storeId = storeId;
    core::ListQueryMapper::map(model, query);

    PRIVMX_DEBUG_TIME_CHECKPOINT(PlatformStore, storeFileList)
    auto serverFilesResult = _serverApi->storeFileList(model);
    PRIVMX_DEBUG_TIME_CHECKPOINT(PlatformStore, storeFileList, data send);
    auto store = serverFilesResult.store;
    _storeDataSchemaMapper.assertDataIntegrity(store);
    setNewModuleKeysInCache(store.id, storeToModuleKeys(store), store.version);
    auto files = _fileMetaDataSchemaMapper.validateDecryptAndConvertFiles(
        serverFilesResult.files, storeToModuleKeys(store), _keyProvider
    );
    PRIVMX_DEBUG_TIME_STOP(PlatformStore, storeFileList, data decrypted)
    return core::PagingList<File>({.totalAvailable = serverFilesResult.count, .readItems = files});
}

void StoreApiImpl::deleteFile(const std::string& fileId) {
    PRIVMX_DEBUG_TIME_START(PlatformStore, storeFileDelete)
    server::StoreFileDeleteModel model;
    model.fileId = fileId;
    PRIVMX_DEBUG_TIME_CHECKPOINT(PlatformStore, storeFileWrite)
    _serverApi->storeFileDelete(model);
    PRIVMX_DEBUG_TIME_STOP(PlatformStore, storeFileDelete, data send)
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
        result.file, storeToModuleKeys(result.store), _keyProvider
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
            encryptionParams, _serverRequestChunkSize, _userPrivKey, _connection, _serverApi
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
        storeFileDecryptionParams, _serverRequestChunkSize, _serverApi
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
        throw FileSyncFailedHandleCloseException("in file read handle");
    }
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
            throw WritingToFileInteruptedWrittenDataSmallerThenDeclaredException();
        }
    }
    return handlePtr->getFileId();
}

std::string StoreApiImpl::storeFileFinalizeWrite(const std::shared_ptr<FileWriteHandle>& handle) {
    auto data = handle->finalize();
    try {
        privmx::endpoint::core::ModuleKeys storeKey;
        if (handle->getFileId().empty()) {
            storeKey = getModuleKeys(handle->getStoreId());
        } else {
            server::StoreFileGetModel storeFileGetModel;
            storeFileGetModel.fileId = handle->getFileId();
            auto store = _serverApi->storeFileGet(storeFileGetModel).store;
            storeKey = core::ModuleKeys{
                .keys = store.keys,
                .currentKeyId = store.keyId,
                .moduleSchemaVersion = _storeDataSchemaMapper.getDataStructureVersion(store.data.back()),
                .moduleResourceId = store.resourceId.value_or(""),
                .contextId = store.contextId
            };
            setNewModuleKeysInCache(store.id, storeKey, store.version);
        }
        return storeFileFinalizeWriteRequest(handle, data, storeKey);
    } catch (const privmx::utils::PrivmxException& e) {
        if (core::ExceptionConverter::convert(e).getCode() ==
                privmx::endpoint::server::InvalidKeyException().getCode() &&
            handle->getFileId().empty()) {
            privmx::endpoint::core::ModuleKeys storeKey = getNewModuleKeysAndUpdateCache(handle->getStoreId());

            return storeFileFinalizeWriteRequest(handle, data, storeKey);
        }
        throw e;
    }
}

std::string StoreApiImpl::storeFileFinalizeWriteRequest(
    const std::shared_ptr<FileWriteHandle>& handle,
    const ChunksSentInfo& data,
    const core::ModuleKeys& storeKey
) {
    auto serverId = _host;
    auto key = getAndValidateModuleCurrentEncKey(storeKey);
    if (key.statusCode != 0) {
        throw StoreEncryptionKeyValidationException(
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
                auto data = _storeDataSchemaMapper.validateDecryptAndConvertStore(raw, _keyProvider);
                auto event = core::EventBuilder::buildEvent<StoreCreatedEvent>("store", data, notification);
                _eventMiddleware->emitApiEvent(event);
            }
        } else if (type == "storeUpdated") {
            auto raw = server::Store::fromJSON(notification.data);
            if (raw.type.value_or(std::string(STORE_TYPE_FILTER_FLAG)) == STORE_TYPE_FILTER_FLAG) {
                setNewModuleKeysInCache(raw.id, storeToModuleKeys(raw), raw.version);
                auto data = _storeDataSchemaMapper.validateDecryptAndConvertStore(raw, _keyProvider);
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
                    raw, getFileDecryptionKeys(raw), _keyProvider
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
                auto file = _fileMetaDataSchemaMapper.validateDecryptAndConvertFile(raw, storeKeys, _keyProvider);
                auto internalMeta = _fileMetaDataSchemaMapper.validateDecryptFileInternalMeta(
                    raw, storeKeys, _keyProvider
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
    auto key = _keyProvider->getKeysAndVerify(keyProviderRequest).at(location).at(file.keyId);
    return getFileEncryptionParams(file, key);
}

core::ModuleKeys StoreApiImpl::getFileDecryptionKeys(server::File file) {
    return getModuleKeys(
        file.storeId, std::set<std::string>{file.keyId}, _fileMetaDataSchemaMapper.getMinimumStoreSchemaVersion(file)
    );
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
    setNewModuleKeysInCache(store.id, storeToModuleKeys(store), store.version);
    server::File file = storeFileGetResult.file;
    auto statusCode = _fileMetaDataSchemaMapper.validateDataIntegrity(file, store.resourceId.value_or(""));
    if (statusCode != 0) {
        throw FileDataIntegrityException();
    }
    auto key = getAndValidateModuleCurrentEncKey(store);
    if (key.statusCode != 0) {
        throw StoreEncryptionKeyValidationException(
            "Current encryption key statusCode: " + std::to_string(key.statusCode)
        );
    }
    auto fileInternalMeta = _fileMetaDataSchemaMapper.validateDecryptFileInternalMeta(
        file, storeToModuleKeys(store), _keyProvider
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
    _storeDataSchemaMapper.assertDataIntegrity(store);
    return std::make_pair(storeToModuleKeys(store), store.version);
}

core::ModuleKeys StoreApiImpl::storeToModuleKeys(server::Store store) {
    return core::ModuleKeys{
        .keys = store.keys,
        .currentKeyId = store.keyId,
        .moduleSchemaVersion = _storeDataSchemaMapper.getDataStructureVersion(store.data.back()),
        .moduleResourceId = store.resourceId.value_or(""),
        .contextId = store.contextId
    };
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
