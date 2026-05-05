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
#include <privmx/endpoint/core/VarDeserializer.hpp>
#include <privmx/endpoint/core/ExceptionConverter.hpp>
#include <privmx/endpoint/core/TimestampValidator.hpp>

#include <privmx/endpoint/store/StoreException.hpp>
#include "privmx/endpoint/store/DynamicTypes.hpp"
#include "privmx/endpoint/store/ServerTypes.hpp"
#include "privmx/endpoint/store/StoreApiImpl.hpp"
#include "privmx/endpoint/store/Mapper.hpp"
#include "privmx/endpoint/core/ListQueryMapper.hpp"
#include "privmx/endpoint/core/UsersKeysResolver.hpp"
#include "privmx/endpoint/core/Validator.hpp"

#include "privmx/endpoint/store/FileHandler.hpp"
#include "privmx/endpoint/store/encryptors/file/FileMetaEncryptor.hpp"
#include "privmx/endpoint/store/encryptors/fileData/HmacList.hpp"
#include "privmx/endpoint/store/encryptors/fileData/ChunkEncryptor.hpp"
#include "privmx/endpoint/store/interfaces/IFileHandler.hpp"
#include "privmx/endpoint/store/interfaces/IChunkDataProvider.hpp"
#include "privmx/endpoint/store/ChunkDataProvider.hpp"
#include "privmx/endpoint/store/ChunkReader.hpp"
#include <privmx/endpoint/core/ConvertedExceptions.hpp>
#include "privmx/endpoint/core/Mapper.hpp"
#include "privmx/endpoint/core/EventBuilder.hpp"

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
) : ModuleBaseApi(userPrivKey, keyProvider, host, eventMiddleware, connection),
    _keyProvider(keyProvider),
    _serverApi(serverApi),
    _host(host),
    _userPrivKey(userPrivKey),
    _requestApi(requestApi),
    _fileDataProvider(fileDataProvider),
    _eventMiddleware(eventMiddleware),
    _handleManager(handleManager),
    _connection(connection),
    _serverRequestChunkSize(serverRequestChunkSize),

    _fileHandleManager(FileHandleManager(handleManager, "Store")),
    _dataEncryptorCompatV1(core::DataEncryptor<dynamic::compat_v1::StoreData>()),
    _fileMetaEncryptorV1(FileMetaEncryptorV1()),
    _fileKeyIdFormatValidator(FileKeyIdFormatValidator()),
    _subscriber(connection.getImpl()->getGateway(), STORE_TYPE_FILTER_FLAG),
    _fileMetaEncryptorV4(FileMetaEncryptorV4())
{
    _notificationListenerId = _eventMiddleware->addNotificationEventListener(std::bind(&StoreApiImpl::processNotificationEvent, this, std::placeholders::_1, std::placeholders::_2));
    _connectedListenerId = _eventMiddleware->addConnectedEventListener(std::bind(&StoreApiImpl::processConnectedEvent, this));
    _disconnectedListenerId = _eventMiddleware->addDisconnectedEventListener(std::bind(&StoreApiImpl::processDisconnectedEvent, this));
}

StoreApiImpl::~StoreApiImpl() {
    _eventMiddleware->removeNotificationEventListener(_notificationListenerId);
    _eventMiddleware->removeConnectedEventListener(_connectedListenerId);
    _eventMiddleware->removeDisconnectedEventListener(_disconnectedListenerId);
    _guardedExecutor.reset();
    LOG_TRACE("~StoreApiImpl Done");
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
    std::string resourceId = core::EndpointUtils::generateId();
    auto storeDIO = _connection.getImpl()->createDIO(
        contextId,
        resourceId
    );
    auto storeSecret = _keyProvider->generateSecret();
    core::ModuleDataToEncryptV5 storeDataToEncrypt {
        .publicMeta = publicMeta,
        .privateMeta = privateMeta,
        .internalMeta = core::ModuleInternalMetaV5{.secret=storeSecret, .resourceId=resourceId, .randomId=storeDIO.randomId},
        .dio = storeDIO
    };
    server::StoreCreateModel storeCreateModel;
    storeCreateModel.resourceId = resourceId;
    storeCreateModel.contextId = contextId;
    storeCreateModel.keyId = storeKey.id;
    storeCreateModel.data = _storeDataEncryptorV5.encrypt(storeDataToEncrypt, _userPrivKey, storeKey.key).toJSON();
    if (type.length() > 0) {
        storeCreateModel.type = type;
    }
    if (policies.has_value()) {
        storeCreateModel.policy = privmx::endpoint::core::Factory::createPolicyServerObject(policies.value());
    }
    auto all_users = core::EndpointUtils::uniqueListUserWithPubKey(users, managers);
    storeCreateModel.keys = _keyProvider->prepareKeysList(
        all_users,
        storeKey,
        storeDIO,
        {.contextId=contextId, .resourceId=resourceId},
        storeSecret
    );
    std::vector<std::string> usersList;
    for (auto user: users) {
        usersList.push_back(user.userId);
    }
    std::vector<std::string> managersList;
    for (auto x: managers) {
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

    server::StoreGetModel getModel;
    getModel.storeId = storeId;
    auto currentStore {_serverApi->storeGet(getModel).store};
    auto currentStoreEntry = currentStore.data.back();
    auto currentStoreResourceId = currentStore.resourceId.has_value() ? currentStore.resourceId.value() : core::EndpointUtils::generateId();
    auto location {getModuleEncKeyLocation(currentStore, currentStoreResourceId)};
    auto storeKeys {getAndValidateModuleKeys(currentStore, currentStoreResourceId)};
    auto currentStoreKey {findEncKeyByKeyId(storeKeys, currentStoreEntry.keyId)};
    auto storeInternalMeta = extractAndDecryptModuleInternalMeta(currentStoreEntry, currentStoreKey);

    auto usersKeysResolver {core::UsersKeysResolver::create(currentStore, users, managers, forceGenerateNewKey, currentStoreKey)};

    if(!_keyProvider->verifyKeysSecret(storeKeys, location, storeInternalMeta.secret)) {
        throw StoreEncryptionKeyValidationException();
    }
    core::EncKey storeKey = currentStoreKey;
    core::DataIntegrityObject updateStoreDio = _connection.getImpl()->createDIO(currentStore.contextId, currentStoreResourceId);

    std::vector<core::server::KeyEntrySet> keys;
    if(usersKeysResolver->doNeedNewKey()) {
        storeKey = _keyProvider->generateKey();
        keys = _keyProvider->prepareKeysList(
            usersKeysResolver->getNewUsers(),
            storeKey,
            updateStoreDio,
            location,
            storeInternalMeta.secret
        );
    }

    auto usersToAddMissingKey {usersKeysResolver->getUsersToAddKey()};
    if(usersToAddMissingKey.size() > 0) {
        auto tmp = _keyProvider->prepareMissingKeysForNewUsers(
            storeKeys,
            usersToAddMissingKey,
            updateStoreDio,
            location,
            storeInternalMeta.secret
        );
        for(auto t: tmp) keys.push_back(t);
    }

    server::StoreUpdateModel model;
    std::vector<std::string> usersList;
    for (auto user: users) {
        usersList.push_back(user.userId);
    }
    std::vector<std::string> managersList;
    for (auto x: managers) {
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
    core::ModuleDataToEncryptV5 storeDataToEncrypt {
        .publicMeta = publicMeta,
        .privateMeta = privateMeta,
        .internalMeta = core::ModuleInternalMetaV5{.secret=storeInternalMeta.secret, .resourceId=currentStoreResourceId, .randomId=updateStoreDio.randomId},
        .dio = updateStoreDio
    };
    model.data = _storeDataEncryptorV5.encrypt(storeDataToEncrypt, _userPrivKey, storeKey.key).toJSON();

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
    setNewModuleKeysInCache(
        store.id,
        storeToModuleKeys(store),
        store.version
    );
    PRIVMX_DEBUG_TIME_CHECKPOINT(PlatformStore, _storeGetEx, data send)
    auto result = validateDecryptAndConvertStoreDataToStore(store);
    PRIVMX_DEBUG_TIME_STOP(PlatformStore, _getStoreEx, data decrypted)
    return result;
}

core::PagingList<Store> StoreApiImpl::listStores(const std::string& contextId, const core::PagingQuery& query) {
    return _storeListEx(contextId, query, STORE_TYPE_FILTER_FLAG);
}

core::PagingList<Store> StoreApiImpl::listStoresEx(const std::string& contextId, const core::PagingQuery& query, const std::string& type) {
    return _storeListEx(contextId, query, type);
}

core::PagingList<Store> StoreApiImpl::_storeListEx(const std::string& contextId, const core::PagingQuery& query, const std::string& type) {
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
    for (auto store: storesList.stores) {
        setNewModuleKeysInCache(
            store.id,
            storeToModuleKeys(store),
            store.version
        );
    }
    auto stores = validateDecryptAndConvertStoresDataToStores(storesList.stores);
    PRIVMX_DEBUG_TIME_STOP(PlatformStore, _listStoresEx, data decrypted)
    return core::PagingList<Store>({
        .totalAvailable = storesList.count,
        .readItems = stores
    });
}

File StoreApiImpl::getFile(const std::string& fileId) {
    PRIVMX_DEBUG_TIME_START(PlatformStore, getFile)
    server::StoreFileGetModel storeFileGetModel;
    storeFileGetModel.fileId = fileId;
    PRIVMX_DEBUG_TIME_CHECKPOINT(PlatformStore, getFile)
    auto serverFileResult = _serverApi->storeFileGet(storeFileGetModel);
    PRIVMX_DEBUG_TIME_CHECKPOINT(PlatformStore, getFile, data send)
    auto store = serverFileResult.store;
    assertStoreDataIntegrity(store);
    setNewModuleKeysInCache(
        store.id,
        storeToModuleKeys(store),
        store.version
    );
    auto statusCode = validateFileDataIntegrity(serverFileResult.file, store.resourceId.value_or(""));
    if(statusCode != 0) {
        PRIVMX_DEBUG_TIME_STOP(PlatformStore, getFile, data integrity validation failed)
        File result;
        result.statusCode = statusCode;
        return result;
    }
    auto ret {validateDecryptAndConvertFileDataToFileInfo(serverFileResult.file, storeToModuleKeys(store))};
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
    assertStoreDataIntegrity(store);
    setNewModuleKeysInCache(
        store.id,
        storeToModuleKeys(store),
        store.version
    );
    auto files = validateDecryptAndConvertFilesDataToFilesInfo(serverFilesResult.files, storeToModuleKeys(store));
    PRIVMX_DEBUG_TIME_STOP(PlatformStore, storeFileList, data decrypted)
    return core::PagingList<File>({
        .totalAvailable = serverFilesResult.count,
        .readItems = files
    });
}

void StoreApiImpl::deleteFile(const std::string& fileId) {
    PRIVMX_DEBUG_TIME_START(PlatformStore, storeFileDelete)
    server::StoreFileDeleteModel model;
    model.fileId = fileId;
    PRIVMX_DEBUG_TIME_CHECKPOINT(PlatformStore, storeFileWrite)
    _serverApi->storeFileDelete(model);
    PRIVMX_DEBUG_TIME_STOP(PlatformStore, storeFileDelete, data send)
}

int64_t StoreApiImpl::createFile(const std::string& storeId, const core::Buffer& publicMeta, const core::Buffer& privateMeta, const int64_t size, bool randomWriteSupport) {
    assertStoreExist(storeId);
    std::shared_ptr<FileWriteHandle> handle = _fileHandleManager.createFileWriteHandle(
        storeId,
        std::string(),
        core::EndpointUtils::generateId(),
        (uint64_t)size,
        publicMeta,
        privateMeta,
        _CHUNK_SIZE,
        _serverRequestChunkSize,
        _requestApi,
        randomWriteSupport
    );
    handle->createRequestData();
    return handle->getId();
}

int64_t StoreApiImpl::updateFile(const std::string& fileId, const core::Buffer& publicMeta, const core::Buffer& privateMeta, const int64_t size) {
    server::StoreFileGetModel storeFileGetModel;
    storeFileGetModel.fileId = fileId;
    auto result = _serverApi->storeFileGet(storeFileGetModel);
    auto internalMeta = validateDecryptFileInternalMeta(result.file, storeToModuleKeys(result.store));
    std::shared_ptr<FileWriteHandle> handle = _fileHandleManager.createFileWriteHandle(
        result.store.id,
        fileId,
        result.file.resourceId,
        (uint64_t)size,
        publicMeta,
        privateMeta,
        _CHUNK_SIZE,
        _serverRequestChunkSize,
        _requestApi,
        internalMeta.randomWrite.value_or(false)
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
            encryptionParams,
            _serverRequestChunkSize,
            _userPrivKey,
            _connection,
            _serverApi
        );
        return handle->getId();
    }
    return createFileReadHandle(encryptionParams.fileDecryptionParams);
}

FileDecryptionParams StoreApiImpl::getFileDecryptionParams(server::File file, const core::DecryptedEncKey& encKey) {
    auto internalMeta = decryptFileInternalMeta(file, core::DecryptedEncKey(encKey));
    return getFileDecryptionParams(file, internalMeta);
}

FileDecryptionParams StoreApiImpl::getFileDecryptionParams(server::File file, dynamic::InternalStoreFileMeta internalMeta) {
    if ((uint64_t)internalMeta.chunkSize > SIZE_MAX) {
        throw NumberToBigForCPUArchitectureException("chunkSize to big for this CPU architecture");
    }
    return FileDecryptionParams {
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
        throw UnsupportedCipherTypeException(std::to_string(storeFileDecryptionParams.cipherType) + " expected type: 1");
    }
    std::shared_ptr<FileReadHandle> handle = _fileHandleManager.createFileReadHandle(
        storeFileDecryptionParams,
        _serverRequestChunkSize,
        _serverApi
    );
    return handle->getId();
}

void StoreApiImpl::writeToFile(const int64_t handleId, const core::Buffer& dataChunk, bool truncate) {
    std::shared_ptr<FileReadWriteHandle> rw_handle = _fileHandleManager.tryGetFileReadWriteHandle(handleId);
    if (rw_handle) {
        core::Validator::validateBufferSize(dataChunk, 0, 512*1024, "field:dataChunk");
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
            encryptionParams.fileMeta,
            encryptionParams.fileDecryptionParams,
            encryptionParams.encKey
        );
        return;
    }
    std::shared_ptr<FileReadHandle> handlePtr = _fileHandleManager.getFileReadHandle(handle);
    try {
        handlePtr->sync(
            encryptionParams.fileDecryptionParams
        );
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
                .keys=store.keys,
                .currentKeyId=store.keyId,
                .moduleSchemaVersion=getStoreEntryDataStructureVersion(store.data.back()),
                .moduleResourceId=store.resourceId.value_or(""),
                .contextId=store.contextId
            };
            setNewModuleKeysInCache(
                store.id,
                storeKey,
                store.version
            );
        }
        return storeFileFinalizeWriteRequest(handle, data, storeKey);
    } catch (const privmx::utils::PrivmxException& e) {
        if (core::ExceptionConverter::convert(e).getCode() == privmx::endpoint::server::InvalidKeyException().getCode() && handle->getFileId().empty()) {
            privmx::endpoint::core::ModuleKeys storeKey = getNewModuleKeysAndUpdateCache(handle->getStoreId());

            return storeFileFinalizeWriteRequest(handle, data, storeKey);
        }
        throw e;
    }
}

std::string StoreApiImpl::storeFileFinalizeWriteRequest(const std::shared_ptr<FileWriteHandle>& handle, const ChunksSentInfo& data, const core::ModuleKeys& storeKey) {
    auto serverId = _host;
    auto key = getAndValidateModuleCurrentEncKey(storeKey);
    if(key.statusCode != 0) {
        throw StoreEncryptionKeyValidationException("Current encryption key statusCode: " + std::to_string(key.statusCode));
    }
    dynamic::InternalStoreFileMeta internalFileMeta;
    internalFileMeta.version = 4;
    internalFileMeta.size = handle->getSize();
    internalFileMeta.cipherType = data.cipherType;
    internalFileMeta.chunkSize = data.chunkSize;
    internalFileMeta.key = utils::Base64::from(data.key);
    internalFileMeta.hmac = utils::Base64::from(data.hmac);
    internalFileMeta.randomWrite = handle->getRandomWriteSupport();
    auto fileId = core::EndpointUtils::generateId();
    Poco::Dynamic::Var encryptedMetaVar;
    switch (storeKey.moduleSchemaVersion) {
        case StoreDataSchema::Version::UNKNOWN:
            throw UnknowStoreFormatException();
        case StoreDataSchema::Version::VERSION_1:
        case StoreDataSchema::Version::VERSION_4: {
            store::FileMetaToEncryptV4 fileMeta {
                .publicMeta = handle->getPublicMeta(),
                .privateMeta = handle->getPrivateMeta(),
                .fileSize = handle->getSize(),
                .internalMeta = core::Buffer::from(utils::Utils::stringifyVar(internalFileMeta.toJSON()))
            };
            encryptedMetaVar = _fileMetaEncryptorV4.encrypt(fileMeta, _userPrivKey, key.key).toJSON();
            break;
        }
        case StoreDataSchema::Version::VERSION_5: {
            privmx::endpoint::core::DataIntegrityObject fileDIO = _connection.getImpl()->createDIO(
                storeKey.contextId,
                handle->getResourceId(),
                handle->getStoreId(),
                storeKey.moduleResourceId
            );
            store::FileMetaToEncryptV5 fileMeta {
                .publicMeta = handle->getPublicMeta(),
                .privateMeta = handle->getPrivateMeta(),
                .internalMeta = core::Buffer::from(utils::Utils::stringifyVar(internalFileMeta.toJSON())),
                .dio = fileDIO
            };
            auto encryptedMeta = _fileMetaEncryptorV5.encrypt(fileMeta, _userPrivKey, key.key);
            encryptedMetaVar = encryptedMeta.toJSON();

            break;
        }
    }
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
    if(!subscriptionQuery.has_value()) {
        return;
    }
    _guardedExecutor->exec([&, type, notification]() {
        if (type == "storeCreated") {
            auto raw = server::Store::fromJSON(notification.data);
            if(raw.type.value_or(std::string(STORE_TYPE_FILTER_FLAG)) == STORE_TYPE_FILTER_FLAG) {
                setNewModuleKeysInCache(raw.id, storeToModuleKeys(raw), raw.version);
                auto data = validateDecryptAndConvertStoreDataToStore(raw);
                auto event = core::EventBuilder::buildEvent<StoreCreatedEvent>("store", data, notification);
                _eventMiddleware->emitApiEvent(event);
            }
        } else if (type == "storeUpdated") {
            auto raw = server::Store::fromJSON(notification.data);
            if(raw.type.value_or(std::string(STORE_TYPE_FILTER_FLAG)) == STORE_TYPE_FILTER_FLAG) {
                setNewModuleKeysInCache(raw.id, storeToModuleKeys(raw), raw.version);
                auto data = validateDecryptAndConvertStoreDataToStore(raw);
                auto event = core::EventBuilder::buildEvent<StoreUpdatedEvent>("store", data, notification);
                _eventMiddleware->emitApiEvent(event);
            }
        } else if (type == "storeDeleted") {
            auto raw = server::StoreDeletedEventData::fromJSON(notification.data);
            if(raw.type.value_or(std::string(STORE_TYPE_FILTER_FLAG)) == STORE_TYPE_FILTER_FLAG) {
                invalidateModuleKeysInCache(raw.storeId);
                auto data = Mapper::mapToStoreDeletedEventData(raw);
                auto event = core::EventBuilder::buildEvent<StoreDeletedEvent>("store", data, notification);
                _eventMiddleware->emitApiEvent(event);
            }
        } else if (type == "storeStatsChanged") {
            auto raw = server::StoreStatsChangedEventData::fromJSON(notification.data);
            if(raw.type.value_or(std::string(STORE_TYPE_FILTER_FLAG)) == STORE_TYPE_FILTER_FLAG) {
                auto data = Mapper::mapToStoreStatsChangedEventData(raw);
                auto event = core::EventBuilder::buildEvent<StoreStatsChangedEvent>("store", data, notification);
                _eventMiddleware->emitApiEvent(event);
            }
        } else if (type == "storeFileCreated") {
            auto raw = server::StoreFileEventData::fromJSON(notification.data);
            if(raw.containerType.value_or(std::string(STORE_TYPE_FILTER_FLAG)) == STORE_TYPE_FILTER_FLAG) {
                auto file = validateDecryptAndConvertFileDataToFileInfo(raw, getFileDecryptionKeys(raw));
                auto event = core::EventBuilder::buildEvent<StoreFileCreatedEvent>("store/" + raw.storeId + "/files", file, notification);
                _eventMiddleware->emitApiEvent(event);
            }
        } else if (type == "storeFileUpdated") {
            auto raw = server::StoreFileUpdatedEventData::fromJSON(notification.data);
            if(raw.containerType.value_or(std::string(STORE_TYPE_FILTER_FLAG)) == STORE_TYPE_FILTER_FLAG) {
                auto storeKeys = getFileDecryptionKeys(raw);
                auto file = validateDecryptAndConvertFileDataToFileInfo(raw, storeKeys);
                auto internalMeta = validateDecryptFileInternalMeta(raw, storeKeys);
                auto fileDecryptionParams = getFileDecryptionParams(raw, internalMeta);
                auto data = Mapper::mapToStoreFileUpdatedEventData(raw, file, fileDecryptionParams);
                auto event = core::EventBuilder::buildEvent<StoreFileUpdatedEvent>("store/" + raw.storeId + "/files", data, notification);
                _eventMiddleware->emitApiEvent(event);
            }
        } else if (type == "storeFileDeleted") {
            auto raw = server::StoreFileDeletedEventData::fromJSON(notification.data);
            if(raw.containerType.value_or(std::string(STORE_TYPE_FILTER_FLAG)) == STORE_TYPE_FILTER_FLAG) {
                auto data = Mapper::mapToStoreFileDeletedEventData(raw);
                auto event = core::EventBuilder::buildEvent<StoreFileDeletedEvent>("store/" + raw.storeId + "/files", data, notification);
                _eventMiddleware->emitApiEvent(event);
            }
        } else if (type == "storeCollectionChanged") {
            auto raw = core::server::CollectionChangedEventData::fromJSON(notification.data);
            if (raw.containerType.value_or(std::string(STORE_TYPE_FILTER_FLAG)) == STORE_TYPE_FILTER_FLAG) {
                auto data = core::Mapper::mapToCollectionChangedEventData(STORE_TYPE_FILTER_FLAG, raw);
                auto event = core::EventBuilder::buildEvent<core::CollectionChangedEvent>("store/collectionChanged", data, notification);
                _eventMiddleware->emitApiEvent(event);
            }
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

dynamic::compat_v1::StoreData StoreApiImpl::decryptStoreV1(server::StoreDataEntry storeEntry, const core::DecryptedEncKey& encKey) {
    try {
        return _dataEncryptorCompatV1.decrypt(storeEntry.data.convert<std::string>(), encKey);
    } catch (const core::Exception& e) {
        dynamic::compat_v1::StoreData result;
        result.name = std::string();
        result.statusCode = e.getCode();
        return result;
    } catch (const privmx::utils::PrivmxException& e) {
        dynamic::compat_v1::StoreData result;
        result.name = std::string();
        result.statusCode = core::ExceptionConverter::convert(e).getCode();
        return result;
    } catch (...) {
        dynamic::compat_v1::StoreData result;
        result.name = std::string();
        result.statusCode = ENDPOINT_CORE_EXCEPTION_CODE;
        return result;
    }
}

Store StoreApiImpl::convertServerStoreToLibStore(
    server::Store store,
    const core::Buffer& publicMeta,
    const core::Buffer& privateMeta,
    const int64_t& statusCode,
    const int64_t& schemaVersion
) {
    std::vector<std::string> users;
    std::vector<std::string> managers;
    for (auto x : store.users) {
        users.push_back(x);
    }
    for (auto x : store.managers) {
        managers.push_back(x);
    }
    return Store{
        .storeId = store.id,
        .contextId = store.contextId,
        .createDate = store.createDate,
        .creator = store.creator,
        .lastModificationDate = store.lastModificationDate,
        .lastFileDate = store.lastFileDate,
        .lastModifier = store.lastModifier,
        .users = users,
        .managers = managers,
        .version = store.version,
        .publicMeta = publicMeta,
        .privateMeta = privateMeta,
        .policy = core::Factory::parsePolicyServerObject(store.policy),
        .filesCount = store.files,
        .statusCode = statusCode,
        .schemaVersion = schemaVersion
    };
}

Store StoreApiImpl::convertStoreDataV1ToStore(server::Store store, dynamic::compat_v1::StoreData storeData) {
    Poco::JSON::Object::Ptr privateMeta = Poco::JSON::Object::Ptr(new Poco::JSON::Object());
    privateMeta->set("title", storeData.name);
    return convertServerStoreToLibStore(
        store,
        core::Buffer::from(""),
        core::Buffer::from(utils::Utils::stringify(privateMeta)),
        storeData.statusCode,
        StoreDataSchema::Version::VERSION_1

    );
}

Store StoreApiImpl::convertDecryptedStoreDataV4ToStore(server::Store store, const core::DecryptedModuleDataV4& storeData) {
    return convertServerStoreToLibStore(
        store,
        storeData.publicMeta,
        storeData.privateMeta,
        storeData.statusCode,
        StoreDataSchema::Version::VERSION_4
    );
}

Store StoreApiImpl::convertDecryptedStoreDataV5ToStore(server::Store store, const core::DecryptedModuleDataV5& storeData) {
    return convertServerStoreToLibStore(
        store,
        storeData.publicMeta,
        storeData.privateMeta,
        storeData.statusCode,
        StoreDataSchema::Version::VERSION_5
    );
}

StoreDataSchema::Version StoreApiImpl::getStoreEntryDataStructureVersion(server::StoreDataEntry storeEntry) {
    if(storeEntry.data.type() == typeid(Poco::JSON::Object::Ptr)) {
        auto versioned = core::dynamic::VersionedData::fromJSON(storeEntry.data);
        switch (versioned.version) {
            case core::ModuleDataSchema::Version::VERSION_4:
                return StoreDataSchema::Version::VERSION_4;
            case core::ModuleDataSchema::Version::VERSION_5:
                return StoreDataSchema::Version::VERSION_5;
            default:
                return StoreDataSchema::Version::UNKNOWN;
        }
    } else if (storeEntry.data.isString()) {
        return StoreDataSchema::Version::VERSION_1;
    }
    return StoreDataSchema::Version::UNKNOWN;
}

std::tuple<Store, core::DataIntegrityObject> StoreApiImpl::decryptAndConvertStoreDataToStore(server::Store store, server::StoreDataEntry storeEntry, const core::DecryptedEncKey& encKey) {
    switch (getStoreEntryDataStructureVersion(storeEntry)) {
        case StoreDataSchema::Version::UNKNOWN: {
            auto e = UnknowStoreFormatException();
            return std::make_tuple(convertServerStoreToLibStore(store, {}, {}, e.getCode()), core::DataIntegrityObject());
        }
        case StoreDataSchema::Version::VERSION_1: {
            return std::make_tuple(
                convertStoreDataV1ToStore(store, decryptStoreV1(storeEntry, encKey)),
                core::DataIntegrityObject{
                    .creatorUserId = store.lastModifier,
                    .creatorPubKey = "",
                    .contextId = store.contextId,
                    .resourceId = store.resourceId.value_or(""),
                    .timestamp = store.lastModificationDate,
                    .randomId = std::string(),
                    .containerId = std::nullopt,
                    .containerResourceId = std::nullopt,
                    .bridgeIdentity = std::nullopt
                }
            );
        }
        case StoreDataSchema::Version::VERSION_4: {
            auto decryptedStoreData = decryptModuleDataV4(storeEntry, encKey);
            return std::make_tuple(
                convertDecryptedStoreDataV4ToStore(store, decryptedStoreData),
                core::DataIntegrityObject{
                    .creatorUserId = store.lastModifier,
                    .creatorPubKey = decryptedStoreData.authorPubKey,
                    .contextId = store.contextId,
                    .resourceId = store.resourceId.value_or(""),
                    .timestamp = store.lastModificationDate,
                    .randomId = std::string(),
                    .containerId = std::nullopt,
                    .containerResourceId = std::nullopt,
                    .bridgeIdentity = std::nullopt
                }
            );
        }
        case StoreDataSchema::Version::VERSION_5: {
            auto decryptedStoreData = decryptModuleDataV5(storeEntry, encKey);
            return std::make_tuple(convertDecryptedStoreDataV5ToStore(store, decryptedStoreData), decryptedStoreData.dio);
        }
    }
    auto e = UnknowStoreFormatException();
    return std::make_tuple(convertServerStoreToLibStore(store, {}, {}, e.getCode()), core::DataIntegrityObject());
}

std::vector<Store> StoreApiImpl::validateDecryptAndConvertStoresDataToStores(std::vector<server::Store> stores) {
    std::vector<Store> result(stores.size());
    for (size_t i = 0; i < stores.size(); i++) {
        auto store = stores[i];
        result[i].statusCode = validateStoreDataIntegrity(store);
        if(result[i].statusCode != 0) {
            result[i] = convertServerStoreToLibStore(store, {}, {}, result[i].statusCode);
        }
    }
    core::KeyDecryptionAndVerificationRequest keyProviderRequest;
    for (size_t i = 0; i < stores.size(); i++) {
        auto store = stores[i];
        core::EncKeyLocation location{.contextId=store.contextId, .resourceId=store.resourceId.value_or("")};
        auto store_data_entry = store.data.back();
        keyProviderRequest.addOne(store.keys, store_data_entry.keyId, location);
    }
    auto storesKeys {_keyProvider->getKeysAndVerify(keyProviderRequest)};
    std::vector<core::DataIntegrityObject> storesDIO(stores.size());
    std::map<std::string, bool> duplication_check;
    for (size_t i = 0; i < stores.size(); i++) {
        if(result[i].statusCode != 0) {
            storesDIO.push_back(core::DataIntegrityObject{});
        } else {
            auto store = stores[i];
            try {
                auto tmp = decryptAndConvertStoreDataToStore(
                    store,
                    store.data.back(),
                    storesKeys.at(core::EncKeyLocation{.contextId=store.contextId, .resourceId=store.resourceId.value_or("")}).at(store.data.back().keyId)
                );
                result[i] = std::get<0>(tmp);
                auto storeDIO = std::get<1>(tmp);
                storesDIO[i] = storeDIO;
                std::string fullRandomId = storeDIO.randomId + "-" + std::to_string(storeDIO.timestamp);
                if(duplication_check.find(fullRandomId) == duplication_check.end()) {
                    duplication_check.insert(std::make_pair(fullRandomId, true));
                } else {
                    result[i].statusCode = core::DataIntegrityObjectDuplicatedException().getCode();
                }
            } catch (const core::Exception& e) {
                result[i] = convertServerStoreToLibStore(store, {}, {}, e.getCode());
                storesDIO[i] = core::DataIntegrityObject{};
            }
        }
    }
    std::vector<core::VerificationRequest> verifierInput {};
    for (size_t i = 0; i < result.size(); i++) {
        if(result[i].statusCode == 0) {
            verifierInput.push_back(core::VerificationRequest{
                .contextId = result[i].contextId,
                .senderId = result[i].lastModifier,
                .senderPubKey = storesDIO[i].creatorPubKey,
                .date = result[i].lastModificationDate,
                .bridgeIdentity = storesDIO[i].bridgeIdentity
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

Store StoreApiImpl::validateDecryptAndConvertStoreDataToStore(server::Store store) {

    try {
        auto statusCode = validateStoreDataIntegrity(store);
        if(statusCode != 0) {
            return convertServerStoreToLibStore(store, {}, {}, statusCode);
        }
        auto store_data_entry = store.data.back();
        core::KeyDecryptionAndVerificationRequest keyProviderRequest;
        core::EncKeyLocation location{.contextId=store.contextId, .resourceId=store.resourceId.value_or("")};
        keyProviderRequest.addOne(store.keys, store_data_entry.keyId, location);
        auto key = _keyProvider->getKeysAndVerify(keyProviderRequest).at(location).at(store_data_entry.keyId);
        Store result;
        core::DataIntegrityObject storeDIO;
        std::tie(result, storeDIO) = decryptAndConvertStoreDataToStore(store, store_data_entry, key);
        if(result.statusCode != 0) return result;
        std::vector<core::VerificationRequest> verifierInput {};
        verifierInput.push_back(core::VerificationRequest{
            .contextId = result.contextId,
            .senderId = result.lastModifier,
            .senderPubKey = storeDIO.creatorPubKey,
            .date = result.lastModificationDate,
            .bridgeIdentity = storeDIO.bridgeIdentity
        });
        std::vector<bool> verified;
        verified =_connection.getImpl()->getUserVerifier()->verify(verifierInput);
        result.statusCode = verified[0] ? 0 : core::ExceptionConverter::getCodeOfUserVerificationFailureException();
        return result;
    } catch (const core::Exception& e) {
        return convertServerStoreToLibStore(store,{},{},e.getCode());
    } catch (const privmx::utils::PrivmxException& e) {
        return convertServerStoreToLibStore(store,{},{},core::ExceptionConverter::convert(e).getCode());
    } catch (...) {
        return convertServerStoreToLibStore(store,{},{},ENDPOINT_CORE_EXCEPTION_CODE);
    }

}

FileEncryptionParams StoreApiImpl::getFileEncryptionParams(server::File file, const core::DecryptedEncKey& encKey) {
    File decryptedFile;
    core::DataIntegrityObject fileDIO;
    std::tie(decryptedFile, fileDIO) = decryptAndConvertFileDataToFileInfo(file, core::DecryptedEncKey(encKey));
    auto internalMeta = decryptFileInternalMeta(file, core::DecryptedEncKey(encKey));
    return FileEncryptionParams{
        FileMeta{
            .publicMeta=decryptedFile.publicMeta,
            .privateMeta=decryptedFile.privateMeta,
            .internalFileMeta=internalMeta
        },
        getFileDecryptionParams(file, internalMeta),
        encKey
    };
}

FileEncryptionParams StoreApiImpl::getFileEncryptionParams(server::File file, server::Store store) {
    core::KeyDecryptionAndVerificationRequest keyProviderRequest;
    core::EncKeyLocation location{.contextId=store.contextId, .resourceId=store.resourceId.value_or("")};
    keyProviderRequest.addOne(store.keys, file.keyId, location);
    auto key = _keyProvider->getKeysAndVerify(keyProviderRequest).at(location).at(file.keyId);
    return getFileEncryptionParams(file, key);
}

// OLD CODE
StoreFile StoreApiImpl::decryptStoreFileV1(server::File file, const core::DecryptedEncKey& encKey) {
    try {
        auto storeFile = decryptAndVerifyFileV1(encKey.key, file);
        return storeFile;
    } catch (const privmx::endpoint::core::Exception& e) {
        StoreFile result = {.raw=file, .meta=dynamic::compat_v1::StoreFileMeta{}, .verified="invalid"};
        result.meta.statusCode = e.getCode();
        return result;
    } catch (const privmx::utils::PrivmxException& e) {
        StoreFile result = {.raw=file, .meta=dynamic::compat_v1::StoreFileMeta{}, .verified="invalid"};
        result.meta.statusCode = core::ExceptionConverter::convert(e).getCode();
        return result;
    } catch (...) {
        StoreFile result = {.raw=file, .meta=dynamic::compat_v1::StoreFileMeta{}, .verified="invalid"};
        result.meta.statusCode = ENDPOINT_CORE_EXCEPTION_CODE;
        return result;
    }
}
// OLD CODE
std::string StoreApiImpl::verifyFileV1Signature(FileMetaSigned meta, server::File raw, std::string& serverId) {
    try {
        if (meta.signature.length() == 0 || meta.meta.author.pubKey.empty() || meta.meta.destination.server.empty()) {
            return std::string("no-signature");
        }
        if (meta.meta.destination.server != serverId) {
            return std::string("invalid");
        }
        auto storeIdOrStore = meta.meta.destination.storeId.empty() ? meta.meta.destination.store : meta.meta.destination.storeId;
        if (storeIdOrStore != raw.id) {
            return std::string("invalid");
        }
        auto pubKey = privmx::crypto::PublicKey::fromBase58DER(meta.meta.author.pubKey);
        auto result = pubKey.verifyCompactSignatureWithHash(meta.metaBuf, meta.signature);
        return result ? std::string("verified") : std::string("invalid");
    } catch (...) {
        return std::string("invalid");
    }
}
// OLD CODE
StoreFile StoreApiImpl::decryptAndVerifyFileV1(const std::string &filesKey, server::File x) {
    StoreFile odp;
    auto fileMetaSigned = _fileMetaEncryptorV1.decrypt(x.meta.convert<std::string>(), filesKey);
    odp.raw = x;
    odp.meta = fileMetaSigned.meta;
    odp.verified = verifyFileV1Signature(fileMetaSigned, x, _host);
    return odp;
}

DecryptedFileMetaV4 StoreApiImpl::decryptFileMetaV4(server::File file, const core::DecryptedEncKey& encKey) {
    try {
        auto encryptedFileMeta = server::EncryptedFileMetaV4::fromJSON(file.meta);
        return _fileMetaEncryptorV4.decrypt(encryptedFileMeta, encKey.key);
    } catch (const core::Exception& e) {
        return DecryptedFileMetaV4({{.dataStructureVersion = FileDataSchema::Version::VERSION_4, .statusCode = e.getCode()},{},{},{},{},{}});
    } catch (const privmx::utils::PrivmxException& e) {
        return DecryptedFileMetaV4({{.dataStructureVersion = FileDataSchema::Version::VERSION_4, .statusCode = core::ExceptionConverter::convert(e).getCode()},{},{},{},{},{}});
    } catch (...) {
        return DecryptedFileMetaV4({{.dataStructureVersion = FileDataSchema::Version::VERSION_4, .statusCode = ENDPOINT_CORE_EXCEPTION_CODE},{},{},{},{},{}});
    }
}

DecryptedFileMetaV5 StoreApiImpl::decryptFileMetaV5(server::File file, const core::DecryptedEncKey& encKey) {
    try {
        auto encryptedFileMeta = server::EncryptedFileMetaV5::fromJSON(file.meta);
        if(encKey.statusCode != 0) {
            auto tmp = _fileMetaEncryptorV5.extractPublic(encryptedFileMeta);
            tmp.statusCode = encKey.statusCode;
            return tmp;
        } else {
            return _fileMetaEncryptorV5.decrypt(encryptedFileMeta, encKey.key);
        }
    } catch (const core::Exception& e) {
        return DecryptedFileMetaV5({{.dataStructureVersion = FileDataSchema::Version::VERSION_5, .statusCode = e.getCode()},{},{},{},{},{}});
    } catch (const privmx::utils::PrivmxException& e) {
        return DecryptedFileMetaV5({{.dataStructureVersion = FileDataSchema::Version::VERSION_5, .statusCode = core::ExceptionConverter::convert(e).getCode()},{},{},{},{},{}});
    } catch (...) {
        return DecryptedFileMetaV5({{.dataStructureVersion = FileDataSchema::Version::VERSION_5, .statusCode = ENDPOINT_CORE_EXCEPTION_CODE},{},{},{},{},{}});
    }
}

File StoreApiImpl::convertServerFileToLibFile(
    server::File file,
    const core::Buffer& publicMeta,
    const core::Buffer& privateMeta,
    const int64_t& size,
    const std::string& authorPubKey,
    const int64_t& statusCode,
    const int64_t& schemaVersion,
    const bool& randomWrite
) {
    return File{
        .info = {
            .storeId = file.storeId,
            .fileId = file.id,
            .createDate = file.created,
            .author = file.creator,
        },
        .publicMeta = publicMeta,
        .privateMeta = privateMeta,
        .size = size,
        .authorPubKey = authorPubKey,
        .statusCode = statusCode,
        .schemaVersion = schemaVersion,
        .randomWrite = randomWrite
    };
}

File StoreApiImpl::convertStoreFileMetaV1ToFile(server::File file, dynamic::compat_v1::StoreFileMeta storeFileMeta) {
    return convertServerFileToLibFile(
        file,
        core::Buffer(),
        core::Buffer::from(utils::Utils::stringifyVar(storeFileMeta.toJSON())),
        storeFileMeta.size,
        storeFileMeta.author.pubKey,
        storeFileMeta.statusCode,
        FileDataSchema::Version::VERSION_1,
        false
    );
}

File StoreApiImpl::convertDecryptedFileMetaV4ToFile(server::File file, const DecryptedFileMetaV4& fileData) {
    bool randomWrite = false;
    auto statusCode = fileData.statusCode;
    if(statusCode == 0) {
        try {
            auto internalMeta = dynamic::InternalStoreFileMeta::fromJSON(utils::Utils::parseJson(fileData.internalMeta.stdString()));
            randomWrite = internalMeta.randomWrite.value_or(false);
        }  catch (const privmx::endpoint::core::Exception& e) {
            statusCode = e.getCode();
        } catch (const privmx::utils::PrivmxException& e) {
            statusCode = core::ExceptionConverter::convert(e).getCode();
        } catch (...) {
            statusCode = ENDPOINT_CORE_EXCEPTION_CODE;
        }
    }
    return convertServerFileToLibFile(
        file,
        fileData.publicMeta,
        fileData.privateMeta,
        fileData.fileSize,
        fileData.authorPubKey,
        fileData.statusCode,
        FileDataSchema::Version::VERSION_4,
        randomWrite
    );
}

File StoreApiImpl::convertDecryptedFileMetaV5ToFile(server::File file, const DecryptedFileMetaV5& fileData) {
    int64_t size = 0;
    bool randomWrite = false;
    auto statusCode = fileData.statusCode;
    if(statusCode == 0) {
        try {
            auto internalMeta = dynamic::InternalStoreFileMeta::fromJSON(utils::Utils::parseJson(fileData.internalMeta.stdString()));
            size = internalMeta.size;
            randomWrite = internalMeta.randomWrite.value_or(false);
        }  catch (const privmx::endpoint::core::Exception& e) {
            statusCode = e.getCode();
        } catch (const privmx::utils::PrivmxException& e) {
            statusCode = core::ExceptionConverter::convert(e).getCode();
        } catch (...) {
            statusCode = ENDPOINT_CORE_EXCEPTION_CODE;
        }
    }
    return convertServerFileToLibFile(
        file,
        fileData.publicMeta,
        fileData.privateMeta,
        size,
        fileData.authorPubKey,
        statusCode,
        FileDataSchema::Version::VERSION_5,
        randomWrite
    );
}

FileDataSchema::Version StoreApiImpl::getFileDataStructureVersion(server::File file) {
    if (file.meta.type() == typeid(Poco::JSON::Object::Ptr)) {
        auto versioned = core::dynamic::VersionedData::fromJSON(file.meta);
        switch (versioned.version) {
            case FileDataSchema::Version::VERSION_4:
                return FileDataSchema::Version::VERSION_4;
            case FileDataSchema::Version::VERSION_5:
                return FileDataSchema::Version::VERSION_5;
            default:
                return FileDataSchema::Version::UNKNOWN;
        }
    } else if (file.meta.isString()) {
        return FileDataSchema::Version::VERSION_1;
    }
    return FileDataSchema::Version::UNKNOWN;
}

std::tuple<File, core::DataIntegrityObject> StoreApiImpl::decryptAndConvertFileDataToFileInfo(server::File file, const core::DecryptedEncKey& encKey) {
    switch (getFileDataStructureVersion(file)) {
        case FileDataSchema::Version::UNKNOWN: {
            auto e = UnknowFileFormatException();
            return std::make_tuple(convertServerFileToLibFile(file,{},{},{},{},e.getCode()), core::DataIntegrityObject());
        }
        case FileDataSchema::Version::VERSION_1: {
            auto decryptedFile = decryptStoreFileV1(file, encKey).meta;
            return std::make_tuple(
                convertStoreFileMetaV1ToFile(file, decryptedFile),
                core::DataIntegrityObject{
                    .creatorUserId = file.lastModifier,
                    .creatorPubKey = decryptedFile.author.pubKey,
                    .contextId = file.contextId,
                    .resourceId = file.resourceId,
                    .timestamp = file.lastModificationDate,
                    .randomId = std::string(),
                    .containerId = file.storeId,
                    .containerResourceId = std::string(),
                    .bridgeIdentity = std::nullopt
                }
            );
        }
        case FileDataSchema::Version::VERSION_4: {
            auto decryptedFile = decryptFileMetaV4(file, encKey);
            return std::make_tuple(
                convertDecryptedFileMetaV4ToFile(file, decryptedFile),
                core::DataIntegrityObject{
                    .creatorUserId = file.lastModifier,
                    .creatorPubKey = decryptedFile.authorPubKey,
                    .contextId = file.contextId,
                    .resourceId = file.resourceId,
                    .timestamp = file.lastModificationDate,
                    .randomId = std::string(),
                    .containerId = file.storeId,
                    .containerResourceId = std::string(),
                    .bridgeIdentity = std::nullopt
                }
            );
        }
        case FileDataSchema::Version::VERSION_5: {
            auto decryptedFile = decryptFileMetaV5(file, encKey);
            return std::make_tuple(convertDecryptedFileMetaV5ToFile(file, decryptFileMetaV5(file, encKey)), decryptedFile.dio);
        }
    }
    auto e = UnknowFileFormatException();
    return std::make_tuple(convertServerFileToLibFile(file,{},{},{},{},e.getCode()), core::DataIntegrityObject());
}

std::vector<File> StoreApiImpl::validateDecryptAndConvertFilesDataToFilesInfo(std::vector<server::File> files, const core::ModuleKeys& storeKeys) {
    std::set<std::string> keyIds;
    for (auto file : files) {
        keyIds.insert(file.keyId);
    }
    core::KeyDecryptionAndVerificationRequest keyProviderRequest;
    core::EncKeyLocation location{.contextId=storeKeys.contextId, .resourceId=storeKeys.moduleResourceId};
    keyProviderRequest.addMany(storeKeys.keys, keyIds, location);
    auto keyMap = _keyProvider->getKeysAndVerify(keyProviderRequest).at(location);
    std::vector<File> result;
    std::vector<core::DataIntegrityObject> filesDIO;
    std::map<std::string, bool> duplication_check;
    for (auto file : files) {
        try {
            auto statusCode = validateFileDataIntegrity(file, storeKeys.moduleResourceId);
            if(statusCode == 0) {
                auto tmp = decryptAndConvertFileDataToFileInfo(file, keyMap.at(file.keyId));
                result.push_back(std::get<0>(tmp));
                auto fileDIO = std::get<1>(tmp);
                filesDIO.push_back(fileDIO);
                std::string fullRandomId = fileDIO.randomId + "-" + std::to_string(fileDIO.timestamp);
                if(duplication_check.find(fullRandomId) == duplication_check.end()) {
                    duplication_check.insert(std::make_pair(fullRandomId, true));
                } else {
                    result[result.size()-1].statusCode = core::DataIntegrityObjectDuplicatedException().getCode();
                }
            } else {
                result.push_back(convertServerFileToLibFile(file,{},{},{},{},statusCode));
            }
        } catch (const core::Exception& e) {
            result.push_back(convertServerFileToLibFile(file,{},{},{},{},e.getCode()));
        }
    }
    std::vector<core::VerificationRequest> verifierInput {};
    for (size_t i = 0; i < result.size(); i++) {
        if(result[i].statusCode == 0) {
            verifierInput.push_back(core::VerificationRequest{
                .contextId = storeKeys.contextId,
                .senderId = result[i].info.author,
                .senderPubKey = result[i].authorPubKey,
                .date = result[i].info.createDate,
                .bridgeIdentity = filesDIO[i].bridgeIdentity
            });
        }
    }
    std::vector<bool> verified;
    verified = _connection.getImpl()->getUserVerifier()->verify(verifierInput);
    for (size_t j = 0, i = 0; i < result.size(); ++i) {
        if (result[i].statusCode == 0) {
            result[i].statusCode = verified[j] ? 0 : core::ExceptionConverter::getCodeOfUserVerificationFailureException();
            j++;
        }
    }
    return result;
}

File StoreApiImpl::validateDecryptAndConvertFileDataToFileInfo(server::File file, const core::ModuleKeys& storeKeys) {
    try {
        auto keyId = file.keyId;
        _fileKeyIdFormatValidator.assertKeyIdFormat(keyId);
        core::KeyDecryptionAndVerificationRequest keyProviderRequest;
        core::EncKeyLocation location{.contextId=file.contextId, .resourceId=storeKeys.moduleResourceId};
        keyProviderRequest.addOne(storeKeys.keys, keyId, location);
        auto encKey = _keyProvider->getKeysAndVerify(keyProviderRequest).at(location).at(keyId);
        File result;
        core::DataIntegrityObject fileDIO;
        std::tie(result, fileDIO) = decryptAndConvertFileDataToFileInfo(file, encKey);
        if(result.statusCode != 0) return result;
        std::vector<core::VerificationRequest> verifierInput {};
            verifierInput.push_back(core::VerificationRequest{
                .contextId = file.contextId,
                .senderId = result.info.author,
                .senderPubKey = result.authorPubKey,
                .date = result.info.createDate,
                .bridgeIdentity = fileDIO.bridgeIdentity
            });
        std::vector<bool> verified;
        verified = _connection.getImpl()->getUserVerifier()->verify(verifierInput);
        result.statusCode = verified[0] ? 0 : core::ExceptionConverter::getCodeOfUserVerificationFailureException();
        return result;
    } catch (const core::Exception& e) {
        return convertServerFileToLibFile(file,{},{},{},{},e.getCode());
    } catch (const privmx::utils::PrivmxException& e) {
        return convertServerFileToLibFile(file,{},{},{},{},core::ExceptionConverter::convert(e).getCode());
    } catch (...) {
        return convertServerFileToLibFile(file,{},{},{},{},ENDPOINT_CORE_EXCEPTION_CODE);
    }
}

dynamic::InternalStoreFileMeta StoreApiImpl::decryptFileInternalMeta(server::File file, const core::DecryptedEncKey& encKey) {
    if(encKey.statusCode == 0) {
        switch (getFileDataStructureVersion(file)) {
            case FileDataSchema::Version::UNKNOWN: {
                throw UnknowFileFormatException();
            }
            case FileDataSchema::Version::VERSION_1: {
                auto decryptedFile = decryptStoreFileV1(file, encKey);
                dynamic::InternalStoreFileMeta internalFileMeta;
                internalFileMeta.version = 1;
                internalFileMeta.size = decryptedFile.meta.size;
                internalFileMeta.cipherType = decryptedFile.meta.cipherType;
                internalFileMeta.chunkSize = decryptedFile.meta.chunkSize;
                internalFileMeta.key = utils::Base64::from(decryptedFile.meta.key);
                internalFileMeta.hmac = utils::Base64::from(decryptedFile.meta.hmac);
                return internalFileMeta;
            }
            case FileDataSchema::Version::VERSION_4:
                return dynamic::InternalStoreFileMeta::fromJSON(
                    utils::Utils::parseJson(decryptFileMetaV4(file, encKey).internalMeta.stdString())
                );
            case FileDataSchema::Version::VERSION_5:
                return dynamic::InternalStoreFileMeta::fromJSON(
                    utils::Utils::parseJson(decryptFileMetaV5(file, encKey).internalMeta.stdString())
                );
        }
    }
    throw UnknowFileFormatException();
}

dynamic::InternalStoreFileMeta StoreApiImpl::validateDecryptFileInternalMeta(server::File file, const core::ModuleKeys& storeKeys) {
    auto keyId = file.keyId;
    core::KeyDecryptionAndVerificationRequest keyProviderRequest;
    core::EncKeyLocation location{.contextId=file.contextId, .resourceId=storeKeys.moduleResourceId};
    keyProviderRequest.addOne(storeKeys.keys, keyId, location);
    auto encKey = _keyProvider->getKeysAndVerify(keyProviderRequest).at(location).at(keyId);
    _fileKeyIdFormatValidator.assertKeyIdFormat(keyId);
    return decryptFileInternalMeta(file, encKey);
}


core::ModuleKeys StoreApiImpl::getFileDecryptionKeys(server::File file) {
    auto keyId = file.keyId;
    store::StoreDataSchema::Version minimumStoreSchemaVersion;
    switch (getFileDataStructureVersion(file)) {
        case store::FileDataSchema::Version::UNKNOWN:
            minimumStoreSchemaVersion = store::StoreDataSchema::UNKNOWN;
            break;
        case store::FileDataSchema::Version::VERSION_1:
        case store::FileDataSchema::Version::VERSION_4:
            minimumStoreSchemaVersion = store::StoreDataSchema::VERSION_1;
            break;
        case store::FileDataSchema::Version::VERSION_5:
            minimumStoreSchemaVersion = store::StoreDataSchema::VERSION_5;
            break;
    }
    return getModuleKeys(file.storeId, std::set<std::string>{keyId}, minimumStoreSchemaVersion);
}

void StoreApiImpl::updateFileMeta(const std::string& fileId, const core::Buffer& publicMeta, const core::Buffer& privateMeta) {
    server::StoreFileGetModel storeFileGetModel;
    storeFileGetModel.fileId = fileId;

    auto storeFileGetResult = _serverApi->storeFileGet(storeFileGetModel);
    server::Store store = storeFileGetResult.store;
    setNewModuleKeysInCache(
        store.id,
        storeToModuleKeys(store),
        store.version
    );
    server::File file = storeFileGetResult.file;
    auto statusCode = validateFileDataIntegrity(file, store.resourceId.value_or(""));
    if(statusCode != 0) {
        throw FileDataIntegrityException();
    }
    auto key = getAndValidateModuleCurrentEncKey(store);
    if(key.statusCode != 0) {
        throw StoreEncryptionKeyValidationException("Current encryption key statusCode: " + std::to_string(key.statusCode));
    }
    Poco::Dynamic::Var encryptedMetaVar;
    auto fileInternalMeta = validateDecryptFileInternalMeta(file, storeToModuleKeys(store));
    auto internalMeta = core::Buffer::from(utils::Utils::stringifyVar(fileInternalMeta.toJSON()));
    switch (getStoreEntryDataStructureVersion(store.data.back())) {
        case StoreDataSchema::Version::UNKNOWN:
            throw UnknowStoreFormatException();
        case StoreDataSchema::Version::VERSION_1:
        case StoreDataSchema::Version::VERSION_4: {
            store::FileMetaToEncryptV4 fileMeta {
                .publicMeta = publicMeta,
                .privateMeta = privateMeta,
                .fileSize = fileInternalMeta.size,
                .internalMeta = internalMeta
            };
            encryptedMetaVar = _fileMetaEncryptorV4.encrypt(fileMeta, _userPrivKey, key.key).toJSON();
            break;
        }
        case StoreDataSchema::Version::VERSION_5: {
            privmx::endpoint::core::DataIntegrityObject fileDIO = _connection.getImpl()->createDIO(
                file.contextId,
                file.resourceId.empty() ? core::EndpointUtils::generateId() : file.resourceId,
                file.storeId,
                store.resourceId
            );
            store::FileMetaToEncryptV5 fileMeta {
                .publicMeta = publicMeta,
                .privateMeta = privateMeta,
                .internalMeta = internalMeta,
                .dio = fileDIO
            };
            encryptedMetaVar = _fileMetaEncryptorV5.encrypt(fileMeta, _userPrivKey, key.key).toJSON();
            break;
        }
    }
    server::StoreFileUpdateModel storeFileUpdateModel;
    storeFileUpdateModel.fileId = fileId;
    storeFileUpdateModel.meta = encryptedMetaVar;
    storeFileUpdateModel.keyId = key.id;
    _serverApi->storeFileUpdate(storeFileUpdateModel);
}

void StoreApiImpl::assertStoreExist(const std::string& storeId) {
    store::server::StoreGetModel params;
    params.storeId = storeId;
    _serverApi->storeGet(params);
}

void StoreApiImpl::assertFileExist(const std::string& fileId) {
    server::StoreFileGetModel storeFileGetModel;
    storeFileGetModel.fileId = fileId;
    _serverApi->storeFileGet(storeFileGetModel).file;
}

std::pair<core::ModuleKeys, int64_t> StoreApiImpl::getModuleKeysAndVersionFromServer(std::string moduleId) {
    store::server::StoreGetModel params;
    params.storeId = moduleId;
    auto store = _serverApi->storeGet(params).store;
    assertStoreDataIntegrity(store);
    return std::make_pair(storeToModuleKeys(store), store.version);
}

core::ModuleKeys StoreApiImpl::storeToModuleKeys(server::Store store) {
    return core::ModuleKeys{
        .keys=store.keys,
        .currentKeyId=store.keyId,
        .moduleSchemaVersion=getStoreEntryDataStructureVersion(store.data.back()),
        .moduleResourceId=store.resourceId.value_or(""),
        .contextId = store.contextId
    };
}

void StoreApiImpl::assertStoreDataIntegrity(server::Store store) {
    auto store_data_entry = store.data.back();
    switch (getStoreEntryDataStructureVersion(store_data_entry)) {
        case StoreDataSchema::Version::UNKNOWN:
            throw UnknowStoreFormatException();
        case StoreDataSchema::Version::VERSION_1:
            return;
        case StoreDataSchema::Version::VERSION_4:
            return;
        case StoreDataSchema::Version::VERSION_5: {
            auto store_data = core::dynamic::EncryptedModuleDataV5::fromJSON(store_data_entry.data);
            auto dio = _storeDataEncryptorV5.getDIOAndAssertIntegrity(store_data);
            if(
                dio.contextId != store.contextId ||
                dio.resourceId != store.resourceId ||
                dio.creatorUserId != store.lastModifier ||
                !core::TimestampValidator::validate(dio.timestamp, store.lastModificationDate)
            ) {
                throw StoreDataIntegrityException();
            }
            return;
        }
    }
    throw UnknowStoreFormatException();
}

uint32_t StoreApiImpl::validateStoreDataIntegrity(server::Store store) {
    try {
        assertStoreDataIntegrity(store);
        return 0;
    } catch (const core::Exception& e) {
        return e.getCode();
    } catch (const privmx::utils::PrivmxException& e) {
        return core::ExceptionConverter::convert(e).getCode();;
    } catch (...) {
        return ENDPOINT_CORE_EXCEPTION_CODE;
    }
    return UnknowStoreFormatException().getCode();
}

uint32_t StoreApiImpl::validateFileDataIntegrity(server::File file, const std::string& storeResourceId) {
    try {
        switch (getFileDataStructureVersion(file)) {
            case FileDataSchema::Version::UNKNOWN:
                return UnknowFileFormatException().getCode();
            case FileDataSchema::Version::VERSION_1:
                return 0;
            case FileDataSchema::Version::VERSION_4:
                return 0;
            case FileDataSchema::Version::VERSION_5: {
                auto fileMeta = server::EncryptedFileMetaV5::fromJSON(file.meta);
                auto dio = _fileMetaEncryptorV5.getDIOAndAssertIntegrity(fileMeta);
                if(
                    dio.contextId != file.contextId ||
                    dio.resourceId != file.resourceId ||
                    !dio.containerId.has_value() || dio.containerId.value() != file.storeId ||
                    !dio.containerResourceId.has_value() || dio.containerResourceId.value() != storeResourceId ||
                    dio.creatorUserId != file.lastModifier ||
                    !core::TimestampValidator::validate(dio.timestamp, file.lastModificationDate)
                ) {
                    return FileDataIntegrityException().getCode();;
                }
                return 0;
            }
        }
    } catch (const core::Exception& e) {
        return e.getCode();
    } catch (const privmx::utils::PrivmxException& e) {
        return core::ExceptionConverter::convert(e).getCode();
    } catch (...) {
        return ENDPOINT_CORE_EXCEPTION_CODE;
    }
    return UnknowFileFormatException().getCode();
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

std::string StoreApiImpl::buildSubscriptionQuery(EventType eventType, EventSelectorType selectorType, const std::string& selectorId) {
    return SubscriberImpl::buildQuery(eventType, selectorType, selectorId);
}
