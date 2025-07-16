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
#include <privmx/endpoint/core/VarSerializer.hpp>
#include <privmx/endpoint/core/ExceptionConverter.hpp>
#include <privmx/endpoint/core/TimestampValidator.hpp>

#include <privmx/endpoint/store/StoreException.hpp>
#include "privmx/endpoint/store/DynamicTypes.hpp"
#include "privmx/endpoint/store/ServerTypes.hpp"
#include "privmx/endpoint/store/StoreApiImpl.hpp"
#include "privmx/endpoint/store/Mapper.hpp"
#include "privmx/endpoint/store/StoreVarSerializer.hpp"
#include "privmx/endpoint/core/ListQueryMapper.hpp"
#include "privmx/endpoint/core/UsersKeysResolver.hpp"
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
    const std::shared_ptr<core::EventChannelManager>& eventChannelManager,
    const std::shared_ptr<core::HandleManager>& handleManager,
    const core::Connection& connection,
    size_t serverRequestChunkSize
) : ModuleBaseApi(userPrivKey, keyProvider, host, eventMiddleware, eventChannelManager, connection),
    _keyProvider(keyProvider),
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
    _storeSubscriptionHelper(core::SubscriptionHelper(eventChannelManager, 
        "store", "files",
        [&](){},
        [&](){}
    )),
    _fileMetaEncryptorV4(FileMetaEncryptorV4()),
    _forbiddenChannelsNames({INTERNAL_EVENT_CHANNEL_NAME, "store", "files"}) 
{
    _notificationListenerId = _eventMiddleware->addNotificationEventListener(std::bind(&StoreApiImpl::processNotificationEvent, this, std::placeholders::_1, std::placeholders::_2));
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
    // auto new_store_data = utils::TypedObjectFactory::createNewObject<dynamic::StoreData>();
    // new_store_data.name(name);
    auto storeCreateModel = utils::TypedObjectFactory::createNewObject<server::StoreCreateModel>();
    storeCreateModel.resourceId(resourceId);
    storeCreateModel.contextId(contextId);
    storeCreateModel.keyId(storeKey.id);
    storeCreateModel.data(_storeDataEncryptorV5.encrypt(storeDataToEncrypt, _userPrivKey, storeKey.key).asVar());
    if (type.length() > 0) {
        storeCreateModel.type(type);
    }
    if (policies.has_value()) {
        storeCreateModel.policy(privmx::endpoint::core::Factory::createPolicyServerObject(policies.value()));
    }
    auto all_users = core::EndpointUtils::uniqueListUserWithPubKey(users, managers);
    storeCreateModel.keys(
        _keyProvider->prepareKeysList(
            all_users, 
            storeKey, 
            storeDIO,
            {.contextId=contextId, .resourceId=resourceId},
            storeSecret
        )
    );

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
    auto result = _serverApi->storeCreate(storeCreateModel);
    PRIVMX_DEBUG_TIME_STOP(PlatformStore, storeCreate, data send)
    return result.storeId();

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
    auto currentStoreEntry = currentStore.data().get(currentStore.data().size()-1);
    auto currentStoreResourceId = currentStore.resourceIdOpt(core::EndpointUtils::generateId());
    auto location {getModuleEncKeyLocation(currentStore, currentStoreResourceId)};
    auto storeKeys {getAndValidateModuleKeys(currentStore, currentStoreResourceId)};
    auto currentStoreKey {findEncKeyByKeyId(storeKeys, currentStoreEntry.keyId())};
    auto storeInternalMeta = extractAndDecryptModuleInternalMeta(currentStoreEntry, currentStoreKey);

    auto usersKeysResolver {core::UsersKeysResolver::create(currentStore, users, managers, forceGenerateNewKey, currentStoreKey)};

    if(!_keyProvider->verifyKeysSecret(storeKeys, location, storeInternalMeta.secret)) {
        throw StoreEncryptionKeyValidationException();
    }
    // setting store Key adding new users
    core::EncKey storeKey = currentStoreKey;
    core::DataIntegrityObject updateStoreDio = _connection.getImpl()->createDIO(currentStore.contextId(), currentStoreResourceId);
    
    privmx::utils::List<core::server::KeyEntrySet> keys = utils::TypedObjectFactory::createNewList<core::server::KeyEntrySet>();
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
        for(auto t: tmp) keys.add(t);
    }


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
    model.resourceId(currentStoreResourceId);
    model.keyId(storeKey.id);
    model.keys(keys);
    model.users(usersList);
    model.managers(managersList);
    model.version(version);
    model.force(force);
    if (policies.has_value()) {
        model.policy(privmx::endpoint::core::Factory::createPolicyServerObject(policies.value()));
    }
    core::ModuleDataToEncryptV5 storeDataToEncrypt {
        .publicMeta = publicMeta,
        .privateMeta = privateMeta,
        .internalMeta = core::ModuleInternalMetaV5{.secret=storeInternalMeta.secret, .resourceId=currentStoreResourceId, .randomId=updateStoreDio.randomId},
        .dio = updateStoreDio
    };
    model.data(_storeDataEncryptorV5.encrypt(storeDataToEncrypt, _userPrivKey, storeKey.key).asVar());

    PRIVMX_DEBUG_TIME_CHECKPOINT(PlatformStore, storeUpdate, data encrypted)
    _serverApi->storeUpdate(model);
    invalidateModuleKeysInCache(storeId);
    PRIVMX_DEBUG_TIME_STOP(PlatformStore, storeUpdate, data send)
}

void StoreApiImpl::deleteStore(const std::string& storeId) {
    auto model = utils::TypedObjectFactory::createNewObject<server::StoreDeleteModel>();
    model.storeId(storeId);
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
    auto model = privmx::utils::TypedObjectFactory::createNewObject<server::StoreGetModel>();
    model.storeId(storeId);
    if (type.length() > 0) {
        model.type(type);
    }
    PRIVMX_DEBUG_TIME_CHECKPOINT(PlatformStore, _storeGetEx, getting store)
    auto store = _serverApi->storeGet(model).store();
    setNewModuleKeysInCache(
        store.id(), 
        storeToModuleKeys(store),
        store.version()
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
    PRIVMX_DEBUG_TIME_START(PlatformStore, storeList)
    auto storeListModel = utils::TypedObjectFactory::createNewObject<server::StoreListModel>();
    storeListModel.contextId(contextId);
    if (type.length() > 0) {
        storeListModel.type(type);
    }
    core::ListQueryMapper::map(storeListModel, query);
    PRIVMX_DEBUG_TIME_CHECKPOINT(PlatformStore, storeList)
    auto storesList = _serverApi->storeList(storeListModel);
    PRIVMX_DEBUG_TIME_CHECKPOINT(PlatformStore, storeList, data send)
    for (auto store: storesList.stores()) {
        setNewModuleKeysInCache(
            store.id(), 
            storeToModuleKeys(store),
            store.version()
        );
    }
    auto stores = validateDecryptAndConvertStoresDataToStores(storesList.stores());
    PRIVMX_DEBUG_TIME_STOP(PlatformStore, _listStoresEx, data decrypted)
    return core::PagingList<Store>({
        .totalAvailable = storesList.count(),
        .readItems = stores
    });
}

File StoreApiImpl::getFile(const std::string& fileId) {
    PRIVMX_DEBUG_TIME_START(PlatformStore, storeFileGet)
    auto storeFileGetModel = utils::TypedObjectFactory::createNewObject<server::StoreFileGetModel>();
    storeFileGetModel.fileId(fileId);
    PRIVMX_DEBUG_TIME_CHECKPOINT(PlatformStore, storeFileGet)
    auto serverFileResult = _serverApi->storeFileGet(storeFileGetModel);
    PRIVMX_DEBUG_TIME_CHECKPOINT(PlatformStore, storeFileGet, data send)
    auto store = serverFileResult.store();
    assertStoreDataIntegrity(store);
    setNewModuleKeysInCache(
        store.id(), 
        storeToModuleKeys(store),
        store.version()
    );
    auto statusCode = validateFileDataIntegrity(serverFileResult.file(), store.resourceIdOpt(""));
    if(statusCode != 0) {
        PRIVMX_DEBUG_TIME_STOP(PlatformStore, getFile, data integrity validation failed)
        File result;
        result.statusCode = statusCode;
        return result;
    }
    auto ret {validateDecryptAndConvertFileDataToFileInfo(serverFileResult.file(), storeToModuleKeys(store))};
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
    PRIVMX_DEBUG_TIME_CHECKPOINT(PlatformStore, storeFileList, data send);
    auto store = serverFilesResult.store();
    assertStoreDataIntegrity(store);
    // Add Keys to cache
    setNewModuleKeysInCache(
        store.id(), 
        storeToModuleKeys(store),
        store.version()
    );
    auto files = validateDecryptAndConvertFilesDataToFilesInfo(serverFilesResult.files(), storeToModuleKeys(store));
    PRIVMX_DEBUG_TIME_STOP(PlatformStore, storeFileList, data decrypted)
    return core::PagingList<File>({
        .totalAvailable = serverFilesResult.count(),
        .readItems = files
    });
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
        _requestApi
    );
    handle->createRequestData();
    return handle->getId();
}

int64_t StoreApiImpl::updateFile(const std::string& fileId, const core::Buffer& publicMeta, const core::Buffer& privateMeta, const int64_t size) {
    auto storeFileGetModel = utils::TypedObjectFactory::createNewObject<server::StoreFileGetModel>();
    storeFileGetModel.fileId(fileId);
    auto result = _serverApi->storeFileGet(storeFileGetModel);
    std::shared_ptr<FileWriteHandle> handle = _fileHandleManager.createFileWriteHandle(
        result.store().id(),
        fileId,
        result.file().resourceIdOpt(""),
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
    core::KeyDecryptionAndVerificationRequest keyProviderRequest;
    core::EncKeyLocation location{.contextId=file_raw.store().contextId(), .resourceId=file_raw.store().resourceIdOpt(core::EndpointUtils::generateId())};
    keyProviderRequest.addOne(file_raw.store().keys(), file_raw.file().keyId(), location);
    auto key = _keyProvider->getKeysAndVerify(keyProviderRequest).at(location).at(file_raw.file().keyId());
    auto decryptionParams = getFileDecryptionParams(file_raw.file(), key);
    return createFileReadHandle(decryptionParams);
}

FileDecryptionParams StoreApiImpl::getFileDecryptionParams(server::File file, const core::DecryptedEncKey& encKey) {
    auto internalMeta = decryptFileInternalMeta(file, core::DecryptedEncKey(encKey));
    if ((uint64_t)internalMeta.chunkSize() > SIZE_MAX) {
        throw NumberToBigForCPUArchitectureException("chunkSize to big for this CPU architecture");
    }
    return FileDecryptionParams {
        .fileId = file.id(),
        .resourceId = file.resourceIdOpt(""),
        .sizeOnServer = (uint64_t)file.size(),
        .originalSize = (uint64_t)internalMeta.size(),
        .cipherType = internalMeta.cipherType(),
        .chunkSize = (size_t)internalMeta.chunkSize(),
        .key = privmx::utils::Base64::toString(internalMeta.key()),
        .hmac = privmx::utils::Base64::toString(internalMeta.hmac()),
        .version = file.version()
    };
}

int64_t StoreApiImpl::createFileReadHandle(const FileDecryptionParams& storeFileDecryptionParams) {
    if (storeFileDecryptionParams.cipherType != 1) {
        throw UnsupportedCipherTypeException(std::to_string(storeFileDecryptionParams.cipherType) + " expected type: 1");
    }
    std::shared_ptr<FileReadHandle> handle = _fileHandleManager.createFileReadHandle(
        storeFileDecryptionParams.fileId, 
        storeFileDecryptionParams.resourceId,
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
    try {
        privmx::endpoint::core::ModuleKeys storeKey;
        if (handle->getFileId().empty()) {
            storeKey = getModuleKeys(handle->getStoreId());
        } else {
            auto storeFileGetModel = utils::TypedObjectFactory::createNewObject<server::StoreFileGetModel>();
            storeFileGetModel.fileId(handle->getFileId());
            auto store = _serverApi->storeFileGet(storeFileGetModel).store();
            storeKey = core::ModuleKeys{
                .keys=store.keys(),
                .currentKeyId=store.keyId(),
                .moduleSchemaVersion=getStoreEntryDataStructureVersion(store.data().get(store.data().size()-1)),
                .moduleResourceId=store.resourceIdOpt(""),
                .contextId=store.contextId()
            };
            setNewModuleKeysInCache(
                store.id(), 
                storeKey,
                store.version()
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

    auto internalFileMeta = utils::TypedObjectFactory::createNewObject<dynamic::InternalStoreFileMeta>();
    internalFileMeta.version(4);
    internalFileMeta.size(handle->getSize());
    internalFileMeta.cipherType(data.cipherType);
    internalFileMeta.chunkSize(data.chunkSize);
    internalFileMeta.key(utils::Base64::from(data.key));
    internalFileMeta.hmac(utils::Base64::from(data.hmac));
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
                .internalMeta = core::Buffer::from(utils::Utils::stringifyVar(internalFileMeta.asVar()))
            };
            encryptedMetaVar = _fileMetaEncryptorV4.encrypt(fileMeta, _userPrivKey, key.key).asVar();
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
                .internalMeta = core::Buffer::from(utils::Utils::stringifyVar(internalFileMeta.asVar())),
                .dio = fileDIO
            };
            encryptedMetaVar = _fileMetaEncryptorV5.encrypt(fileMeta, _userPrivKey, key.key).asVar();
            break;
        }
    }
    if (handle->getFileId().empty()) {
        // create file
        auto storeFileCreateModel = utils::TypedObjectFactory::createNewObject<server::StoreFileCreateModel>();
        storeFileCreateModel.fileIndex(0);
        storeFileCreateModel.resourceId(handle->getResourceId());
        storeFileCreateModel.storeId(handle->getStoreId());
        storeFileCreateModel.meta(encryptedMetaVar);
        storeFileCreateModel.keyId(key.id);
        storeFileCreateModel.requestId(data.requestId);
        return _serverApi->storeFileCreate(storeFileCreateModel).fileId();
    } else {
        // update file
        auto storeFileWriteModel = utils::TypedObjectFactory::createNewObject<server::StoreFileWriteModel>();
        storeFileWriteModel.fileIndex(0);
        storeFileWriteModel.fileId(handle->getFileId());
        storeFileWriteModel.meta(encryptedMetaVar);
        storeFileWriteModel.keyId(key.id);
        storeFileWriteModel.requestId(data.requestId);
        _serverApi->storeFileWrite(storeFileWriteModel);
        return handle->getFileId();
    }
}


void StoreApiImpl::processNotificationEvent(const std::string& type, const core::NotificationEvent& notification) {
    if(notification.source == core::EventSource::INTERNAL) {
        _storeSubscriptionHelper.processSubscriptionNotificationEvent(type,notification);
        return;
    }
    if(!_storeSubscriptionHelper.hasSubscription(notification.subscriptions)) {
        return;
    }
    if (type == "storeCreated") {
        auto raw = utils::TypedObjectFactory::createObjectFromVar<server::Store>(notification.data);
        if(raw.typeOpt(std::string(STORE_TYPE_FILTER_FLAG)) == STORE_TYPE_FILTER_FLAG) {
            // Add Keys to cache
            setNewModuleKeysInCache(
                raw.id(), 
                core::ModuleKeys{
                    .keys=raw.keys(),
                    .currentKeyId=raw.keyId(),
                    .moduleSchemaVersion=getStoreEntryDataStructureVersion(raw.data().get(raw.data().size()-1)),
                    .moduleResourceId=raw.resourceIdOpt(""),
                    .contextId=raw.contextId()
                },
                raw.version()
            );
            auto data = validateDecryptAndConvertStoreDataToStore(raw);
            std::shared_ptr<StoreCreatedEvent> event(new StoreCreatedEvent());
            event->channel = "store";
            event->data = data;
            _eventMiddleware->emitApiEvent(event);
        }
    } else if (type == "storeUpdated") {
        auto raw = utils::TypedObjectFactory::createObjectFromVar<server::Store>(notification.data);
        if(raw.typeOpt(std::string(STORE_TYPE_FILTER_FLAG)) == STORE_TYPE_FILTER_FLAG) {
            // Add Keys to cache
            setNewModuleKeysInCache(
                raw.id(), 
                core::ModuleKeys{
                    .keys=raw.keys(),
                    .currentKeyId=raw.keyId(),
                    .moduleSchemaVersion=getStoreEntryDataStructureVersion(raw.data().get(raw.data().size()-1)),
                    .moduleResourceId=raw.resourceIdOpt(""),
                    .contextId=raw.contextId()
                },
                raw.version()
            );
            auto data = validateDecryptAndConvertStoreDataToStore(raw);
            std::shared_ptr<StoreUpdatedEvent> event(new StoreUpdatedEvent());
            event->channel = "store";
            event->data = data;
            _eventMiddleware->emitApiEvent(event);
        }
    } else if (type == "storeDeleted") {
        auto raw = utils::TypedObjectFactory::createObjectFromVar<server::StoreDeletedEventData>(notification.data);
        if(raw.typeOpt(std::string(STORE_TYPE_FILTER_FLAG)) == STORE_TYPE_FILTER_FLAG) {
            invalidateModuleKeysInCache(raw.storeId());
            auto data = Mapper::mapToStoreDeletedEventData(raw);
            std::shared_ptr<StoreDeletedEvent> event(new StoreDeletedEvent());
            event->channel = "store";
            event->data = data;
            _eventMiddleware->emitApiEvent(event);
        }
    } else if (type == "storeStatsChanged") {
        auto raw = utils::TypedObjectFactory::createObjectFromVar<server::StoreStatsChangedEventData>(notification.data);
        if(raw.typeOpt(std::string(STORE_TYPE_FILTER_FLAG)) == STORE_TYPE_FILTER_FLAG) {
            auto data = Mapper::mapToStoreStatsChangedEventData(raw);
            std::shared_ptr<StoreStatsChangedEvent> event(new StoreStatsChangedEvent());
            event->channel = "store";
            event->data = data;
            _eventMiddleware->emitApiEvent(event);
        }
    
    } else if (type == "storeFileCreated") {
        auto raw = utils::TypedObjectFactory::createObjectFromVar<server::File>(notification.data);
        auto file = validateDecryptAndConvertFileDataToFileInfo(raw, getFileDecryptionKeys(raw));
        // auto data = _dataResolver->decrypt(std::vector<server::File>{raw})[0];
        std::shared_ptr<StoreFileCreatedEvent> event(new StoreFileCreatedEvent());
        event->channel = "store/" + raw.storeId() + "/files";
        event->data = file;
        _eventMiddleware->emitApiEvent(event);
    } else if (type == "storeFileUpdated") {
        auto raw = utils::TypedObjectFactory::createObjectFromVar<server::File>(notification.data);
        auto file = validateDecryptAndConvertFileDataToFileInfo(raw, getFileDecryptionKeys(raw));
        std::shared_ptr<StoreFileUpdatedEvent> event(new StoreFileUpdatedEvent());
        event->channel = "store/" + raw.storeId() + "/files";
        event->data = file;
        _eventMiddleware->emitApiEvent(event);
    } else if (type == "storeFileDeleted") {
        auto raw = utils::TypedObjectFactory::createObjectFromVar<server::StoreFileDeletedEventData>(notification.data);
        auto data = Mapper::mapToStoreFileDeletedEventData(raw);
        std::shared_ptr<StoreFileDeletedEvent> event(new StoreFileDeletedEvent());
        event->channel = "store/" + raw.storeId() + "/files";
        event->data = data;
        _eventMiddleware->emitApiEvent(event);
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
    assertStoreExist(storeId);
    if(_storeSubscriptionHelper.hasSubscriptionForModuleEntry(storeId)) {
        throw AlreadySubscribedException(storeId);
    }
    _storeSubscriptionHelper.subscribeForModuleEntry(storeId);
}

void StoreApiImpl::unsubscribeFromFileEvents(const std::string& storeId) {
    assertStoreExist(storeId);
    if(!_storeSubscriptionHelper.hasSubscriptionForModuleEntry(storeId)) {
        throw NotSubscribedException(storeId);
    }
    _storeSubscriptionHelper.unsubscribeFromModuleEntry(storeId);
}

void StoreApiImpl::processConnectedEvent() {
    invalidateModuleKeysInCache();
}

void StoreApiImpl::processDisconnectedEvent() {
    invalidateModuleKeysInCache();
}

dynamic::compat_v1::StoreData StoreApiImpl::decryptStoreV1(server::StoreDataEntry storeEntry, const core::DecryptedEncKey& encKey) {
    try {
        return _dataEncryptorCompatV1.decrypt(storeEntry.data(), encKey);
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

Store StoreApiImpl::convertServerStoreToLibStore(
    server::Store store,
    const core::Buffer& publicMeta,
    const core::Buffer& privateMeta,
    const int64_t& statusCode,
    const int64_t& schemaVersion
) {
    std::vector<std::string> users;
    std::vector<std::string> managers;
    if(!store.usersEmpty()) {
        for (auto x : store.users()) {
            users.push_back(x);
        }
    }
    if(!store.managersEmpty()) {
        for (auto x : store.managers()) {
            managers.push_back(x);
        }
    }
    return Store{
        .storeId = store.idOpt(std::string()),
        .contextId = store.contextIdOpt(std::string()),
        .createDate = store.createDateOpt(0),
        .creator = store.creatorOpt(std::string()),
        .lastModificationDate = store.lastModificationDateOpt(0),
        .lastFileDate = store.lastFileDateOpt(0),
        .lastModifier = store.lastModifierOpt(std::string()),
        .users = users,
        .managers = managers,
        .version = store.versionOpt(0),
        .publicMeta = publicMeta,
        .privateMeta = privateMeta,
        .policy = core::Factory::parsePolicyServerObject(store.policyOpt(Poco::JSON::Object::Ptr(new Poco::JSON::Object))),
        .filesCount = store.filesOpt(0),
        .statusCode = statusCode,
        .schemaVersion = schemaVersion
    };
}

Store StoreApiImpl::convertStoreDataV1ToStore(server::Store store, dynamic::compat_v1::StoreData storeData) {
    Poco::JSON::Object::Ptr privateMeta = Poco::JSON::Object::Ptr(new Poco::JSON::Object());
    privateMeta->set("title", storeData.name());
    return convertServerStoreToLibStore(
        store, 
        core::Buffer::from(""),
        core::Buffer::from(utils::Utils::stringify(privateMeta)),
        storeData.statusCodeOpt(0),
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
    if(storeEntry.data().type() == typeid(Poco::JSON::Object::Ptr)) {
        auto versioned = utils::TypedObjectFactory::createObjectFromVar<core::dynamic::VersionedData>(storeEntry.data());
        auto version = versioned.versionOpt(core::ModuleDataSchema::Version::UNKNOWN);
        switch (version) {
            case core::ModuleDataSchema::Version::VERSION_4:
                return StoreDataSchema::Version::VERSION_4;
            case core::ModuleDataSchema::Version::VERSION_5:
                return StoreDataSchema::Version::VERSION_5;
            default:
                return StoreDataSchema::Version::UNKNOWN;
        }
    } else if (storeEntry.data().isString()) {
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
                    .creatorUserId = store.lastModifier(),
                    .creatorPubKey = "",
                    .contextId = store.contextId(),
                    .resourceId = store.resourceIdOpt(""),
                    .timestamp = store.lastModificationDate(),
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
                    .creatorUserId = store.lastModifier(),
                    .creatorPubKey = decryptedStoreData.authorPubKey,
                    .contextId = store.contextId(),
                    .resourceId = store.resourceIdOpt(""),
                    .timestamp = store.lastModificationDate(),
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

std::vector<Store> StoreApiImpl::validateDecryptAndConvertStoresDataToStores(utils::List<server::Store> stores) {
    // Create Result Array
    std::vector<Store> result(stores.size());
    // Validate data Integrity
    for (size_t i = 0; i < stores.size(); i++) {
        auto store = stores.get(i);
        result[i].statusCode = validateStoreDataIntegrity(store);
        if(result[i].statusCode != 0) {
            result[i] = convertServerStoreToLibStore(store, {}, {}, result[i].statusCode);
        }
    }
    core::KeyDecryptionAndVerificationRequest keyProviderRequest;
    // Create request to KeyProvider for keys
    for (size_t i = 0; i < stores.size(); i++) {
        auto store = stores.get(i);
        core::EncKeyLocation location{.contextId=store.contextId(), .resourceId=store.resourceIdOpt("")};
        auto store_data_entry = store.data().get(store.data().size()-1);
        keyProviderRequest.addOne(store.keys(), store_data_entry.keyId(), location);
    }
    // Send request to KeyProvider
    auto storesKeys {_keyProvider->getKeysAndVerify(keyProviderRequest)};
    std::vector<core::DataIntegrityObject> storesDIO(stores.size());
    std::map<std::string, bool> duplication_check;
    for (size_t i = 0; i < stores.size(); i++) {
        if(result[i].statusCode != 0) {
            storesDIO.push_back(core::DataIntegrityObject{});
        } else {
            auto store = stores.get(i);
            try {
                auto tmp = decryptAndConvertStoreDataToStore(
                    store, 
                    store.data().get(store.data().size()-1), 
                    storesKeys.at(core::EncKeyLocation{.contextId=store.contextId(), .resourceId=store.resourceIdOpt("")}).at(store.data().get(store.data().size()-1).keyId())
                );
                result[i] = std::get<0>(tmp);
                auto storeDIO = std::get<1>(tmp);
                storesDIO[i] = storeDIO;
                //find duplication
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
        // Validate data Integrity
        auto statusCode = validateStoreDataIntegrity(store);
        if(statusCode != 0) {
            return convertServerStoreToLibStore(store, {}, {}, statusCode);
        }
        // Get current StoreEntry and Key
        auto store_data_entry = store.data().get(store.data().size()-1);
        // Create request to KeyProvider for keys
        core::KeyDecryptionAndVerificationRequest keyProviderRequest;
        core::EncKeyLocation location{.contextId=store.contextId(), .resourceId=store.resourceIdOpt("")};
        keyProviderRequest.addOne(store.keys(), store_data_entry.keyId(), location);
        //Send request to KeyProvider
        auto key = _keyProvider->getKeysAndVerify(keyProviderRequest).at(location).at(store_data_entry.keyId());
        Store result;
        core::DataIntegrityObject storeDIO;
        // Decrypt
        std::tie(result, storeDIO) = decryptAndConvertStoreDataToStore(store, store_data_entry, key);
        // Validate with UserVerifier
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

// OLD CODE
StoreFile StoreApiImpl::decryptStoreFileV1(server::File file, const core::DecryptedEncKey& encKey) {
    try {
        auto storeFile = decryptAndVerifyFileV1(encKey.key, file);
        return storeFile;
    } catch (const privmx::endpoint::core::Exception& e) {
        StoreFile result = {.raw=file, .meta=privmx::utils::TypedObjectFactory::createNewObject<dynamic::compat_v1::StoreFileMeta>(), .verified="invalid"};
        result.meta.statusCode(e.getCode());
        return result;
    } catch (const privmx::utils::PrivmxException& e) {
        StoreFile result = {.raw=file, .meta=privmx::utils::TypedObjectFactory::createNewObject<dynamic::compat_v1::StoreFileMeta>(), .verified="invalid"};
        result.meta.statusCode(core::ExceptionConverter::convert(e).getCode());
        return result;
    } catch (...) {
        StoreFile result = {.raw=file, .meta=privmx::utils::TypedObjectFactory::createNewObject<dynamic::compat_v1::StoreFileMeta>(), .verified="invalid"};
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

DecryptedFileMetaV4 StoreApiImpl::decryptFileMetaV4(server::File file, const core::DecryptedEncKey& encKey) {
    try {
        auto encryptedFileMeta = utils::TypedObjectFactory::createObjectFromVar<server::EncryptedFileMetaV4>(file.meta());
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
        auto encryptedFileMeta = utils::TypedObjectFactory::createObjectFromVar<server::EncryptedFileMetaV5>(file.meta());
        if(encKey.statusCode != 0) {
            auto tmp =  _fileMetaEncryptorV5.extractPublic(encryptedFileMeta);
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
    const int64_t& schemaVersion
) {
    return File{
        .info = {
            .storeId = file.storeIdOpt(std::string()),
            .fileId = file.idOpt(std::string()),
            .createDate = file.createdOpt(0),
            .author = file.creatorOpt(std::string()),
        },
        .publicMeta = publicMeta,
        .privateMeta = privateMeta,
        .size = size,
        .authorPubKey = authorPubKey,
        .statusCode = statusCode,
        .schemaVersion = schemaVersion
    };
}

File StoreApiImpl::convertStoreFileMetaV1ToFile(server::File file, dynamic::compat_v1::StoreFileMeta storeFileMeta) {
    return convertServerFileToLibFile(
        file,
        core::Buffer(),
        core::Buffer::from(utils::Utils::stringifyVar(storeFileMeta)),
        storeFileMeta.sizeOpt(0),
        storeFileMeta.authorEmpty() ? "" : storeFileMeta.author().pubKeyOpt(""),
        storeFileMeta.statusCodeOpt(0),
        FileDataSchema::Version::VERSION_1
    );
}

File StoreApiImpl::convertDecryptedFileMetaV4ToFile(server::File file, const DecryptedFileMetaV4& fileData) {
    return convertServerFileToLibFile(
        file,
        fileData.publicMeta,
        fileData.privateMeta,
        fileData.fileSize,
        fileData.authorPubKey,
        fileData.statusCode,
        FileDataSchema::Version::VERSION_4
    );
}

File StoreApiImpl::convertDecryptedFileMetaV5ToFile(server::File file, const DecryptedFileMetaV5& fileData) {
    int64_t size = 0;
    auto statusCode = fileData.statusCode;
    if(statusCode == 0) {
        try {
            auto internalMeta = utils::TypedObjectFactory::createObjectFromVar<dynamic::InternalStoreFileMeta>(utils::Utils::parseJson(fileData.internalMeta.stdString()));
            size = internalMeta.size();
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
        FileDataSchema::Version::VERSION_5
    );
}

FileDataSchema::Version StoreApiImpl::getFileDataStructureVersion(server::File file) {
    if (file.meta().type() == typeid(Poco::JSON::Object::Ptr)) {
        auto versioned = utils::TypedObjectFactory::createObjectFromVar<core::dynamic::VersionedData>(file.meta());
        auto version = versioned.versionOpt(FileDataSchema::Version::UNKNOWN);
        switch (version) {
            case FileDataSchema::Version::VERSION_4:
                return FileDataSchema::Version::VERSION_4;
            case FileDataSchema::Version::VERSION_5:
                return FileDataSchema::Version::VERSION_5;
            default:
                return FileDataSchema::Version::UNKNOWN;
        }
    } else if (file.meta().isString()) {
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
                    .creatorUserId = file.lastModifier(),
                    .creatorPubKey = decryptedFile.authorEmpty() ? "" : decryptedFile.author().pubKeyOpt(""),
                    .contextId = file.contextId(),
                    .resourceId = file.resourceIdOpt(""),
                    .timestamp = file.lastModificationDate(),
                    .randomId = std::string(),
                    .containerId = file.storeId(),
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
                    .creatorUserId = file.lastModifier(),
                    .creatorPubKey = decryptedFile.authorPubKey,
                    .contextId = file.contextId(),
                    .resourceId = file.resourceIdOpt(""),
                    .timestamp = file.lastModificationDate(),
                    .randomId = std::string(),
                    .containerId = file.storeId(),
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

std::vector<File> StoreApiImpl::validateDecryptAndConvertFilesDataToFilesInfo(utils::List<server::File> files, const core::ModuleKeys& storeKeys) {
    std::set<std::string> keyIds;
    for (auto file : files) {
        keyIds.insert(file.keyId());
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
                auto tmp = decryptAndConvertFileDataToFileInfo(file,  keyMap.at(file.keyId()));
                result.push_back(std::get<0>(tmp));
                auto fileDIO = std::get<1>(tmp);
                filesDIO.push_back(fileDIO);
                //find duplication
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
        auto keyId = file.keyId();
        _fileKeyIdFormatValidator.assertKeyIdFormat(keyId);
        // Create request to KeyProvider for keys
        core::KeyDecryptionAndVerificationRequest keyProviderRequest;
        core::EncKeyLocation location{.contextId=file.contextId(), .resourceId=storeKeys.moduleResourceId};
        keyProviderRequest.addOne(storeKeys.keys, keyId, location);
        // Send request to KeyProvider
        auto encKey = _keyProvider->getKeysAndVerify(keyProviderRequest).at(location).at(keyId);
        // decrypt file
        File result;
        core::DataIntegrityObject fileDIO;
        std::tie(result, fileDIO) = decryptAndConvertFileDataToFileInfo(file, encKey);
        if(result.statusCode != 0) return result;
        // Validate with UserVerifier
        std::vector<core::VerificationRequest> verifierInput {};
            verifierInput.push_back(core::VerificationRequest{
                .contextId = file.contextId(),
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
                auto internalFileMeta = utils::TypedObjectFactory::createNewObject<dynamic::InternalStoreFileMeta>();
                internalFileMeta.version(1);
                internalFileMeta.size(decryptedFile.meta.size());
                internalFileMeta.cipherType(decryptedFile.meta.cipherType());
                internalFileMeta.chunkSize(decryptedFile.meta.chunkSize());
                internalFileMeta.key(utils::Base64::from(decryptedFile.meta.key()));
                internalFileMeta.hmac(utils::Base64::from(decryptedFile.meta.hmac()));
                return internalFileMeta;
            }
            case FileDataSchema::Version::VERSION_4:
                return utils::TypedObjectFactory::createObjectFromVar<dynamic::InternalStoreFileMeta>(
                    utils::Utils::parseJson(decryptFileMetaV4(file, encKey).internalMeta.stdString())
                );
            case FileDataSchema::Version::VERSION_5:
                return utils::TypedObjectFactory::createObjectFromVar<dynamic::InternalStoreFileMeta>(
                    utils::Utils::parseJson(decryptFileMetaV5(file, encKey).internalMeta.stdString())
                );
        }
    }
    throw UnknowFileFormatException();
}

dynamic::InternalStoreFileMeta StoreApiImpl::validateDecryptFileInternalMeta(server::File file, const core::ModuleKeys& storeKeys) {
    auto keyId = file.keyId();
    // Create request to KeyProvider for keys
    core::KeyDecryptionAndVerificationRequest keyProviderRequest;
    core::EncKeyLocation location{.contextId=file.contextId(), .resourceId=storeKeys.moduleResourceId};
    keyProviderRequest.addOne(storeKeys.keys, keyId, location);
    // Send request to KeyProvider
    auto encKey = _keyProvider->getKeysAndVerify(keyProviderRequest).at(location).at(keyId);
    _fileKeyIdFormatValidator.assertKeyIdFormat(keyId);
    return decryptFileInternalMeta(file, encKey);
}


core::ModuleKeys StoreApiImpl::getFileDecryptionKeys(server::File file) {
    auto keyId = file.keyId();
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
    return getModuleKeys(file.storeId(), std::set<std::string>{keyId}, minimumStoreSchemaVersion);
}

void StoreApiImpl::updateFileMeta(const std::string& fileId, const core::Buffer& publicMeta, const core::Buffer& privateMeta) {
    auto storeFileGetModel = utils::TypedObjectFactory::createNewObject<server::StoreFileGetModel>();
    storeFileGetModel.fileId(fileId);

    auto storeFileGetResult = _serverApi->storeFileGet(storeFileGetModel);
    server::Store store = storeFileGetResult.store();
    setNewModuleKeysInCache(
        store.id(), 
        storeToModuleKeys(store),
        store.version()
    );
    server::File file = storeFileGetResult.file();
    auto statusCode = validateFileDataIntegrity(file, store.resourceIdOpt(""));
    if(statusCode != 0) {
        throw FileDataIntegrityException();
    }
    auto key = getAndValidateModuleCurrentEncKey(store);
    Poco::Dynamic::Var encryptedMetaVar;
    auto fileInternalMeta = validateDecryptFileInternalMeta(file, storeToModuleKeys(store));
    auto internalMeta = core::Buffer::from(utils::Utils::stringifyVar(fileInternalMeta));
    switch (getStoreEntryDataStructureVersion(store.data().get(store.data().size()-1))) {
        case StoreDataSchema::Version::UNKNOWN:
            throw UnknowStoreFormatException();
        case StoreDataSchema::Version::VERSION_1:
        case StoreDataSchema::Version::VERSION_4: {
            store::FileMetaToEncryptV4 fileMeta {
                .publicMeta = publicMeta,
                .privateMeta = privateMeta,
                .fileSize = fileInternalMeta.size(),
                .internalMeta = internalMeta
            };
            encryptedMetaVar = _fileMetaEncryptorV4.encrypt(fileMeta, _userPrivKey, key.key).asVar();
            break;
        }
        case StoreDataSchema::Version::VERSION_5: {
            privmx::endpoint::core::DataIntegrityObject fileDIO = _connection.getImpl()->createDIO(
                file.contextId(),
                file.resourceIdOpt(core::EndpointUtils::generateId()),
                file.storeId(),
                store.resourceIdOpt("")
            );
            store::FileMetaToEncryptV5 fileMeta {
                .publicMeta = publicMeta,
                .privateMeta = privateMeta,
                .internalMeta = internalMeta,
                .dio = fileDIO
            };
            encryptedMetaVar = _fileMetaEncryptorV5.encrypt(fileMeta, _userPrivKey, key.key).asVar();
            break;
        }
    }
    // get Internal Meta
    auto storeFileUpdateModel = utils::TypedObjectFactory::createNewObject<server::StoreFileUpdateModel>();
    storeFileUpdateModel.fileId(fileId);
    storeFileUpdateModel.meta(encryptedMetaVar);
    storeFileUpdateModel.keyId(key.id);
    _serverApi->storeFileUpdate(storeFileUpdateModel);
}

void StoreApiImpl::assertStoreExist(const std::string& storeId) {
    auto params = privmx::utils::TypedObjectFactory::createNewObject<store::server::StoreGetModel>();
    params.storeId(storeId);
    _serverApi->storeGet(params);
}

void StoreApiImpl::assertFileExist(const std::string& fileId) {
    auto storeFileGetModel = utils::TypedObjectFactory::createNewObject<server::StoreFileGetModel>();
    storeFileGetModel.fileId(fileId);
    auto file = _serverApi->storeFileGet(storeFileGetModel).file();
}

std::pair<core::ModuleKeys, int64_t> StoreApiImpl::getModuleKeysAndVersionFromServer(std::string moduleId) {
    auto params = privmx::utils::TypedObjectFactory::createNewObject<store::server::StoreGetModel>();
    params.storeId(moduleId);
    auto store = _serverApi->storeGet(params).store();
    // validate store Data before returning data
    assertStoreDataIntegrity(store);
    return std::make_pair(storeToModuleKeys(store), store.version());
}

core::ModuleKeys StoreApiImpl::storeToModuleKeys(server::Store store) {
    return core::ModuleKeys{
        .keys=store.keys(),
        .currentKeyId=store.keyId(),
        .moduleSchemaVersion=getStoreEntryDataStructureVersion(store.data().get(store.data().size()-1)),
        .moduleResourceId=store.resourceIdOpt(""),
        .contextId = store.contextId()
    };
}

void StoreApiImpl::assertStoreDataIntegrity(server::Store store) {
    auto store_data_entry = store.data().get(store.data().size()-1);
    switch (getStoreEntryDataStructureVersion(store_data_entry)) {
        case StoreDataSchema::Version::UNKNOWN:
            throw UnknowStoreFormatException();
        case StoreDataSchema::Version::VERSION_1:
            return;
        case StoreDataSchema::Version::VERSION_4:
            return;
        case StoreDataSchema::Version::VERSION_5: {
            auto store_data = utils::TypedObjectFactory::createObjectFromVar<core::dynamic::EncryptedModuleDataV5>(store_data_entry.data());
            auto dio = _storeDataEncryptorV5.getDIOAndAssertIntegrity(store_data);
            if(
                dio.contextId != store.contextId() ||
                dio.resourceId != store.resourceIdOpt("") ||
                dio.creatorUserId != store.lastModifier() ||
                !core::TimestampValidator::validate(dio.timestamp, store.lastModificationDate())
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
        return e.getCode();
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
                auto fileMeta = utils::TypedObjectFactory::createObjectFromVar<server::EncryptedFileMetaV5>(file.meta());
                auto dio = _fileMetaEncryptorV5.getDIOAndAssertIntegrity(fileMeta);
                if( 
                    dio.contextId != file.contextId() ||
                    dio.resourceId != file.resourceIdOpt("") ||
                    !dio.containerId.has_value() || dio.containerId.value() != file.storeId() ||
                    !dio.containerResourceId.has_value() || dio.containerResourceId.value() != storeResourceId ||
                    dio.creatorUserId != file.lastModifier() ||
                    !core::TimestampValidator::validate(dio.timestamp, file.lastModificationDate())
                ) {
                    return FileDataIntegrityException().getCode();;
                }
                return 0;
            }
        }
    } catch (const core::Exception& e) {
        return e.getCode();
    } catch (const privmx::utils::PrivmxException& e) {
        return e.getCode();
    } catch (...) {
        return ENDPOINT_CORE_EXCEPTION_CODE;
    } 
    return UnknowFileFormatException().getCode();
}