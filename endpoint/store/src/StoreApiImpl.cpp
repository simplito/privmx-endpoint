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
    _storeProvider(StoreProvider(
        [&](const std::string& id) {
            auto model = privmx::utils::TypedObjectFactory::createNewObject<server::StoreGetModel>();
            model.storeId(id);
            model.type(STORE_TYPE_FILTER_FLAG);
            auto serverStore = _serverApi->storeGet(model).store();
            return serverStore;
        },
        std::bind(&StoreApiImpl::validateStoreDataIntegrity, this, std::placeholders::_1)
    )),
    _subscribeForStore(false),
    _storeSubscriptionHelper(core::SubscriptionHelper(eventChannelManager, "store", "files")),
    _fileMetaEncryptorV4(FileMetaEncryptorV4()),
    _storeDataEncryptorV4(StoreDataEncryptorV4()),
    _forbiddenChannelsNames({INTERNAL_EVENT_CHANNEL_NAME, "store", "files"}) 
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
    std::string resourceId = core::EndpointUtils::generateId();
    auto storeDIO = _connection.getImpl()->createDIO(
        contextId,
        resourceId
    );
    auto storeSecret = _keyProvider->generateSecret();
    StoreDataToEncryptV5 storeDataToEncrypt {
        .publicMeta = publicMeta,
        .privateMeta = privateMeta,
        .internalMeta = StoreInternalMetaV5{.secret=storeSecret, .resourceId=resourceId, .randomId=storeDIO.randomId},
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
    auto currentStoreResourceId = currentStore.resourceIdOpt(core::EndpointUtils::generateId());

    // extract current users info
    auto usersVec {core::EndpointUtils::listToVector<std::string>(currentStore.users())};
    auto managersVec {core::EndpointUtils::listToVector<std::string>(currentStore.managers())};
    auto oldUsersAll {core::EndpointUtils::uniqueList(usersVec, managersVec)};

    auto new_users = core::EndpointUtils::uniqueListUserWithPubKey(users, managers);

    // adjust key
    std::vector<std::string> deletedUsers {core::EndpointUtils::getDifference(oldUsersAll, usersWithPubKeyToIds(new_users))};
    std::vector<std::string> addedUsers {core::EndpointUtils::getDifference(usersWithPubKeyToIds(new_users), oldUsersAll)};
    std::vector<core::UserWithPubKey> usersToAddMissingKey;
    for(auto new_user: new_users) {
        if( std::find(addedUsers.begin(), addedUsers.end(), new_user.userId) != addedUsers.end()) {
            usersToAddMissingKey.push_back(new_user);
        }
    }
    bool needNewKey = deletedUsers.size() > 0 || forceGenerateNewKey;
    
    // read all key to check if all key belongs to this store
    core::KeyDecryptionAndVerificationRequest keyProviderRequest;
    core::EncKeyLocation location{.contextId=currentStore.contextId(), .resourceId=currentStoreResourceId};
    keyProviderRequest.addAll(currentStore.keys(), location);
    auto storeKeys {_keyProvider->getKeysAndVerify(keyProviderRequest).at(location)};
    auto currentStoreEntry = currentStore.data().get(currentStore.data().size()-1);
    core::DecryptedEncKey currentStoreKey;
    for (auto key : storeKeys) {
        if (currentStoreEntry.keyId() == key.first) {
            currentStoreKey = key.second;
            break;
        }
    }
    auto storeInternalMeta = decryptStoreInternalMeta(currentStoreEntry, currentStoreKey);
    if(currentStoreKey.dataStructureVersion != 2) {
        //force update all keys if thread keys is in older version
        usersToAddMissingKey = new_users;
    }
    if(!_keyProvider->verifyKeysSecret(storeKeys, location, storeInternalMeta.secret)) {
        throw StoreEncryptionKeyValidationException();
    }
    // setting store Key adding new users
    core::EncKey storeKey = currentStoreKey;
    core::DataIntegrityObject updateStoreDio = _connection.getImpl()->createDIO(currentStore.contextId(), currentStoreResourceId);
    privmx::utils::List<core::server::KeyEntrySet> keys = utils::TypedObjectFactory::createNewList<core::server::KeyEntrySet>();
    if(needNewKey) {
        storeKey = _keyProvider->generateKey();
        keys = _keyProvider->prepareKeysList(
            new_users, 
            storeKey, 
            updateStoreDio,
            location,
            storeInternalMeta.secret
        );
    }
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
    StoreDataToEncryptV5 storeDataToEncrypt {
        .publicMeta = publicMeta,
        .privateMeta = privateMeta,
        .internalMeta = StoreInternalMetaV5{.secret=storeInternalMeta.secret, .resourceId=currentStoreResourceId, .randomId=updateStoreDio.randomId},
        .dio = updateStoreDio
    };
    model.data(_storeDataEncryptorV5.encrypt(storeDataToEncrypt, _userPrivKey, storeKey.key).asVar());

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
    auto statusCode = validateStoreDataIntegrity(store);
    if(statusCode != 0) {
        if(type == STORE_TYPE_FILTER_FLAG) {
            _storeProvider.updateByValueAndStatus(StoreProvider::ContainerInfo{.container=store, .status=core::DataIntegrityStatus::ValidationFailed});
        }
        return Store{{},{},{},{},{},{},{},{},{},{},{},{},{},{}, .statusCode = statusCode, {}};
    } else {
        if(type == STORE_TYPE_FILTER_FLAG) {
            _storeProvider.updateByValueAndStatus(StoreProvider::ContainerInfo{.container=store, .status=core::DataIntegrityStatus::ValidationSucceed});
        }
    }
    auto result = decryptAndConvertStoreDataToStore(store);
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
    std::vector<Store> stores;
    for (size_t i = 0; i < storesList.stores().size(); i++) {
        auto store = storesList.stores().get(i);
        if(type == STORE_TYPE_FILTER_FLAG) _storeProvider.updateByValue(store);
        auto statusCode = validateStoreDataIntegrity(store);
        stores.push_back(Store{ {},{},{},{},{},{},{},{},{},{},{},{},{},{}, .statusCode = statusCode, {}});
        if(statusCode == 0) {
            if(type == STORE_TYPE_FILTER_FLAG) {
                _storeProvider.updateByValueAndStatus(StoreProvider::ContainerInfo{.container=store, .status=core::DataIntegrityStatus::ValidationSucceed});
            }
        } else {
            if(type == STORE_TYPE_FILTER_FLAG) {
                _storeProvider.updateByValueAndStatus(StoreProvider::ContainerInfo{.container=store, .status=core::DataIntegrityStatus::ValidationFailed});
            }
            storesList.stores().remove(i);
            i--;
        }
    }
    auto tmp = decryptAndConvertStoresDataToStores(storesList.stores());
    for(size_t j = 0, i = 0; i < stores.size(); i++) {
        if(stores[i].statusCode == 0) {
            stores[i] = tmp[j];
            j++;
        }
    }
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
    if(serverFileResult.store().type() == STORE_TYPE_FILTER_FLAG) _storeProvider.updateByValue(serverFileResult.store());
    if(validateStoreDataIntegrity(serverFileResult.store()) != 0) throw StoreDataIntegrityException();
    auto statusCode = validateFileDataIntegrity(serverFileResult.file(), serverFileResult.store().resourceIdOpt(""));
    if(statusCode != 0) {
        PRIVMX_DEBUG_TIME_STOP(PlatformStore, getFile, data integrity validation failed)
        File result;
        result.statusCode = statusCode;
        return result;
    }
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
    PRIVMX_DEBUG_TIME_CHECKPOINT(PlatformStore, storeFileList, data send);
    auto store = serverFilesResult.store();
    if(serverFilesResult.store().type() == STORE_TYPE_FILTER_FLAG) _storeProvider.updateByValue(store);
    if(validateStoreDataIntegrity(store) != 0) throw StoreDataIntegrityException();
    auto files = decryptAndConvertFilesDataToFilesInfo(store, serverFilesResult.files());
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
    auto file = _serverApi->storeFileGet(storeFileGetModel).file();
    std::shared_ptr<FileWriteHandle> handle = _fileHandleManager.createFileWriteHandle(
        std::string(),
        fileId,
        file.resourceIdOpt(""),
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
    auto serverId = _host;
    
    server::Store store;
    if (handle->getFileId().empty()) {
        store = getRawStoreFromCacheOrBridge(handle->getStoreId());
    } else {
        auto storeFileGetModel = utils::TypedObjectFactory::createNewObject<server::StoreFileGetModel>();
        storeFileGetModel.fileId(handle->getFileId());
        store = _serverApi->storeFileGet(storeFileGetModel).store();
    }
    auto key = getStoreCurrentEncKey(store);

    auto internalFileMeta = utils::TypedObjectFactory::createNewObject<dynamic::InternalStoreFileMeta>();
    internalFileMeta.version(4);
    internalFileMeta.size(handle->getSize());
    internalFileMeta.cipherType(data.cipherType);
    internalFileMeta.chunkSize(data.chunkSize);
    internalFileMeta.key(utils::Base64::from(data.key));
    internalFileMeta.hmac(utils::Base64::from(data.hmac));
    auto fileId = core::EndpointUtils::generateId();
    Poco::Dynamic::Var encryptedMetaVar;
    switch (getStoreEntryDataStructureVersion(store.data().get(store.data().size()-1))) {
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
                store.contextId(),
                handle->getResourceId(),
                handle->getStoreId(),
                store.resourceIdOpt("")
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

void StoreApiImpl::processNotificationEvent(const std::string& type, const std::string& channel, const Poco::JSON::Object::Ptr& data) {
    if(!_storeSubscriptionHelper.hasSubscriptionForChannel(channel) && channel != INTERNAL_EVENT_CHANNEL_NAME) {
        return;
    }
    if (type == "storeCreated") {
        auto raw = utils::TypedObjectFactory::createObjectFromVar<server::Store>(data);
        if(raw.typeOpt(std::string(STORE_TYPE_FILTER_FLAG)) == STORE_TYPE_FILTER_FLAG) {
            _storeProvider.updateByValue(raw);
            auto data = decryptAndConvertStoreDataToStore(raw);
            std::shared_ptr<StoreCreatedEvent> event(new StoreCreatedEvent());
            event->channel = channel;
            event->data = data;
            _eventMiddleware->emitApiEvent(event);
        }
    } else if (type == "storeUpdated") {
        auto raw = utils::TypedObjectFactory::createObjectFromVar<server::Store>(data);
        if(raw.typeOpt(std::string(STORE_TYPE_FILTER_FLAG)) == STORE_TYPE_FILTER_FLAG) {
            _storeProvider.updateByValue(raw);
            auto data = decryptAndConvertStoreDataToStore(raw);
            std::shared_ptr<StoreUpdatedEvent> event(new StoreUpdatedEvent());
            event->channel = channel;
            event->data = data;
            _eventMiddleware->emitApiEvent(event);
        }
    } else if (type == "storeDeleted") {
        auto raw = utils::TypedObjectFactory::createObjectFromVar<server::StoreDeletedEventData>(data);
        if(raw.typeOpt(std::string(STORE_TYPE_FILTER_FLAG)) == STORE_TYPE_FILTER_FLAG) {
            _storeProvider.invalidateByContainerId(raw.storeId());
            auto data = Mapper::mapToStoreDeletedEventData(raw);
            std::shared_ptr<StoreDeletedEvent> event(new StoreDeletedEvent());
            event->channel = channel;
            event->data = data;
            _eventMiddleware->emitApiEvent(event);
        }
    } else if (type == "storeStatsChanged") {
        auto raw = utils::TypedObjectFactory::createObjectFromVar<server::StoreStatsChangedEventData>(data);
        if(raw.typeOpt(std::string(STORE_TYPE_FILTER_FLAG)) == STORE_TYPE_FILTER_FLAG) {
            _storeProvider.updateStats(raw);
            auto data = Mapper::mapToStoreStatsChangedEventData(raw);
            std::shared_ptr<StoreStatsChangedEvent> event(new StoreStatsChangedEvent());
            event->channel = channel;
            event->data = data;
            _eventMiddleware->emitApiEvent(event);
        }
    
    } else if (type == "storeFileCreated") {
        auto raw = utils::TypedObjectFactory::createObjectFromVar<server::File>(data);
        auto store {getRawStoreFromCacheOrBridge(raw.storeId())};
        auto file = decryptAndConvertFileDataToFileInfo(store, raw);

        // auto data = _dataResolver->decrypt(std::vector<server::File>{raw})[0];
        std::shared_ptr<StoreFileCreatedEvent> event(new StoreFileCreatedEvent());
        event->channel = channel;
        event->data = file;
        _eventMiddleware->emitApiEvent(event);
    } else if (type == "storeFileUpdated") {
        auto raw = utils::TypedObjectFactory::createObjectFromVar<server::File>(data);
        auto store {getRawStoreFromCacheOrBridge(raw.storeId())};
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
            _storeProvider.invalidate();
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
    assertStoreExist(storeId);
    if(_storeSubscriptionHelper.hasSubscriptionForElement(storeId)) {
        throw AlreadySubscribedException(storeId);
    }
    _storeSubscriptionHelper.subscribeForElement(storeId);
}

void StoreApiImpl::unsubscribeFromFileEvents(const std::string& storeId) {
    assertStoreExist(storeId);
    if(!_storeSubscriptionHelper.hasSubscriptionForElement(storeId)) {
        throw NotSubscribedException(storeId);
    }
    _storeSubscriptionHelper.unsubscribeFromElement(storeId);
}

void StoreApiImpl::processConnectedEvent() {
    _storeProvider.invalidate();
}

void StoreApiImpl::processDisconnectedEvent() {
    _storeProvider.invalidate();
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

DecryptedStoreDataV4 StoreApiImpl::decryptStoreV4(server::StoreDataEntry storeEntry, const core::DecryptedEncKey& encKey) {
    try {
        auto encryptedDataEntryVar = utils::TypedObjectFactory::createObjectFromVar<server::EncryptedStoreDataV4>(storeEntry.data());
        return _storeDataEncryptorV4.decrypt(encryptedDataEntryVar, encKey.key);
    } catch (const core::Exception& e) {
        return DecryptedStoreDataV4({{.dataStructureVersion = 4, .statusCode = e.getCode()},{},{},{},{}});
    } catch (const privmx::utils::PrivmxException& e) {
        return DecryptedStoreDataV4({{.dataStructureVersion = 4, .statusCode = core::ExceptionConverter::convert(e).getCode()},{},{},{},{}});
    } catch (...) {
        return DecryptedStoreDataV4({{.dataStructureVersion = 4, .statusCode = ENDPOINT_CORE_EXCEPTION_CODE},{},{},{},{}});
    }
}

DecryptedStoreDataV5 StoreApiImpl::decryptStoreV5(server::StoreDataEntry storeEntry, const core::DecryptedEncKey& encKey) {
    try {
        auto encryptedDataEntryVar = utils::TypedObjectFactory::createObjectFromVar<server::EncryptedStoreDataV5>(storeEntry.data());
        if(encKey.statusCode != 0) {
            auto tmp = _storeDataEncryptorV5.extractPublic(encryptedDataEntryVar);
            tmp.statusCode = encKey.statusCode;
            return tmp;
        }
        return _storeDataEncryptorV5.decrypt(encryptedDataEntryVar, encKey.key);
    } catch (const core::Exception& e) {
        return DecryptedStoreDataV5({{.dataStructureVersion = 5, .statusCode = e.getCode()},{},{},{},{},{}});
    } catch (const privmx::utils::PrivmxException& e) {
        return DecryptedStoreDataV5({{.dataStructureVersion = 5, .statusCode = core::ExceptionConverter::convert(e).getCode()},{},{},{},{},{}});
    } catch (...) {
        return DecryptedStoreDataV5({{.dataStructureVersion = 5, .statusCode = ENDPOINT_CORE_EXCEPTION_CODE},{},{},{},{},{}});
    }
}

Store StoreApiImpl::convertStoreDataV1ToStore(server::Store store, dynamic::compat_v1::StoreData storeData) {
    std::vector<std::string> users;
    std::vector<std::string> managers;
    for (auto x : store.users()) {
        users.push_back(x);
    }
    for (auto x : store.managers()) {
        managers.push_back(x);
    }
    Poco::JSON::Object::Ptr privateMeta = Poco::JSON::Object::Ptr(new Poco::JSON::Object());
    privateMeta->set("title", storeData.name());
    int64_t statusCode = storeData.statusCodeOpt(0);
    return {
        .storeId = store.id(),
        .contextId = store.contextId(),
        .createDate = store.createDate(),
        .creator = store.creator(),
        .lastModificationDate = store.lastModificationDate(),
        .lastFileDate = store.lastFileDate(),
        .lastModifier = store.lastModifier(),
        .users = users,
        .managers = managers,
        .version = store.version(),
        .publicMeta = core::Buffer::from(""),
        .privateMeta = core::Buffer::from(utils::Utils::stringify(privateMeta)),
        .policy = {},
        .filesCount = store.files(),
        .statusCode = statusCode,
        .schemaVersion = 1
    };
}

Store StoreApiImpl::convertDecryptedStoreDataV4ToStore(server::Store store, const DecryptedStoreDataV4& storeData) {
    std::vector<std::string> users;
    std::vector<std::string> managers;
    for (auto x : store.users()) {
        users.push_back(x);
    }
    for (auto x : store.managers()) {
        managers.push_back(x);
    }
    Store result {
        .storeId = store.id(),
        .contextId = store.contextId(), 
        .createDate = store.createDate(),
        .creator = store.creator(),
        .lastModificationDate = store.lastModificationDate(),
        .lastFileDate = store.lastFileDate(),
        .lastModifier = store.lastModifier(),
        .users = users,
        .managers = managers,
        .version = store.version(),
        .publicMeta = storeData.publicMeta,
        .privateMeta = storeData.privateMeta,
        .policy = core::Factory::parsePolicyServerObject(store.policy()), 
        .filesCount = store.files(),
        .statusCode = storeData.statusCode,
        .schemaVersion = 4
    };
    return result;
}

Store StoreApiImpl::convertDecryptedStoreDataV5ToStore(server::Store store, const DecryptedStoreDataV5& storeData) {
    std::vector<std::string> users;
    std::vector<std::string> managers;
    for (auto x : store.users()) {
        users.push_back(x);
    }
    for (auto x : store.managers()) {
        managers.push_back(x);
    }
    Store result {
        .storeId = store.id(),
        .contextId = store.contextId(), 
        .createDate = store.createDate(),
        .creator = store.creator(),
        .lastModificationDate = store.lastModificationDate(),
        .lastFileDate = store.lastFileDate(),
        .lastModifier = store.lastModifier(),
        .users = users,
        .managers = managers,
        .version = store.version(),
        .publicMeta = storeData.publicMeta,
        .privateMeta = storeData.privateMeta,
        .policy = core::Factory::parsePolicyServerObject(store.policy()), 
        .filesCount = store.files(),
        .statusCode = storeData.statusCode,
        .schemaVersion = 5
    };
    return result;
}

StoreDataSchema::Version StoreApiImpl::getStoreEntryDataStructureVersion(server::StoreDataEntry storeEntry) {
    if(storeEntry.data().type() == typeid(Poco::JSON::Object::Ptr)) {
        auto versioned = utils::TypedObjectFactory::createObjectFromVar<core::dynamic::VersionedData>(storeEntry.data());
        auto version = versioned.versionOpt(StoreDataSchema::Version::UNKNOWN);
        switch (version) {
            case StoreDataSchema::Version::VERSION_4:
                return StoreDataSchema::Version::VERSION_4;
            case StoreDataSchema::Version::VERSION_5:
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
            return std::make_tuple(Store{{},{},{},{},{},{},{},{},{},{},{},{},{},{}, .statusCode = e.getCode()}, core::DataIntegrityObject());
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
                    .containerResourceId = std::nullopt
                }
            );
        }
        case StoreDataSchema::Version::VERSION_4: {
            auto decryptedStoreData = decryptStoreV4(storeEntry, encKey);
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
                    .containerResourceId = std::nullopt
                }
            );
        }
        case StoreDataSchema::Version::VERSION_5: {
            auto decryptedStoreData = decryptStoreV5(storeEntry, encKey);
            return std::make_tuple(convertDecryptedStoreDataV5ToStore(store, decryptedStoreData), decryptedStoreData.dio);
        }
    }
    auto e = UnknowStoreFormatException();
    return std::make_tuple(Store{{},{},{},{},{},{},{},{},{},{},{},{},{},{}, .statusCode = e.getCode(), {}}, core::DataIntegrityObject());
}

std::vector<Store> StoreApiImpl::decryptAndConvertStoresDataToStores(utils::List<server::Store> stores) {
    std::vector<Store> result;
    core::KeyDecryptionAndVerificationRequest keyProviderRequest;
    //create request to KeyProvider for keys
    for (size_t i = 0; i < stores.size(); i++) {
        auto store = stores.get(i);
        core::EncKeyLocation location{.contextId=store.contextId(), .resourceId=store.resourceIdOpt("")};
        auto store_data_entry = store.data().get(store.data().size()-1);
        keyProviderRequest.addOne(store.keys(), store_data_entry.keyId(), location);
    }
    //send request to KeyProvider
    auto storesKeys {_keyProvider->getKeysAndVerify(keyProviderRequest)};
    std::vector<core::DataIntegrityObject> storesDIO;
    std::map<std::string, bool> duplication_check;
    for (size_t i = 0; i < stores.size(); i++) {
        auto store = stores.get(i);
        try {
            auto tmp = decryptAndConvertStoreDataToStore(
                store, 
                store.data().get(store.data().size()-1), 
                storesKeys.at({.contextId=store.contextId(), .resourceId=store.resourceIdOpt("")}).at(store.data().get(store.data().size()-1).keyId())
            );
            result.push_back(std::get<0>(tmp));
            auto storeDIO = std::get<1>(tmp);
            storesDIO.push_back(storeDIO);
            //find duplication
            std::string fullRandomId = storeDIO.randomId + "-" + std::to_string(storeDIO.timestamp);
            if(duplication_check.find(fullRandomId) == duplication_check.end()) {
                duplication_check.insert(std::make_pair(fullRandomId, true));
            } else {
                result[result.size()-1].statusCode = core::DataIntegrityObjectDuplicatedException().getCode();
            }
        } catch (const core::Exception& e) {
            result.push_back(Store{{},{},{},{},{},{},{},{},{},{},{},{},{},{}, .statusCode = e.getCode(), {}});
            storesDIO.push_back(core::DataIntegrityObject());

        }
    }
    std::vector<core::VerificationRequest> verifierInput {};
    for (size_t i = 0; i < result.size(); i++) {
        if(result[i].statusCode == 0) {
            verifierInput.push_back({
                .contextId = result[i].contextId,
                .senderId = result[i].lastModifier,
                .senderPubKey = storesDIO[i].creatorPubKey,
                .date = result[i].lastModificationDate
            });
        }
    }
    std::vector<bool> verified;
    try {
        verified =_connection.getImpl()->getUserVerifier()->verify(verifierInput);
    } catch (...) {
        throw core::UserVerificationMethodUnhandledException();
    }
    for (size_t j = 0, i = 0; i < result.size(); i++) {
        if(result[i].statusCode == 0) {
            result[i].statusCode = verified[j] ? 0 : core::ExceptionConverter::getCodeOfUserVerificationFailureException();
            j++;
        }
    }
    return result;
}

Store StoreApiImpl::decryptAndConvertStoreDataToStore(server::Store store) {
    auto store_data_entry = store.data().get(store.data().size()-1);
    core::KeyDecryptionAndVerificationRequest keyProviderRequest;
    core::EncKeyLocation location{.contextId=store.contextId(), .resourceId=store.resourceIdOpt("")};
    keyProviderRequest.addOne(store.keys(), store_data_entry.keyId(), location);
    auto key = _keyProvider->getKeysAndVerify(keyProviderRequest).at(location).at(store_data_entry.keyId());
    Store result;
    core::DataIntegrityObject storeDIO;
    std::tie(result, storeDIO) = decryptAndConvertStoreDataToStore(store, store_data_entry, key);
    if(result.statusCode != 0) return result;
    std::vector<core::VerificationRequest> verifierInput {};
    verifierInput.push_back({
        .contextId = result.contextId,
        .senderId = result.lastModifier,
        .senderPubKey = storeDIO.creatorPubKey,
        .date = result.lastModificationDate
    });
    std::vector<bool> verified;
    try {
        verified =_connection.getImpl()->getUserVerifier()->verify(verifierInput);
    } catch (...) {
        throw core::UserVerificationMethodUnhandledException();
    }
    result.statusCode = verified[0] ? 0 : core::ExceptionConverter::getCodeOfUserVerificationFailureException();
    return result;
}

core::DecryptedEncKey StoreApiImpl::getStoreCurrentEncKey(server::Store store) {
    auto store_data_entry = store.data().get(store.data().size()-1);
    core::KeyDecryptionAndVerificationRequest keyProviderRequest;
    core::EncKeyLocation location{.contextId=store.contextId(), .resourceId=store.resourceIdOpt("")};
    keyProviderRequest.addOne(store.keys(), store_data_entry.keyId(), location);
    return _keyProvider->getKeysAndVerify(keyProviderRequest).at(location).at(store_data_entry.keyId());
}

StoreInternalMetaV5 StoreApiImpl::decryptStoreInternalMeta(server::StoreDataEntry storeEntry, const core::DecryptedEncKey& encKey) {
    switch (getStoreEntryDataStructureVersion(storeEntry)) {
        case StoreDataSchema::Version::UNKNOWN:
            throw UnknowStoreFormatException();
        case StoreDataSchema::Version::VERSION_1:
            return StoreInternalMetaV5();
        case StoreDataSchema::Version::VERSION_4:
            return StoreInternalMetaV5();
        case StoreDataSchema::Version::VERSION_5:
            return decryptStoreV5(storeEntry, encKey).internalMeta;
    }
    throw UnknowStoreFormatException();
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
        return DecryptedFileMetaV4({{.dataStructureVersion = 4, .statusCode = e.getCode()},{},{},{},{},{}});
    } catch (const privmx::utils::PrivmxException& e) {
        return DecryptedFileMetaV4({{.dataStructureVersion = 4, .statusCode = core::ExceptionConverter::convert(e).getCode()},{},{},{},{},{}});
    } catch (...) {
        return DecryptedFileMetaV4({{.dataStructureVersion = 4, .statusCode = ENDPOINT_CORE_EXCEPTION_CODE},{},{},{},{},{}});
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
        return DecryptedFileMetaV5({{.dataStructureVersion = 5, .statusCode = e.getCode()},{},{},{},{},{}});
    } catch (const privmx::utils::PrivmxException& e) {
        return DecryptedFileMetaV5({{.dataStructureVersion = 5, .statusCode = core::ExceptionConverter::convert(e).getCode()},{},{},{},{},{}});
    } catch (...) {
        return DecryptedFileMetaV5({{.dataStructureVersion = 5, .statusCode = ENDPOINT_CORE_EXCEPTION_CODE},{},{},{},{},{}});
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
        .statusCode = storeFileMeta.statusCodeOpt(0),
        .schemaVersion = 1
    };
    return result;
}

File StoreApiImpl::convertDecryptedFileMetaV4ToFile(server::File file, const DecryptedFileMetaV4& fileData) {
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
        .statusCode = fileData.statusCode,
        .schemaVersion = 4
    };
}

File StoreApiImpl::convertDecryptedFileMetaV5ToFile(server::File file, const DecryptedFileMetaV5& fileData) {
    store::ServerFileInfo fileInfo = {
        .storeId = file.storeId(),
        .fileId = file.id(),
        .createDate = file.created(),
        .author = file.creator(),
    };
    auto internalMeta = utils::TypedObjectFactory::createObjectFromVar<dynamic::InternalStoreFileMeta>(utils::Utils::parseJson(fileData.internalMeta.stdString()));
    return store::File {
        .info = fileInfo,
        .publicMeta = fileData.publicMeta,
        .privateMeta = fileData.privateMeta,
        .size = internalMeta.size(),
        .authorPubKey = fileData.authorPubKey,
        .statusCode = fileData.statusCode,
        .schemaVersion = 5
    };
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
            return std::make_tuple(File{{},{},{},{},{},.statusCode = e.getCode()}, core::DataIntegrityObject());
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
                    .containerResourceId = std::string()
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
                    .containerResourceId = std::string()
                }
            );
        }
        case FileDataSchema::Version::VERSION_5: {
            auto decryptedFile = decryptFileMetaV5(file, encKey);
            return std::make_tuple(convertDecryptedFileMetaV5ToFile(file, decryptFileMetaV5(file, encKey)), decryptedFile.dio);
        }
    }
    auto e = UnknowFileFormatException();
    return std::make_tuple(File{{},{},{},{},{},.statusCode = e.getCode(), {}}, core::DataIntegrityObject());
}

std::vector<File> StoreApiImpl::decryptAndConvertFilesDataToFilesInfo(server::Store store, utils::List<server::File> files) {
    std::set<std::string> keyIds;
    for (auto file : files) {
        keyIds.insert(file.keyId());
    }
    core::KeyDecryptionAndVerificationRequest keyProviderRequest;
    core::EncKeyLocation location{.contextId=store.contextId(), .resourceId=store.resourceIdOpt("")};
    keyProviderRequest.addMany(store.keys(), keyIds, location);
    auto keyMap = _keyProvider->getKeysAndVerify(keyProviderRequest).at(location);
    std::vector<File> result;
    std::map<std::string, bool> duplication_check;
    for (auto file : files) {
        try {
            auto statusCode = validateFileDataIntegrity(file, store.resourceIdOpt(""));
            if(statusCode == 0) {
                auto tmp = decryptAndConvertFileDataToFileInfo(file,  keyMap.at(file.keyId()));
                result.push_back(std::get<0>(tmp));
                auto fileDIO = std::get<1>(tmp);
                //find duplication
                std::string fullRandomId = fileDIO.randomId + "-" + std::to_string(fileDIO.timestamp);
                if(duplication_check.find(fullRandomId) == duplication_check.end()) {
                    duplication_check.insert(std::make_pair(fullRandomId, true));
                } else {
                    result[result.size()-1].statusCode = core::DataIntegrityObjectDuplicatedException().getCode();
                }
            } else {
                result.push_back(File{{},{},{},{},{},.statusCode = statusCode, {}});
            }
        } catch (const core::Exception& e) {
            result.push_back(File{{},{},{},{},{},.statusCode = e.getCode(), {}});
        }
    }
    std::vector<core::VerificationRequest> verifierInput {};
    for (auto file: result) {
        if(file.statusCode == 0) {
            verifierInput.push_back({
                .contextId = store.contextId(),
                .senderId = file.info.author,
                .senderPubKey = file.authorPubKey,
                .date = file.info.createDate
            });
        }
    }
    std::vector<bool> verified;
    try {
        verified = _connection.getImpl()->getUserVerifier()->verify(verifierInput);
    } catch (...) {
        throw core::UserVerificationMethodUnhandledException();
    }
    for (size_t j = 0, i = 0; i < result.size(); ++i) {
        if (result[i].statusCode == 0) {
            result[i].statusCode = verified[j] ? 0 : core::ExceptionConverter::getCodeOfUserVerificationFailureException();
            j++;
        }
    }
    return result;
}

File StoreApiImpl::decryptAndConvertFileDataToFileInfo(server::Store store, server::File file) {
    auto keyId = file.keyId();
    core::KeyDecryptionAndVerificationRequest keyProviderRequest;
    core::EncKeyLocation location{.contextId=store.contextId(), .resourceId=store.resourceIdOpt("")};
    keyProviderRequest.addOne(store.keys(), keyId, location);
    auto encKey = _keyProvider->getKeysAndVerify(keyProviderRequest).at(location).at(keyId);
    _fileKeyIdFormatValidator.assertKeyIdFormat(keyId);
    File result;
    core::DataIntegrityObject fileDIO;
    std::tie(result, fileDIO) = decryptAndConvertFileDataToFileInfo(file, encKey);
    if(result.statusCode != 0) return result;
    std::vector<core::VerificationRequest> verifierInput {};
        verifierInput.push_back({
            .contextId = store.contextId(),
            .senderId = result.info.author,
            .senderPubKey = result.authorPubKey,
            .date = result.info.createDate
        });
    std::vector<bool> verified;
    try {
        verified = _connection.getImpl()->getUserVerifier()->verify(verifierInput);
    } catch (...) {
        throw core::UserVerificationMethodUnhandledException();
    }
    result.statusCode = verified[0] ? 0 : core::ExceptionConverter::getCodeOfUserVerificationFailureException();
    return result;
}

File StoreApiImpl::decryptAndConvertFileDataToFileInfo(server::File file) {
    try {
        auto store = getRawStoreFromCacheOrBridge(file.storeId());
        return decryptAndConvertFileDataToFileInfo(store, file);
    } catch (const core::Exception& e) {
        return File{{},{},{},{},{},.statusCode = e.getCode(), {}};
    } catch (const privmx::utils::PrivmxException& e) {
        return File{{},{},{},{},{},.statusCode = e.getCode(), {}};
    } catch (...) {
        return File{{},{},{},{},{},.statusCode = ENDPOINT_CORE_EXCEPTION_CODE, {}};
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

dynamic::InternalStoreFileMeta StoreApiImpl::decryptFileInternalMeta(server::Store store, server::File file) {
    auto keyId = file.keyId();    
    core::KeyDecryptionAndVerificationRequest keyProviderRequest;
    core::EncKeyLocation location{.contextId=store.contextId(), .resourceId=store.resourceIdOpt("")};
    keyProviderRequest.addOne(store.keys(), keyId, location);
    auto encKey = _keyProvider->getKeysAndVerify(keyProviderRequest).at(location).at(keyId);
    _fileKeyIdFormatValidator.assertKeyIdFormat(keyId);
    return decryptFileInternalMeta(file, encKey);
}

void StoreApiImpl::updateFileMeta(const std::string& fileId, const core::Buffer& publicMeta, const core::Buffer& privateMeta) {
    auto storeFileGetModel = utils::TypedObjectFactory::createNewObject<server::StoreFileGetModel>();
    storeFileGetModel.fileId(fileId);

    auto storeFileGetResult = _serverApi->storeFileGet(storeFileGetModel);
    server::Store store = storeFileGetResult.store();
    server::File file = storeFileGetResult.file();
    auto statusCode = validateFileDataIntegrity(file, store.resourceIdOpt(""));
    if(statusCode != 0) {
        throw FileDataIntegrityException();
    }
    auto key = getStoreCurrentEncKey(store);
    Poco::Dynamic::Var encryptedMetaVar;
    auto fileInternalMeta = decryptFileInternalMeta(store, file);
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

server::Store StoreApiImpl::getRawStoreFromCacheOrBridge(const std::string& storeId) {
    // useing _storeProvider only with STORE_TYPE_FILTER_FLAG 
    // making sure to have valid cache
    if(!_subscribeForStore) _storeProvider.update(storeId);
    auto storeContainerInfo = _storeProvider.get(storeId);
    if(storeContainerInfo.status != core::DataIntegrityStatus::ValidationSucceed) {
        throw StoreDataIntegrityException();
    }
    return storeContainerInfo.container;
}

void StoreApiImpl::assertStoreExist(const std::string& storeId) {
    //check if store is in cache or on server
    getRawStoreFromCacheOrBridge(storeId);
}

void StoreApiImpl::assertFileExist(const std::string& fileId) {
    auto storeFileGetModel = utils::TypedObjectFactory::createNewObject<server::StoreFileGetModel>();
    storeFileGetModel.fileId(fileId);
    auto file = _serverApi->storeFileGet(storeFileGetModel).file();
}

uint32_t StoreApiImpl::validateStoreDataIntegrity(server::Store store) {
    try {
        auto store_data_entry = store.data().get(store.data().size()-1);
        switch (getStoreEntryDataStructureVersion(store_data_entry)) {
            case StoreDataSchema::Version::UNKNOWN:
                return UnknowStoreFormatException().getCode();
            case StoreDataSchema::Version::VERSION_1:
                return 0;
            case StoreDataSchema::Version::VERSION_4:
                return 0;
            case StoreDataSchema::Version::VERSION_5: {
                auto store_data = utils::TypedObjectFactory::createObjectFromVar<server::EncryptedStoreDataV5>(store_data_entry.data());
                auto dio = _storeDataEncryptorV5.getDIOAndAssertIntegrity(store_data);
                if(
                    dio.contextId != store.contextId() ||
                    dio.resourceId != store.resourceIdOpt("") ||
                    dio.creatorUserId != store.lastModifier() ||
                    !core::TimestampValidator::validate(dio.timestamp, store.lastModificationDate())
                ) {
                    return StoreDataIntegrityException().getCode();
                }
                return 0;
            }
        }
        return UnknowStoreFormatException().getCode();
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