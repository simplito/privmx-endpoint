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
#include <privmx/endpoint/core/Exception.hpp>
#include <privmx/endpoint/core/ExceptionConverter.hpp>
#include <privmx/endpoint/core/TimestampValidator.hpp>
#include <privmx/endpoint/store/ChunkBufferedStream.hpp>
#include <privmx/endpoint/store/FileHandle.hpp>
#include <privmx/endpoint/store/StoreApiImpl.hpp>
#include <privmx/endpoint/store/StoreException.hpp>
#include <privmx/endpoint/thread/ServerTypes.hpp>
#include <privmx/endpoint/thread/ThreadApi.hpp>
#include <privmx/endpoint/thread/ThreadApiImpl.hpp>

#include "privmx/endpoint/core/EventBuilder.hpp"
#include "privmx/endpoint/core/ListQueryMapper.hpp"
#include "privmx/endpoint/core/Mapper.hpp"
#include "privmx/endpoint/core/UsersKeysResolver.hpp"
#include "privmx/endpoint/inbox/InboxApiImpl.hpp"
#include "privmx/endpoint/inbox/InboxDataHelper.hpp"
#include "privmx/endpoint/inbox/InboxException.hpp"
#include "privmx/endpoint/inbox/ServerTypes.hpp"

using namespace privmx::endpoint::inbox;
using namespace privmx::endpoint;
using namespace privmx::utils;
using namespace privmx;

const Poco::Int64 InboxApiImpl::_CHUNK_SIZE = 128 * 1024;

InboxApiImpl::InboxApiImpl(
    const core::Connection& connection,
    const thread::ThreadApi& threadApi,
    const store::StoreApi& storeApi,
    const std::shared_ptr<core::KeyProvider>& keyProvider,
    const std::shared_ptr<ServerApi>& serverApi,
    const std::shared_ptr<store::RequestApi>& requestApi,
    const std::string& host,
    const privmx::crypto::PrivateKey& userPrivKey,
    const std::shared_ptr<core::EventMiddleware>& eventMiddleware,
    const std::shared_ptr<core::HandleManager>& handleManager,
    size_t serverRequestChunkSize
)
    : ModuleBaseApi(userPrivKey, keyProvider, host, eventMiddleware, connection), _connection(connection),
      _threadApi(threadApi), _storeApi(storeApi), _keyProvider(keyProvider), _serverApi(serverApi),
      _requestApi(requestApi), _host(host), _userPrivKey(userPrivKey), _eventMiddleware(eventMiddleware),
      _handleManager(handleManager), _inboxHandleManager(InboxHandleManager(handleManager)),
      _messageKeyIdFormatValidator(MessageKeyIdFormatValidator()),
      _fileKeyIdFormatValidator(FileKeyIdFormatValidator()), _serverRequestChunkSize(serverRequestChunkSize),
      _subscriber(connection.getImpl()->getGateway(), INBOX_TYPE_FILTER_FLAG),
      _inboxDataSchemaMapper(userPrivKey, connection), _inboxEntryDataSchemaMapper(keyProvider, serverApi, storeApi) {
    _notificationListenerId = _eventMiddleware->addNotificationEventListener(
        std::bind(&InboxApiImpl::processNotificationEvent, this, std::placeholders::_1, std::placeholders::_2)
    );
    _connectedListenerId = _eventMiddleware->addConnectedEventListener(
        std::bind(&InboxApiImpl::processConnectedEvent, this)
    );
    _disconnectedListenerId = _eventMiddleware->addDisconnectedEventListener(
        std::bind(&InboxApiImpl::processDisconnectedEvent, this)
    );
}

InboxApiImpl::~InboxApiImpl() {
    _eventMiddleware->removeNotificationEventListener(_notificationListenerId);
    _eventMiddleware->removeConnectedEventListener(_connectedListenerId);
    _eventMiddleware->removeDisconnectedEventListener(_disconnectedListenerId);
    _guardedExecutor.reset();
    LOG_TRACE("~InboxApiImpl Done");
}

std::string InboxApiImpl::createInbox(
    const std::string& contextId,
    const std::vector<core::UserWithPubKey>& users,
    const std::vector<core::UserWithPubKey>& managers,
    const core::Buffer& publicMeta,
    const core::Buffer& privateMeta,
    const std::optional<inbox::FilesConfig>& fileConfig,
    const std::optional<core::ContainerPolicyWithoutItem>& policies
) {

    auto inboxKey = _keyProvider->generateKey();
    auto eccKey = crypto::ECC::fromPrivateKey(inboxKey.key);
    auto privateKey = crypto::PrivateKey(eccKey);
    auto pubKey = privateKey.getPublicKey();

    auto randName{InboxDataHelper::getRandomName()};
    auto randNameAsBuf{privmx::endpoint::core::Buffer::from(randName)};
    auto emptyBuf{privmx::endpoint::core::Buffer::from(std::string())};

    std::optional<core::ContainerPolicy> policiesWithItems{
        policies.has_value() ? std::make_optional<core::ContainerPolicy>({policies.value(), std::nullopt}) :
                               std::nullopt
    };

    auto storeId = _storeApi.getImpl()->createStoreEx(
        contextId, users, managers, emptyBuf, randNameAsBuf, INBOX_TYPE_FILTER_FLAG, policiesWithItems
    );
    auto threadId = _threadApi.getImpl()->createThreadEx(
        contextId, users, managers, emptyBuf, randNameAsBuf, INBOX_TYPE_FILTER_FLAG, policiesWithItems
    );
    auto resourceId = core::EndpointUtils::generateId();
    auto inboxDIO = _connection.getImpl()->createDIO(contextId, resourceId);
    auto inboxSecret = _keyProvider->generateSecret();
    InboxDataProcessorModelV5 inboxDataIn{
        .storeId = storeId,
        .threadId = threadId,
        .filesConfig = getFilesConfigOptOrDefault(fileConfig),
        .privateData =
            {.privateMeta = privateMeta,
             .internalMeta =
                 InboxInternalMetaV5{.secret = inboxSecret, .resourceId = resourceId, .randomId = inboxDIO.randomId},
             .dio = inboxDIO},
        .publicData = {
            .publicMeta = publicMeta,
            .inboxEntriesPubKeyBase58DER = pubKey.toBase58DER(),
            .inboxEntriesKeyId = inboxKey.id
        }
    };

    server::InboxCreateModel createInboxModel;
    createInboxModel.resourceId = resourceId;
    createInboxModel.contextId = contextId;
    createInboxModel.users = InboxDataHelper::mapUsers(users);
    createInboxModel.managers = InboxDataHelper::mapUsers(managers);
    createInboxModel.data = _inboxDataSchemaMapper.encrypt(inboxDataIn, inboxKey.key);
    createInboxModel.keyId = inboxKey.id;
    auto all_users = core::EndpointUtils::uniqueListUserWithPubKey(users, managers);
    auto keysList = _keyProvider->prepareKeysList(
        all_users, inboxKey, inboxDIO, {.contextId = contextId, .resourceId = resourceId}, inboxSecret
    );
    createInboxModel.keys = keysList;
    if (policies.has_value()) {
        createInboxModel.policy = privmx::endpoint::core::Factory::createPolicyServerObject(policiesWithItems.value());
    }

    auto result = _serverApi->inboxCreate(createInboxModel);
    return result.inboxId;
}

void InboxApiImpl::updateInbox(
    const std::string& inboxId,
    const std::vector<core::UserWithPubKey>& users,
    const std::vector<core::UserWithPubKey>& managers,
    const core::Buffer& publicMeta,
    const core::Buffer& privateMeta,
    const std::optional<inbox::FilesConfig>& fileConfig,
    const int64_t version,
    const bool force,
    const bool forceGenerateNewKey,
    const std::optional<core::ContainerPolicyWithoutItem>& policies
) {
    auto currentInbox = getServerInbox(inboxId);
    auto currentInboxEntry = getInboxCurrentDataEntry(currentInbox);
    auto currentInboxData = currentInboxEntry.data;
    auto currentInboxResourceId = currentInbox.resourceId.has_value() ? currentInbox.resourceId.value() :
                                                                        core::EndpointUtils::generateId();
    auto location{getModuleEncKeyLocation(currentInbox, currentInboxResourceId)};
    auto inboxKeys{getAndValidateModuleKeys(currentInbox, currentInboxResourceId)};
    auto currentInboxKey{findEncKeyByKeyId(inboxKeys, currentInboxEntry.keyId)};
    auto inboxInternalMeta = _inboxDataSchemaMapper.decryptInternalMeta(currentInboxEntry, currentInboxKey);

    auto usersKeysResolver{
        core::UsersKeysResolver::create(currentInbox, users, managers, forceGenerateNewKey, currentInboxKey)
    };

    if (!_keyProvider->verifyKeysSecret(inboxKeys, location, inboxInternalMeta.secret)) {
        throw InboxEncryptionKeyValidationException();
    }
    core::EncKey inboxKey = currentInboxKey;
    core::DataIntegrityObject updateInboxDio = _connection.getImpl()->createDIO(
        currentInbox.contextId, currentInboxResourceId
    );

    std::vector<core::server::KeyEntrySet> keysList;
    if (usersKeysResolver->doNeedNewKey()) {
        inboxKey = _keyProvider->generateKey();
        keysList = _keyProvider->prepareKeysList(
            usersKeysResolver->getNewUsers(), inboxKey, updateInboxDio, location, inboxInternalMeta.secret
        );
    }

    auto usersToAddMissingKey{usersKeysResolver->getUsersToAddKey()};
    if (usersToAddMissingKey.size() > 0) {
        auto tmp = _keyProvider->prepareMissingKeysForNewUsers(
            inboxKeys, usersToAddMissingKey, updateInboxDio, location, inboxInternalMeta.secret
        );
        for (auto t : tmp)
            keysList.push_back(t);
    }

    auto eccKey = crypto::ECC::fromPrivateKey(inboxKey.key);
    auto privateKey = crypto::PrivateKey(eccKey);
    auto pubKey = privateKey.getPublicKey();
    InboxDataProcessorModelV5 inboxDataIn{
        .storeId = currentInboxData.storeId,
        .threadId = currentInboxData.threadId,
        .filesConfig = getFilesConfigOptOrDefault(fileConfig),
        .privateData =
            {.privateMeta = privateMeta,
             .internalMeta =
                 InboxInternalMetaV5{
                     .secret = inboxInternalMeta.secret,
                     .resourceId = currentInboxResourceId,
                     .randomId = updateInboxDio.randomId
                 },
             .dio = updateInboxDio},
        .publicData = {
            .publicMeta = publicMeta,
            .inboxEntriesPubKeyBase58DER = pubKey.toBase58DER(),
            .inboxEntriesKeyId = inboxKey.id
        }
    };

    server::InboxUpdateModel inboxUpdateModel;
    inboxUpdateModel.id = inboxId;
    inboxUpdateModel.resourceId = currentInboxResourceId;
    inboxUpdateModel.users = InboxDataHelper::mapUsers(users);
    inboxUpdateModel.managers = InboxDataHelper::mapUsers(managers);
    inboxUpdateModel.data = _inboxDataSchemaMapper.encrypt(inboxDataIn, inboxKey.key);
    inboxUpdateModel.keyId = inboxKey.id;
    inboxUpdateModel.keys = keysList;
    inboxUpdateModel.force = force;
    inboxUpdateModel.version = version;

    std::optional<core::ContainerPolicy> policiesWithItems{
        policies.has_value() ? std::make_optional<core::ContainerPolicy>({policies.value(), std::nullopt}) :
                               std::nullopt
    };

    if (policies.has_value()) {
        inboxUpdateModel.policy = privmx::endpoint::core::Factory::createPolicyServerObject(policies.value());
    }

    _serverApi->inboxUpdate(inboxUpdateModel);
    invalidateModuleKeysInCache(inboxId);

    auto store = _storeApi.getImpl()->getStoreEx(currentInboxData.storeId, INBOX_TYPE_FILTER_FLAG);
    _storeApi.getImpl()->updateStore(
        currentInboxData.storeId, users, managers, store.publicMeta, store.privateMeta, store.version, force,
        forceGenerateNewKey, policiesWithItems
    );
    auto thread = _threadApi.getImpl()->getThreadEx(currentInboxData.threadId, INBOX_TYPE_FILTER_FLAG);
    _threadApi.getImpl()->updateThread(
        currentInboxData.threadId, users, managers, thread.publicMeta, thread.privateMeta, thread.version, force,
        forceGenerateNewKey, policiesWithItems
    );
}

Inbox InboxApiImpl::getInbox(const std::string& inboxId) {
    return _getInboxEx(inboxId, std::string());
}

Inbox InboxApiImpl::getInboxEx(const std::string& inboxId, const std::string& type) {
    return _getInboxEx(inboxId, type);
}

inbox::server::InboxInfo InboxApiImpl::getServerInbox(
    const std::string& inboxId,
    const std::optional<std::string>& type
) {
    PRIVMX_DEBUG_TIME_START(PlatformInbox, getServerInbox)
    server::InboxGetModel model{.id = inboxId, .type = std::nullopt};
    if (type.has_value() && type->length() > 0) {
        model.type = type.value();
    }
    PRIVMX_DEBUG_TIME_CHECKPOINT(PlatformInbox, getServerInbox, getting inbox)
    auto inbox = _serverApi->inboxGet(model).inbox;
    PRIVMX_DEBUG_TIME_STOP(PlatformInbox, getServerInbox, data recived)
    return inbox;
}

Inbox InboxApiImpl::_getInboxEx(const std::string& inboxId, const std::string& type) {
    PRIVMX_DEBUG_TIME_START(PlatformInbox, _getInboxEx)
    auto inbox = getServerInbox(inboxId, type);
    PRIVMX_DEBUG_TIME_CHECKPOINT(PlatformInbox, _getInboxEx, data send)
    setNewModuleKeysInCache(inbox.id, inboxToModuleKeys(inbox), inbox.version);
    auto result = _inboxDataSchemaMapper.validateDecryptAndConvertInbox(inbox, _keyProvider);
    PRIVMX_DEBUG_TIME_STOP(PlatformInbox, _getInboxEx, data decrypted)
    return result;
}

core::PagingList<inbox::Inbox> InboxApiImpl::listInboxes(const std::string& contextId, const core::PagingQuery& query) {
    if (query.queryAsJson.has_value()) {
        throw InboxModuleDoesNotSupportQueriesYetException();
    }
    inbox::server::InboxListModel model;
    model.contextId = contextId;
    core::ListQueryMapper::map(model, query);
    auto inboxesListResult = _serverApi->inboxList(model);
    for (auto inbox : inboxesListResult.inboxes) {
        setNewModuleKeysInCache(inbox.id, inboxToModuleKeys(inbox), inbox.version);
    }
    std::vector<Inbox> inboxes = _inboxDataSchemaMapper.validateDecryptAndConvertInboxes(
        inboxesListResult.inboxes, _keyProvider
    );
    return core::PagingList<inbox::Inbox>({.totalAvailable = inboxesListResult.count, .readItems = inboxes});
}

InboxPublicView InboxApiImpl::getInboxPublicView(const std::string& inboxId) {
    auto publicData{getInboxPublicViewData(inboxId)};
    return inbox::InboxPublicView{
        .inboxId = publicData.inboxId, .version = publicData.version, .publicMeta = publicData.publicMeta
    };
}

void InboxApiImpl::deleteInbox(const std::string& inboxId) {
    auto inboxDataRaw{getInboxCurrentDataEntry(getServerInbox(inboxId)).data};
    server::InboxDeleteModel inboxDeleteModel{.inboxId = inboxId};
    _serverApi->inboxDelete(inboxDeleteModel);
    invalidateModuleKeysInCache(inboxId);
    _storeApi.getImpl()->deleteStore(inboxDataRaw.storeId);
    _threadApi.getImpl()->deleteThread(inboxDataRaw.threadId);
}

int64_t InboxApiImpl::prepareEntry(
    const std::string& inboxId,
    const core::Buffer& data,
    const std::vector<int64_t>& inboxFileHandles,
    const std::optional<std::string>& userPrivKey
) {
    auto inboxPublicData{getInboxPublicViewData(inboxId)};
    if (!inboxFileHandles.empty()) {
        std::vector<std::shared_ptr<store::FileWriteHandle>> fileHandles;
        std::vector<store::server::FileDefinition> filesList;
        for (auto inboxFileHandle : inboxFileHandles) {
            std::shared_ptr<store::FileWriteHandle> handle = _inboxHandleManager.getFileWriteHandle(inboxFileHandle);
            fileHandles.push_back(handle);

            auto fileSizeInfo = handle->getEncryptedFileSize();
            store::server::FileDefinition fileDefinition;
            fileDefinition.size = fileSizeInfo.size;
            fileDefinition.checksumSize = fileSizeInfo.checksumSize;
            filesList.push_back(fileDefinition);
        }
        store::server::CreateRequestModel requestModel;
        requestModel.files = filesList;
        store::server::CreateRequestResult requestResult = _requestApi->createRequest(requestModel);
        for (size_t i = 0; i < fileHandles.size(); i++) {
            std::string key = privmx::crypto::Crypto::randomBytes(32);
            fileHandles[i]->setRequestData(requestResult.id, key, (i));
        }
    }
    std::shared_ptr<InboxHandle> handle = _inboxHandleManager.createInboxHandle(
        inboxId, inboxPublicData.resourceId, data.stdString(), inboxFileHandles, userPrivKey
    );
    return handle->id;
}

void InboxApiImpl::sendEntry(const int64_t inboxHandle) {
    auto handle = _inboxHandleManager.getInboxHandle(inboxHandle);
    auto publicData{getInboxPublicViewData(handle->inboxId)};

    auto inboxPubKeyECC = privmx::crypto::PublicKey::fromBase58DER(publicData.inboxEntriesPubKeyBase58DER);
    auto _userPrivKeyECC =
        (handle->userPrivKey.has_value() ? privmx::crypto::PrivateKey::fromWIF(handle->userPrivKey.value()) :
                                           _userPrivKey);
    auto _userPubKeyECC = _userPrivKeyECC.getPublicKey();
    std::string filesMetaKey;
    bool hasFiles = !handle->inboxFileHandles.empty();
    filesMetaKey = (hasFiles ? crypto::Crypto::randomBytes(32) : std::string());

    InboxEntrySendModel modelForSerializer{
        .publicData =
            {.userPubKey = _userPubKeyECC.toBase58DER(),
             .keyPreset = handle->userPrivKey.has_value(),
             .usedInboxKeyId = publicData.inboxEntriesKeyId},
        .privateData = {.filesMetaKey = filesMetaKey, .text = handle->data}
    };

    std::vector<inbox::server::InboxFile> inboxFiles;
    std::string requestId;

    if (hasFiles) {
        int fileIndex = -1;
        CommitSendInfo commitSentInfo;
        try {
            commitSentInfo = _inboxHandleManager.commitInboxHandle(inboxHandle);
        } catch (const core::DataDifferentThanDeclaredException& e) {
            _inboxHandleManager.abortInboxHandle(inboxHandle);
            throw WritingToEntryInteruptedWrittenDataSmallerThenDeclaredException();
        }
        for (auto fileInfo : commitSentInfo.filesInfo) {
            fileIndex++;
            auto fileDIO = _connection.getImpl()->createPublicDIO(
                "", core::EndpointUtils::generateId(), _userPrivKeyECC.getPublicKey(), handle->inboxId,
                handle->inboxResourceId
            );
            auto encryptedFileMeta = _fileMetaEncryptorV4.encrypt(prepareMeta(fileInfo), _userPrivKeyECC, filesMetaKey);
            inbox::server::InboxFile inboxFile;
            inboxFile.fileIndex = fileIndex;
            inboxFile.meta = encryptedFileMeta.toJSON();
            inboxFile.resourceId = fileDIO.resourceId;
            inboxFiles.push_back(inboxFile);
        }
        requestId = commitSentInfo.filesInfo[0].fileSendResult.requestId;
    }

    auto messageDIO = _connection.getImpl()->createPublicDIO(
        "", core::EndpointUtils::generateId(), _userPrivKeyECC.getPublicKey(), handle->inboxId, handle->inboxResourceId
    );
    auto serializedMessage = _inboxEntryDataSchemaMapper.encrypt(modelForSerializer, _userPrivKeyECC, inboxPubKeyECC);
    inbox::server::InboxSendModel model;
    if (hasFiles) {
        model.requestId = requestId;
    }
    model.files = inboxFiles;
    model.inboxId = handle->inboxId;
    model.message = serializedMessage;
    model.resourceId = messageDIO.resourceId;
    model.version = EntryDataSchema::Version::VERSION_1;
    _serverApi->inboxSend(model);
}

inbox::InboxEntry InboxApiImpl::readEntry(const std::string& inboxEntryId) {
    PRIVMX_DEBUG_TIME_START(InboxApi, readEntry)
    PRIVMX_DEBUG_TIME_CHECKPOINT(InboxApi, readEntry)
    auto messageRaw = getServerMessage(inboxEntryId);
    PRIVMX_DEBUG_TIME_CHECKPOINT(InboxApi, readEntry, data recv);
    auto result = _inboxEntryDataSchemaMapper.decryptAndConvertInboxEntry(
        messageRaw, getEntryDecryptionKeys(messageRaw)
    );
    PRIVMX_DEBUG_TIME_STOP(InboxApi, readEntry, data decrypted)
    return result;
}

core::PagingList<inbox::InboxEntry> InboxApiImpl::listEntries(
    const std::string& inboxId,
    const core::PagingQuery& query
) {
    if (query.queryAsJson.has_value()) {
        throw InboxModuleDoesNotSupportQueriesYetException();
    }
    PRIVMX_DEBUG_TIME_START(InboxApi, listEntries)
    auto inboxRaw{getServerInbox(inboxId)};
    setNewModuleKeysInCache(inboxRaw.id, inboxToModuleKeys(inboxRaw), inboxRaw.version);
    auto inboxData{getInboxCurrentDataEntry(inboxRaw).data};
    auto threadId = inboxData.threadId;
    thread::server::ThreadMessagesGetModel model;
    model.threadId = threadId;
    core::ListQueryMapper::map(model, query);
    PRIVMX_DEBUG_TIME_CHECKPOINT(InboxApi, listEntries)
    auto messagesList = _serverApi->threadMessagesGet(model);
    PRIVMX_DEBUG_TIME_CHECKPOINT(InboxApi, listEntries, data recv)
    std::vector<inbox::InboxEntry> messages;
    if (messagesList.messages.size() > 0) {
        for (auto message : messagesList.messages) {
            messages.push_back(
                _inboxEntryDataSchemaMapper.decryptAndConvertInboxEntry(message, getEntryDecryptionKeys(message))
            );
        }
    }
    PRIVMX_DEBUG_TIME_STOP(InboxApi, listEntries, data decrypted)
    return core::PagingList<inbox::InboxEntry>{.totalAvailable = messagesList.count, .readItems = messages};
}

void InboxApiImpl::deleteEntry(const std::string& inboxEntryId) {
    auto messageRaw = getServerMessage(inboxEntryId);
    _messageKeyIdFormatValidator.assertKeyIdFormat(messageRaw.keyId);
    deleteMessageAndFiles(messageRaw);
}

int64_t InboxApiImpl::createFileHandle(
    const core::Buffer& publicMeta,
    const core::Buffer& privateMeta,
    const int64_t fileSize
) {
    std::shared_ptr<store::FileWriteHandle> handle = _inboxHandleManager.createFileWriteHandle(
        std::string(), std::string(), (uint64_t)fileSize, publicMeta, privateMeta, _CHUNK_SIZE, _serverRequestChunkSize,
        _requestApi
    );
    return handle->getId();
}

int64_t InboxApiImpl::createInboxFileHandleForRead(const privmx::endpoint::store::server::File& file) {
    PRIVMX_DEBUG_TIME_START(InboxApi, createInboxFileHandleForRead, handle_to_create)
    auto messageRaw = getServerMessage(readMessageIdFromFileKeyId(file.keyId));

    auto inboxKeys = getEntryDecryptionKeys(messageRaw);

    auto messageData = _inboxEntryDataSchemaMapper.decryptInboxEntry(messageRaw, inboxKeys);
    core::DecryptedEncKey fileMetaEncKey{
        core::EncKey{.id = "", .key = messageData.privateData.filesMetaKey},
        core::DecryptedVersionedData{.dataStructureVersion = 0, .statusCode = 0}
    };
    auto decryptionParams = _storeApi.getImpl()->getFileDecryptionParams(file, fileMetaEncKey);
    PRIVMX_DEBUG_TIME_CHECKPOINT(InboxApi, createInboxFileHandleForRead, file_key_extracted)
    std::shared_ptr<store::FileReadHandle> handle = _inboxHandleManager.createFileReadHandle(
        decryptionParams, _serverRequestChunkSize, _serverApi
    );
    PRIVMX_DEBUG_TIME_STOP(InboxApi, createInboxFileHandleForRead, handle_created)
    return handle->getId();
}

void InboxApiImpl::writeToFile(
    const int64_t inboxHandle,
    const int64_t inboxFileHandle,
    const core::Buffer& dataChunk
) {
    if (_inboxHandleManager.getInboxHandle(inboxHandle)->inboxFileHandles.empty()) {
        throw InboxHandleIsNotTiedToInboxFileHandleException();
    }
    std::shared_ptr<store::FileWriteHandle> handle = _inboxHandleManager.getFileWriteHandle(inboxFileHandle);
    handle->write(dataChunk.stdString());
}

int64_t InboxApiImpl::openFile(const std::string& fileId) {
    PRIVMX_DEBUG_TIME_START(InboxApi, openFile)
    store::server::StoreFileGetModel storeFileGetModel{.fileId = fileId};
    auto file{_serverApi->storeFileGet(storeFileGetModel).file};
    PRIVMX_DEBUG_TIME_CHECKPOINT(InboxApi, openFile, data recv);
    auto result = createInboxFileHandleForRead(file);
    PRIVMX_DEBUG_TIME_STOP(InboxApi, openFile, data decrypted);
    return result;
}

core::Buffer InboxApiImpl::readFromFile(const int64_t handle, const int64_t length) {
    PRIVMX_DEBUG_TIME_START(InboxApi, readFromFile)
    std::shared_ptr<store::FileReadHandle> handlePtr = _inboxHandleManager.getFileReadHandle(handle);
    core::Buffer result;
    try {
        result = core::Buffer::from(handlePtr->read(length));
    } catch (const store::FileVersionMismatchException& e) {
        closeFile(handle);
        throw FileVersionMismatchHandleClosedException();
    }
    PRIVMX_DEBUG_TIME_STOP(InboxApi, readFromFile)
    return result;
}

void InboxApiImpl::seekInFile(const int64_t handle, const int64_t pos) {
    PRIVMX_DEBUG_TIME_START(InboxApi, seekInFile)
    _inboxHandleManager.getFileReadHandle(handle)->seek(pos);
    PRIVMX_DEBUG_TIME_STOP(InboxApi, seekInFile)
}

std::string InboxApiImpl::closeFile(const int64_t handle) {
    PRIVMX_DEBUG_TIME_START(InboxApi, closeFile)
    if (!_inboxHandleManager.isFileReadHandle(handle)) {
        throw InvalidFileReadHandleException(
            "CloseFile() invalid file handle. Expected FILE_READ_HANDLE, but FILE_WRITE_HANDLE used."
        );
    }
    std::shared_ptr<store::FileHandle> handlePtr = _inboxHandleManager.getFileReadHandle(handle);
    _inboxHandleManager.removeFileHandle(handle);
    PRIVMX_DEBUG_TIME_STOP(InboxApi, closeFile)
    return handlePtr->getFileId();
}

store::FileMetaToEncryptV4 InboxApiImpl::prepareMeta(const privmx::endpoint::inbox::CommitFileInfo& commitFileInfo) {
    store::dynamic::InternalStoreFileMeta internalFileMeta;
    internalFileMeta.version = 5;
    internalFileMeta.size = commitFileInfo.size;
    internalFileMeta.cipherType = commitFileInfo.fileSendResult.cipherType;
    internalFileMeta.chunkSize = commitFileInfo.fileSendResult.chunkSize;
    internalFileMeta.key = utils::Base64::from(commitFileInfo.fileSendResult.key);
    internalFileMeta.hmac = utils::Base64::from(commitFileInfo.fileSendResult.hmac);
    store::FileMetaToEncryptV4 fileMetaToEncrypt = {
        .publicMeta = commitFileInfo.publicMeta,
        .privateMeta = commitFileInfo.privateMeta,
        .fileSize = commitFileInfo.size,
        .internalMeta = core::Buffer::from(internalFileMeta.serialize())
    };
    return fileMetaToEncrypt;
}

inbox::server::InboxDataEntry InboxApiImpl::getInboxCurrentDataEntry(inbox::server::InboxInfo inboxRaw) {
    return inboxRaw.data.back();
}

InboxPublicViewData InboxApiImpl::getInboxPublicViewData(const std::string& inboxId) {
    server::InboxGetModel model;
    model.id = inboxId;
    return _inboxDataSchemaMapper.getPublicViewData(_serverApi->inboxGetPublicView(model));
}

inbox::FilesConfig InboxApiImpl::getFilesConfigOptOrDefault(const std::optional<inbox::FilesConfig>& fileConfig) {
    inbox::FilesConfig _fileConfig;
    if (fileConfig.has_value()) {
        _fileConfig = fileConfig.value();
    } else {
        int maxFiles = 10;
        int maxFileSize = 100 * 1024 * 1024;
        _fileConfig = {
            .minCount = 0,
            .maxCount = maxFiles,
            .maxFileSize = maxFileSize,
            .maxWholeUploadSize = maxFiles * maxFileSize
        };
    }
    return _fileConfig;
}

void InboxApiImpl::processNotificationEvent(const std::string& type, const core::NotificationEvent& notification) {
    auto subscriptionQuery = _subscriber.getSubscriptionQuery(notification.subscriptions);
    if (!subscriptionQuery.has_value()) {
        LOG_WARN("Not subscribed for Event type=", type)
        return;
    }
    _guardedExecutor->exec([&, type, notification]() {
        if (type == "inboxCreated") {
            auto raw = server::InboxInfo::fromJSON(notification.data);
            if (raw.type.value_or(std::string(INBOX_TYPE_FILTER_FLAG)) == INBOX_TYPE_FILTER_FLAG) {
                setNewModuleKeysInCache(raw.id, inboxToModuleKeys(raw), raw.version);
                auto data = _inboxDataSchemaMapper.validateDecryptAndConvertInbox(raw, _keyProvider);
                auto event = core::EventBuilder::buildEvent<InboxCreatedEvent>("inbox", data, notification);
                _eventMiddleware->emitApiEvent(event);
            }
        } else if (type == "inboxUpdated") {
            auto raw = server::InboxInfo::fromJSON(notification.data);
            if (raw.type.value_or(std::string(INBOX_TYPE_FILTER_FLAG)) == INBOX_TYPE_FILTER_FLAG) {
                setNewModuleKeysInCache(raw.id, inboxToModuleKeys(raw), raw.version);
                auto data = _inboxDataSchemaMapper.validateDecryptAndConvertInbox(raw, _keyProvider);
                auto event = core::EventBuilder::buildEvent<InboxUpdatedEvent>("inbox", data, notification);
                _eventMiddleware->emitApiEvent(event);
            }
        } else if (type == "inboxDeleted") {
            auto raw = server::InboxDeletedEventData::fromJSON(notification.data);
            if (raw.type.value_or(std::string(INBOX_TYPE_FILTER_FLAG)) == INBOX_TYPE_FILTER_FLAG) {
                invalidateModuleKeysInCache(raw.inboxId);
                auto data = convertInboxDeletedEventData(raw);
                auto event = core::EventBuilder::buildEvent<InboxDeletedEvent>("inbox", data, notification);
                _eventMiddleware->emitApiEvent(event);
            }
        } else if (type == "threadNewMessage") {
            auto raw = privmx::endpoint::thread::server::ThreadMessageEventData::fromJSON(notification.data);
            if (raw.containerType.value_or("") == INBOX_TYPE_FILTER_FLAG) {
                auto inboxId = readInboxIdFromMessageKeyId(raw.keyId);
                auto message = _inboxEntryDataSchemaMapper.decryptAndConvertInboxEntry(
                    raw, getEntryDecryptionKeys(raw)
                );
                auto event = core::EventBuilder::buildEvent<InboxEntryCreatedEvent>(
                    "inbox/" + inboxId + "/entries", message, notification
                );
                _eventMiddleware->emitApiEvent(event);
            }
        } else if (type == "threadDeletedMessage") {
            auto raw = privmx::endpoint::thread::server::ThreadDeletedMessageEventData::fromJSON(notification.data);
            if (raw.containerType.value_or("") == INBOX_TYPE_FILTER_FLAG) {
                std::string inboxId;
                auto tmp = _subscriber.convertKnownThreadIdToInboxId(raw.threadId);
                if (tmp.has_value()) {
                    inboxId = tmp.value();
                } else {
                    inboxId = "";
                }
                auto data = InboxEntryDeletedEventData{.inboxId = inboxId, .entryId = raw.messageId};
                auto event = core::EventBuilder::buildEvent<InboxEntryDeletedEvent>(
                    "inbox/" + inboxId + "/entries", data, notification
                );
                _eventMiddleware->emitApiEvent(event);
            }
        } else if (type == "threadCollectionChanged") {
            auto raw = core::server::CollectionChangedEventData::fromJSON(notification.data);
            if (raw.containerType.value_or("") == INBOX_TYPE_FILTER_FLAG) {
                auto data = core::Mapper::mapToCollectionChangedEventData(INBOX_TYPE_FILTER_FLAG, raw);
                auto event = core::EventBuilder::buildEvent<core::CollectionChangedEvent>(
                    "inbox/collectionChanged", data, notification
                );
                auto tmp = _subscriber.convertKnownThreadIdToInboxId(event->data.moduleId);
                if (tmp.has_value()) {
                    event->data.moduleId = tmp.value();
                } else {
                    event->data.moduleId = "";
                }
                _eventMiddleware->emitApiEvent(event);
            }
        } else {
            LOG_ERROR("UNRESOLVED EVENT in CPP layer: '", type, "'");
        }
    });
}

void InboxApiImpl::processConnectedEvent() {
    invalidateModuleKeysInCache();
}

void InboxApiImpl::processDisconnectedEvent() {
    LOG_TRACE("InboxApiImpl recived DisconnectedEvent");
    invalidateModuleKeysInCache();
    privmx::utils::ManualManagedClass<InboxApiImpl>::cleanup();
}

InboxDeletedEventData InboxApiImpl::convertInboxDeletedEventData(server::InboxDeletedEventData data) {
    return InboxDeletedEventData{.inboxId = data.inboxId};
}

std::string InboxApiImpl::readInboxIdFromMessageKeyId(const std::string& keyId) {
    _messageKeyIdFormatValidator.assertKeyIdFormat(keyId);
    std::string trimmedKeyId = keyId.substr(1, keyId.size() - 2);
    std::vector<std::string> tmp = utils::Utils::split(trimmedKeyId, "-");
    return tmp[1];
}

std::string InboxApiImpl::readMessageIdFromFileKeyId(const std::string& keyId) {
    _fileKeyIdFormatValidator.assertKeyIdFormat(keyId);
    std::string trimmedKeyId = keyId.substr(1, keyId.size() - 2);
    std::vector<std::string> tmp = utils::Utils::split(trimmedKeyId, "-");
    return tmp[3];
}

void InboxApiImpl::deleteMessageAndFiles(thread::server::Message message) {
    auto publicMeta = InboxEntryDataSchemaMapper::unpackInboxOrigMessage(message.data);
    for (auto fileId : publicMeta.files) {
        _storeApi.deleteFile(fileId);
    }
    _threadApi.deleteMessage(message.id);
}

thread::server::Message InboxApiImpl::getServerMessage(const std::string& messageId) {
    thread::server::ThreadMessageGetModel model;
    model.messageId = messageId;
    return _serverApi->threadMessageGet(model).message;
}

core::ModuleKeys InboxApiImpl::getEntryDecryptionKeys(thread::server::Message message) {
    auto inboxId = readInboxIdFromMessageKeyId(message.keyId);
    auto inboxMessageServer = InboxEntryDataSchemaMapper::unpackInboxOrigMessage(message.data);
    auto msgData = inboxMessageServer.message;
    auto msgPublicData = _inboxEntryDataSchemaMapper.decryptPublicOnly(msgData);
    auto keyId = msgPublicData.usedInboxKeyId;
    return getModuleKeys(inboxId, std::set<std::string>{keyId}, inbox::InboxDataSchema::VERSION_4);
}

std::pair<core::ModuleKeys, int64_t> InboxApiImpl::getModuleKeysAndVersionFromServer(std::string moduleId) {
    auto inbox = getServerInbox(moduleId);
    _inboxDataSchemaMapper.assertDataIntegrity(inbox);
    return std::make_pair(inboxToModuleKeys(inbox), inbox.version);
}

core::ModuleKeys InboxApiImpl::inboxToModuleKeys(inbox::server::InboxInfo inbox) {
    return core::ModuleKeys{
        .keys = inbox.keys,
        .currentKeyId = inbox.keyId,
        .moduleSchemaVersion = _inboxDataSchemaMapper.getDataStructureVersion(inbox.data.back()),
        .moduleResourceId = inbox.resourceId.value_or(""),
        .contextId = inbox.contextId
    };
}

std::vector<std::string> InboxApiImpl::subscribeFor(const std::vector<std::string>& subscriptionQueries) {
    auto result = _subscriber.subscribeFor(subscriptionQueries);
    _eventMiddleware->notificationEventListenerAddSubscriptionIds(_notificationListenerId, result);
    return result;
}

void InboxApiImpl::unsubscribeFrom(const std::vector<std::string>& subscriptionIds) {
    _subscriber.unsubscribeFrom(subscriptionIds);
    _eventMiddleware->notificationEventListenerRemoveSubscriptionIds(_notificationListenerId, subscriptionIds);
}

std::string InboxApiImpl::buildSubscriptionQuery(
    EventType eventType,
    EventSelectorType selectorType,
    const std::string& selectorId
) {
    return SubscriberImpl::buildQuery(eventType, selectorType, selectorId);
}
