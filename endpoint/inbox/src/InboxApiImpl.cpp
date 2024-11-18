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

#include <privmx/utils/TypedObject.hpp>
#include <privmx/endpoint/core/EndpointUtils.hpp>
#include <privmx/endpoint/core/Exception.hpp>
#include <privmx/endpoint/core/ExceptionConverter.hpp>
#include <privmx/endpoint/thread/ServerTypes.hpp>
#include <privmx/endpoint/thread/ThreadApi.hpp>
#include <privmx/endpoint/store/FileHandle.hpp>
#include <privmx/endpoint/store/ChunkBufferedStream.hpp>
#include <privmx/endpoint/store/StoreApiImpl.hpp>
#include <privmx/endpoint/store/StoreException.hpp>
#include <privmx/endpoint/thread/ThreadApiImpl.hpp>

#include "privmx/endpoint/inbox/ServerTypes.hpp"
#include "privmx/endpoint/inbox/InboxApiImpl.hpp"
#include "privmx/endpoint/inbox/InboxException.hpp"
#include "privmx/endpoint/core/ListQueryMapper.hpp"
#include "privmx/endpoint/inbox/InboxDataHelper.hpp"


using namespace privmx::endpoint::inbox;
using namespace privmx::endpoint;
using namespace privmx::utils;
using namespace privmx;

const Poco::Int64 InboxApiImpl::_CHUNK_SIZE = 128 * 1024;

InboxApiImpl::InboxApiImpl(
    const thread::ThreadApi& threadApi,
    const store::StoreApi& storeApi,
    const std::shared_ptr<core::KeyProvider>& keyProvider,
    const std::shared_ptr<ServerApi>& serverApi,
    const std::shared_ptr<store::RequestApi>& requestApi,
    const std::string &host,
    const privmx::crypto::PrivateKey& userPrivKey,
    const std::shared_ptr<core::EventMiddleware>& eventMiddleware,
    const std::shared_ptr<core::EventChannelManager>& eventChannelManager,
    const std::shared_ptr<core::HandleManager>& handleManager,
    size_t serverRequestChunkSize
)
    : _threadApi(threadApi),
    _storeApi(storeApi),
    _keyProvider(keyProvider),
    _serverApi(serverApi),
    _requestApi(requestApi),
    _host(host),
    _userPrivKey(userPrivKey),
    _eventMiddleware(eventMiddleware),
    _handleManager(handleManager),
    _inboxHandleManager(InboxHandleManager(handleManager)),
    _messageKeyIdFormatValidator(MessageKeyIdFormatValidator()),
    _fileKeyIdFormatValidator(FileKeyIdFormatValidator()),
    _serverRequestChunkSize(serverRequestChunkSize),
    _inboxSubscriptionHelper(core::SubscriptionHelper(eventChannelManager, "inbox", "entries")),
    _threadSubscriptionHelper(core::SubscriptionHelperExt(eventChannelManager, "thread", "messages"))
{
    _notificationListenerId = _eventMiddleware->addNotificationEventListener(std::bind(&InboxApiImpl::processNotificationEvent, this, std::placeholders::_1, std::placeholders::_2, std::placeholders::_3));
    _connectedListenerId = _eventMiddleware->addConnectedEventListener(std::bind(&InboxApiImpl::processConnectedEvent, this));
    _disconnectedListenerId = _eventMiddleware->addDisconnectedEventListener(std::bind(&InboxApiImpl::processDisconnectedEvent, this));
}

InboxApiImpl::~InboxApiImpl() {
    _eventMiddleware->removeNotificationEventListener(_notificationListenerId);
    _eventMiddleware->removeConnectedEventListener(_connectedListenerId);
    _eventMiddleware->removeDisconnectedEventListener(_disconnectedListenerId);
}

std::string InboxApiImpl::createInbox(
    const std::string& contextId, const std::vector<core::UserWithPubKey>& users,
    const std::vector<core::UserWithPubKey>& managers, const core::Buffer& publicMeta, const core::Buffer& privateMeta,
    const std::optional<inbox::FilesConfig>& fileConfig,
    const std::optional<core::ContainerPolicyWithoutItem>& policies) {

    // prep keys
    auto inboxKey = _keyProvider->generateKey();
    auto eccKey = crypto::ECC::fromPrivateKey(inboxKey.key);
    auto privateKey = crypto::PrivateKey(eccKey);
    auto pubKey = privateKey.getPublicKey();

    // fill in data for server
    auto randName {InboxDataHelper::getRandomName()};
    auto randNameAsBuf {privmx::endpoint::core::Buffer::from(randName)};
    auto emptyBuf {privmx::endpoint::core::Buffer::from(std::string())};
    auto storeId = (_storeApi.getImpl())->createStoreEx(contextId, users, managers, emptyBuf, randNameAsBuf,  INBOX_TYPE_FILTER_FLAG, policies);
    auto threadId = (_threadApi.getImpl())->createThreadEx(contextId, users, managers, emptyBuf, randNameAsBuf, INBOX_TYPE_FILTER_FLAG, policies);

    InboxDataProcessorModel inboxDataIn {
        .storeId = storeId,
        .threadId = threadId,
        .filesConfig = getFilesConfigOptOrDefault(fileConfig),
        .privateData = {
            .privateMeta = privateMeta,
            .internalMeta = std::nullopt
        },
        .publicData = {
            .publicMeta = publicMeta,
            .inboxEntriesPubKeyBase58DER = pubKey.toBase58DER(),
            .inboxEntriesKeyId = inboxKey.id
        }
    };

    auto createInboxModel = Factory::createObject<inbox::server::InboxCreateModel>();
    createInboxModel.contextId(contextId);
    createInboxModel.users(InboxDataHelper::mapUsers(users));
    createInboxModel.managers(InboxDataHelper::mapUsers(managers));
    createInboxModel.data(_inboxDataProcessorV4.packForServer(inboxDataIn, _userPrivKey, inboxKey.key));
    
    // add current inbox key
    createInboxModel.keyId(inboxKey.id);
    auto all_users = core::EndpointUtils::uniqueListUserWithPubKey(users, managers);
    auto keysList = _keyProvider->prepareKeysList(all_users, inboxKey);
    createInboxModel.keys(keysList);
    if (policies.has_value()) {
        createInboxModel.policy(privmx::endpoint::core::Factory::createPolicyServerObject(policies.value()));
    }

    auto inboxId = _serverApi->inboxCreate(createInboxModel).inboxId();
    return inboxId;
}


void InboxApiImpl::updateInbox(
const std::string& inboxId, const std::vector<core::UserWithPubKey>& users,
                     const std::vector<core::UserWithPubKey>& managers,
                     const core::Buffer& publicMeta, const core::Buffer& privateMeta,
                     const std::optional<inbox::FilesConfig>& fileConfig, const int64_t version, const bool force,
                     const bool forceGenerateNewKey, const std::optional<core::ContainerPolicyWithoutItem>& policies
) {
    // get current inbox
    auto currentInbox = getInboxFromServerOrCache(inboxId);
    auto currentInboxReadable = decryptInbox(currentInbox);

    // extract current users info
    auto usersVec {core::EndpointUtils::listToVector<std::string>(currentInbox.users())};
    auto managersVec {core::EndpointUtils::listToVector<std::string>(currentInbox.managers())};
    auto oldUsersAll {core::EndpointUtils::uniqueList(usersVec, managersVec)};

    auto new_users = core::EndpointUtils::uniqueListUserWithPubKey(users, managers);

    // adjust key
    std::vector<std::string> usersDiff {core::EndpointUtils::getDifference(oldUsersAll, core::EndpointUtils::usersWithPubKeyToIds(new_users))};
    bool needNewKey = usersDiff.size() > 0;

    // key
    auto currentKey {_keyProvider->getKey(currentInbox.keys(), currentInbox.keyId())};
    auto inboxKey = forceGenerateNewKey || needNewKey ? _keyProvider->generateKey() : currentKey;

    auto keysList = _keyProvider->prepareKeysList(new_users, inboxKey);

    // prep keys
    auto eccKey = crypto::ECC::fromPrivateKey(inboxKey.key);
    auto privateKey = crypto::PrivateKey(eccKey);
    auto pubKey = privateKey.getPublicKey();

    InboxDataProcessorModel inboxDataIn {
        .storeId = currentInboxReadable.storeId,
        .threadId = currentInboxReadable.threadId,
        .filesConfig = getFilesConfigOptOrDefault(fileConfig),
        .privateData = {
            .privateMeta = privateMeta,
            .internalMeta = currentInboxReadable.privateData.internalMeta
        },
        .publicData = {
            .publicMeta = publicMeta,
            .inboxEntriesPubKeyBase58DER = pubKey.toBase58DER(),
            .inboxEntriesKeyId = inboxKey.id
        }
    };

    auto inboxUpdateModel = Factory::createObject<inbox::server::InboxUpdateModel>();
    inboxUpdateModel.id(inboxId);
    inboxUpdateModel.users(InboxDataHelper::mapUsers(users));
    inboxUpdateModel.managers(InboxDataHelper::mapUsers(managers));
    inboxUpdateModel.data(_inboxDataProcessorV4.packForServer(inboxDataIn, _userPrivKey, inboxKey.key));
    inboxUpdateModel.keyId(inboxKey.id);
    inboxUpdateModel.keys(keysList);
    inboxUpdateModel.force(force);
    inboxUpdateModel.version(version);

    if (policies.has_value()) {
        // strip policies item field for Inbox container itself
        auto policiesStripped = policies.value();
        policiesStripped.item = std::nullopt;
        inboxUpdateModel.policy(privmx::endpoint::core::Factory::createPolicyServerObject(policiesStripped));
    }

    _serverApi->inboxUpdate(inboxUpdateModel);

    auto store = (_storeApi.getImpl())->getStoreEx(currentInboxReadable.storeId, INBOX_TYPE_FILTER_FLAG);
    (_storeApi.getImpl())->updateStore(
        currentInboxReadable.storeId,
        users,
        managers,
        store.publicMeta,
        store.privateMeta,
        store.version,
        force,
        forceGenerateNewKey,
        policies
    );
    auto thread = (_threadApi.getImpl())->getThreadEx(currentInboxReadable.threadId, INBOX_TYPE_FILTER_FLAG);
    (_threadApi.getImpl())->updateThread(
        currentInboxReadable.threadId,
        users,
        managers,
        thread.publicMeta,
        thread.privateMeta,
        thread.version,
        force,
        forceGenerateNewKey,
        policies
    );
}


Inbox InboxApiImpl::getInbox(const std::string& inboxId) {
    return convertInbox(getInboxFromServerOrCache(inboxId));
}

core::PagingList<inbox::Inbox> InboxApiImpl::listInboxes(const std::string& contextId, const core::PagingQuery& query) {
    auto model = Factory::createObject<inbox::server::InboxListModel>();
    model.contextId(contextId);
    core::ListQueryMapper::map(model, query);

    auto inboxesListResult = _serverApi->inboxList(model);
    auto inboxesRaw = inboxesListResult.inboxes();
    std::vector<inbox::Inbox> ret;
    for (auto inboxRaw: inboxesRaw) {
        auto inbox = convertInbox(inboxRaw);
        ret.push_back(inbox);
    }
    return core::PagingList<Inbox> {
        .totalAvailable = inboxesListResult.count(),
        .readItems = ret
    };
}

InboxPublicView InboxApiImpl::getInboxPublicView(const std::string& inboxId) {
    auto publicData {getInboxPublicData(inboxId)};
    return inbox::InboxPublicView {
        .inboxId = publicData.inboxId,
        .version = publicData.version,
        .publicMeta = publicData.publicMeta
    };
}

void InboxApiImpl::deleteInbox(const std::string& inboxId) {
    auto inboxDataRaw {getInboxDataEntry(getInboxFromServerOrCache(inboxId)).data()};
    auto inboxDeleteModel = Factory::createObject<server::InboxDeleteModel>();
    inboxDeleteModel.inboxId(inboxId);

    _serverApi->inboxDelete(inboxDeleteModel);
    (_storeApi.getImpl())->deleteStore(inboxDataRaw.storeId());
    (_threadApi.getImpl())->deleteThread(inboxDataRaw.threadId()); 
}


int64_t InboxApiImpl::prepareEntry(
            const std::string& inboxId, 
            const core::Buffer& data,
            const std::vector<int64_t>& inboxFileHandles,
            const std::optional<std::string>& userPrivKey
    ) {

    //check if inbox exist
    auto inboxPublicData {getInboxPublicData(inboxId)};

    std::vector<std::shared_ptr<store::FileWriteHandle>> fileHandles;
    auto requestModel = Factory::createObject<store::server::CreateRequestModel>();
    auto filesList = Factory::createList<store::server::FileDefinition>();
    
    if(!inboxFileHandles.empty()) {
        for(auto inboxFileHandle: inboxFileHandles) {
            std::shared_ptr<store::FileWriteHandle> handle = _inboxHandleManager.getFileWriteHandle(inboxFileHandle);
            fileHandles.push_back(handle);

            auto fileSizeInfo = handle->getEncryptedFileSize();
            filesList.add(
                Factory::createStoreFileDefinition(fileSizeInfo.size, fileSizeInfo.checksumSize)
            );
        }
        requestModel.files(filesList);
        store::server::CreateRequestResult requestResult = _requestApi->createRequest(requestModel);
        for(size_t i = 0; i < fileHandles.size();i++) {
            std::string key = privmx::crypto::Crypto::randomBytes(32);
            fileHandles[i]->setRequestData(requestResult.id(), key, (i));
        }
    }
    int64_t id;
    std::shared_ptr<InboxHandle> handle;
    std::tie(id, handle) = _inboxHandleManager.createInboxHandle();
    handle->inboxId = inboxId;
    handle->data = data.stdString();
    handle->inboxFileHandles = inboxFileHandles;
    handle->userPrivKey = userPrivKey;
    return id;
}

void InboxApiImpl::sendEntry(const int64_t inboxHandle) {
    auto handle = _inboxHandleManager.getInboxHandle(inboxHandle);
    auto publicData {getInboxPublicData(handle->inboxId)};

    auto inboxPubKeyECC = privmx::crypto::PublicKey::fromBase58DER(publicData.inboxEntriesPubKeyBase58DER);// keys to encrypt message (generated or taken from param)
    auto _userPrivKeyECC = (handle->userPrivKey.has_value() ? privmx::crypto::PrivateKey::fromWIF(handle->userPrivKey.value()) : privmx::crypto::PrivateKey::generateRandom());
    auto _userPubKeyECC = _userPrivKey.getPublicKey();

    std::string filesMetaKey;
    bool hasFiles = !handle->inboxFileHandles.empty();
    filesMetaKey = (hasFiles ? crypto::Crypto::randomBytes(32) : std::string());

    InboxEntrySendModel modelForSerializer {
        .publicData = {
            .userPubKey = _userPubKeyECC.toBase58DER(),
            .keyPreset = handle->userPrivKey.has_value(),
            .usedInboxKeyId = publicData.inboxEntriesKeyId
        },
        .privateData = {
            .filesMetaKey = filesMetaKey,
            .text = handle->data
        }
    };

    auto inboxFiles = Factory::createList<inbox::server::InboxFile>();
    std::string requestId;

    if (hasFiles) {
        int fileIndex = -1;
        auto commitSentInfo = _inboxHandleManager.commitInboxHandle(inboxHandle);
        for (auto fileInfo : commitSentInfo.filesInfo) {
            fileIndex++;
            auto encryptedFileMeta = _fileMetaEncryptorV4.encrypt(prepareMeta(fileInfo), _userPrivKeyECC, filesMetaKey);
            inboxFiles.add(Factory::createInboxFile(fileIndex, encryptedFileMeta.asVar()));
        }
        requestId = commitSentInfo.filesInfo[0].fileSendResult.requestId;
    }

    auto serializer = InboxEntriesDataEncryptorSerializer::Ptr(new InboxEntriesDataEncryptorSerializer());
    auto serializedMessage = serializer->packMessage(modelForSerializer, _userPrivKeyECC, inboxPubKeyECC);

    // prepare server model
    auto model = Factory::createObject<inbox::server::InboxSendModel>();
    if (hasFiles) {
        model.requestId(requestId);
    }
    model.files(inboxFiles);
    model.inboxId(handle->inboxId);
    model.message(serializedMessage);
    model.version(1);
    _serverApi->inboxSend(model);
}

inbox::InboxEntry InboxApiImpl::readEntry(const std::string& inboxEntryId) {
    PRIVMX_DEBUG_TIME_START(InboxApi, readEntry)
    PRIVMX_DEBUG_TIME_CHECKPOINT(InboxApi, readEntry)
    auto messageRaw = getServerMessage(inboxEntryId);
    PRIVMX_DEBUG_TIME_CHECKPOINT(InboxApi, readEntry, data recv);
    auto inboxId {readInboxIdFromMessageKeyId(messageRaw.keyId())};
    auto inbox {getInboxFromServerOrCache(inboxId)};
    auto result = convertInboxEntry(inbox, messageRaw);
    PRIVMX_DEBUG_TIME_STOP(InboxApi, readEntry, data decrypted)
    return result;
}

core::PagingList<inbox::InboxEntry> InboxApiImpl::listEntries(const std::string& inboxId, const core::PagingQuery& query) {
    PRIVMX_DEBUG_TIME_START(InboxApi, listEntries)
    auto inboxRaw {getInboxFromServerOrCache(inboxId)};
    auto inboxData {getInboxDataEntry(inboxRaw).data()};
    auto threadId = inboxData.threadId();
    auto model = Factory::createObject<thread::server::ThreadMessagesGetModel>();
    model.threadId(threadId);
    core::ListQueryMapper::map(model, query);
    PRIVMX_DEBUG_TIME_CHECKPOINT(InboxApi, listEntries)
    auto messagesList = _serverApi->threadMessagesGet(model);
    PRIVMX_DEBUG_TIME_CHECKPOINT(InboxApi, listEntries, data recv)
    std::vector<inbox::InboxEntry> messages;
    if(messagesList.messages().size()>0) {
        auto inbox = getInboxFromServerOrCache(readInboxIdFromMessageKeyId(messagesList.messages().get(0).keyId()));
        for (auto message : messagesList.messages()) {
            messages.push_back(convertInboxEntry(inbox, message));
        }
    }
    PRIVMX_DEBUG_TIME_STOP(InboxApi, listEntries, data decrypted)
    return core::PagingList<inbox::InboxEntry> {
        .totalAvailable = messagesList.count(),
        .readItems = messages
    };
}

void InboxApiImpl::deleteEntry(const std::string& inboxEntryId) {
    auto messageRaw = getServerMessage(inboxEntryId);
    _messageKeyIdFormatValidator.assertKeyIdFormat(messageRaw.keyId());
    deleteMessageAndFiles(messageRaw);
}

int64_t InboxApiImpl::createFileHandle(const core::Buffer& publicMeta, const core::Buffer& privateMeta, const int64_t fileSize) {
    int64_t id;
    std::shared_ptr<store::FileWriteHandle> handle;
    std::tie(id, handle) = _inboxHandleManager.createFileWriteHandle(
        std::string(),
        std::string(),
        (uint64_t)fileSize,
        publicMeta,
        privateMeta,
        _CHUNK_SIZE,
        _serverRequestChunkSize,
        _requestApi
    );
    return id;
}

int64_t InboxApiImpl::createInboxFileHandleForRead(const privmx::endpoint::store::server::File& file) {
    PRIVMX_DEBUG_TIME_START(InboxApi, createInboxFileHandleForRead, handle_to_create)
    auto messageRaw = getServerMessage(readMessageIdFromFileKeyId(file.keyId()));

    auto inbox = getInboxFromServerOrCache(readInboxIdFromMessageKeyId(messageRaw.keyId()));

    auto messageData = decryptInboxEntry(inbox, messageRaw);
    auto decryptedFile = decryptInboxFileMetaV4(file, messageData.privateData.filesMetaKey);
    auto internalMeta = Factory::createObject<store::dynamic::InternalStoreFileMeta>(utils::Utils::parseJson(decryptedFile.internalMeta.stdString()));
    PRIVMX_DEBUG_TIME_CHECKPOINT(InboxApi, createInboxFileHandleForRead, file_key_extracted)
    int64_t id;
    std::shared_ptr<store::FileReadHandle> handle;
    if ((uint64_t)internalMeta.chunkSize() > SIZE_MAX) {
        throw NumberToBigForCPUArchitectureException("chunkSize to big for this CPU architecture");
    }
    std::tie(id, handle) = _inboxHandleManager.createFileReadHandle(
        file.id(), 
        (uint64_t)internalMeta.size(),
        (uint64_t)file.size(),
        (size_t)internalMeta.chunkSize(),
        _serverRequestChunkSize,
        file.version(),
        privmx::utils::Base64::toString(internalMeta.key()),
        privmx::utils::Base64::toString(internalMeta.hmac()),
        _serverApi
    );
    PRIVMX_DEBUG_TIME_STOP(InboxApi, createInboxFileHandleForRead, handle_created)
    return id;    
}

void InboxApiImpl::writeToFile(const int64_t inboxHandle, const int64_t inboxFileHandle, const core::Buffer& dataChunk) {
    if(_inboxHandleManager.getInboxHandle(inboxHandle)->inboxFileHandles.empty()) {
        throw InboxHandleIsNotTiedToInboxFileHandleException();
    }
    std::shared_ptr<store::FileWriteHandle> handle = _inboxHandleManager.getFileWriteHandle(inboxFileHandle);
    handle->write(dataChunk.stdString());
}

int64_t InboxApiImpl::openFile(const std::string& fileId) {
    PRIVMX_DEBUG_TIME_START(InboxApi, openFile)
    auto file {_serverApi->storeFileGet(Factory::createStoreFileGetModel(fileId)).file()};
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
    } catch(const store::FileVersionMismatchException& e) {
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
    std::shared_ptr<store::FileHandle> handlePtr = _inboxHandleManager.getFileReadHandle(handle);
    _inboxHandleManager.removeFileReadHandle(handle);
    PRIVMX_DEBUG_TIME_STOP(InboxApi, closeFile)
    return handlePtr->getFileId();
}

store::FileMetaToEncrypt InboxApiImpl::prepareMeta(const privmx::endpoint::inbox::CommitFileInfo& commitFileInfo) {
    auto internalFileMeta = Factory::createObject<store::dynamic::InternalStoreFileMeta>();
    internalFileMeta.version(4);
    internalFileMeta.size(commitFileInfo.size);
    internalFileMeta.cipherType(commitFileInfo.fileSendResult.cipherType);
    internalFileMeta.chunkSize(commitFileInfo.fileSendResult.chunkSize);
    internalFileMeta.key(utils::Base64::from(commitFileInfo.fileSendResult.key));
    internalFileMeta.hmac(utils::Base64::from(commitFileInfo.fileSendResult.hmac));
    store::FileMetaToEncrypt fileMetaToEncrypt = {
        .publicMeta = commitFileInfo.publicMeta,
        .privateMeta = commitFileInfo.privateMeta,
        .fileSize = commitFileInfo.size,
        .internalMeta = core::Buffer::from(utils::Utils::stringifyVar(internalFileMeta.asVar()))
    };
    return fileMetaToEncrypt;
}

inbox::server::InboxDataEntry InboxApiImpl::getInboxDataEntry(const inbox::server::Inbox& inboxRaw) {
    auto dataEntry = inboxRaw.data().get(inboxRaw.data().size()-1);
    return dataEntry;
}


InboxDataResult InboxApiImpl::decryptInbox(const inbox::server::Inbox& inboxRaw) {
    auto inboxDataEntry {getInboxDataEntry(inboxRaw)};
    return _inboxDataProcessorV4.unpackAll(inboxDataEntry.data(), _keyProvider->getKey(inboxRaw.keys(), inboxDataEntry.keyId()).key);
}

InboxPublicViewAsResult InboxApiImpl::getInboxPublicData(const std::string& inboxId) {
    auto model = Factory::createObject<inbox::server::InboxGetModel>();
    model.id(inboxId);
    auto publicView = _serverApi->inboxGetPublicView(model);
    auto publicData {_inboxDataProcessorV4.unpackPublicOnly(publicView.publicData())};
    
    InboxPublicViewAsResult result;
    result.inboxId = publicView.inboxId();
    result.version = publicView.version();
    result.authorPubKey = publicData.authorPubKey;
    result.inboxEntriesPubKeyBase58DER = publicData.inboxEntriesPubKeyBase58DER;
    result.inboxEntriesKeyId = publicData.inboxEntriesKeyId;
    result.publicMeta = publicData.publicMeta;
    result.statusCode = publicData.statusCode;
    return result;
}

Inbox InboxApiImpl::convertInbox(const inbox::server::Inbox& inboxRaw) {
    auto inboxData = decryptInbox(inboxRaw);
    inbox::Inbox ret {
        .inboxId = inboxRaw.id(),
        .contextId = inboxRaw.contextId(),
        .createDate = inboxRaw.createDate(),
        .creator = inboxRaw.creator(),
        .lastModificationDate = inboxRaw.lastModificationDate(),
        .lastModifier = inboxRaw.lastModifier(),
        .users = listToVector<std::string>(inboxRaw.users()),
        .managers = listToVector<std::string>(inboxRaw.managers()),
        .version = inboxRaw.version(),
        .publicMeta = inboxData.publicData.publicMeta,
        .privateMeta = inboxData.privateData.privateMeta,
        .filesConfig = inboxData.filesConfig,
        .policy = core::Factory::parsePolicyServerObject(inboxRaw.policy()),
        .statusCode = inboxData.statusCode
    };
    return ret;
}

inbox::server::InboxMessageServer InboxApiImpl::unpackInboxOrigMessage(const std::string& serialized) {
    auto message = Factory::createObject<inbox::server::InboxMessageServer>();
    try {
        auto json = utils::Base64::toString(serialized);
        Poco::JSON::Parser parser;
        message = Factory::createObject<inbox::server::InboxMessageServer>(
                parser.parse(json).extract<Poco::JSON::Object::Ptr>()
        );
    } catch (...) {
        throw FailedToExtractMessagePublicMetaException();
    }
    return message;
}

InboxEntryResult InboxApiImpl::decryptInboxEntry(const privmx::endpoint::inbox::server::Inbox& inbox, const thread::server::Message& message) {
    InboxEntryResult result;
    result.statusCode = 0;
    try {
        auto inboxMessageServer = unpackInboxOrigMessage(message.data());
        auto msgData = inboxMessageServer.message();

        auto serializer = inbox::InboxEntriesDataEncryptorSerializer::Ptr(new inbox::InboxEntriesDataEncryptorSerializer());
        auto msgPublicData = serializer->unpackMessagePublicOnly(msgData);
        
        auto encKey = _keyProvider->getKey(inbox.keys(), msgPublicData.usedInboxKeyId);
        auto eccKey = crypto::ECC::fromPrivateKey(encKey.key);
        auto privKeyECC = crypto::PrivateKey(eccKey);
        auto decrypted = serializer->unpackMessage(msgData, privKeyECC);

        result.publicData = decrypted.publicData;
        result.privateData = decrypted.privateData;
        result.storeId = inboxMessageServer.store();
        result.filesIds = getFilesIdsFromServerMessage(inboxMessageServer);
        return result;
    } catch (const privmx::endpoint::core::Exception& e) {
        return getEmptyResultWithStatusCode(e.getCode());
    } catch (const privmx::utils::PrivmxException& e) {
        return getEmptyResultWithStatusCode(core::ExceptionConverter::convert(e).getCode());
    } catch (...) {
        return getEmptyResultWithStatusCode(ENDPOINT_CORE_EXCEPTION_CODE);
    }
}

InboxEntryResult InboxApiImpl::getEmptyResultWithStatusCode(const int64_t statusCode) {
    InboxEntryResult result;
    result.statusCode = statusCode;
    return result;
}

std::vector<std::string> InboxApiImpl::getFilesIdsFromServerMessage(const privmx::endpoint::inbox::server::InboxMessageServer& serverMessage) {
    if (serverMessage.filesEmpty()) {
        return {};
    }
    return listToVector<std::string>(serverMessage.files());
}

inbox::InboxEntry InboxApiImpl::convertInboxEntry(const privmx::endpoint::inbox::server::Inbox& inbox, const thread::server::Message& message) {
    inbox::InboxEntry result;
    result.entryId = message.id();
    result.inboxId = inbox.id();
    result.createDate = message.createDate();
    auto inboxEntry {decryptInboxEntry(inbox, message)};
    std::string filesMetaKey = inboxEntry.privateData.filesMetaKey;
    result.data = core::Buffer::from(inboxEntry.privateData.text);
    result.authorPubKey = inboxEntry.publicData.userPubKey;
    result.statusCode = inboxEntry.statusCode;
    if(inboxEntry.statusCode == 0) {
        try {
            auto filesGetModel {Factory::createStoreFileGetManyModel(inboxEntry.storeId, inboxEntry.filesIds, false)};
            auto serverFiles {_serverApi->storeFileGetMany(filesGetModel)};
            for (auto file : serverFiles.files()) {
                if(file.errorEmpty()) {
                    result.files.push_back(decryptAndConvertFileDataToFileInfo(file, filesMetaKey));
                } else {
                    store::File error;
                    auto e = FileFetchFailedException();
                    error.statusCode = e.getCode();
                    result.files.push_back(error);
                }
            }
        } catch (const privmx::endpoint::core::Exception& e) {
            result.statusCode = e.getCode();
        } catch (const privmx::utils::PrivmxException& e) {
            result.statusCode = core::ExceptionConverter::convert(e).getCode();
        } catch (...) {
            result.statusCode = ENDPOINT_CORE_EXCEPTION_CODE;
        }   
    }
    return result;
}

inbox::FilesConfig InboxApiImpl::getFilesConfigOptOrDefault(const std::optional<inbox::FilesConfig>& fileConfig) {
    inbox::FilesConfig _fileConfig;
    if (fileConfig.has_value()) {
        _fileConfig = fileConfig.value();
    } else {
        // default fileconfig
        int maxFiles = 10;
        int maxFileSize = 100 * 1024 * 1024;
        _fileConfig = {.minCount = 0, .maxCount = maxFiles, .maxFileSize = maxFileSize, .maxWholeUploadSize = maxFiles * maxFileSize};
    }
    return _fileConfig;
}

void InboxApiImpl::processNotificationEvent(const std::string& type, [[maybe_unused]] const std::string& channel, const Poco::JSON::Object::Ptr& data) {
    if(_inboxSubscriptionHelper.hasSubscriptionForModule()) {
        if (type == "inboxCreated") {
            auto raw = Factory::createObject<server::Inbox>(data);
            auto data = convertInbox(raw);
            std::shared_ptr<InboxCreatedEvent> event(new InboxCreatedEvent());
            event->channel = "inbox";
            event->data = data;
            _eventMiddleware->emitApiEvent(event);
        } else if (type == "inboxUpdated") {
            auto raw = Factory::createObject<server::Inbox>(data);
            auto data = convertInbox(raw);
            std::shared_ptr<InboxUpdatedEvent> event(new InboxUpdatedEvent());
            event->channel = "inbox";
            event->data = data;
            _eventMiddleware->emitApiEvent(event);
        } else if (type == "inboxDeleted") {
            auto raw = Factory::createObject<server::InboxDeletedEventData>(data);
            auto data = convertInboxDeletedEventData(raw);
            std::shared_ptr<InboxDeletedEvent> event(new InboxDeletedEvent());
            event->channel = "inbox";
            event->data = data;
            _eventMiddleware->emitApiEvent(event);
        }
    }
    if (type == "threadNewMessage") {
        auto raw = Factory::createObject<privmx::endpoint::thread::server::Message>(data); 
        if(_threadSubscriptionHelper.hasSubscriptionForElement(raw.threadId())) {
            auto inbox = getInboxFromServerOrCache(readInboxIdFromMessageKeyId(raw.keyId()));
            auto message = convertInboxEntry(inbox, raw);
            std::shared_ptr<InboxEntryCreatedEvent> event(new InboxEntryCreatedEvent());
            event->channel = "inbox/" + inbox.id() + "/entries";
            event->data = message;
            _eventMiddleware->emitApiEvent(event);
        }
    }
    if (type == "threadDeletedMessage") {
        auto raw = Factory::createObject<privmx::endpoint::thread::server::ThreadDeletedMessageEventData>(data); 
        if(_threadSubscriptionHelper.hasSubscriptionForElement(raw.threadId())) {
            auto inboxId = _threadSubscriptionHelper.getParentModuleId(raw.threadId());
            std::shared_ptr<InboxEntryDeletedEvent> event(new InboxEntryDeletedEvent());
            event->channel = "inbox/" + inboxId + "/entries";
            event->data = {
                .inboxId = inboxId,
                .entryId = raw.messageId()
            };
            _eventMiddleware->emitApiEvent(event);
        }
    }
}

void InboxApiImpl::subscribeForInboxEvents() {
    if(_inboxSubscriptionHelper.hasSubscriptionForModule()) {
        throw AlreadySubscribedException();
    }
    _inboxSubscriptionHelper.subscribeForModule();
}

void InboxApiImpl::unsubscribeFromInboxEvents() {
    if(!_inboxSubscriptionHelper.hasSubscriptionForModule()) {
        throw NotSubscribedException();
    }
    _inboxSubscriptionHelper.unsubscribeFromModule();
}

void InboxApiImpl::subscribeForEntryEvents(const std::string &inboxId) {
    auto inbox = getInboxFromServerOrCache(inboxId);
    auto inboxData = getInboxDataEntry(inbox).data();
    if(_threadSubscriptionHelper.hasSubscriptionForElement(inboxData.threadId())) {
        throw AlreadySubscribedException(inboxId);
    }
    _threadSubscriptionHelper.subscribeForElement(inboxData.threadId(), inboxId);
}

void InboxApiImpl::unsubscribeFromEntryEvents(const std::string& inboxId) {
    auto inbox = getInboxFromServerOrCache(inboxId);
    auto inboxData = getInboxDataEntry(inbox).data();
    if(!_threadSubscriptionHelper.hasSubscriptionForElement(inboxData.threadId())) {
        throw NotSubscribedException(inboxId);
    }
    _threadSubscriptionHelper.unsubscribeFromElement(inboxData.threadId());
}

void InboxApiImpl::processConnectedEvent() {
//    _storeMap.clear();
}

void InboxApiImpl::processDisconnectedEvent() {
//    _storeMap.clear();
}

InboxDeletedEventData InboxApiImpl::convertInboxDeletedEventData(const server::InboxDeletedEventData& data) {
    return InboxDeletedEventData {
       .inboxId = data.inboxId()
   };
}

store::File InboxApiImpl::decryptAndConvertFileDataToFileInfo(const store::server::File& file, const std::string& filesMetaKey) {
    return tryDecryptAndConvertFileV4(file, filesMetaKey);
}

store::File InboxApiImpl::convertFileV4(const store::server::File& file, const store::DecryptedFileMeta& decryptedFileMeta) {
    return store::File {
        .info = {
            .storeId = file.storeId(),
            .fileId = file.id(),
            .createDate = file.created(),
            .author = file.creator()
        },
        .publicMeta = decryptedFileMeta.publicMeta,
        .privateMeta = decryptedFileMeta.privateMeta,
        .size = decryptedFileMeta.fileSize,
        .authorPubKey = decryptedFileMeta.authorPubKey,
        .statusCode = 0
    };
}

store::File InboxApiImpl::tryDecryptAndConvertFileV4(const store::server::File& file, const std::string& filesMetaKey) {
    store::File result;
    try {
        return convertFileV4(file, decryptInboxFileMetaV4(file, filesMetaKey));
    } catch (const privmx::endpoint::core::Exception& e) {
        result.statusCode = e.getCode();
    } catch (const privmx::utils::PrivmxException& e) {
        result.statusCode = core::ExceptionConverter::convert(e).getCode();
    } catch (...) {
        result.statusCode = ENDPOINT_CORE_EXCEPTION_CODE;
    }
    return result;    
}

store::DecryptedFileMeta InboxApiImpl::decryptInboxFileMetaV4(const store::server::File& file, const std::string& filesMetaKey) {
    if (file.meta().isString()) {
        throw FailedToDecryptFileMetaException(); // TODO
    }
    auto encryptedFileMeta = Factory::createObject<store::server::EncryptedFileMetaV4>(file.meta());
    return _fileMetaEncryptorV4.decrypt(encryptedFileMeta, filesMetaKey);
}

std::string InboxApiImpl::readInboxIdFromMessageKeyId(const std::string& keyId) {
    _messageKeyIdFormatValidator.assertKeyIdFormat(keyId);
    std::string trimmedKeyId = keyId.substr(1, keyId.size() - 2);
    return utils::Utils::splitStringByCharacter(trimmedKeyId, '-')[1];
}

std::string InboxApiImpl::readMessageIdFromFileKeyId(const std::string& keyId) {
    _fileKeyIdFormatValidator.assertKeyIdFormat(keyId);
    std::string trimmedKeyId = keyId.substr(1, keyId.size() - 2);
    return utils::Utils::splitStringByCharacter(trimmedKeyId, '-')[3];
}

void InboxApiImpl::deleteMessageAndFiles(const thread::server::Message& message) {
    auto publicMeta = unpackInboxOrigMessage(message.data());
    for(auto fileId : publicMeta.files()) {
        _storeApi.deleteFile(fileId);
    }
    _threadApi.deleteMessage(message.id());
}

inbox::server::Inbox InboxApiImpl::getInboxFromServerOrCache(const std::string& inboxId) {
    auto inboxGetModel = Factory::createObject<inbox::server::InboxGetModel>();
    inboxGetModel.id(inboxId);
    return _serverApi->inboxGet(inboxGetModel).inbox();
}

thread::server::Message InboxApiImpl::getServerMessage(const std::string& messageId) {
    auto model = Factory::createObject<thread::server::ThreadMessageGetModel>();
    model.messageId(messageId);
    return _serverApi->threadMessageGet(model).message();
}