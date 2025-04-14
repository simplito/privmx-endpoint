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
#include <privmx/endpoint/core/TimestampValidator.hpp>
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
    const core::Connection& connection,
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
    : _connection(connection),
    _threadApi(threadApi),
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
    _inboxProvider(InboxProvider(
        [&](const std::string& id) {
            auto model = Factory::createObject<server::InboxGetModel>();
            model.id(id);
            return _serverApi->inboxGet(model).inbox();
        },
        std::bind(&InboxApiImpl::validateInboxDataIntegrity, this, std::placeholders::_1)
    )),
    _subscribeForInbox(false),
    _serverRequestChunkSize(serverRequestChunkSize),
    _inboxSubscriptionHelper(core::SubscriptionHelper(eventChannelManager, "inbox", "entries")),
    _threadSubscriptionHelper(core::SubscriptionHelperExt(eventChannelManager, "thread", "messages")),
    _forbiddenChannelsNames({INTERNAL_EVENT_CHANNEL_NAME, "inbox", "entries"}) 
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

    std::optional<core::ContainerPolicy> policiesWithItems { policies.has_value() ? std::make_optional<core::ContainerPolicy>({policies.value(), std::nullopt}) : std::nullopt};

    auto storeId = (_storeApi.getImpl())->createStoreEx(contextId, users, managers, emptyBuf, randNameAsBuf,  INBOX_TYPE_FILTER_FLAG, policiesWithItems);
    auto threadId = (_threadApi.getImpl())->createThreadEx(contextId, users, managers, emptyBuf, randNameAsBuf, INBOX_TYPE_FILTER_FLAG, policiesWithItems);
    auto inboxId = core::EndpointUtils::generateId();
    auto inboxDIO = _connection.getImpl()->createDIOForNewContainer(
        contextId,
        inboxId
    );
    auto inboxCCN = _keyProvider->generateContainerControlNumber();
    InboxDataProcessorModelV5 inboxDataIn {
        .storeId = storeId,
        .threadId = threadId,
        .filesConfig = getFilesConfigOptOrDefault(fileConfig),
        .privateData = {
            .privateMeta = privateMeta,
            .internalMeta = core::Buffer::from(inboxCCN),
            .dio = inboxDIO
        },
        .publicData = {
            .publicMeta = publicMeta,
            .inboxEntriesPubKeyBase58DER = pubKey.toBase58DER(),
            .inboxEntriesKeyId = inboxKey.id
        }
    };

    auto createInboxModel = Factory::createObject<inbox::server::InboxCreateModel>();
    createInboxModel.inboxId(inboxId);
    createInboxModel.contextId(contextId);
    createInboxModel.users(InboxDataHelper::mapUsers(users));
    createInboxModel.managers(InboxDataHelper::mapUsers(managers));
    createInboxModel.data(_inboxDataProcessorV5.packForServer(inboxDataIn, _userPrivKey, inboxKey.key));
    
    // add current inbox key
    createInboxModel.keyId(inboxKey.id);
    auto all_users = core::EndpointUtils::uniqueListUserWithPubKey(users, managers);
    auto keysList = _keyProvider->prepareKeysList(
        all_users, 
        inboxKey, 
        inboxDIO,
        inboxCCN
    );
    createInboxModel.keys(keysList);
    if (policies.has_value()) {
        createInboxModel.policy(privmx::endpoint::core::Factory::createPolicyServerObject(policiesWithItems.value()));
    }

    auto result = _serverApi->inboxCreate(createInboxModel);
    return result.inboxId();
}


void InboxApiImpl::updateInbox(
const std::string& inboxId, const std::vector<core::UserWithPubKey>& users,
                     const std::vector<core::UserWithPubKey>& managers,
                     const core::Buffer& publicMeta, const core::Buffer& privateMeta,
                     const std::optional<inbox::FilesConfig>& fileConfig, const int64_t version, const bool force,
                     const bool forceGenerateNewKey, const std::optional<core::ContainerPolicyWithoutItem>& policies
) {
    // get current inbox
    auto currentInbox = getRawInboxFromCacheOrBridge(inboxId);
    auto currentInboxData = getInboxCurrentDataEntry(currentInbox).data();

    // extract current users info
    auto usersVec {core::EndpointUtils::listToVector<std::string>(currentInbox.users())};
    auto managersVec {core::EndpointUtils::listToVector<std::string>(currentInbox.managers())};
    auto oldUsersAll {core::EndpointUtils::uniqueList(usersVec, managersVec)};

    auto new_users = core::EndpointUtils::uniqueListUserWithPubKey(users, managers);

    // adjust key
    std::vector<std::string> deletedUsers {core::EndpointUtils::getDifference(oldUsersAll, core::EndpointUtils::usersWithPubKeyToIds(new_users))};
    std::vector<std::string> addedUsers {core::EndpointUtils::getDifference(core::EndpointUtils::usersWithPubKeyToIds(new_users), oldUsersAll)};
    std::vector<core::UserWithPubKey> usersToAddMissingKey;
    for(auto new_user: new_users) {
        if( std::find(addedUsers.begin(), addedUsers.end(), new_user.userId) != addedUsers.end()) {
            usersToAddMissingKey.push_back(new_user);
        }
    }
    bool needNewKey = deletedUsers.size() > 0 || forceGenerateNewKey;
    
    // read all key to check if all key belongs to this inbox
    core::KeyDecryptionAndVerificationRequest keyProviderRequest;
    core::EncKeyLocation location{.contextId=currentInbox.contextId(), .containerId=inboxId};
    keyProviderRequest.addAll(currentInbox.keys(), location);
    auto inboxKeys {_keyProvider->getKeysAndVerify(keyProviderRequest).at(location)};
    auto currentInboxEntry = currentInbox.data().get(currentInbox.data().size()-1);
    core::DecryptedEncKey currentInboxKey;
    for (auto key : inboxKeys) {
        if (currentInboxEntry.keyId() == key.first) {
            currentInboxKey = key.second;
            break;
        }
    }
    auto inboxCCN = decryptInboxInternalMeta(currentInboxEntry, currentInboxKey);
    for(auto key : inboxKeys) {
        if(key.second.statusCode != 0 || (key.second.dataStructureVersion == 2 && key.second.containerControlNumber != inboxCCN)) {
            throw InboxEncryptionKeyValidationException();
        }
    }
    
    // setting inbox Key adding new users
    core::EncKey inboxKey = currentInboxKey;
    core::DataIntegrityObject updateInboxDio = _connection.getImpl()->createDIO(currentInbox.contextId(), inboxId);
    privmx::utils::List<core::server::KeyEntrySet> keysList = utils::TypedObjectFactory::createNewList<core::server::KeyEntrySet>();
    if(needNewKey) {
        inboxKey = _keyProvider->generateKey();
        keysList = _keyProvider->prepareKeysList(
            new_users, 
            inboxKey, 
            updateInboxDio,
            inboxCCN
        );
    }
    if(usersToAddMissingKey.size() > 0) {
        auto tmp = _keyProvider->prepareMissingKeysForNewUsers(
            inboxKeys,
            usersToAddMissingKey, 
            updateInboxDio, 
            inboxCCN
        );
        for(auto t: tmp) keysList.add(t);
    }

    // prep keys
    auto eccKey = crypto::ECC::fromPrivateKey(inboxKey.key);
    auto privateKey = crypto::PrivateKey(eccKey);
    auto pubKey = privateKey.getPublicKey();
    InboxDataProcessorModelV5 inboxDataIn {
        .storeId = currentInboxData.storeId(),
        .threadId = currentInboxData.threadId(),
        .filesConfig = getFilesConfigOptOrDefault(fileConfig),
        .privateData = {
            .privateMeta = privateMeta,
            .internalMeta = core::Buffer::from(inboxCCN),
            .dio = updateInboxDio
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
    inboxUpdateModel.data(_inboxDataProcessorV5.packForServer(inboxDataIn, _userPrivKey, inboxKey.key));
    inboxUpdateModel.keyId(inboxKey.id);
    inboxUpdateModel.keys(keysList);
    inboxUpdateModel.force(force);
    inboxUpdateModel.version(version);

    std::optional<core::ContainerPolicy> policiesWithItems { policies.has_value() ? std::make_optional<core::ContainerPolicy>({policies.value(), std::nullopt}) : std::nullopt};

    if (policies.has_value()) {
        inboxUpdateModel.policy(privmx::endpoint::core::Factory::createPolicyServerObject(policies.value()));
    }

    _serverApi->inboxUpdate(inboxUpdateModel);

    auto store = (_storeApi.getImpl())->getStoreEx(currentInboxData.storeId(), INBOX_TYPE_FILTER_FLAG);
    (_storeApi.getImpl())->updateStore(
        currentInboxData.storeId(),
        users,
        managers,
        store.publicMeta,
        store.privateMeta,
        store.version,
        force,
        forceGenerateNewKey,
        policiesWithItems
    );
    auto thread = (_threadApi.getImpl())->getThreadEx(currentInboxData.threadId(), INBOX_TYPE_FILTER_FLAG);
    (_threadApi.getImpl())->updateThread(
        currentInboxData.threadId(),
        users,
        managers,
        thread.publicMeta,
        thread.privateMeta,
        thread.version,
        force,
        forceGenerateNewKey,
        policiesWithItems
    );
}

Inbox InboxApiImpl::getInbox(const std::string& inboxId) {
    return _getInboxEx(inboxId, std::string());
}

Inbox InboxApiImpl::getInboxEx(const std::string& inboxId, const std::string& type) {
    return _getInboxEx(inboxId, type);
}

Inbox InboxApiImpl::_getInboxEx(const std::string& inboxId, const std::string& type) {
    PRIVMX_DEBUG_TIME_START(PlatformInbox, _getInboxEx)
    auto model = Factory::createObject<server::InboxGetModel>();
    model.id(inboxId);
    if (type.length() > 0) {
        model.type(type);
    }
    PRIVMX_DEBUG_TIME_CHECKPOINT(PlatformInbox, _getInboxEx, getting inbox)
    auto inbox = _serverApi->inboxGet(model).inbox();
    PRIVMX_DEBUG_TIME_CHECKPOINT(PlatformInbox, _getInboxEx, data send)
    _inboxProvider.updateByValue(inbox);
    auto statusCode = validateInboxDataIntegrity(inbox);
    if(statusCode != 0) {
        _inboxProvider.updateByValueAndStatus(privmx::endpoint::inbox::InboxProvider::ContainerInfo{.container=inbox, .status=core::DataIntegrityStatus::ValidationFailed});
        return Inbox{ {},{},{},{},{},{},{},{},{},{},{},{},{}, .statusCode = statusCode};
    } else {
        _inboxProvider.updateByValueAndStatus(privmx::endpoint::inbox::InboxProvider::ContainerInfo{.container=inbox, .status=core::DataIntegrityStatus::ValidationSucceed});
    }
    auto result = decryptAndConvertInboxDataToInbox(inbox);
    PRIVMX_DEBUG_TIME_STOP(PlatformInbox, _getInboxEx, data decrypted)
    return result;
}

core::PagingList<inbox::Inbox> InboxApiImpl::listInboxes(const std::string& contextId, const core::PagingQuery& query) {
    if(query.queryAsJson.has_value()) {
        throw InboxModuleDoesNotSupportQueriesYetException();
    }
    auto model = Factory::createObject<inbox::server::InboxListModel>();
    model.contextId(contextId);
    core::ListQueryMapper::map(model, query);

    auto inboxesListResult = _serverApi->inboxList(model);
    auto inboxesRaw = inboxesListResult.inboxes();
    std::vector<inbox::Inbox> inboxes;
    for (size_t i = 0; i < inboxesRaw.size(); i++) {
        auto inbox = inboxesRaw.get(i);
        _inboxProvider.updateByValue(inbox);
        auto statusCode = validateInboxDataIntegrity(inbox);
        inboxes.push_back(Inbox{ {},{},{},{},{},{},{},{},{},{},{},{},{}, .statusCode = statusCode});
        if(statusCode == 0) {
            _inboxProvider.updateByValueAndStatus(InboxProvider::ContainerInfo{.container=inbox, .status=core::DataIntegrityStatus::ValidationSucceed});
        } else {
            _inboxProvider.updateByValueAndStatus(InboxProvider::ContainerInfo{.container=inbox, .status=core::DataIntegrityStatus::ValidationFailed});
            inboxesRaw.remove(i);
            i--;
        }
    }
    auto tmp = decryptAndConvertInboxesDataToInboxes(inboxesRaw);
    for(size_t j = 0, i = 0; i < inboxes.size(); i++) {
        if(inboxes[i].statusCode == 0) {
            inboxes[i] = tmp[j];
            j++;
        }
    }
    return core::PagingList<inbox::Inbox>({
        .totalAvailable = inboxesListResult.count(),
        .readItems = inboxes
    });
}

InboxPublicView InboxApiImpl::getInboxPublicView(const std::string& inboxId) {
    auto publicData {getInboxPublicViewData(inboxId)};
    return inbox::InboxPublicView {
        .inboxId = publicData.inboxId,
        .version = publicData.version,
        .publicMeta = publicData.publicMeta
    };
}

void InboxApiImpl::deleteInbox(const std::string& inboxId) {
    auto inboxDataRaw {getInboxCurrentDataEntry(getRawInboxFromCacheOrBridge(inboxId)).data()};
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
    auto inboxPublicData {getInboxPublicViewData(inboxId)};
    if(!inboxFileHandles.empty()) {
        std::vector<std::shared_ptr<store::FileWriteHandle>> fileHandles;
        auto filesList = Factory::createList<store::server::FileDefinition>();
        for(auto inboxFileHandle: inboxFileHandles) {
            std::shared_ptr<store::FileWriteHandle> handle = _inboxHandleManager.getFileWriteHandle(inboxFileHandle);
            fileHandles.push_back(handle);

            auto fileSizeInfo = handle->getEncryptedFileSize();
            filesList.add(
                Factory::createStoreFileDefinition(fileSizeInfo.size, fileSizeInfo.checksumSize)
            );
        }
        auto requestModel = Factory::createObject<store::server::CreateRequestModel>();
        requestModel.files(filesList);
        store::server::CreateRequestResult requestResult = _requestApi->createRequest(requestModel);
        for(size_t i = 0; i < fileHandles.size();i++) {
            std::string key = privmx::crypto::Crypto::randomBytes(32);
            fileHandles[i]->setRequestData(requestResult.id(), key, (i));
        }
    }
    std::shared_ptr<InboxHandle> handle = _inboxHandleManager.createInboxHandle(inboxId, data.stdString(), inboxFileHandles, userPrivKey);
    return handle->id;
}

void InboxApiImpl::sendEntry(const int64_t inboxHandle) {
    auto handle = _inboxHandleManager.getInboxHandle(inboxHandle);
    auto publicData {getInboxPublicViewData(handle->inboxId)};

    auto inboxPubKeyECC = privmx::crypto::PublicKey::fromBase58DER(publicData.inboxEntriesPubKeyBase58DER);// keys to encrypt message (generated or taken from param)
    auto _userPrivKeyECC = (handle->userPrivKey.has_value() ? privmx::crypto::PrivateKey::fromWIF(handle->userPrivKey.value()) : _userPrivKey);
    auto _userPubKeyECC = _userPrivKeyECC.getPublicKey();
    auto inboxDIO = _connection.getImpl()->createPublicDIO(
        "",
        handle->inboxId,
        std::nullopt,
        _userPrivKeyECC.getPublicKey()
    );
    //update Key
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
        CommitSendInfo commitSentInfo;
        try {
            commitSentInfo = _inboxHandleManager.commitInboxHandle(inboxHandle);
        } catch (const core::DataDifferentThanDeclaredException& e) {
            _inboxHandleManager.abortInboxHandle(inboxHandle);
            throw WritingToEntryInteruptedWrittenDataSmallerThenDeclaredException();
        }
        for (auto fileInfo : commitSentInfo.filesInfo) {
            fileIndex++;
            auto encryptedFileMeta = _fileMetaEncryptorV5.encrypt(prepareMeta(fileInfo, inboxDIO), _userPrivKeyECC, filesMetaKey);
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
    auto inbox {getRawInboxFromCacheOrBridge(inboxId)};
    auto result = decryptAndConvertInboxEntryDataToInboxEntry(inbox, messageRaw);
    PRIVMX_DEBUG_TIME_STOP(InboxApi, readEntry, data decrypted)
    return result;
}

core::PagingList<inbox::InboxEntry> InboxApiImpl::listEntries(const std::string& inboxId, const core::PagingQuery& query) {
    if(query.queryAsJson.has_value()) {
        throw InboxModuleDoesNotSupportQueriesYetException();
    }
    PRIVMX_DEBUG_TIME_START(InboxApi, listEntries)
    auto inboxRaw {getRawInboxFromCacheOrBridge(inboxId)};
    auto inboxData {getInboxCurrentDataEntry(inboxRaw).data()};
    auto threadId = inboxData.threadId();
    auto model = Factory::createObject<thread::server::ThreadMessagesGetModel>();
    model.threadId(threadId);
    core::ListQueryMapper::map(model, query);
    PRIVMX_DEBUG_TIME_CHECKPOINT(InboxApi, listEntries)
    auto messagesList = _serverApi->threadMessagesGet(model);
    PRIVMX_DEBUG_TIME_CHECKPOINT(InboxApi, listEntries, data recv)
    std::vector<inbox::InboxEntry> messages;
    if(messagesList.messages().size()>0) {
        auto inbox = getRawInboxFromCacheOrBridge(readInboxIdFromMessageKeyId(messagesList.messages().get(0).keyId()));
        for (auto message : messagesList.messages()) {
            messages.push_back(decryptAndConvertInboxEntryDataToInboxEntry(inbox, message));
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
    std::shared_ptr<store::FileWriteHandle> handle = _inboxHandleManager.createFileWriteHandle(
        std::string(),
        std::string(),
        (uint64_t)fileSize,
        publicMeta,
        privateMeta,
        _CHUNK_SIZE,
        _serverRequestChunkSize,
        _requestApi
    );
    return handle->getId();
}

int64_t InboxApiImpl::createInboxFileHandleForRead(const privmx::endpoint::store::server::File& file) {
    PRIVMX_DEBUG_TIME_START(InboxApi, createInboxFileHandleForRead, handle_to_create)
    auto messageRaw = getServerMessage(readMessageIdFromFileKeyId(file.keyId()));

    auto inbox = getRawInboxFromCacheOrBridge(readInboxIdFromMessageKeyId(messageRaw.keyId()));

    auto messageData = decryptInboxEntry(inbox, messageRaw);
    core::DecryptedEncKey fileMetaEncKey{
        core::EncKey{.id="", .key=messageData.privateData.filesMetaKey},
        core::DecryptedVersionedData{.dataStructureVersion=0, .statusCode=0}
    };
    auto decryptionParams = _storeApi.getImpl()->getFileDecryptionParams(file, fileMetaEncKey);
    PRIVMX_DEBUG_TIME_CHECKPOINT(InboxApi, createInboxFileHandleForRead, file_key_extracted)
    std::shared_ptr<store::FileReadHandle> handle = _inboxHandleManager.createFileReadHandle(
        file.id(), 
        decryptionParams.originalSize,
        decryptionParams.sizeOnServer,
        decryptionParams.chunkSize,
        _serverRequestChunkSize,
        file.version(),
        decryptionParams.key,
        decryptionParams.hmac,
        _serverApi
    );
    PRIVMX_DEBUG_TIME_STOP(InboxApi, createInboxFileHandleForRead, handle_created)
    return handle->getId();    
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
    if(!_inboxHandleManager.isFileReadHandle(handle)) {
        throw InvalidFileReadHandleException("CloseFile() invalid file handle. Expected FILE_READ_HANDLE, but FILE_WRITE_HANDLE used.");
    }
    std::shared_ptr<store::FileHandle> handlePtr = _inboxHandleManager.getFileReadHandle(handle);
    _inboxHandleManager.removeFileHandle(handle);
    PRIVMX_DEBUG_TIME_STOP(InboxApi, closeFile)
    return handlePtr->getFileId();
}

store::FileMetaToEncryptV5 InboxApiImpl::prepareMeta(const privmx::endpoint::inbox::CommitFileInfo& commitFileInfo, privmx::endpoint::core::DataIntegrityObject fileDIO) {
    auto internalFileMeta = Factory::createObject<store::dynamic::InternalStoreFileMeta>();
    internalFileMeta.version(5);
    internalFileMeta.size(commitFileInfo.size);
    internalFileMeta.cipherType(commitFileInfo.fileSendResult.cipherType);
    internalFileMeta.chunkSize(commitFileInfo.fileSendResult.chunkSize);
    internalFileMeta.key(utils::Base64::from(commitFileInfo.fileSendResult.key));
    internalFileMeta.hmac(utils::Base64::from(commitFileInfo.fileSendResult.hmac));
    store::FileMetaToEncryptV5 fileMetaToEncrypt = {
        .publicMeta = commitFileInfo.publicMeta,
        .privateMeta = commitFileInfo.privateMeta,
        .internalMeta = core::Buffer::from(utils::Utils::stringifyVar(internalFileMeta.asVar())),
        .dio = fileDIO
    };
    return fileMetaToEncrypt;
}

inbox::server::InboxDataEntry InboxApiImpl::getInboxCurrentDataEntry(inbox::server::Inbox inboxRaw) {
    auto dataEntry = inboxRaw.data().get(inboxRaw.data().size()-1);
    return dataEntry;
}


InboxDataResultV4 InboxApiImpl::decryptInboxV4(inbox::server::InboxDataEntry inboxEntry, const core::DecryptedEncKey& encKey) {
    return _inboxDataProcessorV4.unpackAll(inboxEntry.data(), encKey.key);
}

Inbox InboxApiImpl::convertInboxV4(const inbox::server::Inbox& inboxRaw, const InboxDataResultV4& inboxData) {
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
        .policy = core::Factory::parsePolicyServerObjectWithoutItem(inboxRaw.policy()),
        .statusCode = inboxData.statusCode
    };
    return ret;
}

InboxDataResultV5 InboxApiImpl::decryptInboxV5(inbox::server::InboxDataEntry inboxEntry, const core::DecryptedEncKey& encKey) {
    return _inboxDataProcessorV5.unpackAll(inboxEntry.data(), encKey.key);
}

Inbox InboxApiImpl::convertInboxV5(const inbox::server::Inbox& inboxRaw, const InboxDataResultV5& inboxData) {
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
        .policy = core::Factory::parsePolicyServerObjectWithoutItem(inboxRaw.policy()),
        .statusCode = inboxData.statusCode
    };
    return ret;
}

InboxPublicViewData InboxApiImpl::getInboxPublicViewData(const std::string& inboxId) {
    auto model = Factory::createObject<inbox::server::InboxGetModel>();
    model.id(inboxId);
    auto publicView = _serverApi->inboxGetPublicView(model);
    
    InboxPublicViewData result;

    if (publicView.publicData().type() == typeid(Poco::JSON::Object::Ptr)) {
        auto versioned = utils::TypedObjectFactory::createObjectFromVar<core::dynamic::VersionedData>(publicView.publicData());
        if (!versioned.versionEmpty()) {
            switch (versioned.version()) {
                case 4:
                    {
                        auto publicData {_inboxDataProcessorV4.unpackPublicOnly(publicView.publicData())};
                        result.inboxId = publicView.inboxId();
                        result.version = publicView.version();
                        result.dataStructureVersion = publicData.dataStructureVersion;
                        result.authorPubKey = publicData.authorPubKey;
                        result.inboxEntriesPubKeyBase58DER = publicData.inboxEntriesPubKeyBase58DER;
                        result.inboxEntriesKeyId = publicData.inboxEntriesKeyId;
                        result.publicMeta = publicData.publicMeta;
                        result.statusCode = publicData.statusCode;
                        return result;
                    }
                case 5:
                    {
                        auto publicData {_inboxDataProcessorV5.unpackPublicOnly(publicView.publicData())};
                        result.inboxId = publicView.inboxId();
                        result.version = publicView.version();
                        result.dataStructureVersion = publicData.dataStructureVersion;
                        result.authorPubKey = publicData.authorPubKey;
                        result.inboxEntriesPubKeyBase58DER = publicData.inboxEntriesPubKeyBase58DER;
                        result.inboxEntriesKeyId = publicData.inboxEntriesKeyId;
                        result.publicMeta = publicData.publicMeta;
                        result.statusCode = publicData.statusCode;
                        return result;
                    }
            }
        }
    }
    auto e = UnknownInboxFormatException();
    result.statusCode = e.getCode();
    return result;
}


std::tuple<inbox::Inbox, core::DataIntegrityObject> InboxApiImpl::decryptAndConvertInboxDataToInbox(inbox::server::Inbox inbox, inbox::server::InboxDataEntry inboxEntry, const core::DecryptedEncKey& encKey) {
    if (inboxEntry.data().meta().type() == typeid(Poco::JSON::Object::Ptr)) {
        auto versioned = utils::TypedObjectFactory::createObjectFromVar<core::dynamic::VersionedData>(inboxEntry.data().meta());
        if (!versioned.versionEmpty()) {
            switch (versioned.version()) {
                case 4: {
                    auto decryptedInboxData = decryptInboxV4(inboxEntry, encKey);
                    return std::make_tuple(
                        convertInboxV4(inbox, decryptedInboxData),
                        core::DataIntegrityObject{
                            .creatorUserId = inbox.lastModifier(),
                            .creatorPubKey = decryptedInboxData.privateData.authorPubKey,
                            .contextId = inbox.contextId(),
                            .containerId = inbox.id(),
                            .timestamp = inbox.lastModificationDate(),
                            .randomId = std::string(),
                            .itemId = std::nullopt
                        }
                        
                    );
                }
                case 5: {
                    auto decryptedInboxData = decryptInboxV5(inboxEntry, encKey);
                    return std::make_tuple(convertInboxV5(inbox, decryptedInboxData), decryptedInboxData.privateData.dio);
                }
            }
        }
    }
    auto e = UnknownInboxFormatException();
    return std::make_tuple(Inbox{ {},{},{},{},{},{},{},{},{},{},{},{},{}, .statusCode =  e.getCode()}, core::DataIntegrityObject());
}


std::vector<Inbox> InboxApiImpl::decryptAndConvertInboxesDataToInboxes(utils::List<inbox::server::Inbox> inboxes) {
    std::vector<Inbox> result;
    core::KeyDecryptionAndVerificationRequest keyProviderRequest;
    //create request to KeyProvider for keys
    for (size_t i = 0; i < inboxes.size(); i++) {
        auto inbox = inboxes.get(i);
        core::EncKeyLocation location{.contextId=inbox.contextId(), .containerId=inbox.id()};
        auto inbox_data_entry = inbox.data().get(inbox.data().size()-1);
        keyProviderRequest.addOne(inbox.keys(), inbox_data_entry.keyId(), location);
    }
    //send request to KeyProvider
    auto storesKeys {_keyProvider->getKeysAndVerify(keyProviderRequest)};
    std::vector<core::DataIntegrityObject> inboxesDIO;
    std::map<std::string, bool> duplication_check;
    for (size_t i = 0; i < inboxes.size(); i++) {
        auto inbox = inboxes.get(i);
        try {;
            auto tmp = decryptAndConvertInboxDataToInbox(
                inbox, 
                inbox.data().get(inbox.data().size()-1), 
                storesKeys.at({.contextId=inbox.contextId(), .containerId=inbox.id()}).at(inbox.data().get(inbox.data().size()-1).keyId())
            );
            result.push_back(std::get<0>(tmp));
            auto inboxDIO = std::get<1>(tmp);
            inboxesDIO.push_back(inboxDIO);
            //find duplication
            std::string fullRandomId = inboxDIO.randomId + "-" + std::to_string(inboxDIO.timestamp);
            if(duplication_check.find(fullRandomId) == duplication_check.end()) {
                duplication_check.insert(std::make_pair(fullRandomId, true));
            } else {
                result[result.size()-1].statusCode = core::DataIntegrityObjectDuplicatedException().getCode();
            }
        } catch (const core::Exception& e) {
            result.push_back(Inbox{ {},{},{},{},{},{},{},{},{},{},{},{},{}, .statusCode = e.getCode()});
            inboxesDIO.push_back(core::DataIntegrityObject{});
        }
    }
    std::vector<core::VerificationRequest> verifierInput {};
    for (size_t i = 0; i < result.size(); i++) {
        if(result[i].statusCode == 0) {
            verifierInput.push_back({
                .contextId = result[i].contextId,
                .senderId = result[i].lastModifier,
                .senderPubKey = inboxesDIO[i].creatorPubKey,
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

inbox::Inbox InboxApiImpl::decryptAndConvertInboxDataToInbox(inbox::server::Inbox inbox) {
    auto entry = getInboxCurrentDataEntry(inbox);
    core::KeyDecryptionAndVerificationRequest keyProviderRequest;
    core::EncKeyLocation location{.contextId=inbox.contextId(), .containerId=inbox.id()};
    keyProviderRequest.addOne(inbox.keys(), entry.keyId(), location);
    auto key = _keyProvider->getKeysAndVerify(keyProviderRequest).at(location).at(entry.keyId());
    inbox::Inbox result;
    core::DataIntegrityObject inboxDIO;
    std::tie(result, inboxDIO) = decryptAndConvertInboxDataToInbox(inbox, entry, key);
    if(result.statusCode != 0) return result;
    std::vector<core::VerificationRequest> verifierInput {};
    verifierInput.push_back({
        .contextId = result.contextId,
        .senderId = result.lastModifier,
        .senderPubKey = inboxDIO.creatorPubKey,
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


std::string InboxApiImpl::decryptInboxInternalMeta(inbox::server::InboxDataEntry inboxEntry, const core::DecryptedEncKey& encKey) {
    if (inboxEntry.data().meta().type() == typeid(Poco::JSON::Object::Ptr)) {
        auto versioned = utils::TypedObjectFactory::createObjectFromVar<core::dynamic::VersionedData>(inboxEntry.data().meta());
        if (!versioned.versionEmpty()) {
            switch (versioned.version()) {
                case 4: {
                    return std::string();
                }
                case 5: {
                    auto decryptedInboxData = decryptInboxV5(inboxEntry, encKey);
                    return decryptedInboxData.privateData.internalMeta.stdString();
                }
            }
        }
    }
    throw UnknownInboxFormatException();
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
        core::KeyDecryptionAndVerificationRequest keyProviderRequest;
        core::EncKeyLocation location{.contextId=inbox.contextId(), .containerId=inbox.id()};
        keyProviderRequest.addOne(inbox.keys(), msgPublicData.usedInboxKeyId, location);
        auto encKey = _keyProvider->getKeysAndVerify(keyProviderRequest).at(location).at(msgPublicData.usedInboxKeyId);
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

inbox::InboxEntry InboxApiImpl::convertInboxEntry(const privmx::endpoint::inbox::server::Inbox& inbox, const thread::server::Message& message, const inbox::InboxEntryResult& inboxEntry) {
    inbox::InboxEntry result;
    result.entryId = message.id();
    result.inboxId = inbox.id();
    result.createDate = message.createDate();
    core::DecryptedEncKey fileMetaEncKey{
        core::EncKey{.id="", .key=inboxEntry.privateData.filesMetaKey},
        core::DecryptedVersionedData{.dataStructureVersion=0, .statusCode=0}
    };
    result.data = core::Buffer::from(inboxEntry.privateData.text);
    result.authorPubKey = inboxEntry.publicData.userPubKey;
    result.statusCode = inboxEntry.statusCode;
    if(inboxEntry.statusCode == 0) {
        try {
            auto filesGetModel {Factory::createStoreFileGetManyModel(inboxEntry.storeId, inboxEntry.filesIds, false)};
            auto serverFiles {_serverApi->storeFileGetMany(filesGetModel)};
            for (auto file : serverFiles.files()) {
                if(file.errorEmpty()) {
                    result.files.push_back(std::get<0>(_storeApi.getImpl()->decryptAndConvertFileDataToFileInfo(file, fileMetaEncKey)));
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

inbox::InboxEntry InboxApiImpl::decryptAndConvertInboxEntryDataToInboxEntry(const privmx::endpoint::inbox::server::Inbox& inbox, const thread::server::Message& message) {
    auto inboxEntry = decryptInboxEntry(inbox, message);
    return convertInboxEntry(inbox, message, inboxEntry);
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

    if(!(_inboxSubscriptionHelper.hasSubscriptionForChannel(channel) || _threadSubscriptionHelper.hasSubscriptionForChannel(channel)) && channel != INTERNAL_EVENT_CHANNEL_NAME) {
        return;
    }
    if (type == "inboxCreated") {
        auto raw = Factory::createObject<server::Inbox>(data);
        _inboxProvider.updateByValue(raw);
        auto data = decryptAndConvertInboxDataToInbox(raw);
        std::shared_ptr<InboxCreatedEvent> event(new InboxCreatedEvent());
        event->channel = "inbox";
        event->data = data;
        _eventMiddleware->emitApiEvent(event);
    } else if (type == "inboxUpdated") {
        auto raw = Factory::createObject<server::Inbox>(data);
        _inboxProvider.updateByValue(raw);
        auto data = decryptAndConvertInboxDataToInbox(raw);
        std::shared_ptr<InboxUpdatedEvent> event(new InboxUpdatedEvent());
        event->channel = "inbox";
        event->data = data;
        _eventMiddleware->emitApiEvent(event);
    } else if (type == "inboxDeleted") {
        auto raw = Factory::createObject<server::InboxDeletedEventData>(data);
        _inboxProvider.invalidateByContainerId(raw.inboxId());
        auto data = convertInboxDeletedEventData(raw);
        std::shared_ptr<InboxDeletedEvent> event(new InboxDeletedEvent());
        event->channel = "inbox";
        event->data = data;
        _eventMiddleware->emitApiEvent(event);
    } else if (type == "threadNewMessage") {
        auto raw = Factory::createObject<privmx::endpoint::thread::server::Message>(data); 
        if(_threadSubscriptionHelper.hasSubscriptionForElement(raw.threadId())) {
            auto inbox = getRawInboxFromCacheOrBridge(readInboxIdFromMessageKeyId(raw.keyId()));
            auto message = decryptAndConvertInboxEntryDataToInboxEntry(inbox, raw);
            std::shared_ptr<InboxEntryCreatedEvent> event(new InboxEntryCreatedEvent());
            event->channel = "inbox/" + inbox.id() + "/entries";
            event->data = message;
            _eventMiddleware->emitApiEvent(event);
        }
    } else if (type == "threadDeletedMessage") {
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
    } else if (type == "subscribe") {
        std::string channel = data->has("channel") ? data->get("channel") : "";
        if(channel == "inbox") {
            PRIVMX_DEBUG("InboxApi", "Cache", "Enabled")
            _subscribeForInbox = true;
        }
    } else if (type == "unsubscribe") {
        std::string channel = data->has("channel") ? data->get("channel") : "";
        if(channel == "inbox") {
            PRIVMX_DEBUG("InboxApi", "Cache", "Disabled")
            _subscribeForInbox = false;
            _inboxProvider.invalidate();
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
    auto inbox = getRawInboxFromCacheOrBridge(inboxId);
    auto inboxData = getInboxCurrentDataEntry(inbox).data();
    if(_threadSubscriptionHelper.hasSubscriptionForElement(inboxData.threadId())) {
        throw AlreadySubscribedException(inboxId);
    }
    _threadSubscriptionHelper.subscribeForElement(inboxData.threadId(), inboxId);
}

void InboxApiImpl::unsubscribeFromEntryEvents(const std::string& inboxId) {
    auto inbox = getRawInboxFromCacheOrBridge(inboxId);
    auto inboxData = getInboxCurrentDataEntry(inbox).data();
    if(!_threadSubscriptionHelper.hasSubscriptionForElement(inboxData.threadId())) {
        throw NotSubscribedException(inboxId);
    }
    _threadSubscriptionHelper.unsubscribeFromElement(inboxData.threadId());
}

void InboxApiImpl::processConnectedEvent() {
   _inboxProvider.invalidate();
}

void InboxApiImpl::processDisconnectedEvent() {
   _inboxProvider.invalidate();
}

InboxDeletedEventData InboxApiImpl::convertInboxDeletedEventData(const server::InboxDeletedEventData& data) {
    return InboxDeletedEventData {
       .inboxId = data.inboxId()
   };
}
std::string InboxApiImpl::readInboxIdFromMessageKeyId(const std::string& keyId) {
    _messageKeyIdFormatValidator.assertKeyIdFormat(keyId);
    std::string trimmedKeyId = keyId.substr(1, keyId.size() - 2);
    std::vector<std::string> tmp = utils::Utils::split(trimmedKeyId, "-");
    if(tmp.size() == 1+1+4) {
        return tmp[1]+"-"+tmp[2]+"-"+tmp[3]+"-"+tmp[4]+"-"+tmp[5];
    }
    return tmp[1];
}

std::string InboxApiImpl::readMessageIdFromFileKeyId(const std::string& keyId) {
    _fileKeyIdFormatValidator.assertKeyIdFormat(keyId);
    std::string trimmedKeyId = keyId.substr(1, keyId.size() - 2);
    std::vector<std::string> tmp = utils::Utils::split(trimmedKeyId, "-");
    if(tmp.size() == 1+3+4+4) {
        return tmp[6]+"-"+tmp[7]+"-"+tmp[8]+"-"+tmp[9]+"-"+tmp[10]+":"+tmp[11];
    }
    return tmp[3];
}

void InboxApiImpl::deleteMessageAndFiles(const thread::server::Message& message) {
    auto publicMeta = unpackInboxOrigMessage(message.data());
    for(auto fileId : publicMeta.files()) {
        _storeApi.deleteFile(fileId);
    }
    _threadApi.deleteMessage(message.id());
}

thread::server::Message InboxApiImpl::getServerMessage(const std::string& messageId) {
    auto model = Factory::createObject<thread::server::ThreadMessageGetModel>();
    model.messageId(messageId);
    return _serverApi->threadMessageGet(model).message();
}

server::Inbox InboxApiImpl::getRawInboxFromCacheOrBridge(const std::string& inboxId) {
    // useing inboxProvider only with INBOX_TYPE_FILTER_FLAG 
    // making sure to have valid cache
    if(!_subscribeForInbox) _inboxProvider.update(inboxId);
    auto inboxContainerInfo = _inboxProvider.get(inboxId);
    if(inboxContainerInfo.status != core::DataIntegrityStatus::ValidationSucceed) {
        throw InboxDataIntegrityException();
    }
    return inboxContainerInfo.container;
}

void InboxApiImpl::assertInboxExist(const std::string& inboxId) {
    //check if inbox is in cache or on server
    getRawInboxFromCacheOrBridge(inboxId);
}

uint32_t InboxApiImpl::validateInboxDataIntegrity(server::Inbox inbox) {
    auto inbox_data_entry = inbox.data().get(inbox.data().size()-1);
    auto versioned = utils::TypedObjectFactory::createObjectFromVar<core::dynamic::VersionedData>(inbox_data_entry.data().meta());
    if (!versioned.versionEmpty()) {
        switch (versioned.version()) {
        case 4:
            return 0;
        case 5: 
            {
                auto inbox_data = utils::TypedObjectFactory::createObjectFromVar<server::InboxData>(inbox_data_entry.data());
                auto dio = _inboxDataProcessorV5.getDIOAndAssertIntegrity(inbox_data);
                if(
                    dio.contextId != inbox.contextId() ||
                    dio.containerId != inbox.id() ||
                    dio.creatorUserId != inbox.lastModifier() ||
                    !core::TimestampValidator::validate(dio.timestamp, inbox.lastModificationDate())
                ) {
                    return InboxDataIntegrityException().getCode();
                }
                return 0;
            }
        }
    } 
    return UnknownInboxFormatException().getCode();
}