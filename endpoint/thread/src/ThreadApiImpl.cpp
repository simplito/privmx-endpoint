/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include <privmx/utils/Debug.hpp>
#include <privmx/utils/Utils.hpp>

#include <privmx/endpoint/core/Types.hpp>
#include <privmx/endpoint/core/EndpointUtils.hpp>
#include <privmx/endpoint/core/Utils.hpp>
#include <privmx/endpoint/core/EventMiddleware.hpp>
#include <privmx/endpoint/core/VarDeserializer.hpp>
#include <privmx/endpoint/core/VarSerializer.hpp>
#include <privmx/endpoint/core/ExceptionConverter.hpp>
#include <privmx/endpoint/core/TimestampValidator.hpp>

#include "privmx/endpoint/thread/DynamicTypes.hpp"
#include "privmx/endpoint/thread/ThreadApiImpl.hpp"
#include "privmx/endpoint/thread/ServerTypes.hpp"
#include "privmx/endpoint/thread/Mapper.hpp"
#include "privmx/endpoint/thread/ThreadVarSerializer.hpp"
#include "privmx/endpoint/thread/ThreadException.hpp"
#include "privmx/endpoint/core/ListQueryMapper.hpp"

using namespace privmx::endpoint;
using namespace thread;

ThreadApiImpl::ThreadApiImpl(
    const privfs::RpcGateway::Ptr& gateway,
    const privmx::crypto::PrivateKey& userPrivKey,
    const std::shared_ptr<core::KeyProvider>& keyProvider,
    const std::string& host,
    const std::shared_ptr<core::EventMiddleware>& eventMiddleware,
    const std::shared_ptr<core::EventChannelManager>& eventChannelManager,
    const core::Connection& connection
) : _gateway(gateway),
    _userPrivKey(userPrivKey),
    _keyProvider(keyProvider),
    _host(host),
    _eventMiddleware(eventMiddleware),
    _connection(connection),
    _serverApi(ServerApi(gateway)),
    _dataEncryptorThread(core::DataEncryptor<dynamic::ThreadDataV1>()),
    _messageDataV2Encryptor(MessageDataV2Encryptor()),
    _messageDataV3Encryptor(MessageDataV3Encryptor()),
    _messageKeyIdFormatValidator(MessageKeyIdFormatValidator()),
    _threadProvider(ThreadProvider(
        [&](const std::string& id) {
            auto model = privmx::utils::TypedObjectFactory::createNewObject<server::ThreadGetModel>();
            model.threadId(id);
            model.type(THREAD_TYPE_FILTER_FLAG);
            auto serverThread = _serverApi.threadGet(model).thread();
            return serverThread;
        },
        std::bind(&ThreadApiImpl::validateThreadDataIntegrity, this, std::placeholders::_1)
    )),
    _subscribeForThread(false),
    _threadSubscriptionHelper(core::SubscriptionHelper(eventChannelManager, "thread", "messages")),
    _forbiddenChannelsNames({INTERNAL_EVENT_CHANNEL_NAME, "thread", "messages"}) 
{
    _notificationListenerId = _eventMiddleware->addNotificationEventListener(std::bind(&ThreadApiImpl::processNotificationEvent, this, std::placeholders::_1, std::placeholders::_2, std::placeholders::_3));
    _connectedListenerId = _eventMiddleware->addConnectedEventListener(std::bind(&ThreadApiImpl::processConnectedEvent, this));
    _disconnectedListenerId = _eventMiddleware->addDisconnectedEventListener(std::bind(&ThreadApiImpl::processDisconnectedEvent, this));
}

ThreadApiImpl::~ThreadApiImpl() {
    _eventMiddleware->removeNotificationEventListener(_notificationListenerId);
    _eventMiddleware->removeConnectedEventListener(_connectedListenerId);
    _eventMiddleware->removeDisconnectedEventListener(_disconnectedListenerId);
}

std::string ThreadApiImpl::createThread(
    const std::string& contextId, 
    const std::vector<core::UserWithPubKey>& users, 
    const std::vector<core::UserWithPubKey>& managers, 
    const core::Buffer& publicMeta, 
    const core::Buffer& privateMeta,
    const std::optional<core::ContainerPolicy>& policies
) {
    return _createThreadEx(contextId, users, managers, publicMeta, privateMeta, THREAD_TYPE_FILTER_FLAG, policies);
}

std::string ThreadApiImpl::createThreadEx(
    const std::string& contextId, 
    const std::vector<core::UserWithPubKey>& users, 
    const std::vector<core::UserWithPubKey>& managers, 
    const core::Buffer& publicMeta, 
    const core::Buffer& privateMeta, 
    const std::string& type,
    const std::optional<core::ContainerPolicy>& policies
) {
    return _createThreadEx(contextId, users, managers, publicMeta, privateMeta, type, policies);
}

std::string ThreadApiImpl::_createThreadEx(
    const std::string& contextId, 
    const std::vector<core::UserWithPubKey>& users, 
    const std::vector<core::UserWithPubKey>& managers, 
    const core::Buffer& publicMeta, 
    const core::Buffer& privateMeta, 
    const std::string& type,
    const std::optional<core::ContainerPolicy>& policies
) {
    PRIVMX_DEBUG_TIME_START(PlatformThread, _createThreadEx)
    auto threadKey = _keyProvider->generateKey();
    std::string threadId = utils::Utils::getNowTimestampStr() + utils::Hex::from(crypto::Crypto::randomBytes(8));
    auto threadDIO = _connection.getImpl()->createDIOForNewContainer(
        contextId,
        threadId
    );
    auto threadCCN = _keyProvider->generateContainerControlNumber();
    ThreadDataToEncryptV5 threadDataToEncrypt {
        .publicMeta = publicMeta,
        .privateMeta = privateMeta,
        .internalMeta = core::Buffer::from(threadCCN),
        .dio = threadDIO
    };
    auto create_thread_model = utils::TypedObjectFactory::createNewObject<server::ThreadCreateModel>();
    create_thread_model.threadId(threadId);
    create_thread_model.contextId(contextId);
    create_thread_model.keyId(threadKey.id);
    create_thread_model.data(_threadDataEncryptorV5.encrypt(threadDataToEncrypt, _userPrivKey, threadKey.key).asVar());
    auto allUsers = core::EndpointUtils::uniqueListUserWithPubKey(users, managers);
    create_thread_model.keys(
        _keyProvider->prepareKeysList(
            allUsers, 
            threadKey, 
            threadDIO,
            threadCCN
        )
    );

    create_thread_model.users(mapUsers(users));
    create_thread_model.managers(mapUsers(managers));
    if (type.length() > 0) {
        create_thread_model.type(type);
    }
    if (policies.has_value()) {
        create_thread_model.policy(privmx::endpoint::core::Factory::createPolicyServerObject(policies.value()));
    }
    PRIVMX_DEBUG_TIME_CHECKPOINT(PlatformThread, _createThreadEx, data encrypted)
    auto result = _serverApi.threadCreate(create_thread_model);
    PRIVMX_DEBUG_TIME_STOP(PlatformThread, _createThreadEx, data send)
    return result.threadId();
}

void ThreadApiImpl::updateThread(
    const std::string& threadId,
    const std::vector<core::UserWithPubKey>& users,
    const std::vector<core::UserWithPubKey>& managers, 
    const core::Buffer& publicMeta,
    const core::Buffer& privateMeta, 
    const int64_t version, 
    const bool force, 
    const bool forceGenerateNewKey,
    const std::optional<core::ContainerPolicy>& policies
) {
    PRIVMX_DEBUG_TIME_START(PlatformThread, updateThread)

    // get current thread

    auto getModel = utils::TypedObjectFactory::createNewObject<server::ThreadGetModel>();
    getModel.threadId(threadId);
    auto currentThread = _serverApi.threadGet(getModel).thread();

    // extract current users info
    auto usersVec {core::EndpointUtils::listToVector<std::string>(currentThread.users())};
    auto managersVec {core::EndpointUtils::listToVector<std::string>(currentThread.managers())};
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

    // read all key to check if all key belongs to this thread
    auto threadKeys {_keyProvider->getAllKeysAndVerify(currentThread.keys(), {.contextId=currentThread.contextId(), .containerId=threadId})};
    auto currentThreadEntry = currentThread.data().get(currentThread.data().size()-1);
    core::DecryptedEncKey currentThreadKey;
    for (auto key : threadKeys) {
        if (currentThreadEntry.keyId() == key.id) {
            currentThreadKey = key;
            break;
        }
    }
    auto threadCCN = decryptThreadInternalMeta(currentThreadEntry, currentThreadKey);
    for(auto key : threadKeys) {
        if(key.statusCode != 0 || (key.dataStructureVersion == 2 && key.containerControlNumber != threadCCN)) {

            throw ThreadEncryptionKeyValidationException();
        }
    }
    // setting thread Key adding new users
    core::EncKey threadKey;
    core::DataIntegrityObject updateThreadDio = _connection.getImpl()->createDIO(currentThread.contextId(), threadId);
    privmx::utils::List<core::server::KeyEntrySet> keys = utils::TypedObjectFactory::createNewList<core::server::KeyEntrySet>();
    if(needNewKey) {
        threadKey = _keyProvider->generateKey();
        keys = _keyProvider->prepareKeysList(
            new_users, 
            threadKey, 
            updateThreadDio,
            threadCCN
        );
    } else {
        // find key with corresponding keyId 
        for(size_t i = 0; i < threadKeys.size(); i++) {
            threadKey = threadKeys[i];
        }
    }
    if(usersToAddMissingKey.size() > 0) {
        auto tmp = _keyProvider->prepareMissingKeysForNewUsers(
            threadKeys,
            usersToAddMissingKey, 
            updateThreadDio, 
            threadCCN
        );
        for(auto t: tmp) keys.add(t);
    }
    auto model = utils::TypedObjectFactory::createNewObject<server::ThreadUpdateModel>();


    auto usersList = utils::TypedObjectFactory::createNewList<std::string>();
    for (auto user: users) {
        usersList.add(user.userId);
    }
    auto managersList = utils::TypedObjectFactory::createNewList<std::string>();
    for (auto x: managers) {
        managersList.add(x.userId);
    }

    model.id(threadId);
    model.keyId(threadKey.id);
    model.keys(keys);
    model.users(usersList);
    model.managers(managersList);
    model.version(version);
    model.force(force);
    if (policies.has_value()) {
        model.policy(privmx::endpoint::core::Factory::createPolicyServerObject(policies.value()));
    }
    auto threadDIO = _connection.getImpl()->createDIO(
        currentThread.contextId(),
        threadId
    );
    ThreadDataToEncryptV5 threadDataToEncrypt {
        .publicMeta = publicMeta,
        .privateMeta = privateMeta,
        .internalMeta = core::Buffer::from(threadCCN),
        .dio = threadDIO
    };
    model.data(_threadDataEncryptorV5.encrypt(threadDataToEncrypt, _userPrivKey, threadKey.key).asVar());

    PRIVMX_DEBUG_TIME_CHECKPOINT(PlatformThread, updateThread, data encrypted)
    _serverApi.threadUpdate(model);
    PRIVMX_DEBUG_TIME_STOP(PlatformThread, updateThread, data send)
}

void ThreadApiImpl::deleteThread(const std::string& threadId) {
    auto model = utils::TypedObjectFactory::createNewObject<server::ThreadDeleteModel>();
    model.threadId(threadId);
    _serverApi.threadDelete(model);
}

Thread ThreadApiImpl::getThread(const std::string& threadId) {
    return _getThreadEx(threadId, THREAD_TYPE_FILTER_FLAG);
}

Thread ThreadApiImpl::getThreadEx(const std::string& threadId, const std::string& type) {
    return _getThreadEx(threadId, type);
}

Thread ThreadApiImpl::_getThreadEx(const std::string& threadId, const std::string& type) {
    PRIVMX_DEBUG_TIME_START(PlatformThread, _getThreadEx)
    Poco::JSON::Object::Ptr params = new Poco::JSON::Object();
    params->set("threadId", threadId);
    if (type.length() > 0) {
        params->set("type", type);
    }
    PRIVMX_DEBUG_TIME_CHECKPOINT(PlatformThread, _getThreadEx, getting thread)
    auto thread = _serverApi.threadGet(params).thread();
    if(type == THREAD_TYPE_FILTER_FLAG) _threadProvider.updateByValue(thread);
    PRIVMX_DEBUG_TIME_CHECKPOINT(PlatformThread, _getThreadEx, data send)
    auto statusCode = validateThreadDataIntegrity(thread);
    if(statusCode != 0) {
        if(type == THREAD_TYPE_FILTER_FLAG) _threadProvider.updateByValueAndStatus(thread, core::DataIntegrityStatus::ValidationFailed);
        return Thread{ {},{},{},{},{},{},{},{},{},{},{},{},{},{}, .statusCode = statusCode};
    } else {
        if(type == THREAD_TYPE_FILTER_FLAG) _threadProvider.updateByValueAndStatus(thread, core::DataIntegrityStatus::ValidationSucceed);
    }
    auto result = decryptAndConvertThreadDataToThread(thread);
    PRIVMX_DEBUG_TIME_CHECKPOINT(PlatformThread, _getThreadEx, data decrypted)
    return result;
}

core::PagingList<Thread> ThreadApiImpl::listThreads(const std::string& contextId, const core::PagingQuery& pagingQuery) {
    return _listThreadsEx(contextId, pagingQuery, THREAD_TYPE_FILTER_FLAG);
}

core::PagingList<Thread> ThreadApiImpl::listThreadsEx(const std::string& contextId, const core::PagingQuery& pagingQuery, const std::string& type) {
    return _listThreadsEx(contextId, pagingQuery, type);
}

core::PagingList<Thread> ThreadApiImpl::_listThreadsEx(const std::string& contextId, const core::PagingQuery& pagingQuery, const std::string& type) {
    PRIVMX_DEBUG_TIME_START(PlatformThread, _listThreadsEx)
    auto model = utils::TypedObjectFactory::createNewObject<server::ThreadListModel>();
    model.contextId(contextId);
    if (type.length() > 0) {
        model.type(type);
    }
    core::ListQueryMapper::map(model, pagingQuery);
    PRIVMX_DEBUG_TIME_CHECKPOINT(PlatformThread, _listThreadsEx, getting threadList)
    auto threadsList = _serverApi.threadList(model);
    PRIVMX_DEBUG_TIME_CHECKPOINT(PlatformThread, _listThreadsEx, data send)
    std::vector<Thread> threads;
    for (size_t i = 0; i < threadsList.threads().size(); i++) {
        auto thread = threadsList.threads().get(i);
        if(type == THREAD_TYPE_FILTER_FLAG) _threadProvider.updateByValue(thread);
        auto statusCode = validateThreadDataIntegrity(thread);
        threads.push_back(Thread{ {},{},{},{},{},{},{},{},{},{},{},{},{},{}, .statusCode = statusCode});
        if(statusCode == 0) {
            if(type == THREAD_TYPE_FILTER_FLAG) _threadProvider.updateByValueAndStatus(thread ,core::DataIntegrityStatus::ValidationSucceed);
        } else {
            if(type == THREAD_TYPE_FILTER_FLAG) _threadProvider.updateByValueAndStatus(thread ,core::DataIntegrityStatus::ValidationFailed);
            threadsList.threads().remove(i);
            i--;
        }
    }
    auto tmp = decryptAndConvertThreadsDataToThreads(threadsList.threads());
    for(size_t j = 0, i = 0; i < threads.size(); i++) {
        if(threads[i].statusCode == 0) {
            threads[i] = tmp[j];
            j++;
        }
    }
    PRIVMX_DEBUG_TIME_STOP(PlatformThread, _listThreadsEx, data decrypted)
    return core::PagingList<Thread>({
        .totalAvailable = threadsList.count(),
        .readItems = threads
    });
}
Message ThreadApiImpl::getMessage(const std::string& messageId) {
    PRIVMX_DEBUG_TIME_START(PlatformThread, getMessage)
    auto model = utils::TypedObjectFactory::createNewObject<server::ThreadMessageGetModel>();
    model.messageId(messageId);
    PRIVMX_DEBUG_TIME_CHECKPOINT(PlatformThread, getMessage, getting message)
    auto message = _serverApi.threadMessageGet(model).message();
    PRIVMX_DEBUG_TIME_CHECKPOINT(PlatformThread, getMessage, data recived);
    privmx::endpoint::thread::server::ThreadInfo thread;
    Message result;
    try {
        PRIVMX_DEBUG_TIME_CHECKPOINT(PlatformThread, getMessage, getting thread)
        thread = getRawThreadFromCacheOrBridge(message.threadId());
        PRIVMX_DEBUG_TIME_CHECKPOINT(PlatformThread, getMessage, decrypting message)
        auto statusCode = validateMessageDataIntegrity(message);
        if(statusCode != 0) {
            PRIVMX_DEBUG_TIME_STOP(PlatformThread, getMessage, data integrity validation failed)
            result.statusCode = statusCode;
            return result;
        }
        result = decryptAndConvertMessageDataToMessage(thread, message);
    } catch (const core::Exception& e) {
        PRIVMX_DEBUG_TIME_STOP(PlatformThread, getMessage, data decrypted failed)
        result.statusCode = e.getCode();
        return result;
    }
    PRIVMX_DEBUG_TIME_STOP(PlatformThread, getMessage, data decrypted)
    return result;
}

core::PagingList<Message> ThreadApiImpl::listMessages(const std::string& threadId, const core::PagingQuery& pagingQuery) {
    PRIVMX_DEBUG_TIME_START(PlatformThread, listMessages)
    auto model = utils::TypedObjectFactory::createNewObject<server::ThreadMessagesGetModel>();
    model.threadId(threadId);
    core::ListQueryMapper::map(model, pagingQuery);
    PRIVMX_DEBUG_TIME_CHECKPOINT(PlatformThread, listMessages, getting messageList)
    auto messagesList = _serverApi.threadMessagesGet(model);
    PRIVMX_DEBUG_TIME_CHECKPOINT(PlatformThread, listMessages, getting thread)
    auto thread = getRawThreadFromCacheOrBridge(threadId);
    PRIVMX_DEBUG_TIME_CHECKPOINT(PlatformThread, listMessages, data send)
    auto messages = decryptAndConvertMessagesDataToMessages(thread, messagesList.messages());
    PRIVMX_DEBUG_TIME_STOP(PlatformThread, listMessages, data decrypted)
    return core::PagingList<Message>({
        .totalAvailable = messagesList.count(),
        .readItems = messages
    });
}
std::string ThreadApiImpl::sendMessage(const std::string& threadId, const core::Buffer& publicMeta, const core::Buffer& privateMeta, const core::Buffer& data) {
    PRIVMX_DEBUG_TIME_START(PlatformThread, sendMessage);
    auto thread = getRawThreadFromCacheOrBridge(threadId);
    PRIVMX_DEBUG_TIME_CHECKPOINT(PlatformThread, sendMessage, getThread)
    auto msgKey = getThreadCurrentEncKey(thread);
    auto  send_message_model = utils::TypedObjectFactory::createNewObject<server::ThreadMessageSendModel>();
    send_message_model.threadId(thread.id());
    send_message_model.keyId(msgKey.id);
    auto messageDIO = _connection.getImpl()->createDIO(
        thread.contextId(),
        threadId
    );
    MessageDataToEncryptV5 messageData {
        .publicMeta = publicMeta,
        .privateMeta = privateMeta,
        .data = data,
        .internalMeta = std::nullopt,
        .dio = messageDIO
    };
    auto encryptedMessageData = _messageDataEncryptorV5.encrypt(messageData, _userPrivKey, msgKey.key);
    send_message_model.data(encryptedMessageData.asVar());
    PRIVMX_DEBUG_TIME_CHECKPOINT(PlatformThread, sendMessage, data encrypted)
    auto result = _serverApi.threadMessageSend(send_message_model);
    PRIVMX_DEBUG_TIME_STOP(PlatformThread, sendMessage, data send)
    return result.messageId();
}
void ThreadApiImpl::deleteMessage(const std::string& messageId) {
    auto model = utils::TypedObjectFactory::createNewObject<server::ThreadMessageDeleteModel>();
    model.messageId(messageId);
    _serverApi.threadMessageDelete(model);
}
void ThreadApiImpl::updateMessage(
    const std::string& messageId, 
    const core::Buffer& publicMeta, 
    const core::Buffer& privateMeta, 
    const core::Buffer& data
) {
    PRIVMX_DEBUG_TIME_START(PlatformThread, updateMessage);
    auto model = utils::TypedObjectFactory::createNewObject<server::ThreadMessageGetModel>();
    model.messageId(messageId);
    PRIVMX_DEBUG_TIME_CHECKPOINT(PlatformThread, updateMessage, getting message)
    auto message = _serverApi.threadMessageGet(model).message();
    auto statusCode = validateMessageDataIntegrity(message);
    if(statusCode != 0) {
        throw MessageDataIntegrityException();
    }
    PRIVMX_DEBUG_TIME_CHECKPOINT(PlatformThread, updateMessage, getting thread)

    auto thread = getRawThreadFromCacheOrBridge(message.threadId());

    PRIVMX_DEBUG_TIME_CHECKPOINT(PlatformThread, updateMessage, data preparing)
    auto msgKey = getThreadCurrentEncKey(thread);
    auto  send_message_model = utils::TypedObjectFactory::createNewObject<server::ThreadMessageUpdateModel>();
    send_message_model.messageId(messageId);
    send_message_model.keyId(msgKey.id);
    auto messageDIO = _connection.getImpl()->createDIO(
        message.contextId(),
        message.threadId()
    );
    MessageDataToEncryptV5 messageData {
        .publicMeta = publicMeta,
        .privateMeta = privateMeta,
        .data = data,
        .internalMeta = std::nullopt,
        .dio = messageDIO
    };
    auto encryptedMessageData = _messageDataEncryptorV5.encrypt(messageData, _userPrivKey, msgKey.key);
    send_message_model.data(encryptedMessageData.asVar());
    PRIVMX_DEBUG_TIME_CHECKPOINT(PlatformThread, updateMessage, data encrypted)
    _serverApi.threadMessageUpdate(send_message_model);
    PRIVMX_DEBUG_TIME_STOP(PlatformThread, updateMessage, data send)
}

void ThreadApiImpl::processNotificationEvent(const std::string& type, const std::string& channel, const Poco::JSON::Object::Ptr& data) {
    if(!_threadSubscriptionHelper.hasSubscriptionForChannel(channel) && channel != INTERNAL_EVENT_CHANNEL_NAME) {
        return;
    }
    if (type == "threadCreated") {
        auto raw = utils::TypedObjectFactory::createObjectFromVar<server::ThreadInfo>(data);
        if(raw.typeOpt(std::string(THREAD_TYPE_FILTER_FLAG)) == THREAD_TYPE_FILTER_FLAG) {
            _threadProvider.updateByValue(raw);
            auto statusCode = validateThreadDataIntegrity(raw);
            privmx::endpoint::thread::Thread data;
            if(statusCode == 0) {
                data = decryptAndConvertThreadDataToThread(raw); 
            } else {
                data = Thread{ {},{},{},{},{},{},{},{},{},{},{},{},{},{}, .statusCode = statusCode};
            }
            std::shared_ptr<ThreadCreatedEvent> event(new ThreadCreatedEvent());
            event->channel = channel;
            event->data = data;
            _eventMiddleware->emitApiEvent(event);
        }
    } else if (type == "threadUpdated") {
        auto raw = utils::TypedObjectFactory::createObjectFromVar<server::ThreadInfo>(data);
        if(raw.typeOpt(std::string(THREAD_TYPE_FILTER_FLAG)) == THREAD_TYPE_FILTER_FLAG) {
            _threadProvider.updateByValue(raw);
            auto statusCode = validateThreadDataIntegrity(raw);
            privmx::endpoint::thread::Thread data;
            if(statusCode == 0) {
                data = decryptAndConvertThreadDataToThread(raw); 
            } else {
                data = Thread{ {},{},{},{},{},{},{},{},{},{},{},{},{},{}, .statusCode = statusCode};
            }
            std::shared_ptr<ThreadUpdatedEvent> event(new ThreadUpdatedEvent());
            event->channel = channel;
            event->data = data;
            _eventMiddleware->emitApiEvent(event);
        }
    } else if (type == "threadDeleted") {
        auto raw = utils::TypedObjectFactory::createObjectFromVar<server::ThreadDeletedEventData>(data);
        if(raw.typeOpt(std::string(THREAD_TYPE_FILTER_FLAG)) == THREAD_TYPE_FILTER_FLAG) {
            _threadProvider.invalidateByContainerId(raw.threadId());
            auto data = Mapper::mapToThreadDeletedEventData(raw);
            std::shared_ptr<ThreadDeletedEvent> event(new ThreadDeletedEvent());
            event->channel = channel;
            event->data = data;
            _eventMiddleware->emitApiEvent(event);
        }
    } else if (type == "threadStats") {
        auto raw = utils::TypedObjectFactory::createObjectFromVar<server::ThreadStatsEventData>(data);
        if(raw.typeOpt(std::string(THREAD_TYPE_FILTER_FLAG)) == THREAD_TYPE_FILTER_FLAG) {
            _threadProvider.updateStats(raw);
            auto data = Mapper::mapToThreadStatsEventData(raw);
            std::shared_ptr<ThreadStatsChangedEvent> event(new ThreadStatsChangedEvent());
            event->channel = channel;
            event->data = data;
            _eventMiddleware->emitApiEvent(event);
        }
    } else if (type == "threadNewMessage") {
        auto raw = utils::TypedObjectFactory::createObjectFromVar<server::Message>(data);
        auto data = decryptAndConvertMessageDataToMessage(raw);
        std::shared_ptr<ThreadNewMessageEvent> event(new ThreadNewMessageEvent());
        event->channel = channel;
        event->data = data;
        _eventMiddleware->emitApiEvent(event);
    } else if (type == "threadUpdatedMessage") {
        auto raw = utils::TypedObjectFactory::createObjectFromVar<server::Message>(data);
        auto data = decryptAndConvertMessageDataToMessage(raw);
        std::shared_ptr<ThreadMessageUpdatedEvent> event(new ThreadMessageUpdatedEvent());
        event->channel = channel;
        event->data = data;
        _eventMiddleware->emitApiEvent(event);
    } else if (type == "threadDeletedMessage") {
        auto raw = utils::TypedObjectFactory::createObjectFromVar<server::ThreadDeletedMessageEventData>(data);
        auto data = Mapper::mapToThreadDeletedMessageEventData(raw);
        std::shared_ptr<ThreadMessageDeletedEvent> event(new ThreadMessageDeletedEvent());
        event->channel = channel;
        event->data = data;
        _eventMiddleware->emitApiEvent(event);
    } else if (type == "subscribe") {
        std::string channelName = data->has("channel") ? data->getValue<std::string>("channel") : "";
        if(channelName == "thread") {
            PRIVMX_DEBUG("ThreadApi", "Cache", "Enabled")
            _subscribeForThread = true;
        }
    } else if (type == "unsubscribe") {
        std::string channelName = data->has("channel") ?  data->getValue<std::string>("channel") : "";
        if(channelName == "thread") {
            PRIVMX_DEBUG("ThreadApi", "Cache", "Disabled")
            _subscribeForThread = false;
            _threadProvider.invalidate();
        }
    }
}

void ThreadApiImpl::subscribeForThreadEvents() {
    if(_threadSubscriptionHelper.hasSubscriptionForModule()) {
        throw AlreadySubscribedException();
    }
    _threadSubscriptionHelper.subscribeForModule();
}

void ThreadApiImpl::unsubscribeFromThreadEvents() {
    if(!_threadSubscriptionHelper.hasSubscriptionForModule()) {
        throw NotSubscribedException();
    }
    _threadSubscriptionHelper.unsubscribeFromModule();
}

void ThreadApiImpl::subscribeForMessageEvents(std::string threadId) {
    assertThreadExist(threadId);
    if(_threadSubscriptionHelper.hasSubscriptionForElement(threadId)) {
        throw AlreadySubscribedException(threadId);
    }
    _threadSubscriptionHelper.subscribeForElement(threadId);
}

void ThreadApiImpl::unsubscribeFromMessageEvents(std::string threadId) {
    assertThreadExist(threadId);
    if(!_threadSubscriptionHelper.hasSubscriptionForElement(threadId)) {
        throw NotSubscribedException(threadId);
    }
    _threadSubscriptionHelper.unsubscribeFromElement(threadId);
}

void ThreadApiImpl::processConnectedEvent() {
    _threadProvider.invalidate();
}

void ThreadApiImpl::processDisconnectedEvent() {
    _threadProvider.invalidate();
}

privmx::utils::List<std::string> ThreadApiImpl::mapUsers(const std::vector<core::UserWithPubKey>& users) {
    auto result = privmx::utils::TypedObjectFactory::createNewList<std::string>();
    for (auto user : users) {
        result.add(user.userId);
    }
    return result;
}

dynamic::ThreadDataV1 ThreadApiImpl::decryptThreadV1(server::Thread2DataEntry threadEntry, const core::DecryptedEncKey& encKey) {
    try {
        return _dataEncryptorThread.decrypt(threadEntry.data(), encKey);
    } catch (const core::Exception& e) {
        dynamic::ThreadDataV1 result = utils::TypedObjectFactory::createNewObject<dynamic::ThreadDataV1>();
        result.title(std::string());
        result.statusCode(e.getCode());
        return result;
    } catch (const privmx::utils::PrivmxException& e) {
        dynamic::ThreadDataV1 result = utils::TypedObjectFactory::createNewObject<dynamic::ThreadDataV1>();
        result.title(std::string());
        result.statusCode(core::ExceptionConverter::convert(e).getCode());
        return result;
    } catch (...) {
        dynamic::ThreadDataV1 result = utils::TypedObjectFactory::createNewObject<dynamic::ThreadDataV1>();
        result.title(std::string());
        result.statusCode(ENDPOINT_CORE_EXCEPTION_CODE);
        return result;
    }
}

DecryptedThreadDataV4 ThreadApiImpl::decryptThreadV4(server::Thread2DataEntry threadEntry, const core::DecryptedEncKey& encKey) {
    try {
        auto encryptedThreadData = utils::TypedObjectFactory::createObjectFromVar<server::EncryptedThreadDataV4>(threadEntry.data());
        return _threadDataEncryptorV4.decrypt(encryptedThreadData, encKey.key);
    } catch (const core::Exception& e) {
        return DecryptedThreadDataV4{{.dataStructureVersion = 4, .statusCode = e.getCode()}, {},{},{},{}};
    } catch (const privmx::utils::PrivmxException& e) {
        return DecryptedThreadDataV4{{.dataStructureVersion = 4, .statusCode = core::ExceptionConverter::convert(e).getCode()}, {},{},{},{}};
    } catch (...) {
        return DecryptedThreadDataV4{{.dataStructureVersion = 4, .statusCode = ENDPOINT_CORE_EXCEPTION_CODE}, {},{},{},{}};
    }
}

DecryptedThreadDataV5 ThreadApiImpl::decryptThreadV5(server::Thread2DataEntry threadEntry, const core::DecryptedEncKey& encKey) {
    try {
        auto encryptedThreadData = utils::TypedObjectFactory::createObjectFromVar<server::EncryptedThreadDataV5>(threadEntry.data());
        if(encKey.statusCode != 0) {
            auto tmp = _threadDataEncryptorV5.extractPublic(encryptedThreadData);
            tmp.statusCode = encKey.statusCode;
            return tmp;
        }
        return _threadDataEncryptorV5.decrypt(encryptedThreadData, encKey.key);
    } catch (const core::Exception& e) {
        return DecryptedThreadDataV5{{.dataStructureVersion = 5, .statusCode = e.getCode()}, {},{},{},{},{}};
    } catch (const privmx::utils::PrivmxException& e) {
        return DecryptedThreadDataV5{{.dataStructureVersion = 5, .statusCode = core::ExceptionConverter::convert(e).getCode()}, {},{},{},{},{}};
    } catch (...) {
        return DecryptedThreadDataV5{{.dataStructureVersion = 5, .statusCode = ENDPOINT_CORE_EXCEPTION_CODE}, {},{},{},{},{}};
    }
}

Thread ThreadApiImpl::convertThreadDataV1ToThread(server::ThreadInfo threadInfo, dynamic::ThreadDataV1 threadData) {
    std::vector<std::string> users;
    std::vector<std::string> managers;
    for (auto x : threadInfo.users()) {
        users.push_back(x);
    }
    for (auto x : threadInfo.managers()) {
        managers.push_back(x);
    }
    Poco::JSON::Object::Ptr privateMeta = Poco::JSON::Object::Ptr(new Poco::JSON::Object());
    privateMeta->set("title", threadData.title());
    int64_t statusCode = threadData.statusCodeOpt(0);
    return {
        .contextId = threadInfo.contextId(),
        .threadId = threadInfo.id(),
        .createDate = threadInfo.createDate(),
        .creator = threadInfo.creator(),
        .lastModificationDate = threadInfo.lastModificationDate(),
        .lastModifier = threadInfo.lastModifier(),
        .users = users,
        .managers = managers,
        .version = threadInfo.version(),
        .lastMsgDate = threadInfo.lastMsgDate(),
        .publicMeta = core::Buffer::from(""),
        .privateMeta = core::Buffer::from(utils::Utils::stringify(privateMeta)),
        .policy = {},
        .messagesCount = threadInfo.messages(),
        .statusCode = statusCode
    };
}

Thread ThreadApiImpl::convertDecryptedThreadDataV4ToThread(server::ThreadInfo threadInfo, const DecryptedThreadDataV4& threadData) {
    std::vector<std::string> users;
    std::vector<std::string> managers;
    for (auto x : threadInfo.users()) {
        users.push_back(x);
    }
    for (auto x : threadInfo.managers()) {
        managers.push_back(x);
    }

    return {
        .contextId = threadInfo.contextId(),
        .threadId = threadInfo.id(),
        .createDate = threadInfo.createDate(),
        .creator = threadInfo.creator(),
        .lastModificationDate = threadInfo.lastModificationDate(),
        .lastModifier = threadInfo.lastModifier(),
        .users = users,
        .managers = managers,
        .version = threadInfo.version(),
        .lastMsgDate = threadInfo.lastMsgDate(),
        .publicMeta = threadData.publicMeta,
        .privateMeta = threadData.privateMeta,
        .policy = core::Factory::parsePolicyServerObject(threadInfo.policy()), 
        .messagesCount = threadInfo.messages(),
        .statusCode = threadData.statusCode
    };
}

Thread ThreadApiImpl::convertDecryptedThreadDataV5ToThread(server::ThreadInfo threadInfo, const DecryptedThreadDataV5& threadData) {
    std::vector<std::string> users;
    std::vector<std::string> managers;
    for (auto x : threadInfo.users()) {
        users.push_back(x);
    }
    for (auto x : threadInfo.managers()) {
        managers.push_back(x);
    }

    return {
        .contextId = threadInfo.contextId(),
        .threadId = threadInfo.id(),
        .createDate = threadInfo.createDate(),
        .creator = threadInfo.creator(),
        .lastModificationDate = threadInfo.lastModificationDate(),
        .lastModifier = threadInfo.lastModifier(),
        .users = users,
        .managers = managers,
        .version = threadInfo.version(),
        .lastMsgDate = threadInfo.lastMsgDate(),
        .publicMeta = threadData.publicMeta,
        .privateMeta = threadData.privateMeta,
        .policy = core::Factory::parsePolicyServerObject(threadInfo.policy()), 
        .messagesCount = threadInfo.messages(),
        .statusCode = threadData.statusCode
    };
}

std::tuple<Thread, core::DataIntegrityObject> ThreadApiImpl::decryptAndConvertThreadDataToThread(server::ThreadInfo thread, server::Thread2DataEntry threadEntry, const core::DecryptedEncKey& encKey) {
    if (threadEntry.data().type() == typeid(Poco::JSON::Object::Ptr)) {
        auto versioned = utils::TypedObjectFactory::createObjectFromVar<core::server::VersionedData>(threadEntry.data());
        if (!versioned.versionEmpty()) {
            switch (versioned.version()) {
                case 4: {
                    auto decryptedThreadData = decryptThreadV4(threadEntry, encKey);
                    return std::make_tuple(
                        convertDecryptedThreadDataV4ToThread(thread, decryptedThreadData), 
                        core::DataIntegrityObject{
                            .creatorUserId = thread.lastModifier(),
                            .creatorPubKey = decryptedThreadData.authorPubKey,
                            .contextId = thread.contextId(),
                            .containerId = thread.id(),
                            .timestamp = thread.lastModificationDate(),
                            .randomId = 0
                        }
                    );
                }
                case 5: {
                    auto decryptedThreadData = decryptThreadV5(threadEntry, encKey);
                    return std::make_tuple(convertDecryptedThreadDataV5ToThread(thread, decryptedThreadData), decryptedThreadData.dio);
                }
            }
        } 
    } else if (threadEntry.data().isString()) {
        return std::make_tuple(
            convertThreadDataV1ToThread(thread, decryptThreadV1(threadEntry, encKey)),
            core::DataIntegrityObject{
                .creatorUserId = thread.lastModifier(),
                .creatorPubKey = "",
                .contextId = thread.contextId(),
                .containerId = thread.id(),
                .timestamp = thread.lastModificationDate(),
                .randomId = 0
            }
        );
    }
    auto e = UnknowThreadFormatException();
    return std::make_tuple(Thread{ {},{},{},{},{},{},{},{},{},{},{},{},{},{}, .statusCode = e.getCode()}, core::DataIntegrityObject());
}


std::vector<Thread> ThreadApiImpl::decryptAndConvertThreadsDataToThreads(privmx::utils::List<server::ThreadInfo> threads) {
    std::vector<Thread> result;
    std::vector<core::DecryptedEncKeyV2> keys;
    //create verification request for keys
    for (size_t i = 0; i < threads.size(); i++) {
        auto thread = threads.get(i);
        auto thread_data_entry = thread.data().get(thread.data().size()-1);
        auto key = _keyProvider->getKeyAndVerify(thread.keys(), thread_data_entry.keyId(), {.contextId=thread.contextId(), .containerId=thread.id(), .enableVerificationRequest=false});
        keys.push_back(key);
    }
    //send verification request and update key statuscode
    _keyProvider->validateUserData(keys);
    //
    std::vector<core::DataIntegrityObject> threadsDIO;
    std::map<std::string, bool> duplication_check;
    for (size_t i = 0; i < threads.size(); i++) {
        auto thread = threads.get(i);
        try {
            auto tmp = decryptAndConvertThreadDataToThread(thread, thread.data().get(thread.data().size()-1), keys[i]);
            result.push_back(std::get<0>(tmp));
            auto threadDIO = std::get<1>(tmp);
            threadsDIO.push_back(threadDIO);
            //find duplication
            std::string fullRandomId = threadDIO.randomId + "-" + std::to_string(threadDIO.timestamp);
            if(duplication_check.find(fullRandomId) == duplication_check.end()) {
                duplication_check.insert(std::make_pair(fullRandomId, true));
            } else {
                result[result.size()-1].statusCode = core::DataIntegrityObjectDuplicatedException().getCode();
            }
        } catch (const core::Exception& e) {
            result.push_back(Thread{ {},{},{},{},{},{},{},{},{},{},{},{},{},{}, .statusCode = e.getCode()});
            threadsDIO.push_back(core::DataIntegrityObject{});
        }
    }
    std::vector<core::VerificationRequest> verifierInput {};
    for (size_t i = 0; i < result.size(); i++) {
        if(result[i].statusCode == 0) {
            verifierInput.push_back({
                .contextId = result[i].contextId,
                .senderId = result[i].lastModifier,
                .senderPubKey = threadsDIO[i].creatorPubKey,
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

Thread ThreadApiImpl::decryptAndConvertThreadDataToThread(server::ThreadInfo thread) {
    auto thread_data_entry = thread.data().get(thread.data().size()-1);
    auto key = _keyProvider->getKeyAndVerify(thread.keys(), thread_data_entry.keyId(), {.contextId=thread.contextId(), .containerId=thread.id()});
    Thread result;
    core::DataIntegrityObject threadDIO;
    std::tie(result, threadDIO) = decryptAndConvertThreadDataToThread(thread, thread_data_entry, key);
    if(result.statusCode != 0) return result;
    std::vector<core::VerificationRequest> verifierInput {};
    verifierInput.push_back({
        .contextId = result.contextId,
        .senderId = result.lastModifier,
        .senderPubKey = threadDIO.creatorPubKey,
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

dynamic::MessageDataV2 ThreadApiImpl::decryptMessageDataV2(server::Message message, const core::DecryptedEncKey& encKey) {
    try {
        auto msg = _messageDataV2Encryptor.decryptAndGetSign(message.data(), encKey);
        return msg.data();
    } catch (const core::Exception& e) {
        dynamic::MessageDataV2 result = utils::TypedObjectFactory::createNewObject<dynamic::MessageDataV2>();
        result.v(0);
        result.statusCode(e.getCode());
        return result;
    } catch (const privmx::utils::PrivmxException& e) {
        dynamic::MessageDataV2 result = utils::TypedObjectFactory::createNewObject<dynamic::MessageDataV2>();
        result.v(0);
        result.statusCode(core::ExceptionConverter::convert(e).getCode());
        return result;
    } catch (...) {
        dynamic::MessageDataV2 result = utils::TypedObjectFactory::createNewObject<dynamic::MessageDataV2>();
        result.v(0);
        result.statusCode(ENDPOINT_CORE_EXCEPTION_CODE);
        return result;
    }
    
}

dynamic::MessageDataV3 ThreadApiImpl::decryptMessageDataV3(server::Message message, const core::DecryptedEncKey& encKey) {
    try {
        auto msg = _messageDataV3Encryptor.decryptAndGetSign(message.data(), encKey);
        return msg.data();
    } catch (const core::Exception& e) {
        dynamic::MessageDataV3 result = utils::TypedObjectFactory::createNewObject<dynamic::MessageDataV3>();
        result.v(0);
        result.statusCode(e.getCode());
        return result;
    } catch (const privmx::utils::PrivmxException& e) {
        dynamic::MessageDataV3 result = utils::TypedObjectFactory::createNewObject<dynamic::MessageDataV3>();
        result.v(0);
        result.statusCode(core::ExceptionConverter::convert(e).getCode());
        return result;
    } catch (...) {
        dynamic::MessageDataV3 result = utils::TypedObjectFactory::createNewObject<dynamic::MessageDataV3>();
        result.v(0);
        result.statusCode(ENDPOINT_CORE_EXCEPTION_CODE);
        return result;
    }
}

DecryptedMessageDataV4 ThreadApiImpl::decryptMessageDataV4(server::Message message, const core::DecryptedEncKey& encKey) {
    try {
        auto encryptedMessageData = utils::TypedObjectFactory::createObjectFromVar<server::EncryptedMessageDataV4>(message.data());
        return _messageDataEncryptorV4.decrypt(encryptedMessageData, encKey.key);
    } catch (const core::Exception& e) {
        return DecryptedMessageDataV4{{.dataStructureVersion = 4, .statusCode = e.getCode()}, {},{},{},{},{}};
    } catch (const privmx::utils::PrivmxException& e) {
        return DecryptedMessageDataV4{{.dataStructureVersion = 4, .statusCode = core::ExceptionConverter::convert(e).getCode()}, {},{},{},{},{}};
    } catch (...) {
        return DecryptedMessageDataV4{{.dataStructureVersion = 4, .statusCode = ENDPOINT_CORE_EXCEPTION_CODE}, {},{},{},{},{}};
    }
}

DecryptedMessageDataV5 ThreadApiImpl::decryptMessageDataV5(server::Message message, const core::DecryptedEncKey& encKey) {
    try {
        auto encryptedMessageData = utils::TypedObjectFactory::createObjectFromVar<server::EncryptedMessageDataV5>(message.data());
        if(encKey.statusCode != 0) {
            auto tmp = _messageDataEncryptorV5.extractPublic(encryptedMessageData);
            tmp.statusCode = encKey.statusCode;
            return tmp;
        }
        return _messageDataEncryptorV5.decrypt(encryptedMessageData, encKey.key);
    } catch (const core::Exception& e) {
        return DecryptedMessageDataV5{{.dataStructureVersion = 5, .statusCode = e.getCode()}, {},{},{},{},{},{}};
    } catch (const privmx::utils::PrivmxException& e) {
        return DecryptedMessageDataV5{{.dataStructureVersion = 5, .statusCode = core::ExceptionConverter::convert(e).getCode()}, {},{},{},{},{},{}};
    } catch (...) {
        return DecryptedMessageDataV5{{.dataStructureVersion = 5, .statusCode = ENDPOINT_CORE_EXCEPTION_CODE}, {},{},{},{},{},{}};
    }
}

Message ThreadApiImpl::convertMessageDataV2ToMessage(server::Message message, dynamic::MessageDataV2 messageData) {
    Pson::BinaryString data = messageData.textOpt("");
    Poco::JSON::Object::Ptr privateMeta = messageData.copy();
    privateMeta->remove("text");
    privateMeta->remove("statusCode");
    Message ret {
        .info = {
            .threadId = message.threadId(),
            .messageId = message.id(),
            .createDate = message.createDate(),
            .author = message.author(),
        },
        .publicMeta = core::Buffer(), 
        .privateMeta = core::Buffer::from(privmx::utils::Utils::stringify(privateMeta)),
        .data = core::Buffer::from(data),
        .authorPubKey = messageData.author().pubKey(),
        .statusCode = messageData.statusCodeOpt(0)
    };
    return ret;
}

Message ThreadApiImpl::convertMessageDataV3ToMessage(server::Message message, dynamic::MessageDataV3 messageData) {
    Message ret {
        .info = {
            .threadId = message.threadId(),
            .messageId = message.id(),
            .createDate = message.createDate(),
            .author = message.author(),
        },
        .publicMeta = core::Buffer::from(messageData.publicMetaOpt(Pson::BinaryString())), 
        .privateMeta = core::Buffer::from(messageData.privateMetaOpt(Pson::BinaryString())),
        .data = core::Buffer::from(messageData.dataOpt(Pson::BinaryString())),
        .authorPubKey = std::string(),
        .statusCode = messageData.statusCodeOpt(0)
    };
    return ret;
}

Message ThreadApiImpl::convertDecryptedMessageDataV4ToMessage(server::Message message, DecryptedMessageDataV4 messageData) {
    Message ret {
        .info = {
            .threadId = message.threadId(),
            .messageId = message.id(),
            .createDate = message.createDate(),
            .author = message.author(),
        },
        .publicMeta = messageData.publicMeta, 
        .privateMeta = messageData.privateMeta,
        .data = messageData.data,
        .authorPubKey = messageData.authorPubKey,
        .statusCode = messageData.statusCode
    };
    return ret;
}

Message ThreadApiImpl::convertDecryptedMessageDataV5ToMessage(server::Message message, DecryptedMessageDataV5 messageData) {
    Message ret {
        .info = {
            .threadId = message.threadId(),
            .messageId = message.id(),
            .createDate = message.createDate(),
            .author = message.author(),
        },
        .publicMeta = messageData.publicMeta, 
        .privateMeta = messageData.privateMeta,
        .data = messageData.data,
        .authorPubKey = messageData.authorPubKey,
        .statusCode = messageData.statusCode
    };
    return ret;
}

std::tuple<Message, core::DataIntegrityObject> ThreadApiImpl::decryptAndConvertMessageDataToMessage(server::Message message, const core::DecryptedEncKey& encKey) {
    // If data is not string, then data is object and has version field
    // Solution with data as object is newer than data as base64 string
    if (message.data().type() == typeid(Poco::JSON::Object::Ptr)) {
        auto versioned = utils::TypedObjectFactory::createObjectFromVar<core::server::VersionedData>(message.data());
        if (!versioned.versionEmpty()) {
            switch (versioned.version()) {
            case 4: {
                auto decryptedMessage = decryptMessageDataV4(message, encKey);
                return std::make_tuple(
                    convertDecryptedMessageDataV4ToMessage(message, decryptedMessage), 
                    core::DataIntegrityObject{
                        .creatorUserId = message.updates().size() == 0 ? message.author() : message.updates().get(message.updates().size()-1).author(),
                        .creatorPubKey = decryptedMessage.authorPubKey,
                        .contextId = message.contextId(),
                        .containerId = message.threadId(),
                        .timestamp = message.updates().size() == 0 ? message.createDate() : message.updates().get(message.updates().size()-1).createDate(),
                        .randomId = 0
                    }
                );
            }
            case 5:
                auto decryptedMessage = decryptMessageDataV5(message, encKey);
                return std::make_tuple(
                    convertDecryptedMessageDataV5ToMessage(message, decryptedMessage), 
                    decryptedMessage.dio
                );
            }
        } 
    } else if (message.data().isString()) {
        // Temporary Solution need better way to dif V3 from V2
        if(core::DataEncryptorUtil::hasSign(utils::Base64::toString(message.data()))) {
            return std::make_tuple(
                convertMessageDataV3ToMessage(message,  decryptMessageDataV3(message, encKey)), 
                core::DataIntegrityObject{
                    .creatorUserId = message.updates().size() == 0 ? message.author() : message.updates().get(message.updates().size()-1).author(),
                    .creatorPubKey = "",
                    .contextId = message.contextId(),
                    .containerId = message.threadId(),
                    .timestamp = message.updates().size() == 0 ? message.createDate() : message.updates().get(message.updates().size()-1).createDate(),
                    .randomId = 0
                }
            );
        }
        return std::make_tuple(
            convertMessageDataV2ToMessage(message,  decryptMessageDataV2(message, encKey)), 
            core::DataIntegrityObject{
                .creatorUserId = message.updates().size() == 0 ? message.author() : message.updates().get(message.updates().size()-1).author(),
                .creatorPubKey = "",
                .contextId = message.contextId(),
                .containerId = message.threadId(),
                .timestamp = message.updates().size() == 0 ? message.createDate() : message.updates().get(message.updates().size()-1).createDate(),
                .randomId = 0
            }
        );
    }

    auto e = UnknowMessageFormatException();
    return std::make_tuple(Message{{},{},{},{},{},.statusCode = e.getCode()}, core::DataIntegrityObject());
}

std::vector<Message> ThreadApiImpl::decryptAndConvertMessagesDataToMessages(server::ThreadInfo thread, utils::List<server::Message> messages) {
    std::set<std::string> keyIds;
    for (auto message : messages) {
        keyIds.insert(message.keyId());
    }
    auto keyMap = _keyProvider->getKeysAndVerify(thread.keys(), keyIds, {.contextId=thread.contextId(), .containerId=thread.id()});
    std::vector<Message> result;
    std::map<std::string, bool> duplication_check;
    for (auto message : messages) {
        try {
            auto statusCode = validateMessageDataIntegrity(message);
            if(statusCode == 0) {
                auto tmp = decryptAndConvertMessageDataToMessage(message, keyMap.at(message.keyId()));
                result.push_back(std::get<0>(tmp));
                auto messageDIO = std::get<1>(tmp);
                //find duplication
                std::string fullRandomId =  messageDIO.randomId + "-" + std::to_string(messageDIO.timestamp);
                if(duplication_check.find(fullRandomId) == duplication_check.end()) {
                    duplication_check.insert(std::make_pair(fullRandomId, true));
                } else {
                    result[result.size()-1].statusCode = core::DataIntegrityObjectDuplicatedException().getCode();
                }
            } else {
                result.push_back(Message{{},{},{},{},{},.statusCode = statusCode});
            }
        } catch (const core::Exception& e) {
            result.push_back(Message{{},{},{},{},{},.statusCode = e.getCode()});
        }
    }
    std::vector<core::VerificationRequest> verifierInput {};
    for (auto message: result) {
        if(message.statusCode == 0) {
            verifierInput.push_back({
                .contextId = thread.contextId(),
                .senderId = message.info.author,
                .senderPubKey = message.authorPubKey,
                .date = message.info.createDate
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

Message ThreadApiImpl::decryptAndConvertMessageDataToMessage(server::ThreadInfo thread, server::Message message) {
    auto keyId = message.keyId();
    auto encKey = _keyProvider->getKeyAndVerify(thread.keys(), keyId, {.contextId=thread.contextId(), .containerId=thread.id()});
    _messageKeyIdFormatValidator.assertKeyIdFormat(keyId);
    Message result;
    core::DataIntegrityObject messageDIO;
    std::tie(result, messageDIO) = decryptAndConvertMessageDataToMessage(message, encKey);
    if(result.statusCode != 0) return result;
    std::vector<core::VerificationRequest> verifierInput {};
        verifierInput.push_back({
            .contextId = thread.contextId(),
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

Message ThreadApiImpl::decryptAndConvertMessageDataToMessage(server::Message message) {
    try {
        auto thread = getRawThreadFromCacheOrBridge(message.threadId());
        return decryptAndConvertMessageDataToMessage(thread, message);
    } catch (const core::Exception& e) {
        return Message{{},{},{},{},{},.statusCode = e.getCode()};
    } catch (const privmx::utils::PrivmxException& e) {
        return Message{{},{},{},{},{},.statusCode = e.getCode()};
    } catch (...) {
        return Message{{},{},{},{},{},.statusCode = ENDPOINT_CORE_EXCEPTION_CODE};
    }
}

std::string ThreadApiImpl::decryptThreadInternalMeta(server::Thread2DataEntry threadEntry, const core::DecryptedEncKey& encKey) {
    if (threadEntry.data().type() == typeid(Poco::JSON::Object::Ptr)) {
        auto versioned = utils::TypedObjectFactory::createObjectFromVar<core::server::VersionedData>(threadEntry.data());
        if (!versioned.versionEmpty()) {
            switch (versioned.version()) {
            case 4:
                return std::string();
            case 5:
                return decryptThreadV5(threadEntry, encKey).internalMeta.stdString();
            }
        } 
    } else if (threadEntry.data().isString()) {
        return std::string();
    }
    throw UnknowThreadFormatException();
}

core::DecryptedEncKey ThreadApiImpl::getThreadCurrentEncKey(server::ThreadInfo thread) {
    auto thread_data_entry = thread.data().get(thread.data().size()-1);
    auto key = _keyProvider->getKeyAndVerify(thread.keys(), thread_data_entry.keyId(), 
        {.contextId=thread.contextId(), .containerId=thread.id()}
    );
    return key;
}

server::ThreadInfo ThreadApiImpl::getRawThreadFromCacheOrBridge(const std::string& threadId) {
    // useing threadProvider only with THREAD_TYPE_FILTER_FLAG 
    // making sure to have valid cache
    if(!_subscribeForThread) _threadProvider.update(threadId);
    auto threadContainerInfo = _threadProvider.get(threadId);
    if(threadContainerInfo.status != core::DataIntegrityStatus::ValidationSucceed) {
        throw ThreadDataIntegrityException();
    }
    return threadContainerInfo.container;
}

void ThreadApiImpl::assertThreadExist(const std::string& threadId) {
    //check if thread is in cache or on server
    getRawThreadFromCacheOrBridge(threadId);
}

uint32_t ThreadApiImpl::validateThreadDataIntegrity(server::ThreadInfo thread) {
    auto thread_data_entry = thread.data().get(thread.data().size()-1);
    if (thread_data_entry.data().type() == typeid(Poco::JSON::Object::Ptr)) {
        auto versioned = utils::TypedObjectFactory::createObjectFromVar<core::server::VersionedData>(thread_data_entry.data());
        if (!versioned.versionEmpty()) {
            switch (versioned.version()) {
            case 4:
                return 0;
            case 5: 
                {
                    auto thread_data = utils::TypedObjectFactory::createObjectFromVar<server::EncryptedThreadDataV5>(thread_data_entry.data());
                    auto dio = _threadDataEncryptorV5.getDIOAndAssertIntegrity(thread_data);
                    if(
                        dio.contextId != thread.contextId() ||
                        dio.containerId != thread.id() ||
                        dio.creatorUserId != thread.lastModifier() ||
                        !core::TimestampValidator::validate(dio.timestamp, thread.lastModificationDate())
                    ) {
                        return ThreadDataIntegrityException().getCode();
                    }
                    return 0;
                }
            }
        } 
    } else if(thread_data_entry.data().isString()) {
        return 0;
    }
    return UnknowThreadFormatException().getCode();
}

uint32_t ThreadApiImpl::validateMessageDataIntegrity(server::Message message) {
    auto message_data = message.data();
    if (message_data.type() == typeid(Poco::JSON::Object::Ptr)) {
        auto versioned = utils::TypedObjectFactory::createObjectFromVar<core::server::VersionedData>(message_data);
        if (!versioned.versionEmpty()) {
            switch (versioned.version()) {
            case 4:
                return 0;
            case 5: 
                {
                    auto encData = utils::TypedObjectFactory::createObjectFromVar<server::EncryptedMessageDataV5>(message_data);
                    auto dio = _messageDataEncryptorV5.getDIOAndAssertIntegrity(encData);
                    if(
                        dio.contextId != message.contextId() ||
                        dio.containerId != message.threadId() ||
                        dio.creatorUserId != (message.updates().size() == 0 ? message.author() : message.updates().get(message.updates().size()-1).author()) ||
                        !core::TimestampValidator::validate(dio.timestamp, (message.updates().size() == 0 ? message.createDate() : message.updates().get(message.updates().size()-1).createDate()))
                    ) {
                        return MessageDataIntegrityException().getCode();
                    }
                    return 0;
                }
            }
        }
    } else if(message_data.isString()) {
        return 0;
    }
    return UnknowMessageFormatException().getCode();
}


