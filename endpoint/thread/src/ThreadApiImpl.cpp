/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include <privmx/utils/Debug.hpp>
#include <privmx/utils/JsonHelper.hpp>
#include <privmx/utils/Utils.hpp>

#include <privmx/endpoint/core/CoreConstants.hpp>
#include <privmx/endpoint/core/EndpointUtils.hpp>
#include <privmx/endpoint/core/EventMiddleware.hpp>
#include <privmx/endpoint/core/ExceptionConverter.hpp>
#include <privmx/endpoint/core/TimestampValidator.hpp>
#include <privmx/endpoint/core/Types.hpp>
#include <privmx/endpoint/core/Utils.hpp>
#include <privmx/endpoint/core/VarDeserializer.hpp>
#include <privmx/endpoint/core/VarSerializer.hpp>

#include "privmx/endpoint/core/EventBuilder.hpp"
#include "privmx/endpoint/core/ListQueryMapper.hpp"
#include "privmx/endpoint/core/Mapper.hpp"
#include "privmx/endpoint/core/UsersKeysResolver.hpp"
#include "privmx/endpoint/thread/Mapper.hpp"
#include "privmx/endpoint/thread/ServerTypes.hpp"
#include "privmx/endpoint/thread/ThreadApiImpl.hpp"
#include "privmx/endpoint/thread/ThreadException.hpp"
#include <privmx/endpoint/core/ConvertedExceptions.hpp>

using namespace privmx::endpoint;
using namespace thread;

ThreadApiImpl::ThreadApiImpl(
    const privfs::RpcGateway::Ptr& gateway,
    const privmx::crypto::PrivateKey& userPrivKey,
    const std::shared_ptr<core::KeyProvider>& keyProvider,
    const std::string& host,
    const std::shared_ptr<core::EventMiddleware>& eventMiddleware,
    const core::Connection& connection
)
    : ModuleBaseApi(userPrivKey, keyProvider, host, eventMiddleware, connection), _gateway(gateway),
      _userPrivKey(userPrivKey), _keyProvider(keyProvider), _host(host), _eventMiddleware(eventMiddleware),
      _connection(connection), _serverApi(ServerApi(gateway)), _subscriber(gateway, THREAD_TYPE_FILTER_FLAG),
      _messageDataSchemaMapper(userPrivKey, connection), _threadDataSchemaMapper(userPrivKey, connection),
      _forbiddenChannelsNames({INTERNAL_EVENT_CHANNEL_NAME, "thread", "messages"}) {
    _notificationListenerId = _eventMiddleware->addNotificationEventListener(
        std::bind(&ThreadApiImpl::processNotificationEvent, this, std::placeholders::_1, std::placeholders::_2)
    );
    _connectedListenerId = _eventMiddleware->addConnectedEventListener(
        std::bind(&ThreadApiImpl::processConnectedEvent, this)
    );
    _disconnectedListenerId = _eventMiddleware->addDisconnectedEventListener(
        std::bind(&ThreadApiImpl::processDisconnectedEvent, this)
    );
}

ThreadApiImpl::~ThreadApiImpl() {
    _eventMiddleware->removeNotificationEventListener(_notificationListenerId);
    _eventMiddleware->removeConnectedEventListener(_connectedListenerId);
    _eventMiddleware->removeDisconnectedEventListener(_disconnectedListenerId);
    _guardedExecutor.reset();
    LOG_TRACE("~ThreadApiImpl Done");
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
    std::string resourceId = core::EndpointUtils::generateId();
    auto threadDIO = _connection.getImpl()->createDIO(contextId, resourceId);
    auto threadSecret = _keyProvider->generateSecret();

    core::ModuleDataToEncryptV5 threadDataToEncrypt{
        .publicMeta = publicMeta,
        .privateMeta = privateMeta,
        .internalMeta = core::
            ModuleInternalMetaV5{.secret = threadSecret, .resourceId = resourceId, .randomId = threadDIO.randomId},
        .dio = threadDIO
    };
    auto allUsers = core::EndpointUtils::uniqueListUserWithPubKey(users, managers);
    server::ThreadCreateModel create_thread_model;
    create_thread_model.resourceId = resourceId;
    create_thread_model.contextId = contextId;
    create_thread_model.keyId = threadKey.id;
    create_thread_model.data = _threadDataSchemaMapper.encrypt(threadDataToEncrypt, threadKey.key);
    create_thread_model.keys = _keyProvider->prepareKeysList(
        allUsers, threadKey, threadDIO, {.contextId = contextId, .resourceId = resourceId}, threadSecret
    );
    create_thread_model.users = mapUsers(users);
    create_thread_model.managers = mapUsers(managers);
    if (type.length() > 0) {
        create_thread_model.type = type;
    }
    if (policies.has_value()) {
        create_thread_model.policy = privmx::endpoint::core::Factory::createPolicyServerObject(policies.value());
    }
    PRIVMX_DEBUG_TIME_CHECKPOINT(PlatformThread, _createThreadEx, data encrypted)
    auto result = _serverApi.threadCreate(create_thread_model);
    PRIVMX_DEBUG_TIME_STOP(PlatformThread, _createThreadEx, data send)
    return result.threadId;
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
    server::ThreadGetModel getModel;
    getModel.threadId = threadId;
    auto currentThread = _serverApi.threadGet(getModel).thread;
    const auto& currentThreadEntry = currentThread.data.back();
    auto currentThreadResourceId = currentThread.resourceId ? currentThread.resourceId.value() :
                                                              core::EndpointUtils::generateId();
    core::EncKeyLocation location{.contextId = currentThread.contextId, .resourceId = currentThreadResourceId};
    core::KeyDecryptionAndVerificationRequest keysRequest;
    keysRequest.addAll(currentThread.keys, location);
    auto threadKeys{_keyProvider->getKeysAndVerify(keysRequest).at(location)};
    auto currentThreadKey{findEncKeyByKeyId(threadKeys, currentThreadEntry.keyId)};
    auto threadInternalMeta = extractAndDecryptModuleInternalMeta(currentThreadEntry, currentThreadKey);

    auto usersKeysResolver{core::UsersKeysResolver::create(
        currentThread.users, currentThread.managers, users, managers, forceGenerateNewKey, currentThreadKey
    )};

    if (!_keyProvider->verifyKeysSecret(threadKeys, location, threadInternalMeta.secret)) {
        throw ThreadEncryptionKeyValidationException();
    }
    // setting thread Key adding new users
    core::EncKey threadKey = currentThreadKey;
    core::DataIntegrityObject updateThreadDio = _connection.getImpl()->createDIO(
        currentThread.contextId, currentThreadResourceId
    );

    std::vector<core::server::KeyEntrySet> keys;
    if (usersKeysResolver->doNeedNewKey()) {
        threadKey = _keyProvider->generateKey();
        keys = _keyProvider->prepareKeysList(
            usersKeysResolver->getNewUsers(), threadKey, updateThreadDio, location, threadInternalMeta.secret
        );
    }

    auto usersToAddMissingKey{usersKeysResolver->getUsersToAddKey()};
    if (usersToAddMissingKey.size() > 0) {
        auto tmp = _keyProvider->prepareMissingKeysForNewUsers(
            threadKeys, usersToAddMissingKey, updateThreadDio, location, threadInternalMeta.secret
        );
        keys.insert(keys.end(), tmp.begin(), tmp.end());
    }
    server::ThreadUpdateModel model;
    model.id = threadId;
    model.resourceId = currentThreadResourceId;
    model.keyId = threadKey.id;
    model.keys = keys;
    model.users = mapUsers(users);
    model.managers = mapUsers(managers);
    model.version = version;
    model.force = force;
    if (policies.has_value()) {
        model.policy = privmx::endpoint::core::Factory::createPolicyServerObject(policies.value());
    }
    core::ModuleDataToEncryptV5 threadDataToEncrypt{
        .publicMeta = publicMeta,
        .privateMeta = privateMeta,
        .internalMeta =
            core::ModuleInternalMetaV5{
                .secret = threadInternalMeta.secret,
                .resourceId = currentThreadResourceId,
                .randomId = updateThreadDio.randomId
            },
        .dio = updateThreadDio
    };
    model.data = _threadDataSchemaMapper.encrypt(threadDataToEncrypt, threadKey.key);

    PRIVMX_DEBUG_TIME_CHECKPOINT(PlatformThread, updateThread, data encrypted)
    _serverApi.threadUpdate(model);
    invalidateModuleKeysInCache(threadId);
    PRIVMX_DEBUG_TIME_STOP(PlatformThread, updateThread, data send)
}

void ThreadApiImpl::deleteThread(const std::string& threadId) {
    server::ThreadDeleteModel model{.threadId = threadId};
    _serverApi.threadDelete(model);
    invalidateModuleKeysInCache(threadId);
}

Thread ThreadApiImpl::getThread(const std::string& threadId) {
    return _getThreadEx(threadId, THREAD_TYPE_FILTER_FLAG);
}

Thread ThreadApiImpl::getThreadEx(const std::string& threadId, const std::string& type) {
    return _getThreadEx(threadId, type);
}

Thread ThreadApiImpl::_getThreadEx(const std::string& threadId, const std::string& type) {
    PRIVMX_DEBUG_TIME_START(PlatformThread, _getThreadEx)
    server::ThreadGetModel params;
    params.threadId = threadId;
    if (type.length() > 0) {
        params.type = type;
    }
    PRIVMX_DEBUG_TIME_CHECKPOINT(PlatformThread, _getThreadEx, getting thread)
    auto thread = _serverApi.threadGet(params).thread;
    PRIVMX_DEBUG_TIME_CHECKPOINT(PlatformThread, _getThreadEx, data send)
    // Add to cache
    setNewModuleKeysInCache(thread.id, threadToModuleKeys(thread), thread.version);
    // decrypt
    auto result = _threadDataSchemaMapper.validateDecryptAndConvertThread(thread, _keyProvider);
    PRIVMX_DEBUG_TIME_CHECKPOINT(PlatformThread, _getThreadEx, data decrypted)
    return result;
}

core::PagingList<Thread> ThreadApiImpl::listThreads(
    const std::string& contextId,
    const core::PagingQuery& pagingQuery
) {
    return _listThreadsEx(contextId, pagingQuery, THREAD_TYPE_FILTER_FLAG);
}

core::PagingList<Thread> ThreadApiImpl::listThreadsEx(
    const std::string& contextId,
    const core::PagingQuery& pagingQuery,
    const std::string& type
) {
    return _listThreadsEx(contextId, pagingQuery, type);
}

core::PagingList<Thread> ThreadApiImpl::_listThreadsEx(
    const std::string& contextId,
    const core::PagingQuery& pagingQuery,
    const std::string& type
) {
    PRIVMX_DEBUG_TIME_START(PlatformThread, _listThreadsEx)
    server::ThreadListModel model;
    model.contextId = contextId;
    if (type.length() > 0) {
        model.type = type;
    }
    core::ListQueryMapper::map(model, pagingQuery);
    PRIVMX_DEBUG_TIME_CHECKPOINT(PlatformThread, _listThreadsEx, getting threadList)
    auto threadsList = _serverApi.threadList(model);
    PRIVMX_DEBUG_TIME_CHECKPOINT(PlatformThread, _listThreadsEx, data send)
    for (const auto& thread : threadsList.threads) {
        setNewModuleKeysInCache(thread.id, threadToModuleKeys(thread), thread.version);
    }
    std::vector<Thread> threads = _threadDataSchemaMapper.validateDecryptAndConvertThreads(
        threadsList.threads, _keyProvider
    );
    PRIVMX_DEBUG_TIME_STOP(PlatformThread, _listThreadsEx, data decrypted)
    return core::PagingList<Thread>({.totalAvailable = threadsList.count, .readItems = threads});
}

Message ThreadApiImpl::getMessage(const std::string& messageId) {
    PRIVMX_DEBUG_TIME_START(PlatformThread, getMessage)
    server::ThreadMessageGetModel model{.messageId = messageId};
    PRIVMX_DEBUG_TIME_CHECKPOINT(PlatformThread, getMessage, getting message)
    auto message = _serverApi.threadMessageGet(model).message;
    PRIVMX_DEBUG_TIME_CHECKPOINT(PlatformThread, getMessage, data recived);
    Message result;
    PRIVMX_DEBUG_TIME_CHECKPOINT(PlatformThread, getMessage, decrypting message)
    result = _messageDataSchemaMapper.validateDecryptAndConvertMessage(
        message, getMessageDecryptionKeys(message), _keyProvider
    );
    PRIVMX_DEBUG_TIME_STOP(PlatformThread, getMessage, data decrypted)
    return result;
}

core::PagingList<Message> ThreadApiImpl::listMessages(
    const std::string& threadId,
    const core::PagingQuery& pagingQuery
) {
    PRIVMX_DEBUG_TIME_START(PlatformThread, listMessages)
    server::ThreadMessagesGetModel model;
    model.threadId = threadId;
    core::ListQueryMapper::map(model, pagingQuery);
    PRIVMX_DEBUG_TIME_CHECKPOINT(PlatformThread, listMessages, getting messageList)
    auto messagesList = _serverApi.threadMessagesGet(model);
    PRIVMX_DEBUG_TIME_CHECKPOINT(PlatformThread, listMessages, getting thread)
    const auto& thread = messagesList.thread;
    _threadDataSchemaMapper.assertDataIntegrity(thread);
    setNewModuleKeysInCache(thread.id, threadToModuleKeys(thread), thread.version);
    PRIVMX_DEBUG_TIME_CHECKPOINT(PlatformThread, listMessages, data send)
    auto messages = _messageDataSchemaMapper.validateDecryptAndConvertMessages(
        messagesList.messages, threadToModuleKeys(thread), _keyProvider
    );
    PRIVMX_DEBUG_TIME_STOP(PlatformThread, listMessages, data decrypted)
    return core::PagingList<Message>({.totalAvailable = messagesList.count, .readItems = messages});
}
std::string ThreadApiImpl::sendMessage(
    const std::string& threadId,
    const core::Buffer& publicMeta,
    const core::Buffer& privateMeta,
    const core::Buffer& data
) {
    try {
        auto currentKeys{getModuleKeys(threadId)};
        return sendMessageRequest(threadId, publicMeta, privateMeta, data, currentKeys);
    } catch (const privmx::utils::PrivmxException& e) {
        if (core::ExceptionConverter::convert(e).getCode() ==
            privmx::endpoint::server::InvalidThreadKeyException().getCode()) {
            auto newestKeys{getNewModuleKeysAndUpdateCache(threadId)};
            return sendMessageRequest(threadId, publicMeta, privateMeta, data, newestKeys);
        }
        throw e;
    }
}

std::string ThreadApiImpl::sendMessageRequest(
    const std::string& threadId,
    const core::Buffer& publicMeta,
    const core::Buffer& privateMeta,
    const core::Buffer& data,
    const core::ModuleKeys& keys
) {
    PRIVMX_DEBUG_TIME_START(PlatformThread, sendMessageRequest);
    core::DecryptedEncKeyV2 msgKey = getAndValidateModuleCurrentEncKey(keys);
    if (msgKey.statusCode != 0) {
        throw ThreadEncryptionKeyValidationException(
            "Current encryption key statusCode: " + std::to_string(msgKey.statusCode)
        );
    }
    auto resourceId = core::EndpointUtils::generateId();
    server::ThreadMessageSendModel send_message_model;
    send_message_model.resourceId = resourceId;
    send_message_model.threadId = threadId;
    send_message_model.keyId = msgKey.id;
    send_message_model.data = encryptMessageData(threadId, resourceId, publicMeta, privateMeta, data, keys);
    PRIVMX_DEBUG_TIME_CHECKPOINT(PlatformThread, sendMessageRequest, data encrypted)
    auto result = _serverApi.threadMessageSend(send_message_model);
    PRIVMX_DEBUG_TIME_STOP(PlatformThread, sendMessageRequest, data send)
    return result.messageId;
}

void ThreadApiImpl::deleteMessage(const std::string& messageId) {
    server::ThreadMessageDeleteModel model{.messageId = messageId};
    _serverApi.threadMessageDelete(model);
}
void ThreadApiImpl::updateMessage(
    const std::string& messageId,
    const core::Buffer& publicMeta,
    const core::Buffer& privateMeta,
    const core::Buffer& data
) {
    PRIVMX_DEBUG_TIME_START(PlatformThread, updateMessage);
    server::ThreadMessageGetModel model;
    model.messageId = messageId;
    PRIVMX_DEBUG_TIME_CHECKPOINT(PlatformThread, updateMessage, getting message)
    auto message = _serverApi.threadMessageGet(model).message;
    try {
        auto currentKeys{getModuleKeys(message.threadId)};
        return updateMessageRequest(
            messageId, message.resourceId.empty() ? core::EndpointUtils::generateId() : message.resourceId,
            message.threadId, publicMeta, privateMeta, data, currentKeys
        );
    } catch (const privmx::utils::PrivmxException& e) {
        if (core::ExceptionConverter::convert(e).getCode() ==
            privmx::endpoint::server::InvalidThreadKeyException().getCode()) {
            auto newestKeys{getNewModuleKeysAndUpdateCache(message.threadId)};
            return updateMessageRequest(
                messageId, message.resourceId.empty() ? core::EndpointUtils::generateId() : message.resourceId,
                message.threadId, publicMeta, privateMeta, data, newestKeys
            );
        }
        e.rethrow();
    }
}

void ThreadApiImpl::updateMessageRequest(
    const std::string& messageId,
    const std::string& resourceId,
    const std::string& threadId,
    const core::Buffer& publicMeta,
    const core::Buffer& privateMeta,
    const core::Buffer& data,
    const core::ModuleKeys& keys
) {
    PRIVMX_DEBUG_TIME_START(PlatformThread, updateMessageRequest);
    core::DecryptedEncKeyV2 msgKey = getAndValidateModuleCurrentEncKey(keys);
    if (msgKey.statusCode != 0) {
        throw ThreadEncryptionKeyValidationException(
            "Current encryption key statusCode: " + std::to_string(msgKey.statusCode)
        );
    }
    server::ThreadMessageUpdateModel send_message_model;
    send_message_model.messageId = messageId;
    send_message_model.keyId = msgKey.id;
    send_message_model.data = encryptMessageData(threadId, resourceId, publicMeta, privateMeta, data, keys);
    PRIVMX_DEBUG_TIME_CHECKPOINT(PlatformThread, updateMessageRequest, data encrypted)
    _serverApi.threadMessageUpdate(send_message_model);
    PRIVMX_DEBUG_TIME_STOP(PlatformThread, updateMessageRequest, data send)
}

void ThreadApiImpl::processNotificationEvent(const std::string& type, const core::NotificationEvent& notification) {
    auto subscriptionQuery = _subscriber.getSubscriptionQuery(notification.subscriptions);
    if (!subscriptionQuery.has_value()) {
        return;
    }
    _guardedExecutor->exec([&, type, notification]() {
        if (type == "threadCreated") {
            auto raw = server::ThreadInfo::fromJSON(notification.data);
            if (raw.type.value_or(std::string(THREAD_TYPE_FILTER_FLAG)) == THREAD_TYPE_FILTER_FLAG) {
                setNewModuleKeysInCache(raw.id, threadToModuleKeys(raw), raw.version);
                auto data = _threadDataSchemaMapper.validateDecryptAndConvertThread(raw, _keyProvider);
                auto event = core::EventBuilder::buildEvent<ThreadCreatedEvent>("thread", data, notification);
                _eventMiddleware->emitApiEvent(event);
            }
        } else if (type == "threadUpdated") {
            auto raw = server::ThreadInfo::fromJSON(notification.data);
            if (raw.type.value_or(std::string(THREAD_TYPE_FILTER_FLAG)) == THREAD_TYPE_FILTER_FLAG) {
                setNewModuleKeysInCache(raw.id, threadToModuleKeys(raw), raw.version);
                auto data = _threadDataSchemaMapper.validateDecryptAndConvertThread(raw, _keyProvider);
                auto event = core::EventBuilder::buildEvent<ThreadUpdatedEvent>("thread", data, notification);
                _eventMiddleware->emitApiEvent(event);
            }
        } else if (type == "threadDeleted") {
            auto raw = server::ThreadDeletedEventData::fromJSON(notification.data);
            if (raw.type.value_or(std::string(THREAD_TYPE_FILTER_FLAG)) == THREAD_TYPE_FILTER_FLAG) {
                invalidateModuleKeysInCache(raw.threadId);
                auto data = Mapper::mapToThreadDeletedEventData(raw);
                auto event = core::EventBuilder::buildEvent<ThreadDeletedEvent>("thread", data, notification);
                _eventMiddleware->emitApiEvent(event);
            }
        } else if (type == "threadStats") {
            auto raw = server::ThreadStatsEventData::fromJSON(notification.data);
            if (raw.type.value_or(std::string(THREAD_TYPE_FILTER_FLAG)) == THREAD_TYPE_FILTER_FLAG) {
                auto data = Mapper::mapToThreadStatsEventData(raw);
                auto event = core::EventBuilder::buildEvent<ThreadStatsChangedEvent>("thread", data, notification);
                _eventMiddleware->emitApiEvent(event);
            }
        } else if (type == "threadNewMessage") {
            auto raw = server::ThreadMessageEventData::fromJSON(notification.data);
            if (raw.containerType.value_or(std::string(THREAD_TYPE_FILTER_FLAG)) == THREAD_TYPE_FILTER_FLAG) {
                auto data = _messageDataSchemaMapper.validateDecryptAndConvertMessage(
                    raw, getMessageDecryptionKeys(raw), _keyProvider
                );
                auto event = core::EventBuilder::buildEvent<ThreadNewMessageEvent>(
                    "thread/" + raw.threadId + "/messages", data, notification
                );
                _eventMiddleware->emitApiEvent(event);
            }
        } else if (type == "threadUpdatedMessage") {
            auto raw = server::ThreadMessageEventData::fromJSON(notification.data);
            if (raw.containerType.value_or(std::string(THREAD_TYPE_FILTER_FLAG)) == THREAD_TYPE_FILTER_FLAG) {
                auto data = _messageDataSchemaMapper.validateDecryptAndConvertMessage(
                    raw, getMessageDecryptionKeys(raw), _keyProvider
                );
                auto event = core::EventBuilder::buildEvent<ThreadMessageUpdatedEvent>(
                    "thread/" + raw.threadId + "/messages", data, notification
                );
                _eventMiddleware->emitApiEvent(event);
            }
        } else if (type == "threadDeletedMessage") {
            auto raw = server::ThreadDeletedMessageEventData::fromJSON(notification.data);
            if (raw.containerType.value_or(std::string(THREAD_TYPE_FILTER_FLAG)) == THREAD_TYPE_FILTER_FLAG) {
                auto data = Mapper::mapToThreadDeletedMessageEventData(raw);
                auto event = core::EventBuilder::buildEvent<ThreadMessageDeletedEvent>(
                    "thread/" + raw.threadId + "/messages", data, notification
                );
                _eventMiddleware->emitApiEvent(event);
            }
        } else if (type == "threadCollectionChanged") {
            auto raw = core::server::CollectionChangedEventData::fromJSON(notification.data);
            if (raw.containerType.value_or(std::string(THREAD_TYPE_FILTER_FLAG)) == THREAD_TYPE_FILTER_FLAG) {
                auto data = core::Mapper::mapToCollectionChangedEventData(THREAD_TYPE_FILTER_FLAG, raw);
                auto event = core::EventBuilder::buildEvent<core::CollectionChangedEvent>(
                    "thread/collectionChanged", data, notification
                );
                _eventMiddleware->emitApiEvent(event);
            }
        } else {
            LOG_ERROR("UNRESOLVED EVENT in CPP layer: '", type, "'");
        }
    });
}

void ThreadApiImpl::processConnectedEvent() {
    invalidateModuleKeysInCache();
}

void ThreadApiImpl::processDisconnectedEvent() {
    LOG_TRACE("ThreadApiImpl recived DisconnectedEvent");
    invalidateModuleKeysInCache();
    privmx::utils::ManualManagedClass<ThreadApiImpl>::cleanup();
}

std::vector<std::string> ThreadApiImpl::mapUsers(const std::vector<core::UserWithPubKey>& users) {
    std::vector<std::string> result;
    for (const auto& user : users) {
        result.push_back(user.userId);
    }
    return result;
}

core::ModuleKeys ThreadApiImpl::getMessageDecryptionKeys(server::Message message) {
    return getModuleKeys(
        message.threadId, std::set<std::string>{message.keyId},
        _messageDataSchemaMapper.getMinimumContainerSchemaVersionForMessage(message)
    );
}

Poco::Dynamic::Var ThreadApiImpl::encryptMessageData(
    const std::string& threadId,
    const std::string& resourceId,
    const core::Buffer& publicMeta,
    const core::Buffer& privateMeta,
    const core::Buffer& data,
    const core::ModuleKeys& threadKeys
) {
    core::DecryptedEncKeyV2 msgKey = getAndValidateModuleCurrentEncKey(threadKeys);
    return _messageDataSchemaMapper.encrypt(
        threadId, resourceId, threadKeys.contextId, threadKeys.moduleResourceId, publicMeta, privateMeta, data, msgKey
    );
}

void ThreadApiImpl::assertThreadExist(const std::string& threadId) {
    thread::server::ThreadGetModel params;
    params.threadId = threadId;
    _serverApi.threadGet(params);
}

std::pair<core::ModuleKeys, int64_t> ThreadApiImpl::getModuleKeysAndVersionFromServer(std::string moduleId) {
    thread::server::ThreadGetModel params{.threadId = moduleId, .type = std::nullopt};
    auto thread = _serverApi.threadGet(params).thread;
    // validate thread Data before returning data
    _threadDataSchemaMapper.assertDataIntegrity(thread);
    return std::make_pair(threadToModuleKeys(thread), thread.version);
}

core::ModuleKeys ThreadApiImpl::threadToModuleKeys(server::ThreadInfo thread) {
    return core::ModuleKeys{
        .keys = thread.keys,
        .currentKeyId = thread.keyId,
        .moduleSchemaVersion = _threadDataSchemaMapper.getDataStructureVersion(thread.data.back()),
        .moduleResourceId = thread.resourceId.value_or(""),
        .contextId = thread.contextId
    };
}

std::vector<std::string> ThreadApiImpl::subscribeFor(const std::vector<std::string>& subscriptionQueries) {
    auto result = _subscriber.subscribeFor(subscriptionQueries);
    _eventMiddleware->notificationEventListenerAddSubscriptionIds(_notificationListenerId, result);
    return result;
}

void ThreadApiImpl::unsubscribeFrom(const std::vector<std::string>& subscriptionIds) {
    _subscriber.unsubscribeFrom(subscriptionIds);
    _eventMiddleware->notificationEventListenerRemoveSubscriptionIds(_notificationListenerId, subscriptionIds);
}

std::string ThreadApiImpl::buildSubscriptionQuery(
    EventType eventType,
    EventSelectorType selectorType,
    const std::string& selectorId
) {
    return SubscriberImpl::buildQuery(eventType, selectorType, selectorId);
}
