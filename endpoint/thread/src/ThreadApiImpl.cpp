/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include <algorithm>

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
#include "privmx/endpoint/group/GroupApiImpl.hpp"
#include "privmx/endpoint/thread/Mapper.hpp"
#include "privmx/endpoint/thread/ServerTypes.hpp"
#include "privmx/endpoint/thread/ThreadApiImpl.hpp"
#include "privmx/endpoint/thread/ThreadException.hpp"
#include <privmx/endpoint/core/ConvertedExceptions.hpp>

using namespace privmx::endpoint;
using namespace privmx::endpoint::thread;

ThreadApiImpl::ThreadApiImpl(
    const privfs::RpcGateway::Ptr& gateway,
    const privmx::crypto::PrivateKey& userPrivKey,
    const std::shared_ptr<core::KeyProvider>& keyProvider,
    const std::string& host,
    const std::shared_ptr<core::EventMiddleware>& eventMiddleware,
    const core::Connection& connection,
    const std::optional<group::GroupApi>& groupApi
)
    : ModuleBaseApi(userPrivKey, keyProvider, host, eventMiddleware, connection), _gateway(gateway),
      _userPrivKey(userPrivKey), _keyProvider(keyProvider), _host(host), _eventMiddleware(eventMiddleware),
      _connection(connection), _serverApi(ServerApi(gateway)), _subscriber(gateway, THREAD_TYPE_FILTER_FLAG),
      _messageDataSchemaMapper(userPrivKey, connection),
      _threadDataSchemaMapper(std::make_shared<ThreadDataSchemaMapper>(userPrivKey, connection)),
      _forbiddenChannelsNames({INTERNAL_EVENT_CHANNEL_NAME, "thread", "messages"}) {
    if (groupApi.has_value()) {
        _groupApiImpl = groupApi->getImpl();
    } else {
        _groupApiImpl = nullptr;
    }
    if (_groupApiImpl) {
        auto groupApiImpl = _groupApiImpl;
        _groupPrivKeyResolver =
            [groupApiImpl](const std::string& groupId, int64_t epoch) -> std::optional<privmx::crypto::PrivateKey> {
            try {
                return groupApiImpl->resolveGroupPrivKey(groupId, epoch);
            } catch (...) {
                // not a member of this group at this epoch — skip
                return std::nullopt;
            }
        };
    }
    initModuleDataSchemaMapper(_threadDataSchemaMapper);
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
    const std::optional<core::ContainerPolicy>& policies,
    const std::string& type,
    const std::vector<core::GroupGrantWithKey>& groups
) {
    auto ctx = prepareContainerCreate(contextId, users, managers);
    core::ModuleDataToEncryptV5 threadDataToEncrypt{
        .publicMeta = publicMeta,
        .privateMeta = privateMeta,
        .internalMeta = core::
            ModuleInternalMetaV5{.secret = ctx.secret, .resourceId = ctx.resourceId, .randomId = ctx.dio.randomId},
        .dio = ctx.dio
    };
    server::ThreadCreateModel create_thread_model;
    fillContainerCreateModel(
        create_thread_model, contextId, users, managers, ctx,
        _threadDataSchemaMapper->encrypt(threadDataToEncrypt, ctx.key.key)
    );
    if (type.length() > 0) {
        create_thread_model.type = type;
    }
    if (policies.has_value()) {
        create_thread_model.policy = privmx::endpoint::core::Factory::createPolicyServerObject(policies.value());
    }
    if (!groups.empty()) {
        // Populate groupEpoch from current group state when caller didn't supply it (EP-13/14)
        std::vector<privmx::endpoint::core::GroupGrantWithKey> resolvedGroups = groups;
        std::unordered_map<std::string, GroupEpochInfo> groupEpochCache;
        resolveGroupEpochs(contextId, resolvedGroups, groupEpochCache);
        create_thread_model.groupKeys = buildGroupKeyEntries(
            resolvedGroups, ctx.key, ctx.dio, contextId, ctx.resourceId, ctx.secret
        );
        std::vector<core::server::GroupGrant> groupGrants;
        for (const auto& g : resolvedGroups) {
            groupGrants.push_back({.groupId = g.groupId, .role = g.role});
        }
        create_thread_model.groups = std::move(groupGrants);
    }
    auto result = _serverApi.threadCreate(create_thread_model);
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
    const std::optional<core::ContainerPolicy>& policies,
    const std::vector<core::GroupGrantWithKey>& groups
) {
    // get current thread
    server::ThreadGetModel getModel;
    getModel.threadId = threadId;
    auto currentThread = _serverApi.threadGet(getModel).thread;
    const auto& currentThreadEntry = currentThread.data.back();
    auto currentThreadResourceId = currentThread.resourceId ? currentThread.resourceId.value() :
                                                              core::EndpointUtils::generateId();
    // Force key rotation when groups are being removed so the old group
    // no longer has access to the new key (Bridge rejects if it does).
    bool groupRemovalForcesNewKey = false;
    {
        std::set<std::string> newGroupIds;
        for (const auto& g : groups) {
            newGroupIds.insert(g.groupId);
        }
        for (const auto& current : currentThread.groups) {
            if (newGroupIds.find(current.groupId) == newGroupIds.end()) {
                groupRemovalForcesNewKey = true;
                break;
            }
        }
    }
    // EP-13: detect if any grantee group's epoch has advanced; if so, force new thread key.
    bool epochStaleness = false;
    std::unordered_map<std::string, GroupEpochInfo> groupEpochCache;
    if (!groups.empty()) {
        epochStaleness = isRekeyNeeded(currentThread);
    }

    auto ctx = prepareContainerUpdate(
        currentThread, currentThreadEntry, currentThreadResourceId, users, managers,
        forceGenerateNewKey || groupRemovalForcesNewKey || epochStaleness
    );
    server::ThreadUpdateModel model;
    fillContainerUpdateModel(model, threadId, currentThreadResourceId, users, managers, ctx, version, force);
    if (policies.has_value()) {
        model.policy = privmx::endpoint::core::Factory::createPolicyServerObject(policies.value());
    }
    if (!groups.empty()) {
        // Populate groupEpoch from current group state when caller didn't supply it (EP-13/14). The grant list
        // itself is the caller's: this is the call that adds and removes group grantees.
        std::vector<core::GroupGrantWithKey> resolvedGroups = groups;
        resolveGroupEpochs(currentThread.contextId, resolvedGroups, groupEpochCache);
        model.groupKeys = buildGroupKeyEntries(
            resolvedGroups, ctx.key, ctx.dio, currentThread.contextId, currentThreadResourceId, ctx.secret
        );
        std::vector<core::server::GroupGrant> groupGrants;
        for (const auto& g : resolvedGroups) {
            groupGrants.push_back({.groupId = g.groupId, .role = g.role});
        }
        model.groups = std::move(groupGrants);
    } else {
        model.groups = std::vector<core::server::GroupGrant>{};
    }
    core::ModuleDataToEncryptV5 threadDataToEncrypt{
        .publicMeta = publicMeta,
        .privateMeta = privateMeta,
        .internalMeta =
            core::ModuleInternalMetaV5{
                .secret = ctx.secret, .resourceId = currentThreadResourceId, .randomId = ctx.dio.randomId
            },
        .dio = ctx.dio
    };
    model.data = _threadDataSchemaMapper->encrypt(threadDataToEncrypt, ctx.key.key);
    _serverApi.threadUpdate(model);
    invalidateModuleKeysInCache(threadId);
}

void ThreadApiImpl::rotateThreadKeys(
    const std::string& threadId,
    const std::vector<core::UserWithPubKey>& users,
    const std::vector<core::UserWithPubKey>& managers,
    const int64_t version,
    const bool force,
    const std::vector<core::GroupGrantWithKey>& groups
) {
    server::ThreadGetModel getModel;
    getModel.threadId = threadId;
    auto currentThread = _serverApi.threadGet(getModel).thread;
    const auto& currentEntry = currentThread.data.back();
    auto resourceId = currentThread.resourceId.value_or(core::EndpointUtils::generateId());

    auto ctx = prepareContainerUpdate(currentThread, currentEntry, resourceId, users, managers, true);

    server::ThreadRotateKeysModel model;
    model.id = threadId;
    model.keyId = ctx.key.id;
    model.keys = ctx.keyEntries;
    model.version = version;
    model.force = force;

    // A re-key changes no grants, so the grantees are the Thread's own — `currentThread.groups`, which the bridge
    // serves in full. Taking them from `groups` instead would silently drop every grantee the caller did not name,
    // and a caller can only name the groups it belongs to: `groupKeys`, the one place a Thread's grantee groups
    // show up in its payload, is narrowed to those. The bridge rejects a re-key that leaves a granted group without
    // an entry at the new keyId, so the dropped grantees would fail the whole call.
    auto resolvedGroups = resolveGranteesForRekey(currentThread, groups);
    if (!resolvedGroups.empty()) {
        model.groupKeys = buildGroupKeyEntries(
            resolvedGroups, ctx.key, ctx.dio, currentThread.contextId, resourceId, ctx.secret
        );
    }

    _serverApi.threadRotateKeys(model);
    invalidateModuleKeysInCache(threadId);
}

void ThreadApiImpl::deleteThread(const std::string& threadId) {
    server::ThreadDeleteModel model{.threadId = threadId};
    _serverApi.threadDelete(model);
    invalidateModuleKeysInCache(threadId);
}

Thread ThreadApiImpl::getThread(const std::string& threadId, const std::string& type) {
    server::ThreadGetModel params;
    params.threadId = threadId;
    if (type.length() > 0) {
        params.type = type;
    }
    auto thread = _serverApi.threadGet(params).thread;
    setNewModuleKeysInCache(thread.id, threadToModuleKeys(thread), thread.version);
    auto result = _threadDataSchemaMapper->validateDecryptAndConvertThread(thread, _keyProvider, _groupPrivKeyResolver);
    return result;
}

core::PagingList<Thread> ThreadApiImpl::listThreads(
    const std::string& contextId,
    const core::PagingQuery& pagingQuery,
    const std::string& type
) {
    server::ThreadListModel model;
    model.contextId = contextId;
    if (type.length() > 0) {
        model.type = type;
    }
    core::ListQueryMapper::map(model, pagingQuery);
    auto threadsList = _serverApi.threadList(model);
    for (const auto& thread : threadsList.threads) {
        setNewModuleKeysInCache(thread.id, threadToModuleKeys(thread), thread.version);
    }
    std::vector<Thread> threads = _threadDataSchemaMapper->validateDecryptAndConvertThreads(
        threadsList.threads, _keyProvider, _groupPrivKeyResolver
    );
    return core::PagingList<Thread>({.totalAvailable = threadsList.count, .readItems = threads});
}

Message ThreadApiImpl::getMessage(const std::string& messageId) {
    server::ThreadMessageGetModel model{.messageId = messageId};
    auto message = _serverApi.threadMessageGet(model).message;
    Message result;
    result = _messageDataSchemaMapper.validateDecryptAndConvertMessage(
        message, getMessageDecryptionKeys(message), _keyProvider, _groupPrivKeyResolver
    );
    return result;
}

core::PagingList<Message> ThreadApiImpl::listMessages(
    const std::string& threadId,
    const core::PagingQuery& pagingQuery
) {
    server::ThreadMessagesGetModel model;
    model.threadId = threadId;
    core::ListQueryMapper::map(model, pagingQuery);
    auto messagesList = _serverApi.threadMessagesGet(model);
    const auto& thread = messagesList.thread;
    _threadDataSchemaMapper->assertDataIntegrity(thread);
    setNewModuleKeysInCache(thread.id, threadToModuleKeys(thread), thread.version);
    auto messages = _messageDataSchemaMapper.validateDecryptAndConvertMessages(
        messagesList.messages, threadToModuleKeys(thread), _keyProvider, _groupPrivKeyResolver
    );
    return core::PagingList<Message>({.totalAvailable = messagesList.count, .readItems = messages});
}
std::string ThreadApiImpl::sendMessage(
    const std::string& threadId,
    const core::Buffer& publicMeta,
    const core::Buffer& privateMeta,
    const core::Buffer& data
) {
    return withKeyRefresh<std::string>(
        threadId, privmx::endpoint::server::InvalidThreadKeyException().getCode(),
        [&](const core::ModuleKeys& keys) { return sendMessageRequest(threadId, publicMeta, privateMeta, data, keys); }
    );
}

std::string ThreadApiImpl::sendMessageRequest(
    const std::string& threadId,
    const core::Buffer& publicMeta,
    const core::Buffer& privateMeta,
    const core::Buffer& data,
    const core::ModuleKeys& keys
) {
    core::DecryptedEncKeyV2 msgKey = getAndValidateModuleCurrentEncKey(keys, _groupPrivKeyResolver);
    if (msgKey.statusCode != 0) {
        throw core::EncryptionKeyValidationException(
            "Current encryption key statusCode: " + std::to_string(msgKey.statusCode)
        );
    }
    auto resourceId = core::EndpointUtils::generateId();
    server::ThreadMessageSendModel send_message_model;
    send_message_model.resourceId = resourceId;
    send_message_model.threadId = threadId;
    send_message_model.keyId = msgKey.id;
    send_message_model.data = encryptMessageData(threadId, resourceId, publicMeta, privateMeta, data, keys);
    auto result = _serverApi.threadMessageSend(send_message_model);
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
    server::ThreadMessageGetModel model;
    model.messageId = messageId;
    auto message = _serverApi.threadMessageGet(model).message;
    const std::string resourceId = message.resourceId.empty() ? core::EndpointUtils::generateId() : message.resourceId;
    withKeyRefresh<void>(
        message.threadId, privmx::endpoint::server::InvalidThreadKeyException().getCode(),
        [&](const core::ModuleKeys& keys) {
            updateMessageRequest(messageId, resourceId, message.threadId, publicMeta, privateMeta, data, keys);
        }
    );
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
    core::DecryptedEncKeyV2 msgKey = getAndValidateModuleCurrentEncKey(keys, _groupPrivKeyResolver);
    if (msgKey.statusCode != 0) {
        throw core::EncryptionKeyValidationException(
            "Current encryption key statusCode: " + std::to_string(msgKey.statusCode)
        );
    }
    server::ThreadMessageUpdateModel send_message_model;
    send_message_model.messageId = messageId;
    send_message_model.keyId = msgKey.id;
    send_message_model.data = encryptMessageData(threadId, resourceId, publicMeta, privateMeta, data, keys);
    _serverApi.threadMessageUpdate(send_message_model);
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
                auto data = _threadDataSchemaMapper->validateDecryptAndConvertThread(
                    raw, _keyProvider, _groupPrivKeyResolver
                );
                auto event = core::EventBuilder::buildEvent<ThreadCreatedEvent>("thread", data, notification);
                _eventMiddleware->emitApiEvent(event);
            }
        } else if (type == "threadUpdated") {
            auto raw = server::ThreadInfo::fromJSON(notification.data);
            if (raw.type.value_or(std::string(THREAD_TYPE_FILTER_FLAG)) == THREAD_TYPE_FILTER_FLAG) {
                setNewModuleKeysInCache(raw.id, threadToModuleKeys(raw), raw.version);
                auto data = _threadDataSchemaMapper->validateDecryptAndConvertThread(
                    raw, _keyProvider, _groupPrivKeyResolver
                );
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
                    raw, getMessageDecryptionKeys(raw), _keyProvider, _groupPrivKeyResolver
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
                    raw, getMessageDecryptionKeys(raw), _keyProvider, _groupPrivKeyResolver
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

core::ModuleKeys ThreadApiImpl::getMessageDecryptionKeys(server::Message message) {
    return getModuleKeysForItem(
        message.threadId, message.keyId, _messageDataSchemaMapper.getMinimumContainerSchemaVersionForMessage(message)
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
    core::DecryptedEncKeyV2 msgKey = getAndValidateModuleCurrentEncKey(threadKeys, _groupPrivKeyResolver);
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
    _threadDataSchemaMapper->assertDataIntegrity(thread);
    return std::make_pair(threadToModuleKeys(thread), thread.version);
}

core::ModuleKeys ThreadApiImpl::threadToModuleKeys(server::ThreadInfo thread) {
    return core::ModuleKeys{
        .keys = thread.keys,
        .groupKeys = thread.groupKeys,
        .currentKeyId = thread.keyId,
        .moduleSchemaVersion = _threadDataSchemaMapper->getDataStructureVersion(thread.data.back()),
        .moduleResourceId = thread.resourceId.value_or(""),
        .contextId = thread.contextId
    };
}

bool ThreadApiImpl::isRekeyNeeded(
    const server::ThreadInfo& thread
) {
    return !thread.staleGroups.empty();
}

std::vector<core::GroupGrantWithKey> ThreadApiImpl::resolveGranteesForRekey(
    const server::ThreadInfo& thread,
    const std::vector<core::GroupGrantWithKey>& callerSupplied
) {
    std::vector<core::GroupGrantWithKey> grants;
    grants.reserve(thread.groups.size());
    for (const auto& grant : thread.groups) {
        auto supplied = std::find_if(
            callerSupplied.begin(), callerSupplied.end(),
            [&](const core::GroupGrantWithKey& g) { return g.groupId == grant.groupId; }
        );
        if (supplied != callerSupplied.end()) {
            // The caller's public key wins where it has one: it is the key it verified out-of-band, and the role
            // still comes from the grant, which a re-key cannot change.
            grants.push_back(
                core::GroupGrantWithKey{
                    .groupId = grant.groupId,
                    .role = grant.role,
                    .groupPubKey = supplied->groupPubKey,
                    .groupEpoch = supplied->groupEpoch
                }
            );
        } else {
            grants.push_back(core::GroupGrantWithKey{.groupId = grant.groupId, .role = grant.role});
        }
    }
    for (const auto& g : callerSupplied) {
        auto granted = std::find_if(
            thread.groups.begin(), thread.groups.end(),
            [&](const core::server::GroupGrant& grant) { return grant.groupId == g.groupId; }
        );
        if (granted == thread.groups.end()) {
            // Not dropped silently: a re-key cannot add a grant (the bridge refuses a key entry for a group the
            // Thread does not grant), so a group named here that the Thread does not grant is a caller mistake
            // that updateThread, not this call, is the fix for.
            LOG_DEBUG("[resolveGranteesForRekey] group ", g.groupId, " is not a grantee of this thread — ignored")
        }
    }
    std::unordered_map<std::string, GroupEpochInfo> groupCache;
    resolveGroupEpochs(thread.contextId, grants, groupCache);
    return grants;
}

void ThreadApiImpl::resolveGroupEpochs(
    const std::string& contextId,
    std::vector<core::GroupGrantWithKey>& grants,
    std::unordered_map<std::string, GroupEpochInfo>& groupCache
) {
    auto isComplete = [](const core::GroupGrantWithKey& g) {
        return g.groupEpoch > 0 && !g.groupPubKey.empty();
    };
    std::vector<std::string> toFetch;
    for (const auto& g : grants) {
        if (isComplete(g) || groupCache.find(g.groupId) != groupCache.end())
            continue;
        if (std::find(toFetch.begin(), toFetch.end(), g.groupId) == toFetch.end())
            toFetch.push_back(g.groupId);
    }
    if (!toFetch.empty()) {
        fetchGroupEpochs(contextId, toFetch, groupCache);
    }
    for (auto& g : grants) {
        if (isComplete(g))
            continue;
        auto resolved = groupCache.find(g.groupId);
        if (resolved == groupCache.end()) {
            throw UnresolvedGroupGranteeException("groupId=" + g.groupId);
        }
        // Both fields, never one: the epoch names which key pair the entry is readable with, so a caller-supplied
        // public key cannot be kept alongside an epoch read from somewhere else.
        g.groupPubKey = resolved->second.groupPubKey;
        g.groupEpoch = resolved->second.keyVersion;
    }
}

void ThreadApiImpl::fetchGroupEpochs(
    const std::string& contextId,
    const std::vector<std::string>& groupIds,
    std::unordered_map<std::string, GroupEpochInfo>& groupCache
) {
    if (!_groupApiImpl)
        return;
    // The bridge caps a listing at 100 items, so the id filter is spent in batches of that size.
    constexpr size_t BATCH = 100;
    for (size_t offset = 0; offset < groupIds.size(); offset += BATCH) {
        std::vector<std::string> batch(
            groupIds.begin() + offset, groupIds.begin() + std::min(offset + BATCH, groupIds.size())
        );
        Poco::JSON::Array::Ptr ids = new Poco::JSON::Array();
        for (const auto& id : batch) {
            ids->add(id);
        }
        Poco::JSON::Object::Ptr in = new Poco::JSON::Object();
        in->set("$in", ids);
        Poco::JSON::Object::Ptr query = new Poco::JSON::Object();
        query->set("#id", in);
        core::PagingQuery pagingQuery{
            .skip = 0,
            .limit = static_cast<int64_t>(batch.size()),
            .sortOrder = "asc",
            .queryAsJson = privmx::utils::Utils::stringify(query)
        };
        try {
            auto listed = _groupApiImpl->listGroups(contextId, pagingQuery);
            for (const auto& summary : listed.readItems) {
                groupCache[summary.groupId] =
                    GroupEpochInfo{.keyVersion = summary.keyVersion, .groupPubKey = summary.groupPubKey};
            }
        } catch (const std::exception& e) {
            // A deployment may set `group.listAll: "none"`; the per-group read below is then the only way in,
            // and it only works for groups we belong to.
            LOG_DEBUG("[fetchGroupEpochs] groupList by id unavailable: ", e.what())
        }
    }
    for (const auto& id : groupIds) {
        if (groupCache.find(id) != groupCache.end())
            continue;
        try {
            auto fetched = _groupApiImpl->getGroup(id);
            groupCache[id] = GroupEpochInfo{.keyVersion = fetched.keyVersion, .groupPubKey = fetched.groupPubKey};
        } catch (const std::exception& e) {
            // Deleted, in another context, or one we are not a member of — left out, so the caller of
            // resolveGroupEpochs can name it in the error rather than sending an entry it cannot fill in.
            LOG_DEBUG("[fetchGroupEpochs] cannot read group ", id, ": ", e.what())
        }
    }
}

void ThreadApiImpl::applyRekeyIfNeeded(const std::string& threadId, const server::ThreadInfo& thread) {
    if (!isRekeyNeeded(thread))
        return;
    // Rekey: rebuild GroupGrantWithKey list with current epoch public keys, then force updateThread.
    // The caller of updateThread must provide users/managers with public keys; since we don't have
    // them here, we skip the rekey and let the next explicit updateThread call perform it.
    // updateThread always checks group epochs and sets groupEpoch correctly when given groups[].
    LOG_DEBUG("[applyRekeyIfNeeded] thread ", threadId, " has stale group key epoch — rekey on next updateThread")
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
