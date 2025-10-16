/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include "privmx/endpoint/core/ConnectionImpl.hpp"

#include <cstdint>
#include <privmx/rpc/Types.hpp>
#include <privmx/utils/Logger.hpp>
#include "privmx/endpoint/core/CoreException.hpp"
#include "privmx/endpoint/core/EventQueueImpl.hpp"
#include "privmx/endpoint/core/Exception.hpp"
#include "privmx/endpoint/core/ListQueryMapper.hpp"
#include "privmx/endpoint/core/ServerTypes.hpp"
#include "privmx/endpoint/core/Constants.hpp"
#include "privmx/endpoint/core/EndpointUtils.hpp"
#include "privmx/endpoint/core/Mapper.hpp"
#include "privmx/endpoint/core/EventBuilder.hpp"
#include <privmx/endpoint/core/SingletonsHolder.hpp>

using namespace privmx::endpoint::core;

ConnectionImpl::ConnectionImpl() : _connectionId(generateConnectionId()) {
    _userVerifier = std::make_shared<core::UserVerifier>(std::make_shared<core::DefaultUserVerifierInterface>());
}
ConnectionImpl::~ConnectionImpl() {
    _guardedExecutor.reset();
}

void ConnectionImpl::connect(const std::string& userPrivKey, const std::string& solutionId,
                             const std::string& platformUrl, const PKIVerificationOptions& verificationOptions) {
    LOG_TIME_DEBUG_START(Platform platformConnect, "")
    rpc::ConnectionOptions options;
    auto port = Poco::URI(platformUrl).getPort();
    options.host = Poco::URI(platformUrl).getHost() + ":" + std::to_string(port);
    options.url = platformUrl + (platformUrl.back() == '/' ? "" : "/") + "api/v2.0";
    options.websocket = true;
    _bridgeIdentity = BridgeIdentity{
        .url=options.url, 
        .pubKey=verificationOptions.bridgePubKey, 
        .instanceId=verificationOptions.bridgeInstanceId
    };
    auto key = privmx::crypto::PrivateKey::fromWIF(userPrivKey);
    if(verificationOptions.bridgePubKey.has_value()) {
        _gateway = privfs::RpcGateway::createGatewayFromEcdhexConnection(key, options, solutionId, crypto::PublicKey::fromBase58DER(verificationOptions.bridgePubKey.value()));
    } else {
        _gateway = privfs::RpcGateway::createGatewayFromEcdhexConnection(key, options, solutionId);
    }
    _host = _gateway->getInfo().cast<rpc::EcdhexConnectionInfo>()->host;
    _serverConfig = _gateway->getInfo().cast<rpc::EcdhexConnectionInfo>()->serverConfig;
    _userPrivKey = key;
    _keyProvider = std::shared_ptr<KeyProvider>(new KeyProvider(key, std::bind(&ConnectionImpl::getUserVerifier, this)));
    _eventMiddleware =
        std::shared_ptr<EventMiddleware>(new EventMiddleware(EventQueueImpl::getInstance(), _connectionId));
    _handleManager = std::shared_ptr<HandleManager>(new HandleManager());
    _eventMiddleware->addConnectedEventListener([&] {
        auto event = EventBuilder::buildLibEvent<LibConnectedEvent>();
        _eventMiddleware->emitApiEvent(event);
    });
    _contextProvider = std::make_shared<ContextProvider>([&](const std::string& id) {
        auto model = privmx::utils::TypedObjectFactory::createNewObject<server::ContextGetModel>();
        model.id(id);
        return utils::TypedObjectFactory::createObjectFromVar<server::ContextGetResult>(_gateway->request("context.contextGet", model)).context();
    });
    if (_gateway->isConnected()) {
        auto event = EventBuilder::buildLibEvent<LibConnectedEvent>();
        _eventMiddleware->emitApiEvent(event);
    }
    _eventMiddleware->addDisconnectedEventListener([&] {
        auto event = EventBuilder::buildLibEvent<LibDisconnectedEvent>();
        _eventMiddleware->emitApiEvent(event);
    });
    _gateway->addNotificationEventListener([&, this](const rpc::NotificationEvent& event) {
        _eventMiddleware->emitNotificationEvent(event.type, convertRpcNotificationEventToCoreNotificationEvent(event));
    });
    _gateway->addConnectedEventListener(
        [&, this]([[maybe_unused]] const rpc::ConnectedEvent& event) { _eventMiddleware->emitConnectedEvent(); });
    _gateway->addDisconnectedEventListener(
        [&, this]([[maybe_unused]] const rpc::DisconnectedEvent& event) { _eventMiddleware->emitDisconnectedEvent(); });
    _gateway->addSessionLostEventListener(
        [&, this]([[maybe_unused]] const rpc::SessionLostEvent& event) { _eventMiddleware->emitDisconnectedEvent(); });
    _notificationListenerId = _eventMiddleware->addNotificationEventListener(
        std::bind(&ConnectionImpl::processNotificationEvent, this, std::placeholders::_1, std::placeholders::_2));
    _subscriber = std::make_shared<SubscriberImpl>(_gateway);
    assertServerVersion();
    LOG_TIME_DEBUG_STOP(Platform platformConnect, "")
}

void ConnectionImpl::connectPublic(const std::string& solutionId, const std::string& platformUrl, const PKIVerificationOptions& verificationOptions) {
    // TODO: solutionId is reserved for future use
    LOG_TIME_DEBUG_START(Platform platformConnectPublic, "")
    rpc::ConnectionOptions options;
    auto port = Poco::URI(platformUrl).getPort();
    options.host = Poco::URI(platformUrl).getHost() + ":" + std::to_string(port);
    options.url = platformUrl + (platformUrl.back() == '/' ? "" : "/") + "api/v2.0";
    options.websocket = false;
    _bridgeIdentity = BridgeIdentity{
        .url=options.url, 
        .pubKey=verificationOptions.bridgePubKey, 
        .instanceId=verificationOptions.bridgeInstanceId
    };
    auto key = privmx::crypto::PrivateKey::generateRandom();
    _userPrivKey = key;
    _keyProvider = std::shared_ptr<KeyProvider>(new KeyProvider(key, std::bind(&ConnectionImpl::getUserVerifier, this)));
    _gateway = privfs::RpcGateway::createGatewayFromEcdheConnection(key, options, solutionId);
    _serverConfig = _gateway->getInfo().cast<rpc::EcdheConnectionInfo>()->serverConfig;
    _eventMiddleware =
        std::shared_ptr<EventMiddleware>(new EventMiddleware(EventQueueImpl::getInstance(), _connectionId));
    _handleManager = std::shared_ptr<HandleManager>(new HandleManager());
    _eventMiddleware->addConnectedEventListener([&] {
        auto event = EventBuilder::buildLibEvent<LibConnectedEvent>();
        _eventMiddleware->emitApiEvent(event);
    });
    _contextProvider = std::make_shared<ContextProvider>([&](const std::string& id) {
        auto context = privmx::utils::TypedObjectFactory::createNewObject<server::ContextInfo>();
        context.contextId(id);
        context.userId("<anonymous>");
        return context;
    });
    if (_gateway->isConnected()) {
        auto event = EventBuilder::buildLibEvent<LibConnectedEvent>();
        _eventMiddleware->emitApiEvent(event);
    }
    _eventMiddleware->addDisconnectedEventListener([&] {
        auto event = EventBuilder::buildLibEvent<LibDisconnectedEvent>();
        _eventMiddleware->emitApiEvent(event);
    });
    _gateway->addNotificationEventListener([&, this](const rpc::NotificationEvent& event) {
        _eventMiddleware->emitNotificationEvent(event.type, convertRpcNotificationEventToCoreNotificationEvent(event));
    });
    _gateway->addConnectedEventListener(
        [&, this]([[maybe_unused]] const rpc::ConnectedEvent& event) { _eventMiddleware->emitConnectedEvent(); });
    _gateway->addDisconnectedEventListener(
        [&, this]([[maybe_unused]] const rpc::DisconnectedEvent& event) { _eventMiddleware->emitDisconnectedEvent(); });
    _gateway->addSessionLostEventListener(
        [&, this]([[maybe_unused]] const rpc::SessionLostEvent& event) { _eventMiddleware->emitDisconnectedEvent(); });
    _notificationListenerId = _eventMiddleware->addNotificationEventListener(
        std::bind(&ConnectionImpl::processNotificationEvent, this, std::placeholders::_1, std::placeholders::_2));
    _subscriber = std::make_shared<SubscriberImpl>(_gateway);
    assertServerVersion();
    LOG_TIME_DEBUG_STOP(Platform platformConnectPublic, "")
}

int64_t ConnectionImpl::getConnectionId() {
    return _connectionId;
}

PagingList<Context> ConnectionImpl::listContexts(const PagingQuery& pagingQuery) {

    LOG_TIME_DEBUG_START(PlatformThread contextList, "")
    auto listModel = utils::TypedObjectFactory::createNewObject<server::ListModel>();
    ListQueryMapper::map(listModel, pagingQuery);
    LOG_TIME_DEBUG_CHECKPOINT(PlatformThread contextList, "data")
    auto response = utils::TypedObjectFactory::createObjectFromVar<server::ContextListResult>(
        _gateway->request("context.contextList", listModel));
    LOG_TIME_DEBUG_CHECKPOINT(PlatformThread contextList, "data send")
    std::vector<Context> contexts{};
    for (auto resp : response.contexts()) {
        contexts.push_back({.userId = resp.userId(), .contextId = resp.contextId()});
    }
    LOG_TIME_DEBUG_STOP(PlatformThread contextList , "")
    return PagingList<Context>{.totalAvailable = response.count(), .readItems = contexts};
}

PagingList<UserInfo> ConnectionImpl::listContextUsers(const std::string& contextId, const PagingQuery& pagingQuery) {
    auto model = utils::TypedObjectFactory::createNewObject<server::ContextListUsersModel>();
    model.contextId(contextId);
    ListQueryMapper::map(model, pagingQuery);
    auto response = utils::TypedObjectFactory::createObjectFromVar<server::ContextListUsersResult>(
        _gateway->request("context.contextListUsers", model));
    PagingList<UserInfo> result;
    result.readItems.reserve(response.users().size());
    for (auto user : response.users()) {
        result.readItems.push_back(UserInfo {
            .user=UserWithPubKey{
                .userId=user.id(), 
                .pubKey=user.pub()
            }, 
            .isActive= user.status() == "active",
            .lastStatusChange = user.lastStatusChangeEmpty() ? std::nullopt : std::make_optional(UserStatusChange{
                .action = user.lastStatusChange().action(),
                .timestamp = user.lastStatusChange().timestamp()
            })
        });
    }
    result.totalAvailable = response.count();
    return result;
}

void ConnectionImpl::setUserVerifier(std::shared_ptr<UserVerifierInterface> verifier) {
    std::unique_lock lock(_mutex);
    _userVerifier = std::make_shared<UserVerifier>(verifier);
}

std::vector<std::string> ConnectionImpl::subscribeFor(const std::vector<std::string>& subscriptionQueries) {
    auto result = _subscriber->subscribeFor(subscriptionQueries);
    _eventMiddleware->notificationEventListenerAddSubscriptionIds(_notificationListenerId, result);
    return result;
}

void ConnectionImpl::unsubscribeFrom(const std::vector<std::string>& subscriptionIds) {
    _subscriber->unsubscribeFrom(subscriptionIds);
    _eventMiddleware->notificationEventListenerRemoveSubscriptionIds(_notificationListenerId, subscriptionIds);
}

std::string ConnectionImpl::buildSubscriptionQuery(EventType eventType, EventSelectorType selectorType, const std::string& selectorId) {
    return SubscriberImpl::buildQuery(eventType, selectorType, selectorId);
}

void ConnectionImpl::disconnect() {
    if (!_gateway.isNull()) {
        _gateway->destroy();
    }
    _gateway.reset();
    auto event = EventBuilder::buildLibEvent<LibPlatformDisconnectedEvent>();
    _eventMiddleware->emitApiEvent(event);
}

int64_t ConnectionImpl::generateConnectionId() {
    return reinterpret_cast<std::intptr_t>(this);
}

std::string ConnectionImpl::getMyUserId(const std::string& contextId) {
    return _contextProvider->get(contextId).container.userId();
}

DataIntegrityObject ConnectionImpl::createDIO(
    const std::string& contextId, 
    const std::string& resourceId, 
    const std::optional<std::string>& containerId, 
    const std::optional<std::string>& containerResourceId
) {
    return createDIOExt(contextId, resourceId, containerId, containerResourceId);
}

DataIntegrityObject ConnectionImpl::createPublicDIO(
    const std::string& contextId, 
    const std::string& resourceId, 
    const crypto::PublicKey& pubKey, 
    const std::optional<std::string>& containerId, 
    const std::optional<std::string>& containerResourceId
) {
    return createDIOExt(contextId, resourceId, containerId, containerResourceId, "<anonymous>", pubKey);
}

DataIntegrityObject ConnectionImpl::createDIOExt(
    const std::string& contextId, 
    const std::string& resourceId, 
    const std::optional<std::string>& containerId, 
    const std::optional<std::string>& containerResourceId,
    const std::optional<std::string>& creatorUserId,
    const std::optional<crypto::PublicKey>& creatorPublicKey
) {
    
    return core::DataIntegrityObject{
        .creatorUserId = creatorUserId.has_value() ? creatorUserId.value() : getMyUserId(contextId),
        .creatorPubKey = creatorPublicKey.has_value() ? creatorPublicKey.value().toBase58DER() : _userPrivKey.getPublicKey().toBase58DER(),
        .contextId = contextId,
        .resourceId = resourceId,
        .timestamp = privmx::utils::Utils::getNowTimestamp(),
        .randomId = EndpointUtils::generateDIORandomId(),
        .containerId = containerId,
        .containerResourceId = containerResourceId,
        .bridgeIdentity = _bridgeIdentity
    };
}

NotificationEvent ConnectionImpl::convertRpcNotificationEventToCoreNotificationEvent(const rpc::NotificationEvent& event) {
    std::vector<std::string> subscriptions;
    auto tmp = privmx::utils::TypedObjectFactory::createObjectFromVar<server::RpcEvent>(event.data);
    for(auto subscription : tmp.subscriptions()) {
        subscriptions.push_back(subscription);
    }
    return NotificationEvent{
        .source = EventSource::SERVER,
        .type = event.type,
        .data = tmp.data(),
        .version = tmp.version(),
        .timestamp = tmp.timestamp(),
        .subscriptions = subscriptions
    };
}

void ConnectionImpl::assertServerVersion() {
    if(_serverConfig.serverVersion < privmx::utils::VersionNumber(MINIMUM_REQUIRED_BRIDGE_VERSION)) {
        disconnect();
        throw ServerVersionMismatchException(
            "Bridge Server current version: " + (std::string)_serverConfig.serverVersion + "\n" +
            "PrivMX Ednpoint library current version: " + ENDPOINT_VERSION + "\n"
            "Bridge Server minimal expected version: " + MINIMUM_REQUIRED_BRIDGE_VERSION
        );
    }
}

void ConnectionImpl::processNotificationEvent(const std::string& type, const core::NotificationEvent& notification) {
    auto subscriptionQuery = _subscriber->getSubscriptionQuery(notification.subscriptions);
    if(!subscriptionQuery.has_value()) {
        return;
    }
    _guardedExecutor->exec([&, type, notification]() {
        if (type == "contextUserAdded") {
            auto raw = utils::TypedObjectFactory::createObjectFromVar<server::ContextUserEventData>(notification.data);
            auto data = Mapper::mapToContextUserEventData(raw);
            auto event = EventBuilder::buildEvent<ContextUserAddedEvent>("context/userAdded", data, notification);
            _eventMiddleware->emitApiEvent(event);
        } else if (type == "contextUserRemoved") {
            auto raw = utils::TypedObjectFactory::createObjectFromVar<server::ContextUserEventData>(notification.data);
            auto data = Mapper::mapToContextUserEventData(raw);
            auto event = EventBuilder::buildEvent<ContextUserRemovedEvent>("context/userRemoved", data, notification);
            _eventMiddleware->emitApiEvent(event);
        } else if (type == "contextUserStatusChanged") {
            auto raw = utils::TypedObjectFactory::createObjectFromVar<server::ContextUsersStatusChangeEventData>(notification.data);
            auto data = Mapper::mapToContextUsersStatusChangedEventData(raw);
            auto event = EventBuilder::buildEvent<ContextUsersStatusChangedEvent>("context/userStatus", data, notification);
            _eventMiddleware->emitApiEvent(event);
        }
    });
}
