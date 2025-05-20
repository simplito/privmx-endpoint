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
#include <privmx/utils/Debug.hpp>

#include "privmx/endpoint/core/CoreException.hpp"
#include "privmx/endpoint/core/EventQueueImpl.hpp"
#include "privmx/endpoint/core/Exception.hpp"
#include "privmx/endpoint/core/ListQueryMapper.hpp"
#include "privmx/endpoint/core/ServerTypes.hpp"
#include "privmx/endpoint/core/Constants.hpp"

using namespace privmx::endpoint::core;

ConnectionImpl::ConnectionImpl() : _connectionId(generateConnectionId()) {
    _userVerifier = std::make_shared<core::DefaultUserVerifierInterface>();
}

void ConnectionImpl::connect(const std::string& userPrivKey, const std::string& solutionId,
                             const std::string& platformUrl, const PKIVerificationOptions& verificationOptions) {
    PRIVMX_DEBUG_TIME_START(Platform, platformConnect)
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
    _eventChannelManager = std::make_shared<EventChannelManager>(_gateway, _eventMiddleware);
    _handleManager = std::shared_ptr<HandleManager>(new HandleManager());
    _eventMiddleware->addConnectedEventListener([&] {
        std::shared_ptr<LibConnectedEvent> event(new LibConnectedEvent());
        _eventMiddleware->emitApiEvent(event);
    });
    _contextProvider = std::make_shared<ContextProvider>([&](const std::string& id) {
        auto model = privmx::utils::TypedObjectFactory::createNewObject<server::ContextGetModel>();
        model.id(id);
        return utils::TypedObjectFactory::createObjectFromVar<server::ContextGetResult>(_gateway->request("context.contextGet", model)).context();
    });
    if (_gateway->isConnected()) {
        std::shared_ptr<LibConnectedEvent> event(new LibConnectedEvent());
        _eventMiddleware->emitApiEvent(event);
    }
    _eventMiddleware->addDisconnectedEventListener([&] {
        std::shared_ptr<LibDisconnectedEvent> event(new LibDisconnectedEvent());
        _eventMiddleware->emitApiEvent(event);
    });
    _gateway->addNotificationEventListener([&, this](const rpc::NotificationEvent& event) {
        _eventMiddleware->emitNotificationEvent(event.type, event.channel, event.data);
    });
    _gateway->addConnectedEventListener(
        [&, this]([[maybe_unused]] const rpc::ConnectedEvent& event) { _eventMiddleware->emitConnectedEvent(); });
    _gateway->addDisconnectedEventListener(
        [&, this]([[maybe_unused]] const rpc::DisconnectedEvent& event) { _eventMiddleware->emitDisconnectedEvent(); });
    _gateway->addSessionLostEventListener(
        [&, this]([[maybe_unused]] const rpc::SessionLostEvent& event) { _eventMiddleware->emitDisconnectedEvent(); });
    assertServerVersion();
    PRIVMX_DEBUG_TIME_STOP(Platform, platformConnect)
}

void ConnectionImpl::connectPublic(const std::string& solutionId, const std::string& platformUrl, const PKIVerificationOptions& verificationOptions) {
    // TODO: solutionId is reserved for future use
    PRIVMX_DEBUG_TIME_START(Platform, platformConnect)
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
    _eventChannelManager = std::make_shared<EventChannelManager>(_gateway, _eventMiddleware);
    _handleManager = std::shared_ptr<HandleManager>(new HandleManager());
    _eventMiddleware->addConnectedEventListener([&] {
        std::shared_ptr<LibConnectedEvent> event(new LibConnectedEvent());
        _eventMiddleware->emitApiEvent(event);
    });
    _contextProvider = std::make_shared<ContextProvider>([&](const std::string& id) {
        auto context = privmx::utils::TypedObjectFactory::createNewObject<server::ContextInfo>();
        context.contextId(id);
        context.userId("<anonymous>");
        return context;
    });
    if (_gateway->isConnected()) {
        std::shared_ptr<LibConnectedEvent> event(new LibConnectedEvent());
        _eventMiddleware->emitApiEvent(event);
    }
    _eventMiddleware->addDisconnectedEventListener([&] {
        std::shared_ptr<LibDisconnectedEvent> event(new LibDisconnectedEvent());
        _eventMiddleware->emitApiEvent(event);
    });
    _gateway->addNotificationEventListener([&, this](const rpc::NotificationEvent& event) {
        _eventMiddleware->emitNotificationEvent(event.type, event.channel, event.data);
    });
    _gateway->addConnectedEventListener(
        [&, this]([[maybe_unused]] const rpc::ConnectedEvent& event) { _eventMiddleware->emitConnectedEvent(); });
    _gateway->addDisconnectedEventListener(
        [&, this]([[maybe_unused]] const rpc::DisconnectedEvent& event) { _eventMiddleware->emitDisconnectedEvent(); });
    _gateway->addSessionLostEventListener(
        [&, this]([[maybe_unused]] const rpc::SessionLostEvent& event) { _eventMiddleware->emitDisconnectedEvent(); });
    assertServerVersion();
    PRIVMX_DEBUG_TIME_STOP(Platform, platformConnect)
}

int64_t ConnectionImpl::getConnectionId() {
    return _connectionId;
}

PagingList<Context> ConnectionImpl::listContexts(const PagingQuery& pagingQuery) {
    PRIVMX_DEBUG_TIME_START(PlatformThread, contextList)
    auto listModel = utils::TypedObjectFactory::createNewObject<server::ListModel>();
    ListQueryMapper::map(listModel, pagingQuery);
    PRIVMX_DEBUG_TIME_CHECKPOINT(PlatformThread, contextList, data)
    auto response = utils::TypedObjectFactory::createObjectFromVar<server::ContextListResult>(
        _gateway->request("context.contextList", listModel));
    PRIVMX_DEBUG_TIME_CHECKPOINT(PlatformThread, contextList, data send)
    std::vector<Context> contexts{};
    for (auto resp : response.contexts()) {
        contexts.push_back({.userId = resp.userId(), .contextId = resp.contextId()});
    }
    PRIVMX_DEBUG_TIME_STOP(PlatformThread, contextList)
    return PagingList<Context>{.totalAvailable = response.count(), .readItems = contexts};
}

std::vector<UserInfo> ConnectionImpl::getContextUsers(const std::string& contextId) {
    PRIVMX_DEBUG_TIME_START(PlatformThread, getContextUsers)
    auto model = utils::TypedObjectFactory::createNewObject<server::ContextGetUsersModel>();
    model.contextId(contextId);
    PRIVMX_DEBUG_TIME_CHECKPOINT(PlatformThread, getContextUsers, data)
    auto response = utils::TypedObjectFactory::createObjectFromVar<server::ContextGetUserResult>(
        _gateway->request("context.contextGetUsers", model));
    PRIVMX_DEBUG_TIME_CHECKPOINT(PlatformThread, getContextUsers, data send)
    std::vector<UserInfo> usersInfo {};
    for (auto user : response.users()) {
        usersInfo.push_back(
            UserInfo{
                .user=UserWithPubKey{
                    .userId=user.id(), 
                    .pubKey=user.pub()
                }, 
                .isActive= user.status() == "active"
            }
        );
    }
    PRIVMX_DEBUG_TIME_STOP(PlatformThread, getContextUsers)
    return usersInfo;
}

void ConnectionImpl::setUserVerifier(std::shared_ptr<UserVerifierInterface> verifier) {
    std::unique_lock lock(_mutex);
    _userVerifier = verifier;
}

void ConnectionImpl::disconnect() {
    if (!_gateway.isNull()) {
        _gateway->destroy();
    }
    _gateway.reset();
    std::shared_ptr<LibPlatformDisconnectedEvent> event(new LibPlatformDisconnectedEvent());
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


std::string ConnectionImpl::generateDIORandomId() {
    return privmx::utils::Hex::from(privmx::crypto::Crypto::randomBytes(8));
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
        .randomId = generateDIORandomId(),
        .containerId = containerId,
        .containerResourceId = containerResourceId,
        .bridgeIdentity = _bridgeIdentity
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