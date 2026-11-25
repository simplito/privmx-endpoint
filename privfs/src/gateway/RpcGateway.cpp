/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include <string>
#include <Poco/Dynamic/Var.h>
#include <Poco/JSON/Object.h>
#include <Poco/JSON/Parser.h>

#include <privmx/privfs/gateway/RpcGateway.hpp>
#include <privmx/crypto/Crypto.hpp>
#include <privmx/crypto/CryptoPrivmx.hpp>
#include <privmx/crypto/ecc/PrivateKey.hpp>
#include <privmx/privfs/types/Types.hpp>
#include <privmx/utils/TypedObject.hpp>
#include <privmx/utils/Utils.hpp>
#include <privmx/rpc/ConnectionManager.hpp>
#include <privmx/utils/PrivmxException.hpp>
#include <privmx/privfs/PrivFsException.hpp>
#include <optional>

using namespace privmx;
using namespace privmx::crypto;
using namespace privmx::privfs;
using namespace privmx::utils;
using namespace std;
using namespace Poco::JSON;
using Poco::Dynamic::Var;
using rpc::MessageSendOptionsEx;

RpcGateway::Ptr RpcGateway::createGatewayFromEcdheConnection(const std::optional<crypto::PrivateKey>& key, const rpc::ConnectionOptions& options, const std::optional<std::string>& solution, const std::optional<crypto::PublicKey>& serverPubKey) {
    auto connection = rpc::ConnectionManager::getInstance()->createEcdheConnection({.key = key, .solution = solution, .serverPubKey = serverPubKey}, options);
    return new RpcGateway(connection);
}

RpcGateway::Ptr RpcGateway::createGatewayFromEcdhexConnection(const crypto::PrivateKey& key, const rpc::ConnectionOptions& options, const std::optional<std::string>& solution, const std::optional<crypto::PublicKey>& serverPubKey, const std::optional<rpc::SplitIdentity>& identity) {
    auto connection = rpc::ConnectionManager::getInstance()->createEcdhexConnection({.key = key, .solution = solution, .serverPubKey = serverPubKey, .identity = identity}, options);
    return new RpcGateway(connection);
}

RpcGateway::RpcGateway(rpc::AuthorizedConnection::Ptr rpc) : _rpc(rpc) {
    bindEventsFromRpc();
}

Var RpcGateway::request(const string& method, Object::Ptr params, MessageSendOptionsEx settings, utils::CancellationToken::Ptr token) {
    if(isConnected()) {
        try {
            return _rpc->call(method, params, settings, token);
        } catch (const privmx::rpc::HttpRequestException& e) {
            return _rpc->call(method, params, settings, token);
        }
    }
    throw NotConnectedException();
    return Var();
}

void RpcGateway::probe() {
    auto options = getOptions();
    rpc::ConnectionManager::getInstance()->probe(options.url);
}

void RpcGateway::verifyConnection() {
    _rpc->verifyConnection();
}

void RpcGateway::destroy() {
    _rpc->destroy();
}

bool RpcGateway::isConnected() {
    return _rpc->isConnected();
}

rpc::ConnectionInfo::Ptr RpcGateway::getInfo() {
    return _rpc->getInfo();
}

std::string RpcGateway::getHost() {
    return _rpc->getHost();
}

const rpc::ConnectionOptionsFull& RpcGateway::getOptions() {
    return _rpc->getOptions();
}

std::string RpcGateway::getType() {
    return _rpc->getInfo()->type;
}

int RpcGateway::addNotificationEventListener(const utils::Callback<rpc::NotificationEvent>& event_listener, int listener_id) {
    return _notification_event_dispatcher.addEventListener(event_listener, listener_id);
}

int RpcGateway::addSessionLostEventListener(const utils::Callback<rpc::SessionLostEvent>& event_listener, int listener_id) {
    return _session_lost_event_dispatcher.addEventListener(event_listener, listener_id);
}

int RpcGateway::addConnectedEventListener(const utils::Callback<rpc::ConnectedEvent>& event_listener, int listener_id) {
    return _connected_event_dispatcher.addEventListener(event_listener, listener_id);
}

int RpcGateway::addDisconnectedEventListener(const utils::Callback<rpc::DisconnectedEvent>& event_listener, int listener_id) {
    return _disconnected_event_dispatcher.addEventListener(event_listener, listener_id);
}

void RpcGateway::removeNotificationEventListener(int listener_id) {
    _notification_event_dispatcher.removeEventListener(listener_id);
}

void RpcGateway::removeSessionLostEventListener(int listener_id) {
    _session_lost_event_dispatcher.removeEventListener(listener_id);
}

void RpcGateway::removeConnectedEventListener(int listener_id) {
    _connected_event_dispatcher.removeEventListener(listener_id);
}

void RpcGateway::removeDisconnectedEventListener(int listener_id) {
    _disconnected_event_dispatcher.removeEventListener(listener_id);
}

void RpcGateway::bindEventsFromRpc() {
    if (_rpc.isNull()) {
        return;
    }
    _rpc->addNotificationEventListener([&](const auto& x){ _notification_event_dispatcher.dispatch(x); });
    _rpc->addSessionLostEventListener([&](const auto& x){ _session_lost_event_dispatcher.dispatch(x); });
    _rpc->addConnectedEventListener([&](const auto& x){ _connected_event_dispatcher.dispatch(x); });
    _rpc->addDisconnectedEventListener([&](const auto& x){ _disconnected_event_dispatcher.dispatch(x); });
}
