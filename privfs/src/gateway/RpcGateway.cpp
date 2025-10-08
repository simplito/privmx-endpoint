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
#include <privmx/crypto/ecc/ExtKey.hpp>
#include <privmx/crypto/ecc/PrivateKey.hpp>
#include <privmx/privfs/types/Types.hpp>
#include <privmx/utils/TypedObject.hpp>
#include <privmx/utils/Utils.hpp>
#include <privmx/rpc/ConnectionManager.hpp>
#include <privmx/crypto/BIP39.hpp>
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
    return new RpcGateway(connection, nullopt);
}

RpcGateway::Ptr RpcGateway::createGatewayFromEcdhexConnection(const crypto::PrivateKey& key, const rpc::ConnectionOptions& options, const std::optional<std::string>& solution, const std::optional<crypto::PublicKey>& serverPubKey) {
    auto connection = rpc::ConnectionManager::getInstance()->createEcdhexConnection({.key = key, .solution = solution, .serverPubKey = serverPubKey}, options);
    return new RpcGateway(connection, nullopt);
}

RpcGateway::Ptr RpcGateway::createGatewayFromKeyConnection(const crypto::PrivateKey& key, types::InitParameters init_parameters) {
    auto connection = rpc::ConnectionManager::getInstance()->createKeyConnection({
        .key = key,
        .properties = init_parameters.gateway_properties,
        .on_additional_login_step = init_parameters.additional_login_step_callback
    }, init_parameters.options);
    return new RpcGateway(connection, init_parameters.additional_login_step_callback);
}

RpcGateway::Ptr RpcGateway::createGatewayFromSrpConnection(const std::string& username, const std::string& password, types::InitParameters init_parameters) {
    auto connection = rpc::ConnectionManager::getInstance()->createSrpConnection({
        .username = username,
        .password = password,
        .properties = init_parameters.gateway_properties,
        .on_additional_login_step = init_parameters.additional_login_step_callback
    }, init_parameters.options);
    return new RpcGateway(connection, init_parameters.additional_login_step_callback);
}

RpcGateway::RpcGateway(rpc::AuthorizedConnection::Ptr rpc, std::optional<rpc::AdditionalLoginStepCallback> additional_login_step_on_relogin_callback)
        : _rpc(rpc), _additional_login_step_on_relogin_callback(additional_login_step_on_relogin_callback) {
    bindEventsFromRpc();
}

Var RpcGateway::request(const string& method, Object::Ptr params, MessageSendOptionsEx settings, utils::CancellationToken::Ptr token) {
    if(isConnected()) {
        return _rpc->call(method, params, settings, token);
    }
    std::cerr << "not connected on request" << std::endl;
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

bool RpcGateway::isSessionEstablished() {
    return _rpc->isSessionEstablished();
}

bool RpcGateway::isRestorableBySession() {
    auto info = getInfo();
    return info->type != "ecdhe" && info.cast<rpc::ConnectionInfoWithSession>();
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

rpc::GatewayProperties::Ptr RpcGateway::getProperties() {
    auto info = _rpc->getInfo();
    auto session_info = info.cast<rpc::ConnectionInfoWithSession>();
    if (session_info.isNull()) {
        throw CannotGetPropertiesFromNonSrpKeySessionConnectionException();
    }
    return session_info->properties;
}

std::string RpcGateway::getUsername() {
    auto info = _rpc->getInfo();
    auto session_info = info.cast<rpc::ConnectionInfoWithSession>();
    if (session_info.isNull()) {
        throw CannotGetUsernameFromNonSrpKeySessionConnectionException();
    }
    return session_info->username;
}

types::InitParameters RpcGateway::getInitParameters() {
    types::InitParameters res;
    res.options = getOptions().asOpt();
    res.gateway_properties = getProperties();
    res.additional_login_step_callback = _additional_login_step_on_relogin_callback;
    return res;
}

void RpcGateway::srpRelogin([[maybe_unused]] const std::string& username, [[maybe_unused]] const std::string& password) {
    auto new_rpc = rpc::ConnectionManager::getInstance()->createSrpConnection({
        .username = username,
        .password = password,
        .properties = getProperties(),
        .on_additional_login_step = _additional_login_step_on_relogin_callback
    }, getOptions().asOpt());
    if (new_rpc->getInfo().cast<rpc::SrpConnectionInfo>()->username != getUsername()) {
        throw CannotReloginUserMismatchException();
    }
    switchRpc(new_rpc);
}

void RpcGateway::keyRelogin(const BIP39_t& recovery) {
    auto new_rpc = rpc::ConnectionManager::getInstance()->createKeyConnection({
        .key = recovery.ext_key.getPrivateKey(),
        .properties = getProperties(),
        .on_additional_login_step = _additional_login_step_on_relogin_callback
    }, getOptions().asOpt());
    if (new_rpc->getInfo().cast<rpc::SrpConnectionInfo>()->username != getUsername()) {
        throw CannotReloginUserMismatchException();
    }
    switchRpc(new_rpc);
}

void RpcGateway::tryRestoreBySession() {
    auto info = getInfo().cast<rpc::ConnectionInfoWithSession>();
    if (info.isNull() || !info->session_key.has_value()) {
        throw ConnectionCannotBeRestoredBySessionException();
    }
    try {
        auto new_rpc = rpc::ConnectionManager::getInstance()->createSessionConnection({
            .session_id = info->session_id,
            .session_key = info->session_key.value(),
            .username = info->username,
            .properties = info->properties
        }, getOptions().asOpt());
        switchRpc(new_rpc);
    } catch (PrivmxException& e) {
        if (e.getType() == PrivmxException::ALERT) {
            info->session_key = nullopt;
        }
        e.rethrow();
    }
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

void RpcGateway::switchRpc(rpc::AuthorizedConnection::Ptr new_rpc) {
    if (_rpc) _rpc->destroy();
    _rpc = new_rpc;
    bindEventsFromRpc();
    _connected_event_dispatcher.dispatch({});
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
