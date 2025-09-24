/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include <Poco/URI.h>

#include <privmx/rpc/AuthorizedConnection.hpp>
#include <privmx/rpc/ClientEndpoint.hpp>
#include <privmx/crypto/Crypto.hpp>
#include <privmx/rpc/RpcException.hpp>
#include <privmx/rpc/RpcConfig.hpp>
#include <privmx/utils/Logger.hpp>

#ifdef PRIVMX_ENABLE_NET_EMSCRIPTEN
#include <emscripten/emscripten.h>
#include <emscripten/bind.h>
#endif

using namespace privmx::rpc;
using namespace std;
using Poco::Dynamic::Var;

AuthorizedConnection::AuthorizedConnection(const ConnectionOptionsFull& options)
        : _options(options), _ticket_updater_cancellation_token(utils::CancellationToken::create()) {
    initChannel();
}

void AuthorizedConnection::init() {
    if (_options.websocket) {
        if (_options.notifications) {
            authorizeWebsocket();
        }
    }
    _channels_connected = true;
    _session_checked = true;
    _session_established = true;
}

AuthorizedConnection::~AuthorizedConnection() {
    _ticket_updater_cancellation_token->cancel();
    destroyChannel();
}

bool AuthorizedConnection::isConnected() {
    return !_destroyed && _channels_connected && _session_checked && _session_established;
}

bool AuthorizedConnection::isSessionEstablished() {
    return _session_established;
}

ConnectionInfo::Ptr AuthorizedConnection::getInfo() {
    return _connection_info;
}

std::string AuthorizedConnection::getHost() {
    return _options.host;
}

const ConnectionOptionsFull& AuthorizedConnection::getOptions() {
    return _options;
}

Var AuthorizedConnection::call(const std::string& method, Poco::JSON::Object::Ptr params, const MessageSendOptionsEx& options, privmx::utils::CancellationToken::Ptr token, bool force_plain) {
    ClientEndpoint endpoint(_tickets_manager, _options);
    try {
        auto result = endpoint.call(method, params, force_plain);
        bool web_socket = options.channel_type.value_or(_options.main_channel) == ChannelType::WEBSOCKET;
        
        sendRequest(endpoint, web_socket, token);        
        #ifdef PRIVMX_ENABLE_NET_EMSCRIPTEN
        std::future_status status;
        do{
            status = result.wait_for(std::chrono::milliseconds(0));
            emscripten_sleep(10);
        } while(status == std::future_status::timeout);
        #endif
        return result.get();
    } catch (const TicketsCountIsEqualZeroException& e) {
        _session_established = false;
        e.rethrow();
    } catch (const utils::PrivmxException& e) {
        if (e.hasTypeAndMessage(utils::PrivmxException::ALERT, "Invalid ticket")) {
            _session_established = false;
        }
        e.rethrow();
    }
    throw RpcException("Call error");
}

void AuthorizedConnection::verifyConnection() {
    checkState();
    checkConnectionAndSessionAndRepairIfNeeded();
}

void AuthorizedConnection::destroy() {
    if (_destroyed) return;
    _ticket_updater_cancellation_token->cancel();
    clearWebSocket();
    _destroyed = true;
    _channels_connected = false;
    _session_checked = false;
    _session_established = false;
    
    _tickets_manager.clear();
    _disconnected_event_dispatcher.dispatch({});
}

int AuthorizedConnection::addNotificationEventListener(const utils::Callback<NotificationEvent>& event_listener) {
    return _notification_event_dispatcher.addEventListener(event_listener);
}

int AuthorizedConnection::addSessionLostEventListener(const utils::Callback<SessionLostEvent>& event_listener) {
    return _session_lost_event_dispatcher.addEventListener(event_listener);
}

int AuthorizedConnection::addConnectedEventListener(const utils::Callback<ConnectedEvent>& event_listener) {
    return _connected_event_dispatcher.addEventListener(event_listener);
}

int AuthorizedConnection::addDisconnectedEventListener(const utils::Callback<DisconnectedEvent>& event_listener) {
    return _disconnected_event_dispatcher.addEventListener(event_listener);
}

void AuthorizedConnection::removeNotificationEventListener(int listener_id) {
    _notification_event_dispatcher.removeEventListener(listener_id);
}

void AuthorizedConnection::removeSessionLostEventListener(int listener_id) {
    _session_lost_event_dispatcher.removeEventListener(listener_id);
}

void AuthorizedConnection::removeConnectedEventListener(int listener_id) {
    _connected_event_dispatcher.removeEventListener(listener_id);
}

void AuthorizedConnection::removeDisconnectedEventListener(int listener_id) {
    _disconnected_event_dispatcher.removeEventListener(listener_id);
}

void AuthorizedConnection::checkState() {
    checkDestroyed();
    checkSessionEstablished();
}

void AuthorizedConnection::checkDestroyed() {
    if (_destroyed) {
        throw ConnectionDestroyedException();
    }
}

void AuthorizedConnection::checkSessionEstablished() {
    if (!_session_established) {
        throw SessionLostException();
    }
}

void AuthorizedConnection::sendRequest(ClientEndpoint& endpoint, bool web_socket, privmx::utils::CancellationToken::Ptr token) {
    string request_buff_str = endpoint.request_buff.str();
    endpoint.flush();
    if (request_buff_str.length() <= 0) return;
    std::future  future_response = _server_channels->send(request_buff_str, web_socket, Poco::URI(_options.url).getPathAndQuery(), std::vector<std::pair<std::string, std::string>>{}, token);
    #ifdef PRIVMX_ENABLE_NET_EMSCRIPTEN
    std::future_status status;
    do{
        status = future_response.wait_for(std::chrono::milliseconds(0));
        emscripten_sleep(10);
    } while(status == std::future_status::timeout);
    #endif
    std::string response = future_response.get();
    stringstream stream(response);
    endpoint.connection.process(stream);
}

void AuthorizedConnection::ecdheConnect(const crypto::PrivateKey& key, const std::optional<std::string>& solution, const std::optional<crypto::PublicKey>& serverPubKey) {
    ClientEndpoint endpoint(_tickets_manager, _options);
    endpoint.connection.ecdheHandshake(key, solution, serverPubKey);
    endpoint.connection.ticketRequest(endpoint.TICKETS_MAX_COUNT);
    sendRequest(endpoint);
    EcdheConnectionInfo::Ptr info = new EcdheConnectionInfo();
    info->key = key.getPublicKey();
    info->serverConfig = endpoint.connection.getServerConfig();
    _connection_info = info;
    activate();
}

void AuthorizedConnection::ecdhexConnect(const crypto::PrivateKey& key, const std::optional<std::string>& solution, const std::optional<crypto::PublicKey>& serverPubKey) {
    ClientEndpoint endpoint(_tickets_manager, _options);
    endpoint.connection.ecdhexHandshake(key, solution, serverPubKey);
    endpoint.connection.ticketRequest(endpoint.TICKETS_MAX_COUNT);
    sendRequest(endpoint);
    EcdhexConnectionInfo::Ptr info = new EcdhexConnectionInfo();
    info->key = key.getPublicKey();
    info->host = endpoint.connection.getHost();
    info->serverConfig = endpoint.connection.getServerConfig();
    _connection_info = info;
    activate();
}

Poco::JSON::Object::Ptr AuthorizedConnection::srpConnect(const string& username, const string& password, GatewayProperties::Ptr properties) {
    ClientEndpoint endpoint(_tickets_manager, _options);
    endpoint.connection.ecdheHandshake();
    endpoint.connection.ticketRequest(endpoint.TICKETS_MIN_COUNT);
    sendRequest(endpoint);
    endpoint.connection.reset();
    endpoint.connection.ticketHandshake();
    endpoint.connection.srpHandshake2(username, getHost(), password, endpoint.TICKETS_MAX_COUNT, properties);
    // send srp init
    sendRequest(endpoint);
    // send srp exchange
    sendRequest(endpoint);
    const auto& handshake_result = endpoint.connection.getSrpHandshakeResult();
    SrpConnectionInfo::Ptr info = new SrpConnectionInfo();
    info->session_id = handshake_result.session_id;
    info->session_key = handshake_result.session_key;
    info->username = username,
    info->mixed = handshake_result.mixed;
    info->properties = properties;
    _connection_info = info;
    activate();
    return handshake_result.additional_login_step;
}

Poco::JSON::Object::Ptr AuthorizedConnection::keyConnect(const crypto::PrivateKey& private_key, GatewayProperties::Ptr properties) {
    ClientEndpoint endpoint(_tickets_manager,_options);
    endpoint.connection.ecdheHandshake();
    endpoint.connection.ticketRequest(endpoint.TICKETS_MIN_COUNT);
    sendRequest(endpoint);
    endpoint.connection.reset();
    endpoint.connection.ticketHandshake();
    endpoint.connection.keyHandshake2(private_key, endpoint.TICKETS_MAX_COUNT, properties);
    // send key init
    sendRequest(endpoint);
    // send key exchange
    sendRequest(endpoint);
    const auto& handshake_result = endpoint.connection.getKeyHandshakeResult();
    KeyConnectionInfo::Ptr info = new KeyConnectionInfo();
    info->session_id = handshake_result.session_id;
    info->session_key = handshake_result.session_key;
    info->username = handshake_result.username;
    info->key = private_key.getPublicKey();
    info->properties = properties;
    _connection_info = info;
    activate();
    return handshake_result.additional_login_step;
}

void AuthorizedConnection::sessionConnect(const SessionRestoreOptionsEx& options) {
    ClientEndpoint endpoint(_tickets_manager, _options);
    endpoint.connection.ecdheHandshake();
    endpoint.connection.ticketRequest(endpoint.TICKETS_MIN_COUNT);
    sendRequest(endpoint);
    endpoint.connection.reset();
    endpoint.connection.ticketHandshake();
    endpoint.connection.sessionHandshake(options.session_id, options.session_key, options.properties);
    endpoint.connection.ticketRequest(endpoint.TICKETS_MAX_COUNT);
    // send session
    sendRequest(endpoint);
    SessionConnectionInfo::Ptr info = new SessionConnectionInfo();
    info->session_id = options.session_id;
    info->session_key = options.session_key;
    info->username = options.username;
    info->properties = options.properties;
    _connection_info = info;
    activate();
}

void AuthorizedConnection::initChannel() {
    _channel_manager = ChannelManager::getInstance();
    if (_is_initialized) return;
    _server_channels = _channel_manager->add(url2schemeAndHost());
    _is_initialized = true;
}

void AuthorizedConnection::destroyChannel() {
    if (!_is_initialized) return;
    _channel_manager->remove(url2schemeAndHost());
    _is_initialized = false;
}

void AuthorizedConnection::activate() {
    _session_established = true;
    activateUpdateTicketLoop();
}

Poco::URI AuthorizedConnection::url2schemeAndHost() {
    Poco::URI url(_options.url);
    Poco::URI url2;
    url2.setScheme(url.getScheme());
    url2.setHost(url.getHost());
    url2.setPort(url.getPort());
    return url2;
}

void AuthorizedConnection::authorizeWebsocket() {
    auto key = crypto::Crypto::randomBytes(32);
    Poco::JSON::Object::Ptr params = new Poco::JSON::Object();
    params->set("key", utils::Base64::from(key));
    params->set("addWsChannelId", true);
    auto wschannel_id = call("authorizeWebSocket", params, {.channel_type = ChannelType::WEBSOCKET})
        .extract<Poco::JSON::Object::Ptr>()->getValue<Poco::Int32>("wsChannelId");
    _wschannel_id = wschannel_id;
    _server_channels->notify->add(wschannel_id, [&, key](const std::string& data){
        string decrypted = crypto::Crypto::aes256CbcHmac256Decrypt(data, key);
        Pson::Decoder decoder;
        auto decoded = decoder.decode(decrypted).extract<Poco::JSON::Object::Ptr>();
        auto type = decoded->optValue<std::string>("type", std::string());
        if (type == "disconnected") {
            return;
        }
        _notification_event_dispatcher.dispatch({.type = type, .data = decoded});
    }, [&]{
        _channels_connected = false;
        _session_checked = false;
        _disconnected_event_dispatcher.dispatch({});
    });
}

void AuthorizedConnection::checkConnectionAndSessionAndRepairIfNeeded() {
    checkConnectionAndRepairIfNeeded();
    checkSessionAndRepairIfNeeded();
}

void AuthorizedConnection::checkConnectionAndRepairIfNeeded() {
    if (_channels_connected) {
        return;
    }
    if (_options.websocket) {
        reconnectWebSocket();
    } else {
        performPlainTestPing();
    }
    _channels_connected = true;
}

void AuthorizedConnection::checkSessionAndRepairIfNeeded() {
    if (_session_checked) {
        return;
    }
    if (_options.websocket) {
        if (_options.notifications) {
            authorizeWebsocket();
        } else {
            performTicketTest(true);
        }
    } else {
        performTicketTest();
    }
    _session_checked = true;
    _connected_event_dispatcher.dispatch({});
}

void AuthorizedConnection::reconnectWebSocket() {
    // TODO
    clearWebSocket();
    performPlainTestPing(true);
}

void AuthorizedConnection::performPlainTestPing(bool websocket) {
    call("ping", Poco::JSON::Object::Ptr(new Poco::JSON::Object()), {.channel_type = websocket ? ChannelType::WEBSOCKET : ChannelType::AJAX},
            utils::CancellationToken::create(), true);
}

void AuthorizedConnection::performTicketTest(bool websocket) {
    // TODO
    call("ping", Poco::JSON::Object::Ptr(new Poco::JSON::Object()), {.channel_type = websocket ? ChannelType::WEBSOCKET : ChannelType::AJAX});
}

void AuthorizedConnection::clearWebSocket() {
    auto id = _wschannel_id.exchange(-1);
    if (id != -1) {
        if(_tickets_manager.ticketsCount() != 0) {
            try {
                call("unauthorizeWebSocket", Poco::JSON::Object::Ptr(new Poco::JSON::Object), {.channel_type = ChannelType::WEBSOCKET});
            } catch (...) {}
        }
        _server_channels->notify->remove(id);
    }
}

void AuthorizedConnection::activateUpdateTicketLoop() {
    if(_ticket_updater_cancellation_token->isCancelled()) {
        _ticket_updater_cancellation_token = utils::CancellationToken::create();
    }
    auto t = std::thread([&](privmx::utils::CancellationToken::Ptr token){
        LOG_INFO("AuthorizedConnection:TicketLoop Created")
        while(!token->isCancelled()) {
            try {
                if(_tickets_manager.shouldAskForNewTickets(ClientEndpoint::TICKETS_MIN_COUNT)) {
                    ClientEndpoint endpoint(_tickets_manager, _options);
                    endpoint.connection.reset();
                    endpoint.connection.ticketHandshake();
                    endpoint.connection.ticketRequest(ClientEndpoint::TICKETS_MAX_COUNT);
                    sendRequest(endpoint);
                    LOG_INFO("AuthorizedConnection:TicketLoop AskForNewTickets:success")
                } else {
                    token->sleep(std::chrono::seconds(10));
                }
            } catch (const privmx::utils::OperationCancelledException &e) {
                LOG_INFO("AuthorizedConnection:TicketLoop Cancel:Closing")
                return;
            } catch (...) {
                LOG_ERROR("AuthorizedConnection:TicketLoop catch(...)")
                token->sleep(std::chrono::seconds(1));
            }
        }
    }, _ticket_updater_cancellation_token);
    t.detach();
}