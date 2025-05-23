/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_RPC_AUTHORIZEDCONNECTION_HPP_
#define _PRIVMXLIB_RPC_AUTHORIZEDCONNECTION_HPP_

#include <atomic>
#include <Poco/SharedPtr.h>

#include <privmx/crypto/SRP.hpp>
#include <privmx/rpc/channel/ChannelManager.hpp>
#include <privmx/rpc/Types.hpp>
#include <privmx/rpc/tls/TicketsManager.hpp>
#include <privmx/rpc/ClientEndpoint.hpp>
#include <privmx/utils/EventDispatcher.hpp>
#include <privmx/rpc/RpcException.hpp>

namespace privmx {
namespace rpc {

struct NotificationEvent
{
    std::string type;
    Poco::JSON::Object::Ptr data;
};

struct SessionLostEvent
{

};

struct ConnectedEvent
{

};

struct DisconnectedEvent
{

};

class AuthorizedConnection
{
public:
    using Ptr = Poco::SharedPtr<AuthorizedConnection>;

    AuthorizedConnection(const ConnectionOptionsFull& options);
    ~AuthorizedConnection();
    void init();
    bool isConnected();
    bool isSessionEstablished();
    ConnectionInfo::Ptr getInfo();
    std::string getHost();
    const ConnectionOptionsFull& getOptions();
    Poco::Dynamic::Var call(const std::string& method, Poco::JSON::Object::Ptr params, const MessageSendOptionsEx& options = MessageSendOptionsEx(), privmx::utils::CancellationToken::Ptr token = privmx::utils::CancellationToken::create(), bool force_plain = false);
    void verifyConnection();
    void destroy();
    int addNotificationEventListener(const utils::Callback<NotificationEvent>& event_listener);
    int addSessionLostEventListener(const utils::Callback<SessionLostEvent>& event_listener);
    int addConnectedEventListener(const utils::Callback<ConnectedEvent>& event_listener);
    int addDisconnectedEventListener(const utils::Callback<DisconnectedEvent>& event_listener);
    void removeNotificationEventListener(int listener_id);
    void removeSessionLostEventListener(int listener_id);
    void removeConnectedEventListener(int listener_id);
    void removeDisconnectedEventListener(int listener_id);

    //
    void ecdheConnect(const crypto::PrivateKey& key, const std::optional<std::string>& solution, const std::optional<crypto::PublicKey>& serverPubKey);
    void ecdhexConnect(const crypto::PrivateKey& key, const std::optional<std::string>& solution, const std::optional<crypto::PublicKey>& serverPubKey);
    Poco::JSON::Object::Ptr srpConnect(const std::string& username, const std::string& password, GatewayProperties::Ptr properties);
    Poco::JSON::Object::Ptr keyConnect(const crypto::PrivateKey& private_key, GatewayProperties::Ptr properties);
    void sessionConnect(const SessionRestoreOptionsEx& options);

private:
    void checkState();
    void checkDestroyed();
    void checkSessionEstablished();
    void sendRequest(ClientEndpoint& endpoint, bool web_socket = false, privmx::utils::CancellationToken::Ptr token = privmx::utils::CancellationToken::create());
    void initChannel();
    void destroyChannel();
    void activate();
    Poco::URI url2schemeAndHost();
    void authorizeWebsocket();
    void checkConnectionAndSessionAndRepairIfNeeded();
    void checkConnectionAndRepairIfNeeded();
    void checkSessionAndRepairIfNeeded();
    void reconnectWebSocket();
    void performPlainTestPing(bool websocket = false);
    void performTicketTest(bool websocket = false);
    void clearWebSocket();

    void activateUpdateTicketLoop();

    ChannelManager::Ptr _channel_manager;
    ConnectionOptionsFull _options;
    ConnectionInfo::Ptr _connection_info;
    std::atomic_bool _destroyed = false;
    std::atomic_bool _channels_connected = false;
    std::atomic_bool _session_checked = false;
    std::atomic_bool _session_established = false;
    //
    TicketsManager _tickets_manager;
    SingleServerChannels::Ptr _server_channels;
    std::atomic_bool _is_initialized = false;
    //
    utils::EventDispatcher<NotificationEvent> _notification_event_dispatcher;
    utils::EventDispatcher<SessionLostEvent> _session_lost_event_dispatcher;
    utils::EventDispatcher<ConnectedEvent> _connected_event_dispatcher;
    utils::EventDispatcher<DisconnectedEvent> _disconnected_event_dispatcher;
    std::atomic<Poco::Int32> _wschannel_id = -1;
    //
    privmx::utils::CancellationToken::Ptr _ticket_updater_cancellation_token;
};

class SecondFactorServiceImpl : public SecondFactorService
{
public:
    using Ptr = Poco::SharedPtr<SecondFactorService>;

    SecondFactorServiceImpl(AuthorizedConnection::Ptr connection) : _connection(connection) {}
    std::string getHost() { return _connection->getHost(); }
    void confirm(Poco::JSON::Object::Ptr model) { _connection->call("twofaChallenge", model); }
    void resendCode() { _connection->call("twofaResendCode", Poco::JSON::Object::Ptr(new Poco::JSON::Object())); };
    void reject(const std::string& e) { throw RejectedException(e); }

private:
    AuthorizedConnection::Ptr _connection;
};

} // rpc
} // privmx

#endif // _PRIVMXLIB_RPC_AUTHORIZEDCONNECTION_HPP_
