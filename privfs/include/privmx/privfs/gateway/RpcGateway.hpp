/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_PRIVFS_GATEWAY_RPCGATEWAY_HPP_
#define _PRIVMXLIB_PRIVFS_GATEWAY_RPCGATEWAY_HPP_

#include <functional>
#include <optional>
#include <string>
#include <Poco/Dynamic/Var.h>
#include <Poco/JSON/Object.h>
#include <Poco/SharedPtr.h>

#include "privmx/privfs/gateway/Types.hpp"
#include "privmx/crypto/ecc/ExtKey.hpp"
#include "privmx/crypto/ecc/PrivateKey.hpp"
#include <privmx/rpc/Types.hpp>
#include <privmx/privfs/gateway/Types.hpp>
#include <privmx/rpc/AuthorizedConnection.hpp>
#include <privmx/rpc/EventDispatcher.hpp>
#include <privmx/crypto/BIP39.hpp>

namespace privmx {
namespace privfs {

class RpcGateway
{
public:
    using Ptr = Poco::SharedPtr<RpcGateway>;

    static RpcGateway::Ptr createGatewayFromEcdheConnection(const std::optional<crypto::PrivateKey>& key, const rpc::ConnectionOptions& options, const std::optional<std::string>& solution = {});
    static RpcGateway::Ptr createGatewayFromEcdhexConnection(const crypto::PrivateKey& key, const rpc::ConnectionOptions& options, const std::optional<std::string>& solution = {});
    static RpcGateway::Ptr createGatewayFromKeyConnection(const crypto::PrivateKey& key, types::InitParameters init_parameters);
    static RpcGateway::Ptr createGatewayFromSrpConnection(const std::string& username, const std::string& password, types::InitParameters init_parameters);
    RpcGateway(rpc::AuthorizedConnection::Ptr rpc, std::optional<rpc::AdditionalLoginStepCallback> additional_login_step_on_relogin_callback);
    virtual ~RpcGateway() = default;
    virtual Poco::Dynamic::Var request(const std::string& method, Poco::JSON::Object::Ptr params = new Poco::JSON::Object(), rpc::MessageSendOptionsEx settings = rpc::MessageSendOptionsEx(), utils::CancellationToken::Ptr token = utils::CancellationToken::create());
    virtual void probe();
    virtual void verifyConnection();
    virtual void destroy();
    virtual bool isConnected();
    virtual bool isSessionEstablished();
    virtual bool isRestorableBySession();
    virtual rpc::ConnectionInfo::Ptr getInfo();
    virtual std::string getHost();
    virtual const rpc::ConnectionOptionsFull& getOptions();
    virtual std::string getType();
    virtual rpc::GatewayProperties::Ptr getProperties();
    virtual std::string getUsername();
    virtual types::InitParameters getInitParameters();
    virtual void srpRelogin(const std::string& username, const std::string& password);
    virtual void keyRelogin(const crypto::BIP39_t& recovery);
    virtual void tryRestoreBySession();
    virtual int addNotificationEventListener(const utils::Callback<rpc::NotificationEvent>& event_listener, int listener_id = -1);
    virtual int addSessionLostEventListener(const utils::Callback<rpc::SessionLostEvent>& event_listener, int listener_id = -1);
    virtual int addConnectedEventListener(const utils::Callback<rpc::ConnectedEvent>& event_listener, int listener_id = -1);
    virtual int addDisconnectedEventListener(const utils::Callback<rpc::DisconnectedEvent>& event_listener, int listener_id = -1);
    virtual void removeNotificationEventListener(int listener_id);
    virtual void removeSessionLostEventListener(int listener_id);
    virtual void removeConnectedEventListener(int listener_id);
    virtual void removeDisconnectedEventListener(int listener_id);

private:
    void switchRpc(rpc::AuthorizedConnection::Ptr new_rpc);
    void bindEventsFromRpc();

    rpc::AuthorizedConnection::Ptr _rpc;
    std::optional<rpc::AdditionalLoginStepCallback> _additional_login_step_on_relogin_callback;
    utils::EventDispatcher<rpc::NotificationEvent> _notification_event_dispatcher;
    utils::EventDispatcher<rpc::SessionLostEvent> _session_lost_event_dispatcher;
    utils::EventDispatcher<rpc::ConnectedEvent> _connected_event_dispatcher;
    utils::EventDispatcher<rpc::DisconnectedEvent> _disconnected_event_dispatcher;
};

} // privfs
} // privmx

#endif // _PRIVMXLIB_PRIVFS_GATEWAY_RPCGATEWAY_HPP_
