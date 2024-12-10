/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_RPC_CONNECTIONCLIENT_HPP_
#define _PRIVMXLIB_RPC_CONNECTIONCLIENT_HPP_

#include <functional>
#include <map>
#include <string>
#include <Poco/JSON/Array.h>
#include <Poco/JSON/Object.h>
#include <Poco/Types.h>
#include <Pson/Encoder.hpp>

#include <privmx/crypto/ecc/PrivateKey.hpp>
#include <privmx/crypto/SRP.hpp>
#include <privmx/rpc/tls/ConnectionBase.hpp>
#include <privmx/rpc/tls/TicketsManager.hpp>
#include <privmx/rpc/Types.hpp>
#include <optional>

namespace privmx {
namespace rpc {

class ConnectionClient : public ConnectionBase
{
public:
    ConnectionClient(std::ostream& output, TicketsManager& tickets_manager, const ConnectionOptionsFull& options);
    void processHandshakePacket(const Poco::Dynamic::Var& packet) override;
    void ecdheHandshake(const crypto::PrivateKey& key = crypto::PrivateKey::generateRandom());
    void ecdhexHandshake(const crypto::PrivateKey& key, const std::optional<std::string>& solution);
    void srpHandshake(const std::string& hashmail, const std::string& password, Poco::Int32 tickets = 1);
    void srpHandshake2(const std::string& username, const std::string& host, const std::string& password, Poco::Int32 tickets = 1, GatewayProperties::Ptr properties = nullptr);
    void keyHandshake(const std::string& private_key_buf, Poco::Int32 tickets = 1, const Poco::Dynamic::Var& properties = Poco::JSON::Object::Ptr(new Poco::JSON::Object()));
    void keyHandshake2(const crypto::PrivateKey& private_key, Poco::Int32 tickets = 1, GatewayProperties::Ptr properties = nullptr);
    void sessionHandshake(const std::string& session_id, const crypto::PrivateKey& session_key, GatewayProperties::Ptr properties = nullptr);
    void reset(bool keepSession = false);
    void ticketHandshake();
    void ticketRequest(Poco::Int32 n = 1);
    void restore(const SessionTicket& ticket, const std::string& client_random);
    StatePair getFreshRWStatesFromParams(const StatePairCS& state_pair_cs) override;
    Poco::Dynamic::Var validateSrpInit(const Poco::Dynamic::Var& packet);
    void validateSrpExchange(const Poco::Dynamic::Var& packet);
    Poco::Dynamic::Var validateKeyInit(const Poco::Dynamic::Var& packet);
    void validateKeyExchange(const Poco::Dynamic::Var& packet);
    void validateSessionResponse(const Poco::Dynamic::Var& packet);
    crypto::SrpData getSrpData() const { return _srp.getSrpData(); }
    Poco::JSON::Object::Ptr getAdditionalLoginStep() const { return _additional_login_step; }
    const SrpHandshakeResult& getSrpHandshakeResult() { return _srp_handshake_result; }
    const KeyHandshakeResult& getKeyHandshakeResult() { return _key_handshake_result; }
    const std::string& getHost() { return _host; }
    const ServerConfig& getServerConfig() const { return _serverConfig; }

    std::function<void(void)> on_ticket_response;

private:
    virtual std::string getClientAgent();
    void extractServerConfig(const Poco::Dynamic::Var& packet);

    TicketsManager& _tickets_manager;
    Pson::Encoder _pson_encoder;
    std::optional<crypto::PrivateKey> _ecdhe_private_key;
    std::optional<crypto::PrivateKey> _ecdhex_private_key;
    crypto::SRP _srp;
    std::optional<crypto::PrivateKey> _private_key;
    std::string _K;
    Poco::Int32 _tickets_count;
    Poco::JSON::Object::Ptr _additional_login_step;
    //
    SrpHandshakeResult _srp_handshake_result;
    KeyHandshakeResult _key_handshake_result;
    std::optional<crypto::PrivateKey> _session_key;
    ConnectionOptionsFull _options;
    std::string _host;
    ServerConfig _serverConfig;
};

} // rpc
} // privmx

#endif // _PRIVMXLIB_RPC_CONNECTIONCLIENT_HPP_
