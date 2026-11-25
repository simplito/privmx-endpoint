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
    void ecdheHandshake(
        const crypto::PrivateKey& key = crypto::PrivateKey::generateRandom(),
        const std::optional<std::string>& solution = std::nullopt, 
        const std::optional<crypto::PublicKey>& serverPubKey = std::nullopt
    );
    /**
     * @param key the key the channel's secret is agreed with; also the identity unless @p identity is set
     * @param identity set when the one logging in cannot do key agreement and so cannot be @p key
     */
    void ecdhexHandshake(
        const crypto::PrivateKey& key,
        const std::optional<std::string>& solution,
        const std::optional<crypto::PublicKey>& serverPubKey,
        const std::optional<SplitIdentity>& identity = std::nullopt
    );
    void reset();
    void ticketHandshake();
    void ticketRequest(Poco::Int32 n = 1);
    void restore(const SessionTicket& ticket, const std::string& client_random);
    StatePair getFreshRWStatesFromParams(const StatePairCS& state_pair_cs) override;
    const std::string& getHost() { return _host; }
    const ServerConfig& getServerConfig() const { return _serverConfig; }

    std::function<void(void)> on_ticket_response;

private:
    virtual std::string getClientAgent();
    void extractServerConfig(const Poco::Dynamic::Var& packet);
    void extractAndValidateChallenge(const Poco::Dynamic::Var& packet) ;

    TicketsManager& _tickets_manager;
    Pson::Encoder _pson_encoder;
    std::optional<crypto::PrivateKey> _ecdhe_private_key;
    std::optional<crypto::PrivateKey> _ecdhex_private_key;
    ConnectionOptionsFull _options;
    std::string _host;
    ServerConfig _serverConfig;
    // Challenge
    std::optional<crypto::PublicKey> _serverPubKey;
    std::string _serverChallenge;
    
    static constexpr int64_t ALLOWED_TIME_DIFFERENCE_BETWEEN_SERVER_AND_CLIENT = 150*1000; // in ms
};

} // rpc
} // privmx

#endif // _PRIVMXLIB_RPC_CONNECTIONCLIENT_HPP_
