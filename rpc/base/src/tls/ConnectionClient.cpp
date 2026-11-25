/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include <Poco/HexBinaryEncoder.h>
#include <Poco/JSON/Object.h>
#include <Poco/JSON/Parser.h>
#include <Poco/Timestamp.h>
#include <Pson/BinaryString.hpp>

#include <privmx/crypto/Crypto.hpp>
#include <privmx/crypto/ecc/ECDHE.hpp>
#include <privmx/rpc/tls/ConnectionClient.hpp>
#include <privmx/rpc/RpcException.hpp>
#include <privmx/utils/PrivmxException.hpp>
#include <privmx/utils/Utils.hpp>
#include<optional>

using namespace privmx;
using namespace privmx::crypto;
using namespace privmx::rpc;
using namespace privmx::utils;
using namespace std;
using namespace Poco;
using namespace Poco::JSON;
using namespace Pson;
using Poco::Dynamic::Var;

ConnectionClient::ConnectionClient(std::ostream& output, TicketsManager& tickets_manager, const ConnectionOptionsFull& options)
: ConnectionBase(output), _tickets_manager(tickets_manager), _options(options) {}

void ConnectionClient::processHandshakePacket(const Var& packet) {
    string type = packet.extract<Object::Ptr>()->getValue<string>("type");
    if (type == "ecdhe") {
        if (!_ecdhe_private_key.has_value()) {
            throw UnexpectedEcdhePacketFromServerException();
        }
        string key = packet.extract<Object::Ptr>()->getValue<BinaryString>("key");
        PublicKey public_key = PublicKey::fromDER(key);
        ECDHE ecdhe(_ecdhe_private_key.value(), public_key);
        string secret = ecdhe.getSecret();
        extractServerConfig(packet);
        extractAndValidateChallenge(packet);
        _ecdhe_private_key = nullopt;
        setPreMasterSecret(secret);
    } else if (type == "ecdhex") {
        if (!_ecdhex_private_key.has_value()) {
            throw UnexpectedEcdhexPacketFromServerException();
        }
        string key = packet.extract<Object::Ptr>()->getValue<BinaryString>("key");
        _host = packet.extract<Object::Ptr>()->getValue<std::string>("host");
        extractServerConfig(packet);
        extractAndValidateChallenge(packet);
        PublicKey public_key = PublicKey::fromDER(key);
        ECDHE ecdhe(_ecdhex_private_key.value(), public_key);
        string secret = ecdhe.getSecret();
        _ecdhex_private_key = nullopt;
        setPreMasterSecret(secret);
    } else if (type == "ticket_response") {
        Object::Ptr ticket_response = packet.extract<Object::Ptr>();
        _tickets_manager.saveTickets(ticket_response->getArray("tickets"), ticket_response->getValue<int>("ttl"), _master_secret);
        on_ticket_response();
    }
}

inline string ConnectionClient::getClientAgent() {
    return _options.agent;
}

void ConnectionClient::ecdheHandshake(
    const PrivateKey& key, 
    const std::optional<std::string>& solution, 
    const std::optional<crypto::PublicKey>& serverPubKey
) {
    _ecdhe_private_key = key;
    string public_key = _ecdhe_private_key.value().getPublicKey().toDER();
    Object::Ptr packet = new Object();
    packet->set("type", "ecdhe");
    packet->set("key", BinaryString(public_key));
    packet->set("agent", getClientAgent());
    if (solution.has_value()) {
        packet->set("solution", solution.value());
    }
    if (serverPubKey.has_value()) {
        _serverPubKey = serverPubKey.value();
        _serverChallenge = utils::Hex::from(crypto::Crypto::randomBytes(32));
        packet->set("challenge", _serverChallenge);
    }
    send(_pson_encoder.encode(packet), ContentType::HANDSHAKE);
}

void ConnectionClient::ecdhexHandshake(
    const PrivateKey& key,
    const std::optional<std::string>& solution,
    const std::optional<crypto::PublicKey>& serverPubKey,
    const std::optional<SplitIdentity>& identity
) {
    _ecdhex_private_key = key;
    string timestamp = Utils::getNowTimestampStr();
    string nonce = Base64::from(Crypto::randomBytes(32));
    // Without a split identity the signing key *is* the key the channel is agreed with, and that is
    // what binds the two together. Once they are separate keys the signature has to name the
    // transport key itself, or a captured one could be replayed onto someone else's channel.
    string msg = identity.has_value()
        ? string("ecdhexlogin ").append(identity->transportKey).append(" ").append(nonce).append(" ").append(timestamp)
        : string("ecdhexlogin ").append(nonce).append(" ").append(timestamp);
    string signature = identity.has_value() ? identity->sign(msg) : key.signToCompactSignatureWithHash(msg);
    string public_key = key.getPublicKey().toDER();
    Object::Ptr packet = new Object();
    packet->set("type", "ecdhex");
    packet->set("agent", getClientAgent());
    packet->set("key", BinaryString(public_key));
    if (identity.has_value()) {
        packet->set("identityKey", identity->identityKey);
    }
    packet->set("nonce", nonce);
    packet->set("timestamp", timestamp);
    packet->set("signature", Base64::from(signature));
    if (solution.has_value()) {
        packet->set("solution", solution.value());
    }
    if (serverPubKey.has_value()) {
        _serverPubKey = serverPubKey.value();
        _serverChallenge = utils::Hex::from(crypto::Crypto::randomBytes(32));
        packet->set("challenge", _serverChallenge);
    }
    send(_pson_encoder.encode(packet), ContentType::HANDSHAKE);
}

void ConnectionClient::reset() {
    _read_state = RWState();
    _write_state = RWState();
    _next_read_state = RWState();
    _next_write_state = RWState();
    _client_random = string();
    _server_random = string();
    _master_secret = string();
    _ecdhe_private_key = nullopt;
    _ecdhex_private_key = nullopt;
}

void ConnectionClient::ticketHandshake() {
    SessionTicket ticket = _tickets_manager.useTicket();
    string client_random = Crypto::randomBytes(12);
    Object::Ptr packet = new Object();
    packet->set("type", "ticket");
    packet->set("ticket_id", BinaryString(ticket.id));
    packet->set("client_random", BinaryString(client_random));
    send(_pson_encoder.encode(packet), ContentType::HANDSHAKE);
    restore(ticket, client_random);
}

void ConnectionClient::ticketRequest(Int32 n) {
    Object::Ptr packet = new Object();
    packet->set("type", "ticket_request");
    packet->set("count", n);
    send(_pson_encoder.encode(packet), ContentType::HANDSHAKE);
}

void ConnectionClient::restore(const SessionTicket& ticket, const string& client_random) {
    restoreState(ticket.id, ticket.master_secret, client_random);
}

ConnectionClient::StatePair ConnectionClient::getFreshRWStatesFromParams(const StatePairCS& state_pair_cs) {
    StatePair result;
    result.read_state = state_pair_cs.server_state;
    result.write_state = state_pair_cs.client_state;
    return result;
}

void ConnectionClient::extractServerConfig(const Var& packet) {
    Object::Ptr obj = packet.extract<Object::Ptr>();
    _serverConfig.requestChunkSize = obj->getObject("config")->getValue<size_t>("requestChunkSize");
    if(obj->getObject("config")->has("serverVersion")) {
        _serverConfig.serverVersion = obj->getObject("config")->getValue<std::string>("serverVersion");
    }
}

void ConnectionClient::extractAndValidateChallenge(const Var& packet) {
    Object::Ptr obj = packet.extract<Object::Ptr>();
    if(_serverPubKey.has_value()) {
        if(!obj->has("signature") || obj->get("signature").isEmpty()) {
            throw ServerChallengeMissingSignatureException();
        }
        int64_t serverTimestamp = obj->getObject("signature")->getValue<int64_t>("timestamp");
        if (!utils::Utils::validateTimestamps(utils::Utils::getNowTimestamp(), serverTimestamp, ALLOWED_TIME_DIFFERENCE_BETWEEN_SERVER_AND_CLIENT)) {
            throw TimeDifferenceBetweenServerAndClientBiggerThanAllowedException(
                "Allowed time difference with server is " + std::to_string(ALLOWED_TIME_DIFFERENCE_BETWEEN_SERVER_AND_CLIENT) + "ms"
            );
        }
        std::string challengeResult = utils::Hex::toString(obj->getObject("signature")->getValue<std::string>("challenge"));
        auto result = _serverPubKey.value().verifyCompactSignatureWithHash((_serverChallenge + ";" + std::to_string(serverTimestamp)), challengeResult);
        if(!result) {
            throw ServerChallengeFailedException();
        }   
    }
}
