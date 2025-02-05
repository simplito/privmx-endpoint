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
#include <privmx/crypto/ecc/ECIES.hpp>
#include <privmx/crypto/PasswordMixer.hpp>
#include <privmx/rpc/tls/ConnectionClient.hpp>
#include <privmx/rpc/RpcException.hpp>
#include <privmx/utils/Base58.hpp>
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
        _ecdhe_private_key = nullopt;
        setPreMasterSecret(secret);
    } else if (type == "ecdhex") {
        if (!_ecdhex_private_key.has_value()) {
            throw UnexpectedEcdhexPacketFromServerException();
        }
        string key = packet.extract<Object::Ptr>()->getValue<BinaryString>("key");
        _host = packet.extract<Object::Ptr>()->getValue<std::string>("host");
        extractServerConfig(packet);
        PublicKey public_key = PublicKey::fromDER(key);
        ECDHE ecdhe(_ecdhex_private_key.value(), public_key);
        string secret = ecdhe.getSecret();
        _ecdhex_private_key = nullopt;
        setPreMasterSecret(secret);
    } else if (type == "ticket_response") {
        Object::Ptr ticket_response = packet.extract<Object::Ptr>();
        _tickets_manager.saveTickets(ticket_response->getArray("tickets"), ticket_response->getValue<int>("ttl"), _master_secret);
        on_ticket_response();
    } else if (type == "srp_init") {
        Var exchange = validateSrpInit(packet);
        extractServerConfig(packet);
        reset(true);
        ticketHandshake();
        send(_pson_encoder.encode(exchange), ContentType::HANDSHAKE);
    } else if (type == "srp_exchange") {
        validateSrpExchange(packet);
    } else if (type == "key_init") {
        Var exchange = validateKeyInit(packet);
        extractServerConfig(packet);
        reset(true);
        ticketHandshake();
        send(_pson_encoder.encode(exchange), ContentType::HANDSHAKE);
    } else if (type == "key_exchange") {
        validateKeyExchange(packet);
    } else if (type == "session") {
        validateSessionResponse(packet);
        extractServerConfig(packet);
    }
}

inline string ConnectionClient::getClientAgent() {
    return _options.agent;
}

void ConnectionClient::ecdheHandshake(const PrivateKey& key, const std::optional<std::string>& solution) {
    _ecdhe_private_key = key;
    string public_key = _ecdhe_private_key.value().getPublicKey().toDER();
    Object::Ptr packet = new Object();
    packet->set("type", "ecdhe");
    packet->set("key", BinaryString(public_key));
    packet->set("agent", getClientAgent());
    if (solution.has_value()) {
        packet->set("solution", solution.value());
    }
    send(_pson_encoder.encode(packet), ContentType::HANDSHAKE);
}

void ConnectionClient::ecdhexHandshake(const PrivateKey& key, const std::optional<std::string>& solution) {
    _ecdhex_private_key = key;
    string timestamp = Utils::getNowTimestampStr();
    string nonce = Base64::from(Crypto::randomBytes(32));
    string msg = string("ecdhexlogin ").append(nonce).append(" ").append(timestamp);
    string signature = key.signToCompactSignatureWithHash(msg);
    string public_key = key.getPublicKey().toDER();
    Object::Ptr packet = new Object();
    packet->set("type", "ecdhex");
    packet->set("agent", getClientAgent());
    packet->set("key", BinaryString(public_key));
    packet->set("nonce", nonce);
    packet->set("timestamp", timestamp);
    packet->set("signature", Base64::from(signature));
    if (solution.has_value()) {
        packet->set("solution", solution.value());
    }
    send(_pson_encoder.encode(packet), ContentType::HANDSHAKE);
}

void ConnectionClient::srpHandshake(const string& hashmail, const string& password, Int32 tickets) {
    size_t hash_pos = hashmail.find('#');
    if (hash_pos == string::npos || hash_pos + 2 > hashmail.length()) {
        throw IncorrectHashmailException();
    }
    string username = hashmail.substr(0, hash_pos);
    string host = hashmail.substr(hash_pos + 1);
    if (_srp.isInitialized()) {
        throw InvalidHandshakeStateException();
    }
    Object::Ptr packet = new Object();
    packet->set("type", "srp_init");
    packet->set("I", username);
    packet->set("host", host);
    packet->set("agent", getClientAgent());
    send(_pson_encoder.encode(packet), ContentType::HANDSHAKE);
    _srp.initialize(username, password, tickets);
}

void ConnectionClient::srpHandshake2(const string& username, const std::string& host, const string& password, Int32 tickets, GatewayProperties::Ptr properties) {
    Object::Ptr packet = new Object();
    packet->set("type", "srp_init");
    packet->set("I", username);
    packet->set("host", host);
    packet->set("agent", getClientAgent());
    if (properties) {
        packet->set("properties", properties);
    }
    send(_pson_encoder.encode(packet), ContentType::HANDSHAKE);
    _srp.initialize(username, password, tickets);
}

void ConnectionClient::keyHandshake(const string& private_key_buf, Int32 tickets, const Var& properties) {
    _private_key = PrivateKey(ECC::fromPrivateKey(private_key_buf));
    string pub = _private_key.value().getPublicKey().toBase58DER();
    _tickets_count = tickets;
    Object::Ptr packet = new Object();
    packet->set("type", "key_init");
    packet->set("pub", pub);
    packet->set("agent", getClientAgent());
    if (properties) {
        packet->set("properties", properties);
    }
    send(_pson_encoder.encode(packet), ContentType::HANDSHAKE);
}

void ConnectionClient::keyHandshake2(const PrivateKey& private_key, Int32 tickets, GatewayProperties::Ptr properties) {
    _private_key = private_key;
    string pub = _private_key.value().getPublicKey().toBase58DER();
    _tickets_count = tickets;
    Object::Ptr packet = new Object();
    packet->set("type", "key_init");
    packet->set("pub", pub);
    packet->set("agent", getClientAgent());
    if (properties) {
        packet->set("properties", properties);
    }
    send(_pson_encoder.encode(packet), ContentType::HANDSHAKE);
}

void ConnectionClient::sessionHandshake(const string& session_id, const PrivateKey& session_key, [[maybe_unused]] GatewayProperties::Ptr properties) {
    _session_key = session_key;
    auto nonce = Base64::from(Crypto::randomBytes(32));
    auto timestamp = Utils::getNowTimestampStr();
    auto signature_data = string("restore_").append(session_id).append(" ").append(nonce).append(" ").append(timestamp);
    auto signature = session_key.signToCompactSignatureWithHash(signature_data);
    Object::Ptr packet = new Object();
    packet->set("type", "session");
    packet->set("sessionId", session_id);
    packet->set("sessionKey", session_key.getPublicKey().toBase58DER());
    packet->set("nonce", nonce);
    packet->set("timestamp", timestamp);
    packet->set("signature", Base64::from(signature));
    send(_pson_encoder.encode(packet), ContentType::HANDSHAKE);
}

void ConnectionClient::reset(bool keepSession) {
    _read_state = RWState();
    _write_state = RWState();
    _next_read_state = RWState();
    _next_write_state = RWState();
    _client_random = string();
    _server_random = string();
    _master_secret = string();
    if (keepSession == true) return;
    //session reset
    _ecdhe_private_key = nullopt;
    _ecdhex_private_key = nullopt;
    _private_key = nullopt;
    _srp.clear();
    _K = string();
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

Var ConnectionClient::validateSrpInit(const Var& packet) {
    auto result = _srp.validateSrpInit(packet);
    if (_options.restorable_session) {
        _session_key = PrivateKey::generateRandom();
        auto obj = result.extract<Object::Ptr>();
        obj->set("sessionKey", _session_key.value().getPublicKey().toBase58DER());
    }
    return result;
}

void ConnectionClient::validateSrpExchange(const Var& packet) {
    string K = _srp.validateSrpExchange(packet);
    K = Utils::fillTo32(K);
    setPreMasterSecret(K);
    Object::Ptr tickets_response = packet.extract<Object::Ptr>();
    auto srp_data = _srp.getSrpData();
    _srp_handshake_result.session_id = srp_data.session_id;
    _srp_handshake_result.mixed = srp_data.mixed;
    if (tickets_response->has("additionalLoginStep")) {
        _additional_login_step = tickets_response->getObject("additionalLoginStep");
        _srp_handshake_result.additional_login_step = tickets_response->getObject("additionalLoginStep");
    }
    if (_session_key) {
        _srp_handshake_result.session_key = _session_key;
    }
    _tickets_manager.clear();
    _tickets_manager.saveTickets(tickets_response->getArray("tickets"), tickets_response->getValue<int>("ttl"), _master_secret);
}

Var ConnectionClient::validateKeyInit(const Var& packet) {
    Object::Ptr key_init = packet.extract<Object::Ptr>();
    auto session_id = key_init->getValue<string>("sessionId");
    _key_handshake_result.session_id = session_id;
    _key_handshake_result.username = key_init->getValue<string>("I");
    Int64 timestamp = Timestamp().raw()/1000;
    string nonce = Crypto::randomBytes(32);
    nonce = Base64::from(nonce);
    _K = Crypto::randomBytes(32);
    ECIES ecies(_private_key.value(), PublicKey::fromBase58DER(key_init->getValue<string>("pub")));
    string K_base64 = Base64::from(ecies.encrypt(_K));
    string signature = "login" + K_base64 + " " + nonce + " " + to_string(timestamp);
    signature = Crypto::sha256(signature);
    signature = _private_key.value().signToCompactSignature(signature);
    Object::Ptr result = new Object();
    result->set("type", "key_exchange");
    result->set("sessionId", session_id);
    result->set("nonce", nonce);
    result->set("timestamp", to_string(timestamp));
    result->set("signature", Base64::from(signature));
    result->set("K", K_base64);
    result->set("tickets", _tickets_count);
    if (_options.restorable_session) {
        _session_key = PrivateKey::generateRandom();
        result->set("sessionKey", _session_key.value().getPublicKey().toBase58DER());
    }
    return result;
}

void ConnectionClient::validateKeyExchange(const Var& packet) {
    if (_K.empty()) {
        throw InvalidHandshakeStateException();
    }
    _K = Utils::fillTo32(_K);
    setPreMasterSecret(_K);
    Object::Ptr tickets_response = packet.extract<Object::Ptr>();
    if (tickets_response->has("additionalLoginStep")) {
        _additional_login_step = tickets_response->getObject("additionalLoginStep");
        _key_handshake_result.additional_login_step = tickets_response->getObject("additionalLoginStep");
    }
    if (_session_key) {
        _key_handshake_result.session_key = _session_key;
    }
    _tickets_manager.clear();
    _tickets_manager.saveTickets(tickets_response->getArray("tickets"), tickets_response->getValue<int>("ttl"), _master_secret);
}

void ConnectionClient::validateSessionResponse(const Var& packet) {
    Object::Ptr response = packet.extract<Object::Ptr>();
    auto key = PublicKey(ECC::fromPublicKey(response->getValue<BinaryString>("key")));
    auto derived = Utils::fillTo32(_session_key.value().derive(key));
    setPreMasterSecret(derived);
}

void ConnectionClient::extractServerConfig(const Var& packet) {
    Object::Ptr obj = packet.extract<Object::Ptr>();
    _serverConfig.requestChunkSize = obj->getObject("config")->getValue<size_t>("requestChunkSize");
}
