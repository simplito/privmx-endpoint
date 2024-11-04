/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include <sstream>
#include <Poco/BinaryWriter.h>
#include <Poco/ByteOrder.h>
#include <Poco/HexBinaryDecoder.h>

#include <privmx/crypto/Crypto.hpp>
#include <privmx/rpc/tls/ConnectionBase.hpp>
#include <privmx/utils/BinaryBuffer.hpp>
#include <privmx/utils/PrivmxExtExceptions.hpp>
#include <privmx/rpc/RpcException.hpp>
#include <privmx/utils/Utils.hpp>

using namespace privmx;
using namespace privmx::crypto;
using namespace privmx::rpc;
using namespace privmx::utils;
using namespace std;
using namespace Poco;
using Poco::Dynamic::Var;

const std::vector<std::string> ConnectionBase::DICT = { "type", "ticket", "tickets", "ticket_id", "ticket_request",
        "ticket_response", "ecdhe", "ecdh", "key", "count", "client_random" };

ConnectionBase::ConnectionBase(std::ostream& output) : _output(output) {
    _pson_decoder.dict = DICT;
}

void ConnectionBase::send(const string& packet, UInt8 content_type, bool force_plaintext) {
    BinaryBuffer frame_header;
    BinaryBuffer frame_data;
    BinaryBuffer frame_mac;
    if (!force_plaintext && _write_state.initialized()) {
        UInt32 frame_length = packet.length();
        if (frame_length > 0) {
            frame_length = ((frame_length + 16) >> 4) << 4;
        }
        BinaryBuffer frame_header_body;
        frame_header_body
            << _version 
            << content_type
            << ByteOrder::toBigEndian(frame_length);
        frame_header_body.writeRaw("\0\0", 2);
        BinaryBuffer seq_bin;
        seq_bin << ByteOrder::toBigEndian(_write_state.sequence_number);
        _write_state.sequence_number++;
        string frame_seed = seq_bin.str() + frame_header_body.str();
        string frame_header_tag = Crypto::hmacSha256(_write_state.mac_key, frame_seed);
        string frame_header2 = frame_header_body.str() + frame_header_tag.substr(0, 8);
        frame_header2 = Crypto::aes256EcbEncrypt(frame_header2, _write_state.key);
        frame_header.writeRaw(frame_header2);
        if (frame_length > 0) {
            string iv = frame_header2;
            string frame_data2 = Crypto::aes256CbcPkcs7Encrypt(packet, _write_state.key, iv);
            frame_data.writeRaw(frame_data2);
            string frame_mac_tohmac = frame_seed + iv + frame_data2;
            string frame_mac_str = Crypto::hmacSha256(_write_state.mac_key, frame_mac_tohmac);
            frame_mac_str = frame_mac_str.substr(0, 16);
            frame_mac.writeRaw(frame_mac_str);
        }
    } else {
        frame_header << _version;
        frame_header << content_type;
        UInt32 frame_length = packet.length();
        frame_header << ByteOrder::toBigEndian(frame_length);
        frame_header.writeRaw("\0\0", 2);
        frame_data.writeRaw(packet);
    }
    frame_header.copyToStream(_output);
    frame_data.copyToStream(_output);
    frame_mac.copyToStream(_output);
}

void ConnectionBase::process(istream& input) {
    BinaryReader inputReader(input);
    string frame_header;
    string frame_seed;
    string iv;
    while (!inputReader.eof()) {
        if (_read_state.initialized()) {
            inputReader.readRaw(16, frame_header);
            if (frame_header.length() == 0) {
                return;
            }
            iv = frame_header;
            frame_header = Crypto::aes256EcbDecrypt(frame_header, _read_state.key);
            string frame_header_tag = frame_header.substr(8);
            frame_header = frame_header.substr(0, 8);
            BinaryBuffer seq_bin;
            seq_bin << ByteOrder::fromBigEndian(_read_state.sequence_number);
            _read_state.sequence_number++;
            frame_seed = seq_bin.str() + frame_header;
            string expected_tag = Crypto::hmacSha256(_read_state.mac_key, frame_seed).substr(0, 8);
            if (frame_header_tag != expected_tag) {
                throw FrameHeaderTagsAreNotEqualException();
            }
        } else {
            inputReader.readRaw(8, frame_header);
            if (frame_header.length() == 0) {
                return;
            }
        }
        BinaryBuffer frame_header_bin;
        frame_header_bin.stream.str(frame_header);
        UInt8 frame_version;
        frame_header_bin >> frame_version;
        if (frame_version != _version) {
            throw UnsupportedFrameVersionException(to_string(frame_version));
        }
        UInt8 frame_content_type;
        UInt32 frame_length;
        frame_header_bin >> frame_content_type >> frame_length;
        frame_length = ByteOrder::fromBigEndian(frame_length);
        string frame_data;
        if (frame_length > 0) {
            string ciphertext;
            inputReader.readRaw(frame_length, ciphertext);
            if (_read_state.initialized()) {
                string frame_mac;
                inputReader.readRaw(16, frame_mac);
                string mac_data = frame_seed + iv + ciphertext;
                string expected_mac = Crypto::hmacSha256(_read_state.mac_key, mac_data).substr(0, 16);                
                if(frame_mac != expected_mac){
                    throw FrameMacsAreNotEqualException();
                }
                frame_data = Crypto::aes256CbcPkcs7Decrypt(ciphertext, _read_state.key, iv);
            } else {
                frame_data = ciphertext;
            }
        }
        switch(frame_content_type) {
            case ContentType::APPLICATION_DATA:
                {
                    Var application_data = _pson_decoder.decode(frame_data);
                    application_handler(application_data);
                }
                break;
            case ContentType::HANDSHAKE:
                {
                    Var packet = _pson_decoder.decode(frame_data);
                    processHandshakePacket(packet);
                }
                break;
            case ContentType::CHANGE_CIPHER_SPEC:
                if (!_next_read_state.initialized()) {
                    throw InvalidNextReadStateException();
                }
                _read_state = _next_read_state;
                _next_read_state = RWState();
                break;
            case ContentType::ALERT:
                // errors form connection  
                throw PrivmxException(frame_data, PrivmxException::ALERT);
                break;
        }
    }
}

void ConnectionBase::restoreState(const string& ticket_id, const string& master_secret, const string& client_random) {
    _client_random = client_random;
    _server_random = ticket_id;
    _master_secret = master_secret;
    StatePair rwstates = getFreshRWStates(_master_secret, _client_random, _server_random);
    _next_read_state = rwstates.read_state;
    _next_write_state = rwstates.write_state;
    changeCipherSpec();
}

void ConnectionBase::changeCipherSpec() {
    if (!_next_write_state.initialized()) {
        throw WriteStateIsNotInitializedException();
    }
    send("", ContentType::CHANGE_CIPHER_SPEC);
    _write_state = _next_write_state;
    _next_write_state = RWState();
}

ConnectionBase::StatePair ConnectionBase::getFreshRWStates(const string& master_secret, const string& client_random, const string& server_random) {
    string key_block;
    key_block = Crypto::prf_tls12(master_secret, string("key expansion") + server_random + client_random, 4 * 32);
    string client_mac_key = key_block.substr(0, 32);
    string server_mac_key = key_block.substr(32, 32);
    string client_key = key_block.substr(64, 32);
    string server_key = key_block.substr(96, 32);
    StatePairCS pair_cs;
    pair_cs.client_state = RWState(client_key, client_mac_key);
    pair_cs.server_state = RWState(server_key, server_mac_key);
    return getFreshRWStatesFromParams(pair_cs);
}

void ConnectionBase::setPreMasterSecret(const string& pre_master_secret) {
    string client_random = _client_random;
    string server_random = _server_random;
    string master_secret = Crypto::prf_tls12(pre_master_secret, string("master secret") + client_random + server_random, 48);
    _master_secret = master_secret;
    StatePair rwstates = getFreshRWStates(master_secret, client_random, server_random);
    _next_read_state = rwstates.read_state;
    _next_write_state = rwstates.write_state;
}
