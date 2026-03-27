/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/



#include "privmx/endpoint/stream/encryptors/dataChannel/DataChannelMessageEncryptorV1.hpp"
#include "privmx/endpoint/stream/StreamException.hpp"
#include <privmx/crypto/Crypto.hpp>
#include <privmx/utils/Logger.hpp>

using namespace privmx::endpoint;
using namespace privmx::endpoint::stream;


DataChannelMessageEncryptorV1::DataChannelMessageEncryptorV1(const std::vector<Key>& keys): _keys(keys) {}

core::Buffer DataChannelMessageEncryptorV1::encryptMessage(const core::Buffer& data, uint32_t seq) {
    auto encKey = getEncryptionKey();
    if(encKey.keyId.size() >= 0xff) {
        throw InvalidEncryptionKeyIdLengthException();
    }
    auto iv = privmx::crypto::Crypto::randomBytes(GCM_NONCE_LENGTH_BYTES);
    auto serializedHeader = serializeHeader(Header{.version=WIRE_FORMAT_VERSION, .seq=seq, .iv=iv, .keyId=encKey.keyId});
    std::string ciphertext = privmx::crypto::Crypto::aes256GcmEncrypt(data.stdString(), encKey.key.stdString(), iv, serializedHeader);
    return core::Buffer::from(serializedHeader + ciphertext);
}
std::pair<core::Buffer, uint32_t> DataChannelMessageEncryptorV1::decryptMessage(const core::Buffer& encryptedData) {
    assertData(encryptedData);
    auto parsedEncryptedMessage = parseEncryptedMessage(encryptedData.stdString());
    auto decKey = getDencryptionKey(parsedEncryptedMessage.header.keyId);
    std::string plaintext = privmx::crypto::Crypto::aes256GcmEncrypt(
        parsedEncryptedMessage.ciphertext, 
        decKey.key.stdString(),
        parsedEncryptedMessage.header.iv,
        parsedEncryptedMessage.serializedHeader
    );
    return std::make_pair(core::Buffer::from(plaintext), parsedEncryptedMessage.header.seq);
}
void DataChannelMessageEncryptorV1::updateKey(const std::vector<Key>& keys) {
    std::unique_lock<std::shared_mutex> lock(_keysMutex);
    _keys = keys;
}

std::string DataChannelMessageEncryptorV1::serializeHeader(Header header) {
    std::stringstream serializedHeader;
    serializedHeader << (uint8_t)header.version;
    serializedHeader << (uint8_t)(header.seq >> 24) 
        << (uint8_t)(header.seq >> 16) 
        << (uint8_t)(header.seq >> 8)
        << (uint8_t)(header.seq >> 0);
    serializedHeader << header.iv;
    serializedHeader << (uint8_t)KEY_ID_LENGTH_BYTES;
    serializedHeader << header.keyId;
    return serializedHeader.str();
}
DataChannelMessageEncryptorV1::Header DataChannelMessageEncryptorV1::deserializeHeader(std::string header) {
    Header deserializedHeader;
    deserializedHeader.iv.resize(GCM_NONCE_LENGTH_BYTES);
    deserializedHeader.keyId.resize(KEY_ID_LENGTH_BYTES);
    
    std::stringstream serializedHeader(header);
    serializedHeader >> deserializedHeader.version >> deserializedHeader.iv;
    serializedHeader.read( &deserializedHeader.iv[0], GCM_NONCE_LENGTH_BYTES);
    serializedHeader.read( &deserializedHeader.keyId[0], KEY_ID_LENGTH_BYTES);
    return deserializedHeader;
}

DataChannelMessageEncryptorV1::ParsedEncryptedMessage DataChannelMessageEncryptorV1::parseEncryptedMessage(const std::string& encryptedData) {
    ParsedEncryptedMessage parsedEncryptedMessage;
    parsedEncryptedMessage.serializedHeader = encryptedData.substr(0, FIXED_HEADER_LENGTH);
    parsedEncryptedMessage.ciphertext = encryptedData.substr(FIXED_HEADER_LENGTH);
    parsedEncryptedMessage.header = deserializeHeader(parsedEncryptedMessage.serializedHeader);
    return parsedEncryptedMessage;
}

void DataChannelMessageEncryptorV1::assertData(const core::Buffer& encryptedKvdbData) {
    if(encryptedKvdbData.size() < FIXED_HEADER_LENGTH) {
        throw InvalidMessageHeaderLengthException();
    }
    if((uint8_t)encryptedKvdbData.stdString()[0] != WIRE_FORMAT_VERSION) {
        throw UnsupportedMessageFormatVersionException();
    }
}

Key DataChannelMessageEncryptorV1::getEncryptionKey() {
    std::shared_lock<std::shared_mutex> lock(_keysMutex);
    auto encKey = std::find_if(_keys.begin(), _keys.end(), 
        [](const Key& key) {return key.type == KeyType::LOCAL;}
    );
    if(encKey != _keys.end()) {
        return *encKey;
    }
    throw NoStreamEncryptionKeyException();
}

Key DataChannelMessageEncryptorV1::getDencryptionKey(const std::string& keyId) {
    std::shared_lock<std::shared_mutex> lock(_keysMutex);
    LOG_FATAL(keyId, " | ", _keys.size());
    for(auto key: _keys) {
        LOG_FATAL(key.keyId)
    }
    auto decKey = std::find_if(_keys.begin(), _keys.end(), 
        [keyId](const Key& key) {return key.keyId == keyId;}
    );
    if(decKey != _keys.end()) {
        return *decKey;
    }
    throw NoStreamDecryptionKeyException();
}