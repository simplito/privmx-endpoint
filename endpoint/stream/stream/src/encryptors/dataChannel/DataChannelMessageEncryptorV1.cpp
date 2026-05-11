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
#include <privmx/endpoint/core/ExceptionConverter.hpp>
#include <cstring>
#include <Poco/ByteOrder.h>
#include <privmx/crypto/Crypto.hpp>
#include <privmx/utils/Logger.hpp>

using namespace privmx::endpoint;
using namespace privmx::endpoint::stream;


DataChannelMessageEncryptorV1::DataChannelMessageEncryptorV1(const std::vector<Key>& keys): _keys(keys) {}

core::Buffer DataChannelMessageEncryptorV1::encryptMessage(const DataChannelMessage& plainMessage) {
    auto encKey = getEncryptionKey();
    if(encKey.keyId.size() >= 0xff) {
        throw InvalidEncryptionKeyIdLengthException();
    }
    auto iv = privmx::crypto::Crypto::randomBytes(GCM_NONCE_LENGTH_BYTES);
    auto serializedHeader = serializeHeader(Header{.version=WIRE_FORMAT_VERSION, .seq=static_cast<uint32_t>(plainMessage.seq), .iv=iv, .keyId=encKey.keyId});
    std::string ciphertext = privmx::crypto::Crypto::aes256GcmEncrypt(plainMessage.data.stdString(), encKey.key.stdString(), iv, serializedHeader);
    return core::Buffer::from(serializedHeader + ciphertext);
}

DecryptedDataChannelMessage DataChannelMessageEncryptorV1::decryptMessage(const std::string& remoteStreamId, const core::Buffer& encryptedData) {
    DecryptedDataChannelMessage result = {core::Buffer(), 0, 0};
    try {
        assertData(encryptedData);
    }  catch (const privmx::endpoint::core::Exception& e) {
        result.statusCode = e.getCode();
        return result;
    } catch (const privmx::utils::PrivmxException& e) {
        result.statusCode = core::ExceptionConverter::convert(e).getCode();
        return result;
    } catch (...) {
        result.statusCode = ENDPOINT_CORE_EXCEPTION_CODE;
        return result;
    }
    auto parsedEncryptedMessage = parseEncryptedMessage(encryptedData.stdString());
    assertSeq(remoteStreamId, parsedEncryptedMessage.header.seq);
    try {
        result.seq = parsedEncryptedMessage.header.seq;
        auto decKey = getDencryptionKey(parsedEncryptedMessage.header.keyId);
        result.data = core::Buffer::from(
            privmx::crypto::Crypto::aes256GcmDecrypt(
                parsedEncryptedMessage.ciphertext, 
                decKey.key.stdString(),
                parsedEncryptedMessage.header.iv,
                parsedEncryptedMessage.serializedHeader
            )
        );
        updateSeq(remoteStreamId, parsedEncryptedMessage.header.seq);
    }  catch (const privmx::endpoint::core::Exception& e) {
        result.statusCode = e.getCode();
    } catch (const privmx::utils::PrivmxException& e) {
        result.statusCode = core::ExceptionConverter::convert(e).getCode();
    } catch (...) {
        result.statusCode = ENDPOINT_CORE_EXCEPTION_CODE;
    }
    return result;
}

void DataChannelMessageEncryptorV1::registerRemoteStreamId(const std::string& remoteStreamId, int64_t initialSeq) {
    _remoteStreamSeqMap.set(remoteStreamId, initialSeq);
}

void DataChannelMessageEncryptorV1::updateKey(const std::vector<Key>& keys) {
    std::unique_lock<std::shared_mutex> lock(_keysMutex);
    _keys = keys;
}

std::string DataChannelMessageEncryptorV1::serializeHeader(Header header) {
    std::stringstream serializedHeader;
    uint32_t seq_be = Poco::ByteOrder::toBigEndian(header.seq);
    serializedHeader << (uint8_t)header.version;
    serializedHeader.write(reinterpret_cast<const char*>(&seq_be), sizeof(seq_be));
    serializedHeader << header.iv;
    serializedHeader << (uint8_t)header.keyId.size();
    serializedHeader << header.keyId;
    return serializedHeader.str();
}

DataChannelMessageEncryptorV1::Header DataChannelMessageEncryptorV1::deserializeHeader(std::string header) {
    Header deserializedHeader;
    uint8_t keyId_length = 0;
    deserializedHeader.iv.resize(GCM_NONCE_LENGTH_BYTES);
    size_t offset = 0;
    deserializedHeader.version = header[offset];
    offset += 1;
    uint32_t seq_be = 0;
    std::memcpy(&seq_be, header.data() + offset, sizeof(seq_be));
    deserializedHeader.seq = Poco::ByteOrder::fromBigEndian(seq_be);
    offset += 4;
    deserializedHeader.iv = header.substr(offset, GCM_NONCE_LENGTH_BYTES);
    
    offset += GCM_NONCE_LENGTH_BYTES;
    keyId_length = uint8_t(header[offset]);
    offset += 1;
    deserializedHeader.keyId = header.substr(offset, keyId_length);
    return deserializedHeader;
}

DataChannelMessageEncryptorV1::ParsedEncryptedMessage DataChannelMessageEncryptorV1::parseEncryptedMessage(const std::string& encryptedData) {
    ParsedEncryptedMessage parsedEncryptedMessage;
    parsedEncryptedMessage.serializedHeader = encryptedData.substr(0, FIXED_HEADER_LENGTH+AES_GCM_KEY_LENGTH_BYTES);
    parsedEncryptedMessage.ciphertext = encryptedData.substr(FIXED_HEADER_LENGTH+AES_GCM_KEY_LENGTH_BYTES);
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

void DataChannelMessageEncryptorV1::assertSeq(const std::string& remoteStreamId, uint32_t seq) {
    auto currentSeq = _remoteStreamSeqMap.get(remoteStreamId);
    if(!currentSeq.has_value()) {
        _remoteStreamSeqMap.set(remoteStreamId, -1);
        currentSeq = _remoteStreamSeqMap.get(remoteStreamId);
    }
    if(static_cast<int64_t>(seq) <= currentSeq.value()) {
        throw InvalidDataChannelSeqException(
            "remoteStreamId=" + remoteStreamId +
            ", currentSeq=" + std::to_string(currentSeq.value()) +
            ", receivedSeq=" + std::to_string(seq)
        );
    }
}

void DataChannelMessageEncryptorV1::updateSeq(const std::string& remoteStreamId, uint32_t seq) {
    _remoteStreamSeqMap.set(remoteStreamId, static_cast<int64_t>(seq));
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
    auto decKey = std::find_if(_keys.begin(), _keys.end(), 
        [keyId](const Key& key) {return key.keyId == keyId;}
    );
    if(decKey != _keys.end()) {
        return *decKey;
    }
    throw NoStreamDecryptionKeyException();
}
