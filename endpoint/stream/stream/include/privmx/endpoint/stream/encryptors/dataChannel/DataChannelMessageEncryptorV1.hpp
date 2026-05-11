/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_ENDPOINT_WEBRTC_DATACHANNELMESSAGEENCRYPTORV1_HPP_
#define _PRIVMXLIB_ENDPOINT_WEBRTC_DATACHANNELMESSAGEENCRYPTORV1_HPP_

#include <mutex>
#include <shared_mutex>
#include <privmx/endpoint/core/CoreTypes.hpp>
#include <privmx/utils/ThreadSaveMap.hpp>
#include "privmx/endpoint/stream/WebRTCInterface.hpp"

namespace privmx {
namespace endpoint {
namespace stream {

class DataChannelMessageEncryptorV1 {
public:
    DataChannelMessageEncryptorV1(const std::vector<Key>& keys);
    DataChannelMessageEncryptorV1() = default;
    core::Buffer encryptMessage(const DataChannelMessage& plainMessage);
    DecryptedDataChannelMessage decryptMessage(const std::string& remoteStreamId, const core::Buffer& encryptedMessage);
    void registerRemoteStreamId(const std::string& remoteStreamId, int64_t initialSeq = -1);
    void updateKey(const std::vector<Key>& keys);
private:
    struct Header {
        uint8_t version;
        uint32_t seq;
        std::string iv;
        std::string keyId;
    };

    struct ParsedEncryptedMessage {
        Header header;
        std::string serializedHeader;
        std::string ciphertext;
    };
    std::string serializeHeader(Header header);
    Header deserializeHeader(std::string header);
    ParsedEncryptedMessage parseEncryptedMessage(const std::string& encryptedData);
    void assertData(const core::Buffer& encryptedKvdbData);
    void assertSeq(const std::string& remoteStreamId, uint32_t seq);
    void updateSeq(const std::string& remoteStreamId, uint32_t seq);
    Key getEncryptionKey();
    Key getDencryptionKey(const std::string& keyId);

    static constexpr uint64_t AES_GCM_KEY_LENGTH_BYTES = 32;
    static constexpr uint64_t GCM_NONCE_LENGTH_BYTES = 12;
    static constexpr uint64_t VERSION_LENGTH_BYTES = 1;         //uint8_t
    static constexpr uint64_t KEY_ID_LENGTH_BYTES = 1;          //uint8_t
    static constexpr uint64_t SEQUENCE_NUMBER_LENGTH_BYTES = 4; //uint32_t
    static constexpr uint8_t WIRE_FORMAT_VERSION = 1;
    static constexpr uint64_t FIXED_HEADER_LENGTH = VERSION_LENGTH_BYTES + KEY_ID_LENGTH_BYTES + SEQUENCE_NUMBER_LENGTH_BYTES + GCM_NONCE_LENGTH_BYTES; 
    std::shared_mutex _keysMutex;
    std::vector<Key> _keys;
    privmx::utils::ThreadSaveMap<std::string, int64_t> _remoteStreamSeqMap;

};

}  // namespace core
}  // namespace endpoint
}  // namespace privmx

#endif  //_PRIVMXLIB_ENDPOINT_WEBRTC_DATACHANNELMESSAGEENCRYPTORV1_HPP_
