/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_ENDPOINT_THREAD_STREAM_ROOM_DATA_ENCRYPTOR_V4_HPP
#define _PRIVMXLIB_ENDPOINT_THREAD_STREAM_ROOM_DATA_ENCRYPTOR_V4_HPP

#include "privmx/endpoint/core/CoreTypes.hpp"
#include "privmx/endpoint/core/DataEncryptorV4.hpp"
#include "privmx/endpoint/core/ServerTypes.hpp"
#include "privmx/endpoint/core/Types.hpp"
#include "privmx/endpoint/stream/StreamTypes.hpp"
#include "privmx/endpoint/stream/ServerTypes.hpp"

namespace privmx {
namespace endpoint {
namespace stream {

class StreamRoomDataEncryptorV4 {
public:
    server::EncryptedStreamRoomDataV4 encrypt(const StreamRoomDataToEncrypt& streamRoomData,
                                        const crypto::PrivateKey& authorPrivateKey,
                                        const std::string& encryptionKey);
    DecryptedStreamRoomData decrypt(const server::EncryptedStreamRoomDataV4& encryptedStreamRoomData,
                                const std::string& encryptionKey);

private:
    void validateVersion(const server::EncryptedStreamRoomDataV4& encryptedStreamRoomData);

    core::DataEncryptorV4 _dataEncryptor;
};

}  // namespace stream
}  // namespace endpoint
}  // namespace privmx

#endif  // _PRIVMXLIB_ENDPOINT_THREAD_STREAM_ROOM_DATA_ENCRYPTOR_V4_HPP
