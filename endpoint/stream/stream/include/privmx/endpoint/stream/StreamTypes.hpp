/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_ENDPOINT_STREAM_STREAMTYPES_HPP_
#define _PRIVMXLIB_ENDPOINT_STREAM_STREAMTYPES_HPP_

#include <string>


namespace privmx {
namespace endpoint {
namespace stream {

enum RTCIceTransportPolicy { 
    all,
    relay 
};

struct EncKey {
    std::string key;
    std::string iv;
};

struct InitOptions {
    std::string signalingServer;
    std::string appServer;
    std::string mediaServer;
    std::optional<std::vector<std::string>> turnUrls;
    std::optional<RTCIceTransportPolicy> iceTransportPolicy;
    std::optional<EncKey> encKey;
};

struct VideoStream {
    std::string stream;
    bool isLocal;
    std::string id;  // Assuming the 'id' might be optional in your context, using int64_t
};

struct StreamRoomDataToEncrypt {
    core::Buffer publicMeta;
    core::Buffer privateMeta;
    std::optional<core::Buffer> internalMeta;
};

struct DecryptedStreamRoomData {
    core::Buffer publicMeta;
    core::Buffer privateMeta;
    std::optional<core::Buffer> internalMeta;
    std::string authorPubKey;
    int64_t statusCode;
};

} // stream
} // endpoint
} // privmx

#endif // _PRIVMXLIB_ENDPOINT_STREAM_STREAMTYPES_HPP_
