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

#include <privmx/endpoint/core/Buffer.hpp>
#include <privmx/endpoint/core/CoreTypes.hpp>
#include <string>
#include <vector>
#include <optional>


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


} // stream
} // endpoint
} // privmx

#endif // _PRIVMXLIB_ENDPOINT_STREAM_STREAMTYPES_HPP_
