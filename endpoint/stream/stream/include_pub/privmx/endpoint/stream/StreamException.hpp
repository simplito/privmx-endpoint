/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_ENDPOINT_STREAM_EXT_EXCEPTION_HPP_
#define _PRIVMXLIB_ENDPOINT_STREAM_EXT_EXCEPTION_HPP_


#include "privmx/endpoint/core/Exception.hpp"

#define DECLARE_SCOPE_ENDPOINT_EXCEPTION(NAME, MSG, SCOPE, CODE, ...)                                            \
    class NAME : public privmx::endpoint::core::Exception {                                                      \
    public:                                                                                                      \
        NAME() : privmx::endpoint::core::Exception(MSG, #NAME, SCOPE, (CODE << 16)) {}                           \
        NAME(const std::string& msg, const std::string& name, unsigned int code)                                 \
            : privmx::endpoint::core::Exception(msg, name, SCOPE, (CODE << 16) | code, std::string()) {}         \
        NAME(const std::string& msg, const std::string& name, unsigned int code, const std::string& description) \
            : privmx::endpoint::core::Exception(msg, name, SCOPE, (CODE << 16) | code, description) {}           \
        void rethrow() const override;                                                                           \
    };                                                                                                           \
    inline void NAME::rethrow() const {                                                                          \
        throw *this;                                                                                             \
    };

#define DECLARE_ENDPOINT_EXCEPTION(BASE_SCOPED, NAME, MSG, CODE, ...)                                            \
    class NAME : public BASE_SCOPED {                                                                            \
    public:                                                                                                      \
        NAME() : BASE_SCOPED(MSG, #NAME, CODE) {}                                                                \
        NAME(const std::string& new_of_description) : BASE_SCOPED(MSG, #NAME, CODE, new_of_description) {}       \
        void rethrow() const override;                                                                           \
    };                                                                                                           \
    inline void NAME::rethrow() const {                                                                          \
        throw *this;                                                                                             \
    };

namespace privmx {
namespace endpoint {
namespace stream {

#define ENDPOINT_STREAM_EXCEPTION_CODE 0x00080000

DECLARE_SCOPE_ENDPOINT_EXCEPTION(EndpointStreamException, "Unknown endpoint stream exception", "StreamRoom", 0x0008)
DECLARE_ENDPOINT_EXCEPTION(EndpointStreamException, NotInitializedException, "Endpoint not initialized", 0x0001)
DECLARE_ENDPOINT_EXCEPTION(EndpointStreamException, NotImplementedException, "Not Implemented", 0x0002)
DECLARE_ENDPOINT_EXCEPTION(EndpointStreamException, InvalidEncryptedStreamRoomDataVersionException, "Invalid version of encrypted stream room data", 0x0003)
DECLARE_ENDPOINT_EXCEPTION(EndpointStreamException, StreamRoomPublicDataMismatchException, "Stream room public data mismatch", 0x0004)
DECLARE_ENDPOINT_EXCEPTION(EndpointStreamException, UnknowStreamRoomFormatException, "Unknown stream room format", 0x0005)
DECLARE_ENDPOINT_EXCEPTION(EndpointStreamException, InvalidStreamWebSocketRequestIdException, "Invalid stream web socket request id", 0x0006)
DECLARE_ENDPOINT_EXCEPTION(EndpointStreamException, StreamWebsocketDisconnectedException, "Stream websocket disconnected", 0x0007)
DECLARE_ENDPOINT_EXCEPTION(EndpointStreamException, NetConnectionException, "Network connection error", 0x0008);
DECLARE_ENDPOINT_EXCEPTION(EndpointStreamException, WebRTCException, "WebRTC error", 0x0009);
DECLARE_ENDPOINT_EXCEPTION(EndpointStreamException, IncorrectStreamIdException, "Incorrect stream id", 0x000A);
DECLARE_ENDPOINT_EXCEPTION(EndpointStreamException, StreamCacheException, "Incorrect Stream Cache state", 0x000B);


} // stream
} // endpoint
} // privmx

#undef DECLARE_SCOPE_ENDPOINT_EXCEPTION
#undef DECLARE_ENDPOINT_EXCEPTION

#endif // _PRIVMXLIB_ENDPOINT_STREAM_EXT_EXCEPTION_HPP_