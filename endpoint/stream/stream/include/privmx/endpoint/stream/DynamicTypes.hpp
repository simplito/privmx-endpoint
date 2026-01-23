/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_ENDPOINT_STREAM_DYNAMICTYPES_HPP_
#define _PRIVMXLIB_ENDPOINT_STREAM_DYNAMICTYPES_HPP_

#include <string>

#include <privmx/endpoint/core/TypesMacros.hpp>

namespace privmx {
namespace endpoint {
namespace stream {
namespace dynamic {
//V4

ENDPOINT_CLIENT_TYPE(VersionedData)
    INT64_FIELD(version)
TYPE_END


ENDPOINT_CLIENT_TYPE(StreamEncKey)
    STRING_FIELD(keyId)
    STRING_FIELD(key)
    INT64_FIELD(TTL) // time in miliseconds
TYPE_END

ENDPOINT_CLIENT_TYPE_INHERIT(NewStreamEncKey, StreamEncKey)
    STRING_FIELD(oldKeyId)
    INT64_FIELD(oldKeyTTL) // time in miliseconds
TYPE_END

ENDPOINT_CLIENT_TYPE(StreamCustomEventData)
    STRING_FIELD(streamRoomId)
TYPE_END

ENDPOINT_CLIENT_TYPE_INHERIT(StreamKeyManagementEvent, StreamCustomEventData)
    STRING_FIELD(subtype)
TYPE_END

ENDPOINT_CLIENT_TYPE_INHERIT(RequestKeyEvent, StreamKeyManagementEvent)
TYPE_END

ENDPOINT_CLIENT_TYPE_INHERIT(RequestKeyRespondEvent, StreamKeyManagementEvent)
    OBJECT_FIELD(encKey, StreamEncKey)
TYPE_END

ENDPOINT_CLIENT_TYPE_INHERIT(UpdateKeyEvent, StreamKeyManagementEvent)
    OBJECT_FIELD(encKey, NewStreamEncKey)
TYPE_END

ENDPOINT_CLIENT_TYPE_INHERIT(UpdateKeyACKEvent, StreamKeyManagementEvent)
    STRING_FIELD(keyId)
TYPE_END

ENDPOINT_CLIENT_TYPE(RTCIceCandidate)
/** [MDN Reference](https://developer.mozilla.org/docs/Web/API/RTCIceCandidate/candidate) */
    STRING_FIELD(address) /** string | null */
    STRING_FIELD(candidate)
    STRING_FIELD(component) /** string enum: "rtcp" | "rtp" | null */
    STRING_FIELD(foundation) /** string | null */
    INT64_FIELD(port) /** number | null */
    INT64_FIELD(priority) /** number | null */
    STRING_FIELD(protocol) /** string enum: "tcp" | "udp" | null */
    STRING_FIELD(relatedAddress) /** string | null */
    INT64_FIELD(relatedPort) /** number | null */
    INT64_FIELD(sdpMLineIndex) /** number | null */
    STRING_FIELD(sdpMid) /** string | null */
    STRING_FIELD(tcpType) /** string enum: "active" | "passive" | "so" | null */
    STRING_FIELD(type) /** string enum: "host" | "prflx" | "relay" | "srflx" | null */
    STRING_FIELD(usernameFragment) /** string | null */
TYPE_END

} // dynamic
} // stream
} // endpoint
} // privmx

#endif // _PRIVMXLIB_ENDPOINT_STREAM_DYNAMICTYPES_HPP_
