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

#include <optional>
#include <string>

#include <privmx/utils/JsonHelper.hpp>

namespace privmx {
namespace endpoint {
namespace stream {
namespace dynamic {

#define VERSIONED_DATA_FIELDS(F)\
    F(version, int64_t)
JSON_STRUCT(VersionedData_c_struct, VERSIONED_DATA_FIELDS);

#define STREAM_ENC_KEY_FIELDS(F)\
    F(keyId, std::string)\
    F(key,   std::string)\
    F(TTL,   int64_t)
JSON_STRUCT(StreamEncKey_c_struct, STREAM_ENC_KEY_FIELDS);

#define NEW_STREAM_ENC_KEY_FIELDS(F)\
    F(oldKeyId,  std::string)\
    F(oldKeyTTL, int64_t)
JSON_STRUCT_EXT(NewStreamEncKey_c_struct, StreamEncKey_c_struct, NEW_STREAM_ENC_KEY_FIELDS);

#define STREAM_CUSTOM_EVENT_DATA_FIELDS(F)\
    F(streamRoomId, std::string)
JSON_STRUCT(StreamCustomEventData_c_struct, STREAM_CUSTOM_EVENT_DATA_FIELDS);

#define STREAM_KEY_MANAGEMENT_EVENT_FIELDS(F)\
    F(subtype, std::string)
JSON_STRUCT_EXT(StreamKeyManagementEvent_c_struct, StreamCustomEventData_c_struct, STREAM_KEY_MANAGEMENT_EVENT_FIELDS);

#define REQUEST_KEY_EVENT_FIELDS(F)
JSON_STRUCT_EXT(RequestKeyEvent_c_struct, StreamKeyManagementEvent_c_struct, REQUEST_KEY_EVENT_FIELDS);

#define REQUEST_KEY_RESPOND_EVENT_FIELDS(F)\
    F(encKey, StreamEncKey_c_struct)
JSON_STRUCT_EXT(RequestKeyRespondEvent_c_struct, StreamKeyManagementEvent_c_struct, REQUEST_KEY_RESPOND_EVENT_FIELDS);

#define UPDATE_KEY_EVENT_FIELDS(F)\
    F(encKey, NewStreamEncKey_c_struct)
JSON_STRUCT_EXT(UpdateKeyEvent_c_struct, StreamKeyManagementEvent_c_struct, UPDATE_KEY_EVENT_FIELDS);

#define UPDATE_KEY_ACK_EVENT_FIELDS(F)\
    F(keyId, std::string)
JSON_STRUCT_EXT(UpdateKeyACKEvent_c_struct, StreamKeyManagementEvent_c_struct, UPDATE_KEY_ACK_EVENT_FIELDS);

// [MDN Reference](https://developer.mozilla.org/docs/Web/API/RTCIceCandidate)
#define RTC_ICE_CANDIDATE_FIELDS(F)\
    F(candidate,        std::string)\
    F(address,          std::optional<std::string>)\
    F(component,        std::optional<std::string>)\
    F(foundation,       std::optional<std::string>)\
    F(port,             std::optional<int64_t>)\
    F(priority,         std::optional<int64_t>)\
    F(protocol,         std::optional<std::string>)\
    F(relatedAddress,   std::optional<std::string>)\
    F(relatedPort,      std::optional<int64_t>)\
    F(sdpMLineIndex,    std::optional<int64_t>)\
    F(sdpMid,           std::optional<std::string>)\
    F(tcpType,          std::optional<std::string>)\
    F(type,             std::optional<std::string>)\
    F(usernameFragment, std::optional<std::string>)
JSON_STRUCT(RTCIceCandidate_c_struct, RTC_ICE_CANDIDATE_FIELDS);

} // dynamic
} // stream
} // endpoint
} // privmx

#endif // _PRIVMXLIB_ENDPOINT_STREAM_DYNAMICTYPES_HPP_
