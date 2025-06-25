/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_ENDPOINT_STREAM_CONSTANTS_HPP_
#define _PRIVMXLIB_ENDPOINT_STREAM_CONSTANTS_HPP_

#include <cstdint>

namespace privmx {
namespace endpoint {
namespace stream {

namespace StreamRoomDataSchema {
   enum Version : int64_t {
      UNKNOWN = 0,
      VERSION_5 = 5
   };
}
constexpr static StreamRoomDataSchema::Version CURRENT_STREAM_ROOM_DATA_SCHEMA_VERSION = StreamRoomDataSchema::Version::VERSION_5;

}  // namespace stream
}  // namespace endpoint
}  // namespace privmx

#endif  // #define _PRIVMXLIB_ENDPOINT_STREAM_CONSTANTS_HPP_

