/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_ENDPOINT_EVENT_CONSTANTS_HPP_
#define _PRIVMXLIB_ENDPOINT_EVENT_CONSTANTS_HPP_

#include <cstdint>

namespace privmx {
namespace endpoint {
namespace event {

namespace EventDataSchema {
   enum Version : int64_t {
      UNKNOWN = 0,
      VERSION_1 = 1,
      VERSION_5 = 5
   };
}
constexpr static EventDataSchema::Version CURRENT_EVENT_DATA_SCHEMA_VERSION = EventDataSchema::Version::VERSION_5;

}  // namespace kvdb
}  // namespace endpoint
}  // namespace privmx

#endif  // #define _PRIVMXLIB_ENDPOINT_EVENT_CONSTANTS_HPP_

