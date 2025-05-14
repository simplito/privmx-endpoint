/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_ENDPOINT_INBOX_CONSTANTS_HPP_
#define _PRIVMXLIB_ENDPOINT_INBOX_CONSTANTS_HPP_

#include <cstdint>

namespace privmx {
namespace endpoint {
namespace inbox {

namespace InboxDataSchema {
   enum Version : int64_t {
      UNKNOWN = 0,
      VERSION_4 = 4,
      VERSION_5 = 5
   };
}
constexpr static InboxDataSchema::Version CURRENT_INBOX_DATA_SCHEMA_VERSION = InboxDataSchema::Version::VERSION_5;

namespace EntryDataSchema {
   enum Version : int64_t {
      UNKNOWN = 0,
      VERSION_1 = 1
   };
}
constexpr static EntryDataSchema::Version CURRENT_ENTRY_DATA_SCHEMA_VERSION = EntryDataSchema::Version::VERSION_1;

}  // namespace inbox
}  // namespace endpoint
}  // namespace privmx



#endif  // #define _PRIVMXLIB_ENDPOINT_INBOX_CONSTANTS_HPP_

