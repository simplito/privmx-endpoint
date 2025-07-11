/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_ENDPOINT_KVDB_CONSTANTS_HPP_
#define _PRIVMXLIB_ENDPOINT_KVDB_CONSTANTS_HPP_

#include <cstdint>

namespace privmx {
namespace endpoint {
namespace kvdb {

namespace KvdbDataSchema {
   enum Version : int64_t {
      UNKNOWN = 0,
      VERSION_5 = 5
   };
}
constexpr static KvdbDataSchema::Version CURRENT_KVDB_DATA_SCHEMA_VERSION = KvdbDataSchema::Version::VERSION_5;

namespace KvdbEntryDataSchema {
   enum Version : int64_t {
      UNKNOWN = 0,
      VERSION_5 = 5
   };
}
constexpr static KvdbEntryDataSchema::Version CURRENT_KVDB_ENTRY_DATA_SCHEMA_VERSION = KvdbEntryDataSchema::Version::VERSION_5;

}  // namespace kvdb
}  // namespace endpoint
}  // namespace privmx

#endif  // #define _PRIVMXLIB_ENDPOINT_KVDB_CONSTANTS_HPP_

