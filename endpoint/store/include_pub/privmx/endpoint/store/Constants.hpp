/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_ENDPOINT_STORE_CONSTANTS_HPP_
#define _PRIVMXLIB_ENDPOINT_STORE_CONSTANTS_HPP_


#include <cstdint>

namespace privmx {
namespace endpoint {
namespace store {

namespace StoreDataSchema {
   enum Version : int64_t {
      UNKNOWN = 0,
      VERSION_1 = 1,
      VERSION_4 = 4,
      VERSION_5 = 5
   };
}
constexpr static StoreDataSchema::Version CURRENT_STORE_DATA_SCHEMA_VERSION = StoreDataSchema::Version::VERSION_5;

namespace FileDataSchema {
   enum Version : int64_t {
      UNKNOWN = 0,
      VERSION_1 = 1,
      VERSION_4 = 4,
      VERSION_5 = 5
   };
}
constexpr static FileDataSchema::Version CURRENT_FILE_DATA_SCHEMA_VERSION = FileDataSchema::Version::VERSION_5;

}  // namespace store
}  // namespace endpoint
}  // namespace privmx



#endif  // #define _PRIVMXLIB_ENDPOINT_STORE_CONSTANTS_HPP_

