/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_ENDPOINT_CORE_CORECONSTANTS_HPP_
#define _PRIVMXLIB_ENDPOINT_CORE_CORECONSTANTS_HPP_

#include <cstdint>

namespace privmx {
namespace endpoint {
namespace core {

namespace DataIntegrityObjectDataSchema {
   enum Version : int64_t {
      UNKNOWN = 0,
      VERSION_1 = 1
   };
}
constexpr static DataIntegrityObjectDataSchema::Version CURRENT_DATA_INTEGRITY_OBJECT_DATA_SCHEMA_VERSION = DataIntegrityObjectDataSchema::Version::VERSION_1;


namespace EncryptionKeyDataSchema {
   enum Version : int64_t {
      UNKNOWN = 0,
      VERSION_1 = 1,
      VERSION_2 = 2
   };
}
constexpr static EncryptionKeyDataSchema::Version CURRENT_ENCRYPTION_KEY_DATA_SCHEMA_VERSION = EncryptionKeyDataSchema::Version::VERSION_2;


}  // namespace core
}  // namespace endpoint
}  // namespace privmx



#endif  // _PRIVMXLIB_ENDPOINT_CORE_CORECONSTANTS_HPP_
