/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_ENDPOINT_EVENT_EVENTCONSTANTS_HPP_
#define _PRIVMXLIB_ENDPOINT_EVENT_EVENTCONSTANTS_HPP_

#include <cstdint>

namespace privmx {
namespace endpoint {
namespace event {


namespace EncryptionEventKeyDataSchema {
   enum Version : int64_t {
      UNKNOWN = 0,
      VERSION_1 = 1
   };
}
constexpr static EncryptionEventKeyDataSchema::Version CURRENT_ENCRYPTION_EVENT_KEY_DATA_SCHEMA_VERSION = EncryptionEventKeyDataSchema::Version::VERSION_1;


}  // namespace core
}  // namespace endpoint
}  // namespace privmx



#endif  // _PRIVMXLIB_ENDPOINT_EVENT_EVENTCONSTANTS_HPP_
