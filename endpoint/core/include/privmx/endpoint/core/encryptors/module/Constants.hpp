/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_ENDPOINT_CORE_ENCRYPTORS_MODULE_CONSTANTS_HPP_
#define _PRIVMXLIB_ENDPOINT_CORE_ENCRYPTORS_MODULE_CONSTANTS_HPP_

#include <cstdint>

namespace privmx {
namespace endpoint {
namespace core {

namespace ModuleDataSchema {
   enum Version : int64_t {
      UNKNOWN = 0,
      VERSION_4 = 4,
      VERSION_5 = 5
   };
}

}  // namespace core
}  // namespace endpoint
}  // namespace privmx



#endif  // _PRIVMXLIB_ENDPOINT_CORE_ENCRYPTORS_MODULE_CONSTANTS_HPP_
