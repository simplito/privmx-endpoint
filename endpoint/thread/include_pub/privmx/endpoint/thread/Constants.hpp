/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_ENDPOINT_THREAD_CONSTANTS_HPP_
#define _PRIVMXLIB_ENDPOINT_THREAD_CONSTANTS_HPP_

#include <cstdint>

namespace privmx {
namespace endpoint {
namespace thread {

enum ThreadDataStructVersion : int64_t {
   UNKNOWN = 0,
   VERSION_1 = 1,
   VERSION_4 = 4,
   VERSION_5 = 5
};
constexpr static ThreadDataStructVersion CURRENT_THREAD_DATA_STRUCT_VERSION = ThreadDataStructVersion::VERSION_5;

enum MessageDataStructVersion : int64_t {
   UNKNOWN = 0,
   VERSION_2 = 2,
   VERSION_3 = 3,
   VERSION_4 = 4,
   VERSION_5 = 5
};
constexpr static MessageDataStructVersion CURRENT_MESSAGE_DATA_STRUCT_VERSION = MessageDataStructVersion::VERSION_5;

}  // namespace thread
}  // namespace endpoint
}  // namespace privmx



#endif  // #define _PRIVMXLIB_ENDPOINT_THREAD_CONSTANTS_HPP_

