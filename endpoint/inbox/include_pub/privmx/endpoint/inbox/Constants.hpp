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

enum InboxDataSchemaVersion : int64_t {
   UNKNOWN = 0,
   VERSION_4 = 4,
   VERSION_5 = 5
};
constexpr static InboxDataSchemaVersion CURRENT_INBOX_DATA_SCHEMA_VERSION = InboxDataSchemaVersion::VERSION_5;

enum EntryDataSchemaVersion : int64_t {
   UNKNOWN = 0,
   VERSION_1 = 1
};
constexpr static EntryDataSchemaVersion CURRENT_ENTRY_DATA_SCHEMA_VERSION = EntryDataSchemaVersion::VERSION_1;

}  // namespace inbox
}  // namespace endpoint
}  // namespace privmx



#endif  // #define _PRIVMXLIB_ENDPOINT_INBOX_CONSTANTS_HPP_

