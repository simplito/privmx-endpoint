/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_ENDPOINT_INBOX_DYNAMICTYPES_HPP_
#define _PRIVMXLIB_ENDPOINT_INBOX_DYNAMICTYPES_HPP_

#include <string>

#include <privmx/utils/JsonHelper.hpp>

namespace privmx {
namespace endpoint {
namespace inbox {
namespace dynamic {

#define INBOX_INTERNAL_META_V5_FIELDS(F)\
    F(secret, std::string)\
    F(resourceId, std::string)\
    F(randomId, std::string)
JSON_STRUCT(InboxInternalMetaV5_c_struct, INBOX_INTERNAL_META_V5_FIELDS);

} // dynamic
} // inbox
} // endpoint
} // privmx

#endif // _PRIVMXLIB_ENDPOINT_INBOX_DYNAMICTYPES_HPP_
