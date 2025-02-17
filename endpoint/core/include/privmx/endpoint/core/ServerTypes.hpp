/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_ENDPOINT_CORE_SERVERTYPES_HPP_
#define _PRIVMXLIB_ENDPOINT_CORE_SERVERTYPES_HPP_

#include <string>

#include "privmx/endpoint/core/TypesMacros.hpp"

namespace privmx {
namespace endpoint {
namespace core {
namespace server {

ENDPOINT_SERVER_TYPE(KeyEntry)
    STRING_FIELD(keyId)
    STRING_FIELD(data)
TYPE_END

ENDPOINT_SERVER_TYPE(KeyEntrySet)
    STRING_FIELD(user)
    STRING_FIELD(keyId)
    STRING_FIELD(data)
TYPE_END

ENDPOINT_SERVER_TYPE(ListModel)
    STRING_FIELD(sortOrder)
    INT64_FIELD(skip)
    INT64_FIELD(limit)
    STRING_FIELD(lastId)
    VAR_FIELD(query) // JSON
TYPE_END

ENDPOINT_SERVER_TYPE(ContextInfo)
    STRING_FIELD(userId)
    STRING_FIELD(contextId)
TYPE_END

ENDPOINT_SERVER_TYPE(ContextListResult)
    LIST_FIELD(contexts, ContextInfo)
    INT64_FIELD(count)
TYPE_END


} // server
} // core
} // endpoint
} // privmx

#endif // _PRIVMXLIB_ENDPOINT_CORE_SERVERTYPES_HPP_
