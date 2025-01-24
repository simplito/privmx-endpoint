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
TYPE_END

ENDPOINT_SERVER_TYPE(ContextInfo)
    STRING_FIELD(userId)
    STRING_FIELD(contextId)
TYPE_END

ENDPOINT_SERVER_TYPE(ContextListResult)
    LIST_FIELD(contexts, ContextInfo)
    INT64_FIELD(count)
TYPE_END

ENDPOINT_SERVER_TYPE(UserIdentity)
    STRING_FIELD(id)
    STRING_FIELD(pub)
TYPE_END

ENDPOINT_CLIENT_TYPE(UserKey)
    STRING_FIELD(id)  // userId
    STRING_FIELD(key) // encKey encrypted with user pubkey;
TYPE_END

ENDPOINT_CLIENT_TYPE(CustomEventModel)
    STRING_FIELD(contextId)
    STRING_FIELD(channel)
    STRING_FIELD(data) // encrypted
    LIST_FIELD(users, UserKey)
TYPE_END

ENDPOINT_CLIENT_TYPE(ContextCustomEventData)
    STRING_FIELD(id)
    VAR_FIELD(eventData)
    STRING_FIELD(key) // encrypted Key
    OBJECT_FIELD(author, UserIdentity)
TYPE_END


ENDPOINT_CLIENT_TYPE(CustomEventData) //Internal
    STRING_FIELD(type)
    VAR_FIELD(encryptedData)
TYPE_END

} // server
} // core
} // endpoint
} // privmx

#endif // _PRIVMXLIB_ENDPOINT_CORE_SERVERTYPES_HPP_
