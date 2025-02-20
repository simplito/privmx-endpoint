/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_ENDPOINT_EVENT_SERVERTYPES_HPP_
#define _PRIVMXLIB_ENDPOINT_EVENT_SERVERTYPES_HPP_

#include <string>

#include "privmx/endpoint/core/TypesMacros.hpp"
#include "privmx/endpoint/core/ServerTypes.hpp"

namespace privmx {
namespace endpoint {
namespace event {
namespace server {

ENDPOINT_SERVER_TYPE(UserIdentity)
    STRING_FIELD(id)
    STRING_FIELD(pub)
TYPE_END

ENDPOINT_CLIENT_TYPE(UserKey)
    STRING_FIELD(id)  // userId
    STRING_FIELD(key) // encKey encrypted with user pubkey;
TYPE_END

ENDPOINT_CLIENT_TYPE(ContextEmitCustomEventModel)
    STRING_FIELD(contextId)
    STRING_FIELD(channel)
    VAR_FIELD(data) // encrypted
    LIST_FIELD(users, UserKey)
TYPE_END

ENDPOINT_CLIENT_TYPE(ContextCustomEventData)
    STRING_FIELD(id)
    VAR_FIELD(eventData)
    STRING_FIELD(key) // encryption Key
    OBJECT_FIELD(author, UserIdentity)
TYPE_END

ENDPOINT_CLIENT_TYPE(EncryptedInternalContextEvent) // ForInternalEvents
    STRING_FIELD(type) // public data about event type
    STRING_FIELD(encryptedData)
TYPE_END

} // server
} // event
} // endpoint
} // privmx

#endif // _PRIVMXLIB_ENDPOINT_EVENT_SERVERTYPES_HPP_
