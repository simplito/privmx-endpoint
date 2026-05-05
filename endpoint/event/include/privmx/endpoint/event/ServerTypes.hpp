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

#include <privmx/utils/JsonHelper.hpp>
#include "privmx/endpoint/core/ServerTypes.hpp"

namespace privmx {
namespace endpoint {
namespace event {
namespace server {

#define USER_KEY_FIELDS(F)\
    F(id,  std::string)\
    F(key, std::string)
JSON_STRUCT(UserKey, USER_KEY_FIELDS);

#define CONTEXT_EMIT_CUSTOM_EVENT_MODEL_FIELDS(F)\
    F(contextId, std::string)\
    F(channel,   std::string)\
    F(data,      Poco::Dynamic::Var)\
    F(users,     std::vector<UserKey>)
JSON_STRUCT(ContextEmitCustomEventModel, CONTEXT_EMIT_CUSTOM_EVENT_MODEL_FIELDS);

#define CONTEXT_CUSTOM_EVENT_DATA_FIELDS(F)\
    F(id,        std::string)\
    F(eventData, Poco::Dynamic::Var)\
    F(key,       std::string)\
    F(author,    core::server::UserIdentity)
JSON_STRUCT(ContextCustomEventData, CONTEXT_CUSTOM_EVENT_DATA_FIELDS);

#define ENCRYPTED_INTERNAL_CONTEXT_EVENT_FIELDS(F)\
    F(encryptedData, std::string)\
    F(type,          std::string)
JSON_STRUCT(EncryptedInternalContextEvent, ENCRYPTED_INTERNAL_CONTEXT_EVENT_FIELDS);

#define ENCRYPTED_CONTEXT_EVENT_DATA_V5_FIELDS(F)\
    F(encryptedData, std::string)\
    F(type,          std::optional<std::string>)\
    F(dio,           std::string)
JSON_STRUCT_EXT(EncryptedContextEventDataV5, core::dynamic::VersionedData, ENCRYPTED_CONTEXT_EVENT_DATA_V5_FIELDS);

} // server
} // event
} // endpoint
} // privmx

#endif // _PRIVMXLIB_ENDPOINT_EVENT_SERVERTYPES_HPP_
