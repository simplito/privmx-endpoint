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

ENDPOINT_CLIENT_TYPE(VersionedData)
    INT64_FIELD(version)
TYPE_END

ENDPOINT_CLIENT_TYPE_INHERIT(DataIntegrityObject, VersionedData)
    STRING_FIELD(creatorUserId)
    STRING_FIELD(creatorPublicKey)
    STRING_FIELD(contextId)
    STRING_FIELD(containerId)
    INT64_FIELD(timestamp)
    INT64_FIELD(nonce)
    MAP_FIELD(mapOfDataSha256, std::string)
    INT64_FIELD(objectFormat)
TYPE_END

ENDPOINT_CLIENT_TYPE(EncryptionKey)
    STRING_FIELD(id)
    STRING_FIELD(key)
    INT64_FIELD(containerControlNumber)
TYPE_END

ENDPOINT_CLIENT_TYPE_INHERIT(EncryptedKeyEntryDataV2, VersionedData)
    STRING_FIELD(encryptedKey) // encrypted EncryptionKey
    STRING_FIELD(dio) // signed and encoded in base64 DataIntegrityObject
TYPE_END

ENDPOINT_SERVER_TYPE(KeyEntry)
    STRING_FIELD(keyId)
    VAR_FIELD(data)
TYPE_END

ENDPOINT_SERVER_TYPE(KeyEntrySet)
    STRING_FIELD(user)
    STRING_FIELD(keyId)
    VAR_FIELD(data)
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

ENDPOINT_CLIENT_TYPE(ContextGetUsersModel)
    STRING_FIELD(contextId)
TYPE_END

ENDPOINT_SERVER_TYPE(ContextGetModel)
    STRING_FIELD(id)
TYPE_END

ENDPOINT_CLIENT_TYPE(ContextGetResult)
    OBJECT_FIELD(context, ContextInfo)
TYPE_END

ENDPOINT_CLIENT_TYPE(UserIdentity)
    STRING_FIELD(id)
    STRING_FIELD(pub)
TYPE_END

ENDPOINT_CLIENT_TYPE_INHERIT(UserIdentityWithStatus, UserIdentity)
    STRING_FIELD(status)
TYPE_END

ENDPOINT_CLIENT_TYPE(ContextGetUserResult)
    LIST_FIELD(users, server::UserIdentityWithStatus)
TYPE_END

} // server
} // core
} // endpoint
} // privmx

#endif // _PRIVMXLIB_ENDPOINT_CORE_SERVERTYPES_HPP_
