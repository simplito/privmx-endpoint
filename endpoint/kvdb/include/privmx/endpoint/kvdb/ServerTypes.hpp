/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_ENDPOINT_KVDB_SERVERTYPES_HPP_
#define _PRIVMXLIB_ENDPOINT_KVDB_SERVERTYPES_HPP_

#include <string>

#include "privmx/endpoint/core/TypesMacros.hpp"
#include "privmx/endpoint/core/ServerTypes.hpp"

namespace privmx {
namespace endpoint {
namespace kvdb {
namespace server {

// KVDB
ENDPOINT_SERVER_TYPE(KvdbDataEntry)
    STRING_FIELD(keyId)
    VAR_FIELD(data)
TYPE_END

ENDPOINT_SERVER_TYPE(KvdbInfo)
    STRING_FIELD(id)
    STRING_FIELD(resourceId)
    STRING_FIELD(contextId)
    INT64_FIELD(createDate)
    STRING_FIELD(creator)
    INT64_FIELD(lastModificationDate)
    STRING_FIELD(lastModifier)
    LIST_FIELD(data, KvdbDataEntry)
    STRING_FIELD(keyId)
    LIST_FIELD(users, std::string)
    LIST_FIELD(managers, std::string)
    LIST_FIELD(keys, core::server::KeyEntry)
    INT64_FIELD(version)
    STRING_FIELD(type)
    VAR_FIELD(policy)
    INT64_FIELD(entries)
    INT64_FIELD(lastEntryDate)
TYPE_END

ENDPOINT_SERVER_TYPE(KvdbCreateModel)
    STRING_FIELD(resourceId)
    STRING_FIELD(type)
    STRING_FIELD(contextId)
    LIST_FIELD(users, std::string)
    LIST_FIELD(managers, std::string)
    VAR_FIELD(data)
    STRING_FIELD(keyId)
    LIST_FIELD(keys, core::server::KeyEntrySet)
    VAR_FIELD(policy)
TYPE_END

ENDPOINT_SERVER_TYPE(KvdbCreateResult)
    STRING_FIELD(kvdbId)
TYPE_END

ENDPOINT_SERVER_TYPE(KvdbUpdateModel)
    STRING_FIELD(id)
    STRING_FIELD(resourceId)
    LIST_FIELD(users, std::string)
    LIST_FIELD(managers, std::string)
    VAR_FIELD(data)
    STRING_FIELD(keyId)
    LIST_FIELD(keys, core::server::KeyEntrySet)
    INT64_FIELD(version)
    BOOL_FIELD(force)
    VAR_FIELD(policy)
TYPE_END

ENDPOINT_SERVER_TYPE(KvdbDeleteModel)
    STRING_FIELD(kvdbId)
TYPE_END

ENDPOINT_SERVER_TYPE(KvdbDeleteManyModel)
    LIST_FIELD(kvdbsIds, std::string)
TYPE_END

ENDPOINT_SERVER_TYPE(KvdbDeleteStatus)
    STRING_FIELD(id)
    STRING_FIELD(status) // "OK" | "KVDB_DOES_NOT_EXIST" | "ACCESS_DENIED"
TYPE_END

ENDPOINT_SERVER_TYPE(KvdbDeleteManyResult)
    LIST_FIELD(kvdbsIds, KvdbDeleteStatus)
TYPE_END

ENDPOINT_SERVER_TYPE(KvdbGetModel)
    STRING_FIELD(kvdbId)
    STRING_FIELD(type)
TYPE_END

ENDPOINT_SERVER_TYPE(KvdbGetResult)
    OBJECT_FIELD(kvdb, KvdbInfo)
TYPE_END

ENDPOINT_SERVER_TYPE_INHERIT(KvdbListModel, core::server::ListModel)
    STRING_FIELD(contextId)
    STRING_FIELD(type)
TYPE_END

ENDPOINT_SERVER_TYPE(KvdbListResult)
    LIST_FIELD(kvdbs, KvdbInfo)
    INT64_FIELD(count)
TYPE_END

// KVDB ENTRY

ENDPOINT_SERVER_TYPE(KvdbEntryInfo)
    STRING_FIELD(kvdbEntryKey)
    VAR_FIELD(kvdbEntryValue)
    STRING_FIELD(kvdbId)
    INT64_FIELD(version)
    STRING_FIELD(contextId)
    INT64_FIELD(createDate)
    STRING_FIELD(author)
    STRING_FIELD(keyId)
    INT64_FIELD(lastModificationDate)
    STRING_FIELD(lastModifier)
TYPE_END

ENDPOINT_CLIENT_TYPE_INHERIT(EncryptedKvdbEntryDataV5, core::dynamic::VersionedData)
    STRING_FIELD(publicMeta)
    OBJECT_PTR_FIELD(publicMetaObject)
    STRING_FIELD(privateMeta)
    STRING_FIELD(data)
    STRING_FIELD(internalMeta)
    STRING_FIELD(authorPubKey)
    STRING_FIELD(dio)
TYPE_END

ENDPOINT_CLIENT_TYPE(KvdbEntryGetModel)
    STRING_FIELD(kvdbId)
    STRING_FIELD(kvdbEntryKey)
TYPE_END

ENDPOINT_CLIENT_TYPE(KvdbEntryGetResult)
    OBJECT_FIELD(kvdbEntry, KvdbEntryInfo)
TYPE_END

ENDPOINT_CLIENT_TYPE(KvdbEntrySetModel)
    STRING_FIELD(kvdbId)
    STRING_FIELD(kvdbEntryKey)
    VAR_FIELD(kvdbEntryValue)
    STRING_FIELD(keyId)
    INT64_FIELD(version)
TYPE_END

ENDPOINT_CLIENT_TYPE(KvdbEntryDeleteModel)
    STRING_FIELD(kvdbId)
    STRING_FIELD(kvdbEntryKey)
TYPE_END

ENDPOINT_CLIENT_TYPE_INHERIT(KvdbListKeysModel, core::server::ListModel)
    STRING_FIELD(kvdbId)
TYPE_END

ENDPOINT_CLIENT_TYPE(KvdbListKeysResult)
    OBJECT_FIELD(kvdb, KvdbInfo)
    LIST_FIELD(kvdbEntryKeys, std::string)
    INT64_FIELD(count)
TYPE_END

ENDPOINT_CLIENT_TYPE_INHERIT(KvdbListEntriesModel, core::server::ListModel)
    STRING_FIELD(kvdbId)
TYPE_END

ENDPOINT_CLIENT_TYPE(KvdbListEntriesResult)
    OBJECT_FIELD(kvdb, KvdbInfo)
    LIST_FIELD(kvdbEntries, KvdbEntryInfo)
    INT64_FIELD(count)
TYPE_END

ENDPOINT_CLIENT_TYPE(KvdbEntryDeleteManyModel)
    STRING_FIELD(kvdbId)
    LIST_FIELD(kvdbEntryKeys, std::string)
TYPE_END

ENDPOINT_CLIENT_TYPE(KvdbEntryDeleteStatus)
    STRING_FIELD(kvdbEntryKey)
    STRING_FIELD(status)
TYPE_END

ENDPOINT_CLIENT_TYPE(KvdbEntryDeleteManyResult)
    LIST_FIELD(results, KvdbEntryDeleteStatus)
TYPE_END

// EVENTS

ENDPOINT_CLIENT_TYPE(KvdbDeletedEventData)
    STRING_FIELD(kvdbId)
    STRING_FIELD(type)
TYPE_END

ENDPOINT_CLIENT_TYPE(KvdbDeletedEntryEventData)
    STRING_FIELD(kvdbEntryKey)
    STRING_FIELD(kvdbId)
TYPE_END

ENDPOINT_CLIENT_TYPE(KvdbStatsEventData)
    STRING_FIELD(kvdbId)
    STRING_FIELD(contextId)
    STRING_FIELD(type)
    INT64_FIELD(lastEntryDate)
    INT64_FIELD(entries)

TYPE_END

} // server
} // kvdb
} // endpoint
} // privmx

#endif // _PRIVMXLIB_ENDPOINT_KVDB_SERVERTYPES_HPP_
