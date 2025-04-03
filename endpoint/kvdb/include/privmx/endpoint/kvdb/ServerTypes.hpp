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
TYPE_END

ENDPOINT_CLIENT_TYPE(EncryptedKvdbDataV4) // <- TODO update to V5 before publish
    INT64_FIELD(version)
    STRING_FIELD(publicMeta)
    OBJECT_PTR_FIELD(publicMetaObject)
    STRING_FIELD(privateMeta)
    STRING_FIELD(internalMeta)
    STRING_FIELD(authorPubKey)
TYPE_END

ENDPOINT_SERVER_TYPE(KvdbCreateModel)
    STRING_FIELD(kvdbId)
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
    STRING_FIELD(kvdbId)
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

// KVDB ITEM

ENDPOINT_SERVER_TYPE(KvdbItemInfo)
    STRING_FIELD(kvdbItemKey)
    VAR_FIELD(kvdbItemValue)
    INT64_FIELD(version)
    STRING_FIELD(contextId)
    INT64_FIELD(createDate)
    STRING_FIELD(author)
    STRING_FIELD(keyId)
TYPE_END

ENDPOINT_CLIENT_TYPE(EncryptedKvdbItemDataV4) // <- TODO update to V5 before publish
    INT64_FIELD(version)
    STRING_FIELD(data)
    STRING_FIELD(authorPubKey)
TYPE_END

ENDPOINT_CLIENT_TYPE(KvdbItemGetModel)
    STRING_FIELD(kvdbId)
    STRING_FIELD(kvdbItemKey)
TYPE_END

ENDPOINT_CLIENT_TYPE(KvdbItemGetResult)
    OBJECT_FIELD(kvdbItem, KvdbItemInfo)
TYPE_END

ENDPOINT_CLIENT_TYPE(KvdbItemSetModel)
    STRING_FIELD(kvdbId)
    STRING_FIELD(kvdbItemKey)
    VAR_FIELD(kvdbItemValue)
    STRING_FIELD(keyId)
    INT64_FIELD(version)
TYPE_END

ENDPOINT_CLIENT_TYPE(KvdbItemDeleteModel)
    STRING_FIELD(kvdbId)
    STRING_FIELD(kvdbItemKey)
TYPE_END

ENDPOINT_CLIENT_TYPE(KvdbListKeysModel)
    STRING_FIELD(kvdbId)
    STRING_FIELD(lastKey)
    STRING_FIELD(prefix)
    STRING_FIELD(sortBy)

    INT64_FIELD(skip)
    INT64_FIELD(limit)
    STRING_FIELD(sortOrder)
    STRING_FIELD(query)
TYPE_END

ENDPOINT_CLIENT_TYPE(KvdbListKeysResult)
    OBJECT_FIELD(kvdb, KvdbInfo)
    LIST_FIELD(kvdbItemKeys, std::string)
    INT64_FIELD(number)
TYPE_END

ENDPOINT_CLIENT_TYPE(KvdbItemDeleteManyModel)
    OBJECT_FIELD(kvdb, KvdbInfo)
    LIST_FIELD(kvdbItemKeys, std::string)
TYPE_END

ENDPOINT_CLIENT_TYPE(KvdbItemDeleteStatus)
    STRING_FIELD(kvdbItemKey)
    STRING_FIELD(status)
TYPE_END

ENDPOINT_CLIENT_TYPE(KvdbItemDeleteManyResult)
    LIST_FIELD(results, KvdbItemDeleteStatus)
TYPE_END

// EVENTS

ENDPOINT_CLIENT_TYPE(KvdbDeletedEventData)
    STRING_FIELD(kvdbId)
    STRING_FIELD(type)
TYPE_END

ENDPOINT_CLIENT_TYPE(KvdbDeletedItemEventData)
    STRING_FIELD(kvdbItemKey)
    STRING_FIELD(kvdbId)
TYPE_END

ENDPOINT_CLIENT_TYPE(KvdbStatsEventData)
    STRING_FIELD(kvdbId)
    STRING_FIELD(contextId)
    STRING_FIELD(type)
    INT64_FIELD(lastItemDate)
    INT64_FIELD(items)

TYPE_END

} // server
} // kvdb
} // endpoint
} // privmx

#endif // _PRIVMXLIB_ENDPOINT_KVDB_SERVERTYPES_HPP_
