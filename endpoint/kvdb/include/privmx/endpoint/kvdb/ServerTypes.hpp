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

#include "privmx/endpoint/core/ServerTypes.hpp"
#include <privmx/utils/JsonHelper.hpp>

namespace privmx {
namespace endpoint {
namespace kvdb {
namespace server {

// KVDB

#define KVDB_DATA_ENTRY_FIELDS(F)\
    F(keyId, std::string)\
    F(data,  Poco::Dynamic::Var)
JSON_STRUCT(KvdbDataEntry_c_struct, KVDB_DATA_ENTRY_FIELDS);

#define KVDB_INFO_FIELDS(F)\
    F(id,                   std::string)\
    F(resourceId,           std::string)\
    F(contextId,            std::string)\
    F(createDate,           int64_t)\
    F(creator,              std::string)\
    F(lastModificationDate, int64_t)\
    F(lastModifier,         std::string)\
    F(data,                 std::vector<KvdbDataEntry_c_struct>)\
    F(keyId,                std::string)\
    F(users,                std::vector<std::string>)\
    F(managers,             std::vector<std::string>)\
    F(keys,                 std::vector<core::server::KeyEntry_c_struct>)\
    F(version,              int64_t)\
    F(type,                 std::optional<std::string>)\
    F(policy,               Poco::Dynamic::Var)\
    F(entries,              int64_t)\
    F(lastEntryDate,        int64_t)
JSON_STRUCT(KvdbInfo_c_struct, KVDB_INFO_FIELDS);

#define KVDB_CREATE_MODEL_FIELDS(F)\
    F(resourceId, std::string)\
    F(type,       std::string)\
    F(contextId,  std::string)\
    F(users,      std::vector<std::string>)\
    F(managers,   std::vector<std::string>)\
    F(data,       Poco::Dynamic::Var)\
    F(keyId,      std::string)\
    F(keys,       std::vector<core::server::KeyEntrySet_c_struct>)\
    F(policy,     std::optional<Poco::Dynamic::Var>)
JSON_STRUCT(KvdbCreateModel_c_struct, KVDB_CREATE_MODEL_FIELDS);

#define KVDB_CREATE_RESULT_FIELDS(F)\
    F(kvdbId, std::string)
JSON_STRUCT(KvdbCreateResult_c_struct, KVDB_CREATE_RESULT_FIELDS);

#define KVDB_UPDATE_MODEL_FIELDS(F)\
    F(id,         std::string)\
    F(resourceId, std::string)\
    F(users,      std::vector<std::string>)\
    F(managers,   std::vector<std::string>)\
    F(data,       Poco::Dynamic::Var)\
    F(keyId,      std::string)\
    F(keys,       std::vector<core::server::KeyEntrySet_c_struct>)\
    F(version,    int64_t)\
    F(force,      bool)\
    F(policy,     std::optional<Poco::Dynamic::Var>)
JSON_STRUCT(KvdbUpdateModel_c_struct, KVDB_UPDATE_MODEL_FIELDS);

#define KVDB_DELETE_MODEL_FIELDS(F)\
    F(kvdbId, std::string)
JSON_STRUCT(KvdbDeleteModel_c_struct, KVDB_DELETE_MODEL_FIELDS);

#define KVDB_DELETE_MANY_MODEL_FIELDS(F)\
    F(kvdbsIds, std::vector<std::string>)
JSON_STRUCT(KvdbDeleteManyModel_c_struct, KVDB_DELETE_MANY_MODEL_FIELDS);

// status: "OK" | "KVDB_DOES_NOT_EXIST" | "ACCESS_DENIED"
#define KVDB_DELETE_STATUS_FIELDS(F)\
    F(id,     std::string)\
    F(status, std::string)
JSON_STRUCT(KvdbDeleteStatus_c_struct, KVDB_DELETE_STATUS_FIELDS);

#define KVDB_DELETE_MANY_RESULT_FIELDS(F)\
    F(kvdbsIds, std::vector<KvdbDeleteStatus_c_struct>)
JSON_STRUCT(KvdbDeleteManyResult_c_struct, KVDB_DELETE_MANY_RESULT_FIELDS);

#define KVDB_GET_MODEL_FIELDS(F)\
    F(kvdbId, std::string)\
    F(type,   std::optional<std::string>)
JSON_STRUCT(KvdbGetModel_c_struct, KVDB_GET_MODEL_FIELDS);

#define KVDB_GET_RESULT_FIELDS(F)\
    F(kvdb, KvdbInfo_c_struct)
JSON_STRUCT(KvdbGetResult_c_struct, KVDB_GET_RESULT_FIELDS);

#define KVDB_LIST_MODEL_FIELDS(F)\
    F(contextId, std::string)\
    F(type,      std::string)
JSON_STRUCT_EXT(KvdbListModel_c_struct, core::server::ListModel_c_struct, KVDB_LIST_MODEL_FIELDS);

#define KVDB_LIST_RESULT_FIELDS(F)\
    F(kvdbs, std::vector<KvdbInfo_c_struct>)\
    F(count, int64_t)
JSON_STRUCT(KvdbListResult_c_struct, KVDB_LIST_RESULT_FIELDS);

// KVDB ENTRY

#define KVDB_ENTRY_INFO_FIELDS(F)\
    F(kvdbEntryKey,         std::string)\
    F(kvdbEntryValue,       Poco::Dynamic::Var)\
    F(kvdbId,               std::string)\
    F(version,              int64_t)\
    F(contextId,            std::string)\
    F(createDate,           int64_t)\
    F(author,               std::string)\
    F(keyId,                std::string)\
    F(lastModificationDate, int64_t)\
    F(lastModifier,         std::string)
JSON_STRUCT(KvdbEntryInfo_c_struct, KVDB_ENTRY_INFO_FIELDS);

#define ENCRYPTED_KVDB_ENTRY_DATA_V5_FIELDS(F)\
    F(publicMeta,       std::string)\
    F(publicMetaObject, Poco::Dynamic::Var)\
    F(privateMeta,      std::string)\
    F(data,             std::string)\
    F(internalMeta,     std::optional<std::string>)\
    F(authorPubKey,     std::string)\
    F(dio,              std::string)
JSON_STRUCT_EXT(EncryptedKvdbEntryDataV5_c_struct, core::dynamic::VersionedData_c_struct, ENCRYPTED_KVDB_ENTRY_DATA_V5_FIELDS);

#define KVDB_ENTRY_GET_MODEL_FIELDS(F)\
    F(kvdbId,       std::string)\
    F(kvdbEntryKey, std::string)
JSON_STRUCT(KvdbEntryGetModel_c_struct, KVDB_ENTRY_GET_MODEL_FIELDS);

#define KVDB_ENTRY_GET_RESULT_FIELDS(F)\
    F(kvdbEntry, KvdbEntryInfo_c_struct)
JSON_STRUCT(KvdbEntryGetResult_c_struct, KVDB_ENTRY_GET_RESULT_FIELDS);

#define KVDB_ENTRY_SET_MODEL_FIELDS(F)\
    F(kvdbId,         std::string)\
    F(kvdbEntryKey,   std::string)\
    F(kvdbEntryValue, Poco::Dynamic::Var)\
    F(keyId,          std::string)\
    F(version,        int64_t)
JSON_STRUCT(KvdbEntrySetModel_c_struct, KVDB_ENTRY_SET_MODEL_FIELDS);

#define KVDB_ENTRY_DELETE_MODEL_FIELDS(F)\
    F(kvdbId,       std::string)\
    F(kvdbEntryKey, std::string)
JSON_STRUCT(KvdbEntryDeleteModel_c_struct, KVDB_ENTRY_DELETE_MODEL_FIELDS);

#define KVDB_LIST_KEYS_MODEL_FIELDS(F)\
    F(kvdbId, std::string)
JSON_STRUCT_EXT(KvdbListKeysModel_c_struct, core::server::ListModel_c_struct, KVDB_LIST_KEYS_MODEL_FIELDS);

#define KVDB_LIST_KEYS_RESULT_FIELDS(F)\
    F(kvdb,          KvdbInfo_c_struct)\
    F(kvdbEntryKeys, std::vector<std::string>)\
    F(count,         int64_t)
JSON_STRUCT(KvdbListKeysResult_c_struct, KVDB_LIST_KEYS_RESULT_FIELDS);

#define KVDB_LIST_ENTRIES_MODEL_FIELDS(F)\
    F(kvdbId, std::string)
JSON_STRUCT_EXT(KvdbListEntriesModel_c_struct, core::server::ListModel_c_struct, KVDB_LIST_ENTRIES_MODEL_FIELDS);

#define KVDB_LIST_ENTRIES_RESULT_FIELDS(F)\
    F(kvdb,        KvdbInfo_c_struct)\
    F(kvdbEntries, std::vector<KvdbEntryInfo_c_struct>)\
    F(count,       int64_t)
JSON_STRUCT(KvdbListEntriesResult_c_struct, KVDB_LIST_ENTRIES_RESULT_FIELDS);

#define KVDB_ENTRY_DELETE_MANY_MODEL_FIELDS(F)\
    F(kvdbId,        std::string)\
    F(kvdbEntryKeys, std::vector<std::string>)
JSON_STRUCT(KvdbEntryDeleteManyModel_c_struct, KVDB_ENTRY_DELETE_MANY_MODEL_FIELDS);

#define KVDB_ENTRY_DELETE_STATUS_FIELDS(F)\
    F(kvdbEntryKey, std::string)\
    F(status,       std::string)
JSON_STRUCT(KvdbEntryDeleteStatus_c_struct, KVDB_ENTRY_DELETE_STATUS_FIELDS);

#define KVDB_ENTRY_DELETE_MANY_RESULT_FIELDS(F)\
    F(results, std::vector<KvdbEntryDeleteStatus_c_struct>)
JSON_STRUCT(KvdbEntryDeleteManyResult_c_struct, KVDB_ENTRY_DELETE_MANY_RESULT_FIELDS);

// EVENTS

#define KVDB_DELETED_EVENT_DATA_FIELDS(F)\
    F(kvdbId, std::string)\
    F(type,   std::optional<std::string>)
JSON_STRUCT(KvdbDeletedEventData_c_struct, KVDB_DELETED_EVENT_DATA_FIELDS);

#define KVDB_DELETED_ENTRY_EVENT_DATA_FIELDS(F)\
    F(kvdbEntryKey,  std::string)\
    F(kvdbId,        std::string)\
    F(containerType, std::optional<std::string>)
JSON_STRUCT(KvdbDeletedEntryEventData_c_struct, KVDB_DELETED_ENTRY_EVENT_DATA_FIELDS);

#define KVDB_STATS_EVENT_DATA_FIELDS(F)\
    F(kvdbId,       std::string)\
    F(contextId,    std::string)\
    F(type,         std::optional<std::string>)\
    F(lastEntryDate, int64_t)\
    F(entries,      int64_t)
JSON_STRUCT(KvdbStatsEventData_c_struct, KVDB_STATS_EVENT_DATA_FIELDS);

#define KVDB_ENTRY_EVENT_DATA_FIELDS(F)\
    F(containerType, std::optional<std::string>)
JSON_STRUCT_EXT(KvdbEntryEventData_c_struct, KvdbEntryInfo_c_struct, KVDB_ENTRY_EVENT_DATA_FIELDS);

} // server
} // kvdb
} // endpoint
} // privmx

#endif // _PRIVMXLIB_ENDPOINT_KVDB_SERVERTYPES_HPP_
