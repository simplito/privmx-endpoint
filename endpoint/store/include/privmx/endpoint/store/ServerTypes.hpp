/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_ENDPOINT_STORE_SERVERTYPES_HPP_
#define _PRIVMXLIB_ENDPOINT_STORE_SERVERTYPES_HPP_

#include <privmx/utils/JsonHelper.hpp>
#include <privmx/endpoint/core/ServerTypes.hpp>

namespace privmx {
namespace endpoint {
namespace store {
namespace server {

#define BUFFER_READ_RANGE_FIELDS(F)\
    F(type, std::string)
JSON_STRUCT(BufferReadRange, BUFFER_READ_RANGE_FIELDS);

#define BUFFER_READ_RANGE_SLICE_FIELDS(F)\
    F(from, int64_t)\
    F(to,   int64_t)
JSON_STRUCT_EXT(BufferReadRangeSlice, BufferReadRange, BUFFER_READ_RANGE_SLICE_FIELDS);


#define STORE_DATA_ENTRY_FIELDS(F)\
    F(keyId, std::string)\
    F(data,  Poco::Dynamic::Var)
JSON_STRUCT(StoreDataEntry, STORE_DATA_ENTRY_FIELDS);

#define STORE_FIELDS(F)\
    F(id,                   std::string)\
    F(resourceId,           std::optional<std::string>)\
    F(contextId,            std::string)\
    F(createDate,           int64_t)\
    F(creator,              std::string)\
    F(lastModificationDate, int64_t)\
    F(lastModifier,         std::string)\
    F(data,                 std::vector<StoreDataEntry>)\
    F(keyId,                std::string)\
    F(users,                std::vector<std::string>)\
    F(managers,             std::vector<std::string>)\
    F(keys,                 std::vector<core::server::KeyEntry>)\
    F(version,              int64_t)\
    F(lastFileDate,         int64_t)\
    F(files,                int64_t)\
    F(type,                 std::optional<std::string>)\
    F(policy,               Poco::Dynamic::Var)
JSON_STRUCT(Store, STORE_FIELDS);

#define STORE_CREATE_MODEL_FIELDS(F)\
    F(resourceId, std::string)\
    F(contextId,  std::string)\
    F(users,      std::vector<std::string>)\
    F(managers,   std::vector<std::string>)\
    F(data,       Poco::Dynamic::Var)\
    F(keyId,      std::string)\
    F(keys,       std::vector<core::server::KeyEntrySet>)\
    F(type,       std::string)\
    F(policy,     std::optional<Poco::Dynamic::Var>)
JSON_STRUCT(StoreCreateModel, STORE_CREATE_MODEL_FIELDS);

#define STORE_UPDATE_MODEL_FIELDS(F)\
    F(id,         std::string)\
    F(resourceId, std::string)\
    F(users,      std::vector<std::string>)\
    F(managers,   std::vector<std::string>)\
    F(data,       Poco::Dynamic::Var)\
    F(keyId,      std::string)\
    F(keys,       std::vector<core::server::KeyEntrySet>)\
    F(version,    int64_t)\
    F(force,      bool)\
    F(policy,     std::optional<Poco::Dynamic::Var>)
JSON_STRUCT(StoreUpdateModel, STORE_UPDATE_MODEL_FIELDS);

#define FILE_THUMB_FIELDS(F)\
    F(size, int64_t)
JSON_STRUCT(FileThumb, FILE_THUMB_FIELDS);

#define FILE_FIELDS_SERVER(F)\
    F(id,                   std::string)\
    F(resourceId,           std::string)\
    F(version,              int64_t)\
    F(contextId,            std::string)\
    F(storeId,              std::string)\
    F(created,              int64_t)\
    F(creator,              std::string)\
    F(lastModificationDate, int64_t)\
    F(lastModifier,         std::string)\
    F(meta,                 Poco::Dynamic::Var)\
    F(size,                 int64_t)\
    F(keyId,                std::string)\
    F(thumb,                std::optional<FileThumb>)
JSON_STRUCT(File, FILE_FIELDS_SERVER);

#define FILE_ERROR_FIELDS(F)\
    F(code,    int64_t)\
    F(message, std::string)
JSON_STRUCT(FileError, FILE_ERROR_FIELDS);

#define FILE_LIST_ELEMENT_FIELDS(F)\
    F(error, std::optional<FileError>)
JSON_STRUCT_EXT(FileListElement, File, FILE_LIST_ELEMENT_FIELDS);

#define STORE_FILE_GET_MODEL_FIELDS(F)\
    F(fileId, std::string)
JSON_STRUCT(StoreFileGetModel, STORE_FILE_GET_MODEL_FIELDS);

#define STORE_FILE_GET_MANY_MODEL_FIELDS(F)\
    F(storeId,      std::string)\
    F(fileIds,      std::vector<std::string>)\
    F(failOnError,  bool)
JSON_STRUCT(StoreFileGetManyModel, STORE_FILE_GET_MANY_MODEL_FIELDS);

#define STORE_FILE_GET_RESULT_FIELDS(F)\
    F(store, Store)\
    F(file,  File)
JSON_STRUCT(StoreFileGetResult, STORE_FILE_GET_RESULT_FIELDS);

#define STORE_FILE_GET_MANY_RESULT_FIELDS(F)\
    F(store, Store)\
    F(files, std::vector<FileListElement>)
JSON_STRUCT(StoreFileGetManyResult, STORE_FILE_GET_MANY_RESULT_FIELDS);

#define STORE_FILE_LIST_MODEL_FIELDS(F)\
    F(storeId, std::string)
JSON_STRUCT_EXT(StoreFileListModel, core::server::ListModel, STORE_FILE_LIST_MODEL_FIELDS);

#define STORE_FILE_LIST_RESULT_FIELDS(F)\
    F(store, Store)\
    F(files, std::vector<File>)\
    F(count, int64_t)
JSON_STRUCT(StoreFileListResult, STORE_FILE_LIST_RESULT_FIELDS);

#define ENCRYPTED_FILE_META_V4_FIELDS(F)\
    F(publicMeta,       std::string)\
    F(publicMetaObject, Poco::Dynamic::Var)\
    F(privateMeta,      std::string)\
    F(fileSize,         std::string)\
    F(internalMeta,     std::optional<std::string>)\
    F(authorPubKey,     std::string)
JSON_STRUCT_EXT(EncryptedFileMetaV4, core::dynamic::VersionedData, ENCRYPTED_FILE_META_V4_FIELDS);

#define ENCRYPTED_FILE_META_V5_FIELDS(F)\
    F(publicMeta,       std::string)\
    F(publicMetaObject, Poco::Dynamic::Var)\
    F(privateMeta,      std::string)\
    F(internalMeta,     std::optional<std::string>)\
    F(authorPubKey,     std::string)\
    F(dio,              std::string)
JSON_STRUCT_EXT(EncryptedFileMetaV5, core::dynamic::VersionedData, ENCRYPTED_FILE_META_V5_FIELDS);

#define STORE_CREATE_RESULT_FIELDS(F)\
    F(storeId, std::string)
JSON_STRUCT(StoreCreateResult, STORE_CREATE_RESULT_FIELDS);

#define STORE_DELETE_MODEL_FIELDS(F)\
    F(storeId, std::string)
JSON_STRUCT(StoreDeleteModel, STORE_DELETE_MODEL_FIELDS);

#define STORE_GET_MODEL_FIELDS(F)\
    F(storeId, std::string)\
    F(type,    std::optional<std::string>)
JSON_STRUCT(StoreGetModel, STORE_GET_MODEL_FIELDS);

#define STORE_GET_RESULT_FIELDS(F)\
    F(store, Store)
JSON_STRUCT(StoreGetResult, STORE_GET_RESULT_FIELDS);

#define STORE_LIST_MODEL_FIELDS(F)\
    F(contextId, std::string)\
    F(type,      std::optional<std::string>)
JSON_STRUCT_EXT(StoreListModel, core::server::ListModel, STORE_LIST_MODEL_FIELDS);

#define STORE_LIST_RESULT_FIELDS(F)\
    F(stores, std::vector<Store>)\
    F(count,  int64_t)
JSON_STRUCT(StoreListResult, STORE_LIST_RESULT_FIELDS);

#define STORE_FILE_CREATE_MODEL_FIELDS(F)\
    F(resourceId, std::string)\
    F(storeId,    std::string)\
    F(requestId,  std::string)\
    F(fileIndex,  int64_t)\
    F(meta,       Poco::Dynamic::Var)\
    F(keyId,      std::string)\
    F(thumbIndex, std::optional<int64_t>)
JSON_STRUCT(StoreFileCreateModel, STORE_FILE_CREATE_MODEL_FIELDS);

#define STORE_FILE_CREATE_RESULT_FIELDS(F)\
    F(fileId, std::string)
JSON_STRUCT(StoreFileCreateResult, STORE_FILE_CREATE_RESULT_FIELDS);

#define STORE_FILE_READ_MODEL_FIELDS(F)\
    F(fileId,  std::string)\
    F(range,   Poco::Dynamic::Var)\
    F(version, std::optional<int64_t>)\
    F(thumb,   bool)
JSON_STRUCT(StoreFileReadModel, STORE_FILE_READ_MODEL_FIELDS);

#define STORE_FILE_READ_RESULT_FIELDS(F)\
    F(data, Pson::BinaryString)
JSON_STRUCT(StoreFileReadResult, STORE_FILE_READ_RESULT_FIELDS);

#define STORE_FILE_WRITE_MODEL_FIELDS(F)\
    F(fileId,     std::string)\
    F(requestId,  std::string)\
    F(fileIndex,  int64_t)\
    F(meta,       Poco::Dynamic::Var)\
    F(keyId,      std::string)\
    F(thumbIndex, std::optional<int64_t>)
JSON_STRUCT(StoreFileWriteModel, STORE_FILE_WRITE_MODEL_FIELDS);

#define STORE_FILE_RANDOM_WRITE_OPERATION_FIELDS(F)\
    F(type,     std::string)\
    F(pos,      int64_t)\
    F(data,     Pson::BinaryString)\
    F(truncate, bool)
JSON_STRUCT(StoreFileRandomWriteOperation, STORE_FILE_RANDOM_WRITE_OPERATION_FIELDS);

#define STORE_FILE_WRITE_MODEL_BY_OPERATIONS_FIELDS(F)\
    F(fileId,     std::string)\
    F(operations, std::vector<StoreFileRandomWriteOperation>)\
    F(meta,       Poco::Dynamic::Var)\
    F(keyId,      std::string)\
    F(version,    int64_t)\
    F(force,      bool)
JSON_STRUCT(StoreFileWriteModelByOperations, STORE_FILE_WRITE_MODEL_BY_OPERATIONS_FIELDS);

#define STORE_FILE_UPDATE_MODEL_FIELDS(F)\
    F(fileId, std::string)\
    F(meta,   Poco::Dynamic::Var)\
    F(keyId,  std::string)
JSON_STRUCT(StoreFileUpdateModel, STORE_FILE_UPDATE_MODEL_FIELDS);

#define STORE_FILE_DELETE_MODEL_FIELDS(F)\
    F(fileId, std::string)
JSON_STRUCT(StoreFileDeleteModel, STORE_FILE_DELETE_MODEL_FIELDS);

#define FILE_DEFINITION_FIELDS(F)\
    F(size,         int64_t)\
    F(checksumSize, int64_t)\
    F(randomWrite,  bool)
JSON_STRUCT(FileDefinition, FILE_DEFINITION_FIELDS);

#define CREATE_REQUEST_MODEL_FIELDS(F)\
    F(files, std::vector<FileDefinition>)
JSON_STRUCT(CreateRequestModel, CREATE_REQUEST_MODEL_FIELDS);

#define CREATE_REQUEST_RESULT_FIELDS(F)\
    F(id, std::string)
JSON_STRUCT(CreateRequestResult, CREATE_REQUEST_RESULT_FIELDS);

#define CHUNK_MODEL_FIELDS(F)\
    F(requestId, std::string)\
    F(fileIndex, int64_t)\
    F(seq,       int64_t)\
    F(data,      Pson::BinaryString)
JSON_STRUCT(ChunkModel, CHUNK_MODEL_FIELDS);

#define COMMIT_FILE_MODEL_FIELDS(F)\
    F(requestId, std::string)\
    F(fileIndex, int64_t)\
    F(seq,       int64_t)\
    F(checksum,  Pson::BinaryString)
JSON_STRUCT(CommitFileModel, COMMIT_FILE_MODEL_FIELDS);

#define FILE_SIZE_RESULT_FIELDS(F)\
    F(size,         int64_t)\
    F(checksumSize, int64_t)
JSON_STRUCT(FileSizeResult, FILE_SIZE_RESULT_FIELDS);

#define PREPARE_CHUNK_RESPOND_FIELDS(F)\
    F(hmac,   std::string)\
    F(cipher, std::string)
JSON_STRUCT(PrepareChunkRespond, PREPARE_CHUNK_RESPOND_FIELDS);

#define STORE_DELETED_EVENT_DATA_FIELDS(F)\
    F(storeId, std::string)\
    F(type,    std::optional<std::string>)
JSON_STRUCT(StoreDeletedEventData, STORE_DELETED_EVENT_DATA_FIELDS);

#define STORE_STATS_CHANGED_EVENT_DATA_FIELDS(F)\
    F(id,           std::string)\
    F(contextId,    std::string)\
    F(lastFileDate, int64_t)\
    F(files,        int64_t)\
    F(type,         std::optional<std::string>)
JSON_STRUCT(StoreStatsChangedEventData, STORE_STATS_CHANGED_EVENT_DATA_FIELDS);

#define STORE_FILE_DELETED_EVENT_DATA_FIELDS(F)\
    F(id,            std::string)\
    F(contextId,     std::string)\
    F(storeId,       std::string)\
    F(containerType, std::optional<std::string>)
JSON_STRUCT(StoreFileDeletedEventData, STORE_FILE_DELETED_EVENT_DATA_FIELDS);

#define STORE_FILE_CHANGE_FIELDS(F)\
    F(type,     std::string)\
    F(pos,      int64_t)\
    F(length,   int64_t)\
    F(truncate, bool)
JSON_STRUCT(StoreFileChange, STORE_FILE_CHANGE_FIELDS);

#define STORE_FILE_EVENT_DATA_FIELDS(F)\
    F(containerType, std::optional<std::string>)
JSON_STRUCT_EXT(StoreFileEventData, File, STORE_FILE_EVENT_DATA_FIELDS);

// StoreFileUpdatedEventData extends File directly (not StoreFileEventData)
// to avoid a 3-level JSON_STRUCT_EXT chain, which is unsupported.
#define STORE_FILE_UPDATED_EVENT_DATA_FIELDS(F)\
    F(containerType, std::optional<std::string>)\
    F(changes,       std::optional<std::vector<StoreFileChange>>)
JSON_STRUCT_EXT(StoreFileUpdatedEventData, File, STORE_FILE_UPDATED_EVENT_DATA_FIELDS);

} // server
} // store
} // endpoint
} // privmx

#endif // _PRIVMXLIB_ENDPOINT_STORE_SERVERTYPES_HPP_
