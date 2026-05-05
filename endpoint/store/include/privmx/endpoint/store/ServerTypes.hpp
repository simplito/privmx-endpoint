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
JSON_STRUCT(BufferReadRange_c_struct, BUFFER_READ_RANGE_FIELDS);

#define BUFFER_READ_RANGE_SLICE_FIELDS(F)\
    F(from, int64_t)\
    F(to,   int64_t)
JSON_STRUCT_EXT(BufferReadRangeSlice_c_struct, BufferReadRange_c_struct, BUFFER_READ_RANGE_SLICE_FIELDS);


#define STORE_DATA_ENTRY_FIELDS(F)\
    F(keyId, std::string)\
    F(data,  Poco::Dynamic::Var)
JSON_STRUCT(StoreDataEntry_c_struct, STORE_DATA_ENTRY_FIELDS);

#define STORE_FIELDS(F)\
    F(id,                   std::string)\
    F(resourceId,           std::optional<std::string>)\
    F(contextId,            std::string)\
    F(createDate,           int64_t)\
    F(creator,              std::string)\
    F(lastModificationDate, int64_t)\
    F(lastModifier,         std::string)\
    F(data,                 std::vector<StoreDataEntry_c_struct>)\
    F(keyId,                std::string)\
    F(users,                std::vector<std::string>)\
    F(managers,             std::vector<std::string>)\
    F(keys,                 std::vector<core::server::KeyEntry_c_struct>)\
    F(version,              int64_t)\
    F(lastFileDate,         int64_t)\
    F(files,                int64_t)\
    F(type,                 std::optional<std::string>)\
    F(policy,               Poco::Dynamic::Var)
JSON_STRUCT(Store_c_struct, STORE_FIELDS);

#define STORE_CREATE_MODEL_FIELDS(F)\
    F(resourceId, std::string)\
    F(contextId,  std::string)\
    F(users,      std::vector<std::string>)\
    F(managers,   std::vector<std::string>)\
    F(data,       Poco::Dynamic::Var)\
    F(keyId,      std::string)\
    F(keys,       std::vector<core::server::KeyEntrySet_c_struct>)\
    F(type,       std::string)\
    F(policy,     std::optional<Poco::Dynamic::Var>)
JSON_STRUCT(StoreCreateModel_c_struct, STORE_CREATE_MODEL_FIELDS);

#define STORE_UPDATE_MODEL_FIELDS(F)\
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
JSON_STRUCT(StoreUpdateModel_c_struct, STORE_UPDATE_MODEL_FIELDS);

#define FILE_THUMB_FIELDS(F)\
    F(size, int64_t)
JSON_STRUCT(FileThumb_c_struct, FILE_THUMB_FIELDS);

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
    F(thumb,                std::optional<FileThumb_c_struct>)
JSON_STRUCT(File_c_struct, FILE_FIELDS_SERVER);

#define FILE_ERROR_FIELDS(F)\
    F(code,    int64_t)\
    F(message, std::string)
JSON_STRUCT(FileError_c_struct, FILE_ERROR_FIELDS);

#define FILE_LIST_ELEMENT_FIELDS(F)\
    F(error, std::optional<FileError_c_struct>)
JSON_STRUCT_EXT(FileListElement_c_struct, File_c_struct, FILE_LIST_ELEMENT_FIELDS);

#define STORE_FILE_GET_MODEL_FIELDS(F)\
    F(fileId, std::string)
JSON_STRUCT(StoreFileGetModel_c_struct, STORE_FILE_GET_MODEL_FIELDS);

#define STORE_FILE_GET_MANY_MODEL_FIELDS(F)\
    F(storeId,      std::string)\
    F(fileIds,      std::vector<std::string>)\
    F(failOnError,  bool)
JSON_STRUCT(StoreFileGetManyModel_c_struct, STORE_FILE_GET_MANY_MODEL_FIELDS);

#define STORE_FILE_GET_RESULT_FIELDS(F)\
    F(store, Store_c_struct)\
    F(file,  File_c_struct)
JSON_STRUCT(StoreFileGetResult_c_struct, STORE_FILE_GET_RESULT_FIELDS);

#define STORE_FILE_GET_MANY_RESULT_FIELDS(F)\
    F(store, Store_c_struct)\
    F(files, std::vector<FileListElement_c_struct>)
JSON_STRUCT(StoreFileGetManyResult_c_struct, STORE_FILE_GET_MANY_RESULT_FIELDS);

#define STORE_FILE_LIST_MODEL_FIELDS(F)\
    F(storeId, std::string)
JSON_STRUCT_EXT(StoreFileListModel_c_struct, core::server::ListModel_c_struct, STORE_FILE_LIST_MODEL_FIELDS);

#define STORE_FILE_LIST_RESULT_FIELDS(F)\
    F(store, Store_c_struct)\
    F(files, std::vector<File_c_struct>)\
    F(count, int64_t)
JSON_STRUCT(StoreFileListResult_c_struct, STORE_FILE_LIST_RESULT_FIELDS);

#define ENCRYPTED_FILE_META_V4_FIELDS(F)\
    F(publicMeta,       std::string)\
    F(publicMetaObject, Poco::Dynamic::Var)\
    F(privateMeta,      std::string)\
    F(fileSize,         std::string)\
    F(internalMeta,     std::optional<std::string>)\
    F(authorPubKey,     std::string)
JSON_STRUCT_EXT(EncryptedFileMetaV4_c_struct, core::dynamic::VersionedData_c_struct, ENCRYPTED_FILE_META_V4_FIELDS);

#define ENCRYPTED_FILE_META_V5_FIELDS(F)\
    F(publicMeta,       std::string)\
    F(publicMetaObject, Poco::Dynamic::Var)\
    F(privateMeta,      std::string)\
    F(internalMeta,     std::optional<std::string>)\
    F(authorPubKey,     std::string)\
    F(dio,              std::string)
JSON_STRUCT_EXT(EncryptedFileMetaV5_c_struct, core::dynamic::VersionedData_c_struct, ENCRYPTED_FILE_META_V5_FIELDS);

#define STORE_CREATE_RESULT_FIELDS(F)\
    F(storeId, std::string)
JSON_STRUCT(StoreCreateResult_c_struct, STORE_CREATE_RESULT_FIELDS);

#define STORE_DELETE_MODEL_FIELDS(F)\
    F(storeId, std::string)
JSON_STRUCT(StoreDeleteModel_c_struct, STORE_DELETE_MODEL_FIELDS);

#define STORE_GET_MODEL_FIELDS(F)\
    F(storeId, std::string)\
    F(type,    std::optional<std::string>)
JSON_STRUCT(StoreGetModel_c_struct, STORE_GET_MODEL_FIELDS);

#define STORE_GET_RESULT_FIELDS(F)\
    F(store, Store_c_struct)
JSON_STRUCT(StoreGetResult_c_struct, STORE_GET_RESULT_FIELDS);

#define STORE_LIST_MODEL_FIELDS(F)\
    F(contextId, std::string)\
    F(type,      std::optional<std::string>)
JSON_STRUCT_EXT(StoreListModel_c_struct, core::server::ListModel_c_struct, STORE_LIST_MODEL_FIELDS);

#define STORE_LIST_RESULT_FIELDS(F)\
    F(stores, std::vector<Store_c_struct>)\
    F(count,  int64_t)
JSON_STRUCT(StoreListResult_c_struct, STORE_LIST_RESULT_FIELDS);

#define STORE_FILE_CREATE_MODEL_FIELDS(F)\
    F(resourceId, std::string)\
    F(storeId,    std::string)\
    F(requestId,  std::string)\
    F(fileIndex,  int64_t)\
    F(meta,       Poco::Dynamic::Var)\
    F(keyId,      std::string)\
    F(thumbIndex, std::optional<int64_t>)
JSON_STRUCT(StoreFileCreateModel_c_struct, STORE_FILE_CREATE_MODEL_FIELDS);

#define STORE_FILE_CREATE_RESULT_FIELDS(F)\
    F(fileId, std::string)
JSON_STRUCT(StoreFileCreateResult_c_struct, STORE_FILE_CREATE_RESULT_FIELDS);

#define STORE_FILE_READ_MODEL_FIELDS(F)\
    F(fileId,  std::string)\
    F(range,   Poco::Dynamic::Var)\
    F(version, std::optional<int64_t>)\
    F(thumb,   bool)
JSON_STRUCT(StoreFileReadModel_c_struct, STORE_FILE_READ_MODEL_FIELDS);

#define STORE_FILE_READ_RESULT_FIELDS(F)\
    F(data, Pson::BinaryString)
JSON_STRUCT(StoreFileReadResult_c_struct, STORE_FILE_READ_RESULT_FIELDS);

#define STORE_FILE_WRITE_MODEL_FIELDS(F)\
    F(fileId,     std::string)\
    F(requestId,  std::string)\
    F(fileIndex,  int64_t)\
    F(meta,       Poco::Dynamic::Var)\
    F(keyId,      std::string)\
    F(thumbIndex, std::optional<int64_t>)
JSON_STRUCT(StoreFileWriteModel_c_struct, STORE_FILE_WRITE_MODEL_FIELDS);

#define STORE_FILE_RANDOM_WRITE_OPERATION_FIELDS(F)\
    F(type,     std::string)\
    F(pos,      int64_t)\
    F(data,     Pson::BinaryString)\
    F(truncate, bool)
JSON_STRUCT(StoreFileRandomWriteOperation_c_struct, STORE_FILE_RANDOM_WRITE_OPERATION_FIELDS);

#define STORE_FILE_WRITE_MODEL_BY_OPERATIONS_FIELDS(F)\
    F(fileId,     std::string)\
    F(operations, std::vector<StoreFileRandomWriteOperation_c_struct>)\
    F(meta,       Poco::Dynamic::Var)\
    F(keyId,      std::string)\
    F(version,    int64_t)\
    F(force,      bool)
JSON_STRUCT(StoreFileWriteModelByOperations_c_struct, STORE_FILE_WRITE_MODEL_BY_OPERATIONS_FIELDS);

#define STORE_FILE_UPDATE_MODEL_FIELDS(F)\
    F(fileId, std::string)\
    F(meta,   Poco::Dynamic::Var)\
    F(keyId,  std::string)
JSON_STRUCT(StoreFileUpdateModel_c_struct, STORE_FILE_UPDATE_MODEL_FIELDS);

#define STORE_FILE_DELETE_MODEL_FIELDS(F)\
    F(fileId, std::string)
JSON_STRUCT(StoreFileDeleteModel_c_struct, STORE_FILE_DELETE_MODEL_FIELDS);

#define FILE_DEFINITION_FIELDS(F)\
    F(size,         int64_t)\
    F(checksumSize, int64_t)\
    F(randomWrite,  bool)
JSON_STRUCT(FileDefinition_c_struct, FILE_DEFINITION_FIELDS);

#define CREATE_REQUEST_MODEL_FIELDS(F)\
    F(files, std::vector<FileDefinition_c_struct>)
JSON_STRUCT(CreateRequestModel_c_struct, CREATE_REQUEST_MODEL_FIELDS);

#define CREATE_REQUEST_RESULT_FIELDS(F)\
    F(id, std::string)
JSON_STRUCT(CreateRequestResult_c_struct, CREATE_REQUEST_RESULT_FIELDS);

#define CHUNK_MODEL_FIELDS(F)\
    F(requestId, std::string)\
    F(fileIndex, int64_t)\
    F(seq,       int64_t)\
    F(data,      Pson::BinaryString)
JSON_STRUCT(ChunkModel_c_struct, CHUNK_MODEL_FIELDS);

#define COMMIT_FILE_MODEL_FIELDS(F)\
    F(requestId, std::string)\
    F(fileIndex, int64_t)\
    F(seq,       int64_t)\
    F(checksum,  Pson::BinaryString)
JSON_STRUCT(CommitFileModel_c_struct, COMMIT_FILE_MODEL_FIELDS);

#define FILE_SIZE_RESULT_FIELDS(F)\
    F(size,         int64_t)\
    F(checksumSize, int64_t)
JSON_STRUCT(FileSizeResult_c_struct, FILE_SIZE_RESULT_FIELDS);

#define PREPARE_CHUNK_RESPOND_FIELDS(F)\
    F(hmac,   std::string)\
    F(cipher, std::string)
JSON_STRUCT(PrepareChunkRespond_c_struct, PREPARE_CHUNK_RESPOND_FIELDS);

#define STORE_DELETED_EVENT_DATA_FIELDS(F)\
    F(storeId, std::string)\
    F(type,    std::optional<std::string>)
JSON_STRUCT(StoreDeletedEventData_c_struct, STORE_DELETED_EVENT_DATA_FIELDS);

#define STORE_STATS_CHANGED_EVENT_DATA_FIELDS(F)\
    F(id,           std::string)\
    F(contextId,    std::string)\
    F(lastFileDate, int64_t)\
    F(files,        int64_t)\
    F(type,         std::optional<std::string>)
JSON_STRUCT(StoreStatsChangedEventData_c_struct, STORE_STATS_CHANGED_EVENT_DATA_FIELDS);

#define STORE_FILE_DELETED_EVENT_DATA_FIELDS(F)\
    F(id,            std::string)\
    F(contextId,     std::string)\
    F(storeId,       std::string)\
    F(containerType, std::optional<std::string>)
JSON_STRUCT(StoreFileDeletedEventData_c_struct, STORE_FILE_DELETED_EVENT_DATA_FIELDS);

#define STORE_FILE_CHANGE_FIELDS(F)\
    F(type,     std::string)\
    F(pos,      int64_t)\
    F(length,   int64_t)\
    F(truncate, bool)
JSON_STRUCT(StoreFileChange_c_struct, STORE_FILE_CHANGE_FIELDS);

#define STORE_FILE_EVENT_DATA_FIELDS(F)\
    F(containerType, std::optional<std::string>)
JSON_STRUCT_EXT(StoreFileEventData_c_struct, File_c_struct, STORE_FILE_EVENT_DATA_FIELDS);

// StoreFileUpdatedEventData extends File_c_struct directly (not StoreFileEventData_c_struct)
// to avoid a 3-level JSON_STRUCT_EXT chain, which is unsupported.
#define STORE_FILE_UPDATED_EVENT_DATA_FIELDS(F)\
    F(containerType, std::optional<std::string>)\
    F(changes,       std::optional<std::vector<StoreFileChange_c_struct>>)
JSON_STRUCT_EXT(StoreFileUpdatedEventData_c_struct, File_c_struct, STORE_FILE_UPDATED_EVENT_DATA_FIELDS);

} // server
} // store
} // endpoint
} // privmx

#endif // _PRIVMXLIB_ENDPOINT_STORE_SERVERTYPES_HPP_
