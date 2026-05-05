/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_ENDPOINT_STORE_DYNAMICTYPES_HPP_
#define _PRIVMXLIB_ENDPOINT_STORE_DYNAMICTYPES_HPP_

#include <privmx/utils/JsonHelper.hpp>

namespace privmx {
namespace endpoint {
namespace store {
namespace dynamic {

#define INTERNAL_STORE_FILE_META_FIELDS(F)\
    F(version,     int64_t)\
    F(size,        int64_t)\
    F(cipherType,  int64_t)\
    F(chunkSize,   int64_t)\
    F(key,         std::string)\
    F(hmac,        std::string)\
    F(randomWrite, std::optional<bool>)
JSON_STRUCT(InternalStoreFileMeta_c_struct, INTERNAL_STORE_FILE_META_FIELDS);

#define STORE_FILE_META_V4_FIELDS(F)\
    F(version,           int64_t)\
    F(publicMeta,        std::string)\
    F(privateMeta,       std::string)\
    F(encryptedFileSize, std::string)\
    F(internalMeta,      std::optional<std::string>)\
    F(authorPubKey,      std::string)
JSON_STRUCT(StoreFileMetaV4_c_struct, STORE_FILE_META_V4_FIELDS);

#define BLOB_PROPERTY_BAG_FIELDS(F)\
    F(type, std::string)
JSON_STRUCT(BlobPropertyBag_c_struct, BLOB_PROPERTY_BAG_FIELDS);

#define BLOB_FIELDS(F)\
    F(data,    Pson::BinaryString)\
    F(options, BlobPropertyBag_c_struct)
JSON_STRUCT(Blob_c_struct, BLOB_FIELDS);

// File_c_struct extends Blob_c_struct directly; the intermediate BlobPropertyBag
// chain is avoided to keep within the 2-level JSON_STRUCT_EXT limit.
#define FILE_FIELDS_DYNAMIC(F)\
    F(lastModified,       int64_t)\
    F(name,               std::string)\
    F(webkitRelativePath, std::string)
JSON_STRUCT_EXT(File_c_struct, Blob_c_struct, FILE_FIELDS_DYNAMIC);

#define SEND_FILE_RESULT_FIELDS(F)\
    F(file,      File_c_struct)\
    F(cipherType, int64_t)\
    F(key,        std::string)\
    F(hmac,       std::string)\
    F(chunkSize,  int64_t)
JSON_STRUCT(SendFileResult_c_struct, SEND_FILE_RESULT_FIELDS);

namespace compat_v1 {

#define STORE_DATA_FIELDS(F)\
    F(name,       std::string)\
    F(statusCode, int64_t)
JSON_STRUCT(StoreData_c_struct, STORE_DATA_FIELDS);

#define STORE_FILE_META_AUTHOR_FIELDS(F)\
    F(pubKey, std::string)
JSON_STRUCT(StoreFileMetaAuthor_c_struct, STORE_FILE_META_AUTHOR_FIELDS);

#define STORE_FILE_META_DESTINATION_FIELDS(F)\
    F(server,    std::string)\
    F(contextId, std::string)\
    F(storeId,   std::string)\
    F(store,     std::string)
JSON_STRUCT(StoreFileMetaDestination_c_struct, STORE_FILE_META_DESTINATION_FIELDS);

#define STORE_META_FIELDS(F)\
    F(mimetype,  std::string)\
    F(size,      int64_t)\
    F(cipherType, int64_t)\
    F(chunkSize,  int64_t)\
    F(key,        std::string)\
    F(hmac,       std::string)\
    F(statusCode, int64_t)
JSON_STRUCT(StoreMeta_c_struct, STORE_META_FIELDS);

#define STORE_THUMB_META_FIELDS(F)
JSON_STRUCT_EXT(StoreThumbMeta_c_struct, StoreMeta_c_struct, STORE_THUMB_META_FIELDS);

#define STORE_FILE_META_FIELDS(F)\
    F(ver,         int64_t)\
    F(name,        std::string)\
    F(author,      StoreFileMetaAuthor_c_struct)\
    F(destination, StoreFileMetaDestination_c_struct)\
    F(thumb,       std::optional<StoreThumbMeta_c_struct>)
JSON_STRUCT_EXT(StoreFileMeta_c_struct, StoreMeta_c_struct, STORE_FILE_META_FIELDS);

} // compat_v1

} // dynamic
} // store
} // endpoint
} // privmx

#endif // _PRIVMXLIB_ENDPOINT_STORE_DYNAMICTYPES_HPP_
