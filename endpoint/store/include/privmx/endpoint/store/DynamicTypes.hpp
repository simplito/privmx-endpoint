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

#define INTERNAL_STORE_FILE_META_FIELDS(F)                                                                             \
    F(version, int64_t)                                                                                                \
    F(size, int64_t)                                                                                                   \
    F(cipherType, int64_t)                                                                                             \
    F(chunkSize, int64_t)                                                                                              \
    F(key, std::string)                                                                                                \
    F(hmac, std::string)                                                                                               \
    F(randomWrite, std::optional<bool>)
JSON_STRUCT(InternalStoreFileMeta, INTERNAL_STORE_FILE_META_FIELDS);

#define STORE_FILE_META_V4_FIELDS(F)                                                                                   \
    F(version, int64_t)                                                                                                \
    F(publicMeta, std::string)                                                                                         \
    F(privateMeta, std::string)                                                                                        \
    F(encryptedFileSize, std::string)                                                                                  \
    F(internalMeta, std::optional<std::string>)                                                                        \
    F(authorPubKey, std::string)
JSON_STRUCT(StoreFileMetaV4, STORE_FILE_META_V4_FIELDS);

#define BLOB_PROPERTY_BAG_FIELDS(F) F(type, std::string)
JSON_STRUCT(BlobPropertyBag, BLOB_PROPERTY_BAG_FIELDS);

#define BLOB_FIELDS(F)                                                                                                 \
    F(data, Pson::BinaryString)                                                                                        \
    F(options, BlobPropertyBag)
JSON_STRUCT(Blob, BLOB_FIELDS);

// File extends Blob directly; the intermediate BlobPropertyBag
// chain is avoided to keep within the 2-level JSON_STRUCT_EXT limit.
#define FILE_FIELDS_DYNAMIC(F)                                                                                         \
    F(lastModified, int64_t)                                                                                           \
    F(name, std::string)                                                                                               \
    F(webkitRelativePath, std::string)
JSON_STRUCT_EXT(File, Blob, FILE_FIELDS_DYNAMIC);

#define SEND_FILE_RESULT_FIELDS(F)                                                                                     \
    F(file, File)                                                                                                      \
    F(cipherType, int64_t)                                                                                             \
    F(key, std::string)                                                                                                \
    F(hmac, std::string)                                                                                               \
    F(chunkSize, int64_t)
JSON_STRUCT(SendFileResult, SEND_FILE_RESULT_FIELDS);

} // namespace dynamic
} // namespace store
} // namespace endpoint
} // namespace privmx

#endif // _PRIVMXLIB_ENDPOINT_STORE_DYNAMICTYPES_HPP_
