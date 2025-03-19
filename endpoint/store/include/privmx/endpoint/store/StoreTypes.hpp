/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_ENDPOINT_STORE_STORETYPES_HPP_
#define _PRIVMXLIB_ENDPOINT_STORE_STORETYPES_HPP_

#include <string>

#include "privmx/endpoint/store/DynamicTypes.hpp"
#include "privmx/endpoint/store/ServerTypes.hpp"
#include "privmx/endpoint/core/Buffer.hpp"
#include "privmx/endpoint/core/CoreTypes.hpp"

namespace privmx {
namespace endpoint {
namespace store {

constexpr uint64_t IV_SIZE = 16;
constexpr uint64_t HMAC_SIZE = 32;
constexpr uint64_t CHUNK_PADDING = 16;

struct FileDecryptionParams {
    std::string fileId;
    uint64_t sizeOnServer;
    uint64_t originalSize;
    int64_t cipherType;
    size_t chunkSize;
    std::string key;
    std::string hmac;
    int64_t version;
};

struct FileMetaSigned
{
    dynamic::compat_v1::StoreFileMeta meta;
    std::string metaBuf;
    std::string signature;
};

struct StoreFile
{
    server::File raw;
    dynamic::compat_v1::StoreFileMeta meta;
    std::string verified;
};

struct FileMetaToEncryptV4 {
    core::Buffer publicMeta;
    core::Buffer privateMeta;
    int64_t fileSize;
    core::Buffer internalMeta;
};

struct FileMetaToEncryptV5 {
    core::Buffer publicMeta;
    core::Buffer privateMeta;
    core::Buffer internalMeta;
    core::DataIntegrityObject dio;
};

struct DecryptedFileMetaV4 : core::DecryptedVersionedData {
    core::Buffer publicMeta;
    core::Buffer privateMeta;
    int64_t fileSize;
    core::Buffer internalMeta;
    std::string authorPubKey;
};

struct DecryptedFileMetaV5 : core::DecryptedVersionedData {
    core::Buffer publicMeta;
    core::Buffer privateMeta;
    core::Buffer internalMeta;
    std::string authorPubKey;
    core::DataIntegrityObject dio;
};

struct StoreDataToEncryptV4 {
    core::Buffer publicMeta;
    core::Buffer privateMeta;
    std::optional<core::Buffer> internalMeta;
};

struct StoreDataToEncryptV5 {
    core::Buffer publicMeta;
    core::Buffer privateMeta;
    std::optional<core::Buffer> internalMeta;
    core::DataIntegrityObject dio;
};

struct DecryptedStoreDataV4 : core::DecryptedVersionedData {
    core::Buffer publicMeta;
    core::Buffer privateMeta;
    std::optional<core::Buffer> internalMeta;
    std::string authorPubKey;
};

struct DecryptedStoreDataV5 : core::DecryptedVersionedData {
    core::Buffer publicMeta;
    core::Buffer privateMeta;
    std::optional<core::Buffer> internalMeta;
    std::string authorPubKey;
    core::DataIntegrityObject dio;
};

} // store
} // endpoint
} // privmx

#endif // _PRIVMXLIB_ENDPOINT_STORE_STORETYPES_HPP_
