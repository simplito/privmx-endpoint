#ifndef _PRIVMXLIB_ENDPOINT_STORE_STORETYPES_HPP_
#define _PRIVMXLIB_ENDPOINT_STORE_STORETYPES_HPP_

#include <string>

#include "privmx/endpoint/store/DynamicTypes.hpp"
#include "privmx/endpoint/store/ServerTypes.hpp"
#include "privmx/endpoint/core/Buffer.hpp"

namespace privmx {
namespace endpoint {
namespace store {

constexpr uint64_t IV_SIZE = 16;
constexpr uint64_t HMAC_SIZE = 32;
constexpr uint64_t CHUNK_PADDING = 16;

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

struct FileMetaToEncrypt {
    core::Buffer publicMeta;
    core::Buffer privateMeta;
    int64_t fileSize;
    core::Buffer internalMeta;
};

struct DecryptedFileMeta {
    core::Buffer publicMeta;
    core::Buffer privateMeta;
    int64_t fileSize;
    core::Buffer internalMeta;
    std::string authorPubKey;
    int64_t statusCode;
};

struct StoreDataToEncrypt {
    core::Buffer publicMeta;
    core::Buffer privateMeta;
    std::optional<core::Buffer> internalMeta;
};

struct DecryptedStoreData {
    core::Buffer publicMeta;
    core::Buffer privateMeta;
    std::optional<core::Buffer> internalMeta;
    std::string authorPubKey;
    int64_t statusCode;
};

} // store
} // endpoint
} // privmx

#endif // _PRIVMXLIB_ENDPOINT_STORE_STORETYPES_HPP_
