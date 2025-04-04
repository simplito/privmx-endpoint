/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_ENDPOINT_KVDB_KVDBTYPES_HPP_
#define _PRIVMXLIB_ENDPOINT_KVDB_KVDBTYPES_HPP_

#include <string>
#include <optional>
#include <privmx/endpoint/core/Buffer.hpp>
#include "privmx/endpoint/core/CoreTypes.hpp"


namespace privmx {
namespace endpoint {
namespace kvdb {

struct ItemDataToEncryptV5 {
    core::Buffer publicMeta;
    core::Buffer privateMeta;
    core::Buffer data;
    std::optional<core::Buffer> internalMeta;
    core::DataIntegrityObject dio;
};

struct DecryptedItemDataV5 : public core::DecryptedVersionedData {
    core::Buffer publicMeta;
    core::Buffer privateMeta;
    core::Buffer data;
    std::optional<core::Buffer> internalMeta;
    std::string authorPubKey;
    core::DataIntegrityObject dio;
};

struct KvdbDataToEncryptV5 {
    core::Buffer publicMeta;
    core::Buffer privateMeta;
    core::Buffer internalMeta;
    core::DataIntegrityObject dio;
};

struct DecryptedKvdbDataV5 : public core::DecryptedVersionedData {
    core::Buffer publicMeta;
    core::Buffer privateMeta;
    core::Buffer internalMeta;
    std::string authorPubKey;
    core::DataIntegrityObject dio;
};

} // kvdb
} // endpoint
} // privmx

#endif // _PRIVMXLIB_ENDPOINT_KVDB_KVDBTYPES_HPP_
