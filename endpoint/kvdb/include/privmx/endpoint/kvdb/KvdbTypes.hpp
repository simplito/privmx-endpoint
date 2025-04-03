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


namespace privmx {
namespace endpoint {
namespace kvdb {

struct KvdbDataToEncrypt {
    core::Buffer publicMeta;
    core::Buffer privateMeta;
    std::optional<core::Buffer> internalMeta;
};

struct DecryptedKvdbData {
    core::Buffer publicMeta;
    core::Buffer privateMeta;
    std::optional<core::Buffer> internalMeta;
    std::string authorPubKey;
    int64_t statusCode;
};

struct KvdbItemDataToEncrypt {
    core::Buffer data;
};

struct DecryptedKvdbItemData {
    core::Buffer data;
    std::string authorPubKey;
    int64_t statusCode;
};

} // kvdb
} // endpoint
} // privmx

#endif // _PRIVMXLIB_ENDPOINT_KVDB_KVDBTYPES_HPP_
