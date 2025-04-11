/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_ENDPOINT_CORE_CORETYPES_HPP_
#define _PRIVMXLIB_ENDPOINT_CORE_CORETYPES_HPP_

#include <optional>
#include <string>
#include <privmx/crypto/ecc/PublicKey.hpp>
#include "privmx/endpoint/core/Buffer.hpp"

namespace privmx {
namespace endpoint {
namespace core {

struct EncKey {
    std::string id;
    std::string key;
};

struct DataIntegrityObject {
    std::string creatorUserId;
    std::string creatorPubKey;
    std::string contextId;
    std::string containerId;
    int64_t timestamp;
    std::string randomId;
    std::optional<std::string> itemId;
};

struct DecryptedVersionedData {
    int64_t dataStructureVersion;
    int64_t statusCode;
};

struct DecryptedEncKey : public EncKey, public DecryptedVersionedData {};

struct ExpandedDataIntegrityObject : public DataIntegrityObject {
    int64_t structureVersion;
    std::unordered_map<std::string, std::string> fieldChecksums;
};


struct EncKeyV2ToEncrypt : public EncKey {
    DataIntegrityObject dio;
    std::string containerControlNumber;
};

struct DecryptedEncKeyV2 : public DecryptedEncKey {
    ExpandedDataIntegrityObject dio;
    std::string containerControlNumber;
};

struct EncKeyLocation {
    std::string contextId;
    std::string containerId;
    bool operator==(const EncKeyLocation &other) const {
        return (contextId == other.contextId && containerId == other.containerId);
    }
};

}  // namespace core
}  // namespace endpoint
}  // namespace privmx

template<>
struct std::hash<privmx::endpoint::core::EncKeyLocation> {
    std::size_t operator()(const privmx::endpoint::core::EncKeyLocation& encKeyLocation) const noexcept
    {
        std::size_t h1 = std::hash<std::string>{}(encKeyLocation.contextId);
        std::size_t h2 = std::hash<std::string>{}(encKeyLocation.containerId);
        return h1 ^ (h2 << 1);
    }
};

#endif  // _PRIVMXLIB_ENDPOINT_CORE_CORETYPES_HPP_
