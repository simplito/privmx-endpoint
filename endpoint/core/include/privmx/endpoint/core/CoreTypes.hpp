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

#include "privmx/endpoint/core/CoreException.hpp"
#include "privmx/endpoint/core/ServerTypes.hpp"
#include "privmx/endpoint/core/Types.hpp"
#include <Poco/Dynamic/Var.h>
#include <memory>
#include <optional>
#include <privmx/crypto/ecc/PublicKey.hpp>
#include <string>
#include <unordered_map>

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
    std::string resourceId;
    int64_t timestamp;
    std::string randomId;
    std::optional<std::string> containerId;
    std::optional<std::string> containerResourceId;
    std::optional<BridgeIdentity> bridgeIdentity;
};

// A null `error` means the payload decrypted and verified. Internally the whole exception is kept, cause chain
// included; `statusCode()` narrows it to the single code the public API structs carry.
struct DecryptedVersionedData {
    int64_t dataStructureVersion;
    std::shared_ptr<const Exception> error;

    int64_t statusCode() const noexcept { return error ? (int64_t)error->getCode() : 0; }
};

inline std::shared_ptr<const Exception> asError(const Exception& e) {
    return std::make_shared<const Exception>(e);
}

// for the `catch (...)` paths, which have no exception object to keep
inline std::shared_ptr<const Exception> unknownError(std::string description = std::string()) {
    return std::make_shared<const Exception>(
        "Unknown exception", "UnknownException", "Core", ENDPOINT_CORE_EXCEPTION_CODE, std::move(description)
    );
}

// narrows a retained exception to the Error the public API structs carry; the cause chain stops here
inline Error toPublicError(const Exception& e) {
    return Error{
        .name = e.getName(),
        .scope = e.getScope(),
        .code = e.getCode(),
        .message = e.getMessage(),
        .description = e.getDescription(),
        ._what = e.what()
    };
}

inline std::optional<Error> toPublicError(const std::shared_ptr<const Exception>& e) {
    if (!e) {
        return std::nullopt;
    }
    return toPublicError(*e);
}

struct DecryptedEncKey : public EncKey, public DecryptedVersionedData {};

struct ExpandedDataIntegrityObject : public DataIntegrityObject {
    int64_t structureVersion;
    std::unordered_map<std::string, std::string> fieldChecksums;
};

struct EncKeyLocation {
    std::string contextId;
    std::string resourceId;
    bool operator==(const EncKeyLocation& other) const {
        return (contextId == other.contextId && resourceId == other.resourceId);
    }
};

struct EncKeyV2ToEncrypt : public EncKey {
    DataIntegrityObject dio;
    EncKeyLocation location;
    std::string keySecret;
    std::string secretHash;
};

struct DecryptedEncKeyV2 : public DecryptedEncKey {
    ExpandedDataIntegrityObject dio;
    std::string keySecret;
    std::string secretHash;
};

enum EventSource {
    INTERNAL = 0,
    SERVER = 1
};
struct NotificationEvent {
    EventSource source;
    std::string type;
    Poco::Dynamic::Var data;
    int64_t version;
    int64_t timestamp;
    std::vector<std::string> subscriptions;
};

struct ModuleKeys {
    std::vector<server::KeyEntry> keys;
    std::vector<server::GroupKeysEntry> groupKeys;
    std::vector<std::string> staleGroups;
    std::string currentKeyId;
    int64_t moduleSchemaVersion;
    std::string moduleResourceId;
    std::string contextId;
};

struct GroupEpochInfo {
    int64_t keyVersion;
    std::string groupPubKey;
};

struct ContainerUpdateContext {
    EncKeyLocation location;
    EncKey key;
    DataIntegrityObject dio;
    std::string secret;
    std::vector<server::KeyEntrySet> keyEntries;
};

struct ContainerCreateContext {
    EncKey key;
    std::string resourceId;
    DataIntegrityObject dio;
    std::string secret;
    std::vector<server::KeyEntrySet> keyEntries;
};

} // namespace core
} // namespace endpoint
} // namespace privmx

template<>
struct std::hash<privmx::endpoint::core::EncKeyLocation> {
    std::size_t operator()(const privmx::endpoint::core::EncKeyLocation& encKeyLocation) const noexcept {
        std::size_t h1 = std::hash<std::string>{}(encKeyLocation.contextId);
        std::size_t h2 = std::hash<std::string>{}(encKeyLocation.resourceId);
        return h1 ^ (h2 << 1);
    }
};

#endif // _PRIVMXLIB_ENDPOINT_CORE_CORETYPES_HPP_
