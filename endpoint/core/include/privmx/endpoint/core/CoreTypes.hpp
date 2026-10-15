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

#include "privmx/endpoint/core/ServerTypes.hpp"
#include "privmx/endpoint/core/Types.hpp"
#include <Poco/Dynamic/Var.h>
#include <optional>
#include <privmx/endpoint/core/crypto/CryptoSuite.hpp>
#include <privmx/endpoint/core/crypto/PublicKey.hpp>
#include <string>
#include <unordered_map>

namespace privmx {
namespace endpoint {
namespace core {

struct EncKey {
    std::string id;
    std::string key;
    /**
     * The algorithm suite used to write data protected by this key.
     *
     * It travels with the key, because `EncKey` already passes through the whole encryptor chain —
     * so the suite choice needs no separate channel across a dozen layers. It is also correct on the
     * merits: a key and the algorithm it is used with belong together.
     *
     * This affects **writing only**. A read never looks at it — it takes the suite from the tag
     * written into the frame, so data written with any suite can always be read.
     *
     * The default is the suite chosen at build time (level 1). For a container whose policy names a
     * suite, `ContainerBaseApi` overrides it (level 2).
     */
    CryptoSuite suite = CryptoSuite::defaultForWrite();
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

struct DecryptedVersionedData {
    int64_t dataStructureVersion;
    int64_t statusCode;
};

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
    /**
     * The algorithm suite of the container these keys belong to.
     *
     * Needed because a key read from the server **carries no suite** — `EncKey::suite` is set only
     * on generation. Without this field every item write (a message, a KVDB entry, a group envelope)
     * would use the build's default suite, even though the container named another one.
     */
    CryptoSuite cryptoSuite = CryptoSuite::defaultForWrite();
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
