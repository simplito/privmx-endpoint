/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_ENDPOINT_CORE_DYNAMICTYPES_HPP_
#define _PRIVMXLIB_ENDPOINT_CORE_DYNAMICTYPES_HPP_

#include <privmx/utils/JsonHelper.hpp>

namespace privmx {
namespace endpoint {
namespace core {
namespace dynamic {

#define VERSIONED_DATA_FIELDS(F)\
    F(version, int64_t)
JSON_STRUCT(VersionedData, VERSIONED_DATA_FIELDS);

#define BRIDGE_IDENTITY_FIELDS(F)\
    F(url, std::string)\
    F(pubKey, std::optional<std::string>)\
    F(instanceId, std::optional<std::string>)
JSON_STRUCT(BridgeIdentity, BRIDGE_IDENTITY_FIELDS);

#define DATA_INTEGRITY_OBJECT_FIELDS(F)\
    F(creatorUserId, std::string)\
    F(creatorPublicKey, std::string)\
    F(contextId, std::string)\
    F(resourceId, std::string)\
    F(timestamp, int64_t)\
    F(randomId, std::string)\
    F(containerId, std::optional<std::string>)\
    F(containerResourceId, std::optional<std::string>)\
    F(fieldChecksums, std::unordered_map<std::string, std::string>)\
    F(structureVersion, int64_t)\
    F(bridgeIdentity, std::optional<BridgeIdentity>)
JSON_STRUCT_EXT(DataIntegrityObject, VersionedData, DATA_INTEGRITY_OBJECT_FIELDS);

#define ENCRYPTION_KEY_OBJECT_FIELDS(F)\
    F(id , std::string)\
    F(key, std::string)\
    F(keySecret, std::string)
JSON_STRUCT(EncryptionKey, ENCRYPTION_KEY_OBJECT_FIELDS);


} // dynamic
} // core
} // endpoint
} // privmx

#endif // _PRIVMXLIB_ENDPOINT_CORE_DYNAMICTYPES_HPP_
