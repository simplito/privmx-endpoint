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

#include <string>

#include "privmx/endpoint/core/TypesMacros.hpp"

namespace privmx {
namespace endpoint {
namespace core {
namespace dynamic {

ENDPOINT_CLIENT_TYPE(VersionedData)
    INT64_FIELD(version)
TYPE_END

ENDPOINT_CLIENT_TYPE(BridgeIdentity)
    STRING_FIELD(url)
    STRING_FIELD(pubKey)
    STRING_FIELD(instanceId)
TYPE_END

ENDPOINT_CLIENT_TYPE_INHERIT(DataIntegrityObject, VersionedData)
    STRING_FIELD(creatorUserId)
    STRING_FIELD(creatorPublicKey)
    STRING_FIELD(contextId)
    STRING_FIELD(resourceId)
    INT64_FIELD(timestamp)
    STRING_FIELD(randomId)
    STRING_FIELD(containerId)
    STRING_FIELD(containerResourceId)
    MAP_FIELD(fieldChecksums, std::string)
    INT64_FIELD(structureVersion)
    OBJECT_FIELD(bridgeIdentity, BridgeIdentity)
TYPE_END

ENDPOINT_CLIENT_TYPE(EncryptionKey)
    STRING_FIELD(id)
    STRING_FIELD(key)
    STRING_FIELD(keySecret)
TYPE_END


} // dynamic
} // core
} // endpoint
} // privmx

#endif // _PRIVMXLIB_ENDPOINT_CORE_DYNAMICTYPES_HPP_
