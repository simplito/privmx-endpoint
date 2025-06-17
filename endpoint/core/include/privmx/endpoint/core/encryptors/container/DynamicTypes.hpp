/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_ENDPOINT_CORE_CONTAINER_DYNAMICTYPES_HPP_
#define _PRIVMXLIB_ENDPOINT_CORE_CONTAINER_DYNAMICTYPES_HPP_

#include <privmx/endpoint/core/TypesMacros.hpp>
#include <privmx/endpoint/core/ServerTypes.hpp>


namespace privmx {
namespace endpoint {
namespace core {
namespace container {
namespace dynamic {

// Version 4 (deprecated)

ENDPOINT_CLIENT_TYPE_INHERIT(EncryptedContainerDataV4, core::dynamic::VersionedData)
    STRING_FIELD(publicMeta)
    OBJECT_PTR_FIELD(publicMetaObject)
    STRING_FIELD(privateMeta)
    STRING_FIELD(internalMeta)
    STRING_FIELD(authorPubKey)
TYPE_END

// Version 5 

ENDPOINT_CLIENT_TYPE(ContainerInternalMetaV5)
    STRING_FIELD(secret)
    STRING_FIELD(resourceId)
    STRING_FIELD(randomId)
TYPE_END

ENDPOINT_CLIENT_TYPE_INHERIT(EncryptedContainerDataV5, core::dynamic::VersionedData)
    STRING_FIELD(publicMeta)
    OBJECT_PTR_FIELD(publicMetaObject)
    STRING_FIELD(privateMeta)
    STRING_FIELD(internalMeta)
    STRING_FIELD(authorPubKey)
    STRING_FIELD(dio)
TYPE_END

} // dynamic
} // container
} // core
} // endpoint
} // privmx

#endif // _PRIVMXLIB_ENDPOINT_CORE_ENCRYPTORS_CONTAINER_DYNAMICTYPES_HPP_
