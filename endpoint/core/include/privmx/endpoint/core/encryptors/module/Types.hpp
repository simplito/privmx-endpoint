/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_ENDPOINT_CORE_ENCRYPTORS_MODULE_TYPES_HPP_
#define _PRIVMXLIB_ENDPOINT_CORE_ENCRYPTORS_MODULE_TYPES_HPP_

#include <string>
#include "privmx/endpoint/core/Buffer.hpp"
#include "privmx/endpoint/core/CoreTypes.hpp"

namespace privmx {
namespace endpoint {
namespace core {
    
// Version 4 (deprecated)

struct ModuleDataToEncryptV4 {
    core::Buffer publicMeta;
    core::Buffer privateMeta;
    std::optional<core::Buffer> internalMeta;
};

struct DecryptedModuleDataV4 : public core::DecryptedVersionedData {
    core::Buffer publicMeta;
    core::Buffer privateMeta;
    std::optional<core::Buffer> internalMeta;
    std::string authorPubKey;
};

// Version 5 
struct ModuleInternalMetaV5 {
    std::string secret;
    std::string resourceId;
    std::string randomId;
};

struct ModuleDataToEncryptV5 {
    core::Buffer publicMeta;
    core::Buffer privateMeta;
    ModuleInternalMetaV5 internalMeta;
    core::DataIntegrityObject dio;
};

struct DecryptedModuleDataV5 : public core::DecryptedVersionedData {
    core::Buffer publicMeta;
    core::Buffer privateMeta;
    ModuleInternalMetaV5 internalMeta;
    std::string authorPubKey;
    core::DataIntegrityObject dio;
};

} // core
} // endpoint
} // privmx

#endif // _PRIVMXLIB_ENDPOINT_CORE_ENCRYPTORS_MODULE_TYPES_HPP_
