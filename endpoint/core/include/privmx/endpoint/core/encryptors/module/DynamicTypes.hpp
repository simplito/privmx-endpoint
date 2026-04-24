/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_ENDPOINT_CORE_MODULE_DYNAMICTYPES_HPP_
#define _PRIVMXLIB_ENDPOINT_CORE_MODULE_DYNAMICTYPES_HPP_

#include <privmx/utils/JsonHelper.hpp>
#include <privmx/endpoint/core/ServerTypes.hpp>

namespace privmx {
namespace endpoint {
namespace core {
namespace dynamic {

// Version 4 (deprecated)



#define ENCRYPTED_MODULE_DATA_V4_FIELDS(F)\
    F(publicMeta, std::string)\
    F(publicMetaObject, Poco::Dynamic::Var)\
    F(privateMeta, std::string)\
    F(internalMeta, std::optional<std::string>)\
    F(authorPubKey, std::string)
JSON_STRUCT_EXT(EncryptedModuleDataV4_c_struct, VersionedData_c_struct, ENCRYPTED_MODULE_DATA_V4_FIELDS);

// Version 5 

#define MODULE_INTERNAL_META_V5_FIELDS(F)\
    F(secret, std::string)\
    F(resourceId, std::string)\
    F(randomId, std::string)
JSON_STRUCT(ModuleInternalMetaV5_c_struct, MODULE_INTERNAL_META_V5_FIELDS);

#define ENCRYPTED_MODULE_DATA_V5_FIELDS(F)\
    F(publicMeta, std::string)\
    F(publicMetaObject, Poco::Dynamic::Var)\
    F(privateMeta, std::string)\
    F(internalMeta, std::string)\
    F(authorPubKey, std::string)\
    F(dio, std::string)
JSON_STRUCT_EXT(EncryptedModuleDataV5_c_struct, VersionedData_c_struct, ENCRYPTED_MODULE_DATA_V5_FIELDS);


} // dynamic
} // core
} // endpoint
} // privmx

#endif // _PRIVMXLIB_ENDPOINT_CORE_ENCRYPTORS_MODULE_DYNAMICTYPES_HPP_
