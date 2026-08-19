#ifndef _PRIVMXLIB_ENDPOINT_GROUP_ENCRYPTORS_GROUP_TYPES_HPP_
#define _PRIVMXLIB_ENDPOINT_GROUP_ENCRYPTORS_GROUP_TYPES_HPP_

#include <string>

#include "privmx/endpoint/core/Buffer.hpp"
#include "privmx/endpoint/core/CoreTypes.hpp"
#include <privmx/endpoint/core/encryptors/module/Types.hpp>

#include "privmx/endpoint/group/encryptors/group/DynamicTypes.hpp"

namespace privmx {
namespace endpoint {
namespace group {

struct GroupDataToEncryptV5 {
    core::Buffer publicMeta;
    core::Buffer privateMeta;
    core::ModuleInternalMetaV5 internalMeta;
    core::DataIntegrityObject dio;
    std::string groupPrivKey; // WIF private key string — will be encrypted
    dynamic::MembershipBlock membership;
};

struct DecryptedGroupDataV5 : public core::DecryptedVersionedData {
    core::Buffer publicMeta;
    core::Buffer privateMeta;
    core::ModuleInternalMetaV5 internalMeta;
    std::string authorPubKey;
    core::DataIntegrityObject dio;
    std::string groupPrivKey; // decrypted WIF private key (empty if only public extracted)
    dynamic::MembershipBlock membership;
};

} // namespace group
} // namespace endpoint
} // namespace privmx

#endif // _PRIVMXLIB_ENDPOINT_GROUP_ENCRYPTORS_GROUP_TYPES_HPP_
