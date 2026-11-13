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

// The roster/tree plane. `internalMeta` rides along so a tree op never has to read the metadata entry.
struct GroupRosterToEncryptV5 {
    core::ModuleInternalMetaV5 internalMeta;
    core::DataIntegrityObject dio;
    dynamic::MembershipBlock membership;
};

struct DecryptedGroupRosterV5 : public core::DecryptedVersionedData {
    core::ModuleInternalMetaV5 internalMeta;
    std::string authorPubKey;
    core::DataIntegrityObject dio;
    dynamic::MembershipBlock membership;
};

// The public metadata plane, written only by `updateGroupPublicMeta`. No `internalMeta`: the module's own
// identity is read from the roster head, which is the only place anything reads it from.
struct GroupPublicMetaToEncryptV5 {
    core::Buffer publicMeta;
    core::DataIntegrityObject dio;
    dynamic::MetaBlock meta;
    /**
     * The suite this plane's DIO checksums are computed with.
     *
     * Carried here rather than taken from a key, because the public plane is signed and not
     * encrypted, so no `EncKey` reaches this far — it is the one place in the group where the
     * suite has no other way in. Callers pass the group's own key's suite, so both planes of a
     * group are checksummed alike.
     *
     * Deliberately without a default: `CryptoSuite` has no default constructor, so a call site
     * that forgets it fails to compile instead of quietly falling back to this build's choice.
     */
    core::CryptoSuite suite;
};

struct DecryptedGroupPublicMetaV5 : public core::DecryptedVersionedData {
    core::Buffer publicMeta;
    std::string authorPubKey;
    core::DataIntegrityObject dio;
    dynamic::MetaBlock meta;
};

// The private metadata plane, written only by `updateGroupPrivateMeta`.
struct GroupPrivateMetaToEncryptV5 {
    core::Buffer privateMeta;
    core::DataIntegrityObject dio;
    dynamic::MetaBlock meta;
};

struct DecryptedGroupPrivateMetaV5 : public core::DecryptedVersionedData {
    core::Buffer privateMeta;
    std::string authorPubKey;
    core::DataIntegrityObject dio;
    dynamic::MetaBlock meta;
};

} // namespace group
} // namespace endpoint
} // namespace privmx

#endif // _PRIVMXLIB_ENDPOINT_GROUP_ENCRYPTORS_GROUP_TYPES_HPP_
