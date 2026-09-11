#ifndef _PRIVMXLIB_ENDPOINT_GROUP_ENCRYPTORS_GROUP_GROUPDATAENCRYPTORV5_HPP_
#define _PRIVMXLIB_ENDPOINT_GROUP_ENCRYPTORS_GROUP_GROUPDATAENCRYPTORV5_HPP_

#include <privmx/endpoint/core/CoreTypes.hpp>
#include <privmx/endpoint/core/encryptors/DIO/DIOEncryptorV1.hpp>
#include <privmx/endpoint/core/encryptors/DataEncryptorV4.hpp>
#include <privmx/endpoint/core/encryptors/module/Constants.hpp>

#include "privmx/endpoint/group/encryptors/group/DynamicTypes.hpp"
#include "privmx/endpoint/group/encryptors/group/Types.hpp"

namespace privmx {
namespace endpoint {
namespace group {

/**
 * Three envelopes, one per plane. Each checks only its own field checksums, so no plane can be validated
 * against — or invalidated by — a field another one owns. That is what lets the three be written separately,
 * and what makes the bridge's per-plane grant an enforceable one rather than a declarative one.
 *
 * All three are driven straight from `GroupDataSchemaMapper`: `core::TypedDataSchemaStrategyV5` routes one
 * envelope under one key and declares `decrypt` final, which cannot express two independently-keyed planes.
 */
class GroupDataEncryptorV5 {
public:
    dynamic::EncryptedGroupRosterV5 encryptRoster(
        const GroupRosterToEncryptV5& data,
        const privmx::crypto::PrivateKey& authorPrivateKey,
        const std::string& encryptionKey
    );
    DecryptedGroupRosterV5 decryptRoster(
        const dynamic::EncryptedGroupRosterV5& encryptedData,
        const std::string& encryptionKey
    );
    core::DataIntegrityObject getRosterDIOAndAssertIntegrity(const dynamic::EncryptedGroupRosterV5& encryptedData);

    // Takes no encryption key, and there is nothing for one to do: every field of the public plane is signed
    // and none is encrypted. What the key still decides is whether the entry is *attested* — that is the
    // `publicMetaTag` check in `GroupDataSchemaMapper`, and it is not optional for a caller that has the key.
    dynamic::EncryptedGroupPublicMetaV5 encryptPublicMeta(
        const GroupPublicMetaToEncryptV5& data,
        const privmx::crypto::PrivateKey& authorPrivateKey
    );
    DecryptedGroupPublicMetaV5 extractPublicMeta(const dynamic::EncryptedGroupPublicMetaV5& encryptedData);
    core::DataIntegrityObject getPublicMetaDIOAndAssertIntegrity(
        const dynamic::EncryptedGroupPublicMetaV5& encryptedData
    );

    dynamic::EncryptedGroupPrivateMetaV5 encryptPrivateMeta(
        const GroupPrivateMetaToEncryptV5& data,
        const privmx::crypto::PrivateKey& authorPrivateKey,
        const std::string& encryptionKey
    );
    DecryptedGroupPrivateMetaV5 decryptPrivateMeta(
        const dynamic::EncryptedGroupPrivateMetaV5& encryptedData,
        const std::string& encryptionKey
    );
    core::DataIntegrityObject getPrivateMetaDIOAndAssertIntegrity(
        const dynamic::EncryptedGroupPrivateMetaV5& encryptedData
    );

private:
    void assertRosterFormat(const dynamic::EncryptedGroupRosterV5& encryptedData);
    void assertPublicMetaFormat(const dynamic::EncryptedGroupPublicMetaV5& encryptedData);
    void assertPrivateMetaFormat(const dynamic::EncryptedGroupPrivateMetaV5& encryptedData);
    core::DataEncryptorV4 _dataEncryptor;
    core::DIOEncryptorV1 _DIOEncryptor;
};

} // namespace group
} // namespace endpoint
} // namespace privmx

#endif // _PRIVMXLIB_ENDPOINT_GROUP_ENCRYPTORS_GROUP_GROUPDATAENCRYPTORV5_HPP_
