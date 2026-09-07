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
 * Two envelopes, one per plane. Each checks only its own field checksums, so neither can be validated
 * against — or invalidated by — a field the other owns.
 *
 * The metadata half carries the unqualified names because `core::TypedDataSchemaStrategyV5` binds to them
 * and declares `decrypt` final; the roster half is driven straight from `GroupDataSchemaMapper`.
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

    dynamic::EncryptedGroupMetaV5 encrypt(
        const GroupMetaToEncryptV5& data,
        const privmx::crypto::PrivateKey& authorPrivateKey,
        const std::string& encryptionKey
    );
    DecryptedGroupMetaV5 decrypt(const dynamic::EncryptedGroupMetaV5& encryptedData, const std::string& encryptionKey);
    DecryptedGroupMetaV5 extractPublic(const dynamic::EncryptedGroupMetaV5& encryptedData);
    core::DataIntegrityObject getDIOAndAssertIntegrity(const dynamic::EncryptedGroupMetaV5& encryptedData);

private:
    void assertRosterFormat(const dynamic::EncryptedGroupRosterV5& encryptedData);
    void assertMetaFormat(const dynamic::EncryptedGroupMetaV5& encryptedData);
    core::DataEncryptorV4 _dataEncryptor;
    core::DIOEncryptorV1 _DIOEncryptor;
};

} // namespace group
} // namespace endpoint
} // namespace privmx

#endif // _PRIVMXLIB_ENDPOINT_GROUP_ENCRYPTORS_GROUP_GROUPDATAENCRYPTORV5_HPP_
