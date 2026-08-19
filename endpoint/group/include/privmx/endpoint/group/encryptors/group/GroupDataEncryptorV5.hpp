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

class GroupDataEncryptorV5 {
public:
    dynamic::EncryptedGroupDataV5 encrypt(
        const GroupDataToEncryptV5& data,
        const privmx::crypto::PrivateKey& authorPrivateKey,
        const std::string& encryptionKey
    );
    DecryptedGroupDataV5 decrypt(const dynamic::EncryptedGroupDataV5& encryptedData, const std::string& encryptionKey);
    DecryptedGroupDataV5 extractPublic(const dynamic::EncryptedGroupDataV5& encryptedData);
    core::DataIntegrityObject getDIOAndAssertIntegrity(const dynamic::EncryptedGroupDataV5& encryptedData);

private:
    void assertDataFormat(const dynamic::EncryptedGroupDataV5& encryptedData);
    core::DataEncryptorV4 _dataEncryptor;
    core::DIOEncryptorV1 _DIOEncryptor;
};

} // namespace group
} // namespace endpoint
} // namespace privmx

#endif // _PRIVMXLIB_ENDPOINT_GROUP_ENCRYPTORS_GROUP_GROUPDATAENCRYPTORV5_HPP_
