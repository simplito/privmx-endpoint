/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_ENDPOINT_CORE_ENCRYPTORS_MODULE_MODULEDATAENCRYPTORV5_HPP
#define _PRIVMXLIB_ENDPOINT_CORE_ENCRYPTORS_MODULE_MODULEDATAENCRYPTORV5_HPP

#include <privmx/endpoint/core/CoreTypes.hpp>
#include <privmx/endpoint/core/encryptors/DataEncryptorV4.hpp>
#include <privmx/endpoint/core/encryptors/DIO/DIOEncryptorV1.hpp>
#include <privmx/endpoint/core/encryptors/module/Types.hpp>
#include <privmx/endpoint/core/encryptors/module/DynamicTypes.hpp>
#include <privmx/endpoint/core/encryptors/module/Constants.hpp>
#include <privmx/endpoint/core/encryptors/DataEncryptorV4.hpp>
#include <privmx/endpoint/core/ServerTypes.hpp>
#include <privmx/endpoint/core/Types.hpp>

namespace privmx {
namespace endpoint {
namespace core {

class ModuleDataEncryptorV5 {
public:
    dynamic::EncryptedModuleDataV5 encrypt(
        const ModuleDataToEncryptV5& kvdbData,
        const crypto::PrivateKey& authorPrivateKey,
        const std::string& encryptionKey
    );
    DecryptedModuleDataV5 decrypt(const dynamic::EncryptedModuleDataV5& encryptedModuleData, const std::string& encryptionKey);
    DecryptedModuleDataV5 extractPublic(const dynamic::EncryptedModuleDataV5& encryptedModuleData);
    core::DataIntegrityObject getDIOAndAssertIntegrity(const dynamic::EncryptedModuleDataV5& encryptedModuleData);
private:
    void assertDataFormat(const dynamic::EncryptedModuleDataV5& encryptedModuleData);
    core::DataEncryptorV4 _dataEncryptor;
    core::DIOEncryptorV1 _DIOEncryptor;
};

}  // namespace core
}  // namespace endpoint
}  // namespace privmx

#endif  // _PRIVMXLIB_ENDPOINT_CORE_ENCRYPTORS_MODULE_MODULEDATAENCRYPTORV5_HPP
