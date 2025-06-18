/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_ENDPOINT_CORE_ENCRYPTORS_MODULE_MODULEDATAENCRYPTORV4_HPP
#define _PRIVMXLIB_ENDPOINT_CORE_ENCRYPTORS_MODULE_MODULEDATAENCRYPTORV4_HPP

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

class ModuleDataEncryptorV4 {
public:
    dynamic::EncryptedModuleDataV4 encrypt(const ModuleDataToEncryptV4& moduleData,
                                        const crypto::PrivateKey& authorPrivateKey,
                                        const std::string& encryptionKey);
    DecryptedModuleDataV4 decrypt(const dynamic::EncryptedModuleDataV4& encryptedModuleData,
                                const std::string& encryptionKey);

private:
    void validateVersion(const dynamic::EncryptedModuleDataV4& encryptedModuleData);

    core::DataEncryptorV4 _dataEncryptor;
};


}  // namespace core
}  // namespace endpoint
}  // namespace privmx

#endif  // _PRIVMXLIB_ENDPOINT_CORE_ENCRYPTORS_MODULE_MODULEDATAENCRYPTORV4_HPP
