/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_ENDPOINT_CORE_ENCRYPTORS_CONTAINER_CONTAINERDATAENCRYPTORV5_HPP
#define _PRIVMXLIB_ENDPOINT_CORE_ENCRYPTORS_CONTAINER_CONTAINERDATAENCRYPTORV5_HPP

#include <privmx/endpoint/core/CoreTypes.hpp>
#include <privmx/endpoint/core/encryptors/DataEncryptorV4.hpp>
#include <privmx/endpoint/core/encryptors/DIO/DIOEncryptorV1.hpp>
#include <privmx/endpoint/core/encryptors/container/Types.hpp>
#include <privmx/endpoint/core/encryptors/container/DynamicTypes.hpp>
#include <privmx/endpoint/core/encryptors/container/Constants.hpp>
#include <privmx/endpoint/core/encryptors/DataEncryptorV4.hpp>
#include <privmx/endpoint/core/ServerTypes.hpp>
#include <privmx/endpoint/core/Types.hpp>

namespace privmx {
namespace endpoint {
namespace core {
namespace container {

class ContainerDataEncryptorV5 {
public:
    dynamic::EncryptedContainerDataV5 encrypt(
        const ContainerDataToEncryptV5& kvdbData,
        const crypto::PrivateKey& authorPrivateKey,
        const std::string& encryptionKey
    );
    DecryptedContainerDataV5 decrypt(const dynamic::EncryptedContainerDataV5& encryptedContainerData, const std::string& encryptionKey);
    DecryptedContainerDataV5 extractPublic(const dynamic::EncryptedContainerDataV5& encryptedContainerData);
    core::DataIntegrityObject getDIOAndAssertIntegrity(const dynamic::EncryptedContainerDataV5& encryptedContainerData);
private:
    void assertDataFormat(const dynamic::EncryptedContainerDataV5& encryptedContainerData);
    core::DataEncryptorV4 _dataEncryptor;
    core::DIOEncryptorV1 _DIOEncryptor;
};

}  // namespace container
}  // namespace core
}  // namespace endpoint
}  // namespace privmx

#endif  // _PRIVMXLIB_ENDPOINT_CORE_ENCRYPTORS_CONTAINER_CONTAINERDATAENCRYPTORV5_HPP
