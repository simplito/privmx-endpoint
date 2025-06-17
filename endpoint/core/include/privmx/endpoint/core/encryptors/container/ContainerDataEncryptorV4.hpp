/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_ENDPOINT_CORE_ENCRYPTORS_CONTAINER_CONTAINERDATAENCRYPTORV4_HPP
#define _PRIVMXLIB_ENDPOINT_CORE_ENCRYPTORS_CONTAINER_CONTAINERDATAENCRYPTORV4_HPP

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

class ContainerDataEncryptorV4 {
public:
    dynamic::EncryptedContainerDataV4 encrypt(const ContainerDataToEncryptV4& containerData,
                                        const crypto::PrivateKey& authorPrivateKey,
                                        const std::string& encryptionKey);
    DecryptedContainerDataV4 decrypt(const dynamic::EncryptedContainerDataV4& encryptedContainerData,
                                const std::string& encryptionKey);

private:
    void validateVersion(const dynamic::EncryptedContainerDataV4& encryptedContainerData);

    core::DataEncryptorV4 _dataEncryptor;
};


}  // namespace container
}  // namespace core
}  // namespace endpoint
}  // namespace privmx

#endif  // _PRIVMXLIB_ENDPOINT_CORE_ENCRYPTORS_CONTAINER_CONTAINERDATAENCRYPTORV4_HPP
