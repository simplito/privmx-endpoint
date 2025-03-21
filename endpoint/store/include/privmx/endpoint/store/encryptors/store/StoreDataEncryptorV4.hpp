/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_ENDPOINT_STORE_STOREDATAENCRYPTORV4_HPP_
#define _PRIVMXLIB_ENDPOINT_STORE_STOREDATAENCRYPTORV4_HPP_

#include <privmx/endpoint/core/CoreTypes.hpp>
#include <privmx/endpoint/core/encryptors/DataEncryptorV4.hpp>
#include <privmx/endpoint/core/ServerTypes.hpp>
#include <privmx/endpoint/core/Types.hpp>
#include "privmx/endpoint/store/StoreTypes.hpp"
#include "privmx/endpoint/store/ServerTypes.hpp"

namespace privmx {
namespace endpoint {
namespace store {

class StoreDataEncryptorV4 {
public:
    server::EncryptedStoreDataV4 encrypt(const StoreDataToEncryptV4& plainData,
                                        const crypto::PrivateKey& authorPrivateKey,
                                        const std::string& encryptionKey);
    DecryptedStoreDataV4 decrypt(const server::EncryptedStoreDataV4& encryptedData,
                                const std::string& encryptionKey);

private:
    void validateVersion(const server::EncryptedStoreDataV4& encryptedData);

    core::DataEncryptorV4 _dataEncryptor;
};

}  // namespace store
}  // namespace endpoint
}  // namespace privmx

#endif  //_PRIVMXLIB_ENDPOINT_STORE_STOREDATAENCRYPTORV4_HPP_