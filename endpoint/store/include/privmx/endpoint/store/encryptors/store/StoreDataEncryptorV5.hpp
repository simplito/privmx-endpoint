/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_ENDPOINT_STORE_STOREDATAENCRYPTORV5_HPP_
#define _PRIVMXLIB_ENDPOINT_STORE_STOREDATAENCRYPTORV5_HPP_

#include <privmx/endpoint/core/CoreTypes.hpp>
#include <privmx/endpoint/core/encryptors/DataEncryptorV4.hpp>
#include <privmx/endpoint/core/encryptors/DIO/DIOEncryptorV1.hpp>
#include <privmx/endpoint/core/ServerTypes.hpp>
#include <privmx/endpoint/core/Types.hpp>
#include "privmx/endpoint/store/StoreTypes.hpp"
#include "privmx/endpoint/store/ServerTypes.hpp"

namespace privmx {
namespace endpoint {
namespace store {

class StoreDataEncryptorV5 {
public:
    server::EncryptedStoreDataV5 encrypt(const StoreDataToEncryptV5& storeData,
                                        const crypto::PrivateKey& authorPrivateKey,
                                        const std::string& encryptionKey);
    DecryptedStoreDataV5 decrypt(const server::EncryptedStoreDataV5& encryptedStoreData,
                                const std::string& encryptionKey);
    core::DataIntegrityObject getDIOAndAssertIntegrity(const server::EncryptedStoreDataV5& encryptedStoreData);
private:
    void assertDataFormat(const server::EncryptedStoreDataV5& encryptedStoreData);

    core::DataEncryptorV4 _dataEncryptor;
    core::DIOEncryptorV1 _DIOEncryptor;
};

}  // namespace store
}  // namespace endpoint
}  // namespace privmx

#endif  //_PRIVMXLIB_ENDPOINT_STORE_STOREDATAENCRYPTORV5_HPP_