#ifndef _PRIVMXLIB_ENDPOINT_STORE_STOREDATAENCRYPTORV4_HPP_
#define _PRIVMXLIB_ENDPOINT_STORE_STOREDATAENCRYPTORV4_HPP_

#include "privmx/endpoint/core/CoreTypes.hpp"
#include "privmx/endpoint/core/DataEncryptorV4.hpp"
#include "privmx/endpoint/core/ServerTypes.hpp"
#include "privmx/endpoint/core/Types.hpp"
#include "privmx/endpoint/store/StoreTypes.hpp"
#include "privmx/endpoint/store/ServerTypes.hpp"

namespace privmx {
namespace endpoint {
namespace store {

class StoreDataEncryptorV4 {
public:
    server::EncryptedStoreDataV4 encrypt(const StoreDataToEncrypt& plainData,
                                        const crypto::PrivateKey& authorPrivateKey,
                                        const std::string& encryptionKey);
    DecryptedStoreData decrypt(const server::EncryptedStoreDataV4& encryptedData,
                                const std::string& encryptionKey);

private:
    void validateVersion(const server::EncryptedStoreDataV4& encryptedData);

    core::DataEncryptorV4 _dataEncryptor;
};

}  // namespace store
}  // namespace endpoint
}  // namespace privmx

#endif  //_PRIVMXLIB_ENDPOINT_STORE_STOREDATAENCRYPTORV4_HPP_