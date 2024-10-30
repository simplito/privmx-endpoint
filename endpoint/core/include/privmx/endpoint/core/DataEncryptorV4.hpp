#ifndef _PRIVMXLIB_ENDPOINT_CORE_DATAENCRYPTORV4_HPP_
#define _PRIVMXLIB_ENDPOINT_CORE_DATAENCRYPTORV4_HPP_

#include "privmx/crypto/ecc/PrivateKey.hpp"
#include "privmx/crypto/ecc/PublicKey.hpp"
#include "privmx/endpoint/core/Buffer.hpp"
#include "privmx/endpoint/core/DataInnerEncryptorV4.hpp"

namespace privmx {
namespace endpoint {
namespace core {

class DataEncryptorV4 {
public:
    std::string signAndEncode(const core::Buffer& data, const crypto::PrivateKey& authorPrivateKey);
    std::string signAndEncryptAndEncode(const core::Buffer& data, const crypto::PrivateKey& authorPrivateKey,
                                        const std::string& encryptionKey);
    core::Buffer decodeAndVerify(const std::string& publicDataBase64, const crypto::PublicKey& authorPublicKey);
    core::Buffer decodeAndDecryptAndVerify(const std::string& privateDataBase64,
                                           const crypto::PublicKey& authorPublicKey, const std::string& encryptionKey);

private:
    DataInnerEncryptorV4 _innerEncryptor;
};

}  // namespace core
}  // namespace endpoint
}  // namespace privmx

#endif  // _PRIVMXLIB_ENDPOINT_CORE_DATAENCRYPTORV4_HPP_
