/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_ENDPOINT_CORE_DATAENCRYPTORV4_HPP_
#define _PRIVMXLIB_ENDPOINT_CORE_DATAENCRYPTORV4_HPP_

#include "privmx/crypto/ecc/PrivateKey.hpp"
#include "privmx/crypto/ecc/PublicKey.hpp"
#include "privmx/endpoint/core/Buffer.hpp"
#include "privmx/endpoint/core/encryptors/DataInnerEncryptorV4.hpp"

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
