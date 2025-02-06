/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_ENDPOINT_CRYPTO_CRYPTOAPIIMPL_HPP_
#define _PRIVMXLIB_ENDPOINT_CRYPTO_CRYPTOAPIIMPL_HPP_

#include <memory>
#include <optional>
#include <string>

#include <privmx/crypto/ecc/PrivateKey.hpp>
#include "privmx/endpoint/core/Buffer.hpp"

namespace privmx {
namespace endpoint {
namespace crypto {

class CryptoApiImpl
{
public:
    core::Buffer signData(const core::Buffer& data, const std::string& key);
    bool verifySignature(const core::Buffer& data, const core::Buffer& signature, const std::string& key);
    std::string generatePrivateKey(const std::optional<std::string>& basestring);
    std::string derivePrivateKey_deprecated(const std::string& password, const std::string& salt);
    std::string derivePrivateKey(const std::string& password, const std::string& salt);
    std::string derivePublicKey(const std::string& privkey);
    core::Buffer generateKeySymmetric();
    core::Buffer encryptDataSymmetric(const core::Buffer& data, const core::Buffer& key);
    core::Buffer decryptDataSymmetric(const core::Buffer& data, const core::Buffer& key);
    std::string convertPEMKeytoWIFKey(const std::string& keyPEM);

private:
    privmx::crypto::PrivateKey getPrivKeyFromSeed(const std::string& seed, size_t rounds);
};

} // crypto
} // endpoint
} // privmx

#endif // _PRIVMXLIB_ENDPOINT_CRYPTO_CRYPTOAPIIMPL_HPP_
