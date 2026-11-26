/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_CRYPTO_PMXCRYPTO_CRYPTOSERVICE_HPP_
#define _PRIVMXLIB_CRYPTO_PMXCRYPTO_CRYPTOSERVICE_HPP_

#include <privmx/crypto/CryptoService.hpp>

namespace privmx {
namespace crypto {
namespace pmximpl {

/**
 * @brief `privmx::crypto::CryptoService` backed by pmx-crypto.
 *
 * The API above this class does not change, which is the point: `rpc/`, `privfs/` and the parts of
 * `endpoint/` still on the legacy stack keep compiling untouched, while the driver underneath is
 * gone. That makes the primitives the first half of the crypto migration that can land on its own.
 *
 * The surface is what the remaining callers use and nothing more — see `privmx::crypto::Crypto` for
 * what was removed once the SRP, key and session login paths went, and why an unused primitive is
 * worse than a missing one. Two compositions stay local because they are byte layout rather than
 * cryptography: `hash160` (a digest of a digest) and `ctDecrypt` (a one-byte cipher-type prefix).
 * `prf_tls12` and `aes256CbcHmac256Decrypt` are delegated to pmx-crypto, which implements the same
 * constructions; `CompositionVectorsTest` pins both against an independent model, which is what made
 * that delegation safe to do.
 */
class CryptoService : public privmx::crypto::CryptoService
{
public:
    std::string randomBytes(size_t length) const override;
    std::string hmacSha256(const std::string& key, const std::string& data) const override;
    std::string sha256(const std::string& data) const override;
    std::string aes256CbcNoPadEncrypt(const std::string& data, const std::string& key, const std::string& iv)
        const override;
    std::string aes256CbcNoPadDecrypt(const std::string& data, const std::string& key, const std::string& iv)
        const override;
    std::string aes256CbcPkcs7Encrypt(const std::string& data, const std::string& key, const std::string& iv)
        const override;
    std::string aes256CbcPkcs7Decrypt(const std::string& data, const std::string& key, const std::string& iv)
        const override;
    std::string prf_tls12(const std::string& key, const std::string& seed, size_t length) const override;
    std::string aes256CbcHmac256Decrypt(std::string data, const std::string& key32, size_t taglen = 16) const override;
    std::string ctDecrypt(
        const std::string& data,
        const std::string& key32,
        const std::string& iv16,
        size_t taglen = 16,
        const std::string& key16 = std::string()
    ) const override;
    std::string pbkdf2(
        const std::string& password,
        const std::string& salt,
        const int32_t rounds,
        const size_t length,
        const std::string& hash
    ) const override;
};

} // namespace pmximpl
} // namespace crypto
} // namespace privmx

#endif // _PRIVMXLIB_CRYPTO_PMXCRYPTO_CRYPTOSERVICE_HPP_
