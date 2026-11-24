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
 * @brief `privmx::crypto::CryptoService` backed by pmx-crypto instead of `privmxdrvcrypto`.
 *
 * The API above this class does not change, which is the point: `rpc/`, `privfs/` and the parts of
 * `endpoint/` still on the legacy stack keep compiling untouched, while the driver underneath is
 * gone. That makes the primitives the first half of the crypto migration that can land on its own.
 *
 * Of the 28 methods, only 16 ever reached the driver; the remaining 12 are composition over those
 * (`kdf` and `prf_tls12` over HMAC, the `ct*` framings over CBC, `hash160` over sha256+ripemd160).
 * Those are copied from the driver implementation **unchanged** — they are backend-independent by
 * construction, and rewriting them would risk the byte-for-byte compatibility this whole class
 * exists to preserve. Every one of them is a wire format the bridge also implements.
 *
 * pmx-crypto's own primitives are not reimplemented either: `Aes256CbcHmac` and the PBKDF2 hash
 * selection exist there, but this class deliberately keeps using the *legacy* compositions so the
 * output stays identical to what the driver produced. Swapping those is a separate, observable
 * change; this one is meant to be invisible.
 */
class CryptoService : public privmx::crypto::CryptoService
{
public:
    std::string randomBytes(size_t length) const override;
    std::string hmacSha1(const std::string& key, const std::string& data) const override;
    std::string hmacSha256(const std::string& key, const std::string& data) const override;
    std::string hmacSha512(const std::string& key, const std::string& data) const override;
    std::string sha1(const std::string& data) const override;
    std::string sha256(const std::string& data) const override;
    std::string sha512(const std::string& data) const override;
    std::string ripemd160(const std::string& data) const override;
    std::string hash160(const std::string& data) const override;
    std::string aes256EcbEncrypt(const std::string& data, const std::string& key) const override;
    std::string aes256EcbDecrypt(const std::string& data, const std::string& key) const override;
    std::string aes256CbcPkcs7Encrypt(const std::string& data, const std::string& key, const std::string& iv)
        const override;
    std::string aes256CbcPkcs7Decrypt(const std::string& data, const std::string& key, const std::string& iv)
        const override;
    std::string aes256CbcNoPadEncrypt(const std::string& data, const std::string& key, const std::string& iv)
        const override;
    std::string aes256CbcNoPadDecrypt(const std::string& data, const std::string& key, const std::string& iv)
        const override;
    std::string aes256GcmEncrypt(
        const std::string& data,
        const std::string& key,
        const std::string& iv,
        const std::string& aad
    ) const override;
    std::string aes256GcmDecrypt(
        const std::string& data,
        const std::string& key,
        const std::string& iv,
        const std::string& aad
    ) const override;
    std::string prf_tls12(const std::string& key, const std::string& seed, size_t length) const override;
    std::string kdf(size_t length, const std::string& key, const std::string& label) const override;
    std::string generateIv(const std::string& key, Poco::Int32 idx) const override;
    std::tuple<std::string, std::string> getKEM(const std::string& key, size_t kelen = 32, size_t kmlen = 32)
        const override;
    std::string aes256CbcHmac256Encrypt(std::string data, const std::string& key32, std::string iv, size_t taglen = 16)
        const override;
    std::string aes256CbcHmac256Decrypt(std::string data, const std::string& key32, size_t taglen = 16) const override;
    std::string ctAes256CbcPkcs7NoIv(const std::string& data, const std::string& key, const std::string& iv)
        const override;
    std::string ctAes256CbcPkcs7WithIv(const std::string& data, const std::string& key, const std::string& iv)
        const override;
    std::string ctAes256CbcPkcs7WithIvAndHmacSha256(
        const std::string& data,
        const std::string& key,
        const std::string& iv,
        size_t taglen = 16
    ) const override;
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
