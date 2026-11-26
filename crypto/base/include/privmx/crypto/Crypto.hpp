/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_CRYPTO_CRYPTO_HPP_
#define _PRIVMXLIB_CRYPTO_CRYPTO_HPP_

#include <string>

#include <privmx/crypto/CryptoEnv.hpp>

namespace privmx {
namespace crypto {

/**
 * The primitives the old stack still needs, and only those.
 *
 * This is not a general-purpose crypto facade. Everything here has a caller in `rpc/`, `privfs/` or
 * the part of `endpoint/` not yet on `core::CryptoSuite`; anything that lost its last caller has been
 * removed rather than kept available, because an unused primitive is one someone reaches for later
 * without asking which format it belongs to. New code uses `core::CryptoSuite` and `core::FormatHash`.
 *
 * What went, and why it is not coming back by accident:
 *   - `sha1`, `sha512`, `ripemd160`, `hmacSha1`, `hmacSha512` — no callers. `hash160` still hashes a
 *     digest of a digest, it just does it inside `CryptoService` now.
 *   - `aes256Gcm*` — no callers; GCM is reached through `core::CryptoSuite`.
 *   - `aes256Ecb*` — replaced by `aes256CbcNoPad*`. Its one caller encrypts a single 16-byte block
 *     (the rpc frame header), and for one block CBC with an all-zero IV is the same bytes: CBC is
 *     `E(P xor IV)`, so a zero IV leaves `E(P)`. The wire format is unchanged and ECB — whose whole
 *     problem is that equal blocks encrypt equal — is out of the library.
 *   - `kdf`, `getKEM`, `generateIv` — no callers. The KDF construction itself is alive and on the
 *     wire through `core::FormatHash::kdf`, which `FormatHashVectorsTest` pins.
 *   - the encrypting half of the legacy frame (`aes256CbcHmac256Encrypt`, the three `ct*` framings
 *     and `CryptoPrivmx::privmxEncrypt`) — nothing writes that format any more. The decrypting half
 *     stays, because callers still hold bytes written by 2.x.
 */
class Crypto
{
public:
    static std::string randomBytes(size_t length);
    static std::string hmacSha256(const std::string& key, const std::string& data);
    static std::string sha256(const std::string& data);
    static std::string hash160(const std::string& data);
    static std::string aes256CbcNoPadEncrypt(const std::string& data, const std::string& key, const std::string& iv);
    static std::string aes256CbcNoPadDecrypt(const std::string& data, const std::string& key, const std::string& iv);
    static std::string aes256CbcPkcs7Encrypt(const std::string& data, const std::string& key, const std::string& iv);
    static std::string aes256CbcPkcs7Decrypt(const std::string& data, const std::string& key, const std::string& iv);
    static std::string prf_tls12(const std::string& key, const std::string& seed, size_t length);
    static std::string pbkdf2(const std::string& password, const std::string& salt, size_t rounds, size_t length, const std::string& algorithm);
    static std::string aes256CbcHmac256Decrypt(std::string data, const std::string& key32, size_t taglen = 16);
    static std::string ctDecrypt(const std::string& data, const std::string& key32, const std::string& iv16, size_t taglen = 16, const std::string& key16 = std::string());
};

inline std::string Crypto::randomBytes(size_t length) {
    auto crypto_service = CryptoEnv::getEnv()->getCryptoService();
    return crypto_service->randomBytes(length);
}

inline std::string Crypto::hmacSha256(const std::string& key, const std::string& data) {
    auto crypto_service = CryptoEnv::getEnv()->getCryptoService();
    return crypto_service->hmacSha256(key, data);
}

inline std::string Crypto::sha256(const std::string& data) {
    auto crypto_service = CryptoEnv::getEnv()->getCryptoService();
    return crypto_service->sha256(data);
}

inline std::string Crypto::hash160(const std::string& data) {
    auto crypto_service = CryptoEnv::getEnv()->getCryptoService();
    return crypto_service->hash160(data);
}

inline std::string Crypto::aes256CbcNoPadEncrypt(const std::string& data, const std::string& key, const std::string& iv) {
    auto crypto_service = CryptoEnv::getEnv()->getCryptoService();
    return crypto_service->aes256CbcNoPadEncrypt(data, key, iv);
}

inline std::string Crypto::aes256CbcNoPadDecrypt(const std::string& data, const std::string& key, const std::string& iv) {
    auto crypto_service = CryptoEnv::getEnv()->getCryptoService();
    return crypto_service->aes256CbcNoPadDecrypt(data, key, iv);
}

inline std::string Crypto::aes256CbcPkcs7Encrypt(const std::string& data, const std::string& key, const std::string& iv) {
    auto crypto_service = CryptoEnv::getEnv()->getCryptoService();
    return crypto_service->aes256CbcPkcs7Encrypt(data, key, iv);
}

inline std::string Crypto::aes256CbcPkcs7Decrypt(const std::string& data, const std::string& key, const std::string& iv) {
    auto crypto_service = CryptoEnv::getEnv()->getCryptoService();
    return crypto_service->aes256CbcPkcs7Decrypt(data, key, iv);
}

inline std::string Crypto::prf_tls12(const std::string& key, const std::string& seed, size_t length) {
    auto crypto_service = CryptoEnv::getEnv()->getCryptoService();
    return crypto_service->prf_tls12(key, seed, length);
}

inline std::string Crypto::pbkdf2(const std::string& password, const std::string& salt, size_t rounds, size_t length, const std::string& algorithm) {
    auto crypto_service = CryptoEnv::getEnv()->getCryptoService();
    return crypto_service->pbkdf2(password, salt, rounds, length, algorithm);
}

inline std::string Crypto::aes256CbcHmac256Decrypt(std::string data, const std::string& key32, size_t taglen) {
    auto crypto_service = CryptoEnv::getEnv()->getCryptoService();
    return crypto_service->aes256CbcHmac256Decrypt(data, key32, taglen);
}

inline std::string Crypto::ctDecrypt(const std::string& data, const std::string& key32, const std::string& iv16, size_t taglen, const std::string& key16) {
    auto crypto_service = CryptoEnv::getEnv()->getCryptoService();
    return crypto_service->ctDecrypt(data, key32, iv16, taglen, key16);
}

} // crypto
} // privmx

#endif // _PRIVMXLIB_CRYPTO_CRYPTO_HPP_
