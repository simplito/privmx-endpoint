/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_CRYPTO_CRYPTOPRIVMX_HPP_
#define _PRIVMXLIB_CRYPTO_CRYPTOPRIVMX_HPP_

#include <string>

namespace privmx {
namespace crypto {

struct PrivmxEncryptOptions
{
    enum {
        AES_256_CBC,
        XTEA_ECB
    } algorithm;
    bool attachIv = false;
    enum {
        NO_HMAC,
        SHA_256
    } hmac = NO_HMAC;
    bool deterministic = false;
    size_t taglen = 16;
};

class CryptoPrivmx
{
public:
    static const PrivmxEncryptOptions& privmxOptAesWithSignature();
    static const PrivmxEncryptOptions& privmxOptAesWithDettachedIv();
    static const PrivmxEncryptOptions& privmxOptAesWithAttachedIv();
    static int privmxGetBlockSize(const PrivmxEncryptOptions& options, int block_size);
    static std::string privmxEncrypt(const PrivmxEncryptOptions& options, const std::string& data, const std::string& key, std::string iv = std::string());
    static std::string privmxDecrypt(bool is_signed, const std::string& data, const std::string& key32, const std::string& iv16 = std::string(), size_t taglen = 16);
    static std::string privmxDecrypt(const std::string& data, const std::string& key32, const std::string& iv16 = std::string(), size_t taglen = 16);
};

inline const PrivmxEncryptOptions& CryptoPrivmx::privmxOptAesWithSignature() {
    static const PrivmxEncryptOptions options{PrivmxEncryptOptions::AES_256_CBC, true, PrivmxEncryptOptions::SHA_256};
    return options;
}

inline const PrivmxEncryptOptions& CryptoPrivmx::privmxOptAesWithDettachedIv() {
    static const PrivmxEncryptOptions options{PrivmxEncryptOptions::AES_256_CBC};
    return options;
}

inline const PrivmxEncryptOptions& CryptoPrivmx::privmxOptAesWithAttachedIv() {
    static const PrivmxEncryptOptions options{PrivmxEncryptOptions::AES_256_CBC, true};
    return options;
}

} // crypto
} // privmx

#endif // _PRIVMXLIB_CRYPTO_CRYPTOPRIVMX_HPP_
