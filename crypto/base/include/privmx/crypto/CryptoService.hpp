/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_CRYPTO_CRYPTOSERVICE_HPP_
#define _PRIVMXLIB_CRYPTO_CRYPTOSERVICE_HPP_

#include <tuple>
#include <string>
#include <Poco/SharedPtr.h>
#include <Poco/Types.h>

namespace privmx {
namespace crypto {

class CryptoService
{
public:
    using Ptr = Poco::SharedPtr<CryptoService>;

    virtual ~CryptoService() = default;
    virtual std::string randomBytes(size_t length) const  = 0;
    virtual std::string hmacSha256(const std::string& key, const std::string& data) const  = 0;
    virtual std::string sha256(const std::string& data) const  = 0;
    virtual std::string aes256CbcNoPadEncrypt(const std::string& data, const std::string& key, const std::string& iv) const  = 0;
    virtual std::string aes256CbcNoPadDecrypt(const std::string& data, const std::string& key, const std::string& iv) const  = 0;
    virtual std::string aes256CbcPkcs7Encrypt(const std::string& data, const std::string& key, const std::string& iv) const  = 0;
    virtual std::string aes256CbcPkcs7Decrypt(const std::string& data, const std::string& key, const std::string& iv) const  = 0;
    virtual std::string prf_tls12(const std::string& key, const std::string& seed, size_t length) const  = 0;
    virtual std::string aes256CbcHmac256Decrypt(std::string data, const std::string& key32, size_t taglen = 16) const  = 0;
    virtual std::string pbkdf2(const std::string& password, const std::string& salt, const int32_t rounds, const size_t length, const std::string& hash) const = 0;
};

} // crypto
} // privmx

#endif // _PRIVMXLIB_CRYPTO_CRYPTOSERVICE_HPP_
