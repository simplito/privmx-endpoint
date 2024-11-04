/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_CRYPTO_ECIESENCRYPTOR_HPP_
#define _PRIVMXLIB_CRYPTO_ECIESENCRYPTOR_HPP_

#include <string>
#include <Poco/Dynamic/Var.h>
#include <Poco/JSON/Object.h>

#include <privmx/crypto/ecc/PrivateKey.hpp>
#include <privmx/crypto/ecc/PublicKey.hpp>


namespace privmx {
namespace crypto {

class EciesEncryptor
{
public:
    static Poco::JSON::Object::Ptr decryptObjectFromBase64(const PrivateKey& priv, const std::string& cipher_base64);
    static std::string decryptFromBase64(const PrivateKey& priv, const std::string& cipher_base64);
    static std::string decrypt(const PrivateKey& priv, const std::string& cipher);
    static std::string decryptV0(const PrivateKey& priv, const PublicKey& pub, const std::string& cipher);
    static std::string encryptObjectToBase64(const PublicKey& pub, Poco::JSON::Object::Ptr data);
    static std::string encryptToBase64(const PublicKey& pub, const std::string& data);
    static std::string encrypt(const PublicKey& pub, const std::string& data);
};

} // crypto
} // privmx

#endif // _PRIVMXLIB_CRYPTO_ECIESENCRYPTOR_HPP_
