/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_CRYPTOSERVICE_ECCIMPL_ECIESENCRYPTOR_HPP_
#define _PRIVMXLIB_CRYPTOSERVICE_ECCIMPL_ECIESENCRYPTOR_HPP_

// #include <Poco/Types.h>
#include <string>
#include <optional>
#include <Poco/Dynamic/Var.h>
#include <Poco/JSON/Object.h>

#include "PublicKey.hpp"
#include "PrivateKey.hpp"


namespace privmx {
namespace cryptoservice {
namespace ecc {

class EciesEncryptor
{
public:
    // to move to PrivateKey class:
    static Poco::JSON::Object::Ptr decryptObjectFromBase64(const PrivateKey& priv, const std::string& cipher_base64, const std::optional<PublicKey>& pubOfSignature = std::nullopt);
    static std::string decryptFromBase64(const PrivateKey& priv, const std::string& cipher_base64, const std::optional<PublicKey>& pubOfSignature = std::nullopt);
    static std::string decrypt(const PrivateKey& priv, const std::string& cipher, const std::optional<PublicKey>& pubOfSignature = std::nullopt);
    static std::string decryptV0(const PrivateKey& priv, const PublicKey& pub, const std::string& cipher);
    
    // to move to PublicKey class:
    static std::string encryptObjectToBase64(const PublicKey& pub, Poco::JSON::Object::Ptr data, const PrivateKey& privForSignature);
    static std::string encryptToBase64(const PublicKey& pub, const std::string& data, const PrivateKey& privForSignature);
    static std::string encrypt(const PublicKey& pub, const std::string& data, const PrivateKey& privForSignature);
};

} // ecc
} // cryptoservice
} // privmx

#endif // _PRIVMXLIB_CRYPTOSERVICE_ECCIMPL_ECIESENCRYPTOR_HPP_