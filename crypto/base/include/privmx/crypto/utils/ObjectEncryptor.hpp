/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_CRYPTO_OBJECTENCRYPTOR_HPP_
#define _PRIVMXLIB_CRYPTO_OBJECTENCRYPTOR_HPP_

#include <string>

#include <Poco/SharedPtr.h>
#include <Poco/JSON/Object.h>

#include <privmx/crypto/CryptoPrivmx.hpp>

namespace privmx {
namespace crypto {

class ObjectEncryptor
{
public:
    using Ptr = Poco::SharedPtr<ObjectEncryptor>;

    ObjectEncryptor(const std::string& key, const PrivmxEncryptOptions& encrypt_options = CryptoPrivmx::privmxOptAesWithSignature(), bool signed_opt = true);
    std::string encrypt(Poco::JSON::Object::Ptr obj);
    Poco::JSON::Object::Ptr decrypt(const std::string& encrypted);
private:
    std::string _key;
    PrivmxEncryptOptions _encrypt_options;
    bool _signed;
};

} // crypto
} // privmx

#endif // _PRIVMXLIB_CRYPTO_OBJECTENCRYPTOR_HPP_
