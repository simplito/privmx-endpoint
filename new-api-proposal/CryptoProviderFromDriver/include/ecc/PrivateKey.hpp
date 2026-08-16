/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_CRYPTOSERVICE_ECCIMPL_PRIVATEKEY_HPP_
#define _PRIVMXLIB_CRYPTOSERVICE_ECCIMPL_PRIVATEKEY_HPP_

// #include <functional>
#include <memory>
#include <string>
#include <openssl/ec.h>

#include "ECC.hpp"
#include "PrivateKey.hpp"

namespace privmx {
namespace cryptoservice {
namespace ecc {

class PrivateKey
{
public:
    static PrivateKey fromWIF(const std::string& wif);
    static PrivateKey generateRandom();
    PrivateKey() {}
    PrivateKey(const ECC& key);
    PublicKey getPublicKey() const;
    std::string getPrivateEncKey() const;
    std::string signToCompactSignature(const std::string& message) const;
    std::string signToCompactSignatureWithHash(const std::string& message) const;
    std::string derive(const PublicKey& public_key) const;
    ECC getEccKey() const;
    std::string toWIF() const;

private:
    ECC _key;
};

inline PublicKey PrivateKey::getPublicKey() const {
    return PublicKey(_key);
}

inline ECC PrivateKey::getEccKey() const {
    return _key;
}


} // ecc
} // cryptoservice
} // privmx

#endif // _PRIVMXLIB_CRYPTOSERVICE_ECCIMPL_PRIVATEKEY_HPP_