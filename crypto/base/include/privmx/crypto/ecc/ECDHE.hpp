/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_CRYPTO_ECDHE_HPP_
#define _PRIVMXLIB_CRYPTO_ECDHE_HPP_

#include <string>

#include <privmx/crypto/ecc/PrivateKey.hpp>
#include <privmx/crypto/ecc/PublicKey.hpp>

namespace privmx {
namespace crypto {

class ECDHE
{
public:
    ECDHE(const PrivateKey& private_key, const PublicKey& public_key);
    std::string getSecret() const;

private:
    std::string _secret;
};

inline std::string ECDHE::getSecret() const {
    return _secret;
}

} // crypto
} // privmx

#endif // _PRIVMXLIB_CRYPTO_ECDHE_HPP_
