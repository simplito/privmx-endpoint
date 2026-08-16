/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_CRYPTOSERVICE_ECCIMPL_ECDHE_HPP_
#define _PRIVMXLIB_CRYPTOSERVICE_ECCIMPL_ECDHE_HPP_

#include <memory>
#include <string>

#include <Poco/Types.h>

#include "ECC.hpp"
#include "PublicKey.hpp"
#include "PrivateKey.hpp"

namespace privmx {
namespace cryptoservice {
namespace ecc {

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
 
} // ecc
} // cryptoservice
} // privmx

#endif // _PRIVMXLIB_CRYPTOSERVICE_ECCIMPL_ECDHE_HPP_