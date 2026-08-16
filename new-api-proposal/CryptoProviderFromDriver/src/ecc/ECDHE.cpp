/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

// #include <functional>
// #include <memory>
#include <string>
// #include <openssl/bn.h>
// #include <Poco/SharedPtr.h>

#include "Utils.hpp"
#include "ECDHE.hpp"

namespace privmx {
namespace cryptoservice {
namespace ecc {

ECDHE::ECDHE(const PrivateKey& private_key, const PublicKey& public_key) {
    std::string secret = private_key.derive(public_key);
    _secret = Utils::fillTo32(secret);
}

} // ecc
} // cryptoservice
} // privmx