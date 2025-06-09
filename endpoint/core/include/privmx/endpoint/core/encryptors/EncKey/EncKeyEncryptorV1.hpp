/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_ENDPOINT_CORE_ENCKEYENCRYPTOR_V1_HPP
#define _PRIVMXLIB_ENDPOINT_CORE_ENCKEYENCRYPTOR_V1_HPP

#include <privmx/crypto/ecc/PublicKey.hpp>
#include <privmx/crypto/ecc/PrivateKey.hpp>
#include "privmx/endpoint/core/CoreTypes.hpp"
#include "privmx/endpoint/core/ServerTypes.hpp"
#include "privmx/endpoint/core/Types.hpp"
namespace privmx {
namespace endpoint {
namespace core {

class EncKeyEncryptorV1 {
public:
    std::string decrypt(const std::string& encryptedEncKey, const privmx::crypto::PrivateKey& decryptionKey);
};

}  // namespace core
}  // namespace endpoint
}  // namespace privmx

#endif  // _PRIVMXLIB_ENDPOINT_CORE_ENCKEYENCRYPTOR_V1_HPP
