
/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include "privmx/endpoint/core/encryptors/EncKey/EncKeyEncryptorV1.hpp"
#include <privmx/endpoint/core/crypto/Ecies.hpp>

using namespace privmx::endpoint::core;

std::string EncKeyEncryptorV1::decrypt(
    const std::string& encryptedEncKey,
    const core::PrivateKey& decryptionKey
) {
    return core::Ecies::decryptFromBase64(decryptionKey, encryptedEncKey);
}
