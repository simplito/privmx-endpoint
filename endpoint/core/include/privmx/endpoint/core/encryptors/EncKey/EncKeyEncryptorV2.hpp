/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_ENDPOINT_CORE_ENCKEYENCRYPTOR_V2_HPP
#define _PRIVMXLIB_ENDPOINT_CORE_ENCKEYENCRYPTOR_V2_HPP

#include "privmx/endpoint/core/CoreTypes.hpp"
#include "privmx/endpoint/core/ServerTypes.hpp"
#include "privmx/endpoint/core/Types.hpp"
#include "privmx/endpoint/core/encryptors/DIO/DIOEncryptorV1.hpp"
#include <privmx/crypto/ecc/PrivateKey.hpp>

namespace privmx {
namespace endpoint {
namespace core {

class EncKeyEncryptorV2 {
public:
    server::EncryptedKeyEntryDataV2 encrypt(const EncKeyV2ToEncrypt& key, 
        const privmx::crypto::PublicKey& encryptionKey, const crypto::PrivateKey& authorPrivateKey);
    DecryptedEncKeyV2 decrypt(const server::EncryptedKeyEntryDataV2& encryptedEncKey, const privmx::crypto::PrivateKey& decryptionKey);

private:
    void assertDataFormat(const server::EncryptedKeyEntryDataV2& encryptedEncKey);
    DIOEncryptorV1 _DIOEncryptor;
};

}  // namespace core
}  // namespace endpoint
}  // namespace privmx

#endif  // _PRIVMXLIB_ENDPOINT_CORE_ENCKEYENCRYPTOR_V2_HPP
