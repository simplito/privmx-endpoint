/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_ENDPOINT_CORE_DATAENCRYPTORV4_HPP_
#define _PRIVMXLIB_ENDPOINT_CORE_DATAENCRYPTORV4_HPP_

#include "privmx/endpoint/core/crypto/PrivateKey.hpp"
#include "privmx/endpoint/core/crypto/PublicKey.hpp"
#include "privmx/endpoint/core/Buffer.hpp"
#include "privmx/endpoint/core/encryptors/DataInnerEncryptorV4.hpp"

namespace privmx {
namespace endpoint {
namespace core {

class DataEncryptorV4 {
public:
    std::string signAndEncode(const core::Buffer& data, const core::PrivateKey& authorPrivateKey);
    // Zapis bierze zestaw algorytmow z klucza, odczyt ze znacznika w ramce - stad asymetria
    // typow miedzy ta metoda a `decodeAndDecryptAndVerify`. Patrz `EncKey::suite`.
    std::string signAndEncryptAndEncode(
        const core::Buffer& data,
        const core::PrivateKey& authorPrivateKey,
        const core::EncKey& encryptionKey
    );
    core::Buffer decodeAndVerify(const std::string& publicDataBase64, const core::PublicKey& authorPublicKey);
    core::Buffer decodeAndDecryptAndVerify(
        const std::string& privateDataBase64,
        const core::PublicKey& authorPublicKey,
        const std::string& encryptionKey
    );

private:
    DataInnerEncryptorV4 _innerEncryptor;
};

} // namespace core
} // namespace endpoint
} // namespace privmx

#endif // _PRIVMXLIB_ENDPOINT_CORE_DATAENCRYPTORV4_HPP_
