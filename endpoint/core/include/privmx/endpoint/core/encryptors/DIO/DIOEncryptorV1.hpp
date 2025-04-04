/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_ENDPOINT_CORE_DIOENCRYPTOR_V1_HPP
#define _PRIVMXLIB_ENDPOINT_CORE_DIOENCRYPTOR_V1_HPP

#include <string>
#include <privmx/crypto/ecc/PublicKey.hpp>
#include <privmx/crypto/ecc/PrivateKey.hpp>
#include "privmx/endpoint/core/CoreTypes.hpp"
#include "privmx/endpoint/core/ServerTypes.hpp"
#include "privmx/endpoint/core/encryptors/DataInnerEncryptorV4.hpp"
namespace privmx {
namespace endpoint {
namespace core {

class DIOEncryptorV1 {
public:
    std::string signAndEncode(const core::ExpandedDataIntegrityObject& dio, const privmx::crypto::PrivateKey& autorKey);
    core::ExpandedDataIntegrityObject decodeAndVerify(const std::string& signedDio);
private:
    void assertDataFormat(const server::DataIntegrityObject& dioJSON);
    DataInnerEncryptorV4 _dataEncryptor;
};

}  // namespace core
}  // namespace endpoint
}  // namespace privmx

#endif  // _PRIVMXLIB_ENDPOINT_CORE_DIOENCRYPTOR_V1_HPP
