/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_ENDPOINT_CORE_DATAINNERENCRYPTORV4_HPP_
#define _PRIVMXLIB_ENDPOINT_CORE_DATAINNERENCRYPTORV4_HPP_

#include "privmx/crypto/ecc/PrivateKey.hpp"
#include "privmx/crypto/ecc/PublicKey.hpp"
#include "privmx/endpoint/core/Buffer.hpp"

namespace privmx {
namespace endpoint {
namespace core {

class DataInnerEncryptorV4 {
public:
    struct DataWithSignature {
        core::Buffer signature;
        core::Buffer data;
    };

    std::string encode(const core::Buffer& data);
    core::Buffer decode(const std::string& dataAsBase64);
    core::Buffer encrypt(const core::Buffer& data, const std::string& encryptionKey);
    core::Buffer decrypt(const core::Buffer& privateData, const std::string& encryptionKey);
    core::Buffer signAndPackDataWithSignature(const core::Buffer& data, const crypto::PrivateKey& authorPrivateKey);
    core::Buffer verifyAndExtractData(const core::Buffer& signedData, const crypto::PublicKey& authorPublicKey);
    
    DataWithSignature extractDataWithSignature(const core::Buffer& signedData);
    bool verifySignature(const DataWithSignature& dataWithSignature, const crypto::PublicKey& authorPublicKey);
private:
    DataWithSignature sign(const core::Buffer& data, const crypto::PrivateKey& authorPrivateKey);
    core::Buffer packDataWithSignature(const DataWithSignature& dataWithSignature);
};

}  // namespace core
}  // namespace endpoint
}  // namespace privmx

#endif  // _PRIVMXLIB_ENDPOINT_CORE_DATAINNERENCRYPTORV4_HPP_
