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
    std::string encode(const core::Buffer& data);
    core::Buffer decode(const std::string& dataAsBase64);
    core::Buffer encrypt(const core::Buffer& data, const std::string& encryptionKey);
    core::Buffer decrypt(const core::Buffer& privateData, const std::string& encryptionKey);
    core::Buffer signAndPackDataWithSignature(const core::Buffer& data, const crypto::PrivateKey& authorPrivateKey);
    core::Buffer verifyAndExtractData(const core::Buffer& signedData, const crypto::PublicKey& authorPublicKey);

private:
    struct DataWithSignature {
        core::Buffer signature;
        core::Buffer data;
    };

    DataWithSignature sign(const core::Buffer& data, const crypto::PrivateKey& authorPrivateKey);
    core::Buffer packDataWithSignature(const DataWithSignature& dataWithSignature);
    DataWithSignature extractDataWithSignature(const core::Buffer& signedData);
    bool verifySignature(const DataWithSignature& dataWithSignature, const crypto::PublicKey& authorPublicKey);
};

}  // namespace core
}  // namespace endpoint
}  // namespace privmx

#endif  // _PRIVMXLIB_ENDPOINT_CORE_DATAINNERENCRYPTORV4_HPP_
