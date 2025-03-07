/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include "privmx/endpoint/core/encryptors/DataEncryptorV4.hpp"

using namespace privmx::endpoint;
using namespace privmx::endpoint::core;

std::string DataEncryptorV4::signAndEncode(const core::Buffer& data, const crypto::PrivateKey& authorPrivateKey) {
    auto signedData = _innerEncryptor.signAndPackDataWithSignature(data, authorPrivateKey);
    return _innerEncryptor.encode(signedData);
}

std::string DataEncryptorV4::signAndEncryptAndEncode(const core::Buffer& data,
                                                     const crypto::PrivateKey& authorPrivateKey,
                                                     const std::string& encryptionKey) {
    auto signedData = _innerEncryptor.signAndPackDataWithSignature(data, authorPrivateKey);
    auto encrypted = _innerEncryptor.encrypt(signedData, encryptionKey);
    return _innerEncryptor.encode(encrypted);
}

core::Buffer DataEncryptorV4::decodeAndVerify(const std::string& publicDataAsBase64,
                                              const crypto::PublicKey& authorPublicKey) {
    auto decoded = _innerEncryptor.decode(publicDataAsBase64);
    return _innerEncryptor.verifyAndExtractData(decoded, authorPublicKey);
}

core::Buffer DataEncryptorV4::decodeAndDecryptAndVerify(const std::string& privateDataAsBase64,
                                                        const crypto::PublicKey& authorPublicKey,
                                                        const std::string& encryptionKey) {
    auto decoded = _innerEncryptor.decode(privateDataAsBase64);
    auto decrypted = _innerEncryptor.decrypt(decoded, encryptionKey);
    return _innerEncryptor.verifyAndExtractData(decrypted, authorPublicKey);
}
