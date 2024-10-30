#include "privmx/crypto/CryptoPrivmx.hpp"
#include "privmx/endpoint/core/CoreException.hpp"
#include "privmx/endpoint/core/DataInnerEncryptorV4.hpp"
#include "privmx/utils/Utils.hpp"

using namespace privmx::endpoint;
using namespace privmx::endpoint::core;

std::string DataInnerEncryptorV4::encode(const core::Buffer& data) { return utils::Base64::from(data.stdString()); }

core::Buffer DataInnerEncryptorV4::decode(const std::string& dataAsBase64) {
    auto decoded = utils::Base64::toString(dataAsBase64);
    return core::Buffer::from(decoded);
}

core::Buffer DataInnerEncryptorV4::encrypt(const core::Buffer& data, const std::string& encryptionKey) {
    auto encrypted = privmx::crypto::CryptoPrivmx::privmxEncrypt(
        privmx::crypto::CryptoPrivmx::privmxOptAesWithSignature(), data.stdString(), encryptionKey);
    return core::Buffer::from(encrypted);
}

core::Buffer DataInnerEncryptorV4::decrypt(const core::Buffer& privateData, const std::string& encryptionKey) {
    auto decrypted = privmx::crypto::CryptoPrivmx::privmxDecrypt(true, privateData.stdString(), encryptionKey);
    return core::Buffer::from(decrypted);
}

core::Buffer DataInnerEncryptorV4::signAndPackDataWithSignature(const core::Buffer& data,
                                                                const crypto::PrivateKey& authorPrivateKey) {
    auto dataWithSignature = sign(data, authorPrivateKey);
    return packDataWithSignature(dataWithSignature);
}

core::Buffer DataInnerEncryptorV4::verifyAndExtractData(const core::Buffer& signedData,
                                                        const crypto::PublicKey& authorPublicKey) {
    auto dataWithSignature = extractDataWithSignature(signedData);
    if (!verifySignature(dataWithSignature, authorPublicKey)) {
        throw InvalidDataSignatureException();
    }
    return dataWithSignature.data;
}

DataInnerEncryptorV4::DataWithSignature DataInnerEncryptorV4::sign(const core::Buffer& data,
                                                                   const crypto::PrivateKey& authorPrivateKey) {
    auto signature = authorPrivateKey.signToCompactSignatureWithHash(data.stdString());
    return DataWithSignature{.signature = core::Buffer::from(signature), .data = data};
}

core::Buffer DataInnerEncryptorV4::packDataWithSignature(const DataWithSignature& dataWithSignature) {
    auto packed = std::string(static_cast<std::size_t>(1), static_cast<char>(1))
                      .append(static_cast<std::size_t>(1), static_cast<char>(dataWithSignature.signature.size()))
                      .append(dataWithSignature.signature.stdString())
                      .append(dataWithSignature.data.stdString());
    return core::Buffer::from(packed);
}

DataInnerEncryptorV4::DataWithSignature DataInnerEncryptorV4::extractDataWithSignature(const core::Buffer& signedData) {
    const std::string& buf = signedData.stdString();
    if (buf[0] == 1) {
        size_t signatureLength = reinterpret_cast<const uint8_t&>(buf[1]);
        auto signature = buf.substr(2, signatureLength);
        auto data = buf.substr(2 + signatureLength);
        return DataWithSignature{.signature = core::Buffer::from(signature), .data = core::Buffer::from(data)};
    }
    throw UnsupportedTypeException();
}

bool DataInnerEncryptorV4::verifySignature(const DataWithSignature& dataWithSignature,
                                           const crypto::PublicKey& authorPublicKey) {
    return authorPublicKey.verifyCompactSignatureWithHash(dataWithSignature.data.stdString(),
                                                          dataWithSignature.signature.stdString());
}
