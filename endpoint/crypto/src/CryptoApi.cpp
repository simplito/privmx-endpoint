#include "privmx/endpoint/crypto/CryptoApi.hpp"
#include "privmx/endpoint/crypto/CryptoApiImpl.hpp"

using namespace privmx::endpoint;
using namespace privmx::endpoint::crypto;

CryptoApi CryptoApi::create() {
    std::shared_ptr<CryptoApiImpl> impl(new CryptoApiImpl());
    return CryptoApi(impl);
}

CryptoApi::CryptoApi(const std::shared_ptr<CryptoApiImpl>& impl) : _impl(impl) {}

core::Buffer CryptoApi::signData(const core::Buffer& data, const std::string& privateKey) {
    return _impl->signData(data, privateKey);
}

bool CryptoApi::verifySignature(const core::Buffer& data, const core::Buffer& signature, const std::string& publicKey) {
    return _impl->verifySignature(data, signature, publicKey);
}

std::string CryptoApi::generatePrivateKey(const std::optional<std::string>& randomSeed) {
    return _impl->generatePrivateKey(randomSeed);
}

std::string CryptoApi::derivePrivateKey(const std::string& password, const std::string& salt) {
    return _impl->derivePrivateKey(password, salt);
}

std::string CryptoApi::derivePublicKey(const std::string& privateKey) {
    return _impl->derivePublicKey(privateKey);
}

core::Buffer CryptoApi::generateKeySymmetric() {
    return _impl->generateKeySymmetric();
}

core::Buffer CryptoApi::encryptDataSymmetric(const core::Buffer& data, const core::Buffer& symmetricKey) {
    return _impl->encryptDataSymmetric(data, symmetricKey);
}

core::Buffer CryptoApi::decryptDataSymmetric(const core::Buffer& data, const core::Buffer& symmetricKey) {
    return _impl->decryptDataSymmetric(data, symmetricKey);
}

std::string CryptoApi::convertPEMKeytoWIFKey(const std::string& pemKey) {
    return _impl->convertPEMKeytoWIFKey(pemKey);
}
