/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include "privmx/endpoint/crypto/CryptoApi.hpp"
#include "privmx/endpoint/core/Validator.hpp"
#include "privmx/endpoint/crypto/CryptoApiImpl.hpp"
#include <privmx/endpoint/core/SingletonsHolder.hpp>
#include <privmx/utils/Logger.hpp>

using namespace privmx::endpoint;
using namespace privmx::endpoint::crypto;

CryptoApi CryptoApi::create() {
    std::shared_ptr<CryptoApiImpl> impl(new CryptoApiImpl());
    return CryptoApi(impl);
}

CryptoApi::CryptoApi(const std::shared_ptr<CryptoApiImpl>& impl) : _impl(impl) {}

core::Buffer CryptoApi::signData(const core::Buffer& data, const std::string& privateKey) {
    core::Validator::validatePrivKeyWIF(privateKey, "field:privateKey ");
    return _impl->signData(data, privateKey);
}

bool CryptoApi::verifySignature(const core::Buffer& data, const core::Buffer& signature, const std::string& publicKey) {
    core::Validator::validatePubKeyBase58DER(publicKey, "field:publicKey ");
    core::Validator::validateSignature(signature.stdString(), "field:signature ");
    return _impl->verifySignature(data, signature, publicKey);
}

std::string CryptoApi::generatePrivateKey(const std::optional<std::string>& randomSeed) {
    return _impl->generatePrivateKey(randomSeed);
}

std::string CryptoApi::derivePrivateKey(const std::string& password, const std::string& salt) {
    return _impl->derivePrivateKey_deprecated(password, salt);
}

std::string CryptoApi::derivePrivateKey2(const std::string& password, const std::string& salt) {
    return _impl->derivePrivateKey(password, salt);
}

std::string CryptoApi::derivePublicKey(const std::string& privateKey) {
    core::Validator::validatePrivKeyWIF(privateKey, "field:privateKey ");
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

std::string CryptoApi::convertPGPAsn1KeyToBase58DERKey(const std::string& pgpKey) {
    return _impl->convertPGPAsn1KeyToBase58DERKey(pgpKey);
}

BIP39_t CryptoApi::generateBip39(std::size_t strength, const std::string& password) {
    return _impl->generateBip39(strength, password);
}

BIP39_t CryptoApi::fromMnemonic(const std::string& mnemonic, const std::string& password) {
    return _impl->fromMnemonic(mnemonic, password);
}

BIP39_t CryptoApi::fromEntropy(const core::Buffer& entropy, const std::string& password) {
    return _impl->fromEntropy(entropy, password);
}

std::string CryptoApi::entropyToMnemonic(const core::Buffer& entropy) {
    return _impl->entropyToMnemonic(entropy);
}

core::Buffer CryptoApi::mnemonicToEntropy(const std::string& mnemonic) {
    return _impl->mnemonicToEntropy(mnemonic);
}

core::Buffer CryptoApi::mnemonicToSeed(const std::string& mnemonic, const std::string& password) {
    return _impl->mnemonicToSeed(mnemonic, password);
}
