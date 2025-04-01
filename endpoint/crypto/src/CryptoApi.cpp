/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include "privmx/endpoint/crypto/CryptoApi.hpp"
#include "privmx/endpoint/crypto/CryptoApiImpl.hpp"
#include "privmx/endpoint/core/Validator.hpp"
#include "privmx/endpoint/core/ExceptionConverter.hpp"

using namespace privmx::endpoint;
using namespace privmx::endpoint::crypto;

CryptoApi CryptoApi::create() {
    std::shared_ptr<CryptoApiImpl> impl(new CryptoApiImpl());
    return CryptoApi(impl);
}

CryptoApi::CryptoApi(const std::shared_ptr<CryptoApiImpl>& impl) : _impl(impl) {}

core::Buffer CryptoApi::signData(const core::Buffer& data, const std::string& privateKey) {
    core::Validator::validatePrivKeyWIF(privateKey, "field:privateKey ");
    try {
        return _impl->signData(data, privateKey);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

bool CryptoApi::verifySignature(const core::Buffer& data, const core::Buffer& signature, const std::string& publicKey) {
    core::Validator::validatePubKeyBase58DER(publicKey, "field:publicKey ");
    core::Validator::validateSignature(signature.stdString(), "field:signature ");
    try {
        return _impl->verifySignature(data, signature, publicKey);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

std::string CryptoApi::generatePrivateKey(const std::optional<std::string>& randomSeed) {
    try {
        return _impl->generatePrivateKey(randomSeed);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

std::string CryptoApi::derivePrivateKey(const std::string& password, const std::string& salt) {
    try {
        return _impl->derivePrivateKey_deprecated(password, salt);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

std::string CryptoApi::derivePrivateKey2(const std::string& password, const std::string& salt) {
    try {
        return _impl->derivePrivateKey(password, salt);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

std::string CryptoApi::derivePublicKey(const std::string& privateKey) {
    core::Validator::validatePrivKeyWIF(privateKey, "field:privateKey ");
    try {
        return _impl->derivePublicKey(privateKey);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

core::Buffer CryptoApi::generateKeySymmetric() {
    try {
        return _impl->generateKeySymmetric();
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

core::Buffer CryptoApi::encryptDataSymmetric(const core::Buffer& data, const core::Buffer& symmetricKey) {
    try {
        return _impl->encryptDataSymmetric(data, symmetricKey);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

core::Buffer CryptoApi::decryptDataSymmetric(const core::Buffer& data, const core::Buffer& symmetricKey) {
    try {
        return _impl->decryptDataSymmetric(data, symmetricKey);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

std::string CryptoApi::convertPEMKeytoWIFKey(const std::string& pemKey) {
    try {
        return _impl->convertPEMKeytoWIFKey(pemKey);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

BIP39_t CryptoApi::generateBip39(std::size_t strength, const std::string& password) {
    try {
        return _impl->generateBip39(strength, password);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

BIP39_t CryptoApi::fromMnemonic(const std::string& mnemonic, const std::string& password) {
    try {
        return _impl->fromMnemonic(mnemonic, password);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

BIP39_t CryptoApi::fromEntropy(const core::Buffer& entropy, const std::string& password) {
    try {
        return _impl->fromEntropy(entropy, password);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

std::string CryptoApi::entropyToMnemonic(const core::Buffer& entropy) {
    try {
        return _impl->entropyToMnemonic(entropy);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

core::Buffer CryptoApi::mnemonicToEntropy(const std::string& mnemonic) {
    try {
        return _impl->mnemonicToEntropy(mnemonic);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

core::Buffer CryptoApi::mnemonicToSeed(const std::string& mnemonic, const std::string& password) {
    try {
        return _impl->mnemonicToSeed(mnemonic, password);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}