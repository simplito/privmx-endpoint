/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include <privmx/crypto/Crypto.hpp>
#include <privmx/crypto/CryptoPrivmx.hpp>
#include <privmx/crypto/ecc/ExtKey.hpp>
#include <privmx/crypto/ecc/PrivateKey.hpp>

#include "privmx/endpoint/crypto/CryptoApiImpl.hpp"
#include "privmx/endpoint/crypto/KeyConverter.hpp"

using namespace privmx::endpoint;
using namespace privmx::endpoint::crypto;

core::Buffer CryptoApiImpl::signData(const core::Buffer& data, const std::string& key) {
    auto privKey {privmx::crypto::PrivateKey::fromWIF(key)};
    auto sign {privKey.signToCompactSignatureWithHash(data.stdString())};
    return core::Buffer::from(sign);
}

bool CryptoApiImpl::verifySignature(const core::Buffer& data, const core::Buffer& signature, const std::string& key) {
    auto pubKey {privmx::crypto::PublicKey::fromBase58DER(key)};
    return pubKey.verifyCompactSignatureWithHash(data.stdString(), signature.stdString());
}

std::string CryptoApiImpl::generatePrivateKey(const std::optional<std::string>& basestring) {
    if (basestring.has_value()) {
        auto privWIF {getPrivKeyFromSeed(basestring.value(), 200000).toWIF()};
        return privWIF;
    }
    auto privKey = privmx::crypto::PrivateKey::generateRandom();
    return privKey.toWIF();
}

std::string CryptoApiImpl::derivePrivateKey_deprecated(const std::string& password, const std::string& salt) {
    auto pbkdf2 {privmx::crypto::Crypto::pbkdf2(password, salt, 1000, 32, "SHA512")};
    auto extKey {privmx::crypto::ExtKey::fromSeed(pbkdf2)};
    return extKey.getPrivateKey().toWIF();
}

std::string CryptoApiImpl::derivePrivateKey(const std::string& password, const std::string& salt) {
    auto pbkdf2 {privmx::crypto::Crypto::pbkdf2(password, salt, 200000, 32, "SHA512")};
    auto extKey {privmx::crypto::ExtKey::fromSeed(pbkdf2)};
    return extKey.getPrivateKey().toWIF();
}

std::string CryptoApiImpl::derivePublicKey(const std::string& privkey) {
    auto privKey {privmx::crypto::PrivateKey::fromWIF(privkey.data())};
    auto pubKey {privKey.getPublicKey()};
    return pubKey.toBase58DER();
}

core::Buffer CryptoApiImpl::generateKeySymmetric() {
    auto key {privmx::crypto::Crypto::randomBytes(32)};
    return core::Buffer::from(key);
}

core::Buffer CryptoApiImpl::encryptDataSymmetric(const core::Buffer& data, const core::Buffer& key) {
    auto cipher { privmx::crypto::CryptoPrivmx::privmxEncrypt(
        privmx::crypto::CryptoPrivmx::privmxOptAesWithSignature(), data.stdString(), key.stdString())
    };
    return core::Buffer::from(cipher);
}

core::Buffer CryptoApiImpl::decryptDataSymmetric(const core::Buffer& data, const core::Buffer& key) {
    auto decrypted { privmx::crypto::CryptoPrivmx::privmxDecrypt(true, data.stdString(), key.stdString()) };
    return core::Buffer::from(decrypted);
}

privmx::crypto::PrivateKey CryptoApiImpl::getPrivKeyFromSeed(const std::string& seed, size_t rounds) {
    auto salt {privmx::crypto::Crypto::randomBytes(16)};
    auto pbkdf2 {privmx::crypto::Crypto::pbkdf2(seed, salt, rounds, 32, "SHA512")};
    auto extKey {privmx::crypto::ExtKey::fromSeed(pbkdf2)};
    return extKey.getPrivateKey();
}

std::string CryptoApiImpl::convertPEMKeytoWIFKey(const std::string& keyPEM) {
    return KeyConverter::cryptoKeyConvertPEMToWIF(keyPEM);
}
