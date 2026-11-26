/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include <privmx/crypto/CipherType.hpp>
#include <privmx/crypto/Crypto.hpp>
#include <privmx/crypto/CryptoPrivmx.hpp>

#include <privmx/endpoint/core/crypto/PrivateKey.hpp>
#include <privmx/endpoint/core/crypto/PublicKey.hpp>
#include <privmx/endpoint/crypto/ExtKey.hpp>

#include "privmx/endpoint/core/crypto/CryptoSuite.hpp"
#include "privmx/endpoint/crypto/CryptoApiImpl.hpp"
#include "privmx/endpoint/crypto/KeyConverter.hpp"
using namespace privmx::endpoint;
using namespace privmx::endpoint::crypto;

core::Buffer CryptoApiImpl::signData(const core::Buffer& data, const std::string& key) {
    auto privKey{core::PrivateKey::fromWIF(key)};
    auto sign{privKey.signToCompactSignatureWithHash(data.stdString())};
    return core::Buffer::from(sign);
}

bool CryptoApiImpl::verifySignature(const core::Buffer& data, const core::Buffer& signature, const std::string& key) {
    auto pubKey{core::PublicKey::fromBase58DER(key)};
    return pubKey.verifyCompactSignatureWithHash(data.stdString(), signature.stdString());
}

std::string CryptoApiImpl::generatePrivateKey(const std::optional<std::string>& basestring) {
    if (basestring.has_value()) {
        return getPrivKeyFromSeed(basestring.value(), 200000);
    }
    auto privKey = core::PrivateKey::generateRandom();
    return privKey.toWIF();
}

std::string CryptoApiImpl::derivePrivateKey_deprecated(const std::string& password, const std::string& salt) {
    auto pbkdf2{privmx::crypto::Crypto::pbkdf2(password, salt, 1000, 32, "SHA512")};
    // Same master key as before: `fromSeed` is BIP-32's HMAC-SHA512 over "Bitcoin seed" either way,
    // which `ExtKeyBip32VectorsTest` pins against the specification. The WIF a caller derives from a
    // password therefore does not change - which matters, because that key is what they log in with.
    return crypto::ExtKey::fromSeed(core::Buffer::from(pbkdf2)).getPrivateKey();
}

std::string CryptoApiImpl::derivePrivateKey(const std::string& password, const std::string& salt) {
    auto pbkdf2{privmx::crypto::Crypto::pbkdf2(password, salt, 200000, 32, "SHA512")};
    // Same master key as before: `fromSeed` is BIP-32's HMAC-SHA512 over "Bitcoin seed" either way,
    // which `ExtKeyBip32VectorsTest` pins against the specification. The WIF a caller derives from a
    // password therefore does not change - which matters, because that key is what they log in with.
    return crypto::ExtKey::fromSeed(core::Buffer::from(pbkdf2)).getPrivateKey();
}

std::string CryptoApiImpl::derivePublicKey(const std::string& privkey) {
    auto privKey{core::PrivateKey::fromWIF(privkey.data())};
    auto pubKey{privKey.getPublicKey()};
    return pubKey.toBase58DER();
}

core::Buffer CryptoApiImpl::generateKeySymmetric() {
    auto key{core::CryptoSuite::randomBytes(32)};
    return core::Buffer::from(key);
}

core::Buffer CryptoApiImpl::encryptDataSymmetric(const core::Buffer& data, const core::Buffer& key) {
    auto cipher{core::CryptoSuite::defaultForWrite().encrypt(key.stdString(), data.stdString())};
    return core::Buffer::from(cipher);
}

/**
 * Reads both the suite-tagged frame this API writes now and the one it wrote through 2.x.
 *
 * Unlike every other frame in the library, what this one produces does not live on the bridge: the
 * caller is handed bytes and keeps them wherever it likes. There is no container to migrate and no
 * way to reach the old data, so dropping the old format would strand it permanently.
 *
 * Dispatch is exact despite the two numbering schemes sharing values 1 and 2. `CipherType` runs
 * 1..4, but this API only ever wrote `AES_256_CBC_PKCS7_WITH_IV_AND_HMAC_SHA256` (4) and only ever
 * accepted it — `privmxDecrypt(true, ...)` refuses anything else — so 4 is the whole of the legacy
 * surface here, and it is a value no `SuiteId` uses.
 */
core::Buffer CryptoApiImpl::decryptDataSymmetric(const core::Buffer& data, const core::Buffer& key) {
    const std::string framed = data.stdString();
    if (!framed.empty() &&
        framed[0] == privmx::crypto::CipherType::AES_256_CBC_PKCS7_WITH_IV_AND_HMAC_SHA256) {
        return core::Buffer::from(privmx::crypto::CryptoPrivmx::privmxDecrypt(true, framed, key.stdString()));
    }
    return core::Buffer::from(core::CryptoSuite::decrypt(key.stdString(), framed));
}

// Returns a WIF rather than a key object: the only consumer needs nothing else, and handing back a
// key would pull its type into the header for no gain.
std::string CryptoApiImpl::getPrivKeyFromSeed(const std::string& seed, size_t rounds) {
    auto salt{core::CryptoSuite::randomBytes(16)};
    auto pbkdf2{privmx::crypto::Crypto::pbkdf2(seed, salt, rounds, 32, "SHA512")};
    // Same master key as before: `fromSeed` is BIP-32's HMAC-SHA512 over "Bitcoin seed" either way,
    // which `ExtKeyBip32VectorsTest` pins against the specification. The WIF a caller derives from a
    // password therefore does not change - which matters, because that key is what they log in with.
    return crypto::ExtKey::fromSeed(core::Buffer::from(pbkdf2)).getPrivateKey();
}

std::string CryptoApiImpl::convertPEMKeytoWIFKey(const std::string& keyPEM) {
    return KeyConverter::cryptoKeyConvertPEMToWIF(keyPEM);
}

std::string CryptoApiImpl::convertPGPAsn1KeyToBase58DERKey(const std::string& keyPGP) {
    return KeyConverter::cryptoKeyConvertPGPToBase58DER(keyPGP);
}

