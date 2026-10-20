/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include <privmx/cryptoservice/base/CoreTypes.hpp>
#include <privmx/utils/Utils.hpp>

#include <privmx/endpoint/core/CoreException.hpp>
#include <privmx/endpoint/core/crypto/CryptoErrors.hpp>
#include <privmx/endpoint/core/crypto/CryptoSuite.hpp>
#include <privmx/endpoint/core/crypto/Ecies.hpp>
#include <privmx/endpoint/core/crypto/FormatHash.hpp>
#include <privmx/endpoint/core/crypto/KeyFormats.hpp>
#include <privmx/endpoint/core/crypto/ProviderAccess.hpp>

using namespace privmx::endpoint::core;

namespace cs = privmx::cryptoservice;

namespace {

/**
 * Wrapping to an identity whose agreement half is a 25519 key.
 *
 * pmx-crypto's own ECIES (`seal`/`open`) cannot serve here: it pulls the sender's private scalar out
 * with `toRawP256PrivateOnly`, which is a P256-family operation, and fails on X25519 with "Failed to
 * get private key raw bytes". So the wrap is built from the pieces that do work — a shared secret,
 * a KDF, and the authenticated frame `CryptoSuite` already produces.
 *
 * Frame: `[32 B sender agreement public key][CryptoSuite frame]`. The sender's key travels in the
 * clear because `decrypt` is often called without it — `EncKeyEncryptorV1` has no sender to hand —
 * and it is what the recipient agrees the secret with.
 *
 * This is a different wrapping format from the secp256k1 one, which is fine: nothing was ever
 * written in it, and which one applies follows from the identity's algorithm tag.
 */
constexpr std::size_t AGREEMENT_PUBLIC_LENGTH = 32;
/// An ML-KEM-768 ciphertext. Fixed by the algorithm, which is what lets the frame split by length.
constexpr std::size_t KEM_CIPHERTEXT_LENGTH = 1088;
constexpr const char* WRAP_KDF_LABEL = "privmx-key-wrap";

std::string wrapKeyFor(const std::string& sharedSecret) {
    return FormatHash::kdf(sharedSecret, WRAP_KDF_LABEL, CryptoSuite::defaultForWrite().keyLength());
}

/**
 * The curve a key actually agrees secrets on.
 *
 * A composed identity agrees on its second half; everything else agrees on itself. `secp256k1` and
 * `PrivmxSecp256k1` are one curve in two spellings — the registry keeps them apart only because
 * their data formats differ — so they must not be read as two.
 */
cs::AsymAlg agreementCurveOf(cs::AsymAlg algorithm) {
    if (keyAlgorithmNeedsAgreementKey(algorithm)) {
        return agreementAlgorithmFor(algorithm);
    }
    return algorithm == cs::AsymAlg::secp256k1 ? cs::AsymAlg::PrivmxSecp256k1 : algorithm;
}

/**
 * Both ends of a shared secret have to be on one curve.
 *
 * Checked here because the alternative is worse in both directions: with a composed identity OpenSSL
 * does not fail but trips an internal assertion and **aborts the process**
 * (`keymgmt_lib.c: match_type`), and with two plain keys pmx-crypto reports "Wrong type of private
 * key", which names neither key nor algorithm and reads like a corrupted key rather than a pairing
 * that was never possible.
 */
void assertSameCurve(const PublicKey& pub, const PrivateKey& sender, const std::string& what) {
    if (agreementCurveOf(pub.algorithm()) != agreementCurveOf(sender.algorithm())) {
        throw MalformedEncryptionKeyException(
            what + ": the two keys are of different algorithms (" +
            std::to_string(static_cast<int>(sender.algorithm())) + " and " +
            std::to_string(static_cast<int>(pub.algorithm())) +
            "), and a shared secret needs both ends on one curve"
        );
    }
}

std::string wrapToComposedIdentity(const PublicKey& pub, const std::string& data, const PrivateKey& sender) {
    // A key that names a composed algorithm without carrying its agreement half is not usable as
    // either end; `assertSameCurve` has already ruled out the two naming different ones.
    if (pub.agreementImpl() == pub.impl() || sender.agreementImpl() == sender.impl()) {
        throw MalformedEncryptionKeyException("composed identity is missing its agreement half");
    }
    const std::string senderPublic = keyString(sender.agreementImpl()->publicKey()->export_(cs::KeyFormat::Raw));
    if (senderPublic.size() != AGREEMENT_PUBLIC_LENGTH) {
        throw MalformedEncryptionKeyException("agreement public key of unexpected length");
    }
    std::string shared = keyString(sender.agreementImpl()->deriveSharedSecret(*pub.agreementImpl()));
    // The post-quantum term, when the recipient has one. A key encapsulation is not a Diffie-Hellman:
    // the secret is chosen here and the recipient can only reach it through the ciphertext, which
    // therefore travels with the wrap. Both secrets go through one KDF, so recovering the wrapping
    // key means breaking X25519 **and** ML-KEM-768, not either.
    std::string kemCiphertext;
    if (keyAlgorithmNeedsKemKey(pub.algorithm())) {
        if (pub.kemImpl() == nullptr) {
            throw MalformedEncryptionKeyException("post-quantum identity is missing its encapsulation half");
        }
        const auto [kemSecret, ciphertext] = pub.kemImpl()->encapsulate();
        shared += keyString(kemSecret);
        kemCiphertext = keyString(ciphertext);
    }
    return senderPublic + kemCiphertext + CryptoSuite::defaultForWrite().encrypt(wrapKeyFor(shared), data);
}

std::string unwrapForComposedIdentity(const PrivateKey& priv, const std::string& cipher) {
    // The KEM ciphertext has one length for a given algorithm, so the frame still splits by length
    // alone. An identity with no post-quantum half reads exactly the frame it always did.
    const std::size_t kemLength =
        keyAlgorithmNeedsKemKey(priv.algorithm()) ? KEM_CIPHERTEXT_LENGTH : 0;
    if (cipher.size() <= AGREEMENT_PUBLIC_LENGTH + kemLength) {
        throw MalformedEncryptionKeyException("wrapped key shorter than its own header");
    }
    auto senderPublic = cryptoProvider().importPublicKey(
        keyBytes(cipher.substr(0, AGREEMENT_PUBLIC_LENGTH)),
        cs::KeyFormat::Raw,
        agreementAlgorithmFor(priv.algorithm())
    );
    std::string shared = keyString(priv.agreementImpl()->deriveSharedSecret(*senderPublic));
    if (kemLength != 0) {
        if (priv.kemImpl() == nullptr) {
            throw MalformedEncryptionKeyException("post-quantum identity is missing its encapsulation half");
        }
        shared += keyString(
            priv.kemImpl()->decapsulate(keyBytes(cipher.substr(AGREEMENT_PUBLIC_LENGTH, kemLength)))
        );
    }
    return CryptoSuite::decrypt(wrapKeyFor(shared), cipher.substr(AGREEMENT_PUBLIC_LENGTH + kemLength));
}

} // namespace

std::string Ecies::encrypt(const PublicKey& pub, const std::string& data, const PrivateKey& privForSignature) {
    return mapCryptoErrors("Ecies::encrypt", [&] {
        if (pub.empty() || privForSignature.empty()) {
            throw MalformedEncryptionKeyException("ecies encrypt with an empty key");
        }
        assertSameCurve(pub, privForSignature, "ecies encrypt");
        if (keyAlgorithmNeedsAgreementKey(pub.algorithm())) {
            return wrapToComposedIdentity(pub, data, privForSignature);
        }
        return keyString(pub.agreementImpl()->seal(keyBytes(data), *privForSignature.agreementImpl()));
    });
}

std::string Ecies::decrypt(
    const PrivateKey& priv,
    const std::string& cipher,
    const std::optional<PublicKey>& pubOfSignature
) {
    return mapCryptoErrors("Ecies::decrypt", [&] {
        if (priv.empty()) {
            throw MalformedEncryptionKeyException("ecies decrypt with an empty key");
        }
        if (pubOfSignature.has_value() && pubOfSignature->empty()) {
            throw MalformedEncryptionKeyException("ecies decrypt against an empty signer key");
        }
        if (pubOfSignature.has_value()) {
            assertSameCurve(pubOfSignature.value(), priv, "ecies decrypt");
        }
        if (keyAlgorithmNeedsAgreementKey(priv.algorithm())) {
            return unwrapForComposedIdentity(priv, cipher);
        }
        const privmx::cryptoservice::IPublicKey* expectedSender =
            pubOfSignature.has_value() ? pubOfSignature->agreementImpl().get() : nullptr;
        return keyString(priv.agreementImpl()->open(keyBytes(cipher), expectedSender));
    });
}

std::string Ecies::encryptToBase64(
    const PublicKey& pub,
    const std::string& data,
    const PrivateKey& privForSignature
) {
    return privmx::utils::Base64::from(encrypt(pub, data, privForSignature));
}

std::string Ecies::decryptFromBase64(
    const PrivateKey& priv,
    const std::string& cipherBase64,
    const std::optional<PublicKey>& pubOfSignature
) {
    return decrypt(priv, privmx::utils::Base64::toString(cipherBase64), pubOfSignature);
}

std::string Ecies::encryptObjectToBase64(
    const PublicKey& pub,
    Poco::JSON::Object::Ptr data,
    const PrivateKey& privForSignature
) {
    return encryptToBase64(pub, privmx::utils::Utils::stringify(data), privForSignature);
}

Poco::JSON::Object::Ptr Ecies::decryptObjectFromBase64(
    const PrivateKey& priv,
    const std::string& cipherBase64,
    const std::optional<PublicKey>& pubOfSignature
) {
    return privmx::utils::Utils::parseJsonObject(decryptFromBase64(priv, cipherBase64, pubOfSignature));
}
