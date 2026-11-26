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

#include <privmx/endpoint/core/ConvertedExceptions.hpp>
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
 * This used to be built here by hand — a Diffie-Hellman, an ML-KEM encapsulation concatenated onto
 * it, a KDF and a `CryptoSuite` frame — because pmx-crypto's `seal` could not take an X25519 key at
 * all. That is fixed, and `seal(SealParams, ...)` turns out to be the better construction anyway:
 * it encapsulates to **both** halves of a composed identity, draws a random IV instead of deriving
 * one from the plaintext, and signs the message rather than leaving authentication implicit in the
 * agreement.
 *
 * So this file no longer composes anything. What is left is choosing the key the wrap is addressed
 * to, which is the one thing pmx-crypto cannot do for us: the endpoint keeps a composed identity as
 * separate halves, and a hybrid wrap wants them as one key.
 */

/**
 * The parameters the wrap is written with.
 *
 * **This is wire format.** `SealParams` has no default member initialisers, and every field here
 * ends up deciding bytes: the hashes, the symmetric algorithm, the IV length and the width of the
 * key hashes in the header. A reader has to pass the same values, so they are pinned in one place
 * rather than spelled out at each call site.
 */
const cs::SealParams& wrapParams() {
    static const cs::SealParams params = [] {
        cs::SealParams p{};
        p.alg = cs::SymAlg::Aes256Cbc;
        p.shrKeyHash = cs::Hash::Sha512;
        p.signHash = cs::Hash::Sha256;
        p.pubKeyHash = cs::Hash::Sha512;
        p.symKeyLen = 32;
        p.publHashLen = 32;
        p.ivLen = 16;
        return p;
    }();
    return params;
}

/**
 * The key a 25519 wrap is addressed to.
 *
 * For a plain Ed25519 identity that is the X25519 agreement key as it stands. For one with a
 * post-quantum half it is a single `X25519MLKEM768` key, which `seal` then encapsulates to **both**
 * halves — the property the hand-built wrap used to provide by concatenating two secrets.
 *
 * The halves are concatenated and re-imported because the endpoint keeps them apart: an identity is
 * built from one secret and its halves are separate `IPublicKey`s, while a hybrid wrap wants one
 * key. The raw layouts line up exactly — X25519 public is 32 bytes, ML-KEM-768 public is 1184, and
 * `X25519MLKEM768` reads the first 32 as one and the rest as the other.
 */
std::shared_ptr<cs::IPublicKey> sealTarget(const PublicKey& pub) {
    if (!keyAlgorithmNeedsKemKey(pub.algorithm())) {
        return pub.agreementImpl();
    }
    if (pub.kemImpl() == nullptr) {
        throw MalformedEncryptionKeyException("post-quantum identity is missing its encapsulation half");
    }
    const std::string raw =
        keyString(pub.agreementImpl()->export_(cs::KeyFormat::Raw)) +
        keyString(pub.kemImpl()->export_(cs::KeyFormat::Raw));
    return cryptoProvider().importPublicKey(keyBytes(raw), cs::KeyFormat::Raw, cs::AsymAlg::X25519MLKEM768);
}

/// The private counterpart of `sealTarget`; X25519 raw private is `pub || priv`, hence 64 bytes.
std::shared_ptr<cs::IPrivateKey> openTarget(const PrivateKey& priv) {
    if (!keyAlgorithmNeedsKemKey(priv.algorithm())) {
        return priv.agreementImpl();
    }
    if (priv.kemImpl() == nullptr) {
        throw MalformedEncryptionKeyException("post-quantum identity is missing its encapsulation half");
    }
    const std::string raw =
        keyString(priv.agreementImpl()->export_(cs::KeyFormat::Raw)) +
        keyString(priv.kemImpl()->export_(cs::KeyFormat::Raw));
    return cryptoProvider().importPrivateKey(keyBytes(raw), cs::KeyFormat::Raw, cs::AsymAlg::X25519MLKEM768);
}

/**
 * Both ends of a shared secret have to be on one curve.
 *
 * Checked here because the alternative is worse in both directions: with a composed identity OpenSSL
 * does not fail but trips an internal assertion and **aborts the process**
 * (`keymgmt_lib.c: match_type`), and with two plain keys pmx-crypto reports "Wrong type of private
 * key", which names neither key nor algorithm and reads like a corrupted key rather than a pairing
 * that was never possible.
 *
 * This is the last line of defence, not the first. Callers that know the pairing earlier — a group
 * commit knows every recipient before it plans anything — should refuse with an error that names the
 * real problem; see `keyAlgorithmsCanAgree`.
 */
void assertSameCurve(const PublicKey& pub, const PrivateKey& sender, const std::string& what) {
    if (!keyAlgorithmsCanAgree(pub.algorithm(), sender.algorithm())) {
        throw MalformedEncryptionKeyException(
            what +
            ": the two keys are of different algorithms (" +
            std::to_string(static_cast<int>(sender.algorithm())) +
            " and " +
            std::to_string(static_cast<int>(pub.algorithm())) +
            "), and a shared secret needs both ends on one curve"
        );
    }
}


} // namespace

std::string Ecies::encrypt(const PublicKey& pub, const std::string& data, const PrivateKey& privForSignature) {
    return mapCryptoErrors("Ecies::encrypt", [&] {
        if (pub.empty() || privForSignature.empty()) {
            throw MalformedEncryptionKeyException("ecies encrypt with an empty key");
        }
        assertSameCurve(pub, privForSignature, "ecies encrypt");
        if (keyAlgorithmNeedsAgreementKey(pub.algorithm())) {
            // Signed with the identity's **signing** half, not the agreement one: X25519 cannot
            // sign, and it is the signature that lets `sealedBy` attribute a wrap without opening it.
            return keyString(
                sealTarget(pub)->seal(wrapParams(), keyBytes(data), privForSignature.impl())
            );
        }
        return keyString(pub.agreementImpl()->seal(keyBytes(data), privForSignature.agreementImpl()));
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
            // `open` verifies the signature when a sender is named, and skips it when none is —
            // `EncKeyEncryptorV1` has no sender to hand, and the wrap still opens for its recipient.
            return keyString(openTarget(priv)->open(
                wrapParams(), keyBytes(cipher), pubOfSignature.has_value() ? pubOfSignature->impl() : nullptr
            ));
        }
        const std::shared_ptr<cs::IPublicKey> expectedSender = pubOfSignature.has_value() ?
            pubOfSignature->agreementImpl() :
            nullptr;
        return keyString(priv.agreementImpl()->open(keyBytes(cipher), expectedSender));
    });
}

std::string Ecies::encryptToBase64(const PublicKey& pub, const std::string& data, const PrivateKey& privForSignature) {
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

bool Ecies::sealedBy(const std::string& cipherBase64, const std::string& senderBase58DER) {
    try {
        const PublicKey sender = PublicKey::fromBase58DER(senderBase58DER);
        if (sender.empty()) {
            return false;
        }
        const std::string cipher = privmx::utils::Base64::toString(cipherBase64);
        if (keyAlgorithmNeedsAgreementKey(sender.algorithm())) {
            // Checks the signature, not just the sender field — so this answers "X sealed it",
            // where the branch below only answers "the frame says X". The asymmetry is the two
            // formats, not a decision: the legacy one carries no signature to check.
            return sender.impl()->sealedBy(wrapParams(), keyBytes(cipher));
        }
        // The pmx-crypto frame: 'e' || sender DER || recipient DER || iv || ciphertext || tag.
        const std::string der = sender.toDER();
        return cipher.size() > 1 + der.size() && cipher.front() == 'e' && cipher.compare(1, der.size(), der) == 0;
    } catch (...) { return false; }
}
