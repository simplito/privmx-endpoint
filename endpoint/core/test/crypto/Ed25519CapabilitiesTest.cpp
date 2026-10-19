/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

/**
 * What an Ed25519 key can and cannot be used for here.
 *
 * These tests exist because "use Ed25519 instead of secp256k1" sounds like a swap and is not one.
 * secp256k1 does two jobs in this platform, and Ed25519 can only do the first:
 *
 *   - signing — DIO, author keys, roster tags, the login challenge;
 *   - **key agreement** — every container key is wrapped to each member's public key by ECIES,
 *     which is ECDH plus a symmetric layer (`EncKeyEncryptorV2`).
 *
 * Ed25519 is a signature scheme; its Diffie-Hellman counterpart is X25519, a different key. So a
 * user whose only key is Ed25519 registers and logs in, then fails the moment anything is wrapped
 * to them. These tests pin that boundary so the limit is measured rather than argued about, and so
 * that the day a two-key model lands, whatever stops failing here says exactly what changed.
 */

#include <memory>
#include <string>

#include <gtest/gtest.h>

#include <privmx/endpoint/core/CoreException.hpp>
#include <privmx/endpoint/core/crypto/Ecies.hpp>
#include <privmx/endpoint/core/crypto/FormatHash.hpp>
#include <privmx/endpoint/core/crypto/KeyFormats.hpp>
#include <privmx/endpoint/core/crypto/PrivateKey.hpp>
#include <privmx/endpoint/core/crypto/ProviderAccess.hpp>
#include <privmx/endpoint/core/crypto/PublicKey.hpp>

using namespace privmx::endpoint::core;
namespace cs = privmx::cryptoservice;

namespace {

/// An Ed25519 pair built straight from the provider: `PrivateKey::generateRandom` would give the
/// default algorithm, and the point here is a key the registry does not yet cover.
std::pair<PrivateKey, PublicKey> ed25519Pair() {
    auto priv = cryptoProvider().generatePrivateKey(cs::AsymAlg::ED25519);
    auto pub = priv->publicKey();
    return {PrivateKey(priv, cs::AsymAlg::ED25519), PublicKey(pub, cs::AsymAlg::ED25519)};
}

std::pair<PrivateKey, PublicKey> secp256k1Pair() {
    const PrivateKey priv = PrivateKey::generateRandom();
    return {priv, priv.getPublicKey()};
}

} // namespace

// ---------------------------------------------------------------------------------------------
// The half that works: signatures.
// ---------------------------------------------------------------------------------------------

/// Ed25519 signs and verifies through the provider today. Nothing in the primitive is missing — what
/// is missing is the registry entry that would let the rest of the endpoint reach it.
TEST(Ed25519Capabilities, SigningAndVerifyingWork) {
    const auto [priv, pub] = ed25519Pair();
    const std::string message = "ecdhexlogin abc 1700000000";

    const auto signature = priv.impl()->sign(keyBytes(message), cs::SigScheme::Default);
    EXPECT_EQ(64u, signature.size());

    EXPECT_TRUE(pub.impl()->verify(keyBytes(message), signature, cs::SigScheme::Default));
    EXPECT_FALSE(pub.impl()->verify(keyBytes("other"), signature, cs::SigScheme::Default));
}

/// The registry now covers Ed25519, and covers it as an identity that needs a second key to agree
/// with — which is the only way it can be one here.
TEST(Ed25519Capabilities, TheRegistryCoversItAsAComposedIdentity) {
    EXPECT_TRUE(isSupportedKeyAlgorithm(cs::AsymAlg::ED25519));
    EXPECT_EQ(cs::SigScheme::Default, signatureSchemeFor(cs::AsymAlg::ED25519));

    EXPECT_TRUE(keyAlgorithmNeedsAgreementKey(cs::AsymAlg::ED25519));
    EXPECT_EQ(cs::AsymAlg::X25519, agreementAlgorithmFor(cs::AsymAlg::ED25519));

    // secp256k1 does both jobs with one key, so it has no second half.
    EXPECT_FALSE(keyAlgorithmNeedsAgreementKey(cs::AsymAlg::PrivmxSecp256k1));
    EXPECT_THROW(agreementAlgorithmFor(cs::AsymAlg::PrivmxSecp256k1), UnsupportedKeyAlgorithmException);
}

// ---------------------------------------------------------------------------------------------
// The half that does not: key agreement. This is the blocker.
// ---------------------------------------------------------------------------------------------

/// `PrivateKey::derive` is ECDH. Ed25519 has no ECDH — pmx-crypto refuses it by key type rather than
/// producing something unusable.
TEST(Ed25519Capabilities, DerivingASharedSecretIsRefused) {
    const auto [edPriv, edPub] = ed25519Pair();

    EXPECT_ANY_THROW(edPriv.derive(edPub));

    // ...while the same call on secp256k1 is exactly what the platform relies on.
    const auto [ecPriv, ecPub] = secp256k1Pair();
    const auto [ecPriv2, ecPub2] = secp256k1Pair();
    EXPECT_NO_THROW(ecPriv.derive(ecPub2));
    EXPECT_EQ(ecPriv.derive(ecPub2), ecPriv2.derive(ecPub));
}

/// The one that decides the question: this is how a container key reaches a member
/// (`EncKeyEncryptorV2` → `Ecies::encryptObjectToBase64`). An Ed25519 recipient cannot be wrapped to,
/// so such a user would register and log in and then fail at the first container.
TEST(Ed25519Capabilities, WrappingAContainerKeyToAnEd25519RecipientIsRefused) {
    const auto [edPriv, edPub] = ed25519Pair();
    const auto [ecPriv, ecPub] = secp256k1Pair();
    const std::string containerKey(32, 'k');

    EXPECT_ANY_THROW(Ecies::encrypt(edPub, containerKey, edPriv));
    // Not a sender-side problem: a secp256k1 sender cannot wrap to an Ed25519 recipient either.
    EXPECT_ANY_THROW(Ecies::encrypt(edPub, containerKey, ecPriv));

    // The same wrap between two secp256k1 keys round-trips, which is what makes this a limit of the
    // algorithm rather than of the test.
    const std::string wrapped = Ecies::encrypt(ecPub, containerKey, ecPriv);
    EXPECT_EQ(containerKey, Ecies::decrypt(ecPriv, wrapped));
}

/// X25519 is Ed25519's key-agreement counterpart and the provider already knows it. This is the
/// evidence that a two-key model is buildable: one key signs, the other agrees.
TEST(Ed25519Capabilities, X25519CanDoTheKeyAgreementEd25519Cannot) {
    auto alicePriv = cryptoProvider().generatePrivateKey(cs::AsymAlg::X25519);
    auto bobPriv = cryptoProvider().generatePrivateKey(cs::AsymAlg::X25519);

    const auto aliceSees = alicePriv->deriveSharedSecret(*bobPriv->publicKey());
    const auto bobSees = bobPriv->deriveSharedSecret(*alicePriv->publicKey());

    EXPECT_FALSE(aliceSees.empty());
    EXPECT_EQ(std::string(aliceSees.begin(), aliceSees.end()), std::string(bobSees.begin(), bobSees.end()));
}

// ---------------------------------------------------------------------------------------------
// The shape a fix would take, checked before building it.
// ---------------------------------------------------------------------------------------------

namespace {

/// One secret, two keys. The sub-seeds are domain-separated rather than being the same 32 bytes fed
/// to both algorithms: Ed25519 hashes its seed into a scalar and X25519 clamps its one, so the same
/// bytes would mean two keys whose private scalars are related in a way nobody has analysed.
std::shared_ptr<cs::IPrivateKey> fromSeed(const std::string& seed, const std::string& label, cs::AsymAlg algorithm) {
    const std::string subSeed = FormatHash::kdf(seed, label, 32);
    return cryptoProvider().privateKeyFromSeed(keyBytes(subSeed), algorithm);
}

} // namespace

/// Two keys generated outright do everything the composite design needs: one signs, the other
/// agrees, and the public halves are 32 bytes each — so a composite public key is 64 bytes behind a
/// single tag, and `UserWithPubKey.pubKey` stays one field.
TEST(Ed25519Capabilities, AComposedIdentityCanBothSignAndBeWrappedTo) {
    auto aliceSigning = cryptoProvider().generatePrivateKey(cs::AsymAlg::ED25519);
    auto aliceAgreement = cryptoProvider().generatePrivateKey(cs::AsymAlg::X25519);
    auto bobAgreement = cryptoProvider().generatePrivateKey(cs::AsymAlg::X25519);

    const std::string message = "something to sign";
    const auto signature = aliceSigning->sign(keyBytes(message), cs::SigScheme::Default);
    EXPECT_TRUE(aliceSigning->publicKey()->verify(keyBytes(message), signature, cs::SigScheme::Default));

    EXPECT_EQ(
        keyString(aliceAgreement->deriveSharedSecret(*bobAgreement->publicKey())),
        keyString(bobAgreement->deriveSharedSecret(*aliceAgreement->publicKey()))
    );

    EXPECT_EQ(32u, keyString(aliceSigning->publicKey()->export_(cs::KeyFormat::Raw)).size());
    EXPECT_EQ(32u, keyString(aliceAgreement->publicKey()->export_(cs::KeyFormat::Raw)).size());
}

/// A seed now rebuilds a usable key on both curves — `privateKeyFromSeed` in pmx-crypto. This is
/// what lets an identity stay a single private value while being two keys.
TEST(Ed25519Capabilities, AKeyCanBeRebuiltFromASeedAlone) {
    const std::string seed(32, 'a');

    auto signing = fromSeed(seed, "privmx-identity-sign", cs::AsymAlg::ED25519);
    ASSERT_NE(nullptr, signing);
    EXPECT_NO_THROW(signing->sign(keyBytes("data"), cs::SigScheme::Default));
    EXPECT_EQ(
        keyString(signing->publicKey()->export_(cs::KeyFormat::Raw)),
        keyString(fromSeed(seed, "privmx-identity-sign", cs::AsymAlg::ED25519)->publicKey()->export_(cs::KeyFormat::Raw))
    );

    auto agreement = fromSeed(seed, "privmx-identity-dh", cs::AsymAlg::X25519);
    auto peer = cryptoProvider().generatePrivateKey(cs::AsymAlg::X25519);
    EXPECT_NO_THROW(agreement->deriveSharedSecret(*peer->publicKey()));
}

// ---------------------------------------------------------------------------------------------
// The composed identity as the endpoint now builds it.
// ---------------------------------------------------------------------------------------------

namespace {

/// An Ed25519 identity regardless of what this build's default algorithm is, so these tests describe
/// the composed key itself rather than the build setting.
PrivateKey composedIdentity(const std::string& secret) {
    const std::string signingSeed = deriveIdentitySeed(secret, false);
    const std::string agreementSeed = deriveIdentitySeed(secret, true);
    return PrivateKey(
        cryptoProvider().privateKeyFromSeed(keyBytes(signingSeed), cs::AsymAlg::ED25519),
        cs::AsymAlg::ED25519,
        cryptoProvider().privateKeyFromSeed(keyBytes(agreementSeed), cs::AsymAlg::X25519)
    );
}

} // namespace

/// Both jobs through the endpoint's own types — the thing an Ed25519-only identity could not do.
TEST(Ed25519Composed, SignsAndIsWrappedToThroughOneIdentity) {
    const PrivateKey alice = composedIdentity(std::string(32, 'a'));
    const PrivateKey bob = composedIdentity(std::string(32, 'b'));
    const std::string containerKey(32, 'k');

    const std::string wrapped = Ecies::encrypt(bob.getPublicKey(), containerKey, alice);
    EXPECT_EQ(containerKey, Ecies::decrypt(bob, wrapped));

    EXPECT_EQ(alice.derive(bob.getPublicKey()), bob.derive(alice.getPublicKey()));
}

/// One tagged string carries both halves, so `UserWithPubKey.pubKey` stays a single field and a key
/// still compares equal to itself after a round trip through the wire format.
TEST(Ed25519Composed, RoundTripsThroughTheTaggedEncoding) {
    const PrivateKey alice = composedIdentity(std::string(32, 'a'));
    const std::string encoded = alice.getPublicKey().toBase58DER();

    const TaggedPublicKey decoded = decodeTaggedPublicKey(encoded);
    EXPECT_EQ(cs::AsymAlg::ED25519, decoded.algorithm);
    EXPECT_EQ(32u, decoded.rawKey.size());
    EXPECT_EQ(32u, decoded.rawAgreementKey.size());

    const PublicKey reparsed = PublicKey::fromBase58DER(encoded);
    EXPECT_EQ(alice.getPublicKey(), reparsed);
    EXPECT_EQ(encoded, reparsed.toBase58DER());

    // ...and the reparsed key is usable for the job it is wrapped to with.
    const std::string containerKey(32, 'k');
    EXPECT_EQ(containerKey, Ecies::decrypt(alice, Ecies::encrypt(reparsed, containerKey, alice)));
}

/// One secret rebuilds the whole identity, which is what keeps a WIF enough to be a user.
TEST(Ed25519Composed, IsDeterministicInItsSecret) {
    const std::string secret(32, 'a');

    EXPECT_EQ(
        composedIdentity(secret).getPublicKey().toBase58DER(),
        composedIdentity(secret).getPublicKey().toBase58DER()
    );
    EXPECT_NE(
        composedIdentity(secret).getPublicKey().toBase58DER(),
        composedIdentity(std::string(32, 'b')).getPublicKey().toBase58DER()
    );
}

/// The halves are independent keys, not one scalar wearing two hats.
TEST(Ed25519Composed, TheTwoHalvesAreDifferentKeys) {
    const PrivateKey alice = composedIdentity(std::string(32, 'a'));
    const TaggedPublicKey decoded = decodeTaggedPublicKey(alice.getPublicKey().toBase58DER());

    EXPECT_NE(decoded.rawKey, decoded.rawAgreementKey);
}
