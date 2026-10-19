/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include <map>
#include <optional>
#include <string>

#include <gtest/gtest.h>

#include <privmx/crypto/ecc/ECC.hpp>
#include <privmx/crypto/ecc/PrivateKey.hpp>
#include <privmx/crypto/ecc/PublicKey.hpp>
#include <privmx/utils/Base58.hpp>

#include <privmx/endpoint/core/CoreException.hpp>
#include <privmx/endpoint/core/crypto/FormatHash.hpp>
#include <privmx/endpoint/core/crypto/KeyFormats.hpp>
#include <privmx/endpoint/core/crypto/PrivateKey.hpp>
#include <privmx/endpoint/core/crypto/PublicKey.hpp>
#include <privmx/endpoint/core/crypto/PublicKeyCache.hpp>

using namespace privmx::endpoint::core;

namespace legacy = privmx::crypto;

namespace {

// A vector from pmx-crypto's own test set (ProviderTest_FromWifAndToWif).
const std::string WIF{"L1YwTwAr8dQCBzfmXBzh6ggBkYbLuu15Tc7s4bajrRNDbsogs9a5"};
const std::string MESSAGE{"A message to be signed"};

} // namespace

namespace {

/**
 * The cases below describe secp256k1: they compare against the old implementation, which has no
 * other curve, or they reason about compressed and uncompressed points.
 *
 * Under `PRIVMX_DEFAULT_KEY_ALGORITHM=ed25519` the endpoint correctly builds a different kind of
 * key, so these comparisons have nothing to say rather than something false. They skip, which keeps
 * the suite honest about which build it is describing.
 */
bool isSecp256k1Build() {
    return defaultKeyAlgorithm() == privmx::cryptoservice::AsymAlg::PrivmxSecp256k1;
}

} // namespace

#define SKIP_UNLESS_SECP256K1()                                                                    \
    if (!isSecp256k1Build()) GTEST_SKIP() << "describes secp256k1; this build generates other keys"

// ---------------------------------------------------------------------------------------------
// Compatibility with the old implementation. This is the precondition for migrating 76 files: if
// any of these tests failed, swapping the modules would change the data on the wire, not just the
// types in the code.
// ---------------------------------------------------------------------------------------------

TEST(Keys, WifImportExportMatchesLegacy) {
    EXPECT_EQ(legacy::PrivateKey::fromWIF(WIF).toWIF(), PrivateKey::fromWIF(WIF).toWIF());
    EXPECT_EQ(WIF, PrivateKey::fromWIF(WIF).toWIF());
}

/// The key itself is unchanged; only how it is spelled on the wire is. The DER bytes still match the old
/// implementation byte for byte — the base58 form deliberately does not, because it now carries an
/// algorithm tag in front of exactly those bytes.
TEST(Keys, PublicKeyEncodingMatchesLegacyUnderTheTag) {
    SKIP_UNLESS_SECP256K1();
    const auto legacyPriv = legacy::PrivateKey::fromWIF(WIF);
    const auto priv = PrivateKey::fromWIF(WIF);

    EXPECT_EQ(legacyPriv.getPublicKey().toDER(), priv.getPublicKey().toDER());

    const std::string tagged = priv.getPublicKey().toBase58DER();
    EXPECT_NE(legacyPriv.getPublicKey().toBase58DER(), tagged);
    EXPECT_EQ(encodeTaggedPublicKey(legacyPriv.getPublicKey().toDER(), defaultKeyAlgorithm()), tagged);
    EXPECT_EQ(priv.getPublicKey().toDER(), decodeTaggedPublicKey(tagged).rawKey);
}

TEST(Keys, RawPrivatePartMatchesLegacy) {
    EXPECT_EQ(legacy::PrivateKey::fromWIF(WIF).getPrivateEncKey(), PrivateKey::fromWIF(WIF).getPrivateEncKey());
}

TEST(Keys, FromRawMatchesLegacyEccFromPrivateKey) {
    SKIP_UNLESS_SECP256K1();
    const std::string raw = legacy::PrivateKey::fromWIF(WIF).getPrivateEncKey();
    const auto legacyKey = legacy::PrivateKey(legacy::ECC::fromPrivateKey(raw));

    EXPECT_EQ(legacyKey.toWIF(), PrivateKey::fromRaw(raw).toWIF());
    EXPECT_EQ(legacyKey.getPublicKey().toDER(), PrivateKey::fromRaw(raw).getPublicKey().toDER());
}

TEST(Keys, SharedSecretMatchesLegacy) {
    SKIP_UNLESS_SECP256K1();
    const auto legacyPriv = legacy::PrivateKey::fromWIF(WIF);
    const auto legacyPeer = legacy::PrivateKey::generateRandom();
    const auto priv = PrivateKey::fromWIF(WIF);
    const auto peer = PublicKey::fromDER(legacyPeer.getPublicKey().toDER());

    EXPECT_EQ(legacyPriv.derive(legacyPeer.getPublicKey()), priv.derive(peer));
}

/// The most important compatibility test: a signature made by the new implementation has to pass
/// verification by the old one, and the other way round. It guards against the Compact /
/// CompactWithHash mix-up.
TEST(Keys, SignaturesVerifyAcrossImplementations) {
    SKIP_UNLESS_SECP256K1();
    const auto legacyPriv = legacy::PrivateKey::fromWIF(WIF);
    const auto priv = PrivateKey::fromWIF(WIF);

    const std::string legacySig = legacyPriv.signToCompactSignatureWithHash(MESSAGE);
    const std::string sig = priv.signToCompactSignatureWithHash(MESSAGE);

    EXPECT_EQ(65u, sig.size());
    EXPECT_TRUE(priv.getPublicKey().verifyCompactSignatureWithHash(MESSAGE, legacySig))
        << "the new verification does not accept an old signature";
    EXPECT_TRUE(legacyPriv.getPublicKey().verifyCompactSignatureWithHash(MESSAGE, sig))
        << "the old verification does not accept a new signature";
}

TEST(Keys, SignatureIsRejectedForOtherMessageAndKey) {
    const auto priv = PrivateKey::fromWIF(WIF);
    const std::string sig = priv.signToCompactSignatureWithHash(MESSAGE);

    EXPECT_FALSE(priv.getPublicKey().verifyCompactSignatureWithHash(MESSAGE + "!", sig));
    EXPECT_FALSE(PrivateKey::generateRandom().getPublicKey().verifyCompactSignatureWithHash(MESSAGE, sig));
}

// ---------------------------------------------------------------------------------------------
// A key carries its own algorithm.
//
// Users' keys may be of any algorithm, so signing and verification have to follow what the **key**
// carries, not a compile-time constant. With a single algorithm the difference is invisible — these
// tests pin the mechanism, so that adding a second one (Ed25519 is planned) does not require
// sweeping through every place that signs.
// ---------------------------------------------------------------------------------------------

TEST(KeyAlgorithm, ImportedKeysRememberWhatTheyWereParsedAs) {
    // A WIF *is* a secp256k1 private key by construction, so it reads as one on every build —
    // `defaultKeyAlgorithm()` has no say here. See `AWifReadsAsSecp256k1OnEveryBuild` below.
    const PrivateKey priv = PrivateKey::fromWIF(WIF);

    EXPECT_EQ(privmx::cryptoservice::AsymAlg::PrivmxSecp256k1, priv.algorithm());
    // The public key inherits the private half's algorithm — otherwise a signature made with one
    // would be verified under the other's scheme.
    EXPECT_EQ(priv.algorithm(), priv.getPublicKey().algorithm());
    EXPECT_EQ(priv.algorithm(), PublicKey::fromBase58DER(priv.getPublicKey().toBase58DER()).algorithm());

    // Generation is the one place the build option applies — it says what *new* keys are made of.
    EXPECT_EQ(defaultKeyAlgorithm(), PrivateKey::generateRandom().algorithm());
}

// ---------------------------------------------------------------------------------------------
// A private key names its own algorithm too.
//
// A build option sets a default for keys we *make*; it must not decide which existing keys work. If
// reading a private key consulted the build, the same string would be a different identity — or none
// — depending on how the library happened to be configured, and a user with an Ed25519 key could not
// log in through a client someone built with the secp256k1 default.
// ---------------------------------------------------------------------------------------------

TEST(KeyAlgorithm, AWifReadsAsSecp256k1OnEveryBuild) {
    const PrivateKey priv = PrivateKey::fromWIF(WIF);

    EXPECT_EQ(privmx::cryptoservice::AsymAlg::PrivmxSecp256k1, priv.algorithm());
    // And goes back out as the very string it came from, tag-free: a WIF is already self-describing.
    EXPECT_EQ(WIF, priv.toWIF());
}

TEST(KeyAlgorithm, ATaggedPrivateKeyRoundTripsThroughItsOwnAlgorithm) {
    for (const auto algorithm :
         {privmx::cryptoservice::AsymAlg::PrivmxSecp256k1, privmx::cryptoservice::AsymAlg::ED25519}) {
        const std::string secret = PrivateKey::fromWIF(WIF).getPrivateEncKey();
        ASSERT_EQ(32u, secret.size());

        const std::string encoded = encodePrivateKey(secret, algorithm);
        const TaggedPrivateKey decoded = decodePrivateKey(encoded);

        EXPECT_EQ(algorithm, decoded.algorithm) << "the tag did not survive the encoding";
        EXPECT_EQ(secret, decoded.secret);
        EXPECT_FALSE(decoded.wasWif);
        // Independent of the build: the same string gives the same identity wherever it is read.
        EXPECT_EQ(algorithm, PrivateKey::fromWIF(encoded).algorithm());
    }
}

/// The point of the whole exercise: a key generated by an Ed25519 build is usable by a secp256k1
/// build and the other way round, because the key says which it is.
TEST(KeyAlgorithm, AnEd25519IdentityLoadsOnAnyBuild) {
    const std::string secret = PrivateKey::fromWIF(WIF).getPrivateEncKey();
    const PrivateKey priv = PrivateKey::fromWIF(encodePrivateKey(secret, privmx::cryptoservice::AsymAlg::ED25519));

    EXPECT_EQ(privmx::cryptoservice::AsymAlg::ED25519, priv.algorithm());
    // Both halves of the composed identity are there, so it can sign *and* agree container keys —
    // being able to parse the key would be worth nothing without that.
    const std::string signature = priv.signToCompactSignatureWithHash(MESSAGE);
    EXPECT_EQ(64u, signature.size());
    EXPECT_TRUE(priv.getPublicKey().verifyCompactSignatureWithHash(MESSAGE, signature));
    EXPECT_FALSE(priv.derive(PrivateKey::fromWIF(encodePrivateKey(
                                 std::string(32, '\x07'), privmx::cryptoservice::AsymAlg::ED25519
                             )).getPublicKey())
                     .empty());

    // The identity survives an export/import cycle whole — `toWIF` has to emit the tagged form here,
    // since pmx-crypto's WIF is EC-only and could not carry it.
    EXPECT_EQ(priv.getPublicKey().toBase58DER(), PrivateKey::fromWIF(priv.toWIF()).getPublicKey().toBase58DER());
}

TEST(KeyAlgorithm, APrivateKeyThatNamesNothingWeCanReadIsRefused) {
    // Right length, tag of no algorithm in the registry.
    const std::string unknownTag = privmx::utils::Base58::encodeWithChecksum(
        std::string(1, '\x7F') + std::string(32, '\x01'), FormatHash::sha256
    );
    EXPECT_THROW(decodePrivateKey(unknownTag), MalformedEncryptionKeyException);
    // Known tag, wrong length — a truncated key must not quietly become a valid identity.
    const std::string shortSecret = privmx::utils::Base58::encodeWithChecksum(
        std::string(1, '\x82') + std::string(16, '\x01'), FormatHash::sha256
    );
    EXPECT_THROW(decodePrivateKey(shortSecret), MalformedEncryptionKeyException);
    EXPECT_THROW(encodePrivateKey(std::string(16, '\x01'), defaultKeyAlgorithm()), MalformedEncryptionKeyException);
}

/// As `pmx-crypto` sees it, the uncompressed form is a different algorithm (same curve, different
/// data format). The key should remember the one it was read with, not the default.
TEST(KeyAlgorithm, AnUncompressedImportRemembersItsOwnFormat) {
    SKIP_UNLESS_SECP256K1();
    const PrivateKey priv = PrivateKey::fromWIF(WIF);
    const std::string uncompressed = legacy::PrivateKey::fromWIF(WIF).getPublicKey().getEcc().getPublicKey(false);
    ASSERT_EQ(65u, uncompressed.size());

    const PublicKey imported = PublicKey::fromDER(uncompressed);

    EXPECT_EQ(privmx::cryptoservice::AsymAlg::secp256k1, imported.algorithm());
    // A different algorithm in the registry, yet the same key — the export returns to the compressed form.
    EXPECT_EQ(priv.getPublicKey().toBase58DER(), imported.toBase58DER());
}

/// A signature made with a key verifies under that key's own scheme — including when the public key
/// arrived in a different format from the private one.
TEST(KeyAlgorithm, SigningAndVerifyingFollowTheKey) {
    SKIP_UNLESS_SECP256K1();
    const PrivateKey priv = PrivateKey::fromWIF(WIF);
    const std::string signature = priv.signToCompactSignatureWithHash(MESSAGE);

    EXPECT_TRUE(priv.getPublicKey().verifyCompactSignatureWithHash(MESSAGE, signature));

    const std::string uncompressed = legacy::PrivateKey::fromWIF(WIF).getPublicKey().getEcc().getPublicKey(false);
    EXPECT_TRUE(PublicKey::fromDER(uncompressed).verifyCompactSignatureWithHash(MESSAGE, signature));
}

TEST(KeyAlgorithm, TheRegistryKnowsExactlyWhatItCanUse) {
    EXPECT_TRUE(isSupportedKeyAlgorithm(defaultKeyAlgorithm()));
    EXPECT_TRUE(isSupportedKeyAlgorithm(privmx::cryptoservice::AsymAlg::secp256k1));
    EXPECT_TRUE(isSupportedKeyAlgorithm(privmx::cryptoservice::AsymAlg::ED25519));
    // Still a refusal under its own name for anything the registry does not cover, rather than a
    // signature under some guessed scheme.
    EXPECT_FALSE(isSupportedKeyAlgorithm(privmx::cryptoservice::AsymAlg::MLDSA65));
    EXPECT_THROW(
        signatureSchemeFor(privmx::cryptoservice::AsymAlg::MLDSA65), UnsupportedKeyAlgorithmException
    );
}

// ---------------------------------------------------------------------------------------------
// Value semantics — the reason the wrapper exists at all.
// ---------------------------------------------------------------------------------------------

TEST(Keys, DefaultConstructedIsEmpty) {
    EXPECT_TRUE(PublicKey().empty());
    EXPECT_TRUE(PrivateKey().empty());
    EXPECT_THROW(PublicKey().toBase58DER(), MalformedEncryptionKeyException);
    EXPECT_THROW(PrivateKey().toWIF(), MalformedEncryptionKeyException);
}

TEST(Keys, PublicKeyComparesByValueNotByHandle) {
    const auto base58 = PrivateKey::fromWIF(WIF).getPublicKey().toBase58DER();

    // Two independent parses of the same data have to compare equal.
    EXPECT_EQ(PublicKey::fromBase58DER(base58), PublicKey::fromBase58DER(base58));
    EXPECT_NE(PublicKey::fromBase58DER(base58), PrivateKey::generateRandom().getPublicKey());
    EXPECT_EQ(PublicKey(), PublicKey());
    EXPECT_NE(PublicKey(), PublicKey::fromBase58DER(base58));
}

TEST(Keys, WorksInsideStandardContainers) {
    // Exactly the uses group/keytree relies on.
    std::map<std::string, PublicKey> byUser;
    byUser.emplace("alice", PrivateKey::generateRandom().getPublicKey());
    std::optional<PrivateKey> maybeKey;
    EXPECT_FALSE(maybeKey.has_value());
    maybeKey = PrivateKey::fromWIF(WIF);

    ASSERT_TRUE(maybeKey.has_value());
    EXPECT_EQ(WIF, maybeKey->toWIF());
    EXPECT_EQ(1u, byUser.count("alice"));

    const PublicKey copy = byUser.at("alice");
    EXPECT_EQ(copy, byUser.at("alice"));
}

/// The old implementation accepted a public key in both forms, and external data (a key extracted
/// from a PGP block) arrives uncompressed. The wrapper's first version handled only 33 B and broke
/// `convertPGPAsn1KeyToBase58DERKey`.
TEST(Keys, FromDerAcceptsCompressedAndUncompressed) {
    SKIP_UNLESS_SECP256K1();
    const auto legacyPub = legacy::PrivateKey::fromWIF(WIF).getPublicKey();
    const std::string compressed = legacyPub.toDER();
    const std::string uncompressed = legacyPub.getEcc().getPublicKey(false);

    ASSERT_EQ(33u, compressed.size());
    ASSERT_EQ(65u, uncompressed.size());

    // Both forms describe the same key, so they have to give the same canonical form — under the one
    // secp256k1 tag, even though the uncompressed import is a different `AsymAlg` internally. A second
    // spelling would make a key stop comparing equal to itself.
    EXPECT_EQ(PublicKey::fromDER(compressed), PublicKey::fromDER(uncompressed));
    EXPECT_EQ(PublicKey::fromDER(compressed).toBase58DER(), PublicKey::fromDER(uncompressed).toBase58DER());
    EXPECT_EQ(compressed, decodeTaggedPublicKey(PublicKey::fromDER(uncompressed).toBase58DER()).rawKey);
}

TEST(Keys, MalformedInputIsRejected) {
    EXPECT_ANY_THROW(PublicKey::fromBase58DER("this-is-not-a-key"));
    EXPECT_ANY_THROW(PrivateKey::fromWIF("this-is-not-a-wif"));
}

/// The cut: a key in the pre-3.0.0 encoding is refused by name, not read as secp256k1 by assumption.
TEST(Keys, AnUntaggedKeyIsRefused) {
    SKIP_UNLESS_SECP256K1();
    const auto legacyPub = legacy::PrivateKey::fromWIF(WIF).getPublicKey();

    EXPECT_ANY_THROW(PublicKey::fromBase58DER(legacyPub.toBase58DER()));
    EXPECT_NO_THROW(PublicKey::fromBase58DER(PublicKey::fromDER(legacyPub.toDER()).toBase58DER()));
}

// ---------------------------------------------------------------------------------------------
// Cache
// ---------------------------------------------------------------------------------------------

TEST(PublicKeyCacheTest, ReturnsSameKeyAndCountsEntries) {
    auto cache = PublicKeyCache::getInstance();
    cache->clear();
    const auto base58 = PrivateKey::fromWIF(WIF).getPublicKey().toBase58DER();

    const PublicKey first = cache->fromBase58DER(base58);
    const PublicKey second = cache->fromBase58DER(base58);

    EXPECT_EQ(first, second);
    EXPECT_EQ(base58, first.toBase58DER());
    EXPECT_EQ(1u, cache->size());
    cache->clear();
    EXPECT_EQ(0u, cache->size());
}

TEST(PublicKeyCacheTest, DoesNotCacheUnparsableKey) {
    auto cache = PublicKeyCache::getInstance();
    cache->clear();

    EXPECT_ANY_THROW(cache->fromBase58DER("this-is-not-a-key"));
    EXPECT_EQ(0u, cache->size());
}
