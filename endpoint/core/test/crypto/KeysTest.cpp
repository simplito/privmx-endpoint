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

#include <privmx/endpoint/core/CoreException.hpp>
#include <privmx/endpoint/core/crypto/PrivateKey.hpp>
#include <privmx/endpoint/core/crypto/PublicKey.hpp>
#include <privmx/endpoint/core/crypto/PublicKeyCache.hpp>

using namespace privmx::endpoint::core;

namespace legacy = privmx::crypto;

namespace {

// Wektor z zestawu testowego pmx-crypto (ProviderTest_FromWifAndToWif).
const std::string WIF{"L1YwTwAr8dQCBzfmXBzh6ggBkYbLuu15Tc7s4bajrRNDbsogs9a5"};
const std::string MESSAGE{"Wiadomosc do podpisania"};

} // namespace

// ---------------------------------------------------------------------------------------------
// Zgodnosc ze stara implementacja. To jest warunek migracji 76 plikow: gdyby ktorykolwiek z tych
// testow padl, przepiecie modulow zmienialoby dane na wire, a nie tylko typy w kodzie.
// ---------------------------------------------------------------------------------------------

TEST(Keys, WifImportExportMatchesLegacy) {
    EXPECT_EQ(legacy::PrivateKey::fromWIF(WIF).toWIF(), PrivateKey::fromWIF(WIF).toWIF());
    EXPECT_EQ(WIF, PrivateKey::fromWIF(WIF).toWIF());
}

TEST(Keys, PublicKeyEncodingMatchesLegacy) {
    const auto legacyPriv = legacy::PrivateKey::fromWIF(WIF);
    const auto priv = PrivateKey::fromWIF(WIF);

    EXPECT_EQ(legacyPriv.getPublicKey().toBase58DER(), priv.getPublicKey().toBase58DER());
    EXPECT_EQ(legacyPriv.getPublicKey().toDER(), priv.getPublicKey().toDER());
}

TEST(Keys, RawPrivatePartMatchesLegacy) {
    EXPECT_EQ(legacy::PrivateKey::fromWIF(WIF).getPrivateEncKey(), PrivateKey::fromWIF(WIF).getPrivateEncKey());
}

TEST(Keys, FromRawMatchesLegacyEccFromPrivateKey) {
    const std::string raw = legacy::PrivateKey::fromWIF(WIF).getPrivateEncKey();
    const auto legacyKey = legacy::PrivateKey(legacy::ECC::fromPrivateKey(raw));

    EXPECT_EQ(legacyKey.toWIF(), PrivateKey::fromRaw(raw).toWIF());
    EXPECT_EQ(legacyKey.getPublicKey().toBase58DER(), PrivateKey::fromRaw(raw).getPublicKey().toBase58DER());
}

TEST(Keys, SharedSecretMatchesLegacy) {
    const auto legacyPriv = legacy::PrivateKey::fromWIF(WIF);
    const auto legacyPeer = legacy::PrivateKey::generateRandom();
    const auto priv = PrivateKey::fromWIF(WIF);
    const auto peer = PublicKey::fromBase58DER(legacyPeer.getPublicKey().toBase58DER());

    EXPECT_EQ(legacyPriv.derive(legacyPeer.getPublicKey()), priv.derive(peer));
}

/// Najwazniejszy test zgodnosci: podpis zlozony nowa implementacja musi przejsc weryfikacje stara
/// i odwrotnie. Zabezpiecza przed pomylka Compact / CompactWithHash.
TEST(Keys, SignaturesVerifyAcrossImplementations) {
    const auto legacyPriv = legacy::PrivateKey::fromWIF(WIF);
    const auto priv = PrivateKey::fromWIF(WIF);

    const std::string legacySig = legacyPriv.signToCompactSignatureWithHash(MESSAGE);
    const std::string sig = priv.signToCompactSignatureWithHash(MESSAGE);

    EXPECT_EQ(65u, sig.size());
    EXPECT_TRUE(priv.getPublicKey().verifyCompactSignatureWithHash(MESSAGE, legacySig))
        << "nowa weryfikacja nie przyjmuje starego podpisu";
    EXPECT_TRUE(legacyPriv.getPublicKey().verifyCompactSignatureWithHash(MESSAGE, sig))
        << "stara weryfikacja nie przyjmuje nowego podpisu";
}

TEST(Keys, SignatureIsRejectedForOtherMessageAndKey) {
    const auto priv = PrivateKey::fromWIF(WIF);
    const std::string sig = priv.signToCompactSignatureWithHash(MESSAGE);

    EXPECT_FALSE(priv.getPublicKey().verifyCompactSignatureWithHash(MESSAGE + "!", sig));
    EXPECT_FALSE(PrivateKey::generateRandom().getPublicKey().verifyCompactSignatureWithHash(MESSAGE, sig));
}

// ---------------------------------------------------------------------------------------------
// Semantyka wartosciowa - to dla niej w ogole powstal wrapper.
// ---------------------------------------------------------------------------------------------

TEST(Keys, DefaultConstructedIsEmpty) {
    EXPECT_TRUE(PublicKey().empty());
    EXPECT_TRUE(PrivateKey().empty());
    EXPECT_THROW(PublicKey().toBase58DER(), MalformedEncryptionKeyException);
    EXPECT_THROW(PrivateKey().toWIF(), MalformedEncryptionKeyException);
}

TEST(Keys, PublicKeyComparesByValueNotByHandle) {
    const auto base58 = PrivateKey::fromWIF(WIF).getPublicKey().toBase58DER();

    // Dwa niezalezne parsowania tych samych danych musza byc rowne.
    EXPECT_EQ(PublicKey::fromBase58DER(base58), PublicKey::fromBase58DER(base58));
    EXPECT_NE(PublicKey::fromBase58DER(base58), PrivateKey::generateRandom().getPublicKey());
    EXPECT_EQ(PublicKey(), PublicKey());
    EXPECT_NE(PublicKey(), PublicKey::fromBase58DER(base58));
}

TEST(Keys, WorksInsideStandardContainers) {
    // Dokladnie te uzycia, na ktorych opiera sie group/keytree.
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

TEST(Keys, MalformedInputIsRejected) {
    EXPECT_ANY_THROW(PublicKey::fromBase58DER("to-nie-jest-klucz"));
    EXPECT_ANY_THROW(PrivateKey::fromWIF("to-nie-jest-wif"));
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

    EXPECT_ANY_THROW(cache->fromBase58DER("to-nie-jest-klucz"));
    EXPECT_EQ(0u, cache->size());
}
