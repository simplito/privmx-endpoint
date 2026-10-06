/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include <algorithm>
#include <string>

#include <gtest/gtest.h>

#include <privmx/endpoint/core/CoreException.hpp>
#include <privmx/endpoint/core/crypto/CryptoSuite.hpp>

using namespace privmx::endpoint::core;
using namespace privmx::endpoint::core::crypto;

namespace {

const std::string PLAINTEXT{"Wiadomosc testowa o dlugosci wiekszej niz jeden blok AES."};

std::string key32() {
    return CryptoSuite::defaultForWrite().randomBytes(32);
}

} // namespace

/// Testy przebiegaja po calym rejestrze, zamiast byc pisane per wariant - inaczej
/// pokrycie zostaloby w tyle przy kazdym dodanym zestawie.
class CryptoSuiteAllSuites : public ::testing::TestWithParam<SuiteId> {};

INSTANTIATE_TEST_SUITE_P(
    Registry,
    CryptoSuiteAllSuites,
    ::testing::ValuesIn(CryptoSuite::known()),
    [](const ::testing::TestParamInfo<SuiteId>& info) {
        return "Suite" + std::to_string(static_cast<unsigned>(info.param));
    }
);

TEST_P(CryptoSuiteAllSuites, RoundTrip) {
    const auto suite = CryptoSuite::forId(GetParam());
    const std::string key = key32();

    const std::string framed = suite.encrypt(key, PLAINTEXT);

    EXPECT_NE(framed.find(PLAINTEXT), 0u) << "dane nie moga byc widoczne jawnie";
    EXPECT_EQ(PLAINTEXT, CryptoSuite::decrypt(key, framed));
}

TEST_P(CryptoSuiteAllSuites, FrameCarriesSuiteId) {
    const auto suite = CryptoSuite::forId(GetParam());
    const std::string framed = suite.encrypt(key32(), PLAINTEXT);

    EXPECT_EQ(GetParam(), CryptoSuite::readSuiteId(framed));
}

TEST_P(CryptoSuiteAllSuites, DecryptNeedsNoAlgorithmHint) {
    // Sedno warstwy: odczyt dobiera zestaw z ramki, a nie z wiedzy wolajacego.
    const auto suite = CryptoSuite::forId(GetParam());
    const std::string key = key32();

    EXPECT_EQ(PLAINTEXT, CryptoSuite::decrypt(key, suite.encrypt(key, PLAINTEXT)));
}

TEST_P(CryptoSuiteAllSuites, EncryptIsRandomized) {
    const auto suite = CryptoSuite::forId(GetParam());
    const std::string key = key32();

    EXPECT_NE(suite.encrypt(key, PLAINTEXT), suite.encrypt(key, PLAINTEXT)) << "IV musi byc losowe";
}

TEST_P(CryptoSuiteAllSuites, TamperedCiphertextIsRejected) {
    const auto suite = CryptoSuite::forId(GetParam());
    const std::string key = key32();
    std::string framed = suite.encrypt(key, PLAINTEXT);

    framed[framed.size() - 1] = static_cast<char>(framed[framed.size() - 1] ^ 0x01);

    EXPECT_ANY_THROW(CryptoSuite::decrypt(key, framed));
}

TEST_P(CryptoSuiteAllSuites, WrongKeyIsRejected) {
    const auto suite = CryptoSuite::forId(GetParam());
    const std::string framed = suite.encrypt(key32(), PLAINTEXT);

    EXPECT_ANY_THROW(CryptoSuite::decrypt(key32(), framed));
}

TEST_P(CryptoSuiteAllSuites, DeriveKeyHasRequestedLength) {
    const auto suite = CryptoSuite::forId(GetParam());

    EXPECT_EQ(32u, suite.deriveKey("sekret", "etykieta", 32).size());
    EXPECT_EQ(64u, suite.deriveKey("sekret", "etykieta", 64).size());
}

TEST_P(CryptoSuiteAllSuites, DeriveKeyIsDeterministic) {
    const auto suite = CryptoSuite::forId(GetParam());

    EXPECT_EQ(suite.deriveKey("sekret", "etykieta", 32), suite.deriveKey("sekret", "etykieta", 32));
    EXPECT_NE(suite.deriveKey("sekret", "etykieta", 32), suite.deriveKey("sekret", "inna", 32));
}

/// Podmiana znacznika zestawu na slabszy musi zostac wykryta - znacznik idzie jako AAD.
/// To jest zabezpieczenie przed downgrade, ktorego nie ma stary bajt CipherType.
TEST(CryptoSuite, TamperedSuiteIdIsRejected) {
    const auto written = CryptoSuite::forId(SuiteId::Aes256GcmSha512);
    const std::string key = key32();
    std::string framed = written.encrypt(key, PLAINTEXT);
    ASSERT_EQ(SuiteId::Aes256GcmSha512, CryptoSuite::readSuiteId(framed));

    framed[0] = static_cast<char>(SuiteId::Aes256GcmSha256);

    EXPECT_ANY_THROW(CryptoSuite::decrypt(key, framed));
}

TEST(CryptoSuite, UnknownSuiteIdIsRejected) {
    EXPECT_FALSE(CryptoSuite::isKnown(static_cast<SuiteId>(0xFE)));
    EXPECT_THROW(CryptoSuite::forId(static_cast<SuiteId>(0xFE)), UnknownCryptoSuiteException);

    std::string framed = CryptoSuite::defaultForWrite().encrypt(key32(), PLAINTEXT);
    framed[0] = static_cast<char>(0xFE);
    EXPECT_THROW(CryptoSuite::decrypt(key32(), framed), UnknownCryptoSuiteException);
}

TEST(CryptoSuite, MalformedFrameIsRejected) {
    EXPECT_THROW(CryptoSuite::readSuiteId(""), MalformedCryptoFrameException);
    EXPECT_THROW(CryptoSuite::decrypt(key32(), ""), MalformedCryptoFrameException);

    const std::string tooShort(4, static_cast<char>(SuiteId::Aes256GcmSha256));
    EXPECT_THROW(CryptoSuite::decrypt(key32(), tooShort), MalformedCryptoFrameException);
}

TEST(CryptoSuite, RegistryIsCompleteAndDefaultBelongsToIt) {
    const auto all = CryptoSuite::known();

    ASSERT_FALSE(all.empty());
    EXPECT_NE(std::find(all.begin(), all.end(), CryptoSuite::defaultForWrite().id()), all.end());
    for (SuiteId id : all) {
        EXPECT_TRUE(CryptoSuite::isKnown(id));
        EXPECT_NE(SuiteId::Unknown, id);
    }
}

TEST(CryptoSuite, HashLengthFollowsSuite) {
    EXPECT_EQ(32u, CryptoSuite::forId(SuiteId::Aes256GcmSha256).hash(PLAINTEXT).size());
    EXPECT_EQ(64u, CryptoSuite::forId(SuiteId::Aes256GcmSha512).hash(PLAINTEXT).size());
}

TEST(CryptoSuite, MacLengthFollowsSuite) {
    const std::string key = key32();
    EXPECT_EQ(32u, CryptoSuite::forId(SuiteId::Aes256GcmSha256).mac(key, PLAINTEXT).size());
    EXPECT_EQ(64u, CryptoSuite::forId(SuiteId::Aes256GcmSha512).mac(key, PLAINTEXT).size());
}

TEST(CryptoSuite, RandomBytesHasRequestedLength) {
    const auto suite = CryptoSuite::defaultForWrite();

    EXPECT_EQ(16u, suite.randomBytes(16).size());
    EXPECT_EQ(32u, suite.randomBytes(32).size());
    EXPECT_NE(suite.randomBytes(32), suite.randomBytes(32));
}
