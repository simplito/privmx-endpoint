/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include <string>

#include <gtest/gtest.h>

#include <privmx/endpoint/core/Buffer.hpp>
#include <privmx/endpoint/core/CoreTypes.hpp>
#include <privmx/endpoint/core/KeyProvider.hpp>
#include <privmx/endpoint/core/crypto/CryptoSuite.hpp>
#include <privmx/endpoint/core/crypto/PrivateKey.hpp>
#include <privmx/endpoint/core/encryptors/DataEncryptor.hpp>
#include <privmx/endpoint/core/encryptors/DataInnerEncryptorV4.hpp>

using namespace privmx::endpoint::core;

namespace {

const std::string KEY32(32, 'k');
const std::string PLAIN{"container contents"};

/// A suite other than this build's default — needed so the test can tell "took it from the key"
/// apart from "took a constant".
CryptoSuite nonDefaultSuite() {
    for (const SuiteId id : CryptoSuite::known()) {
        if (id != CryptoSuite::defaultForWrite().id()) {
            return CryptoSuite::forId(id);
        }
    }
    throw std::logic_error("the registry holds only one suite — this test cannot be run");
}

} // namespace

// ---------------------------------------------------------------------------------------------
// `EncKey::suite` carries the suite choice taken from the container's policy (level 2). These
// tests guard the one property that matters: that the suite attached to a key really does land in
// the data, and is not dropped along the way in favour of a compile-time constant.
// ---------------------------------------------------------------------------------------------

TEST(EncKeySuite, DefaultsToBuildWriteSuite) {
    EXPECT_EQ(CryptoSuite::defaultForWrite().id(), EncKey{}.suite.id());
}

TEST(EncKeySuite, InnerEncryptorWritesWithSuiteFromKey) {
    const CryptoSuite other = nonDefaultSuite();
    ASSERT_NE(CryptoSuite::defaultForWrite().id(), other.id());

    DataInnerEncryptorV4 encryptor;
    const EncKey encKey{.id = "k1", .key = KEY32, .suite = other};

    const std::string framed = encryptor.encrypt(Buffer::from(PLAIN), encKey).stdString();

    EXPECT_EQ(other.id(), CryptoSuite::readSuiteId(framed));
    // Reading follows the frame's own tag, so it need not know what the data was written with.
    EXPECT_EQ(PLAIN, encryptor.decrypt(Buffer::from(framed), encKey.key).stdString());
}

TEST(EncKeySuite, InnerEncryptorFallsBackToDefaultWhenKeyCarriesNoChoice) {
    DataInnerEncryptorV4 encryptor;
    const EncKey encKey{.id = "k1", .key = KEY32};

    const std::string framed = encryptor.encrypt(Buffer::from(PLAIN), encKey).stdString();

    EXPECT_EQ(CryptoSuite::defaultForWrite().id(), CryptoSuite::readSuiteId(framed));
}

TEST(EncKeySuite, DataEncryptorWritesWithSuiteFromKey) {
    const CryptoSuite other = nonDefaultSuite();
    DataEncryptor<Pson::BinaryString> encryptor;
    const EncKey encKey{.id = "k1", .key = KEY32, .suite = other};

    const std::string base64 = encryptor.encrypt(Pson::BinaryString(PLAIN), encKey);
    const std::string framed = privmx::utils::Base64::toString(base64);

    EXPECT_EQ(other.id(), CryptoSuite::readSuiteId(framed));
    EXPECT_EQ(PLAIN, std::string(encryptor.decrypt(base64, encKey)));
}

/// The raw-key overload has nowhere to take a suite from, so it must use the default — including
/// when an `EncKey` naming another one exists alongside. Otherwise "write with this key" would mean
/// different things depending on which overload the caller happened to reach.
TEST(EncKeySuite, RawKeyOverloadAlwaysUsesDefault) {
    DataEncryptor<Pson::BinaryString> encryptor;

    const std::string base64 = encryptor.encrypt(Pson::BinaryString(PLAIN), KEY32);
    const std::string framed = privmx::utils::Base64::toString(base64);

    EXPECT_EQ(CryptoSuite::defaultForWrite().id(), CryptoSuite::readSuiteId(framed));
}

/// Data written with one suite must be readable by any key of the same value, whatever suite the
/// `EncKey` used for reading happens to carry. That is precisely why `suite` concerns writing only.
TEST(EncKeySuite, ReadIgnoresSuiteOnTheKeyAndFollowsTheFrame) {
    const CryptoSuite other = nonDefaultSuite();
    DataEncryptor<Pson::BinaryString> encryptor;

    const std::string base64 = encryptor.encrypt(
        Pson::BinaryString(PLAIN), EncKey{.id = "k1", .key = KEY32, .suite = other}
    );

    const EncKey readerKey{.id = "k1", .key = KEY32, .suite = CryptoSuite::defaultForWrite()};
    EXPECT_EQ(PLAIN, std::string(encryptor.decrypt(base64, readerKey)));
}

// ---------------------------------------------------------------------------------------------
// The invariant: a freshly generated key is as long as its suite requires. Before the change
// `generateKey` always returned 32 bytes, which was correct only because both of today's suites
// happen to want exactly that.
// ---------------------------------------------------------------------------------------------

TEST(EncKeySuite, GeneratedKeyMatchesItsSuite) {
    KeyProvider provider(PrivateKey::generateRandom(), [] { return nullptr; });

    for (const SuiteId id : CryptoSuite::known()) {
        const CryptoSuite suite = CryptoSuite::forId(id);
        const EncKey key = provider.generateKey(suite);

        EXPECT_EQ(suite.id(), key.suite.id());
        EXPECT_EQ(suite.keyLength(), key.key.size());
        EXPECT_FALSE(key.id.empty());
        // The key must be immediately usable with its own suite — this catches a drift between
        // `keyLength()` and what was actually generated.
        EXPECT_NO_THROW(suite.encrypt(key.key, PLAIN));
    }
}

TEST(EncKeySuite, GeneratedKeysDiffer) {
    KeyProvider provider(PrivateKey::generateRandom(), [] { return nullptr; });
    const CryptoSuite suite = CryptoSuite::defaultForWrite();

    const EncKey first = provider.generateKey(suite);
    const EncKey second = provider.generateKey(suite);

    EXPECT_NE(first.key, second.key);
    EXPECT_NE(first.id, second.id);
}
