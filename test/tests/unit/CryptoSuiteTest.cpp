/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

/**
 * Tests of the container's algorithm-agility layer (`core::CryptoSuite`).
 *
 * The whole point of this layer comes down to one sentence: **a write follows the choice, a read
 * follows the tag in the data**. Everything else follows from it — the read registry has to be
 * complete in every build, and the tag has to be authenticated, or it could be swapped for a weaker
 * suite. These tests pin those properties, not the particular algorithms.
 *
 * Frame format: `[1 B SuiteId][12 B IV][ciphertext || 16 B tag]`, the tag passed as AAD.
 */

#include <string>

#include <gtest/gtest.h>

#include <privmx/endpoint/core/CoreException.hpp>
#include <privmx/endpoint/core/crypto/CryptoSuite.hpp>

using namespace privmx::endpoint;
using namespace privmx::endpoint::core;

namespace {

std::string keyFor(const CryptoSuite& suite, char fill = 'k') {
    return std::string(suite.keyLength(), fill);
}

} // namespace

// ---------------------------------------------------------------------------------------------
// The suite registry
// ---------------------------------------------------------------------------------------------

/// The **read** registry is complete whatever the build configuration. If the build option narrowed
/// reading too, clients built with different settings could not read each other's data — which is
/// exactly what this layer exists to prevent.
TEST(CryptoSuite, EveryBuildCanReadEverySuite) {
    EXPECT_TRUE(CryptoSuite::isKnown(SuiteId::Aes256GcmSha256));
    EXPECT_TRUE(CryptoSuite::isKnown(SuiteId::Aes256GcmSha512));
    EXPECT_EQ(2u, CryptoSuite::known().size());

    EXPECT_FALSE(CryptoSuite::isKnown(SuiteId::Unknown));
    EXPECT_FALSE(CryptoSuite::isKnown(static_cast<SuiteId>(0x7F)));
    EXPECT_THROW(CryptoSuite::forId(static_cast<SuiteId>(0x7F)), UnknownCryptoSuiteException);
}

TEST(CryptoSuite, DefaultForWriteIsASuiteThisBuildCanRead) {
    EXPECT_TRUE(CryptoSuite::isKnown(CryptoSuite::defaultForWrite().id()));
}

/// Checks that `PRIVMX_DEFAULT_CRYPTO_SUITE` actually **reached the compiled library**, rather than
/// merely being printed at configure time. Such a silent loss has already happened: definitions
/// added by `target_compile_definitions` were wiped by a later
/// `set_target_properties(... COMPILE_DEFINITIONS ...)`, so the build announced one suite and wrote
/// with another — and nothing reported it.
TEST(CryptoSuite, BuildOptionReachedTheLibrary) {
    EXPECT_EQ(
        static_cast<int>(PRIVMX_DEFAULT_CRYPTO_SUITE_ID),
        static_cast<int>(CryptoSuite::defaultForWrite().id())
    ) << "PRIVMX_DEFAULT_CRYPTO_SUITE did not reach privmxendpointcore";
}

/// The tag values are part of the data format — once issued, a value must never be redefined.
TEST(CryptoSuite, SuiteIdsAreFrozen) {
    EXPECT_EQ(0x00, static_cast<int>(SuiteId::Unknown));
    EXPECT_EQ(0x01, static_cast<int>(SuiteId::Aes256GcmSha256));
    EXPECT_EQ(0x02, static_cast<int>(SuiteId::Aes256GcmSha512));
}

TEST(CryptoSuite, PolicyValueRoundTrips) {
    for (const SuiteId id : CryptoSuite::known()) {
        const CryptoSuite suite = CryptoSuite::forId(id);
        const std::string value = suite.policyValue();

        EXPECT_FALSE(value.empty());
        EXPECT_TRUE(CryptoSuite::isKnownPolicyValue(value));
        EXPECT_EQ(id, CryptoSuite::forPolicyValue(value).id());
    }

    EXPECT_FALSE(CryptoSuite::isKnownPolicyValue("rot13"));
    EXPECT_THROW(CryptoSuite::forPolicyValue("rot13"), UnknownCryptoSuiteException);
}

// ---------------------------------------------------------------------------------------------
// The frame
// ---------------------------------------------------------------------------------------------

/// `group` derives the chunk size from the overhead and addresses chunks as
/// `index * encryptedChunkSize(suite)`, so the declared overhead has to match to the byte what the
/// frame actually adds. A one-byte drift means reading chunks from shifted offsets, not a decryption
/// error.
TEST(CryptoSuite, FrameOverheadMatchesWhatTheFrameActuallyAdds) {
    for (const SuiteId id : CryptoSuite::known()) {
        const CryptoSuite suite = CryptoSuite::forId(id);

        for (const size_t length : {size_t{0}, size_t{1}, size_t{100}, size_t{5000}}) {
            const std::string plain(length, 'a');
            const std::string framed = suite.encrypt(keyFor(suite), plain);

            EXPECT_EQ(plain.size() + suite.frameOverhead(), framed.size())
                << "suite " << static_cast<int>(id) << ", length " << length;
        }
    }
}

TEST(CryptoSuite, FrameStartsWithItsSuiteTag) {
    for (const SuiteId id : CryptoSuite::known()) {
        const CryptoSuite suite = CryptoSuite::forId(id);
        const std::string framed = suite.encrypt(keyFor(suite), "anything");

        EXPECT_EQ(static_cast<char>(id), framed[0]) << "suite " << static_cast<int>(id);
        EXPECT_EQ(id, CryptoSuite::readSuiteId(framed)) << "suite " << static_cast<int>(id);
    }
}

/// The heart of the layer: a read does not accept an algorithm being named — it picks one from the
/// tag. That is why data written with any suite reads in a build set to write with another.
TEST(CryptoSuite, AnySuiteIsReadableRegardlessOfTheWriteDefault) {
    for (const SuiteId id : CryptoSuite::known()) {
        const CryptoSuite suite = CryptoSuite::forId(id);
        const std::string key = keyFor(suite);

        for (const std::string& plain : {std::string(), std::string(1, 'x'), std::string(5000, 'y')}) {
            const std::string framed = suite.encrypt(key, plain);
            EXPECT_EQ(plain, CryptoSuite::decrypt(key, framed))
                << "suite " << static_cast<int>(id) << ", length " << plain.size();
        }
    }
}

/// The tag travels as AAD, so it is authenticated. If it were not, an attacker could switch it to a
/// suite with a weaker hash and the read would go their way.
TEST(CryptoSuite, SwappingTheSuiteTagInvalidatesTheFrame) {
    const CryptoSuite suite = CryptoSuite::forId(SuiteId::Aes256GcmSha256);
    const std::string key = keyFor(suite);
    std::string framed = suite.encrypt(key, "secret");

    framed[0] = static_cast<char>(SuiteId::Aes256GcmSha512);

    EXPECT_ANY_THROW(CryptoSuite::decrypt(key, framed));
}

TEST(CryptoSuite, TamperedCiphertextIsRejected) {
    const CryptoSuite suite = CryptoSuite::defaultForWrite();
    const std::string key = keyFor(suite);
    std::string framed = suite.encrypt(key, "secret");

    framed[framed.size() - 1] ^= 0xFF;

    EXPECT_ANY_THROW(CryptoSuite::decrypt(key, framed));
}

TEST(CryptoSuite, WrongKeyIsRejected) {
    const CryptoSuite suite = CryptoSuite::defaultForWrite();
    const std::string framed = suite.encrypt(keyFor(suite, 'k'), "secret");

    EXPECT_ANY_THROW(CryptoSuite::decrypt(keyFor(suite, 'z'), framed));
}

TEST(CryptoSuite, UnknownTagIsReportedAsSuchAndNotAsCorruption) {
    const CryptoSuite suite = CryptoSuite::defaultForWrite();
    std::string framed = suite.encrypt(keyFor(suite), "secret");

    framed[0] = static_cast<char>(0x7F);

    EXPECT_THROW(CryptoSuite::decrypt(keyFor(suite), framed), UnknownCryptoSuiteException);
    EXPECT_EQ(static_cast<SuiteId>(0x7F), CryptoSuite::readSuiteId(framed));
}

TEST(CryptoSuite, FrameShorterThanItsOwnOverheadIsRejected) {
    const CryptoSuite suite = CryptoSuite::defaultForWrite();
    const std::string framed = suite.encrypt(keyFor(suite), "");

    for (const size_t cut : {size_t{0}, size_t{1}, framed.size() - 1}) {
        EXPECT_THROW(CryptoSuite::decrypt(keyFor(suite), framed.substr(0, cut)), Exception)
            << "truncated to " << cut;
    }
}

/// A key that is too short has to be rejected **before** it reaches OpenSSL, which reads as many
/// bytes as the algorithm requires without regard for the length of the string it was given.
TEST(CryptoSuite, KeyOfWrongLengthIsRejectedBeforeReachingTheCipher) {
    for (const SuiteId id : CryptoSuite::known()) {
        const CryptoSuite suite = CryptoSuite::forId(id);

        EXPECT_ANY_THROW(suite.encrypt(std::string(suite.keyLength() - 1, 'k'), "secret"))
            << "suite " << static_cast<int>(id) << ", key too short";
        EXPECT_ANY_THROW(suite.encrypt(std::string(suite.keyLength() + 1, 'k'), "secret"))
            << "suite " << static_cast<int>(id) << ", key too long";
        EXPECT_ANY_THROW(suite.encrypt(std::string(), "secret"))
            << "suite " << static_cast<int>(id) << ", key empty";
    }
}

// ---------------------------------------------------------------------------------------------
// Primitives
// ---------------------------------------------------------------------------------------------

/// The suites differ in their hash — if `hash()` gave the same result in both, the whole choice
/// would be illusory.
TEST(CryptoSuite, SuitesDifferInTheirHash) {
    const std::string data = "data";
    const std::string sha256 = CryptoSuite::forId(SuiteId::Aes256GcmSha256).hash(data);
    const std::string sha512 = CryptoSuite::forId(SuiteId::Aes256GcmSha512).hash(data);

    EXPECT_EQ(32u, sha256.size());
    EXPECT_EQ(64u, sha512.size());
    EXPECT_NE(sha256, sha512);
}

TEST(CryptoSuite, MacAndDeriveKeyFollowTheSuite) {
    const std::string key(32, 'k');

    for (const SuiteId id : CryptoSuite::known()) {
        const CryptoSuite suite = CryptoSuite::forId(id);

        // Deterministic — the same pair of inputs gives the same result.
        EXPECT_EQ(suite.mac(key, "data"), suite.mac(key, "data")) << "suite " << static_cast<int>(id);
        EXPECT_NE(suite.mac(key, "data"), suite.mac(key, "other")) << "suite " << static_cast<int>(id);

        for (const size_t length : {size_t{16}, size_t{32}, size_t{64}}) {
            const std::string derived = suite.deriveKey(key, "label", length);
            EXPECT_EQ(length, derived.size()) << "suite " << static_cast<int>(id);
            EXPECT_EQ(derived, suite.deriveKey(key, "label", length));
            EXPECT_NE(derived, suite.deriveKey(key, "other", length));
        }
    }
}

/// The key length has to match what the suite's cipher requires — `generateKey` takes it from here,
/// so a drift would end in a key rejected on every write.
TEST(CryptoSuite, KeyLengthMatchesWhatTheCipherAccepts) {
    for (const SuiteId id : CryptoSuite::known()) {
        const CryptoSuite suite = CryptoSuite::forId(id);

        EXPECT_EQ(32u, suite.keyLength()) << "suite " << static_cast<int>(id);
        EXPECT_NO_THROW(suite.encrypt(CryptoSuite::randomBytes(suite.keyLength()), "secret"));
    }
}

TEST(CryptoSuite, RandomBytesHasTheRequestedLengthAndVaries) {
    EXPECT_EQ(0u, CryptoSuite::randomBytes(0).size());
    EXPECT_EQ(32u, CryptoSuite::randomBytes(32).size());
    EXPECT_NE(CryptoSuite::randomBytes(32), CryptoSuite::randomBytes(32));
}
