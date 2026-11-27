/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

/**
 * Base58 arrived here from the `crypto/` module, and changed its API on the way: the
 * checksummed variants take their hash function from outside, because `utils` cannot call into
 * cryptography. These tests check that the encoding itself did not change along with it.
 */

#include <string>

#include <gtest/gtest.h>

#include <privmx/utils/Base58.hpp>
#include <privmx/utils/PrivmxException.hpp>

using privmx::utils::Base58;

namespace {

/// A stand-in SHA-256 for the test — a fixed function, so that cryptography is not pulled in here.
/// It does not compute a real SHA-256; all that is checked is that the checksum is computed with
/// **the function given** and that its result really decides whether data is rejected.
std::string fakeSha256(const std::string& data) {
    std::string out(32, '\0');
    for (std::size_t i = 0; i < data.size(); ++i) {
        out[i % 32] = static_cast<char>(out[i % 32] ^ data[i] ^ static_cast<char>(i));
    }
    return out;
}

std::string otherSha256(const std::string& data) {
    return fakeSha256(data + "other");
}

} // namespace

// ---------------------------------------------------------------------------------------------
// The encoding itself — no cryptography.
// ---------------------------------------------------------------------------------------------

TEST(Base58Test, KnownVectors) {
    EXPECT_EQ("2g", Base58::encode("a"));
    EXPECT_EQ("StV1DL6CwTryKyV", Base58::encode("hello world"));
}

TEST(Base58Test, RoundTrip) {
    for (const std::string& s : {std::string("a"), std::string("hello world"),
                                 std::string("\x00\x00\x01\x02", 4), std::string(100, 'z')}) {
        EXPECT_EQ(s, Base58::decode(Base58::encode(s)));
    }
}

/**
 * An all-zero input does not round-trip: `encode("")` gives "1", while `decode("1")` gives a zero
 * byte. The cause is that the zero padding is counted alongside the numeric value, which for
 * all-zero input is empty.
 *
 * This behaviour is **inherited**, not introduced by the move — and deliberately left unfixed,
 * because Base58 encodes keys here and changing the encoding would change their form on disk and
 * on the wire. Unreachable in practice: a public key starts with 0x02/0x03 and a WIF with 0x80.
 *
 * The test records the actual state of affairs, so that nobody takes it for an accident.
 */
TEST(Base58Test, AllZeroInputDoesNotRoundTripAndThatIsKnown) {
    EXPECT_EQ("1", Base58::encode(""));
    EXPECT_EQ("11", Base58::encode(std::string(1, '\0')));

    EXPECT_NE("", Base58::decode(Base58::encode("")));
}

/// Leading zeros are encoded as '1' and have to survive a round trip — the commonest Base58 bug.
TEST(Base58Test, LeadingZerosSurvive) {
    const std::string s("\x00\x00\x00\x2a", 4);

    const std::string encoded = Base58::encode(s);

    EXPECT_EQ("111", encoded.substr(0, 3));
    EXPECT_EQ(s, Base58::decode(encoded));
}

TEST(Base58Test, IsAcceptsOnlyTheAlphabet) {
    EXPECT_TRUE(Base58::is("StV1DL6CwTryKyV"));
    EXPECT_TRUE(Base58::is(""));
    // Characters excluded from the Base58 alphabet because they are easily confused by eye.
    EXPECT_FALSE(Base58::is("0"));
    EXPECT_FALSE(Base58::is("O"));
    EXPECT_FALSE(Base58::is("I"));
    EXPECT_FALSE(Base58::is("l"));
    EXPECT_FALSE(Base58::is("has a space"));
}

// ---------------------------------------------------------------------------------------------
// Base58Check — the checksum computed with the injected function.
// ---------------------------------------------------------------------------------------------

TEST(Base58Test, ChecksumRoundTrip) {
    const std::string payload("data to encode");

    const std::string encoded = Base58::encodeWithChecksum(payload, fakeSha256);

    EXPECT_EQ(payload, Base58::decodeWithChecksum(encoded, fakeSha256));
}

/// The crux of the API change: the checksum must come from the function **given**. Were the
/// implementation to call anything else, a read with a different function would succeed.
TEST(Base58Test, ChecksumIsComputedWithTheGivenFunction) {
    const std::string encoded = Base58::encodeWithChecksum("data", fakeSha256);

    EXPECT_THROW(Base58::decodeWithChecksum(encoded, otherSha256), privmx::utils::PrivmxException);
}

TEST(Base58Test, CorruptedPayloadIsRejected) {
    std::string encoded = Base58::encodeWithChecksum("data to encode", fakeSha256);

    encoded[2] = (encoded[2] == 'z' ? 'y' : 'z');
    EXPECT_THROW(Base58::decodeWithChecksum(encoded, fakeSha256), privmx::utils::PrivmxException);
}

/// Input shorter than the checksum itself. Before the move `data.length() - 4` wrapped around and
/// `substr` was handed a value near the top of the `size_t` range.
TEST(Base58Test, InputShorterThanTheChecksumIsRejected) {
    EXPECT_THROW(Base58::decodeWithChecksum("", fakeSha256), privmx::utils::PrivmxException);
    EXPECT_THROW(Base58::decodeWithChecksum("2g", fakeSha256), privmx::utils::PrivmxException);
}
