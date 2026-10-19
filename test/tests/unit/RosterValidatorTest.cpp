/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

/**
 * Format-only validation of a roster.
 *
 * A membership change in a tree-backed group wraps to the handful of leaves beside one path and passes the rest
 * of the roster only so the server can be told who the members are. Validating every entry as a curve point cost
 * 3.0 s at 16 384 members — a full subgroup check per key inside the ECC driver — for keys the operation never
 * touches. `validateUserListFormat` checks that they are well-formed and stops there.
 *
 * "Format only" must not quietly become "nothing is checked", which is what these tests are for. Whatever a key
 * has to survive to reach a cryptographic operation is still checked at that operation, in full.
 */

#include <gtest/gtest.h>

#include <string>
#include <vector>

#include <privmx/endpoint/core/crypto/PrivateKey.hpp>
#include <privmx/endpoint/core/CoreException.hpp>
#include <privmx/endpoint/core/Types.hpp>
#include <privmx/endpoint/core/Validator.hpp>
#include <privmx/endpoint/core/crypto/FormatHash.hpp>
#include <privmx/endpoint/core/crypto/KeyFormats.hpp>
#include <privmx/utils/Base58.hpp>

using privmx::endpoint::core::PrivateKey;
using privmx::endpoint::core::UserWithPubKey;
using privmx::endpoint::core::Validator;

namespace {

std::string validKey() {
    return PrivateKey::generateRandom().getPublicKey().toBase58DER();
}

std::vector<UserWithPubKey> roster(std::size_t count) {
    std::vector<UserWithPubKey> users;
    for (std::size_t i = 0; i < count; ++i) {
        users.push_back(UserWithPubKey{"user_" + std::to_string(i), validKey()});
    }
    return users;
}

} // namespace

TEST(RosterValidator, AcceptsAWellFormedRoster) {
    EXPECT_NO_THROW(Validator::validateUserListFormat(roster(64), "field:users"));
}

TEST(RosterValidator, RefusesAKeyOutsideTheBase58Alphabet) {
    auto users = roster(4);
    users[2].pubKey = "0OIl" + users[2].pubKey.substr(4);   // the four characters base58 leaves out
    EXPECT_THROW(Validator::validateUserListFormat(users, "field:users"), privmx::endpoint::core::Exception);
}

TEST(RosterValidator, RefusesATruncatedKey) {
    // Truncation survives the alphabet check and dies on the checksum, which is why the checksum is part of the
    // cheap path rather than left to whoever eventually parses the key.
    auto users = roster(4);
    users[1].pubKey = users[1].pubKey.substr(0, users[1].pubKey.size() - 3);
    EXPECT_THROW(Validator::validateUserListFormat(users, "field:users"), privmx::endpoint::core::Exception);
}

TEST(RosterValidator, RefusesACorruptedKeyWhoseChecksumNoLongerMatches) {
    auto users = roster(4);
    std::string& key = users[3].pubKey;
    key[5] = key[5] == 'a' ? 'b' : 'a';
    EXPECT_THROW(Validator::validateUserListFormat(users, "field:users"), privmx::endpoint::core::Exception);
}

TEST(RosterValidator, RefusesSomethingThatDecodesButIsNotAPointEncoding) {
    // The point at infinity is spelled exactly like this — a single zero byte — and `EC_POINT_oct2point` accepts
    // it. A key of the wrong length has no business in a roster whatever the curve says about it.
    auto users = roster(2);
    users[0].pubKey = privmx::utils::Base58::encodeWithChecksum(
        std::string(1, '\0'), privmx::endpoint::core::FormatHash::sha256
    );
    EXPECT_THROW(Validator::validateUserListFormat(users, "field:users"), privmx::endpoint::core::Exception);
}

TEST(RosterValidator, RefusesAnEmptyUserId) {
    auto users = roster(2);
    users[1].userId = "";
    EXPECT_THROW(Validator::validateUserListFormat(users, "field:users"), privmx::endpoint::core::Exception);
}

TEST(RosterValidator, RefusesAnEncodingWithoutAnAlgorithmTag) {
    // The encodings used before the 3.0.0 cut: a bare compressed point, and a bare uncompressed one. Both are
    // well-formed Base58Check and both are refused, because a key has to say which algorithm it is. A key
    // imported from an uncompressed point is re-encoded compressed under the secp256k1 tag.
    for (const std::size_t length : {std::size_t{33}, std::size_t{65}}) {
        std::string der(length, '\0');
        der[0] = length == 33 ? 0x02 : 0x04;
        EXPECT_THROW(
            Validator::validatePubKeyFormat(
                privmx::utils::Base58::encodeWithChecksum(der, privmx::endpoint::core::FormatHash::sha256),
                "field:pubKey"
            ),
            privmx::endpoint::core::Exception
        ) << "length " << length;
    }
}

TEST(RosterValidator, WhatItDeliberatelyDoesNotDo) {
    // Specific to secp256k1: the gap between the two checks is a byte string that is a well-formed key
    // but not a point on the curve, and "not a point" is a notion this curve has. Under another
    // identity algorithm the same gap exists but is reached differently, so this case describes the
    // build it was written for rather than asserting something false about the other.
    if (privmx::endpoint::core::defaultKeyAlgorithm() != privmx::cryptoservice::AsymAlg::PrivmxSecp256k1) {
        GTEST_SKIP() << "describes the secp256k1 curve check";
    }
    std::string der(33, '\0');
    der[0] = 0x02;
    for (std::size_t i = 1; i < der.size(); ++i) {
        der[i] = static_cast<char>(0xFF);   // x = 2^256-1 > p, so no point exists
    }
    const std::string encoded = privmx::endpoint::core::encodeTaggedPublicKey(
        der, privmx::endpoint::core::defaultKeyAlgorithm()
    );
    EXPECT_NO_THROW(Validator::validatePubKeyFormat(encoded, "field:pubKey"));
    EXPECT_THROW(Validator::validatePubKeyBase58DER(encoded, "field:pubKey"), privmx::endpoint::core::Exception);
}
