/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

/**
 * Golden vectors for the PrivMX KDF, at the entry point that still has callers.
 *
 * These values were computed from an independent model of the construction (Python's hmac/hashlib),
 * not captured from this implementation, and they arrive here from `CompositionVectorsTest`, where
 * they covered `privmx::crypto::Crypto::kdf`. That function is gone — nothing called it — but the
 * construction underneath is the same one and is very much alive: `FormatHash::kdf` derives the
 * wrapping key for every container key sent to a 25519 identity (`Ecies.cpp`), so these bytes are on
 * the wire. Moving the vectors rather than deleting them with their old caller is the whole point.
 *
 * `FormatHash` is deliberately not suite-dependent: the hash here is fixed by the format and must
 * not follow `PRIVMX_DEFAULT_CRYPTO_SUITE`, which is exactly what a pinned vector is for.
 *
 * Input is fixed: secret = bytes 0x00..0x1f.
 */

#include <string>

#include <gtest/gtest.h>

#include <privmx/endpoint/core/crypto/FormatHash.hpp>

using namespace std;
using namespace privmx::endpoint::core;

namespace {

string secret32() {
    string secret(32, '\0');
    for (size_t i = 0; i < secret.size(); ++i) {
        secret[i] = static_cast<char>(i);
    }
    return secret;
}

const string LABEL = "privmx-kdf-label";

TEST(FormatHashVectorsTest, Kdf) {
    EXPECT_EQ(
        string("\x0e\x4b\xa8\x72\x99\x2e\xdf\xbc\xaf\x35\xf6\x98\x75\xae\xb3\x20"
               "\x2e\xaa\x0a\x19\x49\xab\x58\x38\x60\x78\xae\xa3\xe0\xb7\x37\xaa", 32),
        FormatHash::kdf(secret32(), LABEL, 32)
    );
}

/// Longer than one HMAC block, so the counter actually advances.
TEST(FormatHashVectorsTest, KdfAcrossSeveralBlocks) {
    EXPECT_EQ(
        string("\xe7\x4c\x44\x9e\xe6\xca\x06\x48\x10\xfc\xc1\xf3\xf5\x16\xf8\x64"
               "\x66\x99\x74\x7a\x3b\x61\x93\x99\x94\xeb\xff\x39\x5a\x78\xb8\x03"
               "\xe8\x1f\x3f\x92\xcf\xd7\xa9\x95\xef\x87\xf9\x1a\x71\xf2\xaf\x7e"
               "\x12\x90\x8a\x3b\x40\x6a\xf2\xce\x06\x0a\x5a\xef\xa9\x3d\x48\x5a"
               "\xb4\x02\x5d\x5e\x71\x06\xb9\x3d\x76\x66\x89\x2b\x45\x0b\x12\xc2", 80),
        FormatHash::kdf(secret32(), LABEL, 80)
    );
}

/// The label is domain separation, so two labels over one secret must not agree.
TEST(FormatHashVectorsTest, KdfSeparatesByLabel) {
    EXPECT_NE(FormatHash::kdf(secret32(), LABEL, 32), FormatHash::kdf(secret32(), LABEL + "2", 32));
}

} // namespace
