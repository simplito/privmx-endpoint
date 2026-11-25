/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

/**
 * Golden vectors for the composed constructions in `CryptoService`.
 *
 * `kdf`, `prf_tls12`, `getKEM` and `aes256CbcHmac256Encrypt` are not primitives the provider hands
 * over whole — they are built here from HMAC and CBC. That is the kind of code that should not be
 * written twice, and these vectors are what makes it safe to stop writing it: they pin the output
 * so the implementation underneath can be replaced by pmx-crypto's equivalents and the wire format
 * can be shown, not assumed, to be unchanged. The bridge implements the same constructions, so a
 * silent change here would not fail a build — it would fail a conversation between two clients.
 *
 * The expected values are **not** captured from this implementation. They were computed from an
 * independent model of each construction (Python's hmac/hashlib and a separate AES), so a test
 * failure means the construction differs from its specification, not merely from what the code
 * happened to do yesterday — freezing the latter would freeze a bug along with it.
 *
 * Inputs are fixed: key = bytes 0x00..0x1f.
 */

#include <string>

#include <gtest/gtest.h>

#include <privmx/crypto/Crypto.hpp>
#include <privmx/crypto/CryptoException.hpp>

using namespace std;

namespace privmx {
namespace crypto {
namespace {

string key32() {
    string key(32, '\0');
    for (size_t i = 0; i < key.size(); ++i) {
        key[i] = static_cast<char>(i);
    }
    return key;
}

const string DATA = "PrivMX legacy composition vector";
const string LABEL = "privmx-kdf-label";
const string SEED = "privmx-prf-seed";

TEST(CompositionVectorsTest, Kdf) {
    EXPECT_EQ(
        string("\x0e\x4b\xa8\x72\x99\x2e\xdf\xbc\xaf\x35\xf6\x98\x75\xae\xb3\x20"
               "\x2e\xaa\x0a\x19\x49\xab\x58\x38\x60\x78\xae\xa3\xe0\xb7\x37\xaa", 32),
        Crypto::kdf(32, key32(), LABEL)
    );

    // Longer than one HMAC block, so the counter actually advances.
    EXPECT_EQ(
        string("\xe7\x4c\x44\x9e\xe6\xca\x06\x48\x10\xfc\xc1\xf3\xf5\x16\xf8\x64"
               "\x66\x99\x74\x7a\x3b\x61\x93\x99\x94\xeb\xff\x39\x5a\x78\xb8\x03"
               "\xe8\x1f\x3f\x92\xcf\xd7\xa9\x95\xef\x87\xf9\x1a\x71\xf2\xaf\x7e"
               "\x12\x90\x8a\x3b\x40\x6a\xf2\xce\x06\x0a\x5a\xef\xa9\x3d\x48\x5a"
               "\xb4\x02\x5d\x5e\x71\x06\xb9\x3d\x76\x66\x89\x2b\x45\x0b\x12\xc2", 80),
        Crypto::kdf(80, key32(), LABEL)
    );
}

TEST(CompositionVectorsTest, PrfTls12) {
    EXPECT_EQ(
        string("\x82\x19\xd1\xe2\xf4\xf4\xb8\x98\xe9\x52\x11\xe2\xff\xf1\x0c\xa8"
               "\x8c\x78\x8e\x15\x05\xbf\x54\x48\xb5\x71\x4d\x35\x95\x87\xb2\x1e", 32),
        Crypto::prf_tls12(key32(), SEED, 32)
    );

    // A second iteration: the first 32 bytes have to stay identical.
    EXPECT_EQ(
        string("\x82\x19\xd1\xe2\xf4\xf4\xb8\x98\xe9\x52\x11\xe2\xff\xf1\x0c\xa8"
               "\x8c\x78\x8e\x15\x05\xbf\x54\x48\xb5\x71\x4d\x35\x95\x87\xb2\x1e"
               "\xa2\x31\xaf\xf9\xbb\xfa\xf3\x85\x52\xe3\x97\x98\xea\x71\x74\xed", 48),
        Crypto::prf_tls12(key32(), SEED, 48)
    );
}

TEST(CompositionVectorsTest, GetKEM) {
    string kE, kM;
    tie(kE, kM) = Crypto::getKEM(key32());

    EXPECT_EQ(
        string("\x84\x84\x12\x2e\xee\x07\xf5\x61\x1f\x54\x32\x30\xbb\x5d\xd3\x93"
               "\x09\x36\x57\x42\x3c\x3b\xf1\x76\x17\x2f\xb4\xed\x23\x8a\x90\x69", 32),
        kE
    );
    EXPECT_EQ(
        string("\x18\x18\x9a\xfe\xd9\xbd\x22\xd5\xa9\x65\xb7\x50\xf3\x4a\x64\xdf"
               "\x2b\x2d\x1e\x6d\x9d\xbf\x42\xe7\x96\xc1\xd6\xc9\x50\x77\x06\x05", 32),
        kM
    );
}

TEST(CompositionVectorsTest, Aes256CbcHmac256EncryptWithGivenIv) {
    EXPECT_EQ(
        string("\x30\xb5\xb0\xad\x1b\xf5\xc3\xc1\xdf\x76\x89\xa3\x9e\xb3\x0b\xbe"
               "\x0f\x1f\xec\xc9\x4a\x3f\xf1\xd9\xa6\x1f\xa3\xdb\x3c\x77\xd7\x57"
               "\x3a\x4e\x23\x07\x87\x4b\x49\x88\x6a\x0c\x6e\xb8\x8c\xa3\xf9\x45"
               "\x38\xcc\x0b\xf6\x96\x38\x9a\x95\x78\xf4\xb3\x76\xd0\x7c\x5d\xdc"
               "\xb3\xad\xc1\xd2\x1d\xe7\x39\x62\x1a\x95\xda\xc1\x6f\x68\x0b\x04", 80),
        Crypto::aes256CbcHmac256Encrypt(DATA, key32(), string(16, '\0'))
    );
}

/**
 * The deterministic-IV branch: an empty IV means "derive one from the plaintext", which makes the
 * whole ciphertext a function of key and data alone. Pinned separately because it is a different
 * code path and the quieter of the two to break.
 */
TEST(CompositionVectorsTest, Aes256CbcHmac256EncryptWithDerivedIv) {
    EXPECT_EQ(
        string("\x14\xc2\x4b\xc5\x30\x74\xd7\x7f\x4a\x4c\x0b\xa4\xb0\xde\xe0\xa3"
               "\x46\x85\x0c\xe2\x2a\x32\xb0\x0e\x35\x1e\xfd\x7e\x24\xc1\x44\x96"
               "\x10\x5e\xf5\x0b\x12\xe4\xb0\x9c\xf3\xc5\xf6\xf1\xc6\xc9\x6c\xc6"
               "\x35\xd0\xd6\xa3\xd7\x8a\xec\x86\x15\x49\x6d\x74\x12\xd2\x66\x6a"
               "\xe6\x71\x7c\x4b\xf0\x59\x45\xf0\x0c\x9d\xe9\x85\xad\xf1\xd1\xe1", 80),
        Crypto::aes256CbcHmac256Encrypt(DATA, key32(), string())
    );
}

TEST(CompositionVectorsTest, Aes256CbcHmac256RoundTrip) {
    const string cipher = Crypto::aes256CbcHmac256Encrypt(DATA, key32(), string(16, '\0'));
    EXPECT_EQ(DATA, Crypto::aes256CbcHmac256Decrypt(cipher, key32()));
}

/// A tampered tag has to be refused rather than returning plaintext.
TEST(CompositionVectorsTest, Aes256CbcHmac256RejectsATamperedTag) {
    string cipher = Crypto::aes256CbcHmac256Encrypt(DATA, key32(), string(16, '\0'));
    cipher[cipher.size() - 1] ^= 0xFF;

    EXPECT_THROW(Crypto::aes256CbcHmac256Decrypt(cipher, key32()), WrongMessageSecurityTagException);
}

TEST(CompositionVectorsTest, GenerateIv) {
    EXPECT_EQ(
        string("\x8b\xfb\x0e\xa2\x68\x36\xeb\x72\x29\xdf\x1b\x7e\x55\xb6\x64\x8d", 16),
        Crypto::generateIv(key32(), 7)
    );
}

} // namespace
} // namespace crypto
} // namespace privmx
