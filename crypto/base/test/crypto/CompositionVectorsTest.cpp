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
 * `prf_tls12` and the CBC+HMAC frame are not primitives the provider hands over whole — they are
 * built from HMAC and CBC. That is the kind of code that should not be written twice, and these
 * vectors are what made it safe to stop writing it: they pin the output so the implementation
 * underneath could be replaced by pmx-crypto's equivalents and the wire format shown, not assumed,
 * to be unchanged. The bridge implements the same constructions, so a silent change here would not
 * fail a build — it would fail a conversation between two clients.
 *
 * The expected values are **not** captured from this implementation. They were computed from an
 * independent model of each construction (Python's hmac/hashlib and a separate AES), so a test
 * failure means the construction differs from its specification, not merely from what the code
 * happened to do yesterday — freezing the latter would freeze a bug along with it.
 *
 * The CBC+HMAC cases now **verify** rather than produce: nothing writes that frame any more, so
 * `aes256CbcHmac256Encrypt` is gone and the two independently computed ciphertexts are inputs to
 * the decrypt side that survives. The vectors are the same bytes either way, and this direction is
 * the one still on the wire. The KDF vectors moved with their construction to
 * `FormatHashVectorsTest`, which covers the entry point that still has callers.
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
const string SEED = "privmx-prf-seed";

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

/// Built with a 16-byte zero IV. 80 bytes: IV, two AES blocks, and a 16-byte tag.
string cipherWithGivenIv() {
    return string("\x30\xb5\xb0\xad\x1b\xf5\xc3\xc1\xdf\x76\x89\xa3\x9e\xb3\x0b\xbe"
                  "\x0f\x1f\xec\xc9\x4a\x3f\xf1\xd9\xa6\x1f\xa3\xdb\x3c\x77\xd7\x57"
                  "\x3a\x4e\x23\x07\x87\x4b\x49\x88\x6a\x0c\x6e\xb8\x8c\xa3\xf9\x45"
                  "\x38\xcc\x0b\xf6\x96\x38\x9a\x95\x78\xf4\xb3\x76\xd0\x7c\x5d\xdc"
                  "\xb3\xad\xc1\xd2\x1d\xe7\x39\x62\x1a\x95\xda\xc1\x6f\x68\x0b\x04", 80);
}

TEST(CompositionVectorsTest, Aes256CbcHmac256OpensACipherWithAGivenIv) {
    EXPECT_EQ(DATA, Crypto::aes256CbcHmac256Decrypt(cipherWithGivenIv(), key32()));
}

/**
 * The deterministic-IV branch: writing it, an empty IV meant "derive one from the plaintext", which
 * made the whole ciphertext a function of key and data alone. Kept as a separate vector because the
 * IV it produced is part of the frame, so a reader that mishandled it would still open the one
 * above.
 */
TEST(CompositionVectorsTest, Aes256CbcHmac256OpensACipherWithADerivedIv) {
    const string cipher(
        "\x14\xc2\x4b\xc5\x30\x74\xd7\x7f\x4a\x4c\x0b\xa4\xb0\xde\xe0\xa3"
        "\x46\x85\x0c\xe2\x2a\x32\xb0\x0e\x35\x1e\xfd\x7e\x24\xc1\x44\x96"
        "\x10\x5e\xf5\x0b\x12\xe4\xb0\x9c\xf3\xc5\xf6\xf1\xc6\xc9\x6c\xc6"
        "\x35\xd0\xd6\xa3\xd7\x8a\xec\x86\x15\x49\x6d\x74\x12\xd2\x66\x6a"
        "\xe6\x71\x7c\x4b\xf0\x59\x45\xf0\x0c\x9d\xe9\x85\xad\xf1\xd1\xe1", 80
    );
    EXPECT_EQ(DATA, Crypto::aes256CbcHmac256Decrypt(cipher, key32()));
}

/// A tampered tag has to be refused rather than returning plaintext.
TEST(CompositionVectorsTest, Aes256CbcHmac256RejectsATamperedTag) {
    string cipher = cipherWithGivenIv();
    cipher[cipher.size() - 1] ^= 0xFF;

    EXPECT_THROW(Crypto::aes256CbcHmac256Decrypt(cipher, key32()), WrongMessageSecurityTagException);
}

/**
 * The rpc frame header, which used to be encrypted with AES-256-ECB.
 *
 * ECB is gone from this library — its weakness is that equal blocks encrypt equal, which is exactly
 * wrong for repeated, structured headers. The header is a single 16-byte block, and for one block
 * CBC without padding and an all-zero IV produces the same bytes, because CBC is `E(P xor IV)` and a
 * zero IV leaves `E(P)`. That equality is what let the mode change without touching the wire format
 * shared with the bridge, so it is pinned here rather than argued in a commit message.
 *
 * The expected value comes from `openssl enc -aes-256-ecb -nopad`, i.e. from the mode that is no
 * longer in the codebase. A round-trip could not say this: it would pass just as happily if both
 * ends moved together.
 */
TEST(CompositionVectorsTest, FrameHeaderBlockMatchesTheEcbItReplaced) {
    const string block = "PrivMX frame hdr"; // exactly 16 bytes
    const string zeroIv(16, '\0');
    const string expected(
        "\x67\xf4\x90\x29\xd6\xa4\x90\x85\x7c\x91\x3b\x60\xc7\x3a\xd3\xfa", 16
    );

    ASSERT_EQ(16u, block.size());
    EXPECT_EQ(expected, Crypto::aes256CbcNoPadEncrypt(block, key32(), zeroIv));
    EXPECT_EQ(block, Crypto::aes256CbcNoPadDecrypt(expected, key32(), zeroIv));
}

} // namespace
} // namespace crypto
} // namespace privmx
