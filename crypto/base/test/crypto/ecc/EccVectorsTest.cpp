/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

/**
 * Golden vectors for `ECC`, so its backend can be replaced without changing what goes on the wire.
 *
 * The signature encoding is the reason this file exists. `ECC::sign` emits 65 bytes as
 * `0x1b || r || s`, where the leading byte is written as a **constant** rather than derived from a
 * recovery id — and `ECC::verify` only range-checks it (27..42) before ignoring it. So two
 * implementations can disagree about that byte while still verifying each other's signatures: the
 * existing cross-implementation tests would stay green and the bytes on the wire would differ.
 * Pinning the whole 65 bytes is what closes that gap.
 *
 * `ECC` is secp256k1 whatever `PRIVMX_DEFAULT_KEY_ALGORITHM` the build was configured with — it is
 * the old stack, which knows one curve — so these vectors are not skipped on any build.
 *
 * The key is a fixed private scalar; the expected values were taken from the driver-backed
 * implementation, which is the behaviour already deployed and therefore the definition of correct
 * here. Reimplementing secp256k1 to check them would be the very mistake being avoided — but one
 * question does have an independent answer, and `SignsOverASingleSha256` asks it: **how many times
 * the message is hashed** is settled by a signature the `openssl` command line produced from this
 * same scalar, which no code in this repository had a hand in.
 */

#include <string>

#include <gtest/gtest.h>

#include <privmx/crypto/ecc/ECC.hpp>
#include <privmx/utils/Utils.hpp>

using namespace std;

namespace privmx {
namespace crypto {
namespace {

/// A fixed 32-byte private scalar, well below the group order.
string privateScalar() {
    string key(32, '\0');
    for (size_t i = 0; i < key.size(); ++i) {
        key[i] = static_cast<char>(i + 1);
    }
    return key;
}

const string MESSAGE = "PrivMX ECC vector message";

string hex(const string& data) {
    return privmx::utils::Hex::from(data);
}

TEST(EccVectorsTest, PublicKeyCompressed) {
    const ECC key = ECC::fromPrivateKey(privateScalar());
    EXPECT_EQ("0284bf7562262bbd6940085748f3be6afa52ae317155181ece31b66351ccffa4b0", hex(key.getPublicKey(true)));
}

TEST(EccVectorsTest, PublicKeyUncompressed) {
    const ECC key = ECC::fromPrivateKey(privateScalar());
    const string uncompressed = key.getPublicKey(false);
    ASSERT_EQ(65u, uncompressed.size());
    EXPECT_EQ(
        "0484bf7562262bbd6940085748f3be6afa52ae317155181ece31b66351ccffa4b0"
        "8cc43d63b2859d469fee15f31c9edb5324266e6fd0407e87382d60fc4511acd8",
        hex(uncompressed)
    );
}

TEST(EccVectorsTest, PrivateKeyRoundTrips) {
    const ECC key = ECC::fromPrivateKey(privateScalar());
    EXPECT_EQ(privateScalar(), key.getPrivateKey());
    EXPECT_TRUE(key.hasPrivate());
}

/**
 * The signature's shape, which is what a backend swap can change silently.
 *
 * The bytes themselves cannot be pinned: signing here picks a random `k` rather than deriving it
 * from the message (RFC 6979), so two signatures over the same input with the same key differ. That
 * is asserted below, because it is load-bearing for this file — a golden vector would have looked
 * reasonable and failed on the second run.
 *
 * What is fixed is the framing: 65 bytes, `0x1b || r || s`. The leading byte is written as a
 * constant rather than derived from a recovery id, and `verify` only range-checks it before
 * ignoring it — so a backend that computed a real recovery tag would still interoperate while
 * putting different bytes on the wire. This is the assertion that would catch that.
 */
TEST(EccVectorsTest, CompactSignatureFraming) {
    const ECC key = ECC::fromPrivateKey(privateScalar());
    const string first = key.sign(MESSAGE);
    const string second = key.sign(MESSAGE);

    ASSERT_EQ(65u, first.size());
    EXPECT_EQ(0x1b, static_cast<unsigned char>(first[0])) << "the leading byte is a constant, not a recovery id";
    EXPECT_EQ(0x1b, static_cast<unsigned char>(second[0]));
    EXPECT_NE(first, second) << "signing draws a fresh k; if this ever holds, k became deterministic";
}

/**
 * Which digest the signature is over — the one thing here an outside tool can settle.
 *
 * `sign`/`verify` take the **message** and hash it once with SHA-256 themselves. A signature over
 * `sha256(sha256(message))` is what the wrapper in `crypto/base` used to build, by hashing before
 * calling in, and nothing else accepts it: the bridge verifies over a single digest
 * (`NonceService`, `src/utils/crypto/VerifyKey.ts`) and so does `core::PublicKey`. It reached
 * production as an `INVALID_SIGNATURE` at login on every secp256k1 build.
 *
 * A round-trip cannot catch that, because hashing twice on both sides still agrees with itself —
 * which is exactly how it got through. These two signatures were made by `openssl dgst -sha256
 * -sign` from `privateScalar()`, over the message and over its digest respectively, so they fix the
 * hash count from outside this code. Verification is deterministic, so unlike a signature of our
 * own they can be pinned (see `CompactSignatureFraming` for why signing cannot).
 */
TEST(EccVectorsTest, SignsOverASingleSha256) {
    const ECC key = ECC::fromPrivateKey(privateScalar());
    const string overMessage = privmx::utils::Hex::toString(
        "1b1d29c1af25818c9486036709f2056edb99d56966d51e3a6e91820b46a79eb5"
        "af572d11c81008db767bb990c040f009be9cc1ca8e4629cab91fde837cf09d7b94"
    );
    const string overItsDigest = privmx::utils::Hex::toString(
        "1be00111a40909b8ec6e317fc6787ae1687493911f5cd2dc60f9a547435dbcd0"
        "81a31665e5b98359a70fca0bbcf395c9b1b1c74766e8ce221fe9a2672e235b52e5"
    );

    EXPECT_TRUE(key.verify(MESSAGE, overMessage)) << "the signature is over sha256(message)";
    EXPECT_FALSE(key.verify(MESSAGE, overItsDigest)) << "hashing twice is the bug this pins";
}

TEST(EccVectorsTest, SignatureVerifies) {
    const ECC key = ECC::fromPrivateKey(privateScalar());
    const string signature = key.sign(MESSAGE);

    EXPECT_TRUE(key.verify(MESSAGE, signature));
    EXPECT_FALSE(key.verify(MESSAGE + "!", signature));
}

/// ECDH against a second fixed key. Used by the rpc handshake, so a change here breaks login.
TEST(EccVectorsTest, SharedSecret) {
    string otherScalar(32, '\0');
    for (size_t i = 0; i < otherScalar.size(); ++i) {
        otherScalar[i] = static_cast<char>(0x40 + i);
    }

    const ECC mine = ECC::fromPrivateKey(privateScalar());
    const ECC theirs = ECC::fromPrivateKey(otherScalar);

    const string ab = mine.derive(ECC::fromPublicKey(theirs.getPublicKey()));
    const string ba = theirs.derive(ECC::fromPublicKey(mine.getPublicKey()));

    EXPECT_EQ(ab, ba) << "Diffie-Hellman has to agree in both directions";
    EXPECT_EQ("080b82140316bac00c39bd3cf10a1c6568b035f3c8e8387a2cfdd00938abd1a6", hex(ab));
}

// The curve order used to be pinned here, next to `ECC::getOrder`. Both are gone: the order was a
// hand-written domain parameter whose only caller was BIP32 child derivation in the legacy `ExtKey`,
// and pmx-crypto's `IExtKey` derives children itself.

} // namespace
} // namespace crypto
} // namespace privmx
