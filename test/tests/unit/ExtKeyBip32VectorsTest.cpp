/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

/**
 * The official BIP-32 test vectors, checked against key material rather than serialisation.
 *
 * The expected values are the chain code and private key carried *inside* the specification's
 * `xprv…` strings, decoded out of them. They are therefore still the spec's numbers, not this
 * implementation's output — which is the whole point of having them.
 *
 * Checking the material rather than the `xprv` string is deliberate. BIP-32's envelope encodes one
 * key and one algorithm; this library now has to serialise extended keys that may carry a composed
 * identity, so the base58 form is a different, wider envelope. The derivation underneath is
 * unchanged — HMAC-SHA512 over the chain code, the hardening offset, `ki = (IL + k) mod n` — and
 * that is exactly what these vectors pin. A backend that derived the wrong key would fail here even
 * though every byte of the envelope looked plausible.
 *
 * Vectors 3 and 4 are included because their master keys have a leading zero byte, which is where
 * implementations go wrong: a scalar padded to 32 bytes in one place and left short in another
 * produces a believable wrong answer instead of a crash. That mistake was made twice while moving
 * the EC backend onto pmx-crypto, and these are the vectors that caught it.
 *
 * They live at the public API, not beside an implementation, so that replacing the implementation
 * cannot quietly delete them.
 */

#include <string>

#include <gtest/gtest.h>

#include <privmx/endpoint/core/Buffer.hpp>
#include <privmx/endpoint/crypto/ExtKey.hpp>
#include <privmx/utils/Utils.hpp>

using namespace std;
using namespace privmx::endpoint;

namespace {

crypto::ExtKey fromSeed(const string& seed) {
    return crypto::ExtKey::fromSeed(core::Buffer::from(seed));
}

string chainCodeHex(const crypto::ExtKey& key) {
    return privmx::utils::Hex::from(key.getChainCode().stdString());
}

} // namespace

TEST(ExtKeyBip32Vectors, Vector1) {
    const string seed("\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f", 16);

    const crypto::ExtKey master = fromSeed(seed);
    EXPECT_EQ("873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d508", chainCodeHex(master));
    EXPECT_EQ("L52XzL2cMkHxqxBXRyEpnPQZGUs3uKiL3R11XbAdHigRzDozKZeW", master.getPrivateKey());

    const crypto::ExtKey hardened0 = master.deriveHardened(0);
    EXPECT_EQ("47fdacbd0f1097043b78c63c20c34ef4ed9a111d980047ad16282c7ae6236141", chainCodeHex(hardened0));
    EXPECT_EQ("L5BmPijJjrKbiUfG4zbiFKNqkvuJ8usooJmzuD7Z8dkRoTThYnAT", hardened0.getPrivateKey());

    // A normal step after a hardened one, which is where the two derivation paths meet.
    const crypto::ExtKey normal1 = hardened0.derive(1);
    EXPECT_EQ("2a7857631386ba23dacac34180dd1983734e444fdbf774041578e9b6adb37c19", chainCodeHex(normal1));
    EXPECT_EQ("KyFAjQ5rgrKvhXvNMtFB5PCSKUYD1yyPEe3xr3T34TZSUHycXtMM", normal1.getPrivateKey());
}

/// Master key with a leading zero byte. See the note at the top of the file.
TEST(ExtKeyBip32Vectors, Vector3) {
    const string seed(
        "\x4b\x38\x15\x41\x58\x3b\xe4\x42\x33\x46\xc6\x43\x85\x0d\xa4\xb3\x20\xe4\x6a\x87\xae\x3d\x2a\x4e\x6d\xa1\x1e"
        "\xba\x81\x9c\xd4\xac\xba\x45\xd2\x39\x31\x9a\xc1\x4f\x86\x3b\x8d\x5a\xb5\xa0\xd0\xc6\x4d\x2e\x8a\x1e\x7d\x14"
        "\x57\xdf\x2e\x5a\x3c\x51\xc7\x32\x35\xbe",
        64
    );

    const crypto::ExtKey master = fromSeed(seed);
    EXPECT_EQ("01d28a3e53cffa419ec122c968b3259e16b65076495494d97cae10bbfec3c36f", chainCodeHex(master));
    EXPECT_EQ("KwFPqAq9SKx1sPg15Qk56mqkHwrfGPuywtLUxoWPkiTSBoxCs8am", master.getPrivateKey());

    const crypto::ExtKey hardened0 = master.deriveHardened(0);
    EXPECT_EQ("e5fea12a97b927fc9dc3d2cb0d1ea1cf50aa5a1fdc1f933e8906bb38df3377bd", chainCodeHex(hardened0));
    EXPECT_EQ("KyfrPaeirL5yYAoZvfzyoKXSdszeLqg5vb6dNy9ymvjzZrMZY8GW", hardened0.getPrivateKey());
}

/// The other leading-zero case, over two hardened steps.
TEST(ExtKeyBip32Vectors, Vector4) {
    const string seed(
        "\x3d\xdd\x56\x02\x28\x58\x99\xa9\x46\x11\x45\x06\x15\x7c\x79\x97\xe5\x44\x45\x28\xf3\x00\x3f\x61\x34\x71\x21"
        "\x47\xdb\x19\xb6\x78",
        32
    );

    const crypto::ExtKey master = fromSeed(seed);
    EXPECT_EQ("d0c8a1f6edf2500798c3e0b54f1b56e45f6d03e6076abd36e5e2f54101e44ce6", chainCodeHex(master));
    EXPECT_EQ("KwrAWXgyy1L75ZBRp1PzHj2aWBoYcddgrEMfF6iBJFuw8adwRNLu", master.getPrivateKey());

    const crypto::ExtKey hardened0 = master.deriveHardened(0);
    EXPECT_EQ("cdc0f06456a14876c898790e0b3b1a41c531170aec69da44ff7b7265bfe7743b", chainCodeHex(hardened0));
    EXPECT_EQ("KwFMsuZ3pmk7ebtbTiPirTpdcPkS6wvnSazU3bvixwiCw1bNQLhG", hardened0.getPrivateKey());

    const crypto::ExtKey hardened0_1 = hardened0.deriveHardened(1);
    EXPECT_EQ("a48ee6674c5264a237703fd383bccd9fad4d9378ac98ab05e6e7029b06360c0d", chainCodeHex(hardened0_1));
    EXPECT_EQ("KyAhgkU6sXTCm3eiHu81ev4jhcnEs6Toppbr8hqcm82jUFxbLX3u", hardened0_1.getPrivateKey());
}
