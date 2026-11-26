/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

/**
 * The format a container key is wrapped in for a 25519 identity.
 *
 * `Ecies` does not compose this any more - it hands the work to pmx-crypto's `seal`. What stays
 * here is a choice that **is** wire format: `SealParams`. That struct has no default member
 * initialisers, so every field is spelled out in `Ecies.cpp`, and every one of them decides bytes -
 * the two hashes, the symmetric algorithm, the IV length and the width of the key hashes in the
 * header. A reader has to pass the same values or nothing opens.
 *
 * A round-trip cannot notice a change there, because both ends move together; `Ed25519Capabilities`
 * is full of round-trips and all of them would stay green. So the wrap below is **pinned**: a blob
 * produced once, which today's code must still open. The blob itself cannot be produced
 * deterministically - `seal` draws a random IV and a fresh encapsulation, which is the point of it -
 * so this is the direction that can be pinned at all, the same way the 2.x blob is in `CryptoTest`.
 */

#include <string>

#include <gtest/gtest.h>

#include <privmx/cryptoservice/base/CoreTypes.hpp>
#include <privmx/utils/Utils.hpp>

#include <privmx/endpoint/core/crypto/Ecies.hpp>
#include <privmx/endpoint/core/crypto/PrivateKey.hpp>
#include <privmx/endpoint/core/crypto/PublicKey.hpp>

namespace cs = privmx::cryptoservice;

using namespace privmx::endpoint::core;

namespace {

const std::string CONTAINER_KEY(32, 'k');

PrivateKey alice(cs::AsymAlg alg) { return PrivateKey::fromRaw(std::string(32, 'a'), alg); }
PrivateKey bob(cs::AsymAlg alg) { return PrivateKey::fromRaw(std::string(32, 'b'), alg); }
PrivateKey mallory(cs::AsymAlg alg) { return PrivateKey::fromRaw(std::string(32, 'm'), alg); }

/// Wrapped by Alice to Bob, captured from this code once the hand-built wrap was replaced.
std::string pinnedWrap() {
    return privmx::utils::Hex::toString(
        "45000000b500000020000000200000002094dbdefea220c8a876dbd81510ddcc1ed4a58d12f8596b1994f4cb6f"
        "db37089845bf4f4f2b178eea94983fe674fea47f202fd8dce535386799e4acf78090e3628bdb44b953f5643955"
        "7031e41be1195031d9c025b82f852ec885c8904631515150980ed7fa5bc6dc6bff4229e0cad65fb914c4e6d000"
        "e73b807ae06bf7b03a7425a6a91802f1802d34a052d6a225f3aeda9ca1559bccb05532fc6afff5ffa60904d962"
        "163b7f90a3bfd1a91bf8ce68a4c618c977281c5c033edc208b33e533f0e87cf3f4a033315adedf6d8121da410b"
        "633123c660158fa94121499e178d5c31e4281f0a"
    );
}

} // namespace

/// If `SealParams` drifts - another hash, another IV length - this stops opening.
TEST(WrapFormatVectors, APinnedWrapStillOpens) {
    EXPECT_EQ(CONTAINER_KEY, Ecies::decrypt(bob(cs::AsymAlg::ED25519), pinnedWrap()));
}

/// And the sender named in it is still read the same way.
TEST(WrapFormatVectors, APinnedWrapIsStillAttributedToItsSender) {
    const std::string base64 = privmx::utils::Base64::from(pinnedWrap());
    EXPECT_TRUE(Ecies::sealedBy(base64, alice(cs::AsymAlg::ED25519).getPublicKey().toBase58DER()));
    EXPECT_FALSE(Ecies::sealedBy(base64, mallory(cs::AsymAlg::ED25519).getPublicKey().toBase58DER()));
}

/// Opening it against the wrong named sender is a failure, not a silently accepted wrap.
TEST(WrapFormatVectors, APinnedWrapIsRefusedForTheWrongSender) {
    EXPECT_ANY_THROW(
        Ecies::decrypt(bob(cs::AsymAlg::ED25519), pinnedWrap(), mallory(cs::AsymAlg::ED25519).getPublicKey())
    );
}

/**
 * The post-quantum half is really in there.
 *
 * This is the assertion that matters most about the hybrid, and the one a round-trip cannot make:
 * a wrap that quietly degraded to Diffie-Hellman alone would still encrypt, still decrypt, and
 * still pass every other test in the suite - while being classical. An ML-KEM-768 encapsulation is
 * 1088 bytes and nothing else in the frame depends on the identity's algorithm, so the two wraps
 * differ by exactly that. The size is the evidence.
 *
 * Sizes rather than a pinned blob because a 1333-byte literal pins the same `SealParams` the
 * Ed25519 vector above already pins, and would say nothing extra.
 */
TEST(WrapFormatVectors, APostQuantumWrapCarriesItsEncapsulation) {
    constexpr std::size_t MLKEM768_CIPHERTEXT = 1088;

    const std::string classical =
        Ecies::encrypt(bob(cs::AsymAlg::ED25519).getPublicKey(), CONTAINER_KEY, alice(cs::AsymAlg::ED25519));
    const std::string hybrid = Ecies::encrypt(
        bob(cs::AsymAlg::X25519MLKEM768).getPublicKey(), CONTAINER_KEY, alice(cs::AsymAlg::X25519MLKEM768)
    );

    EXPECT_EQ(classical.size() + MLKEM768_CIPHERTEXT, hybrid.size());
}

/// Two wraps of one key to one recipient must differ: `seal` draws a fresh IV and encapsulation.
TEST(WrapFormatVectors, WrappingTwiceDoesNotRepeatItself) {
    const PublicKey recipient = bob(cs::AsymAlg::ED25519).getPublicKey();
    const PrivateKey sender = alice(cs::AsymAlg::ED25519);

    EXPECT_NE(
        Ecies::encrypt(recipient, CONTAINER_KEY, sender), Ecies::encrypt(recipient, CONTAINER_KEY, sender)
    );
}
