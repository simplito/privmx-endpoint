/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include <string>
#include <vector>

#include <gtest/gtest.h>

#include <privmx/crypto/CryptoException.hpp>
#include <privmx/endpoint/core/ConvertedExceptions.hpp>
#include <privmx/endpoint/core/CoreException.hpp>
#include <privmx/endpoint/core/crypto/CryptoSuite.hpp>
#include <privmx/endpoint/core/crypto/Ecies.hpp>
#include <privmx/endpoint/core/crypto/PrivateKey.hpp>
#include <privmx/endpoint/core/crypto/PublicKey.hpp>

using namespace privmx::endpoint::core;

// The crypto exception scope lives in the crypto library now, not under endpoint/. The alias keeps
// its name so the expectations below read unchanged.
namespace epcrypto = privmx::crypto;

namespace {

const std::string WIF{"L1YwTwAr8dQCBzfmXBzh6ggBkYbLuu15Tc7s4bajrRNDbsogs9a5"};
const std::string KEY32(32, 'k');

std::string someFrame() {
    return CryptoSuite::defaultForWrite().encrypt(KEY32, "tresc");
}

} // namespace

// -------------------------------------------------------------------------------------------
// A necessary condition for the whole layer: no pmx-crypto exception may leave it in its own form.
// The public API boundary catches `PrivmxException` only, so an exception that is not a
// `core::Exception` would cross it as a type no wrapper recognises.
// -------------------------------------------------------------------------------------------

TEST(CryptoErrors, EveryFailurePathProducesCoreException) {
    const std::vector<std::pair<const char*, std::function<void()>>> cases{
        {"fromWIF/garbage", [] { PrivateKey::fromWIF("this-is-not-a-wif"); }},
        {"fromWIF/short", [] { PrivateKey::fromWIF("5"); }},
        {"fromWIF/bad checksum",
         [] { PrivateKey::fromWIF("L1YwTwAr8dQCBzfmXBzh6ggBkYbLuu15Tc7s4bajrRNDbsogs9a6"); }},
        {"fromBase58DER/garbage", [] { PublicKey::fromBase58DER("this-is-not-a-key"); }},
        {"fromBase58DER/empty", [] { PublicKey::fromBase58DER(""); }},
        {"fromDER/wrong length", [] { PublicKey::fromDER(std::string(10, '\0')); }},
        {"fromRaw/too short", [] { PrivateKey::fromRaw("abc"); }},
        {"encrypt/short key", [] { CryptoSuite::defaultForWrite().encrypt("short", "content"); }},
        {"decrypt/wrong key", [] { CryptoSuite::decrypt(std::string(32, 'z'), someFrame()); }},
        {"decrypt/empty frame", [] { CryptoSuite::decrypt(KEY32, ""); }},
        {"ecies/wrong key", [] {
             const auto a = PrivateKey::fromWIF(WIF);
             Ecies::decrypt(PrivateKey::generateRandom(), Ecies::encrypt(a.getPublicKey(), "content", a));
         }},
    };

    for (const auto& [name, action] : cases) {
        try {
            action();
            ADD_FAILURE() << name << ": expected an exception, got none";
        } catch (const Exception& e) { EXPECT_NE(0u, e.getCode()) << name; } catch (const std::exception& e) {
            ADD_FAILURE() << name << ": the exception escaped the endpoint hierarchy: " << e.what();
        }
    }

    // Verification is the one refusal that need not be an exception, and which it is depends on the
    // algorithm: secp256k1 throws out of the ECC driver, Ed25519 just reports a mismatch. What has to
    // hold either way is that garbage is not accepted, so that is what this asserts.
    try {
        EXPECT_FALSE(PrivateKey::fromWIF(WIF).getPublicKey().verifyCompactSignatureWithHash("m", "xx"))
            << "verify/garbage as a signature: garbage accepted as a signature";
    } catch (const Exception& e) {
        EXPECT_NE(0u, e.getCode()) << "verify/garbage as a signature";
    } catch (const std::exception& e) {
        ADD_FAILURE() << "verify/garbage as a signature: the exception escaped the endpoint hierarchy: " << e.what();
    }
}

// -------------------------------------------------------------------------------------------
// The specific mappings. These codes were in the API before the migration — wrappers may react
// to them.
// -------------------------------------------------------------------------------------------

/// A failed AEAD authentication. The trap: pmx-crypto reports this case as
/// `DecryptionFinalizationFailed`, not as `DecryptionInvalidTag`.
TEST(CryptoErrors, AuthenticationFailureKeepsItsOwnCode) {
    EXPECT_THROW(CryptoSuite::decrypt(std::string(32, 'z'), someFrame()), epcrypto::WrongMessageSecurityTagException);

    std::string tampered = someFrame();
    tampered[tampered.size() - 1] ^= 0xFF;
    EXPECT_THROW(CryptoSuite::decrypt(KEY32, tampered), epcrypto::WrongMessageSecurityTagException);
}

TEST(CryptoErrors, WifChecksumFailureKeepsItsOwnCode) {
    EXPECT_THROW(
        PrivateKey::fromWIF("L1YwTwAr8dQCBzfmXBzh6ggBkYbLuu15Tc7s4bajrRNDbsogs9a6"), epcrypto::InvalidChecksumException
    );
}

TEST(CryptoErrors, UnknownSuiteTagIsReportedAsSuchNotAsCipherFailure) {
    std::string framed = someFrame();
    framed[0] = 0x7F;
    EXPECT_THROW(CryptoSuite::decrypt(KEY32, framed), UnknownCryptoSuiteException);
}

/// The wrappers' own exceptions must pass through the mapper without their code changing.
TEST(CryptoErrors, EndpointOwnExceptionsPassThroughUnchanged) {
    EXPECT_THROW(PublicKey().toBase58DER(), MalformedEncryptionKeyException);
    EXPECT_THROW(PrivateKey().toWIF(), MalformedEncryptionKeyException);
    EXPECT_THROW(PrivateKey::fromWIF(WIF).derive(PublicKey()), MalformedEncryptionKeyException);
    EXPECT_THROW(CryptoSuite::decrypt(KEY32, ""), MalformedCryptoFrameException);
}

// -------------------------------------------------------------------------------------------
// Symmetric key length.
//
// This is not a courtesy check: `CryptoProvider` passes `key.data()` to OpenSSL without looking at
// `key.size()`, and OpenSSL reads as many bytes as the cipher requires. Without this condition a
// shorter key gives a read past the end of the buffer rather than an error.
// -------------------------------------------------------------------------------------------

TEST(CryptoErrors, ShortKeyIsRejectedInsteadOfBeingReadPastItsEnd) {
    for (const SuiteId id : CryptoSuite::known()) {
        const CryptoSuite suite = CryptoSuite::forId(id);
        ASSERT_EQ(32u, suite.keyLength());

        EXPECT_THROW(suite.encrypt("", "tresc"), epcrypto::EncryptInvalidKeyLengthException);
        EXPECT_THROW(suite.encrypt(std::string(31, 'k'), "tresc"), epcrypto::EncryptInvalidKeyLengthException);
        EXPECT_THROW(suite.encrypt(std::string(33, 'k'), "tresc"), epcrypto::EncryptInvalidKeyLengthException);

        const std::string framed = suite.encrypt(KEY32, "tresc");
        EXPECT_THROW(CryptoSuite::decrypt(std::string(31, 'k'), framed), epcrypto::DecryptInvalidKeyLengthException);
        EXPECT_THROW(CryptoSuite::decrypt("", framed), epcrypto::DecryptInvalidKeyLengthException);
    }
}
