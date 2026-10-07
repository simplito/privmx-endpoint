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

#include <privmx/endpoint/core/ConvertedExceptions.hpp>
#include <privmx/endpoint/core/CoreException.hpp>
#include <privmx/endpoint/core/crypto/CryptoSuite.hpp>
#include <privmx/endpoint/core/crypto/Ecies.hpp>
#include <privmx/endpoint/core/crypto/PrivateKey.hpp>
#include <privmx/endpoint/core/crypto/PublicKey.hpp>

using namespace privmx::endpoint::core;

namespace epcrypto = privmx::endpoint::crypto;

namespace {

const std::string WIF{"L1YwTwAr8dQCBzfmXBzh6ggBkYbLuu15Tc7s4bajrRNDbsogs9a5"};
const std::string KEY32(32, 'k');

std::string someFrame() {
    return CryptoSuite::defaultForWrite().encrypt(KEY32, "tresc");
}

} // namespace

// -------------------------------------------------------------------------------------------
// Warunek konieczny calej warstwy: zaden wyjatek pmx-crypto nie moze wyjsc poza nia w swojej
// postaci. Granica publicznego API lapie tylko `PrivmxException`, wiec wyjatek, ktory nie jest
// `core::Exception`, przeszedlby przez nia jako typ nieznany zadnemu wrapperowi.
// -------------------------------------------------------------------------------------------

TEST(CryptoErrors, EveryFailurePathProducesCoreException) {
    const std::vector<std::pair<const char*, std::function<void()>>> cases{
        {"fromWIF/smiec", [] { PrivateKey::fromWIF("to-nie-jest-wif"); }},
        {"fromWIF/krotki", [] { PrivateKey::fromWIF("5"); }},
        {"fromWIF/zla suma", [] { PrivateKey::fromWIF("L1YwTwAr8dQCBzfmXBzh6ggBkYbLuu15Tc7s4bajrRNDbsogs9a6"); }},
        {"fromBase58DER/smiec", [] { PublicKey::fromBase58DER("to-nie-jest-klucz"); }},
        {"fromBase58DER/pusty", [] { PublicKey::fromBase58DER(""); }},
        {"fromDER/zla dlugosc", [] { PublicKey::fromDER(std::string(10, '\0')); }},
        {"fromRaw/za krotki", [] { PrivateKey::fromRaw("abc"); }},
        {"encrypt/krotki klucz", [] { CryptoSuite::defaultForWrite().encrypt("krotki", "tresc"); }},
        {"decrypt/zly klucz", [] { CryptoSuite::decrypt(std::string(32, 'z'), someFrame()); }},
        {"decrypt/pusta ramka", [] { CryptoSuite::decrypt(KEY32, ""); }},
        {"verify/smiec jako podpis",
         [] { PrivateKey::fromWIF(WIF).getPublicKey().verifyCompactSignatureWithHash("m", "xx"); }},
        {"ecies/nie ten klucz",
         [] {
             const auto a = PrivateKey::fromWIF(WIF);
             Ecies::decrypt(PrivateKey::generateRandom(), Ecies::encrypt(a.getPublicKey(), "tresc", a));
         }},
    };

    for (const auto& [name, action] : cases) {
        try {
            action();
            ADD_FAILURE() << name << ": oczekiwano wyjatku, nie bylo zadnego";
        } catch (const Exception& e) {
            EXPECT_NE(0u, e.getCode()) << name;
        } catch (const std::exception& e) {
            ADD_FAILURE() << name << ": wyjatek wyszedl poza hierarchie endpointu: " << e.what();
        }
    }
}

// -------------------------------------------------------------------------------------------
// Konkretne odwzorowania. Te kody byly w API przed migracja - wrappery moga na nie reagowac.
// -------------------------------------------------------------------------------------------

/// Nieudane uwierzytelnienie AEAD. Pulapka: pmx-crypto zglasza ten przypadek jako
/// `DecryptionFinalizationFailed`, a nie jako `DecryptionInvalidTag`.
TEST(CryptoErrors, AuthenticationFailureKeepsItsOwnCode) {
    EXPECT_THROW(CryptoSuite::decrypt(std::string(32, 'z'), someFrame()), epcrypto::WrongMessageSecurityTagException);

    std::string tampered = someFrame();
    tampered[tampered.size() - 1] ^= 0xFF;
    EXPECT_THROW(CryptoSuite::decrypt(KEY32, tampered), epcrypto::WrongMessageSecurityTagException);
}

TEST(CryptoErrors, WifChecksumFailureKeepsItsOwnCode) {
    EXPECT_THROW(
        PrivateKey::fromWIF("L1YwTwAr8dQCBzfmXBzh6ggBkYbLuu15Tc7s4bajrRNDbsogs9a6"),
        epcrypto::InvalidChecksumException
    );
}

TEST(CryptoErrors, UnknownSuiteTagIsReportedAsSuchNotAsCipherFailure) {
    std::string framed = someFrame();
    framed[0] = 0x7F;
    EXPECT_THROW(CryptoSuite::decrypt(KEY32, framed), UnknownCryptoSuiteException);
}

/// Wyjatki wlasne wrapperow musza przechodzic przez mapper bez zmiany kodu.
TEST(CryptoErrors, EndpointOwnExceptionsPassThroughUnchanged) {
    EXPECT_THROW(PublicKey().toBase58DER(), MalformedEncryptionKeyException);
    EXPECT_THROW(PrivateKey().toWIF(), MalformedEncryptionKeyException);
    EXPECT_THROW(PrivateKey::fromWIF(WIF).derive(PublicKey()), MalformedEncryptionKeyException);
    EXPECT_THROW(CryptoSuite::decrypt(KEY32, ""), MalformedCryptoFrameException);
}

// -------------------------------------------------------------------------------------------
// Dlugosc klucza symetrycznego.
//
// To nie jest kontrola kurtuazyjna: `CryptoProvider` przekazuje `key.data()` do OpenSSL
// nie patrzac na `key.size()`, a OpenSSL czyta tyle bajtow, ile wymaga szyfr. Bez tego
// warunku krotszy klucz daje odczyt poza buforem zamiast bledu.
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
