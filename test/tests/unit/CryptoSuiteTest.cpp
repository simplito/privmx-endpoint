/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

/**
 * Testy warstwy zwinnosci algorytmicznej kontenera (`core::CryptoSuite`).
 *
 * Caly sens tej warstwy sprowadza sie do jednego zdania: **zapis idzie za wyborem, odczyt idzie
 * za znacznikiem w danych**. Z tego wynika reszta - rejestr odczytu musi byc kompletny w kazdym
 * buildzie, a znacznik musi byc uwierzytelniony, inaczej dalby sie podmienic na slabszy zestaw.
 * Te testy przybijaja wlasnie te wlasnosci, a nie konkretne algorytmy.
 *
 * Format ramki: `[1 B SuiteId][12 B IV][szyfrogram || 16 B tag]`, znacznik jako AAD.
 */

#include <string>

#include <gtest/gtest.h>

#include <privmx/endpoint/core/CoreException.hpp>
#include <privmx/endpoint/core/crypto/CryptoSuite.hpp>

using namespace privmx::endpoint;
using namespace privmx::endpoint::core;

namespace {

std::string keyFor(const CryptoSuite& suite, char fill = 'k') {
    return std::string(suite.keyLength(), fill);
}

} // namespace

// ---------------------------------------------------------------------------------------------
// Rejestr zestawow
// ---------------------------------------------------------------------------------------------

/// Rejestr **odczytu** jest kompletny niezaleznie od konfiguracji budowania. Gdyby opcja budowania
/// zawezala tez odczyt, klienci zbudowani z roznymi ustawieniami nie odczytaliby swoich danych -
/// a to jest dokladnie to, czemu ta warstwa ma zapobiegac.
TEST(CryptoSuite, EveryBuildCanReadEverySuite) {
    EXPECT_TRUE(CryptoSuite::isKnown(SuiteId::Aes256GcmSha256));
    EXPECT_TRUE(CryptoSuite::isKnown(SuiteId::Aes256GcmSha512));
    EXPECT_EQ(2u, CryptoSuite::known().size());

    EXPECT_FALSE(CryptoSuite::isKnown(SuiteId::Unknown));
    EXPECT_FALSE(CryptoSuite::isKnown(static_cast<SuiteId>(0x7F)));
    EXPECT_THROW(CryptoSuite::forId(static_cast<SuiteId>(0x7F)), UnknownCryptoSuiteException);
}

TEST(CryptoSuite, DefaultForWriteIsASuiteThisBuildCanRead) {
    EXPECT_TRUE(CryptoSuite::isKnown(CryptoSuite::defaultForWrite().id()));
}

/// Sprawdza, ze `PRIVMX_DEFAULT_CRYPTO_SUITE` faktycznie **doszlo do kompilacji biblioteki**,
/// a nie tylko wypisalo sie przy konfiguracji. Taka cicha strata juz sie zdarzyla: definicje
/// dodane przez `target_compile_definitions` kasowal pozniejszy
/// `set_target_properties(... COMPILE_DEFINITIONS ...)`, wiec build deklarowal jeden zestaw,
/// a zapisywal innym - i nic tego nie zglaszalo.
TEST(CryptoSuite, BuildOptionReachedTheLibrary) {
    EXPECT_EQ(
        static_cast<int>(PRIVMX_DEFAULT_CRYPTO_SUITE_ID),
        static_cast<int>(CryptoSuite::defaultForWrite().id())
    ) << "PRIVMX_DEFAULT_CRYPTO_SUITE nie dotarlo do privmxendpointcore";
}

/// Wartosci znacznika sa czescia formatu danych - raz wydanej nie wolno przedefiniowac.
TEST(CryptoSuite, SuiteIdsAreFrozen) {
    EXPECT_EQ(0x00, static_cast<int>(SuiteId::Unknown));
    EXPECT_EQ(0x01, static_cast<int>(SuiteId::Aes256GcmSha256));
    EXPECT_EQ(0x02, static_cast<int>(SuiteId::Aes256GcmSha512));
}

TEST(CryptoSuite, PolicyValueRoundTrips) {
    for (const SuiteId id : CryptoSuite::known()) {
        const CryptoSuite suite = CryptoSuite::forId(id);
        const std::string value = suite.policyValue();

        EXPECT_FALSE(value.empty());
        EXPECT_TRUE(CryptoSuite::isKnownPolicyValue(value));
        EXPECT_EQ(id, CryptoSuite::forPolicyValue(value).id());
    }

    EXPECT_FALSE(CryptoSuite::isKnownPolicyValue("rot13"));
    EXPECT_THROW(CryptoSuite::forPolicyValue("rot13"), UnknownCryptoSuiteException);
}

// ---------------------------------------------------------------------------------------------
// Ramka
// ---------------------------------------------------------------------------------------------

/// `DEFAULT_FRAME_OVERHEAD` jest stala kompilacji, z ktorej `group` liczy rozmiar chunku i adresuje
/// chunki. Dopoki trzyma ja **kazdy** zestaw z rejestru, zmiana zestawu zapisu nie przestawia
/// adresowania. Ten test pilnuje tego zalozenia przy kazdym nowym zestawie.
TEST(CryptoSuite, FrameOverheadHoldsForEverySuite) {
    const std::string plain(100, 'a');

    for (const SuiteId id : CryptoSuite::known()) {
        const CryptoSuite suite = CryptoSuite::forId(id);
        const std::string framed = suite.encrypt(keyFor(suite), plain);

        EXPECT_EQ(plain.size() + CryptoSuite::DEFAULT_FRAME_OVERHEAD, framed.size())
            << "zestaw " << static_cast<int>(id);
    }
}

TEST(CryptoSuite, FrameStartsWithItsSuiteTag) {
    for (const SuiteId id : CryptoSuite::known()) {
        const CryptoSuite suite = CryptoSuite::forId(id);
        const std::string framed = suite.encrypt(keyFor(suite), "cokolwiek");

        EXPECT_EQ(static_cast<char>(id), framed[0]) << "zestaw " << static_cast<int>(id);
        EXPECT_EQ(id, CryptoSuite::readSuiteId(framed)) << "zestaw " << static_cast<int>(id);
    }
}

/// Sedno warstwy: odczyt nie przyjmuje wskazania algorytmu - dobiera go ze znacznika. Dlatego
/// dane zapisane dowolnym zestawem czytaja sie w buildzie ustawionym na inny zestaw zapisu.
TEST(CryptoSuite, AnySuiteIsReadableRegardlessOfTheWriteDefault) {
    for (const SuiteId id : CryptoSuite::known()) {
        const CryptoSuite suite = CryptoSuite::forId(id);
        const std::string key = keyFor(suite);

        for (const std::string& plain : {std::string(), std::string(1, 'x'), std::string(5000, 'y')}) {
            const std::string framed = suite.encrypt(key, plain);
            EXPECT_EQ(plain, CryptoSuite::decrypt(key, framed))
                << "zestaw " << static_cast<int>(id) << ", dlugosc " << plain.size();
        }
    }
}

/// Znacznik idzie jako AAD, wiec jest uwierzytelniony. Gdyby nie byl, atakujacy przestawilby go
/// na zestaw o slabszym skrocie i odczyt poszedlby po jego mysli.
TEST(CryptoSuite, SwappingTheSuiteTagInvalidatesTheFrame) {
    const CryptoSuite suite = CryptoSuite::forId(SuiteId::Aes256GcmSha256);
    const std::string key = keyFor(suite);
    std::string framed = suite.encrypt(key, "tajne");

    framed[0] = static_cast<char>(SuiteId::Aes256GcmSha512);

    EXPECT_ANY_THROW(CryptoSuite::decrypt(key, framed));
}

TEST(CryptoSuite, TamperedCiphertextIsRejected) {
    const CryptoSuite suite = CryptoSuite::defaultForWrite();
    const std::string key = keyFor(suite);
    std::string framed = suite.encrypt(key, "tajne");

    framed[framed.size() - 1] ^= 0xFF;

    EXPECT_ANY_THROW(CryptoSuite::decrypt(key, framed));
}

TEST(CryptoSuite, WrongKeyIsRejected) {
    const CryptoSuite suite = CryptoSuite::defaultForWrite();
    const std::string framed = suite.encrypt(keyFor(suite, 'k'), "tajne");

    EXPECT_ANY_THROW(CryptoSuite::decrypt(keyFor(suite, 'z'), framed));
}

TEST(CryptoSuite, UnknownTagIsReportedAsSuchAndNotAsCorruption) {
    const CryptoSuite suite = CryptoSuite::defaultForWrite();
    std::string framed = suite.encrypt(keyFor(suite), "tajne");

    framed[0] = static_cast<char>(0x7F);

    EXPECT_THROW(CryptoSuite::decrypt(keyFor(suite), framed), UnknownCryptoSuiteException);
    EXPECT_EQ(static_cast<SuiteId>(0x7F), CryptoSuite::readSuiteId(framed));
}

TEST(CryptoSuite, FrameShorterThanItsOwnOverheadIsRejected) {
    const CryptoSuite suite = CryptoSuite::defaultForWrite();
    const std::string framed = suite.encrypt(keyFor(suite), "");

    for (const size_t cut : {size_t{0}, size_t{1}, framed.size() - 1}) {
        EXPECT_THROW(CryptoSuite::decrypt(keyFor(suite), framed.substr(0, cut)), Exception)
            << "obcieta do " << cut;
    }
}

/// Klucz za krotki musi zostac odrzucony **przed** wejsciem do OpenSSL-a, ktory czyta tyle bajtow,
/// ile wymaga algorytm, nie ogladajac sie na dlugosc podanego ciagu.
TEST(CryptoSuite, KeyOfWrongLengthIsRejectedBeforeReachingTheCipher) {
    for (const SuiteId id : CryptoSuite::known()) {
        const CryptoSuite suite = CryptoSuite::forId(id);

        EXPECT_ANY_THROW(suite.encrypt(std::string(suite.keyLength() - 1, 'k'), "tajne"))
            << "zestaw " << static_cast<int>(id) << ", klucz za krotki";
        EXPECT_ANY_THROW(suite.encrypt(std::string(suite.keyLength() + 1, 'k'), "tajne"))
            << "zestaw " << static_cast<int>(id) << ", klucz za dlugi";
        EXPECT_ANY_THROW(suite.encrypt(std::string(), "tajne"))
            << "zestaw " << static_cast<int>(id) << ", klucz pusty";
    }
}

// ---------------------------------------------------------------------------------------------
// Prymitywy
// ---------------------------------------------------------------------------------------------

/// Zestawy roznia sie skrotem - gdyby `hash()` dawal to samo w obu, caly wybor bylby pozorny.
TEST(CryptoSuite, SuitesDifferInTheirHash) {
    const std::string data = "dane";
    const std::string sha256 = CryptoSuite::forId(SuiteId::Aes256GcmSha256).hash(data);
    const std::string sha512 = CryptoSuite::forId(SuiteId::Aes256GcmSha512).hash(data);

    EXPECT_EQ(32u, sha256.size());
    EXPECT_EQ(64u, sha512.size());
    EXPECT_NE(sha256, sha512);
}

TEST(CryptoSuite, MacAndDeriveKeyFollowTheSuite) {
    const std::string key(32, 'k');

    for (const SuiteId id : CryptoSuite::known()) {
        const CryptoSuite suite = CryptoSuite::forId(id);

        // Deterministyczne - ta sama para wejsc daje ten sam wynik.
        EXPECT_EQ(suite.mac(key, "dane"), suite.mac(key, "dane")) << "zestaw " << static_cast<int>(id);
        EXPECT_NE(suite.mac(key, "dane"), suite.mac(key, "inne")) << "zestaw " << static_cast<int>(id);

        for (const size_t length : {size_t{16}, size_t{32}, size_t{64}}) {
            const std::string derived = suite.deriveKey(key, "etykieta", length);
            EXPECT_EQ(length, derived.size()) << "zestaw " << static_cast<int>(id);
            EXPECT_EQ(derived, suite.deriveKey(key, "etykieta", length));
            EXPECT_NE(derived, suite.deriveKey(key, "inna", length));
        }
    }
}

/// Dlugosc klucza musi zgadzac sie z tym, czego wymaga szyfr zestawu - `generateKey` bierze ja
/// stad, wiec rozjazd konczylby sie kluczem odrzucanym przy kazdym zapisie.
TEST(CryptoSuite, KeyLengthMatchesWhatTheCipherAccepts) {
    for (const SuiteId id : CryptoSuite::known()) {
        const CryptoSuite suite = CryptoSuite::forId(id);

        EXPECT_EQ(32u, suite.keyLength()) << "zestaw " << static_cast<int>(id);
        EXPECT_NO_THROW(suite.encrypt(CryptoSuite::randomBytes(suite.keyLength()), "tajne"));
    }
}

TEST(CryptoSuite, RandomBytesHasTheRequestedLengthAndVaries) {
    EXPECT_EQ(0u, CryptoSuite::randomBytes(0).size());
    EXPECT_EQ(32u, CryptoSuite::randomBytes(32).size());
    EXPECT_NE(CryptoSuite::randomBytes(32), CryptoSuite::randomBytes(32));
}
