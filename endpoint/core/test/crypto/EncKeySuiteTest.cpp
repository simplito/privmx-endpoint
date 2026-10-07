/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include <string>

#include <gtest/gtest.h>

#include <privmx/endpoint/core/Buffer.hpp>
#include <privmx/endpoint/core/CoreTypes.hpp>
#include <privmx/endpoint/core/KeyProvider.hpp>
#include <privmx/endpoint/core/crypto/CryptoSuite.hpp>
#include <privmx/endpoint/core/crypto/PrivateKey.hpp>
#include <privmx/endpoint/core/encryptors/DataEncryptor.hpp>
#include <privmx/endpoint/core/encryptors/DataInnerEncryptorV4.hpp>

using namespace privmx::endpoint::core;

namespace {

const std::string KEY32(32, 'k');
const std::string PLAIN{"tresc kontenera"};

/// Zestaw inny niz domyslny dla buildu - potrzebny, zeby test odroznil "wzielo z klucza"
/// od "wzielo stala".
CryptoSuite nonDefaultSuite() {
    for (const SuiteId id : CryptoSuite::known()) {
        if (id != CryptoSuite::defaultForWrite().id()) {
            return CryptoSuite::forId(id);
        }
    }
    throw std::logic_error("rejestr ma tylko jeden zestaw - tego testu nie da sie przeprowadzic");
}

} // namespace

// ---------------------------------------------------------------------------------------------
// `EncKey::suite` jest nosnikiem wyboru zestawu z polityki kontenera (poziom 2). Te testy
// pilnuja jedynej wlasnosci, ktora sie liczy: ze zestaw przypisany do klucza faktycznie laduje
// w danych, a nie jest po drodze gubiony na rzecz stalej kompilacji.
// ---------------------------------------------------------------------------------------------

TEST(EncKeySuite, DefaultsToBuildWriteSuite) {
    EXPECT_EQ(CryptoSuite::defaultForWrite().id(), EncKey{}.suite.id());
}

TEST(EncKeySuite, InnerEncryptorWritesWithSuiteFromKey) {
    const CryptoSuite other = nonDefaultSuite();
    ASSERT_NE(CryptoSuite::defaultForWrite().id(), other.id());

    DataInnerEncryptorV4 encryptor;
    const EncKey encKey{.id = "k1", .key = KEY32, .suite = other};

    const std::string framed = encryptor.encrypt(Buffer::from(PLAIN), encKey).stdString();

    EXPECT_EQ(other.id(), CryptoSuite::readSuiteId(framed));
    // Odczyt idzie za znacznikiem z ramki, wiec nie potrzebuje wiedziec, czym zapisano.
    EXPECT_EQ(PLAIN, encryptor.decrypt(Buffer::from(framed), encKey.key).stdString());
}

TEST(EncKeySuite, InnerEncryptorFallsBackToDefaultWhenKeyCarriesNoChoice) {
    DataInnerEncryptorV4 encryptor;
    const EncKey encKey{.id = "k1", .key = KEY32};

    const std::string framed = encryptor.encrypt(Buffer::from(PLAIN), encKey).stdString();

    EXPECT_EQ(CryptoSuite::defaultForWrite().id(), CryptoSuite::readSuiteId(framed));
}

TEST(EncKeySuite, DataEncryptorWritesWithSuiteFromKey) {
    const CryptoSuite other = nonDefaultSuite();
    DataEncryptor<Pson::BinaryString> encryptor;
    const EncKey encKey{.id = "k1", .key = KEY32, .suite = other};

    const std::string base64 = encryptor.encrypt(Pson::BinaryString(PLAIN), encKey);
    const std::string framed = privmx::utils::Base64::toString(base64);

    EXPECT_EQ(other.id(), CryptoSuite::readSuiteId(framed));
    EXPECT_EQ(PLAIN, std::string(encryptor.decrypt(base64, encKey)));
}

/// Przeciazenie z golym kluczem nie ma skad wziac zestawu, wiec musi uzyc domyslnego - takze
/// wtedy, gdy obok istnieje `EncKey` z innym. Inaczej "zapisz tym kluczem" znaczyloby co innego
/// w zaleznosci od tego, ktore przeciazenie trafi sie wolajacemu.
TEST(EncKeySuite, RawKeyOverloadAlwaysUsesDefault) {
    DataEncryptor<Pson::BinaryString> encryptor;

    const std::string base64 = encryptor.encrypt(Pson::BinaryString(PLAIN), KEY32);
    const std::string framed = privmx::utils::Base64::toString(base64);

    EXPECT_EQ(CryptoSuite::defaultForWrite().id(), CryptoSuite::readSuiteId(framed));
}

/// Dane zapisane jednym zestawem musza byc czytelne dla kazdego klucza o tej samej wartosci,
/// niezaleznie od tego, jaki zestaw niesie `EncKey` uzyty do odczytu. To jest wlasnie powod,
/// dla ktorego `suite` dotyczy wylacznie zapisu.
TEST(EncKeySuite, ReadIgnoresSuiteOnTheKeyAndFollowsTheFrame) {
    const CryptoSuite other = nonDefaultSuite();
    DataEncryptor<Pson::BinaryString> encryptor;

    const std::string base64 = encryptor.encrypt(
        Pson::BinaryString(PLAIN), EncKey{.id = "k1", .key = KEY32, .suite = other}
    );

    const EncKey readerKey{.id = "k1", .key = KEY32, .suite = CryptoSuite::defaultForWrite()};
    EXPECT_EQ(PLAIN, std::string(encryptor.decrypt(base64, readerKey)));
}

// ---------------------------------------------------------------------------------------------
// Niezmiennik: swiezo wygenerowany klucz ma dlugosc wymagana przez swoj zestaw. Przed zmiana
// `generateKey` zwracal zawsze 32 bajty, co bylo poprawne tylko dlatego, ze oba dzisiejsze
// zestawy akurat tyle chca.
// ---------------------------------------------------------------------------------------------

TEST(EncKeySuite, GeneratedKeyMatchesItsSuite) {
    KeyProvider provider(PrivateKey::generateRandom(), [] { return nullptr; });

    for (const SuiteId id : CryptoSuite::known()) {
        const CryptoSuite suite = CryptoSuite::forId(id);
        const EncKey key = provider.generateKey(suite);

        EXPECT_EQ(suite.id(), key.suite.id());
        EXPECT_EQ(suite.keyLength(), key.key.size());
        EXPECT_FALSE(key.id.empty());
        // Klucz musi dac sie od razu uzyc swoim wlasnym zestawem - to lapie rozjazd miedzy
        // `keyLength()` a tym, co faktycznie wygenerowano.
        EXPECT_NO_THROW(suite.encrypt(key.key, PLAIN));
    }
}

TEST(EncKeySuite, GeneratedKeysDiffer) {
    KeyProvider provider(PrivateKey::generateRandom(), [] { return nullptr; });
    const CryptoSuite suite = CryptoSuite::defaultForWrite();

    const EncKey first = provider.generateKey(suite);
    const EncKey second = provider.generateKey(suite);

    EXPECT_NE(first.key, second.key);
    EXPECT_NE(first.id, second.id);
}
