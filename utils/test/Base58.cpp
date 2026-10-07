/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

/**
 * Base58 trafil tu z modulu `crypto/`, a przy przeprowadzce zmienil API: warianty z suma
 * kontrolna dostaja funkcje haszujaca z zewnatrz, bo `utils` nie moze wolac kryptografii.
 * Te testy sprawdzaja, ze samo kodowanie sie przy tym nie zmienilo.
 */

#include <string>

#include <gtest/gtest.h>

#include <privmx/utils/Base58.hpp>
#include <privmx/utils/PrivmxException.hpp>

using privmx::utils::Base58;

namespace {

/// SHA-256 na potrzeby testu - staly wektor, zeby nie wciagac tu kryptografii.
/// Nie liczy prawdziwego SHA-256; sprawdzamy wylacznie, ze suma kontrolna jest liczona
/// **ta podana** funkcja i ze jej wynik faktycznie decyduje o odrzuceniu danych.
std::string fakeSha256(const std::string& data) {
    std::string out(32, '\0');
    for (std::size_t i = 0; i < data.size(); ++i) {
        out[i % 32] = static_cast<char>(out[i % 32] ^ data[i] ^ static_cast<char>(i));
    }
    return out;
}

std::string otherSha256(const std::string& data) {
    return fakeSha256(data + "inna");
}

} // namespace

// ---------------------------------------------------------------------------------------------
// Samo kodowanie - bez kryptografii.
// ---------------------------------------------------------------------------------------------

TEST(Base58Test, KnownVectors) {
    EXPECT_EQ("2g", Base58::encode("a"));
    EXPECT_EQ("StV1DL6CwTryKyV", Base58::encode("hello world"));
}

TEST(Base58Test, RoundTrip) {
    for (const std::string& s : {std::string("a"), std::string("hello world"),
                                 std::string("\x00\x00\x01\x02", 4), std::string(100, 'z')}) {
        EXPECT_EQ(s, Base58::decode(Base58::encode(s)));
    }
}

/**
 * Wejscie zlozone z samych zer nie przechodzi obrotu: `encode("")` daje "1", a `decode("1")`
 * daje bajt zerowy. Zrodlem jest liczenie dopelnienia zerami obok wartosci liczbowej, ktora dla
 * samych zer jest pusta.
 *
 * To zachowanie **zastane**, nie wprowadzone przeprowadzka - i celowo nienaprawione, bo Base58
 * koduje tu klucze, a zmiana kodowania zmienilaby ich postac na dysku i na wire. W praktyce
 * nieosiagalne: klucz publiczny zaczyna sie od 0x02/0x03, a WIF od 0x80.
 *
 * Test opisuje stan faktyczny, zeby nikt nie uznal go za przypadek.
 */
TEST(Base58Test, AllZeroInputDoesNotRoundTripAndThatIsKnown) {
    EXPECT_EQ("1", Base58::encode(""));
    EXPECT_EQ("11", Base58::encode(std::string(1, '\0')));

    EXPECT_NE("", Base58::decode(Base58::encode("")));
}

/// Wiodace zera sa kodowane jako '1' i musza przezyc obrot - to najczestszy blad w Base58.
TEST(Base58Test, LeadingZerosSurvive) {
    const std::string s("\x00\x00\x00\x2a", 4);

    const std::string encoded = Base58::encode(s);

    EXPECT_EQ("111", encoded.substr(0, 3));
    EXPECT_EQ(s, Base58::decode(encoded));
}

TEST(Base58Test, IsAcceptsOnlyTheAlphabet) {
    EXPECT_TRUE(Base58::is("StV1DL6CwTryKyV"));
    EXPECT_TRUE(Base58::is(""));
    // Znaki wylaczone z alfabetu Base58, bo myla sie wzrokowo.
    EXPECT_FALSE(Base58::is("0"));
    EXPECT_FALSE(Base58::is("O"));
    EXPECT_FALSE(Base58::is("I"));
    EXPECT_FALSE(Base58::is("l"));
    EXPECT_FALSE(Base58::is("ma spacje"));
}

// ---------------------------------------------------------------------------------------------
// Base58Check - suma kontrolna liczona wstrzyknieta funkcja.
// ---------------------------------------------------------------------------------------------

TEST(Base58Test, ChecksumRoundTrip) {
    const std::string payload("dane do zakodowania");

    const std::string encoded = Base58::encodeWithChecksum(payload, fakeSha256);

    EXPECT_EQ(payload, Base58::decodeWithChecksum(encoded, fakeSha256));
}

/// Sedno zmiany API: suma kontrolna ma pochodzic z **podanej** funkcji. Gdyby implementacja
/// wolala cokolwiek innego, odczyt inna funkcja by przeszedl.
TEST(Base58Test, ChecksumIsComputedWithTheGivenFunction) {
    const std::string encoded = Base58::encodeWithChecksum("dane", fakeSha256);

    EXPECT_THROW(Base58::decodeWithChecksum(encoded, otherSha256), privmx::utils::PrivmxException);
}

TEST(Base58Test, CorruptedPayloadIsRejected) {
    std::string encoded = Base58::encodeWithChecksum("dane do zakodowania", fakeSha256);

    encoded[2] = (encoded[2] == 'z' ? 'y' : 'z');
    EXPECT_THROW(Base58::decodeWithChecksum(encoded, fakeSha256), privmx::utils::PrivmxException);
}

/// Wejscie krotsze niz sama suma kontrolna. Przed przeprowadzka `data.length() - 4` przekrecalo
/// licznik i `substr` dostawal wartosc bliska zakresowi `size_t`.
TEST(Base58Test, InputShorterThanTheChecksumIsRejected) {
    EXPECT_THROW(Base58::decodeWithChecksum("", fakeSha256), privmx::utils::PrivmxException);
    EXPECT_THROW(Base58::decodeWithChecksum("2g", fakeSha256), privmx::utils::PrivmxException);
}
