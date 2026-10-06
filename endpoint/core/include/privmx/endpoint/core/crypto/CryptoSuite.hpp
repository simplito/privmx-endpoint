/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_ENDPOINT_CORE_CRYPTOSUITE_HPP_
#define _PRIVMXLIB_ENDPOINT_CORE_CRYPTOSUITE_HPP_

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace privmx {
namespace endpoint {
namespace core {

// Uwaga: celowo bez podprzestrzeni `crypto`. W drzewie istnieja juz `privmx::crypto`
// i `privmx::endpoint::crypto`, a trzecia przeslanialaby je dla kodu wewnatrz `core`,
// gdzie skrocona forma `crypto::PrivateKey` jest w powszechnym uzyciu.

/**
 * @brief Identyfikator zestawu algorytmow, zapisywany w ramce zaszyfrowanych danych.
 *
 * Wartosci sa czescia formatu danych - raz uzytej nie wolno zmieniac znaczenia.
 * Numer wycofanego zestawu zostaje zarezerwowany i nie jest ponownie uzywany.
 */
enum class SuiteId : std::uint8_t {
    Unknown = 0x00,
    /// AES-256-GCM + SHA-256 + KDF. Zestaw domyslny dla zapisu.
    Aes256GcmSha256 = 0x01,
    /// AES-256-GCM + SHA-512 + KDF.
    Aes256GcmSha512 = 0x02,
};

/**
 * @brief Warstwa wyboru algorytmow kryptograficznych.
 *
 * Moduly endpointu wolaja ja intencjami ("policz skrot", "zaszyfruj tym kluczem")
 * i **nie nazywaja algorytmow**. Konkretne algorytmy wynikaja z zestawu (suite),
 * a ten jest zapisany w ramce danych - dzieki czemu odczyt zawsze dziala
 * niezaleznie od tego, czym zapisywal autor.
 *
 * Zapis: wedlug zestawu wybranego dla danej operacji (domyslnie `defaultForWrite()`).
 * Odczyt: zawsze wedlug znacznika odczytanego z danych.
 *
 * Format ramki produkowanej przez `encrypt()`:
 * @code
 *   [1B SuiteId][IV][ciphertext || tag AEAD]
 * @endcode
 * Bajt `SuiteId` jest przekazywany jako AAD, wiec jest **uwierzytelniony** -
 * podmiana znacznika na slabszy zestaw unieważnia tag i deszyfrowanie sie nie powiedzie.
 */
class CryptoSuite {
public:
    /**
     * @brief Zestaw uzywany do zapisu, gdy nic go nie wskazuje jawnie.
     *
     * Odpowiada stalej kompilacji (poziom 1 wyboru formatu zapisu).
     */
    static CryptoSuite defaultForWrite();

    /**
     * @brief Zestaw o podanym identyfikatorze.
     * @throws UnknownCryptoSuiteException gdy identyfikator nie jest znany temu buildowi
     */
    static CryptoSuite forId(SuiteId id);

    /// @brief Czy ten build potrafi obsluzyc dany zestaw.
    static bool isKnown(SuiteId id);

    /**
     * @brief Wszystkie znane zestawy.
     *
     * Rejestr odczytu jest **kompletny w kazdym buildzie** - konfiguracja budowania
     * wybiera wylacznie domyslny zestaw zapisu, nigdy zakres odczytu. Inaczej klienci
     * z roznych buildow nie odczytaliby swoich danych.
     */
    static std::vector<SuiteId> known();

    SuiteId id() const { return _id; }

    std::string randomBytes(std::size_t length) const;
    std::string hash(const std::string& data) const;
    std::string mac(const std::string& key, const std::string& data) const;
    std::string deriveKey(const std::string& secret, const std::string& label, std::size_t length) const;

    /// @brief Szyfruje i oprawia w ramke z uwierzytelnionym znacznikiem zestawu.
    std::string encrypt(const std::string& key, const std::string& plaintext) const;

    /**
     * @brief Deszyfruje ramke, dobierajac zestaw na podstawie jej znacznika.
     *
     * Statyczna celowo: odczyt nie wymaga - i nie przyjmuje - wskazania algorytmu.
     *
     * @throws MalformedCryptoFrameException gdy ramka jest za krotka
     * @throws UnknownCryptoSuiteException gdy znacznik jest nieznany temu buildowi
     */
    static std::string decrypt(const std::string& key, const std::string& framed);

    /// @brief Odczytuje sam znacznik zestawu, bez deszyfrowania.
    static SuiteId readSuiteId(const std::string& framed);

private:
    explicit CryptoSuite(SuiteId id) : _id(id) {}

    SuiteId _id;
};

} // namespace core
} // namespace endpoint
} // namespace privmx

#endif // _PRIVMXLIB_ENDPOINT_CORE_CRYPTOSUITE_HPP_
