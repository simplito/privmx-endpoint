/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_ENDPOINT_STORE_FILECIPHER_HPP_
#define _PRIVMXLIB_ENDPOINT_STORE_FILECIPHER_HPP_

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "privmx/endpoint/store/interfaces/IChunkEncryptor.hpp"

namespace privmx {
namespace endpoint {
namespace store {

/**
 * @brief Format danych pliku: jeden zestaw parametrow i operacji, wybierany przez `cipherType`.
 *
 * **Czemu to nie jest `core::CryptoSuite`.** W kontenerze zestaw algorytmow zmienia tylko
 * *zawartosc* ramki - znacznik siedzi w kazdej ramce z osobna, a ramki nie sa adresowane po
 * przesunieciu. W pliku jest inaczej: dlugosc skrotu jest **krokiem tablicy skrotow**
 * (`chunkIndex * hashLength()`), a rozmiar zaszyfrowanego chunku sluzy do adresowania chunkow
 * w pliku na serwerze (`index * encryptedChunkSize()`). Zmiana algorytmu przestawia wiec caly
 * uklad pliku, a nie tylko jego tresc - i dlatego ma wlasny, grubszy znacznik.
 *
 * **Gdzie siedzi znacznik.** `cipherType` w wewnetrznym meta pliku. Pole istnialo wczesniej:
 * bylo zapisywane jako `1` i sprawdzane przy odczycie. Teraz jest to pelnoprawny wybor formatu.
 *
 * Dodanie nowego formatu to wpis w tablicy w `FileCipher.cpp` plus jego wlasne `encryptChunk`
 * i `decryptChunk`. Raz wydanej wartosci `cipherType` nie wolno przedefiniowac - pliki zapisane
 * stara wartoscia zostaja na dysku.
 */
class FileCipher {
public:
    /// AES-256-CBC + PKCS#7, HMAC-SHA256 nad `IV || szyfrogram`, klucz chunku `sha256(fileKey || BE32(index))`.
    static constexpr int64_t AES_CBC_HMAC_SHA256 = 1;

    /**
     * @brief Format o podanym znaczniku.
     * @throws UnsupportedCipherTypeException gdy ten build nie zna takiego formatu
     */
    static FileCipher forType(int64_t cipherType);

    /// @brief Format uzywany przy zapisie nowych plikow.
    static FileCipher defaultForWrite();

    static bool isKnown(int64_t cipherType);

    /// @brief Wszystkie znane formaty. Rejestr odczytu jest kompletny w kazdym buildzie.
    static std::vector<int64_t> known();

    int64_t type() const { return _type; }

    std::size_t ivLength() const;

    /// @brief Dlugosc skrotu chunku. Jest to **krok tablicy skrotow**, nie tylko rozmiar wyniku.
    std::size_t hashLength() const;

    /// @brief Rozmiar bloku dopelnienia; 0, gdy format nie dopelnia.
    std::size_t paddingBlock() const;

    /// @brief Klucz chunku o danym indeksie. Indeks wchodzi do klucza, wiec chunki nie sa zamienne.
    std::string chunkKey(const std::string& fileKey, std::uint64_t index) const;

    IChunkEncryptor::Chunk encryptChunk(const std::string& chunkKey, const std::string& plain) const;

    /**
     * @throws FileChunkInvalidCipherChecksumException gdy skrot ramki sie nie zgadza
     */
    std::string decryptChunk(const std::string& chunkKey, const IChunkEncryptor::Chunk& chunk) const;

    /// @brief Skrot wiazacy cala tablice skrotow chunkow.
    std::string topHash(const std::string& topHashKey, const std::string& hashes) const;

    std::size_t encryptedChunkSize(std::size_t plainChunkSize) const;

    std::uint64_t encryptedFileSize(std::uint64_t fileSize, std::size_t plainChunkSize) const;

private:
    explicit FileCipher(int64_t type) : _type(type) {}

    int64_t _type;
};

} // namespace store
} // namespace endpoint
} // namespace privmx

#endif // _PRIVMXLIB_ENDPOINT_STORE_FILECIPHER_HPP_
