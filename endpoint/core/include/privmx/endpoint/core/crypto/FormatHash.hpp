/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_ENDPOINT_CORE_FORMATHASH_HPP_
#define _PRIVMXLIB_ENDPOINT_CORE_FORMATHASH_HPP_

#include <cstddef>
#include <string>

namespace privmx {
namespace endpoint {
namespace core {

/**
 * @brief Hasze przybite przez format danych, a nie wybierane przez zestaw algorytmow.
 *
 * Nie kazde uzycie haszu podlega wyborowi z `CryptoSuite`. Czesc z nich jest **czescia definicji
 * formatu** i czytajacy musi wiedziec z gory, czym weryfikowac, bo nie ma przy nich zadnego
 * znacznika:
 *
 *  - suma kontrolna Base58Check (SHA-256 jest wpisany w definicje tego kodowania),
 *  - sumy kontrolne pol w DIO oraz `secretHash` w `EncKeyV2` - wersjonowane przez
 *    `structureVersion` tych struktur, nie przez znacznik zestawu.
 *
 * Ta klasa jest dla nich jedynym punktem wejscia. Istnieje po to, zeby takie miejsca nie musialy
 * wolac `privmx::crypto::Crypto` - czyli znikajacego modulu - i zeby odroznienie "hasz ustalony
 * formatem" od "hasz z zestawu" bylo widoczne w kodzie, a nie tylko w komentarzu.
 *
 * **Nie uzywac tego do danych szyfrowanych kluczem kontenera** - tam hasz ma pochodzic
 * z `CryptoSuite`, zeby dalo sie go zmienic razem z reszta zestawu.
 */
class FormatHash {
public:
    static std::string sha256(const std::string& data);

    /**
     * @brief HMAC-SHA256 przybity formatem.
     *
     * Uzywany tam, gdzie znacznik uwierzytelniajacy jest **czescia definicji struktury**, a nie
     * wyborem: `secretHash` w `EncKeyV2`, tagi rostera i metadanych grupy, klucz chunku w kopercie
     * plikowej. Wszystkie sa wersjonowane przez `structureVersion` albo przez wersje koperty,
     * nie przez znacznik zestawu - czytajacy musi wiedziec z gory, czym weryfikowac.
     */
    static std::string hmacSha256(const std::string& key, const std::string& data);

    /**
     * @brief KDF na SHA-256, przybity formatem.
     *
     * Odpowiada `CryptoSuite::deriveKey` dla zestawu z SHA-256, ale bez przechodzenia przez zestaw:
     * wyprowadzenia opisane tutaj naleza do formatu danych i nie zmieniaja sie razem z nim.
     */
    static std::string kdf(const std::string& secret, const std::string& label, std::size_t length);
};

} // namespace core
} // namespace endpoint
} // namespace privmx

#endif // _PRIVMXLIB_ENDPOINT_CORE_FORMATHASH_HPP_
