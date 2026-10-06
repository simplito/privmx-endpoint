/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_ENDPOINT_CORE_CRYPTO_KEYFORMATS_HPP_
#define _PRIVMXLIB_ENDPOINT_CORE_CRYPTO_KEYFORMATS_HPP_

#include <cstdint>
#include <string>

#include <privmx/cryptoservice/base/CoreTypes.hpp>

namespace privmx {
namespace endpoint {
namespace core {

/**
 * @brief Algorytm kluczy tozsamosci.
 *
 * `PrivmxSecp256k1` to secp256k1 z formatami danych PrivMX: czesc prywatna jako samo 32 B,
 * klucz publiczny jako 33 B w postaci skompresowanej. Zwykly `secp256k1` uzywa innych,
 * dluzszych postaci, wiec nie jest zamiennikiem.
 *
 * Warstwa zewnetrzna (dostep do kontenera, podpisy autorstwa) jest **ustalona** - zmiennosc
 * algorytmow dotyczy na razie tego, co dzieje sie wewnatrz kontenera. Patrz
 * crypto-update/warstwa-agility.md §5.
 */
constexpr privmx::cryptoservice::AsymAlg KEY_ALGORITHM = privmx::cryptoservice::AsymAlg::PrivmxSecp256k1;

/**
 * @brief Schemat podpisu odpowiadajacy dotychczasowemu `signToCompactSignatureWithHash`.
 *
 * To **`Compact`**, nie `CompactWithHash`. `Compact` daje ECDSA nad `sha256(m)`;
 * `CompactWithHash` liczy `sha256` dodatkowo, czyli ECDSA nad `sha256(sha256(m))`.
 * Nazwa sugeruje odwrotnosc - zmiana na `CompactWithHash` wyprodukuje podpisy, ktore
 * zweryfikuja sie wylacznie miedzy soba, bez bledu kompilacji ani wykonania.
 * Dowod pomiarowy: crypto-update/B1-podpisy-compact.md
 */
constexpr privmx::cryptoservice::SigScheme SIGNATURE_SCHEME = privmx::cryptoservice::SigScheme::Compact;

inline privmx::cryptoservice::BytesView keyBytes(const std::string& data) {
    return privmx::cryptoservice::BytesView(reinterpret_cast<const std::uint8_t*>(data.data()), data.size());
}

inline std::string keyString(const privmx::cryptoservice::Bytes& data) {
    return std::string(reinterpret_cast<const char*>(data.data()), data.size());
}

} // namespace core
} // namespace endpoint
} // namespace privmx

#endif // _PRIVMXLIB_ENDPOINT_CORE_CRYPTO_KEYFORMATS_HPP_
