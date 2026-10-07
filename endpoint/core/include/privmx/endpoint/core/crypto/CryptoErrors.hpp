/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_ENDPOINT_CORE_CRYPTOERRORS_HPP_
#define _PRIVMXLIB_ENDPOINT_CORE_CRYPTOERRORS_HPP_

#include <exception>
#include <string>

#include <privmx/utils/PrivmxException.hpp>

#include "privmx/endpoint/core/Exception.hpp"

namespace privmx {
namespace endpoint {
namespace core {

/**
 * @brief Tlumaczy wyjatki pmx-crypto na hierarchie wyjatkow endpointu.
 *
 * Dlaczego to w ogole musi istniec: `cryptoservice::Exception` dziedziczy po `std::exception`,
 * a nie po `privmx::utils::PrivmxException`. Cala granica publicznego API endpointu lapie
 * wylacznie `PrivmxException` i przepuszcza ja przez `ExceptionConverter`, wiec wyjatek
 * z pmx-crypto przeszedlby przez ta granice nietkniety - jako typ, ktorego zaden wrapper
 * (Java, Swift, JS) nie rozpoznaje.
 *
 * Tlumaczymy u zrodla, a nie na granicy API, z dwoch powodow:
 *  - granica to ~250 blokow `catch` w kilkunastu plikach `*Api.cpp`,
 *  - tylko tutaj znamy kontekst wywolania (import klucza, weryfikacja, deszyfrowanie),
 *    a same wyjatki pmx-crypto nie niosa kodu (wszystkie maja `code == 0`).
 *
 * Caly styk endpointu z pmx-crypto to pliki w `core/src/crypto/`, wiec opakowanie ich
 * wywolan domyka szczelnie ten zakres.
 */
class CryptoErrors {
public:
    /**
     * Rzuca odpowiednik wyjatku pmx-crypto z hierarchii `endpoint::crypto::*`.
     *
     * @param e wyjatek zlapany na styku z pmx-crypto
     * @param context nazwa operacji endpointu, dopisywana do opisu
     */
    [[noreturn]] static void rethrow(const std::exception& e, const std::string& context);
};

/**
 * Wykonuje `fn`, tlumaczac wyjatki pmx-crypto. Zwraca to, co `fn`.
 *
 * Lapiemy `std::exception`, a nie `cryptoservice::Exception`, bo pmx-crypto rzuca tez
 * goly `std::runtime_error` (`PrivmxDriverCryptoException` to jego alias). Wyjatki, ktore
 * juz naleza do hierarchii endpointu, przepuszczamy bez zmian - inaczej wlasna walidacja
 * wrapperow (np. `MalformedEncryptionKeyException` z pustego klucza) gubilaby swoj kod.
 */
template <typename F>
decltype(auto) mapCryptoErrors(const char* context, F&& fn) {
    try {
        return fn();
    } catch (const Exception&) {
        throw;
    } catch (const privmx::utils::PrivmxException&) {
        throw;
    } catch (const std::exception& e) {
        CryptoErrors::rethrow(e, context);
        throw; // nieosiagalne - `rethrow` jest [[noreturn]]; ucisza analize przeplywu
    }
}

} // namespace core
} // namespace endpoint
} // namespace privmx

#endif // _PRIVMXLIB_ENDPOINT_CORE_CRYPTOERRORS_HPP_
