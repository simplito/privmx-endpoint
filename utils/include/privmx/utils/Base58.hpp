/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_UTILS_BASE58_HPP_
#define _PRIVMXLIB_UTILS_BASE58_HPP_

#include <functional>
#include <string>

namespace privmx {
namespace utils {

/**
 * @brief Kodowanie Base58 oraz Base58Check.
 *
 * **Czemu funkcja haszujaca przychodzi z zewnatrz.** Base58Check liczy sume kontrolna jako
 * `sha256(sha256(payload))[0..4)`. `utils` lezy ponizej warstwy kryptograficznej i nie moze jej
 * wolac - wczesniej rozwiazywano to tak, ze cala klasa mieszkala w module `crypto/`, a w `utils`
 * stal naglowek przekierowujacy z komentarzem o cyklicznej zaleznosci. Wstrzykniecie funkcji
 * zrywa ten cykl i pozwala modulowi `crypto/` zniknac.
 *
 * To **nie jest** miejsce na wybor algorytmu: SHA-256 jest wpisany w definicje Base58Check,
 * wiec wolajacy ma podac SHA-256, a nie "swoj aktualny hasz".
 */
class Base58 {
public:
    /// Liczy SHA-256 z podanych danych.
    using Sha256 = std::function<std::string(const std::string&)>;

    static std::string encode(const std::string& s);
    static std::string decode(const std::string& s);
    static bool is(const std::string& s);

    static std::string encodeWithChecksum(const std::string& s, const Sha256& sha256);

    /**
     * @throws PrivmxException gdy suma kontrolna sie nie zgadza
     */
    static std::string decodeWithChecksum(const std::string& s, const Sha256& sha256);

private:
    static std::string gmp2bitcoin(std::string s);
    static std::string bitcoin2gmp(std::string s);
};

} // namespace utils
} // namespace privmx

#endif // _PRIVMXLIB_UTILS_BASE58_HPP_
