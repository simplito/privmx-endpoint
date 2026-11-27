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
 * @brief Base58 and Base58Check encoding.
 *
 * **Why the hash function is injected.** Base58Check computes its checksum as
 * `sha256(sha256(payload))[0..4)`. `utils` sits below the cryptographic layer and cannot call into
 * it — the previous answer to that was to keep the whole class in the `crypto/` module and leave a
 * forwarding header in `utils` with a comment about the circular dependency. Injecting the function
 * breaks the cycle and lets the `crypto/` module go away.
 *
 * This is **not** a place to choose an algorithm: SHA-256 is written into the definition of
 * Base58Check, so the caller is to pass SHA-256, not "whatever hash they currently use".
 */
class Base58 {
public:
    /// Computes SHA-256 of the given data.
    using Sha256 = std::function<std::string(const std::string&)>;

    static std::string encode(const std::string& s);
    static std::string decode(const std::string& s);
    static bool is(const std::string& s);

    static std::string encodeWithChecksum(const std::string& s, const Sha256& sha256);

    /**
     * @throws PrivmxException when the checksum does not match
     */
    static std::string decodeWithChecksum(const std::string& s, const Sha256& sha256);

private:
    static std::string gmp2bitcoin(std::string s);
    static std::string bitcoin2gmp(std::string s);
};

} // namespace utils
} // namespace privmx

#endif // _PRIVMXLIB_UTILS_BASE58_HPP_
