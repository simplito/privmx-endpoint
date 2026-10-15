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
 * @brief Hashes pinned by the data format, rather than chosen by an algorithm suite.
 *
 * Not every use of a hash is subject to the `CryptoSuite` choice. Some are **part of the format's
 * definition**, and a reader has to know up front what to verify with, because they carry no tag:
 *
 *  - the Base58Check checksum (SHA-256 is written into that encoding's definition),
 *  - the DIO field checksums and `EncKeyV2.secretHash` — versioned by those structures'
 *    `structureVersion`, not by a suite tag.
 *
 * This class is their single entry point. It exists so that such places do not have to call
 * `privmx::crypto::Crypto` — the module on its way out — and so that the distinction between "a hash
 * pinned by the format" and "a hash from the suite" is visible in the code, not only in a comment.
 *
 * **Do not use this for data encrypted with a container key** — there the hash should come from
 * `CryptoSuite`, so it can be changed along with the rest of the suite.
 */
class FormatHash {
public:
    static std::string sha256(const std::string& data);

    /**
     * @brief HMAC-SHA256 pinned by the format.
     *
     * Used where the authentication tag is **part of a structure's definition** rather than a
     * choice: `EncKeyV2.secretHash`, the group roster and metadata tags, the chunk key in a file
     * envelope. All of them are versioned by `structureVersion` or by the envelope version, not by a
     * suite tag — a reader has to know up front what to verify with.
     */
    static std::string hmacSha256(const std::string& key, const std::string& data);

    /**
     * @brief A SHA-256 KDF pinned by the format.
     *
     * Equivalent to `CryptoSuite::deriveKey` for a SHA-256 suite, but without going through a suite:
     * the derivations covered here belong to the data format and do not change when the suite does.
     */
    static std::string kdf(const std::string& secret, const std::string& label, std::size_t length);
};

} // namespace core
} // namespace endpoint
} // namespace privmx

#endif // _PRIVMXLIB_ENDPOINT_CORE_FORMATHASH_HPP_
