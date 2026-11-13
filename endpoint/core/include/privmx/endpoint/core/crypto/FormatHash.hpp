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
 * Not every use of a hash is subject to the `CryptoSuite` choice. What remains here is pinned for a
 * reason of its own, and each reason is specific — none of them is "nobody got round to it":
 *
 *  - the **Base58Check checksum**: SHA-256 is written into that encoding's definition, so this is not
 *    a choice at all;
 *  - the **group key tree** (`TreeCommits`, commit and node hashes): the bridge recomputes exactly
 *    these in `src/service/cloud/keytree/TreeHash.ts`, so they are a cross-repo wire format, governed
 *    by `TreeMath::TREE_VERSION` and not by any one container's suite;
 *  - the **file envelope's chunk key** (`GroupEnvelopeEncryptor`) and the **SRTP key** in `stream`:
 *    both have to be exactly 32 bytes, which a SHA-512 suite would not give;
 *  - **local state** (`LocalSeal`, `ConnectionImpl::localStateScope`): never leaves this machine, so
 *    there is no second party to agree an algorithm with.
 *
 * Things that used to be here and no longer are — the DIO field checksums, `EncKeyV2.secretHash`, the
 * group's roster and metadata tags — all follow the container's suite now. They could, once the DIO
 * started recording the suite it was written under and a decrypted key started reporting its own.
 *
 * **Do not use this for anything reached through a container key.** If a hash is applied to data a
 * container owns, it belongs to that container's `CryptoSuite`; the right question when tempted here
 * is which of the four reasons above applies, and if none does, the answer is the suite.
 */
class FormatHash {
public:
    static std::string sha256(const std::string& data);

    /**
     * @brief HMAC-SHA256 pinned by the format.
     *
     * What is left on it is the chunk key in a file envelope, which has to be 32 bytes, and the
     * local-state tag, which no one else ever verifies. `EncKeyV2.secretHash` and the group's roster
     * and metadata tags have moved to `CryptoSuite::mac`.
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
