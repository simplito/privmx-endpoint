/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_ENDPOINT_GROUP_KEYTREE_LADDERKEYS_HPP_
#define _PRIVMXLIB_ENDPOINT_GROUP_KEYTREE_LADDERKEYS_HPP_

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "privmx/endpoint/group/keytree/LadderTypes.hpp"
#include "privmx/endpoint/group/keytree/TreeKeys.hpp"

namespace privmx {
namespace endpoint {
namespace group {
namespace keytree {

/**
 * The Epoch Ladder with real EC keys: publishing rungs and descending them.
 *
 * The ladder gives historical key access at **two ciphertexts per epoch amortised, independent of group size**,
 * and **zero cost when a member joins** — a newcomer descends on rungs that already exist rather than having
 * past keys re-encrypted to them.
 *
 * It is orthogonal to the key tree. A rung is wrapped to the group's **own** grant key, never to a member or a
 * tree node, so its cost does not change whether the current key is distributed flat, by tree, or by TreeKEM.
 *
 * Epoch grant keys are cached in the shared `TreeKeyStore`, so a climb and a descent feed the same cache: the
 * climb supplies the current epoch, the descent walks back from it.
 */
class LadderKeys {
public:
    LadderKeys(TreeKeyStore& store);

    // ── Publishing ──────────────────────────────────────────────────────────

    /**
     * Builds the rungs a newly created epoch must publish.
     *
     * Always emits the **mandatory unit rung** to the previous epoch, and additionally the aligned skip rungs
     * whose target keys are available.
     *
     * The unit rung is not optional above the era floor: an epoch committed without it leaves a **permanent,
     * unrepairable gap**, because afterwards no party will ever again hold both the previous epoch's private key
     * and the new epoch's public key. A missing skip rung, by contrast, costs only walk time, so an unavailable
     * older key is skipped silently.
     *
     * @param previousEpochKey `sk_{newEpoch-1}`; may be omitted only at the era floor
     * @throws std::invalid_argument when the unit rung cannot be built above the era floor
     */
    std::vector<ArchiveRung> buildRungs(
        std::uint32_t newEpoch,
        const privmx::crypto::PublicKey& newGrantPublicKey,
        const std::optional<privmx::crypto::PrivateKey>& previousEpochKey,
        std::uint32_t eraFloor,
        const std::string& author,
        const privmx::crypto::PrivateKey& signer,
        bool includeSkipRungs = true
    );

    /**
     * Builds era-crossing links: the closing era's **top** key delivered to each entitled principal.
     *
     * One delivery unlocks a whole era, not one epoch — below the boundary ordinary rungs resume. Addressing a
     * **group** rather than individuals costs `O(1)` instead of `O(entitled)`, and lets someone added to that
     * group later gain the closed era with no new ciphertext at all.
     */
    std::vector<ArchiveRung> buildEraLinks(
        std::uint32_t closingEpoch,
        const privmx::crypto::PrivateKey& closingEpochKey,
        const std::vector<EraLinkRecipient>& entitled,
        const std::string& author,
        const privmx::crypto::PrivateKey& signer
    );

    // ── Descending ──────────────────────────────────────────────────────────

    /**
     * Descends from an epoch the caller holds down to an older one, caching every key recovered on the way.
     *
     * Costs `O(log delta)` ECIES decryptions with aligned skip rungs. Greedy: at each step it takes the rung
     * with the smallest target not below the goal — the largest jump that does not overshoot.
     *
     * **Verifies every recovered key against `registry` at every hop**, not only the last. A malicious
     * intermediate rung would otherwise hand back a key that merely fails to decrypt anything later, and the
     * blame would land on the container. A key that fails verification is never cached.
     *
     * Rungs violating the direction invariant are ignored outright, even if they somehow reached storage:
     * traversing one is exactly what would hand a removed member a later key.
     */
    DescentResult descend(
        std::uint32_t from,
        std::uint32_t to,
        const std::vector<ArchiveRung>& available,
        const std::vector<EpochRegistryEntry>& registry,
        std::uint32_t eraFloor = 1,
        std::optional<std::uint32_t> prunedBelow = std::nullopt,
        std::uint32_t maxWalk = 256
    );

    /**
     * Crosses an era boundary using a link addressed to the caller or to one of their groups.
     *
     * Verification against the registry applies here too. On success the closing era's top key is cached, and an
     * ordinary `descend` can continue from it.
     */
    DescentResult crossEraBoundary(
        const std::vector<ArchiveRung>& available,
        const std::string& ownUserId,
        const privmx::crypto::PrivateKey& ownUserKey,
        const std::vector<std::pair<std::string, privmx::crypto::PrivateKey>>& ownGroupKeys,
        const std::vector<EpochRegistryEntry>& registry
    );

    /** Public grant key of an epoch from the registry, or empty when absent. */
    static std::optional<privmx::crypto::PublicKey> publicKeyOfEpoch(
        std::uint32_t epoch,
        const std::vector<EpochRegistryEntry>& registry
    );

private:
    /** Confirms a recovered key really is the epoch's grant key. Invariant B. */
    bool verifyAgainstRegistry(
        const privmx::crypto::PrivateKey& recovered,
        std::uint32_t epoch,
        const std::vector<EpochRegistryEntry>& registry
    ) const;

    TreeKeyStore& _store;
};

} // namespace keytree
} // namespace group
} // namespace endpoint
} // namespace privmx

#endif // _PRIVMXLIB_ENDPOINT_GROUP_KEYTREE_LADDERKEYS_HPP_
