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
#include "privmx/endpoint/group/keytree/TreeKeyCache.hpp"

namespace privmx {
namespace endpoint {
namespace group {
namespace keytree {

/**
 * Outcome of gathering the older grant keys a full rung set needs.
 *
 * `missingTargets` is what makes a failure reportable: it names the epochs whose rungs would be absent, so a
 * refusal can say which stretch of history is at stake instead of just "could not build the rungs".
 */
struct RungKeyGathering {
    /** True when the cache now holds every older key `buildRungs` is about to ask for. */
    bool complete = true;
    /** Skip targets still unreachable, nearest first. Empty when `complete`. */
    std::vector<std::uint32_t> missingTargets;
    /** Why the gathering stopped. `None` only when `complete`. */
    DescentFailure failure = DescentFailure::None;
    /** Publisher of an offending rung, when `failure == Tampered`. */
    std::optional<std::string> blame;
    /** Rungs unwrapped. On a ladder carrying its skip rungs this is one per target — about `log2(newEpoch)`. */
    std::uint32_t unwraps = 0;
};

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
 * Epoch grant keys are cached in the shared `TreeKeyCache`, so a climb and a descent feed the same cache: the
 * climb supplies the current epoch, the descent walks back from it.
 */
class LadderKeys {
public:
    LadderKeys(TreeKeyCache& cache);

    // ── Publishing ──────────────────────────────────────────────────────────

    /**
     * Builds the **complete** rung set a newly created epoch must publish: the mandatory unit rung to the previous
     * epoch, plus every aligned skip rung the epoch owes.
     *
     * No rung in this set is optional, and none of them is repairable later. A rung may only ever be published at
     * the moment its own epoch is created — its span is `at == newEpoch`, which the bridge enforces — so after the
     * rotation commits, no party will ever again hold both the target epoch's private key and this epoch's public
     * key. Publish a set with a hole and the hole is there for good; publish enough of them and the surviving
     * ladder is a chain of unit rungs, which puts history further back than `descend`'s bound out of reach for
     * **everyone, permanently**. So a target key this client does not hold is a refusal, not an omission — call
     * `gatherRungKeys` first, which is what puts those keys in the cache.
     *
     * @param previousEpochKey `sk_{newEpoch-1}`; may be omitted only at the era floor
     * @param includeSkipRungs `false` emits the unit rung alone. For fixtures and for a caller that has no
     *                         archive to gather from — not for a rotation, which owes the full set.
     * @param prunedBelow      the archive's prune watermark, when it has one. Targets below it are neither
     *                         demanded nor emitted: the bridge rejects them and their keys are gone for everyone.
     * @throws std::invalid_argument when the unit rung cannot be built above the era floor, or when a skip rung
     *                              the epoch owes has no key in the cache
     */
    std::vector<ArchiveRung> buildRungs(
        std::uint32_t newEpoch,
        const privmx::crypto::PublicKey& newGrantPublicKey,
        const std::optional<privmx::crypto::PrivateKey>& previousEpochKey,
        std::uint32_t eraFloor,
        const std::string& author,
        const privmx::crypto::PrivateKey& signer,
        bool includeSkipRungs = true,
        std::optional<std::uint32_t> prunedBelow = std::nullopt
    );

    /**
     * Recovers into the cache every older grant key `buildRungs` will ask for at `newEpoch`, so that a rotation
     * from a cold client publishes the same full set a long-running one would.
     *
     * This is the step that keeps the ladder logarithmic across restarts. A manager's cache holds only what this
     * session climbed or descended to; without this it holds one key, and the rotation would owe skip rungs it
     * cannot build.
     *
     * Costs **one unwrap per skip target** on a healthy ladder — about `log2(newEpoch)`, so ~10 for a group at
     * epoch 1024. That falls out of the alignment rather than being tuned: the targets are `newEpoch - 2^j`, and
     * `newEpoch - 2^j` is itself divisible by `2^j`, so it published a skip rung landing exactly on the next
     * target down. The walk therefore chains through the targets in order instead of restarting at `newEpoch-1`
     * for each.
     *
     * Requires `sk_{newEpoch-1}` in the cache — the climb supplies it, and the unit rung needs it anyway.
     * Recovered keys are verified against `registry` at every hop, exactly as in a reader's descent.
     */
    RungKeyGathering gatherRungKeys(
        std::uint32_t newEpoch,
        const std::vector<ArchiveRung>& available,
        const std::vector<EpochRegistryEntry>& registry,
        std::uint32_t eraFloor = 1,
        std::optional<std::uint32_t> prunedBelow = std::nullopt
    );

    /**
     * The skip targets `newEpoch` owes a rung to, **nearest first**, excluding the unit rung's own target.
     *
     * The order is not cosmetic: `gatherRungKeys` walks it as a chain, each descent starting where the previous
     * one landed. Targets at or below the era floor, and below the prune watermark, are left out — the bridge
     * would reject those rungs and the keys behind them are unrecoverable by policy, not by accident.
     *
     * Also tells a caller cheaply whether an archive fetch is needed at all: an empty result means the unit rung
     * is the whole set, and its key came from the climb.
     */
    static std::vector<std::uint32_t> requiredSkipTargets(
        std::uint32_t newEpoch,
        std::uint32_t eraFloor,
        std::optional<std::uint32_t> prunedBelow = std::nullopt
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

    TreeKeyCache& _cache;
};

} // namespace keytree
} // namespace group
} // namespace endpoint
} // namespace privmx

#endif // _PRIVMXLIB_ENDPOINT_GROUP_KEYTREE_LADDERKEYS_HPP_
