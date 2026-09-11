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

// Outcome of gathering the older grant keys a full rung set needs.
struct RungKeyGathering {
    // True when the cache now holds every older key `buildRungs` is about to ask for.
    bool complete = true;
    // Skip targets still unreachable, nearest first — names the stretch of history a refusal is about.
    std::vector<std::uint32_t> missingTargets;
    // `None` only when `complete`.
    DescentFailure failure = DescentFailure::None;
    // Publisher of an offending rung, when `failure == Tampered`.
    std::optional<std::string> blame;
    // One per target on a ladder carrying its skip rungs — about `log2(newEpoch)`.
    std::uint32_t unwraps = 0;
};

// The Epoch Ladder with real EC keys: two ciphertexts per epoch amortised, independent of group size, and nothing
// at all when a member joins. Orthogonal to the tree — a rung wraps to the group's own grant key, never a member.
class LadderKeys {
public:
    LadderKeys(TreeKeyCache& cache);

    // ── Publishing ──────────────────────────────────────────────────────────

    // The complete rung set a new epoch must publish: the unit rung to the previous epoch plus every aligned skip
    // rung it owes. A rung is publishable only at its own epoch, so a key not in the cache is a refusal, not a hole.
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

    // Recovers into the cache every older grant key `buildRungs` will ask for, so a cold client publishes the same
    // full set a long-running one would. One unwrap per skip target (~`log2(newEpoch)`); needs `sk_{newEpoch-1}`.
    RungKeyGathering gatherRungKeys(
        std::uint32_t newEpoch,
        const std::vector<ArchiveRung>& available,
        const std::vector<EpochRegistryEntry>& registry,
        std::uint32_t eraFloor = 1,
        std::optional<std::uint32_t> prunedBelow = std::nullopt
    );

    // The skip targets `newEpoch` owes a rung to, nearest first, minus the unit rung's target and anything at or
    // below the era floor or prune watermark. The order is a chain `gatherRungKeys` walks; empty means no fetch.
    static std::vector<std::uint32_t> requiredSkipTargets(
        std::uint32_t newEpoch,
        std::uint32_t eraFloor,
        std::optional<std::uint32_t> prunedBelow = std::nullopt
    );

    // Era-crossing links: the closing era's top key delivered to each entitled principal, one delivery per era.
    // Addressing a group rather than individuals costs `O(1)` and covers anyone added to that group later.
    std::vector<ArchiveRung> buildEraLinks(
        std::uint32_t closingEpoch,
        const privmx::crypto::PrivateKey& closingEpochKey,
        const std::vector<EraLinkRecipient>& entitled,
        const std::string& author,
        const privmx::crypto::PrivateKey& signer
    );

    // ── Descending ──────────────────────────────────────────────────────────

    // Descends from an epoch the caller holds to an older one, greedily taking the largest jump that does not
    // overshoot (`O(log delta)`). Verified against `registry` at every hop; wrong-direction rungs are ignored.
    DescentResult descend(
        std::uint32_t from,
        std::uint32_t to,
        const std::vector<ArchiveRung>& available,
        const std::vector<EpochRegistryEntry>& registry,
        std::uint32_t eraFloor = 1,
        std::optional<std::uint32_t> prunedBelow = std::nullopt,
        std::uint32_t maxWalk = 256
    );

    // Crosses an era boundary on a link addressed to the caller or one of their groups; on success the closing
    // era's top key is cached and an ordinary `descend` continues from it.
    DescentResult crossEraBoundary(
        const std::vector<ArchiveRung>& available,
        const std::string& ownUserId,
        const privmx::crypto::PrivateKey& ownUserKey,
        const std::vector<std::pair<std::string, privmx::crypto::PrivateKey>>& ownGroupKeys,
        const std::vector<EpochRegistryEntry>& registry
    );

    static std::optional<privmx::crypto::PublicKey> publicKeyOfEpoch(
        std::uint32_t epoch,
        const std::vector<EpochRegistryEntry>& registry
    );

private:
    // Confirms a recovered key really is the epoch's grant key. Invariant B.
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
