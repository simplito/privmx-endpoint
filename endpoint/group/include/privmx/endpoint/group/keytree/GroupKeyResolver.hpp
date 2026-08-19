/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_ENDPOINT_GROUP_KEYTREE_GROUPKEYRESOLVER_HPP_
#define _PRIVMXLIB_ENDPOINT_GROUP_KEYTREE_GROUPKEYRESOLVER_HPP_

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "privmx/endpoint/group/ServerTypes.hpp"
#include "privmx/endpoint/group/keytree/LadderKeys.hpp"
#include "privmx/endpoint/group/keytree/TreeKeys.hpp"

namespace privmx {
namespace endpoint {
namespace group {
namespace keytree {

/** Why a group's grant key could not be resolved through the tree and ladder. */
enum class ResolveFailure {
    None,
    /** The group carries no tree state, so there is nothing to climb. */
    NoTree,
    /** The caller holds no leaf, or the climb broke. `climb` carries the detail. */
    ClimbFailed,
    /** The current epoch was reached but the requested older one was not. `descent` carries the detail. */
    DescentFailed,
};

struct ResolveResult {
    std::optional<privmx::crypto::PrivateKey> key;
    ResolveFailure failure = ResolveFailure::None;
    /** Detail when `failure == ClimbFailed`. */
    ClimbFailure climb = ClimbFailure::None;
    /** Detail when `failure == DescentFailed` — distinguishes an era boundary from tampering. */
    DescentFailure descent = DescentFailure::None;
    /** Publisher of an offending rung or edge, when tampering was detected. */
    std::optional<std::string> blame;
};

/**
 * Resolves a group's grant private key for a given epoch, using the hidden key tree and the Epoch Ladder.
 *
 * Two steps, in order:
 * 1. **climb** the tree from the caller's leaf to the current epoch's grant key,
 * 2. **descend** the ladder from there to the requested epoch, if an older one was asked for.
 *
 * This class deliberately knows nothing about `KeyProvider` or the server transport: it takes an already-fetched
 * `server::GroupInfo` and returns a key. That keeps it unit-testable without a running bridge.
 *
 * A group served without tree fields yields `ResolveFailure::NoTree` — there is no other path left to fall
 * back to.
 */
class GroupKeyResolver {
public:
    GroupKeyResolver(TreeKeyCache& cache);

    /**
     * @param group       the group as served by the bridge
     * @param epoch       requested epoch; `0` means "current"
     * @param ownUserKey  the caller's long-term private key
     * @param archive     the Epoch Ladder, fetched separately
     *
     * The bridge does not put the archive in `groupGet`: it grows with the group's whole history, while a client
     * needs it only when it is actually reaching for an older epoch. The caller fetches it with
     * `groupGetKeyArchive` at that point and hands it in here.
     *
     * The caller's own identity comes from `group.ownLeafPosition`, which the bridge fills in because it knows
     * who is asking — the same reason it already filters `keys` to the caller. That keeps the endpoint from
     * having to know its own user id here, which it otherwise does not.
     */
    ResolveResult resolve(
        const server::GroupInfo& group,
        std::int64_t epoch,
        const privmx::crypto::PrivateKey& ownUserKey,
        const server::GroupGetKeyArchiveResult& archive
    );

    /** The caller's user id, read out of the leaf the bridge pointed at. Empty when unavailable. */
    static std::optional<std::string> ownUserId(const server::GroupInfo& group);

    /** Whether the group carries enough tree state to be climbed at all. */
    static bool hasTree(const server::GroupInfo& group);

    // ── Conversions from the wire types. Public so they can be tested directly. ──

    /**
     * Builds the runtime tree state from a served group.
     *
     * An empty string in `leafAssignment` denotes a blank left by a removal, which is how the wire format
     * represents "no member here" without a nullable array element.
     */
    static TreeGroupState toTreeState(const server::GroupInfo& group);

    /**
     * Converts the rungs of a fetched archive.
     *
     * **Rungs violating the direction invariant are dropped here**, before anything can traverse them. The
     * bridge already rejects them, but a client that trusted the server on this would be trusting the one party
     * the design assumes may be hostile.
     */
    static std::vector<ArchiveRung> toRungs(const server::GroupGetKeyArchiveResult& archive);

    /** The epoch registry, assembled from `groupPubKey` (current epoch) plus `keyHistory` (past ones). */
    static std::vector<EpochRegistryEntry> toRegistry(const server::GroupInfo& group);

    /**
     * The registry assembled from a fetched archive plus the group's current public key.
     *
     * The current epoch has to come from the group rather than the archive: `keyHistory` holds past epochs only,
     * and an epoch this client cannot verify is one it refuses to accept a key for.
     */
    static std::vector<EpochRegistryEntry> toRegistry(
        const server::GroupInfo& group,
        const server::GroupGetKeyArchiveResult& archive
    );

private:
    /** Climb, then descend with the given ladder. */
    ResolveResult resolveWith(
        const server::GroupInfo& group,
        std::int64_t epoch,
        const privmx::crypto::PrivateKey& ownUserKey,
        const std::vector<ArchiveRung>& rungs,
        const std::vector<EpochRegistryEntry>& registry,
        std::uint32_t eraFloor,
        const std::optional<std::uint32_t>& prunedBelow
    );

    TreeKeyCache& _cache;
};

} // namespace keytree
} // namespace group
} // namespace endpoint
} // namespace privmx

#endif // _PRIVMXLIB_ENDPOINT_GROUP_KEYTREE_GROUPKEYRESOLVER_HPP_
