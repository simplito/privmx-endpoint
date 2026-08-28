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

enum class ResolveFailure {
    None,
    // The group carries no tree state, so there is nothing to climb.
    NoTree,
    // The caller holds no leaf, or the climb broke.
    ClimbFailed,
    // The current epoch was reached but the requested older one was not.
    DescentFailed,
};

struct ResolveResult {
    std::optional<privmx::crypto::PrivateKey> key;
    ResolveFailure failure = ResolveFailure::None;
    // Detail when `failure == ClimbFailed`.
    ClimbFailure climb = ClimbFailure::None;
    // Detail when `failure == DescentFailed` — distinguishes an era boundary from tampering.
    DescentFailure descent = DescentFailure::None;
    // Publisher of an offending rung or edge, when tampering was detected.
    std::optional<std::string> blame;
};

// Resolves a group's grant private key for an epoch: climb the tree to the current one, then descend the ladder
// if an older was asked for. Knows nothing of KeyProvider or transport, so it is testable without a bridge.
class GroupKeyResolver {
public:
    GroupKeyResolver(TreeKeyCache& cache);

    // `epoch` 0 means current; `archive` is the ladder, fetched separately because it grows with the whole history
    // and is only needed for an older epoch. The caller's identity comes from `group.ownLeafPosition`.
    ResolveResult resolve(
        const server::GroupInfo& group,
        std::int64_t epoch,
        const privmx::crypto::PrivateKey& ownUserKey,
        const server::GroupGetKeyArchiveResult& archive
    );

    // The caller's user id, read out of the leaf the bridge pointed at.
    static std::optional<std::string> ownUserId(const server::GroupInfo& group);

    static bool hasTree(const server::GroupInfo& group);

    // ── Conversions from the wire types. Public so they can be tested directly. ──

    // An empty string in `leafAssignment` is a blank left by a removal — the wire format's "no member here".
    static TreeGroupState toTreeState(const server::GroupInfo& group);

    // Rungs violating the direction invariant are dropped here, before anything can traverse them: the bridge
    // rejects them too, but trusting it on this would trust the one party the design assumes may be hostile.
    static std::vector<ArchiveRung> toRungs(const server::GroupGetKeyArchiveResult& archive);

    // Assembled from `groupPubKey` (current epoch) plus `keyHistory` (past ones).
    static std::vector<EpochRegistryEntry> toRegistry(const server::GroupInfo& group);

    // The current epoch comes from the group, not the archive: `keyHistory` holds past epochs only, and an epoch
    // this client cannot verify is one it refuses to accept a key for.
    static std::vector<EpochRegistryEntry> toRegistry(
        const server::GroupInfo& group,
        const server::GroupGetKeyArchiveResult& archive
    );

private:
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
