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
#include <map>
#include <optional>
#include <string>
#include <vector>

#include "privmx/endpoint/group/ServerTypes.hpp"
#include "privmx/endpoint/group/keytree/LadderKeys.hpp"
#include "privmx/endpoint/group/keytree/TreeCommits.hpp"
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
    // The group's tree has a layout (`treeVersion`) this client does not read.
    UnsupportedTreeVersion,
    // The requested epoch lies past the current one: there is no key for it yet.
    FutureEpoch,
    // The requested epoch is negative or outside the range epochs have.
    InvalidEpoch,
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

    // `epoch` 0 means current; one past the current fails as `FutureEpoch`. `archive` is the ladder, fetched
    // separately because it grows with the whole history and is only needed for an older epoch. The caller's
    // identity comes from `group.ownLeafPosition`.
    ResolveResult resolve(
        const server::GroupInfo& group,
        std::int64_t epoch,
        const privmx::crypto::PrivateKey& ownUserKey,
        const server::GroupGetKeyArchiveResult& archive
    );

    static std::optional<std::string> ownUserId(const server::GroupInfo& group);

    // The lowest node of the caller's keyed path it should self-update over, if any: one blank in the served state
    // (left so by a removal), or set by somebody not seated under it (the creator or an adder), who keeps that key.
    static std::optional<std::uint32_t> nodeNeedingSelfUpdate(const server::GroupInfo& group);
    // Whether the caller holds the lowest occupied seat under `node` (a node of its own keyed path). That seat heals
    // the node first; every other seat under it only stands in when it did not, so a node draws one commit, not one
    // per member under it.
    static bool healsFirst(const server::GroupInfo& group, std::uint32_t node);

    static bool hasTree(const server::GroupInfo& group);

    // Who published what a climb found tampered (`ClimbResult::tamperedNode`): a node's edges come from the
    // statement that set its key (`setBy`), the grant edge (no node) from the latest one, which rewrites it.
    static std::optional<std::string> tamperedBy(
        const server::GroupInfo& group,
        const std::optional<std::uint32_t>& tamperedNode
    );

    // Whether the tree is in the one layout this client reads (TreeMath::TREE_VERSION). Older groups are refused,
    // not migrated.
    static bool hasSupportedTree(const server::GroupInfo& group);

    // ── Conversions from the wire types. Public so they can be tested directly. ──

    // An empty string in `leafAssignment` is a blank left by a removal — the wire format's "no member here".
    static TreeGroupState toTreeState(const server::GroupInfo& group);

    // The bridge rejects upward rungs too, but trusting it on that would trust the one party assumed hostile.
    static std::vector<ArchiveRung> toDownwardRungs(const server::GroupGetKeyArchiveResult& archive);

    // `groupPubKey` is the current epoch, `keyHistory` the past ones.
    static std::vector<EpochRegistryEntry> registryFromGroupHistory(const server::GroupInfo& group);

    // The current epoch still comes from the group, not the archive, because an epoch this client cannot
    // verify is one it refuses to accept a key for.
    static std::vector<EpochRegistryEntry> registryFromArchive(
        const server::GroupInfo& group,
        const server::GroupGetKeyArchiveResult& archive
    );

    // The archive as the group's statements vouch for it, `openers` being the statement that opened each epoch
    // (TreeVerifier::epochOpeners): each past grant key off its statement rather than the bridge's `keyHistory`, and
    // only the rungs sealed by the committer that opened the epoch they hang from, named as their author. A rung the
    // bridge sealed itself is dropped.
    static server::GroupGetKeyArchiveResult authenticated(
        server::GroupGetKeyArchiveResult archive,
        const std::map<std::uint64_t, CommitStatement>& openers
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
