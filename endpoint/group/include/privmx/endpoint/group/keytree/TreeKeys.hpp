/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_ENDPOINT_GROUP_KEYTREE_TREEKEYS_HPP_
#define _PRIVMXLIB_ENDPOINT_GROUP_KEYTREE_TREEKEYS_HPP_

#include <cstdint>
#include <map>
#include <optional>
#include <set>
#include <string>
#include <vector>

#include "privmx/endpoint/group/keytree/TreeKeyCache.hpp"
#include "privmx/endpoint/group/keytree/TreeTypes.hpp"

namespace privmx {
namespace endpoint {
namespace group {
namespace keytree {

// Builds and traverses the hidden key tree; every wrap is an ECIES encryption of a private key, verified on
// unwrap.
//
// The invariant everything here preserves (TreeKEM's): a node's private key is known only to members whose leaves
// are in that node's subtree. So a commit mints keys for the committer's own keyed path and nothing else, always
// fresh random — never derived from the key they replace, or a removed member would compute the next one — and
// every other node a change touches is blanked rather than re-keyed. Blanks are refilled by their own members'
// self-updates. A member therefore never holds a copath key, which is what a removal relies on: blanking the
// leaver's path and refreshing the remover's leaves nothing the leaver can open.
class TreeKeys {
public:
    explicit TreeKeys(TreeKeyCache& cache);

    // ── Traversal ───────────────────────────────────────────────────────────

    // Climbs from the caller's leaf to the grant private key, verifying every recovered key against `state.nodes`
    // and the grant key against `state.grantPublicKey`; recovered node keys are cached per node and generation.
    // useCache=false when the node keys on the way are the point.
    ClimbResult climbToGrantKey(
        const TreeGroupState& state,
        const std::string& ownUserId,
        const privmx::crypto::PrivateKey& ownUserKey,
        bool useCache = true
    );

    // The resolution of a node, ascending: itself when keyed and filled, a seated leaf as itself, otherwise the
    // resolution of its children — the set an edge-holder above it has to wrap to. Leaves come back as their node
    // index (`2 * position`).
    static std::vector<std::uint32_t> resolution(const TreeGroupState& state, std::uint32_t nodeIndex);

    // ── Commit shapes: who sits where afterwards, what gets blanked, whose path is refreshed ───────────────

    // Members are seated in the order given.
    static CommitShape shapeCreate(const std::vector<std::string>& memberIds, const std::string& creatorId);

    // `positions` are index-aligned with `newMemberIds`: blanks a removal left, or appended contiguously.
    static CommitShape shapeAddition(
        const TreeGroupState& state,
        const std::vector<std::string>& newMemberIds,
        const std::vector<std::uint32_t>& positions,
        const std::string& adderId
    );

    // Refuses a remover who is among the leaving: the remover mints the next grant key.
    static CommitShape shapeRemoval(
        const TreeGroupState& state,
        const std::vector<std::string>& leavingUserIds,
        const std::string& removerId
    );

    static CommitShape shapeSelfUpdate(const TreeGroupState& state, const std::string& memberId);

    // The members a commit of this shape wraps to directly — whose long-term public keys it needs. Ascending.
    static std::vector<std::string> recipients(const TreeGroupState& state, const CommitShape& shape);

    // ── Planning: one commit each. Member keys come from `setMemberKeys*` (newcomers' from the arguments). ──

    // Epoch 1, a fresh grant key.
    CommitPlan planCreate(
        const std::vector<TreeMember>& members,
        const std::string& creatorId,
        const privmx::crypto::PrivateKey& signer
    );

    // Same epoch and grant key, which must already be in the cache (climb first).
    CommitPlan planAddition(
        const TreeGroupState& state,
        const std::vector<TreeMember>& newMembers,
        const std::vector<std::uint32_t>& positions,
        const std::string& adderId,
        const privmx::crypto::PrivateKey& signer
    );

    // Next epoch, a fresh grant key.
    CommitPlan planRemoval(
        const TreeGroupState& state,
        const std::vector<std::string>& leavingUserIds,
        const std::string& removerId,
        const privmx::crypto::PrivateKey& signer
    );

    // Same epoch and grant key, which must already be in the cache (climb first).
    CommitPlan planSelfUpdate(
        const TreeGroupState& state,
        const std::string& memberId,
        const privmx::crypto::PrivateKey& signer
    );

    // Supplies the members' long-term public keys, which are not part of the tree state.
    void setMemberKeys(const std::vector<TreeMember>& members);

    // The same keys as base58 strings, parsed only when a wrap needs one. Overrides any earlier `setMemberKeys`.
    void setMemberKeyStrings(std::map<std::string, std::string> membersByUserId);

    // Seats for `count` newcomers: blanks a removal left, lowest first, then appended past the last leaf.
    // The live path asks the server for this instead; here for planning against a state already in hand.
    static std::vector<std::uint32_t> choosePositions(const TreeGroupState& state, std::uint32_t count);

    static std::optional<std::uint32_t> positionOf(const TreeGroupState& state, const std::string& userId);

    // ── Primitives, exposed for tests and for the ladder module ─────────────

    static std::string wrapKey(
        const privmx::crypto::PrivateKey& keyToWrap,
        const privmx::crypto::PublicKey& to,
        const privmx::crypto::PrivateKey& signer
    );

    static std::optional<privmx::crypto::PrivateKey> unwrapKey(
        const std::string& blob,
        const privmx::crypto::PrivateKey& with
    );

private:
    // The single planner behind every operation (§6): blank `shape.blanked`, mint fresh keys for the committer's
    // keyed path, and wrap each of them to the resolution of its children on the resulting state.
    CommitPlan commit(
        const TreeGroupState& state,
        CommitShape shape,
        std::uint32_t epoch,
        const privmx::crypto::PrivateKey& grantKey,
        const privmx::crypto::PrivateKey& signer
    );

    // The records a commit of this shape starts from: blanked nodes lose their key, keep their generation.
    static TreeGroupState postState(const TreeGroupState& state, const CommitShape& shape);

    privmx::crypto::PrivateKey currentGrantKey(const TreeGroupState& state) const;

    static const TreeNodeState* findNode(const TreeGroupState& state, std::uint32_t nodeIndex);

    // Parsed on first use.
    std::optional<privmx::crypto::PublicKey> memberKey(const std::string& userId);

    TreeKeyCache& _cache;
    // Parsed keys: supplied whole by `setMemberKeys`, or filled in on demand from the strings below.
    std::map<std::string, privmx::crypto::PublicKey> _memberKeys;
    // Unparsed roster from `setMemberKeyStrings`, base58-DER per user id.
    std::map<std::string, std::string> _memberKeyStrings;
};

} // namespace keytree
} // namespace group
} // namespace endpoint
} // namespace privmx

#endif // _PRIVMXLIB_ENDPOINT_GROUP_KEYTREE_TREEKEYS_HPP_
