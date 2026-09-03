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
#include <set>
#include <optional>
#include <string>
#include <vector>

#include "privmx/endpoint/group/keytree/TreeKeyCache.hpp"
#include "privmx/endpoint/group/keytree/TreeTypes.hpp"

namespace privmx {
namespace endpoint {
namespace group {
namespace keytree {

// Builds and traverses the hidden key tree; every wrap is an ECIES encryption of a private key, verified on
// unwrap. Minted keys must never be derived from the key they replace — a removed member would compute the next.
class TreeKeys {
public:
    explicit TreeKeys(TreeKeyCache& cache);

    // ── Traversal ───────────────────────────────────────────────────────────

    // Climbs from the caller's leaf to the grant private key (`log2(numLeaves)` unwraps, cached per node and
    // generation), verifying each against `state.nodes`. useCache=false when the node keys on the way are the point.
    ClimbResult climbToGrantKey(
        const TreeGroupState& state,
        const std::string& ownUserId,
        const privmx::crypto::PrivateKey& ownUserKey,
        bool useCache = true
    );

    // ── Construction ────────────────────────────────────────────────────────

    // Builds a complete tree for a new group, bottom-up. Costs `2(N-1) + 1` wraps, once.
    BuildPlan build(const std::vector<TreeMember>& members, const privmx::crypto::PrivateKey& signer);

    // Re-keys the new leaf's direct path and wraps each new key to both children (`2*depth + 1` wraps). The cheaper
    // one-wrap shape needs the parent's private key, which a climb only ever recovers for the caller's own seat.
    AdditionPlan planAddition(
        const TreeGroupState& state,
        const std::vector<TreeMember>& newMembers,
        const std::vector<std::uint32_t>& positions,
        const privmx::crypto::PrivateKey& signer
    );

    // Refreshes every node on the leaving member's direct path, mints a fresh grant keypair and re-links the grant
    // edge. Blank subtrees are wrapped to anyway: unopenable, but skipping them would break the chain of edges.
    RemovalPlan planRemoval(
        const TreeGroupState& state,
        const std::vector<std::string>& leavingUserIds,
        const privmx::crypto::PrivateKey& signer
    );

    // Supplies the members' long-term public keys: a removal wraps to surviving sibling leaves, whose keys are not
    // in the tree state the server serves, and skipping them would silently cut those members off.
    void setMemberKeys(const std::vector<TreeMember>& members);

    // The same keys as base58 strings, parsed only when a wrap needs one — a plan touches `log n` of them but the
    // caller hands over the whole roster. Overrides any earlier `setMemberKeys`.
    void setMemberKeyStrings(std::map<std::string, std::string> membersByUserId);

    /**
     * Seats for `count` newcomers: blanks a removal left, lowest first, then appended past the last leaf.
     *
     * The same answer `groupGet`'s `forNewMembers` gives server-side, and the client asks the server for it —
     * this exists for planning against a `TreeGroupState` already in hand, which is what the tests and the
     * state-dump tool do. Nothing on the live path calls it.
     */
    static std::vector<std::uint32_t> choosePositions(const TreeGroupState& state, std::uint32_t count);

    static std::optional<std::uint32_t> positionOf(const TreeGroupState& state, const std::string& userId);

    /**
     * Members a plan over `positions` will wrap to: the occupied leaves hanging off the refreshed frontier.
     *
     * `O(k log n)` of them, against a roster of `n`. The caller needs their public keys and the tree state does
     * not carry any, so this is what says which ones to go and find — resolving the whole roster to use fourteen
     * of it is the cost this exists to avoid. `excludedSeats` drops seats the operation is emptying: nobody wraps
     * to a departing member, and looking their key up would fail if they have already left the context.
     */
    static std::vector<std::string> membersToWrapTo(
        const TreeGroupState& state,
        const std::vector<std::uint32_t>& positions,
        std::uint32_t numLeaves,
        const std::set<std::uint32_t>& excludedSeats = {}
    );

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
    static const TreeEdge* findEdgeFromNode(
        const TreeGroupState& state,
        std::uint32_t childIndex,
        std::uint32_t childGeneration
    );
    static const TreeEdge* findEdgeFromUser(const TreeGroupState& state, const std::string& userId);
    static const TreeEdge* findGrantEdge(const TreeGroupState& state);
    static const TreeNodeState* findNode(const TreeGroupState& state, std::uint32_t nodeIndex);

    // The public key of a member's leaf, parsed on first use.
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
