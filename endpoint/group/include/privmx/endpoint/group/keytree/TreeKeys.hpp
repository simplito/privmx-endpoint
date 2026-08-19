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
#include <string>
#include <vector>

#include "privmx/endpoint/group/keytree/TreeKeyCache.hpp"
#include "privmx/endpoint/group/keytree/TreeTypes.hpp"

namespace privmx {
namespace endpoint {
namespace group {
namespace keytree {

/**
 * Building and traversing the hidden key tree with real EC keys.
 *
 * Every wrap is an ECIES encryption of a private key (as WIF) to the recipient's public key, signed by the
 * author. Every unwrap verifies the recovered key against the public key the server published for that node —
 * the tree's analogue of the ladder's registry check, and the reason a corrupted edge is detectable rather than
 * silently wrong.
 *
 * All keys minted here come from `PrivateKey::generateRandom()`. **They must never be derived from the key they
 * replace**: a removed member holds the previous key and would compute the next one, which defeats the whole
 * construction. The server cannot detect this, so it is guarded by review and by an explicit negative test.
 */
class TreeKeys {
public:
    explicit TreeKeys(TreeKeyCache& cache);

    // ── Traversal ───────────────────────────────────────────────────────────

    /**
     * Climbs from the caller's leaf to the group's grant private key, caching every node key on the way.
     *
     * Cost is `log2(numLeaves)` ECIES decryptions, amortised to near zero across repeated reads because the
     * intermediate keys are cached per `(node, generation)`.
     *
     * Verifies each recovered node key against `state.nodes`; a mismatch stops the climb with
     * `ClimbFailure::Tampered` and the offending node, and must not be retried.
     */
    /**
     * @param useCache when true (the default) a grant key already in the store short-circuits the whole walk.
     *
     * Pass **false** when the node keys along the way are what you are after — planning an addition or a
     * removal needs them, and a cached grant key would otherwise hand back the answer without ever recovering
     * them. Reading content only needs the grant key, so there the cache is exactly right.
     */
    ClimbResult climbToGrantKey(
        const TreeGroupState& state,
        const std::string& ownUserId,
        const privmx::crypto::PrivateKey& ownUserKey,
        bool useCache = true
    );

    // ── Construction ────────────────────────────────────────────────────────

    /**
     * Builds a complete tree for a new group, bottom-up. Costs `2(N-1) + 1` wraps, once.
     *
     * @param signer key used to sign every wrap, for attribution
     */
    BuildPlan build(const std::vector<TreeMember>& members, const privmx::crypto::PrivateKey& signer);

    /**
     * Prepares an addition. **One wrap** in the common case: the new member's leaf parent key wrapped to them.
     *
     * From there the new member climbs on edges that already exist. Nothing rotates, the epoch does not advance,
     * and no container is touched — nobody loses access. When the tree grows a level the new root is minted and
     * the grant edge re-linked, but `grantPublicKey` stays the same, so containers never notice.
     */
    AdditionPlan planAddition(
        const TreeGroupState& state,
        const TreeMember& newMember,
        const privmx::crypto::PrivateKey& signer
    );

    /**
     * Prepares a removal: refreshes every node on the leaving member's direct path, mints a fresh grant keypair
     * and re-links the grant edge.
     *
     * Costs `2*depth - 1` tree wraps plus the grant edge. Each refreshed node wraps to all of its existing
     * children — the on-path child at its **new** generation, the copath child at its **current** one — and the
     * blanked leaf is skipped.
     *
     * Blank subtrees are wrapped to anyway, deliberately: nobody holds their current keys (their nodes were
     * refreshed by the removals that emptied them), so the ciphertext is unopenable and harmless, while skipping
     * would break the chain and make a later addition repair edges.
     *
     * @throws std::invalid_argument when the member holds no leaf
     */
    RemovalPlan planRemoval(
        const TreeGroupState& state,
        const std::string& leavingUserId,
        const privmx::crypto::PrivateKey& signer
    );

    /**
     * Supplies the members' long-term public keys.
     *
     * A removal wraps the refreshed node keys to the surviving sibling leaves, and those leaves are members
     * whose public keys are not part of the tree state the server serves. Without this the removal would have
     * to skip them — silently cutting them off, which is exactly the ghosting the design forbids.
     */
    void setMemberKeys(const std::vector<TreeMember>& members);

    /** Chooses a position for a new member: lowest blank leaf, else append. Never moves anyone. */
    static std::uint32_t choosePosition(const TreeGroupState& state);

    /** Leaf position of a member, or empty when they hold none. */
    static std::optional<std::uint32_t> positionOf(const TreeGroupState& state, const std::string& userId);

    // ── Primitives, exposed for tests and for the ladder module ─────────────

    /** ECIES-encrypts a private key to a public key, signing with `signer`. */
    static std::string wrapKey(
        const privmx::crypto::PrivateKey& keyToWrap,
        const privmx::crypto::PublicKey& to,
        const privmx::crypto::PrivateKey& signer
    );

    /** Reverses `wrapKey`. Returns empty optional when the blob does not open or is malformed. */
    static std::optional<privmx::crypto::PrivateKey> unwrapKey(
        const std::string& blob,
        const privmx::crypto::PrivateKey& with
    );

private:
    /** Finds the edge leading up from a node, at the given generation. */
    static const TreeEdge* findEdgeFromNode(
        const TreeGroupState& state,
        std::uint32_t childIndex,
        std::uint32_t childGeneration
    );
    /** Finds the edge leading up from a member's leaf. */
    static const TreeEdge* findEdgeFromUser(const TreeGroupState& state, const std::string& userId);
    static const TreeEdge* findGrantEdge(const TreeGroupState& state);
    static const TreeNodeState* findNode(const TreeGroupState& state, std::uint32_t nodeIndex);

    TreeKeyCache& _cache;
    /** Member public keys supplied by `setMemberKeys`, needed to wrap to surviving sibling leaves. */
    std::map<std::string, privmx::crypto::PublicKey> _memberKeys;
};

} // namespace keytree
} // namespace group
} // namespace endpoint
} // namespace privmx

#endif // _PRIVMXLIB_ENDPOINT_GROUP_KEYTREE_TREEKEYS_HPP_
