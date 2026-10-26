/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_ENDPOINT_GROUP_KEYTREE_TREETYPES_HPP_
#define _PRIVMXLIB_ENDPOINT_GROUP_KEYTREE_TREETYPES_HPP_

#include <algorithm>
#include <cstdint>
#include <map>
#include <optional>
#include <set>
#include <string>
#include <vector>

#include <privmx/crypto/ecc/PrivateKey.hpp>
#include <privmx/crypto/ecc/PublicKey.hpp>
#include <privmx/crypto/ecc/PublicKeyCache.hpp>

namespace privmx {
namespace endpoint {
namespace group {
namespace keytree {

enum class EdgeChildKind {
    Node, // an internal node's public key at a given generation
    User, // a leaf, i.e. a member's long-term public key
};

// One edge of the tree: `wrap(sk_parent -> pk_child)`. Encrypted to the child and carrying the parent's private
// key, so members travel strictly upward — that asymmetry is where collusion resistance comes from.
//
// The parent is the child's lowest FILLED keyed ancestor, not necessarily its structural parent: buckets carry no
// key and blank nodes have none to give, so an edge skips over them. Every member and every filled node has exactly
// one incoming edge besides the grant edge.
struct TreeEdge {
    // When true the parent is the grant keypair rather than a tree node, and the child is the tree root (or the
    // sole member of a one-leaf tree).
    bool isGrantEdge = false;
    // Meaningless when `isGrantEdge`.
    std::uint32_t parentIndex = 0;
    // Generation of the parent key carried inside the blob; the epoch when `isGrantEdge`.
    std::uint32_t parentGeneration = 0;

    EdgeChildKind childKind = EdgeChildKind::Node;
    std::uint32_t childIndex = 0;      // for EdgeChildKind::Node
    std::uint32_t childGeneration = 0; // for EdgeChildKind::Node
    std::string childUserId;           // for EdgeChildKind::User

    // ECIES ciphertext, base64. Opaque to the server.
    std::string blob;
};

// A node's public key kept as served, turned into a point only where one is needed: parsing runs the subgroup
// check at ~0.19 ms a key, while a climb touches `log n` of them. Compare and re-serialise on the base58 form.
class NodePublicKey {
public:
    NodePublicKey() = default;
    // From a key this process already holds — a minted one.
    NodePublicKey(const privmx::crypto::PublicKey& key) : _parsed(key), _der(key.toBase58DER()) {}

    static NodePublicKey fromBase58DER(std::string der) {
        NodePublicKey result;
        result._der = std::move(der);
        return result;
    }

    // Parsed on first use and kept, so wrapping to the same node twice costs one parse. The cache behind it
    // carries that across the short-lived `TreeGroupState` objects a resolve rebuilds every time.
    const privmx::crypto::PublicKey& parsed() const {
        if (!_parsed.has_value()) {
            _parsed = privmx::crypto::PublicKeyCache::getInstance()->fromBase58DER(_der);
        }
        return _parsed.value();
    }

    const std::string& toBase58DER() const { return _der; }

    bool operator==(const privmx::crypto::PublicKey& other) const { return _der == other.toBase58DER(); }
    bool operator!=(const privmx::crypto::PublicKey& other) const { return !(*this == other); }
    bool operator==(const NodePublicKey& other) const { return _der == other._der; }
    bool operator!=(const NodePublicKey& other) const { return _der != other._der; }

private:
    mutable std::optional<privmx::crypto::PublicKey> _parsed;
    std::string _der;
};

// A keyed node's record. Blanking drops the key and keeps the generation, so the next fill is one generation on and
// the bridge can tell an advanced node from a minted one. A keyed node with no record at all is blank too.
struct TreeNodeState {
    std::uint32_t nodeIndex = 0;
    std::uint32_t generation = 0;
    // Absent on a blank node.
    std::optional<NodePublicKey> publicKey;
    // On a filled node: `seq` of the commit statement that set this key, the one that vouches for it.
    std::optional<std::uint64_t> setBy;
};

// The group state a client needs to work with the tree, as served. Topology is not stored — it follows from
// `numLeaves` through the arithmetic in TreeMath.
struct TreeGroupState {
    std::uint32_t numLeaves = 0;
    // Position -> member; empty optional is a blank left by a removal.
    std::vector<std::optional<std::string>> leafAssignment;
    std::vector<TreeNodeState> nodes;
    std::vector<TreeEdge> edges;

    // Current epoch and its public grant key — what containers wrap to.
    std::uint32_t epoch = 0;
    privmx::crypto::PublicKey grantPublicKey;
    // `seq` of the latest commit statement; the next commit is this plus one.
    std::uint64_t commitSeq = 0;
    // `seq` -> committer of the statements the filled nodes cite (`setBy`): who minted each key, which a removal
    // needs to blank everything the leaver could know.
    std::map<std::uint64_t, std::string> setters;
};

enum class ClimbFailure {
    None,
    NotAMember,    // the caller holds no leaf in this tree
    MissingEdge,   // the chain is broken: no edge leads on from a node we reached
    DecryptFailed, // an edge did not open with the key we hold
    // The first edge above our own leaf does not open with the key we hold: our identity key changed since it was
    // wrapped, or its wrapper garbled it. `tamperedNode` as for `DecryptFailed` (unset in a one-leaf tree).
    LeafDidNotOpen,
    // A recovered key does not match the published one: corrupted, substituted, or from another tree. A security
    // event, not a transient failure — never retry, it is deterministic and adversarial.
    Tampered,
};

struct ClimbResult {
    std::optional<privmx::crypto::PrivateKey> grantKey;
    ClimbFailure failure = ClimbFailure::None;
    // Deepest node reached before stopping. Partial progress is still cached and useful.
    std::uint32_t reachedNode = 0;
    // The node whose edge failed, when `failure` is `Tampered`, `DecryptFailed` or `LeafDidNotOpen`; none for the grant
    // edge.
    std::optional<std::uint32_t> tamperedNode;
};

// What one commit changes, before any key exists: who sits where afterwards, which nodes it blanks and which it
// mints. Every operation — create, add, remove, self-update — is one of these.
struct CommitShape {
    std::uint32_t numLeaves = 0;
    std::vector<std::optional<std::string>> leafAssignment;
    // Keyed nodes a removal blanks: everything the leavers could know (their paths, every node they set, and every
    // ancestor of those), minus the committer's own path, which it re-keys.
    std::set<std::uint32_t> blanked;
    // Keyed nodes minted besides the committer's path: every other keyed node at creation, the newcomers' paths
    // below the adder's on an addition.
    std::set<std::uint32_t> filledOffPath;
    std::uint32_t committerSeat = 0;
    // Seats added (index-aligned with the newcomers) or emptied (ascending); empty for create and self-update.
    std::vector<std::uint32_t> subjectSeats;
};

// One node the commit mints, with its fresh key.
struct RefreshedNode {
    std::uint32_t nodeIndex = 0;
    // The generation the node was read at; absent when it had no record.
    std::optional<std::uint32_t> fromGeneration;
    std::uint32_t generation = 0;
    privmx::crypto::PrivateKey key;
};

struct CommitPlan {
    CommitShape shape;
    // `shape.filledOffPath` ascending, then the committer's keyed path bottom-up, root last.
    std::vector<RefreshedNode> refreshed;
    // Every edge the refreshed nodes owe on the post state, then the grant edge.
    std::vector<TreeEdge> edges;
    // The grant edge's epoch and the key it carries: new on a removal or create, the current one otherwise.
    std::uint32_t epoch = 0;
    privmx::crypto::PrivateKey grantKey;
    // The statement this commit is signed as, and the hash of the tree it leaves behind (refreshed nodes carry
    // `setBy = seq`). Raw bytes.
    std::uint64_t seq = 0;
    std::string treeHash;
    // `CH` of every inner node of the post state, by index: what each statement path entry signs.
    std::map<std::uint32_t, std::string> subtreeHashes;
};

struct TreeMember {
    std::string userId;
    privmx::crypto::PublicKey publicKey;
};

// `generations[node]` raised to `generation` if that is higher; whether it rose.
inline bool raiseGeneration(
    std::map<std::uint32_t, std::uint32_t>& generations,
    std::uint32_t node,
    std::uint32_t generation
) {
    std::uint32_t& value = generations[node];
    const bool rose = generation > value;
    value = std::max(value, generation);
    return rose;
}

// The record of `nodeIndex`, or null when it has none.
template<typename State>
auto* findRecord(State& state, std::uint32_t nodeIndex) {
    const auto it = std::find_if(state.nodes.begin(), state.nodes.end(), [&](const TreeNodeState& node) {
        return node.nodeIndex == nodeIndex;
    });
    return it == state.nodes.end() ? nullptr : &*it;
}

} // namespace keytree
} // namespace group
} // namespace endpoint
} // namespace privmx

#endif // _PRIVMXLIB_ENDPOINT_GROUP_KEYTREE_TREETYPES_HPP_
