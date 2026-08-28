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

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include <privmx/crypto/ecc/PrivateKey.hpp>
#include <privmx/crypto/ecc/PublicKey.hpp>

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
struct TreeEdge {
    // When true the parent is the grant keypair rather than a tree node, and the child is the tree root.
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

    // Parsed on first use and kept, so wrapping to the same node twice costs one parse.
    const privmx::crypto::PublicKey& parsed() const {
        if (!_parsed.has_value()) {
            _parsed = privmx::crypto::PublicKey::fromBase58DER(_der);
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

// Nodes are never deleted, only refreshed into a new generation.
struct TreeNodeState {
    std::uint32_t nodeIndex = 0;
    std::uint32_t generation = 0;
    NodePublicKey publicKey;
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
};

enum class ClimbFailure {
    None,
    NotAMember,    // the caller holds no leaf in this tree
    MissingEdge,   // the chain is broken: no edge leads on from a node we reached
    DecryptFailed, // an edge did not open with the key we hold
    // A recovered key does not match the published one: corrupted, substituted, or from another tree. A security
    // event, not a transient failure — never retry, it is deterministic and adversarial.
    Tampered,
};

struct ClimbResult {
    std::optional<privmx::crypto::PrivateKey> grantKey;
    ClimbFailure failure = ClimbFailure::None;
    // Deepest node reached before stopping. Partial progress is still cached and useful.
    std::uint32_t reachedNode = 0;
    // Which node failed verification, when `failure == Tampered`.
    std::optional<std::uint32_t> tamperedNode;
};

// A node refreshed by a removal: a fresh keypair plus edges to all of its existing children.
struct NodeRefresh {
    std::uint32_t nodeIndex = 0;
    std::uint32_t newGeneration = 0;
    privmx::crypto::PrivateKey newKey;
    std::vector<TreeEdge> edges;
};

// Everything a removal must submit, plus the wrap count so callers can assert the cost.
struct RemovalPlan {
    std::vector<NodeRefresh> pathRefresh;
    privmx::crypto::PrivateKey newGrantKey;
    TreeEdge grantEdge;
    std::uint32_t newEpoch = 0;
    // Tree edges + the grant edge. Excludes ladder rungs, which the ladder module builds.
    std::uint32_t wrapCount = 0;
};

// Everything an addition must submit: the new leaf's path re-keyed, `2*depth + 1` wraps.
struct AdditionPlan {
    std::uint32_t position = 0;
    std::vector<TreeEdge> edges;
    // Every node on the new leaf's path: minted where the tree grew, one generation on where it existed.
    std::vector<TreeNodeState> nodes;
    // The keys behind those nodes, to keep locally so the next climb starts from cache.
    std::vector<std::pair<std::uint32_t, privmx::crypto::PrivateKey>> nodeKeys;
    // Present only when the tree grew a level; the grant keypair is unchanged either way.
    std::optional<TreeNodeState> newRoot;
    std::optional<privmx::crypto::PrivateKey> newRootKey;
    std::uint32_t newNumLeaves = 0;
    std::uint32_t wrapCount = 0;
};

struct BuildPlan {
    std::uint32_t numLeaves = 0;
    std::vector<TreeNodeState> nodes;
    std::vector<TreeEdge> edges;
    privmx::crypto::PrivateKey grantKey;
    // Kept locally; the server only ever receives the public halves.
    std::vector<std::pair<std::uint32_t, privmx::crypto::PrivateKey>> nodeKeys;
    std::uint32_t wrapCount = 0;
};

struct TreeMember {
    std::string userId;
    privmx::crypto::PublicKey publicKey;
};

} // namespace keytree
} // namespace group
} // namespace endpoint
} // namespace privmx

#endif // _PRIVMXLIB_ENDPOINT_GROUP_KEYTREE_TREETYPES_HPP_
