/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_ENDPOINT_GROUP_KEYTREE_TREEMATH_HPP_
#define _PRIVMXLIB_ENDPOINT_GROUP_KEYTREE_TREEMATH_HPP_

#include <cstdint>
#include <vector>

namespace privmx {
namespace endpoint {
namespace group {
namespace keytree {

// Array-indexed left-balanced binary tree arithmetic, laid out per RFC 9420 §4.1: leaf `i` at index `2i`, internal
// nodes odd, topology a pure function of the leaf count. Must agree with the bridge's own computation exactly.
class TreeMath {
public:
    // The tree layout and statement format this client reads and writes. A group carrying any other version is
    // refused, never migrated. 3: rung blobs bound to their span, the genesis roster served beside the chain, custom
    // events bound to their channel, no confirmation tag.
    static constexpr std::uint32_t TREE_VERSION = 3;

    // Internal nodes at or below this level carry no key: a bucket of `2^BUCKET_LEVEL` seats is wrapped to leaf by
    // leaf. Tied to TREE_VERSION, not configurable per group — the bridge derives the same keyed set.
    static constexpr std::uint32_t BUCKET_LEVEL = 4;

    static std::uint32_t nodeCount(std::uint32_t numLeaves);

    static std::uint32_t leafNode(std::uint32_t position);

    // Throws when the node is internal.
    static std::uint32_t leafPosition(std::uint32_t nodeIndex);

    // Leaves sit at even indices, internal nodes at odd ones.
    static bool isLeaf(std::uint32_t nodeIndex);

    // Trailing 1-bits of the index; leaves are level 0. e.g. 7 = 0b111 -> 3, 13 = 0b1101 -> 1, 6 = 0b110 -> 0.
    static std::uint32_t level(std::uint32_t nodeIndex);

    // `2^ceil(log2 N) - 1`.
    static std::uint32_t root(std::uint32_t numLeaves);

    // `ceil(log2 N)`. Also the maximum length of a direct path.
    static std::uint32_t depth(std::uint32_t numLeaves);

    static bool exists(std::uint32_t nodeIndex, std::uint32_t numLeaves);

    // ── Structural steps (size-unaware; building blocks, not for callers) ────

    // Always in range when the node is.
    static std::uint32_t leftStep(std::uint32_t nodeIndex);

    // May fall outside a truncated tree.
    static std::uint32_t rightStep(std::uint32_t nodeIndex);

    // May fall outside a truncated tree.
    static std::uint32_t parentStep(std::uint32_t nodeIndex);

    // ── Size-aware relations (use these) ────────────────────────────────────

    static std::uint32_t left(std::uint32_t nodeIndex, std::uint32_t numLeaves);

    // In a truncated tree the real right child is the root of the truncated right subtree: `right(3, 3) == 4`.
    static std::uint32_t right(std::uint32_t nodeIndex, std::uint32_t numLeaves);

    // In a truncated tree the real parent is found by walking further up: `parent(4, 3) == 3`, 5 not existing.
    // Throws on the root.
    static std::uint32_t parent(std::uint32_t nodeIndex, std::uint32_t numLeaves);

    static std::uint32_t sibling(std::uint32_t nodeIndex, std::uint32_t numLeaves);

    static std::vector<std::uint32_t> children(std::uint32_t nodeIndex, std::uint32_t numLeaves);

    // ── Paths ───────────────────────────────────────────────────────────────

    // Leaf's parent up to and including the root, bottom-up. Empty for one leaf.
    static std::vector<std::uint32_t> directPath(std::uint32_t position, std::uint32_t numLeaves);

    // Index-aligned with `directPath`.
    static std::vector<std::uint32_t> copath(std::uint32_t position, std::uint32_t numLeaves);

    // Ascending.
    static std::vector<std::uint32_t> leavesUnder(std::uint32_t nodeIndex, std::uint32_t numLeaves);

    // Whether the node may carry a key at all: internal, and above the buckets or the root. Leaves never are — a
    // leaf is its member's long-term key.
    static bool isKeyed(std::uint32_t nodeIndex, std::uint32_t numLeaves);

    // `directPath` filtered by `isKeyed`, bottom-up: the nodes every commit by this seat refreshes (a creation and
    // an addition also fill nodes off it). Ends at the root; empty for one leaf.
    static std::vector<std::uint32_t> keyedPath(std::uint32_t position, std::uint32_t numLeaves);

    // Every keyed node of the tree, ascending.
    static std::vector<std::uint32_t> keyedNodes(std::uint32_t numLeaves);

    // Grows past the current count when appending at the end.
    static std::uint32_t numLeavesToSeat(std::uint32_t position, std::uint32_t currentNumLeaves);

    // Order-independent: seating is only ever an append.
    static std::uint32_t numLeavesToSeatAll(
        const std::vector<std::uint32_t>& positions,
        std::uint32_t currentNumLeaves
    );

private:
    static std::uint32_t pow2(std::uint32_t exponent);

    static void assertNumLeaves(std::uint32_t numLeaves);
    static void assertLeafInTree(std::uint32_t leaf, std::uint32_t numLeaves);
};

} // namespace keytree
} // namespace group
} // namespace endpoint
} // namespace privmx

#endif // _PRIVMXLIB_ENDPOINT_GROUP_KEYTREE_TREEMATH_HPP_
