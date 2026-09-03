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

    // Leaf's parent up to and including the root, bottom-up — exactly the set a removal must refresh, no less (a
    // hole in confidentiality) and no more (an unrequested epoch change). The server checks it. Empty for one leaf.
    static std::vector<std::uint32_t> directPath(std::uint32_t position, std::uint32_t numLeaves);

    // The nodes a refresh wraps to, index-aligned with `directPath`. A member never reaches a copath node; that
    // is where collusion resistance comes from.
    static std::vector<std::uint32_t> copath(std::uint32_t position, std::uint32_t numLeaves);

    // All leaf positions under a node, ascending. Used to decide whether a subtree is entirely blank.
    static std::vector<std::uint32_t> leavesUnder(std::uint32_t nodeIndex, std::uint32_t numLeaves);

    // Grows past the current count when appending at the end.
    static std::uint32_t numLeavesToSeat(std::uint32_t position, std::uint32_t currentNumLeaves);

    // Union of several leaves' direct paths, ascending — the node set a batch operation must refresh.
    //
    // Nearby leaves share ancestors, so this is strictly smaller than their paths concatenated, and that is the
    // point: a shared ancestor is refreshed ONCE. Refreshing it once per leaf would mint two keys claiming the
    // same node and generation, and whichever landed second would orphan the other's edges.
    static std::vector<std::uint32_t> frontier(
        const std::vector<std::uint32_t>& positions,
        std::uint32_t numLeaves
    );

    // Leaves needed to seat every one of `positions`. Order-independent: seating is only ever an append.
    static std::uint32_t numLeavesToSeatAll(
        const std::vector<std::uint32_t>& positions,
        std::uint32_t currentNumLeaves
    );

    // Whether the grant edge must be re-linked. Growth must not advance the epoch, so keeping the grant keypair
    // separate from the root costs one re-linked edge instead of invalidating every container.
    static bool growthChangesRoot(std::uint32_t position, std::uint32_t currentNumLeaves);

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
