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

/**
 * Array-indexed left-balanced binary tree arithmetic for the hidden key tree.
 *
 * Layout follows RFC 9420 §4.1 — this arithmetic is the only thing borrowed from MLS. For `N` leaves the tree
 * occupies node indices `0 .. 2N-2`; leaf `i` sits at index `2i`; internal nodes are at odd indices.
 *
 * The topology is a pure function of the leaf count, so no tree structure is stored anywhere.
 *
 * **This must agree with the bridge implementation exactly.** The server performs the same computation to
 * decide which nodes a removal is obliged to refresh; if the two disagree, either the server rejects valid
 * removals or — worse — accepts ones that leave a removed member holding a current node key. The reference
 * tables in the unit tests are shared with the bridge for that reason.
 *
 * **Left-balanced means the right edge may be incomplete.** With `N = 3` the root is at index 3, but index 5
 * does not exist, so node 3's right child is node 4 (found by walking down) and node 4's parent is node 3
 * (found by walking up). Callers must always use the size-aware relations, never the raw steps.
 */
class TreeMath {
public:
    /** Total number of nodes in a tree with `numLeaves` leaves. */
    static std::uint32_t nodeCount(std::uint32_t numLeaves);

    /** Node index of the leaf at the given position. */
    static std::uint32_t leafNode(std::uint32_t position);

    /** Leaf position of a leaf node index. Throws when the node is internal. */
    static std::uint32_t leafPosition(std::uint32_t nodeIndex);

    /** Leaves sit at even indices, internal nodes at odd ones. */
    static bool isLeaf(std::uint32_t nodeIndex);

    /**
     * Level of a node: the number of trailing 1-bits of its index. Leaves are level 0.
     *
     * e.g. 7 = 0b111 -> 3, 11 = 0b1011 -> 2, 13 = 0b1101 -> 1, 6 = 0b110 -> 0.
     */
    static std::uint32_t level(std::uint32_t nodeIndex);

    /** Root index for a tree with `numLeaves` leaves: `2^ceil(log2 N) - 1`. */
    static std::uint32_t root(std::uint32_t numLeaves);

    /** Depth of the tree: `ceil(log2 N)`. Also the maximum length of a direct path. */
    static std::uint32_t depth(std::uint32_t numLeaves);

    /** Whether the node exists in a tree of the given size. */
    static bool exists(std::uint32_t nodeIndex, std::uint32_t numLeaves);

    // ── Structural steps (size-unaware; building blocks, not for callers) ────

    /** Left child ignoring tree size. Always in range when the node is. */
    static std::uint32_t leftStep(std::uint32_t nodeIndex);

    /** Right child ignoring tree size. May fall outside a truncated tree. */
    static std::uint32_t rightStep(std::uint32_t nodeIndex);

    /** Parent ignoring tree size. May fall outside a truncated tree. */
    static std::uint32_t parentStep(std::uint32_t nodeIndex);

    // ── Size-aware relations (use these) ────────────────────────────────────

    /** Left child within a tree of the given size. */
    static std::uint32_t left(std::uint32_t nodeIndex, std::uint32_t numLeaves);

    /**
     * Right child within a tree of the given size.
     *
     * In a truncated tree the naive right child may not exist; the real right child is then the root of the
     * truncated right subtree, found by walking down-left. e.g. `right(3, 3) == 4`.
     */
    static std::uint32_t right(std::uint32_t nodeIndex, std::uint32_t numLeaves);

    /**
     * Parent within a tree of the given size.
     *
     * In a truncated tree the naive parent may not exist; the real parent is then found by walking further up.
     * e.g. `parent(4, 3) == 3`, because index 5 does not exist.
     *
     * @throws std::logic_error when called on the root, which has no parent
     */
    static std::uint32_t parent(std::uint32_t nodeIndex, std::uint32_t numLeaves);

    /** The other child of this node's parent. */
    static std::uint32_t sibling(std::uint32_t nodeIndex, std::uint32_t numLeaves);

    /** Existing children of a node: two for an internal node, none for a leaf. */
    static std::vector<std::uint32_t> children(std::uint32_t nodeIndex, std::uint32_t numLeaves);

    // ── Paths ───────────────────────────────────────────────────────────────

    /**
     * Nodes from the leaf's parent up to and including the root, bottom-up.
     *
     * This is **exactly** the set of nodes a removal must refresh — no less (a hole in post-removal
     * confidentiality) and no more (an unrequested epoch change). The server checks the submitted set against
     * this, so producing anything else means the removal is rejected.
     *
     * Empty for a single-leaf tree, where the leaf is itself the root.
     */
    static std::vector<std::uint32_t> directPath(std::uint32_t position, std::uint32_t numLeaves);

    /**
     * Siblings alongside the leaf's direct path — the nodes a refresh wraps to.
     *
     * A member never reaches a copath node; that is where collusion resistance comes from. Index-aligned with
     * `directPath`, so `copath[i]` is the sibling encountered when stepping to `directPath[i]`.
     */
    static std::vector<std::uint32_t> copath(std::uint32_t position, std::uint32_t numLeaves);

    /** All leaf positions under a node, ascending. Used to decide whether a subtree is entirely blank. */
    static std::vector<std::uint32_t> leavesUnder(std::uint32_t nodeIndex, std::uint32_t numLeaves);

    /** Leaf count needed to seat `position`, growing past the current count when appending at the end. */
    static std::uint32_t numLeavesToSeat(std::uint32_t position, std::uint32_t currentNumLeaves);

    /**
     * Whether seating `position` changes the root index, i.e. whether the grant edge must be re-linked.
     *
     * Growth must **not** advance the epoch: the grant keypair is deliberately separate from the tree root, so
     * a growing tree costs one re-linked edge instead of invalidating every container granted to the group.
     */
    static bool growthChangesRoot(std::uint32_t position, std::uint32_t currentNumLeaves);

private:
    /** `2^exponent`. */
    static std::uint32_t pow2(std::uint32_t exponent);

    static void assertNumLeaves(std::uint32_t numLeaves);
    static void assertLeafInTree(std::uint32_t leaf, std::uint32_t numLeaves);
};

} // namespace keytree
} // namespace group
} // namespace endpoint
} // namespace privmx

#endif // _PRIVMXLIB_ENDPOINT_GROUP_KEYTREE_TREEMATH_HPP_
