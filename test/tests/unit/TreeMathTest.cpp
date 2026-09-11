/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

/** Unit tests for the hidden key tree arithmetic; needs no server, no docker and no network — pure arithmetic. Reference tables are the same ones used by the bridge's TreeMath tests, deliberately: the two implementations must agree exactly, or the server will either reject valid removals or accept ones that leave a removed member holding a current node key. The truncated cases (leaf count not a power of two) are what break naive implementations, so they carry the most coverage. */

#include <gtest/gtest.h>

#include <algorithm>
#include <cstdint>
#include <set>
#include <vector>

#include <privmx/endpoint/group/keytree/TreeMath.hpp>

using privmx::endpoint::group::keytree::TreeMath;
using Nodes = std::vector<std::uint32_t>;

// level

class TreeMathLevel : public testing::Test {};

TEST_F(TreeMathLevel, MatchesReferenceTableForEightLeaves) {
    // level(x) = number of trailing 1-bits. Table for the N=8 tree from the spec.
    const std::vector<std::pair<std::uint32_t, std::uint32_t>> table = {
        {0, 0}, {1, 1}, {2, 0},  {3, 2},  {4, 0},  {5, 1},  {6, 0},  {7, 3},
        {8, 0}, {9, 1}, {10, 0}, {11, 2}, {12, 0}, {13, 1}, {14, 0},
    };
    for (const auto& [node, expected] : table) {
        EXPECT_EQ(TreeMath::level(node), expected) << "level(" << node << ")";
    }
}

TEST_F(TreeMathLevel, LeavesAreAlwaysLevelZero) {
    for (std::uint32_t position = 0; position < 64; ++position) {
        EXPECT_EQ(TreeMath::level(TreeMath::leafNode(position)), 0u) << "position " << position;
    }
}

// leaf indexing

class TreeMathLeaves : public testing::Test {};

TEST_F(TreeMathLeaves, LeafSitsAtTwiceItsPositionAndRoundTrips) {
    for (std::uint32_t position = 0; position < 32; ++position) {
        const std::uint32_t node = TreeMath::leafNode(position);
        EXPECT_EQ(node, 2 * position);
        EXPECT_TRUE(TreeMath::isLeaf(node));
        EXPECT_EQ(TreeMath::leafPosition(node), position);
    }
}

TEST_F(TreeMathLeaves, OddIndicesAreInternal) {
    for (const std::uint32_t node : {1u, 3u, 5u, 7u, 9u, 11u, 13u}) {
        EXPECT_FALSE(TreeMath::isLeaf(node)) << "node " << node;
    }
}

TEST_F(TreeMathLeaves, LeafPositionRejectsInternalNode) {
    EXPECT_THROW(TreeMath::leafPosition(3), std::invalid_argument);
}

// root / depth / nodeCount

class TreeMathShape : public testing::Test {};

TEST_F(TreeMathShape, MatchesReferenceTable) {
    struct Row {
        std::uint32_t numLeaves;
        std::uint32_t root;
        std::uint32_t depth;
        std::uint32_t nodeCount;
    };
    const std::vector<Row> table = {
        {1, 0, 0, 1},  {2, 1, 1, 3},  {3, 3, 2, 5},  {4, 3, 2, 7},   {5, 7, 3, 9},
        {6, 7, 3, 11}, {7, 7, 3, 13}, {8, 7, 3, 15}, {9, 15, 4, 17}, {1000, 1023, 10, 1999},
    };
    for (const auto& row : table) {
        EXPECT_EQ(TreeMath::root(row.numLeaves), row.root) << "N=" << row.numLeaves;
        EXPECT_EQ(TreeMath::depth(row.numLeaves), row.depth) << "N=" << row.numLeaves;
        EXPECT_EQ(TreeMath::nodeCount(row.numLeaves), row.nodeCount) << "N=" << row.numLeaves;
    }
}

TEST_F(TreeMathShape, RejectsZeroLeaves) {
    EXPECT_THROW(TreeMath::root(0), std::invalid_argument);
    EXPECT_THROW(TreeMath::depth(0), std::invalid_argument);
    EXPECT_THROW(TreeMath::nodeCount(0), std::invalid_argument);
}

// parent — complete and truncated

class TreeMathParent : public testing::Test {};

TEST_F(TreeMathParent, CompleteTreeOfFour) {
    // N=4: leaves 0,2,4,6; node 1 = parent(0,2); node 5 = parent(4,6); node 3 = root.
    const std::vector<std::pair<std::uint32_t, std::uint32_t>> table = {
        {0, 1}, {2, 1}, {1, 3}, {5, 3}, {4, 5}, {6, 5},
    };
    for (const auto& [node, expected] : table) {
        EXPECT_EQ(TreeMath::parent(node, 4), expected) << "parent(" << node << ", N=4)";
    }
}

TEST_F(TreeMathParent, RootHasNoParent) {
    EXPECT_THROW(TreeMath::parent(3, 4), std::logic_error);
    EXPECT_THROW(TreeMath::parent(0, 1), std::logic_error);
}

TEST_F(TreeMathParent, WalksPastNonExistentParentWhenRightEdgeIsTruncated) {
    // N=3: nodes 0..4, root=3. Node 5 does not exist, so node 4's naive parent must be walked past; this is the case that breaks implementations using the bare formula.
    EXPECT_EQ(TreeMath::parentStep(4), 5u) << "naive parent is out of range";
    EXPECT_FALSE(TreeMath::exists(5, 3));
    EXPECT_EQ(TreeMath::parent(4, 3), 3u);
}

TEST_F(TreeMathParent, LoneLeafAttachesDirectlyToRoot) {
    // N=5: nodes 0..8, root=7. Leaf 4 sits at node 8 whose ancestors 9, 11 are absent.
    EXPECT_FALSE(TreeMath::exists(9, 5));
    EXPECT_EQ(TreeMath::parent(8, 5), 7u);
}

TEST_F(TreeMathParent, SixLeavesFormAFullRightSubtree) {
    EXPECT_EQ(TreeMath::parent(8, 6), 9u);
    EXPECT_EQ(TreeMath::parent(10, 6), 9u);
    EXPECT_EQ(TreeMath::parent(9, 6), 7u);
}

TEST_F(TreeMathParent, EveryNonRootNodeHasAnExistingParent) {
    for (std::uint32_t numLeaves = 2; numLeaves <= 40; ++numLeaves) {
        const std::uint32_t rootIndex = TreeMath::root(numLeaves);
        for (std::uint32_t node = 0; node < TreeMath::nodeCount(numLeaves); ++node) {
            if (node == rootIndex) {
                continue;
            }
            const std::uint32_t p = TreeMath::parent(node, numLeaves);
            EXPECT_TRUE(TreeMath::exists(p, numLeaves)) << "parent(" << node << ", " << numLeaves << ")=" << p;
            EXPECT_NE(p, node);
        }
    }
}

// right / children — truncated

class TreeMathChildren : public testing::Test {};

TEST_F(TreeMathChildren, WalksDownToTruncatedRightSubtree) {
    EXPECT_EQ(TreeMath::rightStep(3), 5u) << "naive right child is out of range";
    EXPECT_EQ(TreeMath::right(3, 3), 4u);
    EXPECT_EQ(TreeMath::left(3, 3), 1u);
}

TEST_F(TreeMathChildren, RootsRightChildIsTheLoneLeaf) {
    EXPECT_EQ(TreeMath::right(7, 5), 8u);
}

TEST_F(TreeMathChildren, AreMutualWithParent) {
    for (std::uint32_t numLeaves = 2; numLeaves <= 40; ++numLeaves) {
        for (std::uint32_t node = 1; node < TreeMath::nodeCount(numLeaves); node += 2) {
            for (const std::uint32_t child : TreeMath::children(node, numLeaves)) {
                EXPECT_EQ(TreeMath::parent(child, numLeaves), node)
                    << "child " << child << " of " << node << " N=" << numLeaves;
            }
        }
    }
}

TEST_F(TreeMathChildren, LeavesHaveNone) {
    EXPECT_TRUE(TreeMath::children(0, 4).empty());
    EXPECT_THROW(TreeMath::leftStep(0), std::invalid_argument);
    EXPECT_THROW(TreeMath::rightStep(2), std::invalid_argument);
}

// sibling

class TreeMathSibling : public testing::Test {};

TEST_F(TreeMathSibling, CompleteTreeOfFour) {
    const std::vector<std::pair<std::uint32_t, std::uint32_t>> table = {
        {0, 2}, {2, 0}, {1, 5}, {5, 1}, {4, 6}, {6, 4},
    };
    for (const auto& [node, expected] : table) {
        EXPECT_EQ(TreeMath::sibling(node, 4), expected) << "sibling(" << node << ", N=4)";
    }
}

TEST_F(TreeMathSibling, TruncatedSiblingIsTheWholeSubtree) {
    EXPECT_EQ(TreeMath::sibling(4, 3), 1u);
    EXPECT_EQ(TreeMath::sibling(1, 3), 4u);
}

TEST_F(TreeMathSibling, IsSymmetric) {
    for (std::uint32_t numLeaves = 2; numLeaves <= 40; ++numLeaves) {
        const std::uint32_t rootIndex = TreeMath::root(numLeaves);
        for (std::uint32_t node = 0; node < TreeMath::nodeCount(numLeaves); ++node) {
            if (node == rootIndex) {
                continue;
            }
            const std::uint32_t s = TreeMath::sibling(node, numLeaves);
            EXPECT_EQ(TreeMath::sibling(s, numLeaves), node) << "N=" << numLeaves << " node=" << node;
        }
    }
}

// directPath — the set a removal must refresh

class TreeMathDirectPath : public testing::Test {};

TEST_F(TreeMathDirectPath, MatchesSpecTableForEightLeaves) {
    EXPECT_EQ(TreeMath::directPath(0, 8), Nodes({1, 3, 7}));
}

TEST_F(TreeMathDirectPath, MatchesReferenceTable) {
    EXPECT_EQ(TreeMath::directPath(0, 4), Nodes({1, 3}));
    EXPECT_EQ(TreeMath::directPath(1, 4), Nodes({1, 3}));
    EXPECT_EQ(TreeMath::directPath(2, 4), Nodes({5, 3}));
    EXPECT_EQ(TreeMath::directPath(3, 4), Nodes({5, 3}));
    EXPECT_EQ(TreeMath::directPath(7, 8), Nodes({13, 11, 7}));
    EXPECT_EQ(TreeMath::directPath(0, 2), Nodes({1}));
}

TEST_F(TreeMathDirectPath, IsEmptyForSingleLeafTree) {
    EXPECT_TRUE(TreeMath::directPath(0, 1).empty());
}

TEST_F(TreeMathDirectPath, TruncatedTreeGivesUnequalPathLengths) {
    // N=3: leaf 0 climbs two levels, leaf 2 only one. Left-balanced asymmetry, expected.
    EXPECT_EQ(TreeMath::directPath(0, 3), Nodes({1, 3}));
    EXPECT_EQ(TreeMath::directPath(1, 3), Nodes({1, 3}));
    EXPECT_EQ(TreeMath::directPath(2, 3), Nodes({3}));
}

TEST_F(TreeMathDirectPath, AlwaysEndsAtRootAndNeverExceedsDepth) {
    for (std::uint32_t numLeaves = 1; numLeaves <= 64; ++numLeaves) {
        const std::uint32_t rootIndex = TreeMath::root(numLeaves);
        for (std::uint32_t position = 0; position < numLeaves; ++position) {
            const Nodes path = TreeMath::directPath(position, numLeaves);
            if (numLeaves > 1) {
                ASSERT_FALSE(path.empty()) << "N=" << numLeaves << " pos=" << position;
                EXPECT_EQ(path.back(), rootIndex) << "N=" << numLeaves << " pos=" << position;
            }
            EXPECT_LE(path.size(), TreeMath::depth(numLeaves)) << "N=" << numLeaves << " pos=" << position;
            EXPECT_EQ(std::set<std::uint32_t>(path.begin(), path.end()).size(), path.size()) << "no repeats";
        }
    }
}

TEST_F(TreeMathDirectPath, ContainsOnlyInternalNodes) {
    for (std::uint32_t numLeaves = 2; numLeaves <= 40; ++numLeaves) {
        for (std::uint32_t position = 0; position < numLeaves; ++position) {
            for (const std::uint32_t node : TreeMath::directPath(position, numLeaves)) {
                EXPECT_FALSE(TreeMath::isLeaf(node)) << "N=" << numLeaves << " node=" << node;
            }
        }
    }
}

TEST_F(TreeMathDirectPath, RejectsPositionOutsideTree) {
    EXPECT_THROW(TreeMath::directPath(4, 4), std::invalid_argument);
}

// copath — the set a refresh wraps to

class TreeMathCopath : public testing::Test {};

TEST_F(TreeMathCopath, MatchesSpecTableForEightLeaves) {
    EXPECT_EQ(TreeMath::copath(0, 8), Nodes({2, 5, 11}));
}

TEST_F(TreeMathCopath, IsIndexAlignedWithDirectPath) {
    for (std::uint32_t numLeaves = 2; numLeaves <= 40; ++numLeaves) {
        for (std::uint32_t position = 0; position < numLeaves; ++position) {
            const Nodes path = TreeMath::directPath(position, numLeaves);
            const Nodes co = TreeMath::copath(position, numLeaves);
            ASSERT_EQ(co.size(), path.size()) << "N=" << numLeaves << " pos=" << position;
            std::uint32_t current = TreeMath::leafNode(position);
            for (std::size_t i = 0; i < path.size(); ++i) {
                Nodes kids = TreeMath::children(path[i], numLeaves);
                Nodes pair = {current, co[i]};
                std::sort(kids.begin(), kids.end());
                std::sort(pair.begin(), pair.end());
                EXPECT_EQ(pair, kids) << "N=" << numLeaves << " pos=" << position << " level=" << i;
                current = path[i];
            }
        }
    }
}

TEST_F(TreeMathCopath, NeverContainsANodeOnTheDirectPath) {
    for (std::uint32_t numLeaves = 2; numLeaves <= 40; ++numLeaves) {
        for (std::uint32_t position = 0; position < numLeaves; ++position) {
            const Nodes path = TreeMath::directPath(position, numLeaves);
            const std::set<std::uint32_t> onPath(path.begin(), path.end());
            for (const std::uint32_t node : TreeMath::copath(position, numLeaves)) {
                EXPECT_EQ(onPath.count(node), 0u) << "N=" << numLeaves << " node=" << node;
            }
        }
    }
}

TEST_F(TreeMathCopath, NeverContainsOwnLeaf) {
    for (std::uint32_t numLeaves = 2; numLeaves <= 40; ++numLeaves) {
        for (std::uint32_t position = 0; position < numLeaves; ++position) {
            const std::uint32_t own = TreeMath::leafNode(position);
            const Nodes co = TreeMath::copath(position, numLeaves);
            EXPECT_EQ(std::count(co.begin(), co.end(), own), 0) << "N=" << numLeaves << " pos=" << position;
        }
    }
}

// leavesUnder

class TreeMathLeavesUnder : public testing::Test {};

TEST_F(TreeMathLeavesUnder, RootCoversEveryLeaf) {
    for (std::uint32_t numLeaves = 1; numLeaves <= 40; ++numLeaves) {
        Nodes expected;
        for (std::uint32_t i = 0; i < numLeaves; ++i) {
            expected.push_back(i);
        }
        EXPECT_EQ(TreeMath::leavesUnder(TreeMath::root(numLeaves), numLeaves), expected) << "N=" << numLeaves;
    }
}

TEST_F(TreeMathLeavesUnder, ALeafCoversOnlyItself) {
    EXPECT_EQ(TreeMath::leavesUnder(4, 4), Nodes({2}));
}

TEST_F(TreeMathLeavesUnder, ChildrenPartitionTheirParent) {
    for (std::uint32_t numLeaves = 2; numLeaves <= 40; ++numLeaves) {
        for (std::uint32_t node = 1; node < TreeMath::nodeCount(numLeaves); node += 2) {
            const Nodes kids = TreeMath::children(node, numLeaves);
            Nodes joined = TreeMath::leavesUnder(kids[0], numLeaves);
            const Nodes rightLeaves = TreeMath::leavesUnder(kids[1], numLeaves);
            joined.insert(joined.end(), rightLeaves.begin(), rightLeaves.end());
            EXPECT_EQ(TreeMath::leavesUnder(node, numLeaves), joined) << "N=" << numLeaves << " node=" << node;
        }
    }
}

// cost properties claimed by the whitepaper

class TreeMathCost : public testing::Test {};

TEST_F(TreeMathCost, BalancedRemovalCostsTwoTimesDepthMinusOneWraps) {
    // A removal refreshes directPath and wraps to two children per node, minus the blanked leaf.
    const std::vector<std::pair<std::uint32_t, std::uint32_t>> table = {
        {8, 5},
        {16, 7},
        {1024, 19},
        {32768, 29},
    };
    for (const auto& [numLeaves, expectedWraps] : table) {
        const Nodes path = TreeMath::directPath(0, numLeaves);
        EXPECT_EQ(path.size(), TreeMath::depth(numLeaves)) << "N=" << numLeaves;
        std::uint32_t wraps = 0;
        for (std::size_t i = 0; i < path.size(); ++i) {
            const std::uint32_t kids = static_cast<std::uint32_t>(TreeMath::children(path[i], numLeaves).size());
            wraps += (i == 0) ? kids - 1 : 2;
        }
        EXPECT_EQ(wraps, expectedWraps) << "N=" << numLeaves;
    }
}

TEST_F(TreeMathCost, LargeGroupRemovalTouchesLogarithmicallyManyNodes) {
    EXPECT_EQ(TreeMath::directPath(0, 32768).size(), 15u);
}

TEST_F(TreeMathCost, GrowthChangesRootOnlyAtPowersOfTwo) {
    EXPECT_TRUE(TreeMath::growthChangesRoot(4, 4)) << "seating a 5th member grows the tree";
    EXPECT_FALSE(TreeMath::growthChangesRoot(2, 4)) << "filling a blank does not";
    EXPECT_FALSE(TreeMath::growthChangesRoot(4, 8)) << "room already exists";
    EXPECT_EQ(TreeMath::numLeavesToSeat(4, 4), 5u);
    EXPECT_EQ(TreeMath::numLeavesToSeat(1, 4), 4u);
}
