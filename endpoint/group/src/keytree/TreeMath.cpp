/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include "privmx/endpoint/group/keytree/TreeMath.hpp"

#include <stdexcept>
#include <string>

using namespace privmx::endpoint::group::keytree;

std::uint32_t TreeMath::pow2(std::uint32_t exponent) {
    std::uint32_t value = 1;
    for (std::uint32_t i = 0; i < exponent; ++i) {
        value *= 2;
    }
    return value;
}

void TreeMath::assertNumLeaves(std::uint32_t numLeaves) {
    if (numLeaves < 1) {
        throw std::invalid_argument("numLeaves must be at least 1");
    }
}

void TreeMath::assertLeafInTree(std::uint32_t leaf, std::uint32_t numLeaves) {
    if (!exists(leaf, numLeaves)) {
        throw std::invalid_argument(
            "leaf node " + std::to_string(leaf) + " outside tree of " + std::to_string(numLeaves) + " leaves"
        );
    }
}

std::uint32_t TreeMath::nodeCount(std::uint32_t numLeaves) {
    assertNumLeaves(numLeaves);
    return 2 * numLeaves - 1;
}

std::uint32_t TreeMath::leafNode(std::uint32_t position) {
    return 2 * position;
}

std::uint32_t TreeMath::leafPosition(std::uint32_t nodeIndex) {
    if (!isLeaf(nodeIndex)) {
        throw std::invalid_argument("node " + std::to_string(nodeIndex) + " is not a leaf");
    }
    return nodeIndex / 2;
}

bool TreeMath::isLeaf(std::uint32_t nodeIndex) {
    return nodeIndex % 2 == 0;
}

std::uint32_t TreeMath::level(std::uint32_t nodeIndex) {
    std::uint32_t k = 0;
    std::uint32_t x = nodeIndex;
    while (x % 2 == 1) {
        ++k;
        x = (x - 1) / 2;
    }
    return k;
}

std::uint32_t TreeMath::root(std::uint32_t numLeaves) {
    assertNumLeaves(numLeaves);
    std::uint32_t w = 1;
    while (w < numLeaves) {
        w *= 2;
    }
    return w - 1;
}

std::uint32_t TreeMath::depth(std::uint32_t numLeaves) {
    assertNumLeaves(numLeaves);
    std::uint32_t d = 0;
    std::uint32_t w = 1;
    while (w < numLeaves) {
        w *= 2;
        ++d;
    }
    return d;
}

bool TreeMath::exists(std::uint32_t nodeIndex, std::uint32_t numLeaves) {
    return nodeIndex < nodeCount(numLeaves);
}

std::uint32_t TreeMath::leftStep(std::uint32_t nodeIndex) {
    const std::uint32_t k = level(nodeIndex);
    if (k == 0) {
        throw std::invalid_argument("leaf " + std::to_string(nodeIndex) + " has no children");
    }
    return nodeIndex - pow2(k - 1);
}

std::uint32_t TreeMath::rightStep(std::uint32_t nodeIndex) {
    const std::uint32_t k = level(nodeIndex);
    if (k == 0) {
        throw std::invalid_argument("leaf " + std::to_string(nodeIndex) + " has no children");
    }
    return nodeIndex + pow2(k - 1);
}

std::uint32_t TreeMath::parentStep(std::uint32_t nodeIndex) {
    // Bitwise form is `(x | 2^k) & ~(2^(k+1))`. A node of level k has exactly k trailing 1-bits, so its bit k
    // is 0 and the OR is an addition; the AND then clears bit k+1 if it is set.
    const std::uint32_t k = level(nodeIndex);
    const std::uint32_t bit = pow2(k);
    const std::uint32_t withBitSet = nodeIndex + bit;
    const std::uint32_t nextBit = bit * 2;
    const bool nextBitIsSet = (withBitSet / nextBit) % 2 == 1;
    return nextBitIsSet ? withBitSet - nextBit : withBitSet;
}

std::uint32_t TreeMath::left(std::uint32_t nodeIndex, std::uint32_t numLeaves) {
    const std::uint32_t l = leftStep(nodeIndex);
    if (!exists(l, numLeaves)) {
        // Unreachable for a left child: leftStep only decreases the index.
        throw std::logic_error("left child " + std::to_string(l) + " outside tree");
    }
    return l;
}

std::uint32_t TreeMath::right(std::uint32_t nodeIndex, std::uint32_t numLeaves) {
    std::uint32_t r = rightStep(nodeIndex);
    while (!exists(r, numLeaves)) {
        r = leftStep(r);
    }
    return r;
}

std::uint32_t TreeMath::parent(std::uint32_t nodeIndex, std::uint32_t numLeaves) {
    const std::uint32_t rootIndex = root(numLeaves);
    if (nodeIndex == rootIndex) {
        throw std::logic_error("root " + std::to_string(nodeIndex) + " has no parent");
    }
    if (!exists(nodeIndex, numLeaves)) {
        throw std::invalid_argument("node " + std::to_string(nodeIndex) + " outside tree");
    }
    std::uint32_t p = parentStep(nodeIndex);
    while (!exists(p, numLeaves)) {
        p = parentStep(p);
    }
    return p;
}

std::uint32_t TreeMath::sibling(std::uint32_t nodeIndex, std::uint32_t numLeaves) {
    const std::uint32_t p = parent(nodeIndex, numLeaves);
    return nodeIndex < p ? right(p, numLeaves) : left(p, numLeaves);
}

std::vector<std::uint32_t> TreeMath::children(std::uint32_t nodeIndex, std::uint32_t numLeaves) {
    if (isLeaf(nodeIndex)) {
        return {};
    }
    return {left(nodeIndex, numLeaves), right(nodeIndex, numLeaves)};
}

std::vector<std::uint32_t> TreeMath::directPath(std::uint32_t position, std::uint32_t numLeaves) {
    const std::uint32_t leaf = leafNode(position);
    assertLeafInTree(leaf, numLeaves);
    const std::uint32_t rootIndex = root(numLeaves);
    std::vector<std::uint32_t> path;
    std::uint32_t current = leaf;
    while (current != rootIndex) {
        current = parent(current, numLeaves);
        path.push_back(current);
    }
    return path;
}

std::vector<std::uint32_t> TreeMath::copath(std::uint32_t position, std::uint32_t numLeaves) {
    const std::uint32_t leaf = leafNode(position);
    assertLeafInTree(leaf, numLeaves);
    const std::uint32_t rootIndex = root(numLeaves);
    std::vector<std::uint32_t> co;
    std::uint32_t current = leaf;
    while (current != rootIndex) {
        co.push_back(sibling(current, numLeaves));
        current = parent(current, numLeaves);
    }
    return co;
}

std::vector<std::uint32_t> TreeMath::leavesUnder(std::uint32_t nodeIndex, std::uint32_t numLeaves) {
    if (isLeaf(nodeIndex)) {
        return {leafPosition(nodeIndex)};
    }
    std::vector<std::uint32_t> result = leavesUnder(left(nodeIndex, numLeaves), numLeaves);
    const std::vector<std::uint32_t> rightLeaves = leavesUnder(right(nodeIndex, numLeaves), numLeaves);
    result.insert(result.end(), rightLeaves.begin(), rightLeaves.end());
    return result;
}

std::uint32_t TreeMath::numLeavesToSeat(std::uint32_t position, std::uint32_t currentNumLeaves) {
    if (position < currentNumLeaves) {
        return currentNumLeaves;
    }
    return position + 1;
}

bool TreeMath::growthChangesRoot(std::uint32_t position, std::uint32_t currentNumLeaves) {
    const std::uint32_t next = numLeavesToSeat(position, currentNumLeaves);
    return root(next) != root(currentNumLeaves);
}
