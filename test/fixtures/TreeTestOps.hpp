/*
PrivMX Endpoint.
Copyright © 2026 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

// Key-tree operations the live path leaves to the bridge, for the unit tests and the tools that stand in for it.

#ifndef _PRIVMXLIB_TEST_FIXTURES_TREETESTOPS_HPP_
#define _PRIVMXLIB_TEST_FIXTURES_TREETESTOPS_HPP_

#include <cstdint>
#include <map>
#include <set>
#include <string>
#include <vector>

#include <privmx/endpoint/group/keytree/TreeKeys.hpp>
#include <privmx/endpoint/group/keytree/TreeMath.hpp>
#include <privmx/endpoint/group/keytree/TreeWire.hpp>

namespace treetest {

using namespace privmx::endpoint::group;
using namespace privmx::endpoint::group::keytree;

// Seats for `count` newcomers: lowest blank first, then append. Never moves anyone; appends are contiguous, since a
// skipped seat is one nothing can ever reuse and the bridge refuses it.
inline std::vector<std::uint32_t> choosePositions(const TreeGroupState& state, std::uint32_t count) {
    std::vector<std::uint32_t> seats;
    for (std::size_t i = 0; i < state.leafAssignment.size() && seats.size() < count; ++i) {
        if (!state.leafAssignment[i].has_value()) {
            seats.push_back(static_cast<std::uint32_t>(i));
        }
    }
    for (auto position = static_cast<std::uint32_t>(state.leafAssignment.size()); seats.size() < count; ++position) {
        seats.push_back(position);
    }
    return seats;
}

inline void setMemberKeys(TreeKeys& keys, const std::vector<TreeMember>& members) {
    std::map<std::string, std::string> byUserId;
    for (const TreeMember& member : members) {
        byUserId[member.userId] = member.publicKey.toBase58DER();
    }
    keys.setMemberKeyStrings(std::move(byUserId));
}

// The whole state after a commit, by the bridge's storage rule: blanked nodes keep their generation and lose their
// key, refreshed ones are replaced, and every edge hanging off either is replaced by the plan's. A record growth
// pushed into a bucket (an old root at a low level) goes with its edges.
inline server::GroupTreeState afterCommit(const server::GroupTreeState& before, const CommitPlan& plan) {
    server::GroupTreeState after;
    after.numLeaves = static_cast<std::int64_t>(plan.shape.numLeaves);
    for (const auto& seat : plan.shape.leafAssignment) {
        after.leafAssignment.push_back(seat.value_or(std::string()));
    }

    // Every node whose outgoing edges the commit invalidates: refreshed, blanked, or no longer keyed at all.
    std::set<std::uint32_t> replaced(plan.shape.blanked.begin(), plan.shape.blanked.end());
    std::map<std::uint32_t, server::GroupTreeNode> nodes;
    for (const server::GroupTreeNode& node : before.nodes) {
        const auto index = static_cast<std::uint32_t>(node.nodeIndex);
        if (!TreeMath::isKeyed(index, plan.shape.numLeaves)) {
            replaced.insert(index);
            continue;
        }
        nodes[index] = node;
        if (plan.shape.blanked.count(index) > 0) {
            nodes[index].publicKey = std::nullopt;
            nodes[index].setBy = std::nullopt;
        }
    }
    for (const RefreshedNode& refreshed : plan.refreshed) {
        replaced.insert(refreshed.nodeIndex);
        nodes[refreshed.nodeIndex] = TreeWire::toWire(
            TreeNodeState{refreshed.nodeIndex, refreshed.generation, refreshed.key.getPublicKey(), plan.seq}
        );
    }
    for (const auto& [index, node] : nodes) {
        after.nodes.push_back(node);
    }

    for (const server::GroupTreeEdge& edge : before.edges) {
        if (edge.isGrantEdge.value_or(false) ||
            replaced.count(static_cast<std::uint32_t>(edge.parentIndex.value_or(0))) > 0) {
            continue;
        }
        after.edges.push_back(edge);
    }
    for (const TreeEdge& edge : plan.edges) {
        after.edges.push_back(TreeWire::toWire(edge));
    }
    return after;
}

} // namespace treetest

#endif // _PRIVMXLIB_TEST_FIXTURES_TREETESTOPS_HPP_
