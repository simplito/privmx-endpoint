/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include "privmx/endpoint/group/keytree/TreeWire.hpp"

#include <map>
#include <set>

#include "privmx/endpoint/group/keytree/TreeMath.hpp"

using namespace privmx::endpoint::group::keytree;
namespace server = privmx::endpoint::group::server;

server::GroupTreeNode TreeWire::toWire(const TreeNodeState& node) {
    server::GroupTreeNode wire;
    wire.nodeIndex = static_cast<std::int64_t>(node.nodeIndex);
    wire.generation = static_cast<std::int64_t>(node.generation);
    if (node.publicKey.has_value()) {
        wire.publicKey = node.publicKey->toBase58DER();
    }
    return wire;
}

server::GroupTreeEdge TreeWire::toWire(const TreeEdge& edge) {
    server::GroupTreeEdge wire;
    if (edge.isGrantEdge) {
        wire.isGrantEdge = true;
    } else {
        wire.parentIndex = static_cast<std::int64_t>(edge.parentIndex);
    }
    wire.parentGeneration = static_cast<std::int64_t>(edge.parentGeneration);
    if (edge.childKind == EdgeChildKind::User) {
        wire.childKind = "user";
        wire.childUserId = edge.childUserId;
    } else {
        wire.childKind = "node";
        wire.childIndex = static_cast<std::int64_t>(edge.childIndex);
        wire.childGeneration = static_cast<std::int64_t>(edge.childGeneration);
    }
    wire.data = edge.blob;
    return wire;
}

server::GroupArchiveRung TreeWire::toWire(const ArchiveRung& rung) {
    server::GroupArchiveRung wire;
    wire.atKeyVersion = static_cast<std::int64_t>(rung.span.at);
    wire.targetKeyVersion = static_cast<std::int64_t>(rung.span.target);
    switch (rung.recipientKind) {
    case RungRecipientKind::User:
        wire.recipientKind = "user";
        break;
    case RungRecipientKind::Group:
        wire.recipientKind = "group";
        break;
    default:
        wire.recipientKind = "epoch";
        break;
    }
    if (!rung.recipientId.empty()) {
        wire.recipient = rung.recipientId;
    }
    wire.data = rung.blob;
    if (!rung.author.empty()) {
        wire.author = rung.author;
    }
    return wire;
}

std::vector<server::GroupArchiveRung> TreeWire::toWire(const std::vector<ArchiveRung>& rungs) {
    std::vector<server::GroupArchiveRung> wire;
    wire.reserve(rungs.size());
    for (const ArchiveRung& rung : rungs) {
        wire.push_back(toWire(rung));
    }
    return wire;
}

namespace {

std::vector<std::string> leafAssignmentToWire(const std::vector<std::optional<std::string>>& seats) {
    // A blank is spelled as an empty string: that is how the wire format says "nobody here" without a nullable
    // element.
    std::vector<std::string> wire;
    for (const auto& seat : seats) {
        wire.push_back(seat.value_or(std::string()));
    }
    return wire;
}

template<typename TWireNode>
std::vector<TWireNode> refreshedToWire(const CommitPlan& plan) {
    std::vector<TWireNode> wire;
    for (const RefreshedNode& refreshed : plan.refreshed) {
        TWireNode node;
        node.nodeIndex = static_cast<std::int64_t>(refreshed.nodeIndex);
        // The generation the node was read at travels with the refresh: the server refuses the commit if the node
        // has moved since, rather than applying it to a base the client never saw.
        if (refreshed.fromGeneration.has_value()) {
            node.fromGeneration = static_cast<std::int64_t>(refreshed.fromGeneration.value());
        }
        node.generation = static_cast<std::int64_t>(refreshed.generation);
        node.publicKey = refreshed.key.getPublicKey().toBase58DER();
        wire.push_back(node);
    }
    return wire;
}

std::vector<server::GroupTreeEdge> edgesToWire(const CommitPlan& plan) {
    std::vector<server::GroupTreeEdge> wire;
    for (const TreeEdge& edge : plan.edges) {
        wire.push_back(TreeWire::toWire(edge));
    }
    return wire;
}

} // namespace

server::GroupTreeState TreeWire::toCreateTree(const CommitPlan& plan) {
    server::GroupTreeState tree;
    tree.numLeaves = static_cast<std::int64_t>(plan.shape.numLeaves);
    tree.leafAssignment = leafAssignmentToWire(plan.shape.leafAssignment);
    for (const RefreshedNode& refreshed : plan.refreshed) {
        tree.nodes.push_back(
            toWire(TreeNodeState{refreshed.nodeIndex, refreshed.generation, refreshed.key.getPublicKey()})
        );
    }
    tree.edges = edgesToWire(plan);
    return tree;
}

server::GroupTreeState TreeWire::fromGroupInfo(const server::GroupInfo& group) {
    server::GroupTreeState tree;
    tree.numLeaves = group.numLeaves.value_or(0);
    tree.leafAssignment = group.leafAssignment.value_or(std::vector<std::string>{});
    tree.nodes = group.treeNodes.value_or(std::vector<server::GroupTreeNode>{});
    tree.edges = group.treeEdges.value_or(std::vector<server::GroupTreeEdge>{});
    return tree;
}

TreeGroupState TreeWire::toRuntime(
    const server::GroupTreeState& tree,
    std::uint32_t epoch,
    const privmx::crypto::PublicKey& grantPublicKey
) {
    TreeGroupState state;
    state.numLeaves = static_cast<std::uint32_t>(tree.numLeaves);
    state.epoch = epoch;
    state.grantPublicKey = grantPublicKey;
    for (const std::string& userId : tree.leafAssignment) {
        if (userId.empty()) {
            state.leafAssignment.push_back(std::nullopt);
        } else {
            state.leafAssignment.push_back(userId);
        }
    }
    for (const server::GroupTreeNode& node : tree.nodes) {
        TreeNodeState converted{
            static_cast<std::uint32_t>(node.nodeIndex), static_cast<std::uint32_t>(node.generation), std::nullopt
        };
        if (!node.publicKey.value_or("").empty()) {
            converted.publicKey = NodePublicKey::fromBase58DER(node.publicKey.value());
        }
        state.nodes.push_back(converted);
    }
    for (const server::GroupTreeEdge& edge : tree.edges) {
        TreeEdge converted;
        converted.isGrantEdge = edge.isGrantEdge.value_or(false);
        converted.parentIndex = static_cast<std::uint32_t>(edge.parentIndex.value_or(0));
        converted.parentGeneration = static_cast<std::uint32_t>(edge.parentGeneration);
        if (edge.childKind == "user") {
            converted.childKind = EdgeChildKind::User;
            converted.childUserId = edge.childUserId.value_or("");
        } else {
            converted.childKind = EdgeChildKind::Node;
            converted.childIndex = static_cast<std::uint32_t>(edge.childIndex.value_or(0));
            converted.childGeneration = static_cast<std::uint32_t>(edge.childGeneration.value_or(0));
        }
        converted.blob = edge.data;
        state.edges.push_back(converted);
    }
    return state;
}

server::GroupTreeAdditionTransition TreeWire::toAdditionTransition(
    const CommitPlan& plan,
    std::int64_t baseKeyVersion
) {
    server::GroupTreeAdditionTransition transition;
    transition.baseKeyVersion = baseKeyVersion;
    for (const std::uint32_t position : plan.shape.subjectSeats) {
        transition.positions.push_back(static_cast<std::int64_t>(position));
    }
    transition.seatedNodes = refreshedToWire<server::GroupTreeSeatedNode>(plan);
    transition.edges = edgesToWire(plan);
    return transition;
}

server::GroupTreeTransition TreeWire::toRemovalTransition(const CommitPlan& plan, std::int64_t baseKeyVersion) {
    server::GroupTreeTransition transition;
    transition.baseKeyVersion = baseKeyVersion;
    for (const std::uint32_t position : plan.shape.subjectSeats) {
        transition.blankedPositions.push_back(static_cast<std::int64_t>(position));
    }
    transition.refreshedNodes = refreshedToWire<server::GroupTreeRefreshedNode>(plan);
    transition.edges = edgesToWire(plan);
    return transition;
}

server::GroupTreeSelfUpdateTransition TreeWire::toSelfUpdateTransition(
    const CommitPlan& plan,
    std::int64_t baseKeyVersion
) {
    server::GroupTreeSelfUpdateTransition transition;
    transition.baseKeyVersion = baseKeyVersion;
    transition.refreshedNodes = refreshedToWire<server::GroupTreeRefreshedNode>(plan);
    transition.edges = edgesToWire(plan);
    return transition;
}

server::GroupTreeState TreeWire::afterCommit(const server::GroupTreeState& before, const CommitPlan& plan) {
    server::GroupTreeState after;
    after.numLeaves = static_cast<std::int64_t>(plan.shape.numLeaves);
    after.leafAssignment = leafAssignmentToWire(plan.shape.leafAssignment);

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
        }
    }
    for (const RefreshedNode& refreshed : plan.refreshed) {
        replaced.insert(refreshed.nodeIndex);
        nodes[refreshed.nodeIndex] = toWire(
            TreeNodeState{refreshed.nodeIndex, refreshed.generation, refreshed.key.getPublicKey()}
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
    for (const server::GroupTreeEdge& edge : edgesToWire(plan)) {
        after.edges.push_back(edge);
    }
    return after;
}
