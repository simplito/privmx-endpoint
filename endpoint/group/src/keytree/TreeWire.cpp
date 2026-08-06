/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include "privmx/endpoint/group/keytree/TreeWire.hpp"

#include <algorithm>
#include <set>

#include "privmx/endpoint/group/keytree/TreeMath.hpp"

using namespace privmx::endpoint::group::keytree;
namespace server = privmx::endpoint::group::server;

server::GroupTreeNode TreeWire::toWire(const TreeNodeState& node) {
    server::GroupTreeNode wire;
    wire.nodeIndex = static_cast<std::int64_t>(node.nodeIndex);
    wire.generation = static_cast<std::int64_t>(node.generation);
    wire.publicKey = node.publicKey.toBase58DER();
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

server::GroupTreeState TreeWire::fromBuildPlan(const BuildPlan& plan, const std::vector<TreeMember>& members) {
    server::GroupTreeState tree;
    tree.numLeaves = static_cast<std::int64_t>(plan.numLeaves);
    // Positions beyond the member list exist only when the tree was padded; they are blanks, spelled as empty
    // strings because that is how the wire format says "nobody here" without a nullable element.
    tree.leafAssignment.assign(plan.numLeaves, std::string());
    for (std::size_t i = 0; i < members.size() && i < plan.numLeaves; ++i) {
        tree.leafAssignment[i] = members[i].userId;
    }
    for (const TreeNodeState& node : plan.nodes) {
        tree.nodes.push_back(toWire(node));
    }
    for (const TreeEdge& edge : plan.edges) {
        tree.edges.push_back(toWire(edge));
    }
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
        state.nodes.push_back(TreeNodeState{
            static_cast<std::uint32_t>(node.nodeIndex),
            static_cast<std::uint32_t>(node.generation),
            privmx::crypto::PublicKey::fromBase58DER(node.publicKey),
        });
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

server::GroupTreeState TreeWire::afterRemoval(
    const server::GroupTreeState& before,
    const RemovalPlan& plan,
    std::uint32_t position
) {
    server::GroupTreeState after;
    after.numLeaves = before.numLeaves;
    after.leafAssignment = before.leafAssignment;
    const std::string departing = position < after.leafAssignment.size() ? after.leafAssignment[position] : std::string();
    if (position < after.leafAssignment.size()) {
        after.leafAssignment[position] = std::string();
    }

    std::set<std::uint32_t> refreshed;
    for (const NodeRefresh& refresh : plan.pathRefresh) {
        refreshed.insert(refresh.nodeIndex);
    }

    // Nodes off the path come through byte-identical; nodes on it are replaced by their refreshed selves.
    for (const server::GroupTreeNode& node : before.nodes) {
        if (refreshed.count(static_cast<std::uint32_t>(node.nodeIndex)) == 0) {
            after.nodes.push_back(node);
        }
    }
    for (const NodeRefresh& refresh : plan.pathRefresh) {
        after.nodes.push_back(toWire(TreeNodeState{
            refresh.nodeIndex, refresh.newGeneration, refresh.newKey.getPublicKey()
        }));
    }

    for (const server::GroupTreeEdge& edge : before.edges) {
        if (edge.isGrantEdge.value_or(false)) {
            continue; // replaced below, at the new epoch
        }
        if (refreshed.count(static_cast<std::uint32_t>(edge.parentIndex.value_or(0))) > 0) {
            // Its parent's key is gone, so the blob decrypts to a key nobody holds any more. The refresh
            // supplies the replacement; keeping this one would make the state fail the generation check.
            continue;
        }
        if (edge.childKind == "user" && !departing.empty() && edge.childUserId.value_or("") == departing) {
            continue; // the whole point of the operation
        }
        after.edges.push_back(edge);
    }
    for (const NodeRefresh& refresh : plan.pathRefresh) {
        for (const TreeEdge& edge : refresh.edges) {
            after.edges.push_back(toWire(edge));
        }
    }
    after.edges.push_back(toWire(plan.grantEdge));
    return after;
}

server::GroupTreeState TreeWire::afterAddition(
    const server::GroupTreeState& before,
    const AdditionPlan& plan,
    const std::string& newMemberId
) {
    server::GroupTreeState after;
    after.numLeaves = static_cast<std::int64_t>(plan.newNumLeaves);
    after.leafAssignment = before.leafAssignment;
    after.leafAssignment.resize(plan.newNumLeaves, std::string());
    after.leafAssignment[plan.position] = newMemberId;
    after.nodes = before.nodes;
    for (const TreeNodeState& node : plan.nodes) {
        after.nodes.push_back(toWire(node));
    }

    // Growth re-parents nodes and leaves at the truncated edge of the tree, so an edge that was correct a moment
    // ago can name a parent that is no longer the child's parent. Those have to go: the plan supplies the
    // replacement, and keeping the old one would leave the state describing a topology that no longer exists.
    const auto stillCorrect = [&](const server::GroupTreeEdge& edge) {
        if (edge.isGrantEdge.value_or(false)) {
            return true; // the plan replaces it when the root changed; otherwise it still points at the root
        }
        const std::uint32_t parentIndex = static_cast<std::uint32_t>(edge.parentIndex.value_or(0));
        std::uint32_t childNode = 0;
        if (edge.childKind == "user") {
            const std::string& userId = edge.childUserId.value_or("");
            const auto seat = std::find(before.leafAssignment.begin(), before.leafAssignment.end(), userId);
            if (seat == before.leafAssignment.end()) {
                return false;
            }
            childNode = TreeMath::leafNode(
                static_cast<std::uint32_t>(std::distance(before.leafAssignment.begin(), seat))
            );
        } else {
            childNode = static_cast<std::uint32_t>(edge.childIndex.value_or(0));
        }
        const std::uint32_t root = TreeMath::root(plan.newNumLeaves);
        if (childNode == root) {
            return false; // the old root is now somebody's child; only the plan knows whose
        }
        return TreeMath::parent(childNode, plan.newNumLeaves) == parentIndex;
    };

    std::set<std::string> replaced;
    const auto edgeKey = [](const server::GroupTreeEdge& edge) {
        if (edge.isGrantEdge.value_or(false)) {
            return std::string("grant");
        }
        const std::string child = edge.childKind == "user"
            ? "user:" + edge.childUserId.value_or("")
            : "node:" + std::to_string(edge.childIndex.value_or(0));
        return std::to_string(edge.parentIndex.value_or(0)) + ">" + child;
    };
    std::vector<server::GroupTreeEdge> added;
    for (const TreeEdge& edge : plan.edges) {
        const server::GroupTreeEdge wire = toWire(edge);
        replaced.insert(edgeKey(wire));
        added.push_back(wire);
    }
    for (const server::GroupTreeEdge& edge : before.edges) {
        if (replaced.count(edgeKey(edge)) > 0 || !stillCorrect(edge)) {
            continue;
        }
        after.edges.push_back(edge);
    }
    for (const server::GroupTreeEdge& edge : added) {
        after.edges.push_back(edge);
    }
    return after;
}
