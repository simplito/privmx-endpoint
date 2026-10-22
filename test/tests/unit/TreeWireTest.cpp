/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

/**
 * Turning commit plans into what the bridge receives, with real EC keys: the tree of a new group, and the
 * transition every later commit sends. A mistake here does not produce a wrong key but a commit the server
 * rejects or, worse, accepts while a member can no longer climb. The server's own view of the same states is checked
 * from the bridge's test suite, against fixtures emitted by test/tools/keytree_state_dump.cpp.
 *
 * Tests named SECURITY guard confidentiality and fail silently at runtime if the guard regresses.
 */

#include <gtest/gtest.h>

#include <algorithm>
#include <cstdint>
#include <functional>
#include <map>
#include <string>
#include <vector>

#include <privmx/crypto/ecc/PrivateKey.hpp>

#include <privmx/endpoint/group/keytree/TreeKeys.hpp>
#include <privmx/endpoint/group/keytree/TreeMath.hpp>
#include <privmx/endpoint/group/keytree/TreeWire.hpp>

#include "TreeTestOps.hpp"

using privmx::crypto::PrivateKey;
using namespace privmx::endpoint::group;
using namespace privmx::endpoint::group::keytree;

class TreeWireTest : public testing::Test {
protected:
    struct Member {
        std::string userId;
        PrivateKey priv;
    };

    // A group as stored on the bridge, the members behind it, and the plan that made its current state.
    struct Group {
        std::vector<Member> members;
        server::GroupTreeState tree;
        std::uint32_t epoch = 1;
        privmx::crypto::PublicKey grant;
        std::map<std::uint64_t, std::string> setters; // statement seq -> committer
    };

    std::vector<TreeMember> publicOf(const std::vector<Member>& members) {
        std::vector<TreeMember> result;
        for (const Member& member : members) {
            result.push_back(TreeMember{member.userId, member.priv.getPublicKey()});
        }
        return result;
    }

    TreeGroupState runtime(const Group& group) {
        TreeGroupState state = TreeWire::toRuntime(group.tree, group.epoch, group.grant);
        state.setters = group.setters;
        state.commitSeq = group.setters.rbegin()->first;
        return state;
    }

    Group create(std::uint32_t count, std::uint32_t creator = 0) {
        Group group;
        for (std::uint32_t i = 0; i < count; ++i) {
            group.members.push_back(Member{"u" + std::to_string(i), PrivateKey::generateRandom()});
        }
        TreeKeyCache cache;
        TreeKeys keys(cache);
        const CommitPlan plan =
            keys.planCreate(publicOf(group.members), group.members[creator].userId, group.members[creator].priv);
        group.tree = TreeWire::toCreateTree(plan);
        group.grant = plan.grantKey.getPublicKey();
        group.setters[plan.seq] = group.members[creator].userId;
        return group;
    }

    // Plans as `committer` from a cold cache, then stores the result the way the bridge does.
    CommitPlan commit(
        Group& group,
        std::uint32_t committer,
        const std::function<CommitPlan(TreeKeys&, const TreeGroupState&, const Member&)>& plan
    ) {
        TreeKeyCache cache;
        TreeKeys keys(cache);
        const TreeGroupState state = runtime(group);
        const Member& who = group.members[committer];
        EXPECT_EQ(keys.climbToGrantKey(state, who.userId, who.priv, false).failure, ClimbFailure::None);
        treetest::setMemberKeys(keys, publicOf(group.members));
        const CommitPlan result = plan(keys, state, who);
        group.tree = treetest::afterCommit(group.tree, result);
        group.epoch = result.epoch;
        group.grant = result.grantKey.getPublicKey();
        group.setters[result.seq] = who.userId;
        return result;
    }

    CommitPlan remove(Group& group, std::uint32_t remover, std::uint32_t leaving) {
        return commit(group, remover, [&](TreeKeys& keys, const TreeGroupState& state, const Member& who) {
            return keys.planRemoval(state, {group.members[leaving].userId}, who.userId, who.priv);
        });
    }

    CommitPlan add(Group& group, std::uint32_t adder) {
        const Member newcomer{"new" + std::to_string(group.members.size()), PrivateKey::generateRandom()};
        const CommitPlan plan = commit(group, adder, [&](TreeKeys& keys, const TreeGroupState& state, const Member& who) {
            return keys.planAddition(
                state, publicOf({newcomer}), treetest::choosePositions(state, 1), who.userId, who.priv
            );
        });
        group.members.push_back(newcomer);
        return plan;
    }

    bool canClimb(const Group& group, const Member& member) {
        TreeKeyCache cache;
        TreeKeys keys(cache);
        const ClimbResult climb = keys.climbToGrantKey(runtime(group), member.userId, member.priv, false);
        return climb.failure == ClimbFailure::None && climb.grantKey.has_value();
    }

    static const server::GroupTreeEdge* grantEdgeOf(const std::vector<server::GroupTreeEdge>& edges) {
        const auto grant = std::find_if(edges.begin(), edges.end(), [](const server::GroupTreeEdge& edge) {
            return edge.isGrantEdge.value_or(false);
        });
        return grant == edges.end() ? nullptr : &*grant;
    }

    static const server::GroupTreeNode* nodeOf(const server::GroupTreeState& tree, std::uint32_t nodeIndex) {
        for (const server::GroupTreeNode& node : tree.nodes) {
            if (node.nodeIndex == static_cast<std::int64_t>(nodeIndex)) {
                return &node;
            }
        }
        return nullptr;
    }
};

// creation

TEST_F(TreeWireTest, ACreatedTreeSeatsEveryoneAndCarriesEveryKeyedNode) {
    for (const std::uint32_t count : {1u, 2u, 3u, 16u, 17u, 33u, 40u}) {
        const std::uint32_t creator = count - 1;
        const Group group = create(count, creator);
        EXPECT_EQ(group.tree.numLeaves, static_cast<std::int64_t>(count));
        ASSERT_EQ(group.tree.leafAssignment.size(), count);
        for (std::uint32_t i = 0; i < count; ++i) {
            EXPECT_EQ(group.tree.leafAssignment[i], group.members[i].userId);
        }
        std::vector<std::uint32_t> nodes;
        for (const server::GroupTreeNode& node : group.tree.nodes) {
            nodes.push_back(static_cast<std::uint32_t>(node.nodeIndex));
            EXPECT_EQ(node.generation, 0);
            EXPECT_TRUE(node.publicKey.has_value());
        }
        EXPECT_EQ(nodes, TreeMath::keyedNodes(count)) << "N=" << count;
    }
}

TEST_F(TreeWireTest, ACreatedTreeStaysWithinTheBridgesSubmissionCaps) {
    // Every member gets exactly one edge, every keyed node below the root one more, plus the grant edge — which
    // in a one-seat tree is the member's edge.
    for (const std::uint32_t count : {1u, 2u, 3u, 8u, 16u, 17u, 32u, 33u, 64u, 100u}) {
        const Group group = create(count);
        const std::size_t keyed = TreeMath::keyedNodes(count).size();
        EXPECT_EQ(group.tree.edges.size(), count == 1 ? 1u : count + keyed) << "N=" << count;
        EXPECT_LE(group.tree.nodes.size(), std::max<std::size_t>(count, 1) - 1) << "N=" << count;
        EXPECT_LE(group.tree.edges.size(), 2u * count - 1) << "N=" << count;
    }
}

TEST_F(TreeWireTest, EveryMemberCanClimbTheTreeThatWasSubmitted) {
    const Group group = create(40, 20);
    for (const Member& member : group.members) {
        EXPECT_TRUE(canClimb(group, member)) << member.userId << " cannot climb";
    }
}

TEST_F(TreeWireTest, TheGrantEdgeCarriesTheEpochAndNamesTheRoot) {
    const Group group = create(40);
    const server::GroupTreeEdge* grant = grantEdgeOf(group.tree.edges);
    ASSERT_NE(grant, nullptr);
    EXPECT_EQ(grant->parentGeneration, 1);
    EXPECT_EQ(grant->childKind, "node");
    EXPECT_EQ(grant->childIndex.value_or(0), TreeMath::root(40));
    EXPECT_EQ(grant->childGeneration.value_or(-1), 0);
    EXPECT_FALSE(grant->parentIndex.has_value());

    const Group alone = create(1);
    const server::GroupTreeEdge* direct = grantEdgeOf(alone.tree.edges);
    ASSERT_NE(direct, nullptr);
    EXPECT_EQ(direct->childKind, "user");
    EXPECT_EQ(direct->childUserId.value_or(""), alone.members[0].userId);
}

// transitions

TEST_F(TreeWireTest, ARemovalSendsTheRemoversPathTheBlankedSeatAndTheNewEpoch) {
    Group group = create(40, 0);
    const CommitPlan plan = remove(group, 35, 5);
    const server::GroupTreeTransition transition = TreeWire::toRemovalTransition(plan, 1);
    EXPECT_EQ(transition.baseKeyVersion, 1);
    EXPECT_EQ(transition.blankedPositions, std::vector<std::int64_t>({5}));
    ASSERT_EQ(transition.refreshedNodes.size(), 1u);
    EXPECT_EQ(transition.refreshedNodes[0].nodeIndex, 63);
    EXPECT_EQ(transition.refreshedNodes[0].fromGeneration, std::optional<std::int64_t>(0));
    EXPECT_EQ(transition.refreshedNodes[0].generation, 1);
    const server::GroupTreeEdge* grant = grantEdgeOf(transition.edges);
    ASSERT_NE(grant, nullptr);
    EXPECT_EQ(grant->parentGeneration, 2);
    EXPECT_EQ(grant->childGeneration.value_or(-1), 1);
    for (const server::GroupTreeEdge& edge : transition.edges) {
        EXPECT_NE(edge.childUserId.value_or(""), group.members[5].userId);
    }
}

TEST_F(TreeWireTest, AFreshlyMintedNodeIsSentWithoutAFromGeneration) {
    // 32 seats to 33: the root 63 did not exist, node 31 did.
    Group group = create(32, 0);
    const CommitPlan plan = add(group, 0);
    const server::GroupTreeAdditionTransition transition = TreeWire::toAdditionTransition(plan, 1);
    EXPECT_EQ(transition.positions, std::vector<std::int64_t>({32}));
    ASSERT_EQ(transition.seatedNodes.size(), 2u);
    EXPECT_EQ(transition.seatedNodes[0].nodeIndex, 31);
    EXPECT_EQ(transition.seatedNodes[0].fromGeneration, std::optional<std::int64_t>(0));
    EXPECT_EQ(transition.seatedNodes[1].nodeIndex, 63);
    EXPECT_FALSE(transition.seatedNodes[1].fromGeneration.has_value());
    EXPECT_EQ(transition.seatedNodes[1].generation, 0);
    EXPECT_FALSE(transition.toJSON()->getArray("seatedNodes")->getObject(1)->has("fromGeneration"))
        << "absent on the wire, not null or zero";
    EXPECT_EQ(grantEdgeOf(transition.edges)->parentGeneration, 1) << "re-linking is not a rotation";
}

TEST_F(TreeWireTest, ASelfUpdateSendsTheMembersPathAtTheUnchangedEpoch) {
    Group group = create(40, 0);
    remove(group, 35, 5);
    const CommitPlan plan = commit(group, 9, [&](TreeKeys& keys, const TreeGroupState& state, const Member& who) {
        return keys.planSelfUpdate(state, who.userId, who.priv);
    });
    const server::GroupTreeSelfUpdateTransition transition = TreeWire::toSelfUpdateTransition(plan, 2);
    EXPECT_EQ(transition.baseKeyVersion, 2);
    ASSERT_EQ(transition.refreshedNodes.size(), 2u);
    EXPECT_EQ(transition.refreshedNodes[0].nodeIndex, 31);
    EXPECT_EQ(transition.refreshedNodes[1].nodeIndex, 63);
    EXPECT_EQ(grantEdgeOf(transition.edges)->parentGeneration, 2);
    const auto json = transition.toJSON();
    EXPECT_TRUE(json->has("baseKeyVersion") && json->has("refreshedNodes") && json->has("edges"));
}

// the stored state

TEST_F(TreeWireTest, SECURITY_ABlankedNodeKeepsItsGenerationAndLosesItsKey) {
    Group group = create(40, 0);
    remove(group, 35, 5);
    const server::GroupTreeNode* blank = nodeOf(group.tree, 31);
    ASSERT_NE(blank, nullptr);
    EXPECT_EQ(blank->generation, 0);
    EXPECT_FALSE(blank->publicKey.has_value());
    for (const server::GroupTreeEdge& edge : group.tree.edges) {
        EXPECT_NE(edge.parentIndex.value_or(-1), 31) << "a blank node holds no edges";
        EXPECT_NE(edge.childUserId.value_or(""), group.members[5].userId) << "nothing addressed to the leaver";
    }
    EXPECT_FALSE(canClimb(group, group.members[5]));
    for (std::uint32_t i = 0; i < 40; ++i) {
        if (i != 5) {
            EXPECT_TRUE(canClimb(group, group.members[i])) << group.members[i].userId << " lost access";
        }
    }
}

TEST_F(TreeWireTest, GrowthPastSixteenDropsTheOldRootWithItsEdges) {
    Group group = create(16, 4);
    add(group, 4);
    EXPECT_EQ(group.tree.numLeaves, 17);
    EXPECT_EQ(nodeOf(group.tree, 15), nullptr) << "level 4 is a bucket once it is not the root";
    for (const server::GroupTreeEdge& edge : group.tree.edges) {
        EXPECT_NE(edge.parentIndex.value_or(-1), 15);
    }
    for (const Member& member : group.members) {
        EXPECT_TRUE(canClimb(group, member)) << member.userId;
    }
}

TEST_F(TreeWireTest, AServedBlankReadsAsBlankWhetherAbsentOrEmpty) {
    server::GroupTreeState tree;
    tree.numLeaves = 40;
    tree.leafAssignment.assign(40, "u");
    tree.nodes = {
        server::GroupTreeNode{31, 2, std::nullopt},
        server::GroupTreeNode{63, 4, std::string()},
    };
    const TreeGroupState state = TreeWire::toRuntime(tree, 1, PrivateKey::generateRandom().getPublicKey());
    ASSERT_EQ(state.nodes.size(), 2u);
    EXPECT_FALSE(state.nodes[0].publicKey.has_value());
    EXPECT_EQ(state.nodes[0].generation, 2u);
    EXPECT_FALSE(state.nodes[1].publicKey.has_value());
    EXPECT_FALSE(TreeWire::toWire(state.nodes[0]).toJSON()->has("publicKey"));
}
