/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

/** Unit tests for turning removal and addition plans into the complete tree state the bridge receives, with real EC keys, checking both the shape of the state and that the members who should still be able to climb it actually can, since a mistake here does not produce a wrong key but a state the server rejects or, worse, accepts while a member can no longer climb; the server's own view of the same states is checked from the bridge's test suite against fixtures emitted by test/tools/keytree_state_dump.cpp, and tests named SECURITY guard confidentiality and fail silently at runtime if the guard regresses. */

#include <gtest/gtest.h>

#include <algorithm>
#include <map>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>

#include <privmx/crypto/ecc/PrivateKey.hpp>

#include <privmx/endpoint/group/keytree/TreeKeys.hpp>
#include <privmx/endpoint/group/keytree/TreeMath.hpp>
#include <privmx/endpoint/group/keytree/TreeWire.hpp>

using privmx::crypto::PrivateKey;
using namespace privmx::endpoint::group;
using namespace privmx::endpoint::group::keytree;

class TreeWireTestBase : public testing::Test {
protected:
    struct Member {
        std::string userId;
        PrivateKey priv;
    };

    std::vector<Member> makeMembers(std::uint32_t count) {
        std::vector<Member> members;
        for (std::uint32_t i = 0; i < count; ++i) {
            members.push_back(Member{"u" + std::to_string(i), PrivateKey::generateRandom()});
        }
        return members;
    }

    std::vector<TreeMember> publicOf(const std::vector<Member>& members) {
        std::vector<TreeMember> result;
        for (const Member& member : members) {
            result.push_back(TreeMember{member.userId, member.priv.getPublicKey()});
        }
        return result;
    }

    /** A tree-backed group, with the store that holds the builder's node keys. */
    struct Fixture {
        std::vector<Member> members;
        TreeKeyCache store;
        server::GroupTreeState tree;
        TreeGroupState state;
        PrivateKey grantKey;
        std::uint32_t epoch = 1;
    };

    std::shared_ptr<Fixture> build(std::uint32_t count, std::uint32_t epoch = 1) {
        auto fixture = std::make_shared<Fixture>();
        fixture->members = makeMembers(count);
        fixture->epoch = epoch;
        TreeKeys builder(fixture->store);
        const std::vector<TreeMember> members = publicOf(fixture->members);
        const BuildPlan plan = builder.build(members, fixture->members[0].priv);
        fixture->grantKey = plan.grantKey;
        fixture->tree = TreeWire::fromBuildPlan(plan, members);
        for (server::GroupTreeEdge& edge : fixture->tree.edges) {
            if (edge.isGrantEdge.value_or(false)) {
                edge.parentGeneration = static_cast<std::int64_t>(epoch);
            }
        }
        fixture->state = TreeWire::toRuntime(fixture->tree, epoch, plan.grantKey.getPublicKey());
        return fixture;
    }

    /** Whether the given member can climb the state to the grant key, from a store holding nothing. */
    bool canClimb(const server::GroupTreeState& tree, std::uint32_t epoch, const privmx::crypto::PublicKey& grantPub,
                  const Member& member) {
        TreeKeyCache store;
        TreeKeys tree_keys(store);
        const TreeGroupState state = TreeWire::toRuntime(tree, epoch, grantPub);
        const ClimbResult climb = tree_keys.climbToGrantKey(state, member.userId, member.priv, false);
        return climb.failure == ClimbFailure::None && climb.grantKey.has_value();
    }

    const server::GroupTreeEdge* grantEdgeOf(const server::GroupTreeState& tree) {
        for (const server::GroupTreeEdge& edge : tree.edges) {
            if (edge.isGrantEdge.value_or(false)) {
                return &edge;
            }
        }
        return nullptr;
    }

    std::size_t countUserEdges(const server::GroupTreeState& tree, const std::string& userId) {
        std::size_t count = 0;
        for (const server::GroupTreeEdge& edge : tree.edges) {
            if (edge.childKind == "user" && edge.childUserId.value_or("") == userId) {
                ++count;
            }
        }
        return count;
    }

    struct RemovalOutcome {
        server::GroupTreeState after;
        RemovalPlan plan;
    };

    RemovalOutcome removeMember(Fixture& fixture, std::uint32_t position, std::uint32_t remover) {
        TreeKeys tree(fixture.store);
        tree.setMemberKeys(publicOf(fixture.members));
        const ClimbResult climb = tree.climbToGrantKey(
            fixture.state, fixture.members[remover].userId, fixture.members[remover].priv, false
        );
        if (climb.failure != ClimbFailure::None) {
            throw std::runtime_error("the remover could not climb");
        }
        RemovalPlan plan =
            tree.planRemoval(fixture.state, fixture.members[position].userId, fixture.members[remover].priv);
        server::GroupTreeState after = TreeWire::afterRemoval(fixture.tree, plan, position);
        return RemovalOutcome{after, plan};
    }

    struct AdditionOutcome {
        server::GroupTreeState after;
        AdditionPlan plan;
        Member newcomer;
    };

    AdditionOutcome addMember(Fixture& fixture, const std::vector<TreeMember>& roster) {
        TreeKeys tree(fixture.store);
        tree.setMemberKeys(roster);
        const ClimbResult climb =
            tree.climbToGrantKey(fixture.state, fixture.members[0].userId, fixture.members[0].priv, false);
        if (climb.failure != ClimbFailure::None) {
            throw std::runtime_error("the adder could not climb");
        }
        const Member newcomer{"newcomer", PrivateKey::generateRandom()};
        std::vector<TreeMember> withNewcomer = roster;
        withNewcomer.push_back(TreeMember{newcomer.userId, newcomer.priv.getPublicKey()});
        TreeKeys planner(fixture.store);
        planner.setMemberKeys(withNewcomer);
        const AdditionPlan plan = planner.planAddition(
            fixture.state, TreeMember{newcomer.userId, newcomer.priv.getPublicKey()}, fixture.members[0].priv
        );
        server::GroupTreeState after = TreeWire::afterAddition(fixture.tree, plan, newcomer.userId);
        return AdditionOutcome{after, plan, newcomer};
    }
};

// creation

class TreeWireBuild : public TreeWireTestBase {};

TEST_F(TreeWireBuild, SeatsEveryMemberAndPublishesEveryInternalNode) {
    for (const std::uint32_t count : {1u, 2u, 3u, 4u, 5u, 8u, 9u}) {
        const auto fixture = build(count);
        EXPECT_EQ(fixture->tree.numLeaves, static_cast<std::int64_t>(count)) << "N=" << count;
        ASSERT_EQ(fixture->tree.leafAssignment.size(), count);
        for (std::uint32_t i = 0; i < count; ++i) {
            EXPECT_EQ(fixture->tree.leafAssignment[i], fixture->members[i].userId);
        }
        // Internal nodes are the odd indices below 2N-1: one keypair each, leaves carrying none because a member's own long-term key already is the leaf.
        const std::size_t expectedNodes = count == 1 ? 0 : (count - 1);
        EXPECT_EQ(fixture->tree.nodes.size(), expectedNodes) << "N=" << count;
    }
}

TEST_F(TreeWireBuild, EveryMemberCanClimbTheStateThatWasSubmitted) {
    // The functional counterpart to the shape checks: a state that looks right but nobody can climb is worse than one the server rejects.
    const auto fixture = build(5);
    for (const Member& member : fixture->members) {
        EXPECT_TRUE(canClimb(fixture->tree, fixture->epoch, fixture->grantKey.getPublicKey(), member))
            << member.userId << " cannot climb";
    }
}

TEST_F(TreeWireBuild, TheGrantEdgeCarriesTheEpochRatherThanANodeGeneration) {
    const auto fixture = build(4, 9);
    const server::GroupTreeEdge* grant = grantEdgeOf(fixture->tree);
    ASSERT_NE(grant, nullptr);
    EXPECT_EQ(grant->parentGeneration, 9);
    EXPECT_EQ(grant->childKind, "node");
    EXPECT_EQ(grant->childIndex.value_or(0), TreeMath::root(4));
}

TEST_F(TreeWireBuild, AOneMemberGroupWrapsTheGrantKeyStraightToTheMember) {
    const auto fixture = build(1);
    const server::GroupTreeEdge* grant = grantEdgeOf(fixture->tree);
    ASSERT_NE(grant, nullptr);
    EXPECT_EQ(grant->childKind, "user");
    EXPECT_EQ(grant->childUserId.value_or(""), fixture->members[0].userId);
    EXPECT_TRUE(canClimb(fixture->tree, 1, fixture->grantKey.getPublicKey(), fixture->members[0]));
}

// removal

class TreeWireRemoval : public TreeWireTestBase {};

TEST_F(TreeWireRemoval, BlanksTheLeafAndKeepsTheTreeTheSameSize) {
    auto fixture = build(8, 5);
    const RemovalOutcome outcome = removeMember(*fixture, 3, 0);
    EXPECT_EQ(outcome.after.numLeaves, fixture->tree.numLeaves) << "a removal leaves a blank, it does not compact";
    EXPECT_TRUE(outcome.after.leafAssignment[3].empty());
    EXPECT_EQ(outcome.after.leafAssignment[4], fixture->members[4].userId) << "nobody else moved";
}

TEST_F(TreeWireRemoval, ReplacesEveryRefreshedNodeExactlyOnce) {
    auto fixture = build(8, 5);
    const RemovalOutcome outcome = removeMember(*fixture, 3, 0);
    EXPECT_EQ(outcome.after.nodes.size(), fixture->tree.nodes.size()) << "nodes are refreshed, never added";
    for (const NodeRefresh& refresh : outcome.plan.pathRefresh) {
        std::size_t matching = 0;
        for (const server::GroupTreeNode& node : outcome.after.nodes) {
            if (static_cast<std::uint32_t>(node.nodeIndex) == refresh.nodeIndex) {
                ++matching;
                EXPECT_EQ(node.generation, static_cast<std::int64_t>(refresh.newGeneration));
                EXPECT_EQ(node.publicKey, refresh.newKey.getPublicKey().toBase58DER());
            }
        }
        EXPECT_EQ(matching, 1u) << "node " << refresh.nodeIndex << " appears " << matching << " times";
    }
}

TEST_F(TreeWireRemoval, SECURITY_LeavesNoEdgeAddressedToTheDepartingMember) {
    auto fixture = build(8, 5);
    const std::string departing = fixture->members[3].userId;
    const RemovalOutcome outcome = removeMember(*fixture, 3, 0);
    EXPECT_EQ(countUserEdges(outcome.after, departing), 0u);
}

TEST_F(TreeWireRemoval, SECURITY_TheRemovedMemberCanNoLongerClimb) {
    // The point of the whole operation, checked with real crypto rather than by inspecting the shape.
    auto fixture = build(8, 5);
    const RemovalOutcome outcome = removeMember(*fixture, 3, 0);
    EXPECT_FALSE(canClimb(
        outcome.after, outcome.plan.newEpoch, outcome.plan.newGrantKey.getPublicKey(), fixture->members[3]
    ));
}

TEST_F(TreeWireRemoval, EveryRemainingMemberCanStillClimb) {
    for (const std::uint32_t count : {2u, 3u, 4u, 5u, 8u}) {
        for (std::uint32_t position = 0; position < count; ++position) {
            auto fixture = build(count, 5);
            const std::uint32_t remover = position == 0 ? 1 : 0;
            const RemovalOutcome outcome = removeMember(*fixture, position, remover);
            for (std::uint32_t i = 0; i < count; ++i) {
                if (i == position) {
                    continue;
                }
                EXPECT_TRUE(canClimb(
                    outcome.after, outcome.plan.newEpoch, outcome.plan.newGrantKey.getPublicKey(),
                    fixture->members[i]
                )) << "N=" << count << " removed " << position << ", " << fixture->members[i].userId
                   << " lost access";
            }
        }
    }
}

TEST_F(TreeWireRemoval, TheGrantEdgeMovesToTheNewEpoch) {
    auto fixture = build(4, 5);
    const RemovalOutcome outcome = removeMember(*fixture, 2, 0);
    const server::GroupTreeEdge* grant = grantEdgeOf(outcome.after);
    ASSERT_NE(grant, nullptr);
    EXPECT_EQ(grant->parentGeneration, static_cast<std::int64_t>(outcome.plan.newEpoch));
    std::size_t grantEdges = 0;
    for (const server::GroupTreeEdge& edge : outcome.after.edges) {
        if (edge.isGrantEdge.value_or(false)) {
            ++grantEdges;
        }
    }
    EXPECT_EQ(grantEdges, 1u) << "the old grant edge must be gone, not merely joined by a new one";
}

TEST_F(TreeWireRemoval, EveryEdgeNamesTheCurrentGenerationOfBothEndpoints) {
    // This is the rule the server leans on to make refresh coverage automatic, so the client has to satisfy it exactly rather than approximately.
    auto fixture = build(8, 5);
    const RemovalOutcome outcome = removeMember(*fixture, 5, 0);
    std::map<std::uint32_t, std::int64_t> generations;
    for (const server::GroupTreeNode& node : outcome.after.nodes) {
        generations[static_cast<std::uint32_t>(node.nodeIndex)] = node.generation;
    }
    for (const server::GroupTreeEdge& edge : outcome.after.edges) {
        if (edge.isGrantEdge.value_or(false)) {
            continue;
        }
        const auto parent = generations.find(static_cast<std::uint32_t>(edge.parentIndex.value_or(0)));
        ASSERT_NE(parent, generations.end()) << "edge from unknown node " << edge.parentIndex.value_or(0);
        EXPECT_EQ(edge.parentGeneration, parent->second) << "stale parent generation";
        if (edge.childKind == "node") {
            const auto child = generations.find(static_cast<std::uint32_t>(edge.childIndex.value_or(0)));
            ASSERT_NE(child, generations.end());
            EXPECT_EQ(edge.childGeneration.value_or(-1), child->second) << "stale child generation";
        }
    }
}

// addition

class TreeWireAddition : public TreeWireTestBase {};

TEST_F(TreeWireAddition, SECURITY_DoesNotMoveTheEpoch) {
    // If an addition rotated the grant key, every container the group can read would go stale — one new member would force the whole group to re-key, which is the cost the grant indirection exists to avoid.
    auto fixture = build(4, 5);
    const AdditionOutcome outcome = addMember(*fixture, publicOf(fixture->members));
    const server::GroupTreeEdge* grant = grantEdgeOf(outcome.after);
    ASSERT_NE(grant, nullptr);
    EXPECT_EQ(grant->parentGeneration, 5);
}

TEST_F(TreeWireAddition, GrowthPastAFullLevelTouchesNoExistingNodeKey) {
    // Four full seats, so the newcomer is appended and their whole path is a single node that did not exist a
    // moment ago. Re-keying a path costs nothing here — there is nothing on it to re-key.
    auto fixture = build(4, 5);
    const AdditionOutcome outcome = addMember(*fixture, publicOf(fixture->members));
    for (const server::GroupTreeNode& before : fixture->tree.nodes) {
        for (const server::GroupTreeNode& after : outcome.after.nodes) {
            if (after.nodeIndex == before.nodeIndex) {
                EXPECT_EQ(after.generation, before.generation) << "node " << before.nodeIndex << " was refreshed";
                EXPECT_EQ(after.publicKey, before.publicKey);
            }
        }
    }
}

TEST_F(TreeWireAddition, TheNewcomerAndEveryoneElseCanClimb) {
    for (const std::uint32_t count : {1u, 2u, 3u, 4u, 5u, 8u}) {
        auto fixture = build(count, 5);
        const AdditionOutcome outcome = addMember(*fixture, publicOf(fixture->members));
        EXPECT_TRUE(canClimb(outcome.after, 5, fixture->grantKey.getPublicKey(), outcome.newcomer))
            << "N=" << count << ": the newcomer cannot climb";
        for (const Member& member : fixture->members) {
            EXPECT_TRUE(canClimb(outcome.after, 5, fixture->grantKey.getPublicKey(), member))
                << "N=" << count << ": " << member.userId << " lost access to an addition";
        }
    }
}

TEST_F(TreeWireAddition, GrowthThatReParentsALeafDropsTheSupersededEdge) {
    // N=3 -> 4 moves leaf 2 under a node that did not exist. The edge naming its old parent describes a topology that is gone, and a state carrying both would be rejected — and rightly, since only one of them is real.
    auto fixture = build(3, 5);
    const AdditionOutcome outcome = addMember(*fixture, publicOf(fixture->members));
    EXPECT_EQ(outcome.after.numLeaves, 4);
    EXPECT_EQ(countUserEdges(outcome.after, fixture->members[2].userId), 1u)
        << "the re-parented member must have exactly one edge, naming its new parent";
    const std::uint32_t newParent = TreeMath::parent(TreeMath::leafNode(2), 4);
    for (const server::GroupTreeEdge& edge : outcome.after.edges) {
        if (edge.childKind == "user" && edge.childUserId.value_or("") == fixture->members[2].userId) {
            EXPECT_EQ(edge.parentIndex.value_or(0), newParent);
        }
    }
}

TEST_F(TreeWireAddition, GrowthMintsANewRootAndRelinksTheGrantEdgeToIt) {
    auto fixture = build(2, 5);
    const AdditionOutcome outcome = addMember(*fixture, publicOf(fixture->members));
    ASSERT_TRUE(outcome.plan.newRoot.has_value()) << "growing from 2 to 3 leaves changes the root";
    const server::GroupTreeEdge* grant = grantEdgeOf(outcome.after);
    ASSERT_NE(grant, nullptr);
    EXPECT_EQ(grant->childIndex.value_or(0), TreeMath::root(3));
    EXPECT_EQ(grant->parentGeneration, 5) << "re-linking is not a rotation";
    std::size_t grantEdges = 0;
    for (const server::GroupTreeEdge& edge : outcome.after.edges) {
        if (edge.isGrantEdge.value_or(false)) {
            ++grantEdges;
        }
    }
    EXPECT_EQ(grantEdges, 1u);
}

TEST_F(TreeWireAddition, SeatingIntoABlankRekeysThePathAndAddsNoNode) {
    auto fixture = build(4, 5);
    const RemovalOutcome removal = removeMember(*fixture, 2, 0);
    // Continue from the post-removal state, which is where a blank comes from in the first place.
    Fixture next;
    next.members = fixture->members;
    next.members.erase(next.members.begin() + 2);
    next.epoch = removal.plan.newEpoch;
    next.grantKey = removal.plan.newGrantKey;
    next.tree = removal.after;
    next.store.putGrantKey(next.epoch, removal.plan.newGrantKey);
    for (const NodeRefresh& refresh : removal.plan.pathRefresh) {
        next.store.putNodeKey(refresh.nodeIndex, refresh.newGeneration, refresh.newKey);
    }
    next.state = TreeWire::toRuntime(next.tree, next.epoch, next.grantKey.getPublicKey());

    const AdditionOutcome outcome = addMember(next, publicOf(next.members));
    EXPECT_EQ(outcome.plan.position, 2u) << "the blank is filled before the tree grows";
    // Two nodes on the path of a four-leaf tree, two children each, plus the grant edge re-issued to the root.
    // Not one wrap: seating somebody under a node the caller cannot reach means re-keying the path to it.
    EXPECT_EQ(outcome.plan.wrapCount, 5u);
    EXPECT_EQ(outcome.after.nodes.size(), next.tree.nodes.size())
        << "the path is re-keyed in place, so no node index appears twice";
    EXPECT_TRUE(canClimb(outcome.after, next.epoch, next.grantKey.getPublicKey(), outcome.newcomer));
}
