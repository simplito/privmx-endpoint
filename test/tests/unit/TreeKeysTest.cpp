/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

/** Unit tests for the hidden key tree with real EC keys and real ECIES; no server, no docker, no network, but no crypto stubs either — every wrap is a genuine ECIES encryption and every climb a genuine decryption, because the properties under test are cryptographic ones: that a removed member cannot reach a refreshed key, and that a corrupted edge is detected rather than silently producing the wrong key. Tests named SECURITY guard confidentiality and fail silently at runtime if the guard regresses. */

#include <gtest/gtest.h>

#include <string>
#include <thread>
#include <vector>

#include <privmx/crypto/ecc/PrivateKey.hpp>

#include <privmx/endpoint/group/keytree/TreeKeyCache.hpp>
#include <privmx/endpoint/group/keytree/TreeKeyCacheRegistry.hpp>
#include <privmx/endpoint/group/keytree/TreeKeys.hpp>
#include <privmx/endpoint/group/keytree/TreeMath.hpp>

using privmx::crypto::PrivateKey;
using namespace privmx::endpoint::group::keytree;

/** Shared fixture base: a member together with the private half, and helpers to assemble tree state from a plan. */
class TreeKeysTestBase : public testing::Test {
protected:
    /** A member together with the private half, which only the test holds. */
    struct TestMember {
        std::string userId;
        PrivateKey priv;
    };

    std::vector<TestMember> makeMembers(std::uint32_t count) {
        std::vector<TestMember> members;
        for (std::uint32_t i = 0; i < count; ++i) {
            members.push_back(TestMember{"user" + std::to_string(i), PrivateKey::generateRandom()});
        }
        return members;
    }

    std::vector<TreeMember> publicOf(const std::vector<TestMember>& members) {
        std::vector<TreeMember> result;
        for (const TestMember& member : members) {
            result.push_back(TreeMember{member.userId, member.priv.getPublicKey()});
        }
        return result;
    }

    /** Assembles the state a bridge would serve after a build. */
    TreeGroupState stateFromBuild(const BuildPlan& plan, const std::vector<TestMember>& members) {
        TreeGroupState state;
        state.numLeaves = plan.numLeaves;
        for (const TestMember& member : members) {
            state.leafAssignment.push_back(member.userId);
        }
        state.nodes = plan.nodes;
        state.edges = plan.edges;
        state.epoch = 1;
        state.grantPublicKey = plan.grantKey.getPublicKey();
        return state;
    }

    /** Applies a removal plan to the state, the way the bridge would after accepting it. */
    void applyRemoval(TreeGroupState& state, const RemovalPlan& plan, const std::string& leavingUserId) {
        for (std::size_t i = 0; i < state.leafAssignment.size(); ++i) {
            if (state.leafAssignment[i].has_value() && state.leafAssignment[i].value() == leavingUserId) {
                state.leafAssignment[i] = std::nullopt;
            }
        }
        for (const NodeRefresh& refresh : plan.pathRefresh) {
            for (TreeNodeState& node : state.nodes) {
                if (node.nodeIndex == refresh.nodeIndex) {
                    node.generation = refresh.newGeneration;
                    node.publicKey = refresh.newKey.getPublicKey();
                }
            }
            // Replace this node's edges with the refreshed ones.
            std::vector<TreeEdge> kept;
            for (const TreeEdge& edge : state.edges) {
                if (edge.isGrantEdge || edge.parentIndex != refresh.nodeIndex) {
                    kept.push_back(edge);
                }
            }
            kept.insert(kept.end(), refresh.edges.begin(), refresh.edges.end());
            state.edges = kept;
        }
        std::vector<TreeEdge> withoutGrant;
        for (const TreeEdge& edge : state.edges) {
            if (!edge.isGrantEdge) {
                withoutGrant.push_back(edge);
            }
        }
        withoutGrant.push_back(plan.grantEdge);
        state.edges = withoutGrant;
        state.epoch = plan.newEpoch;
        state.grantPublicKey = plan.newGrantKey.getPublicKey();
    }
};

// wrap / unwrap primitives

class TreeKeysPrimitives : public TreeKeysTestBase {};

TEST_F(TreeKeysPrimitives, WrapRoundTripsThroughRealEcies) {
    const PrivateKey secret = PrivateKey::generateRandom();
    const PrivateKey recipient = PrivateKey::generateRandom();
    const PrivateKey signer = PrivateKey::generateRandom();

    const std::string blob = TreeKeys::wrapKey(secret, recipient.getPublicKey(), signer);
    const auto recovered = TreeKeys::unwrapKey(blob, recipient);

    ASSERT_TRUE(recovered.has_value());
    EXPECT_EQ(recovered->getPublicKey(), secret.getPublicKey());
    EXPECT_EQ(recovered->toWIF(), secret.toWIF());
}

TEST_F(TreeKeysPrimitives, WrapDoesNotOpenWithTheWrongKey) {
    const PrivateKey secret = PrivateKey::generateRandom();
    const PrivateKey recipient = PrivateKey::generateRandom();
    const PrivateKey stranger = PrivateKey::generateRandom();

    const std::string blob = TreeKeys::wrapKey(secret, recipient.getPublicKey(), recipient);
    EXPECT_FALSE(TreeKeys::unwrapKey(blob, stranger).has_value());
}

TEST_F(TreeKeysPrimitives, GarbageBlobIsRejectedNotCrashed) {
    const PrivateKey key = PrivateKey::generateRandom();
    EXPECT_FALSE(TreeKeys::unwrapKey("not-a-blob", key).has_value());
    EXPECT_FALSE(TreeKeys::unwrapKey("", key).has_value());
}

// build + climb

class TreeKeysBuild : public TreeKeysTestBase {};

TEST_F(TreeKeysBuild, CostsTwoTimesLeavesMinusOnePlusGrantEdge) {
    for (const std::uint32_t count : {1u, 2u, 3u, 4u, 5u, 8u}) {
        const std::vector<TestMember> members = makeMembers(count);
        TreeKeyCache store;
        TreeKeys keys(store);
        const BuildPlan plan = keys.build(publicOf(members), members[0].priv);
        const std::uint32_t expected = count == 1 ? 1 : 2 * (count - 1) + 1;
        EXPECT_EQ(plan.wrapCount, expected) << "count=" << count;
        EXPECT_EQ(plan.nodes.size(), count - 1) << "count=" << count;
    }
}

TEST_F(TreeKeysBuild, RejectsAnEmptyMemberList) {
    TreeKeyCache store;
    TreeKeys keys(store);
    EXPECT_THROW(keys.build({}, PrivateKey::generateRandom()), std::invalid_argument);
}

class TreeKeysClimb : public TreeKeysTestBase {};

TEST_F(TreeKeysClimb, EveryMemberReachesTheGrantKey) {
    for (const std::uint32_t count : {2u, 3u, 4u, 5u, 6u, 7u, 8u, 9u}) {
        const std::vector<TestMember> members = makeMembers(count);
        TreeKeyCache buildStore;
        TreeKeys builder(buildStore);
        const BuildPlan plan = builder.build(publicOf(members), members[0].priv);
        const TreeGroupState state = stateFromBuild(plan, members);

        for (const TestMember& member : members) {
            TreeKeyCache store;
            TreeKeys keys(store);
            const ClimbResult result = keys.climbToGrantKey(state, member.userId, member.priv);
            ASSERT_EQ(result.failure, ClimbFailure::None) << "count=" << count << " member=" << member.userId;
            ASSERT_TRUE(result.grantKey.has_value());
            EXPECT_EQ(result.grantKey->getPublicKey(), plan.grantKey.getPublicKey())
                << "count=" << count << " member=" << member.userId;
        }
    }
}

TEST_F(TreeKeysClimb, CachesEveryIntermediateKeySoASecondClimbIsFree) {
    const std::vector<TestMember> members = makeMembers(8);
    TreeKeyCache buildStore;
    TreeKeys builder(buildStore);
    const BuildPlan plan = builder.build(publicOf(members), members[0].priv);
    const TreeGroupState state = stateFromBuild(plan, members);

    TreeKeyCache store;
    TreeKeys keys(store);
    ASSERT_EQ(keys.climbToGrantKey(state, members[0].userId, members[0].priv).failure, ClimbFailure::None);
    // depth(8) == 3 nodes on the direct path, all cached on the way up.
    EXPECT_EQ(store.nodeKeyCount(), TreeMath::depth(8));

    // A second climb is served from the cached grant key and touches nothing.
    const std::size_t before = store.nodeKeyCount();
    const ClimbResult again = keys.climbToGrantKey(state, members[0].userId, members[0].priv);
    EXPECT_EQ(again.failure, ClimbFailure::None);
    EXPECT_EQ(store.nodeKeyCount(), before);
}

TEST_F(TreeKeysClimb, ANonMemberCannotClimb) {
    const std::vector<TestMember> members = makeMembers(4);
    TreeKeyCache buildStore;
    TreeKeys builder(buildStore);
    const TreeGroupState state = stateFromBuild(builder.build(publicOf(members), members[0].priv), members);

    TreeKeyCache store;
    TreeKeys keys(store);
    const PrivateKey outsider = PrivateKey::generateRandom();
    const ClimbResult result = keys.climbToGrantKey(state, "stranger", outsider);
    EXPECT_EQ(result.failure, ClimbFailure::NotAMember);
    EXPECT_FALSE(result.grantKey.has_value());
}

TEST_F(TreeKeysClimb, SingleMemberGroupClimbsStraightToTheGrantKey) {
    const std::vector<TestMember> members = makeMembers(1);
    TreeKeyCache buildStore;
    TreeKeys builder(buildStore);
    const BuildPlan plan = builder.build(publicOf(members), members[0].priv);
    const TreeGroupState state = stateFromBuild(plan, members);

    TreeKeyCache store;
    TreeKeys keys(store);
    const ClimbResult result = keys.climbToGrantKey(state, members[0].userId, members[0].priv);
    ASSERT_EQ(result.failure, ClimbFailure::None);
    EXPECT_EQ(result.grantKey->getPublicKey(), plan.grantKey.getPublicKey());
}

/** SECURITY — a corrupted edge must be detected, never allowed to yield a wrong key silently. */
TEST_F(TreeKeysClimb, SECURITY_DetectsACorruptedEdge) {
    const std::vector<TestMember> members = makeMembers(4);
    TreeKeyCache buildStore;
    TreeKeys builder(buildStore);
    TreeGroupState state = stateFromBuild(builder.build(publicOf(members), members[0].priv), members);

    // Replace the edge from member 0's leaf with a wrap of an unrelated key, correctly encrypted to them.
    const PrivateKey impostor = PrivateKey::generateRandom();
    for (TreeEdge& edge : state.edges) {
        if (!edge.isGrantEdge && edge.childKind == EdgeChildKind::User && edge.childUserId == members[0].userId) {
            edge.blob = TreeKeys::wrapKey(impostor, members[0].priv.getPublicKey(), members[0].priv);
        }
    }

    TreeKeyCache store;
    TreeKeys keys(store);
    const ClimbResult result = keys.climbToGrantKey(state, members[0].userId, members[0].priv);
    EXPECT_EQ(result.failure, ClimbFailure::Tampered);
    EXPECT_FALSE(result.grantKey.has_value());
    EXPECT_TRUE(result.tamperedNode.has_value());
    EXPECT_EQ(store.nodeKeyCount(), 0u) << "a key failing verification must never be cached";
}

TEST_F(TreeKeysClimb, ReportsAMissingEdgeDistinctlyFromTampering) {
    const std::vector<TestMember> members = makeMembers(4);
    TreeKeyCache buildStore;
    TreeKeys builder(buildStore);
    TreeGroupState state = stateFromBuild(builder.build(publicOf(members), members[0].priv), members);

    std::vector<TreeEdge> pruned;
    for (const TreeEdge& edge : state.edges) {
        const bool isOwnLeafEdge = !edge.isGrantEdge && edge.childKind == EdgeChildKind::User &&
            edge.childUserId == members[0].userId;
        if (!isOwnLeafEdge) {
            pruned.push_back(edge);
        }
    }
    state.edges = pruned;

    TreeKeyCache store;
    TreeKeys keys(store);
    EXPECT_EQ(keys.climbToGrantKey(state, members[0].userId, members[0].priv).failure, ClimbFailure::MissingEdge);
}

// removal — the property that matters

class TreeKeysRemoval : public TreeKeysTestBase {};

TEST_F(TreeKeysRemoval, CostsTwoTimesDepthMinusOnePlusGrantEdge) {
    const std::vector<TestMember> members = makeMembers(8);
    TreeKeyCache store;
    TreeKeys keys(store);
    const BuildPlan plan = keys.build(publicOf(members), members[0].priv);
    const TreeGroupState state = stateFromBuild(plan, members);

    keys.setMemberKeys(publicOf(members));
    const RemovalPlan removal = keys.planRemoval(state, members[0].userId, members[1].priv);

    EXPECT_EQ(removal.pathRefresh.size(), TreeMath::depth(8));
    // 2*depth - 1 tree wraps (bottom node skips the blanked leaf) + 1 grant edge
    EXPECT_EQ(removal.wrapCount, 2 * TreeMath::depth(8) - 1 + 1);
    EXPECT_EQ(removal.newEpoch, 2u);
}

TEST_F(TreeKeysRemoval, RefreshesExactlyTheDirectPath) {
    const std::vector<TestMember> members = makeMembers(8);
    TreeKeyCache store;
    TreeKeys keys(store);
    const TreeGroupState state = stateFromBuild(keys.build(publicOf(members), members[0].priv), members);
    keys.setMemberKeys(publicOf(members));

    const RemovalPlan removal = keys.planRemoval(state, members[2].userId, members[0].priv);
    std::vector<std::uint32_t> refreshed;
    for (const NodeRefresh& refresh : removal.pathRefresh) {
        refreshed.push_back(refresh.nodeIndex);
    }
    EXPECT_EQ(refreshed, TreeMath::directPath(2, 8));
}

TEST_F(TreeKeysRemoval, MintsIndependentKeysNotDerivedFromTheOldOnes) {
    const std::vector<TestMember> members = makeMembers(4);
    TreeKeyCache store;
    TreeKeys keys(store);
    const BuildPlan plan = keys.build(publicOf(members), members[0].priv);
    const TreeGroupState state = stateFromBuild(plan, members);
    keys.setMemberKeys(publicOf(members));

    const RemovalPlan removal = keys.planRemoval(state, members[0].userId, members[1].priv);
    for (const NodeRefresh& refresh : removal.pathRefresh) {
        for (const auto& [nodeIndex, oldKey] : plan.nodeKeys) {
            if (nodeIndex == refresh.nodeIndex) {
                EXPECT_NE(refresh.newKey.toWIF(), oldKey.toWIF()) << "node " << nodeIndex << " must get a fresh key";
            }
        }
    }
    EXPECT_NE(removal.newGrantKey.toWIF(), plan.grantKey.toWIF());
}

TEST_F(TreeKeysRemoval, RejectsRemovingTheOnlyMember) {
    const std::vector<TestMember> members = makeMembers(1);
    TreeKeyCache store;
    TreeKeys keys(store);
    const TreeGroupState state = stateFromBuild(keys.build(publicOf(members), members[0].priv), members);
    keys.setMemberKeys(publicOf(members));
    EXPECT_THROW(keys.planRemoval(state, members[0].userId, members[0].priv), std::invalid_argument);
}

TEST_F(TreeKeysRemoval, RejectsANonMember) {
    const std::vector<TestMember> members = makeMembers(4);
    TreeKeyCache store;
    TreeKeys keys(store);
    const TreeGroupState state = stateFromBuild(keys.build(publicOf(members), members[0].priv), members);
    keys.setMemberKeys(publicOf(members));
    EXPECT_THROW(keys.planRemoval(state, "stranger", members[0].priv), std::invalid_argument);
}

/** SECURITY — the whole point of the construction: after a removal every surviving member must reach the new grant key, and the removed member must not. */
TEST_F(TreeKeysRemoval, SECURITY_SurvivorsReachTheNewKeyAndTheRemovedMemberDoesNot) {
    for (const std::uint32_t count : {2u, 4u, 5u, 8u}) {
        const std::vector<TestMember> members = makeMembers(count);
        TreeKeyCache ownerStore;
        TreeKeys owner(ownerStore);
        const BuildPlan plan = owner.build(publicOf(members), members[0].priv);
        TreeGroupState state = stateFromBuild(plan, members);

        // The remover must hold the path keys, so it climbs first — as a real client would.
        ASSERT_EQ(owner.climbToGrantKey(state, members[0].userId, members[0].priv).failure, ClimbFailure::None);
        owner.setMemberKeys(publicOf(members));

        const std::string leaving = members[count - 1].userId;
        const RemovalPlan removal = owner.planRemoval(state, leaving, members[0].priv);
        applyRemoval(state, removal, leaving);

        for (const TestMember& member : members) {
            TreeKeyCache store;
            TreeKeys keys(store);
            const ClimbResult result = keys.climbToGrantKey(state, member.userId, member.priv);
            if (member.userId == leaving) {
                EXPECT_NE(result.failure, ClimbFailure::None)
                    << "count=" << count << ": removed member must NOT reach the new grant key";
                EXPECT_FALSE(result.grantKey.has_value());
            } else {
                ASSERT_EQ(result.failure, ClimbFailure::None)
                    << "count=" << count << " member=" << member.userId << " must survive the removal";
                EXPECT_EQ(result.grantKey->getPublicKey(), removal.newGrantKey.getPublicKey());
            }
        }
    }
}

/** SECURITY — the removed member's old keys must not open anything in the new epoch. */
TEST_F(TreeKeysRemoval, SECURITY_OldPathKeysDoNotOpenRefreshedEdges) {
    const std::vector<TestMember> members = makeMembers(8);
    TreeKeyCache ownerStore;
    TreeKeys owner(ownerStore);
    const BuildPlan plan = owner.build(publicOf(members), members[0].priv);
    TreeGroupState state = stateFromBuild(plan, members);
    ASSERT_EQ(owner.climbToGrantKey(state, members[0].userId, members[0].priv).failure, ClimbFailure::None);
    owner.setMemberKeys(publicOf(members));

    // Capture what the leaving member held before the removal.
    TreeKeyCache leaverStore;
    TreeKeys leaver(leaverStore);
    ASSERT_EQ(leaver.climbToGrantKey(state, members[7].userId, members[7].priv).failure, ClimbFailure::None);
    const std::vector<std::uint32_t> hadPath = TreeMath::directPath(7, 8);
    std::vector<PrivateKey> heldKeys;
    for (const std::uint32_t node : hadPath) {
        const auto key = leaverStore.getNodeKey(node, 0);
        ASSERT_TRUE(key.has_value()) << "node " << node;
        heldKeys.push_back(key.value());
    }

    const RemovalPlan removal = owner.planRemoval(state, members[7].userId, members[0].priv);

    // Not one of the keys the leaver holds may open any refreshed edge.
    for (const NodeRefresh& refresh : removal.pathRefresh) {
        for (const TreeEdge& edge : refresh.edges) {
            for (const PrivateKey& held : heldKeys) {
                EXPECT_FALSE(TreeKeys::unwrapKey(edge.blob, held).has_value())
                    << "a stale key opened a refreshed edge at node " << refresh.nodeIndex;
            }
            EXPECT_FALSE(TreeKeys::unwrapKey(edge.blob, members[7].priv).has_value())
                << "the leaver's own key opened a refreshed edge";
        }
    }
    EXPECT_FALSE(TreeKeys::unwrapKey(removal.grantEdge.blob, members[7].priv).has_value());
}

/** SECURITY — collusion: two members removed at different times must not pool their way in. */
TEST_F(TreeKeysRemoval, SECURITY_CollusionBetweenTwoRemovedMembersYieldsNothing) {
    const std::vector<TestMember> members = makeMembers(8);
    TreeKeyCache ownerStore;
    TreeKeys owner(ownerStore);
    TreeGroupState state = stateFromBuild(owner.build(publicOf(members), members[0].priv), members);
    ASSERT_EQ(owner.climbToGrantKey(state, members[0].userId, members[0].priv).failure, ClimbFailure::None);
    owner.setMemberKeys(publicOf(members));

    // Remove member 7, then member 6 — different subtrees, different epochs.
    const RemovalPlan first = owner.planRemoval(state, members[7].userId, members[0].priv);
    applyRemoval(state, first, members[7].userId);
    ownerStore.clear();
    ASSERT_EQ(owner.climbToGrantKey(state, members[0].userId, members[0].priv).failure, ClimbFailure::None);
    const RemovalPlan second = owner.planRemoval(state, members[6].userId, members[0].priv);
    applyRemoval(state, second, members[6].userId);

    // Neither alone nor together can they climb in the current epoch.
    for (const std::uint32_t idx : {6u, 7u}) {
        TreeKeyCache store;
        TreeKeys keys(store);
        EXPECT_NE(keys.climbToGrantKey(state, members[idx].userId, members[idx].priv).failure, ClimbFailure::None)
            << "member " << idx;
    }
    // Pooling: every edge in the current state, against both long-term keys.
    for (const TreeEdge& edge : state.edges) {
        for (const std::uint32_t idx : {6u, 7u}) {
            const auto opened = TreeKeys::unwrapKey(edge.blob, members[idx].priv);
            if (opened.has_value()) {
                // Only their own (now blanked) leaf edges could open, and those were removed; assert none remain.
                FAIL() << "removed member " << idx << " opened an edge in the current epoch";
            }
        }
    }
}

// addition

class TreeKeysAddition : public TreeKeysTestBase {};

TEST_F(TreeKeysAddition, FillingABlankCostsOneWrapAndDoesNotRotate) {
    const std::vector<TestMember> members = makeMembers(4);
    TreeKeyCache ownerStore;
    TreeKeys owner(ownerStore);
    const BuildPlan plan = owner.build(publicOf(members), members[0].priv);
    TreeGroupState state = stateFromBuild(plan, members);
    ASSERT_EQ(owner.climbToGrantKey(state, members[0].userId, members[0].priv).failure, ClimbFailure::None);
    owner.setMemberKeys(publicOf(members));

    // Remove member 1, leaving a blank at position 1.
    const RemovalPlan removal = owner.planRemoval(state, members[1].userId, members[0].priv);
    applyRemoval(state, removal, members[1].userId);
    ownerStore.clear();
    ASSERT_EQ(owner.climbToGrantKey(state, members[0].userId, members[0].priv).failure, ClimbFailure::None);

    const TestMember newcomer{"newcomer", PrivateKey::generateRandom()};
    const AdditionPlan addition = owner.planAddition(
        state, TreeMember{newcomer.userId, newcomer.priv.getPublicKey()}, members[0].priv
    );

    EXPECT_EQ(addition.position, 1u) << "must reuse the blank rather than append";
    EXPECT_EQ(addition.wrapCount, 1u) << "filling a blank is one wrap";
    EXPECT_EQ(addition.newNumLeaves, state.numLeaves) << "topology unchanged";
    EXPECT_FALSE(addition.newRoot.has_value());

    // The newcomer can now climb: the epoch and grant key are untouched by the addition.
    state.leafAssignment[1] = newcomer.userId;
    state.edges.insert(state.edges.end(), addition.edges.begin(), addition.edges.end());
    TreeKeyCache store;
    TreeKeys keys(store);
    const ClimbResult result = keys.climbToGrantKey(state, newcomer.userId, newcomer.priv);
    ASSERT_EQ(result.failure, ClimbFailure::None);
    EXPECT_EQ(result.grantKey->getPublicKey(), removal.newGrantKey.getPublicKey())
        << "an addition must not change the grant key";
}

TEST_F(TreeKeysAddition, ChoosesTheLowestBlankThenAppends) {
    TreeGroupState state;
    state.numLeaves = 4;
    state.leafAssignment = {std::string("a"), std::nullopt, std::string("c"), std::nullopt};
    EXPECT_EQ(TreeKeys::choosePosition(state), 1u);

    state.leafAssignment = {std::string("a"), std::string("b"), std::string("c"), std::string("d")};
    EXPECT_EQ(TreeKeys::choosePosition(state), 4u) << "no blanks: append";
}

TEST_F(TreeKeysAddition, RequiresTheParentKeyAndSaysSo) {
    const std::vector<TestMember> members = makeMembers(4);
    TreeKeyCache ownerStore;
    TreeKeys owner(ownerStore);
    TreeGroupState state = stateFromBuild(owner.build(publicOf(members), members[0].priv), members);
    state.leafAssignment[1] = std::nullopt;

    // A fresh store holds no node keys, so the addition cannot be prepared without climbing first.
    TreeKeyCache emptyStore;
    TreeKeys keys(emptyStore);
    const TestMember newcomer{"newcomer", PrivateKey::generateRandom()};
    EXPECT_THROW(
        keys.planAddition(state, TreeMember{newcomer.userId, newcomer.priv.getPublicKey()}, members[0].priv),
        std::invalid_argument
    );
}

TEST_F(TreeKeysAddition, SECURITY_RejectsANodeKeyThatDoesNotMatchThePublishedOne) {
    const std::vector<TestMember> members = makeMembers(4);
    TreeKeyCache ownerStore;
    TreeKeys owner(ownerStore);
    TreeGroupState state = stateFromBuild(owner.build(publicOf(members), members[0].priv), members);
    state.leafAssignment[1] = std::nullopt;

    // A key for the right (node, generation) slot, but not the key the state publishes for that node — the shape a cross-group collision used to produce. Wrapping it would seat the newcomer on an edge nobody can open, and their failure would surface much later as `Tampered`.
    const std::uint32_t parentIndex = TreeMath::parent(TreeMath::leafNode(1), state.numLeaves);
    TreeKeyCache poisoned;
    for (const TreeNodeState& node : state.nodes) {
        if (node.nodeIndex == parentIndex) {
            poisoned.putNodeKey(parentIndex, node.generation, PrivateKey::generateRandom());
        }
    }

    TreeKeys keys(poisoned);
    const TestMember newcomer{"newcomer", PrivateKey::generateRandom()};
    EXPECT_THROW(
        keys.planAddition(state, TreeMember{newcomer.userId, newcomer.priv.getPublicKey()}, members[0].priv),
        std::invalid_argument
    );
}

// TreeKeyCache — the cache itself

class TreeKeyCacheBasics : public testing::Test {};

TEST_F(TreeKeyCacheBasics, PutOverwritesInPlace) {
    const PrivateKey first = PrivateKey::generateRandom();
    const PrivateKey second = PrivateKey::generateRandom();

    TreeKeyCache store;
    store.putNodeKey(1, 0, first);
    store.putNodeKey(1, 0, second);
    ASSERT_TRUE(store.getNodeKey(1, 0).has_value());
    EXPECT_EQ(store.getNodeKey(1, 0)->toWIF(), second.toWIF());
    EXPECT_EQ(store.nodeKeyCount(), 1u) << "same slot, not a second entry";

    store.putGrantKey(1, first);
    store.putGrantKey(1, second);
    ASSERT_TRUE(store.getGrantKey(1).has_value());
    EXPECT_EQ(store.getGrantKey(1)->toWIF(), second.toWIF());
}

TEST_F(TreeKeyCacheBasics, GenerationIsPartOfTheNodeKeyIdentity) {
    const PrivateKey oldKey = PrivateKey::generateRandom();
    const PrivateKey refreshed = PrivateKey::generateRandom();

    TreeKeyCache store;
    store.putNodeKey(1, 0, oldKey);
    store.putNodeKey(1, 1, refreshed);
    EXPECT_EQ(store.nodeKeyCount(), 2u) << "a refresh makes the old key a different key";
    EXPECT_EQ(store.getNodeKey(1, 0)->toWIF(), oldKey.toWIF());
    EXPECT_EQ(store.getNodeKey(1, 1)->toWIF(), refreshed.toWIF());
}

TEST_F(TreeKeyCacheBasics, HighestGrantEpochReportsTheLargestCached) {
    TreeKeyCache store;
    EXPECT_FALSE(store.highestGrantEpoch().has_value());

    store.putGrantKey(1, PrivateKey::generateRandom());
    store.putGrantKey(7, PrivateKey::generateRandom());
    store.putGrantKey(3, PrivateKey::generateRandom());
    ASSERT_TRUE(store.highestGrantEpoch().has_value());
    EXPECT_EQ(store.highestGrantEpoch().value(), 7u) << "largest, not last written";
}

TEST_F(TreeKeyCacheBasics, ClearNodeKeysKeepsGrantKeys) {
    TreeKeyCache store;
    store.putNodeKey(1, 0, PrivateKey::generateRandom());
    store.putGrantKey(4, PrivateKey::generateRandom());

    store.clearNodeKeys();
    EXPECT_EQ(store.nodeKeyCount(), 0u);
    // A removal kills the node generations but not the epoch keys: `buildRungs` still needs the older ones.
    EXPECT_TRUE(store.getGrantKey(4).has_value());
}

TEST_F(TreeKeyCacheBasics, ForgetGrantKeyRemovesOnlyThatEpoch) {
    TreeKeyCache store;
    store.putGrantKey(1, PrivateKey::generateRandom());
    store.putGrantKey(2, PrivateKey::generateRandom());
    store.putNodeKey(1, 0, PrivateKey::generateRandom());

    store.forgetGrantKey(1);
    EXPECT_FALSE(store.getGrantKey(1).has_value());
    EXPECT_TRUE(store.getGrantKey(2).has_value());
    EXPECT_EQ(store.nodeKeyCount(), 1u);
}

TEST_F(TreeKeyCacheBasics, ConcurrentReadersAndWritersDoNotRace) {
    // Worth most under TSan; without a sanitiser this is a smoke test that the locking does not deadlock.
    TreeKeyCache store;
    const PrivateKey anchor = PrivateKey::generateRandom();
    store.putGrantKey(99, anchor);

    std::vector<std::thread> threads;
    for (std::uint32_t t = 0; t < 4; ++t) {
        threads.emplace_back([&store, t]() {
            for (std::uint32_t i = 0; i < 200; ++i) {
                store.putNodeKey(t, i, PrivateKey::generateRandom());
                (void)store.getNodeKey(t, i);
                (void)store.getGrantKey(99);
                (void)store.highestGrantEpoch();
                if (i % 50 == 0) {
                    store.clearNodeKeys();
                }
            }
        });
    }
    for (std::thread& thread : threads) {
        thread.join();
    }
    ASSERT_TRUE(store.getGrantKey(99).has_value()) << "clearNodeKeys must never touch the grant keys";
    EXPECT_EQ(store.getGrantKey(99)->toWIF(), anchor.toWIF());
}

// TreeKeyCacheRegistry — one store per group

class TreeKeyCacheRegistryTest : public testing::Test {};

TEST_F(TreeKeyCacheRegistryTest, SECURITY_GivesEachGroupItsOwnStore) {
    // The whole bug in one assertion: two groups both at epoch 1, sharing one registry, must not see each other's grant key. Node indices and epochs are small integers that every group reuses from 1.
    const PrivateKey keyA = PrivateKey::generateRandom();
    const PrivateKey keyB = PrivateKey::generateRandom();

    TreeKeyCacheRegistry registry;
    registry.get("groupA")->putGrantKey(1, keyA);
    registry.get("groupB")->putGrantKey(1, keyB);

    EXPECT_EQ(registry.get("groupA")->getGrantKey(1)->toWIF(), keyA.toWIF());
    EXPECT_EQ(registry.get("groupB")->getGrantKey(1)->toWIF(), keyB.toWIF());
    EXPECT_NE(registry.get("groupA")->getGrantKey(1)->toWIF(), keyB.toWIF());

    registry.get("groupA")->putNodeKey(1, 0, keyA);
    registry.get("groupB")->putNodeKey(1, 0, keyB);
    EXPECT_EQ(registry.get("groupA")->getNodeKey(1, 0)->toWIF(), keyA.toWIF());
    EXPECT_EQ(registry.get("groupB")->getNodeKey(1, 0)->toWIF(), keyB.toWIF());
}

TEST_F(TreeKeyCacheRegistryTest, ReturnsTheSameStoreForTheSameGroup) {
    TreeKeyCacheRegistry registry;
    EXPECT_EQ(registry.get("g").get(), registry.get("g").get());
    EXPECT_EQ(registry.groupCount(), 1u);
}

TEST_F(TreeKeyCacheRegistryTest, DropDetachesWithoutInvalidatingAHeldHandle) {
    TreeKeyCacheRegistry registry;
    const auto held = registry.get("g");
    held->putGrantKey(1, PrivateKey::generateRandom());

    registry.drop("g");
    // The handle a mid-flight climb is holding stays alive and writable — it is simply nobody else's any more.
    EXPECT_NO_THROW(held->putGrantKey(2, PrivateKey::generateRandom()));
    EXPECT_TRUE(held->getGrantKey(1).has_value());

    const auto fresh = registry.get("g");
    EXPECT_NE(fresh.get(), held.get()) << "the group starts over with an empty store";
    EXPECT_FALSE(fresh->getGrantKey(1).has_value());
}

TEST_F(TreeKeyCacheRegistryTest, DropIsScopedToOneGroup) {
    TreeKeyCacheRegistry registry;
    const auto storeB = registry.get("groupB");
    storeB->putGrantKey(1, PrivateKey::generateRandom());
    registry.get("groupA")->putGrantKey(1, PrivateKey::generateRandom());

    registry.drop("groupA");
    EXPECT_EQ(registry.get("groupB").get(), storeB.get()) << "same store, untouched";
    EXPECT_TRUE(registry.get("groupB")->getGrantKey(1).has_value());
}

TEST_F(TreeKeyCacheRegistryTest, DropAllClearsEveryGroup) {
    TreeKeyCacheRegistry registry;
    registry.get("a")->putGrantKey(1, PrivateKey::generateRandom());
    registry.get("b")->putGrantKey(1, PrivateKey::generateRandom());
    ASSERT_EQ(registry.groupCount(), 2u);

    registry.dropAll();
    EXPECT_EQ(registry.groupCount(), 0u);
    EXPECT_FALSE(registry.get("a")->getGrantKey(1).has_value());
}

TEST_F(TreeKeyCacheRegistryTest, ConcurrentGetOfTheSameGroupYieldsOneStore) {
    // Get-or-create has to be atomic: two stores for one group means one of them silently absorbs climbs nobody ever reads back.
    TreeKeyCacheRegistry registry;
    std::vector<std::thread> threads;
    std::vector<TreeKeyCache*> seen(8, nullptr);
    for (std::size_t t = 0; t < seen.size(); ++t) {
        threads.emplace_back([&registry, &seen, t]() { seen[t] = registry.get("g").get(); });
    }
    for (std::thread& thread : threads) {
        thread.join();
    }
    for (const TreeKeyCache* store : seen) {
        EXPECT_EQ(store, seen.front());
    }
    EXPECT_EQ(registry.groupCount(), 1u);
}

// The cache-hit path must verify, not just hit

TEST_F(TreeKeysClimb, SECURITY_ACachedGrantKeyThatDoesNotMatchThePublishedOneIsNotServed) {
    const std::vector<TestMember> members = makeMembers(4);
    TreeKeyCache buildStore;
    TreeKeys builder(buildStore);
    const BuildPlan plan = builder.build(publicOf(members), members[0].priv);
    const TreeGroupState state = stateFromBuild(plan, members);

    // Exactly what a cross-group collision looked like: some other group's epoch-1 key sitting in this slot.
    TreeKeyCache store;
    store.putGrantKey(state.epoch, PrivateKey::generateRandom());

    TreeKeys keys(store);
    const ClimbResult result = keys.climbToGrantKey(state, members[0].userId, members[0].priv);

    ASSERT_EQ(result.failure, ClimbFailure::None) << "a stale cache entry self-heals; it is not an attack";
    ASSERT_TRUE(result.grantKey.has_value());
    EXPECT_EQ(result.grantKey->getPublicKey(), plan.grantKey.getPublicKey())
        << "the impostor must be ignored and the real key recovered by climbing";
    ASSERT_TRUE(store.getGrantKey(state.epoch).has_value());
    EXPECT_EQ(store.getGrantKey(state.epoch)->toWIF(), plan.grantKey.toWIF())
        << "the impostor must be evicted, not merely bypassed";
}

TEST_F(TreeKeysClimb, AMatchingCachedGrantKeyStillShortCircuitsTheWalk) {
    const std::vector<TestMember> members = makeMembers(8);
    TreeKeyCache buildStore;
    TreeKeys builder(buildStore);
    const BuildPlan plan = builder.build(publicOf(members), members[0].priv);
    const TreeGroupState state = stateFromBuild(plan, members);

    TreeKeyCache store;
    TreeKeys keys(store);
    ASSERT_EQ(keys.climbToGrantKey(state, members[0].userId, members[0].priv).failure, ClimbFailure::None);

    // Drop the node keys but keep the grant key: if the second climb really short-circuits, it recovers no node key on the way and the count stays at zero. Counting equality alone would also pass if it re-walked.
    store.clearNodeKeys();
    const ClimbResult again = keys.climbToGrantKey(state, members[0].userId, members[0].priv);
    EXPECT_EQ(again.failure, ClimbFailure::None);
    EXPECT_EQ(store.nodeKeyCount(), 0u) << "verification must not cost the short-circuit";
}

TEST_F(TreeKeysClimb, TwoTreesAtTheSameEpochDoNotAliasThroughOneStore) {
    // The unscoped-cache bug, reproduced at the climb level: two independent groups, both epoch 1. Even sharing a store, the verification on the hit path keeps each climb honest.
    const std::vector<TestMember> membersA = makeMembers(4);
    const std::vector<TestMember> membersB = makeMembers(4);
    TreeKeyCache buildStoreA, buildStoreB;
    TreeKeys builderA(buildStoreA), builderB(buildStoreB);
    const BuildPlan planA = builderA.build(publicOf(membersA), membersA[0].priv);
    const BuildPlan planB = builderB.build(publicOf(membersB), membersB[0].priv);
    const TreeGroupState stateA = stateFromBuild(planA, membersA);
    const TreeGroupState stateB = stateFromBuild(planB, membersB);
    ASSERT_EQ(stateA.epoch, stateB.epoch);
    ASSERT_NE(planA.grantKey.toWIF(), planB.grantKey.toWIF());

    TreeKeyCache shared;
    TreeKeys keys(shared);
    const ClimbResult a = keys.climbToGrantKey(stateA, membersA[0].userId, membersA[0].priv);
    ASSERT_EQ(a.failure, ClimbFailure::None);
    EXPECT_EQ(a.grantKey->getPublicKey(), planA.grantKey.getPublicKey());

    const ClimbResult b = keys.climbToGrantKey(stateB, membersB[0].userId, membersB[0].priv);
    ASSERT_EQ(b.failure, ClimbFailure::None);
    EXPECT_EQ(b.grantKey->getPublicKey(), planB.grantKey.getPublicKey())
        << "group B must not be handed group A's grant key";
}
