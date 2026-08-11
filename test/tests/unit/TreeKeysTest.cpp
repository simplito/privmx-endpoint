/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

/**
 * Unit tests for the hidden key tree with **real EC keys and real ECIES**.
 *
 * No server, no docker, no network — but no crypto stubs either: every wrap is a genuine ECIES encryption and
 * every climb a genuine decryption. That matters, because the properties under test are cryptographic ones:
 * that a removed member cannot reach a refreshed key, and that a corrupted edge is detected rather than
 * silently producing the wrong key.
 *
 * Tests named SECURITY guard confidentiality and fail silently at runtime if the guard regresses.
 */

#include <gtest/gtest.h>

#include <string>
#include <vector>

#include <privmx/crypto/ecc/PrivateKey.hpp>

#include <privmx/endpoint/group/keytree/TreeKeys.hpp>
#include <privmx/endpoint/group/keytree/TreeMath.hpp>

using privmx::crypto::PrivateKey;
using namespace privmx::endpoint::group::keytree;

namespace {

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
                node.publicKeyBase58 = refresh.newKey.getPublicKey().toBase58DER();
                node.parsedCache.reset();
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

} // namespace

// ─────────────────────────────────────────────────────────────────────────────
// wrap / unwrap primitives
// ─────────────────────────────────────────────────────────────────────────────

TEST(TreeKeysPrimitives, WrapRoundTripsThroughRealEcies) {
    const PrivateKey secret = PrivateKey::generateRandom();
    const PrivateKey recipient = PrivateKey::generateRandom();
    const PrivateKey signer = PrivateKey::generateRandom();

    const std::string blob = TreeKeys::wrapKey(secret, recipient.getPublicKey(), signer);
    const auto recovered = TreeKeys::unwrapKey(blob, recipient);

    ASSERT_TRUE(recovered.has_value());
    EXPECT_EQ(recovered->getPublicKey(), secret.getPublicKey());
    EXPECT_EQ(recovered->toWIF(), secret.toWIF());
}

TEST(TreeKeysPrimitives, WrapDoesNotOpenWithTheWrongKey) {
    const PrivateKey secret = PrivateKey::generateRandom();
    const PrivateKey recipient = PrivateKey::generateRandom();
    const PrivateKey stranger = PrivateKey::generateRandom();

    const std::string blob = TreeKeys::wrapKey(secret, recipient.getPublicKey(), recipient);
    EXPECT_FALSE(TreeKeys::unwrapKey(blob, stranger).has_value());
}

TEST(TreeKeysPrimitives, GarbageBlobIsRejectedNotCrashed) {
    const PrivateKey key = PrivateKey::generateRandom();
    EXPECT_FALSE(TreeKeys::unwrapKey("not-a-blob", key).has_value());
    EXPECT_FALSE(TreeKeys::unwrapKey("", key).has_value());
}

// ─────────────────────────────────────────────────────────────────────────────
// build + climb
// ─────────────────────────────────────────────────────────────────────────────

TEST(TreeKeysBuild, CostsTwoTimesLeavesMinusOnePlusGrantEdge) {
    for (const std::uint32_t count : {1u, 2u, 3u, 4u, 5u, 8u}) {
        const std::vector<TestMember> members = makeMembers(count);
        TreeKeyStore store;
        TreeKeys keys(store);
        const BuildPlan plan = keys.build(publicOf(members), members[0].priv);
        const std::uint32_t expected = count == 1 ? 1 : 2 * (count - 1) + 1;
        EXPECT_EQ(plan.wrapCount, expected) << "count=" << count;
        EXPECT_EQ(plan.nodes.size(), count - 1) << "count=" << count;
    }
}

TEST(TreeKeysBuild, RejectsAnEmptyMemberList) {
    TreeKeyStore store;
    TreeKeys keys(store);
    EXPECT_THROW(keys.build({}, PrivateKey::generateRandom()), std::invalid_argument);
}

TEST(TreeKeysClimb, EveryMemberReachesTheGrantKey) {
    for (const std::uint32_t count : {2u, 3u, 4u, 5u, 6u, 7u, 8u, 9u}) {
        const std::vector<TestMember> members = makeMembers(count);
        TreeKeyStore buildStore;
        TreeKeys builder(buildStore);
        const BuildPlan plan = builder.build(publicOf(members), members[0].priv);
        const TreeGroupState state = stateFromBuild(plan, members);

        for (const TestMember& member : members) {
            TreeKeyStore store;
            TreeKeys keys(store);
            const ClimbResult result = keys.climbToGrantKey(state, member.userId, member.priv);
            ASSERT_EQ(result.failure, ClimbFailure::None) << "count=" << count << " member=" << member.userId;
            ASSERT_TRUE(result.grantKey.has_value());
            EXPECT_EQ(result.grantKey->getPublicKey(), plan.grantKey.getPublicKey())
                << "count=" << count << " member=" << member.userId;
        }
    }
}

TEST(TreeKeysClimb, CachesEveryIntermediateKeySoASecondClimbIsFree) {
    const std::vector<TestMember> members = makeMembers(8);
    TreeKeyStore buildStore;
    TreeKeys builder(buildStore);
    const BuildPlan plan = builder.build(publicOf(members), members[0].priv);
    const TreeGroupState state = stateFromBuild(plan, members);

    TreeKeyStore store;
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

TEST(TreeKeysClimb, ANonMemberCannotClimb) {
    const std::vector<TestMember> members = makeMembers(4);
    TreeKeyStore buildStore;
    TreeKeys builder(buildStore);
    const TreeGroupState state = stateFromBuild(builder.build(publicOf(members), members[0].priv), members);

    TreeKeyStore store;
    TreeKeys keys(store);
    const PrivateKey outsider = PrivateKey::generateRandom();
    const ClimbResult result = keys.climbToGrantKey(state, "stranger", outsider);
    EXPECT_EQ(result.failure, ClimbFailure::NotAMember);
    EXPECT_FALSE(result.grantKey.has_value());
}

TEST(TreeKeysClimb, SingleMemberGroupClimbsStraightToTheGrantKey) {
    const std::vector<TestMember> members = makeMembers(1);
    TreeKeyStore buildStore;
    TreeKeys builder(buildStore);
    const BuildPlan plan = builder.build(publicOf(members), members[0].priv);
    const TreeGroupState state = stateFromBuild(plan, members);

    TreeKeyStore store;
    TreeKeys keys(store);
    const ClimbResult result = keys.climbToGrantKey(state, members[0].userId, members[0].priv);
    ASSERT_EQ(result.failure, ClimbFailure::None);
    EXPECT_EQ(result.grantKey->getPublicKey(), plan.grantKey.getPublicKey());
}

/** SECURITY — a corrupted edge must be detected, never allowed to yield a wrong key silently. */
TEST(TreeKeysClimb, SECURITY_DetectsACorruptedEdge) {
    const std::vector<TestMember> members = makeMembers(4);
    TreeKeyStore buildStore;
    TreeKeys builder(buildStore);
    TreeGroupState state = stateFromBuild(builder.build(publicOf(members), members[0].priv), members);

    // Replace the edge from member 0's leaf with a wrap of an unrelated key, correctly encrypted to them.
    const PrivateKey impostor = PrivateKey::generateRandom();
    for (TreeEdge& edge : state.edges) {
        if (!edge.isGrantEdge && edge.childKind == EdgeChildKind::User && edge.childUserId == members[0].userId) {
            edge.blob = TreeKeys::wrapKey(impostor, members[0].priv.getPublicKey(), members[0].priv);
        }
    }

    TreeKeyStore store;
    TreeKeys keys(store);
    const ClimbResult result = keys.climbToGrantKey(state, members[0].userId, members[0].priv);
    EXPECT_EQ(result.failure, ClimbFailure::Tampered);
    EXPECT_FALSE(result.grantKey.has_value());
    EXPECT_TRUE(result.tamperedNode.has_value());
    EXPECT_EQ(store.nodeKeyCount(), 0u) << "a key failing verification must never be cached";
}

TEST(TreeKeysClimb, ReportsAMissingEdgeDistinctlyFromTampering) {
    const std::vector<TestMember> members = makeMembers(4);
    TreeKeyStore buildStore;
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

    TreeKeyStore store;
    TreeKeys keys(store);
    EXPECT_EQ(keys.climbToGrantKey(state, members[0].userId, members[0].priv).failure, ClimbFailure::MissingEdge);
}

// ─────────────────────────────────────────────────────────────────────────────
// removal — the property that matters
// ─────────────────────────────────────────────────────────────────────────────

TEST(TreeKeysRemoval, CostsTwoTimesDepthMinusOnePlusGrantEdge) {
    const std::vector<TestMember> members = makeMembers(8);
    TreeKeyStore store;
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

TEST(TreeKeysRemoval, RefreshesExactlyTheDirectPath) {
    const std::vector<TestMember> members = makeMembers(8);
    TreeKeyStore store;
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

TEST(TreeKeysRemoval, MintsIndependentKeysNotDerivedFromTheOldOnes) {
    const std::vector<TestMember> members = makeMembers(4);
    TreeKeyStore store;
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

TEST(TreeKeysRemoval, RejectsRemovingTheOnlyMember) {
    const std::vector<TestMember> members = makeMembers(1);
    TreeKeyStore store;
    TreeKeys keys(store);
    const TreeGroupState state = stateFromBuild(keys.build(publicOf(members), members[0].priv), members);
    keys.setMemberKeys(publicOf(members));
    EXPECT_THROW(keys.planRemoval(state, members[0].userId, members[0].priv), std::invalid_argument);
}

TEST(TreeKeysRemoval, RejectsANonMember) {
    const std::vector<TestMember> members = makeMembers(4);
    TreeKeyStore store;
    TreeKeys keys(store);
    const TreeGroupState state = stateFromBuild(keys.build(publicOf(members), members[0].priv), members);
    keys.setMemberKeys(publicOf(members));
    EXPECT_THROW(keys.planRemoval(state, "stranger", members[0].priv), std::invalid_argument);
}

/**
 * SECURITY — the whole point of the construction.
 *
 * After a removal every surviving member must reach the new grant key, and the removed member must not.
 */
TEST(TreeKeysRemoval, SECURITY_SurvivorsReachTheNewKeyAndTheRemovedMemberDoesNot) {
    for (const std::uint32_t count : {2u, 4u, 5u, 8u}) {
        const std::vector<TestMember> members = makeMembers(count);
        TreeKeyStore ownerStore;
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
            TreeKeyStore store;
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
TEST(TreeKeysRemoval, SECURITY_OldPathKeysDoNotOpenRefreshedEdges) {
    const std::vector<TestMember> members = makeMembers(8);
    TreeKeyStore ownerStore;
    TreeKeys owner(ownerStore);
    const BuildPlan plan = owner.build(publicOf(members), members[0].priv);
    TreeGroupState state = stateFromBuild(plan, members);
    ASSERT_EQ(owner.climbToGrantKey(state, members[0].userId, members[0].priv).failure, ClimbFailure::None);
    owner.setMemberKeys(publicOf(members));

    // Capture what the leaving member held before the removal.
    TreeKeyStore leaverStore;
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
TEST(TreeKeysRemoval, SECURITY_CollusionBetweenTwoRemovedMembersYieldsNothing) {
    const std::vector<TestMember> members = makeMembers(8);
    TreeKeyStore ownerStore;
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
        TreeKeyStore store;
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

// ─────────────────────────────────────────────────────────────────────────────
// addition
// ─────────────────────────────────────────────────────────────────────────────

TEST(TreeKeysAddition, FillingABlankCostsOneWrapAndDoesNotRotate) {
    const std::vector<TestMember> members = makeMembers(4);
    TreeKeyStore ownerStore;
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
    TreeKeyStore store;
    TreeKeys keys(store);
    const ClimbResult result = keys.climbToGrantKey(state, newcomer.userId, newcomer.priv);
    ASSERT_EQ(result.failure, ClimbFailure::None);
    EXPECT_EQ(result.grantKey->getPublicKey(), removal.newGrantKey.getPublicKey())
        << "an addition must not change the grant key";
}

TEST(TreeKeysAddition, ChoosesTheLowestBlankThenAppends) {
    TreeGroupState state;
    state.numLeaves = 4;
    state.leafAssignment = {std::string("a"), std::nullopt, std::string("c"), std::nullopt};
    EXPECT_EQ(TreeKeys::choosePosition(state), 1u);

    state.leafAssignment = {std::string("a"), std::string("b"), std::string("c"), std::string("d")};
    EXPECT_EQ(TreeKeys::choosePosition(state), 4u) << "no blanks: append";
}

TEST(TreeKeysAddition, RequiresTheParentKeyAndSaysSo) {
    const std::vector<TestMember> members = makeMembers(4);
    TreeKeyStore ownerStore;
    TreeKeys owner(ownerStore);
    TreeGroupState state = stateFromBuild(owner.build(publicOf(members), members[0].priv), members);
    state.leafAssignment[1] = std::nullopt;

    // A fresh store holds no node keys, so the addition cannot be prepared without climbing first.
    TreeKeyStore emptyStore;
    TreeKeys keys(emptyStore);
    const TestMember newcomer{"newcomer", PrivateKey::generateRandom()};
    EXPECT_THROW(
        keys.planAddition(state, TreeMember{newcomer.userId, newcomer.priv.getPublicKey()}, members[0].priv),
        std::invalid_argument
    );
}
