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

#include <algorithm>
#include <set>
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

    /** Applies an addition plan the way the bridge would after accepting it. */
    void applyAddition(TreeGroupState& state, const AdditionPlan& plan, const std::string& newMemberId) {
        const std::vector<std::optional<std::string>> seatingBefore = state.leafAssignment;
        state.numLeaves = plan.newNumLeaves;
        state.leafAssignment.resize(plan.newNumLeaves, std::nullopt);
        state.leafAssignment[plan.positions.at(0)] = newMemberId;

        std::set<std::uint32_t> rekeyed;
        for (const TreeNodeState& node : plan.nodes) {
            rekeyed.insert(node.nodeIndex);
            const auto existing = std::find_if(state.nodes.begin(), state.nodes.end(), [&](const TreeNodeState& n) {
                return n.nodeIndex == node.nodeIndex;
            });
            if (existing == state.nodes.end()) {
                state.nodes.push_back(node);
            } else {
                *existing = node;
            }
        }

        std::vector<TreeEdge> kept;
        for (const TreeEdge& edge : state.edges) {
            if (edge.isGrantEdge || rekeyed.count(edge.parentIndex) > 0) {
                continue; // superseded: the plan re-issues every edge under a node it re-keyed, and the grant edge
            }
            std::uint32_t childNode = edge.childIndex;
            if (edge.childKind == EdgeChildKind::User) {
                const auto seat = std::find_if(seatingBefore.begin(), seatingBefore.end(), [&](const auto& holder) {
                    return holder.has_value() && holder.value() == edge.childUserId;
                });
                if (seat == seatingBefore.end()) {
                    continue;
                }
                childNode =
                    TreeMath::leafNode(static_cast<std::uint32_t>(std::distance(seatingBefore.begin(), seat)));
            }
            // Growth re-parents nodes at the truncated right edge, so an edge can name a parent that is no longer
            // the child's parent. The plan supplies the replacement.
            if (childNode == TreeMath::root(plan.newNumLeaves)) {
                continue;
            }
            if (TreeMath::parent(childNode, plan.newNumLeaves) != edge.parentIndex) {
                continue;
            }
            kept.push_back(edge);
        }
        kept.insert(kept.end(), plan.edges.begin(), plan.edges.end());
        state.edges = kept;
    }

    /** Every seated member reaches the grant key from a cold cache — the check that nobody was locked out. */
    void expectEveryoneClimbs(const TreeGroupState& state, const std::vector<TestMember>& members) {
        for (const TestMember& member : members) {
            const auto seated = std::find_if(
                state.leafAssignment.begin(), state.leafAssignment.end(),
                [&](const auto& holder) { return holder.has_value() && holder.value() == member.userId; }
            );
            if (seated == state.leafAssignment.end()) {
                continue;
            }
            TreeKeyCache cache;
            TreeKeys keys(cache);
            const ClimbResult result = keys.climbToGrantKey(state, member.userId, member.priv);
            EXPECT_EQ(result.failure, ClimbFailure::None) << member.userId << " can no longer climb";
            ASSERT_TRUE(result.grantKey.has_value()) << member.userId;
            EXPECT_EQ(result.grantKey->getPublicKey(), state.grantPublicKey) << member.userId;
        }
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

/**
 * The boundary of what a wrap proves about its author: nothing.
 *
 * `wrapKey` takes a signer and `EciesEncryptor::encrypt` puts that signer's public key in the blob in the clear,
 * but `unwrapKey` passes no `pubOfSignature`, so the field is carried and never compared. Two wraps of the same
 * key to the same recipient by two different authors are therefore equally acceptable. Membership changes are
 * attributable one layer up — the group entry is signed and `GroupDataSchemaMapper` refuses an author who is not
 * a manager — and this test records that a single edge inside such an entry is not.
 */
TEST_F(TreeKeysPrimitives, AnEdgeOpensWithoutRegardToWhoSignedIt) {
    const PrivateKey secret = PrivateKey::generateRandom();
    const PrivateKey recipient = PrivateKey::generateRandom();
    const PrivateKey manager = PrivateKey::generateRandom();
    const PrivateKey stranger = PrivateKey::generateRandom();

    const auto byManager =
        TreeKeys::unwrapKey(TreeKeys::wrapKey(secret, recipient.getPublicKey(), manager), recipient);
    const auto byStranger =
        TreeKeys::unwrapKey(TreeKeys::wrapKey(secret, recipient.getPublicKey(), stranger), recipient);

    ASSERT_TRUE(byManager.has_value());
    ASSERT_TRUE(byStranger.has_value())
        << "an edge from an unexpected author was refused: authorship is checked now, so this boundary moved — "
           "widen the test to say who is accepted rather than deleting it";
    EXPECT_EQ(byManager->toWIF(), byStranger->toWIF());
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

/** The same authorship boundary inside a whole state: an edge re-issued by somebody else is followed as readily as the original, because the climb verifies recovered keys against the published node keys and asks nothing about who published either. */
TEST_F(TreeKeysClimb, AnEdgeReissuedByAStrangerIsStillFollowed) {
    const std::vector<TestMember> members = makeMembers(4);
    TreeKeyCache buildStore;
    TreeKeys builder(buildStore);
    const BuildPlan plan = builder.build(publicOf(members), members[0].priv);
    TreeGroupState state = stateFromBuild(plan, members);

    // Re-issue member 1's leaf edge: same parent key, same recipient, a different author. Only somebody already
    // holding the parent key can do this — a manager, or anyone whose own climb passes through that node.
    const auto leafEdge = std::find_if(state.edges.begin(), state.edges.end(), [&](const TreeEdge& edge) {
        return !edge.isGrantEdge && edge.childKind == EdgeChildKind::User && edge.childUserId == members[1].userId;
    });
    ASSERT_NE(leafEdge, state.edges.end());
    const auto parentKey = std::find_if(plan.nodeKeys.begin(), plan.nodeKeys.end(), [&](const auto& entry) {
        return entry.first == leafEdge->parentIndex;
    });
    ASSERT_NE(parentKey, plan.nodeKeys.end());
    const PrivateKey stranger = PrivateKey::generateRandom();
    leafEdge->blob = TreeKeys::wrapKey(parentKey->second, members[1].priv.getPublicKey(), stranger);

    TreeKeyCache store;
    TreeKeys keys(store);
    const ClimbResult result = keys.climbToGrantKey(state, members[1].userId, members[1].priv);
    EXPECT_EQ(result.failure, ClimbFailure::None);
    ASSERT_TRUE(result.grantKey.has_value());
    EXPECT_EQ(result.grantKey->getPublicKey(), plan.grantKey.getPublicKey());
}

/**
 * What a member sees when the state they are served simply leaves their edge out.
 *
 * `ReportsAMissingEdgeDistinctlyFromTampering` covers the mechanics; the point here is the attribution. The
 * victim gets the same `MissingEdge` a truncated response or a bug produces, with nothing marked as tampered
 * because nothing was forged, while for every other member the state is entirely ordinary and the roster still
 * seats the victim. A manager cutting one member off is therefore indistinguishable from a broken chain, and no
 * assertion here says otherwise — it is the documented limit of what the tree alone can prove.
 */
TEST_F(TreeKeysClimb, AWithheldEdgeIsIndistinguishableFromABrokenState) {
    const std::vector<TestMember> members = makeMembers(4);
    TreeKeyCache buildStore;
    TreeKeys builder(buildStore);
    const BuildPlan plan = builder.build(publicOf(members), members[0].priv);
    TreeGroupState state = stateFromBuild(plan, members);

    std::vector<TreeEdge> published;
    for (const TreeEdge& edge : state.edges) {
        const bool cutOff = !edge.isGrantEdge && edge.childKind == EdgeChildKind::User &&
            edge.childUserId == members[3].userId;
        if (!cutOff) {
            published.push_back(edge);
        }
    }
    state.edges = published;

    TreeKeyCache victimStore;
    TreeKeys victim(victimStore);
    const ClimbResult result = victim.climbToGrantKey(state, members[3].userId, members[3].priv);
    EXPECT_EQ(result.failure, ClimbFailure::MissingEdge);
    EXPECT_FALSE(result.grantKey.has_value());
    EXPECT_FALSE(result.tamperedNode.has_value());

    EXPECT_TRUE(state.leafAssignment[3].has_value()) << "the roster still names the member who was cut off";
    for (std::size_t i = 0; i + 1 < members.size(); ++i) {
        TreeKeyCache store;
        TreeKeys keys(store);
        EXPECT_EQ(keys.climbToGrantKey(state, members[i].userId, members[i].priv).failure, ClimbFailure::None)
            << members[i].userId << " must be unaffected by another member's edge going missing";
    }
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
    const RemovalPlan removal = keys.planRemoval(state, {members[0].userId}, members[1].priv);

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

    const RemovalPlan removal = keys.planRemoval(state, {members[2].userId}, members[0].priv);
    std::vector<std::uint32_t> refreshed;
    for (const NodeRefresh& refresh : removal.pathRefresh) {
        refreshed.push_back(refresh.nodeIndex);
    }
    // Compared as a set: the plan refreshes the union of the departing members' paths, which comes out ascending
    // rather than bottom-up. Nothing depends on the order — every node's fresh key is minted before any edge is
    // built, so a parent can wrap to a child whichever of them the loop reaches first.
    std::vector<std::uint32_t> expected = TreeMath::directPath(2, 8);
    std::sort(refreshed.begin(), refreshed.end());
    std::sort(expected.begin(), expected.end());
    EXPECT_EQ(refreshed, expected);
}

TEST_F(TreeKeysRemoval, BatchRefreshesTheUnionOfPathsOnceEach) {
    // Seats 0 and 1 sit under one parent, so their paths differ only in that leaf-level node. Refreshing the
    // shared ancestors once is the whole reason a batch is not k removals sent together: doing it per member
    // would mint two keys claiming one node and generation, and the second write would orphan the first's edges.
    const std::vector<TestMember> members = makeMembers(8);
    TreeKeyCache store;
    TreeKeys keys(store);
    const TreeGroupState state = stateFromBuild(keys.build(publicOf(members), members[0].priv), members);
    keys.setMemberKeys(publicOf(members));

    const RemovalPlan removal = keys.planRemoval(state, {members[0].userId, members[1].userId}, members[2].priv);
    std::vector<std::uint32_t> refreshed;
    for (const NodeRefresh& refresh : removal.pathRefresh) {
        refreshed.push_back(refresh.nodeIndex);
    }
    std::sort(refreshed.begin(), refreshed.end());
    EXPECT_EQ(refreshed, (std::vector<std::uint32_t>{1, 3, 7})) << "the union, not the two paths concatenated";
    EXPECT_EQ(removal.blankedPositions, (std::vector<std::uint32_t>{0, 1}));

    // Both leaves under node 1 are leaving, so it owes no edge at all: it still takes a fresh key so the refresh
    // reaches the root, but nothing can climb into it.
    for (const NodeRefresh& refresh : removal.pathRefresh) {
        if (refresh.nodeIndex == 1) {
            EXPECT_TRUE(refresh.edges.empty()) << "a node whose every leaf is blanked has nobody to wrap to";
        }
    }
    // And neither departing member is wrapped to anywhere in the plan.
    for (const NodeRefresh& refresh : removal.pathRefresh) {
        for (const TreeEdge& edge : refresh.edges) {
            EXPECT_NE(edge.childUserId, members[0].userId);
            EXPECT_NE(edge.childUserId, members[1].userId);
        }
    }
}

TEST_F(TreeKeysRemoval, BatchRefusesTheSameMemberTwice) {
    const std::vector<TestMember> members = makeMembers(4);
    TreeKeyCache store;
    TreeKeys keys(store);
    const TreeGroupState state = stateFromBuild(keys.build(publicOf(members), members[0].priv), members);
    keys.setMemberKeys(publicOf(members));

    EXPECT_THROW(
        keys.planRemoval(state, {members[1].userId, members[1].userId}, members[0].priv),
        std::invalid_argument
    );
}

TEST_F(TreeKeysRemoval, BatchRefusesAnEmptyMemberList) {
    const std::vector<TestMember> members = makeMembers(4);
    TreeKeyCache store;
    TreeKeys keys(store);
    const TreeGroupState state = stateFromBuild(keys.build(publicOf(members), members[0].priv), members);
    keys.setMemberKeys(publicOf(members));

    EXPECT_THROW(keys.planRemoval(state, {}, members[0].priv), std::invalid_argument);
}

TEST_F(TreeKeysRemoval, MintsIndependentKeysNotDerivedFromTheOldOnes) {
    const std::vector<TestMember> members = makeMembers(4);
    TreeKeyCache store;
    TreeKeys keys(store);
    const BuildPlan plan = keys.build(publicOf(members), members[0].priv);
    const TreeGroupState state = stateFromBuild(plan, members);
    keys.setMemberKeys(publicOf(members));

    const RemovalPlan removal = keys.planRemoval(state, {members[0].userId}, members[1].priv);
    for (const NodeRefresh& refresh : removal.pathRefresh) {
        for (const auto& [nodeIndex, oldKey] : plan.nodeKeys) {
            if (nodeIndex == refresh.nodeIndex) {
                EXPECT_NE(refresh.newKey.toWIF(), oldKey.toWIF()) << "node " << nodeIndex << " must get a fresh key";
            }
        }
    }
    EXPECT_NE(removal.newGrantKey.toWIF(), plan.grantKey.toWIF());
}

/**
 * SECURITY — the freshness line in `planRemoval`, pinned by the only property that survives a rewrite.
 *
 * The test above compares the new key with the one it replaces, which every derivation also passes: `sha256(old)`
 * is a different key. And no unwrap test can catch a derivation either — the refreshed edges are encrypted to the
 * new keys, so nothing the leaver holds opens them whether the new keys were minted or computed. What a removed
 * member actually needs is *predictability*, so that is what has to be denied: planning the same removal twice
 * from the same state must not produce the same keys. Any key derived from the state being replaced is a function
 * of that state and lands here as an equality; entropy cannot collide.
 */
TEST_F(TreeKeysRemoval, SECURITY_ARemovedMemberCannotRecomputeWhatReplacedTheirPath) {
    const std::vector<TestMember> members = makeMembers(8);
    TreeKeyCache store;
    TreeKeys keys(store);
    const TreeGroupState state = stateFromBuild(keys.build(publicOf(members), members[0].priv), members);
    keys.setMemberKeys(publicOf(members));

    // Two plans for the same removal: the served state, the roster and the departing member are identical
    // between them, so everything a removed member could feed a derivation is identical too.
    const RemovalPlan first = keys.planRemoval(state, {members[7].userId}, members[0].priv);
    const RemovalPlan second = keys.planRemoval(state, {members[7].userId}, members[0].priv);

    ASSERT_EQ(first.pathRefresh.size(), second.pathRefresh.size());
    for (std::size_t i = 0; i < first.pathRefresh.size(); ++i) {
        ASSERT_EQ(first.pathRefresh[i].nodeIndex, second.pathRefresh[i].nodeIndex);
        EXPECT_NE(first.pathRefresh[i].newKey.toWIF(), second.pathRefresh[i].newKey.toWIF())
            << "node " << first.pathRefresh[i].nodeIndex
            << " is a function of the state it replaces, so whoever held the old key computes the new one";
    }
    EXPECT_NE(first.newGrantKey.toWIF(), second.newGrantKey.toWIF())
        << "the new epoch's grant key is a function of the old state: the removed member reads on";
}

TEST_F(TreeKeysRemoval, RejectsRemovingTheOnlyMember) {
    const std::vector<TestMember> members = makeMembers(1);
    TreeKeyCache store;
    TreeKeys keys(store);
    const TreeGroupState state = stateFromBuild(keys.build(publicOf(members), members[0].priv), members);
    keys.setMemberKeys(publicOf(members));
    EXPECT_THROW(keys.planRemoval(state, {members[0].userId}, members[0].priv), std::invalid_argument);
}

TEST_F(TreeKeysRemoval, RejectsANonMember) {
    const std::vector<TestMember> members = makeMembers(4);
    TreeKeyCache store;
    TreeKeys keys(store);
    const TreeGroupState state = stateFromBuild(keys.build(publicOf(members), members[0].priv), members);
    keys.setMemberKeys(publicOf(members));
    EXPECT_THROW(keys.planRemoval(state, {"stranger"}, members[0].priv), std::invalid_argument);
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
        const RemovalPlan removal = owner.planRemoval(state, {leaving}, members[0].priv);
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

    const RemovalPlan removal = owner.planRemoval(state, {members[7].userId}, members[0].priv);

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
    const RemovalPlan first = owner.planRemoval(state, {members[7].userId}, members[0].priv);
    applyRemoval(state, first, members[7].userId);
    ownerStore.clear();
    ASSERT_EQ(owner.climbToGrantKey(state, members[0].userId, members[0].priv).failure, ClimbFailure::None);
    const RemovalPlan second = owner.planRemoval(state, {members[6].userId}, members[0].priv);
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

TEST_F(TreeKeysAddition, FillingABlankRekeysThePathAndDoesNotRotate) {
    const std::vector<TestMember> members = makeMembers(4);
    TreeKeyCache ownerStore;
    TreeKeys owner(ownerStore);
    const BuildPlan plan = owner.build(publicOf(members), members[0].priv);
    TreeGroupState state = stateFromBuild(plan, members);
    ASSERT_EQ(owner.climbToGrantKey(state, members[0].userId, members[0].priv).failure, ClimbFailure::None);
    owner.setMemberKeys(publicOf(members));

    // Remove member 1, leaving a blank at position 1.
    const RemovalPlan removal = owner.planRemoval(state, {members[1].userId}, members[0].priv);
    applyRemoval(state, removal, members[1].userId);
    ownerStore.clear();
    ASSERT_EQ(owner.climbToGrantKey(state, members[0].userId, members[0].priv).failure, ClimbFailure::None);

    const TestMember newcomer{"newcomer", PrivateKey::generateRandom()};
    std::vector<TreeMember> roster = publicOf(members);
    roster.push_back(TreeMember{newcomer.userId, newcomer.priv.getPublicKey()});
    owner.setMemberKeys(roster);
    const AdditionPlan addition = owner.planAddition(
state, std::vector<TreeMember>{TreeMember{newcomer.userId, newcomer.priv.getPublicKey()}},
TreeKeys::choosePositions(state, 1), members[0].priv
);

    EXPECT_EQ(addition.positions.at(0), 1u) << "must reuse the blank rather than append";
    EXPECT_EQ(addition.newNumLeaves, state.numLeaves) << "topology unchanged";
    EXPECT_FALSE(addition.newRoot.has_value());
    // Two nodes on the path for four leaves, each wrapping to two children, plus the grant edge.
    EXPECT_EQ(addition.nodes.size(), 2u);
    EXPECT_EQ(addition.wrapCount, 5u);
    for (const TreeNodeState& node : addition.nodes) {
        const auto before = std::find_if(state.nodes.begin(), state.nodes.end(), [&](const TreeNodeState& n) {
            return n.nodeIndex == node.nodeIndex;
        });
        ASSERT_NE(before, state.nodes.end());
        EXPECT_EQ(node.generation, before->generation + 1) << "node " << node.nodeIndex;
        EXPECT_NE(node.publicKey.toBase58DER(), before->publicKey.toBase58DER()) << "node " << node.nodeIndex;
    }

    const privmx::crypto::PublicKey grantBefore = state.grantPublicKey;
    applyAddition(state, addition, newcomer.userId);
    EXPECT_EQ(state.grantPublicKey.toBase58DER(), grantBefore.toBase58DER())
        << "an addition must not change the grant key";
    EXPECT_EQ(state.epoch, removal.newEpoch) << "an addition must not advance the epoch";

    std::vector<TestMember> after = members;
    after.push_back(newcomer);
    expectEveryoneClimbs(state, after);
}

TEST_F(TreeKeysAddition, SeatsAMemberUnderANodeTheCallerCannotReach) {
    // The case that a four-member group hides: with eight seats the blank at position 5 sits under node 11, and
    // nothing on the caller's own climb from seat 0 ever yields that node's key. Wrapping to an existing parent
    // key is therefore impossible here, and this is the shape production groups are almost entirely made of.
    const std::vector<TestMember> members = makeMembers(8);
    TreeKeyCache ownerStore;
    TreeKeys owner(ownerStore);
    TreeGroupState state = stateFromBuild(owner.build(publicOf(members), members[0].priv), members);
    owner.setMemberKeys(publicOf(members));
    ASSERT_EQ(owner.climbToGrantKey(state, members[0].userId, members[0].priv).failure, ClimbFailure::None);

    const RemovalPlan removal = owner.planRemoval(state, {members[5].userId}, members[0].priv);
    applyRemoval(state, removal, members[5].userId);
    ownerStore.clear();
    ASSERT_EQ(owner.climbToGrantKey(state, members[0].userId, members[0].priv).failure, ClimbFailure::None);
    // The seat's parent is genuinely out of reach: the climb cached nothing for it.
    const std::uint32_t seatParent = TreeMath::parent(TreeMath::leafNode(5), state.numLeaves);
    const auto parentState = std::find_if(state.nodes.begin(), state.nodes.end(), [&](const TreeNodeState& n) {
        return n.nodeIndex == seatParent;
    });
    ASSERT_NE(parentState, state.nodes.end());
    ASSERT_FALSE(ownerStore.getNodeKey(seatParent, parentState->generation).has_value());

    const TestMember newcomer{"newcomer", PrivateKey::generateRandom()};
    std::vector<TreeMember> roster = publicOf(members);
    roster.push_back(TreeMember{newcomer.userId, newcomer.priv.getPublicKey()});
    owner.setMemberKeys(roster);
    const AdditionPlan addition = owner.planAddition(
state, std::vector<TreeMember>{TreeMember{newcomer.userId, newcomer.priv.getPublicKey()}},
TreeKeys::choosePositions(state, 1), members[0].priv
);
    EXPECT_EQ(addition.positions.at(0), 5u);
    EXPECT_EQ(addition.nodes.size(), 3u) << "three nodes on the path of an eight-leaf tree";

    applyAddition(state, addition, newcomer.userId);
    std::vector<TestMember> after = members;
    after[5] = newcomer; // seat 5 changed hands
    expectEveryoneClimbs(state, after);

    // And the member who was removed from that seat is still out, despite the path having been re-keyed since.
    TreeKeyCache removedStore;
    TreeKeys removedKeys(removedStore);
    EXPECT_NE(removedKeys.climbToGrantKey(state, members[5].userId, members[5].priv).failure, ClimbFailure::None);
}

TEST_F(TreeKeysAddition, GrowsTheTreeWithoutBorrowingAnyExistingKey) {
    // Growth re-parents leaves at the truncated right edge, which used to need several other members' node keys
    // at once. Re-keying the new leaf's path removes that requirement entirely.
    const std::vector<TestMember> members = makeMembers(5);
    TreeKeyCache ownerStore;
    TreeKeys owner(ownerStore);
    TreeGroupState state = stateFromBuild(owner.build(publicOf(members), members[0].priv), members);
    owner.setMemberKeys(publicOf(members));
    ASSERT_EQ(owner.climbToGrantKey(state, members[0].userId, members[0].priv).failure, ClimbFailure::None);

    const TestMember newcomer{"newcomer", PrivateKey::generateRandom()};
    std::vector<TreeMember> roster = publicOf(members);
    roster.push_back(TreeMember{newcomer.userId, newcomer.priv.getPublicKey()});
    owner.setMemberKeys(roster);
    const AdditionPlan addition = owner.planAddition(
state, std::vector<TreeMember>{TreeMember{newcomer.userId, newcomer.priv.getPublicKey()}},
TreeKeys::choosePositions(state, 1), members[0].priv
);
    EXPECT_EQ(addition.positions.at(0), 5u) << "every seat is taken, so the tree grows";
    EXPECT_EQ(addition.newNumLeaves, 6u);

    const privmx::crypto::PublicKey grantBefore = state.grantPublicKey;
    const std::uint32_t epochBefore = state.epoch;
    applyAddition(state, addition, newcomer.userId);
    EXPECT_EQ(state.grantPublicKey.toBase58DER(), grantBefore.toBase58DER());
    EXPECT_EQ(state.epoch, epochBefore) << "growth must not stale a single container";

    std::vector<TestMember> after = members;
    after.push_back(newcomer);
    expectEveryoneClimbs(state, after);
}

TEST_F(TreeKeysAddition, GrowsAcrossARootChangeAndKeepsEverybodyClimbing) {
    // Four seats to five: the root index itself changes and the grant edge moves to a node that did not exist a
    // moment ago, while the grant keypair stays put.
    const std::vector<TestMember> members = makeMembers(4);
    TreeKeyCache ownerStore;
    TreeKeys owner(ownerStore);
    TreeGroupState state = stateFromBuild(owner.build(publicOf(members), members[0].priv), members);
    ASSERT_EQ(owner.climbToGrantKey(state, members[0].userId, members[0].priv).failure, ClimbFailure::None);

    const TestMember newcomer{"newcomer", PrivateKey::generateRandom()};
    std::vector<TreeMember> roster = publicOf(members);
    roster.push_back(TreeMember{newcomer.userId, newcomer.priv.getPublicKey()});
    owner.setMemberKeys(roster);
    const AdditionPlan addition = owner.planAddition(
state, std::vector<TreeMember>{TreeMember{newcomer.userId, newcomer.priv.getPublicKey()}},
TreeKeys::choosePositions(state, 1), members[0].priv
);
    ASSERT_TRUE(addition.newRoot.has_value()) << "growing from four to five leaves changes the root";
    EXPECT_EQ(addition.newRoot->nodeIndex, TreeMath::root(5));

    const privmx::crypto::PublicKey grantBefore = state.grantPublicKey;
    applyAddition(state, addition, newcomer.userId);
    EXPECT_EQ(state.grantPublicKey.toBase58DER(), grantBefore.toBase58DER());

    std::vector<TestMember> after = members;
    after.push_back(newcomer);
    expectEveryoneClimbs(state, after);
}

TEST_F(TreeKeysAddition, SeatsTheSecondMemberOfAOneMemberGroup) {
    // The one tree with no internal node at all: the root is the founder's own leaf, and the grant edge is
    // addressed to them directly. Seating anybody mints the first internal node and moves that edge onto it.
    const std::vector<TestMember> members = makeMembers(1);
    TreeKeyCache ownerStore;
    TreeKeys owner(ownerStore);
    TreeGroupState state = stateFromBuild(owner.build(publicOf(members), members[0].priv), members);
    ASSERT_EQ(owner.climbToGrantKey(state, members[0].userId, members[0].priv).failure, ClimbFailure::None);

    const TestMember newcomer{"newcomer", PrivateKey::generateRandom()};
    std::vector<TreeMember> roster = publicOf(members);
    roster.push_back(TreeMember{newcomer.userId, newcomer.priv.getPublicKey()});
    owner.setMemberKeys(roster);
    const AdditionPlan addition = owner.planAddition(
state, std::vector<TreeMember>{TreeMember{newcomer.userId, newcomer.priv.getPublicKey()}},
TreeKeys::choosePositions(state, 1), members[0].priv
);
    EXPECT_EQ(addition.positions.at(0), 1u);
    EXPECT_EQ(addition.nodes.size(), 1u);

    const privmx::crypto::PublicKey grantBefore = state.grantPublicKey;
    applyAddition(state, addition, newcomer.userId);
    EXPECT_EQ(state.grantPublicKey.toBase58DER(), grantBefore.toBase58DER());
    std::vector<TestMember> after = members;
    after.push_back(newcomer);
    expectEveryoneClimbs(state, after);
}

/**
 * SECURITY — the same freshness line in `planAddition`, where a blank is being refilled.
 *
 * The path under a blank leaf is the path the member removed from that seat used to climb, and they still hold
 * every node key on it. Were a seating to derive its new keys from the ones it replaces, that member would
 * recompute the refreshed path and be back inside the tree with nobody re-seating them. Same detector as the
 * removal case: the same seating planned twice must not repeat itself.
 */
TEST_F(TreeKeysAddition, SECURITY_RefillingASeatDoesNotRepeatTheKeysItReplaces) {
    const std::vector<TestMember> members = makeMembers(4);
    TreeKeyCache ownerStore;
    TreeKeys owner(ownerStore);
    TreeGroupState state = stateFromBuild(owner.build(publicOf(members), members[0].priv), members);
    ASSERT_EQ(owner.climbToGrantKey(state, members[0].userId, members[0].priv).failure, ClimbFailure::None);
    owner.setMemberKeys(publicOf(members));

    // Member 1 out, leaving a blank at position 1.
    const RemovalPlan removal = owner.planRemoval(state, {members[1].userId}, members[0].priv);
    applyRemoval(state, removal, members[1].userId);
    ownerStore.clear();
    ASSERT_EQ(owner.climbToGrantKey(state, members[0].userId, members[0].priv).failure, ClimbFailure::None);

    const TestMember newcomer{"newcomer", PrivateKey::generateRandom()};
    std::vector<TreeMember> roster = publicOf(members);
    roster.push_back(TreeMember{newcomer.userId, newcomer.priv.getPublicKey()});
    owner.setMemberKeys(roster);
    const TreeMember seated{newcomer.userId, newcomer.priv.getPublicKey()};

    const AdditionPlan first =
        owner.planAddition(state, {seated}, TreeKeys::choosePositions(state, 1), members[0].priv);
    const AdditionPlan second =
        owner.planAddition(state, {seated}, TreeKeys::choosePositions(state, 1), members[0].priv);

    ASSERT_EQ(first.positions, second.positions) << "the same seating must land on the same seat";
    ASSERT_EQ(first.nodeKeys.size(), second.nodeKeys.size());
    ASSERT_FALSE(first.nodeKeys.empty());
    for (std::size_t i = 0; i < first.nodeKeys.size(); ++i) {
        ASSERT_EQ(first.nodeKeys[i].first, second.nodeKeys[i].first);
        EXPECT_NE(first.nodeKeys[i].second.toWIF(), second.nodeKeys[i].second.toWIF())
            << "node " << first.nodeKeys[i].first << " is a function of the key it replaces";
    }
}

TEST_F(TreeKeysRemoval, ParsesOnlyTheRosterKeysItWrapsTo) {
    // The roster arrives whole because the API takes it whole, but a removal wraps to the sibling leaf beside the
    // departing one and to nothing else. Every other entry here is unparseable: if planning touched them it would
    // throw, so this is the guard on the laziness rather than a claim about it.
    const std::vector<TestMember> members = makeMembers(8);
    TreeKeyCache store;
    TreeKeys keys(store);
    TreeGroupState state = stateFromBuild(keys.build(publicOf(members), members[0].priv), members);
    ASSERT_EQ(keys.climbToGrantKey(state, members[0].userId, members[0].priv).failure, ClimbFailure::None);

    const std::uint32_t leaving = 5;
    const std::uint32_t sibling = 4; // the other leaf under node 9
    std::map<std::string, std::string> roster;
    for (std::size_t i = 0; i < members.size(); ++i) {
        roster[members[i].userId] = i == sibling
            ? members[i].priv.getPublicKey().toBase58DER()
            : std::string("not-a-key");
    }
    keys.setMemberKeyStrings(roster);

    RemovalPlan plan;
    ASSERT_NO_THROW({ plan = keys.planRemoval(state, {members[leaving].userId}, members[0].priv); });
    EXPECT_EQ(plan.newEpoch, state.epoch + 1);
}

TEST_F(TreeKeysRemoval, StillFailsWhenTheKeyItDoesNeedIsUnusable) {
    // The other direction: lazy must not mean never. The sibling's key is the one entry that gets parsed.
    const std::vector<TestMember> members = makeMembers(8);
    TreeKeyCache store;
    TreeKeys keys(store);
    TreeGroupState state = stateFromBuild(keys.build(publicOf(members), members[0].priv), members);
    ASSERT_EQ(keys.climbToGrantKey(state, members[0].userId, members[0].priv).failure, ClimbFailure::None);

    std::map<std::string, std::string> roster;
    for (const TestMember& member : members) {
        roster[member.userId] = member.priv.getPublicKey().toBase58DER();
    }
    roster[members[4].userId] = "not-a-key";
    keys.setMemberKeyStrings(roster);
    EXPECT_ANY_THROW(keys.planRemoval(state, {members[5].userId}, members[0].priv));
}

TEST_F(TreeKeysClimb, ReadsAServedStateWithoutParsingNodeKeys) {
    // Climbing verifies each recovered key against the published one, which is a string comparison — so a state
    // whose off-path nodes carry unparseable keys still climbs. That is what makes reading a 4000-member tree
    // cost `log n` subgroup checks instead of 4000.
    const std::vector<TestMember> members = makeMembers(8);
    TreeKeyCache store;
    TreeKeys keys(store);
    TreeGroupState state = stateFromBuild(keys.build(publicOf(members), members[0].priv), members);
    const std::vector<std::uint32_t> mine = TreeMath::directPath(0, state.numLeaves);
    for (TreeNodeState& node : state.nodes) {
        if (std::find(mine.begin(), mine.end(), node.nodeIndex) == mine.end()) {
            node.publicKey = NodePublicKey::fromBase58DER("not-a-key");
        }
    }
    EXPECT_EQ(keys.climbToGrantKey(state, members[0].userId, members[0].priv).failure, ClimbFailure::None);
}

TEST_F(TreeKeysAddition, ChoosesTheLowestBlankThenAppends) {
    TreeGroupState state;
    state.numLeaves = 4;
    state.leafAssignment = {std::string("a"), std::nullopt, std::string("c"), std::nullopt};
    EXPECT_EQ(TreeKeys::choosePositions(state, 1).at(0), 1u);

    state.leafAssignment = {std::string("a"), std::string("b"), std::string("c"), std::string("d")};
    EXPECT_EQ(TreeKeys::choosePositions(state, 1).at(0), 4u) << "no blanks: append";
}

TEST_F(TreeKeysAddition, RequiresTheGrantKeyAndSaysSo) {
    const std::vector<TestMember> members = makeMembers(4);
    TreeKeyCache ownerStore;
    TreeKeys owner(ownerStore);
    TreeGroupState state = stateFromBuild(owner.build(publicOf(members), members[0].priv), members);
    state.leafAssignment[1] = std::nullopt;

    // Re-keying the path needs no existing node key, but the root's new key has to be joined to the grant keypair
    // — and that one has to be climbed for. A fresh cache holds neither.
    TreeKeyCache emptyStore;
    TreeKeys keys(emptyStore);
    keys.setMemberKeys(publicOf(members));
    const TestMember newcomer{"newcomer", PrivateKey::generateRandom()};
    EXPECT_THROW(
        keys.planAddition(
state, std::vector<TreeMember>{TreeMember{newcomer.userId, newcomer.priv.getPublicKey()}},
TreeKeys::choosePositions(state, 1), members[0].priv
),
        std::invalid_argument
    );
}

TEST_F(TreeKeysAddition, RequiresTheRosterForTheSiblingsItRewrapsTo) {
    // The siblings' public keys are not in the tree state — a leaf *is* the member's key — so a caller who did
    // not supply the roster would silently leave them without an edge to the re-keyed path.
    const std::vector<TestMember> members = makeMembers(4);
    TreeKeyCache ownerStore;
    TreeKeys owner(ownerStore);
    TreeGroupState state = stateFromBuild(owner.build(publicOf(members), members[0].priv), members);
    ASSERT_EQ(owner.climbToGrantKey(state, members[0].userId, members[0].priv).failure, ClimbFailure::None);
    state.leafAssignment[1] = std::nullopt;

    const TestMember newcomer{"newcomer", PrivateKey::generateRandom()};
    EXPECT_THROW(
        owner.planAddition(
state, std::vector<TreeMember>{TreeMember{newcomer.userId, newcomer.priv.getPublicKey()}},
TreeKeys::choosePositions(state, 1), members[0].priv
),
        std::invalid_argument
    ) << "no setMemberKeys call, so the sibling leaves cannot be wrapped to";
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
        << "group B must not be handed group A's grant key";}

// ─────────────────────────────────────────────────────────────────────────────
// batch additions
// ─────────────────────────────────────────────────────────────────────────────

TEST_F(TreeKeysAddition, BatchSeatsSeveralAndRekeysTheUnionOnce) {
    // Two newcomers appended past the end of a four-leaf tree. Their paths meet at the root, so the root is
    // re-keyed once — the same reason a batch removal is not k removals, applied to the cheap direction.
    const std::vector<TestMember> members = makeMembers(4);
    TreeKeyCache ownerStore;
    TreeKeys owner(ownerStore);
    const BuildPlan plan = owner.build(publicOf(members), members[0].priv);
    TreeGroupState state = stateFromBuild(plan, members);
    ASSERT_EQ(owner.climbToGrantKey(state, members[0].userId, members[0].priv).failure, ClimbFailure::None);

    const TestMember first{"newcomer-a", PrivateKey::generateRandom()};
    const TestMember second{"newcomer-b", PrivateKey::generateRandom()};
    std::vector<TreeMember> roster = publicOf(members);
    roster.push_back(TreeMember{first.userId, first.priv.getPublicKey()});
    roster.push_back(TreeMember{second.userId, second.priv.getPublicKey()});
    owner.setMemberKeys(roster);

    const std::vector<std::uint32_t> seats = TreeKeys::choosePositions(state, 2);
    EXPECT_EQ(seats, (std::vector<std::uint32_t>{4, 5})) << "every seat is taken, so both append, contiguously";

    const AdditionPlan addition = owner.planAddition(
        state,
        std::vector<TreeMember>{
            TreeMember{first.userId, first.priv.getPublicKey()},
            TreeMember{second.userId, second.priv.getPublicKey()},
        },
        seats, members[0].priv
    );
    EXPECT_EQ(addition.positions, seats);
    EXPECT_EQ(addition.newNumLeaves, 6u) << "the tree grows once for the batch, not once per newcomer";

    // Each node appears exactly once in the plan: that is what "union" means here.
    std::vector<std::uint32_t> seated;
    for (const TreeNodeState& node : addition.nodes) {
        seated.push_back(node.nodeIndex);
    }
    std::vector<std::uint32_t> unique = seated;
    std::sort(unique.begin(), unique.end());
    unique.erase(std::unique(unique.begin(), unique.end()), unique.end());
    EXPECT_EQ(seated.size(), unique.size()) << "a shared ancestor must not be re-keyed twice";

    // Both newcomers are wrapped to, or one of them joins a group they cannot read.
    bool wrappedFirst = false;
    bool wrappedSecond = false;
    for (const TreeEdge& edge : addition.edges) {
        wrappedFirst = wrappedFirst || edge.childUserId == first.userId;
        wrappedSecond = wrappedSecond || edge.childUserId == second.userId;
    }
    EXPECT_TRUE(wrappedFirst);
    EXPECT_TRUE(wrappedSecond);
}

TEST_F(TreeKeysAddition, BatchRefusesMismatchedMembersAndSeats) {
    const std::vector<TestMember> members = makeMembers(4);
    TreeKeyCache ownerStore;
    TreeKeys owner(ownerStore);
    const TreeGroupState state = stateFromBuild(owner.build(publicOf(members), members[0].priv), members);
    owner.setMemberKeys(publicOf(members));

    const TestMember newcomer{"newcomer", PrivateKey::generateRandom()};
    const std::vector<TreeMember> one{TreeMember{newcomer.userId, newcomer.priv.getPublicKey()}};
    EXPECT_THROW(owner.planAddition(state, one, {4, 5}, members[0].priv), std::invalid_argument);
    EXPECT_THROW(owner.planAddition(state, {}, {}, members[0].priv), std::invalid_argument);
}

TEST_F(TreeKeysAddition, BatchRefusesTheSameNewcomerTwice) {
    // Two seats for one userId leaves a second leaf nobody ever blanks: `positionOf` finds only the first, so a
    // later removal re-keys one path and the other keeps climbing to the new grant key.
    const std::vector<TestMember> members = makeMembers(4);
    TreeKeyCache ownerStore;
    TreeKeys owner(ownerStore);
    const TreeGroupState state = stateFromBuild(owner.build(publicOf(members), members[0].priv), members);
    const TestMember newcomer{"newcomer", PrivateKey::generateRandom()};
    std::vector<TreeMember> roster = publicOf(members);
    roster.push_back(TreeMember{newcomer.userId, newcomer.priv.getPublicKey()});
    owner.setMemberKeys(roster);

    EXPECT_THROW(
        owner.planAddition(
            state,
            std::vector<TreeMember>{
                TreeMember{newcomer.userId, newcomer.priv.getPublicKey()},
                TreeMember{newcomer.userId, newcomer.priv.getPublicKey()},
            },
            {4, 5}, members[0].priv
        ),
        std::invalid_argument
    );
}

TEST_F(TreeKeysAddition, BatchRefusesSomebodyWhoAlreadyHoldsALeaf) {
    const std::vector<TestMember> members = makeMembers(4);
    TreeKeyCache ownerStore;
    TreeKeys owner(ownerStore);
    const TreeGroupState state = stateFromBuild(owner.build(publicOf(members), members[0].priv), members);
    owner.setMemberKeys(publicOf(members));

    EXPECT_THROW(
        owner.planAddition(
            state,
            std::vector<TreeMember>{TreeMember{members[1].userId, members[1].priv.getPublicKey()}},
            {4}, members[0].priv
        ),
        std::invalid_argument
    );
}

TEST_F(TreeKeysAddition, BatchRefusesTwoNewcomersOnOneSeat) {
    const std::vector<TestMember> members = makeMembers(4);
    TreeKeyCache ownerStore;
    TreeKeys owner(ownerStore);
    const TreeGroupState state = stateFromBuild(owner.build(publicOf(members), members[0].priv), members);
    const TestMember first{"newcomer-a", PrivateKey::generateRandom()};
    const TestMember second{"newcomer-b", PrivateKey::generateRandom()};
    std::vector<TreeMember> roster = publicOf(members);
    roster.push_back(TreeMember{first.userId, first.priv.getPublicKey()});
    roster.push_back(TreeMember{second.userId, second.priv.getPublicKey()});
    owner.setMemberKeys(roster);

    EXPECT_THROW(
        owner.planAddition(
            state,
            std::vector<TreeMember>{
                TreeMember{first.userId, first.priv.getPublicKey()},
                TreeMember{second.userId, second.priv.getPublicKey()},
            },
            {4, 4}, members[0].priv
        ),
        std::invalid_argument
    );
}
