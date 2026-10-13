/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

/**
 * The hidden key tree, with real EC keys and real ECIES.
 *
 * No server, no docker, no network, but no crypto stubs either — every wrap is a genuine ECIES encryption and
 * every climb a genuine decryption, because the properties under test are cryptographic ones: that a removed
 * member cannot reach a refreshed key, and that a corrupted edge is detected rather than silently producing the
 * wrong key. States are carried from one commit to the next by `TreeWire::afterCommit`, the bridge's storage rule.
 *
 * Groups above 32 seats appear throughout: below that the root is the only keyed node, and the interesting cases —
 * blank nodes, edges skipping a blank, a commit wrapping through a blank to a whole bucket — need a second one.
 *
 * Tests named SECURITY guard confidentiality and fail silently at runtime if the guard regresses.
 */

#include <gtest/gtest.h>

#include <algorithm>
#include <functional>
#include <map>
#include <set>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

#include <privmx/crypto/ecc/PrivateKey.hpp>

#include <privmx/endpoint/group/keytree/TreeKeyCache.hpp>
#include <privmx/endpoint/group/keytree/TreeKeyCacheRegistry.hpp>
#include <privmx/endpoint/group/keytree/TreeKeys.hpp>
#include <privmx/endpoint/group/keytree/TreeMath.hpp>
#include <privmx/endpoint/group/keytree/TreeWire.hpp>

using privmx::crypto::PrivateKey;
using namespace privmx::endpoint::group;
using namespace privmx::endpoint::group::keytree;
using Nodes = std::vector<std::uint32_t>;

class TreeKeysTestBase : public testing::Test {
protected:
    // A member together with the private half, which only the test holds.
    struct TestMember {
        std::string userId;
        PrivateKey priv;
    };

    // A group as the bridge would hold it, and everybody who ever held a seat in it.
    struct Group {
        std::vector<TestMember> members;
        TreeGroupState state;
    };

    std::vector<TestMember> makeMembers(std::uint32_t count, const std::string& prefix = "user") {
        std::vector<TestMember> members;
        for (std::uint32_t i = 0; i < count; ++i) {
            members.push_back(TestMember{prefix + std::to_string(i), PrivateKey::generateRandom()});
        }
        return members;
    }

    static std::vector<TreeMember> publicOf(const std::vector<TestMember>& members) {
        std::vector<TreeMember> result;
        for (const TestMember& member : members) {
            result.push_back(TreeMember{member.userId, member.priv.getPublicKey()});
        }
        return result;
    }

    static server::GroupTreeState wireOf(const TreeGroupState& state) {
        server::GroupTreeState tree;
        tree.numLeaves = state.numLeaves;
        for (const auto& seat : state.leafAssignment) {
            tree.leafAssignment.push_back(seat.value_or(""));
        }
        for (const TreeNodeState& node : state.nodes) {
            tree.nodes.push_back(TreeWire::toWire(node));
        }
        for (const TreeEdge& edge : state.edges) {
            tree.edges.push_back(TreeWire::toWire(edge));
        }
        return tree;
    }

    // The state the bridge stores once it accepts the commit.
    static TreeGroupState applied(const TreeGroupState& before, const CommitPlan& plan) {
        TreeGroupState after =
            TreeWire::toRuntime(TreeWire::afterCommit(wireOf(before), plan), plan.epoch, plan.grantKey.getPublicKey());
        after.commitSeq = plan.seq;
        after.setters = before.setters;
        after.setters[plan.seq] = plan.shape.leafAssignment.at(plan.shape.committerSeat).value();
        return after;
    }

    // `created`, when given, receives the creator's plan.
    Group create(std::uint32_t count, std::uint32_t creator = 0, CommitPlan* created = nullptr) {
        Group group;
        group.members = makeMembers(count);
        TreeKeyCache cache;
        TreeKeys keys(cache);
        const CommitPlan plan =
            keys.planCreate(publicOf(group.members), group.members[creator].userId, group.members[creator].priv);
        group.state = applied(TreeGroupState{}, plan);
        if (created != nullptr) {
            *created = plan;
        }
        return group;
    }

    // The committer plans the way a live client does: a cold cache, a climb, the roster's keys, then the plan.
    CommitPlan planBy(
        const Group& group,
        std::uint32_t committer,
        const std::function<CommitPlan(TreeKeys&, const TestMember&)>& plan
    ) {
        TreeKeyCache cache;
        TreeKeys keys(cache);
        const TestMember& who = group.members[committer];
        if (keys.climbToGrantKey(group.state, who.userId, who.priv, false).failure != ClimbFailure::None) {
            throw std::runtime_error(who.userId + " cannot climb");
        }
        keys.setMemberKeys(publicOf(group.members));
        return plan(keys, who);
    }

    CommitPlan remove(Group& group, std::uint32_t remover, const std::vector<std::uint32_t>& leaving) {
        std::vector<std::string> ids;
        for (const std::uint32_t index : leaving) {
            ids.push_back(group.members[index].userId);
        }
        const CommitPlan plan = planBy(group, remover, [&](TreeKeys& keys, const TestMember& who) {
            return keys.planRemoval(group.state, ids, who.userId, who.priv);
        });
        group.state = applied(group.state, plan);
        return plan;
    }

    // Newcomers join `group.members` at the end, so their index there is stable.
    CommitPlan add(Group& group, std::uint32_t adder, std::uint32_t count) {
        const std::vector<TestMember> newcomers =
            makeMembers(count, "new" + std::to_string(group.members.size()) + "-");
        const CommitPlan plan = planBy(group, adder, [&](TreeKeys& keys, const TestMember& who) {
            return keys.planAddition(
                group.state, publicOf(newcomers), TreeKeys::choosePositions(group.state, count), who.userId, who.priv
            );
        });
        group.members.insert(group.members.end(), newcomers.begin(), newcomers.end());
        group.state = applied(group.state, plan);
        return plan;
    }

    CommitPlan selfUpdate(Group& group, std::uint32_t member) {
        const CommitPlan plan = planBy(group, member, [&](TreeKeys& keys, const TestMember& who) {
            return keys.planSelfUpdate(group.state, who.userId, who.priv);
        });
        group.state = applied(group.state, plan);
        return plan;
    }

    static bool isSeated(const TreeGroupState& state, const std::string& userId) {
        return TreeKeys::positionOf(state, userId).has_value();
    }

    static ClimbResult climb(const TreeGroupState& state, const TestMember& member) {
        TreeKeyCache cache;
        TreeKeys keys(cache);
        return keys.climbToGrantKey(state, member.userId, member.priv);
    }

    // Every seated member reaches the grant key from a cold cache — the check that nobody was locked out.
    void expectEveryoneSeatedClimbs(const Group& group) {
        for (const TestMember& member : group.members) {
            if (!isSeated(group.state, member.userId)) {
                continue;
            }
            const ClimbResult result = climb(group.state, member);
            EXPECT_EQ(result.failure, ClimbFailure::None) << member.userId << " can no longer climb";
            ASSERT_TRUE(result.grantKey.has_value()) << member.userId;
            EXPECT_EQ(result.grantKey->getPublicKey(), group.state.grantPublicKey) << member.userId;
        }
    }

    static Nodes refreshedOf(const CommitPlan& plan) {
        Nodes nodes;
        for (const RefreshedNode& refreshed : plan.refreshed) {
            nodes.push_back(refreshed.nodeIndex);
        }
        return nodes;
    }

    // The keys the committer of `plan` held right after it: the grant key and every node key it minted.
    static std::vector<PrivateKey> keysOf(const CommitPlan& plan) {
        std::vector<PrivateKey> keys{plan.grantKey};
        for (const RefreshedNode& minted : plan.refreshed) {
            keys.push_back(minted.key);
        }
        return keys;
    }

    // Nothing in `held` opens the current grant key or any current node key.
    static void expectReachesNothingCurrent(const TreeGroupState& state, std::vector<PrivateKey>& held) {
        const std::set<std::string> reached = reachable(state, held);
        EXPECT_EQ(reached.count(state.grantPublicKey.toBase58DER()), 0u) << "reaches the current grant key";
        for (const TreeNodeState& node : state.nodes) {
            if (node.publicKey.has_value()) {
                EXPECT_EQ(reached.count(node.publicKey->toBase58DER()), 0u)
                    << "reaches current node " << node.nodeIndex;
            }
        }
    }

    static Nodes sorted(Nodes nodes) {
        std::sort(nodes.begin(), nodes.end());
        return nodes;
    }

    // Public keys of everything that opens over the state's edges from the keys given, by real decryption: what a
    // member — or a coalition of former members pooling everything they ever held — can reach. `known` grows by
    // every key opened, so a caller can carry it across states.
    static std::set<std::string> reachable(const TreeGroupState& state, std::vector<PrivateKey>& known) {
        std::set<std::string> reached;
        for (const PrivateKey& key : known) {
            reached.insert(key.getPublicKey().toBase58DER());
        }
        std::set<std::pair<std::size_t, std::size_t>> tried;
        for (bool grew = true; grew;) {
            grew = false;
            for (std::size_t e = 0; e < state.edges.size(); ++e) {
                for (std::size_t k = 0; k < known.size(); ++k) {
                    if (!tried.insert({e, k}).second) {
                        continue;
                    }
                    const auto opened = TreeKeys::unwrapKey(state.edges[e].blob, known[k]);
                    if (opened.has_value() && reached.insert(opened->getPublicKey().toBase58DER()).second) {
                        known.push_back(opened.value());
                        grew = true;
                    }
                }
            }
        }
        return reached;
    }

    // The private key of `nodeIndex` as `holder` opens it over the state's edges.
    static PrivateKey openedKey(const TreeGroupState& state, const PrivateKey& holder, std::uint32_t nodeIndex) {
        std::vector<PrivateKey> known{holder};
        reachable(state, known);
        for (const PrivateKey& key : known) {
            if (recordOf(state, nodeIndex)->publicKey.value() == key.getPublicKey()) {
                return key;
            }
        }
        throw std::runtime_error("node " + std::to_string(nodeIndex) + " does not open");
    }

    static std::optional<PrivateKey> mintedKey(const CommitPlan& plan, std::uint32_t nodeIndex) {
        for (const RefreshedNode& refreshed : plan.refreshed) {
            if (refreshed.nodeIndex == nodeIndex) {
                return refreshed.key;
            }
        }
        return std::nullopt;
    }

    static const TreeNodeState* recordOf(const TreeGroupState& state, std::uint32_t nodeIndex) {
        for (const TreeNodeState& node : state.nodes) {
            if (node.nodeIndex == nodeIndex) {
                return &node;
            }
        }
        return nullptr;
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

// `unwrapKey` passes no `pubOfSignature`, so the signer's public key in the blob is carried and never compared.
// Membership changes are attributable one layer up, on the signed group entry; a single edge is not.
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

// resolution — the expectations the bridge's own tests share

class TreeKeysResolution : public TreeKeysTestBase {
protected:
    // Forty seated leaves; `filled` names the keyed nodes that carry a key, every other keyed node is blank.
    static TreeGroupState fortyLeaves(const std::set<std::uint32_t>& filled, const std::set<std::uint32_t>& blankSeats) {
        TreeGroupState state;
        state.numLeaves = 40;
        for (std::uint32_t i = 0; i < 40; ++i) {
            state.leafAssignment.push_back(
                blankSeats.count(i) > 0 ? std::nullopt : std::optional<std::string>("u" + std::to_string(i))
            );
        }
        for (const std::uint32_t node : {31u, 63u}) {
            TreeNodeState record{node, 3, std::nullopt};
            if (filled.count(node) > 0) {
                record.publicKey = PrivateKey::generateRandom().getPublicKey();
            }
            state.nodes.push_back(record);
        }
        return state;
    }

    static Nodes leaves(std::uint32_t from, std::uint32_t to, const std::set<std::uint32_t>& skip = {}) {
        Nodes nodes;
        for (std::uint32_t position = from; position < to; ++position) {
            if (skip.count(position) == 0) {
                nodes.push_back(TreeMath::leafNode(position));
            }
        }
        return nodes;
    }
};

TEST_F(TreeKeysResolution, AFilledKeyedNodeResolvesToItself) {
    const TreeGroupState state = fortyLeaves({31, 63}, {});
    EXPECT_EQ(TreeKeys::resolution(state, 63), Nodes({63}));
    EXPECT_EQ(TreeKeys::resolution(state, 31), Nodes({31}));
}

TEST_F(TreeKeysResolution, ABucketNodeResolvesToItsSeatedLeaves) {
    const TreeGroupState state = fortyLeaves({31, 63}, {3, 34});
    EXPECT_EQ(TreeKeys::resolution(state, 15), leaves(0, 16, {3})) << "level 4 carries no key";
    EXPECT_EQ(TreeKeys::resolution(state, 71), leaves(32, 40, {34})) << "the truncated right edge";
    EXPECT_EQ(TreeKeys::resolution(state, TreeMath::leafNode(3)), Nodes{}) << "a blank seat resolves to nobody";
}

TEST_F(TreeKeysResolution, ABlankKeyedNodeResolvesThroughToWhatLiesBelow) {
    const TreeGroupState state = fortyLeaves({63}, {5});
    EXPECT_EQ(TreeKeys::resolution(state, 31), leaves(0, 32, {5}));
    Nodes everyone = leaves(0, 32, {5});
    const Nodes right = leaves(32, 40);
    everyone.insert(everyone.end(), right.begin(), right.end());
    EXPECT_EQ(TreeKeys::resolution(fortyLeaves({}, {5}), 63), everyone) << "a blank root resolves to every member";
}

// creation

class TreeKeysCreate : public TreeKeysTestBase {};

TEST_F(TreeKeysCreate, MintsEveryKeyedNodeItsOwnPathLast) {
    for (const std::uint32_t count : {1u, 2u, 3u, 16u, 17u, 33u, 40u, 64u, 128u}) {
        for (const std::uint32_t creator : {0u, count / 2, count - 1}) {
            const std::vector<TestMember> members = makeMembers(count);
            TreeKeyCache cache;
            TreeKeys keys(cache);
            const CommitPlan plan = keys.planCreate(publicOf(members), members[creator].userId, members[creator].priv);
            EXPECT_EQ(sorted(refreshedOf(plan)), TreeMath::keyedNodes(count)) << "N=" << count << " c=" << creator;
            const Nodes own = TreeMath::keyedPath(creator, count);
            const Nodes refreshed = refreshedOf(plan);
            EXPECT_EQ(Nodes(refreshed.end() - own.size(), refreshed.end()), own) << "its own path last, root last";
            for (const RefreshedNode& refreshed : plan.refreshed) {
                EXPECT_EQ(refreshed.generation, 0u);
                EXPECT_FALSE(refreshed.fromGeneration.has_value()) << "a created node has no record to come from";
            }
            EXPECT_EQ(plan.epoch, 1u);
            EXPECT_EQ(plan.edges.back().isGrantEdge, true) << "the grant edge comes last";
        }
    }
}

TEST_F(TreeKeysCreate, EveryMemberClimbs) {
    for (const std::uint32_t count : {1u, 2u, 5u, 17u, 33u, 40u}) {
        expectEveryoneSeatedClimbs(create(count, count - 1));
    }
}

TEST_F(TreeKeysCreate, WrapsEachMintedKeyToTheResolutionOfItsChildren) {
    // Forty seats, the creator at 0: node 31 wraps to its two buckets leaf by leaf, the root to node 31 and to the
    // eight-seat right edge leaf by leaf — 32 + 1 + 8 tree edges and the grant edge.
    const Group group = create(40, 0);
    EXPECT_EQ(group.state.edges.size(), 32u + 1u + 8u + 1u);
    for (const TreeEdge& edge : group.state.edges) {
        if (edge.isGrantEdge) {
            EXPECT_EQ(edge.childIndex, 63u);
            continue;
        }
        if (edge.childKind == EdgeChildKind::Node) {
            EXPECT_EQ(edge.parentIndex, 63u);
            EXPECT_EQ(edge.childIndex, 31u);
            continue;
        }
        const std::uint32_t seat = TreeKeys::positionOf(group.state, edge.childUserId).value();
        EXPECT_EQ(edge.parentIndex, seat < 32 ? 31u : 63u) << "seat " << seat;
    }
}

TEST_F(TreeKeysCreate, ASingleMemberGroupWrapsTheGrantKeyStraightToTheMember) {
    const Group group = create(1);
    ASSERT_EQ(group.state.edges.size(), 1u);
    EXPECT_TRUE(group.state.edges[0].isGrantEdge);
    EXPECT_EQ(group.state.edges[0].childKind, EdgeChildKind::User);
    EXPECT_EQ(climb(group.state, group.members[0]).failure, ClimbFailure::None);
}

TEST_F(TreeKeysCreate, RefusesWhatItCannotCommit) {
    const std::vector<TestMember> members = makeMembers(4);
    TreeKeyCache cache;
    TreeKeys keys(cache);
    EXPECT_THROW(keys.planCreate({}, "user0", members[0].priv), std::invalid_argument);
    EXPECT_THROW(keys.planCreate(publicOf(members), "outsider", members[0].priv), std::invalid_argument)
        << "a creator without a seat has no path of its own to key";
    std::vector<TreeMember> twice = publicOf(members);
    twice.push_back(twice[1]);
    EXPECT_THROW(keys.planCreate(twice, "user0", members[0].priv), std::invalid_argument);
}

// climbing

class TreeKeysClimb : public TreeKeysTestBase {};

TEST_F(TreeKeysClimb, ANonMemberCannotClimb) {
    const Group group = create(4);
    const TestMember outsider{"stranger", PrivateKey::generateRandom()};
    const ClimbResult result = climb(group.state, outsider);
    EXPECT_EQ(result.failure, ClimbFailure::NotAMember);
    EXPECT_FALSE(result.grantKey.has_value());
}

TEST_F(TreeKeysClimb, SECURITY_DetectsACorruptedEdge) {
    Group group = create(40);
    // Replace the edge to member 0 with a wrap of an unrelated key, correctly encrypted to them.
    const PrivateKey impostor = PrivateKey::generateRandom();
    for (TreeEdge& edge : group.state.edges) {
        if (!edge.isGrantEdge && edge.childKind == EdgeChildKind::User && edge.childUserId == group.members[0].userId) {
            edge.blob = TreeKeys::wrapKey(impostor, group.members[0].priv.getPublicKey(), group.members[0].priv);
        }
    }
    TreeKeyCache store;
    TreeKeys keys(store);
    const ClimbResult result = keys.climbToGrantKey(group.state, group.members[0].userId, group.members[0].priv);
    EXPECT_EQ(result.failure, ClimbFailure::Tampered);
    EXPECT_FALSE(result.grantKey.has_value());
    EXPECT_EQ(result.tamperedNode, std::optional<std::uint32_t>(31u));
}

TEST_F(TreeKeysClimb, SECURITY_DetectsASubstitutedGrantKey) {
    Group group = create(4);
    group.state.grantPublicKey = PrivateKey::generateRandom().getPublicKey();
    EXPECT_EQ(climb(group.state, group.members[2]).failure, ClimbFailure::Tampered);
}

TEST_F(TreeKeysClimb, ReportsAMissingEdgeDistinctlyFromTampering) {
    Group group = create(4);
    std::vector<TreeEdge> pruned;
    for (const TreeEdge& edge : group.state.edges) {
        if (edge.isGrantEdge || edge.childUserId != group.members[0].userId) {
            pruned.push_back(edge);
        }
    }
    group.state.edges = pruned;
    EXPECT_EQ(climb(group.state, group.members[0]).failure, ClimbFailure::MissingEdge);
}

// The same authorship boundary inside a whole state: an edge re-issued by somebody else is followed as readily
// as the original — the climb verifies keys against the published node keys and asks nothing about who wrote them.
TEST_F(TreeKeysClimb, AnEdgeReissuedByAStrangerIsStillFollowed) {
    const std::vector<TestMember> members = makeMembers(4);
    TreeKeyCache cache;
    TreeKeys keys(cache);
    const CommitPlan plan = keys.planCreate(publicOf(members), members[0].userId, members[0].priv);
    TreeGroupState state = applied(TreeGroupState{}, plan);

    const auto leafEdge = std::find_if(state.edges.begin(), state.edges.end(), [&](const TreeEdge& edge) {
        return !edge.isGrantEdge && edge.childUserId == members[1].userId;
    });
    ASSERT_NE(leafEdge, state.edges.end());
    leafEdge->blob = TreeKeys::wrapKey(
        mintedKey(plan, leafEdge->parentIndex).value(), members[1].priv.getPublicKey(), PrivateKey::generateRandom()
    );
    const ClimbResult result = climb(state, members[1]);
    EXPECT_EQ(result.failure, ClimbFailure::None);
    ASSERT_TRUE(result.grantKey.has_value());
    EXPECT_EQ(result.grantKey->getPublicKey(), plan.grantKey.getPublicKey());
}

// The victim gets the same `MissingEdge` a truncated response produces, nothing is marked tampered, and the
// roster still seats them — so a server cutting one member off cannot be told from a broken chain.
TEST_F(TreeKeysClimb, AWithheldEdgeIsIndistinguishableFromABrokenState) {
    Group group = create(4);
    std::vector<TreeEdge> published;
    for (const TreeEdge& edge : group.state.edges) {
        if (edge.isGrantEdge || edge.childUserId != group.members[3].userId) {
            published.push_back(edge);
        }
    }
    group.state.edges = published;
    const ClimbResult result = climb(group.state, group.members[3]);
    EXPECT_EQ(result.failure, ClimbFailure::MissingEdge);
    EXPECT_FALSE(result.tamperedNode.has_value());
    for (std::size_t i = 0; i < 3; ++i) {
        EXPECT_EQ(climb(group.state, group.members[i]).failure, ClimbFailure::None)
            << group.members[i].userId << " must be unaffected by another member's edge going missing";
    }
}

TEST_F(TreeKeysClimb, PassesOverAnEdgeFromAnOlderGeneration) {
    // A leftover from before a refresh, served first: it names the node's previous generation, so the climb
    // skips it instead of opening it into a key that no longer matches the published one.
    Group group = create(40);
    const TreeEdge current = *std::find_if(group.state.edges.begin(), group.state.edges.end(), [&](const TreeEdge& e) {
        return e.childUserId == group.members[0].userId;
    });
    TreeEdge stale = current;
    stale.parentGeneration = current.parentGeneration + 7;
    stale.blob = TreeKeys::wrapKey(PrivateKey::generateRandom(), group.members[0].priv.getPublicKey(),
                                   group.members[0].priv);
    group.state.edges.insert(group.state.edges.begin(), stale);
    EXPECT_EQ(climb(group.state, group.members[0]).failure, ClimbFailure::None);
}

TEST_F(TreeKeysClimb, SECURITY_FollowsNoEdgeFromANodeOffItsOwnPath) {
    // Forty seats: node 31 covers seats 0-31, so for seat 35 it is not an ancestor. An edge from it, even one that
    // opens and verifies, must not be taken — it could only come from a server rearranging the tree.
    Group group = create(40, 0);
    const TestMember& outside = group.members[35];
    std::vector<TreeEdge> rearranged;
    for (const TreeEdge& edge : group.state.edges) {
        if (edge.isGrantEdge || edge.childUserId != outside.userId) {
            rearranged.push_back(edge);
        }
    }
    TreeEdge offPath;
    offPath.parentIndex = 31;
    offPath.parentGeneration = recordOf(group.state, 31)->generation;
    offPath.childKind = EdgeChildKind::User;
    offPath.childUserId = outside.userId;
    offPath.blob = TreeKeys::wrapKey(
        openedKey(group.state, group.members[0].priv, 31), outside.priv.getPublicKey(), outside.priv
    );
    rearranged.push_back(offPath);
    group.state.edges = rearranged;
    EXPECT_EQ(climb(group.state, outside).failure, ClimbFailure::MissingEdge);
}

TEST_F(TreeKeysClimb, ReadsAServedStateWithoutParsingNodeKeys) {
    // Climbing verifies each recovered key against the published one by string comparison, so off-path nodes
    // may carry unparseable keys — which is what makes reading a large tree cost `log n` subgroup checks.
    Group group = create(100, 0);
    const Nodes mine = TreeMath::keyedPath(0, 100);
    for (TreeNodeState& node : group.state.nodes) {
        if (std::find(mine.begin(), mine.end(), node.nodeIndex) == mine.end()) {
            node.publicKey = NodePublicKey::fromBase58DER("not-a-key");
        }
    }
    EXPECT_EQ(climb(group.state, group.members[0]).failure, ClimbFailure::None);
}

// The cache-hit path must verify, not just hit

TEST_F(TreeKeysClimb, SECURITY_ACachedGrantKeyThatDoesNotMatchThePublishedOneIsNotServed) {
    const Group group = create(4);
    // Exactly what a cross-group collision looked like: some other group's epoch-1 key sitting in this slot.
    TreeKeyCache store;
    store.putGrantKey(group.state.epoch, PrivateKey::generateRandom());

    TreeKeys keys(store);
    const ClimbResult result = keys.climbToGrantKey(group.state, group.members[0].userId, group.members[0].priv);
    ASSERT_EQ(result.failure, ClimbFailure::None) << "a stale cache entry self-heals; it is not an attack";
    ASSERT_TRUE(result.grantKey.has_value());
    EXPECT_EQ(result.grantKey->getPublicKey(), group.state.grantPublicKey)
        << "the impostor must be ignored and the real key recovered by climbing";
    EXPECT_EQ(store.getGrantKey(group.state.epoch)->getPublicKey(), group.state.grantPublicKey)
        << "the impostor must be evicted, not merely bypassed";
}

TEST_F(TreeKeysClimb, AMatchingCachedGrantKeyStillShortCircuitsTheWalk) {
    const Group group = create(40);
    TreeKeyCache store;
    TreeKeys keys(store);
    ASSERT_EQ(keys.climbToGrantKey(group.state, group.members[0].userId, group.members[0].priv).failure,
              ClimbFailure::None);
    // Strip the edges: if the second climb really short-circuits, it needs none of them.
    TreeGroupState edgeless = group.state;
    edgeless.edges.clear();
    EXPECT_EQ(keys.climbToGrantKey(edgeless, group.members[0].userId, group.members[0].priv).failure,
              ClimbFailure::None) << "verification must not cost the short-circuit";
}

TEST_F(TreeKeysClimb, TwoTreesAtTheSameEpochDoNotAliasThroughOneStore) {
    // The unscoped-cache bug, reproduced at the climb level: two independent groups, both epoch 1. Even
    // sharing a store, the verification on the hit path keeps each climb honest.
    const Group a = create(4);
    const Group b = create(4);
    ASSERT_EQ(a.state.epoch, b.state.epoch);

    TreeKeyCache shared;
    TreeKeys keys(shared);
    const ClimbResult first = keys.climbToGrantKey(a.state, a.members[0].userId, a.members[0].priv);
    ASSERT_EQ(first.failure, ClimbFailure::None);
    EXPECT_EQ(first.grantKey->getPublicKey(), a.state.grantPublicKey);
    const ClimbResult second = keys.climbToGrantKey(b.state, b.members[0].userId, b.members[0].priv);
    ASSERT_EQ(second.failure, ClimbFailure::None);
    EXPECT_EQ(second.grantKey->getPublicKey(), b.state.grantPublicKey)
        << "group B must not be handed group A's grant key";
}

// removal — the property that matters

class TreeKeysRemoval : public TreeKeysTestBase {};

TEST_F(TreeKeysRemoval, RefreshesTheRemoversPathAndBlanksTheLeaversRest) {
    // Seat 5 sits under node 31, seat 35 does not: removing 5 from 35 refreshes the root, blanks node 31, and
    // the root now wraps through the blank to node 31's 31 remaining members one by one.
    Group group = create(40, 0);
    const CommitPlan plan = remove(group, 35, {5});
    EXPECT_EQ(refreshedOf(plan), TreeMath::keyedPath(35, 40));
    EXPECT_EQ(plan.shape.blanked, (std::set<std::uint32_t>{31})) << "the root is re-keyed, not blanked";
    EXPECT_EQ(plan.epoch, 2u);
    EXPECT_EQ(plan.shape.subjectSeats, Nodes({5}));
    ASSERT_NE(recordOf(group.state, 31), nullptr);
    EXPECT_FALSE(recordOf(group.state, 31)->publicKey.has_value()) << "blank, not re-keyed for somebody else";
    EXPECT_EQ(recordOf(group.state, 31)->generation, 0u) << "blanking keeps the generation";
    EXPECT_EQ(plan.edges.size(), 31u + 8u + 1u);
    expectEveryoneSeatedClimbs(group);
}

TEST_F(TreeKeysRemoval, SECURITY_RefusesARemoverAmongTheLeaving) {
    // The remover mints the next grant key; removing yourself would hand you the key meant to lock you out.
    const Group group = create(8);
    EXPECT_THROW(
        planBy(group, 1, [&](TreeKeys& keys, const TestMember& who) {
            return keys.planRemoval(group.state, {group.members[3].userId, who.userId}, who.userId, who.priv);
        }),
        std::invalid_argument
    );
}

TEST_F(TreeKeysRemoval, RefusesWhatItCannotCommit) {
    const Group group = create(4);
    const auto refuse = [&](const std::vector<std::string>& leaving) {
        return planBy(group, 0, [&](TreeKeys& keys, const TestMember& who) {
            return keys.planRemoval(group.state, leaving, who.userId, who.priv);
        });
    };
    EXPECT_THROW(refuse({}), std::invalid_argument);
    EXPECT_THROW(refuse({"user1", "user1"}), std::invalid_argument);
    EXPECT_THROW(refuse({"stranger"}), std::invalid_argument);
    const Group alone = create(1);
    EXPECT_THROW(
        planBy(alone, 0, [&](TreeKeys& keys, const TestMember& who) {
            return keys.planRemoval(alone.state, {who.userId}, who.userId, who.priv);
        }),
        std::invalid_argument
    );
}

TEST_F(TreeKeysRemoval, BatchBlanksTheUnionOfPathsAndWrapsToNoneOfTheLeavers) {
    Group group = create(40, 0);
    const CommitPlan plan = remove(group, 0, {3, 34});
    EXPECT_EQ(plan.shape.subjectSeats, Nodes({3, 34}));
    EXPECT_EQ(refreshedOf(plan), Nodes({31, 63}));
    for (const TreeEdge& edge : plan.edges) {
        EXPECT_NE(edge.childUserId, group.members[3].userId);
        EXPECT_NE(edge.childUserId, group.members[34].userId);
    }
    expectEveryoneSeatedClimbs(group);
}

TEST_F(TreeKeysRemoval, SECURITY_SurvivorsReachTheNewKeyAndTheRemovedDoNot) {
    struct Case {
        std::uint32_t count;
        std::uint32_t remover;
        std::vector<std::uint32_t> leaving;
    };
    const std::vector<Case> cases = {
        {2, 0, {1}},        {4, 3, {0}},         {5, 1, {0}},          {17, 16, {0, 3}},
        {33, 32, {0}},      {33, 0, {32}},       {40, 1, {0}},         {40, 35, {5, 36}},
    };
    for (const Case& c : cases) {
        Group group = create(c.count, 0); // the creator first, then a removal that may take it out
        const CommitPlan plan = remove(group, c.remover, c.leaving);
        for (const std::uint32_t gone : c.leaving) {
            const ClimbResult result = climb(group.state, group.members[gone]);
            EXPECT_NE(result.failure, ClimbFailure::None) << "N=" << c.count << " removed member climbed";
            EXPECT_FALSE(result.grantKey.has_value());
        }
        expectEveryoneSeatedClimbs(group);
        EXPECT_EQ(group.state.grantPublicKey, plan.grantKey.getPublicKey());
    }
}

// The C1 finding, as it was found: the creator mints every node key, and a removal that re-keyed only the leaver's
// own path left the copath keys the leaver had minted opening the refreshed root. Now the removal blanks every node
// the leaver set (V2: seat 40 removes the creator of 64 and re-keys 63 and 95; node 31 is off its path).
TEST_F(TreeKeysRemoval, SECURITY_ARemovedCreatorReachesNothingWithEverythingItEverHeld) {
    CommitPlan created;
    Group group = create(64, 0, &created);
    std::vector<PrivateKey> held = keysOf(created);
    held.push_back(group.members[0].priv);

    const CommitPlan plan = remove(group, 40, {0});
    EXPECT_EQ(sorted(refreshedOf(plan)), Nodes({63, 95}));
    EXPECT_EQ(plan.shape.blanked, (std::set<std::uint32_t>{31}));
    expectReachesNothingCurrent(group.state, held);
}

// The two were removed at different epochs, so between them they hold two generations of the shared path.
TEST_F(TreeKeysRemoval, SECURITY_CollusionBetweenTwoRemovedMembersYieldsNothing) {
    Group group = create(40, 0);
    std::vector<PrivateKey> pooled;
    for (const std::uint32_t leaver : {7u, 36u}) {
        std::vector<PrivateKey> held{group.members[leaver].priv};
        reachable(group.state, held); // everything the leaver could open before leaving
        pooled.insert(pooled.end(), held.begin(), held.end());
        remove(group, 20, {leaver});
    }
    EXPECT_EQ(reachable(group.state, pooled).count(group.state.grantPublicKey.toBase58DER()), 0u);
    expectEveryoneSeatedClimbs(group);
}

// V5: node 63 was re-keyed by seat 40, but it wraps to node 31, which the creator set — so the creator opens it, and
// the removal has to blank the ancestors of what it set too, not only what it set.
TEST_F(TreeKeysRemoval, SECURITY_ARemovalBlanksTheAncestorsOfWhatTheLeaverSet) {
    CommitPlan created;
    Group group = create(128, 0, &created);
    std::vector<PrivateKey> held = keysOf(created);
    held.push_back(group.members[0].priv);
    selfUpdate(group, 40);
    reachable(group.state, held); // whatever the creator opens before it goes

    const CommitPlan plan = remove(group, 100, {0});
    EXPECT_EQ(sorted(refreshedOf(plan)), Nodes({127, 191, 223}));
    EXPECT_EQ(plan.shape.blanked, (std::set<std::uint32_t>{31, 63, 159}));
    expectReachesNothingCurrent(group.state, held);
    expectEveryoneSeatedClimbs(group);
}

// V8: the adder of seat 5 keeps node 31, which it minted off its own path; removing the adder blanks what is left
// of that (node 95), while the remover's path re-keys 31 and 63.
TEST_F(TreeKeysRemoval, SECURITY_ARemovedAdderReachesNothingItMintedForOthers) {
    Group group = create(64, 0);
    std::vector<PrivateKey> held{group.members[40].priv};
    reachable(group.state, held);
    const auto keep = [&](const CommitPlan& plan) {
        const std::vector<PrivateKey> minted = keysOf(plan);
        held.insert(held.end(), minted.begin(), minted.end());
    };
    keep(remove(group, 40, {5}));
    const CommitPlan added = add(group, 40, 1);
    EXPECT_EQ(added.shape.subjectSeats, Nodes({5}));
    EXPECT_EQ(added.shape.filledOffPath, (std::set<std::uint32_t>{31}));
    keep(added);
    reachable(group.state, held);

    const CommitPlan plan = remove(group, 0, {40});
    EXPECT_EQ(sorted(refreshedOf(plan)), Nodes({31, 63}));
    EXPECT_EQ(plan.shape.blanked, (std::set<std::uint32_t>{95}));
    expectReachesNothingCurrent(group.state, held);
    expectEveryoneSeatedClimbs(group);
}

TEST_F(TreeKeysRemoval, RefusesANodeWithNoKnownSetter) {
    Group group = create(64, 0);
    group.state.setters.clear();
    EXPECT_THROW(TreeKeys::shapeRemoval(group.state, {group.members[5].userId}, group.members[40].userId),
                 std::invalid_argument);
}

// A member garbles every wrap, so nobody climbs — itself included, which is the point: it must not be able to block
// its own removal. The plan reads public state only, so the remover needs no climb and no cached key.
TEST_F(TreeKeysRemoval, SECURITY_PlansWithoutAClimbWhenEveryWrapIsGarbled) {
    Group group = create(40, 0);
    for (TreeEdge& edge : group.state.edges) {
        const PrivateKey stranger = PrivateKey::generateRandom();
        edge.blob = TreeKeys::wrapKey(PrivateKey::generateRandom(), stranger.getPublicKey(), stranger);
    }
    ASSERT_NE(climb(group.state, group.members[35]).failure, ClimbFailure::None);

    TreeKeyCache cold;
    TreeKeys keys(cold);
    keys.setMemberKeys(publicOf(group.members));
    const CommitPlan plan = keys.planRemoval(
        group.state, {group.members[0].userId}, group.members[35].userId, group.members[35].priv
    );
    group.state = applied(group.state, plan);
    expectEveryoneSeatedClimbs(group);
    EXPECT_NE(climb(group.state, group.members[0]).failure, ClimbFailure::None);
}

TEST_F(TreeKeysRemoval, ParsesOnlyTheRosterKeysItWrapsTo) {
    // Seat 35 removed by seat 36: the root is the remover's only keyed node and node 31 stays filled, so the root
    // wraps to node 31 and to the seven members left on the right edge — nobody else. Every other roster entry is
    // unparseable here, so planning throws the moment it touches one.
    const Group group = create(40, 0);
    const TestMember& remover = group.members[36];
    const std::vector<std::string> wanted = TreeKeys::recipients(
        group.state, TreeKeys::shapeRemoval(group.state, {group.members[35].userId}, remover.userId)
    );
    EXPECT_EQ(wanted.size(), 7u);
    EXPECT_EQ(std::count(wanted.begin(), wanted.end(), group.members[35].userId), 0) << "never the leaver";

    std::map<std::string, std::string> roster;
    for (const TestMember& member : group.members) {
        const bool needed = std::find(wanted.begin(), wanted.end(), member.userId) != wanted.end();
        roster[member.userId] = needed ? member.priv.getPublicKey().toBase58DER() : std::string("not-a-key");
    }
    TreeKeyCache cache;
    TreeKeys keys(cache);
    ASSERT_EQ(keys.climbToGrantKey(group.state, remover.userId, remover.priv).failure, ClimbFailure::None);
    keys.setMemberKeyStrings(roster);
    EXPECT_NO_THROW(keys.planRemoval(group.state, {group.members[35].userId}, remover.userId, remover.priv));

    // The other direction: lazy must not mean never. One key it does need, made unusable, fails the plan.
    roster[wanted.front()] = "not-a-key";
    keys.setMemberKeyStrings(roster);
    EXPECT_ANY_THROW(keys.planRemoval(group.state, {group.members[35].userId}, remover.userId, remover.priv));
}

// addition

class TreeKeysAddition : public TreeKeysTestBase {};

TEST_F(TreeKeysAddition, TheNewcomersPathIsFilledByTheAdder) {
    // Seat 5 emptied (node 31 blank), then refilled by seat 35: the adder mints node 31 for the newcomer, then its
    // own path (the root). It keeps node 31's key, which its own removal will blank.
    Group group = create(40, 0);
    remove(group, 35, {5});
    const std::uint32_t epoch = group.state.epoch;
    const auto grantBefore = group.state.grantPublicKey;

    const CommitPlan plan = add(group, 35, 1);
    EXPECT_EQ(plan.shape.subjectSeats, Nodes({5})) << "the blank is reused before the tree grows";
    EXPECT_EQ(refreshedOf(plan), Nodes({31, 63}));
    EXPECT_EQ(plan.refreshed[0].fromGeneration, std::optional<std::uint32_t>(0u));
    EXPECT_EQ(plan.refreshed[0].generation, 1u);
    EXPECT_TRUE(plan.shape.blanked.empty()) << "an addition blanks nothing";
    EXPECT_EQ(recordOf(group.state, 31)->setBy, std::optional<std::uint64_t>(plan.seq));
    EXPECT_EQ(group.state.epoch, epoch) << "an addition must not advance the epoch";
    EXPECT_EQ(group.state.grantPublicKey, grantBefore) << "nor change the grant key";
    expectEveryoneSeatedClimbs(group);
    EXPECT_NE(climb(group.state, group.members[5]).failure, ClimbFailure::None) << "the seat's old holder stays out";
}

TEST_F(TreeKeysAddition, GrowthAcrossARootChangeKeepsTheOldRootWhenItIsHighEnough) {
    // 32 seats to 33: root 31 becomes the left child of root 63 and, at level 5, stays keyed.
    Group group = create(32, 0);
    const CommitPlan plan = add(group, 0, 1);
    EXPECT_EQ(group.state.numLeaves, 33u);
    EXPECT_EQ(refreshedOf(plan), Nodes({31, 63}));
    EXPECT_TRUE(plan.shape.blanked.empty()) << "the newcomer's only keyed node is the adder's root";
    const auto grant = std::find_if(group.state.edges.begin(), group.state.edges.end(), [](const TreeEdge& e) {
        return e.isGrantEdge;
    });
    ASSERT_NE(grant, group.state.edges.end());
    EXPECT_EQ(grant->childIndex, 63u);
    expectEveryoneSeatedClimbs(group);
}

TEST_F(TreeKeysAddition, GrowthDropsAnOldRootThatLandsInABucket) {
    // 16 seats to 17: root 15 is a level-4 node under the new root 31, so it carries no key any more. Its record
    // and every edge it held go, or the state would describe keys nobody may use.
    Group group = create(16, 3);
    const CommitPlan plan = add(group, 3, 1);
    EXPECT_EQ(refreshedOf(plan), Nodes({31}));
    EXPECT_EQ(recordOf(group.state, 15), nullptr);
    for (const TreeEdge& edge : group.state.edges) {
        EXPECT_TRUE(edge.isGrantEdge || edge.parentIndex == 31u) << "edge from node " << edge.parentIndex;
    }
    expectEveryoneSeatedClimbs(group);
}

TEST_F(TreeKeysAddition, SeatsTheSecondMemberOfAOneMemberGroup) {
    // The one tree with no internal node at all: the grant edge is addressed to the founder directly, and seating
    // anybody mints the first internal node and moves that edge onto it.
    Group group = create(1);
    const auto grantBefore = group.state.grantPublicKey;
    const CommitPlan plan = add(group, 0, 1);
    EXPECT_EQ(refreshedOf(plan), Nodes({1}));
    EXPECT_EQ(group.state.grantPublicKey, grantBefore);
    expectEveryoneSeatedClimbs(group);
}

TEST_F(TreeKeysAddition, BatchSeatsSeveralAndRefreshesTheAddersPathOnce) {
    Group group = create(30, 2);
    const CommitPlan plan = add(group, 2, 4);
    EXPECT_EQ(plan.shape.subjectSeats, Nodes({30, 31, 32, 33})) << "contiguous appends";
    EXPECT_EQ(group.state.numLeaves, 34u);
    EXPECT_EQ(refreshedOf(plan), TreeMath::keyedPath(2, 34));
    for (std::uint32_t i = 30; i < 34; ++i) {
        const std::string& newcomer = group.members[i].userId;
        EXPECT_EQ(std::count_if(plan.edges.begin(), plan.edges.end(), [&](const TreeEdge& e) {
                      return e.childUserId == newcomer;
                  }),
                  1)
            << newcomer << " must be wrapped to exactly once";
    }
    expectEveryoneSeatedClimbs(group);
}

TEST_F(TreeKeysAddition, RefusesWhatItCannotCommit) {
    const Group group = create(4);
    const std::vector<TestMember> newcomers = makeMembers(2, "new");
    const auto refuse = [&](const std::vector<TreeMember>& who, const Nodes& seats, std::uint32_t adder = 0) {
        return planBy(group, adder, [&](TreeKeys& keys, const TestMember& by) {
            return keys.planAddition(group.state, who, seats, by.userId, by.priv);
        });
    };
    const std::vector<TreeMember> one{publicOf(newcomers)[0]};
    EXPECT_THROW(refuse(one, {4, 5}), std::invalid_argument) << "seats and newcomers must pair up";
    EXPECT_THROW(refuse({}, {}), std::invalid_argument);
    EXPECT_THROW(refuse({one[0], one[0]}, {4, 5}), std::invalid_argument) << "the same newcomer twice";
    EXPECT_THROW(refuse({publicOf(group.members)[1]}, {4}), std::invalid_argument) << "already seated";
    EXPECT_THROW(refuse(publicOf(newcomers), {4, 4}), std::invalid_argument) << "two on one seat";
    EXPECT_THROW(refuse(one, {2}), std::invalid_argument) << "an occupied seat";
}

TEST_F(TreeKeysAddition, RequiresTheGrantKeyAndSaysSo) {
    // The root's new key has to be joined to the grant keypair — which has to be climbed for first.
    const Group group = create(4);
    TreeKeyCache empty;
    TreeKeys keys(empty);
    keys.setMemberKeys(publicOf(group.members));
    const std::vector<TestMember> newcomer = makeMembers(1, "new");
    EXPECT_THROW(
        keys.planAddition(group.state, publicOf(newcomer), {4}, group.members[0].userId, group.members[0].priv),
        std::invalid_argument
    );
}

TEST_F(TreeKeysAddition, RequiresTheRosterForTheMembersItWrapsTo) {
    // Members' public keys are not in the tree state — a leaf *is* the member's key — so a caller who did not
    // supply them would leave somebody without an edge.
    const Group group = create(4);
    TreeKeyCache cache;
    TreeKeys keys(cache);
    ASSERT_EQ(keys.climbToGrantKey(group.state, group.members[0].userId, group.members[0].priv).failure,
              ClimbFailure::None);
    const std::vector<TestMember> newcomer = makeMembers(1, "new");
    EXPECT_THROW(
        keys.planAddition(group.state, publicOf(newcomer), {4}, group.members[0].userId, group.members[0].priv),
        std::invalid_argument
    );
}

TEST_F(TreeKeysAddition, ChoosesTheLowestBlankThenAppends) {
    TreeGroupState state;
    state.numLeaves = 4;
    state.leafAssignment = {std::string("a"), std::nullopt, std::string("c"), std::nullopt};
    EXPECT_EQ(TreeKeys::choosePositions(state, 1), Nodes({1}));
    EXPECT_EQ(TreeKeys::choosePositions(state, 3), Nodes({1, 3, 4}));
    state.leafAssignment = {std::string("a"), std::string("b"), std::string("c"), std::string("d")};
    EXPECT_EQ(TreeKeys::choosePositions(state, 1), Nodes({4})) << "no blanks: append";
}

// self-update

class TreeKeysSelfUpdate : public TreeKeysTestBase {};

TEST_F(TreeKeysSelfUpdate, RefillsTheBlanksOnItsOwnPathAndNothingElse) {
    Group group = create(40, 0);
    remove(group, 35, {5}); // node 31 blank, the root at generation 1
    const std::uint32_t epoch = group.state.epoch;
    const auto grant = group.state.grantPublicKey;

    const CommitPlan plan = selfUpdate(group, 9);
    ASSERT_EQ(refreshedOf(plan), Nodes({31, 63}));
    EXPECT_EQ(plan.refreshed[0].fromGeneration, std::optional<std::uint32_t>(0u)) << "the blank kept generation 0";
    EXPECT_EQ(plan.refreshed[0].generation, 1u);
    EXPECT_EQ(plan.refreshed[1].fromGeneration, std::optional<std::uint32_t>(1u));
    EXPECT_EQ(plan.refreshed[1].generation, 2u);
    EXPECT_TRUE(plan.shape.blanked.empty());
    EXPECT_TRUE(recordOf(group.state, 31)->publicKey.has_value());
    EXPECT_EQ(group.state.epoch, epoch) << "a self-update is not a rotation";
    EXPECT_EQ(group.state.grantPublicKey, grant);
    expectEveryoneSeatedClimbs(group);
    EXPECT_NE(climb(group.state, group.members[5]).failure, ClimbFailure::None);
}

TEST_F(TreeKeysSelfUpdate, RefusesWhatItCannotCommit) {
    const Group alone = create(1);
    EXPECT_THROW(
        planBy(alone, 0, [&](TreeKeys& keys, const TestMember& who) {
            return keys.planSelfUpdate(alone.state, who.userId, who.priv);
        }),
        std::invalid_argument
    ) << "a one-leaf tree has nothing to refresh";
    const Group group = create(4);
    EXPECT_THROW(
        planBy(group, 0, [&](TreeKeys& keys, const TestMember& who) {
            return keys.planSelfUpdate(group.state, "stranger", who.priv);
        }),
        std::invalid_argument
    );
    TreeKeyCache empty;
    TreeKeys keys(empty);
    keys.setMemberKeys(publicOf(group.members));
    EXPECT_THROW(keys.planSelfUpdate(group.state, group.members[0].userId, group.members[0].priv),
                 std::invalid_argument)
        << "re-linking the grant edge needs the grant key, climbed for first";
}

// every commit

class TreeKeysCommit : public TreeKeysTestBase {};

// What a removed member needs is predictability, so that is what has to be denied: any key derived from the
// state being replaced is a function of that state and shows up here as an equality; entropy cannot collide.
TEST_F(TreeKeysCommit, SECURITY_NoMintedKeyIsAFunctionOfTheStateItReplaces) {
    Group group = create(40, 0);
    remove(group, 35, {5});
    const std::vector<TestMember> newcomer = makeMembers(1, "new");
    const std::vector<std::function<CommitPlan(TreeKeys&, const TestMember&)>> operations = {
        [&](TreeKeys& keys, const TestMember& who) {
            return keys.planRemoval(group.state, {group.members[7].userId}, who.userId, who.priv);
        },
        [&](TreeKeys& keys, const TestMember& who) {
            return keys.planAddition(group.state, publicOf(newcomer), {5}, who.userId, who.priv);
        },
        [&](TreeKeys& keys, const TestMember& who) { return keys.planSelfUpdate(group.state, who.userId, who.priv); },
    };
    for (const auto& operation : operations) {
        const CommitPlan first = planBy(group, 1, operation);
        const CommitPlan second = planBy(group, 1, operation);
        ASSERT_EQ(refreshedOf(first), refreshedOf(second));
        for (std::size_t i = 0; i < first.refreshed.size(); ++i) {
            EXPECT_NE(first.refreshed[i].key.toWIF(), second.refreshed[i].key.toWIF())
                << "node " << first.refreshed[i].nodeIndex << " is a function of the state it replaces";
        }
    }
    const CommitPlan a = planBy(group, 1, operations[0]);
    const CommitPlan b = planBy(group, 1, operations[0]);
    EXPECT_NE(a.grantKey.toWIF(), b.grantKey.toWIF()) << "the new epoch's grant key is a function of the old state";
}

// TreeKeyCache — the cache itself

class TreeKeyCacheBasics : public testing::Test {};

TEST_F(TreeKeyCacheBasics, PutOverwritesInPlace) {
    const PrivateKey first = PrivateKey::generateRandom();
    const PrivateKey second = PrivateKey::generateRandom();

    TreeKeyCache store;
    store.putGrantKey(1, first);
    store.putGrantKey(1, second);
    ASSERT_TRUE(store.getGrantKey(1).has_value());
    EXPECT_EQ(store.getGrantKey(1)->toWIF(), second.toWIF());
}

TEST_F(TreeKeyCacheBasics, ForgetGrantKeyRemovesOnlyThatEpoch) {
    TreeKeyCache store;
    store.putGrantKey(1, PrivateKey::generateRandom());
    store.putGrantKey(2, PrivateKey::generateRandom());

    store.forgetGrantKey(1);
    EXPECT_FALSE(store.getGrantKey(1).has_value());
    EXPECT_TRUE(store.getGrantKey(2).has_value());
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
                store.putGrantKey(100 + t, PrivateKey::generateRandom());
                (void)store.getGrantKey(99);
                if (i % 50 == 0) {
                    store.forgetGrantKey(100 + t);
                }
            }
        });
    }
    for (std::thread& thread : threads) {
        thread.join();
    }
    ASSERT_TRUE(store.getGrantKey(99).has_value()) << "another epoch's writes must never touch it";
    EXPECT_EQ(store.getGrantKey(99)->toWIF(), anchor.toWIF());
}

// TreeKeyCacheRegistry — one store per group

class TreeKeyCacheRegistryTest : public testing::Test {};

TEST_F(TreeKeyCacheRegistryTest, SECURITY_GivesEachGroupItsOwnStore) {
    // The whole bug in one assertion: two groups both at epoch 1, sharing one registry, must not see each
    // other's grant key. Node indices and epochs are small integers that every group reuses from 1.
    const PrivateKey keyA = PrivateKey::generateRandom();
    const PrivateKey keyB = PrivateKey::generateRandom();

    TreeKeyCacheRegistry registry;
    registry.get("groupA")->putGrantKey(1, keyA);
    registry.get("groupB")->putGrantKey(1, keyB);

    EXPECT_EQ(registry.get("groupA")->getGrantKey(1)->toWIF(), keyA.toWIF());
    EXPECT_EQ(registry.get("groupB")->getGrantKey(1)->toWIF(), keyB.toWIF());
    EXPECT_NE(registry.get("groupA")->getGrantKey(1)->toWIF(), keyB.toWIF());

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
    // Get-or-create has to be atomic: two stores for one group means one of them silently absorbs climbs
    // nobody ever reads back.
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

