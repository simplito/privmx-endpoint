/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

/**
 * Resolving a group's grant key through the wire types, with real EC keys.
 *
 * These go through `server::GroupInfo` rather than the runtime structs, since that conversion is exactly where a
 * field mismatch would hide. No server is involved: the group info is assembled here the way the bridge would
 * serve it, with the Epoch Ladder in a separate `server::GroupGetKeyArchiveResult`, because `groupGet` does not
 * carry it.
 *
 * Tests named SECURITY guard confidentiality and fail silently at runtime if the guard regresses.
 */

#include <gtest/gtest.h>

#include <map>
#include <string>
#include <vector>

#include <privmx/crypto/ecc/PrivateKey.hpp>

#include <privmx/endpoint/group/keytree/GroupKeyResolver.hpp>
#include <privmx/endpoint/group/keytree/TreeMath.hpp>
#include <privmx/endpoint/group/keytree/TreeWire.hpp>

using privmx::crypto::PrivateKey;
using namespace privmx::endpoint::group;
using namespace privmx::endpoint::group::keytree;

class GroupKeyResolverTestBase : public testing::Test {
protected:
    struct TestMember {
        std::string userId;
        PrivateKey priv;
    };

    // A tree-backed group as the bridge would serve it after `createGroup`. `archive` mirrors the split in the
    // real API: `groupGet` serves the tree, `groupGetKeyArchive` the ladder, and both go to `resolve()`.
    struct Fixture {
        std::vector<TestMember> members;
        server::GroupInfo group;
        server::GroupGetKeyArchiveResult archive;
        PrivateKey grantKey;
    };

    // The archive as the bridge serves it for a group that has never rotated: no rungs, no history.
    server::GroupGetKeyArchiveResult emptyArchive(std::int64_t keyVersion = 1) {
        server::GroupGetKeyArchiveResult archive;
        archive.keyVersion = keyVersion;
        archive.eraFloor = 1;
        archive.archivePrunedBelow = std::nullopt;
        return archive;
    }

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

    Fixture buildFixture(std::uint32_t memberCount) {
        Fixture fixture;
        fixture.members = makeMembers(memberCount);

        TreeKeyCache buildStore;
        TreeKeys builder(buildStore);
        const CommitPlan plan =
            builder.planCreate(publicOf(fixture.members), fixture.members[0].userId, fixture.members[0].priv);
        fixture.grantKey = plan.grantKey;
        const server::GroupTreeState tree = TreeWire::toCreateTree(plan);

        server::GroupInfo& group = fixture.group;
        group.id = "grp1";
        group.contextId = "ctx1";
        group.groupPubKey = plan.grantKey.getPublicKey().toBase58DER();
        group.keyVersion = 1;
        group.treeVersion = TreeMath::TREE_VERSION;
        group.numLeaves = tree.numLeaves;
        group.leafAssignment = tree.leafAssignment;
        group.treeNodes = tree.nodes;
        group.treeEdges = tree.edges;
        // Only what the resolver reads off the creation statement: who committed it, from which seat.
        server::GroupTreeCommit created;
        created.seq = 1;
        created.committer = fixture.members[0].userId;
        created.committerSeat = 0;
        group.treeCommit = created;
        fixture.archive = emptyArchive(1);
        return fixture;
    }

    void setOwnLeafPosition(server::GroupInfo& group, std::uint32_t position) {
        group.ownLeafPosition = static_cast<std::int64_t>(position);
    }
};

// tree detection — the switch that keeps flat groups untouched

class ResolverDetection : public GroupKeyResolverTestBase {};

// conversions — where a field mismatch would hide

class ResolverConversion : public GroupKeyResolverTestBase {};

// resolving the current epoch

class ResolverCurrentEpoch : public GroupKeyResolverTestBase {};

// resolving an older epoch — tree then ladder

class ResolverOldEpoch : public GroupKeyResolverTestBase {
protected:
    // Advances a tree-backed group through epochs, publishing rungs, and returns the epoch keys.
    std::vector<PrivateKey> advanceEpochs(Fixture& fixture, std::uint32_t upTo) {
        std::vector<PrivateKey> epochKeys{fixture.grantKey};
        std::vector<server::GroupArchiveRung> wireRungs;
        std::vector<server::GroupKeyHistoryEntry> history;

        TreeKeyCache store;
        LadderKeys ladder(store);
        store.putGrantKey(1, fixture.grantKey);
        const PrivateKey signer = fixture.members[0].priv;

        for (std::uint32_t epoch = 2; epoch <= upTo; ++epoch) {
            history.push_back(server::GroupKeyHistoryEntry{
                static_cast<std::int64_t>(epoch - 1), epochKeys.back().getPublicKey().toBase58DER()
            });
            const PrivateKey next = PrivateKey::generateRandom();
            for (const ArchiveRung& rung :
                 ladder.buildRungs(epoch, next.getPublicKey(), epochKeys.back(), 1, "alice", signer)) {
                wireRungs.push_back(server::GroupArchiveRung{
                    static_cast<std::int64_t>(rung.span.at),
                    static_cast<std::int64_t>(rung.span.target),
                    rung.blob, rung.author,
                });
            }
            epochKeys.push_back(next);
            store.putGrantKey(epoch, next);
        }

        // The tree still hands out epoch 1's grant key, so re-link it: the grant edge is what the climb ends
        // on, and the newest epoch key must be what it yields.
        auto edges = fixture.group.treeEdges.value();
        for (server::GroupTreeEdge& edge : edges) {
            if (edge.isGrantEdge.value_or(false)) {
                const TreeGroupState state = GroupKeyResolver::toTreeState(fixture.group);
                const std::uint32_t rootIndex = TreeMath::root(state.numLeaves);
                for (const TreeNodeState& node : state.nodes) {
                    if (node.nodeIndex == rootIndex) {
                        edge.data = TreeKeys::wrapKey(epochKeys.back(), node.publicKey->parsed(), signer);
                    }
                }
                edge.parentGeneration = static_cast<std::int64_t>(upTo);
            }
        }
        fixture.group.treeEdges = edges;
        fixture.group.keyVersion = static_cast<std::int64_t>(upTo);
        fixture.group.groupPubKey = epochKeys.back().getPublicKey().toBase58DER();
        fixture.group.keyHistory = history;
        // The ladder travels in the archive, not on the group: `resolve()` reads the registry and the rungs from
        // what `groupGetKeyArchive` returned, so publishing them anywhere else would not be seen.
        fixture.archive.keyVersion = static_cast<std::int64_t>(upTo);
        fixture.archive.keyHistory = history;
        fixture.archive.rungs = wireRungs;
        fixture.archive.eraFloor = 1;
        return epochKeys;
    }
};

// tree detection — the switch that keeps flat groups untouched

TEST_F(ResolverDetection, AGroupWithoutTreeFieldsIsFlat) {
    server::GroupInfo flat;
    flat.groupPubKey = PrivateKey::generateRandom().getPublicKey().toBase58DER();
    flat.keyVersion = 1;
    EXPECT_FALSE(GroupKeyResolver::hasTree(flat));

    TreeKeyCache store;
    GroupKeyResolver resolver(store);
    const ResolveResult result = resolver.resolve(flat, 0, PrivateKey::generateRandom(), emptyArchive());
    EXPECT_EQ(result.failure, ResolveFailure::NoTree)
        << "a flat group must be reported as such, so the caller keeps using the per-member key entry";
    EXPECT_FALSE(result.key.has_value());
}

TEST_F(ResolverDetection, APartiallyPopulatedTreeIsNotTreatedAsATree) {
    Fixture fixture = buildFixture(4);
    fixture.group.treeEdges = std::nullopt; // nodes present, edges missing
    EXPECT_FALSE(GroupKeyResolver::hasTree(fixture.group));
}

TEST_F(ResolverDetection, AFullyPopulatedTreeIsRecognised) {
    const Fixture fixture = buildFixture(4);
    EXPECT_TRUE(GroupKeyResolver::hasTree(fixture.group));
    EXPECT_TRUE(GroupKeyResolver::hasSupportedTree(fixture.group));
}

TEST_F(ResolverDetection, SECURITY_ATreeOfAnotherVersionIsRefusedNotClimbed) {
    // An older tree climbs just as well and means something else: nothing in it says who set a node. The bridge
    // serves version 1 for groups made before the field existed.
    // Version 2 statements and rungs carry neither the genesis roster nor the rung spans (T3-26).
    for (const std::optional<std::int64_t> version : {std::optional<std::int64_t>(), std::optional<std::int64_t>(1),
                                                      std::optional<std::int64_t>(2), std::optional<std::int64_t>(4)}) {
        Fixture fixture = buildFixture(4);
        fixture.group.treeVersion = version;
        setOwnLeafPosition(fixture.group, 1);
        TreeKeyCache store;
        GroupKeyResolver resolver(store);
        const ResolveResult result = resolver.resolve(fixture.group, 0, fixture.members[1].priv, fixture.archive);
        EXPECT_EQ(result.failure, ResolveFailure::UnsupportedTreeVersion);
        EXPECT_FALSE(result.key.has_value());
    }
}

TEST_F(ResolverDetection, SpotsABlankOnTheCallersOwnPathOnly) {
    Fixture fixture = buildFixture(40);
    setOwnLeafPosition(fixture.group, 0);
    EXPECT_FALSE(GroupKeyResolver::nodeNeedingSelfUpdate(fixture.group).has_value());

    // Node 31 blanked: on seat 0's keyed path, not on seat 35's.
    auto nodes = fixture.group.treeNodes.value();
    for (server::GroupTreeNode& node : nodes) {
        if (node.nodeIndex == 31) {
            node.publicKey = std::nullopt;
        }
    }
    fixture.group.treeNodes = nodes;
    EXPECT_TRUE(GroupKeyResolver::nodeNeedingSelfUpdate(fixture.group).has_value());
    setOwnLeafPosition(fixture.group, 35);
    EXPECT_FALSE(GroupKeyResolver::nodeNeedingSelfUpdate(fixture.group).has_value());

    // A keyed node with no record at all is blank too.
    fixture.group.treeNodes = std::vector<server::GroupTreeNode>{};
    EXPECT_TRUE(GroupKeyResolver::nodeNeedingSelfUpdate(fixture.group).has_value());
}

TEST_F(ResolverDetection, SpotsANodeOnTheCallersPathSetFromOutsideIt) {
    // 64 seats created by seat 0, which minted node 95 (seats 32..63) from outside it.
    Fixture fixture = buildFixture(64);
    setOwnLeafPosition(fixture.group, 0);
    EXPECT_FALSE(GroupKeyResolver::nodeNeedingSelfUpdate(fixture.group).has_value())
        << "the creator's own path is its own";
    setOwnLeafPosition(fixture.group, 40);
    EXPECT_TRUE(GroupKeyResolver::nodeNeedingSelfUpdate(fixture.group).has_value());

    // Seat 40 self-updates over 63 and 95: healed, for seat 63 under 95 as well.
    server::GroupTreeCommit healed;
    healed.seq = 2;
    healed.committer = fixture.members[40].userId;
    healed.committerSeat = 40;
    fixture.group.treeCommits = std::vector<server::GroupTreeCommit>{fixture.group.treeCommit.value()};
    fixture.group.treeCommit = healed;
    auto nodes = fixture.group.treeNodes.value();
    for (server::GroupTreeNode& node : nodes) {
        if (node.nodeIndex == 63 || node.nodeIndex == 95) {
            node.setBy = 2;
        }
    }
    fixture.group.treeNodes = nodes;
    EXPECT_FALSE(GroupKeyResolver::nodeNeedingSelfUpdate(fixture.group).has_value());
    setOwnLeafPosition(fixture.group, 63);
    EXPECT_FALSE(GroupKeyResolver::nodeNeedingSelfUpdate(fixture.group).has_value());

    // A node citing no statement served with it is healed too.
    setOwnLeafPosition(fixture.group, 0);
    EXPECT_FALSE(GroupKeyResolver::nodeNeedingSelfUpdate(fixture.group).has_value());
    for (server::GroupTreeNode& node : nodes) {
        if (node.nodeIndex == 31) {
            node.setBy = 7;
        }
    }
    fixture.group.treeNodes = nodes;
    EXPECT_TRUE(GroupKeyResolver::nodeNeedingSelfUpdate(fixture.group).has_value());
}

TEST_F(ResolverDetection, OnlyTheLowestOccupiedSeatUnderANodeHealsItFirst) {
    // 64 seats created by seat 0, which minted node 95 (seats 32..63) from outside it: all 32 seats need it healed,
    // and one commit does it.
    Fixture fixture = buildFixture(64);
    setOwnLeafPosition(fixture.group, 40);
    ASSERT_EQ(GroupKeyResolver::nodeNeedingSelfUpdate(fixture.group), std::optional<std::uint32_t>(95));
    for (const std::uint32_t seat : {32u, 40u, 63u}) {
        setOwnLeafPosition(fixture.group, seat);
        EXPECT_EQ(GroupKeyResolver::healsFirst(fixture.group, 95), seat == 32) << "seat " << seat;
    }
    // Seats 32..39 left: the lowest occupied one is now 40.
    auto seats = fixture.group.leafAssignment.value();
    std::fill(seats.begin() + 32, seats.begin() + 40, std::string());
    fixture.group.leafAssignment = seats;
    setOwnLeafPosition(fixture.group, 40);
    EXPECT_TRUE(GroupKeyResolver::healsFirst(fixture.group, 95));
    setOwnLeafPosition(fixture.group, 41);
    EXPECT_FALSE(GroupKeyResolver::healsFirst(fixture.group, 95));
}

// conversions — where a field mismatch would hide

TEST_F(ResolverConversion, RoundTripsTheTreeState) {
    const Fixture fixture = buildFixture(8);
    const TreeGroupState state = GroupKeyResolver::toTreeState(fixture.group);

    EXPECT_EQ(state.numLeaves, 8u);
    EXPECT_EQ(state.epoch, 1u);
    EXPECT_EQ(state.grantPublicKey, fixture.grantKey.getPublicKey());
    EXPECT_EQ(state.nodes.size(), 1u) << "eight leaves are one bucket under the root, the only keyed node";
    EXPECT_EQ(state.edges.size(), 8u + 1u) << "one edge per member plus the grant edge";
    for (std::size_t i = 0; i < 8; ++i) {
        ASSERT_TRUE(state.leafAssignment[i].has_value());
        EXPECT_EQ(state.leafAssignment[i].value(), fixture.members[i].userId);
    }
}

TEST_F(ResolverConversion, AnEmptyStringInLeafAssignmentBecomesABlank) {
    Fixture fixture = buildFixture(4);
    auto leaves = fixture.group.leafAssignment.value();
    leaves[2] = ""; // the wire representation of a blank left by a removal
    fixture.group.leafAssignment = leaves;

    const TreeGroupState state = GroupKeyResolver::toTreeState(fixture.group);
    EXPECT_FALSE(state.leafAssignment[2].has_value());
    EXPECT_TRUE(state.leafAssignment[1].has_value());
}

TEST_F(ResolverConversion, DistinguishesTheGrantEdgeFromOrdinaryEdges) {
    const Fixture fixture = buildFixture(4);
    const TreeGroupState state = GroupKeyResolver::toTreeState(fixture.group);
    std::uint32_t grantEdges = 0;
    for (const TreeEdge& edge : state.edges) {
        if (edge.isGrantEdge) {
            ++grantEdges;
        }
    }
    EXPECT_EQ(grantEdges, 1u) << "exactly one edge joins the grant keypair to the root";
}

TEST_F(ResolverConversion, RegistryIncludesTheCurrentEpochNotJustHistory) {
    Fixture fixture = buildFixture(2);
    const PrivateKey older = PrivateKey::generateRandom();
    fixture.group.keyVersion = 5;
    fixture.group.keyHistory = std::vector<server::GroupKeyHistoryEntry>{
        server::GroupKeyHistoryEntry{4, older.getPublicKey().toBase58DER()},
    };

    const std::vector<EpochRegistryEntry> registry = GroupKeyResolver::registryFromGroupHistory(fixture.group);
    ASSERT_EQ(registry.size(), 2u);
    // The newest epoch lives in `groupPubKey`, not in `keyHistory`; missing that would leave it unverifiable,
    // and an unverifiable key is one the client refuses.
    const auto current = LadderKeys::publicKeyOfEpoch(5, registry);
    ASSERT_TRUE(current.has_value());
    EXPECT_EQ(current.value(), fixture.grantKey.getPublicKey());
    const auto past = LadderKeys::publicKeyOfEpoch(4, registry);
    ASSERT_TRUE(past.has_value());
    EXPECT_EQ(past.value(), older.getPublicKey());
}

// The overload `resolve()` actually calls: history from the archive, current epoch from the group.
TEST_F(ResolverConversion, RegistryFromAnArchiveTakesTheCurrentEpochFromTheGroup) {
    Fixture fixture = buildFixture(2);
    const PrivateKey older = PrivateKey::generateRandom();
    fixture.group.keyVersion = 5;
    fixture.archive.keyVersion = 5;
    fixture.archive.keyHistory = std::vector<server::GroupKeyHistoryEntry>{
        server::GroupKeyHistoryEntry{4, older.getPublicKey().toBase58DER()},
    };

    const std::vector<EpochRegistryEntry> registry =
        GroupKeyResolver::registryFromArchive(fixture.group, fixture.archive);
    ASSERT_EQ(registry.size(), 2u);
    // The archive carries past epochs only, so an archive-built registry that did not reach into the group
    // would leave the newest epoch unverifiable — and the client accepts no key it cannot verify.
    const auto current = LadderKeys::publicKeyOfEpoch(5, registry);
    ASSERT_TRUE(current.has_value());
    EXPECT_EQ(current.value(), fixture.grantKey.getPublicKey());
    const auto past = LadderKeys::publicKeyOfEpoch(4, registry);
    ASSERT_TRUE(past.has_value());
    EXPECT_EQ(past.value(), older.getPublicKey());
}

// SECURITY — the client must not take the server's word on rung direction.
TEST_F(ResolverConversion, SECURITY_DropsUpwardRungsDuringConversion) {
    server::GroupGetKeyArchiveResult archive = emptyArchive(8);
    archive.rungs = std::vector<server::GroupArchiveRung>{
        server::GroupArchiveRung{8, 7, "ok", std::nullopt},
        server::GroupArchiveRung{8, 8, "self", std::nullopt},
        server::GroupArchiveRung{8, 9, "upward", std::nullopt},
    };
    const std::vector<ArchiveRung> rungs = GroupKeyResolver::toDownwardRungs(archive);
    ASSERT_EQ(rungs.size(), 1u) << "only the downward rung may survive conversion";
    EXPECT_EQ(rungs[0].span.at, 8u);
    EXPECT_EQ(rungs[0].span.target, 7u);
}

// resolving the current epoch

TEST_F(ResolverCurrentEpoch, EveryMemberResolvesTheGrantKey) {
    for (const std::uint32_t count : {2u, 3u, 4u, 5u, 8u}) {
        Fixture fixture = buildFixture(count);
        for (std::uint32_t position = 0; position < count; ++position) {
            setOwnLeafPosition(fixture.group, position);
            TreeKeyCache store;
            GroupKeyResolver resolver(store);
            const ResolveResult result =
                resolver.resolve(fixture.group, 0, fixture.members[position].priv, fixture.archive);
            ASSERT_EQ(result.failure, ResolveFailure::None) << "count=" << count << " pos=" << position;
            ASSERT_TRUE(result.key.has_value());
            EXPECT_EQ(result.key->getPublicKey(), fixture.grantKey.getPublicKey());
        }
    }
}

TEST_F(ResolverCurrentEpoch, EpochZeroAndTheCurrentEpochAreEquivalent) {
    Fixture fixture = buildFixture(4);
    setOwnLeafPosition(fixture.group, 1);
    TreeKeyCache store;
    GroupKeyResolver resolver(store);
    const ResolveResult byZero = resolver.resolve(fixture.group, 0, fixture.members[1].priv, fixture.archive);
    const ResolveResult byOne = resolver.resolve(fixture.group, 1, fixture.members[1].priv, fixture.archive);
    ASSERT_TRUE(byZero.key.has_value());
    ASSERT_TRUE(byOne.key.has_value());
    EXPECT_EQ(byZero.key->toWIF(), byOne.key->toWIF());
}

TEST_F(ResolverCurrentEpoch, SECURITY_AnEpochPastTheCurrentOneHasNoKey) {
    // C3: asking for epoch 2 of a group at epoch 1 used to return epoch 1's key under epoch 2's name — something a
    // caller would then use to open or seal content it believes belongs to an epoch that does not exist yet.
    Fixture fixture = buildFixture(4);
    setOwnLeafPosition(fixture.group, 1);
    TreeKeyCache store;
    GroupKeyResolver resolver(store);
    const ResolveResult future = resolver.resolve(fixture.group, 2, fixture.members[1].priv, fixture.archive);
    EXPECT_EQ(future.failure, ResolveFailure::FutureEpoch);
    EXPECT_FALSE(future.key.has_value());

    // Range-checked before narrowing: neither may wrap round into a real epoch.
    for (const std::int64_t outOfRange : {std::int64_t(-1), (std::int64_t(1) << 32) + 1}) {
        const ResolveResult result = resolver.resolve(fixture.group, outOfRange, fixture.members[1].priv, fixture.archive);
        EXPECT_EQ(result.failure, ResolveFailure::InvalidEpoch) << outOfRange;
        EXPECT_FALSE(result.key.has_value());
    }
    EXPECT_TRUE(resolver.resolve(fixture.group, 1, fixture.members[1].priv, fixture.archive).key.has_value());
    EXPECT_TRUE(resolver.resolve(fixture.group, 0, fixture.members[1].priv, fixture.archive).key.has_value());
}

TEST_F(ResolverCurrentEpoch, WithoutOwnLeafPositionTheCallerIsNotAMember) {
    const Fixture fixture = buildFixture(4);
    // ownLeafPosition deliberately unset: the bridge did not point at a leaf for this caller.
    TreeKeyCache store;
    GroupKeyResolver resolver(store);
    const ResolveResult result = resolver.resolve(fixture.group, 0, fixture.members[0].priv, fixture.archive);
    EXPECT_EQ(result.failure, ResolveFailure::ClimbFailed);
    EXPECT_EQ(result.climb, ClimbFailure::NotAMember);
}

TEST_F(ResolverCurrentEpoch, AnOutOfRangeLeafPositionIsRejected) {
    Fixture fixture = buildFixture(4);
    setOwnLeafPosition(fixture.group, 99);
    TreeKeyCache store;
    GroupKeyResolver resolver(store);
    EXPECT_EQ(
        resolver.resolve(fixture.group, 0, fixture.members[0].priv, fixture.archive).climb,
        ClimbFailure::NotAMember
    );
}

TEST_F(ResolverCurrentEpoch, AWrongKeyForTheGivenLeafFails) {
    Fixture fixture = buildFixture(4);
    setOwnLeafPosition(fixture.group, 0);
    TreeKeyCache store;
    GroupKeyResolver resolver(store);
    // Pointed at member 0's leaf but holding member 1's key.
    const ResolveResult result = resolver.resolve(fixture.group, 0, fixture.members[1].priv, fixture.archive);
    EXPECT_EQ(result.failure, ResolveFailure::ClimbFailed);
    EXPECT_FALSE(result.key.has_value());
}

TEST_F(ResolverCurrentEpoch, SECURITY_DetectsACorruptedEdge) {
    Fixture fixture = buildFixture(4);
    setOwnLeafPosition(fixture.group, 0);

    const PrivateKey impostor = PrivateKey::generateRandom();
    auto edges = fixture.group.treeEdges.value();
    for (server::GroupTreeEdge& edge : edges) {
        if (edge.childKind == "user" && edge.childUserId.value_or("") == fixture.members[0].userId) {
            edge.data = TreeKeys::wrapKey(
                impostor, fixture.members[0].priv.getPublicKey(), fixture.members[0].priv
            );
        }
    }
    fixture.group.treeEdges = edges;

    TreeKeyCache store;
    GroupKeyResolver resolver(store);
    const ResolveResult result = resolver.resolve(fixture.group, 0, fixture.members[0].priv, fixture.archive);
    EXPECT_EQ(result.failure, ResolveFailure::ClimbFailed);
    EXPECT_EQ(result.climb, ClimbFailure::Tampered) << "tampering must be reported distinctly from a plain miss";
}

TEST_F(ResolverCurrentEpoch, BlamesTheCommitterWhoseStatementSetTheTamperedNode) {
    Fixture fixture = buildFixture(4);
    setOwnLeafPosition(fixture.group, 0);
    server::GroupTreeCommit creation;
    creation.seq = 1; // what the root's record cites
    creation.committer = "creator";
    server::GroupTreeCommit latest;
    latest.seq = 2;
    latest.committer = "latest";
    fixture.group.treeCommits = std::vector<server::GroupTreeCommit>{creation};
    fixture.group.treeCommit = latest;

    const PrivateKey impostor = PrivateKey::generateRandom();
    const std::uint32_t rootIndex = TreeMath::root(4);
    EXPECT_EQ(GroupKeyResolver::tamperedBy(fixture.group, rootIndex), "creator") << "the root's edges are its setter's";
    EXPECT_EQ(GroupKeyResolver::tamperedBy(fixture.group, std::nullopt), "latest") << "the grant edge is the latest's";

    // Through a real climb: member 0's edge to the root opens to the wrong key.
    auto edges = fixture.group.treeEdges.value();
    for (server::GroupTreeEdge& edge : edges) {
        if (edge.childKind == "user" && edge.childUserId.value_or("") == fixture.members[0].userId) {
            edge.data = TreeKeys::wrapKey(impostor, fixture.members[0].priv.getPublicKey(), fixture.members[0].priv);
        }
    }
    fixture.group.treeEdges = edges;
    TreeKeyCache store;
    GroupKeyResolver resolver(store);
    const ResolveResult result = resolver.resolve(fixture.group, 0, fixture.members[0].priv, fixture.archive);
    EXPECT_EQ(result.climb, ClimbFailure::Tampered);
    EXPECT_EQ(result.blame, std::optional<std::string>("creator"));
}

TEST_F(ResolverCurrentEpoch, SECURITY_BlamesTheSetterOfTheNodeWhoseEdgeDoesNotOpen) {
    // T3-16: a garbled edge (sealed to somebody else) fails to decrypt rather than to verify; whoever set the node
    // above it wrote that edge all the same.
    Fixture fixture = buildFixture(4);
    setOwnLeafPosition(fixture.group, 0);
    server::GroupTreeCommit creation;
    creation.seq = 1;
    creation.committer = "creator";
    server::GroupTreeCommit latest;
    latest.seq = 2;
    latest.committer = "latest";
    fixture.group.treeCommits = std::vector<server::GroupTreeCommit>{creation};
    fixture.group.treeCommit = latest;
    auto edges = fixture.group.treeEdges.value();
    for (server::GroupTreeEdge& edge : edges) {
        if (edge.childKind == "user" && edge.childUserId.value_or("") == fixture.members[0].userId) {
            const PrivateKey somebodyElse = PrivateKey::generateRandom();
            edge.data = TreeKeys::wrapKey(somebodyElse, somebodyElse.getPublicKey(), fixture.members[0].priv);
        }
    }
    fixture.group.treeEdges = edges;
    TreeKeyCache store;
    GroupKeyResolver resolver(store);
    const ResolveResult result = resolver.resolve(fixture.group, 0, fixture.members[0].priv, fixture.archive);
    EXPECT_EQ(result.climb, ClimbFailure::DecryptFailed);
    EXPECT_EQ(result.blame, std::optional<std::string>("creator"));
}

// resolving an older epoch — tree then ladder

TEST_F(ResolverOldEpoch, ClimbsThenDescendsToReachAnOlderEpoch) {
    Fixture fixture = buildFixture(4);
    const std::vector<PrivateKey> epochKeys = advanceEpochs(fixture, 12);
    setOwnLeafPosition(fixture.group, 2);

    for (const std::uint32_t target : {1u, 5u, 8u, 11u, 12u}) {
        TreeKeyCache store;
        GroupKeyResolver resolver(store);
        const ResolveResult result = resolver.resolve(
            fixture.group, static_cast<std::int64_t>(target), fixture.members[2].priv, fixture.archive
        );
        ASSERT_EQ(result.failure, ResolveFailure::None) << "target epoch " << target;
        ASSERT_TRUE(result.key.has_value());
        EXPECT_EQ(result.key->toWIF(), epochKeys[target - 1].toWIF()) << "target epoch " << target;
    }
}

// The ladder rides in the archive, not on the group, so an archive that does not cover the target is a broken
// chain rather than a silent fall back to the current epoch.
TEST_F(ResolverOldEpoch, AnArchiveWithoutTheNeededRungsReportsABrokenChain) {
    Fixture fixture = buildFixture(4);
    advanceEpochs(fixture, 12);
    fixture.archive.rungs.clear(); // the window the caller asked `groupGetKeyArchive` for held nothing useful
    setOwnLeafPosition(fixture.group, 2);

    TreeKeyCache store;
    GroupKeyResolver resolver(store);
    const ResolveResult result = resolver.resolve(fixture.group, 3, fixture.members[2].priv, fixture.archive);
    EXPECT_EQ(result.failure, ResolveFailure::DescentFailed);
    EXPECT_EQ(result.descent, DescentFailure::MissingRung);
    EXPECT_FALSE(result.key.has_value()) << "an unreachable epoch must yield no key at all, not the current one";
}

// The payoff of the whole design, end to end through the wire types: a newcomer holding nothing but a leaf
// reaches content from epoch 1, and no ciphertext in the archive is addressed to them.
TEST_F(ResolverOldEpoch, ANewcomerReachesTheOldestEpochWithNothingWrappedToThem) {
    Fixture fixture = buildFixture(4);
    const std::vector<PrivateKey> epochKeys = advanceEpochs(fixture, 12);

    // Seat a newcomer in a blank left by a removal, and give them one edge — the only thing created for them.
    const TestMember newcomer{"newcomer", PrivateKey::generateRandom()};
    auto leaves = fixture.group.leafAssignment.value();
    leaves[3] = newcomer.userId;
    fixture.group.leafAssignment = leaves;

    // The seat's edge comes from its lowest keyed ancestor, which every member's climb passes through — so another
    // member re-wraps it to the newcomer: one wrap, nothing refreshed, and nothing else addressed to them.
    auto edges = fixture.group.treeEdges.value();
    for (server::GroupTreeEdge& edge : edges) {
        if (edge.childKind == "user" && edge.childUserId.value_or("") == fixture.members[3].userId) {
            const auto parentKey = TreeKeys::unwrapKey(edge.data, fixture.members[3].priv); // what the adder climbs past
            ASSERT_TRUE(parentKey.has_value());
            edge.childUserId = newcomer.userId;
            edge.data = TreeKeys::wrapKey(parentKey.value(), newcomer.priv.getPublicKey(), fixture.members[2].priv);
        }
    }
    fixture.group.treeEdges = edges;
    setOwnLeafPosition(fixture.group, 3);

    TreeKeyCache store;
    GroupKeyResolver resolver(store);
    const ResolveResult result = resolver.resolve(fixture.group, 1, newcomer.priv, fixture.archive);
    ASSERT_EQ(result.failure, ResolveFailure::None);
    EXPECT_EQ(result.key->toWIF(), epochKeys[0].toWIF()) << "the newcomer reads epoch 1";

    // Nothing in the archive is addressed to an individual — every rung opens with an epoch's grant key.
    for (const ArchiveRung& rung : GroupKeyResolver::toDownwardRungs(fixture.archive)) {
        EXPECT_TRUE(LadderKeys::openRung(rung, epochKeys[rung.span.at - 1]).has_value());
    }
}

TEST_F(ResolverOldEpoch, StopsAtAnEraFloorAndReportsIt) {
    Fixture fixture = buildFixture(4);
    advanceEpochs(fixture, 12);
    fixture.archive.eraFloor = 8;
    setOwnLeafPosition(fixture.group, 1);

    TreeKeyCache store;
    GroupKeyResolver resolver(store);
    const ResolveResult result = resolver.resolve(fixture.group, 3, fixture.members[1].priv, fixture.archive);
    EXPECT_EQ(result.failure, ResolveFailure::DescentFailed);
    EXPECT_EQ(result.descent, DescentFailure::EraBoundary) << "policy, not an error";
    EXPECT_FALSE(result.key.has_value());
}

TEST_F(ResolverOldEpoch, ReportsPruningDistinctlyFromAnEraBoundary) {
    Fixture fixture = buildFixture(4);
    advanceEpochs(fixture, 12);
    fixture.archive.eraFloor = 2;
    fixture.archive.archivePrunedBelow = 9;
    setOwnLeafPosition(fixture.group, 1);

    TreeKeyCache store;
    GroupKeyResolver resolver(store);
    const ResolveResult result = resolver.resolve(fixture.group, 3, fixture.members[1].priv, fixture.archive);
    EXPECT_EQ(result.descent, DescentFailure::Pruned)
        << "retention and entitlement must read differently to the user";
}

TEST_F(ResolverOldEpoch, SECURITY_DetectsASubstitutedRung) {
    Fixture fixture = buildFixture(4);
    const std::vector<PrivateKey> epochKeys = advanceEpochs(fixture, 8);
    setOwnLeafPosition(fixture.group, 1);

    const PrivateKey impostor = PrivateKey::generateRandom();
    auto rungs = fixture.archive.rungs;
    for (server::GroupArchiveRung& rung : rungs) {
        if (rung.atKeyVersion == 8 && rung.targetKeyVersion == 7) {
            rung.data =
                LadderKeys::sealRung(impostor, RungSpan{8, 7}, epochKeys[7].getPublicKey(), fixture.members[0].priv);
            rung.author = "mallory";
        }
    }
    fixture.archive.rungs = rungs;

    TreeKeyCache store;
    GroupKeyResolver resolver(store);
    const ResolveResult result = resolver.resolve(fixture.group, 7, fixture.members[1].priv, fixture.archive);
    EXPECT_EQ(result.failure, ResolveFailure::DescentFailed);
    EXPECT_EQ(result.descent, DescentFailure::Tampered);
    ASSERT_TRUE(result.blame.has_value());
    EXPECT_EQ(result.blame.value(), "mallory");
}

TEST_F(ResolverOldEpoch, SECURITY_TheLadderIsTakenOnlyAsTheStatementsVouchForIt) {
    // T3-09: the bridge seals a key of its own into the rung down to epoch 7 and lists that key as epoch 7's. Off its
    // `keyHistory` the descent takes it; off the statements, neither the rung nor the key stands.
    Fixture fixture = buildFixture(4);
    const std::vector<PrivateKey> epochKeys = advanceEpochs(fixture, 8);
    setOwnLeafPosition(fixture.group, 1);
    std::map<std::uint64_t, CommitStatement> openers;
    for (std::uint64_t epoch = 1; epoch <= 8; ++epoch) {
        CommitStatement statement;
        statement.keyVersion = epoch;
        statement.groupPubKey = epochKeys[epoch - 1].getPublicKey().toBase58DER();
        statement.committer = "remover";
        statement.committerPubKey = fixture.members[0].priv.getPublicKey().toBase58DER(); // who sealed the rungs
        openers.emplace(epoch, statement);
    }
    const PrivateKey planted = PrivateKey::generateRandom();
    server::GroupGetKeyArchiveResult forged = fixture.archive;
    for (server::GroupArchiveRung& rung : forged.rungs) {
        if (rung.atKeyVersion == 8 && rung.targetKeyVersion == 7) {
            rung.data = LadderKeys::sealRung(
                planted, RungSpan{8, 7}, epochKeys[7].getPublicKey(), PrivateKey::generateRandom()
            );
        }
    }
    for (server::GroupKeyHistoryEntry& entry : forged.keyHistory) {
        if (entry.keyVersion == 7) {
            entry.groupPubKey = planted.getPublicKey().toBase58DER();
        }
    }
    const auto resolve7 = [&](const server::GroupGetKeyArchiveResult& archive) {
        TreeKeyCache store;
        GroupKeyResolver resolver(store);
        return resolver.resolve(fixture.group, 7, fixture.members[1].priv, archive);
    };
    const ResolveResult taken = resolve7(forged);
    ASSERT_TRUE(taken.key.has_value());
    EXPECT_EQ(taken.key->toWIF(), planted.toWIF()) << "the attack, against the archive as served";

    // The planted rung is kept (any member may append a repair rung), but unattributed, and it fails the registry
    // check: the statement names epoch 7's real key, so the planted one is never taken.
    EXPECT_FALSE(resolve7(GroupKeyResolver::authenticated(forged, openers)).key.has_value());

    const server::GroupGetKeyArchiveResult honest = GroupKeyResolver::authenticated(fixture.archive, openers);
    EXPECT_EQ(honest.rungs.size(), fixture.archive.rungs.size());
    for (const server::GroupArchiveRung& rung : honest.rungs) {
        EXPECT_EQ(rung.author, std::optional<std::string>("remover")) << "named by the statement, not the bridge";
    }
    const ResolveResult reached = resolve7(honest);
    ASSERT_TRUE(reached.key.has_value());
    EXPECT_EQ(reached.key->toWIF(), epochKeys[6].toWIF());
}

// Openers of epochs 1..upTo, each naming `committer` (sealing with `sealer`) and the epoch's real grant key.
static std::map<std::uint64_t, CommitStatement> openersOf(
    const std::vector<PrivateKey>& epochKeys, const std::string& committer, const PrivateKey& sealer
) {
    std::map<std::uint64_t, CommitStatement> openers;
    for (std::uint64_t epoch = 1; epoch <= epochKeys.size(); ++epoch) {
        CommitStatement statement;
        statement.keyVersion = epoch;
        statement.groupPubKey = epochKeys[epoch - 1].getPublicKey().toBase58DER();
        statement.committer = committer;
        statement.committerPubKey = sealer.getPublicKey().toBase58DER();
        openers.emplace(epoch, statement);
    }
    return openers;
}

TEST_F(ResolverOldEpoch, SECURITY_ARungSealedByAnotherMemberIsKeptButAttributedToNobody) {
    // L-1: a repair rung appended by another member is what lets a reader cross a broken rung. It is kept, so the
    // descent can use it, but it names nobody: blame comes from the signed statement, never from the bridge.
    Fixture fixture = buildFixture(4);
    const std::vector<PrivateKey> epochKeys = advanceEpochs(fixture, 8);
    setOwnLeafPosition(fixture.group, 1);
    const auto openers = openersOf(epochKeys, "remover", fixture.members[0].priv);
    server::GroupGetKeyArchiveResult archive = fixture.archive;
    for (server::GroupArchiveRung& rung : archive.rungs) {
        if (rung.atKeyVersion == 8 && rung.targetKeyVersion == 7) {
            rung.data = LadderKeys::sealRung(PrivateKey::generateRandom(), RungSpan{8, 7}, epochKeys[7].getPublicKey(),
                                             fixture.members[0].priv); // the opener's rung is garbage
        }
    }
    server::GroupArchiveRung repair{8, 7, LadderKeys::sealRung(epochKeys[6], RungSpan{8, 7}, epochKeys[7].getPublicKey(),
                                                              fixture.members[2].priv), std::string("bridge-says-carol")};
    archive.rungs.push_back(repair);

    const server::GroupGetKeyArchiveResult authenticated = GroupKeyResolver::authenticated(archive, openers);
    ASSERT_EQ(authenticated.rungs.size(), archive.rungs.size()) << "nothing dropped by sealer";
    EXPECT_FALSE(authenticated.rungs.back().author.has_value()) << "another member's rung names nobody";

    TreeKeyCache store;
    GroupKeyResolver resolver(store);
    const ResolveResult result = resolver.resolve(fixture.group, 7, fixture.members[1].priv, authenticated);
    ASSERT_TRUE(result.key.has_value());
    EXPECT_EQ(result.key->toWIF(), epochKeys[6].toWIF()) << "crossed on the repair";
}

TEST_F(ResolverOldEpoch, SECURITY_AtMostEightRungsPerSpanAreKeptOpenerSealedFirst) {
    // A lying bridge serving a span many times over can cost a reader at most eight attempts per span, and the
    // opener's own rung is never pushed out by others.
    Fixture fixture = buildFixture(4);
    const std::vector<PrivateKey> epochKeys = advanceEpochs(fixture, 8);
    const auto openers = openersOf(epochKeys, "remover", fixture.members[0].priv);
    server::GroupGetKeyArchiveResult archive = fixture.archive;
    server::GroupArchiveRung opener;
    std::vector<server::GroupArchiveRung> rest;
    for (const server::GroupArchiveRung& rung : archive.rungs) {
        if (rung.atKeyVersion == 8 && rung.targetKeyVersion == 7) {
            opener = rung;
        } else {
            rest.push_back(rung);
        }
    }
    // Twenty unattributed copies served before the opener's, and twenty more opener-sealed ones after it.
    archive.rungs = rest;
    for (int i = 0; i < 20; ++i) {
        archive.rungs.push_back(server::GroupArchiveRung{8, 7, LadderKeys::sealRung(PrivateKey::generateRandom(),
            RungSpan{8, 7}, epochKeys[7].getPublicKey(), PrivateKey::generateRandom()), std::nullopt});
    }
    archive.rungs.push_back(opener);
    for (int i = 0; i < 20; ++i) {
        archive.rungs.push_back(opener);
    }
    const server::GroupGetKeyArchiveResult authenticated = GroupKeyResolver::authenticated(archive, openers);
    std::vector<server::GroupArchiveRung> span;
    for (const server::GroupArchiveRung& rung : authenticated.rungs) {
        if (rung.atKeyVersion == 8 && rung.targetKeyVersion == 7) {
            span.push_back(rung);
        }
    }
    ASSERT_EQ(span.size(), GroupKeyResolver::MAX_SERVED_RUNGS_PER_SPAN);
    EXPECT_EQ(span.front().data, opener.data) << "the opener's rung comes first";
    EXPECT_EQ(span.front().author, std::optional<std::string>("remover"));
}

// caching — the seam GroupApiImpl::resolveGroupPrivKey actually calls on every read

TEST_F(ResolverCurrentEpoch, ASecondResolveIsServedFromTheCacheWithoutClimbing) {
    // Every other test hands resolve() a fresh cache, proving it correct but never cache-backed. This reuses one
    // cache across two calls, then removes the edges, so a pass can only mean the cached grant key answered.
    Fixture fixture = buildFixture(8);
    setOwnLeafPosition(fixture.group, 0);
    TreeKeyCache store;
    GroupKeyResolver resolver(store);

    const ResolveResult first = resolver.resolve(fixture.group, 0, fixture.members[0].priv, fixture.archive);
    ASSERT_EQ(first.failure, ResolveFailure::None);
    ASSERT_TRUE(first.key.has_value());

    // Strip the tree edges: a real second climb is now impossible.
    fixture.group.treeEdges = std::vector<server::GroupTreeEdge>{};

    const ResolveResult second = resolver.resolve(fixture.group, 0, fixture.members[0].priv, fixture.archive);
    EXPECT_EQ(second.failure, ResolveFailure::None)
        << "resolve() tried to re-climb instead of using the cached grant key, and there was nothing left to "
           "climb with";
    ASSERT_TRUE(second.key.has_value());
    EXPECT_EQ(second.key->toWIF(), first.key->toWIF());
}
