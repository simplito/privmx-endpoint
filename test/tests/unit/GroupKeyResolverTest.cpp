/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

/** Unit tests for resolving a group's grant key through the wire types with real EC keys, going through `server::GroupInfo` rather than the runtime structs since that conversion is exactly where a field mismatch would hide; no server is involved, the group info is assembled here the way the bridge would serve it — with the Epoch Ladder in a separate `server::GroupGetKeyArchiveResult`, because `groupGet` does not carry it — and tests named SECURITY guard confidentiality and fail silently at runtime if the guard regresses. */

#include <gtest/gtest.h>

#include <string>
#include <vector>

#include <privmx/crypto/ecc/PrivateKey.hpp>

#include <privmx/endpoint/group/keytree/GroupKeyResolver.hpp>
#include <privmx/endpoint/group/keytree/TreeMath.hpp>

using privmx::crypto::PrivateKey;
using namespace privmx::endpoint::group;
using namespace privmx::endpoint::group::keytree;

class GroupKeyResolverTestBase : public testing::Test {
protected:
    struct TestMember {
        std::string userId;
        PrivateKey priv;
    };

    /**
     * Builds a tree-backed group exactly as the bridge would serve it after `createGroup`.
     *
     * `archive` mirrors the split in the real API: `groupGet` serves the tree, `groupGetKeyArchive` serves the
     * ladder, and the caller hands both to `resolve()`.
     */
    struct Fixture {
        std::vector<TestMember> members;
        server::GroupInfo group;
        server::GroupGetKeyArchiveResult archive;
        PrivateKey grantKey;
    };

    /** The archive as the bridge serves it for a group that has never rotated: no rungs, no history. */
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

    /** Serialises a runtime edge into the wire shape the bridge would send. */
    server::GroupTreeEdge toWire(const TreeEdge& edge) {
        server::GroupTreeEdge wire;
        wire.isGrantEdge = edge.isGrantEdge;
        wire.parentIndex = static_cast<std::int64_t>(edge.parentIndex);
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

    Fixture buildFixture(std::uint32_t memberCount) {
        Fixture fixture;
        fixture.members = makeMembers(memberCount);

        TreeKeyCache buildStore;
        TreeKeys builder(buildStore);
        const BuildPlan plan = builder.build(publicOf(fixture.members), fixture.members[0].priv);
        fixture.grantKey = plan.grantKey;

        server::GroupInfo& group = fixture.group;
        group.id = "grp1";
        group.contextId = "ctx1";
        group.groupPubKey = plan.grantKey.getPublicKey().toBase58DER();
        group.keyVersion = 1;
        group.numLeaves = static_cast<std::int64_t>(plan.numLeaves);

        std::vector<std::string> leaves;
        for (const TestMember& member : fixture.members) {
            leaves.push_back(member.userId);
        }
        group.leafAssignment = leaves;

        std::vector<server::GroupTreeNode> nodes;
        for (const TreeNodeState& node : plan.nodes) {
            nodes.push_back(server::GroupTreeNode{
                static_cast<std::int64_t>(node.nodeIndex),
                static_cast<std::int64_t>(node.generation),
                node.publicKey.toBase58DER(),
            });
        }
        group.treeNodes = nodes;

        std::vector<server::GroupTreeEdge> edges;
        for (const TreeEdge& edge : plan.edges) {
            edges.push_back(toWire(edge));
        }
        group.treeEdges = edges;
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
    /** Advances a tree-backed group through epochs, publishing rungs, and returns the epoch keys. */
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
                    std::nullopt, std::nullopt, rung.blob, rung.author,
                });
            }
            epochKeys.push_back(next);
            store.putGrantKey(epoch, next);
        }

        // The tree still hands out epoch 1's grant key, so re-link it: the grant edge is what the climb ends on, and the newest epoch key must be what it yields.
        auto edges = fixture.group.treeEdges.value();
        for (server::GroupTreeEdge& edge : edges) {
            if (edge.isGrantEdge.value_or(false)) {
                const TreeGroupState state = GroupKeyResolver::toTreeState(fixture.group);
                const std::uint32_t rootIndex = TreeMath::root(state.numLeaves);
                for (const TreeNodeState& node : state.nodes) {
                    if (node.nodeIndex == rootIndex) {
                        edge.data = TreeKeys::wrapKey(epochKeys.back(), node.publicKey.parsed(), signer);
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
}

// conversions — where a field mismatch would hide

TEST_F(ResolverConversion, RoundTripsTheTreeState) {
    const Fixture fixture = buildFixture(8);
    const TreeGroupState state = GroupKeyResolver::toTreeState(fixture.group);

    EXPECT_EQ(state.numLeaves, 8u);
    EXPECT_EQ(state.epoch, 1u);
    EXPECT_EQ(state.grantPublicKey, fixture.grantKey.getPublicKey());
    EXPECT_EQ(state.nodes.size(), 7u) << "8 leaves means 7 internal nodes";
    EXPECT_EQ(state.edges.size(), 2u * 7u + 1u) << "two edges per internal node plus the grant edge";
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

    const std::vector<EpochRegistryEntry> registry = GroupKeyResolver::toRegistry(fixture.group);
    ASSERT_EQ(registry.size(), 2u);
    // The newest epoch lives in `groupPubKey`, not in `keyHistory`; missing that would leave it unverifiable, and an unverifiable key is one the client refuses.
    const auto current = LadderKeys::publicKeyOfEpoch(5, registry);
    ASSERT_TRUE(current.has_value());
    EXPECT_EQ(current.value(), fixture.grantKey.getPublicKey());
    const auto past = LadderKeys::publicKeyOfEpoch(4, registry);
    ASSERT_TRUE(past.has_value());
    EXPECT_EQ(past.value(), older.getPublicKey());
}

/** The overload `resolve()` actually calls: history from the archive, current epoch from the group. */
TEST_F(ResolverConversion, RegistryFromAnArchiveTakesTheCurrentEpochFromTheGroup) {
    Fixture fixture = buildFixture(2);
    const PrivateKey older = PrivateKey::generateRandom();
    fixture.group.keyVersion = 5;
    fixture.archive.keyVersion = 5;
    fixture.archive.keyHistory = std::vector<server::GroupKeyHistoryEntry>{
        server::GroupKeyHistoryEntry{4, older.getPublicKey().toBase58DER()},
    };

    const std::vector<EpochRegistryEntry> registry =
        GroupKeyResolver::toRegistry(fixture.group, fixture.archive);
    ASSERT_EQ(registry.size(), 2u);
    // The archive carries past epochs only, so an archive-built registry that did not reach into the group would leave the newest epoch unverifiable — and the client accepts no key it cannot verify.
    const auto current = LadderKeys::publicKeyOfEpoch(5, registry);
    ASSERT_TRUE(current.has_value());
    EXPECT_EQ(current.value(), fixture.grantKey.getPublicKey());
    const auto past = LadderKeys::publicKeyOfEpoch(4, registry);
    ASSERT_TRUE(past.has_value());
    EXPECT_EQ(past.value(), older.getPublicKey());
}

/** SECURITY — the client must not take the server's word on rung direction. */
TEST_F(ResolverConversion, SECURITY_DropsUpwardRungsDuringConversion) {
    server::GroupGetKeyArchiveResult archive = emptyArchive(8);
    archive.rungs = std::vector<server::GroupArchiveRung>{
        server::GroupArchiveRung{8, 7, std::nullopt, std::nullopt, "ok", std::nullopt},
        server::GroupArchiveRung{8, 8, std::nullopt, std::nullopt, "self", std::nullopt},
        server::GroupArchiveRung{8, 9, std::nullopt, std::nullopt, "upward", std::nullopt},
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

/** SECURITY — a corrupted edge on the caller's path must be detected, not silently mis-decrypted. */
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

/** The ladder rides in the archive, not on the group, so an archive that does not cover the target is a broken chain rather than a silent fall back to the current epoch. */
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

/** The payoff of the whole design, end to end through the wire types: a newcomer holding nothing but a leaf reaches content from epoch 1, and no ciphertext in the archive is addressed to them. */
TEST_F(ResolverOldEpoch, ANewcomerReachesTheOldestEpochWithNothingWrappedToThem) {
    Fixture fixture = buildFixture(4);
    const std::vector<PrivateKey> epochKeys = advanceEpochs(fixture, 12);

    // Seat a newcomer in a blank left by a removal, and give them one edge — the only thing created for them.
    const TestMember newcomer{"newcomer", PrivateKey::generateRandom()};
    auto leaves = fixture.group.leafAssignment.value();
    leaves[3] = newcomer.userId;
    fixture.group.leafAssignment = leaves;

    // The seat's parent is on leaf 2's direct path but not on leaf 0's, so the one wrap is authored by the member sharing the blank's parent — the cheap case the design aims for: seating into a blank whose parent key the adder already holds costs exactly one wrap and refreshes nothing.
    const TreeGroupState state = GroupKeyResolver::toTreeState(fixture.group);
    const std::uint32_t parentIndex = TreeMath::parent(TreeMath::leafNode(3), state.numLeaves);
    std::uint32_t parentGeneration = 0;
    for (const TreeNodeState& node : state.nodes) {
        if (node.nodeIndex == parentIndex) {
            parentGeneration = node.generation;
        }
    }
    TreeKeyCache adderStore;
    TreeKeys adder(adderStore);
    ASSERT_EQ(
        adder.climbToGrantKey(state, fixture.members[2].userId, fixture.members[2].priv).failure,
        ClimbFailure::None
    );
    const auto parentKey = adderStore.getNodeKey(parentIndex, parentGeneration);
    ASSERT_TRUE(parentKey.has_value()) << "the adder's own climb passes through the blank's parent";

    auto edges = fixture.group.treeEdges.value();
    for (server::GroupTreeEdge& edge : edges) {
        if (edge.childKind == "user" && edge.childUserId.value_or("") == fixture.members[3].userId) {
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

    // Nothing in the archive is addressed to an individual — every rung targets an epoch.
    for (const server::GroupArchiveRung& rung : fixture.archive.rungs) {
        EXPECT_FALSE(rung.recipient.has_value() && !rung.recipient.value().empty());
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

/** SECURITY — a substituted rung is detected during resolution and attributed. */
TEST_F(ResolverOldEpoch, SECURITY_DetectsASubstitutedRung) {
    Fixture fixture = buildFixture(4);
    const std::vector<PrivateKey> epochKeys = advanceEpochs(fixture, 8);
    setOwnLeafPosition(fixture.group, 1);

    const PrivateKey impostor = PrivateKey::generateRandom();
    auto rungs = fixture.archive.rungs;
    for (server::GroupArchiveRung& rung : rungs) {
        if (rung.atKeyVersion == 8 && rung.targetKeyVersion == 7) {
            rung.data = TreeKeys::wrapKey(impostor, epochKeys[7].getPublicKey(), fixture.members[0].priv);
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

// caching — the seam GroupApiImpl::resolveGroupPrivKey actually calls on every read

TEST_F(ResolverCurrentEpoch, ASecondResolveIsServedFromTheCacheWithoutClimbing) {
    // GroupApiImpl keeps one TreeKeyCache alive per group for the whole connection and passes it into every resolve() call; every other test in this file hands resolve() a fresh cache, which proves resolve() is correct but never proves it is cache-backed, so this reuses one cache across two calls, then makes a real second climb impossible (no edges left), so a pass can only mean the cached grant key answered it.
    Fixture fixture = buildFixture(8);
    setOwnLeafPosition(fixture.group, 0);
    TreeKeyCache store;
    GroupKeyResolver resolver(store);

    const ResolveResult first = resolver.resolve(fixture.group, 0, fixture.members[0].priv, fixture.archive);
    ASSERT_EQ(first.failure, ResolveFailure::None);
    ASSERT_TRUE(first.key.has_value());
    ASSERT_EQ(store.nodeKeyCount(), 3u) << "depth(8) == 3 nodes on the direct path, cached by the first climb";

    // Drop the node keys and strip the tree edges: a real second climb is now impossible.
    store.clearNodeKeys();
    fixture.group.treeEdges = std::vector<server::GroupTreeEdge>{};

    const ResolveResult second = resolver.resolve(fixture.group, 0, fixture.members[0].priv, fixture.archive);
    EXPECT_EQ(second.failure, ResolveFailure::None)
        << "resolve() tried to re-climb instead of using the cached grant key, and there was nothing left to "
           "climb with";
    ASSERT_TRUE(second.key.has_value());
    EXPECT_EQ(second.key->toWIF(), first.key->toWIF());
    EXPECT_EQ(store.nodeKeyCount(), 0u) << "a real cache hit recovers no node key";
}
