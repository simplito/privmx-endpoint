/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

/** Unit tests for the Epoch Ladder with real EC keys and real ECIES; no server, no docker, no network, and no crypto stubs, since the properties under test are cryptographic — that a member holding only a recent epoch key can reach older ones, that a removed member cannot walk forward, and that a substituted rung is detected rather than silently yielding a wrong key — and tests named SECURITY guard confidentiality and fail silently at runtime if the guard regresses. */

#include <gtest/gtest.h>

#include <string>
#include <vector>

#include <privmx/crypto/ecc/PrivateKey.hpp>

#include <privmx/endpoint/group/keytree/LadderKeys.hpp>
#include <privmx/endpoint/group/keytree/TreeKeys.hpp>

using privmx::crypto::PrivateKey;
using namespace privmx::endpoint::group::keytree;

// shared epoch-history simulation used by every Ladder Keys suite below
class LadderKeysTestBase : public testing::Test {
protected:
    static constexpr char AUTHOR[] = "alice";

    /** A group's epoch history: one grant keypair per epoch, all independently random. */
    struct EpochHistory {
        std::vector<PrivateKey> keys; ///< index i holds the key for epoch i+1
        std::vector<EpochRegistryEntry> registry;
        std::vector<ArchiveRung> rungs;
    };

    EpochHistory simulateEpochHistory(std::uint32_t upTo, std::uint32_t eraFloor, bool withSkips = true) {
        EpochHistory history;
        TreeKeyCache store;
        LadderKeys ladder(store);
        const PrivateKey signer = PrivateKey::generateRandom();

        for (std::uint32_t epoch = eraFloor; epoch <= upTo; ++epoch) {
            const PrivateKey key = PrivateKey::generateRandom();
            history.keys.push_back(key);
            history.registry.push_back(EpochRegistryEntry{epoch, key.getPublicKey()});

            const std::optional<PrivateKey> previous = epoch > eraFloor ?
                std::optional<PrivateKey>(history.keys[history.keys.size() - 2]) :
                std::nullopt;
            const std::vector<ArchiveRung> published = ladder.buildRungs(
                epoch, key.getPublicKey(), previous, eraFloor, AUTHOR, signer, withSkips
            );
            history.rungs.insert(history.rungs.end(), published.begin(), published.end());

            // The publisher holds every epoch key it has minted, which is what lets it build skip rungs.
            store.putGrantKey(epoch, key);
        }
        return history;
    }

    const PrivateKey& keyOf(const EpochHistory& history, std::uint32_t epoch, std::uint32_t eraFloor) {
        return history.keys[epoch - eraFloor];
    }
};

class LadderKeysBuild : public LadderKeysTestBase {};
class LadderKeysGather : public LadderKeysTestBase {};
class LadderKeysDescend : public LadderKeysTestBase {};
class LadderKeysEras : public LadderKeysTestBase {};
class LadderKeysRegistry : public LadderKeysTestBase {};

// building rungs

TEST_F(LadderKeysBuild, EmitsNothingAtTheEraFloor) {
    TreeKeyCache store;
    LadderKeys ladder(store);
    const PrivateKey key = PrivateKey::generateRandom();
    EXPECT_TRUE(ladder.buildRungs(1, key.getPublicKey(), std::nullopt, 1, AUTHOR, key).empty())
        << "genesis of an era has nothing below to link to";
    EXPECT_TRUE(ladder.buildRungs(20, key.getPublicKey(), std::nullopt, 20, AUTHOR, key).empty());
}

/** SECURITY — a missing unit rung would be an unrepairable hole, so it must fail loudly. */
TEST_F(LadderKeysBuild, SECURITY_RefusesToBuildWithoutThePreviousEpochKey) {
    TreeKeyCache store;
    LadderKeys ladder(store);
    const PrivateKey key = PrivateKey::generateRandom();
    EXPECT_THROW(ladder.buildRungs(8, key.getPublicKey(), std::nullopt, 1, AUTHOR, key), std::invalid_argument);
}

TEST_F(LadderKeysBuild, AlwaysEmitsTheUnitRung) {
    const EpochHistory history = simulateEpochHistory(20, 1);
    for (std::uint32_t epoch = 2; epoch <= 20; ++epoch) {
        bool found = false;
        for (const ArchiveRung& rung : history.rungs) {
            if (rung.span.at == epoch && rung.span.target == epoch - 1) {
                found = true;
            }
        }
        EXPECT_TRUE(found) << "epoch " << epoch << " must publish its unit rung";
    }
}

TEST_F(LadderKeysBuild, EmitsAlignedSkipRungsWhenTheKeysAreHeld) {
    const EpochHistory history = simulateEpochHistory(8, 1);
    std::vector<std::uint32_t> targetsAtEight;
    for (const ArchiveRung& rung : history.rungs) {
        if (rung.span.at == 8) {
            targetsAtEight.push_back(rung.span.target);
        }
    }
    std::sort(targetsAtEight.begin(), targetsAtEight.end());
    EXPECT_EQ(targetsAtEight, std::vector<std::uint32_t>({4, 6, 7}));
}

// A skip rung can only be published at the moment its own epoch is created, so a set committed without one is
// a hole no later rotation can fill — and enough holes put history past `descend`'s bound out of everyone's reach.
TEST_F(LadderKeysBuild, SECURITY_RefusesToBuildAnIncompleteSkipSet) {
    TreeKeyCache store;
    LadderKeys ladder(store);
    const PrivateKey previous = PrivateKey::generateRandom();
    const PrivateKey current = PrivateKey::generateRandom();
    // Epoch 8 owes skip rungs to 4 and 6; a publisher holding only epoch 7's key can build neither.
    EXPECT_THROW(
        ladder.buildRungs(8, current.getPublicKey(), previous, 1, AUTHOR, current), std::invalid_argument
    );
}

TEST_F(LadderKeysBuild, EmitsTheUnitRungAloneOnlyWhenAskedTo) {
    TreeKeyCache store;
    LadderKeys ladder(store);
    const PrivateKey previous = PrivateKey::generateRandom();
    const PrivateKey current = PrivateKey::generateRandom();
    const std::vector<ArchiveRung> rungs =
        ladder.buildRungs(8, current.getPublicKey(), previous, 1, AUTHOR, current, /*includeSkipRungs*/ false);
    ASSERT_EQ(rungs.size(), 1u);
    EXPECT_EQ(rungs[0].span.target, 7u);
}

TEST_F(LadderKeysBuild, DoesNotDemandTargetsBelowThePruneWatermark) {
    // Pruning is retention policy: those keys are gone for every member alike, and the bridge rejects rungs
    // pointing below the watermark. Demanding them would block every future rotation on a pruned group.
    EXPECT_EQ(LadderKeys::requiredSkipTargets(8, 1), std::vector<std::uint32_t>({6, 4}));
    EXPECT_EQ(LadderKeys::requiredSkipTargets(8, 1, /*prunedBelow*/ 5), std::vector<std::uint32_t>({6}));

    TreeKeyCache store;
    LadderKeys ladder(store);
    const PrivateKey atSix = PrivateKey::generateRandom();
    const PrivateKey previous = PrivateKey::generateRandom();
    const PrivateKey current = PrivateKey::generateRandom();
    store.putGrantKey(6, atSix);
    const std::vector<ArchiveRung> rungs =
        ladder.buildRungs(8, current.getPublicKey(), previous, 1, AUTHOR, current, true, /*prunedBelow*/ 5);
    ASSERT_EQ(rungs.size(), 2u) << "the unit rung and the one surviving skip target";
    EXPECT_EQ(rungs[0].span.target, 7u);
    EXPECT_EQ(rungs[1].span.target, 6u);
}

TEST_F(LadderKeysBuild, EverySpanPointsDownwards) {
    const EpochHistory history = simulateEpochHistory(40, 1);
    for (const ArchiveRung& rung : history.rungs) {
        EXPECT_LT(rung.span.target, rung.span.at);
        EXPECT_EQ(rung.author, AUTHOR);
    }
}

TEST_F(LadderKeysBuild, CostsAboutTwoRungsPerEpoch) {
    const EpochHistory history = simulateEpochHistory(200, 1);
    const double perEpoch = static_cast<double>(history.rungs.size()) / 199.0;
    EXPECT_LT(perEpoch, 2.0) << "got " << perEpoch;
    EXPECT_GT(perEpoch, 1.5) << "got " << perEpoch;
}

// gathering the older keys a rotation owes rungs to

// The case the gather exists for: a manager whose client started a moment ago holds one grant key, and has to
// publish the same full set a long-running client would.
TEST_F(LadderKeysGather, ColdCacheStillPublishesTheFullSet) {
    const EpochHistory history = simulateEpochHistory(7, 1);

    TreeKeyCache cold;
    LadderKeys ladder(cold);
    cold.putGrantKey(7, keyOf(history, 7, 1)); // all a fresh client has, straight off the climb

    const RungKeyGathering gathered = ladder.gatherRungKeys(8, history.rungs, history.registry);
    ASSERT_TRUE(gathered.complete) << "static_cast<int>(failure)=" << static_cast<int>(gathered.failure);
    EXPECT_TRUE(gathered.missingTargets.empty());

    const PrivateKey next = PrivateKey::generateRandom();
    const std::vector<ArchiveRung> rungs =
        ladder.buildRungs(8, next.getPublicKey(), keyOf(history, 7, 1), 1, AUTHOR, next);
    std::vector<std::uint32_t> targets;
    for (const ArchiveRung& rung : rungs) {
        targets.push_back(rung.span.target);
    }
    std::sort(targets.begin(), targets.end());
    EXPECT_EQ(targets, std::vector<std::uint32_t>({4, 6, 7}));
}

// One unwrap per skip target rather than one walk per target: each target `newEpoch - 2^j` is divisible by
// `2^j`, so its skip rung lands on the next target down and the gather chains through them.
TEST_F(LadderKeysGather, CostsOneUnwrapPerSkipTarget) {
    const EpochHistory history = simulateEpochHistory(255, 1);

    TreeKeyCache cold;
    LadderKeys ladder(cold);
    cold.putGrantKey(255, keyOf(history, 255, 1));

    const RungKeyGathering gathered = ladder.gatherRungKeys(256, history.rungs, history.registry);
    ASSERT_TRUE(gathered.complete);
    const std::size_t targetCount = LadderKeys::requiredSkipTargets(256, 1).size();
    EXPECT_EQ(gathered.unwraps, targetCount) << "one hop per target, so logarithmic in the epoch";
    EXPECT_LE(gathered.unwraps, 8u) << "log2(256)";
}

TEST_F(LadderKeysGather, SkipsTargetsAlreadyInTheCache) {
    const EpochHistory history = simulateEpochHistory(7, 1);

    TreeKeyCache warm;
    LadderKeys ladder(warm);
    for (std::uint32_t epoch = 1; epoch <= 7; ++epoch) {
        warm.putGrantKey(epoch, keyOf(history, epoch, 1));
    }
    const RungKeyGathering gathered = ladder.gatherRungKeys(8, history.rungs, history.registry);
    EXPECT_TRUE(gathered.complete);
    EXPECT_EQ(gathered.unwraps, 0u) << "nothing to recover, so nothing to unwrap";
}

// A ladder with no skip rungs is still walkable one rung at a time. The gather pays that cost once, so the set
// it then publishes restores the fast path.
TEST_F(LadderKeysGather, WalksALinearLadderRatherThanGivingUpOnIt) {
    const EpochHistory history = simulateEpochHistory(63, 1, /*withSkips*/ false);

    TreeKeyCache cold;
    LadderKeys ladder(cold);
    cold.putGrantKey(63, keyOf(history, 63, 1));

    const RungKeyGathering gathered = ladder.gatherRungKeys(64, history.rungs, history.registry);
    ASSERT_TRUE(gathered.complete) << "a unit-only ladder is slower to walk, not unwalkable";
    EXPECT_GT(gathered.unwraps, LadderKeys::requiredSkipTargets(64, 1).size()) << "no skip rungs to ride";

    const PrivateKey next = PrivateKey::generateRandom();
    EXPECT_NO_THROW(ladder.buildRungs(64, next.getPublicKey(), keyOf(history, 63, 1), 1, AUTHOR, next));
}

TEST_F(LadderKeysGather, ReportsEveryTargetCutOffByABreakInTheLadder) {
    const EpochHistory history = simulateEpochHistory(7, 1);

    // Drop every rung landing on epoch 4 — the 6->4 skip and the 5->4 unit rung alike. Epoch 6 is still one hop
    // away, so the walk gets there and then finds nothing leading on.
    std::vector<ArchiveRung> broken;
    for (const ArchiveRung& rung : history.rungs) {
        if (rung.span.target != 4) {
            broken.push_back(rung);
        }
    }

    TreeKeyCache cold;
    LadderKeys ladder(cold);
    cold.putGrantKey(7, keyOf(history, 7, 1));

    const RungKeyGathering gathered = ladder.gatherRungKeys(8, broken, history.registry);
    EXPECT_FALSE(gathered.complete);
    EXPECT_EQ(gathered.failure, DescentFailure::MissingRung);
    EXPECT_EQ(gathered.missingTargets, std::vector<std::uint32_t>({4})) << "6 is still reachable, 4 is not";
}

TEST_F(LadderKeysGather, ReportsNoStartingKeyAsSuch) {
    const EpochHistory history = simulateEpochHistory(7, 1);
    TreeKeyCache empty;
    LadderKeys ladder(empty);
    const RungKeyGathering gathered = ladder.gatherRungKeys(8, history.rungs, history.registry);
    EXPECT_FALSE(gathered.complete);
    EXPECT_EQ(gathered.failure, DescentFailure::NotEntitled);
    EXPECT_EQ(gathered.missingTargets, std::vector<std::uint32_t>({6, 4}));
}

/** SECURITY — the gather verifies at every hop, exactly as a reader's descent does, and names the publisher. */
TEST_F(LadderKeysGather, SECURITY_DetectsASubstitutedRungAndRefusesToCacheIt) {
    const EpochHistory history = simulateEpochHistory(7, 1);
    const PrivateKey attacker = PrivateKey::generateRandom();

    std::vector<ArchiveRung> tampered = history.rungs;
    for (ArchiveRung& rung : tampered) {
        if (rung.span.at == 7 && rung.span.target == 6) {
            // A key that decrypts fine but is not epoch 6's, published under a name the blame can land on.
            rung.blob = TreeKeys::wrapKey(attacker, keyOf(history, 7, 1).getPublicKey(), attacker);
            rung.author = "mallory";
        }
    }

    TreeKeyCache cold;
    LadderKeys ladder(cold);
    cold.putGrantKey(7, keyOf(history, 7, 1));

    const RungKeyGathering gathered = ladder.gatherRungKeys(8, tampered, history.registry);
    EXPECT_FALSE(gathered.complete);
    EXPECT_EQ(gathered.failure, DescentFailure::Tampered);
    ASSERT_TRUE(gathered.blame.has_value());
    EXPECT_EQ(gathered.blame.value(), "mallory");
    EXPECT_FALSE(cold.getGrantKey(6).has_value()) << "a key that failed verification is never cached";
}

// descending

TEST_F(LadderKeysDescend, RecoversEveryOlderEpochKey) {
    const EpochHistory history = simulateEpochHistory(16, 1);
    for (std::uint32_t target = 1; target <= 16; ++target) {
        TreeKeyCache store;
        LadderKeys ladder(store);
        store.putGrantKey(16, keyOf(history, 16, 1));
        const DescentResult result = ladder.descend(16, target, history.rungs, history.registry);
        ASSERT_EQ(result.failure, DescentFailure::None) << "target " << target;
        ASSERT_TRUE(result.key.has_value());
        EXPECT_EQ(result.key->toWIF(), keyOf(history, target, 1).toWIF()) << "target " << target;
    }
}

TEST_F(LadderKeysDescend, ReturnsTheHeldKeyWhenAlreadyAtTheTarget) {
    const EpochHistory history = simulateEpochHistory(4, 1);
    TreeKeyCache store;
    LadderKeys ladder(store);
    store.putGrantKey(4, keyOf(history, 4, 1));
    const DescentResult result = ladder.descend(4, 4, history.rungs, history.registry);
    ASSERT_EQ(result.failure, DescentFailure::None);
    EXPECT_EQ(result.key->toWIF(), keyOf(history, 4, 1).toWIF());
}

TEST_F(LadderKeysDescend, CachesEveryKeyRecoveredOnTheWay) {
    const EpochHistory history = simulateEpochHistory(16, 1);
    TreeKeyCache store;
    LadderKeys ladder(store);
    store.putGrantKey(16, keyOf(history, 16, 1));
    ASSERT_EQ(ladder.descend(16, 1, history.rungs, history.registry).failure, DescentFailure::None);

    // Everything the walk passed through is now free to fetch.
    for (std::uint32_t epoch : {1u, 16u}) {
        EXPECT_TRUE(store.getGrantKey(epoch).has_value()) << "epoch " << epoch;
    }
}

TEST_F(LadderKeysDescend, WithSkipRungsIsLogarithmicNotLinear) {
    const EpochHistory withSkips = simulateEpochHistory(256, 1, true);
    const EpochHistory unitOnly = simulateEpochHistory(256, 1, false);

    // Count how many rungs are addressed to each epoch: with skips there are more, so the walk is shorter.
    EXPECT_GT(withSkips.rungs.size(), unitOnly.rungs.size());

    TreeKeyCache storeA;
    LadderKeys ladderA(storeA);
    storeA.putGrantKey(256, keyOf(withSkips, 256, 1));
    ASSERT_EQ(ladderA.descend(256, 1, withSkips.rungs, withSkips.registry).failure, DescentFailure::None);

    TreeKeyCache storeB;
    LadderKeys ladderB(storeB);
    storeB.putGrantKey(256, keyOf(unitOnly, 256, 1));
    ASSERT_EQ(ladderB.descend(256, 1, unitOnly.rungs, unitOnly.registry).failure, DescentFailure::None);

    // With skips the descent caches far fewer intermediates, because it lands on fewer epochs.
    std::uint32_t cachedWithSkips = 0;
    std::uint32_t cachedUnitOnly = 0;
    for (std::uint32_t epoch = 1; epoch <= 256; ++epoch) {
        if (storeA.getGrantKey(epoch).has_value()) {
            ++cachedWithSkips;
        }
        if (storeB.getGrantKey(epoch).has_value()) {
            ++cachedUnitOnly;
        }
    }
    EXPECT_LT(cachedWithSkips, 40u) << "expected a logarithmic walk, cached " << cachedWithSkips;
    EXPECT_EQ(cachedUnitOnly, 256u) << "unit-only walk must touch every epoch";
}

TEST_F(LadderKeysDescend, FailsWithoutAStartingKey) {
    const EpochHistory history = simulateEpochHistory(8, 1);
    TreeKeyCache store;
    LadderKeys ladder(store);
    const DescentResult result = ladder.descend(8, 1, history.rungs, history.registry);
    EXPECT_EQ(result.failure, DescentFailure::NotEntitled);
    EXPECT_FALSE(result.key.has_value());
}

TEST_F(LadderKeysDescend, ReportsAMissingRungDistinctly) {
    EpochHistory history = simulateEpochHistory(8, 1);
    std::vector<ArchiveRung> gapped;
    for (const ArchiveRung& rung : history.rungs) {
        if (rung.span.at != 5) {
            gapped.push_back(rung);
        }
    }
    TreeKeyCache store;
    LadderKeys ladder(store);
    store.putGrantKey(5, keyOf(history, 5, 1));
    const DescentResult result = ladder.descend(5, 1, gapped, history.registry);
    EXPECT_EQ(result.failure, DescentFailure::MissingRung);
    EXPECT_EQ(result.reachedEpoch, 5u);
}

TEST_F(LadderKeysDescend, RefusesToDescendUpwards) {
    const EpochHistory history = simulateEpochHistory(4, 1);
    TreeKeyCache store;
    LadderKeys ladder(store);
    store.putGrantKey(2, keyOf(history, 2, 1));
    EXPECT_THROW(ladder.descend(2, 4, history.rungs, history.registry), std::invalid_argument);
}

TEST_F(LadderKeysDescend, StopsAtAnEraFloorAndSaysSo) {
    const EpochHistory history = simulateEpochHistory(20, 1);
    TreeKeyCache store;
    LadderKeys ladder(store);
    store.putGrantKey(20, keyOf(history, 20, 1));
    const DescentResult result = ladder.descend(20, 1, history.rungs, history.registry, /*eraFloor*/ 12);
    EXPECT_EQ(result.failure, DescentFailure::EraBoundary);
    EXPECT_EQ(result.reachedEpoch, 12u) << "partial progress must still be reported";
    EXPECT_FALSE(result.key.has_value());
    EXPECT_TRUE(store.getGrantKey(12).has_value()) << "and cached";
}

TEST_F(LadderKeysDescend, ReportsPruningInPreferenceToTheEraFloor) {
    const EpochHistory history = simulateEpochHistory(20, 1);
    TreeKeyCache store;
    LadderKeys ladder(store);
    store.putGrantKey(20, keyOf(history, 20, 1));
    const DescentResult result = ladder.descend(
        20, 1, history.rungs, history.registry, /*eraFloor*/ 3, /*prunedBelow*/ 15
    );
    EXPECT_EQ(result.failure, DescentFailure::Pruned) << "the stronger constraint is the more useful message";
    EXPECT_EQ(result.reachedEpoch, 15u);
}

TEST_F(LadderKeysDescend, EnforcesTheWalkBound) {
    const EpochHistory history = simulateEpochHistory(64, 1, false);
    TreeKeyCache store;
    LadderKeys ladder(store);
    store.putGrantKey(64, keyOf(history, 64, 1));
    const DescentResult result = ladder.descend(64, 1, history.rungs, history.registry, 1, std::nullopt, /*maxWalk*/ 5);
    EXPECT_EQ(result.failure, DescentFailure::TooLong);
}

TEST_F(LadderKeysDescend, SECURITY_DetectsASubstitutedRung) {
    EpochHistory history = simulateEpochHistory(8, 1);
    const PrivateKey impostor = PrivateKey::generateRandom();
    const PrivateKey signer = PrivateKey::generateRandom();

    // Replace the rung 8->7 with a correctly-encrypted wrap of an unrelated key, authored by someone else.
    for (ArchiveRung& rung : history.rungs) {
        if (rung.span.at == 8 && rung.span.target == 7) {
            rung.blob = TreeKeys::wrapKey(impostor, keyOf(history, 8, 1).getPublicKey(), signer);
            rung.author = "mallory";
        }
    }

    TreeKeyCache store;
    LadderKeys ladder(store);
    store.putGrantKey(8, keyOf(history, 8, 1));
    const DescentResult result = ladder.descend(8, 7, history.rungs, history.registry);
    EXPECT_EQ(result.failure, DescentFailure::Tampered);
    EXPECT_FALSE(result.key.has_value());
    ASSERT_TRUE(result.blame.has_value());
    EXPECT_EQ(result.blame.value(), "mallory") << "tampering must be attributable";
    EXPECT_FALSE(store.getGrantKey(7).has_value()) << "a key failing verification must never be cached";
}

TEST_F(LadderKeysDescend, SECURITY_RoutesAroundACorruptedUnitRungViaASkip) {
    EpochHistory history = simulateEpochHistory(8, 1);
    for (ArchiveRung& rung : history.rungs) {
        if (rung.span.at == 8 && rung.span.target == 7) {
            rung.blob = "corrupted";
        }
    }
    TreeKeyCache store;
    LadderKeys ladder(store);
    store.putGrantKey(8, keyOf(history, 8, 1));

    // Epoch 8 also publishes skips to 6 and 4, so a descent to 4 need not touch the broken rung.
    const DescentResult result = ladder.descend(8, 4, history.rungs, history.registry);
    ASSERT_EQ(result.failure, DescentFailure::None) << "the skip rung should carry the walk";
    EXPECT_EQ(result.key->toWIF(), keyOf(history, 4, 1).toWIF());
}

// The rung is placed in storage directly, because a client that validates on write would never emit one.
TEST_F(LadderKeysDescend, SECURITY_IgnoresAnUpwardRung) {
    EpochHistory history = simulateEpochHistory(8, 1);
    const PrivateKey signer = PrivateKey::generateRandom();

    // Forge a rung claiming to carry epoch 9's key, wrapped so epoch 5's holder could open it.
    const PrivateKey future = PrivateKey::generateRandom();
    ArchiveRung upward;
    upward.span = RungSpan{5, 9};
    upward.recipientKind = RungRecipientKind::Epoch;
    upward.blob = TreeKeys::wrapKey(future, keyOf(history, 5, 1).getPublicKey(), signer);
    upward.author = "mallory";
    history.rungs.push_back(upward);
    history.registry.push_back(EpochRegistryEntry{9, future.getPublicKey()});

    TreeKeyCache store;
    LadderKeys ladder(store);
    store.putGrantKey(5, keyOf(history, 5, 1));
    ASSERT_EQ(ladder.descend(5, 4, history.rungs, history.registry).failure, DescentFailure::None);
    EXPECT_FALSE(store.getGrantKey(9).has_value()) << "an upward rung must never be traversed";
}

/** SECURITY — the ladder must not let a removed member walk forward: a member removed after epoch 5 holds epochs 1..5, and every rung published at 6 and above is wrapped to a grant key they never received, so none of them opens. */
TEST_F(LadderKeysDescend, SECURITY_RemovedMemberCannotWalkForward) {
    const EpochHistory history = simulateEpochHistory(10, 1);
    const std::uint32_t removedAfter = 5;

    for (const ArchiveRung& rung : history.rungs) {
        if (rung.span.at <= removedAfter) {
            continue;
        }
        for (std::uint32_t held = 1; held <= removedAfter; ++held) {
            EXPECT_FALSE(TreeKeys::unwrapKey(rung.blob, keyOf(history, held, 1)).has_value())
                << "epoch " << held << " key opened a rung published at epoch " << rung.span.at;
        }
    }

    // And a descent cannot be started from an epoch they do not hold.
    TreeKeyCache store;
    LadderKeys ladder(store);
    for (std::uint32_t held = 1; held <= removedAfter; ++held) {
        store.putGrantKey(held, keyOf(history, held, 1));
    }
    const DescentResult result = ladder.descend(10, 1, history.rungs, history.registry);
    EXPECT_EQ(result.failure, DescentFailure::NotEntitled);
}

/** The payoff: a member who joins late reads old content with zero ciphertexts created for them. */
TEST_F(LadderKeysDescend, ANewcomerReachesOldEpochsWithNothingWrappedToThem) {
    const EpochHistory history = simulateEpochHistory(12, 1);

    // The newcomer is handed exactly one thing: the current epoch key, through the tree.
    TreeKeyCache store;
    LadderKeys ladder(store);
    store.putGrantKey(12, keyOf(history, 12, 1));

    const DescentResult result = ladder.descend(12, 5, history.rungs, history.registry);
    ASSERT_EQ(result.failure, DescentFailure::None);
    EXPECT_EQ(result.key->toWIF(), keyOf(history, 5, 1).toWIF());

    // Nothing in the archive is addressed to an individual: every rung targets an epoch.
    for (const ArchiveRung& rung : history.rungs) {
        EXPECT_EQ(rung.recipientKind, RungRecipientKind::Epoch);
        EXPECT_TRUE(rung.recipientId.empty());
    }
}

// eras

TEST_F(LadderKeysEras, ALinkAddressedToAUserUnlocksTheClosedEra) {
    const EpochHistory closed = simulateEpochHistory(10, 1);
    const PrivateKey member = PrivateKey::generateRandom();
    const PrivateKey signer = PrivateKey::generateRandom();

    TreeKeyCache store;
    LadderKeys ladder(store);
    const std::vector<ArchiveRung> links = ladder.buildEraLinks(
        10, keyOf(closed, 10, 1), {EraLinkRecipient{RungRecipientKind::User, "bob", member.getPublicKey()}}, AUTHOR,
        signer
    );
    ASSERT_EQ(links.size(), 1u);
    // The link satisfies the direction invariant the server enforces on every rung.
    EXPECT_LT(links[0].span.target, links[0].span.at);
    EXPECT_EQ(links[0].span.target, 10u) << "it carries the closing era's top key";

    const DescentResult crossed = ladder.crossEraBoundary(links, "bob", member, {}, closed.registry);
    ASSERT_EQ(crossed.failure, DescentFailure::None);
    EXPECT_EQ(crossed.key->toWIF(), keyOf(closed, 10, 1).toWIF());

    // From there an ordinary descent continues into the closed era.
    const DescentResult deeper = ladder.descend(10, 1, closed.rungs, closed.registry);
    ASSERT_EQ(deeper.failure, DescentFailure::None);
    EXPECT_EQ(deeper.key->toWIF(), keyOf(closed, 1, 1).toWIF());
}

TEST_F(LadderKeysEras, ALinkAddressedToAGroupCostsOneCiphertextForEveryone) {
    const EpochHistory closed = simulateEpochHistory(6, 1);
    const PrivateKey entitlementGroupKey = PrivateKey::generateRandom();
    const PrivateKey signer = PrivateKey::generateRandom();

    TreeKeyCache store;
    LadderKeys ladder(store);
    const std::vector<ArchiveRung> links = ladder.buildEraLinks(
        6, keyOf(closed, 6, 1),
        {EraLinkRecipient{RungRecipientKind::Group, "oldtimers", entitlementGroupKey.getPublicKey()}}, AUTHOR, signer
    );
    ASSERT_EQ(links.size(), 1u) << "one wrap regardless of how many people are entitled";

    // Any member of that group opens it with the group's key.
    const DescentResult crossed = ladder.crossEraBoundary(
        links, "anyone", PrivateKey::generateRandom(), {{"oldtimers", entitlementGroupKey}}, closed.registry
    );
    ASSERT_EQ(crossed.failure, DescentFailure::None);
    EXPECT_EQ(crossed.key->toWIF(), keyOf(closed, 6, 1).toWIF());
}

TEST_F(LadderKeysEras, WithoutALinkTheBoundaryHolds) {
    const EpochHistory closed = simulateEpochHistory(6, 1);
    const PrivateKey signer = PrivateKey::generateRandom();
    const PrivateKey entitled = PrivateKey::generateRandom();

    TreeKeyCache store;
    LadderKeys ladder(store);
    const std::vector<ArchiveRung> links = ladder.buildEraLinks(
        6, keyOf(closed, 6, 1), {EraLinkRecipient{RungRecipientKind::User, "bob", entitled.getPublicKey()}}, AUTHOR,
        signer
    );

    // Carol is not entitled: the link exists but is not addressed to her.
    const DescentResult result = ladder.crossEraBoundary(
        links, "carol", PrivateKey::generateRandom(), {}, closed.registry
    );
    EXPECT_EQ(result.failure, DescentFailure::EraBoundary);
    EXPECT_FALSE(result.key.has_value());
}

TEST_F(LadderKeysEras, RejectsAnEraLinkAddressedToAnEpoch) {
    TreeKeyCache store;
    LadderKeys ladder(store);
    const PrivateKey key = PrivateKey::generateRandom();
    EXPECT_THROW(
        ladder.buildEraLinks(6, key, {EraLinkRecipient{RungRecipientKind::Epoch, "", key.getPublicKey()}}, AUTHOR, key),
        std::invalid_argument
    );
}

TEST_F(LadderKeysEras, RejectsAnEraLinkThatNamesNoRecipient) {
    // The bridge pairs the two fields: an `epoch` rung names nobody, an era-crossing kind must name who it is
    // for. A link built without an id would be refused there, so it is refused here with an actionable reason.
    TreeKeyCache store;
    LadderKeys ladder(store);
    const PrivateKey key = PrivateKey::generateRandom();
    EXPECT_THROW(
        ladder.buildEraLinks(6, key, {EraLinkRecipient{RungRecipientKind::User, "", key.getPublicKey()}}, AUTHOR, key),
        std::invalid_argument
    );
    EXPECT_THROW(
        ladder.buildEraLinks(6, key, {EraLinkRecipient{RungRecipientKind::Group, "", key.getPublicKey()}}, AUTHOR, key),
        std::invalid_argument
    );
}

TEST_F(LadderKeysEras, SECURITY_DetectsATamperedEraLink) {
    const EpochHistory closed = simulateEpochHistory(6, 1);
    const PrivateKey member = PrivateKey::generateRandom();
    const PrivateKey impostor = PrivateKey::generateRandom();
    const PrivateKey signer = PrivateKey::generateRandom();

    ArchiveRung forged;
    forged.span = RungSpan{7, 6};
    forged.recipientKind = RungRecipientKind::User;
    forged.recipientId = "bob";
    forged.blob = TreeKeys::wrapKey(impostor, member.getPublicKey(), signer);
    forged.author = "mallory";

    TreeKeyCache store;
    LadderKeys ladder(store);
    const DescentResult result = ladder.crossEraBoundary({forged}, "bob", member, {}, closed.registry);
    EXPECT_EQ(result.failure, DescentFailure::Tampered);
    ASSERT_TRUE(result.blame.has_value());
    EXPECT_EQ(result.blame.value(), "mallory");
}

// registry

TEST_F(LadderKeysRegistry, LooksUpAnEpochsPublicKey) {
    const EpochHistory history = simulateEpochHistory(4, 1);
    const auto found = LadderKeys::publicKeyOfEpoch(3, history.registry);
    ASSERT_TRUE(found.has_value());
    EXPECT_EQ(found.value(), keyOf(history, 3, 1).getPublicKey());
    EXPECT_FALSE(LadderKeys::publicKeyOfEpoch(99, history.registry).has_value());
}

/** SECURITY — a key for an epoch absent from the registry cannot be vouched for, so it must be refused. */
TEST_F(LadderKeysRegistry, SECURITY_RefusesAKeyForAnUnknownEpoch) {
    EpochHistory history = simulateEpochHistory(8, 1);
    // Drop epoch 7 from the registry, leaving the rung 8->7 unverifiable.
    std::vector<EpochRegistryEntry> pruned;
    for (const EpochRegistryEntry& entry : history.registry) {
        if (entry.epoch != 7) {
            pruned.push_back(entry);
        }
    }
    TreeKeyCache store;
    LadderKeys ladder(store);
    store.putGrantKey(8, keyOf(history, 8, 1));
    const DescentResult result = ladder.descend(8, 7, history.rungs, pruned);
    EXPECT_EQ(result.failure, DescentFailure::Tampered) << "unverifiable must not mean accepted";
}
