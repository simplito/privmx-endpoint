/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

/**
 * The Epoch Ladder, with real EC keys and real ECIES.
 *
 * No server, no docker, no network, and no crypto stubs, since the properties under test are cryptographic:
 * that a member holding only a recent epoch key can reach older ones, that a removed member cannot walk
 * forward, and that a substituted rung is detected rather than silently yielding a wrong key.
 *
 * Tests named SECURITY guard confidentiality and fail silently at runtime if the guard regresses.
 */

#include <gtest/gtest.h>

#include <algorithm>
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

    // A group's epoch history: one grant keypair per epoch, all independently random.
    struct EpochHistory {
        std::vector<PrivateKey> keys; // index i holds the key for epoch i+1
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
class LadderKeysRegistry : public LadderKeysTestBase {};
class LadderKeysRepair : public LadderKeysTestBase {};
class LadderKeysSelfCheck : public LadderKeysTestBase {};

// building rungs

TEST_F(LadderKeysBuild, EmitsNothingAtTheEraFloor) {
    TreeKeyCache store;
    LadderKeys ladder(store);
    const PrivateKey key = PrivateKey::generateRandom();
    EXPECT_TRUE(ladder.buildRungs(1, key.getPublicKey(), std::nullopt, 1, AUTHOR, key).empty())
        << "genesis of an era has nothing below to link to";
    EXPECT_TRUE(ladder.buildRungs(20, key.getPublicKey(), std::nullopt, 20, AUTHOR, key).empty());
}

// SECURITY — a missing unit rung would be an unrepairable hole, so it must fail loudly.
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
        ladder.buildRungs(8, current.getPublicKey(), previous, 1, AUTHOR, current, false);
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
    const EpochHistory history = simulateEpochHistory(63, 1, false);

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

// SECURITY — the gather verifies at every hop, exactly as a reader's descent does, and names the publisher.
TEST_F(LadderKeysGather, SECURITY_DetectsASubstitutedRungAndRefusesToCacheIt) {
    const EpochHistory history = simulateEpochHistory(7, 1);
    const PrivateKey attacker = PrivateKey::generateRandom();

    std::vector<ArchiveRung> tampered = history.rungs;
    for (ArchiveRung& rung : tampered) {
        if (rung.span.at == 7 && rung.span.target == 6) {
            // A key that decrypts fine but is not epoch 6's, published under a name the blame can land on.
            rung.blob = LadderKeys::sealRung(attacker, rung.span, keyOf(history, 7, 1).getPublicKey(), attacker);
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
            rung.blob = LadderKeys::sealRung(impostor, rung.span, keyOf(history, 8, 1).getPublicKey(), signer);
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

TEST_F(LadderKeysDescend, SECURITY_AForgedSkipRungIsPassedOverForTheNextRoute) {
    // T4-08: anyone holding epoch 8's key can seal a rung at 8 under any span and any sealer, so a rung that does not
    // open to its target's registered key costs the walk that rung, not the descent.
    EpochHistory history = simulateEpochHistory(8, 1);
    for (ArchiveRung& rung : history.rungs) {
        if (rung.span.at == 8 && rung.span.target == 4) {
            rung.blob = LadderKeys::sealRung(
                PrivateKey::generateRandom(), rung.span, keyOf(history, 8, 1).getPublicKey(),
                PrivateKey::generateRandom()
            );
        }
    }
    TreeKeyCache store;
    LadderKeys ladder(store);
    store.putGrantKey(8, keyOf(history, 8, 1));
    const DescentResult result = ladder.descend(8, 4, history.rungs, history.registry);
    ASSERT_EQ(result.failure, DescentFailure::None);
    EXPECT_EQ(result.key->toWIF(), keyOf(history, 4, 1).toWIF());
}

TEST_F(LadderKeysDescend, SECURITY_AnHonestRungRelabelledByTheBridgeBlamesNobody) {
    // T4-08: the span is sealed inside the blob, so the bridge serving the honest rung 8->4 as 8->7 gets a rung that
    // does not open, not one that opens to the wrong epoch's key and names its honest sealer as the tamperer.
    EpochHistory history = simulateEpochHistory(8, 1);
    std::vector<ArchiveRung> served;
    for (const ArchiveRung& rung : history.rungs) {
        if (rung.span.at == 8 && rung.span.target == 4) {
            ArchiveRung relabelled = rung;
            relabelled.span.target = 7;
            served.push_back(relabelled);
        } else if (rung.span.at != 8) {
            served.push_back(rung);
        }
    }
    TreeKeyCache store;
    LadderKeys ladder(store);
    store.putGrantKey(8, keyOf(history, 8, 1));
    const DescentResult result = ladder.descend(8, 7, served, history.registry);
    EXPECT_EQ(result.failure, DescentFailure::DecryptFailed);
    EXPECT_FALSE(result.blame.has_value());
}

// The rung is placed in storage directly, because a client that validates on write would never emit one.
TEST_F(LadderKeysDescend, SECURITY_IgnoresAnUpwardRung) {
    EpochHistory history = simulateEpochHistory(8, 1);
    const PrivateKey signer = PrivateKey::generateRandom();

    // Forge a rung claiming to carry epoch 9's key, wrapped so epoch 5's holder could open it.
    const PrivateKey future = PrivateKey::generateRandom();
    ArchiveRung upward;
    upward.span = RungSpan{5, 9};
    upward.blob = LadderKeys::sealRung(future, upward.span, keyOf(history, 5, 1).getPublicKey(), signer);
    upward.author = "mallory";
    history.rungs.push_back(upward);
    history.registry.push_back(EpochRegistryEntry{9, future.getPublicKey()});

    TreeKeyCache store;
    LadderKeys ladder(store);
    store.putGrantKey(5, keyOf(history, 5, 1));
    ASSERT_EQ(ladder.descend(5, 4, history.rungs, history.registry).failure, DescentFailure::None);
    EXPECT_FALSE(store.getGrantKey(9).has_value()) << "an upward rung must never be traversed";
}

// SECURITY — the ladder must not let a removed member walk forward: a member removed after epoch 5 holds epochs
// 1..5, and every rung published at 6 and above is wrapped to a grant key they never received, so none opens.
TEST_F(LadderKeysDescend, SECURITY_RemovedMemberCannotWalkForward) {
    const EpochHistory history = simulateEpochHistory(10, 1);
    const std::uint32_t removedAfter = 5;

    for (const ArchiveRung& rung : history.rungs) {
        if (rung.span.at <= removedAfter) {
            continue;
        }
        for (std::uint32_t held = 1; held <= removedAfter; ++held) {
            EXPECT_FALSE(LadderKeys::openRung(rung, keyOf(history, held, 1)).has_value())
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

// The payoff: a member who joins late reads old content with zero ciphertexts created for them.
TEST_F(LadderKeysDescend, ANewcomerReachesOldEpochsWithNothingWrappedToThem) {
    const EpochHistory history = simulateEpochHistory(12, 1);

    // The newcomer is handed exactly one thing: the current epoch key, through the tree.
    TreeKeyCache store;
    LadderKeys ladder(store);
    store.putGrantKey(12, keyOf(history, 12, 1));

    const DescentResult result = ladder.descend(12, 5, history.rungs, history.registry);
    ASSERT_EQ(result.failure, DescentFailure::None);
    EXPECT_EQ(result.key->toWIF(), keyOf(history, 5, 1).toWIF());

    // Nothing in the archive is addressed to an individual: every rung opens with an epoch's grant key.
    for (const ArchiveRung& rung : history.rungs) {
        EXPECT_TRUE(LadderKeys::openRung(rung, keyOf(history, rung.span.at, 1)).has_value());
    }
}

// repair rungs (L-1): a span may hold more than one rung; only the registry decides which one is right

namespace {
ArchiveRung sealed(const RungSpan& span, const PrivateKey& carried, const PrivateKey& at, const std::string& author) {
    ArchiveRung rung;
    rung.span = span;
    rung.blob = LadderKeys::sealRung(carried, span, at.getPublicKey(), PrivateKey::generateRandom());
    rung.author = author;
    return rung;
}

std::vector<ArchiveRung> without(std::vector<ArchiveRung> rungs, const RungSpan& span) {
    rungs.erase(std::remove_if(rungs.begin(), rungs.end(), [&](const ArchiveRung& rung) {
        return rung.span.at == span.at && rung.span.target == span.target;
    }), rungs.end());
    return rungs;
}
} // namespace

TEST_F(LadderKeysDescend, SECURITY_ABrokenUnitRungIsCrossedOnARepairRungBesideIt) {
    const EpochHistory history = simulateEpochHistory(8, 1);
    std::vector<ArchiveRung> served = without(history.rungs, RungSpan{8, 7});
    served.push_back(sealed(RungSpan{8, 7}, PrivateKey::generateRandom(), keyOf(history, 8, 1), AUTHOR)); // opener's: garbage
    served.push_back(sealed(RungSpan{8, 7}, keyOf(history, 7, 1), keyOf(history, 8, 1), ""));          // a repair
    TreeKeyCache store;
    LadderKeys ladder(store);
    store.putGrantKey(8, keyOf(history, 8, 1));
    const DescentResult result = ladder.descend(8, 7, served, history.registry);
    ASSERT_EQ(result.failure, DescentFailure::None);
    EXPECT_EQ(result.key->toWIF(), keyOf(history, 7, 1).toWIF());
    EXPECT_FALSE(result.blame.has_value());
    EXPECT_EQ(result.hops, 1u);
}

TEST_F(LadderKeysDescend, ReportsTheSpansItPassedOver) {
    const EpochHistory history = simulateEpochHistory(8, 1);
    std::vector<ArchiveRung> served = without(history.rungs, RungSpan{8, 4});
    served.push_back(sealed(RungSpan{8, 4}, PrivateKey::generateRandom(), keyOf(history, 8, 1), AUTHOR));
    TreeKeyCache store;
    LadderKeys ladder(store);
    store.putGrantKey(8, keyOf(history, 8, 1));
    const DescentResult result = ladder.descend(8, 4, served, history.registry);
    ASSERT_EQ(result.failure, DescentFailure::None) << "routed around via (8,6), (6,4)";
    EXPECT_EQ(result.hops, 2u);
    ASSERT_EQ(result.brokenSpans.size(), 1u);
    EXPECT_EQ(result.brokenSpans[0].at, 8u);
    EXPECT_EQ(result.brokenSpans[0].target, 4u);
}

TEST_F(LadderKeysDescend, SECURITY_AnUnattributedRungThatOpensToTheWrongKeyBlamesNobody) {
    const EpochHistory history = simulateEpochHistory(8, 1);
    std::vector<ArchiveRung> served = without(history.rungs, RungSpan{8, 7});
    served.push_back(sealed(RungSpan{8, 7}, PrivateKey::generateRandom(), keyOf(history, 8, 1), ""));
    TreeKeyCache store;
    LadderKeys ladder(store);
    store.putGrantKey(8, keyOf(history, 8, 1));
    const DescentResult result = ladder.descend(8, 7, served, history.registry);
    EXPECT_EQ(result.failure, DescentFailure::Tampered);
    EXPECT_FALSE(result.blame.has_value()) << "whoever sealed it, the statements do not name them";
    ASSERT_EQ(result.brokenSpans.size(), 1u);
}

TEST_F(LadderKeysDescend, SECURITY_AnUnattributedRungDoesNotHideTheOpenersBadRung) {
    // The unattributed (8,4) is tried first (lowest target) and fails first; the opener's bad (8,7) is still blamed.
    const EpochHistory history = simulateEpochHistory(8, 1);
    std::vector<ArchiveRung> served = without(without(without(history.rungs, RungSpan{8, 7}), RungSpan{8, 6}), RungSpan{8, 4});
    served.push_back(sealed(RungSpan{8, 4}, PrivateKey::generateRandom(), keyOf(history, 8, 1), ""));
    served.push_back(sealed(RungSpan{8, 7}, PrivateKey::generateRandom(), keyOf(history, 8, 1), "opener"));
    TreeKeyCache store;
    LadderKeys ladder(store);
    store.putGrantKey(8, keyOf(history, 8, 1));
    const DescentResult result = ladder.descend(8, 4, served, history.registry);
    EXPECT_EQ(result.failure, DescentFailure::Tampered);
    ASSERT_TRUE(result.blame.has_value());
    EXPECT_EQ(result.blame.value(), "opener");
}

TEST_F(LadderKeysDescend, GarbageDuplicatesCostAttemptsNotHops) {
    const EpochHistory history = simulateEpochHistory(32, 1);
    std::vector<ArchiveRung> served;
    for (const ArchiveRung& rung : history.rungs) {
        for (int i = 0; i < 3; ++i) {
            served.push_back(sealed(rung.span, PrivateKey::generateRandom(), keyOf(history, rung.span.at, 1), ""));
        }
        served.push_back(rung);
    }
    TreeKeyCache clean;
    LadderKeys cleanLadder(clean);
    clean.putGrantKey(32, keyOf(history, 32, 1));
    const DescentResult expected = cleanLadder.descend(32, 3, history.rungs, history.registry);
    TreeKeyCache store;
    LadderKeys ladder(store);
    store.putGrantKey(32, keyOf(history, 32, 1));
    const DescentResult result = ladder.descend(32, 3, served, history.registry);
    ASSERT_EQ(result.failure, DescentFailure::None);
    EXPECT_EQ(result.key->toWIF(), keyOf(history, 3, 1).toWIF());
    EXPECT_EQ(result.hops, expected.hops);
    EXPECT_TRUE(result.brokenSpans.empty()) << "a span with a good rung in it is not broken";
}

// finding what to repair

namespace {
// A cache holding every key of `history` from `from` to `to`, as a member online across those epochs would.
void holdEpochs(TreeKeyCache& cache, const std::vector<PrivateKey>& keys, std::uint32_t from, std::uint32_t to) {
    for (std::uint32_t epoch = from; epoch <= to; ++epoch) {
        cache.putGrantKey(epoch, keys[epoch - 1]);
    }
}
} // namespace

TEST_F(LadderKeysRepair, FindsABrokenUnitRung) {
    const EpochHistory history = simulateEpochHistory(8, 1);
    std::vector<ArchiveRung> served = without(history.rungs, RungSpan{8, 7});
    served.push_back(sealed(RungSpan{8, 7}, PrivateKey::generateRandom(), keyOf(history, 8, 1), AUTHOR));
    TreeKeyCache cache;
    holdEpochs(cache, history.keys, 1, 8);
    const std::vector<RungSpan> unopened = LadderKeys::unopenedSpans(8, served, cache, 1);
    ASSERT_EQ(unopened.size(), 1u);
    EXPECT_EQ(unopened[0].target, 7u);
    EXPECT_TRUE(LadderKeys::unopenedSpans(8, history.rungs, cache, 1).empty()) << "an intact epoch needs nothing";
}

TEST_F(LadderKeysRepair, IgnoresASpanAnyServedRungOpens) {
    const EpochHistory history = simulateEpochHistory(8, 1);
    std::vector<ArchiveRung> served = history.rungs;
    // Garbage beside the good one: already repaired, or never broken.
    served.push_back(sealed(RungSpan{8, 7}, PrivateKey::generateRandom(), keyOf(history, 8, 1), ""));
    TreeKeyCache cache;
    holdEpochs(cache, history.keys, 1, 8);
    EXPECT_TRUE(LadderKeys::unopenedSpans(8, served, cache, 1).empty());
}

TEST_F(LadderKeysRepair, SkipsSpansWhoseTargetKeyIsNotHeld) {
    const EpochHistory history = simulateEpochHistory(8, 1);
    TreeKeyCache cache;
    holdEpochs(cache, history.keys, 7, 8); // joined at 7: holds neither 6 nor 4
    EXPECT_TRUE(LadderKeys::unopenedSpans(8, {}, cache, 1).size() == 1u) << "only (8,7) is sealable by this member";
    TreeKeyCache cold;
    cold.putGrantKey(7, keyOf(history, 7, 1));
    EXPECT_TRUE(LadderKeys::unopenedSpans(8, {}, cold, 1).empty()) << "without sk_8 nothing can be checked or sealed";
}

TEST_F(LadderKeysRepair, SECURITY_NamesOnlyCanonicalDownwardSpansAtOrAboveTheFloor) {
    const EpochHistory history = simulateEpochHistory(8, 1);
    TreeKeyCache cache;
    holdEpochs(cache, history.keys, 1, 8);
    const std::vector<RungSpan> unopened = LadderKeys::unopenedSpans(8, {}, cache, 6);
    std::vector<std::uint32_t> targets;
    for (const RungSpan& span : unopened) {
        EXPECT_EQ(span.at, 8u);
        EXPECT_LT(span.target, span.at);
        targets.push_back(span.target);
    }
    std::sort(targets.begin(), targets.end());
    EXPECT_EQ(targets, (std::vector<std::uint32_t>{6, 7})) << "never (8,4), below the floor; never (8,5)";
}

TEST_F(LadderKeysRepair, TheRememberedFloorNeverGoesDown) {
    TreeKeyCache cache;
    EXPECT_EQ(cache.raiseFloor(1), 1u);
    EXPECT_EQ(cache.raiseFloor(5), 5u);
    EXPECT_EQ(cache.raiseFloor(2), 5u) << "a lower floor served later is ignored";
    cache.clear();
    EXPECT_EQ(cache.raiseFloor(1), 5u) << "forgetting keys does not forget the floor";
}

// the commit self-check

TEST_F(LadderKeysSelfCheck, AnHonestSetPasses) {
    const EpochHistory history = simulateEpochHistory(8, 1);
    std::vector<ArchiveRung> atEight;
    for (const ArchiveRung& rung : history.rungs) {
        if (rung.span.at == 8) {
            atEight.push_back(rung);
        }
    }
    ASSERT_EQ(atEight.size(), 3u);
    EXPECT_FALSE(LadderKeys::firstRungNotOpeningToTheChain(atEight, keyOf(history, 8, 1), history.registry).has_value());
}

TEST_F(LadderKeysSelfCheck, SECURITY_ARungSealingAKeyTheRegistryDoesNotNameIsRefused) {
    // A wrong key in the committer's cache (a client bug) would otherwise become a permanent broken skip rung.
    const EpochHistory history = simulateEpochHistory(8, 1);
    const std::vector<ArchiveRung> rungs{
        sealed(RungSpan{8, 7}, keyOf(history, 7, 1), keyOf(history, 8, 1), AUTHOR),
        sealed(RungSpan{8, 6}, PrivateKey::generateRandom(), keyOf(history, 8, 1), AUTHOR),
    };
    const auto bad = LadderKeys::firstRungNotOpeningToTheChain(rungs, keyOf(history, 8, 1), history.registry);
    ASSERT_TRUE(bad.has_value());
    EXPECT_EQ(bad->target, 6u);
}

TEST_F(LadderKeysSelfCheck, SECURITY_AWrongLabelIsRefused) {
    const EpochHistory history = simulateEpochHistory(8, 1);
    ArchiveRung relabelled = sealed(RungSpan{8, 6}, keyOf(history, 7, 1), keyOf(history, 8, 1), AUTHOR);
    relabelled.span = RungSpan{8, 7}; // the right key, sealed under another span's label
    const auto bad = LadderKeys::firstRungNotOpeningToTheChain({relabelled}, keyOf(history, 8, 1), history.registry);
    ASSERT_TRUE(bad.has_value());
    EXPECT_EQ(bad->target, 7u);
}

TEST_F(LadderKeysSelfCheck, SECURITY_ARungToAnotherRecipientIsRefused) {
    const EpochHistory history = simulateEpochHistory(8, 1);
    const ArchiveRung elsewhere = sealed(RungSpan{8, 7}, keyOf(history, 7, 1), PrivateKey::generateRandom(), AUTHOR);
    EXPECT_TRUE(LadderKeys::firstRungNotOpeningToTheChain({elsewhere}, keyOf(history, 8, 1), history.registry).has_value());
}

// registry

TEST_F(LadderKeysRegistry, LooksUpAnEpochsPublicKey) {
    const EpochHistory history = simulateEpochHistory(4, 1);
    const auto found = LadderKeys::publicKeyOfEpoch(3, history.registry);
    ASSERT_TRUE(found.has_value());
    EXPECT_EQ(found.value(), keyOf(history, 3, 1).getPublicKey());
    EXPECT_FALSE(LadderKeys::publicKeyOfEpoch(99, history.registry).has_value());
}

// SECURITY — a key for an epoch absent from the registry cannot be vouched for, so it must be refused.
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
