/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

/**
 * Unit tests for the Epoch Ladder with **real EC keys and real ECIES**.
 *
 * No server, no docker, no network, and no crypto stubs. The properties under test are cryptographic: that a
 * member holding only a recent epoch key can reach older ones, that a removed member cannot walk forward, and
 * that a substituted rung is detected rather than silently yielding a wrong key.
 *
 * Tests named SECURITY guard confidentiality and fail silently at runtime if the guard regresses.
 */

#include <gtest/gtest.h>

#include <string>
#include <vector>

#include <privmx/crypto/ecc/PrivateKey.hpp>

#include <privmx/endpoint/group/keytree/LadderKeys.hpp>

using privmx::crypto::PrivateKey;
using namespace privmx::endpoint::group::keytree;

namespace {

constexpr char AUTHOR[] = "alice";

/** A group's epoch history: one grant keypair per epoch, all independently random. */
struct EpochHistory {
    std::vector<PrivateKey> keys; ///< index i holds the key for epoch i+1
    std::vector<EpochRegistryEntry> registry;
    std::vector<ArchiveRung> rungs;
};

/**
 * Simulates a group advancing through `upTo` epochs, publishing rungs at each step exactly as a client would.
 *
 * Each epoch key is freshly generated — never derived from its predecessor. That independence is what makes a
 * removal irreversible, and building the fixture this way keeps the tests honest about it.
 */
EpochHistory runEpochs(std::uint32_t upTo, std::uint32_t eraFloor, bool withSkips = true) {
    EpochHistory history;
    TreeKeyStore store;
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

} // namespace

// ─────────────────────────────────────────────────────────────────────────────
// building rungs
// ─────────────────────────────────────────────────────────────────────────────

TEST(LadderKeysBuild, EmitsNothingAtTheEraFloor) {
    TreeKeyStore store;
    LadderKeys ladder(store);
    const PrivateKey key = PrivateKey::generateRandom();
    EXPECT_TRUE(ladder.buildRungs(1, key.getPublicKey(), std::nullopt, 1, AUTHOR, key).empty())
        << "genesis of an era has nothing below to link to";
    EXPECT_TRUE(ladder.buildRungs(20, key.getPublicKey(), std::nullopt, 20, AUTHOR, key).empty());
}

/** SECURITY — a missing unit rung would be an unrepairable hole, so it must fail loudly. */
TEST(LadderKeysBuild, SECURITY_RefusesToBuildWithoutThePreviousEpochKey) {
    TreeKeyStore store;
    LadderKeys ladder(store);
    const PrivateKey key = PrivateKey::generateRandom();
    EXPECT_THROW(ladder.buildRungs(8, key.getPublicKey(), std::nullopt, 1, AUTHOR, key), std::invalid_argument);
}

TEST(LadderKeysBuild, AlwaysEmitsTheUnitRung) {
    const EpochHistory history = runEpochs(20, 1);
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

TEST(LadderKeysBuild, EmitsAlignedSkipRungsWhenTheKeysAreHeld) {
    const EpochHistory history = runEpochs(8, 1);
    std::vector<std::uint32_t> targetsAtEight;
    for (const ArchiveRung& rung : history.rungs) {
        if (rung.span.at == 8) {
            targetsAtEight.push_back(rung.span.target);
        }
    }
    std::sort(targetsAtEight.begin(), targetsAtEight.end());
    EXPECT_EQ(targetsAtEight, std::vector<std::uint32_t>({4, 6, 7}));
}

TEST(LadderKeysBuild, SkipsUnavailableTargetsSilently) {
    // A publisher that holds only the previous epoch key still produces a valid, if slower, ladder.
    TreeKeyStore store;
    LadderKeys ladder(store);
    const PrivateKey previous = PrivateKey::generateRandom();
    const PrivateKey current = PrivateKey::generateRandom();
    const std::vector<ArchiveRung> rungs = ladder.buildRungs(8, current.getPublicKey(), previous, 1, AUTHOR, current);
    ASSERT_EQ(rungs.size(), 1u) << "no older keys held, so only the unit rung";
    EXPECT_EQ(rungs[0].span.target, 7u);
}

TEST(LadderKeysBuild, EverySpanPointsDownwards) {
    const EpochHistory history = runEpochs(40, 1);
    for (const ArchiveRung& rung : history.rungs) {
        EXPECT_LT(rung.span.target, rung.span.at);
        EXPECT_EQ(rung.author, AUTHOR);
    }
}

TEST(LadderKeysBuild, CostsAboutTwoRungsPerEpoch) {
    const EpochHistory history = runEpochs(200, 1);
    const double perEpoch = static_cast<double>(history.rungs.size()) / 199.0;
    EXPECT_LT(perEpoch, 2.0) << "got " << perEpoch;
    EXPECT_GT(perEpoch, 1.5) << "got " << perEpoch;
}

// ─────────────────────────────────────────────────────────────────────────────
// descending
// ─────────────────────────────────────────────────────────────────────────────

TEST(LadderKeysDescend, RecoversEveryOlderEpochKey) {
    const EpochHistory history = runEpochs(16, 1);
    for (std::uint32_t target = 1; target <= 16; ++target) {
        TreeKeyStore store;
        LadderKeys ladder(store);
        store.putGrantKey(16, keyOf(history, 16, 1));
        const DescentResult result = ladder.descend(16, target, history.rungs, history.registry);
        ASSERT_EQ(result.failure, DescentFailure::None) << "target " << target;
        ASSERT_TRUE(result.key.has_value());
        EXPECT_EQ(result.key->toWIF(), keyOf(history, target, 1).toWIF()) << "target " << target;
    }
}

TEST(LadderKeysDescend, ReturnsTheHeldKeyWhenAlreadyAtTheTarget) {
    const EpochHistory history = runEpochs(4, 1);
    TreeKeyStore store;
    LadderKeys ladder(store);
    store.putGrantKey(4, keyOf(history, 4, 1));
    const DescentResult result = ladder.descend(4, 4, history.rungs, history.registry);
    ASSERT_EQ(result.failure, DescentFailure::None);
    EXPECT_EQ(result.key->toWIF(), keyOf(history, 4, 1).toWIF());
}

TEST(LadderKeysDescend, CachesEveryKeyRecoveredOnTheWay) {
    const EpochHistory history = runEpochs(16, 1);
    TreeKeyStore store;
    LadderKeys ladder(store);
    store.putGrantKey(16, keyOf(history, 16, 1));
    ASSERT_EQ(ladder.descend(16, 1, history.rungs, history.registry).failure, DescentFailure::None);

    // Everything the walk passed through is now free to fetch.
    for (std::uint32_t epoch : {1u, 16u}) {
        EXPECT_TRUE(store.getGrantKey(epoch).has_value()) << "epoch " << epoch;
    }
}

TEST(LadderKeysDescend, WithSkipRungsIsLogarithmicNotLinear) {
    const EpochHistory withSkips = runEpochs(256, 1, true);
    const EpochHistory unitOnly = runEpochs(256, 1, false);

    // Count how many rungs are addressed to each epoch: with skips there are more, so the walk is shorter.
    EXPECT_GT(withSkips.rungs.size(), unitOnly.rungs.size());

    TreeKeyStore storeA;
    LadderKeys ladderA(storeA);
    storeA.putGrantKey(256, keyOf(withSkips, 256, 1));
    ASSERT_EQ(ladderA.descend(256, 1, withSkips.rungs, withSkips.registry).failure, DescentFailure::None);

    TreeKeyStore storeB;
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

TEST(LadderKeysDescend, FailsWithoutAStartingKey) {
    const EpochHistory history = runEpochs(8, 1);
    TreeKeyStore store;
    LadderKeys ladder(store);
    const DescentResult result = ladder.descend(8, 1, history.rungs, history.registry);
    EXPECT_EQ(result.failure, DescentFailure::NotEntitled);
    EXPECT_FALSE(result.key.has_value());
}

TEST(LadderKeysDescend, ReportsAMissingRungDistinctly) {
    EpochHistory history = runEpochs(8, 1);
    std::vector<ArchiveRung> gapped;
    for (const ArchiveRung& rung : history.rungs) {
        if (rung.span.at != 5) {
            gapped.push_back(rung);
        }
    }
    TreeKeyStore store;
    LadderKeys ladder(store);
    store.putGrantKey(5, keyOf(history, 5, 1));
    const DescentResult result = ladder.descend(5, 1, gapped, history.registry);
    EXPECT_EQ(result.failure, DescentFailure::MissingRung);
    EXPECT_EQ(result.reachedEpoch, 5u);
}

TEST(LadderKeysDescend, RefusesToDescendUpwards) {
    const EpochHistory history = runEpochs(4, 1);
    TreeKeyStore store;
    LadderKeys ladder(store);
    store.putGrantKey(2, keyOf(history, 2, 1));
    EXPECT_THROW(ladder.descend(2, 4, history.rungs, history.registry), std::invalid_argument);
}

TEST(LadderKeysDescend, StopsAtAnEraFloorAndSaysSo) {
    const EpochHistory history = runEpochs(20, 1);
    TreeKeyStore store;
    LadderKeys ladder(store);
    store.putGrantKey(20, keyOf(history, 20, 1));
    const DescentResult result = ladder.descend(20, 1, history.rungs, history.registry, /*eraFloor*/ 12);
    EXPECT_EQ(result.failure, DescentFailure::EraBoundary);
    EXPECT_EQ(result.reachedEpoch, 12u) << "partial progress must still be reported";
    EXPECT_FALSE(result.key.has_value());
    EXPECT_TRUE(store.getGrantKey(12).has_value()) << "and cached";
}

TEST(LadderKeysDescend, ReportsPruningInPreferenceToTheEraFloor) {
    const EpochHistory history = runEpochs(20, 1);
    TreeKeyStore store;
    LadderKeys ladder(store);
    store.putGrantKey(20, keyOf(history, 20, 1));
    const DescentResult result = ladder.descend(
        20, 1, history.rungs, history.registry, /*eraFloor*/ 3, /*prunedBelow*/ 15
    );
    EXPECT_EQ(result.failure, DescentFailure::Pruned) << "the stronger constraint is the more useful message";
    EXPECT_EQ(result.reachedEpoch, 15u);
}

TEST(LadderKeysDescend, EnforcesTheWalkBound) {
    const EpochHistory history = runEpochs(64, 1, false);
    TreeKeyStore store;
    LadderKeys ladder(store);
    store.putGrantKey(64, keyOf(history, 64, 1));
    const DescentResult result = ladder.descend(64, 1, history.rungs, history.registry, 1, std::nullopt, /*maxWalk*/ 5);
    EXPECT_EQ(result.failure, DescentFailure::TooLong);
}

/** SECURITY — a substituted rung must be detected, never allowed to yield a wrong key. */
TEST(LadderKeysDescend, SECURITY_DetectsASubstitutedRung) {
    EpochHistory history = runEpochs(8, 1);
    const PrivateKey impostor = PrivateKey::generateRandom();
    const PrivateKey signer = PrivateKey::generateRandom();

    // Replace the rung 8->7 with a correctly-encrypted wrap of an unrelated key, authored by someone else.
    for (ArchiveRung& rung : history.rungs) {
        if (rung.span.at == 8 && rung.span.target == 7) {
            rung.blob = TreeKeys::wrapKey(impostor, keyOf(history, 8, 1).getPublicKey(), signer);
            rung.author = "mallory";
        }
    }

    TreeKeyStore store;
    LadderKeys ladder(store);
    store.putGrantKey(8, keyOf(history, 8, 1));
    const DescentResult result = ladder.descend(8, 7, history.rungs, history.registry);
    EXPECT_EQ(result.failure, DescentFailure::Tampered);
    EXPECT_FALSE(result.key.has_value());
    ASSERT_TRUE(result.blame.has_value());
    EXPECT_EQ(result.blame.value(), "mallory") << "tampering must be attributable";
    EXPECT_FALSE(store.getGrantKey(7).has_value()) << "a key failing verification must never be cached";
}

/** SECURITY — with skip rungs a single corrupted unit rung must not sever the chain. */
TEST(LadderKeysDescend, SECURITY_RoutesAroundACorruptedUnitRungViaASkip) {
    EpochHistory history = runEpochs(8, 1);
    for (ArchiveRung& rung : history.rungs) {
        if (rung.span.at == 8 && rung.span.target == 7) {
            rung.blob = "corrupted";
        }
    }
    TreeKeyStore store;
    LadderKeys ladder(store);
    store.putGrantKey(8, keyOf(history, 8, 1));

    // Epoch 8 also publishes skips to 6 and 4, so a descent to 4 need not touch the broken rung.
    const DescentResult result = ladder.descend(8, 4, history.rungs, history.registry);
    ASSERT_EQ(result.failure, DescentFailure::None) << "the skip rung should carry the walk";
    EXPECT_EQ(result.key->toWIF(), keyOf(history, 4, 1).toWIF());
}

/** SECURITY — an upward rung must be ignored even if it reached storage. */
TEST(LadderKeysDescend, SECURITY_IgnoresAnUpwardRung) {
    EpochHistory history = runEpochs(8, 1);
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

    TreeKeyStore store;
    LadderKeys ladder(store);
    store.putGrantKey(5, keyOf(history, 5, 1));
    ASSERT_EQ(ladder.descend(5, 4, history.rungs, history.registry).failure, DescentFailure::None);
    EXPECT_FALSE(store.getGrantKey(9).has_value()) << "an upward rung must never be traversed";
}

/**
 * SECURITY — the ladder must not let a removed member walk forward.
 *
 * A member removed after epoch 5 holds epochs 1..5. Every rung published at 6 and above is wrapped to a grant
 * key they never received, so none of them opens.
 */
TEST(LadderKeysDescend, SECURITY_RemovedMemberCannotWalkForward) {
    const EpochHistory history = runEpochs(10, 1);
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
    TreeKeyStore store;
    LadderKeys ladder(store);
    for (std::uint32_t held = 1; held <= removedAfter; ++held) {
        store.putGrantKey(held, keyOf(history, held, 1));
    }
    const DescentResult result = ladder.descend(10, 1, history.rungs, history.registry);
    EXPECT_EQ(result.failure, DescentFailure::NotEntitled);
}

/**
 * The payoff: a member who joins late reads old content with **zero** ciphertexts created for them.
 */
TEST(LadderKeysDescend, ANewcomerReachesOldEpochsWithNothingWrappedToThem) {
    const EpochHistory history = runEpochs(12, 1);

    // The newcomer is handed exactly one thing: the current epoch key, through the tree.
    TreeKeyStore store;
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

// ─────────────────────────────────────────────────────────────────────────────
// eras
// ─────────────────────────────────────────────────────────────────────────────

TEST(LadderKeysEras, ALinkAddressedToAUserUnlocksTheClosedEra) {
    const EpochHistory closed = runEpochs(10, 1);
    const PrivateKey member = PrivateKey::generateRandom();
    const PrivateKey signer = PrivateKey::generateRandom();

    TreeKeyStore store;
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

TEST(LadderKeysEras, ALinkAddressedToAGroupCostsOneCiphertextForEveryone) {
    const EpochHistory closed = runEpochs(6, 1);
    const PrivateKey entitlementGroupKey = PrivateKey::generateRandom();
    const PrivateKey signer = PrivateKey::generateRandom();

    TreeKeyStore store;
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

TEST(LadderKeysEras, WithoutALinkTheBoundaryHolds) {
    const EpochHistory closed = runEpochs(6, 1);
    const PrivateKey signer = PrivateKey::generateRandom();
    const PrivateKey entitled = PrivateKey::generateRandom();

    TreeKeyStore store;
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

TEST(LadderKeysEras, RejectsAnEraLinkAddressedToAnEpoch) {
    TreeKeyStore store;
    LadderKeys ladder(store);
    const PrivateKey key = PrivateKey::generateRandom();
    EXPECT_THROW(
        ladder.buildEraLinks(6, key, {EraLinkRecipient{RungRecipientKind::Epoch, "", key.getPublicKey()}}, AUTHOR, key),
        std::invalid_argument
    );
}

/** SECURITY — a tampered era link is detected and attributed, not silently accepted. */
TEST(LadderKeysEras, SECURITY_DetectsATamperedEraLink) {
    const EpochHistory closed = runEpochs(6, 1);
    const PrivateKey member = PrivateKey::generateRandom();
    const PrivateKey impostor = PrivateKey::generateRandom();
    const PrivateKey signer = PrivateKey::generateRandom();

    ArchiveRung forged;
    forged.span = RungSpan{7, 6};
    forged.recipientKind = RungRecipientKind::User;
    forged.recipientId = "bob";
    forged.blob = TreeKeys::wrapKey(impostor, member.getPublicKey(), signer);
    forged.author = "mallory";

    TreeKeyStore store;
    LadderKeys ladder(store);
    const DescentResult result = ladder.crossEraBoundary({forged}, "bob", member, {}, closed.registry);
    EXPECT_EQ(result.failure, DescentFailure::Tampered);
    ASSERT_TRUE(result.blame.has_value());
    EXPECT_EQ(result.blame.value(), "mallory");
}

// ─────────────────────────────────────────────────────────────────────────────
// registry
// ─────────────────────────────────────────────────────────────────────────────

TEST(LadderKeysRegistry, LooksUpAnEpochsPublicKey) {
    const EpochHistory history = runEpochs(4, 1);
    const auto found = LadderKeys::publicKeyOfEpoch(3, history.registry);
    ASSERT_TRUE(found.has_value());
    EXPECT_EQ(found.value(), keyOf(history, 3, 1).getPublicKey());
    EXPECT_FALSE(LadderKeys::publicKeyOfEpoch(99, history.registry).has_value());
}

/** SECURITY — a key for an epoch absent from the registry cannot be vouched for, so it must be refused. */
TEST(LadderKeysRegistry, SECURITY_RefusesAKeyForAnUnknownEpoch) {
    EpochHistory history = runEpochs(8, 1);
    // Drop epoch 7 from the registry, leaving the rung 8->7 unverifiable.
    std::vector<EpochRegistryEntry> pruned;
    for (const EpochRegistryEntry& entry : history.registry) {
        if (entry.epoch != 7) {
            pruned.push_back(entry);
        }
    }
    TreeKeyStore store;
    LadderKeys ladder(store);
    store.putGrantKey(8, keyOf(history, 8, 1));
    const DescentResult result = ladder.descend(8, 7, history.rungs, pruned);
    EXPECT_EQ(result.failure, DescentFailure::Tampered) << "unverifiable must not mean accepted";
}
