/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

/** Unit tests for the Epoch Ladder rules; needs no server, no docker and no network, and mirrors the bridge's LadderMath tests, which must agree with this implementation since the server enforces the same invariants on submitted rung sets — tests named SECURITY guard confidentiality and must not be deleted or relaxed even though they fail silently at runtime if the guard regresses. */

#include <gtest/gtest.h>

#include <cstdint>
#include <vector>

#include <privmx/endpoint/group/keytree/LadderMath.hpp>

using privmx::endpoint::group::keytree::DescentFloorReason;
using privmx::endpoint::group::keytree::LadderMath;
using privmx::endpoint::group::keytree::LadderProblemKind;
using privmx::endpoint::group::keytree::RungSpan;

using Targets = std::vector<std::uint32_t>;
using Spans = std::vector<RungSpan>;

// Shared helpers for suites that build a client's local rung archive.
class LadderMathTestBase : public testing::Test {
protected:
    Spans spansThrough(std::uint32_t upTo, std::uint32_t floor = 1) {
        Spans all;
        for (std::uint32_t epoch = floor + 1; epoch <= upTo; ++epoch) {
            const Spans spans = LadderMath::rungSpansFor(epoch, floor);
            all.insert(all.end(), spans.begin(), spans.end());
        }
        return all;
    }

    Targets targetsOf(const Spans& spans) {
        Targets result;
        for (const RungSpan& span : spans) {
            result.push_back(span.target);
        }
        return result;
    }
};

// skipRungTargets
class LadderSkipTargets : public testing::Test {};

TEST_F(LadderSkipTargets, MatchesReferenceTable) {
    EXPECT_EQ(LadderMath::skipRungTargets(2, 1), Targets({}));
    EXPECT_EQ(LadderMath::skipRungTargets(4, 1), Targets({2}));
    EXPECT_EQ(LadderMath::skipRungTargets(8, 1), Targets({4, 6}));
    EXPECT_EQ(LadderMath::skipRungTargets(16, 1), Targets({8, 12, 14}));
    EXPECT_EQ(LadderMath::skipRungTargets(12, 1), Targets({8, 10}));
    EXPECT_EQ(LadderMath::skipRungTargets(9, 1), Targets({}));
    EXPECT_EQ(LadderMath::skipRungTargets(7, 1), Targets({}));
    EXPECT_EQ(LadderMath::skipRungTargets(6, 1), Targets({4}));
}

TEST_F(LadderSkipTargets, ClampsToEraFloor) {
    EXPECT_EQ(LadderMath::skipRungTargets(16, 12), Targets({12, 14}));
    EXPECT_EQ(LadderMath::skipRungTargets(16, 15), Targets({}));
}

TEST_F(LadderSkipTargets, NeverReturnsATargetAtOrAboveTheEpoch) {
    for (std::uint32_t epoch = 1; epoch <= 300; ++epoch) {
        for (const std::uint32_t target : LadderMath::skipRungTargets(epoch, 1)) {
            EXPECT_LT(target, epoch);
            EXPECT_GE(target, 1u);
        }
    }
}

TEST_F(LadderSkipTargets, HandlesLargeEpochs) {
    const std::uint32_t large = 1048576; // 2^20
    const Targets targets = LadderMath::skipRungTargets(large, 1);
    EXPECT_FALSE(targets.empty());
    for (const std::uint32_t target : targets) {
        EXPECT_GE(target, 1u);
        EXPECT_LT(target, large);
    }
}

// rungSpansFor
class LadderRungSpans : public LadderMathTestBase {};

TEST_F(LadderRungSpans, AlwaysIncludesTheMandatoryUnitRung) {
    for (std::uint32_t epoch = 2; epoch <= 200; ++epoch) {
        const Targets targets = targetsOf(LadderMath::rungSpansFor(epoch, 1));
        EXPECT_NE(std::find(targets.begin(), targets.end(), epoch - 1), targets.end())
            << "epoch " << epoch << " must include the unit rung";
    }
}

TEST_F(LadderRungSpans, IsEmptyAtTheEraFloor) {
    EXPECT_TRUE(LadderMath::rungSpansFor(1, 1).empty());
    EXPECT_TRUE(LadderMath::rungSpansFor(20, 20).empty());
}

TEST_F(LadderRungSpans, MatchesWorkedExampleFromWhitepaper) {
    Targets targets = targetsOf(LadderMath::rungSpansFor(8, 1));
    std::sort(targets.begin(), targets.end());
    EXPECT_EQ(targets, Targets({4, 6, 7}));
}

TEST_F(LadderRungSpans, NeverDuplicatesTheUnitRungAsASkip) {
    for (std::uint32_t epoch = 2; epoch <= 200; ++epoch) {
        Targets targets = targetsOf(LadderMath::rungSpansFor(epoch, 1));
        const std::size_t before = targets.size();
        std::sort(targets.begin(), targets.end());
        targets.erase(std::unique(targets.begin(), targets.end()), targets.end());
        EXPECT_EQ(targets.size(), before) << "epoch " << epoch;
    }
}

TEST_F(LadderRungSpans, WithSkipsDisabledProducesExactlyOneRung) {
    const Spans spans = LadderMath::rungSpansFor(8, 1, false);
    ASSERT_EQ(spans.size(), 1u);
    EXPECT_EQ(spans[0], RungSpan({8, 7}));
}

TEST_F(LadderRungSpans, EverySpanPointsDownwards) {
    for (std::uint32_t epoch = 1; epoch <= 200; ++epoch) {
        for (const RungSpan& span : LadderMath::rungSpansFor(epoch, 1)) {
            EXPECT_LT(span.target, span.at) << "epoch " << epoch;
            EXPECT_EQ(span.at, epoch);
        }
    }
}

// the amortised cost claim
class LadderCost : public testing::Test {};

TEST_F(LadderCost, StaysUnderTwoRungsPerEpoch) {
    for (const std::uint32_t upTo : {100u, 1000u, 10000u}) {
        const double perEpoch = static_cast<double>(LadderMath::totalRungsThrough(upTo)) /
            static_cast<double>(upTo - 1);
        EXPECT_LT(perEpoch, 2.0) << "upTo=" << upTo << " got " << perEpoch;
        EXPECT_GT(perEpoch, 1.9) << "upTo=" << upTo << " got " << perEpoch;
    }
}

// planDescent
class LadderDescent : public LadderMathTestBase {};

TEST_F(LadderDescent, ReturnsEmptyPlanWhenAlreadyAtTarget) {
    const auto plan = LadderMath::planDescent(5, 5, spansThrough(10));
    ASSERT_TRUE(plan.has_value());
    EXPECT_TRUE(plan->empty());
}

TEST_F(LadderDescent, LandsExactlyOnTheTarget) {
    const auto plan = LadderMath::planDescent(12, 5, spansThrough(12));
    ASSERT_TRUE(plan.has_value());
    ASSERT_FALSE(plan->empty());
    EXPECT_EQ(plan->back().target, 5u);
    EXPECT_EQ(plan->front().at, 12u);
}

TEST_F(LadderDescent, EachStepContinuesFromWhereThePreviousEnded) {
    const auto plan = LadderMath::planDescent(30, 3, spansThrough(30));
    ASSERT_TRUE(plan.has_value());
    std::uint32_t current = 30;
    for (const RungSpan& step : *plan) {
        EXPECT_EQ(step.at, current) << "step must be addressed to the current epoch";
        EXPECT_LT(step.target, current) << "step must go down";
        current = step.target;
    }
    EXPECT_EQ(current, 3u);
}

TEST_F(LadderDescent, NeverOvershootsBelowTheTarget) {
    const auto plan = LadderMath::planDescent(64, 40, spansThrough(64));
    ASSERT_TRUE(plan.has_value());
    for (const RungSpan& step : *plan) {
        EXPECT_GE(step.target, 40u);
    }
}

TEST_F(LadderDescent, StaysInsideTheLogarithmicBound) {
    const std::vector<std::pair<std::uint32_t, std::uint32_t>> cases = {
        {16, 1}, {64, 1}, {256, 1}, {1024, 1}, {10000, 1}, {1000, 500},
    };
    for (const auto& [from, to] : cases) {
        const auto plan = LadderMath::planDescent(from, to, spansThrough(from));
        ASSERT_TRUE(plan.has_value()) << "from=" << from << " to=" << to;
        const std::uint32_t bound = LadderMath::descentBound(from, to);
        EXPECT_LE(plan->size(), bound) << "from=" << from << " to=" << to << " steps=" << plan->size();
    }
}

TEST_F(LadderDescent, LongDescentCostsLogarithmicallyManySteps) {
    const auto plan = LadderMath::planDescent(10000, 1, spansThrough(10000));
    ASSERT_TRUE(plan.has_value());
    EXPECT_LT(plan->size(), 40u) << "got " << plan->size();
    EXPECT_GT(plan->size(), 5u) << "sanity";
}

TEST_F(LadderDescent, WithUnitRungsOnlyTheWalkIsLinear) {
    Spans unitOnly;
    for (std::uint32_t epoch = 2; epoch <= 12; ++epoch) {
        unitOnly.push_back(RungSpan{epoch, epoch - 1});
    }
    const auto plan = LadderMath::planDescent(12, 5, unitOnly);
    ASSERT_TRUE(plan.has_value());
    EXPECT_EQ(plan->size(), 7u);
}

TEST_F(LadderDescent, FailsWhenARungIsMissing) {
    Spans gapped;
    for (const RungSpan& span : spansThrough(12)) {
        if (span.at != 8) {
            gapped.push_back(span);
        }
    }
    EXPECT_FALSE(LadderMath::planDescent(8, 1, gapped).has_value());
}

TEST_F(LadderDescent, FailsWhenTargetIsBelowEverythingAvailable) {
    EXPECT_FALSE(LadderMath::planDescent(20, 3, spansThrough(20, 10)).has_value());
}

TEST_F(LadderDescent, SECURITY_IgnoresAnUpwardRungEntirely) {
    const Spans poisoned = {
        RungSpan{5, 9}, // upward: must be ignored
        RungSpan{5, 4},
        RungSpan{4, 3},
    };
    const auto plan = LadderMath::planDescent(5, 3, poisoned);
    ASSERT_TRUE(plan.has_value());
    ASSERT_EQ(plan->size(), 2u);
    EXPECT_EQ((*plan)[0], RungSpan({5, 4}));
    EXPECT_EQ((*plan)[1], RungSpan({4, 3}));
    for (const RungSpan& step : *plan) {
        EXPECT_LT(step.target, step.at);
    }
}

TEST_F(LadderDescent, SECURITY_SelfLoopRungCannotHangTheWalk) {
    const Spans looped = {RungSpan{5, 5}, RungSpan{5, 5}};
    EXPECT_FALSE(LadderMath::planDescent(5, 1, looped).has_value());
}

TEST_F(LadderDescent, RefusesToDescendUpwards) {
    EXPECT_THROW(LadderMath::planDescent(3, 9, {}), std::invalid_argument);
}

// descentFloor
class LadderDescentFloor : public testing::Test {};

TEST_F(LadderDescentFloor, ReportsNoReasonWhenNothingConstrainsTheDescent) {
    const auto result = LadderMath::descentFloor(1);
    EXPECT_EQ(result.floor, 1u);
    EXPECT_EQ(result.reason, DescentFloorReason::None);
}

TEST_F(LadderDescentFloor, ReportsEraBoundaryWhenOnlyAnEraFloorApplies) {
    const auto result = LadderMath::descentFloor(20);
    EXPECT_EQ(result.floor, 20u);
    EXPECT_EQ(result.reason, DescentFloorReason::EraBoundary);
}

TEST_F(LadderDescentFloor, PrefersPrunedWhenTheWatermarkIsStronger) {
    const auto result = LadderMath::descentFloor(20, 8000);
    EXPECT_EQ(result.floor, 8000u);
    EXPECT_EQ(result.reason, DescentFloorReason::Pruned);
}

TEST_F(LadderDescentFloor, KeepsEraBoundaryWhenHigherThanTheWatermark) {
    const auto result = LadderMath::descentFloor(9000, 8000);
    EXPECT_EQ(result.floor, 9000u);
    EXPECT_EQ(result.reason, DescentFloorReason::EraBoundary);
}

// validateRungSet
class LadderValidate : public testing::Test {};

TEST_F(LadderValidate, AcceptsAWellFormedSet) {
    EXPECT_TRUE(LadderMath::validateRungSet(LadderMath::rungSpansFor(8, 1), 8, 1).ok);
}

TEST_F(LadderValidate, AcceptsAnEmptySetAtTheEraFloor) {
    EXPECT_TRUE(LadderMath::validateRungSet({}, 1, 1).ok);
    EXPECT_TRUE(LadderMath::validateRungSet({}, 20, 20).ok);
}

TEST_F(LadderValidate, AcceptsUnitRungOnlyBecauseSkipsAreOptional) {
    EXPECT_TRUE(LadderMath::validateRungSet({RungSpan{8, 7}}, 8, 1).ok);
}

TEST_F(LadderValidate, AcceptsANonAlignedSkipBecauseAlignmentIsAdvisory) {
    EXPECT_TRUE(LadderMath::validateRungSet({RungSpan{8, 7}, RungSpan{8, 5}}, 8, 1).ok);
}

/** SECURITY — the single check that stops a removed member reading forward. */
TEST_F(LadderValidate, SECURITY_RejectsUpwardAndSelfRungs) {
    for (const std::uint32_t target : {8u, 9u, 100u}) {
        const auto result = LadderMath::validateRungSet({RungSpan{8, target}}, 8, 1);
        EXPECT_FALSE(result.ok) << "target " << target;
        EXPECT_EQ(result.problem, LadderProblemKind::Direction) << "target " << target;
    }
}

/** SECURITY — a missing unit rung is an unrepairable hole, so it must fail at write time. */
TEST_F(LadderValidate, SECURITY_RejectsASetWithoutTheUnitRung) {
    auto result = LadderMath::validateRungSet({}, 8, 1);
    EXPECT_FALSE(result.ok);
    EXPECT_EQ(result.problem, LadderProblemKind::UnitRungMissing);

    result = LadderMath::validateRungSet({RungSpan{8, 6}}, 8, 1);
    EXPECT_FALSE(result.ok);
    EXPECT_EQ(result.problem, LadderProblemKind::UnitRungMissing);
}

TEST_F(LadderValidate, RejectsARungAddressedToADifferentEpoch) {
    const auto result = LadderMath::validateRungSet({RungSpan{7, 6}}, 8, 1);
    EXPECT_FALSE(result.ok);
    EXPECT_EQ(result.problem, LadderProblemKind::WrongEpoch);
}

TEST_F(LadderValidate, RejectsARungTargetingBelowTheEraFloor) {
    const auto result = LadderMath::validateRungSet({RungSpan{8, 7}, RungSpan{8, 3}}, 8, 5);
    EXPECT_FALSE(result.ok);
    EXPECT_EQ(result.problem, LadderProblemKind::BelowEraFloor);
}

TEST_F(LadderValidate, RejectsARungTargetingBelowThePruneWatermark) {
    const auto result = LadderMath::validateRungSet({RungSpan{8, 7}, RungSpan{8, 4}}, 8, 1, 5);
    EXPECT_FALSE(result.ok);
    EXPECT_EQ(result.problem, LadderProblemKind::BelowPruneWatermark);
}

TEST_F(LadderValidate, RejectsDuplicatesInOneSubmission) {
    const auto result = LadderMath::validateRungSet({RungSpan{8, 7}, RungSpan{8, 7}}, 8, 1);
    EXPECT_FALSE(result.ok);
    EXPECT_EQ(result.problem, LadderProblemKind::Duplicate);
}

TEST_F(LadderValidate, AcceptsEveryGeneratedSetForALongRun) {
    for (std::uint32_t epoch = 1; epoch <= 500; ++epoch) {
        EXPECT_TRUE(LadderMath::validateRungSet(LadderMath::rungSpansFor(epoch, 1), epoch, 1).ok) << "epoch " << epoch;
    }
}

TEST_F(LadderValidate, AcceptsGeneratedSetsUnderAnEraFloor) {
    const std::uint32_t floor = 137;
    for (std::uint32_t epoch = floor; epoch <= floor + 200; ++epoch) {
        EXPECT_TRUE(LadderMath::validateRungSet(LadderMath::rungSpansFor(epoch, floor), epoch, floor).ok)
            << "epoch " << epoch;
    }
}
