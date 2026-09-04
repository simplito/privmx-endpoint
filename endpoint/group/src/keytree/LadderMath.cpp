/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include "privmx/endpoint/group/keytree/LadderMath.hpp"

#include <algorithm>
#include <cmath>
#include <set>
#include <stdexcept>
#include <string>

using namespace privmx::endpoint::group::keytree;

void LadderMath::assertEpoch(std::uint32_t value, const char* name) {
    if (value < 1) {
        throw std::invalid_argument(std::string("invalid ") + name + ": " + std::to_string(value));
    }
}

std::vector<std::uint32_t> LadderMath::skipRungTargets(std::uint32_t newEpoch, std::uint32_t eraFloor) {
    assertEpoch(newEpoch, "newEpoch");
    assertEpoch(eraFloor, "eraFloor");
    std::vector<std::uint32_t> targets;
    for (std::uint32_t span = 2; span <= newEpoch; span *= 2) {
        if (newEpoch % span != 0) {
            continue;
        }
        const std::uint32_t target = newEpoch - span;
        if (target < eraFloor) {
            continue;
        }
        targets.push_back(target);
    }
    std::sort(targets.begin(), targets.end());
    return targets;
}

std::vector<RungSpan> LadderMath::rungSpansFor(std::uint32_t newEpoch, std::uint32_t eraFloor, bool includeSkips) {
    assertEpoch(newEpoch, "newEpoch");
    assertEpoch(eraFloor, "eraFloor");
    if (newEpoch <= eraFloor) {
        return {};
    }
    std::vector<RungSpan> spans{RungSpan{newEpoch, newEpoch - 1}};
    if (includeSkips) {
        for (const std::uint32_t target : skipRungTargets(newEpoch, eraFloor)) {
            if (target != newEpoch - 1) {
                spans.push_back(RungSpan{newEpoch, target});
            }
        }
    }
    return spans;
}

bool LadderMath::requiresUnitRung(std::uint32_t newEpoch, std::uint32_t eraFloor) {
    assertEpoch(newEpoch, "newEpoch");
    assertEpoch(eraFloor, "eraFloor");
    return newEpoch > eraFloor;
}

std::uint32_t LadderMath::totalRungsThrough(std::uint32_t upToEpoch) {
    assertEpoch(upToEpoch, "upToEpoch");
    std::uint32_t total = 0;
    for (std::uint32_t epoch = 2; epoch <= upToEpoch; ++epoch) {
        total += static_cast<std::uint32_t>(rungSpansFor(epoch, 1).size());
    }
    return total;
}

std::optional<std::vector<RungSpan>> LadderMath::planDescent(
    std::uint32_t from,
    std::uint32_t to,
    const std::vector<RungSpan>& available
) {
    assertEpoch(from, "from");
    assertEpoch(to, "to");
    if (to > from) {
        throw std::invalid_argument(
            "cannot descend upwards: from " + std::to_string(from) + " to " + std::to_string(to)
        );
    }
    if (to == from) {
        return std::vector<RungSpan>{};
    }

    std::vector<RungSpan> plan;
    std::uint32_t current = from;
    std::set<std::uint32_t> visited{from};
    while (current > to) {
        const RungSpan* best = nullptr;
        for (const RungSpan& rung : available) {
            // Invariant D violation: never traverse such a rung, even if it somehow got stored. It is exactly
            // the shape that would hand a removed member a later key.
            if (rung.target >= rung.at) {
                continue;
            }
            if (rung.at != current || rung.target < to) {
                continue;
            }
            if (best == nullptr || rung.target < best->target) {
                best = &rung;
            }
        }
        if (best == nullptr) {
            return std::nullopt;
        }
        plan.push_back(*best);
        current = best->target;
        if (visited.count(current) > 0) {
            // Defensive: a malformed rung set must not spin forever.
            return std::nullopt;
        }
        visited.insert(current);
    }
    return plan;
}

std::uint32_t LadderMath::descentBound(std::uint32_t from, std::uint32_t to) {
    assertEpoch(from, "from");
    assertEpoch(to, "to");
    if (to >= from) {
        return 0;
    }
    const std::uint32_t delta = from - to;
    return 2 * static_cast<std::uint32_t>(std::ceil(std::log2(static_cast<double>(delta + 1)))) + 2;
}

DescentFloor LadderMath::descentFloor(std::uint32_t eraFloor, std::optional<std::uint32_t> prunedBelow) {
    assertEpoch(eraFloor, "eraFloor");
    const DescentFloorReason eraReason = eraFloor > 1 ? DescentFloorReason::EraBoundary : DescentFloorReason::None;
    if (!prunedBelow.has_value()) {
        return DescentFloor{eraFloor, eraReason};
    }
    assertEpoch(prunedBelow.value(), "prunedBelow");
    if (prunedBelow.value() > eraFloor) {
        return DescentFloor{prunedBelow.value(), DescentFloorReason::Pruned};
    }
    return DescentFloor{eraFloor, eraReason};
}

LadderValidation LadderMath::validateRungSet(
    const std::vector<RungSpan>& submitted,
    std::uint32_t newEpoch,
    std::uint32_t eraFloor,
    std::optional<std::uint32_t> prunedBelow
) {
    assertEpoch(newEpoch, "newEpoch");
    assertEpoch(eraFloor, "eraFloor");

    std::set<std::pair<std::uint32_t, std::uint32_t>> seen;
    for (const RungSpan& rung : submitted) {
        if (rung.target >= rung.at) {
            return LadderValidation{false, LadderProblemKind::Direction, rung};
        }
        if (rung.at != newEpoch) {
            return LadderValidation{false, LadderProblemKind::WrongEpoch, rung};
        }
        if (rung.target < eraFloor) {
            return LadderValidation{false, LadderProblemKind::BelowEraFloor, rung};
        }
        if (prunedBelow.has_value() && rung.target < prunedBelow.value()) {
            return LadderValidation{false, LadderProblemKind::BelowPruneWatermark, rung};
        }
        const auto key = std::make_pair(rung.at, rung.target);
        if (seen.count(key) > 0) {
            return LadderValidation{false, LadderProblemKind::Duplicate, rung};
        }
        seen.insert(key);
    }

    if (requiresUnitRung(newEpoch, eraFloor)) {
        const auto unitKey = std::make_pair(newEpoch, newEpoch - 1);
        if (seen.count(unitKey) == 0) {
            return LadderValidation{false, LadderProblemKind::UnitRungMissing, RungSpan{newEpoch, newEpoch - 1}};
        }
    }
    return LadderValidation{true, LadderProblemKind::None, RungSpan{0, 0}};
}
