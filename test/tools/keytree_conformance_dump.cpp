/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

/**
 * Emits the key-tree conformance vectors on stdout.
 *
 * The bridge has an identical dumper. Diffing the two outputs is what proves the client and the server agree
 * on the tree topology — and they must, because the server performs the same computation to decide which
 * nodes a removal is obliged to refresh. If they disagree, the server either rejects valid removals or, worse,
 * accepts ones that leave a removed member holding a current node key.
 *
 * See test/tools/README.md for how to run the diff.
 */

#include <cstdint>
#include <cstdio>
#include <string>
#include <vector>

#include <privmx/endpoint/group/keytree/LadderMath.hpp>
#include <privmx/endpoint/group/keytree/TreeMath.hpp>

using T = privmx::endpoint::group::keytree::TreeMath;
using L = privmx::endpoint::group::keytree::LadderMath;
using privmx::endpoint::group::keytree::DescentFloorReason;
using privmx::endpoint::group::keytree::LadderProblemKind;
using privmx::endpoint::group::keytree::RungSpan;

namespace {

std::string join(const std::vector<std::uint32_t>& values) {
    std::string result;
    for (std::size_t i = 0; i < values.size(); ++i) {
        if (i > 0) {
            result += ",";
        }
        result += std::to_string(values[i]);
    }
    return result;
}

std::string joinSpans(const std::vector<RungSpan>& spans) {
    std::string result;
    for (std::size_t i = 0; i < spans.size(); ++i) {
        if (i > 0) {
            result += ",";
        }
        result += std::to_string(spans[i].at) + ">" + std::to_string(spans[i].target);
    }
    return result;
}

std::string reasonName(DescentFloorReason reason) {
    switch (reason) {
    case DescentFloorReason::EraBoundary:
        return "ERA_BOUNDARY";
    case DescentFloorReason::Pruned:
        return "PRUNED";
    default:
        return "NONE";
    }
}

std::string problemName(LadderProblemKind problem) {
    switch (problem) {
    case LadderProblemKind::Direction:
        return "DIRECTION";
    case LadderProblemKind::WrongEpoch:
        return "WRONG_EPOCH";
    case LadderProblemKind::BelowEraFloor:
        return "BELOW_ERA_FLOOR";
    case LadderProblemKind::BelowPruneWatermark:
        return "BELOW_PRUNE_WATERMARK";
    case LadderProblemKind::Duplicate:
        return "DUPLICATE";
    case LadderProblemKind::UnitRungMissing:
        return "UNIT_RUNG_MISSING";
    default:
        return "OK";
    }
}

/** Every rung published across epochs `floor+1 .. upTo` — a client's local archive. */
std::vector<RungSpan> spansThrough(std::uint32_t upTo, std::uint32_t floor) {
    std::vector<RungSpan> all;
    for (std::uint32_t epoch = floor + 1; epoch <= upTo; ++epoch) {
        const std::vector<RungSpan> spans = L::rungSpansFor(epoch, floor);
        all.insert(all.end(), spans.begin(), spans.end());
    }
    return all;
}

constexpr std::uint32_t MAX_LEAVES = 64;
constexpr std::uint32_t MAX_EPOCH = 200;

void dumpTree() {
    for (std::uint32_t n = 1; n <= MAX_LEAVES; ++n) {
        printf("N=%u root=%u depth=%u nodes=%u\n", n, T::root(n), T::depth(n), T::nodeCount(n));
        for (std::uint32_t p = 0; p < n; ++p) {
            printf("  p=%u dp=[%s] cp=[%s]\n", p, join(T::directPath(p, n)).c_str(), join(T::copath(p, n)).c_str());
        }
        for (std::uint32_t x = 0; x < T::nodeCount(n); ++x) {
            const bool isRoot = x == T::root(n);
            const std::string par = isRoot ? "-" : std::to_string(T::parent(x, n));
            const std::string sib = isRoot ? "-" : std::to_string(T::sibling(x, n));
            const std::string kids = T::isLeaf(x) ? "" : join(T::children(x, n));
            printf("  x=%u lvl=%u par=%s sib=%s kids=[%s]\n", x, T::level(x), par.c_str(), sib.c_str(), kids.c_str());
        }
    }
}

void dumpLadder() {
    for (const std::uint32_t floor : {1u, 137u}) {
        printf("LADDER floor=%u\n", floor);
        for (std::uint32_t epoch = floor; epoch <= floor + MAX_EPOCH; ++epoch) {
            printf(
                "  e=%u spans=[%s] skips=[%s] unit=%d\n", epoch, joinSpans(L::rungSpansFor(epoch, floor)).c_str(),
                join(L::skipRungTargets(epoch, floor)).c_str(), L::requiresUnitRung(epoch, floor) ? 1 : 0
            );
        }
    }

    printf("DESCENTS\n");
    const std::vector<std::pair<std::uint32_t, std::uint32_t>> descents = {
        {1, 1}, {2, 1}, {8, 1}, {12, 5}, {16, 1}, {30, 3}, {64, 40}, {256, 1}, {1024, 1}, {1000, 500},
    };
    for (const auto& [from, to] : descents) {
        const auto plan = L::planDescent(from, to, spansThrough(from, 1));
        printf(
            "  from=%u to=%u bound=%u plan=[%s]\n", from, to, L::descentBound(from, to),
            plan.has_value() ? joinSpans(*plan).c_str() : "NONE"
        );
    }

    printf("FLOORS\n");
    const std::vector<std::pair<std::uint32_t, int>> floors = {
        {1, -1}, {20, -1}, {20, 8000}, {9000, 8000}, {1, 5},
    };
    for (const auto& [era, pruned] : floors) {
        const auto result = pruned < 0 ? L::descentFloor(era) :
                                         L::descentFloor(era, static_cast<std::uint32_t>(pruned));
        printf("  era=%u pruned=%d floor=%u reason=%s\n", era, pruned, result.floor, reasonName(result.reason).c_str());
    }

    printf("VALIDATIONS\n");
    struct Case {
        std::vector<RungSpan> spans;
        std::uint32_t epoch;
        std::uint32_t floor;
        int pruned;
    };
    const std::vector<Case> cases = {
        {{}, 1, 1, -1},
        {{}, 20, 20, -1},
        {{}, 8, 1, -1},
        {{RungSpan{8, 7}}, 8, 1, -1},
        {{RungSpan{8, 7}, RungSpan{8, 5}}, 8, 1, -1},
        {{RungSpan{8, 8}}, 8, 1, -1},
        {{RungSpan{8, 9}}, 8, 1, -1},
        {{RungSpan{7, 6}}, 8, 1, -1},
        {{RungSpan{8, 6}}, 8, 1, -1},
        {{RungSpan{8, 7}, RungSpan{8, 3}}, 8, 5, -1},
        {{RungSpan{8, 7}, RungSpan{8, 4}}, 8, 1, 5},
        {{RungSpan{8, 7}, RungSpan{8, 7}}, 8, 1, -1},
    };
    for (std::size_t i = 0; i < cases.size(); ++i) {
        const Case& c = cases[i];
        const auto result = c.pruned < 0 ?
            L::validateRungSet(c.spans, c.epoch, c.floor) :
            L::validateRungSet(c.spans, c.epoch, c.floor, static_cast<std::uint32_t>(c.pruned));
        printf("  case=%zu ok=%d problem=%s\n", i, result.ok ? 1 : 0, problemName(result.problem).c_str());
    }
}

} // namespace

int main() {
    dumpTree();
    dumpLadder();
    return 0;
}
