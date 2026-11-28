/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_ENDPOINT_GROUP_KEYTREE_LADDERMATH_HPP_
#define _PRIVMXLIB_ENDPOINT_GROUP_KEYTREE_LADDERMATH_HPP_

#include <algorithm>
#include <cstdint>
#include <optional>
#include <type_traits>
#include <vector>

namespace privmx {
namespace endpoint {
namespace group {
namespace keytree {

// A rung reduced to what the rules operate on. `target < at` always holds for a valid rung.
struct RungSpan {
    // The epoch whose public key the rung is wrapped to.
    std::uint32_t at;
    // The (older) epoch whose private key the rung carries.
    std::uint32_t target;

    bool operator==(const RungSpan& other) const { return at == other.at && target == other.target; }
};

// Mirrors the protocol errors the bridge returns.
enum class LadderProblemKind {
    None,
    Direction,       // `target >= at` — the entire security guarantee of this layer
    WrongEpoch,      // not addressed to the epoch being created
    BelowEraFloor,   // would cross an era boundary
    Duplicate,       // same span submitted twice
    UnitRungMissing, // the mandatory rung to the previous epoch is absent
    NotCanonical,    // a span the epoch does not owe (`rungSpansFor` above the floor)
};

struct LadderValidation {
    bool ok = true;
    LadderProblemKind problem = LadderProblemKind::None;
    // The offending rung, when the problem concerns one.
    RungSpan rung{0, 0};
};

enum class DescentFloorReason {
    None,        // nothing constrains the descent
    EraBoundary, // an era floor is in the way — an entitlement matter
};

struct DescentFloor {
    std::uint32_t floor;
    DescentFloorReason reason;
};

// How `LadderMath::walkDown` ended.
enum class LadderWalkEnd {
    Reached, // at the goal
    NoRung,  // nothing served at `reached` points down to a version not below the goal
    Refused, // every such rung failed to open, or opened to a key that did not verify
    TooLong, // `maxHops` spent
};

template<typename Key>
struct LadderWalk {
    LadderWalkEnd end;
    std::uint32_t reached; // the lowest version whose key the walk holds
    Key key;               // that version's key
    std::uint32_t hops;
};

// Pure epoch arithmetic: which rungs an epoch must publish and how a descent traverses them. Must agree with the
// bridge exactly — `test/tools/keytree_conformance_dump.cpp` emits vectors for diffing the two.
class LadderMath {
public:
    // `a - 2^j` for every `j >= 1` with `2^j | a`, clamped to the era floor, ascending. Aligning skips on powers of
    // two gives two rungs per epoch amortised and makes a descent `O(log delta)` instead of `O(delta)`.
    static std::vector<std::uint32_t> skipRungTargets(std::uint32_t newEpoch, std::uint32_t eraFloor);

    // The unit rung plus aligned skips; empty at the era floor. Absence of the unit rung must be rejected at write
    // time — afterwards no party ever again holds both the previous epoch's private key and this epoch's public one.
    static std::vector<RungSpan> rungSpansFor(std::uint32_t newEpoch, std::uint32_t eraFloor, bool includeSkips = true);

    // False only at the era floor.
    static bool requiresUnitRung(std::uint32_t newEpoch, std::uint32_t eraFloor);

    // Under the aligned rule. Exists to make the cost claim testable.
    static std::uint32_t totalRungsThrough(std::uint32_t upToEpoch);

    // Greedy: the smallest target not below `to`, which is optimal for an aligned set and needs no shortest-path
    // search. Wrong-direction rungs are ignored entirely; empty when the target is unreachable.
    static std::optional<std::vector<RungSpan>> planDescent(
        std::uint32_t from,
        std::uint32_t to,
        const std::vector<RungSpan>& available
    );

    // The spans a descent from `from` to `to` walks when every canonical rung (`rungSpansFor`) is stored: at each epoch
    // the one with the smallest target not below `to`, the pick `planDescent` and `LadderKeys::descend` make. What a
    // client asks the bridge for instead of every rung in between. `to` at or above `eraFloor` (the ladder floor);
    // empty when `to >= from`.
    static std::vector<RungSpan> canonicalDescent(std::uint32_t from, std::uint32_t to, std::uint32_t eraFloor);

    // The ways round a descent that stopped at `at`: every other canonical span at `at` reaching no lower than `to`,
    // each followed by its canonical descent to `to`, minus the spans in `known`. Deduplicated, in walk order.
    static std::vector<RungSpan> detourSpans(
        std::uint32_t at,
        std::uint32_t to,
        std::uint32_t eraFloor,
        const std::vector<RungSpan>& known
    );

    // Upper bound on descent length with aligned skip rungs: `2*log2(delta) + 2`.
    static std::uint32_t descentBound(std::uint32_t from, std::uint32_t to);

    // The era floor, and whether it constrains anything: what lets a client say "not available to you" instead of
    // surfacing a decryption failure.
    static DescentFloor descentFloor(std::uint32_t eraFloor);

    // Validates a submitted rung set for an epoch being created. Pure; the caller reports the problem.
    static LadderValidation validateRungSet(
        const std::vector<RungSpan>& submitted,
        std::uint32_t newEpoch,
        std::uint32_t eraFloor
    );

    // The two parts of a ladder that do not depend on what a key is - a group's grant keys (EC, LadderKeys) and a
    // Space's symmetric keys (GroupApiImplSpaces) both use them; sealing, opening and verifying are the caller's.

    // The rung set a new version publishes: `seal(span)` for each of `rungSpansFor(newVersion, floor, includeSkips)`,
    // in that order (the unit rung, then the skips oldest first). `seal` throws for a key it cannot reach.
    template<typename Seal>
    static auto buildRungSet(std::uint32_t newVersion, std::uint32_t floor, bool includeSkips, Seal&& seal) {
        std::vector<std::decay_t<decltype(seal(RungSpan{0, 0}))>> rungs;
        for (const RungSpan& span : rungSpansFor(newVersion, floor, includeSkips)) {
            rungs.push_back(seal(span));
        }
        return rungs;
    }

    // Descends from `from`, whose key is `start`, to `goal`. At each version the rungs `rungsAt(version)` serves
    // (each with a `span`) that point down to a version not below the goal are tried, lowest target first - the
    // largest jump that does not overshoot, `O(log delta)` on an aligned set - until one `open(rung, key)`s to a key
    // `verify(target, key)` accepts; `onStep(rung, key)` then, or `onRefused(rung, opened)` for each that did not.
    // Wrong-direction rungs are never traversed: they are what would hand a removed member a later key.
    template<typename Key, typename RungsAt, typename Open, typename Verify, typename OnRefused, typename OnStep>
    static LadderWalk<Key> walkDown(
        std::uint32_t from,
        std::uint32_t goal,
        const Key& start,
        std::uint32_t maxHops,
        RungsAt&& rungsAt,
        Open&& open,
        Verify&& verify,
        OnRefused&& onRefused,
        OnStep&& onStep
    ) {
        LadderWalk<Key> walk{LadderWalkEnd::Reached, from, start, 0};
        while (walk.reached > goal) {
            if (walk.hops >= maxHops) {
                walk.end = LadderWalkEnd::TooLong;
                return walk;
            }
            auto&& served = rungsAt(walk.reached);
            std::vector<const std::decay_t<decltype(*served.begin())>*> candidates;
            for (const auto& rung : served) {
                if (rung.span.target < rung.span.at && rung.span.at == walk.reached && rung.span.target >= goal) {
                    candidates.push_back(&rung);
                }
            }
            if (candidates.empty()) {
                walk.end = LadderWalkEnd::NoRung;
                return walk;
            }
            std::stable_sort(candidates.begin(), candidates.end(), [](const auto* a, const auto* b) {
                return a->span.target < b->span.target;
            });
            bool stepped = false;
            for (const auto* candidate : candidates) {
                const std::optional<Key> opened = open(*candidate, walk.key);
                if (opened.has_value() && verify(candidate->span.target, opened.value())) {
                    onStep(*candidate, opened.value());
                    walk.reached = candidate->span.target;
                    walk.key = opened.value();
                    ++walk.hops;
                    stepped = true;
                    break;
                }
                onRefused(*candidate, opened.has_value());
            }
            if (!stepped) {
                walk.end = LadderWalkEnd::Refused;
                return walk;
            }
        }
        return walk;
    }

private:
    static void assertEpoch(std::uint32_t value, const char* name);
};

} // namespace keytree
} // namespace group
} // namespace endpoint
} // namespace privmx

#endif // _PRIVMXLIB_ENDPOINT_GROUP_KEYTREE_LADDERMATH_HPP_
