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

#include <cstdint>
#include <optional>
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
    Direction,           // `target >= at` — the entire security guarantee of this layer
    WrongEpoch,          // not addressed to the epoch being created
    BelowEraFloor,       // would cross an era boundary
    BelowPruneWatermark, // targets a pruned epoch
    Duplicate,           // same span submitted twice
    UnitRungMissing,     // the mandatory rung to the previous epoch is absent
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
    Pruned,      // the range was deleted — a retention matter
};

struct DescentFloor {
    std::uint32_t floor;
    DescentFloorReason reason;
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

    // Total rungs written across epochs `1..upToEpoch` under the aligned rule. Makes the cost claim testable.
    static std::uint32_t totalRungsThrough(std::uint32_t upToEpoch);

    // Greedy: the smallest target not below `to`, which is optimal for an aligned set and needs no shortest-path
    // search. Wrong-direction rungs are ignored entirely; empty when the target is unreachable.
    static std::optional<std::vector<RungSpan>> planDescent(
        std::uint32_t from,
        std::uint32_t to,
        const std::vector<RungSpan>& available
    );

    // Upper bound on descent length with aligned skip rungs: `2*log2(delta) + 2`.
    static std::uint32_t descentBound(std::uint32_t from, std::uint32_t to);

    // The higher of the era floor and the prune watermark. Which one applied is what lets a client say "not
    // available to you" versus "deleted" instead of surfacing a decryption failure.
    static DescentFloor descentFloor(std::uint32_t eraFloor, std::optional<std::uint32_t> prunedBelow = std::nullopt);

    // Validates a submitted rung set for an epoch being created. Pure; the caller reports the problem.
    static LadderValidation validateRungSet(
        const std::vector<RungSpan>& submitted,
        std::uint32_t newEpoch,
        std::uint32_t eraFloor,
        std::optional<std::uint32_t> prunedBelow = std::nullopt
    );

private:
    static void assertEpoch(std::uint32_t value, const char* name);
};

} // namespace keytree
} // namespace group
} // namespace endpoint
} // namespace privmx

#endif // _PRIVMXLIB_ENDPOINT_GROUP_KEYTREE_LADDERMATH_HPP_
