/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include "privmx/endpoint/group/keytree/LadderKeys.hpp"

#include <algorithm>
#include <cstddef>
#include <set>
#include <stdexcept>
#include <string>

#include <privmx/endpoint/core/BigEndian.hpp>

#include "privmx/endpoint/group/keytree/TreeCommits.hpp"
#include "privmx/endpoint/group/keytree/TreeKeys.hpp"

using namespace privmx::endpoint::group::keytree;

namespace {

std::string rungLabel(const RungSpan& span) {
    std::string label = TreeCommits::tag("pmx-rung");
    privmx::endpoint::core::bigendian::putU32(label, span.at);
    privmx::endpoint::core::bigendian::putU32(label, span.target);
    return label;
}

} // namespace

LadderKeys::LadderKeys(TreeKeyCache& cache) : _cache(cache) {}

std::string LadderKeys::sealRung(
    const privmx::crypto::PrivateKey& key,
    const RungSpan& span,
    const privmx::crypto::PublicKey& to,
    const privmx::crypto::PrivateKey& signer
) {
    return TreeKeys::wrapKey(key, to, signer, rungLabel(span));
}

std::optional<privmx::crypto::PrivateKey> LadderKeys::openRung(
    const ArchiveRung& rung,
    const privmx::crypto::PrivateKey& with
) {
    // A rung sealed for another span does not open: relabelled, so not this rung's sealer's doing.
    return TreeKeys::unwrapKey(rung.blob, with, rungLabel(rung.span));
}

std::optional<privmx::crypto::PublicKey> LadderKeys::publicKeyOfEpoch(
    std::uint32_t epoch,
    const std::vector<EpochRegistryEntry>& registry
) {
    for (const EpochRegistryEntry& entry : registry) {
        if (entry.epoch == epoch) {
            return entry.grantPublicKey;
        }
    }
    return std::nullopt;
}

bool LadderKeys::verifyAgainstRegistry(
    const privmx::crypto::PrivateKey& recovered,
    std::uint32_t epoch,
    const std::vector<EpochRegistryEntry>& registry
) {
    const auto published = publicKeyOfEpoch(epoch, registry);
    if (!published.has_value()) {
        // No anchor for this epoch means we cannot vouch for the key. Refusing is the safe answer: accepting an
        // unverifiable key is exactly how a substituted rung would slip through.
        return false;
    }
    return published.value() == recovered.getPublicKey();
}

std::optional<RungSpan> LadderKeys::firstRungNotOpeningToTheChain(
    const std::vector<ArchiveRung>& rungs,
    const privmx::crypto::PrivateKey& atKey,
    const std::vector<EpochRegistryEntry>& registry
) {
    for (const ArchiveRung& rung : rungs) {
        const auto recovered = openRung(rung, atKey);
        if (!recovered.has_value() || !verifyAgainstRegistry(recovered.value(), rung.span.target, registry)) {
            return rung.span;
        }
    }
    return std::nullopt;
}

std::vector<std::uint32_t> LadderKeys::requiredSkipTargets(
    std::uint32_t newEpoch,
    std::uint32_t eraFloor,
    std::optional<std::uint32_t> prunedBelow
) {
    std::vector<std::uint32_t> targets;
    if (!LadderMath::requiresUnitRung(newEpoch, eraFloor)) {
        return targets; // genesis of an era: nothing below to link to
    }
    // Only the era floor and the prune watermark may shorten this list: both are policy the bridge applies anyway,
    // and what they cut off is gone for every member alike, unlike a key merely absent from this client's cache.
    const std::uint32_t floor = LadderMath::descentFloor(eraFloor, prunedBelow).floor;
    for (const std::uint32_t target : LadderMath::skipRungTargets(newEpoch, eraFloor)) {
        if (target == newEpoch - 1 || target < floor) {
            continue; // the unit rung already covers `newEpoch - 1`
        }
        targets.push_back(target);
    }
    // Nearest first: `gatherRungKeys` walks this as a chain, each descent resuming where the previous one landed.
    std::sort(targets.begin(), targets.end(), std::greater<std::uint32_t>());
    return targets;
}

RungKeyGathering LadderKeys::gatherRungKeys(
    std::uint32_t newEpoch,
    const std::vector<ArchiveRung>& available,
    const std::vector<EpochRegistryEntry>& registry,
    std::uint32_t eraFloor,
    std::optional<std::uint32_t> prunedBelow
) {
    RungKeyGathering gathering;
    const std::vector<std::uint32_t> targets = requiredSkipTargets(newEpoch, eraFloor, prunedBelow);
    if (targets.empty()) {
        return gathering;
    }

    std::uint32_t from = newEpoch - 1;
    if (!_cache.getGrantKey(from).has_value()) {
        // Nothing to descend from. The rotation cannot proceed regardless — the unit rung needs this same key —
        // but reporting it here keeps the caller's error about the ladder rather than about a failed wrap.
        gathering.complete = false;
        gathering.missingTargets = targets;
        gathering.failure = DescentFailure::NotEntitled;
        return gathering;
    }

    for (std::size_t i = 0; i < targets.size(); ++i) {
        const std::uint32_t target = targets[i];
        if (_cache.getGrantKey(target).has_value()) {
            from = target; // already held, from an earlier gather or a read in this session
            continue;
        }
        // `maxWalk` sized to this hop: the default protects a reader from a pathological rung set, but here even a
        // stretch of nothing but unit rungs must be walked, or it stays linear forever. `descend` has a visited set.
        const DescentResult step = descend(from, target, available, registry, eraFloor, prunedBelow, from - target + 1);
        gathering.unwraps += step.hops;
        if (!step.key.has_value()) {
            gathering.complete = false;
            gathering.failure = step.failure;
            gathering.blame = step.blame;
            // Every deeper target goes with it: the gather descends, so a break here cuts off the rest of the
            // chain too. Naming them all is what lets the caller report the whole stretch at risk.
            gathering.missingTargets.assign(targets.begin() + static_cast<std::ptrdiff_t>(i), targets.end());
            return gathering;
        }
        from = target;
    }
    return gathering;
}

std::vector<ArchiveRung> LadderKeys::buildRungs(
    std::uint32_t newEpoch,
    const privmx::crypto::PublicKey& newGrantPublicKey,
    const std::optional<privmx::crypto::PrivateKey>& previousEpochKey,
    std::uint32_t eraFloor,
    const std::string& author,
    const privmx::crypto::PrivateKey& signer,
    bool includeSkipRungs,
    std::optional<std::uint32_t> prunedBelow
) {
    std::vector<ArchiveRung> rungs;
    if (!LadderMath::requiresUnitRung(newEpoch, eraFloor)) {
        // Genesis of an era: there is nothing below to link to.
        return rungs;
    }

    // The unit rung is mandatory. Its absence is unrepairable after the fact, so failing here is the only
    // correct behaviour — a rotation that proceeds without it silently truncates history forever.
    if (!previousEpochKey.has_value()) {
        throw std::invalid_argument(
            "cannot build the mandatory unit rung for epoch " +
            std::to_string(newEpoch) +
            ": the previous epoch key is unavailable"
        );
    }
    ArchiveRung unitRung;
    unitRung.span = RungSpan{newEpoch, newEpoch - 1};
    unitRung.blob = sealRung(previousEpochKey.value(), unitRung.span, newGrantPublicKey, signer);
    unitRung.author = author;
    rungs.push_back(unitRung);

    if (!includeSkipRungs) {
        return rungs;
    }

    // Emitted oldest target first, undoing the nearest-first order the gather needs.
    const std::vector<std::uint32_t> targets = requiredSkipTargets(newEpoch, eraFloor, prunedBelow);
    for (auto target = targets.rbegin(); target != targets.rend(); ++target) {
        const auto targetKey = _cache.getGrantKey(*target);
        if (!targetKey.has_value()) {
            // Not a skippable optimisation. This rung can never be published again — its span is pinned to this
            // epoch — so committing the set without it orphans everything below it from the fast path forever.
            throw std::invalid_argument(
                "cannot build the aligned skip rung " +
                std::to_string(newEpoch) +
                "->" +
                std::to_string(*target) +
                ": the grant key for epoch " +
                std::to_string(*target) +
                " is not held. Call gatherRungKeys before rotating; a rung missing from this set is unrepairable"
            );
        }
        ArchiveRung rung;
        rung.span = RungSpan{newEpoch, *target};
        rung.blob = sealRung(targetKey.value(), rung.span, newGrantPublicKey, signer);
        rung.author = author;
        rungs.push_back(rung);
    }
    return rungs;
}

DescentResult LadderKeys::descend(
    std::uint32_t from,
    std::uint32_t to,
    const std::vector<ArchiveRung>& available,
    const std::vector<EpochRegistryEntry>& registry,
    std::uint32_t eraFloor,
    std::optional<std::uint32_t> prunedBelow,
    std::uint32_t maxWalk
) {
    DescentResult result;
    result.reachedEpoch = from;

    if (to > from) {
        throw std::invalid_argument(
            "cannot descend upwards: from " + std::to_string(from) + " to " + std::to_string(to)
        );
    }

    const auto startKey = _cache.getGrantKey(from);
    if (!startKey.has_value()) {
        result.failure = DescentFailure::NotEntitled;
        return result;
    }
    if (to == from) {
        result.key = startKey;
        return result;
    }

    // Clamp the goal to whatever the era floor and prune watermark allow, and remember which one applied so the
    // caller can explain the outcome instead of surfacing a decryption failure.
    const DescentFloor floor = LadderMath::descentFloor(eraFloor, prunedBelow);
    std::uint32_t goal = to;
    DescentFailure floorFailure = DescentFailure::None;
    if (floor.floor > to) {
        goal = floor.floor;
        floorFailure = floor.reason == DescentFloorReason::Pruned ? DescentFailure::Pruned :
                                                                    DescentFailure::EraBoundary;
    }

    std::uint32_t current = from;
    privmx::crypto::PrivateKey currentKey = startKey.value();

    while (current > goal) {
        if (result.hops >= maxWalk) {
            result.failure = DescentFailure::TooLong;
            result.reachedEpoch = current;
            return result;
        }

        // Greedy: the smallest target not below the goal is the largest jump that does not overshoot. The span is
        // sealed inside the blob, but the sealer is not authenticated (any holder of the epoch key can seal one), so
        // one that does not open to its target's registered key is skipped for the next; blame only when none does.
        std::vector<const ArchiveRung*> candidates;
        for (const ArchiveRung& rung : available) {
            // Direction invariant. Never traverse an upward rung, even if it somehow got stored: it is exactly
            // the shape that would hand a removed member a later key. It also makes every hop strictly descend.
            if (rung.span.target < rung.span.at && rung.span.at == current && rung.span.target >= goal) {
                candidates.push_back(&rung);
            }
        }
        if (candidates.empty()) {
            result.failure = floorFailure != DescentFailure::None ? floorFailure : DescentFailure::MissingRung;
            result.reachedEpoch = current;
            return result;
        }
        std::stable_sort(candidates.begin(), candidates.end(), [](const ArchiveRung* a, const ArchiveRung* b) {
            return a->span.target < b->span.target;
        });
        const ArchiveRung* best = nullptr;
        std::optional<privmx::crypto::PrivateKey> recovered;
        DescentResult refused = result;
        for (const ArchiveRung* candidate : candidates) {
            recovered = openRung(*candidate, currentKey);
            if (recovered.has_value() && verifyAgainstRegistry(recovered.value(), candidate->span.target, registry)) {
                best = candidate;
                break;
            }
            if (refused.failure == DescentFailure::None) {
                refused.failure = recovered.has_value() ? DescentFailure::Tampered : DescentFailure::DecryptFailed;
                refused.reachedEpoch = current;
            }
            // Blame only a rung its epoch's opener sealed (an author), and the first such one whatever failed
            // first: an unattributed rung tried earlier (a lower span, sorted first) must not hide the opener's.
            if (recovered.has_value() && !candidate->author.empty() && !refused.blame.has_value()) {
                refused.failure = DescentFailure::Tampered;
                refused.blame = candidate->author;
            }
        }
        if (best == nullptr) {
            return refused;
        }

        current = best->span.target;
        currentKey = recovered.value();
        _cache.putGrantKey(current, currentKey);
        result.reachedEpoch = current;
        ++result.hops;
    }

    if (current > to) {
        // We got as far as the floor allowed but not to the requested epoch. Partial progress is cached and the
        // reason is reportable — "history before X is not available to you" rather than an error.
        result.failure = floorFailure;
        return result;
    }
    result.key = currentKey;
    return result;
}
