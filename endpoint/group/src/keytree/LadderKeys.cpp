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

std::string LadderKeys::rungLabel(const RungSpan& span) {
    std::string label = TreeCommits::tag("pmx-rung");
    privmx::endpoint::core::bigendian::putU32(label, span.at);
    privmx::endpoint::core::bigendian::putU32(label, span.target);
    return label;
}

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

std::vector<RungSpan> LadderKeys::unopenedSpans(
    std::uint32_t at,
    const std::vector<ArchiveRung>& served,
    const TreeKeyCache& cache,
    std::uint32_t floor
) {
    std::vector<RungSpan> unopened;
    const auto atKey = cache.getGrantKey(at);
    if (!atKey.has_value() || at < 1 || floor < 1) {
        return unopened;
    }
    for (const RungSpan& span : LadderMath::rungSpansFor(at, floor)) {
        const auto targetKey = cache.getGrantKey(span.target);
        if (!targetKey.has_value()) {
            continue; // nothing this client could seal anyway
        }
        const bool opens = std::any_of(served.begin(), served.end(), [&](const ArchiveRung& rung) {
            if (rung.span.at != span.at || rung.span.target != span.target) {
                return false;
            }
            const auto recovered = openRung(rung, atKey.value());
            return recovered.has_value() && recovered->getPublicKey() == targetKey->getPublicKey();
        });
        if (!opens) {
            unopened.push_back(span);
        }
    }
    return unopened;
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

std::vector<std::uint32_t> LadderKeys::requiredSkipTargets(std::uint32_t newEpoch, std::uint32_t eraFloor) {
    std::vector<std::uint32_t> targets;
    if (!LadderMath::requiresUnitRung(newEpoch, eraFloor)) {
        return targets; // genesis of an era: nothing below to link to
    }
    // Only the era floor may shorten this list: it is policy the bridge applies anyway, and what it cuts off is gone
    // for every member alike, unlike a key merely absent from this client's cache.
    const std::uint32_t floor = LadderMath::descentFloor(eraFloor).floor;
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
    std::uint32_t eraFloor
) {
    RungKeyGathering gathering;
    const std::vector<std::uint32_t> targets = requiredSkipTargets(newEpoch, eraFloor);
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
        const DescentResult step = descend(from, target, available, registry, eraFloor, from - target + 1);
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
    bool includeSkipRungs
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
    return LadderMath::buildRungSet(newEpoch, eraFloor, includeSkipRungs, [&](const RungSpan& span) {
        const auto targetKey = span.target == newEpoch - 1 ? previousEpochKey : _cache.getGrantKey(span.target);
        if (!targetKey.has_value()) {
            // Not a skippable optimisation. This rung can never be published again — its span is pinned to this
            // epoch — so committing the set without it orphans everything below it from the fast path forever.
            throw std::invalid_argument(
                "cannot build the aligned skip rung " +
                std::to_string(newEpoch) +
                "->" +
                std::to_string(span.target) +
                ": the grant key for epoch " +
                std::to_string(span.target) +
                " is not held. Call gatherRungKeys before rotating; a rung missing from this set is unrepairable"
            );
        }
        ArchiveRung rung;
        rung.span = span;
        rung.blob = sealRung(targetKey.value(), span, newGrantPublicKey, signer);
        rung.author = author;
        return rung;
    });
}

DescentResult LadderKeys::descend(
    std::uint32_t from,
    std::uint32_t to,
    const std::vector<ArchiveRung>& available,
    const std::vector<EpochRegistryEntry>& registry,
    std::uint32_t eraFloor,
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

    // Clamp the goal to whatever the era floor allows, and remember that it did so the caller can explain the outcome
    // instead of surfacing a decryption failure.
    const DescentFloor floor = LadderMath::descentFloor(eraFloor);
    std::uint32_t goal = to;
    DescentFailure floorFailure = DescentFailure::None;
    if (floor.floor > to) {
        goal = floor.floor;
        floorFailure = DescentFailure::EraBoundary;
    }

    // The walk itself is LadderMath::walkDown; what is the group's own: a rung opens with an epoch's grant key, the
    // key it gives must be the registry's, and a failed rung is blamed on its author and reported for repair. The
    // span is sealed inside the blob, but the sealer is not authenticated (any holder of the epoch key can seal one),
    // so one that does not open to its target's registered key is skipped for the next; blame only when none does.
    std::set<std::uint32_t> failedTargets; // at the current hop
    DescentFailure hopFailure = DescentFailure::None;
    std::optional<std::string> hopBlame;
    const LadderWalk<privmx::crypto::PrivateKey> walk = LadderMath::walkDown(
        from, goal, startKey.value(), maxWalk,
        [&](std::uint32_t) -> const std::vector<ArchiveRung>& { return available; },
        [](const ArchiveRung& rung, const privmx::crypto::PrivateKey& key) { return openRung(rung, key); },
        [&](std::uint32_t target, const privmx::crypto::PrivateKey& key) {
            return verifyAgainstRegistry(key, target, registry);
        },
        [&](const ArchiveRung& rung, bool opened) {
            failedTargets.insert(rung.span.target);
            if (hopFailure == DescentFailure::None) {
                hopFailure = opened ? DescentFailure::Tampered : DescentFailure::DecryptFailed;
            }
            // Blame only a rung its epoch's opener sealed (an author), and the first such one whatever failed
            // first: an unattributed rung tried earlier (a lower span, sorted first) must not hide the opener's.
            if (opened && !rung.author.empty() && !hopBlame.has_value()) {
                hopFailure = DescentFailure::Tampered;
                hopBlame = rung.author;
            }
        },
        [&](const ArchiveRung& rung, const privmx::crypto::PrivateKey& key) {
            for (const std::uint32_t target : failedTargets) {
                if (target < rung.span.target) {
                    result.brokenSpans.push_back(RungSpan{rung.span.at, target}); // routed around: worth a repair
                }
            }
            failedTargets.clear();
            hopFailure = DescentFailure::None;
            hopBlame.reset();
            _cache.putGrantKey(rung.span.target, key);
        }
    );
    result.reachedEpoch = walk.reached;
    result.hops = walk.hops;
    switch (walk.end) {
    case LadderWalkEnd::TooLong:
        result.failure = DescentFailure::TooLong;
        return result;
    case LadderWalkEnd::NoRung:
        result.failure = floorFailure != DescentFailure::None ? floorFailure : DescentFailure::MissingRung;
        return result;
    case LadderWalkEnd::Refused:
        result.failure = hopFailure;
        result.blame = hopBlame;
        for (const std::uint32_t target : failedTargets) {
            result.brokenSpans.push_back(RungSpan{walk.reached, target});
        }
        return result;
    case LadderWalkEnd::Reached:
        break;
    }
    if (walk.reached > to) {
        // We got as far as the floor allowed but not to the requested epoch. Partial progress is cached and the
        // reason is reportable — "history before X is not available to you" rather than an error.
        result.failure = floorFailure;
        return result;
    }
    result.key = walk.key;
    return result;
}
