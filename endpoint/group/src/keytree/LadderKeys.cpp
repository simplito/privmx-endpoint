/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include "privmx/endpoint/group/keytree/LadderKeys.hpp"

#include <set>
#include <stdexcept>
#include <string>

using namespace privmx::endpoint::group::keytree;

LadderKeys::LadderKeys(TreeKeyStore& store) : _store(store) {}

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
) const {
    const auto published = publicKeyOfEpoch(epoch, registry);
    if (!published.has_value()) {
        // No anchor for this epoch means we cannot vouch for the key. Refusing is the safe answer: accepting an
        // unverifiable key is exactly how a substituted rung would slip through.
        return false;
    }
    return published.value() == recovered.getPublicKey();
}

// ─────────────────────────────────────────────────────────────────────────────
// Publishing
// ─────────────────────────────────────────────────────────────────────────────

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
            "cannot build the mandatory unit rung for epoch " + std::to_string(newEpoch) +
            ": the previous epoch key is unavailable"
        );
    }
    ArchiveRung unitRung;
    unitRung.span = RungSpan{newEpoch, newEpoch - 1};
    unitRung.recipientKind = RungRecipientKind::Epoch;
    unitRung.blob = TreeKeys::wrapKey(previousEpochKey.value(), newGrantPublicKey, signer);
    unitRung.author = author;
    rungs.push_back(unitRung);

    if (!includeSkipRungs) {
        return rungs;
    }

    // Skip rungs are best effort: a target key we do not hold costs walk time, not correctness.
    for (const std::uint32_t target : LadderMath::skipRungTargets(newEpoch, eraFloor)) {
        if (target == newEpoch - 1) {
            continue; // already covered by the unit rung
        }
        const auto targetKey = _store.getGrantKey(target);
        if (!targetKey.has_value()) {
            continue;
        }
        ArchiveRung rung;
        rung.span = RungSpan{newEpoch, target};
        rung.recipientKind = RungRecipientKind::Epoch;
        rung.blob = TreeKeys::wrapKey(targetKey.value(), newGrantPublicKey, signer);
        rung.author = author;
        rungs.push_back(rung);
    }
    return rungs;
}

std::vector<ArchiveRung> LadderKeys::buildEraLinks(
    std::uint32_t closingEpoch,
    const privmx::crypto::PrivateKey& closingEpochKey,
    const std::vector<EraLinkRecipient>& entitled,
    const std::string& author,
    const privmx::crypto::PrivateKey& signer
) {
    std::vector<ArchiveRung> links;
    for (const EraLinkRecipient& recipient : entitled) {
        if (recipient.kind == RungRecipientKind::Epoch) {
            throw std::invalid_argument("an era link must be addressed to a user or a group, not to an epoch");
        }
        ArchiveRung link;
        // An era link is not a descent step — the recipient's own key opens it — but it must still satisfy the
        // direction invariant `target < at`, because the server validates every rung uniformly. So it is
        // addressed at the new era's floor and carries the closing era's top key.
        link.span = RungSpan{closingEpoch + 1, closingEpoch};
        link.recipientKind = recipient.kind;
        link.recipientId = recipient.id;
        link.blob = TreeKeys::wrapKey(closingEpochKey, recipient.publicKey, signer);
        link.author = author;
        links.push_back(link);
    }
    return links;
}

// ─────────────────────────────────────────────────────────────────────────────
// Descending
// ─────────────────────────────────────────────────────────────────────────────

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

    const auto startKey = _store.getGrantKey(from);
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
    std::set<std::uint32_t> visited{from};
    std::uint32_t steps = 0;

    while (current > goal) {
        if (++steps > maxWalk) {
            result.failure = DescentFailure::TooLong;
            result.reachedEpoch = current;
            return result;
        }

        // Greedy: the smallest target not below the goal is the largest jump that does not overshoot.
        const ArchiveRung* best = nullptr;
        for (const ArchiveRung& rung : available) {
            if (rung.recipientKind != RungRecipientKind::Epoch) {
                continue; // era links are crossed explicitly, not walked over
            }
            // Direction invariant. Never traverse an upward rung, even if it somehow got stored: it is exactly
            // the shape that would hand a removed member a later key.
            if (rung.span.target >= rung.span.at) {
                continue;
            }
            if (rung.span.at != current || rung.span.target < goal) {
                continue;
            }
            if (best == nullptr || rung.span.target < best->span.target) {
                best = &rung;
            }
        }
        if (best == nullptr) {
            result.failure = floorFailure != DescentFailure::None ? floorFailure : DescentFailure::MissingRung;
            result.reachedEpoch = current;
            return result;
        }

        const auto recovered = TreeKeys::unwrapKey(best->blob, currentKey);
        if (!recovered.has_value()) {
            result.failure = DescentFailure::DecryptFailed;
            result.reachedEpoch = current;
            return result;
        }
        if (!verifyAgainstRegistry(recovered.value(), best->span.target, registry)) {
            result.failure = DescentFailure::Tampered;
            result.reachedEpoch = current;
            result.blame = best->author;
            return result;
        }

        current = best->span.target;
        currentKey = recovered.value();
        _store.putGrantKey(current, currentKey);
        result.reachedEpoch = current;

        if (visited.count(current) > 0) {
            // Defensive: a malformed rung set must not spin forever.
            result.failure = DescentFailure::MissingRung;
            return result;
        }
        visited.insert(current);
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

DescentResult LadderKeys::crossEraBoundary(
    const std::vector<ArchiveRung>& available,
    const std::string& ownUserId,
    const privmx::crypto::PrivateKey& ownUserKey,
    const std::vector<std::pair<std::string, privmx::crypto::PrivateKey>>& ownGroupKeys,
    const std::vector<EpochRegistryEntry>& registry
) {
    DescentResult result;
    for (const ArchiveRung& link : available) {
        std::optional<privmx::crypto::PrivateKey> opener;
        if (link.recipientKind == RungRecipientKind::User && link.recipientId == ownUserId) {
            opener = ownUserKey;
        } else if (link.recipientKind == RungRecipientKind::Group) {
            for (const auto& [groupId, groupKey] : ownGroupKeys) {
                if (groupId == link.recipientId) {
                    opener = groupKey;
                    break;
                }
            }
        }
        if (!opener.has_value()) {
            continue;
        }

        const auto recovered = TreeKeys::unwrapKey(link.blob, opener.value());
        if (!recovered.has_value()) {
            result.failure = DescentFailure::DecryptFailed;
            continue; // another link may still open
        }
        if (!verifyAgainstRegistry(recovered.value(), link.span.target, registry)) {
            result.failure = DescentFailure::Tampered;
            result.blame = link.author;
            return result;
        }
        _store.putGrantKey(link.span.target, recovered.value());
        result.key = recovered.value();
        result.reachedEpoch = link.span.target;
        result.failure = DescentFailure::None;
        return result;
    }
    if (result.failure == DescentFailure::None) {
        result.failure = DescentFailure::EraBoundary;
    }
    return result;
}
