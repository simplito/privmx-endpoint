/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include "privmx/endpoint/group/GroupKeys.hpp"

#include <algorithm>

#include <privmx/endpoint/core/CoreException.hpp>

#include "privmx/endpoint/group/DeferredWork.hpp"
#include "privmx/endpoint/group/GroupException.hpp"
#include "privmx/endpoint/group/keytree/LadderMath.hpp"
#include "privmx/utils/Logger.hpp"

using namespace privmx::endpoint;
using namespace group;

std::string group::blameSuffix(const std::optional<std::string>& who, const std::string& as) {
    return who.has_value() ? " (" + as + " " + who.value() + ")" : "";
}

std::uint32_t group::ladderFloorOf(
    std::int64_t eraFloor,
    const std::optional<std::int64_t>& prunedBelow,
    std::int64_t currentEpoch
) {
    const std::int64_t floor = std::max<std::int64_t>({1, eraFloor, prunedBelow.value_or(1)});
    if (floor > currentEpoch || floor > static_cast<std::int64_t>(UINT32_MAX)) {
        throw GroupDataIntegrityException("a ladder floor past the last epoch");
    }
    return static_cast<std::uint32_t>(floor);
}

std::int64_t group::newestEpoch(const server::GroupInfo& group, const server::GroupGetKeyArchiveResult& archive) {
    return std::max(group.keyVersion, archive.keyVersion);
}

privmx::crypto::PrivateKey GroupKeys::resolveGroupPrivKey(
    const std::string& groupId,
    int64_t epoch,
    const VerifiedGroup* seatedRead,
    const ClimbWith* with
) const {
    // An epoch's key never changes: once resolved and matched to its published public key it is served from here,
    // with no read, no tree check, no climb and no ladder. 0 ("current") names no fixed epoch, so it always reads.
    if (const auto known = deps.sessions.find(groupId); known && epoch > 0 && with == nullptr) {
        if (auto cached = known->epochKeys.get(epoch); cached.has_value()) {
            return cached.value();
        }
    }
    // Only its own current epoch: any other one needs the archive, which this read decides nothing about.
    const bool reuse = seatedRead != nullptr && (*seatedRead)->id == groupId && epoch == (*seatedRead)->keyVersion;
    // The served path checked against the latest statement before any key off it is used. A group without a
    // supported tree, or a caller without a seat, is left to the resolver, which refuses both without a key.
    std::optional<GroupRead> fresh;
    if (!reuse) {
        fresh = deps.facade.read(pathRead(groupId), keytree::TreeVerifier::Scope::Path);
    }
    const VerifiedGroup* verified = reuse ? seatedRead : (fresh->verified.has_value() ? &fresh->verified.value() : nullptr);
    const server::GroupInfo& group = reuse ? **seatedRead : fresh->group();
    const auto session = deps.sessions.of(groupId); // after the read: the bridge serves the group

    const int64_t currentEpoch = group.keyVersion;
    const auto cache = with != nullptr ? with->cache : session->treeKeys();
    keytree::GroupKeyResolver resolver(*cache);
    const bool needsDescent = verified != nullptr && epoch > 0 && epoch < currentEpoch;
    const privmx::crypto::PrivateKey& ownKey = with != nullptr ? *with->key : deps.userPrivKey;
    const keytree::ResolveResult resolved = needsDescent ?
        resolveDescending(resolver, *verified, epoch, ownKey) :
        resolver.resolve(group, epoch, ownKey, server::GroupGetKeyArchiveResult{});
    if (with != nullptr) {
        // A leaf renewal's previous-key climb: whatever it derived stays in its own cache and dies with the call.
        if (resolved.key.has_value()) {
            return resolved.key.value();
        }
        throw core::EncryptionKeyValidationException(describeResolveFailure(resolved));
    }
    // A descent that routed around, or stopped at, a broken rung: a holder of both keys can repair it. Only a descent
    // finds one, and only a verified read descends.
    for (const keytree::RungSpan& span : resolved.brokenSpans) {
        deferred.scheduleLadderCheck(
            groupId, (*verified)->contextId, span.at, DeferredWork::backgroundWindowMs(*verified)
        );
    }
    // The resolver refuses an unseated read before any key, so a key comes off `verified`.
    if (resolved.key.has_value()) {
        // The climb to the current epoch went through, so the served path is the caller's to vouch for: refill
        // whatever blanks a removal left on it, and re-key what somebody outside it set. Only recorded here: it runs
        // at the end of a later GroupApi call on the group (`runDueWork`), never inside a container's key lookup.
        deferred.scheduleSelfUpdateIfNeeded(groupId, *verified);
        // A rotation this session saw happen: holding both keys, it can check (and repair) the new epoch's rungs.
        const std::uint32_t cur = keytree::GroupKeyResolver::epochOf(currentEpoch);
        if (cur > 1 && cache->getGrantKey(cur).has_value() && cache->getGrantKey(cur - 1).has_value()) {
            deferred.scheduleObservedRotation(
                groupId, (*verified)->contextId, cur, DeferredWork::backgroundWindowMs(*verified)
            );
        }
        // The resolver has checked the key against the epoch's published public key on the way here.
        session->epochKeys.set(epoch == 0 ? currentEpoch : epoch, resolved.key.value());
        return resolved.key.value();
    }
    if (resolved.failure == keytree::ResolveFailure::ClimbFailed &&
        resolved.climb == keytree::ClimbFailure::NotAMember) {
        session->dropTreeKeys();
    }
    throw core::EncryptionKeyValidationException(describeResolveFailure(resolved));
}

server::GroupGetKeyArchiveResult GroupKeys::fetchKeyArchive(
    const VerifiedGroup& group,
    int64_t targetEpoch,
    int64_t currentEpoch
) const {
    server::GroupGetKeyArchiveModel params;
    params.id = group->id;
    params.fromKeyVersion = targetEpoch;
    params.toKeyVersion = currentEpoch;
    return fetchKeyArchive(group, params);
}

server::GroupGetKeyArchiveResult GroupKeys::fetchKeyArchive(
    const VerifiedGroup& group,
    const std::vector<keytree::RungSpan>& spans
) const {
    server::GroupGetKeyArchiveModel params;
    params.id = group->id;
    params.spans = std::vector<server::GroupArchiveSpan>{};
    for (const keytree::RungSpan& span : spans) {
        params.spans->push_back(server::GroupArchiveSpan{.at = span.at, .target = span.target});
    }
    return fetchKeyArchive(group, params);
}

keytree::ResolveResult GroupKeys::resolveDescending(
    keytree::GroupKeyResolver& resolver,
    const VerifiedGroup& group,
    int64_t epoch,
    const privmx::crypto::PrivateKey& ownKey
) const {
    // Anything but a broken or missing rung is the answer: the whole window would refuse the same way.
    const auto settled = [](const keytree::ResolveResult& resolved) {
        return resolved.failure != keytree::ResolveFailure::DescentFailed ||
            resolved.descent == keytree::DescentFailure::EraBoundary ||
            resolved.descent == keytree::DescentFailure::Pruned;
    };
    const std::uint32_t current = keytree::GroupKeyResolver::epochOf(group->keyVersion);
    const std::uint32_t floor = deps.sessions.of(group->id)->treeKeys()->raiseFloor(
        ladderFloorOf(group->eraFloor.value_or(1), group->archivePrunedBelow, group->keyVersion)
    );
    // Below the floor the descent ends at the floor whatever was fetched, so the path goes no lower.
    const std::uint32_t goal = std::max(static_cast<std::uint32_t>(epoch), floor);
    const std::vector<keytree::RungSpan> path = keytree::LadderMath::canonicalDescent(current, goal, floor);
    server::GroupGetKeyArchiveResult archive = fetchKeyArchive(group, path);
    keytree::ResolveResult resolved = resolver.resolve(group, epoch, ownKey, archive);
    if (settled(resolved)) {
        return resolved;
    }
    const std::vector<keytree::RungSpan> detour =
        keytree::LadderMath::detourSpans(std::max(resolved.reachedEpoch, goal), goal, floor, path);
    if (!detour.empty() && detour.size() <= MAX_ARCHIVE_SPANS) {
        const server::GroupGetKeyArchiveResult around = fetchKeyArchive(group, detour);
        archive.rungs.insert(archive.rungs.end(), around.rungs.begin(), around.rungs.end());
        archive.eraFloor = std::max(archive.eraFloor, around.eraFloor);
        if (around.archivePrunedBelow.has_value()) {
            archive.archivePrunedBelow = std::max(archive.archivePrunedBelow.value_or(1), around.archivePrunedBelow.value());
        }
        resolved = resolver.resolve(group, epoch, ownKey, archive);
        if (settled(resolved)) {
            return resolved;
        }
    }
    LOG_WARN("[ladder] the descent path to epoch ", std::to_string(epoch), " of ", group->id, " is broken; reading the whole window")
    return resolver.resolve(group, epoch, ownKey, fetchKeyArchive(group, epoch, group->keyVersion));
}

server::GroupGetKeyArchiveResult GroupKeys::fetchKeyArchive(
    const VerifiedGroup& group,
    const server::GroupGetKeyArchiveModel& params
) const {
    server::GroupGetKeyArchiveResult archive = deps.serverApi.groupGetKeyArchive(params);
    // A window comes a page of rungs at a time: read on from the last page's top epoch while pages come full. That
    // epoch's rungs come again whole on the next page, so they are dropped from this one first.
    // Every further page starts higher, at most at the window's top epoch, so a window takes at most one page per
    // epoch: a bridge serving tops past the window, or pages that never end, gets no more requests than that.
    server::GroupGetKeyArchiveModel next = params;
    const std::int64_t to = params.toKeyVersion.value_or(INT64_MAX);
    for (std::size_t served = archive.rungs.size(); !params.spans.has_value() && served >= ARCHIVE_RUNGS_PER_PAGE;) {
        const std::int64_t top = archive.rungs.back().atKeyVersion;
        if (top <= next.fromKeyVersion.value_or(0) || top > to) {
            break; // a page that does not move on, or not within the window: what was served is all there is to try
        }
        next.fromKeyVersion = top;
        archive.rungs.erase(
            std::remove_if(archive.rungs.begin(), archive.rungs.end(), [&](const auto& rung) { return rung.atKeyVersion == top; }),
            archive.rungs.end()
        );
        const server::GroupGetKeyArchiveResult page = deps.serverApi.groupGetKeyArchive(next);
        archive.rungs.insert(archive.rungs.end(), page.rungs.begin(), page.rungs.end());
        served = page.rungs.size();
    }
    // Remembered no higher than the verified epoch: an epoch the archive names past it is only the bridge's word.
    deps.sessions.of(group->id)->treeKeys()->raiseFloor(
        std::min(
            ladderFloorOf(archive.eraFloor, archive.archivePrunedBelow, newestEpoch(group, archive)),
            keytree::GroupKeyResolver::epochOf(group->keyVersion)
        )
    );
    // `keyHistory` and a rung's `author` are the bridge's word; the statements are the members'.
    return keytree::GroupKeyResolver::authenticated(
        std::move(archive),
        deps.treeVerifier.epochOpeners(
            group->id, group->contextId, treeEnvironment(deps.serverApi, deps.connection, group->id)
        )
    );
}

std::string group::describeResolveFailure(const keytree::ResolveResult& resolved) {
    switch (resolved.failure) {
    case keytree::ResolveFailure::NoTree:
        return "Group key unavailable: group has no key tree";
    case keytree::ResolveFailure::UnsupportedTreeVersion:
        return "Group key unavailable: the group's key tree has a version this client does not support";
    case keytree::ResolveFailure::FutureEpoch:
        return "Group key unavailable: the requested epoch has not happened yet";
    case keytree::ResolveFailure::InvalidEpoch:
        return "Group key unavailable: the requested epoch is out of range";
    case keytree::ResolveFailure::ClimbFailed:
        if (resolved.climb == keytree::ClimbFailure::Tampered) {
            return "Group key tree verification failed: a node key does not match the published public key" +
                blameSuffix(resolved.blame);
        }
        if (resolved.climb == keytree::ClimbFailure::NotAMember) {
            return "Group key unavailable: caller holds no leaf in the key tree";
        }
        if (resolved.climb == keytree::ClimbFailure::LeafDidNotOpen) {
            // A changed identity key looks the same as a garbled leaf edge, so the setter is still named.
            return "Group key unavailable: the edge to your own leaf does not open with your current key. If you "
                   "changed your identity key, call renewLeaf with the previous key; without it, ask a manager to "
                   "remove and re-add you" +
                blameSuffix(resolved.blame);
        }
        if (resolved.climb == keytree::ClimbFailure::DecryptFailed) {
            return "Group key unavailable: a key tree edge does not open" + blameSuffix(resolved.blame);
        }
        return "Group key unavailable: the key tree could not be climbed";
    case keytree::ResolveFailure::DescentFailed:
        switch (resolved.descent) {
        case keytree::DescentFailure::EraBoundary:
            return "History before this era is not available to you";
        case keytree::DescentFailure::Pruned:
            return "History this old has been pruned and is no longer recoverable";
        case keytree::DescentFailure::Tampered:
            return "Epoch ladder verification failed" + blameSuffix(resolved.blame, "rung published by");
        default:
            return "Group key unavailable: the epoch ladder could not be descended";
        }
    default:
        return "Group key unavailable";
    }
}

std::vector<core::server::GroupKeysEntry> group::filterToKeyId(
    const std::vector<core::server::GroupKeysEntry>& all,
    const std::string& groupId,
    const std::string& keyId
) {
    std::vector<core::server::GroupKeysEntry> filtered;
    for (const auto& entry : all) {
        if (entry.group != groupId) {
            continue;
        }
        core::server::GroupKeysEntry kept;
        kept.group = entry.group;
        for (const auto& key : entry.keys) {
            if (key.keyId == keyId) {
                kept.keys.push_back(key);
            }
        }
        if (!kept.keys.empty()) {
            filtered.push_back(kept);
        }
    }
    return filtered;
}

bool group::wrappedByEpochOpener(
    const std::vector<core::server::GroupKeysEntry>& routes,
    const std::string& wrappedBy,
    const std::map<std::uint64_t, keytree::CommitStatement>& openers
) {
    for (const auto& route : routes) {
        for (const auto& key : route.keys) {
            const auto opener = openers.find(static_cast<std::uint64_t>(key.groupEpoch.value_or(0)));
            if (opener != openers.end() && opener->second.committer == wrappedBy) {
                return true;
            }
        }
    }
    return false;
}

core::DecryptedEncKeyV2 GroupKeys::encKeyById(
    const std::string& groupId,
    const std::string& keyId,
    const std::function<core::ModuleKeys(bool fresh)>& moduleKeysOf,
    core::KeyProvider& keyProvider,
    const core::KeyProvider::GroupPrivKeyResolver& resolver
) const {
    if (const auto session = deps.sessions.find(groupId)) {
        if (auto cached = session->envelopeKeys.get(keyId); cached.has_value()) {
            return cached.value();
        }
    }

    // Whatever an earlier `getGroup` or `encrypt` on this group already put in the key cache. Reading it
    // costs nothing; only a keyId we have never seen forces a fetch.
    core::ModuleKeys moduleKeys = moduleKeysOf(false);
    auto candidates = filterToKeyId(moduleKeys.groupKeys, groupId, keyId);
    if (candidates.empty()) {
        // `groupGet` serves only the current epochs, so a past epoch's key is looked up by its id. Its entry is the
        // bridge's word like any other: the DIO, the descent to its epoch and the opener check below decide.
        server::GroupGetEpochKeysModel lookup;
        lookup.id = groupId;
        lookup.keyIds = std::vector<std::string>{keyId};
        candidates = filterToKeyId(deps.serverApi.groupGetEpochKeys(lookup).groupKeys, groupId, keyId);
        const bool pastThePin = std::any_of(candidates.begin(), candidates.end(), [&](const auto& entry) {
            return std::any_of(entry.keys.begin(), entry.keys.end(), [&](const auto& key) {
                return key.groupEpoch.value_or(0) >
                    static_cast<std::int64_t>(deps.treeVerifier.pinnedKeyVersion(groupId));
            });
        });
        // An epoch past the verified pin (a rotation this session has not read yet) has no opener to check its
        // wrapper against: the group is read again, which moves the pin. The entry is still the one looked up:
        // `groupGet` serves only the current epochs, and the lookup's epoch may be one already behind them.
        if (candidates.empty() || pastThePin) {
            moduleKeys = moduleKeysOf(true);
            if (auto current = filterToKeyId(moduleKeys.groupKeys, groupId, keyId); !current.empty() || candidates.empty()) {
                candidates = std::move(current);
            }
        }
    }
    if (candidates.empty()) {
        throw core::EncryptionKeyValidationException("Group " + groupId + " publishes no key " + keyId);
    }
    // The key provider opens one route per group, the first; the opener check below must judge that route and no
    // other. With every served route checked, a key a former member sealed to an old epoch's grant key passed as soon
    // as the bridge listed beside it any epoch that member had opened.
    candidates.erase(candidates.begin() + 1, candidates.end());
    candidates.front().keys.erase(candidates.front().keys.begin() + 1, candidates.front().keys.end());

    core::KeyDecryptionAndVerificationRequest request;
    const auto location = core::EncKeyLocation{
        .contextId = moduleKeys.contextId, .resourceId = moduleKeys.moduleResourceId
    };
    request.addGroupKeys(candidates, location);
    const auto byLocation = keyProvider.getKeysAndVerify(request, resolver);

    const auto atLocation = byLocation.find(location);
    if (atLocation == byLocation.end() || atLocation->second.count(keyId) == 0) {
        throw core::EncryptionKeyValidationException("Group key " + keyId + " could not be resolved");
    }
    const core::DecryptedEncKeyV2 found = atLocation->second.at(keyId);
    if (found.statusCode != 0) {
        // `findEncKeyByKeyId` and friends hand back entries whose decryption failed; unchecked, the empty key
        // surfaces as a cipher length complaint instead of the real cause, usually an era boundary.
        throw core::EncryptionKeyValidationException(
            "Group key " + keyId + " could not be decrypted (status " + std::to_string(found.statusCode) + ")"
        );
    }
    // The id sealed inside the entry, not the label the bridge filed it under: another epoch's entry relabelled with
    // this keyId opens fine, and memoized it would stand in for the real key for the rest of the session.
    if (found.id != keyId) {
        throw core::EncryptionKeyValidationException("Group key " + keyId + " is served under another key's id");
    }
    // The head key's wrapper was checked against the roster by the verified read the module keys came from; an
    // earlier epoch's against who opened it, or a member envelope could come from anybody in the context.
    if (keyId != moduleKeys.currentKeyId &&
        !wrappedByEpochOpener(
            candidates, found.dio.creatorUserId,
            deps.treeVerifier.epochOpeners(
                groupId, moduleKeys.contextId, treeEnvironment(deps.serverApi, deps.connection, groupId)
            )
        )) {
        throw core::EncryptionKeyValidationException("Group key " + keyId + " was not wrapped by its epoch's opener");
    }
    deps.sessions.of(groupId)->envelopeKeys.set(keyId, found);
    return found;
}

privmx::crypto::PrivateKey GroupKeys::grantKeyForPubKey(
    const std::string& groupId,
    const std::string& groupPubKeyBase58
) const {
    // A published grant public key's epoch is immutable, so the lookup is memoized like the envelope keys.
    // Without it every anonymous envelope pays a `groupGet` here on top of `resolveGroupPrivKey`'s.
    if (const auto session = deps.sessions.find(groupId)) {
        if (auto cached = session->envelopeGrantEpochs.get(groupPubKeyBase58); cached.has_value()) {
            return resolveGroupPrivKey(groupId, cached.value(), nullptr, nullptr);
        }
    }

    auto target = privmx::crypto::PublicKey::fromBase58DER(groupPubKeyBase58);
    server::GroupGetEpochKeysModel lookup;
    lookup.id = groupId;
    lookup.groupPubKeys = std::vector<std::string>{target.toBase58DER()}; // as stored: compressed
    // `keyHistory` is the bridge's word: only an epoch whose own key turns out to be the target is remembered.
    for (const auto& entry : deps.serverApi.groupGetEpochKeys(lookup).keyHistory) {
        // Epoch 0 is no epoch: `resolveGroupPrivKey` reads it as "the current one", which a later rotation moves.
        if (entry.keyVersion >= 1 && privmx::crypto::PublicKey::fromBase58DER(entry.groupPubKey) == target) {
            const privmx::crypto::PrivateKey key = resolveGroupPrivKey(groupId, entry.keyVersion, nullptr, nullptr);
            if (key.getPublicKey() == target) {
                deps.sessions.of(groupId)->envelopeGrantEpochs.set(groupPubKeyBase58, entry.keyVersion);
                return key;
            }
        }
    }
    throw InvalidEnvelopeFormatException("envelope names a group key that is not in this group's history");
}

core::KeyProvider::GroupPrivKeyResolver GroupKeys::resolverOver(
    const VerifiedGroup* seatedRead,
    const ClimbWith* with
) const {
    return [this, seatedRead,
            with](const std::string& groupId, int64_t epoch) -> std::optional<privmx::crypto::PrivateKey> {
        try {
            return resolveGroupPrivKey(groupId, epoch, seatedRead, with);
        } catch (const GroupHistoryForkException&) {
            throw; // a rollback is not "no key": it must reach the caller as itself
        } catch (...) {
            // caller holds no leaf in this group's tree at this epoch — skip
            return std::nullopt;
        }
    };
}
