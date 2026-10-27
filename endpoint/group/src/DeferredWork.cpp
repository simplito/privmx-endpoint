/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include "privmx/endpoint/group/DeferredWork.hpp"

#include <algorithm>
#include <random>
#include <vector>

#include <privmx/utils/PrivmxException.hpp>

#include "privmx/endpoint/group/CommitEngine.hpp"
#include "privmx/endpoint/group/GroupKeys.hpp"
#include "privmx/endpoint/group/keytree/GroupKeyResolver.hpp"
#include "privmx/endpoint/group/keytree/LadderKeys.hpp"
#include "privmx/endpoint/group/keytree/TreeWire.hpp"
#include "privmx/utils/Logger.hpp"

using namespace privmx::endpoint;
using namespace group;

namespace {

// How far a group's members spread their deferred work: this much per seat, within the bounds.
constexpr std::int64_t BACKGROUND_MS_PER_SEAT = 8;
constexpr std::int64_t BACKGROUND_WINDOW_MIN_MS = 1000;
constexpr std::int64_t BACKGROUND_WINDOW_MAX_MS = 120000;

// A uniform delay in `[0, windowMs]`, so a group's members do not all hit the bridge at once.
std::chrono::milliseconds jitter(std::int64_t windowMs) {
    static thread_local std::mt19937_64 random{std::random_device{}()};
    return std::chrono::milliseconds(std::uniform_int_distribution<std::int64_t>(0, windowMs)(random));
}

} // namespace

void DeferredWork::scheduleSelfUpdateIfNeeded(const std::string& groupId, const VerifiedGroup& group) {
    const auto node = keytree::GroupKeyResolver::nodeNeedingSelfUpdate(group);
    if (!node.has_value()) {
        return;
    }
    scheduleSelfUpdate(groupId, backgroundWindowMs(group), keytree::GroupKeyResolver::healsFirst(group, node.value()));
}

std::int64_t DeferredWork::backgroundWindowMs(const server::GroupInfo& group) {
    // Limit: 8 ms per seat, 1-120 s. One window holds the first healers of a fresh 16k group (~n/32 commits) at
    // the bridge's ~5-10 commits/s only with retries; a per-group rate limit on the bridge is the upgrade path.
    return std::clamp<std::int64_t>(
        group.numLeaves.value_or(1) * BACKGROUND_MS_PER_SEAT, BACKGROUND_WINDOW_MIN_MS, BACKGROUND_WINDOW_MAX_MS
    );
}

void DeferredWork::scheduleSelfUpdate(
    const std::string& groupId,
    std::int64_t windowMs,
    bool healsFirst,
    int attempts
) {
    const auto session = _deps.sessions.of(groupId);
    std::lock_guard<std::mutex> lock(session->mutex);
    if (session->selfUpdate.has_value()) {
        return;
    }
    // The healer of a node commits within the window; everybody else under it waits the window out first and then
    // finds (on a path read) the node already refilled, unless that healer is gone. Jitter keeps the healers of
    // different nodes, and the stand-ins, from colliding on the generations they all refresh.
    const auto delay = std::chrono::milliseconds(healsFirst ? 0 : windowMs) + jitter(windowMs);
    session->selfUpdate = PendingSelfUpdate{std::chrono::steady_clock::now() + delay, windowMs, attempts};
}

void DeferredWork::scheduleLadderCheck(
    const std::string& groupId,
    const std::string& contextId,
    std::uint32_t at,
    std::int64_t windowMs
) {
    std::unique_lock<std::mutex> lock(_mutex);
    const auto key = std::make_pair(groupId, at);
    if (_ladderChecks.count(key) > 0) {
        return;
    }
    // Jittered so a group's online members do not all check at once; the bridge's serialisation of repairs, and the
    // re-check right before each one, are what keep concurrent repairs within the per-span cap.
    _ladderChecks[key] = {groupId, contextId, at, std::chrono::steady_clock::now() + jitter(windowMs)};
}

void DeferredWork::scheduleObservedRotation(
    const std::string& groupId,
    const std::string& contextId,
    std::uint32_t cur,
    std::int64_t windowMs
) {
    {
        // Several threads resolve keys at once: only the one that moves the mark queues the check.
        std::unique_lock<std::mutex> lock(_mutex);
        std::uint32_t& checked = _ladderCheckedAt[groupId];
        if (checked >= cur) {
            return;
        }
        checked = cur;
    }
    scheduleLadderCheck(groupId, contextId, cur, windowMs);
}

void DeferredWork::markLadderChecked(const std::string& groupId, std::uint32_t epoch) {
    std::unique_lock<std::mutex> lock(_mutex);
    std::uint32_t& checked = _ladderCheckedAt[groupId];
    checked = std::max(checked, epoch);
}

void DeferredWork::forgetChecked() {
    std::unique_lock<std::mutex> lock(_mutex);
    _ladderCheckedAt.clear();
}

void DeferredWork::dropAll() {
    {
        std::unique_lock<std::mutex> lock(_mutex);
        _ladderChecks.clear();
        _ladderCheckedAt.clear();
    }
    _deps.sessions.forEach([](GroupSession& session) {
        std::lock_guard<std::mutex> lock(session.mutex);
        session.selfUpdate.reset();
    });
}

void DeferredWork::checkLadderAt(const std::string& groupId, const std::string& contextId, std::uint32_t at) {
    const auto cache = _deps.sessions.of(groupId)->treeKeys();
    server::GroupGetKeyArchiveResult raw;
    // The rungs at `at` as served, and the floor (never lower than one seen before) nothing is repaired below.
    const auto unopened = [&]() {
        server::GroupGetKeyArchiveModel params;
        params.id = groupId;
        params.fromKeyVersion = at;
        params.toKeyVersion = at;
        raw = _deps.serverApi.groupGetKeyArchive(params);
        // A later epoch the archive names (a rotation since the pin) excuses a higher floor here, but only the
        // verified epoch bounds what the session remembers: the archive's epoch is the bridge's word.
        const auto verified = static_cast<std::uint32_t>(_deps.treeVerifier.pinnedKeyVersion(groupId));
        const std::uint32_t served = ladderFloorOf(
            raw.eraFloor, raw.archivePrunedBelow, std::max(static_cast<std::int64_t>(verified), raw.keyVersion)
        );
        const std::uint32_t floor = std::max(cache->raiseFloor(std::min(served, verified)), served);
        return keytree::LadderKeys::unopenedSpans(at, keytree::GroupKeyResolver::toDownwardRungs(raw), *cache, floor);
    };
    // Cheap stage, the honest path: one fetch, one open per span, no statements read and no UserVerifier call.
    std::vector<keytree::RungSpan> spans = unopened();
    if (spans.empty()) {
        return;
    }
    // Something looks broken. The cache decided that, and the cache is not the chain: every key about to be sealed,
    // and the key it is sealed to, is checked against the epoch's opener first. A mismatch is forgotten, never sealed.
    const auto openers = _deps.treeVerifier.epochOpeners(
        groupId, contextId, treeEnvironment(_deps.serverApi, _deps.connection, groupId)
    );
    const auto matchesChain = [&](std::uint32_t epoch) {
        const auto key = cache->getGrantKey(epoch);
        const auto opener = openers.find(epoch);
        if (!key.has_value() || opener == openers.end()) {
            return false;
        }
        if (key->getPublicKey().toBase58DER() != keytree::TreeVerifier::canonicalKey(opener->second.groupPubKey)) {
            LOG_WARN("[ladder] a cached grant key is not its epoch's; forgotten: ", std::to_string(epoch))
            cache->forgetGrantKey(epoch);
            return false;
        }
        return true;
    };
    if (!matchesChain(at)) {
        return;
    }
    spans.erase(
        std::remove_if(spans.begin(), spans.end(), [&](const keytree::RungSpan& span) { return !matchesChain(span.target); }),
        spans.end()
    );
    for (const keytree::RungSpan& span : spans) {
        // Somebody may have repaired it meanwhile: re-checked right before, so the members who lost the race stop.
        const std::vector<keytree::RungSpan> still = unopened();
        if (std::none_of(still.begin(), still.end(), [&](const keytree::RungSpan& s) { return s.target == span.target; })) {
            continue;
        }
        const auto atKey = cache->getGrantKey(at);
        const auto targetKey = cache->getGrantKey(span.target);
        if (!atKey.has_value() || !targetKey.has_value()) {
            continue;
        }
        keytree::ArchiveRung rung;
        rung.span = span;
        rung.blob = keytree::LadderKeys::sealRung(targetKey.value(), span, atKey->getPublicKey(), _deps.userPrivKey);
        try {
            _deps.serverApi.groupRepairRung(
                server::GroupRepairRungModel{.id = groupId, .rung = keytree::TreeWire::toWire(rung)}
            );
            LOG_INFO("[ladder] repaired rung ", std::to_string(span.at) + "->" + std::to_string(span.target))
        } catch (const privmx::utils::PrivmxException& e) {
            // SPAN_FULL, AUTHOR_HAS_RUNG, ROTATED_ALREADY, the budget: not retried; the next trigger re-checks.
            LOG_WARN("[ladder] repair refused: ", e.what())
        }
    }
}

void DeferredWork::run(const std::string& groupId, const std::function<void()>& selfUpdate) {
    const auto now = std::chrono::steady_clock::now();
    std::vector<PendingLadderCheck> checks;
    std::optional<PendingSelfUpdate> update;
    {
        std::unique_lock<std::mutex> lock(_mutex);
        for (auto it = _ladderChecks.begin(); it != _ladderChecks.end();) {
            if (it->second.groupId == groupId && it->second.due <= now) {
                checks.push_back(it->second);
                it = _ladderChecks.erase(it);
            } else {
                ++it;
            }
        }
    }
    const auto session = _deps.sessions.find(groupId);
    if (session) {
        std::lock_guard<std::mutex> lock(session->mutex);
        if (session->selfUpdate.has_value() && session->selfUpdate->due <= now) {
            update = session->selfUpdate;
            session->selfUpdate.reset();
        }
    }
    for (const PendingLadderCheck& check : checks) {
        try {
            checkLadderAt(check.groupId, check.contextId, check.at);
        } catch (const std::exception& e) {
            LOG_WARN("[ladder] check dropped: ", e.what())
        } catch (...) { LOG_WARN("[ladder] check dropped") }
    }
    if (update.has_value()) {
        bool lostRace = false;
        try {
            selfUpdate();
        } catch (const StalePlan&) {
            lostRace = true; // planned behind a commit of this client's own; re-plan like a lost race
        } catch (const privmx::utils::PrivmxException& e) {
            lostRace = isRetryableCommitRejection(e);
            if (!lostRace) {
                LOG_WARN("[selfUpdate] group key tree self-update dropped: ", e.what())
            }
        } catch (const std::exception& e) {
            LOG_WARN("[selfUpdate] group key tree self-update dropped: ", e.what())
        } catch (...) { LOG_WARN("[selfUpdate] group key tree self-update dropped") }
        {
            // What its own reads recorded meanwhile describes the state before its commit.
            std::lock_guard<std::mutex> lock(session->mutex);
            session->selfUpdate.reset();
        }
        // A lost race is recorded again with a fresh random delay, so the members that collided spread out.
        if (lostRace && update->attempts + 1 < MAX_SELF_UPDATE_ATTEMPTS) {
            scheduleSelfUpdate(groupId, update->windowMs, true, update->attempts + 1);
        } else if (lostRace) {
            LOG_WARN("[selfUpdate] group key tree self-update dropped after repeated concurrent commits")
        }
    }
}
