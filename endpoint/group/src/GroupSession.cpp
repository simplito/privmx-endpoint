/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include "privmx/endpoint/group/GroupSession.hpp"

using namespace privmx::endpoint::group;

std::shared_ptr<keytree::TreeKeyCache> GroupSession::treeKeys() {
    // Under the lock throughout, so get-or-create is atomic: two caches for one group would leave one of them
    // filling up with climbs nobody reads back.
    std::lock_guard<std::mutex> lock(mutex);
    if (!_treeKeys) {
        _treeKeys = std::make_shared<keytree::TreeKeyCache>();
    }
    return _treeKeys;
}

void GroupSession::dropTreeKeys() {
    std::lock_guard<std::mutex> lock(mutex);
    _treeKeys.reset();
}

void GroupSession::dropKeys(bool keepEpochKeys) {
    dropTreeKeys();
    envelopeKeys.clear();
    envelopeGrantEpochs.clear();
    if (!keepEpochKeys) {
        epochKeys.clear();
    }
}

std::shared_ptr<GroupSession> GroupSessions::of(const std::string& groupId) {
    std::lock_guard<std::mutex> lock(_mutex);
    auto& session = _sessions[groupId];
    if (!session) {
        session = std::make_shared<GroupSession>();
    }
    return session;
}

std::shared_ptr<GroupSession> GroupSessions::find(const std::string& groupId) {
    std::lock_guard<std::mutex> lock(_mutex);
    const auto it = _sessions.find(groupId);
    return it == _sessions.end() ? nullptr : it->second;
}

namespace {
// Under the map's lock. Held by the map alone, no call is reading or committing through the session, and none can
// reach it again without that lock; its own lock makes what the last holder wrote visible.
bool idle(const std::shared_ptr<GroupSession>& session) {
    if (session.use_count() != 1) {
        return false;
    }
    std::lock_guard<std::mutex> lock(session->mutex);
    return !session->unresolved.has_value() &&
        !session->pendingCarry.has_value() &&
        !session->selfUpdate.has_value() &&
        session->epochKeys.size() == 0;
}
} // namespace

void GroupSessions::forget(const std::string& groupId) {
    if (const auto session = find(groupId)) {
        session->dropKeys();
    }
    std::lock_guard<std::mutex> lock(_mutex);
    if (const auto it = _sessions.find(groupId); it != _sessions.end() && idle(it->second)) {
        _sessions.erase(it);
    }
}

void GroupSessions::dropKeys(bool keepEpochKeys) {
    forEach([keepEpochKeys](GroupSession& session) { session.dropKeys(keepEpochKeys); });
    std::lock_guard<std::mutex> lock(_mutex);
    for (auto it = _sessions.begin(); it != _sessions.end();) {
        it = idle(it->second) ? _sessions.erase(it) : std::next(it);
    }
}

void GroupSessions::forEach(const std::function<void(GroupSession&)>& visit) {
    std::vector<std::shared_ptr<GroupSession>> all;
    {
        std::lock_guard<std::mutex> lock(_mutex);
        for (const auto& [groupId, session] : _sessions) {
            all.push_back(session);
        }
    }
    for (const auto& session : all) {
        visit(*session);
    }
}
