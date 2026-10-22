/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#pragma once

#include <array>
#include <chrono>
#include <cstdint>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

#include <privmx/endpoint/group/GroupApiImpl.hpp>

namespace privmx::endpoint::group {
// What the unit tests reach inside GroupApiImpl (a friend of it).
struct GroupApiImplTestAccess {
    static constexpr std::uint64_t RELEASE_WINDOW_MS = GroupApiImpl::RELEASE_WINDOW_MS;

    static void selfUpdate(GroupApiImpl& api, const std::string& groupId) { api.selfUpdate(groupId); }
    // No background work is scheduled or run from here on, so what a test counts never depends on the worker's random
    // delay. Self-updates are then only the explicit `selfUpdate` above.
    static void stopBackgroundSelfUpdates(GroupApiImpl& api) { api.stopBackgroundWorker(); }
    static bool savePins(GroupApiImpl& api) { return api.savePins(); }
    static std::array<std::int64_t, 3> versionPins(GroupApiImpl& api, const std::string& groupId) {
        const auto all = api._groupDataSchemaMapper->exportVersionPins();
        const auto it = all.find(groupId);
        return it == all.end() ? std::array<std::int64_t, 3>{0, 0, 0} : it->second;
    }
    static std::uint64_t pinnedSeq(GroupApiImpl& api, const std::string& groupId) {
        return api._treeVerifier.pinnedSeq(groupId);
    }
    static bool pinSaveDue(GroupApiImpl& api) {
        std::lock_guard<std::mutex> lock(api._selfUpdateMutex);
        return api._pinSaveDue.has_value() && api._pinSaveDue.value() <= std::chrono::steady_clock::now();
    }
    // A save is queued, and not yet due.
    static bool pinSaveScheduled(GroupApiImpl& api) {
        std::lock_guard<std::mutex> lock(api._selfUpdateMutex);
        return api._pinSaveDue.has_value() && api._pinSaveDue.value() > std::chrono::steady_clock::now();
    }
    // The spacing between saves of major moves (PIN_SAVE_INTERVAL); a queued save is re-planned under the new one.
    static void setPinSaveInterval(GroupApiImpl& api, std::chrono::milliseconds interval) {
        {
            std::lock_guard<std::mutex> lock(api._selfUpdateMutex);
            api._pinSaveInterval = interval;
        }
        api.pinsMoved(true);
    }
    static std::size_t queuedLadderChecks(GroupApiImpl& api) {
        std::lock_guard<std::mutex> lock(api._selfUpdateMutex);
        return api._ladderChecks.size();
    }
    // As if the call that released the group's unresolved commit ran `ms` earlier: no clock to move in a unit test.
    static void ageUnresolved(GroupApiImpl& api, const std::string& groupId, std::uint64_t ms) {
        std::lock_guard<std::mutex> lock(api._unresolvedMutex);
        api._unresolved.at(groupId).date -= ms;
    }
    // The group's session key cache, to plant a wrong key (a client bug) in it.
    static std::shared_ptr<keytree::TreeKeyCache> keyCacheOf(GroupApiImpl& api, const std::string& groupId) {
        return api.keyCacheOf(groupId);
    }
    static std::vector<core::server::GroupKeysEntry> filterToKeyId(
        const std::vector<core::server::GroupKeysEntry>& all,
        const std::string& groupId,
        const std::string& keyId
    ) {
        return GroupApiImpl::filterToKeyId(all, groupId, keyId);
    }
    static bool wrappedByEpochOpener(
        const std::vector<core::server::GroupKeysEntry>& routes,
        const std::string& wrappedBy,
        const std::map<std::uint64_t, keytree::CommitStatement>& openers
    ) {
        return GroupApiImpl::wrappedByEpochOpener(routes, wrappedBy, openers);
    }
    static std::string describeResolveFailure(const keytree::ResolveResult& resolved) {
        return GroupApiImpl::describeResolveFailure(resolved);
    }
};
} // namespace privmx::endpoint::group
