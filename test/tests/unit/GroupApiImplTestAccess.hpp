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
    // The flush point does nothing from here on, so what a test counts never depends on the random due times.
    // Self-updates are then only the explicit `selfUpdate` above, pin saves only the synchronous ones.
    static void stopDueWork(GroupApiImpl& api) { api._dueWorkOff = true; }
    static std::size_t maxArchiveSpans() { return GroupApiImpl::MAX_ARCHIVE_SPANS; }
    // Whatever is recorded for the group made due now, then the flush point run (as at the end of a public call).
    static void runDueWorkNow(GroupApiImpl& api, const std::string& groupId) {
        {
            std::lock_guard<std::mutex> lock(api._dueMutex);
            for (auto& [key, check] : api._ladderChecks) {
                check.due = {};
            }
            for (auto& [id, pending] : api._selfUpdatePending) {
                pending.due = {};
            }
        }
        api.runDueWork(groupId);
    }
    static bool savePins(GroupApiImpl& api) { return api.savePins(); }
    static std::array<std::int64_t, 3> versionPins(GroupApiImpl& api, const std::string& groupId) {
        const auto all = api._groupDataSchemaMapper->exportVersionPins();
        const auto it = all.find(groupId);
        return it == all.end() ? std::array<std::int64_t, 3>{0, 0, 0} : it->second;
    }
    static std::uint64_t pinnedSeq(GroupApiImpl& api, const std::string& groupId) {
        return api._treeVerifier.pinnedSeq(groupId);
    }
    static std::size_t queuedLadderChecks(GroupApiImpl& api) {
        std::lock_guard<std::mutex> lock(api._dueMutex);
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
    // The group key resolver the key provider is handed (containers, envelopes, the group's own metadata).
    static core::KeyProvider::GroupPrivKeyResolver groupKeyResolver(GroupApiImpl& api) { return api._groupPrivKeyResolver; }
    static std::string describeResolveFailure(const keytree::ResolveResult& resolved) {
        return GroupApiImpl::describeResolveFailure(resolved);
    }
};
} // namespace privmx::endpoint::group
