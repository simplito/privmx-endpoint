/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_ENDPOINT_GROUP_DEFERREDWORK_HPP_
#define _PRIVMXLIB_ENDPOINT_GROUP_DEFERREDWORK_HPP_

#include <chrono>
#include <cstdint>
#include <functional>
#include <map>
#include <mutex>
#include <string>
#include <utility>

#include <privmx/crypto/ecc/PrivateKey.hpp>
#include <privmx/endpoint/core/Connection.hpp>

#include "privmx/endpoint/group/GroupApiHooks.hpp"
#include "privmx/endpoint/group/GroupSession.hpp"
#include "privmx/endpoint/group/ServerApi.hpp"
#include "privmx/endpoint/group/ServerTypes.hpp"
#include "privmx/endpoint/group/VerifiedGroup.hpp"
#include "privmx/endpoint/group/keytree/TreeVerifier.hpp"

namespace privmx {
namespace endpoint {
namespace group {

// The work one GroupApiImpl records on a group for later: the deferred self-update (kept in the GroupSession) and the
// ladder checks (kept here). No thread of its own: it runs at the end of the next public call on the group (`run`),
// after its `due` (a "not before"). Records are dropped on disconnect.
//
// Lock order: GroupSession::commitMutex -> `_mutex`. `_mutex` and GroupSession::mutex are leaves, and `run` holds
// neither while running a task: a ladder check reads the bridge and the UserVerifier.
class DeferredWork {
public:
    explicit DeferredWork(const GroupDeps& deps) : _deps(deps) {}

    static constexpr int MAX_SELF_UPDATE_ATTEMPTS = 3;

    // `clamp(numLeaves·8 ms, 1 s, 120 s)`: how far a group's members spread their deferred work.
    static std::int64_t backgroundWindowMs(const server::GroupInfo& group);

    // Records one when `group` (a seated, verified read) shows the caller's path needs it, due not before a random
    // point within a window that grows with the group for the seat that heals first, one window later for any other
    // (`healsFirst`), so a group's members do not all commit at once. At most one recorded per group.
    void scheduleSelfUpdateIfNeeded(const std::string& groupId, const VerifiedGroup& group);
    void scheduleSelfUpdate(const std::string& groupId, std::int64_t windowMs, bool healsFirst, int attempts = 0);

    // Records one check of the rungs at `at`, once per (group, epoch), due not before a random delay within `windowMs`.
    void scheduleLadderCheck(
        const std::string& groupId,
        const std::string& contextId,
        std::uint32_t at,
        std::int64_t windowMs
    );
    // A rotation to `cur` this session observed while holding `cur - 1`: check `cur`'s rungs, once.
    void scheduleObservedRotation(
        const std::string& groupId,
        const std::string& contextId,
        std::uint32_t cur,
        std::int64_t windowMs
    );
    // The epoch's rungs are known good (this client just checked and committed them).
    void markLadderChecked(const std::string& groupId, std::uint32_t epoch);

    // Runs the group's due ladder checks, then its due self-update (`selfUpdate`); one lost to a concurrent commit
    // (`isRetryableCommitRejection`) is recorded again, up to MAX_SELF_UPDATE_ATTEMPTS in all. Best-effort: failures
    // are logged, never thrown.
    void run(const std::string& groupId, const std::function<void()>& selfUpdate);

    // On connect: which epochs were checked follows the key cache, which is session state.
    void forgetChecked();
    // On disconnect: every record, the self-updates included, and the marks.
    void dropAll();

private:
    struct PendingLadderCheck {
        std::string groupId;
        std::string contextId;
        std::uint32_t at;
        std::chrono::steady_clock::time_point due;
    };

    // No lock held: finds spans at `at` no rung opens and repairs those it holds both keys of, after checking those
    // keys against the chain.
    void checkLadderAt(const std::string& groupId, const std::string& contextId, std::uint32_t at);

    const GroupDeps& _deps;
    std::mutex _mutex; // a leaf; guards the two below
    std::map<std::pair<std::string /* groupId */, std::uint32_t /* at */>, PendingLadderCheck> _ladderChecks;
    std::map<std::string /* groupId */, std::uint32_t> _ladderCheckedAt; // highest `at` already queued or checked
    friend struct GroupApiImplTestAccess; // tests make every check due now and count them
};

} // namespace group
} // namespace endpoint
} // namespace privmx

#endif // _PRIVMXLIB_ENDPOINT_GROUP_DEFERREDWORK_HPP_
