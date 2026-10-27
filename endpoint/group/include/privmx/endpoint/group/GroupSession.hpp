/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_ENDPOINT_GROUP_GROUPSESSION_HPP_
#define _PRIVMXLIB_ENDPOINT_GROUP_GROUPSESSION_HPP_

#include <chrono>
#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <vector>

#include <privmx/crypto/ecc/PrivateKey.hpp>
#include <privmx/utils/ThreadSaveMap.hpp>

#include "privmx/endpoint/core/CoreTypes.hpp"
#include "privmx/endpoint/core/Types.hpp"
#include "privmx/endpoint/group/encryptors/group/GroupDataSchemaMapper.hpp"
#include "privmx/endpoint/group/keytree/TreeKeyCache.hpp"

namespace privmx {
namespace endpoint {
namespace group {

// A commit released to the bridge with no known outcome. A retry of the same operation resends exactly this
// (no second statement, no wasted epoch); any other operation drops it after one resend and plans afresh (a fork
// that leaves open is one a bridge can reach by withholding anyway).
struct UnresolvedCommit {
    std::string digest;     // of the released statement (set by `submit`)
    std::uint64_t seq = 0;  // its seq (set by `submit`)
    std::uint64_t date = 0; // its signed date (set by `submit`)
    std::string op;         // keytree::TreeCommits::opKey of what the caller asked for
    // The op key names the state the call asks for (these members added, those removed): found landed, it is
    // Done whenever. Otherwise it names an event (a rotation), and a later call with the same key is its retry
    // only inside RELEASE_WINDOW_MS from `date`; past it, a new request.
    bool namesEndState = false;
    std::string kind; // "add", "remove", ... for messages
    std::string contextId;
    std::vector<core::UserWithPubKey> newcomers; // add only: re-checked before every resend
    std::function<void()> send;                  // the request as first sent; never re-planned
    std::function<void()> landed;                // pin + caches once accepted; looks the TreeKeyCache up itself
    std::function<void()> after;                 // best-effort follow-up (a removal's metadata refresh) or empty
};

// A narrowing's carry-forward still to do: the planes' authors who lost `update`, and the read before it.
struct PendingCarry {
    std::vector<std::string> losers;
    PriorRole prior;
};

struct PendingSelfUpdate {
    std::chrono::steady_clock::time_point due;
    std::int64_t windowMs; // the delay window it was scheduled with, reused by a retry
    int attempts;          // lost races so far, counted toward MAX_SELF_UPDATE_ATTEMPTS
};

// Everything one GroupApiImpl keeps about one group. Keys are dropped on connect and disconnect, and forgotten
// with the group (`GroupSessions`); the commit state and the pending work are not.
struct GroupSession {
    // Keys already unwrapped for envelopes, by keyId; a keyId names one immutable piece of key material. Dropped on
    // connect and disconnect, so an era cut takes effect at reconnect.
    privmx::utils::ThreadSaveMap<std::string, core::DecryptedEncKeyV2> envelopeKeys;
    // Which epoch a published grant public key (Base58) belongs to.
    privmx::utils::ThreadSaveMap<std::string, int64_t> envelopeGrantEpochs;
    // Grant private keys by epoch, each checked against the epoch's published public key. Kept for the whole
    // connection (dropped on disconnect, not on connect): a removal ends a member's access to later epochs, and a hot
    // session keeps the ones it already held — as it would by keeping the keys themselves.
    privmx::utils::ThreadSaveMap<int64_t, privmx::crypto::PrivateKey> epochKeys;

    // The group's tree key cache: created on first use, never null. Bind the result to a named local before taking
    // a reference into it — `TreeKeys tree(*session->treeKeys())` references a cache whose last owner may die at the
    // end of the expression.
    std::shared_ptr<keytree::TreeKeyCache> treeKeys();

    // The tree cache is detached, not emptied, so a climb already in flight keeps writing into a private orphan
    // rather than putting stale keys back into a live cache.
    void dropTreeKeys();
    // Every key above. `epochKeys` too unless `keepEpochKeys`.
    void dropKeys(bool keepEpochKeys = false);

    // Held only from release to outcome (CommitEngine), never across reads or the UserVerifier. Lock order:
    // commitMutex -> (the facade's pin save locks, DeferredWork's lock) -> `mutex`.
    std::mutex commitMutex;

    // A leaf: nothing else is taken under it. Guards the three below and the tree cache handle.
    std::mutex mutex;
    // One released statement per prevDigest. Survives reconnects on purpose: a dropped connection is the
    // commonest unknown outcome, and the same call retried after it must resend, not be held back.
    std::optional<UnresolvedCommit> unresolved;
    // Limit: in memory only. A crash before the retry leaves the planes refused until a member holding `update`
    // writes metadata (documented on updateGroupPolicy); persist it next to the pins if that ever matters.
    std::optional<PendingCarry> pendingCarry;
    // The deferred self-update, at most one. Dropped on disconnect.
    std::optional<PendingSelfUpdate> selfUpdate;

private:
    std::shared_ptr<keytree::TreeKeyCache> _treeKeys;
};

// One GroupSession per group id, for one GroupApiImpl. A session goes only with its keys (`forget`, `dropKeys`), and
// only once nothing is left in it and no call holds it: commit state and pending work outlive the keys and the group.
class GroupSessions {
public:
    // Created on first use, never null. Only where something is stored: a lookup on an id off the wire uses `find`.
    std::shared_ptr<GroupSession> of(const std::string& groupId);
    // The group's session, or null; never creates one.
    std::shared_ptr<GroupSession> find(const std::string& groupId);

    // A deleted id may come back as another group, whose epochs share the numbers but not the keys: every key of
    // the group goes. Its unresolved commit stays: a deletion seen in an event is the bridge's word alone.
    void forget(const std::string& groupId);

    // `GroupSession::dropKeys` for every group.
    void dropKeys(bool keepEpochKeys = false);

    void forEach(const std::function<void(GroupSession&)>& visit);

private:
    // Taken before a GroupSession's `mutex` only by the erase, for a session nobody else holds; otherwise a leaf.
    std::mutex _mutex;
    std::map<std::string, std::shared_ptr<GroupSession>> _sessions;
};

} // namespace group
} // namespace endpoint
} // namespace privmx

#endif // _PRIVMXLIB_ENDPOINT_GROUP_GROUPSESSION_HPP_
