/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_ENDPOINT_GROUP_COMMITENGINE_HPP_
#define _PRIVMXLIB_ENDPOINT_GROUP_COMMITENGINE_HPP_

#include <cstdint>
#include <exception>
#include <functional>
#include <optional>
#include <string>

#include <privmx/crypto/ecc/PrivateKey.hpp>
#include <privmx/endpoint/core/Connection.hpp>
#include <privmx/utils/PrivmxException.hpp>

#include "privmx/endpoint/group/GroupApiHooks.hpp"
#include "privmx/endpoint/group/GroupSession.hpp"
#include "privmx/endpoint/group/ServerApi.hpp"
#include "privmx/endpoint/group/VerifiedGroup.hpp"
#include "privmx/endpoint/group/keytree/TreeCommits.hpp"
#include "privmx/endpoint/group/keytree/TreeVerifier.hpp"

namespace privmx {
namespace endpoint {
namespace group {

// A plan whose base is behind the pin (the client's own commit, or a read, moved it meanwhile). Retryable: a fresh
// read plans on the newer head. Not an endpoint exception; `commitWithRetry` and `DeferredWork::run` handle it.
struct StalePlan : std::exception {
    const char* what() const noexcept override { return "group commit planned behind the pinned state"; }
};

// How long a released statement with no known outcome holds back a different one at its prevDigest. An honest
// bridge refuses a statement dated more than DATE_TOLERANCE_MS behind its clock; twice that covers both clocks.
constexpr std::uint64_t RELEASE_WINDOW_MS = 2 * keytree::TreeCommits::DATE_TOLERANCE_MS;

inline const std::string SELF_UPDATE_OP = keytree::TreeCommits::opKey("selfUpdate");

// Client time a commit statement is signed at, in milliseconds.
std::uint64_t commitDate();

// The served group's rules: signed only on a verified read, which bound them to its latest statement
// (`describes`). A plan parses them off the read before it refuses an unseated one, as it always has.
keytree::GroupRules rulesOf(const server::GroupInfo& group);

// Runs one attempt of an app commit, and again from a fresh read when a concurrent commit moved the base
// (StalePlan, `isRetryableCommitRejection`), up to three attempts in all.
void commitWithRetry(const std::function<void()>& attempt);

// A concurrent commit moved the generations or versions the refused one was planned against.
bool isRetryableCommitRejection(const privmx::utils::PrivmxException& e);

// Proceed: plan on the read. Done: the caller's own op landed (now or before). Reread: another op of this
// client, or an earlier call of an event op past its window, was completed first; read again. Deferred: a self-update yields to another op's commit.
enum class Settled {
    Proceed,
    Done,
    Reread,
    Deferred
};

// The commits of one GroupApiImpl, from a verified read to a known outcome; the state is the GroupSessions'.
//
// Locks: GroupSession::commitMutex is held from release to outcome (the send, then `complete` with `landed` and the
// pin save), never across a read or the UserVerifier; GroupSession::mutex, a leaf, only around the unresolved slot.
// Lock order: commitMutex -> (the pin save's and the deferred work's locks) -> GroupSession::mutex.
struct CommitEngine {
    const GroupDeps& deps;

    // Right after a read that verified, before planning on it: completes this client's unresolved commit to the
    // group, if any (resend, or noticing it landed: the pin is exactly it). Past its window, behind the pin, or
    // failing again for another op, it is dropped and the caller plans afresh. `mayCompleteOther`: whether a different
    // op may resend it (every app op; not the deferred self-update).
    Settled settle(const std::string& groupId, const std::string& op, bool mayCompleteOther) const;

    // A read to plan a commit for `op` on: verified, with this client's unresolved commit to the group settled first.
    // nullopt: `op` itself landed (Settled::Done). An unseated read is returned to be refused by the plan, unless
    // `refuseUnverified` (which throws) is given.
    std::optional<GroupRead> readForCommit(
        const server::GroupGetModel& model,
        keytree::TreeVerifier::Scope scope,
        const std::string& op,
        bool mayCompleteOther = true,
        const std::function<void()>& refuseUnverified = {}
    ) const;
    // The read after `settle` completed an earlier commit (Settled::Reread). The read before it verified, so this
    // one must too: a commit is never planned or signed on an answer nobody checked.
    VerifiedGroup rereadVerified(const server::GroupGetModel& model, keytree::TreeVerifier::Scope scope) const;

    // Chains an unsigned statement to `group`'s latest (verified) one: its digest as `prevDigest`, and a date no
    // earlier than its, which readers require of the chain. Refused at a seq a statement of ours was refused at as a
    // lost race: that one may have been applied, and a second one there would be a fork.
    void chainTo(keytree::CommitStatement& statement, const VerifiedGroup& group) const;

    // Sends a signed statement and keeps `commit` until its outcome is known. Throws StalePlan for a plan
    // behind the pin. A refusal as a lost race (`isRetryableCommitRejection`) is remembered for `chainTo`.
    void submit(const std::string& groupId, const keytree::CommitStatement& statement, UnresolvedCommit commit) const;
    // The commit's outcome is known and it landed: forgotten, `landed`, and the pins saved (but a self-update's).
    void complete(const std::string& groupId, const UnresolvedCommit& commit) const;
    void forgetUnresolved(const std::string& groupId, const std::string& digest) const;
};

} // namespace group
} // namespace endpoint
} // namespace privmx

#endif // _PRIVMXLIB_ENDPOINT_GROUP_COMMITENGINE_HPP_
