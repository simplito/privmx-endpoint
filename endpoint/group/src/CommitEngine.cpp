/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include "privmx/endpoint/group/CommitEngine.hpp"

#include <algorithm>
#include <mutex>
#include <set>
#include <stdexcept>

#include <privmx/endpoint/core/CoreException.hpp>
#include <privmx/endpoint/core/ExceptionConverter.hpp>
#include <privmx/utils/Utils.hpp>

#include "privmx/endpoint/group/GroupException.hpp"
#include "privmx/utils/Logger.hpp"

using namespace privmx::endpoint;
using namespace group;

namespace {

// Bridge application error codes a commit can be refused with as a lost race.
enum BridgeError : unsigned int {
    ROTATED_ALREADY = 0x621C,
    GROUP_TREE_INVALID = 0x621E, // its data lists the problems found
    GROUP_ROSTER_VERSION_MISMATCH = 0x6224,
};

// Attempts of one app commit against a base that moved (`commitWithRetry`).
constexpr int MAX_COMMIT_ATTEMPTS = 3;

} // namespace

std::uint64_t group::commitDate() {
    return static_cast<std::uint64_t>(privmx::utils::Utils::getNowTimestamp());
}

keytree::GroupRules group::rulesOf(const server::GroupInfo& group) {
    try {
        return keytree::TreeCommits::rules(group.policy, group.creator);
    } catch (const std::invalid_argument&) {
        throw GroupDataIntegrityException("the group's policy does not parse");
    }
}

void group::commitWithRetry(const std::function<void()>& attempt) {
    for (int attemptNo = 1;; ++attemptNo) {
        try {
            attempt();
            return;
        } catch (const StalePlan&) {
            // Another commit of this client to the group landed while this one was planned on the head before it.
            if (attemptNo < MAX_COMMIT_ATTEMPTS) {
                LOG_DEBUG("group commit planned behind this client's own commit, re-planning")
                continue;
            }
            throw RotatedAlreadyException();
        } catch (const privmx::utils::PrivmxException& e) {
            if (attemptNo < MAX_COMMIT_ATTEMPTS && isRetryableCommitRejection(e)) {
                LOG_DEBUG("group commit planned against a moved base, re-planning: ", e.what())
                continue;
            }
            core::ExceptionConverter::rethrowAsCoreException(e);
            throw core::Exception("ExceptionConverter rethrow error");
        }
    }
}

// A concurrent commit — most often a self-update, which every member under a blanked node runs on its own — moved
// the generations or versions this one was planned against. Nothing about the request was wrong, so a fresh read
// and a fresh plan are all it takes; anything else the bridge refuses is reported as it is.
bool group::isRetryableCommitRejection(const privmx::utils::PrivmxException& e) {
    const unsigned int code = e.getCode();
    if ((code & 0xFFFF0000) != 0) {
        return false; // not a bridge application error
    }
    switch (code & 0x0000FFFF) {
    case ROTATED_ALREADY:
    case GROUP_ROSTER_VERSION_MISMATCH:
        return true;
    case GROUP_TREE_INVALID:
        // A rotation moves no node, so a self-update under it shows as its grant edge's stale child generation
        // (the root's); every other commit sees it as a stale base generation.
        return e.getData().find("\"STALE_BASE_GENERATION\"") != std::string::npos ||
               e.getData().find("\"STALE_CHILD_GENERATION\"") != std::string::npos;
    default:
        return false;
    }
}

VerifiedGroup CommitEngine::rereadVerified(const server::GroupGetModel& model, keytree::TreeVerifier::Scope scope) const {
    GroupRead read = deps.facade.read(model, scope);
    if (!read.verified.has_value()) {
        throw GroupDataIntegrityException("the read after an earlier commit landed carries no tree this client checks");
    }
    return std::move(read.verified.value());
}

std::optional<GroupRead> CommitEngine::readForCommit(
    const server::GroupGetModel& model,
    keytree::TreeVerifier::Scope scope,
    const std::string& op,
    bool mayCompleteOther,
    const std::function<void()>& refuseUnverified
) const {
    // Every record a plan reads and every node it wraps to, checked against the statements members signed. `settle`
    // only after a read that verified: it goes by the pin, and the bridge's unverified word moves nothing.
    GroupRead read = deps.facade.read(model, scope);
    if (!read.verified.has_value()) {
        if (refuseUnverified) {
            refuseUnverified();
        }
        return read; // planning on it refuses it (`planOn`)
    }
    switch (settle(model.groupId, op, mayCompleteOther)) {
    case Settled::Done:
        return std::nullopt;
    case Settled::Reread:
        return GroupRead{.verified = rereadVerified(model, scope), .unseated = {}};
    default:
        return read;
    }
}

void CommitEngine::chainTo(keytree::CommitStatement& statement, const VerifiedGroup& group) const {
    // Nothing is signed on pins this device cannot keep, or behind what a sibling instance saved meanwhile.
    deps.treeVerifier.assertMaySignAt(group->id, statement.seq);
    const keytree::CommitStatement previous = keytree::TreeCommits::fromWire(group->treeCommit.value());
    statement.prevDigest = keytree::TreeCommits::digest(previous);
    // A clock behind the last committer's signs its date. The bridge takes a date equal to the previous one even
    // past its tolerance, so this never freezes; keep the max: the exception is equality, not "anything later".
    statement.date = std::max(statement.date, previous.date);
    // What every reader will check, checked before this member signs it, on the verified read it was planned on
    // (`describes` bound group.policy, group.creator and the roster to the latest statement). Without it, a mistaken
    // app call by an honest member gives a malicious bridge a genuinely signed out-of-role statement to land.
    const std::set<std::string> users(group->users.begin(), group->users.end());
    const std::set<std::string> managers(group->managers.begin(), group->managers.end());
    if (const auto problem = keytree::TreeCommits::deltasProblem(statement, users, managers)) {
        throw core::InvalidParamsException(problem.value());
    }
    if (!keytree::TreeCommits::permits(rulesOf(group), statement, users, managers)) {
        throw GroupUnauthorizedSignerException(
            "the group's signed policy does not give this member the role this commit needs"
        );
    }
}

void CommitEngine::forgetUnresolved(const std::string& groupId, const std::string& digest) const {
    const auto session = deps.sessions.of(groupId);
    std::lock_guard<std::mutex> lock(session->mutex);
    if (session->unresolved.has_value() && session->unresolved->digest == digest) {
        session->unresolved.reset();
    }
}

void CommitEngine::submit(
    const std::string& groupId,
    const keytree::CommitStatement& statement,
    UnresolvedCommit commit
) const {
    const auto session = deps.sessions.of(groupId);
    std::unique_lock<std::mutex> lock(session->commitMutex);
    commit.digest = keytree::TreeCommits::digest(statement);
    commit.seq = statement.seq;
    commit.date = statement.date;
    if (statement.seq <= deps.treeVerifier.pinnedSeq(groupId)) {
        throw StalePlan{}; // planned behind a state this client verified (or committed) since
    }
    // Under the lock: a concurrent commit of ours may have been refused as a lost race since this was planned. That
    // is honest concurrency, so re-planned; a plan read that still serves no statement at that seq is refused there
    // (`chainTo`).
    if (!deps.treeVerifier.maySignAt(groupId, statement.seq)) {
        throw StalePlan{};
    }
    {
        std::lock_guard<std::mutex> guard(session->mutex);
        // Another commit of ours, released with no known outcome since this was planned, may land at this seq.
        // `settle` completes it on the re-plan. A deferred self-update yields instead.
        const auto& other = session->unresolved;
        if (other.has_value() && other->digest != commit.digest && other->seq >= statement.seq &&
            other->op != SELF_UPDATE_OP) {
            throw StalePlan{};
        }
        // Replaces a pending deferred self-update only now, when the op superseding it is actually released.
        // Outlives the call: its closures may reference the GroupApiImpl (`invalidateModuleKeys`) and live as long.
        session->unresolved = commit;
    }
    try {
        commit.send();
    } catch (const privmx::utils::PrivmxException& e) {
        // The bridge's word that a concurrent commit took this seq; it may have applied ours all the same.
        if (isRetryableCommitRejection(e)) {
            deps.treeVerifier.refusedAsLostRace(groupId, statement.seq);
        }
        throw; // any failure keeps the body: the bridge may have applied it, and a retry resends it
    }
    complete(groupId, commit);
}

void CommitEngine::complete(const std::string& groupId, const UnresolvedCommit& commit) const {
    forgetUnresolved(groupId, commit.digest);
    commit.landed();
    if (commit.op != SELF_UPDATE_OP) {
        deps.facade.savePins(); // an own commit is in the store before the call returns
    }
}

Settled CommitEngine::settle(const std::string& groupId, const std::string& op, bool mayCompleteOther) const {
    const auto session = deps.sessions.of(groupId);
    std::optional<UnresolvedCommit> first;
    {
        std::lock_guard<std::mutex> lock(session->mutex);
        if (!session->unresolved.has_value()) {
            return Settled::Proceed;
        }
        first = session->unresolved;
    }
    // Landed and built upon since: on the verified chain below the pin. A read, so before the lock. First: a landed
    // add is no failure, whatever the UserVerifier says of its newcomers now.
    const bool landedBelowPin = deps.treeVerifier.pinnedSeq(groupId) > first->seq &&
        deps.treeVerifier.chainedToPin(
            groupId, first->seq, first->digest, treeEnvironment(deps.serverApi, deps.connection, groupId)
        );
    // A resent add wraps to its newcomers' keys again: only while the UserVerifier still vouches for them. Outside
    // every lock of ours, like any verifier call.
    if (!landedBelowPin &&
        !first->newcomers.empty() &&
        deps.treeVerifier.pinnedDigest(groupId) != first->digest &&
        (first->op == op || mayCompleteOther)) {
        try {
            deps.facade.assertUserKeysVerified(first->contextId, first->newcomers);
        } catch (...) {
            forgetUnresolved(groupId, first->digest);
            if (first->op == op) {
                throw;
            }
            return Settled::Proceed; // not resent to unvouched keys; this op plans afresh
        }
    }
    std::unique_lock<std::mutex> lock(session->commitMutex);
    UnresolvedCommit pending;
    {
        std::lock_guard<std::mutex> guard(session->mutex);
        if (!session->unresolved.has_value() || session->unresolved->digest != first->digest) {
            return Settled::Proceed; // settled meanwhile
        }
        pending = session->unresolved.value();
    }
    const auto finish = [&](Settled done) {
        complete(groupId, pending);
        lock.unlock();
        if (pending.after) {
            pending.after();
        }
        if (pending.op != op) {
            return done;
        }
        // An event op (a rotation) found landed past its window is an earlier call's: this call is a new request,
        // planned on a fresh read (`after` changed the group). Never Done then, or the key the caller wants replaced
        // stays current with the call returning success.
        return pending.namesEndState || commitDate() < pending.date + RELEASE_WINDOW_MS ? Settled::Done
                                                                                          : Settled::Reread;
    };
    // Landed only when a verified read pinned it, or a statement chained above it, never on what the bridge serves as
    // the head: a served head is unverified, and `landed` cannot refuse it (its `pinCommitted` passes over a statement
    // below the pin). Before the gate, which lets go of the entry once the pin reaches its seq.
    if (deps.treeVerifier.pinnedDigest(groupId) == pending.digest || landedBelowPin) {
        return finish(Settled::Proceed); // it landed; only the answer was lost
    }
    // Superseded (the pin passed its seq), or past its window (an honest bridge refuses it by its date by now).
    if (deps.treeVerifier.pinnedSeq(groupId) >= pending.seq || commitDate() >= pending.date + RELEASE_WINDOW_MS) {
        forgetUnresolved(groupId, pending.digest);
        return Settled::Proceed;
    }
    if (pending.op == SELF_UPDATE_OP && op != SELF_UPDATE_OP) {
        return Settled::Proceed; // yields; the body stays for a later self-update until this op is released
    }
    if (pending.op != op && !mayCompleteOther) {
        return Settled::Deferred;
    }
    deps.treeVerifier.assertMaySignAt(groupId, pending.seq);
    try {
        pending.send();
    } catch (const std::exception& e) {
        const auto* rejection = dynamic_cast<const privmx::utils::PrivmxException*>(&e);
        if (rejection != nullptr && isRetryableCommitRejection(*rejection)) {
            deps.treeVerifier.refusedAsLostRace(groupId, pending.seq);
            throw;
        }
        if (pending.op == op) {
            throw;
        }
        // Another op: one resend was tried; the earlier commit is dropped and this op plans afresh.
        LOG_WARN("[settle] an earlier ", pending.kind, " to group ", groupId, " is dropped unresolved: ", e.what())
        forgetUnresolved(groupId, pending.digest);
        return Settled::Proceed;
    }
    return finish(Settled::Reread);
}
