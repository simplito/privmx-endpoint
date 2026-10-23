/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_ENDPOINT_GROUP_KEYTREE_TREEVERIFIER_HPP_
#define _PRIVMXLIB_ENDPOINT_GROUP_KEYTREE_TREEVERIFIER_HPP_

#include <array>
#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <set>
#include <string>
#include <vector>

#include <Poco/LRUCache.h>

#include <privmx/endpoint/core/UserVerifierInterface.hpp>

#include "privmx/endpoint/group/ServerTypes.hpp"
#include "privmx/endpoint/group/keytree/TreeCommits.hpp"

namespace privmx {
namespace endpoint {
namespace group {
namespace keytree {

// Checks a served tree against the commit statements members signed, before any key from it is used: the latest
// statement must be genuine and describe exactly the served roster, grant key and tree (by hash); every filled
// node must be vouched for by a genuine statement whose committer is still on that roster and which signed the
// node's current subtree hash; and the history since the last state this client verified must be an unbroken chain
// of statements by members. That closes a bridge substituting node or grant keys, seating outsiders, or rolling a
// node back (with or without a colluding member). Which nodes a member may set is the bridge's and the remover's
// business (a removal blanks everything the leaver could know); one state cannot show who learned a key through a
// since-blanked child.
//
// What it cannot close, by design:
//   - First contact (no pin for the group: per GroupApi without a PinStore, per device, Bridge and identity with one,
//     whose pins every GroupApi of that identity loads and saves, T4-16) trusts the latest validly signed state: trust
//     on first use, as for any delivery service. That state may be any seq, so a first contact is not bound to genesis
//     (T4-19); `epochOpeners`, which reads the chain from seq 1, replays it from the genesis roster.
//   - The bridge may withhold or delay commits.
//
// Roles (T4-10): the rules that govern commits are signed into every statement (`policyHash`), so a replay from a pin,
// or from genesis in `epochOpeners`, holds every statement to the op-effect table of its op and its committer to the
// role the rules before it required (`step`). A genuinely signed out-of-role statement throws
// GroupUnauthorizedSignerException; a first contact takes the latest statement's rules on trust, as its roster.
//
// Failures throw GroupDataIntegrityException, rollbacks GroupHistoryForkException. Pins are kept per group in
// memory and only stored once a verification has passed completely. A latest statement that moves a pin needs its
// committer's key accepted by the UserVerifier both at its date and now (N-3); a first contact checks it at its date.
class TreeVerifier {
public:
    // The bridge chooses how many distinct statements and groups it serves, so nothing it feeds a cache may grow
    // without bound.
    template<typename V>
    using Bounded = Poco::LRUCache<std::string, V>;

    // How much of the tree the response carries: one seat's path ("path", the default `groupGet`), or every
    // record ("plan"/"full").
    enum class Scope {
        Path,
        Plan
    };

    // What a verification needs from outside the served group.
    struct Environment {
        // The connection's UserVerifier; it vouches for each statement's committer and `committerPubKey`.
        std::function<std::vector<bool>(const std::vector<core::VerificationRequest>&)> verifyUsers;
        // One page of the statements with `fromSeq < seq <= toSeq`, ascending from `fromSeq + 1`; it may stop short of
        // `toSeq`, and the verifier asks again from where it stopped. From seq 0, with the genesis roster beside it.
        std::function<server::GroupGetTreeCommitsResult(std::uint64_t fromSeq, std::uint64_t toSeq)> commitsBetween;
    };

    void verify(const server::GroupInfo& group, Scope scope, const Environment& environment);

    // A `groupGet` answer, for a reader or writer that may hold no seat in the group (a listing carries neither the
    // roster nor a statement, so it is never verified itself): its latest statement is genuine and describes the
    // served grant key, counters and roster, and its committer is on that roster. A pinned group must also continue
    // its pin (the pinned statement at its seq, a member-signed chain above it). No tree is checked; the pin is
    // stored or moved up to the statement, so the writer is on first use only once per GroupApi (per device with a PinStore). A statement below
    // the pin passes, and `pinnedSeq` tells it apart. Throws GroupDataIntegrityException.
    void verifyListed(const server::GroupInfo& summary, const Environment& environment);

    // The latest statements of several `groupGet` answers, put to the UserVerifier in one call, so that
    // `verifyListed` on each finds its statement checked already. Refuses nothing itself: a statement that fails is
    // left for `verifyListed`.
    void preverifyListed(const std::vector<server::GroupInfo>& summaries, const Environment& environment);

    // Whether `keyVersion`/`groupPubKey` are exactly the epoch and grant key of the state pinned for the group, in
    // `contextId` — the only way a listing's `groupPubKey`, which no statement comes with, is taken.
    bool pinnedAt(
        const std::string& groupId,
        const std::string& contextId,
        std::int64_t keyVersion,
        const std::string& groupPubKey
    ) const;

    // A grant key handed in from outside (a caller's `GroupGrantWithKey`): unpinned groups are the caller's word,
    // a pinned one only exactly at its pin — an older epoch is one a removed member may still hold.
    bool agreesWithPin(
        const std::string& groupId,
        const std::string& contextId,
        std::int64_t keyVersion,
        const std::string& groupPubKey
    ) const;

    // A commit of this client's own that the bridge accepted is the newest state it knows of: pinned as if read
    // back, so the next read cannot be the state the commit replaced. `users`/`managers` are the roster it signed,
    // `rules` the group's rules after it (`statement.policyHash` is their hash).
    // Throws GroupHistoryForkException when a different statement is pinned at the same seq.
    void pinCommitted(
        const std::string& groupId,
        const std::string& contextId,
        const CommitStatement& statement,
        const std::vector<std::string>& users,
        const std::vector<std::string>& managers,
        const GroupRules& rules
    );

    // P2: the members seated in the tree must be exactly the attested roster, or the next commit wraps to whoever
    // the bridge seated. Throws GroupDataIntegrityException.
    static void assertSeatsMatchRoster(
        const server::GroupInfo& group,
        const std::vector<std::string>& users,
        const std::vector<std::string>& managers
    );

    // `seq` and `keyVersion` of the last state verified for the group, 0 if none. Pins are never dropped: an
    // unauthenticated `groupDeleted` must not turn the next read into a first contact.
    std::uint64_t pinnedSeq(const std::string& groupId) const;
    // `TreeCommits::digest` of the pinned statement, empty if none.
    std::string pinnedDigest(const std::string& groupId) const;
    std::uint64_t pinnedKeyVersion(const std::string& groupId) const;
    // For tests: the entries held by each cache the bridge can feed (openers, verified statements, "now" answers).
    std::array<std::size_t, 3> cacheSizes();

    // The statement that opened each epoch (the first at its `keyVersion`), off the whole chain up to the pin: a
    // statement for every seq from 1, each genuine as `verifyStatements` checks it and chained to the one before by
    // `prevDigest`, the roster replayed forward from the genesis roster seq 1's `rosterHash` binds (I-1) with every
    // committer on it and the pinned `rosterHash` matching, counters and dates never going back, the last one the pinned statement, one
    // grant key per epoch. Kept per group (a bounded number of them), so a later call fetches only the statements
    // since. What a past epoch's grant key and the author of a rung are checked against. Throws
    // GroupDataIntegrityException, also when the group has no pin.
    std::map<std::uint64_t, CommitStatement> epochOpeners(
        const std::string& groupId,
        const std::string& contextId,
        const Environment& environment
    );

    // T4-17: the bridge refused this client's statement at `seq` as a lost race. It may have applied it all the same,
    // so no second statement is signed at that seq (`assertMaySignAt`) until a read shows the seq taken.
    void refusedAsLostRace(const std::string& groupId, std::uint64_t seq);

    // Throws GroupDataIntegrityException when a statement at `seq` or later was refused as a lost race: the bridge
    // then serves a chain that does not reach the seq it claimed a concurrent commit took.
    void assertMaySignAt(const std::string& groupId, std::uint64_t seq);

    // Public for the unit tests of `step` (a walk that skips statements passes `adjacent = false`).
    // The roster as the statements replay it, with the hash the last of them signed.
    struct Roster {
        std::set<std::string> users;
        std::set<std::string> managers;
        std::string hash;
    };

    // Where a chain of statements has been followed to: the last statement's seq, digest, date, counters and tree hash,
    // and the roster and rules replayed up to it.
    struct Head {
        std::uint64_t seq = 0;
        std::string digest;
        std::uint64_t date = 0;
        Roster roster;
        std::uint64_t keyVersion = 0;
        std::string groupPubKey;
        std::uint64_t rosterVersion = 0;
        GroupRules rules;
        std::string treeHash;
    };

    // What a verified state leaves behind for the next read of the same group: the head at its latest statement.
    struct Pin : Head {
        std::string contextId; // authenticated by the group's id
        // Highest generation seen per node index. A blank keeps its generation, so blanking never lowers it.
        std::map<std::uint32_t, std::uint32_t> generations;
        std::uint64_t refusedSeq = 0; // `refusedAsLostRace`
        // 01, persisted. A pin loaded without its roster (a compact record) replays it from genesis before it is
        // extended (`chainFromGenesis`); `seenAt` orders which rosters the blob keeps.
        bool hasRoster = true;
        std::uint64_t seenAt = 0;
    };

    // 01: pins and version-pin counters as the PinBlob holds them.
    struct PinSet {
        std::map<std::string, Pin> tree;
        std::map<std::string, std::array<std::int64_t, 3>> planes; // rosterVersion, publicMetaVersion, privateMetaVersion
    };

    // Copies of the pins for a save: moved since the last export (or all, with `all`) whole, the rest compact (no
    // roster, no generations). Clears the moved set.
    std::map<std::string, Pin> exportPins(bool all);
    // Records this device verified (the slot, or a previous identity's slot) merged into memory by `PinBlob::higher`:
    // per group the higher seq wins, a tie keeps the pin in memory; `refusedSeq` and `seenAt` by max, generations by
    // max when the record wins. A stored record is this device's own verified state, so it is taken without a read.
    // Two instances that verified different branches simply converge on the higher one (a fork is a boundary, not
    // detected here: a bridge able to fork can withhold just as well). `onlyUnpinned`: records only for groups with no
    // pin yet (a previous identity's slot, which whoever holds that key can write: it must never raise a pin).
    void mergeStored(const std::map<std::string, Pin>& stored, bool onlyUnpinned = false);
    // Set once, before use: called after `_mutex` is released whenever something persistent moved. `major`: the
    // context, epoch, roster or rules changed, or `refusedSeq` rose; tree-only moves (self-updates) are minor.
    void onPinsMoved(std::function<void(bool major)> callback);

    enum class Step { Ok, Unauthorized };

    // One statement on top of `head`: the op-effect table (T4-10: seq/op pairing, roster deltas, epoch and grant key,
    // `rosterVersion`, `policyHash`, an empty path for rotate/policy and, when `adjacent`, their tree hash unchanged),
    // the grant key per epoch, the roster (`extend`), the policy replay and the role under the rules and roster before
    // it. A shape failure throws (integrity); a role failure is returned so the caller reports it after the signatures
    // are checked. The only place that advances `head`, on Ok and on Unauthorized. `digest` is
    // `TreeCommits::digest(statement)`; `adjacent` is `statement.seq == head.seq + 1`.
    static Step step(
        Head& head,
        const CommitStatement& statement,
        const std::string& digest,
        std::set<std::string>& grantKeys,
        bool checkHash,
        bool adjacent
    );

private:

    // Signature by `committerPubKey`, that key accepted by the UserVerifier for the committer at the statement's
    // date, and naming this group (at seq 1 through `TreeCommits::groupId`) and tree version. Results are cached per
    // context, group and statement. With `firstStillValid` the first statement's key must be accepted now as well.
    void verifyStatements(
        const std::string& groupId,
        const std::string& contextId,
        const std::vector<CommitStatement>& statements,
        const Environment& environment,
        bool firstStillValid = false
    );

    // One statement as some group's, for `checkStatements`.
    struct Claim {
        const std::string* groupId;
        const std::string* contextId;
        const CommitStatement* statement;
        // N-3: the committer's key must also be accepted at the current time — a key revoked now cannot move a pin.
        // Only the latest statement's: an intermediate one is checked at its own date, so a revoked key's statement
        // followed by one from a key valid now still moves it (a limit, not a guarantee; SECURITY-NOTES T4-04).
        bool now = false;
    };

    // `verifyStatements` over claims for any groups, in one UserVerifier call: caches each that passes and says
    // whether all did.
    bool checkStatements(const std::vector<Claim>& claims, const Environment& environment);

    // `head` moved along the statements up to `toSeq`, fetched page by page and each page checked before the next is
    // fetched (T4-15): a chain nobody on the roster signed is refused at its first page, not once all of it is held.
    // Each statement is the next seq, linked by `prevDigest`, genuine (`verifyStatements`) and passes `step` (its op's
    // effects, the roster, one grant key per epoch with a new epoch's not in `grantKeys` (T4-24), which collects it,
    // the policy). A page with a statement out of its committer's role throws GroupUnauthorizedSignerException once
    // the page's signatures have passed. `each` sees every statement once it passed.
    void followChain(
        const std::string& groupId,
        const std::string& contextId,
        Head& head,
        std::set<std::string>& grantKeys,
        std::uint64_t toSeq,
        const Environment& environment,
        const std::function<void(const CommitStatement&)>& each
    );

    // The chain from the pin to `toSeq` (`followChain`), ending exactly at the statement with `toDigest`. A new
    // epoch's grant key is compared with the pinned one only; `epochOpeners` holds every earlier epoch's.
    void verifyChain(
        const std::string& groupId,
        const std::string& contextId,
        const Pin& pin,
        std::uint64_t toSeq,
        const std::string& toDigest,
        const Environment& environment
    );

    // The pin for the group, or an empty one (seq 0) if none.
    Pin pinOf(const std::string& groupId) const;
    // One field of the group's pin, empty if none.
    template<typename T>
    T pinned(const std::string& groupId, T Head::*field) const {
        std::lock_guard lock(_mutex);
        const auto it = _pins.find(groupId);
        return it == _pins.end() ? T{} : it->second.*field;
    }

    // `statement` applied to `roster`: signed by somebody on it, and with `checkHash` leaving exactly the roster it
    // signs. `followChain` checks the hash at seq 1 (the genesis roster is the bridge's) and at the last statement:
    // the signed deltas between decide the roster either way, and hashing a 16k roster per statement is not free.
    // An unchanged roster is compared by hash, not hashed again (F1).
    static bool extend(Roster& roster, const CommitStatement& statement, bool checkHash);

    // Whether `latest` would move an existing pin: what needs the committer's key valid now (N-3). Not a first contact,
    // which takes the latest genuine statement on trust: there an honest committer who rotated their key since would
    // lock every fresh session out of the group, and with it every commit that could move the group past it.
    bool movesPin(const std::string& groupId, const CommitStatement& latest) const;
    // The latest statement's committer key accepted now as well, unless `checkedNow` says that was done: for a latest
    // statement that moves a pin found only after `movesPin` looked. Sets `checkedNow`.
    void assertValidNow(
        const std::string& groupId,
        const std::string& contextId,
        const CommitStatement& latest,
        const Environment& environment,
        bool& checkedNow
    );

    // `latest` stored as the group's pin, with `nodes`' generations, if the pin is still `seen`; otherwise `seen` is
    // refreshed to the pin as it now stands and nothing is stored (another verification, or a merge of stored
    // records, moved it meanwhile).
    bool storeIfPinned(
        const std::string& groupId,
        Pin& seen,
        const std::string& contextId,
        const CommitStatement& latest,
        const std::vector<std::string>& users,
        const std::vector<std::string>& managers,
        const GroupRules& rules,
        const std::vector<TreeNodeState>& nodes
    );
    // What `movedLocked` compares: a pin's persisted scalars, without its roster (a 16k roster is not copied per read).
    struct Snapshot {
        std::string contextId;
        std::uint64_t seq = 0;
        std::string digest;
        std::uint64_t keyVersion = 0;
        std::string rosterHash;
        std::string rulesHash;
        std::uint64_t refusedSeq = 0;
        bool hasRoster = true;
    };
    static Snapshot snapshotOf(const Pin& pin);
    // Whether `after` differs from `before` in what is persisted: nullopt if not, else whether the move is major.
    // Marks the group moved. Under `_mutex`.
    std::optional<bool> movedLocked(
        const std::string& groupId,
        const Snapshot& before,
        const Pin& after,
        bool generationsRaised
    );
    // Calls the `onPinsMoved` callback; never under `_mutex`.
    void notify(std::optional<bool> major);

    // `stored` moved to `latest` and the roster and rules it signed; under `_mutex`. Generations are the caller's.
    static void storeLocked(
        Pin& stored,
        const std::string& contextId,
        const CommitStatement& latest,
        const std::vector<std::string>& users,
        const std::vector<std::string>& managers,
        const GroupRules& rules
    );

    // `epochOpeners`' last answer per group, extended by the statements since rather than fetched again from seq 1.
    struct Openers {
        Head head;
        std::set<std::string> grantKeys; // every epoch's so far
        std::map<std::uint64_t, CommitStatement> byEpoch;
    };

    // `known` (empty or a memo ending at or below the pin) continued to the pin from genesis: every statement checked
    // as `followChain` checks it, ending exactly at the pinned statement (so the replayed roster reproduces the pinned
    // `rosterHash`). Throws GroupDataIntegrityException otherwise. On return `known.head` is the pin's head.
    void chainFromGenesis(
        const std::string& groupId,
        const std::string& contextId,
        Openers& known,
        std::uint64_t pinSeq,
        const std::string& pinDigest,
        const Environment& environment
    );
    // The memo for the pinned statement, or `chainFromGenesis` from the best memo below it, memoized.
    Openers openersAt(
        const std::string& groupId,
        const std::string& contextId,
        std::uint64_t pinSeq,
        const std::string& pinDigest,
        const Environment& environment
    );

    mutable std::mutex _mutex;
    // Never evicted: a dropped pin turns the next read into a first contact the bridge may answer with any old state.
    std::map<std::string, Pin> _pins;
    std::set<std::string> _dirty; // groups moved since the last `exportPins`
    std::function<void(bool)> _onPinsMoved;
    // Limit: 16 groups' rosters (a 16k roster is ~2 MB); an evicted group refetches from seq 1.
    Bounded<Openers> _openers{16};
    Bounded<bool> _verifiedStatements{4096};
    // `contextId \0 userId \0 pubKey` -> when the UserVerifier last accepted that key "now", reused for
    // `NOW_ANSWER_REUSE_MS` so that a listing's `preverifyListed` and `verifyListed` share one call (M4).
    Bounded<std::uint64_t> _acceptedNow{1024};
};

} // namespace keytree
} // namespace group
} // namespace endpoint
} // namespace privmx

#endif // _PRIVMXLIB_ENDPOINT_GROUP_KEYTREE_TREEVERIFIER_HPP_
