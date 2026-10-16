/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include "privmx/endpoint/group/keytree/TreeVerifier.hpp"

#include <algorithm>
#include <optional>
#include <stdexcept>

#include <privmx/crypto/ecc/PublicKeyCache.hpp>
#include <privmx/utils/Utils.hpp>

#include "privmx/endpoint/group/GroupException.hpp"
#include "privmx/endpoint/group/keytree/PinBlob.hpp"
#include "privmx/endpoint/group/keytree/TreeMath.hpp"
#include "privmx/endpoint/group/keytree/TreeWire.hpp"

using namespace privmx::endpoint::group::keytree;
namespace server = privmx::endpoint::group::server;
using privmx::endpoint::group::GroupDataIntegrityException;
using privmx::endpoint::group::GroupHistoryForkException;
using privmx::endpoint::group::GroupUnauthorizedSignerException;

namespace {

[[noreturn]] void reject() {
    throw GroupDataIntegrityException();
}

[[noreturn]] void reject(const std::string& why) {
    throw GroupDataIntegrityException(why);
}

CommitStatement parse(const server::GroupTreeCommit& wire) {
    try {
        return TreeCommits::fromWire(wire);
    } catch (const std::invalid_argument&) { reject(); }
}

std::uint64_t nowMs() {
    return static_cast<std::uint64_t>(privmx::utils::Utils::getNowTimestamp());
}

// The latest statement, read ahead of this clock. The chain's dates never go back, so the latest one bounds them all,
// and with it how far ahead of real time a member and a misbehaving bridge can push the dates the UserVerifier is
// asked at (the bridge takes a commit dated as the statement it extends past its tolerance, so this bounds date
// creep, not a freeze: N-1). Twice the bridge's own tolerance: an honest commit is dated within it of the bridge's
// clock, and this clock may be as far behind the bridge's.
CommitStatement parseLatest(const server::GroupTreeCommit& wire) {
    CommitStatement latest = parse(wire);
    if (latest.date > nowMs() + 2 * TreeCommits::DATE_TOLERANCE_MS) {
        reject();
    }
    return latest;
}

// ponytail: a "still accepted now" answer is reused for a minute, long enough for one listing's `preverifyListed` and
// its `verifyListed`s. A key revoked within that minute can still move a pin; shorten it if that matters.
constexpr std::uint64_t NOW_ANSWER_REUSE_MS = 60 * 1000;

std::set<std::string> asSet(const std::vector<std::string>& values) {
    return std::set<std::string>(values.begin(), values.end());
}

bool onRoster(
    const std::vector<std::string>& users,
    const std::vector<std::string>& managers,
    const std::string& userId
) {
    return std::find(users.begin(), users.end(), userId) != users.end() ||
        std::find(managers.begin(), managers.end(), userId) != managers.end();
}

// The served policy's rules, which `describes` binds to the latest statement. Throws on one that does not parse.
GroupRules servedRules(const server::GroupInfo& group) {
    try {
        return TreeCommits::rules(group.policy, group.creator);
    } catch (const std::exception&) { reject(); }
}

// The latest statement describes exactly what is served: grant key, counters, roster, and the creator and the four
// commit rules of the policy (T4-10; the rest of the policy is the bridge's and is not attested).
bool describes(const CommitStatement& latest, const server::GroupInfo& group) {
    return latest.keyVersion == static_cast<std::uint64_t>(group.keyVersion) &&
        latest.groupPubKey == group.groupPubKey &&
        latest.rosterVersion == static_cast<std::uint64_t>(group.rosterVersion) &&
        latest.rosterHash == TreeCommits::rosterHash(group.users, group.managers) &&
        latest.policyHash == servedRules(group).hash;
}

// The id is `TreeCommits::groupId(contextId, resourceId)`: the only thing that authenticates the served context, which
// the UserVerifier, the pins and every later check run in.
bool inItsContext(const server::GroupInfo& group) {
    return group.resourceId.has_value() && TreeCommits::groupId(group.contextId, group.resourceId.value()) == group.id;
}

std::string verifiedKey(const std::string& contextId, const std::string& groupId, const CommitStatement& statement) {
    return contextId + '\0' + groupId + '\0' + TreeCommits::digest(statement);
}

bool seatedAt(const TreeGroupState& state, std::uint32_t seat, const std::string& userId) {
    return seat < state.numLeaves && seat < state.leafAssignment.size() && state.leafAssignment[seat] == userId;
}

} // namespace

void TreeVerifier::verifyStatements(
    const std::string& groupId,
    const std::string& contextId,
    const std::vector<CommitStatement>& statements,
    const Environment& environment,
    bool firstStillValid
) {
    std::vector<Claim> claims;
    for (const CommitStatement& statement : statements) {
        claims.push_back(Claim{.groupId = &groupId, .contextId = &contextId, .statement = &statement});
    }
    if (!claims.empty()) {
        claims.front().now = firstStillValid;
    }
    if (!checkStatements(claims, environment)) {
        reject();
    }
}

bool TreeVerifier::checkStatements(const std::vector<Claim>& claims, const Environment& environment) {
    const std::uint64_t now = nowMs();
    const auto keyNow = [](const Claim& claim) {
        return *claim.contextId + '\0' + claim.statement->committer + '\0' + claim.statement->committerPubKey;
    };
    // Per claim, the requests its answer waits on: at the statement's date (unless cached) and now (N-3).
    struct Pending {
        const Claim* claim;
        std::optional<std::size_t> atDate;
        std::optional<std::size_t> atNow;
    };
    std::vector<Pending> pending;
    {
        std::lock_guard lock(_mutex);
        for (const Claim& claim : claims) {
            Pending entry{.claim = &claim, .atDate = std::nullopt, .atNow = std::nullopt};
            if (_verifiedStatements.find(verifiedKey(*claim.contextId, *claim.groupId, *claim.statement)) == nullptr) {
                entry.atDate = 0;
            }
            if (claim.now) {
                const std::uint64_t* accepted = _acceptedNow.find(keyNow(claim));
                if (accepted == nullptr || now > *accepted + NOW_ANSWER_REUSE_MS) {
                    entry.atNow = 0;
                }
            }
            if (entry.atDate.has_value() || entry.atNow.has_value()) {
                pending.push_back(entry);
            }
        }
    }
    bool all = true;
    std::vector<core::VerificationRequest> requests;
    const auto ask = [&](const Claim& claim, std::uint64_t date) {
        requests.push_back(
            core::VerificationRequest{
                .contextId = *claim.contextId,
                .senderId = claim.statement->committer,
                .senderPubKey = claim.statement->committerPubKey,
                .date = static_cast<std::int64_t>(date),
                .bridgeIdentity = std::nullopt
            }
        );
        return requests.size() - 1;
    };
    std::map<std::string, std::size_t> nowRequests; // one per key, however many groups it committed to
    std::vector<Pending> asked;
    for (Pending entry : pending) {
        const Claim& claim = *entry.claim;
        const CommitStatement& statement = *claim.statement;
        if (entry.atDate.has_value()) {
            // A statement names its group, which has no id yet at seq 1: the creator signs its resourceId instead,
            // and the bridge derives the id from it. Never the served resourceId, or one group's genesis passes as
            // another's.
            const bool namesGroup = statement.seq == 1 ?
                TreeCommits::groupId(*claim.contextId, statement.groupId) == *claim.groupId :
                statement.groupId == *claim.groupId;
            bool genuine =
                namesGroup && !statement.groupId.empty() && statement.treeVersion == TreeMath::TREE_VERSION;
            try {
                genuine = genuine &&
                    TreeCommits::verifySignature(
                              statement,
                              privmx::crypto::PublicKeyCache::getInstance()->fromBase58DER(statement.committerPubKey)
                    );
            } catch (...) { genuine = false; }
            if (!genuine) {
                all = false;
                continue;
            }
            // The key the committer signed with, at the time it signed, as the application vouches for its users —
            // the same check a metadata entry's author gets.
            entry.atDate = ask(claim, statement.date);
        }
        // And, for a statement about to move a pin, at the current time: a key the application has revoked since may
        // still be vouched for at a date before the revocation, and the chain's dates allow any date up to now.
        if (entry.atNow.has_value()) {
            const auto [it, fresh] = nowRequests.emplace(keyNow(claim), 0);
            if (fresh) {
                it->second = ask(claim, now);
            }
            entry.atNow = it->second;
        }
        asked.push_back(entry);
    }
    if (requests.empty()) {
        return all;
    }
    const std::vector<bool> verified = environment.verifyUsers(requests);
    if (verified.size() != requests.size()) {
        return false;
    }
    std::lock_guard lock(_mutex);
    for (const Pending& entry : asked) {
        const bool atDate = !entry.atDate.has_value() || verified[entry.atDate.value()];
        const bool atNow = !entry.atNow.has_value() || verified[entry.atNow.value()];
        if (entry.atDate.has_value() && atDate) {
            _verifiedStatements.put(
                verifiedKey(*entry.claim->contextId, *entry.claim->groupId, *entry.claim->statement), true
            );
        }
        if (entry.atNow.has_value() && atNow) {
            _acceptedNow.put(keyNow(*entry.claim), now);
        }
        all = all && atDate && atNow;
    }
    return all;
}

void TreeVerifier::preverifyListed(const std::vector<server::GroupInfo>& summaries, const Environment& environment) {
    std::vector<CommitStatement> latest;
    latest.reserve(summaries.size()); // the claims point into it
    std::vector<Claim> claims;
    for (const server::GroupInfo& summary : summaries) {
        if (!summary.treeCommit.has_value()) {
            continue;
        }
        try {
            latest.push_back(TreeCommits::fromWire(summary.treeCommit.value()));
        } catch (const std::invalid_argument&) { continue; }
        claims.push_back(Claim{
            .groupId = &summary.id,
            .contextId = &summary.contextId,
            .statement = &latest.back(),
            .now = movesPin(summary.id, latest.back())
        });
    }
    checkStatements(claims, environment); // what fails is `verifyListed`'s to refuse, group by group
}

void TreeVerifier::followChain(
    const std::string& groupId,
    const std::string& contextId,
    Head& head,
    std::set<std::string>& grantKeys,
    std::uint64_t toSeq,
    const Environment& environment,
    const std::function<void(const CommitStatement&)>& each
) {
    while (head.seq < toSeq) {
        const server::GroupGetTreeCommitsResult answer = environment.commitsBetween(head.seq, toSeq);
        std::vector<CommitStatement> page;
        for (const server::GroupTreeCommit& wire : answer.commits) {
            page.push_back(parse(wire));
        }
        if (page.empty() || page.size() > toSeq - head.seq) {
            reject(); // a short answer, or more than was asked for
        }
        if (head.seq == 0) {
            // The genesis roster, unsigned beside the chain: seq 1's `rosterHash` binds it (`extend`).
            head.roster = Roster{
                .users = asSet(answer.genesisUsers.value_or(std::vector<std::string>())),
                .managers = asSet(answer.genesisManagers.value_or(std::vector<std::string>()))
            };
        }
        bool unauthorized = false;
        for (const CommitStatement& statement : page) {
            // Each one extends the one before it: the bridge cannot fork or splice the chain.
            if (statement.seq != head.seq + 1 || statement.prevDigest != head.digest) {
                reject();
            }
            const bool checkHash = statement.seq == 1 || statement.seq == toSeq;
            if (step(head, statement, TreeCommits::digest(statement), grantKeys, checkHash, true) == Step::Unauthorized) {
                unauthorized = true;
            }
        }
        verifyStatements(groupId, contextId, page, environment);
        if (unauthorized) {
            // Only now: a statement the bridge forged fails as integrity above, so the new kind names a genuinely
            // signed out-of-role commit.
            throw GroupUnauthorizedSignerException();
        }
        for (const CommitStatement& statement : page) {
            each(statement);
        }
    }
}

TreeVerifier::Step TreeVerifier::step(
    Head& head,
    const CommitStatement& statement,
    const std::string& digest,
    std::set<std::string>& grantKeys,
    bool checkHash,
    bool adjacent
) {
    // The op's row of the effect table (T4-10). Its role is chosen by the op, so the effects must be the op's too, or a
    // removal relabelled as a self-update would need no role at all.
    const CommitOp op = statement.op;
    const bool create = op == CommitOp::Create;
    if ((statement.seq == 1) != create || statement.date < head.date) {
        reject("a statement out of order or dated back");
    }
    if (const auto problem = TreeCommits::deltasProblem(statement, head.roster.users, head.roster.managers)) {
        reject(problem.value());
    }
    const bool newEpoch = create || op == CommitOp::Remove || op == CommitOp::Rotate;
    const bool rosterMoves = newEpoch || op == CommitOp::Add;
    if (create ? statement.keyVersion != 1 || statement.rosterVersion != 1 :
                 statement.keyVersion != head.keyVersion + (newEpoch ? 1 : 0) ||
                     statement.rosterVersion != head.rosterVersion + (rosterMoves ? 1 : 0)) {
        reject("counters the op does not move that way");
    }
    // One grant key per epoch, and a new epoch's never an earlier epoch's (T4-24).
    if (newEpoch && !grantKeys.insert(statement.groupPubKey).second) {
        reject("a new epoch's grant key is an earlier epoch's");
    }
    if (!newEpoch && statement.groupPubKey != head.groupPubKey) {
        reject("a grant key moved outside a new epoch");
    }
    if ((op == CommitOp::Rotate || op == CommitOp::Policy) &&
        (!statement.path.empty() || (adjacent && statement.treeHash != head.treeHash))) {
        reject("a rotation or policy statement that moves the tree");
    }
    // The policy: replayed from the create statement's, moved by a policy statement only.
    std::optional<GroupRules> next;
    if (create || op == CommitOp::Policy) {
        if (!statement.policy.has_value()) {
            reject();
        }
        try {
            next = TreeCommits::rules(statement.policy.value(), create ? statement.committer : head.rules.creator);
        } catch (const std::invalid_argument&) { reject(); }
        if (next->hash != statement.policyHash) {
            reject("a policy that does not hash to the policyHash signed");
        }
    } else if (statement.policyHash != head.rules.hash) {
        reject("a policyHash moved outside a policy statement");
    }
    // The role, under the rules and roster before the statement: a policy granting its own signer a role is judged
    // under the rules it replaces.
    const Step result = TreeCommits::permits(head.rules, statement, head.roster.users, head.roster.managers)
        ? Step::Ok
        : Step::Unauthorized;
    // Signed by somebody who was a member when it was made: a non-member's statement is the bridge's.
    if (!extend(head.roster, statement, checkHash)) {
        reject();
    }
    if (next.has_value()) {
        head.rules = std::move(next.value());
    }
    head.seq = statement.seq;
    head.digest = digest;
    head.date = statement.date;
    head.keyVersion = statement.keyVersion;
    head.groupPubKey = statement.groupPubKey;
    head.rosterVersion = statement.rosterVersion;
    head.treeHash = statement.treeHash;
    return result;
}

void TreeVerifier::verifyChain(
    const std::string& groupId,
    const std::string& contextId,
    const Pin& pin,
    const CommitStatement& latest,
    const Environment& environment
) {
    if (pin.contextId != contextId) {
        reject();
    }
    Head head;
    std::set<std::string> grantKeys;
    if (pin.hasRoster) {
        head = pin;
        grantKeys = {pin.groupPubKey};
    } else {
        // 01: a pin loaded without its roster. The roster to continue from is replayed from genesis and must end at
        // exactly the pinned statement (so it reproduces the pinned rosterHash); the head keeps the pinned tree hash,
        // so a rotation or policy statement next is held to the pinned tree.
        Openers known = openersAt(groupId, contextId, pin.seq, pin.digest, environment);
        head = known.head;
        head.treeHash = pin.treeHash;
        grantKeys = std::move(known.grantKeys);
    }
    followChain(groupId, contextId, head, grantKeys, latest.seq, environment, [](const CommitStatement&) {});
    if (head.digest != TreeCommits::digest(latest)) {
        reject();
    }
}

void TreeVerifier::verify(const server::GroupInfo& group, Scope scope, const Environment& environment) {
    if (!group.treeCommit.has_value() || !inItsContext(group)) {
        reject();
    }
    const CommitStatement latest = parseLatest(group.treeCommit.value());

    // Every statement the served nodes cite, by seq; the latest is one of them whenever it refreshed something.
    std::map<std::uint64_t, CommitStatement> vouchers;
    vouchers.emplace(latest.seq, latest);
    for (const server::GroupTreeCommit& wire : group.treeCommits.value_or(std::vector<server::GroupTreeCommit>{})) {
        const CommitStatement statement = parse(wire);
        const auto [it, inserted] = vouchers.emplace(statement.seq, statement);
        if (!inserted && TreeCommits::digest(it->second) != TreeCommits::digest(statement)) {
            reject(); // two different statements under one seq
        }
    }

    TreeGroupState state;
    try {
        state = TreeWire::toRuntime(
            TreeWire::fromGroupInfo(group), static_cast<std::uint32_t>(group.keyVersion),
            privmx::crypto::PublicKeyCache::getInstance()->fromBase58DER(group.groupPubKey)
        );
    } catch (...) { reject(); }
    if (state.numLeaves == 0 || state.leafAssignment.size() != state.numLeaves) {
        reject();
    }

    // The latest statement describes exactly what is served, the committer's seat included.
    if (!describes(latest, group) || !seatedAt(state, latest.committerSeat, latest.committer)) {
        reject();
    }

    // And the tree, by hash: every record served (and, in the path view, every copath subtree through its hash). In
    // the path view the other seats are only bound through those copath hashes, so the seat checks here and below
    // read a `leafAssignment` the hash does not cover outside the caller's own leaf. That view is only ever climbed,
    // never wrapped to; every planning path reads the "plan" view, where the hash covers all of it.
    std::string treeHash;
    std::map<std::uint32_t, std::string> subtreeHashes;
    try {
        if (scope == Scope::Plan) {
            treeHash = TreeCommits::treeHash(state, &subtreeHashes);
        } else {
            if (!group.ownLeafPosition.has_value() ||
                group.ownLeafPosition.value() < 0 ||
                group.ownLeafPosition.value() >= static_cast<std::int64_t>(state.numLeaves) ||
                !group.copathHashes.has_value()) {
                reject();
            }
            treeHash = TreeCommits::treeHashAlongPath(
                state, static_cast<std::uint32_t>(group.ownLeafPosition.value()), group.copathHashes.value(),
                &subtreeHashes
            );
        }
    } catch (const std::invalid_argument&) { reject(); }
    if (treeHash != latest.treeHash) {
        reject();
    }

    // Each filled node vouched for by the statement that set it, whose committer is still on the roster: a removal
    // blanks or re-keys every node the leaver set, so a node still vouched for by a former member is a planted one.
    // And over the very subtree it was minted over: a node rolled back to an older, genuinely vouched generation
    // sits over children re-keyed since, which a removal would not blank. (A served node off the path view's hashed
    // path has no subtree hash, and is refused.)
    std::vector<CommitStatement> toVerify{latest};
    std::set<std::uint64_t> cited;
    std::set<std::uint32_t> recorded;
    for (const TreeNodeState& node : state.nodes) {
        // Not part of the tree, or (path view) off the hashed path: covered by no hash, so its generation must not
        // reach the pins either, blank or filled.
        if (!TreeMath::isKeyed(node.nodeIndex, state.numLeaves) || subtreeHashes.count(node.nodeIndex) == 0) {
            reject();
        }
        if (!recorded.insert(node.nodeIndex).second) {
            reject(); // a second record for one node: only the first is hashed, but a lookup might take either
        }
        if (!node.publicKey.has_value()) {
            continue;
        }
        if (!node.setBy.has_value()) {
            reject();
        }
        const auto voucher = vouchers.find(node.setBy.value());
        if (voucher == vouchers.end()) {
            reject();
        }
        const CommitStatement& statement = voucher->second;
        const bool listed = std::any_of(statement.path.begin(), statement.path.end(), [&](const StatementNode& entry) {
            return entry.nodeIndex == node.nodeIndex &&
                entry.generation == node.generation &&
                entry.publicKey == node.publicKey->toBase58DER() &&
                entry.subtreeHash == subtreeHashes.at(node.nodeIndex);
        });
        if (!listed || !onRoster(group.users, group.managers, statement.committer)) {
            reject();
        }
        if (cited.insert(statement.seq).second && statement.seq != latest.seq) {
            toVerify.push_back(statement);
        }
    }
    verifyStatements(group.id, group.contextId, toVerify, environment, movesPin(group.id, latest));

    // History: never behind what this session has verified, and connected to it by statements of members. Against
    // the pin as it stands when this state is stored: one a concurrent verification moved meanwhile, perhaps onto
    // another branch, is checked against afresh rather than overwritten.
    Pin pin = usablePin(group.id, environment);
    for (;;) {
        if (pin.seq != 0) {
            if (latest.seq < pin.seq || (latest.seq == pin.seq && TreeCommits::digest(latest) != pin.digest)) {
                throw GroupHistoryForkException();
            }
            if (latest.seq > pin.seq) {
                verifyChain(group.id, group.contextId, pin, latest, environment);
            }
        } else if (!onRoster(group.users, group.managers, latest.committer)) {
            reject(); // trust on first use: the latest genuine statement, by somebody on the roster it attests
        }
        for (const TreeNodeState& node : state.nodes) {
            const auto seen = pin.generations.find(node.nodeIndex);
            if (seen != pin.generations.end() && node.generation < seen->second) {
                throw GroupHistoryForkException(); // a node served at a generation older than one already seen
            }
        }
        // Everything passed; only now does this state become the reference for the next read.
        if (storeIfPinned(
                group.id, pin, group.contextId, latest, group.users, group.managers, servedRules(group), state.nodes,
                pin.seq == 0
            )) {
            return;
        }
        if (pin.forked || pin.unlinked) {
            pin = usablePin(group.id, environment); // a sync marked it meanwhile
        }
    }
}

bool TreeVerifier::storeIfPinned(
    const std::string& groupId,
    Pin& seen,
    const std::string& contextId,
    const CommitStatement& latest,
    const std::vector<std::string>& users,
    const std::vector<std::string>& managers,
    const GroupRules& rules,
    const std::vector<TreeNodeState>& nodes,
    bool firstContact
) {
    std::optional<bool> moved;
    {
        std::lock_guard lock(_mutex);
        Pin& stored = _pins[groupId];
        if (stored.seq != seen.seq || stored.digest != seen.digest || stored.forked || stored.unlinked) {
            seen = stored;
            return false;
        }
        const Snapshot before = snapshotOf(stored);
        storeLocked(stored, contextId, latest, users, managers, rules);
        bool raised = false;
        for (const TreeNodeState& node : nodes) {
            std::uint32_t& generation = stored.generations[node.nodeIndex];
            raised = raised || node.generation > generation;
            generation = std::max(generation, node.generation);
        }
        if (firstContact) {
            stored.firstContact = true;
        }
        moved = movedLocked(groupId, before, stored, raised);
    }
    notify(moved);
    return true;
}

TreeVerifier::Snapshot TreeVerifier::snapshotOf(const Pin& pin) {
    return Snapshot{
        .contextId = pin.contextId,
        .seq = pin.seq,
        .digest = pin.digest,
        .keyVersion = pin.keyVersion,
        .rosterHash = pin.roster.hash,
        .rulesHash = pin.rules.hash,
        .refusedSeq = pin.refusedSeq,
        .hasRoster = pin.hasRoster,
        .forked = pin.forked
    };
}

std::optional<bool> TreeVerifier::movedLocked(
    const std::string& groupId,
    const Snapshot& before,
    const Pin& after,
    bool generationsRaised
) {
    const bool major = before.contextId != after.contextId || before.keyVersion != after.keyVersion ||
        before.rosterHash != after.roster.hash || before.rulesHash != after.rules.hash ||
        before.forked != after.forked || after.refusedSeq > before.refusedSeq;
    const bool minor = before.seq != after.seq || before.digest != after.digest || before.hasRoster != after.hasRoster ||
        generationsRaised;
    if (!major && !minor) {
        return std::nullopt;
    }
    _dirty.insert(groupId);
    return major;
}

void TreeVerifier::notify(std::optional<bool> major) {
    if (major.has_value() && _onPinsMoved) {
        _onPinsMoved(major.value());
    }
}

void TreeVerifier::onPinsMoved(std::function<void(bool)> callback) {
    _onPinsMoved = std::move(callback);
}

TreeVerifier::Pin TreeVerifier::usablePin(const std::string& groupId, const Environment& environment) {
    // ponytail: a few rounds; only a sync racing every link keeps it pending, and then the read is refused.
    for (int round = 0; round < 4; ++round) {
        Pin pin = pinOf(groupId);
        if (pin.forked) {
            throw GroupHistoryForkException(); // two instances of this device verified incompatible histories
        }
        if (!pin.unlinked) {
            return pin;
        }
        link(groupId, environment);
    }
    reject("the group's pin is still being reconciled with another instance's");
}

TreeVerifier::Pin TreeVerifier::pinOf(const std::string& groupId) {
    std::lock_guard lock(_mutex);
    const auto it = _pins.find(groupId);
    return it == _pins.end() ? Pin{} : it->second;
}

void TreeVerifier::storeLocked(
    Pin& stored,
    const std::string& contextId,
    const CommitStatement& latest,
    const std::vector<std::string>& users,
    const std::vector<std::string>& managers,
    const GroupRules& rules
) {
    stored.contextId = contextId;
    stored.seq = latest.seq;
    stored.digest = TreeCommits::digest(latest);
    stored.date = latest.date;
    stored.roster = Roster{.users = asSet(users), .managers = asSet(managers), .hash = latest.rosterHash};
    stored.keyVersion = latest.keyVersion;
    stored.groupPubKey = latest.groupPubKey;
    stored.rosterVersion = latest.rosterVersion;
    stored.rules = rules;
    stored.treeHash = latest.treeHash;
    stored.hasRoster = true;
    stored.seenAt = nowMs();
}

void TreeVerifier::verifyListed(const server::GroupInfo& summary, const Environment& environment) {
    if (!summary.treeCommit.has_value() || !inItsContext(summary)) {
        reject();
    }
    const CommitStatement latest = parseLatest(summary.treeCommit.value());
    if (!describes(latest, summary) || !onRoster(summary.users, summary.managers, latest.committer)) {
        reject();
    }
    verifyStatements(summary.id, summary.contextId, {latest}, environment, movesPin(summary.id, latest));

    // A group this process has verified is taken only as a continuation of that state; below the pin is the caller's.
    // Against the pin as it stands when this one is stored, as in `verify`.
    Pin pin = usablePin(summary.id, environment);
    for (;;) {
        if (pin.seq != 0) {
            if (latest.seq < pin.seq) {
                return; // `pinnedSeq` tells the caller
            }
            if (latest.seq == pin.seq) {
                if (TreeCommits::digest(latest) != pin.digest) {
                    throw GroupHistoryForkException(); // at the pinned seq, only the pinned statement
                }
                return;
            }
            verifyChain(summary.id, summary.contextId, pin, latest, environment);
        }
        // Pinned like a member's read, so the next listing cannot go back to a state from before a removal. No tree
        // was checked, so no generations: those stay whatever a member's read pinned.
        if (storeIfPinned(
                summary.id, pin, summary.contextId, latest, summary.users, summary.managers, servedRules(summary), {},
                pin.seq == 0
            )) {
            return;
        }
        if (pin.forked || pin.unlinked) {
            pin = usablePin(summary.id, environment);
        }
    }
}

void TreeVerifier::pinCommitted(
    const std::string& groupId,
    const std::string& contextId,
    const CommitStatement& statement,
    const std::vector<std::string>& users,
    const std::vector<std::string>& managers,
    const GroupRules& rules
) {
    // The pin's roster is what the next catch-up replays from: never a set the statement's hash does not bind.
    if (TreeCommits::rosterHash(users, managers) != statement.rosterHash) {
        throw GroupDataIntegrityException("the roster pinned with a commit is not the one it signed");
    }
    std::optional<bool> moved;
    {
        std::lock_guard lock(_mutex);
        Pin& stored = _pins[groupId];
        if (stored.forked) {
            throw GroupHistoryForkException();
        }
        if (stored.seq > statement.seq) {
            return; // a read has verified a later state already
        }
        if (stored.seq == statement.seq && stored.digest != TreeCommits::digest(statement)) {
            throw GroupHistoryForkException(); // the bridge took this commit at a seq it has served another one at
        }
        const Snapshot before = snapshotOf(stored);
        storeLocked(stored, contextId, statement, users, managers, rules);
        bool raised = false;
        for (const StatementNode& node : statement.path) {
            std::uint32_t& generation = stored.generations[node.nodeIndex];
            raised = raised || node.generation > generation;
            generation = std::max(generation, node.generation);
        }
        moved = movedLocked(groupId, before, stored, raised);
    }
    notify(moved);
}

void TreeVerifier::assertSeatsMatchRoster(
    const server::GroupInfo& group,
    const std::vector<std::string>& users,
    const std::vector<std::string>& managers
) {
    std::set<std::string> seated;
    for (const std::string& seat : group.leafAssignment.value_or(std::vector<std::string>{})) {
        if (!seat.empty() && !seated.insert(seat).second) {
            reject(); // one member, two seats
        }
    }
    std::set<std::string> roster = asSet(users);
    roster.insert(managers.begin(), managers.end());
    if (seated != roster) {
        reject();
    }
}

bool TreeVerifier::pinnedAt(
    const std::string& groupId,
    const std::string& contextId,
    std::int64_t keyVersion,
    const std::string& groupPubKey
) {
    std::lock_guard lock(_mutex);
    const auto it = _pins.find(groupId);
    return it != _pins.end() && !it->second.forked && !it->second.unlinked && it->second.contextId == contextId &&
        !groupPubKey.empty() &&
        it->second.groupPubKey == groupPubKey &&
        static_cast<std::int64_t>(it->second.keyVersion) == keyVersion;
}

bool TreeVerifier::agreesWithPin(
    const std::string& groupId,
    const std::string& contextId,
    std::int64_t keyVersion,
    const std::string& groupPubKey
) {
    return pinnedSeq(groupId) == 0 || pinnedAt(groupId, contextId, keyVersion, groupPubKey);
}

std::uint64_t TreeVerifier::pinnedSeq(const std::string& groupId) {
    std::lock_guard lock(_mutex);
    const auto it = _pins.find(groupId);
    return it == _pins.end() ? 0 : it->second.seq;
}

std::string TreeVerifier::pinnedDigest(const std::string& groupId) {
    std::lock_guard lock(_mutex);
    const auto it = _pins.find(groupId);
    return it == _pins.end() ? std::string() : it->second.digest;
}

std::uint64_t TreeVerifier::pinnedKeyVersion(const std::string& groupId) {
    std::lock_guard lock(_mutex);
    const auto it = _pins.find(groupId);
    return it == _pins.end() ? 0 : it->second.keyVersion;
}

std::map<std::uint64_t, CommitStatement> TreeVerifier::epochOpeners(
    const std::string& groupId,
    const std::string& contextId,
    const Environment& environment
) {
    std::uint64_t pinSeq = 0;
    std::string pinDigest;
    {
        std::lock_guard lock(_mutex);
        const auto it = _pins.find(groupId);
        if (it == _pins.end() || it->second.seq == 0 || it->second.contextId != contextId || it->second.forked) {
            reject();
        }
        pinSeq = it->second.seq;
        pinDigest = it->second.digest;
    }
    return openersAt(groupId, contextId, pinSeq, pinDigest, environment).byEpoch;
}

TreeVerifier::Openers TreeVerifier::openersAt(
    const std::string& groupId,
    const std::string& contextId,
    std::uint64_t pinSeq,
    const std::string& pinDigest,
    const Environment& environment
) {
    Openers known;
    {
        std::lock_guard lock(_mutex);
        const Openers* memo = _openers.find(groupId);
        if (memo != nullptr && memo->head.seq == pinSeq && memo->head.digest == pinDigest) {
            return *memo;
        }
        if (memo != nullptr && memo->head.seq <= pinSeq) {
            known = *memo;
        }
    }
    chainFromGenesis(groupId, contextId, known, pinSeq, pinDigest, environment);
    std::lock_guard lock(_mutex);
    const Openers* stored = _openers.find(groupId);
    if (stored == nullptr || stored->head.seq < known.head.seq) {
        _openers.put(groupId, known);
    }
    return known;
}

void TreeVerifier::chainFromGenesis(
    const std::string& groupId,
    const std::string& contextId,
    Openers& known,
    std::uint64_t pinSeq,
    const std::string& pinDigest,
    const Environment& environment
) {
    // Only the statements since the last answer: the same checks a fetch from seq 1 makes, the earlier ones having
    // passed them already. Replayed forward from the genesis roster, so each committer was a member when it signed and
    // the pinned roster hash is the replayed roster's (I-1).
    followChain(groupId, contextId, known.head, known.grantKeys, pinSeq, environment, [&](const CommitStatement& s) {
        known.byEpoch.emplace(s.keyVersion, s);
    });
    if (known.head.digest != pinDigest) {
        reject();
    }
}

bool TreeVerifier::extend(Roster& roster, const CommitStatement& statement, bool checkHash) {
    if (roster.users.count(statement.committer) == 0 && roster.managers.count(statement.committer) == 0) {
        return false;
    }
    if (!statement.addedUsers.empty() || !statement.addedManagers.empty() || !statement.removed.empty()) {
        roster.users.insert(statement.addedUsers.begin(), statement.addedUsers.end());
        roster.managers.insert(statement.addedManagers.begin(), statement.addedManagers.end());
        for (const std::string& gone : statement.removed) {
            roster.users.erase(gone);
            roster.managers.erase(gone);
        }
        roster.hash.clear();
    }
    if (!checkHash) {
        return true;
    }
    if (roster.hash.empty()) {
        roster.hash = TreeCommits::rosterHash(
            {roster.users.begin(), roster.users.end()}, {roster.managers.begin(), roster.managers.end()}
        );
    }
    return roster.hash == statement.rosterHash;
}

bool TreeVerifier::movesPin(const std::string& groupId, const CommitStatement& latest) {
    const std::uint64_t pinned = pinnedSeq(groupId);
    return pinned != 0 && latest.seq > pinned;
}

void TreeVerifier::refusedAsLostRace(const std::string& groupId, std::uint64_t seq) {
    std::optional<bool> moved;
    {
        std::lock_guard lock(_mutex);
        Pin& stored = _pins[groupId];
        const Snapshot before = snapshotOf(stored);
        stored.refusedSeq = std::max(stored.refusedSeq, seq);
        moved = movedLocked(groupId, before, stored, false);
    }
    notify(moved);
}

void TreeVerifier::assertMaySignAt(const std::string& groupId, std::uint64_t seq) {
    std::lock_guard lock(_mutex);
    const auto it = _pins.find(groupId);
    if (it == _pins.end()) {
        return;
    }
    if (it->second.forked) {
        throw GroupHistoryForkException();
    }
    if (it->second.unlinked) {
        reject("the group's pin is being reconciled with another instance's; read the group again");
    }
    if (seq <= it->second.refusedSeq) {
        reject(); // the bridge said a concurrent commit took that seq, and now serves none there
    }
}

namespace {

// The pin without what a compact record drops: roster members and generations.
TreeVerifier::Pin compactOf(const TreeVerifier::Pin& pin) {
    TreeVerifier::Pin compact;
    compact.seq = pin.seq;
    compact.digest = pin.digest;
    compact.date = pin.date;
    compact.roster.hash = pin.roster.hash;
    compact.keyVersion = pin.keyVersion;
    compact.groupPubKey = pin.groupPubKey;
    compact.rosterVersion = pin.rosterVersion;
    compact.rules = pin.rules;
    compact.treeHash = pin.treeHash;
    compact.contextId = pin.contextId;
    compact.refusedSeq = pin.refusedSeq;
    compact.hasRoster = false;
    compact.seenAt = pin.seenAt;
    compact.forked = pin.forked;
    compact.synced = pin.synced;
    compact.firstContact = pin.firstContact;
    compact.unlinked = pin.unlinked;
    return compact;
}

bool sameState(const TreeVerifier::Pin* a, const TreeVerifier::Pin* b) {
    if (a == nullptr || b == nullptr) {
        return a == b;
    }
    return a->seq == b->seq && a->digest == b->digest && a->unlinked == b->unlinked && a->forked == b->forked;
}

std::optional<std::pair<std::uint64_t, std::string>> stateOf(const TreeVerifier::Pin& pin) {
    return std::make_pair(pin.seq, pin.digest);
}

} // namespace

std::map<std::string, TreeVerifier::Pin> TreeVerifier::exportPins(bool all) {
    std::lock_guard lock(_mutex);
    std::map<std::string, Pin> exported;
    for (const auto& [groupId, pin] : _pins) {
        exported.emplace_hint(exported.end(), groupId, all || _dirty.count(groupId) > 0 ? pin : compactOf(pin));
    }
    _dirty.clear();
    return exported;
}

std::vector<std::string> TreeVerifier::applyStored(
    const std::map<std::string, Pin>* exported,
    const PinSet& stored,
    bool wrote
) {
    std::vector<std::string> unlinked;
    bool forkedHere = false;
    {
        std::lock_guard lock(_mutex);
        std::set<std::string> groups;
        for (const auto& [groupId, record] : stored.tree) {
            groups.insert(groupId);
        }
        if (exported != nullptr) {
            for (const auto& [groupId, pin] : *exported) {
                groups.insert(groupId);
            }
        }
        for (const std::string& groupId : groups) {
            const auto r = stored.tree.find(groupId);
            const Pin* record = r == stored.tree.end() ? nullptr : &r->second;
            const auto c = _pins.find(groupId);
            Pin* current = c == _pins.end() ? nullptr : &c->second;
            const Pin* mine = current;
            if (exported != nullptr) {
                const auto e = exported->find(groupId);
                mine = e == exported->end() ? nullptr : &e->second;
            }
            const PinBlob::Case row = PinBlob::decide(mine, record);
            const bool asExported = exported == nullptr || sameState(mine, current);
            const bool realRecord = record != nullptr && record->seq > 0;
            if (row == PinBlob::Case::Fork) {
                if (current != nullptr && !current->forked) {
                    current->forked = true;
                    if (!wrote) {
                        _dirty.insert(groupId); // the slot does not say so yet
                        forkedHere = true;
                    }
                }
            } else if (asExported) {
                switch (row) {
                case PinBlob::Case::TakeMine:
                    if (wrote && current != nullptr && current->seq > 0) {
                        current->synced = stateOf(*current);
                    }
                    break;
                case PinBlob::Case::TakeStored: {
                    Pin taken = *record;
                    if (current != nullptr) {
                        taken.refusedSeq = std::max(taken.refusedSeq, current->refusedSeq);
                        taken.seenAt = std::max(taken.seenAt, current->seenAt);
                    }
                    taken.synced = stateOf(*record);
                    taken.firstContact = false;
                    taken.unlinked.reset();
                    _pins[groupId] = std::move(taken);
                    current = &_pins[groupId];
                    break;
                }
                case PinBlob::Case::Same:
                    current->synced = stateOf(*record);
                    break;
                case PinBlob::Case::Unlinked:
                    current->unlinked = std::make_shared<const Pin>(*record);
                    current->synced = stateOf(*record);
                    unlinked.push_back(groupId);
                    break;
                default: // Pending: a link is already due
                    break;
                }
            } else if (current != nullptr) {
                // Moved after the export, by steps of this instance from the exported pin.
                if (wrote && row == PinBlob::Case::TakeMine && mine != nullptr && mine->seq > 0) {
                    current->synced = stateOf(*mine);
                } else if (row == PinBlob::Case::Same) {
                    current->synced = stateOf(*record);
                } else if (realRecord && !current->unlinked &&
                           (current->seq != record->seq || current->digest != record->digest)) {
                    current->unlinked = std::make_shared<const Pin>(*record);
                    current->synced = stateOf(*record);
                    unlinked.push_back(groupId);
                }
            }
            if (record != nullptr && (current != nullptr || record->refusedSeq > 0)) {
                Pin& pin = current != nullptr ? *current : _pins[groupId];
                pin.refusedSeq = std::max(pin.refusedSeq, record->refusedSeq);
                pin.seenAt = std::max(pin.seenAt, record->seenAt);
            }
        }
    }
    if (forkedHere) {
        notify(true);
    }
    return unlinked;
}

void TreeVerifier::link(const std::string& groupId, const Environment& environment) {
    const Pin pin = pinOf(groupId);
    if (!pin.unlinked || pin.forked) {
        return;
    }
    const Pin& other = *pin.unlinked;
    bool linked = pin.seq == other.seq && pin.digest == other.digest;
    if (pin.seq != other.seq) {
        const Pin& lower = pin.seq < other.seq ? pin : other;
        const Pin& higher = pin.seq < other.seq ? other : pin;
        std::uint64_t seq = lower.seq;
        std::string digest = lower.digest;
        linked = true;
        while (linked && seq < higher.seq) {
            const server::GroupGetTreeCommitsResult answer = environment.commitsBetween(seq, higher.seq);
            if (answer.commits.empty() || answer.commits.size() > higher.seq - seq) {
                reject(); // withheld, not disproved: stays pending
            }
            for (const server::GroupTreeCommit& wire : answer.commits) {
                const CommitStatement statement = parse(wire);
                if (statement.seq != seq + 1 || statement.prevDigest != digest) {
                    linked = false;
                    break;
                }
                seq = statement.seq;
                digest = TreeCommits::digest(statement);
            }
        }
        linked = linked && digest == higher.digest;
    }
    std::optional<bool> moved;
    {
        std::lock_guard lock(_mutex);
        Pin& stored = _pins[groupId];
        if (stored.unlinked != pin.unlinked || stored.seq != pin.seq || stored.digest != pin.digest) {
            return; // moved meanwhile; the next use looks again
        }
        const Snapshot before = snapshotOf(stored);
        if (!linked) {
            stored.forked = true;
        } else if (other.seq > stored.seq) {
            Pin next = other;
            next.refusedSeq = std::max(next.refusedSeq, stored.refusedSeq);
            next.seenAt = std::max(next.seenAt, stored.seenAt);
            for (const auto& [node, generation] : stored.generations) {
                std::uint32_t& kept = next.generations[node];
                kept = std::max(kept, generation);
            }
            next.synced = stored.synced;
            next.firstContact = false;
            next.unlinked.reset();
            stored = std::move(next);
        } else {
            stored.unlinked.reset();
        }
        moved = movedLocked(groupId, before, stored, false);
        if (!moved.has_value()) {
            _dirty.insert(groupId); // the slot holds the other record: the next save writes this one
            moved = false;
        }
    }
    notify(moved);
}

bool TreeVerifier::needsRead(const std::string& groupId) {
    std::lock_guard lock(_mutex);
    const auto it = _pins.find(groupId);
    return it != _pins.end() && (it->second.forked || it->second.unlinked);
}

std::map<std::string, TreeVerifier::Pin> TreeVerifier::adoptable(const std::vector<std::string>& groups) {
    std::lock_guard lock(_mutex);
    std::map<std::string, Pin> result;
    for (const std::string& groupId : groups) {
        const auto it = _pins.find(groupId);
        if (it == _pins.end()) {
            result.emplace(groupId, Pin{});
        } else if (it->second.seq == 0 || it->second.firstContact) {
            result.emplace(groupId, compactOf(it->second));
        }
    }
    return result;
}

void TreeVerifier::adopt(const std::map<std::string, Pin>& taken, const std::map<std::string, Pin>& seen) {
    std::lock_guard lock(_mutex);
    for (const auto& [groupId, record] : taken) {
        const auto was = seen.find(groupId);
        const auto it = _pins.find(groupId);
        const Pin* current = it == _pins.end() ? nullptr : &it->second;
        const bool unchanged = was != seen.end() &&
            (current == nullptr ? was->second.seq == 0 && was->second.digest.empty()
                                : current->seq == was->second.seq && current->digest == was->second.digest);
        if (!unchanged) {
            continue; // verified meanwhile: the current identity's state stands
        }
        Pin adopted = record;
        adopted.refusedSeq = std::max(adopted.refusedSeq, current != nullptr ? current->refusedSeq : 0);
        adopted.synced = stateOf(record);
        adopted.firstContact = false;
        adopted.unlinked.reset();
        _pins[groupId] = std::move(adopted);
    }
}
