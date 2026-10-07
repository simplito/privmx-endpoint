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

#include "privmx/endpoint/group/GroupException.hpp"
#include "privmx/endpoint/group/keytree/TreeMath.hpp"
#include "privmx/endpoint/group/keytree/TreeWire.hpp"

using namespace privmx::endpoint::group::keytree;
namespace server = privmx::endpoint::group::server;
using privmx::endpoint::group::GroupDataIntegrityException;
using privmx::endpoint::group::GroupHistoryForkException;

namespace {

[[noreturn]] void reject() {
    throw GroupDataIntegrityException();
}

CommitStatement parse(const server::GroupTreeCommit& wire) {
    try {
        return TreeCommits::fromWire(wire);
    } catch (const std::invalid_argument&) { reject(); }
}

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

// The latest statement describes exactly what is served: grant key, counters, roster.
template<typename TGroup>
bool describes(const CommitStatement& latest, const TGroup& group) {
    return latest.keyVersion == static_cast<std::uint64_t>(group.keyVersion) &&
        latest.groupPubKey == group.groupPubKey &&
        latest.rosterVersion == static_cast<std::uint64_t>(group.rosterVersion) &&
        latest.rosterHash == TreeCommits::rosterHash(group.users, group.managers);
}

bool seatedAt(const TreeGroupState& state, std::uint32_t seat, const std::string& userId) {
    return seat < state.numLeaves && seat < state.leafAssignment.size() && state.leafAssignment[seat] == userId;
}

} // namespace

void TreeVerifier::verifyStatements(
    const std::string& groupId,
    const std::string& resourceId,
    const std::string& contextId,
    const std::vector<CommitStatement>& statements,
    const Environment& environment
) {
    std::vector<const CommitStatement*> unchecked;
    {
        std::lock_guard lock(_mutex);
        for (const CommitStatement& statement : statements) {
            if (_verifiedStatements.count(groupId + "|" + TreeCommits::digest(statement)) == 0) {
                unchecked.push_back(&statement);
            }
        }
    }
    if (unchecked.empty()) {
        return;
    }
    std::vector<core::VerificationRequest> requests;
    for (const CommitStatement* statement : unchecked) {
        // A statement names its group, which has no id yet at seq 1: the creator signs its resourceId instead.
        const std::string& expectedGroup = statement->seq == 1 ? resourceId : groupId;
        if (statement->groupId != expectedGroup ||
            statement->groupId.empty() ||
            statement->treeVersion != TreeMath::TREE_VERSION) {
            reject();
        }
        try {
            const auto publicKey = privmx::crypto::PublicKeyCache::getInstance()->fromBase58DER(
                statement->committerPubKey
            );
            if (!TreeCommits::verifySignature(*statement, publicKey)) {
                reject();
            }
        } catch (const GroupDataIntegrityException&) { throw; } catch (...) {
            reject();
        }
        // The key the committer signed with, at the time it signed, as the application vouches for its users —
        // the same check a metadata entry's author gets.
        requests.push_back(
            core::VerificationRequest{
                .contextId = contextId,
                .senderId = statement->committer,
                .senderPubKey = statement->committerPubKey,
                .date = static_cast<std::int64_t>(statement->date),
                .bridgeIdentity = std::nullopt
            }
        );
    }
    const std::vector<bool> verified = environment.verifyUsers(requests);
    if (verified.size() != requests.size() || std::find(verified.begin(), verified.end(), false) != verified.end()) {
        reject();
    }
    std::lock_guard lock(_mutex);
    for (const CommitStatement* statement : unchecked) {
        _verifiedStatements.insert(groupId + "|" + TreeCommits::digest(*statement));
    }
}

void TreeVerifier::verifyChain(
    const std::string& groupId,
    const std::string& resourceId,
    const std::string& contextId,
    const Pin& pin,
    const CommitStatement& latest,
    const Environment& environment
) {
    std::vector<CommitStatement> chain;
    for (const server::GroupTreeCommit& wire : environment.commitsBetween(pin.seq, latest.seq)) {
        chain.push_back(parse(wire));
    }
    if (chain.empty() || TreeCommits::digest(chain.back()) != TreeCommits::digest(latest)) {
        reject();
    }
    verifyStatements(groupId, resourceId, contextId, chain, environment);

    std::set<std::string> users = pin.users;
    std::set<std::string> managers = pin.managers;
    std::uint64_t seq = pin.seq;
    std::uint64_t keyVersion = pin.keyVersion;
    std::uint64_t rosterVersion = pin.rosterVersion;
    for (const CommitStatement& statement : chain) {
        // Signed by somebody who was a member when it was made: a non-member's statement is the bridge's.
        if (statement.seq != seq + 1 ||
            (users.count(statement.committer) == 0 && managers.count(statement.committer) == 0) ||
            statement.keyVersion < keyVersion ||
            statement.rosterVersion < rosterVersion) {
            reject();
        }
        users.insert(statement.addedUsers.begin(), statement.addedUsers.end());
        managers.insert(statement.addedManagers.begin(), statement.addedManagers.end());
        for (const std::string& gone : statement.removed) {
            users.erase(gone);
            managers.erase(gone);
        }
        if (TreeCommits::rosterHash({users.begin(), users.end()}, {managers.begin(), managers.end()}) !=
            statement.rosterHash) {
            reject();
        }
        seq = statement.seq;
        keyVersion = statement.keyVersion;
        rosterVersion = statement.rosterVersion;
    }
}

void TreeVerifier::verify(const server::GroupInfo& group, Scope scope, const Environment& environment) {
    if (!group.treeCommit.has_value()) {
        reject();
    }
    const CommitStatement latest = parse(group.treeCommit.value());

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
    try {
        if (scope == Scope::Plan) {
            treeHash = TreeCommits::treeHash(state);
        } else {
            if (!group.ownLeafPosition.has_value() ||
                group.ownLeafPosition.value() < 0 ||
                group.ownLeafPosition.value() >= static_cast<std::int64_t>(state.numLeaves) ||
                !group.copathHashes.has_value()) {
                reject();
            }
            treeHash = TreeCommits::treeHashAlongPath(
                state, static_cast<std::uint32_t>(group.ownLeafPosition.value()), group.copathHashes.value()
            );
        }
    } catch (const std::invalid_argument&) { reject(); }
    if (treeHash != latest.treeHash) {
        reject();
    }

    // Each filled node vouched for by the statement that set it, whose committer still sits under it — so a key
    // somebody planted in another member's subtree is refused even when the state around it hashes right.
    std::vector<CommitStatement> toVerify{latest};
    std::set<std::uint64_t> cited;
    std::set<std::uint32_t> recorded;
    for (const TreeNodeState& node : state.nodes) {
        if (!TreeMath::isKeyed(node.nodeIndex, state.numLeaves)) {
            reject(); // not part of the tree, and not covered by its hash
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
                entry.publicKey == node.publicKey->toBase58DER();
        });
        if (!listed || !seatedAt(state, statement.committerSeat, statement.committer)) {
            reject();
        }
        const auto path = TreeMath::directPath(statement.committerSeat, state.numLeaves);
        if (std::find(path.begin(), path.end(), node.nodeIndex) == path.end()) {
            reject();
        }
        if (cited.insert(statement.seq).second && statement.seq != latest.seq) {
            toVerify.push_back(statement);
        }
    }
    verifyStatements(group.id, group.resourceId.value_or(""), group.contextId, toVerify, environment);

    // History: never behind what this session has verified, and connected to it by statements of members.
    Pin pin;
    bool pinned = false;
    {
        std::lock_guard lock(_mutex);
        const auto it = _pins.find(group.id);
        if (it != _pins.end()) {
            pin = it->second;
            pinned = true;
        }
    }
    if (pinned) {
        if (latest.seq < pin.seq || (latest.seq == pin.seq && latest.treeHash != pin.treeHash)) {
            throw GroupHistoryForkException();
        }
        if (latest.seq > pin.seq) {
            verifyChain(group.id, group.resourceId.value_or(""), group.contextId, pin, latest, environment);
        }
    } else {
        // Trust on first use: the latest genuine statement, by somebody on the roster it attests.
        if (!onRoster(group.users, group.managers, latest.committer)) {
            reject();
        }
    }
    for (const TreeNodeState& node : state.nodes) {
        const auto seen = pin.generations.find(node.nodeIndex);
        if (seen != pin.generations.end() && node.generation < seen->second) {
            throw GroupHistoryForkException(); // a node served at a generation older than one already seen
        }
    }

    // Everything passed; only now does this state become the reference for the next read.
    std::lock_guard lock(_mutex);
    Pin& stored = _pins[group.id];
    if (stored.seq > latest.seq ||
        (stored.seq == latest.seq && !stored.treeHash.empty() && stored.treeHash != latest.treeHash)) {
        throw GroupHistoryForkException(); // a concurrent verification got further, with a different history
    }
    stored.seq = latest.seq;
    stored.treeHash = latest.treeHash;
    stored.digest = TreeCommits::digest(latest);
    stored.users = asSet(group.users);
    stored.managers = asSet(group.managers);
    stored.keyVersion = latest.keyVersion;
    stored.rosterVersion = latest.rosterVersion;
    for (const TreeNodeState& node : state.nodes) {
        std::uint32_t& generation = stored.generations[node.nodeIndex];
        generation = std::max(generation, node.generation);
    }
}

void TreeVerifier::verifyListed(const server::GroupSummary& summary, const Environment& environment) {
    if (!summary.treeCommit.has_value()) {
        reject();
    }
    const CommitStatement latest = parse(summary.treeCommit.value());
    if (!describes(latest, summary) || !onRoster(summary.users, summary.managers, latest.committer)) {
        reject();
    }
    verifyStatements(summary.id, summary.resourceId.value_or(""), summary.contextId, {latest}, environment);

    // A group this process has verified is taken only as a continuation of that state; below the pin is the caller's.
    std::optional<Pin> pin;
    {
        std::lock_guard lock(_mutex);
        const auto it = _pins.find(summary.id);
        if (it != _pins.end()) {
            pin = it->second;
        }
    }
    if (!pin.has_value() || latest.seq < pin->seq) {
        return;
    }
    if (latest.seq == pin->seq) {
        if (TreeCommits::digest(latest) != pin->digest) {
            throw GroupHistoryForkException(); // at the pinned seq, only the pinned statement
        }
        return;
    }
    verifyChain(summary.id, summary.resourceId.value_or(""), summary.contextId, pin.value(), latest, environment);
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

void TreeVerifier::forget(const std::string& groupId) {
    std::lock_guard lock(_mutex);
    _pins.erase(groupId);
    for (auto it = _verifiedStatements.lower_bound(groupId + "|");
         it != _verifiedStatements.end() && it->compare(0, groupId.size() + 1, groupId + "|") == 0;) {
        it = _verifiedStatements.erase(it);
    }
}

std::uint64_t TreeVerifier::pinnedSeq(const std::string& groupId) {
    std::lock_guard lock(_mutex);
    const auto it = _pins.find(groupId);
    return it == _pins.end() ? 0 : it->second.seq;
}
