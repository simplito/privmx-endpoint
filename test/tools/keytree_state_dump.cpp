/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

/**
 * Emits the tree states this client produces, as JSON, so the bridge's structural validator can be run against
 * them in its own test suite.
 *
 * The two sides of this design have to agree exactly: the client submits a complete tree state and the server
 * accepts or rejects it on structure alone. Unit tests on either side can only check each half against its own
 * idea of the rules. This dump closes that gap — real EC keys, real ECIES, real plans on this side; the actual
 * production validator on the other. A disagreement shows up as a rejected state rather than as a subtle
 * divergence discovered in production.
 *
 * Wrapped blobs are reduced to a length and a digest by `shorten`. The consumer checks only that an edge
 * carries a ciphertext, never what is inside one, so whole ECIES blobs would multiply the fixture's size for no
 * added coverage. A prefix would be worse than useless, and was: the first 46 base64 characters of an ECIES blob
 * are a fixed header — version byte plus the signer's public key — so a truncated fixture showed the identical
 * string on all 33 edges of a tree.
 *
 * Every case is one commit by a named member: its `before` and `after` states (the after state by the bridge's
 * storage rule, `treetest::afterCommit`), the nodes it refreshed, the signed commit statement (`commit`, signature
 * in full), the post state's `treeHash` and roster (`users`, `managers`, `rosterVersion`). Removals also carry
 * `setters` (the committer of each statement `before`'s filled nodes cite) and `blanked` (what the removal blanks
 * besides the remover's path, ascending); additions carry `blanked: []`. Cases from the A-prime test vectors carry
 * their `id` ("V2" ...). Trees are version 3
 * (`treeVersion` at the top): buckets of 16 seats, blank nodes without a `publicKey`, filled ones with `setBy`.
 * Every user who signs is in the top-level `userPubKeys`; ids are global, so a user's key is the same in every case.
 * A group is "grp", except at seq 1 where its statement names the resourceId "res". Every case also carries the
 * group's policy and creator after its commit (`groupPolicy`, `groupCreator`), which the statement's `policyHash`
 * signs; `policy` cases are policy commits (T4-10), whose `before` and `after` are the same tree.
 *
 * Usage: keytree_state_dump > src/test/fixtures/keytree-states.json   (paths relative to the bridge repo)
 * See test/tools/README.md.
 */

#include <cstdint>
#include <functional>
#include <iostream>
#include <map>
#include <set>
#include <string>
#include <vector>

#include <Poco/JSON/Object.h>

#include <privmx/crypto/Crypto.hpp>
#include <privmx/crypto/ecc/PrivateKey.hpp>
#include <privmx/utils/Utils.hpp>

#include <privmx/endpoint/group/keytree/LadderKeys.hpp>
#include <privmx/endpoint/group/keytree/TreeCommits.hpp>
#include <privmx/endpoint/group/keytree/TreeKeys.hpp>
#include <privmx/endpoint/group/keytree/TreeMath.hpp>
#include <privmx/endpoint/group/keytree/TreeWire.hpp>

#include "TreeTestOps.hpp"

using privmx::crypto::PrivateKey;
using namespace privmx::endpoint::group;
using namespace privmx::endpoint::group::keytree;

namespace {

struct Member {
    std::string userId;
    PrivateKey priv;
};

// One key per user id for the whole dump, so `userPubKeys` can map ids to keys once.
std::map<std::string, PrivateKey>& userKeys() {
    static std::map<std::string, PrivateKey> keys;
    return keys;
}

Member memberNamed(const std::string& userId) {
    auto& keys = userKeys();
    const auto it = keys.find(userId);
    if (it != keys.end()) {
        return Member{userId, it->second};
    }
    const PrivateKey key = PrivateKey::generateRandom();
    keys.emplace(userId, key);
    return Member{userId, key};
}

std::vector<TreeMember> publicOf(const std::vector<Member>& members) {
    std::vector<TreeMember> result;
    for (const Member& member : members) {
        result.push_back(TreeMember{member.userId, member.priv.getPublicKey()});
    }
    return result;
}

// A digest keeps the fixture small while staying distinct per ciphertext, so the consumer can assert that a
// state does not repeat one wrap where it should carry many.
std::string shorten(const std::string& blob) {
    return "b64:" + std::to_string(blob.size()) + ":"
        + privmx::utils::Hex::from(privmx::crypto::Crypto::sha256(blob)).substr(0, 16);
}

std::string quote(const std::string& value) {
    std::string out = "\"";
    for (const char c : value) {
        if (c == '"' || c == '\\') {
            out += '\\';
        }
        out += c;
    }
    return out + "\"";
}

std::string treeToJson(const server::GroupTreeState& tree) {
    std::string out = "{\"numLeaves\":" + std::to_string(tree.numLeaves) + ",\"leafAssignment\":[";
    for (std::size_t i = 0; i < tree.leafAssignment.size(); ++i) {
        out += (i ? "," : "") + quote(tree.leafAssignment[i]);
    }
    out += "],\"nodes\":[";
    for (std::size_t i = 0; i < tree.nodes.size(); ++i) {
        const server::GroupTreeNode& node = tree.nodes[i];
        out += std::string(i ? "," : "") + "{\"nodeIndex\":" + std::to_string(node.nodeIndex)
            + ",\"generation\":" + std::to_string(node.generation);
        if (node.publicKey.has_value()) {
            out += ",\"publicKey\":" + quote(node.publicKey.value()); // absent: a blank node
        }
        if (node.setBy.has_value()) {
            out += ",\"setBy\":" + std::to_string(node.setBy.value());
        }
        out += "}";
    }
    out += "],\"edges\":[";
    for (std::size_t i = 0; i < tree.edges.size(); ++i) {
        const server::GroupTreeEdge& edge = tree.edges[i];
        out += std::string(i ? "," : "") + "{";
        if (edge.isGrantEdge.has_value() && edge.isGrantEdge.value()) {
            out += "\"isGrantEdge\":true,";
        }
        if (edge.parentIndex.has_value()) {
            out += "\"parentIndex\":" + std::to_string(edge.parentIndex.value()) + ",";
        }
        out += "\"parentGeneration\":" + std::to_string(edge.parentGeneration);
        out += ",\"childKind\":" + quote(edge.childKind);
        if (edge.childIndex.has_value()) {
            out += ",\"childIndex\":" + std::to_string(edge.childIndex.value());
        }
        if (edge.childGeneration.has_value()) {
            out += ",\"childGeneration\":" + std::to_string(edge.childGeneration.value());
        }
        if (edge.childUserId.has_value()) {
            out += ",\"childUserId\":" + quote(edge.childUserId.value());
        }
        out += ",\"data\":" + quote(shorten(edge.data)) + "}";
    }
    return out + "]}";
}

std::string idsToJson(const std::vector<std::string>& ids) {
    std::string out = "[";
    for (std::size_t i = 0; i < ids.size(); ++i) {
        out += (i ? "," : "") + quote(ids[i]);
    }
    return out + "]";
}

std::string seatsToJson(const std::vector<std::uint32_t>& seats) {
    std::string out = "[";
    for (std::size_t i = 0; i < seats.size(); ++i) {
        out += (i ? "," : "") + std::to_string(seats[i]);
    }
    return out + "]";
}

// The refreshed nodes as the transition sends them, keys omitted (they are in `after`).
std::string refreshedToJson(const CommitPlan& plan) {
    std::string out = "[";
    for (std::size_t i = 0; i < plan.refreshed.size(); ++i) {
        const RefreshedNode& node = plan.refreshed[i];
        out += std::string(i ? "," : "") + "{\"nodeIndex\":" + std::to_string(node.nodeIndex);
        if (node.fromGeneration.has_value()) {
            out += ",\"fromGeneration\":" + std::to_string(node.fromGeneration.value());
        }
        out += ",\"generation\":" + std::to_string(node.generation) + "}";
    }
    return out + "]";
}

// A tree-backed group as the bridge stores it, with the members' private halves.
struct Group {
    std::vector<Member> members;
    server::GroupTreeState tree;
    std::uint32_t epoch = 1;
    PrivateKey grantKey;
    std::uint64_t commitSeq = 0;
    std::map<std::uint64_t, std::string> setters; // statement seq -> committer
    std::int64_t rosterVersion = 0;
    TreeKeyCache grantKeys; // every epoch's grant key, for the rungs a removal publishes
    std::string lastDigest; // of the latest statement, which the next one chains to
    std::string creator;
    Poco::Dynamic::Var policy = Poco::JSON::Object::Ptr(new Poco::JSON::Object());

    std::vector<std::string> seated() const {
        std::vector<std::string> ids;
        for (const std::string& seat : tree.leafAssignment) {
            if (!seat.empty()) {
                ids.push_back(seat);
            }
        }
        return ids;
    }

    const Member& member(const std::string& userId) const {
        for (const Member& m : members) {
            if (m.userId == userId) {
                return m;
            }
        }
        throw std::runtime_error("no member " + userId);
    }
};

// `statement` signed by its committer and chained to the group's latest, plus what it describes.
std::string signedJson(Group& group, CommitStatement statement) {
    statement.policyHash = TreeCommits::rules(group.policy, group.creator).hash;
    if (statement.op == CommitOp::Create || statement.op == CommitOp::Policy) {
        statement.policy = group.policy;
    }
    statement.prevDigest = statement.seq == 1 ? "" : group.lastDigest;
    TreeCommits::sign(statement, userKeys().at(statement.committer));
    group.lastDigest = TreeCommits::digest(statement);
    const TreeGroupState post = TreeWire::toRuntime(group.tree, group.epoch, group.grantKey.getPublicKey());
    const std::string treeHash = privmx::utils::Hex::from(TreeCommits::treeHash(post));
    if (treeHash != privmx::utils::Hex::from(statement.treeHash)) {
        throw std::runtime_error("the stored state does not hash to what the statement signs");
    }
    return ",\"commit\":" + privmx::utils::Utils::stringify(TreeCommits::toWire(statement).toJSON())
        + ",\"digest\":" + quote(privmx::utils::Hex::from(group.lastDigest))
        + ",\"treeHash\":" + quote(treeHash) + ",\"rosterVersion\":" + std::to_string(group.rosterVersion)
        + ",\"users\":" + idsToJson(group.seated()) + ",\"managers\":[]"
        + ",\"groupPolicy\":" + privmx::utils::Utils::stringifyVar(group.policy)
        + ",\"groupCreator\":" + quote(group.creator);
}

// The statement for a commit already applied to `group`, as the endpoint signs it, plus what it describes.
std::string statementJson(
    Group& group,
    const CommitPlan& plan,
    CommitOp op,
    const std::string& committer,
    std::vector<std::string> added,
    std::vector<std::string> removed
) {
    return signedJson(
        group, TreeCommits::statementFor(
                   plan, op, plan.seq == 1 ? "res" : "grp", 1760000000000 + plan.seq, group.epoch,
                   group.grantKey.getPublicKey().toBase58DER(), static_cast<std::uint64_t>(group.rosterVersion),
                   group.seated(), {}, committer, std::move(added), {}, std::move(removed), std::string()
               )
    );
}

std::string groupCreate(Group& group, std::uint32_t count, std::uint32_t creator) {
    for (std::uint32_t i = 0; i < count; ++i) {
        group.members.push_back(memberNamed("u" + std::to_string(i)));
    }
    TreeKeyCache scratch;
    TreeKeys keys(scratch);
    const CommitPlan plan =
        keys.planCreate(publicOf(group.members), group.members[creator].userId, group.members[creator].priv);
    group.tree = TreeWire::toCreateTree(plan);
    group.grantKey = plan.grantKey;
    group.grantKeys.putGrantKey(1, plan.grantKey);
    group.commitSeq = 1;
    group.setters[1] = group.members[creator].userId;
    group.rosterVersion = 1;
    group.creator = group.members[creator].userId;
    return "{\"kind\":\"create\",\"epoch\":1,\"creator\":" + quote(group.members[creator].userId)
        + ",\"members\":" + idsToJson(group.seated()) + ",\"refreshed\":" + refreshedToJson(plan)
        + statementJson(group, plan, CommitOp::Create, group.members[creator].userId, {}, {})
        + ",\"tree\":" + treeToJson(group.tree) + "}";
}

// Plans as `committer` from what it can climb, and stores the commit the way the bridge does.
CommitPlan commitBy(
    Group& group,
    const std::string& committer,
    const std::function<CommitPlan(TreeKeys&, const TreeGroupState&, const Member&)>& plan
) {
    const Member& who = group.member(committer);
    TreeGroupState state = TreeWire::toRuntime(group.tree, group.epoch, group.grantKey.getPublicKey());
    state.commitSeq = group.commitSeq;
    state.setters = group.setters;
    TreeKeyCache cache;
    TreeKeys keys(cache);
    if (keys.climbToGrantKey(state, who.userId, who.priv, false).failure != ClimbFailure::None) {
        throw std::runtime_error(committer + " cannot climb");
    }
    treetest::setMemberKeys(keys, publicOf(group.members));
    const CommitPlan result = plan(keys, state, who);
    group.tree = treetest::afterCommit(group.tree, result);
    group.epoch = result.epoch;
    group.grantKey = result.grantKey;
    group.grantKeys.putGrantKey(result.epoch, result.grantKey);
    group.commitSeq = result.seq;
    group.setters[result.seq] = committer;
    return result;
}

std::string groupRemove(Group& group, const std::string& remover, const std::vector<std::string>& leaving) {
    const server::GroupTreeState before = group.tree;
    std::string setters = "{";
    std::set<std::int64_t> cited;
    for (const server::GroupTreeNode& node : before.nodes) {
        if (node.publicKey.has_value() && node.setBy.has_value() && cited.insert(node.setBy.value()).second) {
            setters += std::string(setters.size() > 1 ? "," : "") + quote(std::to_string(node.setBy.value())) + ":"
                + quote(group.setters.at(static_cast<std::uint64_t>(node.setBy.value())));
        }
    }
    setters += "}";
    const std::vector<std::string> members = group.seated();
    const std::uint32_t beforeEpoch = group.epoch;
    const CommitPlan plan = commitBy(group, remover, [&](TreeKeys& keys, const TreeGroupState& state, const Member& who) {
        return keys.planRemoval(state, leaving, who.userId, who.priv);
    });
    group.rosterVersion += 1;

    // Unit rung only: no archive is gathered here for the aligned skip targets. A real rotation owes the full set.
    LadderKeys ladder(group.grantKeys);
    const std::vector<ArchiveRung> rungs = ladder.buildRungs(
        plan.epoch, plan.grantKey.getPublicKey(), group.grantKeys.getGrantKey(beforeEpoch), 1, remover,
        group.member(remover).priv, false
    );
    std::string rungJson = "[";
    for (std::size_t i = 0; i < rungs.size(); ++i) {
        rungJson += std::string(i ? "," : "") + "{\"at\":" + std::to_string(rungs[i].span.at)
            + ",\"target\":" + std::to_string(rungs[i].span.target) + "}";
    }
    rungJson += "]";

    return "{\"kind\":\"remove\",\"beforeEpoch\":" + std::to_string(beforeEpoch) + ",\"afterEpoch\":"
        + std::to_string(plan.epoch) + ",\"remover\":" + quote(remover) + ",\"removed\":" + idsToJson(leaving)
        + ",\"positions\":" + seatsToJson(plan.shape.subjectSeats) + ",\"members\":" + idsToJson(members)
        + ",\"remaining\":" + idsToJson(group.seated()) + ",\"refreshed\":" + refreshedToJson(plan)
        + ",\"setters\":" + setters + ",\"blanked\":"
        + seatsToJson(std::vector<std::uint32_t>(plan.shape.blanked.begin(), plan.shape.blanked.end()))
        + statementJson(group, plan, CommitOp::Remove, remover, {}, leaving) + ",\"rungs\":" + rungJson
        + ",\"before\":" + treeToJson(before) + ",\"after\":" + treeToJson(group.tree) + "}";
}

std::string groupAdd(Group& group, const std::string& adder, std::uint32_t count) {
    const server::GroupTreeState before = group.tree;
    const std::vector<std::string> members = group.seated();
    static std::uint32_t nextNewcomer = 0;
    std::vector<Member> newcomers;
    for (std::uint32_t i = 0; i < count; ++i) {
        newcomers.push_back(memberNamed("n" + std::to_string(nextNewcomer++)));
    }
    group.members.insert(group.members.end(), newcomers.begin(), newcomers.end());
    std::vector<std::string> added;
    for (const Member& newcomer : newcomers) {
        added.push_back(newcomer.userId);
    }
    const CommitPlan plan = commitBy(group, adder, [&](TreeKeys& keys, const TreeGroupState& state, const Member& who) {
        return keys.planAddition(
            state, publicOf(newcomers), treetest::choosePositions(state, count), who.userId, who.priv
        );
    });
    group.rosterVersion += 1;
    return "{\"kind\":\"add\",\"epoch\":" + std::to_string(group.epoch) + ",\"adder\":" + quote(adder)
        + ",\"added\":" + idsToJson(added) + ",\"positions\":" + seatsToJson(plan.shape.subjectSeats)
        + ",\"members\":" + idsToJson(members) + ",\"after_members\":" + idsToJson(group.seated())
        + ",\"refreshed\":" + refreshedToJson(plan) + ",\"blanked\":"
        + seatsToJson(std::vector<std::uint32_t>(plan.shape.blanked.begin(), plan.shape.blanked.end()))
        + statementJson(group, plan, CommitOp::Add, adder, added, {})
        + ",\"before\":" + treeToJson(before) + ",\"after\":" + treeToJson(group.tree) + "}";
}

std::string groupSelfUpdate(Group& group, const std::string& memberId) {
    const server::GroupTreeState before = group.tree;
    const CommitPlan plan = commitBy(group, memberId, [&](TreeKeys& keys, const TreeGroupState& state, const Member& who) {
        return keys.planSelfUpdate(state, who.userId, who.priv);
    });
    return "{\"kind\":\"selfUpdate\",\"epoch\":" + std::to_string(group.epoch) + ",\"member\":" + quote(memberId)
        + ",\"members\":" + idsToJson(group.seated()) + ",\"refreshed\":" + refreshedToJson(plan)
        + statementJson(group, plan, CommitOp::SelfUpdate, memberId, {}, {}) + ",\"before\":" + treeToJson(before)
        + ",\"after\":" + treeToJson(group.tree) + "}";
}

// A policy commit by `memberId`, as `GroupApiImpl::updateGroupPolicy` signs it: everything as the latest statement
// says but the policy.
std::string groupPolicyChange(Group& group, const std::string& memberId, const Poco::Dynamic::Var& policy) {
    group.policy = policy;
    const TreeGroupState post = TreeWire::toRuntime(group.tree, group.epoch, group.grantKey.getPublicKey());
    CommitStatement statement;
    statement.seq = ++group.commitSeq;
    statement.op = CommitOp::Policy;
    statement.groupId = "grp";
    statement.treeVersion = TreeMath::TREE_VERSION;
    statement.date = 1760000000000 + statement.seq;
    statement.keyVersion = group.epoch;
    statement.groupPubKey = group.grantKey.getPublicKey().toBase58DER();
    statement.rosterVersion = static_cast<std::uint64_t>(group.rosterVersion);
    statement.rosterHash = TreeCommits::rosterHash(group.seated(), {});
    statement.treeHash = TreeCommits::treeHash(post);
    statement.committer = memberId;
    for (std::size_t i = 0; i < group.tree.leafAssignment.size(); ++i) {
        if (group.tree.leafAssignment[i] == memberId) {
            statement.committerSeat = static_cast<std::uint32_t>(i);
        }
    }
    group.setters[statement.seq] = memberId;
    return "{\"kind\":\"policy\",\"epoch\":" + std::to_string(group.epoch) + ",\"member\":" + quote(memberId)
        + ",\"members\":" + idsToJson(group.seated()) + ",\"policy\":" + privmx::utils::Utils::stringifyVar(policy)
        + ",\"refreshed\":[]" + signedJson(group, statement) + ",\"before\":" + treeToJson(group.tree)
        + ",\"after\":" + treeToJson(group.tree) + "}";
}

Poco::Dynamic::Var policyOf(const std::map<std::string, std::string>& rules) {
    Poco::JSON::Object::Ptr policy = new Poco::JSON::Object();
    for (const auto& [field, rule] : rules) {
        policy->set(field, rule);
    }
    return policy;
}

std::string u(std::uint32_t i) {
    return "u" + std::to_string(i);
}

// Tags a case with its test-vector id.
std::string tagged(const std::string& id, const std::string& json) {
    return "{\"id\":" + quote(id) + "," + json.substr(1);
}

// Checks a vector's blank set as the spec computed it, so a drift fails here rather than in the bridge's suite.
std::string expectBlanked(const std::string& json, const std::string& blanked) {
    if (json.find(",\"blanked\":" + blanked + ",") == std::string::npos) {
        throw std::runtime_error("expected blanked " + blanked);
    }
    return json;
}

} // namespace

int main() {
    std::vector<std::string> cases;
    try {
        // ── creation, across sizes: one keyed node up to 32 seats, then buckets below the root ──
        for (const std::uint32_t count : {1u, 2u, 3u, 4u, 5u, 8u, 16u, 17u, 31u, 32u, 33u, 40u}) {
            Group group;
            cases.push_back(groupCreate(group, count, 0));
        }
        {
            Group group;
            cases.push_back(groupCreate(group, 40, 39)); // a creator on the truncated right edge
        }

        // ── removals: every position of small trees, and the cases that leave blanks above the buckets ──
        for (const std::uint32_t count : {2u, 5u, 17u}) {
            for (std::uint32_t position = 0; position < count; ++position) {
                Group group;
                groupCreate(group, count, 0);
                cases.push_back(groupRemove(group, u(position == 0 ? 1 : 0), {u(position)}));
            }
        }
        struct Removal {
            std::uint32_t count;
            std::uint32_t remover;
            std::vector<std::uint32_t> leaving;
        };
        for (const Removal& removal : std::vector<Removal>{
                 {33, 32, {0}},     // node 31 blanked
                 {33, 0, {32}},     // the remover's own path covers everything
                 {40, 35, {5}},     // node 31 blanked, the root wraps through it to 31 members
                 {40, 1, {0}},      // the creator removed by its bucket neighbour
                 {40, 0, {3, 34}},  // a batch across both halves
             }) {
            Group group;
            groupCreate(group, removal.count, 0);
            std::vector<std::string> leaving;
            for (const std::uint32_t index : removal.leaving) {
                leaving.push_back(u(index));
            }
            cases.push_back(groupRemove(group, u(removal.remover), leaving));
        }

        // ── additions: appends that grow the tree (and move or drop the old root), and blanks refilled ──
        for (const std::uint32_t count : {1u, 2u, 4u, 16u, 32u, 40u}) {
            Group group;
            groupCreate(group, count, 0);
            cases.push_back(groupAdd(group, u(0), 1));
        }
        {
            Group group;
            groupCreate(group, 30, 2);
            cases.push_back(groupAdd(group, u(2), 4)); // a batch across 32
        }
        {
            Group group;
            groupCreate(group, 40, 0);
            groupRemove(group, u(35), {u(5)});
            cases.push_back(groupAdd(group, u(35), 1)); // seat 5 refilled from outside node 31
        }
        {
            Group group;
            groupCreate(group, 5, 0);
            groupRemove(group, u(0), {u(4)});
            cases.push_back(groupAdd(group, u(1), 1));
        }

        // ── A-prime vectors: dense creation, fills by the adder, and the knowledge closure a removal blanks ──
        {
            Group group;
            cases.push_back(tagged("V1", groupCreate(group, 64, 0)));
        }
        {
            Group group;
            groupCreate(group, 64, 0);
            cases.push_back(tagged("V2", expectBlanked(groupRemove(group, u(40), {u(0)}), "[31]")));
        }
        {
            Group group;
            groupCreate(group, 64, 0);
            groupSelfUpdate(group, u(40));
            cases.push_back(tagged("V3", expectBlanked(groupRemove(group, u(5), {u(0)}), "[]")));
        }
        {
            Group group;
            groupCreate(group, 64, 0);
            cases.push_back(tagged("V4", expectBlanked(groupRemove(group, u(5), {u(40)}), "[95]")));
        }
        {
            Group group;
            groupCreate(group, 128, 0);
            groupSelfUpdate(group, u(40));
            cases.push_back(tagged("V5", expectBlanked(groupRemove(group, u(100), {u(0)}), "[31,63,159]")));
        }
        {
            Group group;
            groupCreate(group, 128, 0);
            groupSelfUpdate(group, u(40));
            groupSelfUpdate(group, u(70));
            groupSelfUpdate(group, u(100));
            cases.push_back(tagged("V6", expectBlanked(groupRemove(group, u(40), {u(0), u(70)}), "[31,159,191]")));
        }
        {
            Group group;
            groupCreate(group, 64, 0);
            groupRemove(group, u(40), {u(5)});
            cases.push_back(tagged("V7", expectBlanked(groupAdd(group, u(40), 1), "[]")));
            cases.push_back(tagged("V8", expectBlanked(groupRemove(group, u(0), {u(40)}), "[95]")));
        }
        {
            Group group;
            groupCreate(group, 64, 0);
            groupSelfUpdate(group, u(40));
            groupRemove(group, u(5), {u(41)});
            groupAdd(group, u(0), 1);
            cases.push_back(tagged("V9", expectBlanked(groupRemove(group, u(40), {u(0)}), "[31]")));
        }
        {
            Group group;
            groupCreate(group, 64, 0);
            cases.push_back(tagged("V10", expectBlanked(groupRemove(group, u(40), {u(0), u(63)}), "[31]")));
        }

        // ── self-updates: refilling a blank, and a plain refresh ──
        {
            Group group;
            groupCreate(group, 40, 0);
            groupRemove(group, u(35), {u(5)});
            cases.push_back(groupSelfUpdate(group, u(9)));
            cases.push_back(groupSelfUpdate(group, u(36)));
        }
        {
            Group group;
            groupCreate(group, 2, 0);
            cases.push_back(groupSelfUpdate(group, u(1)));
        }

        // ── policy commits: a change, a commit under the new rules, and back to the defaults ──
        {
            Group group;
            groupCreate(group, 5, 0);
            cases.push_back(groupPolicyChange(group, u(0), policyOf({{"update", "user"}, {"get", "all"}})));
            cases.push_back(groupRemove(group, u(3), {u(4)}));
            cases.push_back(groupPolicyChange(group, u(1), policyOf({})));
            cases.push_back(groupSelfUpdate(group, u(2)));
        }
    } catch (const std::exception& e) {
        std::cerr << "keytree_state_dump: " << e.what() << "\n";
        return 1;
    }

    std::string userPubKeys = "{";
    for (const auto& [userId, key] : userKeys()) {
        userPubKeys += std::string(userPubKeys.size() > 1 ? "," : "") + quote(userId) + ":"
            + quote(key.getPublicKey().toBase58DER());
    }
    userPubKeys += "}";
    std::cout << "{\"treeVersion\":" << TreeMath::TREE_VERSION << ",\"bucketLevel\":" << TreeMath::BUCKET_LEVEL
              << ",\"userPubKeys\":" << userPubKeys << ",\"cases\":[\n";
    for (std::size_t i = 0; i < cases.size(); ++i) {
        std::cout << (i ? ",\n" : "") << cases[i];
    }
    std::cout << "\n]}\n";
    return 0;
}
