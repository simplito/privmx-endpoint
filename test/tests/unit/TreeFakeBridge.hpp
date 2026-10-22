/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

// The bridge's key tree storage rule and `groupGet` views, for unit tests that put a client in front of a bridge.

#ifndef _PRIVMXLIB_TEST_UNIT_TREEFAKEBRIDGE_HPP_
#define _PRIVMXLIB_TEST_UNIT_TREEFAKEBRIDGE_HPP_

#include <gtest/gtest.h>

#include <algorithm>
#include <functional>
#include <map>
#include <optional>
#include <set>
#include <string>
#include <vector>

#include <Poco/JSON/Object.h>

#include <privmx/crypto/ecc/PrivateKey.hpp>
#include <privmx/utils/PrivmxException.hpp>
#include <privmx/utils/Utils.hpp>

#include <privmx/endpoint/group/keytree/TreeCommits.hpp>
#include <privmx/endpoint/group/keytree/TreeMath.hpp>

#include "TestHelpers.hpp"
#include <privmx/endpoint/group/keytree/TreeWire.hpp>

namespace {

using privmx::crypto::PrivateKey;
using namespace privmx::endpoint::group;
using namespace privmx::endpoint::group::keytree;

// What the bridge derives from the context and the resourceId the genesis statement signs.
const std::string GROUP_ID = TreeCommits::groupId("ctx", "res");

// What the test groups are created with unless a test says otherwise: every member may commit, so the existing tests,
// whose removers and adders are plain users, keep their meaning.
const Poco::Dynamic::Var OPEN_POLICY = policyOf({{"update", "user"}, {"rotateKeys", "user"}, {"updatePolicy", "user"}});

// A bridge refusal answering a statement that does not extend the stored latest: a lost race, retryable.
[[noreturn]] void rotatedAlready() {
    throw privmx::utils::PrivmxException("ROTATED_ALREADY", privmx::utils::PrivmxException::RPC, 0x621C);
}

struct Member {
    std::string userId;
    PrivateKey priv;
    privmx::crypto::PublicKey publicKey;
    std::string pub;
};

const TreeNodeState* recordOf(const TreeGroupState& state, std::uint32_t nodeIndex) {
    for (const TreeNodeState& node : state.nodes) {
        if (node.nodeIndex == nodeIndex) {
            return &node;
        }
    }
    return nullptr;
}

std::optional<std::uint32_t> seatOf(const TreeGroupState& state, const std::string& userId) {
    for (std::size_t i = 0; i < state.leafAssignment.size(); ++i) {
        if (state.leafAssignment[i] == userId) {
            return static_cast<std::uint32_t>(i);
        }
    }
    return std::nullopt;
}

std::vector<std::string> seatedIn(const TreeGroupState& state) {
    std::vector<std::string> ids;
    for (const auto& seat : state.leafAssignment) {
        if (seat.has_value()) {
            ids.push_back(seat.value());
        }
    }
    return ids;
}

std::vector<TreeEdge> edgesOf(const std::vector<server::GroupTreeEdge>& wire) {
    server::GroupTreeState carrier;
    carrier.numLeaves = 1;
    carrier.edges = wire;
    return TreeWire::toRuntime(carrier, 0, PrivateKey::generateRandom().getPublicKey()).edges;
}

// The resolution, written again from the spec rather than borrowed from the code under test.
void resolve(const TreeGroupState& state, std::uint32_t node, std::vector<std::string>& out) {
    if (TreeMath::isLeaf(node)) {
        const auto& seat = state.leafAssignment[TreeMath::leafPosition(node)];
        if (seat.has_value()) {
            out.push_back("user:" + seat.value());
        }
        return;
    }
    const TreeNodeState* record = recordOf(state, node);
    if (TreeMath::isKeyed(node, state.numLeaves) && record != nullptr && record->publicKey.has_value()) {
        out.push_back("node:" + std::to_string(node) + "@" + std::to_string(record->generation));
        return;
    }
    for (const std::uint32_t child : TreeMath::children(node, state.numLeaves)) {
        resolve(state, child, out);
    }
}

// `node` if keyed, and every keyed node above it up to the root.
std::set<std::uint32_t> up(std::uint32_t node, std::uint32_t numLeaves) {
    std::set<std::uint32_t> above;
    while (true) {
        if (TreeMath::isKeyed(node, numLeaves)) {
            above.insert(node);
        }
        if (node == TreeMath::root(numLeaves)) {
            return above;
        }
        node = TreeMath::parent(node, numLeaves);
    }
}

std::string edgeIdentity(const TreeEdge& edge) {
    const std::string child = edge.childKind == EdgeChildKind::User ?
        "user:" + edge.childUserId :
        "node:" + std::to_string(edge.childIndex) + "@" + std::to_string(edge.childGeneration);
    if (edge.isGrantEdge) {
        return "grant@" + std::to_string(edge.parentGeneration) + ">" + child;
    }
    return std::to_string(edge.parentIndex) + "@" + std::to_string(edge.parentGeneration) + ">" + child;
}

// What the bridge holds, and the rule it stores a commit by.
class FakeBridge {
public:
    TreeGroupState state;
    // What the last commit blanked.
    std::set<std::uint32_t> lastBlanked;
    // Every commit statement, in order; `seq` is the position plus one.
    std::vector<server::GroupTreeCommit> commits;
    // The roster seq 1 seats, served beside the chain from seq 0.
    std::vector<std::string> genesis;
    std::vector<std::string> genesisManagers;
    std::int64_t rosterVersion = 0;
    // The managers among the seated; everybody else seated is a user.
    std::set<std::string> managers;
    // The group's policy and creator, which every statement's `policyHash` signs (T4-10).
    Poco::Dynamic::Var policy;
    std::string creator;
    // The Context user list: whose key a statement must be signed with.
    std::function<privmx::crypto::PublicKey(const std::string&)> keyOf;
    // The group's id, and what it follows from.
    std::string groupId = GROUP_ID;
    std::string resourceId = "res";
    std::string contextId = "ctx";

    // The users of a post state: the seated who are not managers.
    std::vector<std::string> usersOf(const TreeGroupState& post, const std::set<std::string>& postManagers) const {
        std::vector<std::string> users;
        for (const std::string& id : seatedIn(post)) {
            if (postManagers.count(id) == 0) {
                users.push_back(id);
            }
        }
        return users;
    }
    std::vector<std::string> users() const { return usersOf(state, managers); }

    // The rules the stored policy and creator sign.
    GroupRules rules() const { return TreeCommits::rules(policy, creator); }

    // The shared lost-race check (03): a statement not extending the stored latest is answered ROTATED_ALREADY.
    void assertExtendsHead(const server::GroupTreeCommit& wire) const {
        const CommitStatement statement = TreeCommits::fromWire(wire);
        if (statement.seq != commits.size() + 1 ||
            (!commits.empty() && statement.prevDigest != TreeCommits::digest(TreeCommits::fromWire(commits.back())))) {
            rotatedAlready();
        }
    }

    // The bridge's statement check (§4): every field derived from the post state, nothing taken from the client.
    // `postPolicy` is the policy after the commit (the stored one but for a creation or a policy commit).
    void checkStatement(
        const server::GroupTreeCommit& wire,
        CommitOp op,
        const std::string& committer,
        const TreeGroupState& post,
        std::int64_t postRosterVersion,
        const std::vector<server::GroupTreeRefreshedNode>& refreshed,
        std::vector<std::string> added,
        std::vector<std::string> removed,
        const std::set<std::string>& postManagers,
        std::vector<std::string> addedManagers = {},
        const std::optional<GroupRules>& postRules = std::nullopt
    ) {
        CommitStatement statement;
        ASSERT_NO_THROW(statement = TreeCommits::fromWire(wire));
        EXPECT_EQ(statement.seq, commits.size() + 1);
        EXPECT_EQ(statement.op, op);
        EXPECT_EQ(statement.policyHash, postRules.value_or(rules()).hash) << "the statement signs another policy";
        EXPECT_EQ(statement.policy.has_value(), op == CommitOp::Create || op == CommitOp::Policy);
        const std::vector<std::string> before = users();
        EXPECT_FALSE(TreeCommits::deltasProblem(statement, {before.begin(), before.end()}, managers).has_value())
            << "deltas the op's row refuses";
        EXPECT_EQ(statement.groupId, statement.seq == 1 ? resourceId : groupId);
        EXPECT_EQ(statement.treeVersion, TreeMath::TREE_VERSION);
        EXPECT_EQ(statement.keyVersion, post.epoch);
        EXPECT_EQ(statement.groupPubKey, post.grantPublicKey.toBase58DER());
        EXPECT_EQ(statement.rosterVersion, static_cast<std::uint64_t>(postRosterVersion));
        EXPECT_EQ(statement.rosterHash, TreeCommits::rosterHash(usersOf(post, postManagers), {postManagers.begin(), postManagers.end()}));
        EXPECT_EQ(statement.committer, committer);
        EXPECT_EQ(statement.committerPubKey, keyOf(committer).toBase58DER());
        EXPECT_EQ(std::optional<std::uint32_t>(statement.committerSeat), seatOf(post, committer));
        ASSERT_EQ(statement.path.size(), refreshed.size());
        for (const server::GroupTreeRefreshedNode& node : refreshed) {
            EXPECT_TRUE(std::any_of(statement.path.begin(), statement.path.end(), [&](const StatementNode& entry) {
                return entry.nodeIndex == static_cast<std::uint32_t>(node.nodeIndex) &&
                    entry.generation == static_cast<std::uint32_t>(node.generation) &&
                    entry.publicKey == node.publicKey;
            })) << "the statement does not list node " << node.nodeIndex;
        }
        std::sort(added.begin(), added.end());
        std::sort(addedManagers.begin(), addedManagers.end());
        std::sort(removed.begin(), removed.end());
        EXPECT_EQ(statement.addedUsers, added);
        EXPECT_EQ(statement.addedManagers, addedManagers);
        EXPECT_EQ(statement.removed, removed);
        EXPECT_EQ(statement.treeHash, TreeCommits::treeHash(post)) << "the statement signs another tree";
        EXPECT_TRUE(TreeCommits::verifySignature(statement, keyOf(committer))) << "not signed by the committer";
    }

    // `initialManagers` are the managers among the seated; the policy is the one the statement carries.
    void create(
        const server::GroupTreeState& tree,
        const privmx::crypto::PublicKey& grant,
        const std::string& creator,
        const server::GroupTreeCommit& commit,
        const std::set<std::string>& initialManagers = {}
    ) {
        state = TreeWire::toRuntime(tree, 1, grant);
        managers = initialManagers;
        this->creator = creator;
        policy = commit.policy.value_or(Poco::Dynamic::Var());
        std::vector<server::GroupTreeRefreshedNode> refreshed;
        for (const server::GroupTreeNode& node : tree.nodes) {
            EXPECT_EQ(node.setBy, std::optional<std::int64_t>(1));
            refreshed.push_back(server::GroupTreeRefreshedNode{node.nodeIndex, std::nullopt, node.generation,
                                                               node.publicKey.value_or("")});
        }
        rosterVersion = 1;
        checkStatement(commit, CommitOp::Create, creator, state, 1, refreshed, {}, {}, managers); // the hash binds the roster
        genesis = users();
        genesisManagers = std::vector<std::string>(managers.begin(), managers.end());
        commits.push_back(commit);
        const auto seat = seatOf(state, creator);
        ASSERT_TRUE(seat.has_value()) << "the creator holds no seat";
        std::set<std::uint32_t> created;
        for (const TreeNodeState& node : state.nodes) {
            created.insert(node.nodeIndex);
            EXPECT_EQ(node.generation, 0u);
        }
        const std::vector<std::uint32_t> keyed = TreeMath::keyedNodes(state.numLeaves);
        EXPECT_EQ(created, std::set<std::uint32_t>(keyed.begin(), keyed.end())) << "a create keys every keyed node";
    }

    // Who set a filled node: the committer of the statement it cites.
    std::string setterOf(const TreeNodeState& node) const { return commits.at(node.setBy.value() - 1).committer; }

    // Know(u) on the current state: the keyed ancestors of u's seat and of every node u set.
    std::set<std::uint32_t> know(const std::string& userId) const {
        std::set<std::uint32_t> known;
        if (const auto seat = seatOf(state, userId); seat.has_value()) {
            known = up(TreeMath::leafNode(seat.value()), state.numLeaves);
        }
        for (const TreeNodeState& node : state.nodes) {
            if (node.publicKey.has_value() && setterOf(node) == userId) {
                const auto above = up(node.nodeIndex, state.numLeaves);
                known.insert(above.begin(), above.end());
            }
        }
        return known;
    }

    // `subjects` are the members added (with `positions`; those in `newManagers` as managers) or removed.
    void commit(
        CommitOp op,
        const std::string& committer,
        const std::vector<std::string>& subjects,
        const std::vector<std::uint32_t>& positions,
        const std::vector<server::GroupTreeRefreshedNode>& refreshed,
        const std::vector<server::GroupTreeEdge>& edges,
        const std::optional<privmx::crypto::PublicKey>& newGrant,
        const server::GroupTreeCommit& commit,
        const std::vector<std::string>& newManagers = {}
    ) {
        assertExtendsHead(commit);
        const auto committerSeat = seatOf(state, committer);
        ASSERT_TRUE(committerSeat.has_value()) << "only a seated member commits";
        std::uint32_t numLeaves = state.numLeaves;
        auto seats = state.leafAssignment;
        std::set<std::uint32_t> blanked;
        std::set<std::uint32_t> minted;
        if (op == CommitOp::Add) {
            numLeaves = TreeMath::numLeavesToSeatAll(positions, numLeaves);
            seats.resize(numLeaves);
            for (std::size_t i = 0; i < positions.size(); ++i) {
                ASSERT_FALSE(seats[positions[i]].has_value());
                seats[positions[i]] = subjects[i];
                // The adder mints the newcomers' paths; the part shared with its own is added below anyway.
                for (const std::uint32_t node : TreeMath::keyedPath(positions[i], numLeaves)) {
                    minted.insert(node);
                }
            }
        } else if (op == CommitOp::Remove) {
            for (const std::string& gone : subjects) {
                ASSERT_NE(gone, committer) << "self-removal must never reach the bridge";
                const auto seat = seatOf(state, gone);
                ASSERT_TRUE(seat.has_value());
                const auto known = know(gone);
                blanked.insert(known.begin(), known.end());
            }
            for (const std::string& gone : subjects) {
                seats[seatOf(state, gone).value()] = std::nullopt;
            }
        }

        // Exactly the committer's keyed path and the off-path fills, each node one generation on (or minted at 0),
        // each with a new key. A removal blanks the leavers' Know but for what it re-keys.
        const std::vector<std::uint32_t> path = TreeMath::keyedPath(committerSeat.value(), numLeaves);
        minted.insert(path.begin(), path.end());
        for (const std::uint32_t node : path) {
            blanked.erase(node);
        }
        lastBlanked = blanked;
        std::set<std::uint32_t> submitted;
        for (const server::GroupTreeRefreshedNode& node : refreshed) {
            submitted.insert(static_cast<std::uint32_t>(node.nodeIndex));
        }
        ASSERT_EQ(submitted.size(), refreshed.size()) << "a node submitted twice";
        ASSERT_EQ(submitted, minted) << "a commit mints exactly its path and the newcomers' paths";
        std::map<std::uint32_t, TreeNodeState> records;
        for (const TreeNodeState& node : state.nodes) {
            records[node.nodeIndex] = node;
        }
        for (const server::GroupTreeRefreshedNode& node : refreshed) {
            const auto index = static_cast<std::uint32_t>(node.nodeIndex);
            const auto stored = records.find(index);
            if (stored == records.end()) {
                EXPECT_FALSE(node.fromGeneration.has_value());
                EXPECT_EQ(node.generation, 0);
            } else {
                EXPECT_EQ(node.fromGeneration, std::optional<std::int64_t>(stored->second.generation));
                EXPECT_EQ(node.generation, static_cast<std::int64_t>(stored->second.generation) + 1);
                if (stored->second.publicKey.has_value()) {
                    EXPECT_NE(node.publicKey, stored->second.publicKey->toBase58DER()) << "a key reused";
                }
            }
            ASSERT_FALSE(node.publicKey.empty());
        }

        // Storage: whatever hangs off a blanked, refreshed or no-longer-keyed node goes, and so does the grant edge.
        std::set<std::uint32_t> replaced(blanked.begin(), blanked.end());
        for (auto it = records.begin(); it != records.end();) {
            if (!TreeMath::isKeyed(it->first, numLeaves)) {
                replaced.insert(it->first);
                it = records.erase(it);
            } else {
                if (blanked.count(it->first) > 0) {
                    it->second.publicKey.reset();
                    it->second.setBy.reset();
                }
                ++it;
            }
        }
        for (const server::GroupTreeRefreshedNode& node : refreshed) {
            const auto index = static_cast<std::uint32_t>(node.nodeIndex);
            replaced.insert(index);
            records[index] = TreeNodeState{
                index, static_cast<std::uint32_t>(node.generation), NodePublicKey::fromBase58DER(node.publicKey),
                commits.size() + 1
            };
        }
        std::vector<TreeEdge> kept;
        for (const TreeEdge& edge : state.edges) {
            if (!edge.isGrantEdge && replaced.count(edge.parentIndex) == 0) {
                kept.push_back(edge);
            }
        }
        for (const TreeEdge& edge : edgesOf(edges)) {
            kept.push_back(edge);
        }

        TreeGroupState post = state;
        post.numLeaves = numLeaves;
        post.leafAssignment = seats;
        post.nodes.clear();
        for (const auto& [index, record] : records) {
            post.nodes.push_back(record);
        }
        post.edges = kept;
        if (op == CommitOp::Remove) {
            post.epoch += 1;
            post.grantPublicKey = newGrant.value();
        }
        const std::int64_t postRosterVersion = rosterVersion + (op == CommitOp::SelfUpdate ? 0 : 1);
        std::set<std::string> postManagers = managers;
        std::vector<std::string> addedUsers;
        if (op == CommitOp::Add) {
            for (const std::string& id : subjects) {
                const bool manager = std::find(newManagers.begin(), newManagers.end(), id) != newManagers.end();
                if (manager) {
                    postManagers.insert(id);
                } else {
                    addedUsers.push_back(id);
                }
            }
        } else if (op == CommitOp::Remove) {
            for (const std::string& id : subjects) {
                postManagers.erase(id);
            }
        }
        checkStatement(
            commit, op, committer, post, postRosterVersion, refreshed, addedUsers,
            op == CommitOp::Remove ? subjects : std::vector<std::string>{}, postManagers,
            op == CommitOp::Add ? newManagers : std::vector<std::string>{}
        );
        state = post;
        managers = postManagers;
        rosterVersion = postRosterVersion;
        commits.push_back(commit);
    }

    // What `groupUpdatePolicy` stores: the policy and its statement; the tree, epoch and roster stay.
    void changePolicy(const std::string& committer, const server::GroupTreeCommit& commit) {
        assertExtendsHead(commit);
        ASSERT_TRUE(seatOf(state, committer).has_value()) << "only a seated member commits";
        ASSERT_TRUE(commit.policy.has_value());
        const GroupRules next = TreeCommits::rules(commit.policy.value(), creator);
        checkStatement(commit, CommitOp::Policy, committer, state, rosterVersion, {}, {}, {}, managers, {}, next);
        policy = commit.policy.value();
        commits.push_back(commit);
    }

    // What `generateNewGroupKey` stores: the tree untouched, the grant edge replaced, the epoch and roster version up.
    // Shared with the 09 and 11 tests, which extend `checkStatement`, not this.
    void rotate(
        const std::string& committer,
        const server::GroupTreeEdge& grantEdge,
        const privmx::crypto::PublicKey& newGrant,
        const server::GroupTreeCommit& commit
    ) {
        assertExtendsHead(commit);
        ASSERT_TRUE(seatOf(state, committer).has_value()) << "only a seated member rotates";
        // The bridge's `checkGrantEdge`: an edge to a root that has moved on since the rotator read it (a
        // self-update re-keys the root) is refused, as the bridge refuses it, with the problem in the data.
        const std::uint32_t root = TreeMath::root(state.numLeaves);
        const TreeNodeState* rootRecord = recordOf(state, root);
        if (!TreeMath::isLeaf(root) && rootRecord != nullptr && grantEdge.childGeneration.has_value() &&
            grantEdge.childGeneration.value() != static_cast<std::int64_t>(rootRecord->generation)) {
            throw privmx::utils::PrivmxException(
                "GROUP_TREE_INVALID", privmx::utils::PrivmxException::RPC, 0x621E,
                "[{\"kind\":\"STALE_CHILD_GENERATION\",\"expected\":" + std::to_string(rootRecord->generation) +
                    ",\"got\":" + std::to_string(grantEdge.childGeneration.value()) + "}]"
            );
        }
        TreeGroupState post = state;
        post.epoch += 1;
        post.grantPublicKey = newGrant;
        post.edges.erase(
            std::remove_if(post.edges.begin(), post.edges.end(), [](const TreeEdge& e) { return e.isGrantEdge; }),
            post.edges.end()
        );
        for (const TreeEdge& edge : edgesOf({grantEdge})) {
            post.edges.push_back(edge);
        }
        checkStatement(commit, CommitOp::Rotate, committer, post, rosterVersion + 1, {}, {}, {}, managers);
        state = post;
        rosterVersion += 1;
        commits.push_back(commit);
    }

    // What `groupGet` serves `userId`: scope "plan" (every record) or the default "path" (its own keyed path's
    // records and the copath subtrees' hashes), with the statements the served nodes cite.
    server::GroupInfo serve(const std::string& userId, bool plan) const {
        server::GroupInfo info;
        info.id = groupId;
        info.resourceId = resourceId;
        info.contextId = contextId;
        info.groupPubKey = state.grantPublicKey.toBase58DER();
        info.keyVersion = state.epoch;
        info.rosterVersion = rosterVersion;
        info.users = users();
        info.managers = std::vector<std::string>(managers.begin(), managers.end());
        info.creator = creator;
        info.policy = policy;
        info.treeVersion = TreeMath::TREE_VERSION;
        info.numLeaves = state.numLeaves;
        std::vector<std::string> seats;
        for (const auto& seat : state.leafAssignment) {
            seats.push_back(seat.value_or(""));
        }
        info.leafAssignment = seats;
        const auto position = seatOf(state, userId);
        if (position.has_value()) {
            info.ownLeafPosition = position.value();
        }
        const TreeGroupState served = plan ? servePlan(userId) : servePath(userId);
        std::vector<server::GroupTreeNode> nodes;
        std::vector<server::GroupTreeCommit> cited;
        std::set<std::uint64_t> citedSeqs;
        for (const TreeNodeState& node : served.nodes) {
            nodes.push_back(TreeWire::toWire(node));
            if (node.setBy.has_value() && citedSeqs.insert(node.setBy.value()).second) {
                cited.push_back(commits.at(node.setBy.value() - 1));
            }
        }
        std::vector<server::GroupTreeEdge> edges;
        for (const TreeEdge& edge : served.edges) {
            edges.push_back(TreeWire::toWire(edge));
        }
        info.treeNodes = nodes;
        info.treeEdges = edges;
        info.treeCommit = commits.back();
        info.treeCommits = cited;
        if (!plan && position.has_value()) {
            std::vector<std::string> copath;
            for (const std::uint32_t node : TreeMath::copath(position.value(), state.numLeaves)) {
                copath.push_back(privmx::utils::Hex::from(TreeCommits::subtreeHash(state, node)));
            }
            info.copathHashes = copath;
        }
        return info;
    }

    server::GroupGetTreeCommitsResult commitsBetween(std::uint64_t fromSeq, std::uint64_t toSeq) const {
        server::GroupGetTreeCommitsResult result;
        for (std::uint64_t seq = fromSeq + 1; seq <= toSeq && seq <= commits.size(); ++seq) {
            result.commits.push_back(commits[seq - 1]);
        }
        if (fromSeq == 0) {
            result.genesisUsers = genesis;
            result.genesisManagers = genesisManagers;
        }
        return result;
    }

    // `groupGet` with scope "plan": every record, the caller's climbing edges, the grant edge.
    TreeGroupState servePlan(const std::string& userId) const {
        TreeGroupState served = state;
        served.edges = climbingEdges(userId);
        return served;
    }

    // The default scope "path": records of the caller's keyed path only. Nothing of the tree to a caller without a seat.
    TreeGroupState servePath(const std::string& userId) const {
        if (!seatOf(state, userId).has_value()) {
            TreeGroupState served = state;
            served.nodes.clear();
            served.edges.clear();
            return served;
        }
        TreeGroupState served = servePlan(userId);
        const auto path = TreeMath::keyedPath(seatOf(state, userId).value(), state.numLeaves);
        served.nodes.clear();
        for (const TreeNodeState& node : state.nodes) {
            if (std::find(path.begin(), path.end(), node.nodeIndex) != path.end()) {
                served.nodes.push_back(node);
            }
        }
        return served;
    }

private:
    std::vector<TreeEdge> climbingEdges(const std::string& userId) const {
        const auto path = TreeMath::keyedPath(seatOf(state, userId).value(), state.numLeaves);
        std::vector<TreeEdge> climbing;
        for (const TreeEdge& edge : state.edges) {
            const bool toMe = edge.childKind == EdgeChildKind::User && edge.childUserId == userId;
            const bool toMyPath = edge.childKind == EdgeChildKind::Node &&
                std::find(path.begin(), path.end(), edge.childIndex) != path.end();
            if (edge.isGrantEdge || toMe || toMyPath) {
                climbing.push_back(edge);
            }
        }
        return climbing;
    }
};

} // namespace

#endif // _PRIVMXLIB_TEST_UNIT_TREEFAKEBRIDGE_HPP_
