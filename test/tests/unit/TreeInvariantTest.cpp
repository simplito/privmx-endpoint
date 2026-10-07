/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

/**
 * Seeded random sequences of create / add / remove / self-update, committed by random members against a fake bridge
 * that stores what it is sent by the bridge's storage rule. After every commit:
 *
 *   - knowledge: every member's knowledge is what it minted plus everything reachable over the current edges from
 *     what it already knew — accumulated over the whole run, never forgotten, and computed for former members too.
 *     The TreeKEM invariant then has to hold: a filled node's key is known only to members seated under it;
 *   - removal: nobody unseated knows the current grant key, and every seated member climbs to it (real ECIES);
 *   - consistency: the stored edges are exactly the edges the filled nodes owe their children's resolution, plus
 *     one grant edge.
 *
 * The fake bridge derives what each commit may touch on its own, from the operation and the committer, and refuses
 * a refresh of anything else — the same rule the real one enforces.
 *
 * How the old design fails here: A creates {A, B, C, D} and mints every node key, including node 5 above C and D.
 * B removes A, which re-keyed only A's own direct path, so the refreshed root still wraps to node 5 at the
 * generation A minted. The knowledge check fails right after the create (A knows node 5, outside A's subtree), and
 * the removal check fails after B's commit (A opens the root through node 5, then the new grant key).
 *
 * Keys are real and random, so a run is reproducible in its operations (seeded), not in its key material.
 */

#include <gtest/gtest.h>

#include <algorithm>
#include <functional>
#include <iterator>
#include <map>
#include <memory>
#include <optional>
#include <random>
#include <set>
#include <string>
#include <vector>

#include <privmx/crypto/ecc/PrivateKey.hpp>
#include <privmx/utils/Utils.hpp>

#include <privmx/endpoint/group/GroupException.hpp>
#include <privmx/endpoint/group/keytree/GroupKeyResolver.hpp>
#include <privmx/endpoint/group/keytree/TreeCommits.hpp>
#include <privmx/endpoint/group/keytree/TreeKeys.hpp>
#include <privmx/endpoint/group/keytree/TreeMath.hpp>
#include <privmx/endpoint/group/keytree/TreeVerifier.hpp>
#include <privmx/endpoint/group/keytree/TreeWire.hpp>

using privmx::crypto::PrivateKey;
using namespace privmx::endpoint::group;
using namespace privmx::endpoint::group::keytree;

namespace {

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
    // Every commit statement, in order; `seq` is the position plus one.
    std::vector<server::GroupTreeCommit> commits;
    std::int64_t rosterVersion = 0;
    // The Context user list: whose key a statement must be signed with.
    std::function<privmx::crypto::PublicKey(const std::string&)> keyOf;

    enum class Op { Add, Remove, SelfUpdate };

    // The bridge's statement check (§4): every field derived from the post state, nothing taken from the client.
    void checkStatement(
        const server::GroupTreeCommit& wire,
        CommitOp op,
        const std::string& committer,
        const TreeGroupState& post,
        std::int64_t postRosterVersion,
        const std::vector<server::GroupTreeRefreshedNode>& refreshed,
        std::vector<std::string> added,
        std::vector<std::string> removed
    ) {
        CommitStatement statement;
        ASSERT_NO_THROW(statement = TreeCommits::fromWire(wire));
        EXPECT_EQ(statement.seq, commits.size() + 1);
        EXPECT_EQ(statement.op, op);
        EXPECT_EQ(statement.groupId, statement.seq == 1 ? "res" : "grp");
        EXPECT_EQ(statement.treeVersion, TreeMath::TREE_VERSION);
        EXPECT_EQ(statement.keyVersion, post.epoch);
        EXPECT_EQ(statement.groupPubKey, post.grantPublicKey.toBase58DER());
        EXPECT_EQ(statement.rosterVersion, static_cast<std::uint64_t>(postRosterVersion));
        EXPECT_EQ(statement.rosterHash, TreeCommits::rosterHash(seatedIn(post), {}));
        EXPECT_EQ(statement.committer, committer);
        EXPECT_EQ(statement.committerPubKey, keyOf(committer).toBase58DER());
        EXPECT_EQ(std::optional<std::uint32_t>(statement.committerSeat), seatOf(post, committer));
        ASSERT_EQ(statement.path.size(), refreshed.size());
        for (std::size_t i = 0; i < refreshed.size(); ++i) {
            EXPECT_EQ(statement.path[i].nodeIndex, refreshed[i].nodeIndex);
            EXPECT_EQ(statement.path[i].generation, refreshed[i].generation);
            EXPECT_EQ(statement.path[i].publicKey, refreshed[i].publicKey);
        }
        std::sort(added.begin(), added.end());
        std::sort(removed.begin(), removed.end());
        EXPECT_EQ(statement.addedUsers, added);
        EXPECT_TRUE(statement.addedManagers.empty());
        EXPECT_EQ(statement.removed, removed);
        EXPECT_EQ(statement.treeHash, TreeCommits::treeHash(post)) << "the statement signs another tree";
        EXPECT_TRUE(TreeCommits::verifySignature(statement, keyOf(committer))) << "not signed by the committer";
    }

    void create(
        const server::GroupTreeState& tree,
        const privmx::crypto::PublicKey& grant,
        const std::string& creator,
        const server::GroupTreeCommit& commit
    ) {
        state = TreeWire::toRuntime(tree, 1, grant);
        std::vector<server::GroupTreeRefreshedNode> refreshed;
        for (const server::GroupTreeNode& node : tree.nodes) {
            EXPECT_EQ(node.setBy, std::optional<std::int64_t>(1));
            refreshed.push_back(server::GroupTreeRefreshedNode{node.nodeIndex, std::nullopt, node.generation,
                                                               node.publicKey.value_or("")});
        }
        rosterVersion = 1;
        checkStatement(commit, CommitOp::Create, creator, state, 1, refreshed, {}, {});
        commits.push_back(commit);
        const auto seat = seatOf(state, creator);
        ASSERT_TRUE(seat.has_value()) << "the creator holds no seat";
        std::vector<std::uint32_t> created;
        for (const TreeNodeState& node : state.nodes) {
            created.push_back(node.nodeIndex);
            EXPECT_EQ(node.generation, 0u);
        }
        std::sort(created.begin(), created.end());
        std::vector<std::uint32_t> path = TreeMath::keyedPath(seat.value(), state.numLeaves);
        std::sort(path.begin(), path.end());
        EXPECT_EQ(created, path) << "a create may key the creator's path and nothing else";
    }

    // `subjects` are the users added (with `positions`) or removed. Returns the nodes the commit blanked.
    void commit(
        Op op,
        const std::string& committer,
        const std::vector<std::string>& subjects,
        const std::vector<std::uint32_t>& positions,
        const std::vector<server::GroupTreeRefreshedNode>& refreshed,
        const std::vector<server::GroupTreeEdge>& edges,
        const std::optional<privmx::crypto::PublicKey>& newGrant,
        const server::GroupTreeCommit& commit
    ) {
        const auto committerSeat = seatOf(state, committer);
        ASSERT_TRUE(committerSeat.has_value()) << "only a seated member commits";
        std::uint32_t numLeaves = state.numLeaves;
        auto seats = state.leafAssignment;
        std::set<std::uint32_t> blanked;
        if (op == Op::Add) {
            numLeaves = TreeMath::numLeavesToSeatAll(positions, numLeaves);
            seats.resize(numLeaves);
            for (std::size_t i = 0; i < positions.size(); ++i) {
                ASSERT_FALSE(seats[positions[i]].has_value());
                seats[positions[i]] = subjects[i];
            }
            const auto own = TreeMath::keyedPath(committerSeat.value(), numLeaves);
            for (const std::uint32_t position : positions) {
                for (const std::uint32_t node : TreeMath::keyedPath(position, numLeaves)) {
                    if (std::find(own.begin(), own.end(), node) == own.end()) {
                        blanked.insert(node);
                    }
                }
            }
        } else if (op == Op::Remove) {
            for (const std::string& gone : subjects) {
                ASSERT_NE(gone, committer) << "self-removal must never reach the bridge";
                const auto seat = seatOf(state, gone);
                ASSERT_TRUE(seat.has_value());
                seats[seat.value()] = std::nullopt;
                for (const std::uint32_t node : TreeMath::keyedPath(seat.value(), numLeaves)) {
                    blanked.insert(node);
                }
            }
        }

        // Exactly the committer's keyed path, each node one generation on (or minted at 0), each with a new key.
        const std::vector<std::uint32_t> path = TreeMath::keyedPath(committerSeat.value(), numLeaves);
        ASSERT_EQ(refreshed.size(), path.size()) << "a commit refreshes the committer's keyed path, nothing else";
        std::map<std::uint32_t, TreeNodeState> records;
        for (const TreeNodeState& node : state.nodes) {
            records[node.nodeIndex] = node;
        }
        for (const server::GroupTreeRefreshedNode& node : refreshed) {
            const auto index = static_cast<std::uint32_t>(node.nodeIndex);
            ASSERT_NE(std::find(path.begin(), path.end(), index), path.end()) << "refreshes node " << index;
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
        if (op == Op::Remove) {
            post.epoch += 1;
            post.grantPublicKey = newGrant.value();
        }
        const std::int64_t postRosterVersion = rosterVersion + (op == Op::SelfUpdate ? 0 : 1);
        checkStatement(
            commit, op == Op::Add ? CommitOp::Add : op == Op::Remove ? CommitOp::Remove : CommitOp::SelfUpdate,
            committer, post, postRosterVersion, refreshed, op == Op::Add ? subjects : std::vector<std::string>{},
            op == Op::Remove ? subjects : std::vector<std::string>{}
        );
        state = post;
        rosterVersion = postRosterVersion;
        commits.push_back(commit);
    }

    // What `groupGet` serves `userId`: scope "plan" (every record) or the default "path" (its own keyed path's
    // records and the copath subtrees' hashes), with the statements the served nodes cite.
    server::GroupInfo serve(const std::string& userId, bool plan) const {
        server::GroupInfo info;
        info.id = "grp";
        info.resourceId = "res";
        info.contextId = "ctx";
        info.groupPubKey = state.grantPublicKey.toBase58DER();
        info.keyVersion = state.epoch;
        info.rosterVersion = rosterVersion;
        info.users = seatedIn(state);
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

    std::vector<server::GroupTreeCommit> commitsBetween(std::uint64_t fromSeq, std::uint64_t toSeq) const {
        std::vector<server::GroupTreeCommit> result;
        for (std::uint64_t seq = fromSeq + 1; seq <= toSeq && seq <= commits.size(); ++seq) {
            result.push_back(commits[seq - 1]);
        }
        return result;
    }

    // `groupGet` with scope "plan": every record, the caller's climbing edges, the grant edge.
    TreeGroupState servePlan(const std::string& userId) const {
        TreeGroupState served = state;
        served.edges = climbingEdges(userId);
        return served;
    }

    // The default scope "path": records of the caller's keyed path only.
    TreeGroupState servePath(const std::string& userId) const {
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

class TreeInvariant : public testing::Test {
protected:
    FakeBridge bridge;
    std::vector<Member> everyone;
    // Public key (base58) -> private key, for every key minted or held: the oracle that checks each edge once.
    std::map<std::string, PrivateKey> privateOf;
    // Blob -> (recipient public key, carried public key), established by decrypting each edge as it arrives.
    std::map<std::string, std::pair<std::string, std::string>> wrapped;
    // What each member, current or former, can know: public keys of every private key reachable to it, ever.
    std::map<std::string, std::set<std::string>> knows;
    std::mt19937 random;
    std::uint32_t nextUser = 0;
    // Each member's own client: its pins and verified statements, as kept across reads in one session.
    std::map<std::string, std::unique_ptr<TreeVerifier>> verifiers;

    void SetUp() override {
        bridge.keyOf = [this](const std::string& userId) { return member(userId).publicKey; };
    }

    void reset() {
        bridge = FakeBridge{};
        bridge.keyOf = [this](const std::string& userId) { return member(userId).publicKey; };
        everyone.clear();
        privateOf.clear();
        wrapped.clear();
        knows.clear();
        verifiers.clear();
    }

    TreeVerifier::Environment environment() const {
        TreeVerifier::Environment env;
        // The application's UserVerifier: it knows each user's real key.
        env.verifyUsers = [this](const std::vector<privmx::endpoint::core::VerificationRequest>& requests) {
            std::vector<bool> verified;
            for (const auto& request : requests) {
                const auto found = std::find_if(everyone.begin(), everyone.end(), [&](const Member& m) {
                    return m.userId == request.senderId;
                });
                verified.push_back(found != everyone.end() && found->pub == request.senderPubKey);
            }
            return verified;
        };
        env.commitsBetween = [this](std::uint64_t fromSeq, std::uint64_t toSeq) {
            return bridge.commitsBetween(fromSeq, toSeq);
        };
        return env;
    }

    TreeVerifier& verifierOf(const std::string& userId) {
        auto& verifier = verifiers[userId];
        if (!verifier) {
            verifier = std::make_unique<TreeVerifier>();
        }
        return *verifier;
    }

    // A member's read: what the bridge serves it, verified by its own client before anything is used.
    TreeGroupState verifiedRead(const std::string& userId, bool plan) {
        const server::GroupInfo info = bridge.serve(userId, plan);
        verifierOf(userId).verify(info, plan ? TreeVerifier::Scope::Plan : TreeVerifier::Scope::Path, environment());
        if (plan) {
            TreeVerifier::assertSeatsMatchRoster(info, info.users, info.managers);
        }
        return GroupKeyResolver::toTreeState(info);
    }

    // Signed as GroupApiImpl signs it: the post state's counters and roster, the committer's own key.
    server::GroupTreeCommit sign(
        const CommitPlan& plan,
        CommitOp op,
        const std::string& committer,
        std::uint64_t keyVersion,
        const privmx::crypto::PublicKey& grant,
        std::int64_t rosterVersion,
        const std::vector<std::string>& users,
        std::vector<std::string> added,
        std::vector<std::string> removed
    ) {
        CommitStatement statement = TreeCommits::statementFor(
            plan, op, op == CommitOp::Create ? "res" : "grp", 1760000000000, keyVersion, grant.toBase58DER(),
            static_cast<std::uint64_t>(rosterVersion), users, {}, committer, std::move(added), {}, std::move(removed)
        );
        TreeCommits::sign(statement, member(committer).priv);
        return TreeCommits::toWire(statement);
    }

    Member& newMember() {
        const PrivateKey priv = PrivateKey::generateRandom();
        everyone.push_back(
            Member{"m" + std::to_string(nextUser++), priv, priv.getPublicKey(), priv.getPublicKey().toBase58DER()}
        );
        privateOf[everyone.back().pub] = priv;
        knows[everyone.back().userId].insert(everyone.back().pub);
        return everyone.back();
    }

    const Member& member(const std::string& userId) const {
        return *std::find_if(everyone.begin(), everyone.end(), [&](const Member& m) { return m.userId == userId; });
    }

    std::vector<TreeMember> roster() const {
        std::vector<TreeMember> keys;
        for (const Member& m : everyone) {
            keys.push_back(TreeMember{m.userId, m.publicKey});
        }
        return keys;
    }

    std::vector<std::string> seated() const {
        std::vector<std::string> ids;
        for (const auto& seat : bridge.state.leafAssignment) {
            if (seat.has_value()) {
                ids.push_back(seat.value());
            }
        }
        return ids;
    }

    std::uint32_t pick(std::uint32_t bound) {
        return std::uniform_int_distribution<std::uint32_t>(0, bound - 1)(random);
    }

    // A live client's way in: a cold cache, the verified "plan" view, a climb, then the plan.
    CommitPlan planBy(const std::string& committer, const std::function<CommitPlan(TreeKeys&, const TreeGroupState&)>& plan) {
        const TreeGroupState served = verifiedRead(committer, true);
        TreeKeyCache cache;
        TreeKeys keys(cache);
        const ClimbResult climb = keys.climbToGrantKey(served, committer, member(committer).priv, false);
        EXPECT_EQ(climb.failure, ClimbFailure::None) << committer << " cannot climb to plan";
        keys.setMemberKeys(roster());
        return plan(keys, served);
    }

    // Records what every new edge carries to whom, from the plan, and opens the grant edge and a few random others
    // for real to hold the plan to it. Opening every one would be the honest maximum, but a successful unwrap costs
    // ~5 ms here and a commit to forty members brings forty edges; the climbs after each removal open the rest of
    // what matters for real.
    void learnPlan(const std::string& committer, const CommitPlan& plan) {
        for (const RefreshedNode& refreshed : plan.refreshed) {
            privateOf[refreshed.key.getPublicKey().toBase58DER()] = refreshed.key;
            knows[committer].insert(refreshed.key.getPublicKey().toBase58DER());
        }
        privateOf[plan.grantKey.getPublicKey().toBase58DER()] = plan.grantKey;
        knows[committer].insert(plan.grantKey.getPublicKey().toBase58DER());
        for (const TreeEdge& edge : plan.edges) {
            const std::string recipient = edge.childKind == EdgeChildKind::User ?
                member(edge.childUserId).pub :
                recordOf(bridge.state, edge.childIndex)->publicKey->toBase58DER();
            const std::string carried = edge.isGrantEdge ?
                plan.grantKey.getPublicKey().toBase58DER() :
                recordOf(bridge.state, edge.parentIndex)->publicKey->toBase58DER();
            if (edge.isGrantEdge || pick(10) == 0) {
                const auto opened = TreeKeys::unwrapKey(edge.blob, privateOf.at(recipient));
                ASSERT_TRUE(opened.has_value()) << "an edge does not open with the key it names";
                ASSERT_EQ(opened->getPublicKey().toBase58DER(), carried) << "an edge carries another key than it names";
            }
            wrapped[edge.blob] = {recipient, carried};
        }
    }

    void closeKnowledge() {
        for (auto& [userId, known] : knows) {
            for (bool grew = true; grew;) {
                grew = false;
                for (const TreeEdge& edge : bridge.state.edges) {
                    const auto& [recipient, carried] = wrapped.at(edge.blob);
                    if (known.count(recipient) > 0 && known.insert(carried).second) {
                        grew = true;
                    }
                }
            }
        }
    }

    void checkInvariants(bool afterRemoval) {
        const TreeGroupState& state = bridge.state;
        const std::string grant = state.grantPublicKey.toBase58DER();
        const std::vector<std::string> seatedIds = seated();

        // Knowledge: a filled node's key only under it; the grant key only for the seated.
        for (const TreeNodeState& node : state.nodes) {
            ASSERT_TRUE(TreeMath::isKeyed(node.nodeIndex, state.numLeaves)) << "a record on unkeyed " << node.nodeIndex;
            if (!node.publicKey.has_value()) {
                continue;
            }
            std::set<std::string> under;
            for (const std::uint32_t position : TreeMath::leavesUnder(node.nodeIndex, state.numLeaves)) {
                if (state.leafAssignment[position].has_value()) {
                    under.insert(state.leafAssignment[position].value());
                }
            }
            for (const auto& [userId, known] : knows) {
                if (known.count(node.publicKey->toBase58DER()) > 0) {
                    EXPECT_EQ(under.count(userId), 1u)
                        << userId << " knows node " << node.nodeIndex << " without being seated under it";
                }
            }
        }
        for (const auto& [userId, known] : knows) {
            const bool isSeated = std::find(seatedIds.begin(), seatedIds.end(), userId) != seatedIds.end();
            EXPECT_EQ(known.count(grant) > 0, isSeated)
                << userId << (isSeated ? " cannot reach" : " is not a member but reaches") << " the grant key";
        }

        // Consistency: the stored edges are exactly what the filled nodes owe, plus one grant edge.
        std::vector<std::string> required;
        for (const TreeNodeState& node : state.nodes) {
            if (!node.publicKey.has_value()) {
                continue;
            }
            for (const std::uint32_t child : TreeMath::children(node.nodeIndex, state.numLeaves)) {
                std::vector<std::string> resolved;
                resolve(state, child, resolved);
                for (const std::string& target : resolved) {
                    required.push_back(std::to_string(node.nodeIndex) + "@" + std::to_string(node.generation) + ">" +
                                       target);
                }
            }
        }
        if (state.numLeaves == 1) {
            required.push_back("grant@" + std::to_string(state.epoch) + ">user:" + state.leafAssignment[0].value());
        } else {
            const std::uint32_t root = TreeMath::root(state.numLeaves);
            ASSERT_NE(recordOf(state, root), nullptr);
            ASSERT_TRUE(recordOf(state, root)->publicKey.has_value()) << "the root is filled at rest";
            required.push_back("grant@" + std::to_string(state.epoch) + ">node:" + std::to_string(root) + "@" +
                               std::to_string(recordOf(state, root)->generation));
        }
        std::vector<std::string> stored;
        for (const TreeEdge& edge : state.edges) {
            stored.push_back(edgeIdentity(edge));
        }
        std::sort(required.begin(), required.end());
        std::sort(stored.begin(), stored.end());
        EXPECT_EQ(stored, required) << "the stored edges are not what the filled nodes owe";

        // After a removal, three of the seated climb the default view with real crypto. All of them reach the grant
        // key by the knowledge check above; this holds the climb itself and the "path" view to that.
        if (afterRemoval) {
            std::vector<std::string> climbers;
            std::sample(seatedIds.begin(), seatedIds.end(), std::back_inserter(climbers), 3, random);
            for (const std::string& userId : climbers) {
                TreeKeyCache cache;
                TreeKeys keys(cache);
                const ClimbResult climb = keys.climbToGrantKey(verifiedRead(userId, false), userId, member(userId).priv);
                EXPECT_EQ(climb.failure, ClimbFailure::None) << userId << " cannot climb after the removal";
            }
        }
    }

    // The fake bridge's state, compared with what the client-side storage rule says it should be.
    void expectSameAsAfterCommit(const server::GroupTreeState& expected) {
        const TreeGroupState mine = TreeWire::toRuntime(expected, bridge.state.epoch, bridge.state.grantPublicKey);
        std::vector<std::string> a, b;
        for (const TreeEdge& edge : mine.edges) {
            a.push_back(edgeIdentity(edge) + edge.blob);
        }
        for (const TreeEdge& edge : bridge.state.edges) {
            b.push_back(edgeIdentity(edge) + edge.blob);
        }
        std::sort(a.begin(), a.end());
        std::sort(b.begin(), b.end());
        EXPECT_EQ(a, b) << "TreeWire::afterCommit disagrees with the storage rule";
        ASSERT_EQ(mine.nodes.size(), bridge.state.nodes.size());
        for (const TreeNodeState& node : mine.nodes) {
            const TreeNodeState* other = recordOf(bridge.state, node.nodeIndex);
            ASSERT_NE(other, nullptr);
            EXPECT_EQ(node.generation, other->generation);
            EXPECT_EQ(node.publicKey.has_value(), other->publicKey.has_value());
        }
    }

    server::GroupTreeState wireState() const {
        server::GroupTreeState tree;
        tree.numLeaves = bridge.state.numLeaves;
        for (const auto& seat : bridge.state.leafAssignment) {
            tree.leafAssignment.push_back(seat.value_or(""));
        }
        for (const TreeNodeState& node : bridge.state.nodes) {
            tree.nodes.push_back(TreeWire::toWire(node));
        }
        for (const TreeEdge& edge : bridge.state.edges) {
            tree.edges.push_back(TreeWire::toWire(edge));
        }
        return tree;
    }

    void create(std::uint32_t size, std::uint32_t creatorIndex) {
        std::vector<TreeMember> members;
        for (std::uint32_t i = 0; i < size; ++i) {
            const Member& m = newMember();
            members.push_back(TreeMember{m.userId, m.publicKey});
        }
        const std::string creator = members[creatorIndex].userId;
        TreeKeyCache cache;
        TreeKeys keys(cache);
        const CommitPlan plan = keys.planCreate(members, creator, member(creator).priv);
        std::vector<std::string> ids;
        for (const TreeMember& m : members) {
            ids.push_back(m.userId);
        }
        bridge.create(
            TreeWire::toCreateTree(plan), plan.grantKey.getPublicKey(), creator,
            sign(plan, CommitOp::Create, creator, 1, plan.grantKey.getPublicKey(), 1, ids, {}, {})
        );
        learnPlan(creator, plan);
        closeKnowledge();
        checkInvariants(false);
    }

    void add(const std::string& adder, std::uint32_t count) {
        std::vector<std::string> ids;
        // Former members come back now and then, carrying everything they ever knew.
        for (const Member& m : everyone) {
            if (ids.size() < count && pick(3) == 0 && !seatOf(bridge.state, m.userId).has_value()) {
                ids.push_back(m.userId);
            }
        }
        while (ids.size() < count) {
            ids.push_back(newMember().userId);
        }
        std::vector<TreeMember> newcomers;
        for (const std::string& id : ids) {
            newcomers.push_back(TreeMember{id, member(id).publicKey});
        }
        const auto positions = TreeKeys::choosePositions(bridge.state, count);
        const server::GroupTreeState before = wireState();
        const CommitPlan plan = planBy(adder, [&](TreeKeys& keys, const TreeGroupState& served) {
            return keys.planAddition(served, newcomers, positions, adder, member(adder).priv);
        });
        const auto wire = TreeWire::toAdditionTransition(plan, bridge.state.epoch);
        std::vector<server::GroupTreeRefreshedNode> refreshed;
        for (const server::GroupTreeSeatedNode& node : wire.seatedNodes) {
            refreshed.push_back(server::GroupTreeRefreshedNode{node.nodeIndex, node.fromGeneration, node.generation,
                                                               node.publicKey});
        }
        std::vector<std::string> after = seated();
        after.insert(after.end(), ids.begin(), ids.end());
        bridge.commit(
            FakeBridge::Op::Add, adder, ids, positions, refreshed, wire.edges, std::nullopt,
            sign(plan, CommitOp::Add, adder, bridge.state.epoch, bridge.state.grantPublicKey, bridge.rosterVersion + 1,
                 after, ids, {})
        );
        expectSameAsAfterCommit(TreeWire::afterCommit(before, plan));
        learnPlan(adder, plan);
        closeKnowledge();
        checkInvariants(false);
    }

    void remove(const std::string& remover, const std::vector<std::string>& leaving) {
        const server::GroupTreeState before = wireState();
        const CommitPlan plan = planBy(remover, [&](TreeKeys& keys, const TreeGroupState& served) {
            return keys.planRemoval(served, leaving, remover, member(remover).priv);
        });
        const auto wire = TreeWire::toRemovalTransition(plan, bridge.state.epoch);
        std::vector<std::string> after;
        for (const std::string& id : seated()) {
            if (std::find(leaving.begin(), leaving.end(), id) == leaving.end()) {
                after.push_back(id);
            }
        }
        bridge.commit(
            FakeBridge::Op::Remove, remover, leaving, {}, wire.refreshedNodes, wire.edges, plan.grantKey.getPublicKey(),
            sign(plan, CommitOp::Remove, remover, bridge.state.epoch + 1, plan.grantKey.getPublicKey(),
                 bridge.rosterVersion + 1, after, {}, leaving)
        );
        expectSameAsAfterCommit(TreeWire::afterCommit(before, plan));
        learnPlan(remover, plan);
        closeKnowledge();
        checkInvariants(true);
    }

    void selfUpdate(const std::string& memberId) {
        const server::GroupTreeState before = wireState();
        const CommitPlan plan = planBy(memberId, [&](TreeKeys& keys, const TreeGroupState& served) {
            return keys.planSelfUpdate(served, memberId, member(memberId).priv);
        });
        const auto wire = TreeWire::toSelfUpdateTransition(plan, bridge.state.epoch);
        bridge.commit(
            FakeBridge::Op::SelfUpdate, memberId, {}, {}, wire.refreshedNodes, wire.edges, std::nullopt,
            sign(plan, CommitOp::SelfUpdate, memberId, bridge.state.epoch, bridge.state.grantPublicKey,
                 bridge.rosterVersion, seated(), {}, {})
        );
        expectSameAsAfterCommit(TreeWire::afterCommit(before, plan));
        learnPlan(memberId, plan);
        closeKnowledge();
        checkInvariants(false);
    }

    void runSequence(std::uint32_t seed, std::uint32_t operations) {
        random.seed(seed);
        // Odd seeds start above 32 seats, where the root is not the only keyed node; even ones anywhere from 1 to 32.
        const std::uint32_t size = seed % 2 == 1 ? 33 + pick(8) : 1 + pick(32);
        create(size, pick(size));
        for (std::uint32_t i = 0; i < operations && !HasFatalFailure(); ++i) {
            const std::vector<std::string> members = seated();
            const std::string committer = members[pick(static_cast<std::uint32_t>(members.size()))];
            const std::uint32_t roll = pick(10);
            if (roll < 3 && bridge.state.numLeaves < 48) {
                add(committer, 1 + pick(3));
            } else if (roll < 6 && members.size() > 1) {
                std::vector<std::string> others;
                for (const std::string& id : members) {
                    if (id != committer) {
                        others.push_back(id);
                    }
                }
                std::shuffle(others.begin(), others.end(), random);
                others.resize(std::min<std::size_t>(others.size(), 1 + pick(3)));
                remove(committer, others);
            } else if (bridge.state.numLeaves > 1) {
                selfUpdate(committer);
            }
        }
    }
};

// A client's verification against a bridge that lies, alone or with a member.
class TreeVerification : public TreeInvariant {
protected:
    void verify(const std::string& userId, bool plan) {
        verifierOf(userId).verify(
            bridge.serve(userId, plan), plan ? TreeVerifier::Scope::Plan : TreeVerifier::Scope::Path, environment()
        );
    }

    const std::string& id(std::size_t index) const { return everyone[index].userId; }

    // A statement the bridge stores with none of its checks — what a malicious bridge, or a member colluding with
    // one, can put in front of a client. `change` edits the stored state; the statement then describes the result
    // exactly (counters, roster, tree hash) and is genuinely signed by `signer`.
    void forge(
        const std::string& signer,
        const std::function<void(TreeGroupState&)>& change,
        std::vector<StatementNode> path,
        std::vector<std::string> added = {},
        std::int64_t rosterBump = 0
    ) {
        TreeGroupState next = bridge.state;
        change(next);
        CommitStatement statement;
        statement.seq = bridge.commits.size() + 1;
        statement.op = CommitOp::SelfUpdate;
        statement.groupId = "grp";
        statement.treeVersion = TreeMath::TREE_VERSION;
        statement.date = 1760000000000;
        statement.keyVersion = next.epoch;
        statement.groupPubKey = next.grantPublicKey.toBase58DER();
        statement.rosterVersion = static_cast<std::uint64_t>(bridge.rosterVersion + rosterBump);
        statement.rosterHash = TreeCommits::rosterHash(seatedIn(next), {});
        statement.treeHash = TreeCommits::treeHash(next);
        statement.committer = signer;
        statement.committerSeat = seatOf(next, signer).value();
        statement.path = std::move(path);
        statement.addedUsers = std::move(added);
        TreeCommits::sign(statement, member(signer).priv);
        bridge.state = next;
        bridge.rosterVersion += rosterBump;
        bridge.commits.push_back(TreeCommits::toWire(statement));
    }

    static void setRecord(TreeGroupState& state, const TreeNodeState& record) {
        for (TreeNodeState& node : state.nodes) {
            if (node.nodeIndex == record.nodeIndex) {
                node = record;
                return;
            }
        }
        state.nodes.push_back(record);
    }
};

} // namespace

TEST_F(TreeInvariant, TheC1Scenario) {
    // A creates {A, B, C, D}; B removes A. See the header for how the old design fails exactly here.
    create(4, 0);
    remove(everyone[1].userId, {everyone[0].userId});
    EXPECT_EQ(knows[everyone[0].userId].count(bridge.state.grantPublicKey.toBase58DER()), 0u);
}

TEST_F(TreeInvariant, TheC1ScenarioAboveTheBuckets) {
    // The same with two keyed levels: the creator held node 31 and the root; the remover sits outside node 31.
    create(40, 0);
    remove(everyone[35].userId, {everyone[0].userId});
    selfUpdate(everyone[7].userId);
    remove(everyone[7].userId, {everyone[36].userId, everyone[3].userId});
}

TEST_F(TreeInvariant, RandomSequencesKeepEveryInvariant) {
    // Six runs of 35 commits, half of them in groups past 32 seats; additions stop growing a group at 48.
    for (std::uint32_t seed = 1; seed <= 6 && !HasFatalFailure(); ++seed) {
        SCOPED_TRACE("seed " + std::to_string(seed));
        reset();
        runSequence(seed, 35);
    }
}

// verification

TEST_F(TreeVerification, AcceptsHonestStatesInBothScopes) {
    create(40, 0);
    remove(id(35), {id(5)}); // node 31 blank
    selfUpdate(id(9));       // and refilled
    for (const std::size_t member : {0u, 9u, 33u, 39u}) {
        EXPECT_NO_THROW(verify(id(member), false)) << id(member);
        EXPECT_NO_THROW(verify(id(member), true)) << id(member);
    }
}

TEST_F(TreeVerification, SECURITY_RefusesASubstitutedNodeKey) {
    // P1: an honest committer would wrap the next root to a key the bridge chose.
    create(40, 0);
    for (const bool plan : {false, true}) {
        server::GroupInfo info = bridge.serve(id(9), plan);
        auto nodes = info.treeNodes.value();
        for (server::GroupTreeNode& node : nodes) {
            if (node.nodeIndex == 31) {
                node.publicKey = PrivateKey::generateRandom().getPublicKey().toBase58DER();
            }
        }
        info.treeNodes = nodes;
        TreeVerifier fresh;
        EXPECT_THROW(
            fresh.verify(info, plan ? TreeVerifier::Scope::Plan : TreeVerifier::Scope::Path, environment()),
            GroupDataIntegrityException
        ) << (plan ? "plan" : "path");
    }
}

TEST_F(TreeVerification, SECURITY_RefusesASubstitutedGrantKey) {
    create(40, 0);
    server::GroupInfo info = bridge.serve(id(9), false);
    info.groupPubKey = PrivateKey::generateRandom().getPublicKey().toBase58DER();
    EXPECT_THROW(verifierOf(id(9)).verify(info, TreeVerifier::Scope::Path, environment()), GroupDataIntegrityException);
}

TEST_F(TreeVerification, SECURITY_RefusesAnOutsiderSeated) {
    // P2: the next commit would wrap to whoever sits in the tree.
    create(40, 0);
    remove(id(35), {id(5)});
    server::GroupInfo info = bridge.serve(id(9), true);
    auto seats = info.leafAssignment.value();
    seats[5] = "mallory";
    info.leafAssignment = seats;
    TreeVerifier fresh;
    EXPECT_THROW(fresh.verify(info, TreeVerifier::Scope::Plan, environment()), GroupDataIntegrityException);
    EXPECT_THROW(TreeVerifier::assertSeatsMatchRoster(info, info.users, info.managers), GroupDataIntegrityException)
        << "the seats no longer match the attested roster";
    info.users.push_back("mallory");
    EXPECT_THROW(fresh.verify(info, TreeVerifier::Scope::Plan, environment()), GroupDataIntegrityException)
        << "nor the roster the statement signed";
}

TEST_F(TreeVerification, SECURITY_RefusesANodeVouchedByAStatementOfSomebodyOutsideIt) {
    // C1 through the back door: seat 35, outside node 31, signs a state planting a key it knows at node 31. The
    // state hashes right and the statement is genuine — only who signed it gives it away.
    create(40, 0);
    ASSERT_NO_THROW(verify(id(9), false));
    const PrivateKey planted = PrivateKey::generateRandom();
    const std::uint32_t generation = recordOf(bridge.state, 31)->generation + 1;
    const std::uint64_t seq = bridge.commits.size() + 1;
    forge(
        id(35),
        [&](TreeGroupState& state) { setRecord(state, TreeNodeState{31, generation, planted.getPublicKey(), seq}); },
        {StatementNode{31, generation, planted.getPublicKey().toBase58DER()}}
    );
    EXPECT_THROW(verify(id(9), false), GroupDataIntegrityException);
    EXPECT_THROW(verify(id(10), true), GroupDataIntegrityException) << "a client with no pin refuses it too";
}

TEST_F(TreeVerification, SECURITY_RefusesAStaleGenerationToAClientThatSawTheNewer) {
    // Node 31 rolled back to the generation the creator set — a key a since-removed member could have known —
    // under a genuine statement by a colluding member. The node's own generation pin is what refuses it.
    create(40, 0);
    selfUpdate(id(1)); // node 31 at generation 1, set by statement 2
    ASSERT_NO_THROW(verify(id(2), false));
    const server::GroupTreeCommitPathEntry original = bridge.commits[0].path[0];
    ASSERT_EQ(original.nodeIndex, 31);
    forge(id(3), [&](TreeGroupState& state) {
        setRecord(state, TreeNodeState{31, 0, NodePublicKey::fromBase58DER(original.publicKey), 1});
    }, {});
    EXPECT_THROW(verify(id(2), false), GroupHistoryForkException);
    // The residual, by design: a client that never saw generation 1 accepts the validly vouched older one.
    EXPECT_NO_THROW(verify(id(4), false));
}

TEST_F(TreeVerification, SECURITY_RefusesASecondRecordForOneNode) {
    // Node 31 is blank after the removal. Behind its genuine (hashed) blank record the bridge serves a second one,
    // filled with the key the creator set, vouched by the creator's own genuine statement.
    create(40, 0);
    remove(id(35), {id(5)});
    server::GroupInfo info = bridge.serve(id(9), true);
    const server::GroupTreeCommitPathEntry original = bridge.commits[0].path[0];
    ASSERT_EQ(original.nodeIndex, 31);
    auto nodes = info.treeNodes.value();
    nodes.push_back(
        server::GroupTreeNode{
            .nodeIndex = 31, .generation = original.generation, .publicKey = original.publicKey, .setBy = 1
        }
    );
    info.treeNodes = nodes;
    auto cited = info.treeCommits.value_or(std::vector<server::GroupTreeCommit>{});
    cited.push_back(bridge.commits[0]);
    info.treeCommits = cited;
    TreeVerifier fresh;
    EXPECT_THROW(fresh.verify(info, TreeVerifier::Scope::Plan, environment()), GroupDataIntegrityException);
}

TEST_F(TreeVerification, SECURITY_RefusesARollbackBelowThePin) {
    create(40, 0);
    const FakeBridge before = bridge;
    selfUpdate(id(1));
    ASSERT_NO_THROW(verify(id(9), false));
    bridge = before; // a genuine, fully signed, earlier state
    EXPECT_THROW(verify(id(9), false), GroupHistoryForkException);
}

TEST_F(TreeVerification, AnAnswerBehindThePinIsTellableFromAForkAtThePin) {
    // A served seq below the pin (a concurrent read may have got further) is a fork until the read helper's re-read.
    create(40, 0);
    const server::GroupInfo older = bridge.serve(id(9), false);
    selfUpdate(id(1));
    ASSERT_NO_THROW(verify(id(9), false));
    EXPECT_EQ(verifierOf(id(9)).pinnedSeq("grp"), bridge.commits.size());
    EXPECT_THROW(verifierOf(id(9)).verify(older, TreeVerifier::Scope::Path, environment()), GroupHistoryForkException);
    EXPECT_LT(older.treeCommit->seq, static_cast<std::int64_t>(verifierOf(id(9)).pinnedSeq("grp")));
    EXPECT_NO_THROW(verify(id(9), false)) << "the fresh read passes";
    EXPECT_EQ(TreeVerifier().pinnedSeq("grp"), 0u);
}

TEST_F(TreeVerification, SECURITY_RefusesAChainLinkSignedByANonMember) {
    // The bridge seats mallory and has her sign for it. Each statement is genuine and the state matches it; what
    // gives it away is that mallory was no member when she signed.
    create(40, 0);
    remove(id(35), {id(5)});
    ASSERT_NO_THROW(verify(id(9), false));
    const std::string mallory = newMember().userId;
    forge(mallory, [&](TreeGroupState& state) { state.leafAssignment[5] = mallory; }, {}, {mallory}, 1);
    EXPECT_THROW(verify(id(9), false), GroupDataIntegrityException);
    // The residual, by design: first contact trusts the latest genuine statement by somebody on its roster.
    EXPECT_NO_THROW(verify(id(10), false));
}

TEST_F(TreeVerification, FollowsAChainOfHonestCommits) {
    create(40, 0);
    ASSERT_NO_THROW(verify(id(9), false));
    remove(id(35), {id(5)});
    add(id(1), 2);
    selfUpdate(id(9));
    EXPECT_NO_THROW(verify(id(9), false)) << "four statements past the pin";
    EXPECT_NO_THROW(verify(id(9), true));
}

TEST_F(TreeVerification, SECURITY_RefusesEveryLieInTheLatestStatement) {
    create(40, 0);
    const auto refusedWith = [&](const std::function<void(CommitStatement&)>& lie, bool resign) {
        server::GroupInfo info = bridge.serve(id(9), false);
        CommitStatement statement = TreeCommits::fromWire(info.treeCommit.value());
        lie(statement);
        if (resign) {
            TreeCommits::sign(statement, member(statement.committer).priv);
        }
        const server::GroupTreeCommit wire = TreeCommits::toWire(statement);
        info.treeCommit = wire;
        auto cited = info.treeCommits.value();
        for (server::GroupTreeCommit& entry : cited) {
            if (entry.seq == wire.seq) {
                entry = wire;
            }
        }
        info.treeCommits = cited;
        TreeVerifier fresh;
        try {
            fresh.verify(info, TreeVerifier::Scope::Path, environment());
            return false;
        } catch (const GroupDataIntegrityException&) {
            return true;
        }
    };
    EXPECT_FALSE(refusedWith([](CommitStatement&) {}, true)) << "the honest statement re-signed must pass";
    EXPECT_TRUE(refusedWith([](CommitStatement& s) { s.groupId = "other"; }, true));
    EXPECT_TRUE(refusedWith([](CommitStatement& s) { s.treeVersion = 1; }, true));
    EXPECT_TRUE(refusedWith([](CommitStatement& s) { s.keyVersion += 1; }, true));
    EXPECT_TRUE(refusedWith([](CommitStatement& s) { s.groupPubKey = "other"; }, true));
    EXPECT_TRUE(refusedWith([](CommitStatement& s) { s.rosterVersion += 1; }, true));
    EXPECT_TRUE(refusedWith([](CommitStatement& s) { s.rosterHash[0] ^= 1; }, true));
    EXPECT_TRUE(refusedWith([](CommitStatement& s) { s.treeHash[0] ^= 1; }, true));
    EXPECT_TRUE(refusedWith([](CommitStatement& s) { s.committerSeat += 1; }, true));
    EXPECT_TRUE(refusedWith([&](CommitStatement& s) { s.committer = id(1); }, true)) << "not at that seat";
    EXPECT_TRUE(refusedWith([](CommitStatement& s) { s.path[0].generation += 1; }, true)) << "no longer vouches";
    EXPECT_TRUE(refusedWith([](CommitStatement& s) { s.date += 1; }, false)) << "signature no longer valid";
    EXPECT_TRUE(refusedWith([&](CommitStatement& s) {
        TreeCommits::sign(s, PrivateKey::generateRandom());
    }, false)) << "signed by a key that is not the committer's";

    // And a committer the application does not vouch for at that date.
    TreeVerifier fresh;
    TreeVerifier::Environment env = environment();
    env.verifyUsers = [](const std::vector<privmx::endpoint::core::VerificationRequest>& requests) {
        return std::vector<bool>(requests.size(), false);
    };
    EXPECT_THROW(fresh.verify(bridge.serve(id(9), false), TreeVerifier::Scope::Path, env), GroupDataIntegrityException);
}

TEST_F(TreeVerification, AsksTheUserVerifierOncePerStatementForTheKeyAndDateItWasSignedAt) {
    create(40, 0);
    std::vector<privmx::endpoint::core::VerificationRequest> asked;
    TreeVerifier::Environment env = environment();
    env.verifyUsers = [&](const std::vector<privmx::endpoint::core::VerificationRequest>& requests) {
        for (const auto& request : requests) {
            asked.push_back(request);
        }
        return std::vector<bool>(requests.size(), true);
    };
    TreeVerifier().verify(bridge.serve(id(9), false), TreeVerifier::Scope::Path, env);
    ASSERT_EQ(asked.size(), 1u) << "one statement, one request";
    EXPECT_EQ(asked[0].senderId, id(0));
    EXPECT_EQ(asked[0].senderPubKey, member(id(0)).pub);
    EXPECT_EQ(asked[0].date, 1760000000000);

    env.verifyUsers = [](const std::vector<privmx::endpoint::core::VerificationRequest>&) {
        return std::vector<bool>{};
    };
    EXPECT_THROW(
        TreeVerifier().verify(bridge.serve(id(9), false), TreeVerifier::Scope::Path, env), GroupDataIntegrityException
    ) << "an answer that does not cover every request";
}

TEST_F(TreeVerification, SECURITY_AListedGroupIsTakenOnlyAsItsLatestStatementDescribesIt) {
    create(40, 0);
    remove(id(35), {id(5)}); // seq 2, so the statement names the group id rather than the resourceId
    const server::GroupInfo info = bridge.serve(id(9), false);
    server::GroupSummary honest;
    honest.id = info.id;
    honest.resourceId = info.resourceId;
    honest.contextId = info.contextId;
    honest.users = info.users;
    honest.managers = info.managers;
    honest.keyVersion = info.keyVersion;
    honest.groupPubKey = info.groupPubKey;
    honest.rosterVersion = info.rosterVersion;
    honest.treeCommit = info.treeCommit;
    const auto refused = [&](const std::function<void(server::GroupSummary&)>& lie) {
        server::GroupSummary summary = honest;
        lie(summary);
        try {
            TreeVerifier().verifyListed(summary, environment());
            return false;
        } catch (const GroupDataIntegrityException&) {
            return true;
        }
    };
    EXPECT_FALSE(refused([](server::GroupSummary&) {}));
    EXPECT_TRUE(refused([](server::GroupSummary& s) { s.treeCommit.reset(); }));
    EXPECT_TRUE(refused([](server::GroupSummary& s) {
        s.groupPubKey = PrivateKey::generateRandom().getPublicKey().toBase58DER();
    })) << "a grant key the statement does not sign";
    EXPECT_TRUE(refused([](server::GroupSummary& s) { s.keyVersion += 1; }));
    EXPECT_TRUE(refused([](server::GroupSummary& s) { s.users.push_back("mallory"); })) << "another roster";
    EXPECT_TRUE(refused([](server::GroupSummary& s) { s.id = "other"; })) << "another group's statement";
    EXPECT_TRUE(refused([&](server::GroupSummary& s) {
        CommitStatement statement = TreeCommits::fromWire(s.treeCommit.value());
        TreeCommits::sign(statement, PrivateKey::generateRandom());
        s.treeCommit = TreeCommits::toWire(statement);
    })) << "signed by a key the UserVerifier does not vouch for";
    EXPECT_TRUE(refused([&](server::GroupSummary& s) {
        s.users.erase(std::remove(s.users.begin(), s.users.end(), id(35)), s.users.end());
        CommitStatement statement = TreeCommits::fromWire(s.treeCommit.value());
        statement.rosterHash = TreeCommits::rosterHash(s.users, s.managers);
        TreeCommits::sign(statement, member(id(35)).priv);
        s.treeCommit = TreeCommits::toWire(statement);
    })) << "a committer off the roster it signs";
}

TEST_F(TreeVerification, SECURITY_AListedGroupContinuesThePinOfAClientThatVerifiedIt) {
    create(40, 0);
    remove(id(35), {id(5)}); // seq 2: id(5) is out, but its key stays vouched
    verify(id(9), false);
    const server::GroupInfo info = bridge.serve(id(9), false);
    server::GroupSummary honest;
    honest.id = info.id;
    honest.resourceId = info.resourceId;
    honest.contextId = info.contextId;
    honest.users = info.users;
    honest.managers = info.managers;
    honest.keyVersion = info.keyVersion;
    honest.groupPubKey = info.groupPubKey;
    honest.rosterVersion = info.rosterVersion;
    honest.treeCommit = info.treeCommit;
    EXPECT_NO_THROW(verifierOf(id(9)).verifyListed(honest, environment()));
    // The removed member signs itself back in, with its own grant key, at the pinned seq and past it.
    for (const std::int64_t bump : {0, 1}) {
        server::GroupSummary summary = honest;
        summary.users.push_back(id(5));
        summary.groupPubKey = member(id(5)).pub;
        CommitStatement statement = TreeCommits::fromWire(summary.treeCommit.value());
        statement.seq += bump;
        statement.committer = id(5);
        statement.groupPubKey = summary.groupPubKey;
        statement.rosterHash = TreeCommits::rosterHash(summary.users, summary.managers);
        TreeCommits::sign(statement, member(id(5)).priv);
        summary.treeCommit = TreeCommits::toWire(statement);
        EXPECT_NO_THROW(TreeVerifier().verifyListed(summary, environment())) << "the trust-on-first-use case";
        EXPECT_THROW(verifierOf(id(9)).verifyListed(summary, environment()), EndpointGroupException) << bump;
    }
}
