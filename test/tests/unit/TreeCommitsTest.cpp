/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

/**
 * Tree hashes, roster hashes and the signed bytes of a commit statement, against fixed vectors.
 *
 * The bridge computes the same bytes and must get the same hashes, so the expected values below were computed by an
 * independent reference (Python, hashlib, straight from the spec) rather than by this code. The inputs sit next to
 * every expectation; change one and the vector has to be recomputed from the spec, not from the implementation.
 *
 *     H = sha256; u32/u64 big-endian; lp(s) = u32(len) || s
 *     LH(p)  = H("pmx-tree-leaf\0" || u32(p) || lp(userId))
 *     NH(v)  = H("pmx-tree-node\0" || u32(v) || u8(hasRecord) || [u32(gen) || u8(filled) || [lp(pk) || u64(setBy)]]
 *                || CH(left) || CH(right))                              for a keyed node
 *            = H("pmx-tree-inner\0" || u32(v) || CH(left) || CH(right))  otherwise
 *     TH     = H("pmx-tree\0" || u32(n) || CH(root))
 *     RH     = H("pmx-tree-roster\0" || u32(#u) || lp(u)... || u32(#m) || lp(m)...)   lists deduplicated, sorted
 *     SB     = ... || lp(committer) || lp(committerPubKey) || u32(committerSeat) || ...   see TreeCommits::signedBytes
 */

#include <gtest/gtest.h>

#include <functional>
#include <string>
#include <vector>

#include <privmx/crypto/Crypto.hpp>
#include <privmx/crypto/ecc/PrivateKey.hpp>
#include <privmx/utils/Utils.hpp>

#include <privmx/endpoint/group/keytree/TreeCommits.hpp>
#include <privmx/endpoint/group/keytree/TreeKeys.hpp>
#include <privmx/endpoint/group/keytree/TreeMath.hpp>

using privmx::crypto::PrivateKey;
using namespace privmx::endpoint::group;
using namespace privmx::endpoint::group::keytree;

namespace {

std::string hex(const std::string& bytes) {
    return privmx::utils::Hex::from(bytes);
}

TreeNodeState filled(std::uint32_t index, std::uint32_t generation, const std::string& publicKey, std::uint64_t setBy) {
    return TreeNodeState{index, generation, NodePublicKey::fromBase58DER(publicKey), setBy};
}

// Three seats, the last blank; the root (3) is the only keyed node: generation 2, key "pk3", set by statement 7.
TreeGroupState tinyTree() {
    TreeGroupState state;
    state.numLeaves = 3;
    state.leafAssignment = {std::string("alice"), std::string("bob"), std::nullopt};
    state.nodes = {filled(3, 2, "pk3", 7)};
    return state;
}

// Forty seats "u0".."u39" with seat 5 blank; node 31 blank at generation 1, the root 63 at generation 3 with key
// "pk63" set by statement 9.
TreeGroupState bucketedTree() {
    TreeGroupState state;
    state.numLeaves = 40;
    for (std::uint32_t i = 0; i < 40; ++i) {
        state.leafAssignment.push_back(i == 5 ? std::nullopt : std::optional<std::string>("u" + std::to_string(i)));
    }
    state.nodes = {TreeNodeState{31, 1, std::nullopt, std::nullopt}, filled(63, 3, "pk63", 9)};
    return state;
}

CommitStatement removalStatement() {
    CommitStatement statement;
    statement.seq = 7;
    statement.op = CommitOp::Remove;
    statement.groupId = "grp-1";
    statement.treeVersion = 2;
    statement.date = 1760000000000;
    statement.keyVersion = 4;
    statement.groupPubKey = "GPK";
    statement.rosterVersion = 9;
    statement.rosterHash = TreeCommits::rosterHash({"carol", "alice", "alice"}, {"bob"});
    statement.treeHash = TreeCommits::treeHash(tinyTree());
    statement.committer = "alice";
    statement.committerPubKey = "APK";
    statement.committerSeat = 0;
    statement.path = {StatementNode{3, 2, "pk3"}};
    statement.removed = {"bob"};
    return statement;
}

} // namespace

TEST(TreeCommitsHashes, LeafHashMatchesTheReference) {
    EXPECT_EQ(hex(TreeCommits::leafHash(0, "alice")), "954e9620d070401e5f6818d005b7236989c82b8fd0a2ea49cc071d4a523a814c");
}

TEST(TreeCommitsHashes, ATinyTreeHashesToTheReference) {
    EXPECT_EQ(hex(TreeCommits::treeHash(tinyTree())), "b4db5638b91886d6a97283612ab5a836890e362e279f43dc77f8e059dc17598d");
}

TEST(TreeCommitsHashes, ABucketedTreeHashesToTheReference) {
    EXPECT_EQ(
        hex(TreeCommits::treeHash(bucketedTree())), "bffad38eba44ba2cc2b751121a1f4c5c5ea108fb760cc2154800cbca5eb7c776"
    );
    // A blank record and no record at all are different states, and hash differently.
    TreeGroupState withoutRecord = bucketedTree();
    withoutRecord.nodes.erase(withoutRecord.nodes.begin());
    EXPECT_EQ(
        hex(TreeCommits::treeHash(withoutRecord)), "c552e897b7dc75832b3ddfab2447ce97a285acb3a5e3d5e82529ca9bac0abd20"
    );
}

TEST(TreeCommitsHashes, AOneSeatTreeHashesItsLeafAsTheRoot) {
    TreeGroupState state;
    state.numLeaves = 1;
    state.leafAssignment = {std::string("solo")};
    EXPECT_EQ(hex(TreeCommits::treeHash(state)), "1d949656bc3010296100448ebfa9a0fb2e07c04bac6b9ca49494d9afe8c04e1e");
}

TEST(TreeCommitsHashes, ARosterHashesSortedAndDeduplicated) {
    EXPECT_EQ(
        hex(TreeCommits::rosterHash({"carol", "alice", "alice"}, {"bob"})),
        "d42481d52a260799898e5b45a151ab0cfc6e8ebca9ecc8c87b3f87a7c6783a9d"
    );
    EXPECT_NE(TreeCommits::rosterHash({"alice"}, {"bob"}), TreeCommits::rosterHash({"bob"}, {"alice"}))
        << "a promotion changes the roster";
}

TEST(TreeCommitsHashes, EveryRecordFieldIsInTheHash) {
    const std::string base = TreeCommits::treeHash(bucketedTree());
    const auto changed = [&](const std::function<void(TreeGroupState&)>& change) {
        TreeGroupState state = bucketedTree();
        change(state);
        return TreeCommits::treeHash(state) != base;
    };
    EXPECT_TRUE(changed([](TreeGroupState& s) { s.nodes[1].publicKey = NodePublicKey::fromBase58DER("pk63x"); }));
    EXPECT_TRUE(changed([](TreeGroupState& s) { s.nodes[1].generation = 4; }));
    EXPECT_TRUE(changed([](TreeGroupState& s) { s.nodes[1].setBy = 10; }));
    EXPECT_TRUE(changed([](TreeGroupState& s) { s.nodes[0].generation = 2; }));
    EXPECT_TRUE(changed([](TreeGroupState& s) { s.leafAssignment[5] = std::string("mallory"); }));
    EXPECT_TRUE(changed([](TreeGroupState& s) { s.leafAssignment[37] = std::nullopt; }));
    EXPECT_FALSE(changed([](TreeGroupState& s) { s.nodes.push_back(filled(15, 1, "bucket", 1)); }))
        << "a record on a bucket node is not part of the tree";
}

TEST(TreeCommitsHashes, TheHashAlongOnePathMatchesTheWholeTree) {
    // What a member checks from the default view: its leaf, the records on its path and the copath subtrees'
    // hashes, which have to come to the same tree hash.
    const TreeGroupState state = bucketedTree();
    for (const std::uint32_t seat : {0u, 5u, 31u, 32u, 39u}) {
        std::vector<std::string> copath;
        for (const std::uint32_t node : TreeMath::copath(seat, state.numLeaves)) {
            copath.push_back(hex(TreeCommits::subtreeHash(state, node)));
        }
        EXPECT_EQ(TreeCommits::treeHashAlongPath(state, seat, copath), TreeCommits::treeHash(state)) << "seat " << seat;
        copath[0][0] = copath[0][0] == '0' ? '1' : '0';
        EXPECT_NE(TreeCommits::treeHashAlongPath(state, seat, copath), TreeCommits::treeHash(state));
        copath.pop_back();
        EXPECT_THROW(TreeCommits::treeHashAlongPath(state, seat, copath), std::invalid_argument);
    }
}

TEST(TreeCommitsHashes, AFilledRecordWithoutItsStatementDoesNotHash) {
    TreeGroupState state = tinyTree();
    state.nodes[0].setBy.reset();
    EXPECT_THROW(TreeCommits::treeHash(state), std::invalid_argument);
}

// signed bytes

TEST(TreeCommitsStatement, SignedBytesMatchTheReference) {
    const std::string bytes = TreeCommits::signedBytes(removalStatement());
    EXPECT_EQ(
        hex(bytes),
        "706d782d747265652d636f6d6d697400000000056772702d310000000200000000000000070300000199c82cc000000000000000000400"
        "00000347504b0000000000000009d42481d52a260799898e5b45a151ab0cfc6e8ebca9ecc8c87b3f87a7c6783a9db4db5638b91886d6a9"
        "7283612ab5a836890e362e279f43dc77f8e059dc17598d00000005616c6963650000000341504b00000000000000010000000300000002"
        "00000003706b3300000000000000000000000100000003626f62"
    );
    EXPECT_EQ(hex(privmx::crypto::Crypto::sha256(bytes)), "8d06b165a681d3b8a7501c382459ac619e258ada00bd4dbccf063a68115ccff7");
}

TEST(TreeCommitsStatement, ASignatureCoversEveryField) {
    const PrivateKey alice = PrivateKey::generateRandom();
    CommitStatement statement = removalStatement();
    TreeCommits::sign(statement, alice);
    ASSERT_EQ(statement.signature.size(), 65u);
    EXPECT_EQ(statement.committerPubKey, alice.getPublicKey().toBase58DER()) << "the signer's key";
    EXPECT_TRUE(TreeCommits::verifySignature(statement, alice.getPublicKey()));
    EXPECT_FALSE(TreeCommits::verifySignature(statement, PrivateKey::generateRandom().getPublicKey()));

    const std::vector<std::function<void(CommitStatement&)>> tampering = {
        [](CommitStatement& s) { s.seq += 1; },
        [](CommitStatement& s) { s.op = CommitOp::Add; },
        [](CommitStatement& s) { s.groupId = "grp-2"; },
        [](CommitStatement& s) { s.treeVersion = 1; },
        [](CommitStatement& s) { s.date += 1; },
        [](CommitStatement& s) { s.keyVersion += 1; },
        [](CommitStatement& s) { s.groupPubKey = "GPK2"; },
        [](CommitStatement& s) { s.rosterVersion += 1; },
        [](CommitStatement& s) { s.rosterHash[0] ^= 1; },
        [](CommitStatement& s) { s.treeHash[31] ^= 1; },
        [](CommitStatement& s) { s.committer = "mallory"; },
        [](CommitStatement& s) { s.committerPubKey = "MPK"; },
        [](CommitStatement& s) { s.committerSeat = 1; },
        [](CommitStatement& s) { s.path[0].generation = 3; },
        [](CommitStatement& s) { s.path[0].publicKey = "pk4"; },
        [](CommitStatement& s) { s.path.clear(); },
        [](CommitStatement& s) { s.addedUsers = {"mallory"}; },
        [](CommitStatement& s) { s.addedManagers = {"mallory"}; },
        [](CommitStatement& s) { s.removed.clear(); },
    };
    for (std::size_t i = 0; i < tampering.size(); ++i) {
        CommitStatement changed = statement;
        tampering[i](changed);
        EXPECT_FALSE(TreeCommits::verifySignature(changed, alice.getPublicKey())) << "field change " << i;
    }
}

TEST(TreeCommitsStatement, RoundTripsThroughTheWire) {
    CommitStatement statement = removalStatement();
    TreeCommits::sign(statement, PrivateKey::generateRandom());
    const server::GroupTreeCommit wire = TreeCommits::toWire(statement);
    EXPECT_EQ(wire.op, "remove");
    EXPECT_EQ(wire.treeHash, "b4db5638b91886d6a97283612ab5a836890e362e279f43dc77f8e059dc17598d") << "lowercase hex";
    const CommitStatement back = TreeCommits::fromWire(server::GroupTreeCommit::fromJSON(wire.toJSON()));
    EXPECT_EQ(TreeCommits::digest(back), TreeCommits::digest(statement));
}

TEST(TreeCommitsStatement, RefusesWhatDoesNotDecode) {
    CommitStatement statement = removalStatement();
    TreeCommits::sign(statement, PrivateKey::generateRandom());
    const auto refused = [&](const std::function<void(server::GroupTreeCommit&)>& change) {
        server::GroupTreeCommit wire = TreeCommits::toWire(statement);
        change(wire);
        try {
            TreeCommits::fromWire(wire);
            return false;
        } catch (const std::invalid_argument&) {
            return true;
        }
    };
    EXPECT_TRUE(refused([](server::GroupTreeCommit& w) { w.op = "merge"; }));
    EXPECT_TRUE(refused([](server::GroupTreeCommit& w) { w.seq = -1; }));
    EXPECT_TRUE(refused([](server::GroupTreeCommit& w) { w.committerSeat = std::int64_t(1) << 33; }));
    EXPECT_TRUE(refused([](server::GroupTreeCommit& w) { w.treeHash = w.treeHash.substr(2); }));
    EXPECT_TRUE(refused([](server::GroupTreeCommit& w) { w.rosterHash[0] = 'A'; }));
    EXPECT_TRUE(refused([](server::GroupTreeCommit& w) { w.signature = privmx::utils::Base64::from("short"); }));
}

TEST(TreeCommitsStatement, AStatementForAPlanDescribesThePostState) {
    const std::vector<std::string> ids{"u0", "u1", "u2"};
    std::vector<TreeMember> members;
    for (const std::string& id : ids) {
        members.push_back(TreeMember{id, PrivateKey::generateRandom().getPublicKey()});
    }
    TreeKeyCache cache;
    TreeKeys keys(cache);
    const CommitPlan plan = keys.planCreate(members, "u1", PrivateKey::generateRandom());
    const CommitStatement statement = TreeCommits::statementFor(
        plan, CommitOp::Create, "res", 5, 1, "GPK", 1, {"u2", "u0"}, {"u1"}, "u1", {"u2", "u0"}, {"u1"}, {}
    );
    EXPECT_EQ(statement.seq, 1u);
    EXPECT_EQ(statement.committerSeat, 1u);
    ASSERT_EQ(statement.path.size(), 1u);
    EXPECT_EQ(statement.path[0].nodeIndex, 3u);
    EXPECT_EQ(statement.addedUsers, (std::vector<std::string>{"u0", "u2"})) << "deltas sorted";
    EXPECT_EQ(statement.rosterHash, TreeCommits::rosterHash({"u0", "u2"}, {"u1"}));
    TreeGroupState post;
    post.numLeaves = 3;
    post.leafAssignment = {ids[0], ids[1], ids[2]};
    post.nodes = {TreeNodeState{3, 0, plan.refreshed[0].key.getPublicKey(), 1}};
    EXPECT_EQ(statement.treeHash, TreeCommits::treeHash(post)) << "the refreshed nodes carry setBy = seq";
}
