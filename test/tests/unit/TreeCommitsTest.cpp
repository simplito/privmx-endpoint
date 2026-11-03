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
 * The signed-bytes and policy-hash vectors are read from `test/fixtures/keytree/keytree-vectors.json`, which
 * `test/fixtures/keytree/reference.py` writes; the bridge reads a byte-identical copy of it.
 *
 *     H = sha256; u32/u64 big-endian; lp(s) = u32(len) || s
 *     LH(p)  = H("pmx-tree-leaf\0" || u32(p) || lp(userId))
 *     NH(v)  = H("pmx-tree-node\0" || u32(v) || u8(hasRecord) || [u32(gen) || u8(filled) || [lp(pk) || u64(setBy)]]
 *                || CH(left) || CH(right))                              for a keyed node
 *            = H("pmx-tree-inner\0" || u32(v) || CH(left) || CH(right))  otherwise
 *     TH     = H("pmx-tree\0" || u32(n) || CH(root))
 *     RH     = H("pmx-tree-roster\0" || u32(#u) || lp(u)... || u32(#m) || lp(m)...)   lists deduplicated, sorted
 *     SB     = H-tag || lp(groupId) || u32(treeVersion) || u64(seq) || lp(prevDigest) || ...
 *              ... || RH || TH || PH || lp(committer) || lp(committerPubKey) || u32(committerSeat) || ...
 *              see TreeCommits::signedBytes and reference.py
 *     PH     = H("pmx-group-policy\0" || lp(creator) || lp(update) || lp(rotateKeys) || lp(updatePolicy)
 *                || lp(ownerCanBeRemovedFromManagers))      each rule resolved against the frozen v3 defaults
 *              (each path entry: u32(v) || u32(gen) || lp(pk) || subtreeHash)
 */

#include <gtest/gtest.h>

#include <fstream>
#include <map>
#include <optional>
#include <set>
#include <functional>
#include <sstream>
#include <string>
#include <vector>

#include <Poco/JSON/Array.h>
#include <Poco/JSON/Object.h>

#include <privmx/crypto/Crypto.hpp>
#include <privmx/crypto/ecc/PrivateKey.hpp>
#include <privmx/utils/Utils.hpp>

#include <privmx/endpoint/group/keytree/TreeCommits.hpp>
#include <privmx/endpoint/group/keytree/TreeKeys.hpp>
#include <privmx/endpoint/group/keytree/TreeMath.hpp>

#include "TestHelpers.hpp"

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
    statement.prevDigest = std::string(32, '\x22');
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
    statement.path = {StatementNode{3, 2, "pk3", std::string(32, '\x11')}};
    statement.removed = {"bob"};
    statement.policyHash = TreeCommits::rules(Poco::Dynamic::Var(), "alice").hash;
    return statement;
}

Poco::JSON::Object::Ptr vectors() {
    std::ifstream file(std::string(PRIVMX_TEST_FIXTURES_DIR) + "/keytree/keytree-vectors.json");
    std::stringstream text;
    text << file.rdbuf();
    return privmx::utils::Utils::parseJsonObject(text.str());
}

std::string bytesOf(const std::string& hexString) {
    return privmx::utils::Hex::toString(hexString);
}

// A statement of the vectors file, as the wire form both sides read it.
CommitStatement statementOf(const Poco::JSON::Object::Ptr& wire) {
    CommitStatement statement;
    statement.seq = wire->getValue<std::uint64_t>("seq");
    statement.prevDigest = bytesOf(wire->getValue<std::string>("prevDigest"));
    const std::string op = wire->getValue<std::string>("op");
    statement.op = op == "remove" ? CommitOp::Remove : op == "policy" ? CommitOp::Policy : CommitOp::Create;
    statement.groupId = wire->getValue<std::string>("groupId");
    statement.treeVersion = wire->getValue<std::uint32_t>("treeVersion");
    statement.date = wire->getValue<std::uint64_t>("date");
    statement.keyVersion = wire->getValue<std::uint64_t>("keyVersion");
    statement.groupPubKey = wire->getValue<std::string>("groupPubKey");
    statement.rosterVersion = wire->getValue<std::uint64_t>("rosterVersion");
    statement.rosterHash = bytesOf(wire->getValue<std::string>("rosterHash"));
    statement.treeHash = bytesOf(wire->getValue<std::string>("treeHash"));
    statement.policyHash = bytesOf(wire->getValue<std::string>("policyHash"));
    statement.committer = wire->getValue<std::string>("committer");
    statement.committerPubKey = wire->getValue<std::string>("committerPubKey");
    statement.committerSeat = wire->getValue<std::uint32_t>("committerSeat");
    const auto path = wire->getArray("path");
    for (std::size_t i = 0; i < path->size(); ++i) {
        const auto entry = path->getObject(static_cast<unsigned>(i));
        statement.path.push_back(StatementNode{
            entry->getValue<std::uint32_t>("nodeIndex"), entry->getValue<std::uint32_t>("generation"),
            entry->getValue<std::string>("publicKey"), bytesOf(entry->getValue<std::string>("subtreeHash"))
        });
    }
    for (const auto& [name, list] : std::vector<std::pair<std::string, std::vector<std::string>*>>{
             {"addedUsers", &statement.addedUsers}, {"addedManagers", &statement.addedManagers}, {"removed", &statement.removed}
         }) {
        const auto values = wire->getArray(name);
        for (std::size_t i = 0; i < values->size(); ++i) {
            list->push_back(values->getElement<std::string>(static_cast<unsigned>(i)));
        }
    }
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

TEST(TreeCommitsHashes, SECURITY_AGroupIdFollowsFromItsContextAndResourceId) {
    // The bridge's CommitStatement.test.ts holds the same vector: a genesis statement passes only for this id.
    EXPECT_EQ(TreeCommits::groupId("ctx", "res"), "c05bb98afb4dd712d19bfc4c42f84cf213274a8345b6c2d55d3cf941c2fea17f");
    EXPECT_NE(TreeCommits::groupId("ctxr", "es"), TreeCommits::groupId("ctx", "res"));
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
    const auto all = vectors()->getArray("signedBytes");
    ASSERT_EQ(all->size(), 2u);
    for (std::size_t i = 0; i < all->size(); ++i) {
        const auto vector = all->getObject(static_cast<unsigned>(i));
        const CommitStatement statement = statementOf(vector->getObject("statement"));
        EXPECT_EQ(hex(TreeCommits::signedBytes(statement)), vector->getValue<std::string>("expectedHex")) << i;
    }
    // The first vector is this file's removal statement; the bytes before `policyHash` are those of the old vector.
    EXPECT_EQ(hex(TreeCommits::signedBytes(removalStatement())), all->getObject(0)->getValue<std::string>("expectedHex"));
}

TEST(TreeCommitsPolicy, APolicyHashesToTheSharedVectors) {
    const auto all = vectors()->getArray("policyHash");
    ASSERT_EQ(all->size(), 6u);
    for (std::size_t i = 0; i < all->size(); ++i) {
        const auto vector = all->getObject(static_cast<unsigned>(i));
        EXPECT_EQ(
            hex(TreeCommits::rules(vector->get("policy"), vector->getValue<std::string>("creator")).hash),
            vector->getValue<std::string>("expectedHex")
        ) << i;
    }
}

TEST(TreeCommitsPolicy, InheritDefaultAndAbsentResolveToTheV3Defaults) {
    const GroupRules absent = TreeCommits::rules(Poco::Dynamic::Var(), "alice");
    EXPECT_EQ(absent.update, "manager");
    EXPECT_EQ(absent.rotateKeys, "manager");
    EXPECT_EQ(absent.updatePolicy, "manager");
    EXPECT_EQ(absent.ownerCanBeRemovedFromManagers, "yes");
    EXPECT_EQ(absent.creator, "alice");
    for (const std::string value : {"inherit", "default"}) {
        const GroupRules resolved = TreeCommits::rules(
            policyOf({{"update", value}, {"rotateKeys", value}, {"updatePolicy", value}, {"ownerCanBeRemovedFromManagers", value}}),
            "alice"
        );
        EXPECT_EQ(resolved.hash, absent.hash) << value;
    }
    EXPECT_EQ(TreeCommits::rules(policyOf({}), "alice").hash, absent.hash) << "{} is no policy";
    EXPECT_NE(TreeCommits::rules(policyOf({{"update", "manager"}}), "bob").hash, absent.hash) << "the creator is signed";
    EXPECT_THROW(TreeCommits::rules(Poco::Dynamic::Var(5), "alice"), std::invalid_argument);
    Poco::JSON::Object::Ptr numeric = new Poco::JSON::Object();
    numeric->set("update", 5);
    EXPECT_THROW(TreeCommits::rules(numeric, "alice"), std::invalid_argument);
}

TEST(TreeCommitsPolicy, FieldsTheStatementsDoNotSignDoNotChangeTheHash) {
    const auto base = TreeCommits::rules(policyOf({{"update", "user"}}), "alice").hash;
    Poco::JSON::Object::Ptr wider = policyOf({{"update", "user"}, {"get", "all"}, {"delete", "none"}}).extract<Poco::JSON::Object::Ptr>();
    Poco::JSON::Object::Ptr item = new Poco::JSON::Object();
    item->set("get", "all");
    wider->set("item", item);
    EXPECT_EQ(TreeCommits::rules(wider, "alice").hash, base);
    EXPECT_NE(TreeCommits::rules(policyOf({{"update", "user,manager"}}), "alice").hash, base) << "verbatim";
}

TEST(TreeCommitsPolicy, RulesAreEvaluatedAsTheBridgeEvaluatesThem) {
    // (rule, member, manager, owner) -> allowed, as PolicyService.userMeetsPolicy answers it.
    struct Case {
        std::string rule;
        bool member, manager, owner, allowed;
    };
    for (const Case& c : std::vector<Case>{
             {"manager", true, true, false, true},     {"manager", true, false, false, false},
             {"user", true, false, false, true},       {"user", false, false, false, false},
             {"owner", false, false, true, true},      {"owner", true, true, false, false},
             {"manager,owner", true, false, true, true}, {"manager,owner", true, false, false, false},
             {"owner&user", true, false, true, true},  {"owner&user", false, false, true, false},
             {"none", true, true, true, false},        {"all", false, false, false, true},
             {"itemOwner", true, true, true, false},   {"admin", true, true, true, false},
             {"", true, true, true, false},            {"user,", true, false, false, true},
             // Fail closed: an empty alternative or atom admits nobody.
             {",manager", true, false, false, false},  {"manager,,user", false, false, false, false},
             {"manager,", true, false, false, false},  {"&manager", true, true, false, false},
             {"manager&", true, true, false, false},   {" manager", true, true, false, false},
         }) {
        EXPECT_EQ(TreeCommits::allows(c.rule, c.member, c.manager, c.owner), c.allowed)
            << "'" << c.rule << "' " << c.member << c.manager << c.owner;
    }
}

TEST(TreeCommitsPolicy, SECURITY_ARuleOutsideTheGroupGrammarIsRefused) {
    // The bridge's validator grammar; a rule outside it is never signed and, served, never evaluated.
    for (const std::string field : {"update", "rotateKeys", "updatePolicy"}) {
        for (const std::string rule : {",manager", "manager,,user", "manager,", "&manager", "manager&", " manager",
                                       "admin", "itemOwner", "manager&manager", "user&manager,manager&user",
                                       "all&manager", "none,user", ""}) {
            EXPECT_THROW(TreeCommits::rules(policyOf({{field, rule}}), "alice"), std::invalid_argument)
                << field << " '" << rule << "'";
        }
        for (const std::string rule : {"none", "all", "owner&user,manager", "manager,owner"}) {
            EXPECT_NO_THROW(TreeCommits::rules(policyOf({{field, rule}}), "alice")) << field << " '" << rule << "'";
        }
    }
    EXPECT_THROW(TreeCommits::rules(policyOf({{"ownerCanBeRemovedFromManagers", "maybe"}}), "alice"), std::invalid_argument);
}

TEST(TreeCommitsPolicy, TheOwnerLeavesTheManagersOnlyIfThePolicySaysSo) {
    CommitStatement removal = removalStatement(); // alice removes bob
    removal.removed = {"carol"};
    const std::set<std::string> users{"alice"};
    const std::set<std::string> managers{"carol", "bob"};
    for (const auto& [rule, allowed] : std::vector<std::pair<std::string, bool>>{{"yes", true}, {"no", false}}) {
        const GroupRules rules =
            TreeCommits::rules(policyOf({{"update", "user"}, {"ownerCanBeRemovedFromManagers", rule}}), "carol");
        EXPECT_EQ(TreeCommits::permits(rules, removal, users, managers), allowed) << rule;
    }
    removal.removed = {"bob"}; // not the owner
    const GroupRules no = TreeCommits::rules(policyOf({{"update", "user"}, {"ownerCanBeRemovedFromManagers", "no"}}), "carol");
    EXPECT_TRUE(TreeCommits::permits(no, removal, users, managers));
}

TEST(TreeCommitsPolicy, AnOpWithoutARowIsNotPermitted) {
    CommitStatement statement = removalStatement();
    statement.op = static_cast<CommitOp>(7);
    const GroupRules open = TreeCommits::rules(policyOf({{"update", "all"}, {"rotateKeys", "all"}, {"updatePolicy", "all"}}), "alice");
    EXPECT_FALSE(TreeCommits::permits(open, statement, {"alice"}, {"alice"}));
    EXPECT_TRUE(TreeCommits::deltasProblem(statement, {"alice"}, {}).has_value());
}

TEST(TreeCommitsPolicy, DeltasProblemNamesWhatTheRowRefuses) {
    const std::set<std::string> users{"alice", "bob"};
    const std::set<std::string> managers{"carol"};
    CommitStatement add = removalStatement();
    add.op = CommitOp::Add;
    add.removed.clear();
    add.addedUsers = {"dave"};
    EXPECT_FALSE(TreeCommits::deltasProblem(add, users, managers).has_value());
    add.addedManagers = {"bob"};
    EXPECT_EQ(TreeCommits::deltasProblem(add, users, managers), std::optional<std::string>("user 'bob' is already a member"));
    add.addedManagers = {"dave"};
    EXPECT_TRUE(TreeCommits::deltasProblem(add, users, managers).has_value()) << "the added lists not disjoint";
    add.addedManagers.clear();
    add.addedUsers = {"dave", "dave"};
    EXPECT_TRUE(TreeCommits::deltasProblem(add, users, managers).has_value()) << "a user listed twice";
    add.addedUsers = {"dave"};
    add.removed = {"bob"};
    EXPECT_TRUE(TreeCommits::deltasProblem(add, users, managers).has_value()) << "an add that removes";

    CommitStatement removal = removalStatement(); // alice removes bob
    EXPECT_FALSE(TreeCommits::deltasProblem(removal, users, managers).has_value());
    removal.removed = {"mallory"};
    EXPECT_TRUE(TreeCommits::deltasProblem(removal, users, managers).has_value()) << "a non-member";
    removal.removed = {"alice"};
    EXPECT_TRUE(TreeCommits::deltasProblem(removal, users, managers).has_value()) << "the committer itself";
    removal.removed.clear();
    EXPECT_TRUE(TreeCommits::deltasProblem(removal, users, managers).has_value()) << "nobody";

    for (const CommitOp op : {CommitOp::SelfUpdate, CommitOp::Policy, CommitOp::Rotate, CommitOp::Create}) {
        CommitStatement other = removalStatement();
        other.op = op;
        EXPECT_TRUE(TreeCommits::deltasProblem(other, users, managers).has_value()) << "removed on op " << int(op);
        other.removed.clear();
        EXPECT_FALSE(TreeCommits::deltasProblem(other, users, managers).has_value());
        other.addedUsers = {"dave"};
        EXPECT_TRUE(TreeCommits::deltasProblem(other, users, managers).has_value()) << "added on op " << int(op);
    }
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
        [](CommitStatement& s) { s.prevDigest[0] ^= 1; },
        [](CommitStatement& s) { s.op = CommitOp::Add; },
        [](CommitStatement& s) { s.groupId = "grp-2"; },
        [](CommitStatement& s) { s.treeVersion = 1; },
        [](CommitStatement& s) { s.date += 1; },
        [](CommitStatement& s) { s.keyVersion += 1; },
        [](CommitStatement& s) { s.groupPubKey = "GPK2"; },
        [](CommitStatement& s) { s.rosterVersion += 1; },
        [](CommitStatement& s) { s.rosterHash[0] ^= 1; },
        [](CommitStatement& s) { s.treeHash[31] ^= 1; },
        [](CommitStatement& s) { s.policyHash[0] ^= 1; },
        [](CommitStatement& s) { s.committer = "mallory"; },
        [](CommitStatement& s) { s.committerPubKey = "MPK"; },
        [](CommitStatement& s) { s.committerSeat = 1; },
        [](CommitStatement& s) { s.path[0].generation = 3; },
        [](CommitStatement& s) { s.path[0].publicKey = "pk4"; },
        [](CommitStatement& s) { s.path[0].subtreeHash[0] ^= 1; },
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
    EXPECT_FALSE(wire.toJSON()->has("policy")) << "only a creation and a policy statement carry the policy";
    const CommitStatement back = TreeCommits::fromWire(server::GroupTreeCommit::fromJSON(wire.toJSON()));
    EXPECT_EQ(TreeCommits::digest(back), TreeCommits::digest(statement));

    CommitStatement change = removalStatement();
    change.op = CommitOp::Policy;
    change.removed.clear();
    change.path.clear();
    change.policy = policyOf({{"update", "user"}, {"get", "all"}});
    change.policyHash = TreeCommits::rules(change.policy.value(), "alice").hash;
    TreeCommits::sign(change, PrivateKey::generateRandom());
    const server::GroupTreeCommit changeWire = TreeCommits::toWire(change);
    EXPECT_EQ(changeWire.op, "policy");
    const CommitStatement changeBack = TreeCommits::fromWire(server::GroupTreeCommit::deserialize(changeWire.serialize()));
    EXPECT_EQ(changeBack.op, CommitOp::Policy);
    EXPECT_EQ(TreeCommits::digest(changeBack), TreeCommits::digest(change));
    ASSERT_TRUE(changeBack.policy.has_value());
    EXPECT_EQ(TreeCommits::rules(changeBack.policy.value(), "alice").hash, change.policyHash);
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
    EXPECT_TRUE(refused([](server::GroupTreeCommit& w) { w.op = "policyX"; }));
    EXPECT_TRUE(refused([](server::GroupTreeCommit& w) { w.policyHash = ""; })) << "missing";
    EXPECT_TRUE(refused([](server::GroupTreeCommit& w) { w.policyHash = w.policyHash.substr(2); })) << "short";
    EXPECT_TRUE(refused([](server::GroupTreeCommit& w) { w.seq = -1; }));
    EXPECT_TRUE(refused([](server::GroupTreeCommit& w) { w.seq = 0; }));
    EXPECT_TRUE(refused([](server::GroupTreeCommit& w) { w.keyVersion = 0; }));
    EXPECT_TRUE(refused([](server::GroupTreeCommit& w) { w.keyVersion = std::int64_t(1) << 32; })) << "past 32 bits";
    EXPECT_TRUE(refused([](server::GroupTreeCommit& w) { w.committerSeat = std::int64_t(1) << 33; }));
    EXPECT_TRUE(refused([](server::GroupTreeCommit& w) { w.treeHash = w.treeHash.substr(2); }));
    EXPECT_TRUE(refused([](server::GroupTreeCommit& w) { w.rosterHash[0] = 'A'; }));
    EXPECT_TRUE(refused([](server::GroupTreeCommit& w) { w.path[0].subtreeHash = ""; }));
    EXPECT_TRUE(refused([](server::GroupTreeCommit& w) { w.signature = privmx::utils::Base64::from("short"); }));
    EXPECT_TRUE(refused([](server::GroupTreeCommit& w) { w.prevDigest = ""; })) << "only seq 1 follows nothing";
    EXPECT_TRUE(refused([](server::GroupTreeCommit& w) { w.seq = 1; })) << "and it follows nothing";
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
        plan, CommitOp::Create, "res", 5, 1, "GPK", 1, {"u2", "u0"}, {"u1"}, "u1", {"u2", "u0", "u2"}, {"u1"}, {},
        std::string(32, '\x33')
    );
    EXPECT_EQ(statement.policyHash, std::string(32, '\x33'));
    EXPECT_EQ(statement.seq, 1u);
    EXPECT_EQ(statement.committerSeat, 1u);
    ASSERT_EQ(statement.path.size(), 1u);
    EXPECT_EQ(statement.path[0].nodeIndex, 3u);
    EXPECT_EQ(statement.addedUsers, (std::vector<std::string>{"u0", "u2"}))
        << "deltas sorted and deduplicated, as the bridge expects them";
    EXPECT_EQ(statement.rosterHash, TreeCommits::rosterHash({"u0", "u2"}, {"u1"}));
    TreeGroupState post;
    post.numLeaves = 3;
    post.leafAssignment = {ids[0], ids[1], ids[2]};
    post.nodes = {TreeNodeState{3, 0, plan.refreshed[0].key.getPublicKey(), 1}};
    EXPECT_EQ(statement.treeHash, TreeCommits::treeHash(post)) << "the refreshed nodes carry setBy = seq";
    EXPECT_EQ(statement.path[0].subtreeHash, TreeCommits::subtreeHash(post, 3)) << "and their post-state subtree";
}

TEST(TreeCommits, SECURITY_OpKeysOfDifferentOperationsNeverCollide) {
    // A resend after an unknown outcome is matched by this key: two different operations must never share one.
    EXPECT_NE(TreeCommits::opKey("remove", {std::string("a\0b", 3)}), TreeCommits::opKey("remove", {"a", "b"}));
    EXPECT_NE(
        TreeCommits::opKey("add", {"ab", "user", "K", "c", "user", "K"}),
        TreeCommits::opKey("add", {"a", "buser", "K", "c", "user", "K"})
    );
    EXPECT_NE(TreeCommits::opKey("ab"), TreeCommits::opKey("a", {"b"}));
    EXPECT_NE(TreeCommits::opKey("remove", {}), TreeCommits::opKey("remove", {""}));
    EXPECT_EQ(TreeCommits::opKey("remove", {"a", "b"}), TreeCommits::opKey("remove", {"a", "b"}));
}
