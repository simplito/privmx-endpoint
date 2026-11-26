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
 *     PH     = H("pmx-group-rules-v1\0" || lp(creator) || lp(rule)*9)   the rulesHash, TreeCommits::ruleFields order
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
#include <tuple>
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
    statement.policyHash = TreeCommits::rules(policyOf({}), "alice").hash;
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
    statement.op = op == "remove" ? CommitOp::Remove :
        op == "policy"            ? CommitOp::Policy :
        op == "roles"             ? CommitOp::Roles :
        op == "reseat"            ? CommitOp::Reseat :
                                    CommitOp::Create;
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
    ASSERT_EQ(all->size(), 4u);
    for (std::size_t i = 0; i < all->size(); ++i) {
        const auto vector = all->getObject(static_cast<unsigned>(i));
        const CommitStatement statement = statementOf(vector->getObject("statement"));
        EXPECT_EQ(hex(TreeCommits::signedBytes(statement)), vector->getValue<std::string>("expectedHex")) << i;
    }
    // The first vector is this file's removal statement; the bytes before `policyHash` are those of the old vector.
    EXPECT_EQ(hex(TreeCommits::signedBytes(removalStatement())), all->getObject(0)->getValue<std::string>("expectedHex"));
}

TEST(TreeCommitsPolicy, RulesHashToTheSharedVectors) {
    const auto all = vectors()->getArray("policyHash");
    ASSERT_EQ(all->size(), 7u);
    for (std::size_t i = 0; i < all->size(); ++i) {
        const auto vector = all->getObject(static_cast<unsigned>(i));
        EXPECT_EQ(
            hex(TreeCommits::rules(vector->get("policy"), vector->getValue<std::string>("creator")).hash),
            vector->getValue<std::string>("expectedHex")
        ) << i;
    }
}

TEST(TreeCommitsPolicy, RulesHashToTheBridgesVectors) {
    // Pasted from the Bridge's conformance test, so neither side's generator is the other's only check.
    const std::map<std::string, std::string> fifth{
        {"changeRoles", "nobody"}, {"changeRules", "nobody"}, {"changeVisibility", "members"}, {"editPrivateMeta", "members"}
    };
    std::map<std::string, std::string> allMembers;
    for (const std::string& field : TreeCommits::ruleFields()) {
        allMembers[field] = "members";
    }
    for (const auto& [rules, creator, expected] : std::vector<std::tuple<std::map<std::string, std::string>, std::string, std::string>>{
             {{}, "alice", "293d66587c59ddae7286ffcdeaa73afea8698e3e1f26b13c3e5dafa212372e77"},
             {{}, "bob", "83704acfe39c99a755517ae4a56360a3c0f8dc130c52fe56cf553e5b4a43e477"},
             {{{"addMembers", "members"},
               {"removeMembers", "nobody"},
               {"replaceMemberKeys", "members"},
               {"trimHistory", "nobody"},
               {"editPublicMeta", "members"}},
              "alice",
              "757d92df6e2bef81c90c3aaccddc69642b36a66a0ed15ba807b2ccff639fed9a"},
             {allMembers, "alice", "833ecdd293832d6ac5daa240242a15b72eb9e9cc8102c2d5de59e86641217586"},
             {fifth, "alice", "f6f11160baa6217326dbd3e1c8fb2c3a9bbc59253df0ebb60fa7e13eabc42db8"},
             {{{"trimHistory", "nobody"}}, "alice", "6dfe3f16482ac7cf7cfd4751a784bc12488315209222a81b3c7a60c59f37bbd8"},
         }) {
        EXPECT_EQ(hex(TreeCommits::rules(policyOf(rules), creator).hash), expected) << creator;
    }
}

TEST(TreeCommitsPolicy, SECURITY_RulesOutsideTheContractAreRefused) {
    // Shared with the Bridge: a field missing, an unknown one, a value outside the set, the old grammar.
    const auto invalid = vectors()->getArray("invalidRules");
    ASSERT_EQ(invalid->size(), 9u);
    for (std::size_t i = 0; i < invalid->size(); ++i) {
        EXPECT_THROW(TreeCommits::rules(invalid->get(static_cast<unsigned>(i)), "alice"), std::invalid_argument) << i;
    }
    EXPECT_THROW(TreeCommits::rules(Poco::Dynamic::Var(), "alice"), std::invalid_argument) << "no rules at all";
    EXPECT_THROW(TreeCommits::rules(Poco::Dynamic::Var(5), "alice"), std::invalid_argument);
    for (const std::string& field : TreeCommits::ruleFields()) {
        for (const std::string value : {"managers", "members", "nobody"}) {
            EXPECT_NO_THROW(TreeCommits::rules(policyOf({{field, value}}), "alice")) << field << " " << value;
        }
        for (const std::string value : {"manager", "user", "owner", "all", "none", "managers,members", ""}) {
            EXPECT_THROW(TreeCommits::rules(policyOf({{field, value}}), "alice"), std::invalid_argument)
                << field << " '" << value << "'";
        }
    }
    for (const std::string field : {"manage", "history", "update", "rotateKeys"}) {
        EXPECT_THROW(TreeCommits::rules(policyOf({{field, "managers"}}), "alice"), std::invalid_argument) << field;
    }
}

TEST(TreeCommitsPolicy, EveryRuleAndTheCreatorAreSigned) {
    GroupRules base = TreeCommits::rules(policyOf({}), "alice");
    EXPECT_EQ(base.creator, "alice");
    std::set<std::string> hashes{base.hash};
    for (const std::string& field : TreeCommits::ruleFields()) {
        EXPECT_EQ(TreeCommits::ruleOf(base, field), "managers") << field;
        const GroupRules one = TreeCommits::rules(policyOf({{field, "nobody"}}), "alice");
        EXPECT_TRUE(hashes.insert(one.hash).second) << field;
    }
    EXPECT_TRUE(hashes.insert(TreeCommits::rules(policyOf({}), "bob").hash).second) << "the creator";
}

TEST(TreeCommitsPolicy, RulesAreEvaluatedOnTheRole) {
    for (const auto& [rule, member, manager, allowed] : std::vector<std::tuple<std::string, bool, bool, bool>>{
             {"managers", true, true, true},  {"managers", true, false, false}, {"members", true, false, true},
             {"members", false, false, false}, {"nobody", true, true, false},   {"manager", true, true, false},
             {"", true, true, false},
         }) {
        EXPECT_EQ(TreeCommits::allows(rule, member, manager), allowed) << "'" << rule << "' " << member << manager;
    }
}

// The permission table: every rule an op touches, and only those. alice and dave manage, bob and carol are plain
// members, mallory is not in the group; carol created it and holds no privilege for it.
TEST(TreeCommitsPolicy, SECURITY_ThePermissionTable) {
    const std::set<std::string> users{"bob", "carol"};
    const std::set<std::string> managers{"alice", "dave"};
    const auto statement = [&](const std::string& committer, CommitOp op) {
        CommitStatement result = removalStatement();
        result.committer = committer;
        result.op = op;
        result.removed.clear();
        return result;
    };
    // Whether `s` is permitted with `field` set to `value` and every other rule `others`.
    const auto permitted = [&](const CommitStatement& s, const std::string& field, const std::string& value,
                               const std::string& others = "members") {
        std::map<std::string, std::string> rules;
        for (const std::string& f : TreeCommits::ruleFields()) {
            rules[f] = others;
        }
        if (!field.empty()) {
            rules[field] = value;
        }
        return TreeCommits::permits(TreeCommits::rules(policyOf(rules), "carol"), s, users, managers);
    };
    // The rule `s` needs, by `committer`: allowed when only it is open, refused when only it is closed.
    const auto needs = [&](CommitStatement s, const std::string& field) {
        s.committer = "bob";
        EXPECT_TRUE(permitted(s, field, "members", "nobody") || field.empty())
            << "op " << int(s.op) << " with only " << field << " open";
        EXPECT_FALSE(permitted(s, field, "nobody")) << "op " << int(s.op) << " with " << field << " closed";
        EXPECT_FALSE(permitted(s, field, "managers")) << "a plain member, op " << int(s.op) << " " << field;
        s.committer = "alice";
        EXPECT_TRUE(permitted(s, field, "managers", "nobody") || field.empty()) << "a manager, op " << int(s.op);
    };

    CommitStatement add = statement("bob", CommitOp::Add);
    add.addedUsers = {"erin"};
    needs(add, "addMembers");
    EXPECT_TRUE(permitted(add, "changeRoles", "nobody")) << "a plain addition touches no role";
    add.addedManagers = {"frank"};
    EXPECT_FALSE(permitted(add, "addMembers", "nobody")) << "adding a manager needs addMembers";
    EXPECT_FALSE(permitted(add, "changeRoles", "nobody")) << "and changeRoles";
    EXPECT_TRUE(permitted(add, "", ""));

    CommitStatement removal = statement("bob", CommitOp::Remove);
    removal.removed = {"carol"};
    needs(removal, "removeMembers");
    EXPECT_TRUE(permitted(removal, "changeRoles", "nobody")) << "a plain member's removal touches no role";
    removal.removed = {"alice"};
    EXPECT_FALSE(permitted(removal, "removeMembers", "nobody")) << "removing a manager needs removeMembers";
    EXPECT_FALSE(permitted(removal, "changeRoles", "nobody")) << "and changeRoles";
    EXPECT_FALSE(permitted(removal, "changeRoles", "managers")) << "a plain member removes a manager";
    removal.committer = "dave";
    EXPECT_TRUE(permitted(removal, "", "", "managers"));

    CommitStatement reseat = statement("bob", CommitOp::Reseat);
    reseat.removed = {"alice"};
    needs(reseat, "replaceMemberKeys");
    EXPECT_TRUE(permitted(reseat, "replaceMemberKeys", "members", "nobody")) << "a manager's reseat touches no role";

    CommitStatement roles = statement("bob", CommitOp::Roles);
    roles.addedManagers = {"bob"};
    needs(roles, "changeRoles");

    needs(statement("bob", CommitOp::Policy), "changeRules");

    for (const CommitOp op : {CommitOp::Rotate, CommitOp::SelfUpdate}) {
        EXPECT_TRUE(permitted(statement("bob", op), "", "", "nobody")) << "any member, op " << int(op);
        EXPECT_FALSE(permitted(statement("mallory", op), "", "", "members")) << "a non-member, op " << int(op);
    }
    EXPECT_FALSE(permitted(statement("mallory", CommitOp::Policy), "", "", "members")) << "a non-member holds no rule";
    EXPECT_TRUE(permitted(statement("mallory", CommitOp::Create), "", "", "nobody")) << "the creator, whoever it is";
}

TEST(TreeCommitsPolicy, SECURITY_AGroupWithManagersKeepsOne) {
    const auto rules = TreeCommits::rules(policyOf({}), "carol");
    const std::set<std::string> users{"bob"};
    CommitStatement removal = removalStatement(); // alice removes
    removal.removed = {"dave", "erin"};
    EXPECT_TRUE(TreeCommits::permits(rules, removal, users, {"alice", "dave", "erin"})) << "alice stays";
    // Self-removal is refused on its own (deltasProblem); the table refuses emptying the managers regardless.
    removal.removed = {"alice", "dave"};
    EXPECT_FALSE(TreeCommits::permits(rules, removal, users, {"alice", "dave"})) << "every manager removed";

    CommitStatement demote = removalStatement();
    demote.op = CommitOp::Roles;
    demote.removed.clear();
    demote.committer = "alice";
    demote.addedUsers = {"alice"};
    EXPECT_FALSE(TreeCommits::permits(rules, demote, users, {"alice"})) << "the last manager steps down";
    EXPECT_TRUE(TreeCommits::permits(rules, demote, users, {"alice", "dave"}));
    demote.addedManagers = {"bob"};
    EXPECT_TRUE(TreeCommits::permits(rules, demote, users, {"alice"})) << "stepping down for a successor";
    // A group without managers has nobody to keep.
    CommitStatement plain = removalStatement();
    plain.removed = {"bob"};
    EXPECT_TRUE(
        TreeCommits::permits(TreeCommits::rules(policyOf({{"removeMembers", "members"}}), "x"), plain, {"alice", "bob"}, {})
    );
}

TEST(TreeCommitsPolicy, AnOpWithoutARowIsNotPermitted) {
    CommitStatement statement = removalStatement();
    statement.op = static_cast<CommitOp>(9);
    const GroupRules open = TreeCommits::rules(policyOf({{"addMembers", "members"}, {"removeMembers", "members"}}), "alice");
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
    change.policy = policyOf({{"addMembers", "members"}});
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

// ── The roster's own rules, and the two ops that are neither an addition nor a removal ──────────────────────────

TEST(TreeCommitsRoster, DeltasOfARoleChangeAndAReseat) {
    const std::set<std::string> users{"bob", "carol"};
    const std::set<std::string> managers{"alice"};
    CommitStatement roles = removalStatement();
    roles.op = CommitOp::Roles;
    roles.removed.clear();
    EXPECT_TRUE(TreeCommits::deltasProblem(roles, users, managers).has_value()) << "names nobody";
    roles.addedManagers = {"bob"};
    EXPECT_FALSE(TreeCommits::deltasProblem(roles, users, managers).has_value());
    roles.addedUsers = {"bob"};
    EXPECT_TRUE(TreeCommits::deltasProblem(roles, users, managers).has_value()) << "named for both lists";
    roles.addedUsers = {"dave"};
    EXPECT_TRUE(TreeCommits::deltasProblem(roles, users, managers).has_value()) << "not a member";
    roles.addedUsers.clear();
    roles.addedManagers = {"alice"};
    EXPECT_TRUE(TreeCommits::deltasProblem(roles, users, managers).has_value()) << "already exactly that";
    roles.removed = {"carol"};
    roles.addedManagers = {"bob"};
    EXPECT_TRUE(TreeCommits::deltasProblem(roles, users, managers).has_value()) << "a role change removes nobody";

    CommitStatement reseat = removalStatement(); // alice names bob
    reseat.op = CommitOp::Reseat;
    EXPECT_FALSE(TreeCommits::deltasProblem(reseat, users, managers).has_value());
    reseat.removed = {"alice"};
    EXPECT_TRUE(TreeCommits::deltasProblem(reseat, users, managers).has_value()) << "its own committer";
    reseat.removed = {"dave"};
    EXPECT_TRUE(TreeCommits::deltasProblem(reseat, users, managers).has_value()) << "not a member";
    reseat.removed.clear();
    EXPECT_TRUE(TreeCommits::deltasProblem(reseat, users, managers).has_value()) << "names nobody";
}
