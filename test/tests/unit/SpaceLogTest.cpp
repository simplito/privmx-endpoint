/*
 * A Space's signed history: which statement may follow which.
 *
 * Every case is something the Bridge, or a user who is no recipient, could try to slip into a Space's history. The
 * rules are the whole defence - a reader takes the recipients, the key version and the creator from the statements
 * and from nowhere else - so each rule has the forgery it stops next to it.
 */

#include <gtest/gtest.h>

#include <privmx/crypto/Crypto.hpp>
#include <privmx/crypto/ecc/PrivateKey.hpp>
#include <privmx/endpoint/core/Exception.hpp>

#include <privmx/endpoint/group/GroupException.hpp>
#include <privmx/endpoint/group/keytree/SpaceLog.hpp>

using privmx::crypto::PrivateKey;
using namespace privmx::endpoint;
using namespace privmx::endpoint::group;
using namespace privmx::endpoint::group::keytree;

class SpaceLogRules : public testing::Test {
protected:
    PrivateKey alice = PrivateKey::generateRandom();   // a recipient herself, a manager
    PrivateKey bob = PrivateKey::generateRandom();     // a recipient himself, a user
    PrivateKey carol = PrivateKey::generateRandom();   // a member of the sales group
    PrivateKey eve = PrivateKey::generateRandom();     // a user of the Context, no recipient
    PrivateKey sales1 = PrivateKey::generateRandom();  // the sales group's key, epoch 1
    PrivateKey sales2 = PrivateKey::generateRandom();  // ... and after a removal in sales
    PrivateKey support = PrivateKey::generateRandom();
    std::string key1 = privmx::crypto::Crypto::randomBytes(32);
    std::string key2 = privmx::crypto::Crypto::randomBytes(32);
    const std::string spaceId = std::string(64, 'a');

    SpaceLogUser user(const std::string& id, const PrivateKey& key, const std::string& role) {
        return {.userId = id, .pubKey = key.getPublicKey().toBase58DER(), .role = role};
    }
    SpaceLogGroup group(const std::string& id, const PrivateKey& key, std::uint64_t epoch, const std::string& role) {
        return {.groupId = id, .role = role, .groupKeyVersion = epoch, .groupPubKey = key.getPublicKey().toBase58DER()};
    }
    SpaceStatement statement(SpaceOp op, const std::optional<SpaceLogState>& prior, std::uint64_t keyVersion, const std::string& key) {
        SpaceStatement s;
        s.spaceId = spaceId;
        s.contextId = "ctx";
        s.seq = prior.has_value() ? prior->seq + 1 : 1;
        s.prevDigest = prior.has_value() ? prior->digest : std::string();
        s.op = op;
        s.date = 1700000000000;
        s.keyVersion = keyVersion;
        s.keyCommit = SpaceLog::keyCommit(spaceId, keyVersion, key);
        if (prior.has_value()) {
            s.groups = prior->groups;
            s.users = prior->users;
        }
        return s;
    }
    SpaceStatement by(SpaceStatement s, const std::string& signer, const PrivateKey& key) {
        s.signer = signer;
        s.via.clear();
        SpaceLog::sign(s, key, std::nullopt);
        return s;
    }
    SpaceStatement through(SpaceStatement s, const std::string& signer, const PrivateKey& key, const std::string& via, const PrivateKey& groupKey) {
        s.signer = signer;
        s.via = via;
        SpaceLog::sign(s, key, groupKey);
        return s;
    }
    // alice (manager), bob (user), sales at epoch 1 (manager), support (user); key version 1.
    SpaceLogState created() {
        SpaceStatement s = statement(SpaceOp::Create, std::nullopt, 1, key1);
        s.users = {user("alice", alice, "manager"), user("bob", bob, "user")};
        s.groups = {group("sales", sales1, 1, "manager"), group("support", support, 4, "user")};
        return SpaceLog::apply(std::nullopt, by(s, "alice", alice));
    }
};

TEST_F(SpaceLogRules, TheFirstStatementMakesTheSpaceAndNamesItsCreator) {
    const SpaceLogState state = created();
    EXPECT_EQ(state.creator, "alice");
    EXPECT_EQ(state.seq, 1u);
    EXPECT_EQ(state.keyVersion, 1u);
    EXPECT_EQ(state.keyCommits.at(1), SpaceLog::keyCommit(spaceId, 1, key1));
    EXPECT_EQ(state.roleOfUser("bob"), "user");
    EXPECT_EQ(state.roleOfUser("eve"), "");
    ASSERT_NE(state.group("sales"), nullptr);
    EXPECT_EQ(state.digest.size(), 32u);

    // Through a group she is in: carol makes a Space for sales and signs with the group's key as well.
    SpaceStatement s = statement(SpaceOp::Create, std::nullopt, 1, key1);
    s.groups = {group("sales", sales1, 1, "manager")};
    EXPECT_EQ(SpaceLog::apply(std::nullopt, through(s, "carol", carol, "sales", sales1)).creator, "carol");
}

TEST_F(SpaceLogRules, SECURITY_ASpaceIsMadeByOneOfItsOwnManagers) {
    SpaceStatement s = statement(SpaceOp::Create, std::nullopt, 1, key1);
    s.users = {user("alice", alice, "manager"), user("bob", bob, "user")};
    s.groups = {group("sales", sales1, 1, "user")};
    // Eve lists the right people and signs herself: she is not among them.
    EXPECT_THROW(SpaceLog::apply(std::nullopt, by(s, "eve", eve)), GroupUnauthorizedSignerException);
    // Eve signs as alice, with her own key: the list has alice's.
    EXPECT_THROW(SpaceLog::apply(std::nullopt, by(s, "alice", eve)), GroupUnauthorizedSignerException);
    // A user of the Space, not a manager; and a group that is only a user.
    EXPECT_THROW(SpaceLog::apply(std::nullopt, by(s, "bob", bob)), GroupUnauthorizedSignerException);
    EXPECT_THROW(SpaceLog::apply(std::nullopt, through(s, "carol", carol, "sales", sales1)), GroupUnauthorizedSignerException);
    // Nobody to manage it.
    s.users = {user("bob", bob, "user")};
    EXPECT_THROW(SpaceLog::apply(std::nullopt, by(s, "bob", bob)), GroupDataIntegrityException);
    // Not at key version 1, not as statement 1, or not a creation.
    s = statement(SpaceOp::Create, std::nullopt, 2, key1);
    s.users = {user("alice", alice, "manager")};
    EXPECT_THROW(SpaceLog::apply(std::nullopt, by(s, "alice", alice)), GroupDataIntegrityException);
    s = statement(SpaceOp::Rotate, std::nullopt, 1, key1);
    s.users = {user("alice", alice, "manager")};
    EXPECT_THROW(SpaceLog::apply(std::nullopt, by(s, "alice", alice)), GroupDataIntegrityException);
    // The same recipient twice.
    s = statement(SpaceOp::Create, std::nullopt, 1, key1);
    s.users = {user("alice", alice, "manager"), user("alice", alice, "user")};
    EXPECT_THROW(SpaceLog::apply(std::nullopt, by(s, "alice", alice)), GroupDataIntegrityException);
}

TEST_F(SpaceLogRules, SECURITY_AKeyVersionIsMadeByARecipientAndNobodyElse) {
    const SpaceLogState state = created();
    // The planted key: eve, a user of the Context the UserVerifier accepts, signs a rotation to a key she knows.
    EXPECT_THROW(SpaceLog::apply(state, by(statement(SpaceOp::Rotate, state, 2, key2), "eve", eve)), GroupUnauthorizedSignerException);
    // She names a group she is not in: its key is not hers to sign with.
    EXPECT_THROW(
        SpaceLog::apply(state, through(statement(SpaceOp::Rotate, state, 2, key2), "eve", eve, "sales", eve)),
        GroupUnauthorizedSignerException
    );
    // ... or a group that is no recipient.
    EXPECT_THROW(
        SpaceLog::apply(state, through(statement(SpaceOp::Rotate, state, 2, key2), "eve", eve, "eves-group", eve)),
        GroupUnauthorizedSignerException
    );
    // She adds her group to the list in the same statement: standing is judged before the statement.
    SpaceStatement adding = statement(SpaceOp::Add, state, 1, key1);
    adding.groups.push_back(group("eves-group", eve, 1, "manager"));
    EXPECT_THROW(SpaceLog::apply(state, through(adding, "eve", eve, "eves-group", eve)), GroupUnauthorizedSignerException);

    // Every recipient may: bob himself, carol through sales (a manager), dave through support (a user).
    EXPECT_EQ(SpaceLog::apply(state, by(statement(SpaceOp::Rotate, state, 2, key2), "bob", bob)).keyVersion, 2u);
    const SpaceLogState rotated =
        SpaceLog::apply(state, through(statement(SpaceOp::Rotate, state, 2, key2), "carol", carol, "sales", sales1));
    EXPECT_EQ(rotated.keyCommits.at(2), SpaceLog::keyCommit(spaceId, 2, key2));
    EXPECT_EQ(rotated.keyCommits.at(1), SpaceLog::keyCommit(spaceId, 1, key1));
    EXPECT_EQ(rotated.creator, "alice");
    EXPECT_NO_THROW(SpaceLog::apply(state, through(statement(SpaceOp::Rotate, state, 2, key2), "dave", eve, "support", support)));
}

TEST_F(SpaceLogRules, SECURITY_ARotationChangesTheKeyAndNothingElse) {
    const SpaceLogState state = created();
    // The version moves by one, to a new commitment.
    EXPECT_THROW(SpaceLog::apply(state, by(statement(SpaceOp::Rotate, state, 1, key2), "bob", bob)), GroupDataIntegrityException);
    EXPECT_THROW(SpaceLog::apply(state, by(statement(SpaceOp::Rotate, state, 3, key2), "bob", bob)), GroupDataIntegrityException);
    // A rotation that also lets somebody in, drops somebody, or promotes its author.
    SpaceStatement s = statement(SpaceOp::Rotate, state, 2, key2);
    s.users.push_back(user("eve", eve, "user"));
    EXPECT_THROW(SpaceLog::apply(state, by(s, "bob", bob)), GroupDataIntegrityException);
    s = statement(SpaceOp::Rotate, state, 2, key2);
    s.users.pop_back();
    EXPECT_THROW(SpaceLog::apply(state, by(s, "alice", alice)), GroupDataIntegrityException);
    s = statement(SpaceOp::Rotate, state, 2, key2);
    s.users[1].role = "manager";
    EXPECT_THROW(SpaceLog::apply(state, by(s, "bob", bob)), GroupDataIntegrityException);
    // ... or swaps a user's key for another.
    s = statement(SpaceOp::Rotate, state, 2, key2);
    s.users[0] = user("alice", eve, "manager");
    EXPECT_THROW(SpaceLog::apply(state, by(s, "bob", bob)), GroupDataIntegrityException);
    // A group's epoch and key may move with it: that is what a refresh after a removal in the group is. Bob, a
    // user of the Space, is not the one to do it: with his own key in the sales group's place he would be a manager.
    s = statement(SpaceOp::Rotate, state, 2, key2);
    s.groups[0] = group("sales", sales2, 2, "manager");
    EXPECT_THROW(SpaceLog::apply(state, by(s, "bob", bob)), GroupUnauthorizedSignerException);
    EXPECT_THROW(SpaceLog::apply(state, through(s, "dave", eve, "support", support)), GroupUnauthorizedSignerException);
    // A manager is, and so is the group itself - which shows its standing with the key it had.
    EXPECT_NO_THROW(SpaceLog::apply(state, by(s, "alice", alice)));
    const SpaceLogState refreshed = SpaceLog::apply(state, through(s, "carol", carol, "sales", sales1));
    EXPECT_EQ(refreshed.group("sales")->groupKeyVersion, 2u);
    // A group that is a user of the Space refreshes its own key and nobody else's.
    s = statement(SpaceOp::Rotate, state, 2, key2);
    s.groups[1] = group("support", eve, 5, "user");
    EXPECT_NO_THROW(SpaceLog::apply(state, through(s, "dave", eve, "support", support)));
    s.groups[0] = group("sales", sales2, 2, "manager");
    EXPECT_THROW(SpaceLog::apply(state, through(s, "dave", eve, "support", support)), GroupUnauthorizedSignerException);
    // Only forward, and only to another key.
    s = statement(SpaceOp::Rotate, state, 2, key2);
    s.groups[0] = group("sales", sales2, 1, "manager");
    EXPECT_THROW(SpaceLog::apply(state, by(s, "alice", alice)), GroupDataIntegrityException);
    s.groups[0] = group("sales", sales1, 2, "manager");
    EXPECT_THROW(SpaceLog::apply(state, by(s, "alice", alice)), GroupDataIntegrityException);
    // From then on the group's standing is shown with its new key: the one removed from sales holds only the old.
    EXPECT_THROW(
        SpaceLog::apply(refreshed, through(statement(SpaceOp::Rotate, refreshed, 3, key1), "mallory", eve, "sales", sales1)),
        GroupUnauthorizedSignerException
    );
    EXPECT_NO_THROW(
        SpaceLog::apply(refreshed, through(statement(SpaceOp::Rotate, refreshed, 3, key1), "carol", carol, "sales", sales2))
    );
}

TEST_F(SpaceLogRules, SECURITY_OnlyAManagerChangesTheRecipientsAndOnlyAsTheOpSays) {
    const SpaceLogState state = created();
    SpaceStatement add = statement(SpaceOp::Add, state, 1, key1);
    add.users.push_back(user("dave", eve, "user"));
    // bob is a user; support is a user.
    EXPECT_THROW(SpaceLog::apply(state, by(add, "bob", bob)), GroupUnauthorizedSignerException);
    EXPECT_THROW(SpaceLog::apply(state, through(add, "x", eve, "support", support)), GroupUnauthorizedSignerException);
    const SpaceLogState added = SpaceLog::apply(state, by(add, "alice", alice));
    EXPECT_EQ(added.roleOfUser("dave"), "user");
    EXPECT_EQ(added.keyVersion, 1u);

    // An addition keeps the key, adds somebody, and touches nobody who was there.
    SpaceStatement s = statement(SpaceOp::Add, state, 2, key2);
    s.users.push_back(user("dave", eve, "user"));
    EXPECT_THROW(SpaceLog::apply(state, by(s, "alice", alice)), GroupDataIntegrityException);
    s = statement(SpaceOp::Add, state, 1, key2);
    s.users.push_back(user("dave", eve, "user"));
    EXPECT_THROW(SpaceLog::apply(state, by(s, "alice", alice)), GroupDataIntegrityException);
    EXPECT_THROW(SpaceLog::apply(state, by(statement(SpaceOp::Add, state, 1, key1), "alice", alice)), GroupDataIntegrityException);
    s = statement(SpaceOp::Add, state, 1, key1);
    s.users.push_back(user("dave", eve, "user"));
    s.users[1].role = "manager";
    EXPECT_THROW(SpaceLog::apply(state, by(s, "alice", alice)), GroupDataIntegrityException);
    s = statement(SpaceOp::Add, state, 1, key1);
    s.users.push_back(user("dave", eve, "user"));
    s.groups[0] = group("sales", eve, 2, "manager"); // the old versions would be "wrapped for sales" under eve's key
    EXPECT_THROW(SpaceLog::apply(state, by(s, "alice", alice)), GroupDataIntegrityException);

    // A removal makes a new key, drops somebody, adds nobody, and leaves a manager.
    SpaceStatement remove = statement(SpaceOp::Remove, state, 2, key2);
    remove.users.pop_back();
    const SpaceLogState removed = SpaceLog::apply(state, through(remove, "carol", carol, "sales", sales1));
    EXPECT_EQ(removed.roleOfUser("bob"), "");
    EXPECT_EQ(removed.keyVersion, 2u);
    s = remove;
    s.keyVersion = 1;
    s.keyCommit = SpaceLog::keyCommit(spaceId, 1, key1);
    EXPECT_THROW(SpaceLog::apply(state, by(s, "alice", alice)), GroupDataIntegrityException);
    EXPECT_THROW(SpaceLog::apply(state, by(statement(SpaceOp::Remove, state, 2, key2), "alice", alice)), GroupDataIntegrityException);
    s = statement(SpaceOp::Remove, state, 2, key2);
    s.users[1] = user("eve", eve, "user");
    EXPECT_THROW(SpaceLog::apply(state, by(s, "alice", alice)), GroupDataIntegrityException);
    s = statement(SpaceOp::Remove, state, 2, key2);
    s.users = {user("bob", bob, "user")};
    s.groups = {group("support", support, 4, "user")};
    EXPECT_THROW(SpaceLog::apply(state, by(s, "alice", alice)), GroupDataIntegrityException);
    EXPECT_THROW(SpaceLog::apply(state, by(remove, "bob", bob)), GroupUnauthorizedSignerException);
}

TEST_F(SpaceLogRules, SECURITY_AStatementBelongsToItsPlaceInItsSpace) {
    const SpaceLogState state = created();
    const SpaceStatement rotate = by(statement(SpaceOp::Rotate, state, 2, key2), "bob", bob);
    const SpaceLogState rotated = SpaceLog::apply(state, rotate);
    // Replayed, skipped, or put after another history.
    EXPECT_THROW(SpaceLog::apply(rotated, rotate), GroupDataIntegrityException);
    EXPECT_THROW(SpaceLog::apply(std::nullopt, rotate), GroupDataIntegrityException);
    SpaceStatement s = statement(SpaceOp::Rotate, rotated, 3, key1);
    s.prevDigest = state.digest;
    EXPECT_THROW(SpaceLog::apply(rotated, by(s, "bob", bob)), GroupDataIntegrityException);
    s = statement(SpaceOp::Rotate, rotated, 3, key1);
    s.spaceId = std::string(64, 'b');
    EXPECT_THROW(SpaceLog::apply(rotated, by(s, "bob", bob)), GroupDataIntegrityException);
    s = statement(SpaceOp::Create, rotated, 3, key1);
    EXPECT_THROW(SpaceLog::apply(rotated, by(s, "alice", alice)), GroupDataIntegrityException);

    // Anything changed after signing: the key commitment, a role, the signer, the group named.
    for (const auto& change : std::vector<std::function<void(SpaceStatement&)>>{
             [&](SpaceStatement& t) { t.keyCommit = SpaceLog::keyCommit(spaceId, 2, key1); },
             [&](SpaceStatement& t) { t.users[1].role = "manager"; },
             [&](SpaceStatement& t) { t.groups[1].groupPubKey = eve.getPublicKey().toBase58DER(); },
             [&](SpaceStatement& t) { t.date += 1; },
             [&](SpaceStatement& t) { t.signer = "alice"; },
             [&](SpaceStatement& t) { t.via = "sales"; },
         }) {
        SpaceStatement tampered = rotate;
        change(tampered);
        EXPECT_ANY_THROW(SpaceLog::apply(state, tampered));
    }
    // A statement through a group: its signature is over this statement, and counts in the digest.
    const SpaceStatement viaSales = through(statement(SpaceOp::Rotate, state, 2, key2), "carol", carol, "sales", sales1);
    SpaceStatement lifted = through(statement(SpaceOp::Rotate, state, 2, key1), "eve", eve, "sales", eve);
    lifted.viaSignature = viaSales.viaSignature;
    EXPECT_THROW(SpaceLog::apply(state, lifted), GroupUnauthorizedSignerException);
    SpaceStatement stripped = viaSales;
    stripped.viaSignature.clear();
    EXPECT_NE(SpaceLog::digest(stripped), SpaceLog::digest(viaSales));
    SpaceStatement extra = rotate;
    extra.viaSignature = viaSales.viaSignature; // a group's signature on a statement that names none
    EXPECT_THROW(SpaceLog::apply(state, extra), GroupDataIntegrityException);
}

TEST_F(SpaceLogRules, TheWireFormKeepsEveryByteThatIsSigned) {
    const SpaceLogState state = created();
    const SpaceStatement original = through(statement(SpaceOp::Rotate, state, 2, key2), "carol", carol, "sales", sales1);
    const SpaceStatement back = SpaceLog::fromWire(SpaceLog::toWire(original));
    EXPECT_EQ(SpaceLog::signedBytes(back), SpaceLog::signedBytes(original));
    EXPECT_EQ(SpaceLog::digest(back), SpaceLog::digest(original));
    EXPECT_NO_THROW(SpaceLog::apply(state, back));
    // The order recipients are listed in is not part of what is signed.
    SpaceStatement shuffled = original;
    std::reverse(shuffled.groups.begin(), shuffled.groups.end());
    std::reverse(shuffled.users.begin(), shuffled.users.end());
    EXPECT_EQ(SpaceLog::signedBytes(shuffled), SpaceLog::signedBytes(original));
    // A key commitment is to this Space, this version and this key.
    EXPECT_NE(SpaceLog::keyCommit(spaceId, 1, key1), SpaceLog::keyCommit(spaceId, 2, key1));
    EXPECT_NE(SpaceLog::keyCommit(spaceId, 1, key1), SpaceLog::keyCommit(std::string(64, 'b'), 1, key1));
    EXPECT_NE(SpaceLog::keyCommit(spaceId, 1, key1), SpaceLog::keyCommit(spaceId, 1, key2));
}

// -- the bytes, against the reference both the Endpoint and the Bridge are held to ------------------------------

#include <fstream>
#include <sstream>

#include <privmx/utils/Utils.hpp>

namespace {

Poco::JSON::Object::Ptr vectors() {
    std::ifstream file(std::string(PRIVMX_TEST_FIXTURES_DIR) + "/keytree/keytree-vectors.json");
    std::stringstream text;
    text << file.rdbuf();
    return privmx::utils::Utils::parseJsonObject(text.str());
}

SpaceStatement statementOf(const Poco::JSON::Object::Ptr& wire) {
    return SpaceLog::fromWire(server::SpaceStatement::fromJSON(wire));
}

} // namespace

TEST(SpaceLogVectors, TheSignedBytesAreTheReferenceOnes) {
    const auto cases = vectors()->getArray("spaceStatement");
    ASSERT_EQ(cases->size(), 4u);
    for (std::size_t i = 0; i < cases->size(); ++i) {
        const auto entry = cases->getObject(static_cast<unsigned>(i));
        Poco::JSON::Object::Ptr wire = entry->getObject("statement");
        // The reference lists what is signed; the two signatures are not part of it.
        wire->set("signature", std::string());
        wire->set("viaSignature", std::string());
        const SpaceStatement statement = statementOf(wire);
        EXPECT_EQ(
            privmx::utils::Hex::from(SpaceLog::recipientsHash(statement.groups, statement.users)),
            entry->getValue<std::string>("recipientsHashHex")
        ) << "case " << i;
        EXPECT_EQ(privmx::utils::Hex::from(SpaceLog::signedBytes(statement)), entry->getValue<std::string>("signedBytesHex"))
            << "case " << i;
        EXPECT_EQ(privmx::utils::Hex::from(SpaceLog::viaBytes(statement)), entry->getValue<std::string>("viaBytesHex"))
            << "case " << i;
    }
}

TEST(SpaceLogVectors, AKeyCommitmentIsTheReferenceOne) {
    const auto cases = vectors()->getArray("spaceKeyCommit");
    ASSERT_EQ(cases->size(), 3u);
    for (std::size_t i = 0; i < cases->size(); ++i) {
        const auto entry = cases->getObject(static_cast<unsigned>(i));
        EXPECT_EQ(
            privmx::utils::Hex::from(SpaceLog::keyCommit(
                entry->getValue<std::string>("spaceId"),
                entry->getValue<std::uint64_t>("keyVersion"),
                privmx::utils::Hex::toString(entry->getValue<std::string>("keyHex"))
            )),
            entry->getValue<std::string>("expectedHex")
        ) << "case " << i;
    }
}

TEST(SpaceLogVectors, AStatementSignedByTheBridgesOwnCodeVerifiesHere) {
    // Made and signed by the Bridge's implementation (its SpaceStatement.test.ts, keys 0x11.. and 0x22..): the
    // signatures of another library, and the digest that chains the next statement to this one.
    const std::string json = R"({
        "spaceId": "abababababababababababababababababababababababababababababababab",
        "contextId": "ctx-1", "seq": 2,
        "prevDigest": "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd",
        "op": "rotate", "date": 1700000000000, "keyVersion": 2,
        "keyCommit": "efefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefef",
        "groups": [
            {"groupId": "sales", "role": "manager", "groupKeyVersion": 5, "groupPubKey": "5RWLQudhUehv8bFcVwqJWBor8VTy4psRS2J2s9PwahRhw6fEVp"},
            {"groupId": "billing", "role": "user", "groupKeyVersion": 1, "groupPubKey": "7S7oY6Jrjzq8txrPmBwUhUmKzpN64835E7ura1HDDAVUvqRjJ1"}
        ],
        "users": [
            {"userId": "zoe", "pubKey": "5RWLQudhUehv8bFcVwqJWBor8VTy4psRS2J2s9PwahRhw6fEVp", "role": "user"},
            {"userId": "alice", "pubKey": "7S7oY6Jrjzq8txrPmBwUhUmKzpN64835E7ura1HDDAVUvqRjJ1", "role": "manager"}
        ],
        "signer": "alice", "signerPubKey": "7S7oY6Jrjzq8txrPmBwUhUmKzpN64835E7ura1HDDAVUvqRjJ1", "via": "sales",
        "signature": "G6mLHiR0fTTrDsC3Ke/uZ//1RYR40WbTjqQgaMXi5EWl/Kdmn5VvwLxr53bLfOAO3kAl3byD+sGQEfiEXasM4/4=",
        "viaSignature": "G1TnXQdLHxn6nFvDK6rWIwDIni+O/xF6Vdw7uvenf/Ucnie6YGSnn65ks/MXkPIoQigIX0kTMIyGbbPtvqN/n80="
    })";
    const SpaceStatement statement = statementOf(privmx::utils::Utils::parseJsonObject(json));
    EXPECT_EQ(
        privmx::utils::Hex::from(SpaceLog::recipientsHash(statement.groups, statement.users)),
        "4fb2f91ff12ef35fba60b41356dcdad801e2cc0a44c47acf42d066563cce7a7c"
    );
    EXPECT_EQ(privmx::utils::Hex::from(SpaceLog::digest(statement)), "81cb2d7e7415da314d438d87d4d2980688f92f7acdeabba2abda5571ad01809b");
    using privmx::crypto::PublicKey;
    EXPECT_TRUE(PublicKey::fromBase58DER(statement.signerPubKey).verifyCompactSignatureWithHash(SpaceLog::signedBytes(statement), statement.signature));
    EXPECT_TRUE(PublicKey::fromBase58DER(statement.groups[0].groupPubKey).verifyCompactSignatureWithHash(SpaceLog::viaBytes(statement), statement.viaSignature));
    // And not for a statement one byte off.
    SpaceStatement other = statement;
    other.date += 1;
    EXPECT_FALSE(PublicKey::fromBase58DER(statement.signerPubKey).verifyCompactSignatureWithHash(SpaceLog::signedBytes(other), statement.signature));
}

TEST_F(SpaceLogRules, ARungOpensOnlyUnderItsOwnKeyAndSpan) {
    const std::string sealed = SpaceLog::sealRung(spaceId, 2, 1, key2, key1);
    EXPECT_EQ(sealed.size(), 12u + 32u + 16u) << "iv || ciphertext || tag";
    EXPECT_EQ(SpaceLog::openRung(spaceId, 2, 1, key2, sealed), key1);
    EXPECT_THROW(SpaceLog::openRung(spaceId, 2, 1, key1, sealed), GroupDataIntegrityException) << "another key";
    EXPECT_THROW(SpaceLog::openRung(spaceId, 3, 1, key2, sealed), GroupDataIntegrityException) << "relabelled";
    EXPECT_THROW(SpaceLog::openRung(spaceId, 2, 0, key2, sealed), GroupDataIntegrityException) << "relabelled";
    EXPECT_THROW(SpaceLog::openRung(std::string(64, 'b'), 2, 1, key2, sealed), GroupDataIntegrityException)
        << "another Space's";
    EXPECT_THROW(SpaceLog::openRung(spaceId, 2, 1, key2, sealed.substr(1)), GroupDataIntegrityException);
    EXPECT_THROW(SpaceLog::sealRung(spaceId, 1, 2, key1, key2), std::invalid_argument) << "rungs point down only";
}

TEST_F(SpaceLogRules, AVerifiedStateIsStoredWholeAndReadBackStrictly) {
    const SpaceLogState first = created();
    const SpaceLogState rotated =
        SpaceLog::apply(first, by(statement(SpaceOp::Rotate, first, 2, key2), "alice", alice));
    std::map<std::string, SpaceLogState> states{{spaceId, rotated}};
    const std::string body = SpaceLog::encodeStates(states);
    const auto back = SpaceLog::decodeStates(body);
    ASSERT_TRUE(back.has_value());
    const SpaceLogState& again = back->at(spaceId);
    EXPECT_EQ(again.seq, rotated.seq);
    EXPECT_EQ(again.digest, rotated.digest);
    EXPECT_EQ(again.creator, "alice");
    EXPECT_EQ(again.keyCommits, rotated.keyCommits);
    EXPECT_EQ(again.groups.size(), 2u);
    EXPECT_EQ(again.users.size(), 2u);
    // Good enough to go on from: the next statement applies to it as to the original.
    EXPECT_NO_THROW(SpaceLog::apply(again, by(statement(SpaceOp::Rotate, again, 3, key1), "alice", alice)));
    EXPECT_FALSE(SpaceLog::decodeStates(body + "x").has_value()) << "trailing bytes";
    EXPECT_FALSE(SpaceLog::decodeStates(body.substr(0, body.size() - 1)).has_value()) << "cut short";
    EXPECT_TRUE(SpaceLog::decodeStates(SpaceLog::encodeStates({})).has_value());
}
