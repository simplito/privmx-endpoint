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
    // A statement written as the whole roster after it (`groups`, `users`): `by` and `through` turn that into the
    // deltas from `prior` and the rosterHash (SpaceLog::setRoster), so a case can also write a change no op allows.
    struct Draft : SpaceStatement {
        std::optional<SpaceLogState> prior;
        std::vector<SpaceLogGroup> groups;
        std::vector<SpaceLogUser> users;
    };
    Draft statement(SpaceOp op, const std::optional<SpaceLogState>& prior, std::uint64_t keyVersion, const std::string& key) {
        Draft s;
        s.prior = prior;
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
    SpaceStatement by(Draft draft, const std::string& signer, const PrivateKey& key) {
        SpaceLog::setRoster(draft, draft.prior, draft.groups, draft.users);
        SpaceStatement s = draft;
        s.signer = signer;
        s.via.clear();
        SpaceLog::sign(s, key, std::nullopt);
        return s;
    }
    SpaceStatement through(Draft draft, const std::string& signer, const PrivateKey& key, const std::string& via, const PrivateKey& groupKey) {
        SpaceLog::setRoster(draft, draft.prior, draft.groups, draft.users);
        SpaceStatement s = draft;
        s.signer = signer;
        s.via = via;
        SpaceLog::sign(s, key, groupKey);
        return s;
    }
    // alice (manager), bob (user), sales at epoch 1 (manager), support (user); key version 1.
    SpaceLogState created() {
        Draft s = statement(SpaceOp::Create, std::nullopt, 1, key1);
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
    Draft s = statement(SpaceOp::Create, std::nullopt, 1, key1);
    s.groups = {group("sales", sales1, 1, "manager")};
    EXPECT_EQ(SpaceLog::apply(std::nullopt, through(s, "carol", carol, "sales", sales1)).creator, "carol");
}

TEST_F(SpaceLogRules, SECURITY_ASpaceIsMadeByOneOfItsOwnManagers) {
    Draft s = statement(SpaceOp::Create, std::nullopt, 1, key1);
    s.users = {user("alice", alice, "manager"), user("bob", bob, "user")};
    s.groups = {group("sales", sales1, 1, "user")};
    // Eve lists the right people and signs herself: she is not among them.
    EXPECT_THROW(SpaceLog::apply(std::nullopt, by(s, "eve", eve)), GroupUnauthorizedSignerException);
    // Eve signs as alice, with her own key: the list has alice's.
    EXPECT_THROW(SpaceLog::apply(std::nullopt, by(s, "alice", eve)), GroupUnauthorizedSignerException);
    // A user of the Space, not a manager; and a group that is only a user.
    EXPECT_THROW(SpaceLog::apply(std::nullopt, by(s, "bob", bob)), GroupUnauthorizedSignerException);
    EXPECT_THROW(SpaceLog::apply(std::nullopt, through(s, "carol", carol, "sales", sales1)), GroupUnauthorizedSignerException);
    // Nobody to manage it: whoever signs is no manager.
    s.users = {user("bob", bob, "user")};
    EXPECT_THROW(SpaceLog::apply(std::nullopt, by(s, "bob", bob)), GroupUnauthorizedSignerException);
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
    Draft adding = statement(SpaceOp::Add, state, 1, key1);
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
    Draft s = statement(SpaceOp::Rotate, state, 2, key2);
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

TEST_F(SpaceLogRules, SECURITY_DeltasThatDoNotApplyCleanlyAreRefused) {
    const SpaceLogState state = created();
    // Raw deltas, signed by alice (a manager), with the rosterHash of `groups`/`users` - or of the honest result.
    const auto signedAs = [&](SpaceStatement s) {
        s.signer = "alice";
        s.via.clear();
        SpaceLog::sign(s, alice, std::nullopt);
        return s;
    };
    const auto raw = [&](SpaceOp op, std::uint64_t keyVersion, const std::string& key) {
        SpaceStatement s = statement(op, state, keyVersion, key);
        s.rosterHash = SpaceLog::rosterHash(state.groups, state.users);
        return s;
    };
    const SpaceLogUser dave = user("dave", eve, "user");
    std::vector<SpaceLogUser> withDave = state.users;
    withDave.push_back(dave);

    // The honest addition, for contrast.
    SpaceStatement s = raw(SpaceOp::Add, 1, key1);
    s.addedUsers = {dave};
    s.rosterHash = SpaceLog::rosterHash(state.groups, withDave);
    EXPECT_NO_THROW(SpaceLog::apply(state, signedAs(s)));
    // Its rosterHash is of another roster.
    s.rosterHash = SpaceLog::rosterHash(state.groups, state.users);
    EXPECT_THROW(SpaceLog::apply(state, signedAs(s)), GroupDataIntegrityException);
    // Adding a present recipient.
    s = raw(SpaceOp::Add, 1, key1);
    s.addedUsers = {user("bob", bob, "user")};
    EXPECT_THROW(SpaceLog::apply(state, signedAs(s)), GroupDataIntegrityException);
    s = raw(SpaceOp::Add, 1, key1);
    s.addedGroups = {group("sales", sales1, 1, "manager")};
    EXPECT_THROW(SpaceLog::apply(state, signedAs(s)), GroupDataIntegrityException);
    // The same id twice, in one list or across two.
    s = raw(SpaceOp::Add, 1, key1);
    s.addedUsers = {dave, dave};
    EXPECT_THROW(SpaceLog::apply(state, signedAs(s)), GroupDataIntegrityException);
    s = raw(SpaceOp::Remove, 2, key2);
    s.removedGroups = {"support"};
    s.refreshedGroups = {group("support", eve, 5, "")};
    EXPECT_THROW(SpaceLog::apply(state, signedAs(s)), GroupDataIntegrityException);
    s = raw(SpaceOp::Remove, 2, key2);
    s.removedUsers = {"bob", "bob"};
    EXPECT_THROW(SpaceLog::apply(state, signedAs(s)), GroupDataIntegrityException);
    // Removing an absent recipient.
    s = raw(SpaceOp::Remove, 2, key2);
    s.removedUsers = {"dave"};
    EXPECT_THROW(SpaceLog::apply(state, signedAs(s)), GroupDataIntegrityException);
    s = raw(SpaceOp::Remove, 2, key2);
    s.removedGroups = {"billing"};
    EXPECT_THROW(SpaceLog::apply(state, signedAs(s)), GroupDataIntegrityException);
    // Refreshing a group that is no recipient, or to an epoch that is not later.
    s = raw(SpaceOp::Rotate, 2, key2);
    s.refreshedGroups = {group("billing", eve, 2, "")};
    EXPECT_THROW(SpaceLog::apply(state, signedAs(s)), GroupDataIntegrityException);
    s = raw(SpaceOp::Rotate, 2, key2);
    s.refreshedGroups = {group("sales", sales2, 1, "")};
    EXPECT_THROW(SpaceLog::apply(state, signedAs(s)), GroupDataIntegrityException);
    s = raw(SpaceOp::Rotate, 2, key2);
    s.refreshedGroups = {group("sales", sales1, 2, "")};
    EXPECT_THROW(SpaceLog::apply(state, signedAs(s)), GroupDataIntegrityException) << "the same key";
    // A list its op does not have: an add that refreshes, a rotation that adds, a creation that removes.
    s = raw(SpaceOp::Add, 1, key1);
    s.addedUsers = {dave};
    s.refreshedGroups = {group("sales", sales2, 2, "")};
    EXPECT_THROW(SpaceLog::apply(state, signedAs(s)), GroupDataIntegrityException);
    s = raw(SpaceOp::Rotate, 2, key2);
    s.addedUsers = {dave};
    s.rosterHash = SpaceLog::rosterHash(state.groups, withDave);
    EXPECT_THROW(SpaceLog::apply(state, signedAs(s)), GroupDataIntegrityException);
    SpaceStatement first = statement(SpaceOp::Create, std::nullopt, 1, key1);
    first.addedUsers = {user("alice", alice, "manager")};
    first.removedUsers = {"bob"};
    first.rosterHash = SpaceLog::rosterHash({}, first.addedUsers);
    EXPECT_THROW(SpaceLog::apply(std::nullopt, signedAs(first)), GroupDataIntegrityException);
    // A role that is none.
    s = raw(SpaceOp::Add, 1, key1);
    s.addedUsers = {user("dave", eve, "owner")};
    EXPECT_THROW(SpaceLog::apply(state, signedAs(s)), GroupDataIntegrityException);
}

TEST_F(SpaceLogRules, SECURITY_OnlyAManagerChangesTheRecipientsAndOnlyAsTheOpSays) {
    const SpaceLogState state = created();
    Draft add = statement(SpaceOp::Add, state, 1, key1);
    add.users.push_back(user("dave", eve, "user"));
    // bob is a user; support is a user.
    EXPECT_THROW(SpaceLog::apply(state, by(add, "bob", bob)), GroupUnauthorizedSignerException);
    EXPECT_THROW(SpaceLog::apply(state, through(add, "x", eve, "support", support)), GroupUnauthorizedSignerException);
    const SpaceLogState added = SpaceLog::apply(state, by(add, "alice", alice));
    EXPECT_EQ(added.roleOfUser("dave"), "user");
    EXPECT_EQ(added.keyVersion, 1u);

    // An addition keeps the key, adds somebody, and touches nobody who was there.
    Draft s = statement(SpaceOp::Add, state, 2, key2);
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
    Draft remove = statement(SpaceOp::Remove, state, 2, key2);
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
    Draft s = statement(SpaceOp::Rotate, rotated, 3, key1);
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
             [&](SpaceStatement& t) { t.rosterHash = SpaceLog::rosterHash({}, {user("bob", bob, "manager")}); },
             [&](SpaceStatement& t) { t.addedUsers.push_back(user("eve", eve, "manager")); },
             [&](SpaceStatement& t) { t.refreshedGroups.push_back(group("sales", eve, 9, "")); },
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
    Draft first = statement(SpaceOp::Create, std::nullopt, 1, key1);
    first.users = {user("alice", alice, "manager"), user("bob", bob, "user")};
    first.groups = {group("sales", sales1, 1, "manager"), group("support", support, 4, "user")};
    const SpaceStatement made = by(first, "alice", alice);
    SpaceStatement shuffled = made;
    std::reverse(shuffled.addedGroups.begin(), shuffled.addedGroups.end());
    std::reverse(shuffled.addedUsers.begin(), shuffled.addedUsers.end());
    EXPECT_EQ(SpaceLog::signedBytes(shuffled), SpaceLog::signedBytes(made));
    EXPECT_EQ(SpaceLog::fromWire(SpaceLog::toWire(made)).addedUsers.size(), 2u);
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
    std::vector<SpaceLogGroup> groups;
    std::vector<SpaceLogUser> users;
    for (std::size_t i = 0; i < cases->size(); ++i) {
        const auto entry = cases->getObject(static_cast<unsigned>(i));
        Poco::JSON::Object::Ptr wire = entry->getObject("statement");
        // The reference lists what is signed; the two signatures are not part of it.
        wire->set("signature", std::string());
        wire->set("viaSignature", std::string());
        const SpaceStatement statement = statementOf(wire);
        EXPECT_EQ(privmx::utils::Hex::from(statement.rosterHash), entry->getValue<std::string>("rosterHashHex"))
            << "case " << i;
        // The roster the chain adds up to, hashed here.
        for (const auto& id : statement.removedGroups) {
            groups.erase(
                std::remove_if(groups.begin(), groups.end(), [&](const SpaceLogGroup& g) { return g.groupId == id; }),
                groups.end()
            );
        }
        for (const auto& id : statement.removedUsers) {
            users.erase(
                std::remove_if(users.begin(), users.end(), [&](const SpaceLogUser& u) { return u.userId == id; }),
                users.end()
            );
        }
        for (const auto& refresh : statement.refreshedGroups) {
            for (auto& g : groups) {
                if (g.groupId == refresh.groupId) {
                    g.groupKeyVersion = refresh.groupKeyVersion;
                    g.groupPubKey = refresh.groupPubKey;
                }
            }
        }
        groups.insert(groups.end(), statement.addedGroups.begin(), statement.addedGroups.end());
        users.insert(users.end(), statement.addedUsers.begin(), statement.addedUsers.end());
        EXPECT_EQ(privmx::utils::Hex::from(SpaceLog::rosterHash(groups, users)), entry->getValue<std::string>("rosterHashHex"))
            << "case " << i;
        EXPECT_EQ(
            privmx::utils::Hex::from(privmx::crypto::Crypto::sha256(SpaceLog::signedBytes(statement))),
            entry->getValue<std::string>("signedBytesSha256Hex")
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
