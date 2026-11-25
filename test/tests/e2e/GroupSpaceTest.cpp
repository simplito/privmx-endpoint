#include <gtest/gtest.h>
#include "BaseGroupTest.hpp"
#include <Poco/Util/IniFileConfiguration.h>
#include <chrono>
#include <thread>
#include <privmx/endpoint/core/Connection.hpp>
#include <privmx/endpoint/core/EventQueue.hpp>
#include <privmx/endpoint/group/Events.hpp>
#include <privmx/endpoint/core/CoreException.hpp>
#include <privmx/endpoint/core/Exception.hpp>
#include <privmx/endpoint/group/GroupApi.hpp>
#include <privmx/endpoint/group/GroupException.hpp>

using namespace privmx::endpoint;
using namespace privmx::endpoint::group;

/**
 * Spaces against a running Bridge: one key for several Groups and users, in versions.
 *
 * What a Space must hold to, each a test below: every recipient reads, through its own entry; a value says who
 * wrote it and how they had access; adding a recipient opens the past to them, removing one closes the future;
 * a removal from a recipient Group makes the key stale and the next write replaces it; a Space's envelopes and a
 * Group's never open as each other.
 */
class GroupSpaceTest : public privmx::test::BaseGroupTest {
protected:
    static Path note(const std::string& noteId) {
        return {
            {false, core::Buffer::from("crm")},
            {false, core::Buffer::from("note")},
            {true, GroupApi::idFromString(noteId)},
        };
    }
    static DecryptOptions by(const std::string& userId) {
        return DecryptOptions{.expectedAuthor = userId, .anyAuthor = false, .currentEpochOnly = false};
    }
    static DecryptOptions anyAuthor() {
        return DecryptOptions{.expectedAuthor = "", .anyAuthor = true, .currentEpochOnly = false};
    }
    static core::Buffer text(const std::string& value) { return core::Buffer::from(value); }

    // A group of the connected user's, readable by the Context so that others can wrap a Space's key to it.
    std::string createTeam(const std::vector<core::UserWithPubKey>& members) {
        return groupApi->createGroup(
            contextId(), members, {members.front()}, text("public"), text("private"), std::nullopt, std::nullopt, "context"
        );
    }
    SpaceRecipient team(const std::string& groupId, const std::string& role) {
        return SpaceRecipient{.groupId = groupId, .user = std::nullopt, .role = role};
    }
    SpaceRecipient person(int index, const std::string& role) {
        return SpaceRecipient{.groupId = {}, .user = user(index), .role = role};
    }
    void switchTo(int index) {
        disconnect();
        connectAs(index);
    }
};

TEST_F(GroupSpaceTest, every_recipient_reads_and_a_value_says_how_its_author_had_access) {
    const std::string sales = createTeam({user(1), user(2)});
    switchTo(3);
    const std::string support = createTeam({user(3)});
    switchTo(1);

    const std::string spaceId = groupApi->createSpace(
        contextId(), {team(sales, "manager"), team(support, "user")}, text("project"), text("budget 100")
    );
    const core::Buffer sealed = groupApi->encryptInSpace(spaceId, note("n1"), text("call the client"));

    const EnvelopeHeader plain = GroupApi::peekEnvelope(sealed);
    EXPECT_EQ(plain.spaceId, spaceId);
    EXPECT_EQ(plain.groupId, sales);
    EXPECT_EQ(plain.keyVersion, 1);
    EXPECT_TRUE(plain.hasLocation);

    SpaceState state = groupApi->getSpace(spaceId);
    EXPECT_EQ(state.spaceId, spaceId);
    EXPECT_EQ(state.createdBy, userId(1));
    EXPECT_EQ(state.keyVersion, 1);
    EXPECT_FALSE(state.keyIsStale);
    ASSERT_EQ(state.groups.size(), 2u);
    EXPECT_TRUE(state.users.empty());
    EXPECT_EQ(state.publicMeta.stdString(), "project");
    EXPECT_EQ(state.privateMeta.stdString(), "budget 100");

    // A member of the author's own team sees the roster the author wrote through.
    switchTo(2);
    DecryptedSpaceEnvelope opened = groupApi->decryptInSpace(spaceId, note("n1"), sealed, by(userId(1)));
    EXPECT_EQ(opened.data.stdString(), "call the client");
    EXPECT_EQ(opened.origin.author.userId, userId(1));
    EXPECT_EQ(opened.origin.via, sales);
    EXPECT_EQ(opened.origin.authorAccess, "yes");
    EXPECT_EQ(opened.origin.keyVersion, 1);
    EXPECT_GT(opened.encryptedAt, 0);
    EXPECT_EQ(groupApi->getSpace(spaceId).privateMeta.stdString(), "budget 100");

    // The other team reads the same value through its own entry of the key.
    switchTo(3);
    opened = groupApi->decryptInSpace(spaceId, note("n1"), sealed, by(userId(1)));
    EXPECT_EQ(opened.data.stdString(), "call the client");
    EXPECT_EQ(opened.origin.via, sales);
    // A "user" recipient writes as well; only the recipients and the meta are a manager's.
    const core::Buffer reply = groupApi->encryptInSpace(spaceId, note("n2"), text("done"));
    EXPECT_EQ(GroupApi::peekEnvelope(reply).groupId, support);
    EXPECT_ANY_THROW({ groupApi->updateSpacePublicMeta(spaceId, text("mine now"), 1); });

    switchTo(1);
    EXPECT_EQ(groupApi->decryptInSpace(spaceId, note("n2"), reply, by(userId(3))).origin.via, support);
    const auto listed = groupApi->listSpaces(contextId(), core::PagingQuery{.skip = 0, .limit = 10, .sortOrder = "desc"});
    ASSERT_GE(listed.readItems.size(), 1u);
    EXPECT_EQ(listed.readItems[0].spaceId, spaceId);
    EXPECT_EQ(listed.readItems[0].privateMeta.stdString(), "budget 100");
}

TEST_F(GroupSpaceTest, a_read_names_the_space_the_place_and_the_author) {
    const std::string sales = createTeam({user(1), user(2)});
    const std::string spaceId = groupApi->createSpace(contextId(), {team(sales, "manager")}, text(""), text(""));
    const std::string other = groupApi->createSpace(contextId(), {team(sales, "manager")}, text(""), text(""));
    const core::Buffer sealed = groupApi->encryptInSpace(spaceId, note("n1"), text("x"));
    const core::Buffer inGroup = groupApi->encrypt(sales, note("n1"), text("x"));

    EXPECT_THROW({ groupApi->decryptInSpace(spaceId, note("n2"), sealed, anyAuthor()); }, EnvelopeWrongLocationException);
    EXPECT_THROW(
        { groupApi->decryptInSpace(spaceId, GroupApi::noLocation(), sealed, anyAuthor()); }, EnvelopeWrongLocationException
    );
    EXPECT_THROW({ groupApi->decryptInSpace(spaceId, note("n1"), sealed, by(userId(2))); }, EnvelopeWrongAuthorException);
    EXPECT_THROW(
        { groupApi->decryptInSpace(spaceId, note("n1"), sealed, DecryptOptions{}); }, EnvelopeAuthorNotStatedException
    );
    EXPECT_THROW({ groupApi->decryptInSpace(other, note("n1"), sealed, anyAuthor()); }, EnvelopeWrongGroupException);

    // A Space's envelope and a Group's never open as each other.
    EXPECT_THROW({ groupApi->decrypt(sales, note("n1"), sealed, anyAuthor()); }, EnvelopeWrongKindException);
    EXPECT_THROW({ groupApi->decryptShared(contextId(), note("n1"), sealed, anyAuthor()); }, EnvelopeWrongKindException);
    EXPECT_THROW({ groupApi->decryptInSpace(spaceId, note("n1"), inGroup, anyAuthor()); }, EnvelopeWrongKindException);

    const auto results = groupApi->decryptManyInSpace(
        spaceId,
        {
            DecryptItem{.envelope = sealed, .location = note("n1"), .options = by(userId(1))},
            DecryptItem{.envelope = sealed, .location = note("n2"), .options = by(userId(1))},
            DecryptItem{.envelope = inGroup, .location = note("n1"), .options = by(userId(1))},
        }
    );
    ASSERT_EQ(results.size(), 3u);
    EXPECT_EQ(results[0].statusCode, 0);
    EXPECT_EQ(results[0].envelope.data.stdString(), "x");
    EXPECT_EQ(results[1].statusCode, static_cast<int64_t>(EnvelopeWrongLocationException::FULL_CODE));
    EXPECT_EQ(results[2].statusCode, static_cast<int64_t>(EnvelopeWrongKindException::FULL_CODE));
    EXPECT_EQ(results[2].details.envelopeKind, "member");
}

TEST_F(GroupSpaceTest, a_removal_from_a_team_makes_the_key_stale_and_the_next_write_replaces_it) {
    const std::string sales = createTeam({user(1), user(2)});
    const std::string spaceId = groupApi->createSpace(contextId(), {team(sales, "manager")}, text(""), text(""));
    switchTo(2);
    const core::Buffer byUser2 = groupApi->encryptInSpace(spaceId, note("n0"), text("from user 2"));
    switchTo(1);
    const core::Buffer before = groupApi->encryptInSpace(spaceId, note("n1"), text("before"));
    EXPECT_EQ(groupApi->decryptInSpace(spaceId, note("n0"), byUser2, by(userId(2))).origin.authorAccess, "yes");

    ASSERT_NO_THROW({ groupApi->removeGroupMembers(sales, {userId(2)}); });
    // User 2 still holds version 1 of the key. The Bridge says so, and nothing more is written under it.
    EXPECT_TRUE(groupApi->getSpace(spaceId).keyIsStale);
    const core::Buffer after = groupApi->encryptInSpace(spaceId, note("n2"), text("after"));
    EXPECT_EQ(GroupApi::peekEnvelope(after).keyVersion, 2);
    const SpaceState state = groupApi->getSpace(spaceId);
    EXPECT_EQ(state.keyVersion, 2);
    EXPECT_FALSE(state.keyIsStale);

    // Both versions stay readable to who remains; a reader who wants only the current one says so.
    EXPECT_EQ(groupApi->decryptInSpace(spaceId, note("n1"), before, by(userId(1))).data.stdString(), "before");
    EXPECT_EQ(groupApi->decryptInSpace(spaceId, note("n2"), after, by(userId(1))).data.stdString(), "after");
    EXPECT_THROW(
        {
            groupApi->decryptInSpace(
                spaceId, note("n1"), before, {.expectedAuthor = userId(1), .anyAuthor = false, .currentEpochOnly = true}
            );
        },
        EnvelopeStaleEpochException
    );
    // What user 2 wrote opens with the key they held; that they are no recipient any more is said beside it.
    EXPECT_EQ(groupApi->decryptInSpace(spaceId, note("n0"), byUser2, by(userId(2))).origin.authorAccess, "no");

    switchTo(2);
    EXPECT_ANY_THROW({ groupApi->decryptInSpace(spaceId, note("n2"), after, anyAuthor()); });
    EXPECT_ANY_THROW({ groupApi->encryptInSpace(spaceId, note("n3"), text("still here")); });
}

TEST_F(GroupSpaceTest, an_added_recipient_reads_the_past_and_a_removed_one_gets_no_new_key) {
    const core::Buffer seed = text("project-42");
    const std::string spaceId = groupApi->createSpace(
        contextId(), {person(1, "manager"), person(2, "user")}, text("p"), text("q"), seed
    );
    EXPECT_EQ(spaceId, GroupApi::deriveSpaceId(contextId(), seed));
    const core::Buffer first = groupApi->encryptInSpace(spaceId, note("n1"), text("first"));
    EXPECT_EQ(GroupApi::peekEnvelope(first).groupId, "");
    ASSERT_NO_THROW({ groupApi->rotateSpaceKey(spaceId); });
    const core::Buffer second = groupApi->encryptInSpace(spaceId, note("n2"), text("second"));
    EXPECT_EQ(GroupApi::peekEnvelope(second).keyVersion, 2);

    switchTo(3);
    EXPECT_ANY_THROW({ groupApi->decryptInSpace(spaceId, note("n1"), first, anyAuthor()); });
    switchTo(1);
    ASSERT_NO_THROW({ groupApi->addSpaceRecipients(spaceId, {person(3, "user")}); });
    switchTo(3);
    // Every version was wrapped for the newcomer.
    DecryptedSpaceEnvelope opened = groupApi->decryptInSpace(spaceId, note("n1"), first, by(userId(1)));
    EXPECT_EQ(opened.data.stdString(), "first");
    EXPECT_EQ(opened.origin.via, "user");
    EXPECT_EQ(opened.origin.authorAccess, "yes");
    EXPECT_EQ(groupApi->decryptInSpace(spaceId, note("n2"), second, by(userId(1))).data.stdString(), "second");
    // Not a manager: the recipients are not theirs to change.
    EXPECT_ANY_THROW({ groupApi->removeSpaceRecipients(spaceId, {SpaceRecipientRef{.groupId = {}, .userId = userId(2)}}); });

    switchTo(1);
    int64_t version = 0;
    ASSERT_NO_THROW({
        version = groupApi->removeSpaceRecipients(spaceId, {SpaceRecipientRef{.groupId = {}, .userId = userId(2)}});
    });
    EXPECT_EQ(version, 3);
    const core::Buffer third = groupApi->encryptInSpace(spaceId, note("n3"), text("third"));
    EXPECT_EQ(GroupApi::peekEnvelope(third).keyVersion, 3);
    ASSERT_NO_THROW({ groupApi->updateSpacePublicMeta(spaceId, text("p2"), 1); });
    ASSERT_NO_THROW({ groupApi->updateSpacePrivateMeta(spaceId, text("q2"), 1); });
    const SpaceState state = groupApi->getSpace(spaceId);
    EXPECT_EQ(state.publicMeta.stdString(), "p2");
    EXPECT_EQ(state.privateMeta.stdString(), "q2");
    EXPECT_EQ(state.users.size(), 2u);

    switchTo(3);
    EXPECT_EQ(groupApi->decryptInSpace(spaceId, note("n3"), third, by(userId(1))).data.stdString(), "third");
    EXPECT_EQ(groupApi->getSpace(spaceId).privateMeta.stdString(), "q2");
    switchTo(2);
    EXPECT_ANY_THROW({ groupApi->decryptInSpace(spaceId, note("n3"), third, anyAuthor()); });

    switchTo(1);
    ASSERT_NO_THROW({ groupApi->deleteSpace(spaceId); });
    EXPECT_ANY_THROW({ groupApi->getSpace(spaceId); });
}

TEST_F(GroupSpaceTest, files_and_sequences_in_a_space) {
    const std::string sales = createTeam({user(1), user(2)});
    const std::string spaceId = groupApi->createSpace(
        contextId(), {team(sales, "manager"), person(3, "user")}, text(""), text("")
    );

    FileHandle w = groupApi->beginFileEncryptionInSpace(spaceId, note("scan"));
    const std::string plain(300000, 'f');
    const std::string cipher = groupApi->encryptFileChunk(w, core::Buffer::from(plain)).stdString();
    const core::Buffer fileEnvelope = groupApi->finishFileEncryption(w);
    EXPECT_TRUE(GroupApi::peekEnvelope(fileEnvelope).isFile);
    EXPECT_EQ(GroupApi::peekEnvelope(fileEnvelope).spaceId, spaceId);

    SequenceHandle seq = groupApi->beginSequenceInSpace(spaceId, note("ops"), 0);
    const core::Buffer header = groupApi->getSequenceHeader(seq);
    const core::Buffer item = groupApi->appendToSequence(seq, text("edit")).item;
    const core::Buffer mark = groupApi->checkpointSequence(seq);
    // The Space's key is replaced: the sequence belongs to the version it began under.
    ASSERT_NO_THROW({ groupApi->rotateSpaceKey(spaceId); });
    EXPECT_THROW({ groupApi->appendToSequence(seq, text("late")); }, EnvelopeStaleEpochException);

    switchTo(3);
    FileHandle r = groupApi->beginFileDecryptionInSpace(spaceId, note("scan"), fileEnvelope, by(userId(1)));
    EXPECT_EQ(groupApi->decryptFileChunk(r, core::Buffer::from(cipher)).stdString(), plain);
    const DecryptedFileInfo info = groupApi->finishFileDecryption(r);
    EXPECT_TRUE(info.complete);
    EXPECT_FALSE(info.author.has_value());
    ASSERT_TRUE(info.sender.has_value());
    EXPECT_EQ(info.sender->userId, userId(1));
    EXPECT_EQ(info.via, sales);
    EXPECT_EQ(info.keyVersion, 1);
    // A file of a Space is not a file of a Group, and the other way round.
    EXPECT_THROW({ groupApi->beginFileDecryption(sales, note("scan"), fileEnvelope, anyAuthor()); }, EnvelopeWrongKindException);
    EXPECT_THROW(
        { groupApi->beginFileDecryptionInSpace(spaceId, note("other"), fileEnvelope, anyAuthor()); },
        EnvelopeWrongLocationException
    );

    SequenceHandle reading = groupApi->openSequenceInSpace(spaceId, note("ops"), header, by(userId(1)));
    EXPECT_EQ(groupApi->readSequenceItem(reading, item).data.stdString(), "edit");
    EXPECT_EQ(groupApi->verifySequenceMark(reading, mark).attestedItems, 1);
    const SpaceOrigin origin = groupApi->getSpaceSequenceOrigin(reading);
    EXPECT_EQ(origin.author.userId, userId(1));
    EXPECT_EQ(origin.via, sales);
    EXPECT_EQ(origin.keyVersion, 1);
    EXPECT_THROW({ groupApi->openSequence(sales, note("ops"), header, anyAuthor()); }, EnvelopeWrongKindException);
}

TEST_F(GroupSpaceTest, the_history_of_a_space_is_signed_and_says_who_did_what) {
    const std::string sales = createTeam({user(1), user(2)});
    // User 1 is no recipient themselves: the Space is made, and later changed, through the sales team.
    const std::string spaceId = groupApi->createSpace(contextId(), {team(sales, "manager")}, text(""), text(""));
    ASSERT_NO_THROW({ groupApi->addSpaceRecipients(spaceId, {person(3, "user")}); });
    switchTo(3);
    // A user of the Space replaces the key; the recipients are not theirs to change.
    ASSERT_NO_THROW({ groupApi->rotateSpaceKey(spaceId); });
    EXPECT_ANY_THROW({ groupApi->addSpaceRecipients(spaceId, {person(2, "user")}); });
    switchTo(2);
    int64_t version = 0;
    ASSERT_NO_THROW({
        version = groupApi->removeSpaceRecipients(spaceId, {SpaceRecipientRef{.groupId = {}, .userId = userId(3)}});
    });
    EXPECT_EQ(version, 3);

    // A fresh session of the first user: nothing remembered, the whole history replayed and checked.
    switchTo(1);
    const auto log = groupApi->getSpaceLog(spaceId, core::PagingQuery{.skip = 0, .limit = 10, .sortOrder = "asc"});
    ASSERT_EQ(log.totalAvailable, 4);
    ASSERT_EQ(log.readItems.size(), 4u);
    EXPECT_EQ(log.readItems[0].kind, "create");
    EXPECT_EQ(log.readItems[0].author, userId(1));
    EXPECT_EQ(log.readItems[0].via, sales);
    EXPECT_EQ(log.readItems[0].addedGroups, std::vector<std::string>{sales});
    EXPECT_EQ(log.readItems[0].keyVersion, 1);
    EXPECT_EQ(log.readItems[1].kind, "add");
    EXPECT_EQ(log.readItems[1].addedUsers, std::vector<std::string>{userId(3)});
    EXPECT_EQ(log.readItems[1].keyVersion, 1);
    EXPECT_EQ(log.readItems[2].kind, "rotate");
    EXPECT_EQ(log.readItems[2].author, userId(3));
    EXPECT_EQ(log.readItems[2].via, "user");
    EXPECT_EQ(log.readItems[2].keyVersion, 2);
    EXPECT_EQ(log.readItems[3].kind, "remove");
    EXPECT_EQ(log.readItems[3].author, userId(2));
    EXPECT_EQ(log.readItems[3].via, sales);
    EXPECT_EQ(log.readItems[3].removedUsers, std::vector<std::string>{userId(3)});
    EXPECT_EQ(log.readItems[3].keyVersion, 3);
    const auto newest = groupApi->getSpaceLog(spaceId, core::PagingQuery{.skip = 0, .limit = 1, .sortOrder = "desc"});
    ASSERT_EQ(newest.readItems.size(), 1u);
    EXPECT_EQ(newest.readItems[0].seq, 4);

    // The state is what the statements say: who made the Space, who is in it, which key is current.
    const SpaceState state = groupApi->getSpace(spaceId);
    EXPECT_EQ(state.createdBy, userId(1));
    EXPECT_EQ(state.keyVersion, 3);
    EXPECT_TRUE(state.users.empty());
    ASSERT_EQ(state.groups.size(), 1u);
    // What was written under each version still opens, each key checked against its statement.
    const core::Buffer sealed = groupApi->encryptInSpace(spaceId, note("n1"), text("after"));
    EXPECT_EQ(GroupApi::peekEnvelope(sealed).keyVersion, 3);
    switchTo(3);
    EXPECT_ANY_THROW({ groupApi->getSpaceLog(spaceId, core::PagingQuery{.skip = 0, .limit = 10, .sortOrder = "asc"}); });
}

TEST_F(GroupSpaceTest, a_recipient_is_told_when_the_space_changes_and_when_it_is_gone) {
    const std::string sales = createTeam({user(1), user(2)});
    const std::string spaceId = groupApi->createSpace(contextId(), {team(sales, "manager")}, text(""), text(""));
    core::EventQueue eventQueue = core::EventQueue::getInstance();
    auto connection2 = connect(2);
    auto groupApi2 = group::GroupApi::create(*connection2);
    groupApi2.subscribeFor({
        groupApi2.buildSubscriptionQuery(EventType::SPACE_UPDATE, EventSelectorType::SPACE_ID, spaceId),
        groupApi2.buildSubscriptionQuery(EventType::SPACE_DELETE, EventSelectorType::SPACE_ID, spaceId),
    });
    // Drains: connecting and subscribing put other events in front of the one waited for.
    const auto awaitChange = [&]() -> std::optional<SpaceChangedEvent> {
        for (int i = 0; i < 20; ++i) {
            auto holder = eventQueue.getEvent();
            if (!holder.has_value()) {
                std::this_thread::sleep_for(std::chrono::milliseconds(150));
            } else if (Events::isSpaceChangedEvent(holder.value())) {
                return Events::extractSpaceChangedEvent(holder.value());
            }
        }
        return std::nullopt;
    };

    EXPECT_EQ(groupApi2.getSpace(spaceId).keyVersion, 1);
    groupApi->rotateSpaceKey(spaceId);
    auto rotated = awaitChange();
    ASSERT_TRUE(rotated.has_value());
    EXPECT_EQ(rotated->data.spaceId, spaceId);
    EXPECT_EQ(rotated->data.contextId, contextId());
    EXPECT_EQ(rotated->data.changeKind, "keyRotated");
    EXPECT_EQ(rotated->data.keyVersion, 2);
    // The event dropped the cached read, so this one is fresh and verified.
    EXPECT_EQ(groupApi2.getSpace(spaceId).keyVersion, 2);

    groupApi->deleteSpace(spaceId);
    auto deleted = awaitChange();
    ASSERT_TRUE(deleted.has_value());
    EXPECT_EQ(deleted->data.spaceId, spaceId);
    EXPECT_EQ(deleted->data.changeKind, "deleted");

    // A custom channel is a Group's thing; a Space query never names one.
    EXPECT_ANY_THROW({ groupApi2.subscribeFor({"context/spaces/custom/typing|containerId=" + spaceId}); });
    connection2->disconnect();
}

TEST_F(GroupSpaceTest, a_reader_outside_a_team_verifies_its_key_refresh_through_the_public_tree) {
    std::shared_ptr<core::Connection> keep3;
    switchTo(3);
    const std::string support = createTeam({user(3)});
    switchTo(1);
    const std::string sales = createTeam({user(1), user(2)});
    const std::string spaceId =
        groupApi->createSpace(contextId(), {team(sales, "manager"), team(support, "user")}, text(""), text(""));
    const core::Buffer before = groupApi->encryptInSpace(spaceId, note("n0"), text("before"));
    // User 3 reads before the removal, in a session that stays open: what it verified of sales is the old epoch.
    keep3 = connect(3);
    auto user3 = std::make_shared<group::GroupApi>(group::GroupApi::create(*keep3));
    EXPECT_EQ(user3->decryptInSpace(spaceId, note("n0"), before, by(userId(1))).data.stdString(), "before");
    ASSERT_NO_THROW({ groupApi->removeGroupMembers(sales, {userId(2)}); });
    int64_t version = 0;
    ASSERT_NO_THROW({ version = groupApi->rotateSpaceKey(spaceId); });
    EXPECT_EQ(version, 2);
    const core::Buffer after = groupApi->encryptInSpace(spaceId, note("n1"), text("after"));

    // User 3 is in support, not in sales: the refresh of sales' key, signed through sales, is held to sales'
    // public verified tree, which the Context can see - in the session that verified the old epoch, and a new one.
    EXPECT_NO_THROW({ EXPECT_EQ(user3->getSpace(spaceId).keyVersion, 2); });
    EXPECT_EQ(user3->decryptInSpace(spaceId, note("n1"), after, by(userId(1))).data.stdString(), "after");
    user3.reset();
    keep3->disconnect();
    keep3.reset();
    switchTo(3);
    SpaceState state;
    ASSERT_NO_THROW({ state = groupApi->getSpace(spaceId); });
    EXPECT_EQ(state.keyVersion, 2);
    EXPECT_EQ(groupApi->decryptInSpace(spaceId, note("n1"), after, by(userId(1))).data.stdString(), "after");
}
