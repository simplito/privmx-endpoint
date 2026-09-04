#include <gtest/gtest.h>
#include "../../utils/BaseTest.hpp"
#include <Poco/Util/IniFileConfiguration.h>
#include <privmx/endpoint/core/Connection.hpp>
#include <privmx/endpoint/core/CoreException.hpp>
#include <privmx/endpoint/core/EventQueueImpl.hpp>
#include <privmx/endpoint/core/Exception.hpp>
#include <privmx/endpoint/core/VarSerializer.hpp>
#include <privmx/endpoint/group/GroupApi.hpp>
#include <privmx/endpoint/group/VarSerializer.hpp>
#include <privmx/endpoint/thread/ThreadApi.hpp>
#include <privmx/utils/Utils.hpp>

using namespace privmx::endpoint;

/**
 * End-to-end tests for tree-backed groups, against a running bridge.
 *
 * The unit tests on either side each check one half of the contract: this client builds a state, the server
 * decides whether it is well-formed, and the conformance fixture proves the two agree on paper. What none of them
 * can show is that the whole round trip works — that a member removed here really cannot read afterwards, and that
 * a member added later really can reach content written before they existed. That needs a server, so it lives
 * here.
 *
 * Tests named SECURITY assert that somebody *cannot* do something. They fail silently at runtime if the guard
 * regresses — nothing breaks, access simply persists where it should have ended — so they must not be deleted or
 * weakened into positive assertions.
 */

enum KeyTreeConnectionType {
    KTUser1,
    KTUser2,
    KTUser3
};

class GroupKeyTreeTest : public privmx::test::BaseTest {
protected:
    GroupKeyTreeTest() : BaseTest(privmx::test::BaseTestMode::online) {}

    void connectAs(KeyTreeConnectionType type) {
        std::string privKey;
        if (type == KeyTreeConnectionType::KTUser1) {
            privKey = reader->getString("Login.user_1_privKey");
        } else if (type == KeyTreeConnectionType::KTUser2) {
            privKey = reader->getString("Login.user_2_privKey");
        } else {
            privKey = reader->getString("Login.user_3_privKey");
        }
        connection = std::make_shared<core::Connection>(
            core::Connection::connect(
                privKey, reader->getString("Login.solutionId"),
                getPlatformUrl(reader->getString("Login.instanceUrl"))
            )
        );
        groupApi = std::make_shared<group::GroupApi>(group::GroupApi::create(*connection));
        threadApi = std::make_shared<thread::ThreadApi>(thread::ThreadApi::create(*connection, *groupApi));
    }

    void disconnect() {
        connection->disconnect();
        connection.reset();
        threadApi.reset();
        groupApi.reset();
    }

    void customSetUp() override {
        reader = new Poco::Util::IniFileConfiguration(INI_FILE_PATH);
        connectAs(KeyTreeConnectionType::KTUser1);
    }

    void customTearDown() override {
        connection.reset();
        threadApi.reset();
        groupApi.reset();
        reader.reset();
        core::EventQueueImpl::getInstance()->clear();
    }

    core::UserWithPubKey user(int index) {
        const std::string n = std::to_string(index);
        return core::UserWithPubKey{
            .userId = reader->getString("Login.user_" + n + "_id"),
            .pubKey = reader->getString("Login.user_" + n + "_pubKey")
        };
    }

    std::string contextId() {
        return reader->getString("Context_1.contextId");
    }

    /** A tree-backed group with user_1 managing and the given users as members. */
    std::string createTreeGroup(const std::vector<core::UserWithPubKey>& members) {
        return groupApi->createGroup(
            contextId(), members, std::vector<core::UserWithPubKey>{user(1)},
            core::Buffer::from("keytree_public"), core::Buffer::from("keytree_private")
        );
    }

    /**
     * A thread whose content key is wrapped to the group, so group membership decides who can read it.
     *
     * `forwardSecrecy = "yes"` is what makes the bridge refuse content written under a superseded group epoch.
     * It is a policy rather than a default because it forces every grantee container to re-key when a group
     * rotates: worth it when a removal must bite immediately, a needless cost when it need not.
     */
    std::string createThreadGrantedTo(const group::Group& group, const std::string& forwardSecrecy = "no") {
        core::ContainerPolicy policy;
        policy.get = "all";
        policy.forwardSecrecy = forwardSecrecy;
        policy.item = core::ItemPolicy{.get = "all", .listAll = "all"};
        return threadApi->createThread(
            contextId(),
            std::vector<core::UserWithPubKey>{user(1)},
            std::vector<core::UserWithPubKey>{user(1)},
            core::Buffer::from("kt_thread_public"),
            core::Buffer::from("kt_thread_private"),
            policy,
            std::vector<core::GroupGrantWithKey>{{
                .groupId = group.groupId,
                .role = "user",
                .groupPubKey = group.groupPubKey,
                .groupEpoch = group.keyVersion
            }}
        );
    }

    /**
     * As `createThreadGrantedTo`, with forward secrecy on and user_2 able to write but not to re-key.
     *
     * A stale key normally repairs itself — `sendMessage` re-keys the thread and sends under the new key — so a
     * caller who *may* re-key never sees the window at all. Pinning `rotateKeys` to managers and writing as a
     * plain user is what still puts a writer inside it: refused, until somebody with the right to fix it does.
     */
    std::string createThreadGrantedToWithManagerOnlyRekey(const group::Group& group) {
        core::ContainerPolicy policy;
        policy.get = "all";
        policy.forwardSecrecy = "yes";
        policy.rotateKeys = "manager";
        policy.item = core::ItemPolicy{.get = "all", .listAll = "all"};
        return threadApi->createThread(
            contextId(),
            std::vector<core::UserWithPubKey>{user(1), user(2)},
            std::vector<core::UserWithPubKey>{user(1)},
            core::Buffer::from("kt_thread_public"),
            core::Buffer::from("kt_thread_private"),
            policy,
            std::vector<core::GroupGrantWithKey>{{
                .groupId = group.groupId,
                .role = "user",
                .groupPubKey = group.groupPubKey,
                .groupEpoch = group.keyVersion
            }}
        );
    }

    std::shared_ptr<core::Connection> connection;
    std::shared_ptr<thread::ThreadApi> threadApi;
    std::shared_ptr<group::GroupApi> groupApi;
    Poco::Util::IniFileConfiguration::Ptr reader;
    core::VarSerializer _serializer = core::VarSerializer({});
};

// ─────────────────────────────────────────────────────────────────────────────
// creation
// ─────────────────────────────────────────────────────────────────────────────

TEST_F(GroupKeyTreeTest, createGroup_starts_at_epoch_one) {
    std::string groupId;
    ASSERT_NO_THROW({ groupId = createTreeGroup({user(1), user(2), user(3)}); });
    ASSERT_FALSE(groupId.empty());

    group::Group group;
    ASSERT_NO_THROW({ group = groupApi->getGroup(groupId); });
    EXPECT_EQ(group.statusCode, 0) << "the creator must be able to decrypt the group it just made";
    EXPECT_EQ(group.keyVersion, 1);
    EXPECT_FALSE(group.groupPubKey.empty());
    EXPECT_EQ(group.publicMeta.stdString(), "keytree_public");
    EXPECT_EQ(group.privateMeta.stdString(), "keytree_private");
}

TEST_F(GroupKeyTreeTest, every_member_can_read_a_tree_backed_group) {
    // The group's metadata key is wrapped once, to the group itself. Each member gets at it by climbing the tree,
    // which is the read path this whole design rests on — if it fails, nothing else works.
    std::string groupId;
    ASSERT_NO_THROW({ groupId = createTreeGroup({user(1), user(2), user(3)}); });
    disconnect();

    for (const auto type : {KeyTreeConnectionType::KTUser2, KeyTreeConnectionType::KTUser3}) {
        connectAs(type);
        group::Group group;
        ASSERT_NO_THROW({ group = groupApi->getGroup(groupId); });
        EXPECT_EQ(group.statusCode, 0) << "a member could not decrypt the group";
        EXPECT_EQ(group.privateMeta.stdString(), "keytree_private");
        disconnect();
    }
    connectAs(KeyTreeConnectionType::KTUser1);
}

TEST_F(GroupKeyTreeTest, SECURITY_a_non_member_cannot_read_a_tree_backed_group) {
    std::string groupId;
    ASSERT_NO_THROW({ groupId = createTreeGroup({user(1), user(2)}); });
    disconnect();

    // user_3 holds no leaf: no edge is addressed to them, so there is nothing to climb.
    connectAs(KeyTreeConnectionType::KTUser3);
    group::Group group;
    bool threw = false;
    try {
        group = groupApi->getGroup(groupId);
    } catch (const core::Exception&) {
        threw = true;
    }
    if (!threw) {
        EXPECT_NE(group.statusCode, 0) << "a non-member decrypted the group's metadata";
    }
    disconnect();
    connectAs(KeyTreeConnectionType::KTUser1);
}

// ─────────────────────────────────────────────────────────────────────────────
// addition — the operation that must stay cheap
// ─────────────────────────────────────────────────────────────────────────────

TEST_F(GroupKeyTreeTest, addGroupMember_does_not_advance_the_epoch) {
    // The heart of the economy: adding a member leaves the epoch alone, so no container the group can read goes
    // stale and nobody else re-keys anything.
    std::string groupId;
    ASSERT_NO_THROW({ groupId = createTreeGroup({user(1), user(2)}); });
    group::Group before;
    ASSERT_NO_THROW({ before = groupApi->getGroup(groupId); });

    ASSERT_NO_THROW({
        groupApi->addGroupMembers(
            groupId,
            {group::GroupMemberToAdd{.user = user(3), .role = "user"}}
        );
    });

    group::Group after;
    ASSERT_NO_THROW({ after = groupApi->getGroup(groupId); });
    EXPECT_EQ(after.keyVersion, before.keyVersion) << "an addition rotated the group key";
    EXPECT_EQ(after.groupPubKey, before.groupPubKey) << "an addition replaced the grant key";
    EXPECT_NE(std::find(after.users.begin(), after.users.end(), user(3).userId), after.users.end());
}

TEST_F(GroupKeyTreeTest, an_added_member_can_read_the_group) {
    std::string groupId;
    ASSERT_NO_THROW({ groupId = createTreeGroup({user(1), user(2)}); });
    ASSERT_NO_THROW({
        groupApi->addGroupMembers(
            groupId,
            {group::GroupMemberToAdd{.user = user(3), .role = "user"}}
        );
    });
    disconnect();

    connectAs(KeyTreeConnectionType::KTUser3);
    group::Group group;
    ASSERT_NO_THROW({ group = groupApi->getGroup(groupId); });
    EXPECT_EQ(group.statusCode, 0) << "the newly seated member cannot climb to the group key";
    EXPECT_EQ(group.privateMeta.stdString(), "keytree_private");
    disconnect();
    connectAs(KeyTreeConnectionType::KTUser1);
}

// ─────────────────────────────────────────────────────────────────────────────
// removal — the operation the whole design exists for
// ─────────────────────────────────────────────────────────────────────────────

TEST_F(GroupKeyTreeTest, removeGroupMember_advances_the_epoch_and_replaces_the_grant_key) {
    std::string groupId;
    ASSERT_NO_THROW({ groupId = createTreeGroup({user(1), user(2), user(3)}); });
    group::Group before;
    ASSERT_NO_THROW({ before = groupApi->getGroup(groupId); });

    ASSERT_NO_THROW({
        groupApi->removeGroupMembers(
            groupId,
{user(3).userId}
        );
    });

    group::Group after;
    ASSERT_NO_THROW({ after = groupApi->getGroup(groupId); });
    EXPECT_EQ(after.keyVersion, before.keyVersion + 1) << "a removal must advance the epoch";
    EXPECT_NE(after.groupPubKey, before.groupPubKey) << "a removal must mint a new grant key";
    EXPECT_EQ(std::find(after.users.begin(), after.users.end(), user(3).userId), after.users.end());
    EXPECT_EQ(after.statusCode, 0) << "a remaining member cannot read the group it still belongs to";
}

TEST_F(GroupKeyTreeTest, remaining_members_can_still_read_after_a_removal) {
    std::string groupId;
    ASSERT_NO_THROW({ groupId = createTreeGroup({user(1), user(2), user(3)}); });
    ASSERT_NO_THROW({
        groupApi->removeGroupMembers(
            groupId,
{user(3).userId}
        );
    });
    disconnect();

    connectAs(KeyTreeConnectionType::KTUser2);
    group::Group group;
    ASSERT_NO_THROW({ group = groupApi->getGroup(groupId); });
    EXPECT_EQ(group.statusCode, 0) << "the refresh locked out a member who should have kept access";
    EXPECT_EQ(group.privateMeta.stdString(), "keytree_private");
    disconnect();
    connectAs(KeyTreeConnectionType::KTUser1);
}

TEST_F(GroupKeyTreeTest, SECURITY_a_removed_member_cannot_read_content_written_afterwards) {
    // The claim the whole construction makes. A thread wrapped to the group at epoch 1 stays readable to the
    // removed member — they saw it while they were in — but content wrapped at epoch 2 must not be.
    std::string groupId;
    ASSERT_NO_THROW({ groupId = createTreeGroup({user(1), user(2), user(3)}); });
    group::Group group;
    ASSERT_NO_THROW({ group = groupApi->getGroup(groupId); });

    std::string threadId;
    ASSERT_NO_THROW({ threadId = createThreadGrantedTo(group, "yes"); });
    ASSERT_NO_THROW({
        threadApi->sendMessage(
            threadId, core::Buffer::from("pub_before"), core::Buffer::from("priv_before"),
            core::Buffer::from("data_before")
        );
    });

    ASSERT_NO_THROW({
        groupApi->removeGroupMembers(
            groupId,
{user(3).userId}
        );
    });

    // Re-key the thread to the new epoch, then write again. Until this happens no new content is accepted (see
    // the ROTATE_REQUIRED test below), so this step is what makes the removal bite. Done explicitly rather than
    // left to `sendMessage`'s automatic re-key, so what the removed member is denied is not in doubt.
    group::Group rotated;
    ASSERT_NO_THROW({ rotated = groupApi->getGroup(groupId); });
    ASSERT_NO_THROW({
        threadApi->updateThread(
            threadId, std::vector<core::UserWithPubKey>{user(1)}, std::vector<core::UserWithPubKey>{user(1)},
            core::Buffer::from("kt_thread_public"), core::Buffer::from("kt_thread_private"),
            1, true, true, std::nullopt,
            std::vector<core::GroupGrantWithKey>{{
                .groupId = groupId, .role = "user", .groupPubKey = rotated.groupPubKey,
                .groupEpoch = rotated.keyVersion
            }}
        );
    });
    std::string afterId;
    ASSERT_NO_THROW({
        afterId = threadApi->sendMessage(
            threadId, core::Buffer::from("pub_after"), core::Buffer::from("priv_after"),
            core::Buffer::from("data_after")
        );
    });
    disconnect();

    connectAs(KeyTreeConnectionType::KTUser3);
    thread::Message message;
    bool threw = false;
    try {
        message = threadApi->getMessage(afterId);
    } catch (const core::Exception&) {
        threw = true;
    }
    if (!threw) {
        EXPECT_NE(message.statusCode, 0)
            << "a removed member read content written after their removal";
        EXPECT_NE(message.data.stdString(), "data_after");
    }
    disconnect();
    connectAs(KeyTreeConnectionType::KTUser1);
}

// ─────────────────────────────────────────────────────────────────────────────
// key cache
// ─────────────────────────────────────────────────────────────────────────────

TEST_F(GroupKeyTreeTest, SECURITY_two_groups_at_the_same_epoch_do_not_share_cached_keys) {
    // The client caches the grant key it recovers by climbing. Cached per group, that is a pure optimisation;
    // cached per epoch alone it is a correctness bug, because every group starts at epoch 1. A reader in two such
    // groups would get the first group's key handed back for the second, and the second's content would not open.
    //
    // The read has to go through a group grant to exercise it at all: a member with a personal key entry never
    // climbs. Hence user_2, who is in both groups and named on neither thread.
    std::string groupIdA, groupIdB;
    ASSERT_NO_THROW({ groupIdA = createTreeGroup({user(1), user(2)}); });
    ASSERT_NO_THROW({ groupIdB = createTreeGroup({user(1), user(2)}); });
    group::Group groupA, groupB;
    ASSERT_NO_THROW({ groupA = groupApi->getGroup(groupIdA); });
    ASSERT_NO_THROW({ groupB = groupApi->getGroup(groupIdB); });

    // Preconditions, so this cannot pass vacuously: the collision only exists at equal epochs, between groups
    // that really do have different grant keys.
    ASSERT_EQ(groupA.keyVersion, groupB.keyVersion);
    ASSERT_EQ(groupA.keyVersion, 1);
    ASSERT_NE(groupA.groupPubKey, groupB.groupPubKey);

    std::string threadIdA, threadIdB;
    ASSERT_NO_THROW({ threadIdA = createThreadGrantedTo(groupA); });
    ASSERT_NO_THROW({ threadIdB = createThreadGrantedTo(groupB); });
    std::string messageIdA, messageIdB;
    ASSERT_NO_THROW({
        messageIdA = threadApi->sendMessage(
            threadIdA, core::Buffer::from("pub_a"), core::Buffer::from("priv_a"), core::Buffer::from("data_A")
        );
    });
    ASSERT_NO_THROW({
        messageIdB = threadApi->sendMessage(
            threadIdB, core::Buffer::from("pub_b"), core::Buffer::from("priv_b"), core::Buffer::from("data_B")
        );
    });
    disconnect();

    connectAs(KeyTreeConnectionType::KTUser2);
    thread::Message fromA;
    ASSERT_NO_THROW({ fromA = threadApi->getMessage(messageIdA); });
    ASSERT_EQ(fromA.statusCode, 0);
    ASSERT_EQ(fromA.data.stdString(), "data_A");

    // Group A's epoch-1 key is cached now. Group B is also at epoch 1.
    thread::Message fromB;
    ASSERT_NO_THROW({ fromB = threadApi->getMessage(messageIdB); });
    EXPECT_EQ(fromB.statusCode, 0)
        << "reading group B after group A returned group A's cached grant key for epoch 1";
    EXPECT_EQ(fromB.data.stdString(), "data_B");

    // And back again, so the fix cannot be an eviction that merely swaps which group is broken.
    thread::Message fromAAgain;
    ASSERT_NO_THROW({ fromAAgain = threadApi->getMessage(messageIdA); });
    EXPECT_EQ(fromAAgain.statusCode, 0);
    EXPECT_EQ(fromAAgain.data.stdString(), "data_A");
    disconnect();
    connectAs(KeyTreeConnectionType::KTUser1);
}

TEST_F(GroupKeyTreeTest, removeGroupMember_leaves_the_same_session_able_to_read_both_epochs) {
    // A removal drops the cached node keys, because their generations were just refreshed, and seeds the new
    // epoch's grant key. It must not drop the *older* grant keys: the ladder descent to pre-removal content still
    // needs them. Both halves are checked here, in the session that performed the removal — no reconnect.
    std::string groupId;
    ASSERT_NO_THROW({ groupId = createTreeGroup({user(1), user(2), user(3)}); });
    group::Group group;
    ASSERT_NO_THROW({ group = groupApi->getGroup(groupId); });

    std::string threadId;
    ASSERT_NO_THROW({ threadId = createThreadGrantedTo(group, "yes"); });
    std::string beforeId;
    ASSERT_NO_THROW({
        beforeId = threadApi->sendMessage(
            threadId, core::Buffer::from("pub_before"), core::Buffer::from("priv_before"),
            core::Buffer::from("data_before")
        );
    });

    ASSERT_NO_THROW({
        groupApi->removeGroupMembers(
            groupId,
{user(3).userId}
        );
    });

    group::Group rotated;
    ASSERT_NO_THROW({ rotated = groupApi->getGroup(groupId); });
    ASSERT_EQ(rotated.keyVersion, 2);
    ASSERT_NO_THROW({
        threadApi->updateThread(
            threadId, std::vector<core::UserWithPubKey>{user(1)}, std::vector<core::UserWithPubKey>{user(1)},
            core::Buffer::from("kt_thread_public"), core::Buffer::from("kt_thread_private"),
            1, true, true, std::nullopt,
            std::vector<core::GroupGrantWithKey>{{
                .groupId = groupId, .role = "user", .groupPubKey = rotated.groupPubKey,
                .groupEpoch = rotated.keyVersion
            }}
        );
    });
    std::string afterId;
    ASSERT_NO_THROW({
        afterId = threadApi->sendMessage(
            threadId, core::Buffer::from("pub_after"), core::Buffer::from("priv_after"),
            core::Buffer::from("data_after")
        );
    });

    thread::Message after;
    ASSERT_NO_THROW({ after = threadApi->getMessage(afterId); });
    EXPECT_EQ(after.statusCode, 0) << "the new epoch's grant key was not usable after the removal";
    EXPECT_EQ(after.data.stdString(), "data_after");

    thread::Message before;
    ASSERT_NO_THROW({ before = threadApi->getMessage(beforeId); });
    EXPECT_EQ(before.statusCode, 0) << "the removal discarded the older epoch key the ladder descent needs";
    EXPECT_EQ(before.data.stdString(), "data_before");
}

TEST_F(GroupKeyTreeTest, reconnecting_rebuilds_the_key_cache_from_scratch) {
    // Connect and disconnect both empty the cache. A read after reconnecting has to climb again and succeed.
    std::string groupId;
    ASSERT_NO_THROW({ groupId = createTreeGroup({user(1), user(2)}); });
    group::Group group;
    ASSERT_NO_THROW({ group = groupApi->getGroup(groupId); });

    std::string threadId;
    ASSERT_NO_THROW({ threadId = createThreadGrantedTo(group); });
    std::string messageId;
    ASSERT_NO_THROW({
        messageId = threadApi->sendMessage(
            threadId, core::Buffer::from("pub"), core::Buffer::from("priv"), core::Buffer::from("data_x")
        );
    });
    disconnect();

    connectAs(KeyTreeConnectionType::KTUser2);
    thread::Message first;
    ASSERT_NO_THROW({ first = threadApi->getMessage(messageId); });
    ASSERT_EQ(first.statusCode, 0);
    disconnect();

    connectAs(KeyTreeConnectionType::KTUser2);
    thread::Message second;
    ASSERT_NO_THROW({ second = threadApi->getMessage(messageId); });
    EXPECT_EQ(second.statusCode, 0) << "the cache was emptied on reconnect and the re-climb failed";
    EXPECT_EQ(second.data.stdString(), "data_x");
    disconnect();
    connectAs(KeyTreeConnectionType::KTUser1);
}

TEST_F(GroupKeyTreeTest, ROTATE_REQUIRED_blocks_writes_until_the_container_catches_up) {
    // Lazy revocation: nobody re-keys a container behind its members' backs, and no new content is accepted
    // under a superseded epoch. The window between the removal and the re-key is safe precisely because nothing
    // can be written in it.
    //
    // Two things have to hold for that to be the assertion below. Enforcement is opt-in per container
    // (`forwardSecrecy`), so the thread here asks for it — a container that has not asked keeps accepting writes
    // after a group rotation, deliberately. And the writer has to be someone who cannot close the window
    // themselves: `sendMessage` re-keys a stale thread and retries, so user_1 would never see the refusal. Hence
    // `rotateKeys: "manager"` and a write from user_2, who is a thread user and not a manager. Putting user_1
    // back here would make this test pass for the wrong reason.
    std::string groupId;
    ASSERT_NO_THROW({ groupId = createTreeGroup({user(1), user(2), user(3)}); });
    group::Group group;
    ASSERT_NO_THROW({ group = groupApi->getGroup(groupId); });

    std::string threadId;
    ASSERT_NO_THROW({ threadId = createThreadGrantedToWithManagerOnlyRekey(group); });
    ASSERT_NO_THROW({
        threadApi->sendMessage(
            threadId, core::Buffer::from("p"), core::Buffer::from("p"), core::Buffer::from("before")
        );
    });

    ASSERT_NO_THROW({
        groupApi->removeGroupMembers(
            groupId,
{user(3).userId}
        );
    });

    thread::Thread beforeWrite;
    ASSERT_NO_THROW({ beforeWrite = threadApi->getThread(threadId); });
    ASSERT_EQ(beforeWrite.staleGroups.size(), 1);

    disconnect();
    connectAs(KeyTreeConnectionType::KTUser2);

    // The thread still holds a key wrapped to epoch 1 while the group is at epoch 2, and user_2 may not re-key.
    EXPECT_THROW({
        threadApi->sendMessage(
            threadId, core::Buffer::from("p"), core::Buffer::from("p"), core::Buffer::from("stale")
        );
    }, core::StaleKeyRekeyRequiredException) << "content was accepted under a superseded group epoch";

    // And the refused write left the thread exactly where it was — no partial re-key on the way out.
    thread::Thread afterWrite;
    ASSERT_NO_THROW({ afterWrite = threadApi->getThread(threadId); });
    EXPECT_EQ(afterWrite.version, beforeWrite.version);
    EXPECT_EQ(afterWrite.staleGroups.size(), 1);

    disconnect();
    connectAs(KeyTreeConnectionType::KTUser1);
}

// ─────────────────────────────────────────────────────────────────────────────
// history — the Epoch Ladder, end to end
// ─────────────────────────────────────────────────────────────────────────────

TEST_F(GroupKeyTreeTest, a_remaining_member_reads_content_from_before_a_removal) {
    // Reaching the old message needs the *previous* epoch's grant key, which no longer exists in the tree. It is
    // recovered by descending the ladder — one rung — and this is the first place that path runs against a server.
    std::string groupId;
    ASSERT_NO_THROW({ groupId = createTreeGroup({user(1), user(2), user(3)}); });
    group::Group group;
    ASSERT_NO_THROW({ group = groupApi->getGroup(groupId); });

    std::string threadId;
    ASSERT_NO_THROW({ threadId = createThreadGrantedTo(group); });
    std::string oldMessageId;
    ASSERT_NO_THROW({
        oldMessageId = threadApi->sendMessage(
            threadId, core::Buffer::from("pub_old"), core::Buffer::from("priv_old"),
            core::Buffer::from("data_old")
        );
    });

    ASSERT_NO_THROW({
        groupApi->removeGroupMembers(
            groupId,
{user(3).userId}
        );
    });
    disconnect();

    connectAs(KeyTreeConnectionType::KTUser2);
    thread::Message message;
    ASSERT_NO_THROW({ message = threadApi->getMessage(oldMessageId); });
    EXPECT_EQ(message.statusCode, 0) << "a remaining member lost the group's history at the removal";
    EXPECT_EQ(message.data.stdString(), "data_old");
    disconnect();
    connectAs(KeyTreeConnectionType::KTUser1);
}

TEST_F(GroupKeyTreeTest, a_newcomer_reads_history_that_predates_them) {
    // The payoff of the Epoch Ladder: user_3 is seated *after* a removal bumped the epoch, and reads a message
    // written before they were a member — with nothing in the archive addressed to them personally.
    std::string groupId;
    ASSERT_NO_THROW({ groupId = createTreeGroup({user(1), user(2)}); });
    group::Group group;
    ASSERT_NO_THROW({ group = groupApi->getGroup(groupId); });

    std::string threadId;
    ASSERT_NO_THROW({ threadId = createThreadGrantedTo(group); });
    std::string oldMessageId;
    ASSERT_NO_THROW({
        oldMessageId = threadApi->sendMessage(
            threadId, core::Buffer::from("pub_hist"), core::Buffer::from("priv_hist"),
            core::Buffer::from("data_hist")
        );
    });

    // Rotate the epoch, so reaching the message requires a descent rather than the current key.
    ASSERT_NO_THROW({
        groupApi->removeGroupMembers(
            groupId,
{user(2).userId}
        );
    });
    // Then seat user_3, who has never held any key of this group.
    ASSERT_NO_THROW({
        groupApi->addGroupMembers(
            groupId,
            {group::GroupMemberToAdd{.user = user(3), .role = "user"}}
        );
    });
    disconnect();

    connectAs(KeyTreeConnectionType::KTUser3);
    thread::Message message;
    ASSERT_NO_THROW({ message = threadApi->getMessage(oldMessageId); });
    EXPECT_EQ(message.statusCode, 0)
        << "a newcomer could not descend the ladder to content that predates them";
    EXPECT_EQ(message.data.stdString(), "data_hist");
    disconnect();
    connectAs(KeyTreeConnectionType::KTUser1);
}

TEST_F(GroupKeyTreeTest, several_removals_in_a_row_keep_the_whole_history_reachable) {
    // Each removal adds one rung. After three, reaching the oldest message means descending three of them, and
    // every hop is verified against the epoch registry on the way down.
    std::string groupId;
    ASSERT_NO_THROW({ groupId = createTreeGroup({user(1), user(2), user(3)}); });
    group::Group group;
    ASSERT_NO_THROW({ group = groupApi->getGroup(groupId); });

    std::string threadId;
    ASSERT_NO_THROW({ threadId = createThreadGrantedTo(group); });
    std::string oldestId;
    ASSERT_NO_THROW({
        oldestId = threadApi->sendMessage(
            threadId, core::Buffer::from("p"), core::Buffer::from("p"), core::Buffer::from("oldest")
        );
    });

    // remove user_3, then re-add and remove again, twice more — three epoch bumps in total.
    for (int round = 0; round < 3; round++) {
        ASSERT_NO_THROW({
            groupApi->removeGroupMembers(
            groupId,
{user(3).userId}
        );
        }) << "removal round " << round;
        if (round < 2) {
            ASSERT_NO_THROW({
                groupApi->addGroupMembers(
            groupId,
            {group::GroupMemberToAdd{.user = user(3), .role = "user"}}
        );
            }) << "re-add round " << round;
        }
    }

    group::Group final_state;
    ASSERT_NO_THROW({ final_state = groupApi->getGroup(groupId); });
    EXPECT_EQ(final_state.keyVersion, 4) << "three removals should give epochs 1 -> 4";

    thread::Message message;
    ASSERT_NO_THROW({ message = threadApi->getMessage(oldestId); });
    EXPECT_EQ(message.statusCode, 0) << "the oldest message became unreachable after three epoch bumps";
    EXPECT_EQ(message.data.stdString(), "oldest");
}

// ─────────────────────────────────────────────────────────────────────────────
// rejections the server owes us
// ─────────────────────────────────────────────────────────────────────────────

TEST_F(GroupKeyTreeTest, addGroupMember_rejects_somebody_already_in_the_group) {
    std::string groupId;
    ASSERT_NO_THROW({ groupId = createTreeGroup({user(1), user(2)}); });
    EXPECT_THROW({
        groupApi->addGroupMembers(
            groupId,
            {group::GroupMemberToAdd{.user = user(2), .role = "user"}}
        );
    }, core::Exception);
}

TEST_F(GroupKeyTreeTest, removeGroupMember_rejects_somebody_who_is_not_a_member) {
    std::string groupId;
    ASSERT_NO_THROW({ groupId = createTreeGroup({user(1), user(2)}); });
    EXPECT_THROW({
        groupApi->removeGroupMembers(
            groupId,
{user(3).userId}
        );
    }, core::Exception);
}

TEST_F(GroupKeyTreeTest, SECURITY_a_plain_member_cannot_remove_anybody) {
    // Reaching the keys and being allowed to use them are different questions. Any member can climb, so any
    // member could *compute* a valid removal; the bridge's policy gate is what stops them submitting it.
    std::string groupId;
    ASSERT_NO_THROW({ groupId = createTreeGroup({user(1), user(2), user(3)}); });
    disconnect();

    connectAs(KeyTreeConnectionType::KTUser2);
    EXPECT_THROW({
        groupApi->removeGroupMembers(
            groupId,
{user(3).userId}
        );
    }, core::Exception) << "a non-manager removed a member";
    disconnect();
    connectAs(KeyTreeConnectionType::KTUser1);
}

