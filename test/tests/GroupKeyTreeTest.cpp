#include <gtest/gtest.h>
#include "../utils/BaseTest.hpp"
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
        threadApi = std::make_shared<thread::ThreadApi>(thread::ThreadApi::create(*connection, groupApi.get()));
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
        return groupApi->createGroupWithKeyTree(
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

    std::shared_ptr<core::Connection> connection;
    std::shared_ptr<thread::ThreadApi> threadApi;
    std::shared_ptr<group::GroupApi> groupApi;
    Poco::Util::IniFileConfiguration::Ptr reader;
    core::VarSerializer _serializer = core::VarSerializer({});
};

// ─────────────────────────────────────────────────────────────────────────────
// creation
// ─────────────────────────────────────────────────────────────────────────────

TEST_F(GroupKeyTreeTest, createGroupWithKeyTree_starts_at_epoch_one) {
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
        groupApi->addGroupMember(
            groupId, user(3), false,
            std::vector<core::UserWithPubKey>{user(1), user(2), user(3)},
            std::vector<core::UserWithPubKey>{user(1)},
            core::Buffer::from("keytree_public"), core::Buffer::from("keytree_private")
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
        groupApi->addGroupMember(
            groupId, user(3), false,
            std::vector<core::UserWithPubKey>{user(1), user(2), user(3)},
            std::vector<core::UserWithPubKey>{user(1)},
            core::Buffer::from("keytree_public"), core::Buffer::from("keytree_private")
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
        groupApi->removeGroupMember(
            groupId, user(3).userId,
            std::vector<core::UserWithPubKey>{user(1), user(2)},
            std::vector<core::UserWithPubKey>{user(1)},
            core::Buffer::from("keytree_public"), core::Buffer::from("keytree_private")
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
        groupApi->removeGroupMember(
            groupId, user(3).userId,
            std::vector<core::UserWithPubKey>{user(1), user(2)},
            std::vector<core::UserWithPubKey>{user(1)},
            core::Buffer::from("keytree_public"), core::Buffer::from("keytree_private")
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
        groupApi->removeGroupMember(
            groupId, user(3).userId,
            std::vector<core::UserWithPubKey>{user(1), user(2)},
            std::vector<core::UserWithPubKey>{user(1)},
            core::Buffer::from("keytree_public"), core::Buffer::from("keytree_private")
        );
    });

    // Re-key the thread to the new epoch, then write again. Until this happens the bridge refuses new content
    // (see the ROTATE_REQUIRED test below), so this step is what makes the removal bite.
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

TEST_F(GroupKeyTreeTest, ROTATE_REQUIRED_blocks_writes_until_the_container_catches_up) {
    // Lazy revocation: the bridge does not re-key anyone's containers for them, it refuses new content under a
    // superseded epoch. The window between the removal and the re-key is safe precisely because nothing can be
    // written in it.
    //
    // Enforcement is opt-in per container (`forwardSecrecy`), so the thread here asks for it. A container that
    // has not asked keeps accepting writes after a group rotation — deliberately, and the reason the assertion
    // below would otherwise pass for the wrong reason.
    std::string groupId;
    ASSERT_NO_THROW({ groupId = createTreeGroup({user(1), user(2), user(3)}); });
    group::Group group;
    ASSERT_NO_THROW({ group = groupApi->getGroup(groupId); });

    std::string threadId;
    ASSERT_NO_THROW({ threadId = createThreadGrantedTo(group, "yes"); });
    ASSERT_NO_THROW({
        threadApi->sendMessage(
            threadId, core::Buffer::from("p"), core::Buffer::from("p"), core::Buffer::from("before")
        );
    });

    ASSERT_NO_THROW({
        groupApi->removeGroupMember(
            groupId, user(3).userId,
            std::vector<core::UserWithPubKey>{user(1), user(2)},
            std::vector<core::UserWithPubKey>{user(1)},
            core::Buffer::from("keytree_public"), core::Buffer::from("keytree_private")
        );
    });

    // The thread still holds a key wrapped to epoch 1 while the group is at epoch 2.
    EXPECT_THROW({
        threadApi->sendMessage(
            threadId, core::Buffer::from("p"), core::Buffer::from("p"), core::Buffer::from("stale")
        );
    }, core::Exception) << "the bridge accepted content encrypted under a superseded group epoch";
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
        groupApi->removeGroupMember(
            groupId, user(3).userId,
            std::vector<core::UserWithPubKey>{user(1), user(2)},
            std::vector<core::UserWithPubKey>{user(1)},
            core::Buffer::from("keytree_public"), core::Buffer::from("keytree_private")
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
        groupApi->removeGroupMember(
            groupId, user(2).userId,
            std::vector<core::UserWithPubKey>{user(1)},
            std::vector<core::UserWithPubKey>{user(1)},
            core::Buffer::from("keytree_public"), core::Buffer::from("keytree_private")
        );
    });
    // Then seat user_3, who has never held any key of this group.
    ASSERT_NO_THROW({
        groupApi->addGroupMember(
            groupId, user(3), false,
            std::vector<core::UserWithPubKey>{user(1), user(3)},
            std::vector<core::UserWithPubKey>{user(1)},
            core::Buffer::from("keytree_public"), core::Buffer::from("keytree_private")
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
            groupApi->removeGroupMember(
                groupId, user(3).userId,
                std::vector<core::UserWithPubKey>{user(1), user(2)},
                std::vector<core::UserWithPubKey>{user(1)},
                core::Buffer::from("keytree_public"), core::Buffer::from("keytree_private")
            );
        }) << "removal round " << round;
        if (round < 2) {
            ASSERT_NO_THROW({
                groupApi->addGroupMember(
                    groupId, user(3), false,
                    std::vector<core::UserWithPubKey>{user(1), user(2), user(3)},
                    std::vector<core::UserWithPubKey>{user(1)},
                    core::Buffer::from("keytree_public"), core::Buffer::from("keytree_private")
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
        groupApi->addGroupMember(
            groupId, user(2), false,
            std::vector<core::UserWithPubKey>{user(1), user(2)},
            std::vector<core::UserWithPubKey>{user(1)},
            core::Buffer::from("keytree_public"), core::Buffer::from("keytree_private")
        );
    }, core::Exception);
}

TEST_F(GroupKeyTreeTest, removeGroupMember_rejects_somebody_who_is_not_a_member) {
    std::string groupId;
    ASSERT_NO_THROW({ groupId = createTreeGroup({user(1), user(2)}); });
    EXPECT_THROW({
        groupApi->removeGroupMember(
            groupId, user(3).userId,
            std::vector<core::UserWithPubKey>{user(1), user(2)},
            std::vector<core::UserWithPubKey>{user(1)},
            core::Buffer::from("keytree_public"), core::Buffer::from("keytree_private")
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
        groupApi->removeGroupMember(
            groupId, user(3).userId,
            std::vector<core::UserWithPubKey>{user(1), user(2)},
            std::vector<core::UserWithPubKey>{user(1)},
            core::Buffer::from("keytree_public"), core::Buffer::from("keytree_private")
        );
    }, core::Exception) << "a non-manager removed a member";
    disconnect();
    connectAs(KeyTreeConnectionType::KTUser1);
}

TEST_F(GroupKeyTreeTest, tree_operations_refuse_a_flat_group) {
    // Flat groups are untouched by this change and must stay that way: the tree operations have no state to work
    // from and say so, rather than inventing one.
    std::string flatId;
    ASSERT_NO_THROW({
        flatId = groupApi->createGroup(
            contextId(), std::vector<core::UserWithPubKey>{user(1), user(2)},
            std::vector<core::UserWithPubKey>{user(1)},
            core::Buffer::from("flat_public"), core::Buffer::from("flat_private")
        );
    });
    EXPECT_THROW({
        groupApi->addGroupMember(
            flatId, user(3), false,
            std::vector<core::UserWithPubKey>{user(1), user(2), user(3)},
            std::vector<core::UserWithPubKey>{user(1)},
            core::Buffer::from("flat_public"), core::Buffer::from("flat_private")
        );
    }, core::Exception);
    EXPECT_THROW({
        groupApi->removeGroupMember(
            flatId, user(2).userId,
            std::vector<core::UserWithPubKey>{user(1)},
            std::vector<core::UserWithPubKey>{user(1)},
            core::Buffer::from("flat_public"), core::Buffer::from("flat_private")
        );
    }, core::Exception);
}

TEST_F(GroupKeyTreeTest, a_flat_group_still_behaves_exactly_as_before) {
    // The additive-fallback promise, checked rather than assumed: the pre-tree path is the first one tried, and a
    // group created without a tree neither gains one nor loses anything.
    std::string flatId;
    ASSERT_NO_THROW({
        flatId = groupApi->createGroup(
            contextId(), std::vector<core::UserWithPubKey>{user(1), user(2)},
            std::vector<core::UserWithPubKey>{user(1)},
            core::Buffer::from("flat_public"), core::Buffer::from("flat_private")
        );
    });
    group::Group group;
    ASSERT_NO_THROW({ group = groupApi->getGroup(flatId); });
    EXPECT_EQ(group.statusCode, 0);
    EXPECT_EQ(group.privateMeta.stdString(), "flat_private");
    ASSERT_NO_THROW({
        groupApi->updateGroup(
            flatId, std::vector<core::UserWithPubKey>{user(1), user(2), user(3)},
            std::vector<core::UserWithPubKey>{user(1)},
            core::Buffer::from("flat_public2"), core::Buffer::from("flat_private2"),
            group.version, false, false
        );
    });
    ASSERT_NO_THROW({ group = groupApi->getGroup(flatId); });
    EXPECT_EQ(group.statusCode, 0);
    EXPECT_EQ(group.privateMeta.stdString(), "flat_private2");
}
