#include <gtest/gtest.h>
#include <algorithm>
#include "../../utils/BaseGroupTest.hpp"
#include <privmx/endpoint/core/Exception.hpp>
#include <Poco/Util/IniFileConfiguration.h>
#include <privmx/endpoint/core/EventQueueImpl.hpp>
#include <privmx/utils/Utils.hpp>
#include <privmx/endpoint/core/VarSerializer.hpp>
#include <privmx/endpoint/core/Connection.hpp>
#include <privmx/endpoint/thread/ThreadApi.hpp>
#include <privmx/endpoint/thread/VarSerializer.hpp>
#include <privmx/endpoint/group/GroupApi.hpp>
#include <privmx/endpoint/group/VarSerializer.hpp>
#include <privmx/endpoint/core/ConvertedExceptions.hpp>
#include <privmx/endpoint/core/CoreException.hpp>
#include <privmx/endpoint/core/ConvertedExceptions.hpp>
using namespace privmx::endpoint;

class ThreadUsingGroupsTest : public privmx::test::BaseGroupTest {
protected:
    void setUpModuleApis() override {
        threadApi = std::make_shared<thread::ThreadApi>(thread::ThreadApi::create(*connection, *groupApi));
    }
    void tearDownModuleApis() override {
        threadApi.reset();
    }
    std::string createThreadWithGroup(
        const std::string& contextId,
        const std::string& userId,
        const std::string& userPubKey,
        const group::Group& group
    ) {
        return threadApi->createThread(
            contextId,
            std::vector<core::UserWithPubKey>{{.userId = userId, .pubKey = userPubKey}},
            std::vector<core::UserWithPubKey>{{.userId = userId, .pubKey = userPubKey}},
            core::Buffer::from("group_thread_public"),
            core::Buffer::from("group_thread_private"),
            core::ContainerPolicy(),
            std::vector<core::GroupGrantWithKey>{{
                .groupId = group.groupId,
                .role = "user",
                .groupPubKey = group.groupPubKey
            }}
        );
    }
    // A Thread whose direct members are `users` (as both users and managers) and whose grantee groups are
    // `groups`. Leaving `groupEpoch` at 0 makes the endpoint resolve each group's current epoch from the Bridge.
    std::string createThreadWithGroups(
        const std::string& contextId,
        const std::vector<core::UserWithPubKey>& users,
        const std::vector<group::Group>& groups,
        const std::string& role = "user"
    ) {
        std::vector<core::GroupGrantWithKey> grants;
        grants.reserve(groups.size());
        for (const auto& group : groups) {
            grants.push_back(
                core::GroupGrantWithKey{.groupId = group.groupId, .role = role, .groupPubKey = group.groupPubKey}
            );
        }
        return threadApi->createThread(
            contextId,
            users,
            users,
            core::Buffer::from("group_thread_public"),
            core::Buffer::from("group_thread_private"),
            core::ContainerPolicy(),
            grants
        );
    }
    std::string createThreadWithGroupPolicyReadAll(
        const std::string& contextId,
        const std::string& userId,
        const std::string& userPubKey,
        const group::Group& group
    ) {
        core::ContainerPolicy policy;
        policy.get = "all";
        policy.item = core::ItemPolicy{.get = "all", .listAll = "all"};
        return threadApi->createThread(
            contextId,
            std::vector<core::UserWithPubKey>{{.userId = userId, .pubKey = userPubKey}},
            std::vector<core::UserWithPubKey>{{.userId = userId, .pubKey = userPubKey}},
            core::Buffer::from("group_thread_public"),
            core::Buffer::from("group_thread_private"),
            policy,
            std::vector<core::GroupGrantWithKey>{{
                .groupId = group.groupId,
                .role = "user",
                .groupPubKey = group.groupPubKey
            }}
        );
    }

    std::shared_ptr<thread::ThreadApi> threadApi;
};

TEST_F(ThreadUsingGroupsTest, createThread_with_group_grants) {
    group::Group group_1, group_2;
    ASSERT_NO_THROW({ group_1 = groupApi->getGroup(reader->getString("Group_1.groupId")); });
    ASSERT_NO_THROW({ group_2 = groupApi->getGroup(reader->getString("Group_2.groupId")); });
    ASSERT_EQ(group_1.statusCode, 0);
    ASSERT_EQ(group_2.statusCode, 0);
    ASSERT_FALSE(group_1.groupPubKey.empty());

    // no grants
    std::string threadId;
    thread::Thread t;
    EXPECT_NO_THROW({
        threadId = createThreadWithGroups(
            reader->getString("Context_1.contextId"),
            std::vector<core::UserWithPubKey>{user(1)},
            std::vector<group::Group>{}
        );
    });
    ASSERT_FALSE(threadId.empty());
    EXPECT_NO_THROW({ t = threadApi->getThread(threadId); });
    EXPECT_EQ(t.statusCode, 0);
    EXPECT_EQ(t.groups.size(), 0);

    // one grant
    EXPECT_NO_THROW({
        threadId = createThreadWithGroups(
            reader->getString("Context_1.contextId"),
            std::vector<core::UserWithPubKey>{user(1)},
            std::vector<group::Group>{group_1}
        );
    });
    ASSERT_FALSE(threadId.empty());
    EXPECT_NO_THROW({ t = threadApi->getThread(threadId); });
    EXPECT_EQ(t.statusCode, 0);
    EXPECT_EQ(t.publicMeta.stdString(), "group_thread_public");
    ASSERT_EQ(t.groups.size(), 1);
    EXPECT_EQ(t.groups[0].groupId, group_1.groupId);
    EXPECT_EQ(t.groups[0].role, "user");

    // two grants, each carrying its own role
    EXPECT_NO_THROW({
        threadId = threadApi->createThread(
            reader->getString("Context_1.contextId"),
            std::vector<core::UserWithPubKey>{user(1)},
            std::vector<core::UserWithPubKey>{user(1)},
            core::Buffer::from("two_groups_public"),
            core::Buffer::from("two_groups_private"),
            std::nullopt,
            std::vector<core::GroupGrantWithKey>{
                core::GroupGrantWithKey{
                    .groupId = group_1.groupId,
                    .role = "user",
                    .groupPubKey = group_1.groupPubKey
                },
                core::GroupGrantWithKey{
                    .groupId = group_2.groupId,
                    .role = "manager",
                    .groupPubKey = group_2.groupPubKey
                }
            }
        );
    });
    ASSERT_FALSE(threadId.empty());
    EXPECT_NO_THROW({ t = threadApi->getThread(threadId); });
    EXPECT_EQ(t.statusCode, 0);
    EXPECT_EQ(t.groups.size(), 2);
    bool found1 = false, found2 = false;
    for (const auto& g : t.groups) {
        if (g.groupId == group_1.groupId && g.role == "user") found1 = true;
        if (g.groupId == group_2.groupId && g.role == "manager") found2 = true;
    }
    EXPECT_TRUE(found1);
    EXPECT_TRUE(found2);

    // a grant whose public key is not a key
    EXPECT_THROW({
        threadApi->createThread(
            reader->getString("Context_1.contextId"),
            std::vector<core::UserWithPubKey>{user(1)},
            std::vector<core::UserWithPubKey>{user(1)},
            core::Buffer::from("public"),
            core::Buffer::from("private"),
            std::nullopt,
            std::vector<core::GroupGrantWithKey>{core::GroupGrantWithKey{
                .groupId = reader->getString("Group_1.groupId"),
                .role = "user",
                .groupPubKey = "not_a_valid_base58der_pubkey"
            }}
        );
    }, core::Exception);
}

TEST_F(ThreadUsingGroupsTest, updateThread_add_and_promote_group) {
    group::Group group_1;
    ASSERT_NO_THROW({ group_1 = groupApi->getGroup(reader->getString("Group_1.groupId")); });
    ASSERT_EQ(group_1.statusCode, 0);

    // a thread that starts with no grantee group
    std::string threadId;
    EXPECT_NO_THROW({
        threadId = createThreadWithGroups(
            reader->getString("Context_1.contextId"),
            std::vector<core::UserWithPubKey>{user(1)},
            std::vector<group::Group>{}
        );
    });
    ASSERT_FALSE(threadId.empty());
    thread::Thread t;
    EXPECT_NO_THROW({ t = threadApi->getThread(threadId); });
    EXPECT_EQ(t.groups.size(), 0);

    // add one
    EXPECT_NO_THROW({
        threadApi->updateThread(
            threadId,
            std::vector<core::UserWithPubKey>{user(1)},
            std::vector<core::UserWithPubKey>{user(1)},
            core::Buffer::from("after_group"),
            core::Buffer::from("after_group_private"),
            1,
            false,
            false,
            std::nullopt,
            std::vector<core::GroupGrantWithKey>{core::GroupGrantWithKey{
                .groupId = group_1.groupId,
                .role = "user",
                .groupPubKey = group_1.groupPubKey
            }}
        );
    });
    thread::Thread updated;
    EXPECT_NO_THROW({ updated = threadApi->getThread(threadId); });
    EXPECT_EQ(updated.statusCode, 0);
    EXPECT_EQ(updated.publicMeta.stdString(), "after_group");
    ASSERT_EQ(updated.groups.size(), 1);
    EXPECT_EQ(updated.groups[0].groupId, group_1.groupId);
    EXPECT_EQ(updated.groups[0].role, "user");

    // promote it from "user" to "manager"
    EXPECT_NO_THROW({
        threadApi->updateThread(
            threadId,
            std::vector<core::UserWithPubKey>{user(1)},
            std::vector<core::UserWithPubKey>{user(1)},
            core::Buffer::from("role_change"),
            core::Buffer::from("role_change_private"),
            updated.version,
            false,
            false,
            std::nullopt,
            std::vector<core::GroupGrantWithKey>{core::GroupGrantWithKey{
                .groupId = group_1.groupId,
                .role = "manager",
                .groupPubKey = group_1.groupPubKey
            }}
        );
    });
    EXPECT_NO_THROW({ updated = threadApi->getThread(threadId); });
    ASSERT_EQ(updated.groups.size(), 1);
    EXPECT_EQ(updated.groups[0].groupId, group_1.groupId);
    EXPECT_EQ(updated.groups[0].role, "manager");
}

TEST_F(ThreadUsingGroupsTest, updateThread_remove_group) {
    // Use Group_2 which has user_1 and user_2 as members, so we can verify
    // that user_2 loses access once the group grant is removed.
    group::Group group_2;
    ASSERT_NO_THROW({ group_2 = groupApi->getGroup(reader->getString("Group_2.groupId")); });
    ASSERT_EQ(group_2.statusCode, 0);

    // policy.get="all" so user_2 can always call getThread without throwing; after the group removal they get
    // statusCode!=0 and empty privateMeta instead, holding no decryption key.
    core::ContainerPolicy policy;
    policy.get = "all";

    // Create thread as user_1 with Group_2 grant (gives user_2 access via group)
    std::string threadId;
    EXPECT_NO_THROW({
        threadId = threadApi->createThread(
            reader->getString("Context_1.contextId"),
            std::vector<core::UserWithPubKey>{core::UserWithPubKey{
                .userId = reader->getString("Login.user_1_id"),
                .pubKey = reader->getString("Login.user_1_pubKey")
            }},
            std::vector<core::UserWithPubKey>{core::UserWithPubKey{
                .userId = reader->getString("Login.user_1_id"),
                .pubKey = reader->getString("Login.user_1_pubKey")
            }},
            core::Buffer::from("with_group"),
            core::Buffer::from("with_group_private"),
            policy,
            std::vector<core::GroupGrantWithKey>{core::GroupGrantWithKey{
                .groupId = group_2.groupId,
                .role = "user",
                .groupPubKey = group_2.groupPubKey
            }}
        );
    });
    ASSERT_FALSE(threadId.empty());

    thread::Thread t;
    EXPECT_NO_THROW({ t = threadApi->getThread(threadId); });
    EXPECT_EQ(t.groups.size(), 1);

    // Verify user_2 can decrypt the thread while the group grant is active
    disconnect();
    connectAs(2);
    thread::Thread beforeRemoval;
    EXPECT_NO_THROW({ beforeRemoval = threadApi->getThread(threadId); });
    EXPECT_EQ(beforeRemoval.statusCode, 0);
    EXPECT_FALSE(beforeRemoval.privateMeta.stdString().empty());

    // Switch back to user_1 and remove the group grant
    disconnect();
    connectAs(1);
    EXPECT_NO_THROW({
        threadApi->updateThread(
            threadId,
            std::vector<core::UserWithPubKey>{core::UserWithPubKey{
                .userId = reader->getString("Login.user_1_id"),
                .pubKey = reader->getString("Login.user_1_pubKey")
            }},
            std::vector<core::UserWithPubKey>{core::UserWithPubKey{
                .userId = reader->getString("Login.user_1_id"),
                .pubKey = reader->getString("Login.user_1_pubKey")
            }},
            core::Buffer::from("no_group_now"),
            core::Buffer::from("no_group_private"),
            1,
            false,
            false,
            std::nullopt,
            std::vector<core::GroupGrantWithKey>{}
        );
    });

    thread::Thread updated;
    EXPECT_NO_THROW({ updated = threadApi->getThread(threadId); });
    EXPECT_EQ(updated.statusCode, 0);
    EXPECT_EQ(updated.publicMeta.stdString(), "no_group_now");
    EXPECT_EQ(updated.groups.size(), 0);

    // user_2 can still download (get="all") but cannot decrypt - key was not shared
    disconnect();
    connectAs(2);
    thread::Thread afterRemoval;
    EXPECT_NO_THROW({ afterRemoval = threadApi->getThread(threadId); });
    EXPECT_NE(afterRemoval.statusCode, 0);
    EXPECT_TRUE(afterRemoval.privateMeta.stdString().empty());
}

TEST_F(ThreadUsingGroupsTest, listThreads_includes_groups_field) {
    group::Group group_1;
    ASSERT_NO_THROW({ group_1 = groupApi->getGroup(reader->getString("Group_1.groupId")); });
    ASSERT_EQ(group_1.statusCode, 0);

    std::string threadId;
    EXPECT_NO_THROW({
        threadId = threadApi->createThread(
            reader->getString("Context_1.contextId"),
            std::vector<core::UserWithPubKey>{core::UserWithPubKey{
                .userId = reader->getString("Login.user_1_id"),
                .pubKey = reader->getString("Login.user_1_pubKey")
            }},
            std::vector<core::UserWithPubKey>{core::UserWithPubKey{
                .userId = reader->getString("Login.user_1_id"),
                .pubKey = reader->getString("Login.user_1_pubKey")
            }},
            core::Buffer::from("listed_with_group"),
            core::Buffer::from("listed_with_group_private"),
            std::nullopt,
            std::vector<core::GroupGrantWithKey>{core::GroupGrantWithKey{
                .groupId = group_1.groupId,
                .role = "user",
                .groupPubKey = group_1.groupPubKey
            }}
        );
    });
    ASSERT_FALSE(threadId.empty());

    // Find our newly created thread in the list
    core::PagingList<thread::Thread> list;
    EXPECT_NO_THROW({
        list = threadApi->listThreads(
            reader->getString("Context_1.contextId"),
            core::PagingQuery{.skip = 0, .limit = 100, .sortOrder = "desc"}
        );
    });
    bool found = false;
    for (const auto& t : list.readItems) {
        if (t.threadId == threadId) {
            EXPECT_EQ(t.statusCode, 0);
            EXPECT_EQ(t.groups.size(), 1);
            if (t.groups.size() == 1) {
                EXPECT_EQ(t.groups[0].groupId, group_1.groupId);
                EXPECT_EQ(t.groups[0].role, "user");
            }
            found = true;
            break;
        }
    }
    EXPECT_TRUE(found);
}

TEST_F(ThreadUsingGroupsTest, reads_through_a_group_grant) {
    // Thread_4, Message_3 and Message_4 come from the dataset, so this reads bytes an earlier build wrote.
    // Thread_4 wraps its key to user_1 only and is granted to Group_4 (user_1, user_2) and Group_6 (all three):
    // user_2 arrives through two grants at one keyId, user_3 through one, and neither holds a direct wrap.
    const std::string privateMeta = privmx::utils::Hex::toString(reader->getString("Message_3.privateMeta_inHex"));
    const std::string data = privmx::utils::Hex::toString(reader->getString("Message_3.data_inHex"));

    for (const int index : {2, 3}) {
        disconnect();
        connectAs(index);

        thread::Thread t;
        EXPECT_NO_THROW({ t = threadApi->getThread(reader->getString("Thread_4.threadId")); })
            << "user_" << index << " could not open the thread";
        EXPECT_EQ(t.statusCode, 0);
        EXPECT_EQ(t.groups.size(), 2);

        thread::Message msg;
        EXPECT_NO_THROW({ msg = threadApi->getMessage(reader->getString("Message_3.info_messageId")); })
            << "user_" << index << " could not read the message";
        EXPECT_EQ(msg.statusCode, 0);
        EXPECT_EQ(msg.privateMeta.stdString(), privateMeta);
        EXPECT_EQ(msg.data.stdString(), data);

        // the paging path, which decrypts a batch rather than one row
        core::PagingList<thread::Message> list;
        EXPECT_NO_THROW({
            list = threadApi->listMessages(
                reader->getString("Thread_4.threadId"),
                core::PagingQuery{.skip = 0, .limit = 10, .sortOrder = "desc"}
            );
        });
        EXPECT_EQ(list.totalAvailable, 2);
        for (const auto& listed : list.readItems) {
            EXPECT_EQ(listed.statusCode, 0);
            EXPECT_FALSE(listed.privateMeta.stdString().empty());
            EXPECT_FALSE(listed.data.stdString().empty());
        }
    }
}

TEST_F(ThreadUsingGroupsTest, getMessage_lost_after_group_removal) {
    group::Group group_2;
    ASSERT_NO_THROW({ group_2 = groupApi->getGroup(reader->getString("Group_2.groupId")); });
    ASSERT_EQ(group_2.statusCode, 0);

    std::string threadId;
    ASSERT_NO_THROW({
        threadId = createThreadWithGroupPolicyReadAll(
            reader->getString("Context_1.contextId"),
            reader->getString("Login.user_1_id"),
            reader->getString("Login.user_1_pubKey"),
            group_2
        );
    });
    ASSERT_FALSE(threadId.empty());

    std::string messageId;
    ASSERT_NO_THROW({
        messageId = threadApi->sendMessage(
            threadId,
            core::Buffer::from("msg_public"),
            core::Buffer::from("secret_private"),
            core::Buffer::from("secret_data")
        );
    });
    ASSERT_FALSE(messageId.empty());

    // Verify user_2 can decrypt while group grant is active
    disconnect();
    connectAs(2);
    thread::Message beforeRemoval;
    EXPECT_NO_THROW({ beforeRemoval = threadApi->getMessage(messageId); });
    EXPECT_EQ(beforeRemoval.statusCode, 0);
    EXPECT_EQ(beforeRemoval.privateMeta.stdString(), "secret_private");

    // user_1 removes the group grant and generates a new key
    disconnect();
    connectAs(1);
    EXPECT_NO_THROW({
        threadApi->updateThread(
            threadId,
            std::vector<core::UserWithPubKey>{user(1)},
            std::vector<core::UserWithPubKey>{user(1)},
            core::Buffer::from("no_group"),
            core::Buffer::from("no_group_private"),
            1, false, false,
            std::nullopt,
            std::vector<core::GroupGrantWithKey>{}
        );
    });

    // user_1 sends a NEW message encrypted with the new key
    std::string newMessageId;
    ASSERT_NO_THROW({
        newMessageId = threadApi->sendMessage(
            threadId,
            core::Buffer::from("new_msg_public"),
            core::Buffer::from("new_msg_private"),
            core::Buffer::from("new_msg_data")
        );
    });

    // Historical group key entries are preserved for old key versions, so user_2
    // can still decrypt the old message that was created while the group had access.
    disconnect();
    connectAs(2);
    thread::Message afterRemoval;
    EXPECT_NO_THROW({ afterRemoval = threadApi->getMessage(messageId); });
    EXPECT_EQ(afterRemoval.statusCode, 0);
    EXPECT_EQ(afterRemoval.privateMeta.stdString(), "secret_private");

    // user_2 cannot decrypt the new message either (encrypted with new key they don't have)
    thread::Message newMsg;
    EXPECT_NO_THROW({ newMsg = threadApi->getMessage(newMessageId); });
    EXPECT_NE(newMsg.statusCode, 0);
    EXPECT_TRUE(newMsg.privateMeta.stdString().empty());
}

TEST_F(ThreadUsingGroupsTest, user_added_to_group_gains_access_to_thread_and_messages) {
    // Group_2 has user_1 + user_2; user_3 is not yet a member
    group::Group group_2;
    ASSERT_NO_THROW({ group_2 = groupApi->getGroup(reader->getString("Group_2.groupId")); });
    ASSERT_EQ(group_2.statusCode, 0);

    std::string threadId;
    ASSERT_NO_THROW({
        threadId = createThreadWithGroupPolicyReadAll(
            reader->getString("Context_1.contextId"),
            reader->getString("Login.user_1_id"),
            reader->getString("Login.user_1_pubKey"),
            group_2
        );
    });
    ASSERT_FALSE(threadId.empty());

    std::string messageId;
    ASSERT_NO_THROW({
        messageId = threadApi->sendMessage(
            threadId,
            core::Buffer::from("msg_pub"),
            core::Buffer::from("msg_priv"),
            core::Buffer::from("msg_data")
        );
    });
    ASSERT_FALSE(messageId.empty());

    // user_3 is not in Group_2 yet - can download (policy.get/item.get = "all") but not decrypt
    disconnect();
    connectAs(3);
    thread::Thread tBefore;
    EXPECT_NO_THROW({ tBefore = threadApi->getThread(threadId); });
    EXPECT_NE(tBefore.statusCode, 0);

    thread::Message mBefore;
    EXPECT_NO_THROW({ mBefore = threadApi->getMessage(messageId); });
    EXPECT_NE(mBefore.statusCode, 0);

    // user_1 adds user_3 to Group_2 via the tree-aware path, seating user_3's leaf in the key tree
    // (a metadata write would only re-wrap the group's own metadata key - it never touches tree leaf state)
    disconnect();
    connectAs(1);
    EXPECT_NO_THROW({
        groupApi->addGroupMembers(
            reader->getString("Group_2.groupId"),
            {group::GroupMemberToAdd{
                .user = core::UserWithPubKey{
                    .userId = reader->getString("Login.user_3_id"),
                    .pubKey = reader->getString("Login.user_3_pubKey")
                },
                .role = "user"
            }}
        );
    });

    // user_3 is now a Group_2 member - can decrypt the thread and the existing message
    disconnect();
    connectAs(3);
    thread::Thread tAfter;
    EXPECT_NO_THROW({ tAfter = threadApi->getThread(threadId); });
    EXPECT_EQ(tAfter.statusCode, 0);

    thread::Message mAfter;
    EXPECT_NO_THROW({ mAfter = threadApi->getMessage(messageId); });
    EXPECT_EQ(mAfter.statusCode, 0);
    EXPECT_EQ(mAfter.privateMeta.stdString(), "msg_priv");
    EXPECT_EQ(mAfter.data.stdString(), "msg_data");
}

TEST_F(ThreadUsingGroupsTest, message_from_previous_group_epoch_survives_forced_thread_rekey) {
    // Group G: user_1 (manager) + user_2 + user_3, at epoch 1.
    std::string groupId;
    ASSERT_NO_THROW({
        groupId = groupApi->createGroup(
            reader->getString("Context_1.contextId"),
            std::vector<core::UserWithPubKey>{
                {.userId = reader->getString("Login.user_1_id"), .pubKey = reader->getString("Login.user_1_pubKey")},
                {.userId = reader->getString("Login.user_2_id"), .pubKey = reader->getString("Login.user_2_pubKey")},
                {.userId = reader->getString("Login.user_3_id"), .pubKey = reader->getString("Login.user_3_pubKey")}
            },
            std::vector<core::UserWithPubKey>{
                {.userId = reader->getString("Login.user_1_id"), .pubKey = reader->getString("Login.user_1_pubKey")}
            },
            core::Buffer::from("grp_pub"),
            core::Buffer::from("grp_priv")
        );
    });
    ASSERT_FALSE(groupId.empty());

    group::Group group;
    ASSERT_NO_THROW({ group = groupApi->getGroup(groupId); });
    ASSERT_EQ(group.statusCode, 0);
    ASSERT_EQ(group.keyVersion, 1);

    // user_1 is T's only direct member, so user_2 reads only through the group grant: a personal key wrap would
    // let KeyProvider's flat-key path succeed and mask whatever the group-epoch path does.
    std::string threadId;
    ASSERT_NO_THROW({
        threadId = createThreadWithGroup(
            reader->getString("Context_1.contextId"),
            reader->getString("Login.user_1_id"),
            reader->getString("Login.user_1_pubKey"),
            group
        );
    });
    ASSERT_FALSE(threadId.empty());

    // Sent while G is still at epoch 1 - its keyId is wrapped for G's epoch-1 grant key only.
    std::string oldEpochMessageId;
    ASSERT_NO_THROW({
        oldEpochMessageId = threadApi->sendMessage(
            threadId,
            core::Buffer::from("old_epoch_pub"),
            core::Buffer::from("old_epoch_priv"),
            core::Buffer::from("old_epoch_data")
        );
    });
    ASSERT_FALSE(oldEpochMessageId.empty());

    // Remove user_3 from G - advances G's epoch from 1 to 2. Thread T itself is untouched by this.
    ASSERT_NO_THROW({
        groupApi->removeGroupMembers(groupId, {reader->getString("Login.user_3_id")});
    });

    group::Group rotatedGroup;
    ASSERT_NO_THROW({ rotatedGroup = groupApi->getGroup(groupId); });
    ASSERT_EQ(rotatedGroup.statusCode, 0);
    ASSERT_EQ(rotatedGroup.keyVersion, 2);

    // Rotate T's key while re-granting G at epoch 2. T's groupKeys[G] must keep the epoch-1 wrap resolvable
    // alongside the epoch-2 one; a single scalar epoch per entry would ask for the wrong grant key below.
    ASSERT_NO_THROW({
        threadApi->updateThread(
            threadId,
            std::vector<core::UserWithPubKey>{
                {.userId = reader->getString("Login.user_1_id"), .pubKey = reader->getString("Login.user_1_pubKey")}
            },
            std::vector<core::UserWithPubKey>{
                {.userId = reader->getString("Login.user_1_id"), .pubKey = reader->getString("Login.user_1_pubKey")}
            },
            core::Buffer::from("rekeyed_public"),
            core::Buffer::from("rekeyed_private"),
            1,     // version
            false, // force
            true,  // forceGenerateNewKey
            std::nullopt,
            std::vector<core::GroupGrantWithKey>{{
                .groupId = groupId,
                .role = "user",
                .groupPubKey = rotatedGroup.groupPubKey,
                .groupEpoch = rotatedGroup.keyVersion
            }}
        );
    });

    // Positive control: a message sent after the rekey, under the new epoch, must also be readable.
    std::string newEpochMessageId;
    ASSERT_NO_THROW({
        newEpochMessageId = threadApi->sendMessage(
            threadId,
            core::Buffer::from("new_epoch_pub"),
            core::Buffer::from("new_epoch_priv"),
            core::Buffer::from("new_epoch_data")
        );
    });
    ASSERT_FALSE(newEpochMessageId.empty());

    // user_2 has no personal key wrap on T, and a freshly connected client has an empty ContainerKeyCache - so
    // the first cache-touching call below resolves everything straight from the server's current state.
    disconnect();
    connectAs(2);

    thread::Message oldEpochMessage;
    EXPECT_NO_THROW({ oldEpochMessage = threadApi->getMessage(oldEpochMessageId); });
    EXPECT_EQ(oldEpochMessage.statusCode, 0);
    EXPECT_EQ(oldEpochMessage.privateMeta.stdString(), "old_epoch_priv");
    EXPECT_EQ(oldEpochMessage.data.stdString(), "old_epoch_data");

    thread::Message newEpochMessage;
    EXPECT_NO_THROW({ newEpochMessage = threadApi->getMessage(newEpochMessageId); });
    EXPECT_EQ(newEpochMessage.statusCode, 0);
    EXPECT_EQ(newEpochMessage.privateMeta.stdString(), "new_epoch_priv");
    EXPECT_EQ(newEpochMessage.data.stdString(), "new_epoch_data");
}

TEST_F(ThreadUsingGroupsTest, sendMessage_retries_with_refreshed_key_after_thread_rotation) {
    // user_2 sends under the stale keyId it cached; the bridge answers INVALID_THREAD_KEY and `withKeyRefresh`
    // fetches the new one and retries, so the send succeeds without the caller doing anything.

    // Create a dynamic group containing user_1 and user_2.
    std::string groupId;
    ASSERT_NO_THROW({
        groupId = groupApi->createGroup(
            reader->getString("Context_1.contextId"),
            std::vector<core::UserWithPubKey>{
                {.userId = reader->getString("Login.user_1_id"), .pubKey = reader->getString("Login.user_1_pubKey")},
                {.userId = reader->getString("Login.user_2_id"), .pubKey = reader->getString("Login.user_2_pubKey")}
            },
            std::vector<core::UserWithPubKey>{
                {.userId = reader->getString("Login.user_1_id"), .pubKey = reader->getString("Login.user_1_pubKey")}
            },
            core::Buffer::from("grp_pub"),
            core::Buffer::from("grp_priv")
        );
    });
    ASSERT_FALSE(groupId.empty());

    group::Group dynGroup;
    ASSERT_NO_THROW({ dynGroup = groupApi->getGroup(groupId); });
    ASSERT_EQ(dynGroup.statusCode, 0);

    // Create a thread with user_1=manager, user_2=user, plus group grant.
    // user_2 is a direct thread user so sendMessage is allowed on their connection.
    core::ContainerPolicy policy;
    policy.get = "all";
    policy.item = core::ItemPolicy{.get = "all", .listAll = "all"};
    std::string threadId;
    ASSERT_NO_THROW({
        threadId = threadApi->createThread(
            reader->getString("Context_1.contextId"),
            std::vector<core::UserWithPubKey>{
                {.userId = reader->getString("Login.user_1_id"), .pubKey = reader->getString("Login.user_1_pubKey")},
                {.userId = reader->getString("Login.user_2_id"), .pubKey = reader->getString("Login.user_2_pubKey")}
            },
            std::vector<core::UserWithPubKey>{
                {.userId = reader->getString("Login.user_1_id"), .pubKey = reader->getString("Login.user_1_pubKey")}
            },
            core::Buffer::from("thread_pub"),
            core::Buffer::from("thread_priv"),
            policy,
            std::vector<core::GroupGrantWithKey>{{
                .groupId = groupId,
                .role = "user",
                .groupPubKey = dynGroup.groupPubKey
            }}
        );
    });
    ASSERT_FALSE(threadId.empty());

    // Open a SECOND connection as user_2 (kept alive throughout the test).
    // Fetching the thread populates user_2's key cache with the current keyId K1.
    auto conn2 = std::make_shared<core::Connection>(
        core::Connection::connect(
            reader->getString("Login.user_2_privKey"),
            reader->getString("Login.solutionId"),
            getPlatformUrl(reader->getString("Login.instanceUrl"))
        )
    );
    auto grpApi2 = std::make_shared<group::GroupApi>(group::GroupApi::create(*conn2));
    auto threadApi2 = std::make_shared<thread::ThreadApi>(
        thread::ThreadApi::create(*conn2, *grpApi2)
    );
    thread::Thread cachedThread;
    ASSERT_NO_THROW({ cachedThread = threadApi2->getThread(threadId); });
    ASSERT_EQ(cachedThread.statusCode, 0);

    // user_1 (main connection) rotates the thread key → server advances to keyId K2.
    // user_2's conn2 still holds K1 in its cache.
    thread::Thread threadInfo;
    ASSERT_NO_THROW({ threadInfo = threadApi->getThread(threadId); });
    ASSERT_EQ(threadInfo.statusCode, 0);
    EXPECT_NO_THROW({
        threadApi->rotateThreadKeys(
            threadId,
            std::vector<core::UserWithPubKey>{
                {.userId = reader->getString("Login.user_1_id"), .pubKey = reader->getString("Login.user_1_pubKey")},
                {.userId = reader->getString("Login.user_2_id"), .pubKey = reader->getString("Login.user_2_pubKey")}
            },
            std::vector<core::UserWithPubKey>{
                {.userId = reader->getString("Login.user_1_id"), .pubKey = reader->getString("Login.user_1_pubKey")}
            },
            threadInfo.version,
            false,
            std::vector<core::GroupGrantWithKey>{{
                .groupId = groupId,
                .role = "user",
                .groupPubKey = dynGroup.groupPubKey
            }}
        );
    });

    // user_2 (threadApi2) sends a message with stale keyId K1.
    // Bridge returns INVALID_THREAD_KEY; withKeyRefresh fetches K2 and retries → success.
    std::string msgId;
    EXPECT_NO_THROW({
        msgId = threadApi2->sendMessage(
            threadId,
            core::Buffer::from("msg_pub"),
            core::Buffer::from("msg_priv"),
            core::Buffer::from("msg_data")
        );
    });
    EXPECT_FALSE(msgId.empty());

    conn2->disconnect();
}

TEST_F(ThreadUsingGroupsTest, direct_member_of_granted_group_reads_and_updates) {
    // Every keyId opens from `keys`, so the group branch is skipped. `updateThread` is the interesting half:
    // `verifyKeysSecret` fails on any non-zero status, so an unresolved group entry throws instead of updating.
    group::Group group_1;
    ASSERT_NO_THROW({ group_1 = groupApi->getGroup(reader->getString("Group_1.groupId")); });
    ASSERT_EQ(group_1.statusCode, 0);

    std::string threadId;
    ASSERT_NO_THROW({
        threadId = createThreadWithGroups(
            reader->getString("Context_1.contextId"),
            std::vector<core::UserWithPubKey>{user(1)},
            std::vector<group::Group>{group_1}
        );
    });
    ASSERT_FALSE(threadId.empty());

    std::string messageId;
    ASSERT_NO_THROW({
        messageId = threadApi->sendMessage(
            threadId,
            core::Buffer::from("direct_public"),
            core::Buffer::from("direct_private"),
            core::Buffer::from("direct_data")
        );
    });
    ASSERT_FALSE(messageId.empty());

    thread::Thread t;
    EXPECT_NO_THROW({ t = threadApi->getThread(threadId); });
    EXPECT_EQ(t.statusCode, 0);
    EXPECT_EQ(t.groups.size(), 1);

    thread::Message msg;
    EXPECT_NO_THROW({ msg = threadApi->getMessage(messageId); });
    EXPECT_EQ(msg.statusCode, 0);
    EXPECT_EQ(msg.data.stdString(), "direct_data");

    core::PagingList<thread::Message> list;
    EXPECT_NO_THROW({
        list = threadApi->listMessages(threadId, core::PagingQuery{.skip = 0, .limit = 10, .sortOrder = "desc"});
    });
    EXPECT_EQ(list.totalAvailable, 1);
    ASSERT_EQ(list.readItems.size(), 1);
    EXPECT_EQ(list.readItems[0].statusCode, 0);

    EXPECT_NO_THROW({
        threadApi->updateThread(
            threadId,
            std::vector<core::UserWithPubKey>{user(1)},
            std::vector<core::UserWithPubKey>{user(1)},
            core::Buffer::from("direct_updated_public"),
            core::Buffer::from("direct_updated_private"),
            t.version,
            false,
            false,
            std::nullopt,
            std::vector<core::GroupGrantWithKey>{{
                .groupId = group_1.groupId, .role = "user", .groupPubKey = group_1.groupPubKey
            }}
        );
    });

    thread::Thread updated;
    EXPECT_NO_THROW({ updated = threadApi->getThread(threadId); });
    EXPECT_EQ(updated.statusCode, 0);
    EXPECT_EQ(updated.privateMeta.stdString(), "direct_updated_private");
}

TEST_F(ThreadUsingGroupsTest, caller_in_no_granted_group_reads_via_direct_key) {
    // user_2 is a direct member of Thread_6 and is in no grantee group - Group_7 holds user_1 alone - so the
    // bridge serves it `groupKeys: []` and the read has to come entirely from its own key wrap.
    disconnect();
    connectAs(2);

    thread::Thread t;
    EXPECT_NO_THROW({ t = threadApi->getThread(reader->getString("Thread_6.threadId")); });
    EXPECT_EQ(t.statusCode, 0);
    // `groups` stays unnarrowed, so user_2 still sees the grant it is not part of.
    EXPECT_EQ(t.groups.size(), 1);

    thread::Message msg;
    EXPECT_NO_THROW({ msg = threadApi->getMessage(reader->getString("Message_6.info_messageId")); });
    EXPECT_EQ(msg.statusCode, 0);
    EXPECT_EQ(
        msg.privateMeta.stdString(), privmx::utils::Hex::toString(reader->getString("Message_6.privateMeta_inHex"))
    );
    EXPECT_EQ(msg.data.stdString(), privmx::utils::Hex::toString(reader->getString("Message_6.data_inHex")));
}

TEST_F(ThreadUsingGroupsTest, group_only_member_still_reads_after_container_rekey) {
    // user_3's `keys` is empty on T, so both keyIds - the original and the one the forced rekey mints - go down
    // the group route. Two keyIds under one grant is where a filter keyed by keyId alone drops the wrong half.
    group::Group group_3;
    ASSERT_NO_THROW({ group_3 = groupApi->getGroup(reader->getString("Group_3.groupId")); });
    ASSERT_EQ(group_3.statusCode, 0);

    std::string threadId;
    ASSERT_NO_THROW({
        threadId = createThreadWithGroups(
            reader->getString("Context_1.contextId"),
            std::vector<core::UserWithPubKey>{user(1)},
            std::vector<group::Group>{group_3}
        );
    });
    ASSERT_FALSE(threadId.empty());

    std::string firstKeyMessageId;
    ASSERT_NO_THROW({
        firstKeyMessageId = threadApi->sendMessage(
            threadId,
            core::Buffer::from("first_key_public"),
            core::Buffer::from("first_key_private"),
            core::Buffer::from("first_key_data")
        );
    });
    ASSERT_FALSE(firstKeyMessageId.empty());

    thread::Thread beforeRekey;
    ASSERT_NO_THROW({ beforeRekey = threadApi->getThread(threadId); });
    ASSERT_EQ(beforeRekey.statusCode, 0);

    ASSERT_NO_THROW({
        threadApi->updateThread(
            threadId,
            std::vector<core::UserWithPubKey>{user(1)},
            std::vector<core::UserWithPubKey>{user(1)},
            core::Buffer::from("rekeyed_public"),
            core::Buffer::from("rekeyed_private"),
            beforeRekey.version,
            false,
            true, // forceGenerateNewKey
            std::nullopt,
            std::vector<core::GroupGrantWithKey>{{
                .groupId = group_3.groupId, .role = "user", .groupPubKey = group_3.groupPubKey
            }}
        );
    });

    std::string secondKeyMessageId;
    ASSERT_NO_THROW({
        secondKeyMessageId = threadApi->sendMessage(
            threadId,
            core::Buffer::from("second_key_public"),
            core::Buffer::from("second_key_private"),
            core::Buffer::from("second_key_data")
        );
    });
    ASSERT_FALSE(secondKeyMessageId.empty());

    disconnect();
    connectAs(3);

    thread::Message firstKeyMessage;
    EXPECT_NO_THROW({ firstKeyMessage = threadApi->getMessage(firstKeyMessageId); });
    EXPECT_EQ(firstKeyMessage.statusCode, 0);
    EXPECT_EQ(firstKeyMessage.data.stdString(), "first_key_data");

    thread::Message secondKeyMessage;
    EXPECT_NO_THROW({ secondKeyMessage = threadApi->getMessage(secondKeyMessageId); });
    EXPECT_EQ(secondKeyMessage.statusCode, 0);
    EXPECT_EQ(secondKeyMessage.data.stdString(), "second_key_data");

    core::PagingList<thread::Message> list;
    EXPECT_NO_THROW({
        list = threadApi->listMessages(threadId, core::PagingQuery{.skip = 0, .limit = 10, .sortOrder = "desc"});
    });
    EXPECT_EQ(list.totalAvailable, 2);
    for (const auto& msg : list.readItems) {
        EXPECT_EQ(msg.statusCode, 0);
        EXPECT_FALSE(msg.data.stdString().empty());
    }
}

TEST_F(ThreadUsingGroupsTest, user_role_grantee_permissions) {
    // What the weaker of the two grant roles buys, on one thread. `item.create` is "user" and every grant
    // splices the caller into `users`, so writing new items is already allowed; `update` and `delete` are
    // "manager", which a "user" grant never reaches, and `item.update` is met only by `itemOwner&user`.
    group::Group group_2;
    ASSERT_NO_THROW({ group_2 = groupApi->getGroup(reader->getString("Group_2.groupId")); });
    ASSERT_EQ(group_2.statusCode, 0);

    std::string threadId;
    ASSERT_NO_THROW({
        threadId = createThreadWithGroups(
            reader->getString("Context_1.contextId"),
            std::vector<core::UserWithPubKey>{user(1)},
            std::vector<group::Group>{group_2},
            "user"
        );
    });
    ASSERT_FALSE(threadId.empty());

    // written by user_1, so user_2 does not own it
    std::string othersMessageId;
    ASSERT_NO_THROW({
        othersMessageId = threadApi->sendMessage(
            threadId,
            core::Buffer::from("owner_public"),
            core::Buffer::from("owner_private"),
            core::Buffer::from("owner_data")
        );
    });
    ASSERT_FALSE(othersMessageId.empty());

    disconnect();
    connectAs(2);

    // Positive control: the group route yields the container key, so every rejection below is a policy check
    // and not a failure to open the thread.
    thread::Thread t;
    ASSERT_NO_THROW({ t = threadApi->getThread(threadId); });
    ASSERT_EQ(t.statusCode, 0);
    thread::Message readable;
    ASSERT_NO_THROW({ readable = threadApi->getMessage(othersMessageId); });
    ASSERT_EQ(readable.statusCode, 0);

    // may write its own item
    std::string messageId;
    EXPECT_NO_THROW({
        messageId = threadApi->sendMessage(
            threadId,
            core::Buffer::from("grantee_public"),
            core::Buffer::from("grantee_private"),
            core::Buffer::from("grantee_data")
        );
    });
    ASSERT_FALSE(messageId.empty());
    thread::Message msg;
    EXPECT_NO_THROW({ msg = threadApi->getMessage(messageId); });
    EXPECT_EQ(msg.statusCode, 0);
    EXPECT_EQ(msg.data.stdString(), "grantee_data");
    EXPECT_EQ(msg.info.author, reader->getString("Login.user_2_id"));

    // may not edit somebody else's
    EXPECT_THROW({
        threadApi->updateMessage(
            othersMessageId,
            core::Buffer::from("edited_public"),
            core::Buffer::from("edited_private"),
            core::Buffer::from("edited_data")
        );
    }, server::AccessDeniedException);

    // may not touch the container itself
    EXPECT_THROW({
        threadApi->updateThread(
            threadId,
            std::vector<core::UserWithPubKey>{user(1)},
            std::vector<core::UserWithPubKey>{user(1)},
            core::Buffer::from("denied_public"),
            core::Buffer::from("denied_private"),
            t.version,
            false,
            false,
            std::nullopt,
            std::vector<core::GroupGrantWithKey>{{
                .groupId = group_2.groupId, .role = "user", .groupPubKey = group_2.groupPubKey
            }}
        );
    }, privmx::endpoint::server::AccessDeniedException);

    // and may not destroy it - last, because it would end the test either way
    EXPECT_THROW({ threadApi->deleteThread(threadId); }, server::AccessDeniedException);
    thread::Thread survived;
    EXPECT_NO_THROW({ survived = threadApi->getThread(threadId); });
    EXPECT_EQ(survived.statusCode, 0);
}

TEST_F(ThreadUsingGroupsTest, manager_role_grantee_permissions) {
    // The same thread under the stronger role. `item.update` is "itemOwner&user,manager", so the second
    // alternative is met through the grant alone; `update` needs the grantee to name itself a direct manager,
    // because `updaterIsRemovedFromManagersAndItIsForbidden` compares the submitted `managers` against the
    // group-aware copy the grant put user_2 into; `delete` is guarded by the policy atom alone.
    group::Group group_2;
    ASSERT_NO_THROW({ group_2 = groupApi->getGroup(reader->getString("Group_2.groupId")); });
    ASSERT_EQ(group_2.statusCode, 0);

    std::string threadId;
    ASSERT_NO_THROW({
        threadId = createThreadWithGroups(
            reader->getString("Context_1.contextId"),
            std::vector<core::UserWithPubKey>{user(1)},
            std::vector<group::Group>{group_2},
            "manager"
        );
    });
    ASSERT_FALSE(threadId.empty());

    // written by user_1, so user_2 does not own it
    std::string othersMessageId;
    ASSERT_NO_THROW({
        othersMessageId = threadApi->sendMessage(
            threadId,
            core::Buffer::from("owner_public"),
            core::Buffer::from("owner_private"),
            core::Buffer::from("owner_data")
        );
    });
    ASSERT_FALSE(othersMessageId.empty());

    disconnect();
    connectAs(2);

    thread::Thread t;
    ASSERT_NO_THROW({ t = threadApi->getThread(threadId); });
    ASSERT_EQ(t.statusCode, 0);
    // user_2 holds no direct membership - everything it can do here, it does through the grant.
    ASSERT_EQ(std::count(t.managers.begin(), t.managers.end(), reader->getString("Login.user_2_id")), 0);
    ASSERT_EQ(std::count(t.users.begin(), t.users.end(), reader->getString("Login.user_2_id")), 0);

    // may edit an item it did not write
    EXPECT_NO_THROW({
        threadApi->updateMessage(
            othersMessageId,
            core::Buffer::from("edited_public"),
            core::Buffer::from("edited_private"),
            core::Buffer::from("edited_data")
        );
    });
    thread::Message edited;
    EXPECT_NO_THROW({ edited = threadApi->getMessage(othersMessageId); });
    EXPECT_EQ(edited.statusCode, 0);
    EXPECT_EQ(edited.data.stdString(), "edited_data");

    const std::vector<core::GroupGrantWithKey> grant{{
        .groupId = group_2.groupId, .role = "manager", .groupPubKey = group_2.groupPubKey
    }};

    EXPECT_THROW({
        threadApi->updateThread(
            threadId,
            std::vector<core::UserWithPubKey>{user(1)},
            std::vector<core::UserWithPubKey>{user(1)},
            core::Buffer::from("trap_public"),
            core::Buffer::from("trap_private"),
            t.version,
            false,
            false,
            std::nullopt,
            grant
        );
    }, server::AccessDeniedException);

    // Same call, same version - the refusal above left the thread untouched - but now naming user_2 as a
    // manager of the container itself.
    EXPECT_NO_THROW({
        threadApi->updateThread(
            threadId,
            std::vector<core::UserWithPubKey>{user(1)},
            std::vector<core::UserWithPubKey>{
                user(1), user(2)
            },
            core::Buffer::from("promoted_public"),
            core::Buffer::from("promoted_private"),
            t.version,
            false,
            false,
            std::nullopt,
            grant
        );
    });

    thread::Thread updated;
    EXPECT_NO_THROW({ updated = threadApi->getThread(threadId); });
    EXPECT_EQ(updated.statusCode, 0);
    EXPECT_EQ(updated.privateMeta.stdString(), "promoted_private");
    EXPECT_EQ(std::count(updated.managers.begin(), updated.managers.end(), reader->getString("Login.user_2_id")), 1);

    // and may destroy it - last, because nothing else can run afterwards
    EXPECT_NO_THROW({ threadApi->deleteThread(threadId); });
    EXPECT_THROW({ threadApi->getThread(threadId); }, server::ThreadDoesNotExistException);
}

TEST_F(ThreadUsingGroupsTest, group_manager_role_does_not_grant_container_manager_role) {
    // `getGroupsOfUser` matches `users` OR `managers` and returns a bare list of ids, so the grant's own role is
    // all the policy engine sees. Needs a group user_2 actually manages, hence the dynamic one.
    std::string groupId;
    ASSERT_NO_THROW({
        groupId = groupApi->createGroup(
            reader->getString("Context_1.contextId"),
            std::vector<core::UserWithPubKey>{
                user(1), user(2)
            },
            std::vector<core::UserWithPubKey>{
                user(1), user(2)
            },
            core::Buffer::from("mgr_group_pub"),
            core::Buffer::from("mgr_group_priv")
        );
    });
    ASSERT_FALSE(groupId.empty());

    group::Group managedGroup;
    ASSERT_NO_THROW({ managedGroup = groupApi->getGroup(groupId); });
    ASSERT_EQ(managedGroup.statusCode, 0);
    ASSERT_EQ(std::count(
        managedGroup.managers.begin(), managedGroup.managers.end(), reader->getString("Login.user_2_id")
    ), 1);

    std::string threadId;
    ASSERT_NO_THROW({
        threadId = createThreadWithGroups(
            reader->getString("Context_1.contextId"),
            std::vector<core::UserWithPubKey>{user(1)},
            std::vector<group::Group>{managedGroup},
            "user"
        );
    });
    ASSERT_FALSE(threadId.empty());

    disconnect();
    connectAs(2);

    thread::Thread t;
    ASSERT_NO_THROW({ t = threadApi->getThread(threadId); });
    ASSERT_EQ(t.statusCode, 0);

    // Container-user rights: yes.
    EXPECT_NO_THROW({
        threadApi->sendMessage(
            threadId,
            core::Buffer::from("grp_mgr_public"),
            core::Buffer::from("grp_mgr_private"),
            core::Buffer::from("grp_mgr_data")
        );
    });

    // Container-manager rights: no, despite managing the granted group.
    EXPECT_THROW({
        threadApi->updateThread(
            threadId,
            std::vector<core::UserWithPubKey>{user(1)},
            std::vector<core::UserWithPubKey>{user(1)},
            core::Buffer::from("grp_mgr_denied_public"),
            core::Buffer::from("grp_mgr_denied_private"),
            t.version,
            false,
            false,
            std::nullopt,
            std::vector<core::GroupGrantWithKey>{{
                .groupId = managedGroup.groupId, .role = "user", .groupPubKey = managedGroup.groupPubKey
            }}
        );
    }, server::AccessDeniedException);
    EXPECT_THROW({ threadApi->deleteThread(threadId); }, server::AccessDeniedException);
}

TEST_F(ThreadUsingGroupsTest, rotateThreadKeys_covers_a_grantee_group_the_caller_did_not_name) {
    // The caller passes no `groups`, so the grantee list has to come from `thread.groups`. The caller must be in
    // G: the default group policy hands a group's epoch and public key to members only, and a re-key needs both.
    disconnect();
    connectAs(2);

    std::string groupId;
    ASSERT_NO_THROW({
        groupId = groupApi->createGroup(
            reader->getString("Context_1.contextId"),
            std::vector<core::UserWithPubKey>{
                user(1), user(2),
                user(3)
            },
            std::vector<core::UserWithPubKey>{user(2)},
            core::Buffer::from("grantee_group_pub"),
            core::Buffer::from("grantee_group_priv")
        );
    });
    ASSERT_FALSE(groupId.empty());

    group::Group granteeGroup;
    ASSERT_NO_THROW({ granteeGroup = groupApi->getGroup(groupId); });
    ASSERT_EQ(granteeGroup.statusCode, 0);

    // user_1 is a direct member - enough to re-key under the default `rotateKeys: "user"`.
    std::string threadId;
    ASSERT_NO_THROW({
        threadId = threadApi->createThread(
            reader->getString("Context_1.contextId"),
            std::vector<core::UserWithPubKey>{
                user(1), user(2)
            },
            std::vector<core::UserWithPubKey>{user(2)},
            core::Buffer::from("foreign_grant_public"),
            core::Buffer::from("foreign_grant_private"),
            core::ContainerPolicy(),
            std::vector<core::GroupGrantWithKey>{{
                .groupId = granteeGroup.groupId, .role = "user", .groupPubKey = granteeGroup.groupPubKey
            }}
        );
    });
    ASSERT_FALSE(threadId.empty());

    std::string beforeRotationMessageId;
    ASSERT_NO_THROW({
        beforeRotationMessageId = threadApi->sendMessage(
            threadId,
            core::Buffer::from("before_rotation_public"),
            core::Buffer::from("before_rotation_private"),
            core::Buffer::from("before_rotation_data")
        );
    });
    ASSERT_FALSE(beforeRotationMessageId.empty());

    disconnect();
    connectAs(1);

    thread::Thread t;
    ASSERT_NO_THROW({ t = threadApi->getThread(threadId); });
    ASSERT_EQ(t.statusCode, 0);
    // The grant is there to be read off the thread - which is exactly where the re-key has to get it from.
    ASSERT_EQ(t.groups.size(), 1);
    ASSERT_EQ(t.groups[0].groupId, granteeGroup.groupId);
    EXPECT_TRUE(t.staleGroups.empty());

    // No `groups` argument at all - the whole point is that the caller does not have to supply one.
    EXPECT_NO_THROW({
        threadApi->rotateThreadKeys(
            threadId,
            std::vector<core::UserWithPubKey>{
                user(1), user(2)
            },
            std::vector<core::UserWithPubKey>{user(2)},
            t.version,
            false
        );
    });

    std::string afterRotationMessageId;
    ASSERT_NO_THROW({
        afterRotationMessageId = threadApi->sendMessage(
            threadId,
            core::Buffer::from("after_rotation_public"),
            core::Buffer::from("after_rotation_private"),
            core::Buffer::from("after_rotation_data")
        );
    });
    ASSERT_FALSE(afterRotationMessageId.empty());

    // user_3 reads only through G, so this is what proves the new key really was wrapped to G: it holds no
    // direct key entry on T at either keyId.
    disconnect();
    connectAs(3);

    thread::Message beforeRotation;
    EXPECT_NO_THROW({ beforeRotation = threadApi->getMessage(beforeRotationMessageId); });
    EXPECT_EQ(beforeRotation.statusCode, 0);
    EXPECT_EQ(beforeRotation.data.stdString(), "before_rotation_data");

    thread::Message afterRotation;
    EXPECT_NO_THROW({ afterRotation = threadApi->getMessage(afterRotationMessageId); });
    EXPECT_EQ(afterRotation.statusCode, 0);
    EXPECT_EQ(afterRotation.data.stdString(), "after_rotation_data");
}

TEST_F(ThreadUsingGroupsTest, rotateThreadKeys_clears_staleGroups_after_the_group_advances_its_epoch) {
    // `staleGroups` is the bridge's answer to "does this thread need re-keying", computed over every grant and
    // not over the entries the caller can decrypt. The re-key closes the gap without being told which epoch.
    std::string groupId;
    ASSERT_NO_THROW({
        groupId = groupApi->createGroup(
            reader->getString("Context_1.contextId"),
            std::vector<core::UserWithPubKey>{
                user(1), user(2),
                user(3)
            },
            std::vector<core::UserWithPubKey>{user(1)},
            core::Buffer::from("stale_group_pub"),
            core::Buffer::from("stale_group_priv")
        );
    });
    ASSERT_FALSE(groupId.empty());

    group::Group sharedGroup;
    ASSERT_NO_THROW({ sharedGroup = groupApi->getGroup(groupId); });
    ASSERT_EQ(sharedGroup.statusCode, 0);
    ASSERT_EQ(sharedGroup.keyVersion, 1);

    std::string threadId;
    ASSERT_NO_THROW({
        threadId = createThreadWithGroups(
            reader->getString("Context_1.contextId"),
            std::vector<core::UserWithPubKey>{user(1)},
            std::vector<group::Group>{sharedGroup}
        );
    });
    ASSERT_FALSE(threadId.empty());

    ASSERT_NO_THROW({
        groupApi->removeGroupMembers(groupId, {reader->getString("Login.user_3_id")});
    });

    thread::Thread stale;
    ASSERT_NO_THROW({ stale = threadApi->getThread(threadId); });
    ASSERT_EQ(stale.statusCode, 0);
    ASSERT_EQ(stale.staleGroups.size(), 1);
    EXPECT_EQ(stale.staleGroups[0], groupId);

    // Again with no `groups`: the current epoch and its public key are read from the group itself.
    EXPECT_NO_THROW({
        threadApi->rotateThreadKeys(
            threadId,
            std::vector<core::UserWithPubKey>{user(1)},
            std::vector<core::UserWithPubKey>{user(1)},
            stale.version,
            false
        );
    });

    thread::Thread rekeyed;
    ASSERT_NO_THROW({ rekeyed = threadApi->getThread(threadId); });
    EXPECT_EQ(rekeyed.statusCode, 0);
    EXPECT_TRUE(rekeyed.staleGroups.empty());

    std::string messageId;
    ASSERT_NO_THROW({
        messageId = threadApi->sendMessage(
            threadId,
            core::Buffer::from("post_rekey_public"),
            core::Buffer::from("post_rekey_private"),
            core::Buffer::from("post_rekey_data")
        );
    });

    // user_2 is still in G at its new epoch and holds no direct entry on T.
    disconnect();
    connectAs(2);

    thread::Message message;
    EXPECT_NO_THROW({ message = threadApi->getMessage(messageId); });
    EXPECT_EQ(message.statusCode, 0);
    EXPECT_EQ(message.data.stdString(), "post_rekey_data");
}

TEST_F(ThreadUsingGroupsTest, sendMessage_auto_rotates_a_stale_thread_key) {
    // The same setup as the test above, minus the rotateThreadKeys call: noticing a stale key is not the
    // caller's job. sendMessage sees it, re-keys T with T's own roster, and sends under the new key.
    std::string groupId;
    ASSERT_NO_THROW({
        groupId = groupApi->createGroup(
            reader->getString("Context_1.contextId"),
            std::vector<core::UserWithPubKey>{
                user(1), user(2),
                user(3)
            },
            std::vector<core::UserWithPubKey>{user(1)},
            core::Buffer::from("auto_rotate_group_pub"),
            core::Buffer::from("auto_rotate_group_priv")
        );
    });
    ASSERT_FALSE(groupId.empty());

    group::Group sharedGroup;
    ASSERT_NO_THROW({ sharedGroup = groupApi->getGroup(groupId); });
    ASSERT_EQ(sharedGroup.statusCode, 0);

    std::string threadId;
    ASSERT_NO_THROW({
        threadId = createThreadWithGroups(
            reader->getString("Context_1.contextId"),
            std::vector<core::UserWithPubKey>{user(1)},
            std::vector<group::Group>{sharedGroup}
        );
    });
    ASSERT_FALSE(threadId.empty());

    ASSERT_NO_THROW({
        groupApi->removeGroupMembers(groupId, {reader->getString("Login.user_3_id")});
    });

    thread::Thread stale;
    ASSERT_NO_THROW({ stale = threadApi->getThread(threadId); });
    ASSERT_EQ(stale.statusCode, 0);
    ASSERT_EQ(stale.staleGroups.size(), 1);
    ASSERT_EQ(stale.staleGroups[0], groupId);

    std::string messageId;
    EXPECT_NO_THROW({
        messageId = threadApi->sendMessage(
            threadId,
            core::Buffer::from("auto_rotated_public"),
            core::Buffer::from("auto_rotated_private"),
            core::Buffer::from("auto_rotated_data")
        );
    });

    thread::Thread rekeyed;
    ASSERT_NO_THROW({ rekeyed = threadApi->getThread(threadId); });
    EXPECT_EQ(rekeyed.statusCode, 0);
    EXPECT_TRUE(rekeyed.staleGroups.empty());
    // Exactly one re-key: a rotation appends one history entry and nothing else wrote to T.
    EXPECT_EQ(rekeyed.version, stale.version + 1);
    // The roster a re-key may not touch.
    EXPECT_EQ(rekeyed.users, stale.users);
    EXPECT_EQ(rekeyed.managers, stale.managers);

    // user_2 is in G at its new epoch and holds no direct entry on T: reading the message proves the new key
    // was wrapped to the epoch G actually moved to, not to the one T was stuck on.
    disconnect();
    connectAs(2);

    thread::Message message;
    EXPECT_NO_THROW({ message = threadApi->getMessage(messageId); });
    EXPECT_EQ(message.statusCode, 0);
    EXPECT_EQ(message.data.stdString(), "auto_rotated_data");
}

TEST_F(ThreadUsingGroupsTest, auto_rotation_does_not_repeat_a_re_key_another_client_already_did) {
    // Two clients hold T at the same stale key; the second must send under the winner's key instead of re-keying
    // on top of it. The endpoint gets there by re-reading T before it rotates.
    std::string groupId;
    ASSERT_NO_THROW({
        groupId = groupApi->createGroup(
            reader->getString("Context_1.contextId"),
            std::vector<core::UserWithPubKey>{
                user(1), user(2),
                user(3)
            },
            std::vector<core::UserWithPubKey>{user(1)},
            core::Buffer::from("concurrent_group_pub"),
            core::Buffer::from("concurrent_group_priv")
        );
    });
    ASSERT_FALSE(groupId.empty());

    group::Group sharedGroup;
    ASSERT_NO_THROW({ sharedGroup = groupApi->getGroup(groupId); });
    ASSERT_EQ(sharedGroup.statusCode, 0);

    // Both users are direct members and managers of T, so either of them may send and either may re-key.
    std::string threadId;
    ASSERT_NO_THROW({
        threadId = createThreadWithGroups(
            reader->getString("Context_1.contextId"),
            std::vector<core::UserWithPubKey>{
                user(1), user(2)
            },
            std::vector<group::Group>{sharedGroup}
        );
    });
    ASSERT_FALSE(threadId.empty());

    ASSERT_NO_THROW({
        groupApi->removeGroupMembers(groupId, {reader->getString("Login.user_3_id")});
    });

    // A second, independent connection as user_2, kept alive throughout.
    auto conn2 = std::make_shared<core::Connection>(
        core::Connection::connect(
            reader->getString("Login.user_2_privKey"),
            reader->getString("Login.solutionId"),
            getPlatformUrl(reader->getString("Login.instanceUrl"))
        )
    );
    auto grpApi2 = std::make_shared<group::GroupApi>(group::GroupApi::create(*conn2));
    auto threadApi2 = std::make_shared<thread::ThreadApi>(thread::ThreadApi::create(*conn2, *grpApi2));

    // Both connections read T while it is stale, so both cache a snapshot that says "needs a re-key".
    thread::Thread stale1, stale2;
    ASSERT_NO_THROW({ stale1 = threadApi->getThread(threadId); });
    ASSERT_NO_THROW({ stale2 = threadApi2->getThread(threadId); });
    ASSERT_EQ(stale1.staleGroups.size(), 1);
    ASSERT_EQ(stale2.staleGroups.size(), 1);
    ASSERT_EQ(stale1.version, stale2.version);

    // user_1 wins: its send re-keys T.
    ASSERT_NO_THROW({
        threadApi->sendMessage(
            threadId,
            core::Buffer::from("winner_public"),
            core::Buffer::from("winner_private"),
            core::Buffer::from("winner_data")
        );
    });

    // user_2 still believes T is stale. Its send must succeed without a second re-key.
    std::string loserMessageId;
    EXPECT_NO_THROW({
        loserMessageId = threadApi2->sendMessage(
            threadId,
            core::Buffer::from("loser_public"),
            core::Buffer::from("loser_private"),
            core::Buffer::from("loser_data")
        );
    });

    thread::Thread after;
    ASSERT_NO_THROW({ after = threadApi->getThread(threadId); });
    EXPECT_EQ(after.statusCode, 0);
    EXPECT_TRUE(after.staleGroups.empty());
    // One re-key, not two.
    EXPECT_EQ(after.version, stale1.version + 1);
    // And it was user_1's: `keeper` is set to whoever rotated.
    ASSERT_TRUE(after.keeper.has_value());
    EXPECT_EQ(after.keeper.value(), reader->getString("Login.user_1_id"));

    thread::Message loserMessage;
    EXPECT_NO_THROW({ loserMessage = threadApi->getMessage(loserMessageId); });
    EXPECT_EQ(loserMessage.statusCode, 0);
    EXPECT_EQ(loserMessage.data.stdString(), "loser_data");

    conn2->disconnect();
}

TEST_F(ThreadUsingGroupsTest, sendMessage_still_reports_a_stale_key_when_the_re_key_is_denied) {
    // Auto-rotation is not a way around the rotateKeys policy: a member who may write but may not re-key gets
    // StaleKeyRekeyRequiredException, not an access error for a call they never made.
    std::string groupId;
    ASSERT_NO_THROW({
        groupId = groupApi->createGroup(
            reader->getString("Context_1.contextId"),
            std::vector<core::UserWithPubKey>{
                user(1), user(2),
                user(3)
            },
            std::vector<core::UserWithPubKey>{user(1)},
            core::Buffer::from("denied_group_pub"),
            core::Buffer::from("denied_group_priv")
        );
    });
    ASSERT_FALSE(groupId.empty());

    group::Group sharedGroup;
    ASSERT_NO_THROW({ sharedGroup = groupApi->getGroup(groupId); });
    ASSERT_EQ(sharedGroup.statusCode, 0);

    // user_2 is a user of T but not a manager, and T only lets managers re-key.
    core::ContainerPolicy policy;
    policy.rotateKeys = "manager";
    std::string threadId;
    ASSERT_NO_THROW({
        threadId = threadApi->createThread(
            reader->getString("Context_1.contextId"),
            std::vector<core::UserWithPubKey>{
                user(1), user(2)
            },
            std::vector<core::UserWithPubKey>{user(1)},
            core::Buffer::from("denied_thread_public"),
            core::Buffer::from("denied_thread_private"),
            policy,
            std::vector<core::GroupGrantWithKey>{
                {.groupId = groupId, .role = "user", .groupPubKey = sharedGroup.groupPubKey}
            }
        );
    });
    ASSERT_FALSE(threadId.empty());

    ASSERT_NO_THROW({
        groupApi->removeGroupMembers(groupId, {reader->getString("Login.user_3_id")});
    });

    thread::Thread stale;
    ASSERT_NO_THROW({ stale = threadApi->getThread(threadId); });
    ASSERT_EQ(stale.staleGroups.size(), 1);

    disconnect();
    connectAs(2);

    EXPECT_THROW(
        {
            threadApi->sendMessage(
                threadId,
                core::Buffer::from("denied_public"),
                core::Buffer::from("denied_private"),
                core::Buffer::from("denied_data")
            );
        },
        core::StaleKeyRekeyRequiredException
    );

    // Nothing was re-keyed on the way to that exception.
    thread::Thread untouched;
    ASSERT_NO_THROW({ untouched = threadApi->getThread(threadId); });
    EXPECT_EQ(untouched.version, stale.version);
    EXPECT_EQ(untouched.staleGroups.size(), 1);
}
