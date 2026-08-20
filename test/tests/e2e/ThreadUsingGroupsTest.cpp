#include <gtest/gtest.h>
#include <algorithm>
#include "../../utils/BaseTest.hpp"
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
#include <privmx/endpoint/core/CoreException.hpp>
#include <privmx/endpoint/core/ConvertedExceptions.hpp>
using namespace privmx::endpoint;

enum TUGConnectionType {
    TUGUser1,
    TUGUser2,
    TUGUser3
};

class ThreadUsingGroupsTest : public privmx::test::BaseTest {
protected:
    ThreadUsingGroupsTest() : BaseTest(privmx::test::BaseTestMode::online) {}
    void connectAs(TUGConnectionType type) {
        std::string privKey;
        if (type == TUGConnectionType::TUGUser1) {
            privKey = reader->getString("Login.user_1_privKey");
        } else if (type == TUGConnectionType::TUGUser2) {
            privKey = reader->getString("Login.user_2_privKey");
        } else {
            privKey = reader->getString("Login.user_3_privKey");
        }
        connection = std::make_shared<core::Connection>(
            core::Connection::connect(
                privKey,
                reader->getString("Login.solutionId"),
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
        connection = std::make_shared<core::Connection>(
            core::Connection::connect(
                reader->getString("Login.user_1_privKey"),
                reader->getString("Login.solutionId"),
                getPlatformUrl(reader->getString("Login.instanceUrl"))
            )
        );
        groupApi = std::make_shared<group::GroupApi>(group::GroupApi::create(*connection));
        threadApi = std::make_shared<thread::ThreadApi>(thread::ThreadApi::create(*connection, *groupApi));
    }
    void customTearDown() override {
        connection.reset();
        threadApi.reset();
        groupApi.reset();
        reader.reset();
        core::EventQueueImpl::getInstance()->clear();
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

    /**
     * Creates a thread with an arbitrary direct-member list, any number of group grants, and one grant role
     * shared by all of them.
     *
     * The two helpers above always wrap the key to exactly one direct member and grant exactly one group as
     * `"user"`, which is the one shape neither the narrowed-`groupKeys` tests nor the grant-role tests can use:
     * between them they vary how many grantee groups the *reader* belongs to, whether it also holds a direct
     * wrap, and which role the grant carries.
     */
    std::string createThreadWithGroups(
        const std::string& contextId,
        const std::vector<core::UserWithPubKey>& members,
        const std::vector<group::Group>& groups,
        const std::string& role = "user"
    ) {
        std::vector<core::GroupGrantWithKey> grants;
        for (const auto& g : groups) {
            grants.push_back(
                core::GroupGrantWithKey{.groupId = g.groupId, .role = role, .groupPubKey = g.groupPubKey}
            );
        }
        return threadApi->createThread(
            contextId,
            members,
            std::vector<core::UserWithPubKey>{members.front()},
            core::Buffer::from("group_thread_public"),
            core::Buffer::from("group_thread_private"),
            core::ContainerPolicy(),
            grants
        );
    }
    core::UserWithPubKey userOf(TUGConnectionType type) {
        if (type == TUGConnectionType::TUGUser1) {
            return {
                .userId = reader->getString("Login.user_1_id"), .pubKey = reader->getString("Login.user_1_pubKey")
            };
        } else if (type == TUGConnectionType::TUGUser2) {
            return {
                .userId = reader->getString("Login.user_2_id"), .pubKey = reader->getString("Login.user_2_pubKey")
            };
        }
        return {.userId = reader->getString("Login.user_3_id"), .pubKey = reader->getString("Login.user_3_pubKey")};
    }

    std::shared_ptr<core::Connection> connection;
    std::shared_ptr<thread::ThreadApi> threadApi;
    std::shared_ptr<group::GroupApi> groupApi;
    Poco::Util::IniFileConfiguration::Ptr reader;
    core::VarSerializer _serializer = core::VarSerializer({});
};

TEST_F(ThreadUsingGroupsTest, createThread_with_group_grants) {
    // Fetch groupPubKey of the pre-created Group_1 (user_1 only)
    group::Group group_1;
    ASSERT_NO_THROW({
        group_1 = groupApi->getGroup(reader->getString("Group_1.groupId"));
    });
    ASSERT_EQ(group_1.statusCode, 0);
    ASSERT_FALSE(group_1.groupPubKey.empty());

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
            core::Buffer::from("public_meta"),
            core::Buffer::from("private_meta"),
            std::nullopt,
            std::vector<core::GroupGrantWithKey>{core::GroupGrantWithKey{
                .groupId = group_1.groupId,
                .role = "user",
                .groupPubKey = group_1.groupPubKey
            }}
        );
    });
    ASSERT_FALSE(threadId.empty());

    thread::Thread t;
    EXPECT_NO_THROW({
        t = threadApi->getThread(threadId);
    });
    EXPECT_EQ(t.statusCode, 0);
    EXPECT_EQ(t.publicMeta.stdString(), "public_meta");
    EXPECT_EQ(t.groups.size(), 1);
    if (t.groups.size() == 1) {
        EXPECT_EQ(t.groups[0].groupId, group_1.groupId);
        EXPECT_EQ(t.groups[0].role, "user");
    }
}

TEST_F(ThreadUsingGroupsTest, createThread_with_multiple_group_grants) {
    // Fetch both pre-created groups
    group::Group group_1, group_2;
    ASSERT_NO_THROW({ group_1 = groupApi->getGroup(reader->getString("Group_1.groupId")); });
    ASSERT_NO_THROW({ group_2 = groupApi->getGroup(reader->getString("Group_2.groupId")); });
    ASSERT_EQ(group_1.statusCode, 0);
    ASSERT_EQ(group_2.statusCode, 0);

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

    thread::Thread t;
    EXPECT_NO_THROW({ t = threadApi->getThread(threadId); });
    EXPECT_EQ(t.statusCode, 0);
    EXPECT_EQ(t.groups.size(), 2);
    // Verify both group IDs appear in the groups list
    bool found1 = false, found2 = false;
    for (const auto& g : t.groups) {
        if (g.groupId == group_1.groupId && g.role == "user") found1 = true;
        if (g.groupId == group_2.groupId && g.role == "manager") found2 = true;
    }
    EXPECT_TRUE(found1);
    EXPECT_TRUE(found2);
}

TEST_F(ThreadUsingGroupsTest, createThread_without_groups_has_empty_groups_field) {
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
            core::Buffer::from("no_groups_public"),
            core::Buffer::from("no_groups_private")
        );
    });
    ASSERT_FALSE(threadId.empty());

    thread::Thread t;
    EXPECT_NO_THROW({ t = threadApi->getThread(threadId); });
    EXPECT_EQ(t.statusCode, 0);
    EXPECT_EQ(t.groups.size(), 0);
}

TEST_F(ThreadUsingGroupsTest, updateThread_add_group) {
    // Create thread without groups
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
            core::Buffer::from("before_group"),
            core::Buffer::from("before_group_private")
        );
    });
    ASSERT_FALSE(threadId.empty());

    thread::Thread t;
    EXPECT_NO_THROW({ t = threadApi->getThread(threadId); });
    EXPECT_EQ(t.groups.size(), 0);

    // Fetch Group_1 pubKey for grant
    group::Group group_1;
    ASSERT_NO_THROW({ group_1 = groupApi->getGroup(reader->getString("Group_1.groupId")); });
    ASSERT_EQ(group_1.statusCode, 0);

    // Update to add the group
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
    EXPECT_EQ(updated.groups.size(), 1);
    if (updated.groups.size() == 1) {
        EXPECT_EQ(updated.groups[0].groupId, group_1.groupId);
        EXPECT_EQ(updated.groups[0].role, "user");
    }
}

TEST_F(ThreadUsingGroupsTest, updateThread_remove_group) {
    // Use Group_2 which has user_1 and user_2 as members, so we can verify
    // that user_2 loses access once the group grant is removed.
    group::Group group_2;
    ASSERT_NO_THROW({ group_2 = groupApi->getGroup(reader->getString("Group_2.groupId")); });
    ASSERT_EQ(group_2.statusCode, 0);

    // policy.get="all" so user_2 can always call getThread without throwing;
    // after group removal they receive statusCode!=0 and empty privateMeta
    // because they no longer hold the decryption key.
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
    connectAs(TUGConnectionType::TUGUser2);
    thread::Thread beforeRemoval;
    EXPECT_NO_THROW({ beforeRemoval = threadApi->getThread(threadId); });
    EXPECT_EQ(beforeRemoval.statusCode, 0);
    EXPECT_FALSE(beforeRemoval.privateMeta.stdString().empty());

    // Switch back to user_1 and remove the group grant
    disconnect();
    connectAs(TUGConnectionType::TUGUser1);
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

    // user_2 can still download (get="all") but cannot decrypt — key was not shared
    disconnect();
    connectAs(TUGConnectionType::TUGUser2);
    thread::Thread afterRemoval;
    EXPECT_NO_THROW({ afterRemoval = threadApi->getThread(threadId); });
    EXPECT_NE(afterRemoval.statusCode, 0);
    EXPECT_TRUE(afterRemoval.privateMeta.stdString().empty());
}

TEST_F(ThreadUsingGroupsTest, updateThread_change_group_role) {
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
            core::Buffer::from("role_change"),
            core::Buffer::from("role_change_private"),
            std::nullopt,
            std::vector<core::GroupGrantWithKey>{core::GroupGrantWithKey{
                .groupId = group_1.groupId,
                .role = "user",
                .groupPubKey = group_1.groupPubKey
            }}
        );
    });
    ASSERT_FALSE(threadId.empty());

    // Promote group from "user" to "manager"
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
            core::Buffer::from("role_change"),
            core::Buffer::from("role_change_private"),
            1,
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

    thread::Thread updated;
    EXPECT_NO_THROW({ updated = threadApi->getThread(threadId); });
    EXPECT_EQ(updated.groups.size(), 1);
    if (updated.groups.size() == 1) {
        EXPECT_EQ(updated.groups[0].groupId, group_1.groupId);
        EXPECT_EQ(updated.groups[0].role, "manager");
    }
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

TEST_F(ThreadUsingGroupsTest, createThread_with_invalid_group_pubkey_throws) {
    EXPECT_THROW({
        threadApi->createThread(
            reader->getString("Context_1.contextId"),
            std::vector<core::UserWithPubKey>{core::UserWithPubKey{
                .userId = reader->getString("Login.user_1_id"),
                .pubKey = reader->getString("Login.user_1_pubKey")
            }},
            std::vector<core::UserWithPubKey>{core::UserWithPubKey{
                .userId = reader->getString("Login.user_1_id"),
                .pubKey = reader->getString("Login.user_1_pubKey")
            }},
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

TEST_F(ThreadUsingGroupsTest, getMessage_via_group_grant) {
    // user_1 creates thread with Group_2 grant; user_2 is a Group_2 member
    group::Group group_2;
    ASSERT_NO_THROW({ group_2 = groupApi->getGroup(reader->getString("Group_2.groupId")); });
    ASSERT_EQ(group_2.statusCode, 0);

    std::string threadId;
    ASSERT_NO_THROW({
        threadId = createThreadWithGroup(
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
            core::Buffer::from("msg_private"),
            core::Buffer::from("msg_data")
        );
    });
    ASSERT_FALSE(messageId.empty());

    // user_2 can download and decrypt the message via group key
    disconnect();
    connectAs(TUGConnectionType::TUGUser2);
    thread::Message msg;
    EXPECT_NO_THROW({ msg = threadApi->getMessage(messageId); });
    EXPECT_EQ(msg.statusCode, 0);
    EXPECT_EQ(msg.privateMeta.stdString(), "msg_private");
    EXPECT_EQ(msg.data.stdString(), "msg_data");
}

TEST_F(ThreadUsingGroupsTest, listMessages_via_group_grant) {
    group::Group group_2;
    ASSERT_NO_THROW({ group_2 = groupApi->getGroup(reader->getString("Group_2.groupId")); });
    ASSERT_EQ(group_2.statusCode, 0);

    std::string threadId;
    ASSERT_NO_THROW({
        threadId = createThreadWithGroup(
            reader->getString("Context_1.contextId"),
            reader->getString("Login.user_1_id"),
            reader->getString("Login.user_1_pubKey"),
            group_2
        );
    });
    ASSERT_FALSE(threadId.empty());

    ASSERT_NO_THROW({ threadApi->sendMessage(threadId, core::Buffer::from("pub1"), core::Buffer::from("priv1"), core::Buffer::from("data1")); });
    ASSERT_NO_THROW({ threadApi->sendMessage(threadId, core::Buffer::from("pub2"), core::Buffer::from("priv2"), core::Buffer::from("data2")); });

    // user_2 can list and decrypt messages via group key
    disconnect();
    connectAs(TUGConnectionType::TUGUser2);
    core::PagingList<thread::Message> list;
    EXPECT_NO_THROW({
        list = threadApi->listMessages(
            threadId,
            core::PagingQuery{.skip = 0, .limit = 10, .sortOrder = "desc"}
        );
    });
    EXPECT_EQ(list.totalAvailable, 2);
    for (const auto& msg : list.readItems) {
        EXPECT_EQ(msg.statusCode, 0);
        EXPECT_FALSE(msg.privateMeta.stdString().empty());
        EXPECT_FALSE(msg.data.stdString().empty());
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
    connectAs(TUGConnectionType::TUGUser2);
    thread::Message beforeRemoval;
    EXPECT_NO_THROW({ beforeRemoval = threadApi->getMessage(messageId); });
    EXPECT_EQ(beforeRemoval.statusCode, 0);
    EXPECT_EQ(beforeRemoval.privateMeta.stdString(), "secret_private");

    // user_1 removes the group grant and generates a new key
    disconnect();
    connectAs(TUGConnectionType::TUGUser1);
    EXPECT_NO_THROW({
        threadApi->updateThread(
            threadId,
            std::vector<core::UserWithPubKey>{{.userId = reader->getString("Login.user_1_id"), .pubKey = reader->getString("Login.user_1_pubKey")}},
            std::vector<core::UserWithPubKey>{{.userId = reader->getString("Login.user_1_id"), .pubKey = reader->getString("Login.user_1_pubKey")}},
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
    connectAs(TUGConnectionType::TUGUser2);
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

TEST_F(ThreadUsingGroupsTest, messages_accessible_by_all_group_members) {
    // Group_3 has user_1, user_2, user_3 as members (pre-created in dataset)
    group::Group group_3;
    ASSERT_NO_THROW({ group_3 = groupApi->getGroup(reader->getString("Group_3.groupId")); });
    ASSERT_EQ(group_3.statusCode, 0);

    std::string threadId;
    ASSERT_NO_THROW({
        threadId = createThreadWithGroup(
            reader->getString("Context_1.contextId"),
            reader->getString("Login.user_1_id"),
            reader->getString("Login.user_1_pubKey"),
            group_3
        );
    });
    ASSERT_FALSE(threadId.empty());

    std::string messageId;
    ASSERT_NO_THROW({
        messageId = threadApi->sendMessage(
            threadId,
            core::Buffer::from("shared_public"),
            core::Buffer::from("shared_private"),
            core::Buffer::from("shared_data")
        );
    });
    ASSERT_FALSE(messageId.empty());

    // user_2 (Group_3 member) can decrypt
    disconnect();
    connectAs(TUGConnectionType::TUGUser2);
    thread::Message msgUser2;
    EXPECT_NO_THROW({ msgUser2 = threadApi->getMessage(messageId); });
    EXPECT_EQ(msgUser2.statusCode, 0);
    EXPECT_EQ(msgUser2.privateMeta.stdString(), "shared_private");
    EXPECT_EQ(msgUser2.data.stdString(), "shared_data");

    // user_3 (Group_3 member) can decrypt
    disconnect();
    connectAs(TUGConnectionType::TUGUser3);
    thread::Message msgUser3;
    EXPECT_NO_THROW({ msgUser3 = threadApi->getMessage(messageId); });
    EXPECT_EQ(msgUser3.statusCode, 0);
    EXPECT_EQ(msgUser3.privateMeta.stdString(), "shared_private");
    EXPECT_EQ(msgUser3.data.stdString(), "shared_data");
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

    // user_3 is not in Group_2 yet — can download (policy.get/item.get = "all") but not decrypt
    disconnect();
    connectAs(TUGConnectionType::TUGUser3);
    thread::Thread tBefore;
    EXPECT_NO_THROW({ tBefore = threadApi->getThread(threadId); });
    EXPECT_NE(tBefore.statusCode, 0);

    thread::Message mBefore;
    EXPECT_NO_THROW({ mBefore = threadApi->getMessage(messageId); });
    EXPECT_NE(mBefore.statusCode, 0);

    // user_1 adds user_3 to Group_2 via the tree-aware path, seating user_3's leaf in the key tree
    // (updateGroup would only re-wrap the group's own metadata key — it never touches tree leaf state)
    disconnect();
    connectAs(TUGConnectionType::TUGUser1);
    EXPECT_NO_THROW({
        groupApi->addGroupMember(
            reader->getString("Group_2.groupId"),
            core::UserWithPubKey{
                .userId = reader->getString("Login.user_3_id"), .pubKey = reader->getString("Login.user_3_pubKey")
            },
            false, // asManager
            std::vector<core::UserWithPubKey>{
                {.userId = reader->getString("Login.user_1_id"), .pubKey = reader->getString("Login.user_1_pubKey")},
                {.userId = reader->getString("Login.user_2_id"), .pubKey = reader->getString("Login.user_2_pubKey")},
                {.userId = reader->getString("Login.user_3_id"), .pubKey = reader->getString("Login.user_3_pubKey")}
            },
            std::vector<core::UserWithPubKey>{
                {.userId = reader->getString("Login.user_1_id"), .pubKey = reader->getString("Login.user_1_pubKey")}
            },
            group_2.publicMeta,
            group_2.privateMeta
        );
    });

    // user_3 is now a Group_2 member — can decrypt the thread and the existing message
    disconnect();
    connectAs(TUGConnectionType::TUGUser3);
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
        groupId = groupApi->createGroupWithKeyTree(
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

    // Thread T grants G access; user_1 is the only direct member — user_2's access to it is
    // exclusively through the group grant (no personal key wrap), which matters below: a direct
    // wrap would let KeyProvider's flat-key path succeed and mask whatever the group-epoch path does.
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

    // Sent while G is still at epoch 1 — its keyId is wrapped for G's epoch-1 grant key only.
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

    // Remove user_3 from G — advances G's epoch from 1 to 2. Thread T itself is untouched by this.
    ASSERT_NO_THROW({
        groupApi->removeGroupMember(
            groupId,
            reader->getString("Login.user_3_id"),
            std::vector<core::UserWithPubKey>{
                {.userId = reader->getString("Login.user_1_id"), .pubKey = reader->getString("Login.user_1_pubKey")},
                {.userId = reader->getString("Login.user_2_id"), .pubKey = reader->getString("Login.user_2_pubKey")}
            },
            std::vector<core::UserWithPubKey>{
                {.userId = reader->getString("Login.user_1_id"), .pubKey = reader->getString("Login.user_1_pubKey")}
            },
            core::Buffer::from("grp_removed_pub"),
            core::Buffer::from("grp_removed_priv")
        );
    });

    group::Group rotatedGroup;
    ASSERT_NO_THROW({ rotatedGroup = groupApi->getGroup(groupId); });
    ASSERT_EQ(rotatedGroup.statusCode, 0);
    ASSERT_EQ(rotatedGroup.keyVersion, 2);

    // Force T's own container key to rotate while re-granting G at its now-current epoch (2).
    // T's stored groupKeys[G] entry must keep the epoch-1 wrap resolvable at epoch 1 for
    // oldEpochMessageId, alongside the new epoch-2 wrap — this is exactly the case the Epoch
    // Ladder exists to cover ("historical group key entries stay reachable across a group's own
    // epoch advances"). If groupKeys[G]'s epoch is instead tracked as one scalar for the whole
    // entry and gets overwritten to 2 here, decrypting oldEpochMessageId below fails (statusCode
    // 65553, UnknownEncryptionKeyVersionException) because the wrong grant key gets requested for it.
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

    // user_2 has never been a direct member of T, so this read cannot be served by a personal key
    // wrap, and this is a freshly connected client, so ContainerKeyCache is empty — the very first
    // cache-touching call below must resolve everything straight from the server's current state.
    disconnect();
    connectAs(TUGConnectionType::TUGUser2);

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
    // Scenario: user_2 caches thread keyId K1 via getThread. user_1 then calls
    // rotateThreadKeys → server advances to keyId K2. user_2's sendMessage sends
    // with stale K1; bridge returns INVALID_THREAD_KEY; withKeyRefresh fetches K2
    // and retries transparently → message succeeds.

    // Create a dynamic group containing user_1 and user_2.
    std::string groupId;
    ASSERT_NO_THROW({
        groupId = groupApi->createGroupWithKeyTree(
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

// ─────────────────────────────────────────────────────────────────────────────────────────────────────────────
// EP-22 — `groupKeys` is served narrowed to the caller's own groups
//
// The endpoint change these guard is a cost one: `KeyProvider::getKeysAndVerify` no longer resolves a group
// key entry whose keyId the caller's own `keys` already opened, because the merge that follows discarded that
// result anyway. So none of these can observe the dropped round trips — what they cover is that the filter
// short-circuits exactly the paths it is meant to and none of the ones it is not: a caller holding a direct
// wrap, a caller holding none, a caller in several grantee groups at once.
// ─────────────────────────────────────────────────────────────────────────────────────────────────────────────

TEST_F(ThreadUsingGroupsTest, direct_member_of_granted_group_reads_and_updates) {
    // user_1 is both the only direct member of T and a member of granted Group_1, so every keyId opens from
    // `keys` and the group branch is skipped for all of it. `updateThread` is the interesting half: it runs
    // `verifyKeysSecret` over every key it decrypted, and that check fails on any entry with a non-zero status
    // — so a group entry left unresolved there is the difference between an update and
    // EncryptionKeyValidationException.
    group::Group group_1;
    ASSERT_NO_THROW({ group_1 = groupApi->getGroup(reader->getString("Group_1.groupId")); });
    ASSERT_EQ(group_1.statusCode, 0);

    std::string threadId;
    ASSERT_NO_THROW({
        threadId = createThreadWithGroups(
            reader->getString("Context_1.contextId"),
            std::vector<core::UserWithPubKey>{userOf(TUGConnectionType::TUGUser1)},
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
            std::vector<core::UserWithPubKey>{userOf(TUGConnectionType::TUGUser1)},
            std::vector<core::UserWithPubKey>{userOf(TUGConnectionType::TUGUser1)},
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
    // T grants Group_1, whose only member is user_1. user_2 is a direct member of T and belongs to no grantee
    // group, so the bridge serves it `groupKeys: []` — there is no group route to take, and the read has to be
    // served entirely from its own key wrap.
    group::Group group_1;
    ASSERT_NO_THROW({ group_1 = groupApi->getGroup(reader->getString("Group_1.groupId")); });
    ASSERT_EQ(group_1.statusCode, 0);

    std::string threadId;
    ASSERT_NO_THROW({
        threadId = createThreadWithGroups(
            reader->getString("Context_1.contextId"),
            std::vector<core::UserWithPubKey>{
                userOf(TUGConnectionType::TUGUser1), userOf(TUGConnectionType::TUGUser2)
            },
            std::vector<group::Group>{group_1}
        );
    });
    ASSERT_FALSE(threadId.empty());

    std::string messageId;
    ASSERT_NO_THROW({
        messageId = threadApi->sendMessage(
            threadId,
            core::Buffer::from("nogroup_public"),
            core::Buffer::from("nogroup_private"),
            core::Buffer::from("nogroup_data")
        );
    });
    ASSERT_FALSE(messageId.empty());

    disconnect();
    connectAs(TUGConnectionType::TUGUser2);

    thread::Thread t;
    EXPECT_NO_THROW({ t = threadApi->getThread(threadId); });
    EXPECT_EQ(t.statusCode, 0);
    // `groups` stays unnarrowed, so user_2 still sees the grant it is not part of.
    EXPECT_EQ(t.groups.size(), 1);

    thread::Message msg;
    EXPECT_NO_THROW({ msg = threadApi->getMessage(messageId); });
    EXPECT_EQ(msg.statusCode, 0);
    EXPECT_EQ(msg.privateMeta.stdString(), "nogroup_private");
    EXPECT_EQ(msg.data.stdString(), "nogroup_data");
}

TEST_F(ThreadUsingGroupsTest, caller_in_two_granted_groups_reads) {
    // T grants Group_2 and Group_3 and wraps its key to user_1 only. user_2 belongs to both grantee groups, so
    // narrowing leaves it two entries at the same keyId — with no direct wrap to fall back on, one of them has
    // to carry the read.
    group::Group group_2, group_3;
    ASSERT_NO_THROW({ group_2 = groupApi->getGroup(reader->getString("Group_2.groupId")); });
    ASSERT_NO_THROW({ group_3 = groupApi->getGroup(reader->getString("Group_3.groupId")); });
    ASSERT_EQ(group_2.statusCode, 0);
    ASSERT_EQ(group_3.statusCode, 0);

    std::string threadId;
    ASSERT_NO_THROW({
        threadId = createThreadWithGroups(
            reader->getString("Context_1.contextId"),
            std::vector<core::UserWithPubKey>{userOf(TUGConnectionType::TUGUser1)},
            std::vector<group::Group>{group_2, group_3}
        );
    });
    ASSERT_FALSE(threadId.empty());

    std::string messageId;
    ASSERT_NO_THROW({
        messageId = threadApi->sendMessage(
            threadId,
            core::Buffer::from("twogroups_public"),
            core::Buffer::from("twogroups_private"),
            core::Buffer::from("twogroups_data")
        );
    });
    ASSERT_FALSE(messageId.empty());

    disconnect();
    connectAs(TUGConnectionType::TUGUser2);

    thread::Thread t;
    EXPECT_NO_THROW({ t = threadApi->getThread(threadId); });
    EXPECT_EQ(t.statusCode, 0);
    EXPECT_EQ(t.groups.size(), 2);

    thread::Message msg;
    EXPECT_NO_THROW({ msg = threadApi->getMessage(messageId); });
    EXPECT_EQ(msg.statusCode, 0);
    EXPECT_EQ(msg.privateMeta.stdString(), "twogroups_private");
    EXPECT_EQ(msg.data.stdString(), "twogroups_data");
}

TEST_F(ThreadUsingGroupsTest, group_only_member_still_reads_after_container_rekey) {
    // The negative control for the filter: user_3's `keys` is empty on T, so every keyId — both the original
    // and the one the forced rekey mints — must still go down the group route. Two keyIds under one grant is
    // also the case where a filter keyed by keyId alone could drop the wrong half.
    group::Group group_3;
    ASSERT_NO_THROW({ group_3 = groupApi->getGroup(reader->getString("Group_3.groupId")); });
    ASSERT_EQ(group_3.statusCode, 0);

    std::string threadId;
    ASSERT_NO_THROW({
        threadId = createThreadWithGroups(
            reader->getString("Context_1.contextId"),
            std::vector<core::UserWithPubKey>{userOf(TUGConnectionType::TUGUser1)},
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
            std::vector<core::UserWithPubKey>{userOf(TUGConnectionType::TUGUser1)},
            std::vector<core::UserWithPubKey>{userOf(TUGConnectionType::TUGUser1)},
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
    connectAs(TUGConnectionType::TUGUser3);

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

// ─────────────────────────────────────────────────────────────────────────────────────────────────────────────
// Grant role (`GroupGrantWithKey::role`) — what "user" vs "manager" actually buys
//
// The whole mechanism is one function on the bridge: `BaseContainerService.withGroupMembership` copies the
// container with the caller spliced into `users` for any grant, and into `managers` only for a `"manager"` one,
// then hands that copy to the unchanged policy engine. Two consequences these tests pin down:
//
//   1. The caller's role *inside* the group is irrelevant. `getCallerGroupIds` -> `getGroupsOfUser` matches
//      `users` OR `managers`, so only the grant's role counts. Group_2 in the dataset is {users: user_1,
//      user_2 / managers: user_1}, so user_2 is a plain *user* of it — every "manager grant" test below has it
//      exercising container-manager rights it holds through the grant alone.
//   2. `"manager"` is not uniform across operations. Paths guarded only by a policy atom (delete container,
//      update someone else's item, rotate keys) accept it; `threadUpdate` additionally runs
//      `makeUpdateContainerCheck`, which does not.
//
// Defaults these read against (`DefaultContextPolicy.thread`): get/item.get/item.listAll = "user",
// item.create = "user", item.update = item.delete = "itemOwner&user,manager", update = delete = "manager".
// ─────────────────────────────────────────────────────────────────────────────────────────────────────────────

TEST_F(ThreadUsingGroupsTest, user_role_grantee_can_send_message) {
    // `item.create` is "user" and every grant splices the caller into `users`, so the weaker of the two roles
    // is already enough to write new items — no manager grant, no direct membership.
    group::Group group_2;
    ASSERT_NO_THROW({ group_2 = groupApi->getGroup(reader->getString("Group_2.groupId")); });
    ASSERT_EQ(group_2.statusCode, 0);

    std::string threadId;
    ASSERT_NO_THROW({
        threadId = createThreadWithGroups(
            reader->getString("Context_1.contextId"),
            std::vector<core::UserWithPubKey>{userOf(TUGConnectionType::TUGUser1)},
            std::vector<group::Group>{group_2},
            "user"
        );
    });
    ASSERT_FALSE(threadId.empty());

    disconnect();
    connectAs(TUGConnectionType::TUGUser2);

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
}

TEST_F(ThreadUsingGroupsTest, user_role_grantee_cannot_update_thread) {
    // `update` is "manager", and a "user" grant never reaches `managers` — so the same grantee that can write
    // items cannot touch the container itself.
    group::Group group_2;
    ASSERT_NO_THROW({ group_2 = groupApi->getGroup(reader->getString("Group_2.groupId")); });
    ASSERT_EQ(group_2.statusCode, 0);

    std::string threadId;
    ASSERT_NO_THROW({
        threadId = createThreadWithGroups(
            reader->getString("Context_1.contextId"),
            std::vector<core::UserWithPubKey>{userOf(TUGConnectionType::TUGUser1)},
            std::vector<group::Group>{group_2},
            "user"
        );
    });
    ASSERT_FALSE(threadId.empty());

    disconnect();
    connectAs(TUGConnectionType::TUGUser2);

    // Positive control: the group route yields the container key, so the rejection below is the policy check
    // and not a failure to open the thread.
    thread::Thread t;
    ASSERT_NO_THROW({ t = threadApi->getThread(threadId); });
    ASSERT_EQ(t.statusCode, 0);

    EXPECT_THROW({
        threadApi->updateThread(
            threadId,
            std::vector<core::UserWithPubKey>{userOf(TUGConnectionType::TUGUser1)},
            std::vector<core::UserWithPubKey>{userOf(TUGConnectionType::TUGUser1)},
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
}

TEST_F(ThreadUsingGroupsTest, manager_role_grantee_cannot_update_thread_keeping_manager_list) {
    // The one place `"manager"` is not enough. `makeUpdateContainerCheck` runs
    // `updaterIsRemovedFromManagersAndItIsForbidden` against the group-aware *copy* — in which the grant has
    // already put user_2 into `managers` — while comparing it to the `managers` list the caller submitted. So
    // `canUpdateContainer` passes and the update is then refused for "removing" a manager who was never on the
    // stored list. `updaterCanBeRemovedFromManagers` defaults to "no", so this is the default outcome.
    //
    // The second half is the only way through: name yourself in `managers`. That is not a no-op — it makes the
    // grantee a permanent *direct* manager with its own key wrap, which is exactly what the group grant was
    // supposed to avoid. Contrast `manager_role_grantee_can_delete_thread`, where the same grant is enough.
    group::Group group_2;
    ASSERT_NO_THROW({ group_2 = groupApi->getGroup(reader->getString("Group_2.groupId")); });
    ASSERT_EQ(group_2.statusCode, 0);

    std::string threadId;
    ASSERT_NO_THROW({
        threadId = createThreadWithGroups(
            reader->getString("Context_1.contextId"),
            std::vector<core::UserWithPubKey>{userOf(TUGConnectionType::TUGUser1)},
            std::vector<group::Group>{group_2},
            "manager"
        );
    });
    ASSERT_FALSE(threadId.empty());

    disconnect();
    connectAs(TUGConnectionType::TUGUser2);

    thread::Thread t;
    ASSERT_NO_THROW({ t = threadApi->getThread(threadId); });
    ASSERT_EQ(t.statusCode, 0);
    // user_2 holds no direct membership — everything it can do here, it does through the grant.
    ASSERT_EQ(std::count(t.managers.begin(), t.managers.end(), reader->getString("Login.user_2_id")), 0);
    ASSERT_EQ(std::count(t.users.begin(), t.users.end(), reader->getString("Login.user_2_id")), 0);

    const std::vector<core::GroupGrantWithKey> grant{{
        .groupId = group_2.groupId, .role = "manager", .groupPubKey = group_2.groupPubKey
    }};

    EXPECT_THROW({
        threadApi->updateThread(
            threadId,
            std::vector<core::UserWithPubKey>{userOf(TUGConnectionType::TUGUser1)},
            std::vector<core::UserWithPubKey>{userOf(TUGConnectionType::TUGUser1)},
            core::Buffer::from("trap_public"),
            core::Buffer::from("trap_private"),
            t.version,
            false,
            false,
            std::nullopt,
            grant
        );
    }, server::AccessDeniedException);

    // Same call, same version — the refusal above left the thread untouched — but now naming user_2 as a
    // manager of the container itself.
    EXPECT_NO_THROW({
        threadApi->updateThread(
            threadId,
            std::vector<core::UserWithPubKey>{userOf(TUGConnectionType::TUGUser1)},
            std::vector<core::UserWithPubKey>{
                userOf(TUGConnectionType::TUGUser1), userOf(TUGConnectionType::TUGUser2)
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
}

TEST_F(ThreadUsingGroupsTest, manager_role_grantee_can_update_others_message) {
    // `item.update` is "itemOwner&user,manager": the second alternative is met through the grant alone, so a
    // manager-role grantee edits an item it did not write. `item.delete` carries the identical default.
    group::Group group_2;
    ASSERT_NO_THROW({ group_2 = groupApi->getGroup(reader->getString("Group_2.groupId")); });
    ASSERT_EQ(group_2.statusCode, 0);

    std::string threadId;
    ASSERT_NO_THROW({
        threadId = createThreadWithGroups(
            reader->getString("Context_1.contextId"),
            std::vector<core::UserWithPubKey>{userOf(TUGConnectionType::TUGUser1)},
            std::vector<group::Group>{group_2},
            "manager"
        );
    });
    ASSERT_FALSE(threadId.empty());

    std::string messageId;
    ASSERT_NO_THROW({
        messageId = threadApi->sendMessage(
            threadId,
            core::Buffer::from("owner_public"),
            core::Buffer::from("owner_private"),
            core::Buffer::from("owner_data")
        );
    });
    ASSERT_FALSE(messageId.empty());

    disconnect();
    connectAs(TUGConnectionType::TUGUser2);

    EXPECT_NO_THROW({
        threadApi->updateMessage(
            messageId,
            core::Buffer::from("edited_public"),
            core::Buffer::from("edited_private"),
            core::Buffer::from("edited_data")
        );
    });

    thread::Message edited;
    EXPECT_NO_THROW({ edited = threadApi->getMessage(messageId); });
    EXPECT_EQ(edited.statusCode, 0);
    EXPECT_EQ(edited.data.stdString(), "edited_data");
}

TEST_F(ThreadUsingGroupsTest, user_role_grantee_cannot_update_others_message) {
    // The counterpart: with a "user" grant only `itemOwner&user` can be met, and user_2 does not own this item.
    group::Group group_2;
    ASSERT_NO_THROW({ group_2 = groupApi->getGroup(reader->getString("Group_2.groupId")); });
    ASSERT_EQ(group_2.statusCode, 0);

    std::string threadId;
    ASSERT_NO_THROW({
        threadId = createThreadWithGroups(
            reader->getString("Context_1.contextId"),
            std::vector<core::UserWithPubKey>{userOf(TUGConnectionType::TUGUser1)},
            std::vector<group::Group>{group_2},
            "user"
        );
    });
    ASSERT_FALSE(threadId.empty());

    std::string messageId;
    ASSERT_NO_THROW({
        messageId = threadApi->sendMessage(
            threadId,
            core::Buffer::from("owner_public"),
            core::Buffer::from("owner_private"),
            core::Buffer::from("owner_data")
        );
    });
    ASSERT_FALSE(messageId.empty());

    disconnect();
    connectAs(TUGConnectionType::TUGUser2);

    // Positive control: reading it is allowed (`item.get` is "user"), so only the write is refused.
    thread::Message readable;
    ASSERT_NO_THROW({ readable = threadApi->getMessage(messageId); });
    ASSERT_EQ(readable.statusCode, 0);

    EXPECT_THROW({
        threadApi->updateMessage(
            messageId,
            core::Buffer::from("edited_public"),
            core::Buffer::from("edited_private"),
            core::Buffer::from("edited_data")
        );
    }, server::AccessDeniedException);
}

TEST_F(ThreadUsingGroupsTest, manager_role_grantee_can_delete_thread) {
    // `delete` is "manager" and this path is guarded by the policy atom alone — no
    // `makeUpdateContainerCheck` — so the grant that cannot rename the thread
    // (`manager_role_grantee_cannot_update_thread_keeping_manager_list`) can destroy it.
    group::Group group_2;
    ASSERT_NO_THROW({ group_2 = groupApi->getGroup(reader->getString("Group_2.groupId")); });
    ASSERT_EQ(group_2.statusCode, 0);

    std::string threadId;
    ASSERT_NO_THROW({
        threadId = createThreadWithGroups(
            reader->getString("Context_1.contextId"),
            std::vector<core::UserWithPubKey>{userOf(TUGConnectionType::TUGUser1)},
            std::vector<group::Group>{group_2},
            "manager"
        );
    });
    ASSERT_FALSE(threadId.empty());

    disconnect();
    connectAs(TUGConnectionType::TUGUser2);

    EXPECT_NO_THROW({ threadApi->deleteThread(threadId); });
    EXPECT_THROW({ threadApi->getThread(threadId); }, server::ThreadDoesNotExistException);
}

TEST_F(ThreadUsingGroupsTest, user_role_grantee_cannot_delete_thread) {
    group::Group group_2;
    ASSERT_NO_THROW({ group_2 = groupApi->getGroup(reader->getString("Group_2.groupId")); });
    ASSERT_EQ(group_2.statusCode, 0);

    std::string threadId;
    ASSERT_NO_THROW({
        threadId = createThreadWithGroups(
            reader->getString("Context_1.contextId"),
            std::vector<core::UserWithPubKey>{userOf(TUGConnectionType::TUGUser1)},
            std::vector<group::Group>{group_2},
            "user"
        );
    });
    ASSERT_FALSE(threadId.empty());

    disconnect();
    connectAs(TUGConnectionType::TUGUser2);

    EXPECT_THROW({ threadApi->deleteThread(threadId); }, server::AccessDeniedException);

    thread::Thread survived;
    EXPECT_NO_THROW({ survived = threadApi->getThread(threadId); });
    EXPECT_EQ(survived.statusCode, 0);
}

TEST_F(ThreadUsingGroupsTest, group_manager_role_does_not_grant_container_manager_role) {
    // The other direction of "the role inside the group is irrelevant". The dataset groups all have user_1 as
    // their only manager, and user_1 is always a direct manager of the thread too, so proving this needs a
    // group user_2 actually manages — hence the dynamic one. The thread then grants it as `"user"`.
    //
    // Being a manager of the grantee group buys nothing on the container: `getGroupsOfUser` matches `users` OR
    // `managers` and returns a bare list of ids, so the grant's own role is the only thing the policy engine
    // ever sees.
    std::string groupId;
    ASSERT_NO_THROW({
        groupId = groupApi->createGroupWithKeyTree(
            reader->getString("Context_1.contextId"),
            std::vector<core::UserWithPubKey>{
                userOf(TUGConnectionType::TUGUser1), userOf(TUGConnectionType::TUGUser2)
            },
            std::vector<core::UserWithPubKey>{
                userOf(TUGConnectionType::TUGUser1), userOf(TUGConnectionType::TUGUser2)
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
            std::vector<core::UserWithPubKey>{userOf(TUGConnectionType::TUGUser1)},
            std::vector<group::Group>{managedGroup},
            "user"
        );
    });
    ASSERT_FALSE(threadId.empty());

    disconnect();
    connectAs(TUGConnectionType::TUGUser2);

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
            std::vector<core::UserWithPubKey>{userOf(TUGConnectionType::TUGUser1)},
            std::vector<core::UserWithPubKey>{userOf(TUGConnectionType::TUGUser1)},
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
