#include <gtest/gtest.h>
#include <algorithm>
#include "../../utils/BaseTest.hpp"
#include <privmx/endpoint/core/Exception.hpp>
#include <Poco/Util/IniFileConfiguration.h>
#include <privmx/endpoint/core/EventQueueImpl.hpp>
#include <privmx/utils/Utils.hpp>
#include <privmx/endpoint/core/VarSerializer.hpp>
#include <privmx/endpoint/core/Connection.hpp>
#include <privmx/endpoint/inbox/InboxApi.hpp>
#include <privmx/endpoint/inbox/VarSerializer.hpp>
#include <privmx/endpoint/store/StoreApi.hpp>
#include <privmx/endpoint/thread/ThreadApi.hpp>
#include <privmx/endpoint/group/GroupApi.hpp>
#include <privmx/endpoint/group/VarSerializer.hpp>
#include <privmx/endpoint/core/ConvertedExceptions.hpp>
#include <privmx/endpoint/core/CoreException.hpp>
using namespace privmx::endpoint;

enum IUGConnectionType {
    IUGUser1,
    IUGUser2,
    IUGUser3
};

class InboxUsingGroupsTest : public privmx::test::BaseTest {
protected:
    InboxUsingGroupsTest() : BaseTest(privmx::test::BaseTestMode::online) {}
    /**
     * An Inbox keeps its entries in an inner Thread and their files in an inner Store, and grants/re-keys all
     * three together — so the ThreadApi and StoreApi handed to InboxApi::create must carry the same GroupApi,
     * or the inner containers end up granted to the groups but unreadable through them.
     */
    void buildApis() {
        groupApi = std::make_shared<group::GroupApi>(group::GroupApi::create(*connection));
        threadApi = std::make_shared<thread::ThreadApi>(thread::ThreadApi::create(*connection, *groupApi));
        storeApi = std::make_shared<store::StoreApi>(store::StoreApi::create(*connection, *groupApi));
        inboxApi = std::make_shared<inbox::InboxApi>(
            inbox::InboxApi::create(*connection, *threadApi, *storeApi, *groupApi)
        );
    }
    void connectAs(IUGConnectionType type) {
        std::string privKey;
        if (type == IUGConnectionType::IUGUser1) {
            privKey = reader->getString("Login.user_1_privKey");
        } else if (type == IUGConnectionType::IUGUser2) {
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
        buildApis();
    }
    void disconnect() {
        connection->disconnect();
        connection.reset();
        inboxApi.reset();
        storeApi.reset();
        threadApi.reset();
        groupApi.reset();
    }
    /** One of the fixture's logins as a container names its members — id plus public key, from the same ini. */
    core::UserWithPubKey userOf(IUGConnectionType type) {
        std::string n;
        if (type == IUGConnectionType::IUGUser1) {
            n = "1";
        } else if (type == IUGConnectionType::IUGUser2) {
            n = "2";
        } else {
            n = "3";
        }
        return core::UserWithPubKey{
            .userId = reader->getString("Login.user_" + n + "_id"),
            .pubKey = reader->getString("Login.user_" + n + "_pubKey")
        };
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
        buildApis();
    }
    void customTearDown() override {
        connection.reset();
        inboxApi.reset();
        storeApi.reset();
        threadApi.reset();
        groupApi.reset();
        reader.reset();
        core::EventQueueImpl::getInstance()->clear();
    }
    std::string createInboxWithGroup(
        const std::string& contextId,
        const std::string& userId,
        const std::string& userPubKey,
        const group::Group& group
    ) {
        return inboxApi->createInbox(
            contextId,
            std::vector<core::UserWithPubKey>{{.userId = userId, .pubKey = userPubKey}},
            std::vector<core::UserWithPubKey>{{.userId = userId, .pubKey = userPubKey}},
            core::Buffer::from("group_inbox_public"),
            core::Buffer::from("group_inbox_private"),
            std::nullopt,
            core::ContainerPolicyWithoutItem(),
            std::vector<core::GroupGrantWithKey>{{
                .groupId = group.groupId,
                .role = "user",
                .groupPubKey = group.groupPubKey
            }}
        );
    }
    /**
     * An Inbox whose direct members are `users` — as both users and managers, so any of them can update it —
     * and whose grantee groups are `groups`, each granted at `role`.
     *
     * The grants carry no epoch: leaving `groupEpoch` at 0 is what makes the endpoint resolve each group's
     * current epoch from the Bridge, which is the path these tests are about.
     */
    std::string createInboxWithGroups(
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
        return inboxApi->createInbox(
            contextId,
            users,
            users,
            core::Buffer::from("group_inbox_public"),
            core::Buffer::from("group_inbox_private"),
            std::nullopt,
            core::ContainerPolicyWithoutItem(),
            grants
        );
    }
    std::string createInboxWithGroupPolicyReadAll(
        const std::string& contextId,
        const std::string& userId,
        const std::string& userPubKey,
        const group::Group& group
    ) {
        core::ContainerPolicyWithoutItem policy;
        policy.get = "all";
        return inboxApi->createInbox(
            contextId,
            std::vector<core::UserWithPubKey>{{.userId = userId, .pubKey = userPubKey}},
            std::vector<core::UserWithPubKey>{{.userId = userId, .pubKey = userPubKey}},
            core::Buffer::from("group_inbox_public"),
            core::Buffer::from("group_inbox_private"),
            std::nullopt,
            policy,
            std::vector<core::GroupGrantWithKey>{{
                .groupId = group.groupId,
                .role = "user",
                .groupPubKey = group.groupPubKey
            }}
        );
    }
    /** Submits one entry. The payload is sealed to the Inbox's public key, so any connection can do this. */
    void submitEntry(const std::string& inboxId, const std::string& data) {
        int64_t handle = inboxApi->prepareEntry(inboxId, core::Buffer::from(data));
        inboxApi->sendEntry(handle);
    }
    /** The id of the single entry in an Inbox, read through a member's connection. */
    std::string onlyEntryId(const std::string& inboxId) {
        auto list = inboxApi->listEntries(inboxId, core::PagingQuery{.skip = 0, .limit = 10, .sortOrder = "desc"});
        if (list.readItems.size() != 1) {
            return std::string();
        }
        return list.readItems[0].entryId;
    }

    std::shared_ptr<core::Connection> connection;
    std::shared_ptr<inbox::InboxApi> inboxApi;
    std::shared_ptr<store::StoreApi> storeApi;
    std::shared_ptr<thread::ThreadApi> threadApi;
    std::shared_ptr<group::GroupApi> groupApi;
    Poco::Util::IniFileConfiguration::Ptr reader;
    core::VarSerializer _serializer = core::VarSerializer({});
};

TEST_F(InboxUsingGroupsTest, createInbox_with_group_grants) {
    group::Group group_1;
    ASSERT_NO_THROW({ group_1 = groupApi->getGroup(reader->getString("Group_1.groupId")); });
    ASSERT_EQ(group_1.statusCode, 0);
    ASSERT_FALSE(group_1.groupPubKey.empty());

    std::string inboxId;
    EXPECT_NO_THROW({
        inboxId = inboxApi->createInbox(
            reader->getString("Context_1.contextId"),
            std::vector<core::UserWithPubKey>{userOf(IUGConnectionType::IUGUser1)},
            std::vector<core::UserWithPubKey>{userOf(IUGConnectionType::IUGUser1)},
            core::Buffer::from("public_meta"),
            core::Buffer::from("private_meta"),
            std::nullopt,
            std::nullopt,
            std::vector<core::GroupGrantWithKey>{core::GroupGrantWithKey{
                .groupId = group_1.groupId,
                .role = "user",
                .groupPubKey = group_1.groupPubKey
            }}
        );
    });
    ASSERT_FALSE(inboxId.empty());

    inbox::Inbox i;
    EXPECT_NO_THROW({ i = inboxApi->getInbox(inboxId); });
    EXPECT_EQ(i.statusCode, 0);
    EXPECT_EQ(i.publicMeta.stdString(), "public_meta");
    EXPECT_EQ(i.groups.size(), 1);
    if (i.groups.size() == 1) {
        EXPECT_EQ(i.groups[0].groupId, group_1.groupId);
        EXPECT_EQ(i.groups[0].role, "user");
    }
}

TEST_F(InboxUsingGroupsTest, createInbox_with_multiple_group_grants) {
    group::Group group_1, group_2;
    ASSERT_NO_THROW({ group_1 = groupApi->getGroup(reader->getString("Group_1.groupId")); });
    ASSERT_NO_THROW({ group_2 = groupApi->getGroup(reader->getString("Group_2.groupId")); });
    ASSERT_EQ(group_1.statusCode, 0);
    ASSERT_EQ(group_2.statusCode, 0);

    std::string inboxId;
    EXPECT_NO_THROW({
        inboxId = inboxApi->createInbox(
            reader->getString("Context_1.contextId"),
            std::vector<core::UserWithPubKey>{userOf(IUGConnectionType::IUGUser1)},
            std::vector<core::UserWithPubKey>{userOf(IUGConnectionType::IUGUser1)},
            core::Buffer::from("two_groups_public"),
            core::Buffer::from("two_groups_private"),
            std::nullopt,
            std::nullopt,
            std::vector<core::GroupGrantWithKey>{
                core::GroupGrantWithKey{
                    .groupId = group_1.groupId, .role = "user", .groupPubKey = group_1.groupPubKey
                },
                core::GroupGrantWithKey{
                    .groupId = group_2.groupId, .role = "manager", .groupPubKey = group_2.groupPubKey
                }
            }
        );
    });
    ASSERT_FALSE(inboxId.empty());

    inbox::Inbox i;
    EXPECT_NO_THROW({ i = inboxApi->getInbox(inboxId); });
    EXPECT_EQ(i.statusCode, 0);
    EXPECT_EQ(i.groups.size(), 2);
    bool found1 = false, found2 = false;
    for (const auto& g : i.groups) {
        if (g.groupId == group_1.groupId && g.role == "user") found1 = true;
        if (g.groupId == group_2.groupId && g.role == "manager") found2 = true;
    }
    EXPECT_TRUE(found1);
    EXPECT_TRUE(found2);
}

TEST_F(InboxUsingGroupsTest, createInbox_without_groups_has_empty_groups_field) {
    std::string inboxId;
    EXPECT_NO_THROW({
        inboxId = inboxApi->createInbox(
            reader->getString("Context_1.contextId"),
            std::vector<core::UserWithPubKey>{userOf(IUGConnectionType::IUGUser1)},
            std::vector<core::UserWithPubKey>{userOf(IUGConnectionType::IUGUser1)},
            core::Buffer::from("no_groups_public"),
            core::Buffer::from("no_groups_private"),
            std::nullopt
        );
    });
    ASSERT_FALSE(inboxId.empty());

    inbox::Inbox i;
    EXPECT_NO_THROW({ i = inboxApi->getInbox(inboxId); });
    EXPECT_EQ(i.statusCode, 0);
    EXPECT_EQ(i.groups.size(), 0);
}

TEST_F(InboxUsingGroupsTest, updateInbox_add_group) {
    std::string inboxId;
    EXPECT_NO_THROW({
        inboxId = inboxApi->createInbox(
            reader->getString("Context_1.contextId"),
            std::vector<core::UserWithPubKey>{userOf(IUGConnectionType::IUGUser1)},
            std::vector<core::UserWithPubKey>{userOf(IUGConnectionType::IUGUser1)},
            core::Buffer::from("before_group"),
            core::Buffer::from("before_group_private"),
            std::nullopt
        );
    });
    ASSERT_FALSE(inboxId.empty());

    inbox::Inbox i;
    EXPECT_NO_THROW({ i = inboxApi->getInbox(inboxId); });
    EXPECT_EQ(i.groups.size(), 0);

    group::Group group_1;
    ASSERT_NO_THROW({ group_1 = groupApi->getGroup(reader->getString("Group_1.groupId")); });
    ASSERT_EQ(group_1.statusCode, 0);

    EXPECT_NO_THROW({
        inboxApi->updateInbox(
            inboxId,
            std::vector<core::UserWithPubKey>{userOf(IUGConnectionType::IUGUser1)},
            std::vector<core::UserWithPubKey>{userOf(IUGConnectionType::IUGUser1)},
            core::Buffer::from("after_group"),
            core::Buffer::from("after_group_private"),
            std::nullopt,
            1,
            false,
            false,
            std::nullopt,
            std::vector<core::GroupGrantWithKey>{core::GroupGrantWithKey{
                .groupId = group_1.groupId, .role = "user", .groupPubKey = group_1.groupPubKey
            }}
        );
    });

    inbox::Inbox updated;
    EXPECT_NO_THROW({ updated = inboxApi->getInbox(inboxId); });
    EXPECT_EQ(updated.statusCode, 0);
    EXPECT_EQ(updated.publicMeta.stdString(), "after_group");
    EXPECT_EQ(updated.groups.size(), 1);
    if (updated.groups.size() == 1) {
        EXPECT_EQ(updated.groups[0].groupId, group_1.groupId);
        EXPECT_EQ(updated.groups[0].role, "user");
    }
}

TEST_F(InboxUsingGroupsTest, updateInbox_remove_group) {
    group::Group group_2;
    ASSERT_NO_THROW({ group_2 = groupApi->getGroup(reader->getString("Group_2.groupId")); });
    ASSERT_EQ(group_2.statusCode, 0);

    // policy.get="all" so user_2 can always call getInbox without throwing; after group removal it
    // receives statusCode!=0 and empty privateMeta because it no longer holds the decryption key.
    core::ContainerPolicyWithoutItem policy;
    policy.get = "all";

    std::string inboxId;
    EXPECT_NO_THROW({
        inboxId = inboxApi->createInbox(
            reader->getString("Context_1.contextId"),
            std::vector<core::UserWithPubKey>{userOf(IUGConnectionType::IUGUser1)},
            std::vector<core::UserWithPubKey>{userOf(IUGConnectionType::IUGUser1)},
            core::Buffer::from("with_group"),
            core::Buffer::from("with_group_private"),
            std::nullopt,
            policy,
            std::vector<core::GroupGrantWithKey>{core::GroupGrantWithKey{
                .groupId = group_2.groupId, .role = "user", .groupPubKey = group_2.groupPubKey
            }}
        );
    });
    ASSERT_FALSE(inboxId.empty());

    disconnect();
    connectAs(IUGConnectionType::IUGUser2);
    inbox::Inbox beforeRemoval;
    EXPECT_NO_THROW({ beforeRemoval = inboxApi->getInbox(inboxId); });
    EXPECT_EQ(beforeRemoval.statusCode, 0);
    EXPECT_FALSE(beforeRemoval.privateMeta.stdString().empty());

    disconnect();
    connectAs(IUGConnectionType::IUGUser1);
    EXPECT_NO_THROW({
        inboxApi->updateInbox(
            inboxId,
            std::vector<core::UserWithPubKey>{userOf(IUGConnectionType::IUGUser1)},
            std::vector<core::UserWithPubKey>{userOf(IUGConnectionType::IUGUser1)},
            core::Buffer::from("no_group_now"),
            core::Buffer::from("no_group_private"),
            std::nullopt,
            1,
            false,
            false,
            std::nullopt,
            std::vector<core::GroupGrantWithKey>{}
        );
    });

    inbox::Inbox updated;
    EXPECT_NO_THROW({ updated = inboxApi->getInbox(inboxId); });
    EXPECT_EQ(updated.statusCode, 0);
    EXPECT_EQ(updated.groups.size(), 0);

    disconnect();
    connectAs(IUGConnectionType::IUGUser2);
    inbox::Inbox afterRemoval;
    EXPECT_NO_THROW({ afterRemoval = inboxApi->getInbox(inboxId); });
    EXPECT_NE(afterRemoval.statusCode, 0);
    EXPECT_TRUE(afterRemoval.privateMeta.stdString().empty());
}

TEST_F(InboxUsingGroupsTest, updateInbox_change_group_role) {
    group::Group group_1;
    ASSERT_NO_THROW({ group_1 = groupApi->getGroup(reader->getString("Group_1.groupId")); });
    ASSERT_EQ(group_1.statusCode, 0);

    std::string inboxId;
    ASSERT_NO_THROW({
        inboxId = createInboxWithGroups(
            reader->getString("Context_1.contextId"),
            std::vector<core::UserWithPubKey>{userOf(IUGConnectionType::IUGUser1)},
            std::vector<group::Group>{group_1}
        );
    });
    ASSERT_FALSE(inboxId.empty());

    EXPECT_NO_THROW({
        inboxApi->updateInbox(
            inboxId,
            std::vector<core::UserWithPubKey>{userOf(IUGConnectionType::IUGUser1)},
            std::vector<core::UserWithPubKey>{userOf(IUGConnectionType::IUGUser1)},
            core::Buffer::from("role_change"),
            core::Buffer::from("role_change_private"),
            std::nullopt,
            1,
            false,
            false,
            std::nullopt,
            std::vector<core::GroupGrantWithKey>{core::GroupGrantWithKey{
                .groupId = group_1.groupId, .role = "manager", .groupPubKey = group_1.groupPubKey
            }}
        );
    });

    inbox::Inbox updated;
    EXPECT_NO_THROW({ updated = inboxApi->getInbox(inboxId); });
    EXPECT_EQ(updated.groups.size(), 1);
    if (updated.groups.size() == 1) {
        EXPECT_EQ(updated.groups[0].groupId, group_1.groupId);
        EXPECT_EQ(updated.groups[0].role, "manager");
    }
}

TEST_F(InboxUsingGroupsTest, listInboxes_includes_groups_field) {
    group::Group group_1;
    ASSERT_NO_THROW({ group_1 = groupApi->getGroup(reader->getString("Group_1.groupId")); });
    ASSERT_EQ(group_1.statusCode, 0);

    std::string inboxId;
    ASSERT_NO_THROW({
        inboxId = createInboxWithGroups(
            reader->getString("Context_1.contextId"),
            std::vector<core::UserWithPubKey>{userOf(IUGConnectionType::IUGUser1)},
            std::vector<group::Group>{group_1}
        );
    });
    ASSERT_FALSE(inboxId.empty());

    core::PagingList<inbox::Inbox> list;
    EXPECT_NO_THROW({
        list = inboxApi->listInboxes(
            reader->getString("Context_1.contextId"),
            core::PagingQuery{.skip = 0, .limit = 100, .sortOrder = "desc"}
        );
    });
    bool found = false;
    for (const auto& i : list.readItems) {
        if (i.inboxId == inboxId) {
            EXPECT_EQ(i.statusCode, 0);
            EXPECT_EQ(i.groups.size(), 1);
            if (i.groups.size() == 1) {
                EXPECT_EQ(i.groups[0].groupId, group_1.groupId);
                EXPECT_EQ(i.groups[0].role, "user");
            }
            found = true;
            break;
        }
    }
    EXPECT_TRUE(found);
}

TEST_F(InboxUsingGroupsTest, createInbox_with_invalid_group_pubkey_throws) {
    EXPECT_THROW({
        inboxApi->createInbox(
            reader->getString("Context_1.contextId"),
            std::vector<core::UserWithPubKey>{userOf(IUGConnectionType::IUGUser1)},
            std::vector<core::UserWithPubKey>{userOf(IUGConnectionType::IUGUser1)},
            core::Buffer::from("public"),
            core::Buffer::from("private"),
            std::nullopt,
            std::nullopt,
            std::vector<core::GroupGrantWithKey>{core::GroupGrantWithKey{
                .groupId = reader->getString("Group_1.groupId"),
                .role = "user",
                .groupPubKey = "not_a_valid_base58der_pubkey"
            }}
        );
    }, core::Exception);
}

TEST_F(InboxUsingGroupsTest, readEntry_via_group_grant) {
    // user_1 creates an Inbox granted to Group_2; user_2 is a Group_2 member. Entries live in the Inbox's
    // inner Thread, which createInbox grants to the same group — so this read exercises that propagation.
    group::Group group_2;
    ASSERT_NO_THROW({ group_2 = groupApi->getGroup(reader->getString("Group_2.groupId")); });
    ASSERT_EQ(group_2.statusCode, 0);

    std::string inboxId;
    ASSERT_NO_THROW({
        inboxId = createInboxWithGroup(
            reader->getString("Context_1.contextId"),
            reader->getString("Login.user_1_id"),
            reader->getString("Login.user_1_pubKey"),
            group_2
        );
    });
    ASSERT_FALSE(inboxId.empty());

    ASSERT_NO_THROW({ submitEntry(inboxId, "entry_data"); });

    disconnect();
    connectAs(IUGConnectionType::IUGUser2);
    std::string entryId;
    ASSERT_NO_THROW({ entryId = onlyEntryId(inboxId); });
    ASSERT_FALSE(entryId.empty());

    inbox::InboxEntry entry;
    EXPECT_NO_THROW({ entry = inboxApi->readEntry(entryId); });
    EXPECT_EQ(entry.statusCode, 0);
    EXPECT_EQ(entry.data.stdString(), "entry_data");
}

TEST_F(InboxUsingGroupsTest, listEntries_via_group_grant) {
    group::Group group_2;
    ASSERT_NO_THROW({ group_2 = groupApi->getGroup(reader->getString("Group_2.groupId")); });
    ASSERT_EQ(group_2.statusCode, 0);

    std::string inboxId;
    ASSERT_NO_THROW({
        inboxId = createInboxWithGroup(
            reader->getString("Context_1.contextId"),
            reader->getString("Login.user_1_id"),
            reader->getString("Login.user_1_pubKey"),
            group_2
        );
    });
    ASSERT_FALSE(inboxId.empty());

    ASSERT_NO_THROW({ submitEntry(inboxId, "data1"); });
    ASSERT_NO_THROW({ submitEntry(inboxId, "data2"); });

    disconnect();
    connectAs(IUGConnectionType::IUGUser2);
    core::PagingList<inbox::InboxEntry> list;
    EXPECT_NO_THROW({
        list = inboxApi->listEntries(inboxId, core::PagingQuery{.skip = 0, .limit = 10, .sortOrder = "desc"});
    });
    EXPECT_EQ(list.totalAvailable, 2);
    for (const auto& entry : list.readItems) {
        EXPECT_EQ(entry.statusCode, 0);
        EXPECT_FALSE(entry.data.stdString().empty());
    }
}

TEST_F(InboxUsingGroupsTest, entries_accessible_by_all_group_members) {
    // Group_3 has user_1, user_2 and user_3.
    group::Group group_3;
    ASSERT_NO_THROW({ group_3 = groupApi->getGroup(reader->getString("Group_3.groupId")); });
    ASSERT_EQ(group_3.statusCode, 0);

    std::string inboxId;
    ASSERT_NO_THROW({
        inboxId = createInboxWithGroup(
            reader->getString("Context_1.contextId"),
            reader->getString("Login.user_1_id"),
            reader->getString("Login.user_1_pubKey"),
            group_3
        );
    });
    ASSERT_FALSE(inboxId.empty());

    ASSERT_NO_THROW({ submitEntry(inboxId, "shared_data"); });

    disconnect();
    connectAs(IUGConnectionType::IUGUser2);
    std::string entryIdUser2;
    ASSERT_NO_THROW({ entryIdUser2 = onlyEntryId(inboxId); });
    ASSERT_FALSE(entryIdUser2.empty());
    inbox::InboxEntry entryUser2;
    EXPECT_NO_THROW({ entryUser2 = inboxApi->readEntry(entryIdUser2); });
    EXPECT_EQ(entryUser2.statusCode, 0);
    EXPECT_EQ(entryUser2.data.stdString(), "shared_data");

    disconnect();
    connectAs(IUGConnectionType::IUGUser3);
    std::string entryIdUser3;
    ASSERT_NO_THROW({ entryIdUser3 = onlyEntryId(inboxId); });
    ASSERT_FALSE(entryIdUser3.empty());
    inbox::InboxEntry entryUser3;
    EXPECT_NO_THROW({ entryUser3 = inboxApi->readEntry(entryIdUser3); });
    EXPECT_EQ(entryUser3.statusCode, 0);
    EXPECT_EQ(entryUser3.data.stdString(), "shared_data");
}

TEST_F(InboxUsingGroupsTest, user_added_to_group_gains_access_to_inbox_and_entries) {
    // Group_2 has user_1 + user_2; user_3 is not yet a member.
    group::Group group_2;
    ASSERT_NO_THROW({ group_2 = groupApi->getGroup(reader->getString("Group_2.groupId")); });
    ASSERT_EQ(group_2.statusCode, 0);

    std::string inboxId;
    ASSERT_NO_THROW({
        inboxId = createInboxWithGroupPolicyReadAll(
            reader->getString("Context_1.contextId"),
            reader->getString("Login.user_1_id"),
            reader->getString("Login.user_1_pubKey"),
            group_2
        );
    });
    ASSERT_FALSE(inboxId.empty());

    ASSERT_NO_THROW({ submitEntry(inboxId, "entry_data"); });

    // Capture the entry id from a member's connection while we still have one.
    std::string entryId;
    ASSERT_NO_THROW({ entryId = onlyEntryId(inboxId); });
    ASSERT_FALSE(entryId.empty());

    disconnect();
    connectAs(IUGConnectionType::IUGUser3);
    inbox::Inbox iBefore;
    EXPECT_NO_THROW({ iBefore = inboxApi->getInbox(inboxId); });
    EXPECT_NE(iBefore.statusCode, 0);

    // Seat user_3's leaf in the key tree — updateGroup would only re-wrap the group's metadata key.
    disconnect();
    connectAs(IUGConnectionType::IUGUser1);
    EXPECT_NO_THROW({
        groupApi->addGroupMember(
            reader->getString("Group_2.groupId"),
            userOf(IUGConnectionType::IUGUser3),
            false, // asManager
            std::vector<core::UserWithPubKey>{
                userOf(IUGConnectionType::IUGUser1),
                userOf(IUGConnectionType::IUGUser2),
                userOf(IUGConnectionType::IUGUser3)
            },
            std::vector<core::UserWithPubKey>{userOf(IUGConnectionType::IUGUser1)},
            group_2.publicMeta,
            group_2.privateMeta
        );
    });

    disconnect();
    connectAs(IUGConnectionType::IUGUser3);
    inbox::Inbox iAfter;
    EXPECT_NO_THROW({ iAfter = inboxApi->getInbox(inboxId); });
    EXPECT_EQ(iAfter.statusCode, 0);

    inbox::InboxEntry eAfter;
    EXPECT_NO_THROW({ eAfter = inboxApi->readEntry(entryId); });
    EXPECT_EQ(eAfter.statusCode, 0);
    EXPECT_EQ(eAfter.data.stdString(), "entry_data");
}

TEST_F(InboxUsingGroupsTest, direct_member_of_granted_group_reads_and_updates) {
    // user_1 is the only direct member of the Inbox *and* a member of granted Group_1, so every keyId opens
    // from `keys` and the group branch is skipped. `updateInbox` is the interesting half: `verifyKeysSecret`
    // fails on any non-zero status, so an unresolved group entry there is the difference between an update
    // and an exception — and updateInbox runs it three times, once per container.
    group::Group group_1;
    ASSERT_NO_THROW({ group_1 = groupApi->getGroup(reader->getString("Group_1.groupId")); });
    ASSERT_EQ(group_1.statusCode, 0);

    std::string inboxId;
    ASSERT_NO_THROW({
        inboxId = createInboxWithGroups(
            reader->getString("Context_1.contextId"),
            std::vector<core::UserWithPubKey>{userOf(IUGConnectionType::IUGUser1)},
            std::vector<group::Group>{group_1}
        );
    });
    ASSERT_FALSE(inboxId.empty());

    ASSERT_NO_THROW({ submitEntry(inboxId, "direct_data"); });

    inbox::Inbox i;
    EXPECT_NO_THROW({ i = inboxApi->getInbox(inboxId); });
    EXPECT_EQ(i.statusCode, 0);
    EXPECT_EQ(i.groups.size(), 1);

    std::string entryId;
    ASSERT_NO_THROW({ entryId = onlyEntryId(inboxId); });
    ASSERT_FALSE(entryId.empty());
    inbox::InboxEntry entry;
    EXPECT_NO_THROW({ entry = inboxApi->readEntry(entryId); });
    EXPECT_EQ(entry.statusCode, 0);
    EXPECT_EQ(entry.data.stdString(), "direct_data");

    EXPECT_NO_THROW({
        inboxApi->updateInbox(
            inboxId,
            std::vector<core::UserWithPubKey>{userOf(IUGConnectionType::IUGUser1)},
            std::vector<core::UserWithPubKey>{userOf(IUGConnectionType::IUGUser1)},
            core::Buffer::from("direct_updated_public"),
            core::Buffer::from("direct_updated_private"),
            std::nullopt,
            i.version,
            false,
            false,
            std::nullopt,
            std::vector<core::GroupGrantWithKey>{{
                .groupId = group_1.groupId, .role = "user", .groupPubKey = group_1.groupPubKey
            }}
        );
    });

    inbox::Inbox updated;
    EXPECT_NO_THROW({ updated = inboxApi->getInbox(inboxId); });
    EXPECT_EQ(updated.statusCode, 0);
    EXPECT_EQ(updated.privateMeta.stdString(), "direct_updated_private");
}

TEST_F(InboxUsingGroupsTest, caller_in_no_granted_group_reads_via_direct_key) {
    // The Inbox grants Group_1, whose only member is user_1. user_2 is a direct member and belongs to no
    // grantee group, so the bridge serves it `groupKeys: []` — the read has to be served entirely from its
    // own key wrap.
    group::Group group_1;
    ASSERT_NO_THROW({ group_1 = groupApi->getGroup(reader->getString("Group_1.groupId")); });
    ASSERT_EQ(group_1.statusCode, 0);

    std::string inboxId;
    ASSERT_NO_THROW({
        inboxId = createInboxWithGroups(
            reader->getString("Context_1.contextId"),
            std::vector<core::UserWithPubKey>{
                userOf(IUGConnectionType::IUGUser1), userOf(IUGConnectionType::IUGUser2)
            },
            std::vector<group::Group>{group_1}
        );
    });
    ASSERT_FALSE(inboxId.empty());

    ASSERT_NO_THROW({ submitEntry(inboxId, "nogroup_data"); });

    disconnect();
    connectAs(IUGConnectionType::IUGUser2);

    inbox::Inbox i;
    EXPECT_NO_THROW({ i = inboxApi->getInbox(inboxId); });
    EXPECT_EQ(i.statusCode, 0);
    // `groups` stays unnarrowed, so user_2 still sees the grant it is not part of.
    EXPECT_EQ(i.groups.size(), 1);

    std::string entryId;
    ASSERT_NO_THROW({ entryId = onlyEntryId(inboxId); });
    ASSERT_FALSE(entryId.empty());
    inbox::InboxEntry entry;
    EXPECT_NO_THROW({ entry = inboxApi->readEntry(entryId); });
    EXPECT_EQ(entry.statusCode, 0);
    EXPECT_EQ(entry.data.stdString(), "nogroup_data");
}

TEST_F(InboxUsingGroupsTest, caller_in_two_granted_groups_reads) {
    // The Inbox grants Group_2 and Group_3 and wraps its key to user_1 only. user_2 belongs to both grantee
    // groups, so narrowing leaves it two entries at the same keyId — with no direct wrap to fall back on,
    // one of them has to carry the read.
    group::Group group_2, group_3;
    ASSERT_NO_THROW({ group_2 = groupApi->getGroup(reader->getString("Group_2.groupId")); });
    ASSERT_NO_THROW({ group_3 = groupApi->getGroup(reader->getString("Group_3.groupId")); });
    ASSERT_EQ(group_2.statusCode, 0);
    ASSERT_EQ(group_3.statusCode, 0);

    std::string inboxId;
    ASSERT_NO_THROW({
        inboxId = createInboxWithGroups(
            reader->getString("Context_1.contextId"),
            std::vector<core::UserWithPubKey>{userOf(IUGConnectionType::IUGUser1)},
            std::vector<group::Group>{group_2, group_3}
        );
    });
    ASSERT_FALSE(inboxId.empty());

    ASSERT_NO_THROW({ submitEntry(inboxId, "twogroups_data"); });

    disconnect();
    connectAs(IUGConnectionType::IUGUser2);

    inbox::Inbox i;
    EXPECT_NO_THROW({ i = inboxApi->getInbox(inboxId); });
    EXPECT_EQ(i.statusCode, 0);

    std::string entryId;
    ASSERT_NO_THROW({ entryId = onlyEntryId(inboxId); });
    ASSERT_FALSE(entryId.empty());
    inbox::InboxEntry entry;
    EXPECT_NO_THROW({ entry = inboxApi->readEntry(entryId); });
    EXPECT_EQ(entry.statusCode, 0);
    EXPECT_EQ(entry.data.stdString(), "twogroups_data");
}

TEST_F(InboxUsingGroupsTest, rotateInboxKeys_covers_a_grantee_group_the_caller_did_not_name) {
    // The Inbox grants Group_2. user_2 re-keys naming no groups at all, and the new key must still be re-wrapped
    // to Group_2 across the Inbox and both inner containers — the grantee list comes from the containers, not
    // from the caller's argument.
    //
    // The grantee is a group the caller belongs to, and that is a constraint rather than a convenience: wrapping
    // a key to a group needs its current epoch and public key, and a Bridge running the default group policy
    // (`get: "user"`, `listAll: "none"`) hands those to members only. Re-keying a container granted to a group
    // the caller is not in therefore cannot work — `resolveGroupEpochs` throws `UnresolvedGroupGranteeException`
    // — so do not "restore" this test to Group_1, which holds user_1 alone.
    group::Group granteeGroup;
    ASSERT_NO_THROW({ granteeGroup = groupApi->getGroup(reader->getString("Group_2.groupId")); });
    ASSERT_EQ(granteeGroup.statusCode, 0);

    std::string inboxId;
    ASSERT_NO_THROW({
        inboxId = createInboxWithGroups(
            reader->getString("Context_1.contextId"),
            std::vector<core::UserWithPubKey>{
                userOf(IUGConnectionType::IUGUser1), userOf(IUGConnectionType::IUGUser2)
            },
            std::vector<group::Group>{granteeGroup}
        );
    });
    ASSERT_FALSE(inboxId.empty());

    inbox::Inbox before;
    ASSERT_NO_THROW({ before = inboxApi->getInbox(inboxId); });
    ASSERT_EQ(before.statusCode, 0);

    disconnect();
    connectAs(IUGConnectionType::IUGUser2);
    EXPECT_NO_THROW({
        inboxApi->rotateInboxKeys(
            inboxId,
            std::vector<core::UserWithPubKey>{
                userOf(IUGConnectionType::IUGUser1), userOf(IUGConnectionType::IUGUser2)
            },
            std::vector<core::UserWithPubKey>{
                userOf(IUGConnectionType::IUGUser1), userOf(IUGConnectionType::IUGUser2)
            },
            before.version,
            false,
            std::vector<core::GroupGrantWithKey>{}
        );
    });

    disconnect();
    connectAs(IUGConnectionType::IUGUser1);
    inbox::Inbox after;
    EXPECT_NO_THROW({ after = inboxApi->getInbox(inboxId); });
    EXPECT_EQ(after.statusCode, 0);
    EXPECT_EQ(after.groups.size(), 1);
    if (after.groups.size() == 1) {
        EXPECT_EQ(after.groups[0].groupId, granteeGroup.groupId);
    }

    // An entry submitted after the re-key is readable, proving all three containers got a usable key.
    ASSERT_NO_THROW({ submitEntry(inboxId, "post_rekey_data"); });
    std::string entryId;
    ASSERT_NO_THROW({ entryId = onlyEntryId(inboxId); });
    ASSERT_FALSE(entryId.empty());
    inbox::InboxEntry entry;
    EXPECT_NO_THROW({ entry = inboxApi->readEntry(entryId); });
    EXPECT_EQ(entry.statusCode, 0);
    EXPECT_EQ(entry.data.stdString(), "post_rekey_data");
}

TEST_F(InboxUsingGroupsTest, rotateInboxKeys_clears_staleGroups_after_the_group_advances_its_epoch) {
    // Group G at epoch 1 is granted the Inbox. Removing a member advances G to epoch 2, which leaves the
    // Inbox's key wrapped to a superseded epoch — the bridge reports that as `staleGroups`. A re-key
    // re-wraps to the current epoch and must clear it.
    std::string groupId;
    ASSERT_NO_THROW({
        groupId = groupApi->createGroupWithKeyTree(
            reader->getString("Context_1.contextId"),
            std::vector<core::UserWithPubKey>{
                userOf(IUGConnectionType::IUGUser1),
                userOf(IUGConnectionType::IUGUser2),
                userOf(IUGConnectionType::IUGUser3)
            },
            std::vector<core::UserWithPubKey>{userOf(IUGConnectionType::IUGUser1)},
            core::Buffer::from("grp_pub"),
            core::Buffer::from("grp_priv")
        );
    });
    ASSERT_FALSE(groupId.empty());

    group::Group group;
    ASSERT_NO_THROW({ group = groupApi->getGroup(groupId); });
    ASSERT_EQ(group.statusCode, 0);
    ASSERT_EQ(group.keyVersion, 1);

    std::string inboxId;
    ASSERT_NO_THROW({
        inboxId = createInboxWithGroups(
            reader->getString("Context_1.contextId"),
            std::vector<core::UserWithPubKey>{userOf(IUGConnectionType::IUGUser1)},
            std::vector<group::Group>{group}
        );
    });
    ASSERT_FALSE(inboxId.empty());

    ASSERT_NO_THROW({ submitEntry(inboxId, "old_epoch_data"); });
    std::string oldEpochEntryId;
    ASSERT_NO_THROW({ oldEpochEntryId = onlyEntryId(inboxId); });
    ASSERT_FALSE(oldEpochEntryId.empty());

    ASSERT_NO_THROW({
        groupApi->removeGroupMember(
            groupId,
            reader->getString("Login.user_3_id"),
            std::vector<core::UserWithPubKey>{
                userOf(IUGConnectionType::IUGUser1), userOf(IUGConnectionType::IUGUser2)
            },
            std::vector<core::UserWithPubKey>{userOf(IUGConnectionType::IUGUser1)},
            core::Buffer::from("grp_removed_pub"),
            core::Buffer::from("grp_removed_priv")
        );
    });

    group::Group rotatedGroup;
    ASSERT_NO_THROW({ rotatedGroup = groupApi->getGroup(groupId); });
    ASSERT_EQ(rotatedGroup.statusCode, 0);
    ASSERT_EQ(rotatedGroup.keyVersion, 2);

    inbox::Inbox stale;
    ASSERT_NO_THROW({ stale = inboxApi->getInbox(inboxId); });
    ASSERT_EQ(stale.statusCode, 0);
    EXPECT_EQ(stale.staleGroups.size(), 1);
    if (stale.staleGroups.size() == 1) {
        EXPECT_EQ(stale.staleGroups[0], groupId);
    }

    EXPECT_NO_THROW({
        inboxApi->rotateInboxKeys(
            inboxId,
            std::vector<core::UserWithPubKey>{userOf(IUGConnectionType::IUGUser1)},
            std::vector<core::UserWithPubKey>{userOf(IUGConnectionType::IUGUser1)},
            stale.version,
            false,
            std::vector<core::GroupGrantWithKey>{}
        );
    });

    inbox::Inbox fresh;
    EXPECT_NO_THROW({ fresh = inboxApi->getInbox(inboxId); });
    EXPECT_EQ(fresh.statusCode, 0);
    EXPECT_EQ(fresh.staleGroups.size(), 0);
    EXPECT_EQ(fresh.groups.size(), 1);

    // user_2 is still in G at epoch 2 and was never a direct Inbox member, so this read can only be served
    // through the re-wrapped group entries — on the Inbox *and* on its inner Thread, where the entry lives.
    disconnect();
    connectAs(IUGConnectionType::IUGUser2);
    inbox::InboxEntry oldEpochEntry;
    EXPECT_NO_THROW({ oldEpochEntry = inboxApi->readEntry(oldEpochEntryId); });
    EXPECT_EQ(oldEpochEntry.statusCode, 0);
    EXPECT_EQ(oldEpochEntry.data.stdString(), "old_epoch_data");
}
