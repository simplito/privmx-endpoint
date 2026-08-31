#include <gtest/gtest.h>
#include <algorithm>
#include "../../utils/BaseTest.hpp"
#include <privmx/endpoint/core/Exception.hpp>
#include <Poco/Util/IniFileConfiguration.h>
#include <privmx/endpoint/core/EventQueueImpl.hpp>
#include <privmx/utils/Utils.hpp>
#include <privmx/endpoint/core/VarSerializer.hpp>
#include <privmx/endpoint/core/Connection.hpp>
#include <privmx/endpoint/store/StoreApi.hpp>
#include <privmx/endpoint/store/VarSerializer.hpp>
#include <privmx/endpoint/group/GroupApi.hpp>
#include <privmx/endpoint/group/VarSerializer.hpp>
#include <privmx/endpoint/core/ConvertedExceptions.hpp>
#include <privmx/endpoint/core/CoreException.hpp>
using namespace privmx::endpoint;

enum SUGConnectionType {
    SUGUser1,
    SUGUser2,
    SUGUser3
};

class StoreUsingGroupsTest : public privmx::test::BaseTest {
protected:
    StoreUsingGroupsTest() : BaseTest(privmx::test::BaseTestMode::online) {}
    void connectAs(SUGConnectionType type) {
        std::string privKey;
        if (type == SUGConnectionType::SUGUser1) {
            privKey = reader->getString("Login.user_1_privKey");
        } else if (type == SUGConnectionType::SUGUser2) {
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
        storeApi = std::make_shared<store::StoreApi>(store::StoreApi::create(*connection, *groupApi));
    }
    void disconnect() {
        connection->disconnect();
        connection.reset();
        storeApi.reset();
        groupApi.reset();
    }
    /** One of the fixture's logins as a container names its members — id plus public key, from the same ini. */
    core::UserWithPubKey userOf(SUGConnectionType type) {
        std::string n;
        if (type == SUGConnectionType::SUGUser1) {
            n = "1";
        } else if (type == SUGConnectionType::SUGUser2) {
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
        groupApi = std::make_shared<group::GroupApi>(group::GroupApi::create(*connection));
        storeApi = std::make_shared<store::StoreApi>(store::StoreApi::create(*connection, *groupApi));
    }
    void customTearDown() override {
        connection.reset();
        storeApi.reset();
        groupApi.reset();
        reader.reset();
        core::EventQueueImpl::getInstance()->clear();
    }
    std::string createStoreWithGroup(
        const std::string& contextId,
        const std::string& userId,
        const std::string& userPubKey,
        const group::Group& group
    ) {
        return storeApi->createStore(
            contextId,
            std::vector<core::UserWithPubKey>{{.userId = userId, .pubKey = userPubKey}},
            std::vector<core::UserWithPubKey>{{.userId = userId, .pubKey = userPubKey}},
            core::Buffer::from("group_store_public"),
            core::Buffer::from("group_store_private"),
            core::ContainerPolicy(),
            std::vector<core::GroupGrantWithKey>{{
                .groupId = group.groupId,
                .role = "user",
                .groupPubKey = group.groupPubKey
            }}
        );
    }
    /**
     * A Store whose direct members are `users` — as both users and managers, so any of them can update it —
     * and whose grantee groups are `groups`, each granted at `role`.
     *
     * The grants carry no epoch: leaving `groupEpoch` at 0 is what makes the endpoint resolve each group's
     * current epoch from the Bridge, which is the path these tests are about.
     */
    std::string createStoreWithGroups(
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
        return storeApi->createStore(
            contextId,
            users,
            users,
            core::Buffer::from("group_store_public"),
            core::Buffer::from("group_store_private"),
            core::ContainerPolicy(),
            grants
        );
    }
    std::string createStoreWithGroupPolicyReadAll(
        const std::string& contextId,
        const std::string& userId,
        const std::string& userPubKey,
        const group::Group& group
    ) {
        core::ContainerPolicy policy;
        policy.get = "all";
        policy.item = core::ItemPolicy{.get = "all", .listAll = "all"};
        return storeApi->createStore(
            contextId,
            std::vector<core::UserWithPubKey>{{.userId = userId, .pubKey = userPubKey}},
            std::vector<core::UserWithPubKey>{{.userId = userId, .pubKey = userPubKey}},
            core::Buffer::from("group_store_public"),
            core::Buffer::from("group_store_private"),
            policy,
            std::vector<core::GroupGrantWithKey>{{
                .groupId = group.groupId,
                .role = "user",
                .groupPubKey = group.groupPubKey
            }}
        );
    }
    /** Uploads one file and returns its id. The whole payload goes in a single write. */
    std::string uploadFile(
        const std::string& storeId,
        const std::string& publicMeta,
        const std::string& privateMeta,
        const std::string& data
    ) {
        int64_t handle = storeApi->createFile(
            storeId,
            core::Buffer::from(publicMeta),
            core::Buffer::from(privateMeta),
            (int64_t)data.size()
        );
        storeApi->writeToFile(handle, core::Buffer::from(data));
        return storeApi->closeFile(handle);
    }
    /** Reads a whole file back through a read handle. */
    std::string downloadFile(const std::string& fileId, int64_t size) {
        int64_t handle = storeApi->openFile(fileId);
        auto data = storeApi->readFromFile(handle, size).stdString();
        storeApi->closeFile(handle);
        return data;
    }

    std::shared_ptr<core::Connection> connection;
    std::shared_ptr<store::StoreApi> storeApi;
    std::shared_ptr<group::GroupApi> groupApi;
    Poco::Util::IniFileConfiguration::Ptr reader;
    core::VarSerializer _serializer = core::VarSerializer({});
};

TEST_F(StoreUsingGroupsTest, createStore_with_group_grants) {
    group::Group group_1;
    ASSERT_NO_THROW({ group_1 = groupApi->getGroup(reader->getString("Group_1.groupId")); });
    ASSERT_EQ(group_1.statusCode, 0);
    ASSERT_FALSE(group_1.groupPubKey.empty());

    std::string storeId;
    EXPECT_NO_THROW({
        storeId = storeApi->createStore(
            reader->getString("Context_1.contextId"),
            std::vector<core::UserWithPubKey>{userOf(SUGConnectionType::SUGUser1)},
            std::vector<core::UserWithPubKey>{userOf(SUGConnectionType::SUGUser1)},
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
    ASSERT_FALSE(storeId.empty());

    store::Store s;
    EXPECT_NO_THROW({ s = storeApi->getStore(storeId); });
    EXPECT_EQ(s.statusCode, 0);
    EXPECT_EQ(s.publicMeta.stdString(), "public_meta");
    EXPECT_EQ(s.groups.size(), 1);
    if (s.groups.size() == 1) {
        EXPECT_EQ(s.groups[0].groupId, group_1.groupId);
        EXPECT_EQ(s.groups[0].role, "user");
    }
}

TEST_F(StoreUsingGroupsTest, createStore_with_multiple_group_grants) {
    group::Group group_1, group_2;
    ASSERT_NO_THROW({ group_1 = groupApi->getGroup(reader->getString("Group_1.groupId")); });
    ASSERT_NO_THROW({ group_2 = groupApi->getGroup(reader->getString("Group_2.groupId")); });
    ASSERT_EQ(group_1.statusCode, 0);
    ASSERT_EQ(group_2.statusCode, 0);

    std::string storeId;
    EXPECT_NO_THROW({
        storeId = storeApi->createStore(
            reader->getString("Context_1.contextId"),
            std::vector<core::UserWithPubKey>{userOf(SUGConnectionType::SUGUser1)},
            std::vector<core::UserWithPubKey>{userOf(SUGConnectionType::SUGUser1)},
            core::Buffer::from("two_groups_public"),
            core::Buffer::from("two_groups_private"),
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
    ASSERT_FALSE(storeId.empty());

    store::Store s;
    EXPECT_NO_THROW({ s = storeApi->getStore(storeId); });
    EXPECT_EQ(s.statusCode, 0);
    EXPECT_EQ(s.groups.size(), 2);
    bool found1 = false, found2 = false;
    for (const auto& g : s.groups) {
        if (g.groupId == group_1.groupId && g.role == "user") found1 = true;
        if (g.groupId == group_2.groupId && g.role == "manager") found2 = true;
    }
    EXPECT_TRUE(found1);
    EXPECT_TRUE(found2);
}

TEST_F(StoreUsingGroupsTest, createStore_without_groups_has_empty_groups_field) {
    std::string storeId;
    EXPECT_NO_THROW({
        storeId = storeApi->createStore(
            reader->getString("Context_1.contextId"),
            std::vector<core::UserWithPubKey>{userOf(SUGConnectionType::SUGUser1)},
            std::vector<core::UserWithPubKey>{userOf(SUGConnectionType::SUGUser1)},
            core::Buffer::from("no_groups_public"),
            core::Buffer::from("no_groups_private")
        );
    });
    ASSERT_FALSE(storeId.empty());

    store::Store s;
    EXPECT_NO_THROW({ s = storeApi->getStore(storeId); });
    EXPECT_EQ(s.statusCode, 0);
    EXPECT_EQ(s.groups.size(), 0);
}

TEST_F(StoreUsingGroupsTest, updateStore_add_group) {
    std::string storeId;
    EXPECT_NO_THROW({
        storeId = storeApi->createStore(
            reader->getString("Context_1.contextId"),
            std::vector<core::UserWithPubKey>{userOf(SUGConnectionType::SUGUser1)},
            std::vector<core::UserWithPubKey>{userOf(SUGConnectionType::SUGUser1)},
            core::Buffer::from("before_group"),
            core::Buffer::from("before_group_private")
        );
    });
    ASSERT_FALSE(storeId.empty());

    store::Store s;
    EXPECT_NO_THROW({ s = storeApi->getStore(storeId); });
    EXPECT_EQ(s.groups.size(), 0);

    group::Group group_1;
    ASSERT_NO_THROW({ group_1 = groupApi->getGroup(reader->getString("Group_1.groupId")); });
    ASSERT_EQ(group_1.statusCode, 0);

    EXPECT_NO_THROW({
        storeApi->updateStore(
            storeId,
            std::vector<core::UserWithPubKey>{userOf(SUGConnectionType::SUGUser1)},
            std::vector<core::UserWithPubKey>{userOf(SUGConnectionType::SUGUser1)},
            core::Buffer::from("after_group"),
            core::Buffer::from("after_group_private"),
            1,
            false,
            false,
            std::nullopt,
            std::vector<core::GroupGrantWithKey>{core::GroupGrantWithKey{
                .groupId = group_1.groupId, .role = "user", .groupPubKey = group_1.groupPubKey
            }}
        );
    });

    store::Store updated;
    EXPECT_NO_THROW({ updated = storeApi->getStore(storeId); });
    EXPECT_EQ(updated.statusCode, 0);
    EXPECT_EQ(updated.publicMeta.stdString(), "after_group");
    EXPECT_EQ(updated.groups.size(), 1);
    if (updated.groups.size() == 1) {
        EXPECT_EQ(updated.groups[0].groupId, group_1.groupId);
        EXPECT_EQ(updated.groups[0].role, "user");
    }
}

TEST_F(StoreUsingGroupsTest, updateStore_remove_group) {
    // Group_2 has user_1 and user_2, so removing the grant is observable from user_2's side.
    group::Group group_2;
    ASSERT_NO_THROW({ group_2 = groupApi->getGroup(reader->getString("Group_2.groupId")); });
    ASSERT_EQ(group_2.statusCode, 0);

    // policy.get="all" so user_2 can always call getStore without throwing; after group removal it
    // receives statusCode!=0 and empty privateMeta because it no longer holds the decryption key.
    core::ContainerPolicy policy;
    policy.get = "all";

    std::string storeId;
    EXPECT_NO_THROW({
        storeId = storeApi->createStore(
            reader->getString("Context_1.contextId"),
            std::vector<core::UserWithPubKey>{userOf(SUGConnectionType::SUGUser1)},
            std::vector<core::UserWithPubKey>{userOf(SUGConnectionType::SUGUser1)},
            core::Buffer::from("with_group"),
            core::Buffer::from("with_group_private"),
            policy,
            std::vector<core::GroupGrantWithKey>{core::GroupGrantWithKey{
                .groupId = group_2.groupId, .role = "user", .groupPubKey = group_2.groupPubKey
            }}
        );
    });
    ASSERT_FALSE(storeId.empty());

    store::Store s;
    EXPECT_NO_THROW({ s = storeApi->getStore(storeId); });
    EXPECT_EQ(s.groups.size(), 1);

    disconnect();
    connectAs(SUGConnectionType::SUGUser2);
    store::Store beforeRemoval;
    EXPECT_NO_THROW({ beforeRemoval = storeApi->getStore(storeId); });
    EXPECT_EQ(beforeRemoval.statusCode, 0);
    EXPECT_FALSE(beforeRemoval.privateMeta.stdString().empty());

    disconnect();
    connectAs(SUGConnectionType::SUGUser1);
    EXPECT_NO_THROW({
        storeApi->updateStore(
            storeId,
            std::vector<core::UserWithPubKey>{userOf(SUGConnectionType::SUGUser1)},
            std::vector<core::UserWithPubKey>{userOf(SUGConnectionType::SUGUser1)},
            core::Buffer::from("no_group_now"),
            core::Buffer::from("no_group_private"),
            1,
            false,
            false,
            std::nullopt,
            std::vector<core::GroupGrantWithKey>{}
        );
    });

    store::Store updated;
    EXPECT_NO_THROW({ updated = storeApi->getStore(storeId); });
    EXPECT_EQ(updated.statusCode, 0);
    EXPECT_EQ(updated.publicMeta.stdString(), "no_group_now");
    EXPECT_EQ(updated.groups.size(), 0);

    disconnect();
    connectAs(SUGConnectionType::SUGUser2);
    store::Store afterRemoval;
    EXPECT_NO_THROW({ afterRemoval = storeApi->getStore(storeId); });
    EXPECT_NE(afterRemoval.statusCode, 0);
    EXPECT_TRUE(afterRemoval.privateMeta.stdString().empty());
}

TEST_F(StoreUsingGroupsTest, updateStore_change_group_role) {
    group::Group group_1;
    ASSERT_NO_THROW({ group_1 = groupApi->getGroup(reader->getString("Group_1.groupId")); });
    ASSERT_EQ(group_1.statusCode, 0);

    std::string storeId;
    ASSERT_NO_THROW({
        storeId = createStoreWithGroups(
            reader->getString("Context_1.contextId"),
            std::vector<core::UserWithPubKey>{userOf(SUGConnectionType::SUGUser1)},
            std::vector<group::Group>{group_1}
        );
    });
    ASSERT_FALSE(storeId.empty());

    EXPECT_NO_THROW({
        storeApi->updateStore(
            storeId,
            std::vector<core::UserWithPubKey>{userOf(SUGConnectionType::SUGUser1)},
            std::vector<core::UserWithPubKey>{userOf(SUGConnectionType::SUGUser1)},
            core::Buffer::from("role_change"),
            core::Buffer::from("role_change_private"),
            1,
            false,
            false,
            std::nullopt,
            std::vector<core::GroupGrantWithKey>{core::GroupGrantWithKey{
                .groupId = group_1.groupId, .role = "manager", .groupPubKey = group_1.groupPubKey
            }}
        );
    });

    store::Store updated;
    EXPECT_NO_THROW({ updated = storeApi->getStore(storeId); });
    EXPECT_EQ(updated.groups.size(), 1);
    if (updated.groups.size() == 1) {
        EXPECT_EQ(updated.groups[0].groupId, group_1.groupId);
        EXPECT_EQ(updated.groups[0].role, "manager");
    }
}

TEST_F(StoreUsingGroupsTest, listStores_includes_groups_field) {
    group::Group group_1;
    ASSERT_NO_THROW({ group_1 = groupApi->getGroup(reader->getString("Group_1.groupId")); });
    ASSERT_EQ(group_1.statusCode, 0);

    std::string storeId;
    ASSERT_NO_THROW({
        storeId = createStoreWithGroups(
            reader->getString("Context_1.contextId"),
            std::vector<core::UserWithPubKey>{userOf(SUGConnectionType::SUGUser1)},
            std::vector<group::Group>{group_1}
        );
    });
    ASSERT_FALSE(storeId.empty());

    core::PagingList<store::Store> list;
    EXPECT_NO_THROW({
        list = storeApi->listStores(
            reader->getString("Context_1.contextId"),
            core::PagingQuery{.skip = 0, .limit = 100, .sortOrder = "desc"}
        );
    });
    bool found = false;
    for (const auto& s : list.readItems) {
        if (s.storeId == storeId) {
            EXPECT_EQ(s.statusCode, 0);
            EXPECT_EQ(s.groups.size(), 1);
            if (s.groups.size() == 1) {
                EXPECT_EQ(s.groups[0].groupId, group_1.groupId);
                EXPECT_EQ(s.groups[0].role, "user");
            }
            found = true;
            break;
        }
    }
    EXPECT_TRUE(found);
}

TEST_F(StoreUsingGroupsTest, createStore_with_invalid_group_pubkey_throws) {
    EXPECT_THROW({
        storeApi->createStore(
            reader->getString("Context_1.contextId"),
            std::vector<core::UserWithPubKey>{userOf(SUGConnectionType::SUGUser1)},
            std::vector<core::UserWithPubKey>{userOf(SUGConnectionType::SUGUser1)},
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

TEST_F(StoreUsingGroupsTest, getFile_via_group_grant) {
    // user_1 creates a store granted to Group_2; user_2 is a Group_2 member.
    group::Group group_2;
    ASSERT_NO_THROW({ group_2 = groupApi->getGroup(reader->getString("Group_2.groupId")); });
    ASSERT_EQ(group_2.statusCode, 0);

    std::string storeId;
    ASSERT_NO_THROW({
        storeId = createStoreWithGroup(
            reader->getString("Context_1.contextId"),
            reader->getString("Login.user_1_id"),
            reader->getString("Login.user_1_pubKey"),
            group_2
        );
    });
    ASSERT_FALSE(storeId.empty());

    std::string fileId;
    ASSERT_NO_THROW({ fileId = uploadFile(storeId, "file_public", "file_private", "file_data"); });
    ASSERT_FALSE(fileId.empty());

    // user_2 can read the file meta and its contents via the group key.
    disconnect();
    connectAs(SUGConnectionType::SUGUser2);
    store::File f;
    EXPECT_NO_THROW({ f = storeApi->getFile(fileId); });
    EXPECT_EQ(f.statusCode, 0);
    EXPECT_EQ(f.privateMeta.stdString(), "file_private");

    std::string content;
    EXPECT_NO_THROW({ content = downloadFile(fileId, f.size); });
    EXPECT_EQ(content, "file_data");
}

TEST_F(StoreUsingGroupsTest, listFiles_via_group_grant) {
    group::Group group_2;
    ASSERT_NO_THROW({ group_2 = groupApi->getGroup(reader->getString("Group_2.groupId")); });
    ASSERT_EQ(group_2.statusCode, 0);

    std::string storeId;
    ASSERT_NO_THROW({
        storeId = createStoreWithGroup(
            reader->getString("Context_1.contextId"),
            reader->getString("Login.user_1_id"),
            reader->getString("Login.user_1_pubKey"),
            group_2
        );
    });
    ASSERT_FALSE(storeId.empty());

    ASSERT_NO_THROW({ uploadFile(storeId, "pub1", "priv1", "data1"); });
    ASSERT_NO_THROW({ uploadFile(storeId, "pub2", "priv2", "data2"); });

    disconnect();
    connectAs(SUGConnectionType::SUGUser2);
    core::PagingList<store::File> list;
    EXPECT_NO_THROW({
        list = storeApi->listFiles(storeId, core::PagingQuery{.skip = 0, .limit = 10, .sortOrder = "desc"});
    });
    EXPECT_EQ(list.totalAvailable, 2);
    for (const auto& f : list.readItems) {
        EXPECT_EQ(f.statusCode, 0);
        EXPECT_FALSE(f.privateMeta.stdString().empty());
    }
}

TEST_F(StoreUsingGroupsTest, files_accessible_by_all_group_members) {
    // Group_3 has user_1, user_2 and user_3.
    group::Group group_3;
    ASSERT_NO_THROW({ group_3 = groupApi->getGroup(reader->getString("Group_3.groupId")); });
    ASSERT_EQ(group_3.statusCode, 0);

    std::string storeId;
    ASSERT_NO_THROW({
        storeId = createStoreWithGroup(
            reader->getString("Context_1.contextId"),
            reader->getString("Login.user_1_id"),
            reader->getString("Login.user_1_pubKey"),
            group_3
        );
    });
    ASSERT_FALSE(storeId.empty());

    std::string fileId;
    ASSERT_NO_THROW({ fileId = uploadFile(storeId, "shared_public", "shared_private", "shared_data"); });
    ASSERT_FALSE(fileId.empty());

    disconnect();
    connectAs(SUGConnectionType::SUGUser2);
    store::File fUser2;
    EXPECT_NO_THROW({ fUser2 = storeApi->getFile(fileId); });
    EXPECT_EQ(fUser2.statusCode, 0);
    EXPECT_EQ(fUser2.privateMeta.stdString(), "shared_private");
    std::string contentUser2;
    EXPECT_NO_THROW({ contentUser2 = downloadFile(fileId, fUser2.size); });
    EXPECT_EQ(contentUser2, "shared_data");

    disconnect();
    connectAs(SUGConnectionType::SUGUser3);
    store::File fUser3;
    EXPECT_NO_THROW({ fUser3 = storeApi->getFile(fileId); });
    EXPECT_EQ(fUser3.statusCode, 0);
    EXPECT_EQ(fUser3.privateMeta.stdString(), "shared_private");
    std::string contentUser3;
    EXPECT_NO_THROW({ contentUser3 = downloadFile(fileId, fUser3.size); });
    EXPECT_EQ(contentUser3, "shared_data");
}

TEST_F(StoreUsingGroupsTest, getFile_lost_after_group_removal) {
    group::Group group_2;
    ASSERT_NO_THROW({ group_2 = groupApi->getGroup(reader->getString("Group_2.groupId")); });
    ASSERT_EQ(group_2.statusCode, 0);

    std::string storeId;
    ASSERT_NO_THROW({
        storeId = createStoreWithGroupPolicyReadAll(
            reader->getString("Context_1.contextId"),
            reader->getString("Login.user_1_id"),
            reader->getString("Login.user_1_pubKey"),
            group_2
        );
    });
    ASSERT_FALSE(storeId.empty());

    std::string fileId;
    ASSERT_NO_THROW({ fileId = uploadFile(storeId, "file_public", "secret_private", "secret_data"); });
    ASSERT_FALSE(fileId.empty());

    disconnect();
    connectAs(SUGConnectionType::SUGUser2);
    store::File beforeRemoval;
    EXPECT_NO_THROW({ beforeRemoval = storeApi->getFile(fileId); });
    EXPECT_EQ(beforeRemoval.statusCode, 0);
    EXPECT_EQ(beforeRemoval.privateMeta.stdString(), "secret_private");

    // user_1 drops the grant, which forces a new container key.
    disconnect();
    connectAs(SUGConnectionType::SUGUser1);
    EXPECT_NO_THROW({
        storeApi->updateStore(
            storeId,
            std::vector<core::UserWithPubKey>{userOf(SUGConnectionType::SUGUser1)},
            std::vector<core::UserWithPubKey>{userOf(SUGConnectionType::SUGUser1)},
            core::Buffer::from("no_group"),
            core::Buffer::from("no_group_private"),
            1, false, false,
            std::nullopt,
            std::vector<core::GroupGrantWithKey>{}
        );
    });

    std::string newFileId;
    ASSERT_NO_THROW({ newFileId = uploadFile(storeId, "new_public", "new_private", "new_data"); });
    ASSERT_FALSE(newFileId.empty());

    // Historical group key entries are preserved for old key versions, so user_2 can still decrypt
    // the file that was uploaded while the group had access — but not the one written after.
    disconnect();
    connectAs(SUGConnectionType::SUGUser2);
    store::File afterRemoval;
    EXPECT_NO_THROW({ afterRemoval = storeApi->getFile(fileId); });
    EXPECT_EQ(afterRemoval.statusCode, 0);
    EXPECT_EQ(afterRemoval.privateMeta.stdString(), "secret_private");

    store::File newFile;
    EXPECT_NO_THROW({ newFile = storeApi->getFile(newFileId); });
    EXPECT_NE(newFile.statusCode, 0);
    EXPECT_TRUE(newFile.privateMeta.stdString().empty());
}

TEST_F(StoreUsingGroupsTest, user_added_to_group_gains_access_to_store_and_files) {
    // Group_2 has user_1 + user_2; user_3 is not yet a member.
    group::Group group_2;
    ASSERT_NO_THROW({ group_2 = groupApi->getGroup(reader->getString("Group_2.groupId")); });
    ASSERT_EQ(group_2.statusCode, 0);

    std::string storeId;
    ASSERT_NO_THROW({
        storeId = createStoreWithGroupPolicyReadAll(
            reader->getString("Context_1.contextId"),
            reader->getString("Login.user_1_id"),
            reader->getString("Login.user_1_pubKey"),
            group_2
        );
    });
    ASSERT_FALSE(storeId.empty());

    std::string fileId;
    ASSERT_NO_THROW({ fileId = uploadFile(storeId, "file_pub", "file_priv", "file_data"); });
    ASSERT_FALSE(fileId.empty());

    disconnect();
    connectAs(SUGConnectionType::SUGUser3);
    store::Store sBefore;
    EXPECT_NO_THROW({ sBefore = storeApi->getStore(storeId); });
    EXPECT_NE(sBefore.statusCode, 0);
    store::File fBefore;
    EXPECT_NO_THROW({ fBefore = storeApi->getFile(fileId); });
    EXPECT_NE(fBefore.statusCode, 0);

    // Seat user_3's leaf in the key tree — updateGroup would only re-wrap the group's metadata key.
    disconnect();
    connectAs(SUGConnectionType::SUGUser1);
    EXPECT_NO_THROW({
        groupApi->addGroupMember(
            reader->getString("Group_2.groupId"),
            userOf(SUGConnectionType::SUGUser3),
            false, // asManager
            std::vector<core::UserWithPubKey>{
                userOf(SUGConnectionType::SUGUser1),
                userOf(SUGConnectionType::SUGUser2),
                userOf(SUGConnectionType::SUGUser3)
            },
            std::vector<core::UserWithPubKey>{userOf(SUGConnectionType::SUGUser1)},
            group_2.publicMeta,
            group_2.privateMeta
        );
    });

    disconnect();
    connectAs(SUGConnectionType::SUGUser3);
    store::Store sAfter;
    EXPECT_NO_THROW({ sAfter = storeApi->getStore(storeId); });
    EXPECT_EQ(sAfter.statusCode, 0);
    store::File fAfter;
    EXPECT_NO_THROW({ fAfter = storeApi->getFile(fileId); });
    EXPECT_EQ(fAfter.statusCode, 0);
    EXPECT_EQ(fAfter.privateMeta.stdString(), "file_priv");
}

TEST_F(StoreUsingGroupsTest, direct_member_of_granted_group_reads_and_updates) {
    // user_1 is the only direct member of the Store *and* a member of granted Group_1, so every keyId opens
    // from `keys` and the group branch is skipped. `updateStore` is the interesting half: `verifyKeysSecret`
    // fails on any non-zero status, so an unresolved group entry there is the difference between an update
    // and an exception.
    group::Group group_1;
    ASSERT_NO_THROW({ group_1 = groupApi->getGroup(reader->getString("Group_1.groupId")); });
    ASSERT_EQ(group_1.statusCode, 0);

    std::string storeId;
    ASSERT_NO_THROW({
        storeId = createStoreWithGroups(
            reader->getString("Context_1.contextId"),
            std::vector<core::UserWithPubKey>{userOf(SUGConnectionType::SUGUser1)},
            std::vector<group::Group>{group_1}
        );
    });
    ASSERT_FALSE(storeId.empty());

    std::string fileId;
    ASSERT_NO_THROW({ fileId = uploadFile(storeId, "direct_public", "direct_private", "direct_data"); });
    ASSERT_FALSE(fileId.empty());

    store::Store s;
    EXPECT_NO_THROW({ s = storeApi->getStore(storeId); });
    EXPECT_EQ(s.statusCode, 0);
    EXPECT_EQ(s.groups.size(), 1);

    store::File f;
    EXPECT_NO_THROW({ f = storeApi->getFile(fileId); });
    EXPECT_EQ(f.statusCode, 0);
    std::string content;
    EXPECT_NO_THROW({ content = downloadFile(fileId, f.size); });
    EXPECT_EQ(content, "direct_data");

    EXPECT_NO_THROW({
        storeApi->updateStore(
            storeId,
            std::vector<core::UserWithPubKey>{userOf(SUGConnectionType::SUGUser1)},
            std::vector<core::UserWithPubKey>{userOf(SUGConnectionType::SUGUser1)},
            core::Buffer::from("direct_updated_public"),
            core::Buffer::from("direct_updated_private"),
            s.version,
            false,
            false,
            std::nullopt,
            std::vector<core::GroupGrantWithKey>{{
                .groupId = group_1.groupId, .role = "user", .groupPubKey = group_1.groupPubKey
            }}
        );
    });

    store::Store updated;
    EXPECT_NO_THROW({ updated = storeApi->getStore(storeId); });
    EXPECT_EQ(updated.statusCode, 0);
    EXPECT_EQ(updated.privateMeta.stdString(), "direct_updated_private");
}

TEST_F(StoreUsingGroupsTest, caller_in_no_granted_group_reads_via_direct_key) {
    // The Store grants Group_1, whose only member is user_1. user_2 is a direct member and belongs to no
    // grantee group, so the bridge serves it `groupKeys: []` — the read has to be served entirely from its
    // own key wrap.
    group::Group group_1;
    ASSERT_NO_THROW({ group_1 = groupApi->getGroup(reader->getString("Group_1.groupId")); });
    ASSERT_EQ(group_1.statusCode, 0);

    std::string storeId;
    ASSERT_NO_THROW({
        storeId = createStoreWithGroups(
            reader->getString("Context_1.contextId"),
            std::vector<core::UserWithPubKey>{
                userOf(SUGConnectionType::SUGUser1), userOf(SUGConnectionType::SUGUser2)
            },
            std::vector<group::Group>{group_1}
        );
    });
    ASSERT_FALSE(storeId.empty());

    std::string fileId;
    ASSERT_NO_THROW({ fileId = uploadFile(storeId, "nogroup_public", "nogroup_private", "nogroup_data"); });
    ASSERT_FALSE(fileId.empty());

    disconnect();
    connectAs(SUGConnectionType::SUGUser2);

    store::Store s;
    EXPECT_NO_THROW({ s = storeApi->getStore(storeId); });
    EXPECT_EQ(s.statusCode, 0);
    // `groups` stays unnarrowed, so user_2 still sees the grant it is not part of.
    EXPECT_EQ(s.groups.size(), 1);

    store::File f;
    EXPECT_NO_THROW({ f = storeApi->getFile(fileId); });
    EXPECT_EQ(f.statusCode, 0);
    EXPECT_EQ(f.privateMeta.stdString(), "nogroup_private");
}

TEST_F(StoreUsingGroupsTest, caller_in_two_granted_groups_reads) {
    // The Store grants Group_2 and Group_3 and wraps its key to user_1 only. user_2 belongs to both grantee
    // groups, so narrowing leaves it two entries at the same keyId — with no direct wrap to fall back on,
    // one of them has to carry the read.
    group::Group group_2, group_3;
    ASSERT_NO_THROW({ group_2 = groupApi->getGroup(reader->getString("Group_2.groupId")); });
    ASSERT_NO_THROW({ group_3 = groupApi->getGroup(reader->getString("Group_3.groupId")); });
    ASSERT_EQ(group_2.statusCode, 0);
    ASSERT_EQ(group_3.statusCode, 0);

    std::string storeId;
    ASSERT_NO_THROW({
        storeId = createStoreWithGroups(
            reader->getString("Context_1.contextId"),
            std::vector<core::UserWithPubKey>{userOf(SUGConnectionType::SUGUser1)},
            std::vector<group::Group>{group_2, group_3}
        );
    });
    ASSERT_FALSE(storeId.empty());

    std::string fileId;
    ASSERT_NO_THROW({ fileId = uploadFile(storeId, "twogroups_public", "twogroups_private", "twogroups_data"); });
    ASSERT_FALSE(fileId.empty());

    disconnect();
    connectAs(SUGConnectionType::SUGUser2);

    store::Store s;
    EXPECT_NO_THROW({ s = storeApi->getStore(storeId); });
    EXPECT_EQ(s.statusCode, 0);

    store::File f;
    EXPECT_NO_THROW({ f = storeApi->getFile(fileId); });
    EXPECT_EQ(f.statusCode, 0);
    EXPECT_EQ(f.privateMeta.stdString(), "twogroups_private");
}

TEST_F(StoreUsingGroupsTest, rotateStoreKeys_covers_a_grantee_group_the_caller_did_not_name) {
    // The Store grants Group_2. user_2 re-keys naming no groups at all, and the new key must still be re-wrapped
    // to Group_2 — the grantee list comes from the Store, not from the caller's argument.
    //
    // The grantee is a group the caller belongs to, and that is a constraint rather than a convenience: wrapping
    // a key to a group needs its current epoch and public key, and a Bridge running the default group policy
    // (`get: "user"`, `listAll: "none"`) hands those to members only. Re-keying a container granted to a group
    // the caller is not in therefore cannot work — `resolveGroupEpochs` throws `UnresolvedGroupGranteeException`
    // — so do not "restore" this test to Group_1, which holds user_1 alone.
    group::Group granteeGroup;
    ASSERT_NO_THROW({ granteeGroup = groupApi->getGroup(reader->getString("Group_2.groupId")); });
    ASSERT_EQ(granteeGroup.statusCode, 0);

    std::string storeId;
    ASSERT_NO_THROW({
        storeId = createStoreWithGroups(
            reader->getString("Context_1.contextId"),
            std::vector<core::UserWithPubKey>{
                userOf(SUGConnectionType::SUGUser1), userOf(SUGConnectionType::SUGUser2)
            },
            std::vector<group::Group>{granteeGroup}
        );
    });
    ASSERT_FALSE(storeId.empty());

    store::Store before;
    ASSERT_NO_THROW({ before = storeApi->getStore(storeId); });
    ASSERT_EQ(before.statusCode, 0);

    // user_2 re-keys without naming any group at all.
    disconnect();
    connectAs(SUGConnectionType::SUGUser2);
    EXPECT_NO_THROW({
        storeApi->rotateStoreKeys(
            storeId,
            std::vector<core::UserWithPubKey>{
                userOf(SUGConnectionType::SUGUser1), userOf(SUGConnectionType::SUGUser2)
            },
            std::vector<core::UserWithPubKey>{
                userOf(SUGConnectionType::SUGUser1), userOf(SUGConnectionType::SUGUser2)
            },
            before.version,
            false,
            std::vector<core::GroupGrantWithKey>{}
        );
    });

    // The grant survives the re-key, and user_1 — who reads through the group — still resolves the new key.
    disconnect();
    connectAs(SUGConnectionType::SUGUser1);
    store::Store after;
    EXPECT_NO_THROW({ after = storeApi->getStore(storeId); });
    EXPECT_EQ(after.statusCode, 0);
    EXPECT_EQ(after.groups.size(), 1);
    if (after.groups.size() == 1) {
        EXPECT_EQ(after.groups[0].groupId, granteeGroup.groupId);
    }

    // A file written under the new key is readable, proving the re-key produced a usable key.
    std::string fileId;
    ASSERT_NO_THROW({ fileId = uploadFile(storeId, "post_rekey_pub", "post_rekey_priv", "post_rekey_data"); });
    store::File f;
    EXPECT_NO_THROW({ f = storeApi->getFile(fileId); });
    EXPECT_EQ(f.statusCode, 0);
    EXPECT_EQ(f.privateMeta.stdString(), "post_rekey_priv");
}

TEST_F(StoreUsingGroupsTest, rotateStoreKeys_clears_staleGroups_after_the_group_advances_its_epoch) {
    // Group G at epoch 1 is granted the Store. Removing a member advances G to epoch 2, which leaves the
    // Store's key wrapped to a superseded epoch — the bridge reports that as `staleGroups`. A re-key
    // re-wraps to the current epoch and must clear it.
    std::string groupId;
    ASSERT_NO_THROW({
        groupId = groupApi->createGroup(
            reader->getString("Context_1.contextId"),
            std::vector<core::UserWithPubKey>{
                userOf(SUGConnectionType::SUGUser1),
                userOf(SUGConnectionType::SUGUser2),
                userOf(SUGConnectionType::SUGUser3)
            },
            std::vector<core::UserWithPubKey>{userOf(SUGConnectionType::SUGUser1)},
            core::Buffer::from("grp_pub"),
            core::Buffer::from("grp_priv")
        );
    });
    ASSERT_FALSE(groupId.empty());

    group::Group group;
    ASSERT_NO_THROW({ group = groupApi->getGroup(groupId); });
    ASSERT_EQ(group.statusCode, 0);
    ASSERT_EQ(group.keyVersion, 1);

    std::string storeId;
    ASSERT_NO_THROW({
        storeId = createStoreWithGroups(
            reader->getString("Context_1.contextId"),
            std::vector<core::UserWithPubKey>{userOf(SUGConnectionType::SUGUser1)},
            std::vector<group::Group>{group}
        );
    });
    ASSERT_FALSE(storeId.empty());

    std::string oldEpochFileId;
    ASSERT_NO_THROW({
        oldEpochFileId = uploadFile(storeId, "old_epoch_pub", "old_epoch_priv", "old_epoch_data");
    });
    ASSERT_FALSE(oldEpochFileId.empty());

    ASSERT_NO_THROW({
        groupApi->removeGroupMember(
            groupId,
            reader->getString("Login.user_3_id"),
            std::vector<core::UserWithPubKey>{
                userOf(SUGConnectionType::SUGUser1), userOf(SUGConnectionType::SUGUser2)
            },
            std::vector<core::UserWithPubKey>{userOf(SUGConnectionType::SUGUser1)},
            core::Buffer::from("grp_removed_pub"),
            core::Buffer::from("grp_removed_priv")
        );
    });

    group::Group rotatedGroup;
    ASSERT_NO_THROW({ rotatedGroup = groupApi->getGroup(groupId); });
    ASSERT_EQ(rotatedGroup.statusCode, 0);
    ASSERT_EQ(rotatedGroup.keyVersion, 2);

    store::Store stale;
    ASSERT_NO_THROW({ stale = storeApi->getStore(storeId); });
    ASSERT_EQ(stale.statusCode, 0);
    EXPECT_EQ(stale.staleGroups.size(), 1);
    if (stale.staleGroups.size() == 1) {
        EXPECT_EQ(stale.staleGroups[0], groupId);
    }

    EXPECT_NO_THROW({
        storeApi->rotateStoreKeys(
            storeId,
            std::vector<core::UserWithPubKey>{userOf(SUGConnectionType::SUGUser1)},
            std::vector<core::UserWithPubKey>{userOf(SUGConnectionType::SUGUser1)},
            stale.version,
            false,
            std::vector<core::GroupGrantWithKey>{}
        );
    });

    store::Store fresh;
    EXPECT_NO_THROW({ fresh = storeApi->getStore(storeId); });
    EXPECT_EQ(fresh.statusCode, 0);
    EXPECT_EQ(fresh.staleGroups.size(), 0);
    EXPECT_EQ(fresh.groups.size(), 1);

    // user_2 is still in G at epoch 2 and was never a direct Store member, so this read can only be served
    // through the re-wrapped group entry.
    disconnect();
    connectAs(SUGConnectionType::SUGUser2);
    store::File oldEpochFile;
    EXPECT_NO_THROW({ oldEpochFile = storeApi->getFile(oldEpochFileId); });
    EXPECT_EQ(oldEpochFile.statusCode, 0);
    EXPECT_EQ(oldEpochFile.privateMeta.stdString(), "old_epoch_priv");
}

TEST_F(StoreUsingGroupsTest, uploading_a_file_auto_rotates_a_stale_store_key) {
    // The same ground as the test above, minus the `rotateStoreKeys` call: a stale key is not the caller's
    // problem to notice. Closing the file re-keys the Store with its own roster and writes under the new key.
    std::string groupId;
    ASSERT_NO_THROW({
        groupId = groupApi->createGroup(
            reader->getString("Context_1.contextId"),
            std::vector<core::UserWithPubKey>{
                userOf(SUGConnectionType::SUGUser1),
                userOf(SUGConnectionType::SUGUser2),
                userOf(SUGConnectionType::SUGUser3)
            },
            std::vector<core::UserWithPubKey>{userOf(SUGConnectionType::SUGUser1)},
            core::Buffer::from("auto_grp_pub"),
            core::Buffer::from("auto_grp_priv")
        );
    });
    ASSERT_FALSE(groupId.empty());

    group::Group group;
    ASSERT_NO_THROW({ group = groupApi->getGroup(groupId); });
    ASSERT_EQ(group.statusCode, 0);

    std::string storeId;
    ASSERT_NO_THROW({
        storeId = createStoreWithGroups(
            reader->getString("Context_1.contextId"),
            std::vector<core::UserWithPubKey>{userOf(SUGConnectionType::SUGUser1)},
            std::vector<group::Group>{group}
        );
    });
    ASSERT_FALSE(storeId.empty());

    ASSERT_NO_THROW({
        groupApi->removeGroupMember(
            groupId,
            reader->getString("Login.user_3_id"),
            std::vector<core::UserWithPubKey>{
                userOf(SUGConnectionType::SUGUser1), userOf(SUGConnectionType::SUGUser2)
            },
            std::vector<core::UserWithPubKey>{userOf(SUGConnectionType::SUGUser1)},
            core::Buffer::from("auto_grp_removed_pub"),
            core::Buffer::from("auto_grp_removed_priv")
        );
    });

    store::Store stale;
    ASSERT_NO_THROW({ stale = storeApi->getStore(storeId); });
    ASSERT_EQ(stale.statusCode, 0);
    ASSERT_EQ(stale.staleGroups.size(), 1);
    ASSERT_EQ(stale.staleGroups[0], groupId);

    std::string fileId;
    EXPECT_NO_THROW({ fileId = uploadFile(storeId, "auto_pub", "auto_priv", "auto_data"); });
    EXPECT_FALSE(fileId.empty());

    store::Store rekeyed;
    ASSERT_NO_THROW({ rekeyed = storeApi->getStore(storeId); });
    EXPECT_EQ(rekeyed.statusCode, 0);
    EXPECT_TRUE(rekeyed.staleGroups.empty());
    // Exactly one re-key: a rotation appends one history entry and nothing else wrote to the Store.
    EXPECT_EQ(rekeyed.version, stale.version + 1);
    EXPECT_EQ(rekeyed.users, stale.users);
    EXPECT_EQ(rekeyed.managers, stale.managers);

    // user_2 is in G at its new epoch and holds no direct entry: reading proves the new key was wrapped to the
    // epoch G actually moved to, not the one the Store was stuck on.
    disconnect();
    connectAs(SUGConnectionType::SUGUser2);
    store::File file;
    EXPECT_NO_THROW({ file = storeApi->getFile(fileId); });
    EXPECT_EQ(file.statusCode, 0);
    EXPECT_EQ(downloadFile(fileId, (int64_t)std::string("auto_data").size()), "auto_data");
}
