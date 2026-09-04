#include <gtest/gtest.h>
#include "../../utils/BaseTest.hpp"
#include <privmx/endpoint/core/Exception.hpp>
#include <Poco/Util/IniFileConfiguration.h>
#include <privmx/endpoint/core/EventQueueImpl.hpp>
#include <privmx/utils/Utils.hpp>
#include <privmx/endpoint/core/VarSerializer.hpp>
#include <privmx/endpoint/core/Connection.hpp>
#include <privmx/endpoint/group/GroupApi.hpp>
#include <privmx/endpoint/group/VarSerializer.hpp>
#include <privmx/endpoint/core/CoreException.hpp>

using namespace privmx::endpoint;

enum GroupConnectionType {
    GUser1,
    GUser2
};

class GroupTest : public privmx::test::BaseTest {
protected:
    GroupTest() : BaseTest(privmx::test::BaseTestMode::online) {}
    void connectAs(GroupConnectionType type) {
        if (type == GroupConnectionType::GUser1) {
            connection = std::make_shared<core::Connection>(
                core::Connection::connect(
                    reader->getString("Login.user_1_privKey"),
                    reader->getString("Login.solutionId"),
                    getPlatformUrl(reader->getString("Login.instanceUrl"))
                )
            );
        } else {
            connection = std::make_shared<core::Connection>(
                core::Connection::connect(
                    reader->getString("Login.user_2_privKey"),
                    reader->getString("Login.solutionId"),
                    getPlatformUrl(reader->getString("Login.instanceUrl"))
                )
            );
        }
        groupApi = std::make_shared<group::GroupApi>(group::GroupApi::create(*connection));
    }
    void disconnect() {
        connection->disconnect();
        connection.reset();
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
    }
    void customTearDown() override {
        connection.reset();
        groupApi.reset();
        reader.reset();
        core::EventQueueImpl::getInstance()->clear();
    }
    std::shared_ptr<core::Connection> connection;
    std::shared_ptr<group::GroupApi> groupApi;
    Poco::Util::IniFileConfiguration::Ptr reader;
    core::VarSerializer _serializer = core::VarSerializer({});
};

TEST_F(GroupTest, setup) {
}

TEST_F(GroupTest, getGroup) {
    group::Group group;
    // incorrect groupId
    EXPECT_THROW({
        groupApi->getGroup(reader->getString("Context_1.contextId"));
    }, core::Exception);
    // correct groupId
    EXPECT_NO_THROW({
        group = groupApi->getGroup(reader->getString("Group_1.groupId"));
    });
    EXPECT_EQ(group.contextId, reader->getString("Group_1.contextId"));
    EXPECT_EQ(group.groupId, reader->getString("Group_1.groupId"));
    EXPECT_NE(group.groupPubKey, "");
    EXPECT_EQ(group.createDate, reader->getInt64("Group_1.createDate"));
    EXPECT_EQ(group.creator, reader->getString("Group_1.creator"));
    EXPECT_EQ(group.lastModificationDate, reader->getInt64("Group_1.lastModificationDate"));
    EXPECT_EQ(group.lastModifier, reader->getString("Group_1.lastModifier"));
    EXPECT_EQ(group.version, reader->getInt64("Group_1.version"));
    EXPECT_EQ(group.publicMeta.stdString(), privmx::utils::Hex::toString(reader->getString("Group_1.publicMeta_inHex")));
    EXPECT_EQ(group.privateMeta.stdString(), privmx::utils::Hex::toString(reader->getString("Group_1.privateMeta_inHex")));
    EXPECT_EQ(group.statusCode, 0);
    EXPECT_EQ(group.users.size(), 1);
    if (group.users.size() == 1) {
        EXPECT_EQ(group.users[0], reader->getString("Login.user_1_id"));
    }
    EXPECT_EQ(group.managers.size(), 1);
    if (group.managers.size() == 1) {
        EXPECT_EQ(group.managers[0], reader->getString("Login.user_1_id"));
    }
}

TEST_F(GroupTest, listGroups_incorrect_input_data) {
    // incorrect contextId
    EXPECT_THROW({
        groupApi->listGroups(
            reader->getString("Group_1.groupId"),
            core::PagingQuery{.skip = 0, .limit = 10, .sortOrder = "asc"}
        );
    }, core::Exception);
    // invalid sortOrder
    EXPECT_THROW({
        groupApi->listGroups(
            reader->getString("Context_1.contextId"),
            core::PagingQuery{.skip = 0, .limit = 10, .sortOrder = "bad_sort_order"}
        );
    }, core::Exception);
}

TEST_F(GroupTest, listGroups_correct_input_data) {
    core::PagingList<group::GroupSummary> groupsList;
    EXPECT_NO_THROW({
        groupsList = groupApi->listGroups(
            reader->getString("Context_1.contextId"),
            core::PagingQuery{.skip = 0, .limit = 10, .sortOrder = "asc"}
        );
    });
    // pre-created at least 2
    EXPECT_GE(groupsList.totalAvailable, 2);
    EXPECT_GE(groupsList.readItems.size(), 2);
    for (const auto& g : groupsList.readItems) {
        EXPECT_EQ(g.contextId, reader->getString("Context_1.contextId"));
        EXPECT_FALSE(g.groupId.empty());
        EXPECT_FALSE(g.groupPubKey.empty());
        EXPECT_GE(g.keyVersion, 0);
    }
    // limit=1
    core::PagingList<group::GroupSummary> groupsPage;
    EXPECT_NO_THROW({
        groupsPage = groupApi->listGroups(
            reader->getString("Context_1.contextId"),
            core::PagingQuery{.skip = 0, .limit = 1, .sortOrder = "asc"}
        );
    });
    EXPECT_GE(groupsPage.totalAvailable, 2);
    EXPECT_EQ(groupsPage.readItems.size(), 1);
}


TEST_F(GroupTest, createGroup_incorrect_data) {
    // incorrect contextId
    EXPECT_THROW({
        groupApi->createGroup(
            reader->getString("Group_1.groupId"),
            std::vector<core::UserWithPubKey>{core::UserWithPubKey{
                .userId = reader->getString("Login.user_1_id"),
                .pubKey = reader->getString("Login.user_1_pubKey")
            }},
            std::vector<core::UserWithPubKey>{core::UserWithPubKey{
                .userId = reader->getString("Login.user_1_id"),
                .pubKey = reader->getString("Login.user_1_pubKey")
            }},
            core::Buffer::from("public"),
            core::Buffer::from("private")
        );
    }, core::Exception);
    // user pubKey mismatch
    EXPECT_THROW({
        groupApi->createGroup(
            reader->getString("Context_1.contextId"),
            std::vector<core::UserWithPubKey>{core::UserWithPubKey{
                .userId = reader->getString("Login.user_1_id"),
                .pubKey = reader->getString("Login.user_2_pubKey")
            }},
            std::vector<core::UserWithPubKey>{core::UserWithPubKey{
                .userId = reader->getString("Login.user_1_id"),
                .pubKey = reader->getString("Login.user_1_pubKey")
            }},
            core::Buffer::from("public"),
            core::Buffer::from("private")
        );
    }, core::Exception);
    // manager pubKey mismatch
    EXPECT_THROW({
        groupApi->createGroup(
            reader->getString("Context_1.contextId"),
            std::vector<core::UserWithPubKey>{core::UserWithPubKey{
                .userId = reader->getString("Login.user_1_id"),
                .pubKey = reader->getString("Login.user_1_pubKey")
            }},
            std::vector<core::UserWithPubKey>{core::UserWithPubKey{
                .userId = reader->getString("Login.user_1_id"),
                .pubKey = reader->getString("Login.user_2_pubKey")
            }},
            core::Buffer::from("public"),
            core::Buffer::from("private")
        );
    }, core::Exception);
    // no managers
    EXPECT_THROW({
        groupApi->createGroup(
            reader->getString("Context_1.contextId"),
            std::vector<core::UserWithPubKey>{core::UserWithPubKey{
                .userId = reader->getString("Login.user_1_id"),
                .pubKey = reader->getString("Login.user_1_pubKey")
            }},
            std::vector<core::UserWithPubKey>{},
            core::Buffer::from("public"),
            core::Buffer::from("private")
        );
    }, core::Exception);
}

TEST_F(GroupTest, createGroup) {
    std::string groupId;
    group::Group group;
    // different users and managers
    EXPECT_NO_THROW({
        groupId = groupApi->createGroup(
            reader->getString("Context_1.contextId"),
            std::vector<core::UserWithPubKey>{core::UserWithPubKey{
                .userId = reader->getString("Login.user_2_id"),
                .pubKey = reader->getString("Login.user_2_pubKey")
            }},
            std::vector<core::UserWithPubKey>{core::UserWithPubKey{
                .userId = reader->getString("Login.user_1_id"),
                .pubKey = reader->getString("Login.user_1_pubKey")
            }},
            core::Buffer::from("public"),
            core::Buffer::from("private")
        );
    });
    ASSERT_FALSE(groupId.empty());
    EXPECT_NO_THROW({
        group = groupApi->getGroup(groupId);
    });
    EXPECT_EQ(group.statusCode, 0);
    EXPECT_EQ(group.contextId, reader->getString("Context_1.contextId"));
    EXPECT_EQ(group.publicMeta.stdString(), "public");
    EXPECT_EQ(group.privateMeta.stdString(), "private");
    EXPECT_EQ(group.version, 1);
    EXPECT_NE(group.groupPubKey, "");
    EXPECT_EQ(group.users.size(), 1);
    if (group.users.size() == 1) {
        EXPECT_EQ(group.users[0], reader->getString("Login.user_2_id"));
    }
    EXPECT_EQ(group.managers.size(), 1);
    if (group.managers.size() == 1) {
        EXPECT_EQ(group.managers[0], reader->getString("Login.user_1_id"));
    }
    // same users and managers
    EXPECT_NO_THROW({
        groupId = groupApi->createGroup(
            reader->getString("Context_1.contextId"),
            std::vector<core::UserWithPubKey>{core::UserWithPubKey{
                .userId = reader->getString("Login.user_1_id"),
                .pubKey = reader->getString("Login.user_1_pubKey")
            }},
            std::vector<core::UserWithPubKey>{core::UserWithPubKey{
                .userId = reader->getString("Login.user_1_id"),
                .pubKey = reader->getString("Login.user_1_pubKey")
            }},
            core::Buffer::from("public2"),
            core::Buffer::from("private2")
        );
    });
    ASSERT_FALSE(groupId.empty());
    EXPECT_NO_THROW({
        group = groupApi->getGroup(groupId);
    });
    EXPECT_EQ(group.statusCode, 0);
    EXPECT_EQ(group.publicMeta.stdString(), "public2");
    EXPECT_EQ(group.privateMeta.stdString(), "private2");
    EXPECT_EQ(group.version, 1);
}

TEST_F(GroupTest, updateGroup_incorrect_data) {
    // incorrect groupId
    EXPECT_THROW({
        groupApi->updateGroup(
            reader->getString("Context_1.contextId"),
            core::Buffer::from("public"),
            core::Buffer::from("private"),
            1
        );
    }, core::Exception);
    // Wrong version. There is no way to push past this: the entry's roster tag commits the version it lands at,
    // so an update built against a moved head could only land a tag no reader would accept.
    EXPECT_THROW({
        groupApi->updateGroup(
            reader->getString("Group_2.groupId"),
            core::Buffer::from("public"),
            core::Buffer::from("private"),
            99
        );
    }, core::Exception);
}

TEST_F(GroupTest, updateGroup_correct_data) {
    group::Group group;
    EXPECT_NO_THROW({
        groupApi->updateGroup(
            reader->getString("Group_1.groupId"),
            core::Buffer::from("updated_public"),
            core::Buffer::from("updated_private"),
            1
        );
    });
    EXPECT_NO_THROW({
        group = groupApi->getGroup(reader->getString("Group_1.groupId"));
    });
    EXPECT_EQ(group.statusCode, 0);
    EXPECT_EQ(group.version, 2);
    EXPECT_EQ(group.publicMeta.stdString(), "updated_public");
    EXPECT_EQ(group.privateMeta.stdString(), "updated_private");
    EXPECT_EQ(group.users.size(), 1);
    EXPECT_EQ(group.managers.size(), 1);
    if (group.managers.size() == 1) {
        EXPECT_EQ(group.managers[0], reader->getString("Login.user_1_id"));
    }
    // A second metadata update, and the roster is still the one the group was created with: updateGroup cannot
    // reach it at all any more. Promoting somebody goes through addGroupMembers/removeGroupMembers.
    EXPECT_NO_THROW({
        groupApi->updateGroup(
            reader->getString("Group_1.groupId"),
            core::Buffer::from("updated_public_2"),
            core::Buffer::from("updated_private_2"),
            2
        );
    });
    EXPECT_NO_THROW({
        group = groupApi->getGroup(reader->getString("Group_1.groupId"));
    });
    EXPECT_EQ(group.statusCode, 0);
    EXPECT_EQ(group.version, 3);
    EXPECT_EQ(group.publicMeta.stdString(), "updated_public_2");
    EXPECT_EQ(group.privateMeta.stdString(), "updated_private_2");
    EXPECT_EQ(group.users.size(), 1);
    EXPECT_EQ(group.managers.size(), 1);
}

TEST_F(GroupTest, updateGroup_chain_integrity) {
    // A three-entry group (create + 2 updates) must pass G1/G2 → statusCode=0
    std::string groupId;
    EXPECT_NO_THROW({
        groupId = groupApi->createGroup(
            reader->getString("Context_1.contextId"),
            std::vector<core::UserWithPubKey>{core::UserWithPubKey{
                .userId = reader->getString("Login.user_1_id"),
                .pubKey = reader->getString("Login.user_1_pubKey")
            }},
            std::vector<core::UserWithPubKey>{core::UserWithPubKey{
                .userId = reader->getString("Login.user_1_id"),
                .pubKey = reader->getString("Login.user_1_pubKey")
            }},
            core::Buffer::from("v1"),
            core::Buffer::from("v1_priv")
        );
    });
    ASSERT_FALSE(groupId.empty());
    // update v1→v2
    EXPECT_NO_THROW({
        groupApi->updateGroup(
            groupId,
            core::Buffer::from("v2"),
            core::Buffer::from("v2_priv"),
            1
        );
    });
    // update v2→v3
    EXPECT_NO_THROW({
        groupApi->updateGroup(
            groupId,
            core::Buffer::from("v3"),
            core::Buffer::from("v3_priv"),
            2
        );
    });
    group::Group group;
    EXPECT_NO_THROW({
        group = groupApi->getGroup(groupId);
    });
    EXPECT_EQ(group.version, 3);
    EXPECT_EQ(group.statusCode, 0);
    EXPECT_EQ(group.publicMeta.stdString(), "v3");
    EXPECT_EQ(group.privateMeta.stdString(), "v3_priv");
}

TEST_F(GroupTest, updateGroup_cannot_skip_the_version_check) {
    // What `updateGroup_force` used to assert, inverted: the escape hatch is gone, so a wrong version is refused
    // and the group is left exactly as it was. The refusal is the feature — an update built against a moved head
    // commits a roster tag for a version it will not land at, and every reader would then reject the group.
    group::Group before;
    ASSERT_NO_THROW({ before = groupApi->getGroup(reader->getString("Group_2.groupId")); });
    EXPECT_THROW({
        groupApi->updateGroup(
            reader->getString("Group_2.groupId"),
            core::Buffer::from("forced"),
            core::Buffer::from("forced_priv"),
            99
        );
    }, core::Exception);
    group::Group after;
    EXPECT_NO_THROW({ after = groupApi->getGroup(reader->getString("Group_2.groupId")); });
    EXPECT_EQ(after.statusCode, 0) << "a refused update must leave the group readable";
    EXPECT_EQ(after.version, before.version);
    EXPECT_EQ(after.publicMeta.stdString(), before.publicMeta.stdString());
}

TEST_F(GroupTest, deleteGroup) {
    std::string groupId = reader->getString("Group_1.groupId");
    EXPECT_NO_THROW({
        groupApi->deleteGroup(groupId);
    });
    // group no longer accessible after delete
    EXPECT_THROW({
        groupApi->getGroup(groupId);
    }, core::Exception);
    // deleting a non-existent groupId
    EXPECT_THROW({
        groupApi->deleteGroup(reader->getString("Context_1.contextId"));
    }, core::Exception);
}

TEST_F(GroupTest, group_member_can_read) {
    // Create group with user_1 as manager, user_2 as member
    std::string groupId;
    EXPECT_NO_THROW({
        groupId = groupApi->createGroup(
            reader->getString("Context_1.contextId"),
            std::vector<core::UserWithPubKey>{
                core::UserWithPubKey{
                    .userId = reader->getString("Login.user_1_id"),
                    .pubKey = reader->getString("Login.user_1_pubKey")
                },
                core::UserWithPubKey{
                    .userId = reader->getString("Login.user_2_id"),
                    .pubKey = reader->getString("Login.user_2_pubKey")
                }
            },
            std::vector<core::UserWithPubKey>{core::UserWithPubKey{
                .userId = reader->getString("Login.user_1_id"),
                .pubKey = reader->getString("Login.user_1_pubKey")
            }},
            core::Buffer::from("shared_public"),
            core::Buffer::from("shared_private")
        );
    });
    ASSERT_FALSE(groupId.empty());
    // Connect as user_2 (member, not manager) and read the group
    disconnect();
    connectAs(GroupConnectionType::GUser2);
    group::Group group;
    EXPECT_NO_THROW({
        group = groupApi->getGroup(groupId);
    });
    EXPECT_EQ(group.statusCode, 0);
    EXPECT_EQ(group.publicMeta.stdString(), "shared_public");
    EXPECT_EQ(group.privateMeta.stdString(), "shared_private");
    EXPECT_EQ(group.groupId, groupId);
}
