#include <gtest/gtest.h>
#include <algorithm>
#include "../../utils/BaseTest.hpp"
#include <privmx/endpoint/core/Exception.hpp>
#include <Poco/Util/IniFileConfiguration.h>
#include <privmx/endpoint/core/EventQueueImpl.hpp>
#include <privmx/utils/Utils.hpp>
#include <privmx/endpoint/core/VarSerializer.hpp>
#include <privmx/endpoint/core/Connection.hpp>
#include <privmx/endpoint/stream/StreamApiLow.hpp>
#include <privmx/endpoint/stream/StreamVarSerializer.hpp>
#include <privmx/endpoint/group/GroupApi.hpp>
#include <privmx/endpoint/group/VarSerializer.hpp>
#include <privmx/endpoint/core/ConvertedExceptions.hpp>
#include <privmx/endpoint/core/CoreException.hpp>
using namespace privmx::endpoint;

enum SRUGConnectionType {
    SRUGUser1,
    SRUGUser2,
    SRUGUser3
};

/**
 * Group coverage for StreamRooms. Publishing and subscribing need a WebRTC implementation, so these tests
 * stay at the container level: grants, decryption of room metadata through a group, re-keying, and the
 * staleGroups signal. The media keys derived from the room key are exercised indirectly - a room that
 * decrypts is a room whose key `extractStreamRoomKeys` could resolve.
 */
class StreamRoomUsingGroupsTest : public privmx::test::BaseTest {
protected:
    StreamRoomUsingGroupsTest() : BaseTest(privmx::test::BaseTestMode::online) {}
    void connectAs(SRUGConnectionType type) {
        std::string privKey;
        if (type == SRUGConnectionType::SRUGUser1) {
            privKey = reader->getString("Login.user_1_privKey");
        } else if (type == SRUGConnectionType::SRUGUser2) {
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
        streamApi = std::make_shared<stream::StreamApiLow>(stream::StreamApiLow::create(*connection, *groupApi));
    }
    void disconnect() {
        connection->disconnect();
        connection.reset();
        streamApi.reset();
        groupApi.reset();
    }
    // One of the fixture's logins as a container names its members - id plus public key, from the same ini.
    core::UserWithPubKey userOf(SRUGConnectionType type) {
        std::string n;
        if (type == SRUGConnectionType::SRUGUser1) {
            n = "1";
        } else if (type == SRUGConnectionType::SRUGUser2) {
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
        streamApi = std::make_shared<stream::StreamApiLow>(stream::StreamApiLow::create(*connection, *groupApi));
    }
    void customTearDown() override {
        connection.reset();
        streamApi.reset();
        groupApi.reset();
        reader.reset();
        core::EventQueueImpl::getInstance()->clear();
    }
    // A StreamRoom whose direct members are `users` (as both users and managers) and whose grantee groups are
    // `groups`. Leaving `groupEpoch` at 0 makes the endpoint resolve each group's current epoch from the Bridge.
    std::string createStreamRoomWithGroups(
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
        return streamApi->createStreamRoom(
            contextId,
            users,
            users,
            core::Buffer::from("group_room_public"),
            core::Buffer::from("group_room_private"),
            core::ContainerPolicyWithoutItem(),
            std::nullopt,
            grants
        );
    }

    std::shared_ptr<core::Connection> connection;
    std::shared_ptr<stream::StreamApiLow> streamApi;
    std::shared_ptr<group::GroupApi> groupApi;
    Poco::Util::IniFileConfiguration::Ptr reader;
    core::VarSerializer _serializer = core::VarSerializer({});
};

TEST_F(StreamRoomUsingGroupsTest, createStreamRoom_with_group_grants) {
    group::Group group_1;
    ASSERT_NO_THROW({ group_1 = groupApi->getGroup(reader->getString("Group_1.groupId")); });
    ASSERT_EQ(group_1.statusCode, 0);
    ASSERT_FALSE(group_1.groupPubKey.empty());

    std::string streamRoomId;
    EXPECT_NO_THROW({
        streamRoomId = streamApi->createStreamRoom(
            reader->getString("Context_1.contextId"),
            std::vector<core::UserWithPubKey>{userOf(SRUGConnectionType::SRUGUser1)},
            std::vector<core::UserWithPubKey>{userOf(SRUGConnectionType::SRUGUser1)},
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
    ASSERT_FALSE(streamRoomId.empty());

    stream::StreamRoom r;
    EXPECT_NO_THROW({ r = streamApi->getStreamRoom(streamRoomId); });
    EXPECT_EQ(r.statusCode, 0);
    EXPECT_EQ(r.publicMeta.stdString(), "public_meta");
    EXPECT_EQ(r.groups.size(), 1);
    if (r.groups.size() == 1) {
        EXPECT_EQ(r.groups[0].groupId, group_1.groupId);
        EXPECT_EQ(r.groups[0].role, "user");
    }
}

TEST_F(StreamRoomUsingGroupsTest, createStreamRoom_with_multiple_group_grants) {
    group::Group group_1, group_2;
    ASSERT_NO_THROW({ group_1 = groupApi->getGroup(reader->getString("Group_1.groupId")); });
    ASSERT_NO_THROW({ group_2 = groupApi->getGroup(reader->getString("Group_2.groupId")); });
    ASSERT_EQ(group_1.statusCode, 0);
    ASSERT_EQ(group_2.statusCode, 0);

    std::string streamRoomId;
    EXPECT_NO_THROW({
        streamRoomId = streamApi->createStreamRoom(
            reader->getString("Context_1.contextId"),
            std::vector<core::UserWithPubKey>{userOf(SRUGConnectionType::SRUGUser1)},
            std::vector<core::UserWithPubKey>{userOf(SRUGConnectionType::SRUGUser1)},
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
    ASSERT_FALSE(streamRoomId.empty());

    stream::StreamRoom r;
    EXPECT_NO_THROW({ r = streamApi->getStreamRoom(streamRoomId); });
    EXPECT_EQ(r.statusCode, 0);
    EXPECT_EQ(r.groups.size(), 2);
    bool found1 = false, found2 = false;
    for (const auto& g : r.groups) {
        if (g.groupId == group_1.groupId && g.role == "user") found1 = true;
        if (g.groupId == group_2.groupId && g.role == "manager") found2 = true;
    }
    EXPECT_TRUE(found1);
    EXPECT_TRUE(found2);
}

TEST_F(StreamRoomUsingGroupsTest, createStreamRoom_without_groups_has_empty_groups_field) {
    std::string streamRoomId;
    EXPECT_NO_THROW({
        streamRoomId = streamApi->createStreamRoom(
            reader->getString("Context_1.contextId"),
            std::vector<core::UserWithPubKey>{userOf(SRUGConnectionType::SRUGUser1)},
            std::vector<core::UserWithPubKey>{userOf(SRUGConnectionType::SRUGUser1)},
            core::Buffer::from("no_groups_public"),
            core::Buffer::from("no_groups_private"),
            std::nullopt
        );
    });
    ASSERT_FALSE(streamRoomId.empty());

    stream::StreamRoom r;
    EXPECT_NO_THROW({ r = streamApi->getStreamRoom(streamRoomId); });
    EXPECT_EQ(r.statusCode, 0);
    EXPECT_EQ(r.groups.size(), 0);
}

TEST_F(StreamRoomUsingGroupsTest, updateStreamRoom_add_group) {
    std::string streamRoomId;
    EXPECT_NO_THROW({
        streamRoomId = streamApi->createStreamRoom(
            reader->getString("Context_1.contextId"),
            std::vector<core::UserWithPubKey>{userOf(SRUGConnectionType::SRUGUser1)},
            std::vector<core::UserWithPubKey>{userOf(SRUGConnectionType::SRUGUser1)},
            core::Buffer::from("before_group"),
            core::Buffer::from("before_group_private"),
            std::nullopt
        );
    });
    ASSERT_FALSE(streamRoomId.empty());

    stream::StreamRoom r;
    EXPECT_NO_THROW({ r = streamApi->getStreamRoom(streamRoomId); });
    EXPECT_EQ(r.groups.size(), 0);

    group::Group group_1;
    ASSERT_NO_THROW({ group_1 = groupApi->getGroup(reader->getString("Group_1.groupId")); });
    ASSERT_EQ(group_1.statusCode, 0);

    EXPECT_NO_THROW({
        streamApi->updateStreamRoom(
            streamRoomId,
            std::vector<core::UserWithPubKey>{userOf(SRUGConnectionType::SRUGUser1)},
            std::vector<core::UserWithPubKey>{userOf(SRUGConnectionType::SRUGUser1)},
            core::Buffer::from("after_group"),
            core::Buffer::from("after_group_private"),
            r.version,
            false,
            false,
            std::nullopt,
            std::vector<core::GroupGrantWithKey>{core::GroupGrantWithKey{
                .groupId = group_1.groupId, .role = "user", .groupPubKey = group_1.groupPubKey
            }}
        );
    });

    stream::StreamRoom updated;
    EXPECT_NO_THROW({ updated = streamApi->getStreamRoom(streamRoomId); });
    EXPECT_EQ(updated.statusCode, 0);
    EXPECT_EQ(updated.publicMeta.stdString(), "after_group");
    EXPECT_EQ(updated.groups.size(), 1);
    if (updated.groups.size() == 1) {
        EXPECT_EQ(updated.groups[0].groupId, group_1.groupId);
        EXPECT_EQ(updated.groups[0].role, "user");
    }
}

TEST_F(StreamRoomUsingGroupsTest, updateStreamRoom_remove_group) {
    group::Group group_2;
    ASSERT_NO_THROW({ group_2 = groupApi->getGroup(reader->getString("Group_2.groupId")); });
    ASSERT_EQ(group_2.statusCode, 0);

    // policy.get="all" so user_2 can always call getStreamRoom without throwing; after group removal it
    // receives statusCode!=0 and empty privateMeta because it no longer holds the decryption key.
    core::ContainerPolicyWithoutItem policy;
    policy.get = "all";

    std::string streamRoomId;
    EXPECT_NO_THROW({
        streamRoomId = streamApi->createStreamRoom(
            reader->getString("Context_1.contextId"),
            std::vector<core::UserWithPubKey>{userOf(SRUGConnectionType::SRUGUser1)},
            std::vector<core::UserWithPubKey>{userOf(SRUGConnectionType::SRUGUser1)},
            core::Buffer::from("with_group"),
            core::Buffer::from("with_group_private"),
            policy,
            std::nullopt,
            std::vector<core::GroupGrantWithKey>{core::GroupGrantWithKey{
                .groupId = group_2.groupId, .role = "user", .groupPubKey = group_2.groupPubKey
            }}
        );
    });
    ASSERT_FALSE(streamRoomId.empty());

    stream::StreamRoom created;
    ASSERT_NO_THROW({ created = streamApi->getStreamRoom(streamRoomId); });
    ASSERT_EQ(created.groups.size(), 1);

    disconnect();
    connectAs(SRUGConnectionType::SRUGUser2);
    stream::StreamRoom beforeRemoval;
    EXPECT_NO_THROW({ beforeRemoval = streamApi->getStreamRoom(streamRoomId); });
    EXPECT_EQ(beforeRemoval.statusCode, 0);
    EXPECT_FALSE(beforeRemoval.privateMeta.stdString().empty());

    disconnect();
    connectAs(SRUGConnectionType::SRUGUser1);
    EXPECT_NO_THROW({
        streamApi->updateStreamRoom(
            streamRoomId,
            std::vector<core::UserWithPubKey>{userOf(SRUGConnectionType::SRUGUser1)},
            std::vector<core::UserWithPubKey>{userOf(SRUGConnectionType::SRUGUser1)},
            core::Buffer::from("no_group_now"),
            core::Buffer::from("no_group_private"),
            created.version,
            false,
            false,
            std::nullopt,
            std::vector<core::GroupGrantWithKey>{}
        );
    });

    stream::StreamRoom updated;
    EXPECT_NO_THROW({ updated = streamApi->getStreamRoom(streamRoomId); });
    EXPECT_EQ(updated.statusCode, 0);
    EXPECT_EQ(updated.groups.size(), 0);

    disconnect();
    connectAs(SRUGConnectionType::SRUGUser2);
    stream::StreamRoom afterRemoval;
    EXPECT_NO_THROW({ afterRemoval = streamApi->getStreamRoom(streamRoomId); });
    EXPECT_NE(afterRemoval.statusCode, 0);
    EXPECT_TRUE(afterRemoval.privateMeta.stdString().empty());
}

TEST_F(StreamRoomUsingGroupsTest, updateStreamRoom_change_group_role) {
    group::Group group_1;
    ASSERT_NO_THROW({ group_1 = groupApi->getGroup(reader->getString("Group_1.groupId")); });
    ASSERT_EQ(group_1.statusCode, 0);

    std::string streamRoomId;
    ASSERT_NO_THROW({
        streamRoomId = createStreamRoomWithGroups(
            reader->getString("Context_1.contextId"),
            std::vector<core::UserWithPubKey>{userOf(SRUGConnectionType::SRUGUser1)},
            std::vector<group::Group>{group_1}
        );
    });
    ASSERT_FALSE(streamRoomId.empty());

    stream::StreamRoom created;
    ASSERT_NO_THROW({ created = streamApi->getStreamRoom(streamRoomId); });
    ASSERT_EQ(created.statusCode, 0);

    EXPECT_NO_THROW({
        streamApi->updateStreamRoom(
            streamRoomId,
            std::vector<core::UserWithPubKey>{userOf(SRUGConnectionType::SRUGUser1)},
            std::vector<core::UserWithPubKey>{userOf(SRUGConnectionType::SRUGUser1)},
            core::Buffer::from("role_change"),
            core::Buffer::from("role_change_private"),
            created.version,
            false,
            false,
            std::nullopt,
            std::vector<core::GroupGrantWithKey>{core::GroupGrantWithKey{
                .groupId = group_1.groupId, .role = "manager", .groupPubKey = group_1.groupPubKey
            }}
        );
    });

    stream::StreamRoom updated;
    EXPECT_NO_THROW({ updated = streamApi->getStreamRoom(streamRoomId); });
    EXPECT_EQ(updated.groups.size(), 1);
    if (updated.groups.size() == 1) {
        EXPECT_EQ(updated.groups[0].groupId, group_1.groupId);
        EXPECT_EQ(updated.groups[0].role, "manager");
    }
}

TEST_F(StreamRoomUsingGroupsTest, listStreamRooms_includes_groups_field) {
    group::Group group_1;
    ASSERT_NO_THROW({ group_1 = groupApi->getGroup(reader->getString("Group_1.groupId")); });
    ASSERT_EQ(group_1.statusCode, 0);

    std::string streamRoomId;
    ASSERT_NO_THROW({
        streamRoomId = createStreamRoomWithGroups(
            reader->getString("Context_1.contextId"),
            std::vector<core::UserWithPubKey>{userOf(SRUGConnectionType::SRUGUser1)},
            std::vector<group::Group>{group_1}
        );
    });
    ASSERT_FALSE(streamRoomId.empty());

    core::PagingList<stream::StreamRoom> list;
    EXPECT_NO_THROW({
        list = streamApi->listStreamRooms(
            reader->getString("Context_1.contextId"),
            core::PagingQuery{.skip = 0, .limit = 100, .sortOrder = "desc"}
        );
    });
    bool found = false;
    for (const auto& r : list.readItems) {
        if (r.streamRoomId == streamRoomId) {
            EXPECT_EQ(r.statusCode, 0);
            EXPECT_EQ(r.groups.size(), 1);
            if (r.groups.size() == 1) {
                EXPECT_EQ(r.groups[0].groupId, group_1.groupId);
                EXPECT_EQ(r.groups[0].role, "user");
            }
            found = true;
            break;
        }
    }
    EXPECT_TRUE(found);
}

TEST_F(StreamRoomUsingGroupsTest, createStreamRoom_with_invalid_group_pubkey_throws) {
    EXPECT_THROW({
        streamApi->createStreamRoom(
            reader->getString("Context_1.contextId"),
            std::vector<core::UserWithPubKey>{userOf(SRUGConnectionType::SRUGUser1)},
            std::vector<core::UserWithPubKey>{userOf(SRUGConnectionType::SRUGUser1)},
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

TEST_F(StreamRoomUsingGroupsTest, getStreamRoom_via_group_grant) {
    // user_1 creates a room granted to Group_2; user_2 is a Group_2 member and no direct member of the room,
    // so this read can only be served through the group entry.
    group::Group group_2;
    ASSERT_NO_THROW({ group_2 = groupApi->getGroup(reader->getString("Group_2.groupId")); });
    ASSERT_EQ(group_2.statusCode, 0);

    std::string streamRoomId;
    ASSERT_NO_THROW({
        streamRoomId = createStreamRoomWithGroups(
            reader->getString("Context_1.contextId"),
            std::vector<core::UserWithPubKey>{userOf(SRUGConnectionType::SRUGUser1)},
            std::vector<group::Group>{group_2}
        );
    });
    ASSERT_FALSE(streamRoomId.empty());

    disconnect();
    connectAs(SRUGConnectionType::SRUGUser2);
    stream::StreamRoom r;
    EXPECT_NO_THROW({ r = streamApi->getStreamRoom(streamRoomId); });
    EXPECT_EQ(r.statusCode, 0);
    EXPECT_EQ(r.privateMeta.stdString(), "group_room_private");
}

TEST_F(StreamRoomUsingGroupsTest, room_accessible_by_all_group_members) {
    // Group_3 has user_1, user_2 and user_3.
    group::Group group_3;
    ASSERT_NO_THROW({ group_3 = groupApi->getGroup(reader->getString("Group_3.groupId")); });
    ASSERT_EQ(group_3.statusCode, 0);

    std::string streamRoomId;
    ASSERT_NO_THROW({
        streamRoomId = createStreamRoomWithGroups(
            reader->getString("Context_1.contextId"),
            std::vector<core::UserWithPubKey>{userOf(SRUGConnectionType::SRUGUser1)},
            std::vector<group::Group>{group_3}
        );
    });
    ASSERT_FALSE(streamRoomId.empty());

    disconnect();
    connectAs(SRUGConnectionType::SRUGUser2);
    stream::StreamRoom rUser2;
    EXPECT_NO_THROW({ rUser2 = streamApi->getStreamRoom(streamRoomId); });
    EXPECT_EQ(rUser2.statusCode, 0);
    EXPECT_EQ(rUser2.privateMeta.stdString(), "group_room_private");

    disconnect();
    connectAs(SRUGConnectionType::SRUGUser3);
    stream::StreamRoom rUser3;
    EXPECT_NO_THROW({ rUser3 = streamApi->getStreamRoom(streamRoomId); });
    EXPECT_EQ(rUser3.statusCode, 0);
    EXPECT_EQ(rUser3.privateMeta.stdString(), "group_room_private");
}

TEST_F(StreamRoomUsingGroupsTest, user_added_to_group_gains_access_to_room) {
    // Group_2 has user_1 + user_2; user_3 is not yet a member.
    group::Group group_2;
    ASSERT_NO_THROW({ group_2 = groupApi->getGroup(reader->getString("Group_2.groupId")); });
    ASSERT_EQ(group_2.statusCode, 0);

    core::ContainerPolicyWithoutItem policy;
    policy.get = "all";

    std::string streamRoomId;
    ASSERT_NO_THROW({
        streamRoomId = streamApi->createStreamRoom(
            reader->getString("Context_1.contextId"),
            std::vector<core::UserWithPubKey>{userOf(SRUGConnectionType::SRUGUser1)},
            std::vector<core::UserWithPubKey>{userOf(SRUGConnectionType::SRUGUser1)},
            core::Buffer::from("room_public"),
            core::Buffer::from("room_private"),
            policy,
            std::nullopt,
            std::vector<core::GroupGrantWithKey>{core::GroupGrantWithKey{
                .groupId = group_2.groupId, .role = "user", .groupPubKey = group_2.groupPubKey
            }}
        );
    });
    ASSERT_FALSE(streamRoomId.empty());

    disconnect();
    connectAs(SRUGConnectionType::SRUGUser3);
    stream::StreamRoom rBefore;
    EXPECT_NO_THROW({ rBefore = streamApi->getStreamRoom(streamRoomId); });
    EXPECT_NE(rBefore.statusCode, 0);

    // Seat user_3's leaf in the key tree - updateGroup would only re-wrap the group's metadata key.
    disconnect();
    connectAs(SRUGConnectionType::SRUGUser1);
    EXPECT_NO_THROW({
        groupApi->addGroupMembers(
            reader->getString("Group_2.groupId"),
            {group::GroupMemberToAdd{.user = userOf(SRUGConnectionType::SRUGUser3), .role = "user"}}
        );
    });

    disconnect();
    connectAs(SRUGConnectionType::SRUGUser3);
    stream::StreamRoom rAfter;
    EXPECT_NO_THROW({ rAfter = streamApi->getStreamRoom(streamRoomId); });
    EXPECT_EQ(rAfter.statusCode, 0);
    EXPECT_EQ(rAfter.privateMeta.stdString(), "room_private");
}

TEST_F(StreamRoomUsingGroupsTest, direct_member_of_granted_group_reads_and_updates) {
    // Every keyId opens from `keys`, so the group branch is skipped. `updateStreamRoom` is the interesting half:
    // `verifyKeysSecret` fails on any non-zero status, so an unresolved group entry throws instead of updating.
    group::Group group_1;
    ASSERT_NO_THROW({ group_1 = groupApi->getGroup(reader->getString("Group_1.groupId")); });
    ASSERT_EQ(group_1.statusCode, 0);

    std::string streamRoomId;
    ASSERT_NO_THROW({
        streamRoomId = createStreamRoomWithGroups(
            reader->getString("Context_1.contextId"),
            std::vector<core::UserWithPubKey>{userOf(SRUGConnectionType::SRUGUser1)},
            std::vector<group::Group>{group_1}
        );
    });
    ASSERT_FALSE(streamRoomId.empty());

    stream::StreamRoom r;
    EXPECT_NO_THROW({ r = streamApi->getStreamRoom(streamRoomId); });
    EXPECT_EQ(r.statusCode, 0);
    EXPECT_EQ(r.groups.size(), 1);

    EXPECT_NO_THROW({
        streamApi->updateStreamRoom(
            streamRoomId,
            std::vector<core::UserWithPubKey>{userOf(SRUGConnectionType::SRUGUser1)},
            std::vector<core::UserWithPubKey>{userOf(SRUGConnectionType::SRUGUser1)},
            core::Buffer::from("direct_updated_public"),
            core::Buffer::from("direct_updated_private"),
            r.version,
            false,
            false,
            std::nullopt,
            std::vector<core::GroupGrantWithKey>{{
                .groupId = group_1.groupId, .role = "user", .groupPubKey = group_1.groupPubKey
            }}
        );
    });

    stream::StreamRoom updated;
    EXPECT_NO_THROW({ updated = streamApi->getStreamRoom(streamRoomId); });
    EXPECT_EQ(updated.statusCode, 0);
    EXPECT_EQ(updated.privateMeta.stdString(), "direct_updated_private");
}

TEST_F(StreamRoomUsingGroupsTest, caller_in_no_granted_group_reads_via_direct_key) {
    // user_2 is a direct member of the room and in no grantee group, so the bridge serves it `groupKeys: []`
    // and the read has to come entirely from its own key wrap.
    group::Group group_1;
    ASSERT_NO_THROW({ group_1 = groupApi->getGroup(reader->getString("Group_1.groupId")); });
    ASSERT_EQ(group_1.statusCode, 0);

    std::string streamRoomId;
    ASSERT_NO_THROW({
        streamRoomId = createStreamRoomWithGroups(
            reader->getString("Context_1.contextId"),
            std::vector<core::UserWithPubKey>{
                userOf(SRUGConnectionType::SRUGUser1), userOf(SRUGConnectionType::SRUGUser2)
            },
            std::vector<group::Group>{group_1}
        );
    });
    ASSERT_FALSE(streamRoomId.empty());

    disconnect();
    connectAs(SRUGConnectionType::SRUGUser2);

    stream::StreamRoom r;
    EXPECT_NO_THROW({ r = streamApi->getStreamRoom(streamRoomId); });
    EXPECT_EQ(r.statusCode, 0);
    EXPECT_EQ(r.privateMeta.stdString(), "group_room_private");
    // `groups` stays unnarrowed, so user_2 still sees the grant it is not part of.
    EXPECT_EQ(r.groups.size(), 1);
}

TEST_F(StreamRoomUsingGroupsTest, caller_in_two_granted_groups_reads) {
    // The room wraps its key to user_1 only, and user_2 belongs to both grantee groups: narrowing leaves it two
    // entries at the same keyId, and with no direct wrap to fall back on one of them has to carry the read.
    group::Group group_2, group_3;
    ASSERT_NO_THROW({ group_2 = groupApi->getGroup(reader->getString("Group_2.groupId")); });
    ASSERT_NO_THROW({ group_3 = groupApi->getGroup(reader->getString("Group_3.groupId")); });
    ASSERT_EQ(group_2.statusCode, 0);
    ASSERT_EQ(group_3.statusCode, 0);

    std::string streamRoomId;
    ASSERT_NO_THROW({
        streamRoomId = createStreamRoomWithGroups(
            reader->getString("Context_1.contextId"),
            std::vector<core::UserWithPubKey>{userOf(SRUGConnectionType::SRUGUser1)},
            std::vector<group::Group>{group_2, group_3}
        );
    });
    ASSERT_FALSE(streamRoomId.empty());

    disconnect();
    connectAs(SRUGConnectionType::SRUGUser2);

    stream::StreamRoom r;
    EXPECT_NO_THROW({ r = streamApi->getStreamRoom(streamRoomId); });
    EXPECT_EQ(r.statusCode, 0);
    EXPECT_EQ(r.privateMeta.stdString(), "group_room_private");
}

TEST_F(StreamRoomUsingGroupsTest, rotateStreamRoomKeys_covers_a_grantee_group_the_caller_did_not_name) {
    // user_2 re-keys naming no groups, so the grantee list comes from the room. The caller must be in that
    // group: the default group policy hands a group's epoch and public key to members only.
    group::Group granteeGroup;
    ASSERT_NO_THROW({ granteeGroup = groupApi->getGroup(reader->getString("Group_2.groupId")); });
    ASSERT_EQ(granteeGroup.statusCode, 0);

    std::string streamRoomId;
    ASSERT_NO_THROW({
        streamRoomId = createStreamRoomWithGroups(
            reader->getString("Context_1.contextId"),
            std::vector<core::UserWithPubKey>{
                userOf(SRUGConnectionType::SRUGUser1), userOf(SRUGConnectionType::SRUGUser2)
            },
            std::vector<group::Group>{granteeGroup}
        );
    });
    ASSERT_FALSE(streamRoomId.empty());

    stream::StreamRoom before;
    ASSERT_NO_THROW({ before = streamApi->getStreamRoom(streamRoomId); });
    ASSERT_EQ(before.statusCode, 0);

    disconnect();
    connectAs(SRUGConnectionType::SRUGUser2);
    EXPECT_NO_THROW({
        streamApi->rotateStreamRoomKeys(
            streamRoomId,
            std::vector<core::UserWithPubKey>{
                userOf(SRUGConnectionType::SRUGUser1), userOf(SRUGConnectionType::SRUGUser2)
            },
            std::vector<core::UserWithPubKey>{
                userOf(SRUGConnectionType::SRUGUser1), userOf(SRUGConnectionType::SRUGUser2)
            },
            before.version,
            false,
            std::vector<core::GroupGrantWithKey>{}
        );
    });

    // The grant survives the re-key, and user_1 - who reads through the group - still resolves the new key.
    disconnect();
    connectAs(SRUGConnectionType::SRUGUser1);
    stream::StreamRoom after;
    EXPECT_NO_THROW({ after = streamApi->getStreamRoom(streamRoomId); });
    EXPECT_EQ(after.statusCode, 0);
    EXPECT_EQ(after.privateMeta.stdString(), "group_room_private");
    EXPECT_EQ(after.groups.size(), 1);
    if (after.groups.size() == 1) {
        EXPECT_EQ(after.groups[0].groupId, granteeGroup.groupId);
    }
}

TEST_F(StreamRoomUsingGroupsTest, rotateStreamRoomKeys_clears_staleGroups_after_the_group_advances_its_epoch) {
    // Removing a member advances G to epoch 2, leaving the room's key wrapped to a superseded epoch - which
    // the bridge reports as `staleGroups`. A re-key re-wraps to the current epoch and must clear it.
    std::string groupId;
    ASSERT_NO_THROW({
        groupId = groupApi->createGroup(
            reader->getString("Context_1.contextId"),
            std::vector<core::UserWithPubKey>{
                userOf(SRUGConnectionType::SRUGUser1),
                userOf(SRUGConnectionType::SRUGUser2),
                userOf(SRUGConnectionType::SRUGUser3)
            },
            std::vector<core::UserWithPubKey>{userOf(SRUGConnectionType::SRUGUser1)},
            core::Buffer::from("grp_pub"),
            core::Buffer::from("grp_priv")
        );
    });
    ASSERT_FALSE(groupId.empty());

    group::Group group;
    ASSERT_NO_THROW({ group = groupApi->getGroup(groupId); });
    ASSERT_EQ(group.statusCode, 0);
    ASSERT_EQ(group.keyVersion, 1);

    std::string streamRoomId;
    ASSERT_NO_THROW({
        streamRoomId = createStreamRoomWithGroups(
            reader->getString("Context_1.contextId"),
            std::vector<core::UserWithPubKey>{userOf(SRUGConnectionType::SRUGUser1)},
            std::vector<group::Group>{group}
        );
    });
    ASSERT_FALSE(streamRoomId.empty());

    ASSERT_NO_THROW({
        groupApi->removeGroupMembers(groupId, {reader->getString("Login.user_3_id")});
    });

    group::Group rotatedGroup;
    ASSERT_NO_THROW({ rotatedGroup = groupApi->getGroup(groupId); });
    ASSERT_EQ(rotatedGroup.statusCode, 0);
    ASSERT_EQ(rotatedGroup.keyVersion, 2);

    stream::StreamRoom stale;
    ASSERT_NO_THROW({ stale = streamApi->getStreamRoom(streamRoomId); });
    ASSERT_EQ(stale.statusCode, 0);
    EXPECT_EQ(stale.staleGroups.size(), 1);
    if (stale.staleGroups.size() == 1) {
        EXPECT_EQ(stale.staleGroups[0], groupId);
    }

    EXPECT_NO_THROW({
        streamApi->rotateStreamRoomKeys(
            streamRoomId,
            std::vector<core::UserWithPubKey>{userOf(SRUGConnectionType::SRUGUser1)},
            std::vector<core::UserWithPubKey>{userOf(SRUGConnectionType::SRUGUser1)},
            stale.version,
            false,
            std::vector<core::GroupGrantWithKey>{}
        );
    });

    stream::StreamRoom fresh;
    EXPECT_NO_THROW({ fresh = streamApi->getStreamRoom(streamRoomId); });
    EXPECT_EQ(fresh.statusCode, 0);
    EXPECT_EQ(fresh.staleGroups.size(), 0);
    EXPECT_EQ(fresh.groups.size(), 1);

    // user_2 is still in G at epoch 2 and was never a direct room member, so this read can only be served
    // through the re-wrapped group entry.
    disconnect();
    connectAs(SRUGConnectionType::SRUGUser2);
    stream::StreamRoom afterRekey;
    EXPECT_NO_THROW({ afterRekey = streamApi->getStreamRoom(streamRoomId); });
    EXPECT_EQ(afterRekey.statusCode, 0);
    EXPECT_EQ(afterRekey.privateMeta.stdString(), "group_room_private");
}
