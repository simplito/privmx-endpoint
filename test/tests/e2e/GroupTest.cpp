#include <gtest/gtest.h>
#include "BaseGroupTest.hpp"
#include <privmx/endpoint/core/Exception.hpp>
#include <Poco/Util/IniFileConfiguration.h>
#include <privmx/endpoint/core/EventQueueImpl.hpp>
#include <privmx/utils/Utils.hpp>
#include <privmx/endpoint/core/VarSerializer.hpp>
#include <privmx/endpoint/core/Connection.hpp>
#include <privmx/endpoint/core/EndpointUtils.hpp>
#include <privmx/endpoint/group/GroupApi.hpp>
#include <privmx/endpoint/group/GroupException.hpp>
#include <privmx/endpoint/group/VarSerializer.hpp>
#include <privmx/endpoint/core/CoreException.hpp>

using namespace privmx::endpoint;

/**
 * End-to-end coverage of GroupApi against a running bridge: group lifecycle, roster changes, envelopes, and the
 * file API.
 *
 * The worked examples. GroupApi.hpp documents the file API with three worked examples, and the tests below paste
 * those examples in unchanged rather than paraphrasing them. That is the point: a snippet that drifts from the
 * API stops compiling here, so the documentation cannot quietly rot into something that no longer works.
 */

class GroupTest : public privmx::test::BaseGroupTest {
protected:
    // A group in Context_1 with the given members, managed by whoever is listed first.
    std::string createGroupOf(const std::vector<core::UserWithPubKey>& users) {
        std::string groupId = groupApi->createGroup(
            reader->getString("Context_1.contextId"), users, std::vector<core::UserWithPubKey>{users.front()},
            core::Buffer::from("public"), core::Buffer::from("private")
        );
        EXPECT_FALSE(groupId.empty());
        return groupId;
    }
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
    EXPECT_EQ(group.publicMetaVersion, reader->getInt64("Group_1.publicMetaVersion"));
    EXPECT_EQ(group.privateMetaVersion, reader->getInt64("Group_1.privateMetaVersion"));
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
        EXPECT_TRUE(g.groupPubKey.empty()) << "nothing verified in this process yet, and a listing vouches for nothing";
        EXPECT_GE(g.keyVersion, 0);
    }
    // Once `getGroup` has verified a group, the listing hands out that same key.
    const std::string groupPubKey = groupApi->getGroup(groupsList.readItems[0].groupId).groupPubKey;
    EXPECT_FALSE(groupPubKey.empty());
    const auto relisted = groupApi->listGroups(
        reader->getString("Context_1.contextId"), core::PagingQuery{.skip = 0, .limit = 10, .sortOrder = "asc"}
    );
    EXPECT_EQ(relisted.readItems[0].groupPubKey, groupPubKey);
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
    EXPECT_EQ(group.publicMetaVersion, 1);
    EXPECT_EQ(group.privateMetaVersion, 1);
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
    EXPECT_EQ(group.publicMetaVersion, 1);
    EXPECT_EQ(group.privateMetaVersion, 1);
}

TEST_F(GroupTest, updateGroupPublicMeta_incorrect_data) {
    // incorrect groupId
    EXPECT_THROW({
        groupApi->updateGroupPublicMeta(
            reader->getString("Context_1.contextId"), core::Buffer::from("public"), 1
        );
    }, core::Exception);
    // Wrong version. There is no way to push past this: the entry commits a tag over the version it lands at,
    // so an update built against a moved head could only land a tag no reader would accept.
    EXPECT_THROW({
        groupApi->updateGroupPublicMeta(reader->getString("Group_2.groupId"), core::Buffer::from("public"), 99);
    }, core::Exception);
}

TEST_F(GroupTest, updateGroupPrivateMeta_incorrect_data) {
    EXPECT_THROW({
        groupApi->updateGroupPrivateMeta(
            reader->getString("Context_1.contextId"), core::Buffer::from("private"), 1
        );
    }, core::Exception);
    EXPECT_THROW({
        groupApi->updateGroupPrivateMeta(reader->getString("Group_2.groupId"), core::Buffer::from("private"), 99);
    }, core::Exception);
}

TEST_F(GroupTest, updateGroupPolicy_incorrect_data) {
    // Only the groupId can be wrong here — there is no version to get wrong, because a policy write moves
    // neither metadata counter and so has nothing to compare against.
    EXPECT_THROW({
        groupApi->updateGroupPolicy(reader->getString("Context_1.contextId"), core::ContainerPolicy{});
    }, core::Exception);
}

TEST_F(GroupTest, updateGroupPublicMeta_correct_data) {
    const std::string groupId = reader->getString("Group_1.groupId");
    group::Group before;
    ASSERT_NO_THROW({ before = groupApi->getGroup(groupId); });

    EXPECT_NO_THROW({
        groupApi->updateGroupPublicMeta(groupId, core::Buffer::from("updated_public"), before.publicMetaVersion);
    });
    group::Group group;
    EXPECT_NO_THROW({ group = groupApi->getGroup(groupId); });
    EXPECT_EQ(group.statusCode, 0);
    EXPECT_EQ(group.publicMetaVersion, before.publicMetaVersion + 1);
    EXPECT_EQ(group.publicMeta.stdString(), "updated_public");
    // The whole point of the split: writing one plane leaves the other's counter and bytes untouched.
    EXPECT_EQ(group.privateMetaVersion, before.privateMetaVersion);
    EXPECT_EQ(group.privateMeta.stdString(), before.privateMeta.stdString());
    // And the roster is still the one the group was created with: a metadata write cannot reach it at all.
    // Promoting somebody goes through addGroupMembers/removeGroupMembers.
    EXPECT_EQ(group.rosterVersion, before.rosterVersion);
    EXPECT_EQ(group.users.size(), 1);
    EXPECT_EQ(group.managers.size(), 1);
    if (group.managers.size() == 1) {
        EXPECT_EQ(group.managers[0], reader->getString("Login.user_1_id"));
    }

    // A second write to the same plane, to show the counter keeps climbing on its own.
    EXPECT_NO_THROW({
        groupApi->updateGroupPublicMeta(groupId, core::Buffer::from("updated_public_2"), group.publicMetaVersion);
    });
    EXPECT_NO_THROW({ group = groupApi->getGroup(groupId); });
    EXPECT_EQ(group.statusCode, 0);
    EXPECT_EQ(group.publicMetaVersion, before.publicMetaVersion + 2);
    EXPECT_EQ(group.publicMeta.stdString(), "updated_public_2");
    EXPECT_EQ(group.privateMetaVersion, before.privateMetaVersion);
}

TEST_F(GroupTest, metadata_written_by_a_different_manager_keeps_the_group_readable) {
    // Each plane answers for the author of its own head entry. A metadata write moves `lastModifier` and writes
    // no roster entry, so checking the roster plane against it would fail permanently for an honest group.
    std::string groupId;
    const std::vector<core::UserWithPubKey> both{
        core::UserWithPubKey{
            .userId = reader->getString("Login.user_1_id"), .pubKey = reader->getString("Login.user_1_pubKey")
        },
        core::UserWithPubKey{
            .userId = reader->getString("Login.user_2_id"), .pubKey = reader->getString("Login.user_2_pubKey")
        }
    };
    // Both managers: the roster is written by user_1 here, and user_2 has to be allowed to update metadata.
    EXPECT_NO_THROW({
        groupId = groupApi->createGroup(
            reader->getString("Context_1.contextId"), both, both, core::Buffer::from("public"),
            core::Buffer::from("private")
        );
    });
    ASSERT_FALSE(groupId.empty());

    disconnect();
    connectAs(2);
    EXPECT_NO_THROW({ groupApi->updateGroupPublicMeta(groupId, core::Buffer::from("public2"), 1); });
    EXPECT_NO_THROW({ groupApi->updateGroupPrivateMeta(groupId, core::Buffer::from("private2"), 1); });

    // user_2 wrote both metadata planes; user_1 is still the roster head's author.
    group::Group asUser2;
    EXPECT_NO_THROW({ asUser2 = groupApi->getGroup(groupId); });
    EXPECT_EQ(asUser2.statusCode, 0);
    EXPECT_EQ(asUser2.publicMeta.stdString(), "public2");

    // And the member who did not write the metadata reads it just the same.
    disconnect();
    connectAs(1);
    group::Group asUser1;
    EXPECT_NO_THROW({ asUser1 = groupApi->getGroup(groupId); });
    EXPECT_EQ(asUser1.statusCode, 0);
    EXPECT_EQ(asUser1.privateMeta.stdString(), "private2");
    EXPECT_EQ(asUser1.publicMetaVersion, 2);
    EXPECT_EQ(asUser1.privateMetaVersion, 2);
    EXPECT_EQ(asUser1.rosterVersion, 1);
}

TEST_F(GroupTest, updateGroupPrivateMeta_correct_data) {
    const std::string groupId = reader->getString("Group_1.groupId");
    group::Group before;
    ASSERT_NO_THROW({ before = groupApi->getGroup(groupId); });

    EXPECT_NO_THROW({
        groupApi->updateGroupPrivateMeta(groupId, core::Buffer::from("updated_private"), before.privateMetaVersion);
    });
    group::Group group;
    EXPECT_NO_THROW({ group = groupApi->getGroup(groupId); });
    EXPECT_EQ(group.statusCode, 0);
    EXPECT_EQ(group.privateMetaVersion, before.privateMetaVersion + 1);
    EXPECT_EQ(group.privateMeta.stdString(), "updated_private");
    EXPECT_EQ(group.publicMetaVersion, before.publicMetaVersion);
    EXPECT_EQ(group.publicMeta.stdString(), before.publicMeta.stdString());
    EXPECT_EQ(group.rosterVersion, before.rosterVersion);
}

TEST_F(GroupTest, updateGroupPolicy_correct_data) {
    // A policy write is a commit that appends no metadata entry: neither counter moves and neither buffer changes,
    // so no reader has anything to re-verify.
    const std::string groupId = reader->getString("Group_1.groupId");
    group::Group before;
    ASSERT_NO_THROW({ before = groupApi->getGroup(groupId); });

    core::ContainerPolicy policy;
    policy.get = "all";
    EXPECT_NO_THROW({ groupApi->updateGroupPolicy(groupId, policy); });

    group::Group after;
    EXPECT_NO_THROW({ after = groupApi->getGroup(groupId); });
    EXPECT_EQ(after.statusCode, 0);
    EXPECT_EQ(after.policy.get.value_or(""), "all");
    EXPECT_EQ(after.publicMetaVersion, before.publicMetaVersion);
    EXPECT_EQ(after.privateMetaVersion, before.privateMetaVersion);
    EXPECT_EQ(after.rosterVersion, before.rosterVersion);
    EXPECT_EQ(after.publicMeta.stdString(), before.publicMeta.stdString());
    EXPECT_EQ(after.privateMeta.stdString(), before.privateMeta.stdString());

    // Each call is a signed commit planned on a fresh read, so a second one in a row extends the first.
    policy.get = "user";
    EXPECT_NO_THROW({ groupApi->updateGroupPolicy(groupId, policy); });
    EXPECT_NO_THROW({ after = groupApi->getGroup(groupId); });
    EXPECT_EQ(after.policy.get.value_or(""), "user");
    EXPECT_EQ(after.publicMetaVersion, before.publicMetaVersion);
    EXPECT_EQ(after.privateMetaVersion, before.privateMetaVersion);
}

TEST_F(GroupTest, both_planes_at_version_three_still_verify) {
    // Interleaved writes, so each plane's committed `metaVersion` and the *other* plane's counter diverge —
    // a state the combined entry could never produce.
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
    EXPECT_NO_THROW({ groupApi->updateGroupPublicMeta(groupId, core::Buffer::from("v2"), 1); });
    EXPECT_NO_THROW({ groupApi->updateGroupPrivateMeta(groupId, core::Buffer::from("v2_priv"), 1); });
    EXPECT_NO_THROW({ groupApi->updateGroupPublicMeta(groupId, core::Buffer::from("v3"), 2); });
    EXPECT_NO_THROW({ groupApi->updateGroupPrivateMeta(groupId, core::Buffer::from("v3_priv"), 2); });

    group::Group group;
    EXPECT_NO_THROW({ group = groupApi->getGroup(groupId); });
    EXPECT_EQ(group.statusCode, 0);
    EXPECT_EQ(group.publicMetaVersion, 3);
    EXPECT_EQ(group.privateMetaVersion, 3);
    EXPECT_EQ(group.publicMeta.stdString(), "v3");
    EXPECT_EQ(group.privateMeta.stdString(), "v3_priv");
}

TEST_F(GroupTest, updateGroupPublicMeta_cannot_skip_the_version_check) {
    // A refused update must leave the group exactly as it was — a tag committed for a version it never lands at
    // would make every reader reject the group — and a refused write to one plane must not disturb the other.
    const std::string groupId = reader->getString("Group_2.groupId");
    group::Group before;
    ASSERT_NO_THROW({ before = groupApi->getGroup(groupId); });
    EXPECT_THROW({
        groupApi->updateGroupPublicMeta(groupId, core::Buffer::from("forced"), 99);
    }, core::Exception);
    group::Group after;
    EXPECT_NO_THROW({ after = groupApi->getGroup(groupId); });
    EXPECT_EQ(after.statusCode, 0) << "a refused update must leave the group readable";
    EXPECT_EQ(after.publicMetaVersion, before.publicMetaVersion);
    EXPECT_EQ(after.privateMetaVersion, before.privateMetaVersion);
    EXPECT_EQ(after.publicMeta.stdString(), before.publicMeta.stdString());
    EXPECT_EQ(after.privateMeta.stdString(), before.privateMeta.stdString());
}

TEST_F(GroupTest, updateGroupPrivateMeta_cannot_skip_the_version_check) {
    const std::string groupId = reader->getString("Group_2.groupId");
    group::Group before;
    ASSERT_NO_THROW({ before = groupApi->getGroup(groupId); });
    EXPECT_THROW({
        groupApi->updateGroupPrivateMeta(groupId, core::Buffer::from("forced_priv"), 99);
    }, core::Exception);
    group::Group after;
    EXPECT_NO_THROW({ after = groupApi->getGroup(groupId); });
    EXPECT_EQ(after.statusCode, 0) << "a refused update must leave the group readable";
    EXPECT_EQ(after.publicMetaVersion, before.publicMetaVersion);
    EXPECT_EQ(after.privateMetaVersion, before.privateMetaVersion);
    EXPECT_EQ(after.publicMeta.stdString(), before.publicMeta.stdString());
    EXPECT_EQ(after.privateMeta.stdString(), before.privateMeta.stdString());
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
    connectAs(2);
    group::Group group;
    EXPECT_NO_THROW({
        group = groupApi->getGroup(groupId);
    });
    EXPECT_EQ(group.statusCode, 0);
    EXPECT_EQ(group.publicMeta.stdString(), "shared_public");
    EXPECT_EQ(group.privateMeta.stdString(), "shared_private");
    EXPECT_EQ(group.groupId, groupId);
}

// -- the objects the documented examples talk to --

struct ByteSource {
    std::string data;
    std::size_t pos = 0;
    bool hasMore() const { return pos < data.size(); }
    core::Buffer read(std::size_t n) {
        std::string out = data.substr(pos, n);
        pos += out.size();
        return core::Buffer::from(out);
    }
};

struct ByteSink {
    std::string data;
    void write(const core::Buffer& block) { data.append(block.stdString()); }
};

struct CipherStorage {
    std::string data;
    std::size_t pos = 0;
    bool hasMore() const { return pos < data.size(); }
    // Sequential, as the opening example uses it.
    core::Buffer read(std::size_t n) {
        std::string out = data.substr(pos, n);
        pos += out.size();
        return core::Buffer::from(out);
    }
    // Random access, as the range example uses it.
    core::Buffer read(std::size_t offset, std::size_t n) const {
        return core::Buffer::from(offset >= data.size() ? std::string() : data.substr(offset, n));
    }
};

// -- envelopes -----------------------------------------------------------------------------------------

// What the envelope cases bind to: a message in a chat, as an application would name it.
static group::Path messagePath(const std::string& messageId) {
    return {
        {false, core::Buffer::from("chat")},
        {true, group::GroupApi::idFromString("6f9619ff-8b86-d011-b42d-00c04fc964ff")},
        {false, core::Buffer::from("message")},
        {true, group::GroupApi::idFromString(messageId)},
        {false, core::Buffer::from("body")},
    };
}
static group::DecryptOptions anyAuthor() {
    return group::DecryptOptions{.expectedAuthor = "", .anyAuthor = true, .currentEpochOnly = false};
}
static group::DecryptOptions writtenBy(const std::string& userId) {
    return group::DecryptOptions{.expectedAuthor = userId, .anyAuthor = false, .currentEpochOnly = false};
}

TEST_F(GroupTest, envelope_roundtrip_between_members) {
    std::string groupId = createGroupOf({user(1), user(2)});
    const std::string author = reader->getString("Login.user_1_id");

    core::Buffer envelope;
    EXPECT_NO_THROW({ envelope = groupApi->encrypt(groupId, messagePath("m1"), core::Buffer::from("secret payload")); });
    EXPECT_GT(envelope.size(), 0u);
    EXPECT_EQ(envelope.stdString().find("secret payload"), std::string::npos);

    const group::EnvelopeHeader header = group::GroupApi::peekEnvelope(envelope);
    EXPECT_EQ(header.groupId, groupId);
    EXPECT_EQ(header.keyVersion, 1);
    EXPECT_FALSE(header.fromOutsider);
    EXPECT_TRUE(header.hasLocation);
    EXPECT_EQ(header.authorUserId, author);

    disconnect();
    connectAs(2);

    group::DecryptedEnvelope opened;
    EXPECT_NO_THROW({ opened = groupApi->decrypt(groupId, messagePath("m1"), envelope, writtenBy(author)); });
    EXPECT_EQ(opened.data.stdString(), "secret payload");
    EXPECT_EQ(opened.author.userId, author);
    EXPECT_EQ(opened.author.pubKey, reader->getString("Login.user_1_pubKey"));
    EXPECT_EQ(opened.author.role, "manager");
    EXPECT_EQ(opened.keyVersion, 1);
    EXPECT_GT(opened.encryptedAt, 0);
}

TEST_F(GroupTest, envelope_is_bound_to_its_location_and_its_author) {
    std::string groupId = createGroupOf({user(1), user(2)});
    const std::string author = reader->getString("Login.user_1_id");
    const std::string other = reader->getString("Login.user_2_id");
    core::Buffer envelope = groupApi->encrypt(groupId, messagePath("m1"), core::Buffer::from("pay 100"));
    core::Buffer unbound = groupApi->encrypt(groupId, group::GroupApi::noLocation(), core::Buffer::from("x"));

    disconnect();
    connectAs(2);

    // The application's server stores the envelope under another message, or names another author beside it.
    EXPECT_THROW(
        { groupApi->decrypt(groupId, messagePath("m2"), envelope, anyAuthor()); }, group::EnvelopeWrongLocationException
    );
    EXPECT_THROW(
        { groupApi->decrypt(groupId, group::GroupApi::noLocation(), envelope, anyAuthor()); },
        group::EnvelopeWrongLocationException
    );
    EXPECT_THROW(
        { groupApi->decrypt(groupId, messagePath("m1"), unbound, anyAuthor()); }, group::EnvelopeWrongLocationException
    );
    EXPECT_THROW(
        { groupApi->decrypt(groupId, messagePath("m1"), envelope, writtenBy(other)); },
        group::EnvelopeWrongAuthorException
    );
    EXPECT_THROW(
        { groupApi->decrypt(groupId, messagePath("m1"), envelope, group::DecryptOptions{}); },
        group::EnvelopeAuthorNotStatedException
    );
    EXPECT_EQ(
        groupApi->decrypt(groupId, group::GroupApi::noLocation(), unbound, anyAuthor()).data.stdString(), "x"
    );

    // A page: each item reports on its own.
    const auto page = groupApi->decryptMany(
        groupId,
        {
            {.envelope = envelope, .location = messagePath("m1"), .options = writtenBy(author)},
            {.envelope = envelope, .location = messagePath("m2"), .options = writtenBy(author)},
        }
    );
    ASSERT_EQ(page.size(), 2u);
    EXPECT_EQ(page[0].statusCode, 0);
    EXPECT_EQ(page[0].envelope.data.stdString(), "pay 100");
    EXPECT_EQ(page[1].statusCode, static_cast<int64_t>(group::EnvelopeWrongLocationException::FULL_CODE));
}

TEST_F(GroupTest, envelope_survives_a_key_rotation) {
    // Removing a member advances the group's key epoch. An envelope sealed before that must still open
    // afterwards - which is the whole reason the key id travels inside it.
    std::string groupId = createGroupOf({user(1), user(2)});
    const std::string author = reader->getString("Login.user_1_id");

    core::Buffer before = groupApi->encrypt(groupId, messagePath("m1"), core::Buffer::from("written before the rotation"));
    const int64_t epochBefore = groupApi->getGroup(groupId).keyVersion;

    EXPECT_NO_THROW({
        groupApi->removeGroupMembers(groupId, {reader->getString("Login.user_2_id")});
    });
    EXPECT_GT(groupApi->getGroup(groupId).keyVersion, epochBefore);

    group::DecryptedEnvelope opened;
    EXPECT_NO_THROW({ opened = groupApi->decrypt(groupId, messagePath("m1"), before, writtenBy(author)); });
    EXPECT_EQ(opened.data.stdString(), "written before the rotation");
    EXPECT_EQ(opened.keyVersion, epochBefore);

    // History, readable; but not what a reader takes as having arrived just now.
    EXPECT_THROW(
        {
            groupApi->decrypt(
                groupId, messagePath("m1"), before,
                group::DecryptOptions{.expectedAuthor = author, .anyAuthor = false, .currentEpochOnly = true}
            );
        },
        group::EnvelopeStaleEpochException
    );
}

TEST_F(GroupTest, envelope_of_a_removed_member_is_not_attributed_to_a_member) {
    std::string groupId = createGroupOf({user(1), user(2)});
    disconnect();
    connectAs(2);
    core::Buffer fromUser2 = groupApi->encrypt(groupId, messagePath("m1"), core::Buffer::from("before I left"));
    disconnect();
    connectAs(1);
    ASSERT_NO_THROW({ groupApi->removeGroupMembers(groupId, {reader->getString("Login.user_2_id")}); });

    EXPECT_THROW(
        { groupApi->decrypt(groupId, messagePath("m1"), fromUser2, anyAuthor()); },
        group::EnvelopeAuthorNotMemberException
    );
}

TEST_F(GroupTest, envelope_from_a_non_member) {
    // A group user_2 is deliberately not in.
    std::string groupId = createGroupOf({user(1)});
    const std::string groupPubKey = groupApi->getGroup(groupId).groupPubKey;
    ASSERT_FALSE(groupPubKey.empty());

    disconnect();
    connectAs(2);

    // Not a member: reading the group is refused, but sealing to it is not - that asymmetry is the feature.
    EXPECT_ANY_THROW({ groupApi->getGroup(groupId); });
    core::Buffer anonymous;
    EXPECT_NO_THROW({
        anonymous =
            groupApi->encryptAnonymously(groupId, groupPubKey, messagePath("tip1"), core::Buffer::from("a tip from outside"));
    });
    // The sender cannot read back what they wrote; only the group can.
    EXPECT_ANY_THROW({ groupApi->decryptAnonymous(groupId, messagePath("tip1"), anonymous); });

    disconnect();
    connectAs(1);
    group::DecryptedAnonymousEnvelope opened;
    EXPECT_NO_THROW({ opened = groupApi->decryptAnonymous(groupId, messagePath("tip1"), anonymous); });
    EXPECT_EQ(opened.data.stdString(), "a tip from outside");
    EXPECT_EQ(opened.keyVersion, 1);

    // What nobody signed is never read as somebody's, and never at another place.
    EXPECT_THROW(
        { groupApi->decrypt(groupId, messagePath("tip1"), anonymous, anyAuthor()); }, group::EnvelopeWrongKindException
    );
    EXPECT_THROW(
        { groupApi->decryptFromOutsider(groupId, messagePath("tip1"), anonymous, anyAuthor()); },
        group::EnvelopeWrongKindException
    );
    EXPECT_THROW(
        { groupApi->decryptAnonymous(groupId, messagePath("tip2"), anonymous); }, group::EnvelopeWrongLocationException
    );
}

TEST_F(GroupTest, envelope_signed_by_a_non_member) {
    std::string groupId = createGroupOf({user(1)});
    const std::string contextId = reader->getString("Context_1.contextId");
    EXPECT_EQ(groupApi->getGroup(groupId).visibleTo, "members");

    disconnect();
    connectAs(2);
    // A group shows its key to nobody outside it until a manager says so: there is nothing to seal to.
    EXPECT_ANY_THROW({ groupApi->getGroupPublicKey(contextId, groupId); });
    EXPECT_ANY_THROW({
        groupApi->encryptAsOutsider(contextId, groupId, messagePath("lab1"), core::Buffer::from("a signed result"));
    });
    // And only a manager can say so.
    EXPECT_ANY_THROW({ groupApi->setGroupVisibility(groupId, "context"); });

    disconnect();
    connectAs(1);
    ASSERT_NO_THROW({ groupApi->setGroupVisibility(groupId, "context"); });
    EXPECT_EQ(groupApi->getGroup(groupId).visibleTo, "context");

    disconnect();
    connectAs(2);
    group::GroupPublicKey key;
    EXPECT_NO_THROW({ key = groupApi->getGroupPublicKey(contextId, groupId); });
    EXPECT_EQ(key.groupId, groupId);
    EXPECT_EQ(key.keyVersion, 1);
    EXPECT_FALSE(key.pubKey.empty());
    EXPECT_EQ(key.creator, reader->getString("Login.user_1_id")) << "what an outsider checks a derived ID by";
    // Visible is not readable.
    EXPECT_ANY_THROW({ groupApi->getGroup(groupId); });

    core::Buffer fromOutsider;
    EXPECT_NO_THROW({
        fromOutsider = groupApi->encryptAsOutsider(contextId, groupId, messagePath("lab1"), core::Buffer::from("a signed result"));
    });
    // The writer cannot read it back.
    EXPECT_ANY_THROW({ groupApi->decryptFromOutsider(groupId, messagePath("lab1"), fromOutsider, anyAuthor()); });

    disconnect();
    connectAs(1);
    group::DecryptedOutsiderEnvelope signedResult;
    EXPECT_NO_THROW({
        signedResult = groupApi->decryptFromOutsider(
            groupId, messagePath("lab1"), fromOutsider, writtenBy(reader->getString("Login.user_2_id"))
        );
    });
    EXPECT_EQ(signedResult.data.stdString(), "a signed result");
    EXPECT_EQ(signedResult.sender.userId, reader->getString("Login.user_2_id"));
    EXPECT_EQ(signedResult.sender.pubKey, reader->getString("Login.user_2_pubKey"));
    EXPECT_EQ(signedResult.keyVersion, 1);
    EXPECT_THROW(
        { groupApi->decrypt(groupId, messagePath("lab1"), fromOutsider, anyAuthor()); }, group::EnvelopeWrongKindException
    );
    EXPECT_THROW(
        { groupApi->decryptAnonymous(groupId, messagePath("lab1"), fromOutsider); }, group::EnvelopeWrongKindException
    );
    EXPECT_THROW(
        { groupApi->decryptFromOutsider(groupId, messagePath("lab2"), fromOutsider, anyAuthor()); },
        group::EnvelopeWrongLocationException
    );

    // Hidden again: the next write from outside finds no key. What was written stays readable.
    ASSERT_NO_THROW({ groupApi->setGroupVisibility(groupId, "members"); });
    disconnect();
    connectAs(2);
    EXPECT_ANY_THROW({
        groupApi->encryptAsOutsider(contextId, groupId, messagePath("lab3"), core::Buffer::from("too late"));
    });
}

TEST_F(GroupTest, group_id_follows_from_a_seed) {
    const std::string contextId = reader->getString("Context_1.contextId");
    // What an application has before any group exists: the entity the group is for.
    const core::Buffer seed = core::Buffer::from("contact/chat/" + core::EndpointUtils::generateId());
    const std::string expected = group::GroupApi::deriveGroupId(contextId, seed);
    EXPECT_EQ(expected, group::GroupApi::deriveGroupId(contextId, seed));
    EXPECT_NE(expected, group::GroupApi::deriveGroupId(contextId, core::Buffer::from("contact/chat/other")));
    EXPECT_NE(expected, group::GroupApi::deriveGroupId(reader->getString("Context_2.contextId"), seed));

    std::string groupId;
    ASSERT_NO_THROW({
        groupId = groupApi->createGroup(
            contextId, {user(1), user(2)}, {user(1)}, core::Buffer::from("public"), core::Buffer::from("private"),
            std::nullopt, seed
        );
    });
    EXPECT_EQ(groupId, expected);
    EXPECT_EQ(groupApi->getGroup(groupId).creator, reader->getString("Login.user_1_id"));

    // Another device finds the group from the entity alone, and checks who made it.
    disconnect();
    connectAs(2);
    group::Group found;
    EXPECT_NO_THROW({ found = groupApi->getGroup(group::GroupApi::deriveGroupId(contextId, seed)); });
    EXPECT_EQ(found.creator, reader->getString("Login.user_1_id"));
    // SECURITY: a second group under the seed is refused, whoever asks. Finding one there is not creating it.
    EXPECT_ANY_THROW({
        groupApi->createGroup(
            contextId, {user(2)}, {user(2)}, core::Buffer::from("public"), core::Buffer::from("private"),
            std::nullopt, seed
        );
    });
}

TEST_F(GroupTest, getGroups_reports_each_group_on_its_own) {
    std::string first = createGroupOf({user(1), user(2)});
    std::string second = createGroupOf({user(1)});
    std::vector<group::GroupResult> results;
    ASSERT_NO_THROW({ results = groupApi->getGroups({first, "no-such-group", second}); });
    ASSERT_EQ(results.size(), 3u);
    EXPECT_EQ(results[0].statusCode, 0);
    EXPECT_EQ(results[0].group.groupId, first);
    EXPECT_NE(results[1].statusCode, 0);
    EXPECT_EQ(results[2].statusCode, 0);
    EXPECT_EQ(results[2].group.groupId, second);

    disconnect();
    connectAs(2);
    ASSERT_NO_THROW({ results = groupApi->getGroups({first, second}); });
    EXPECT_EQ(results[0].statusCode, 0);
    EXPECT_NE(results[1].statusCode, 0); // user_2 is not in the second one
}

TEST_F(GroupTest, a_removal_and_a_rotation_say_which_epoch_they_made) {
    std::string groupId = createGroupOf({user(1), user(2)});
    int64_t epoch = 0;
    ASSERT_NO_THROW({ epoch = groupApi->removeGroupMembers(groupId, {reader->getString("Login.user_2_id")}); });
    EXPECT_EQ(epoch, 2);
    EXPECT_EQ(groupApi->getGroup(groupId).keyVersion, 2);
    ASSERT_NO_THROW({ epoch = groupApi->rotateGroupKey(groupId); });
    EXPECT_EQ(epoch, 3);
    // The envelope a server gates on carries that epoch.
    EXPECT_EQ(
        group::GroupApi::peekEnvelope(groupApi->encrypt(groupId, messagePath("m1"), core::Buffer::from("x"))).keyVersion, 3
    );
}

TEST_F(GroupTest, envelope_shared_with_another_group_and_a_user) {
    // The care team writes; billing (another group) and one auditor (a single user) read it too.
    const std::string contextId = reader->getString("Context_1.contextId");
    const std::string user1 = reader->getString("Login.user_1_id");
    const std::string user2 = reader->getString("Login.user_2_id");
    std::string care = createGroupOf({user(1)});
    std::string billing = createGroupOf({user(1), user(2)});

    group::EncryptOptions options;
    options.alsoFor.push_back({.groupId = billing, .user = std::nullopt});
    core::Buffer shared = groupApi->encrypt(care, messagePath("d1"), core::Buffer::from("discharge"), options);

    group::EncryptOptions toUser;
    toUser.alsoFor.push_back({.groupId = "", .user = user(2)});
    core::Buffer sharedWithUser = groupApi->encrypt(care, messagePath("d2"), core::Buffer::from("for the auditor"), toUser);

    // The home group reads it as its own member's, and sees who else can.
    group::DecryptedEnvelope home = groupApi->decrypt(care, messagePath("d1"), shared, writtenBy(user1));
    EXPECT_EQ(home.sharedWith.groups, std::vector<std::string>{billing});
    // user_1 is in billing as well, and in the home group: the sender is known to be a member.
    group::DecryptedSharedEnvelope viaBilling = groupApi->decryptShared(contextId, messagePath("d1"), shared, anyAuthor());
    EXPECT_EQ(viaBilling.via, billing);
    EXPECT_EQ(viaBilling.senderMembership, "member");

    disconnect();
    connectAs(2);

    group::DecryptedSharedEnvelope opened;
    EXPECT_NO_THROW({ opened = groupApi->decryptShared(contextId, messagePath("d1"), shared, writtenBy(user1)); });
    EXPECT_EQ(opened.data.stdString(), "discharge");
    EXPECT_EQ(opened.sender.userId, user1);
    EXPECT_EQ(opened.homeGroupId, care);
    EXPECT_EQ(opened.via, billing);
    // user_2 cannot see the care team's roster: that user_1 wrote this from inside it is user_1's word.
    EXPECT_EQ(opened.senderMembership, "unknown");
    EXPECT_EQ(opened.sharedWith.groups, std::vector<std::string>{billing});
    EXPECT_THROW(
        { groupApi->decryptShared(contextId, messagePath("d9"), shared, anyAuthor()); },
        group::EnvelopeWrongLocationException
    );
    // Not through the home group: user_2 is not in it.
    EXPECT_ANY_THROW({ groupApi->decrypt(care, messagePath("d1"), shared, anyAuthor()); });

    group::DecryptedSharedEnvelope asUser;
    EXPECT_NO_THROW({ asUser = groupApi->decryptShared(contextId, messagePath("d2"), sharedWithUser, anyAuthor()); });
    EXPECT_EQ(asUser.data.stdString(), "for the auditor");
    EXPECT_EQ(asUser.via, "user");
    EXPECT_EQ(asUser.sharedWith.users, std::vector<std::string>{user2});

    // A removal in billing replaces its key: the next envelope is wrapped to the new one, not the old.
    disconnect();
    connectAs(1);
    ASSERT_NO_THROW({ groupApi->removeGroupMembers(billing, {user2}); });
    core::Buffer after = groupApi->encrypt(care, messagePath("d3"), core::Buffer::from("after the removal"), options);
    const group::EnvelopeHeader header = group::GroupApi::peekEnvelope(after);
    ASSERT_EQ(header.alsoForGroups.size(), 1u);
    EXPECT_EQ(header.alsoForGroups[0].keyVersion, 2);
    disconnect();
    connectAs(2);
    EXPECT_ANY_THROW({ groupApi->decryptShared(contextId, messagePath("d3"), after, anyAuthor()); });
}

TEST_F(GroupTest, envelope_file_roundtrip_as_documented) {
    // The sealing and opening examples from GroupApi.hpp, run against a real bridge exactly as written.
    // So the snippets below can be pasted in exactly as the header writes them.
    using namespace privmx::endpoint::group;
    auto& api = *groupApi;
    std::string groupId = createGroupOf({user(1), user(2)});

    // Deliberately not a whole number of chunks, so the short final chunk is exercised.
    std::string plain;
    for (int i = 0; plain.size() < 2 * 1024 * 1024 + 12345; ++i) {
        plain.append("chunk-" + std::to_string(i) + "-payload;");
    }
    ByteSource source{plain};
    ByteSink sink;
    const std::size_t plaintextSize = plain.size();

    // --- verbatim from GroupApi.hpp, beginFileEncryption ---
    FileHandle h = api.beginFileEncryption(groupId, plaintextSize);
    while (source.hasMore()) {
        sink.write(api.encryptFileChunk(h, source.read(1 << 20)));  // may write nothing; that is normal
    }
    Envelope envelope = api.finishFileEncryption(h);  // keep this alongside the ciphertext
    // --- end verbatim ---

    EXPECT_GT(sink.data.size(), plain.size());
    EXPECT_EQ(sink.data.find("chunk-0-payload"), std::string::npos);

    // The ciphertext and the envelope travel to whoever reads it; nothing else is needed.
    CipherStorage storage{sink.data};
    disconnect();
    connectAs(2);

    // A scope of its own so `api`, `h` and `sink` name this connection's reader, letting the example below
    // stay character-for-character what the header says.
    {
        auto& api = *groupApi;
        ByteSink sink;

        // --- verbatim from GroupApi.hpp, beginFileDecryption ---
        FileHandle h = api.beginFileDecryption(envelope);
        while (storage.hasMore()) {
            sink.write(api.decryptFileChunk(h, storage.read(1 << 20)));
        }
        DecryptedFileInfo info = api.finishFileDecryption(h);  // who sent it, and was it whole
        // --- end verbatim ---

        EXPECT_EQ(sink.data, plain);
        EXPECT_EQ(info.groupId, groupId);
        EXPECT_EQ(info.type, ENVELOPE_FROM_MEMBER);
        EXPECT_EQ(info.authorPubKey, reader->getString("Login.user_1_pubKey"));
        // A straight read start to finish is exactly the case that keeps the whole-file guarantee.
        EXPECT_TRUE(info.complete);
    }
}

TEST_F(GroupTest, envelope_file_truncation_is_detected) {
    std::string groupId = createGroupOf({user(1)});

    const std::string plain(300 * 1024, 'x'); // three chunks
    int64_t writeHandle = groupApi->beginFileEncryption(groupId, (int64_t)plain.size());
    std::string cipher = groupApi->encryptFileChunk(writeHandle, core::Buffer::from(plain)).stdString();
    core::Buffer envelope = groupApi->finishFileEncryption(writeHandle);

    // Feed back everything but the final chunk. Each chunk that did arrive verifies on its own, so the only
    // thing that can notice the missing tail is the size signed into the envelope.
    int64_t readHandle = groupApi->beginFileDecryption(envelope);
    const std::size_t twoChunks = 2 * (1 + 16 + (128 * 1024 + 16) + 16);
    groupApi->decryptFileChunk(readHandle, core::Buffer::from(cipher.substr(0, twoChunks)));
    EXPECT_THROW({ groupApi->finishFileDecryption(readHandle); }, core::Exception);
    // The handle is gone even though the close threw — otherwise the file key would outlive the failure.
    EXPECT_ANY_THROW({ groupApi->finishFileDecryption(readHandle); });
}

TEST_F(GroupTest, envelope_file_overrun_is_refused_as_it_arrives) {
    // The mirror of truncation, caught on the way in rather than at the close: bytes past the last chunk can
    // never be opened, so buffering them would let a long ciphertext against a short declared size exhaust memory.
    std::string groupId = createGroupOf({user(1)});

    const std::string plain(200 * 1024, 'y'); // two chunks, the second short
    int64_t writeHandle = groupApi->beginFileEncryption(groupId, (int64_t)plain.size());
    std::string cipher = groupApi->encryptFileChunk(writeHandle, core::Buffer::from(plain)).stdString();
    core::Buffer envelope = groupApi->finishFileEncryption(writeHandle);

    // The whole file, and then a megabyte of anything at all.
    int64_t readHandle = groupApi->beginFileDecryption(envelope);
    EXPECT_THROW(
        { groupApi->decryptFileChunk(readHandle, core::Buffer::from(cipher + std::string(1 << 20, 'z'))); },
        core::Exception
    );
    // A caller that swallowed the throw and closed anyway still gets told: the excess is still buffered, so
    // the close-time classification reaches the same verdict.
    EXPECT_THROW({ groupApi->finishFileDecryption(readHandle); }, core::Exception);

    // Exactly the declared length is still accepted, and still counts as whole.
    int64_t exact = groupApi->beginFileDecryption(envelope);
    groupApi->decryptFileChunk(exact, core::Buffer::from(cipher));
    EXPECT_TRUE(groupApi->finishFileDecryption(exact).complete);
}

TEST_F(GroupTest, envelope_file_range_read_as_documented) {
    // The range-reading example from GroupApi.hpp::seekInEncryptedFile, run as written.
    // So the snippets below can be pasted in exactly as the header writes them.
    using namespace privmx::endpoint::group;
    auto& api = *groupApi;
    std::string groupId = createGroupOf({user(1)});

    std::string plain;
    for (int i = 0; plain.size() < 600 * 1024; ++i) {
        plain.append("seek-" + std::to_string(i) + "-marker;");
    }

    FileHandle writeHandle = api.beginFileEncryption(groupId, plain.size());
    std::string cipher = api.encryptFileChunk(writeHandle, core::Buffer::from(plain)).stdString();
    Envelope envelope = api.finishFileEncryption(writeHandle);

    CipherStorage storage{cipher};
    // Deliberately mid-chunk, so the promised head trim is what makes the result line up.
    const std::size_t from = 300 * 1024 + 777;
    const std::size_t length = 50 * 1024;

    // --- verbatim from GroupApi.hpp, seekInEncryptedFile ---
    FileHandle h = api.beginFileDecryption(envelope);
    CipherOffset at = api.seekInEncryptedFile(h, from);

    std::string out;
    while (out.size() < length) {
        core::Buffer block = storage.read(at, 1 << 20);  // your storage, your transport
        if (block.size() == 0) break;                    // ran off the end of the ciphertext
        at += block.size();
        out += api.decryptFileChunk(h, block).stdString();
    }
    out.resize(length);                                  // front is exact, tail may overshoot
    api.finishFileDecryption(h);
    // --- end verbatim ---

    // The documentation promises the output begins exactly at `from`, despite `from` landing mid-chunk.
    EXPECT_EQ(out, plain.substr(from, length));
    // ...and that the offset it hands back points at a chunk boundary, never into the middle of one.
    const std::size_t encryptedChunk = 1 + 16 + (128 * 1024 + 16) + 16;
    EXPECT_EQ(api.seekInEncryptedFile(api.beginFileDecryption(envelope), from) % encryptedChunk, 0);

    // A range reader that stops once it has enough ends mid-chunk, with bytes buffered and most of the file
    // never opened. Documented usage, so finishing must not error — it once did, on the declared-size check.
    {
        FileHandle partial = api.beginFileDecryption(envelope);
        CipherOffset seekedTo = api.seekInEncryptedFile(partial, from);
        // One block deliberately larger than a chunk and not a whole number of them, so it ends mid-chunk.
        const std::size_t oneAndAHalfChunks = encryptedChunk + encryptedChunk / 2;
        api.decryptFileChunk(
            partial, core::Buffer::from(cipher.substr(seekedTo, oneAndAHalfChunks))
        );
        DecryptedFileInfo info;
        EXPECT_NO_THROW({ info = api.finishFileDecryption(partial); });
        // Not an error, but not a whole-file guarantee either.
        EXPECT_FALSE(info.complete);
        EXPECT_EQ(info.groupId, groupId);
    }

    // A straight read start to finish still earns the guarantee.
    FileHandle whole = api.beginFileDecryption(envelope);
    api.decryptFileChunk(whole, core::Buffer::from(cipher));
    EXPECT_TRUE(api.finishFileDecryption(whole).complete);

    // And a straight read that is genuinely short is still refused.
    FileHandle short_ = api.beginFileDecryption(envelope);
    api.decryptFileChunk(short_, core::Buffer::from(cipher.substr(0, encryptedChunk)));
    EXPECT_THROW({ api.finishFileDecryption(short_); }, core::Exception);

    // Seeking past the end is a caller error, not a silent clamp.
    FileHandle bad = api.beginFileDecryption(envelope);
    EXPECT_THROW({ api.seekInEncryptedFile(bad, (int64_t)plain.size() + 1); }, core::Exception);
    api.seekInEncryptedFile(bad, plain.size());
    api.finishFileDecryption(bad);
}

TEST_F(GroupTest, envelope_repeated_decrypt_and_two_keys_in_one_session) {
    // Opening many envelopes reuses one unwrapped key, and a rotation puts a second key in play alongside it.
    // The risk this guards is not speed but the memo handing back the wrong key once two are cached at once.
    std::string groupId = createGroupOf({user(1), user(2)});

    std::vector<core::Buffer> envelopes;
    for (int i = 0; i < 20; ++i) {
        envelopes.push_back(
            groupApi->encrypt(groupId, messagePath("m" + std::to_string(i)), core::Buffer::from("message " + std::to_string(i)))
        );
    }
    // Every one of these but the first should be served from the unwrapped-key memo. Correctness is what is
    // assertable here; that they cost no round trips is structural, not something the test can observe.
    for (int i = 0; i < 20; ++i) {
        group::DecryptedEnvelope opened;
        EXPECT_NO_THROW({
            opened = groupApi->decrypt(groupId, messagePath("m" + std::to_string(i)), envelopes[i], anyAuthor());
        });
        EXPECT_EQ(opened.data.stdString(), "message " + std::to_string(i));
    }

    // A removal mints a new metadata key, so from here two distinct keyIds are live in the same session.
    ASSERT_NO_THROW({ groupApi->removeGroupMembers(groupId, {reader->getString("Login.user_2_id")}); });
    core::Buffer afterRotation = groupApi->encrypt(groupId, messagePath("after"), core::Buffer::from("after the rotation"));

    // Interleaved on purpose: an envelope under the new key, then one under the old, then the new one again.
    EXPECT_EQ(groupApi->decrypt(groupId, messagePath("after"), afterRotation, anyAuthor()).data.stdString(), "after the rotation");
    EXPECT_EQ(groupApi->decrypt(groupId, messagePath("m7"), envelopes[7], anyAuthor()).data.stdString(), "message 7");
    EXPECT_EQ(groupApi->decrypt(groupId, messagePath("after"), afterRotation, anyAuthor()).data.stdString(), "after the rotation");
    EXPECT_EQ(groupApi->decrypt(groupId, messagePath("m19"), envelopes[19], anyAuthor()).data.stdString(), "message 19");
}

// ── Roles, the roster's own rules, the log ──────────────────────────────────────────────────────────────────────

TEST_F(GroupTest, a_role_change_is_a_statement_every_member_verifies) {
    std::string groupId = createGroupOf({user(1), user(2)});
    const std::string user2 = reader->getString("Login.user_2_id");
    ASSERT_NO_THROW({ groupApi->setGroupRoles(groupId, {group::GroupRoleChange{.userId = user2, .role = "manager"}}); });
    group::Group promoted;
    ASSERT_NO_THROW({ promoted = groupApi->getGroup(groupId); });
    EXPECT_EQ(promoted.statusCode, 0);
    EXPECT_EQ(promoted.keyVersion, 1) << "a role is not a key: no epoch opens";
    EXPECT_EQ(promoted.rosterVersion, 2);
    EXPECT_NE(std::find(promoted.managers.begin(), promoted.managers.end(), user2), promoted.managers.end());
    EXPECT_EQ(std::find(promoted.users.begin(), promoted.users.end(), user2), promoted.users.end());
    // Naming somebody for the role they have changes nothing, and is refused before anything is signed.
    EXPECT_THROW(
        { groupApi->setGroupRoles(groupId, {group::GroupRoleChange{.userId = user2, .role = "manager"}}); },
        core::Exception
    );
    EXPECT_THROW(
        { groupApi->setGroupRoles(groupId, {group::GroupRoleChange{.userId = "nobody", .role = "user"}}); },
        core::Exception
    );

    // The promoted member reads the group from the statements alone, and does what a manager may: rewrite metadata.
    disconnect();
    connectAs(2);
    group::Group asManager;
    ASSERT_NO_THROW({ asManager = groupApi->getGroup(groupId); });
    EXPECT_EQ(asManager.statusCode, 0);
    ASSERT_NO_THROW({
        groupApi->updateGroupPublicMeta(groupId, core::Buffer::from("by the new manager"), asManager.publicMetaVersion);
    });

    // Demoted again, by the other manager. The metadata the demoted member wrote stays readable: it is carried.
    disconnect();
    connectAs(1);
    ASSERT_NO_THROW({ groupApi->setGroupRoles(groupId, {group::GroupRoleChange{.userId = user2, .role = "user"}}); });
    group::Group demoted;
    ASSERT_NO_THROW({ demoted = groupApi->getGroup(groupId); });
    EXPECT_EQ(demoted.statusCode, 0);
    EXPECT_EQ(demoted.publicMeta.stdString(), "by the new manager");
    EXPECT_EQ(std::find(demoted.managers.begin(), demoted.managers.end(), user2), demoted.managers.end());
    // A group that has managers keeps one.
    EXPECT_THROW(
        {
            groupApi->setGroupRoles(
                groupId, {group::GroupRoleChange{.userId = reader->getString("Login.user_1_id"), .role = "user"}}
            );
        },
        core::Exception
    );

    disconnect();
    connectAs(2);
    ASSERT_NO_THROW({ demoted = groupApi->getGroup(groupId); });
    EXPECT_EQ(demoted.statusCode, 0);
    EXPECT_THROW(
        { groupApi->updateGroupPublicMeta(groupId, core::Buffer::from("no longer mine"), demoted.publicMetaVersion); },
        core::Exception
    );
    // A user handing itself the role is refused by its own client, before the Bridge sees anything.
    EXPECT_THROW(
        { groupApi->setGroupRoles(groupId, {group::GroupRoleChange{.userId = user2, .role = "manager"}}); },
        group::GroupUnauthorizedSignerException
    );
}

TEST_F(GroupTest, the_rules_split_adding_from_removing) {
    core::ContainerPolicy policy;
    policy.addMembers = "user";
    std::string groupId = groupApi->createGroup(
        reader->getString("Context_1.contextId"), {user(1), user(2)}, {user(1)}, core::Buffer::from("public"),
        core::Buffer::from("private"), policy
    );
    group::Group created;
    ASSERT_NO_THROW({ created = groupApi->getGroup(groupId); });
    EXPECT_EQ(created.rules.addMembers, "user");
    EXPECT_EQ(created.rules.removeMembers, "manager") << "left unset, it follows update";
    EXPECT_EQ(created.rules.updateMeta, "manager");

    // A plain user adds, and may not remove.
    disconnect();
    connectAs(2);
    ASSERT_NO_THROW({
        groupApi->addGroupMembers(groupId, {group::GroupMemberToAdd{.user = user(3), .role = "user"}});
    });
    EXPECT_THROW(
        { groupApi->addGroupMembers(groupId, {group::GroupMemberToAdd{.user = user(3), .role = "manager"}}); },
        core::Exception
    ) << "adding is not handing out the manager role";
    const std::string user3 = reader->getString("Login.user_3_id");
    EXPECT_THROW({ groupApi->removeGroupMembers(groupId, {user3}); }, group::GroupUnauthorizedSignerException);

    // The manager opens removing to users too; the rest of the policy stays.
    disconnect();
    connectAs(1);
    ASSERT_NO_THROW({ groupApi->updateGroupRules(groupId, group::GroupRulesUpdate{.removeMembers = "user"}); });
    group::Group opened;
    ASSERT_NO_THROW({ opened = groupApi->getGroup(groupId); });
    EXPECT_EQ(opened.statusCode, 0);
    EXPECT_EQ(opened.rules.addMembers, "user");
    EXPECT_EQ(opened.rules.removeMembers, "user");

    disconnect();
    connectAs(2);
    int64_t epoch = 0;
    ASSERT_NO_THROW({ epoch = groupApi->removeGroupMembers(groupId, {user3}); });
    EXPECT_EQ(epoch, 2);
}

TEST_F(GroupTest, the_log_lists_every_statement_from_the_creation) {
    std::string groupId = createGroupOf({user(1), user(2)});
    const std::string user1 = reader->getString("Login.user_1_id");
    const std::string user2 = reader->getString("Login.user_2_id");
    const std::string user3 = reader->getString("Login.user_3_id");
    ASSERT_NO_THROW({
        groupApi->addGroupMembers(groupId, {group::GroupMemberToAdd{.user = user(3), .role = "user"}});
        groupApi->setGroupRoles(groupId, {group::GroupRoleChange{.userId = user2, .role = "manager"}});
        groupApi->removeGroupMembers(groupId, {user3});
    });
    // A self-update is a statement too, and the library makes them when it sees fit: left out of the comparison.
    const auto roster = [&](const core::PagingQuery& query) {
        std::vector<group::GroupLogEntry> entries;
        for (const group::GroupLogEntry& entry : groupApi->getGroupLog(groupId, query).readItems) {
            if (entry.kind != "selfUpdate") {
                entries.push_back(entry);
            }
        }
        return entries;
    };
    std::vector<group::GroupLogEntry> log;
    ASSERT_NO_THROW({ log = roster(core::PagingQuery{.skip = 0, .limit = 100, .sortOrder = "asc"}); });
    ASSERT_EQ(log.size(), 4u);
    EXPECT_EQ(log[0].kind, "create");
    EXPECT_EQ(log[0].seq, 1);
    EXPECT_EQ(log[1].kind, "add");
    EXPECT_EQ(log[1].addedUsers, std::vector<std::string>{user3});
    EXPECT_EQ(log[2].kind, "roles");
    EXPECT_EQ(log[2].addedManagers, std::vector<std::string>{user2});
    EXPECT_EQ(log[3].kind, "remove");
    EXPECT_EQ(log[3].removed, std::vector<std::string>{user3});
    EXPECT_EQ(log[3].keyVersion, 2);
    for (const group::GroupLogEntry& entry : log) {
        EXPECT_EQ(entry.author, user1);
        EXPECT_EQ(entry.authorPubKey, user(1).pubKey);
    }
    // Newest first, and a window of it.
    core::PagingList<group::GroupLogEntry> page;
    ASSERT_NO_THROW({ page = groupApi->getGroupLog(groupId, core::PagingQuery{.skip = 0, .limit = 1, .sortOrder = "desc"}); });
    EXPECT_GE(page.totalAvailable, 4);
    ASSERT_EQ(page.readItems.size(), 1u);
    EXPECT_GE(page.readItems[0].seq, 4);
    EXPECT_THROW(
        { groupApi->getGroupLog(groupId, core::PagingQuery{.skip = 0, .limit = 0, .sortOrder = "asc"}); },
        core::Exception
    );

    // Another member replays the same chain. Somebody outside the group is told nothing.
    disconnect();
    connectAs(2);
    ASSERT_NO_THROW({ log = roster(core::PagingQuery{.skip = 0, .limit = 100, .sortOrder = "asc"}); });
    EXPECT_EQ(log.size(), 4u);
    disconnect();
    connectAs(3);
    EXPECT_THROW(
        { groupApi->getGroupLog(groupId, core::PagingQuery{.skip = 0, .limit = 10, .sortOrder = "asc"}); },
        core::Exception
    );
}
