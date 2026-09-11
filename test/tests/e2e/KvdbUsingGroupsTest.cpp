#include <gtest/gtest.h>
#include <algorithm>
#include "../../utils/BaseGroupTest.hpp"
#include "privmx/utils/Logger.hpp"
#include <privmx/endpoint/core/Exception.hpp>
#include <Poco/Util/IniFileConfiguration.h>
#include <privmx/endpoint/core/EventQueueImpl.hpp>
#include <privmx/utils/Utils.hpp>
#include <privmx/endpoint/core/VarSerializer.hpp>
#include <privmx/endpoint/core/Connection.hpp>
#include <privmx/endpoint/kvdb/KvdbApi.hpp>
#include <privmx/endpoint/kvdb/VarSerializer.hpp>
#include <privmx/endpoint/group/GroupApi.hpp>
#include <privmx/endpoint/group/VarSerializer.hpp>
#include <privmx/endpoint/core/ConvertedExceptions.hpp>
#include <privmx/endpoint/core/CoreException.hpp>
using namespace privmx::endpoint;

class KvdbUsingGroupsTest : public privmx::test::BaseGroupTest {
protected:
    void setUpModuleApis() override {
        kvdbApi = std::make_shared<kvdb::KvdbApi>(kvdb::KvdbApi::create(*connection, *groupApi));
    }
    void tearDownModuleApis() override {
        kvdbApi.reset();
    }
    // A KVDB whose direct members are `users` (as both users and managers) and whose grantee groups are
    // `groups`. Leaving `groupEpoch` at 0 makes the endpoint resolve each group's current epoch from the Bridge.
    std::string createKvdbWithGroups(
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
        return kvdbApi->createKvdb(
            contextId,
            users,
            users,
            core::Buffer::from("group_kvdb_public"),
            core::Buffer::from("group_kvdb_private"),
            core::ContainerPolicy(),
            grants
        );
    }
    std::string createKvdbWithGroupPolicyReadAll(
        const std::string& contextId,
        const std::string& userId,
        const std::string& userPubKey,
        const group::Group& group
    ) {
        core::ContainerPolicy policy;
        policy.get = "all";
        policy.item = core::ItemPolicy{.get = "all", .listAll = "all"};
        return kvdbApi->createKvdb(
            contextId,
            std::vector<core::UserWithPubKey>{{.userId = userId, .pubKey = userPubKey}},
            std::vector<core::UserWithPubKey>{{.userId = userId, .pubKey = userPubKey}},
            core::Buffer::from("group_kvdb_public"),
            core::Buffer::from("group_kvdb_private"),
            policy,
            std::vector<core::GroupGrantWithKey>{{
                .groupId = group.groupId,
                .role = "user",
                .groupPubKey = group.groupPubKey
            }}
        );
    }
    // Writes a brand-new entry (version 0 means "must not exist yet").
    void setNewEntry(
        const std::string& kvdbId,
        const std::string& key,
        const std::string& publicMeta,
        const std::string& privateMeta,
        const std::string& data
    ) {
        kvdbApi->setEntry(
            kvdbId,
            key,
            core::Buffer::from(publicMeta),
            core::Buffer::from(privateMeta),
            core::Buffer::from(data),
            0
        );
    }

    std::shared_ptr<kvdb::KvdbApi> kvdbApi;
};

TEST_F(KvdbUsingGroupsTest, createKvdb_with_group_grants) {
    group::Group group_1;
    ASSERT_NO_THROW({ group_1 = groupApi->getGroup(reader->getString("Group_1.groupId")); });
    ASSERT_EQ(group_1.statusCode, 0);
    ASSERT_FALSE(group_1.groupPubKey.empty());

    std::string kvdbId;

    EXPECT_NO_THROW({
        kvdbId = kvdbApi->createKvdb(
            reader->getString("Context_1.contextId"),
            std::vector<core::UserWithPubKey>{user(1)},
            std::vector<core::UserWithPubKey>{user(1)},
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
    ASSERT_FALSE(kvdbId.empty());

    kvdb::Kvdb k;

    EXPECT_NO_THROW({ k = kvdbApi->getKvdb(kvdbId); });
    EXPECT_EQ(k.statusCode, 0);
    EXPECT_EQ(k.publicMeta.stdString(), "public_meta");
    EXPECT_EQ(k.groups.size(), 1);
    if (k.groups.size() == 1) {
        EXPECT_EQ(k.groups[0].groupId, group_1.groupId);
        EXPECT_EQ(k.groups[0].role, "user");
    }
}

TEST_F(KvdbUsingGroupsTest, createKvdb_with_multiple_group_grants) {
    group::Group group_1, group_2;
    ASSERT_NO_THROW({ group_1 = groupApi->getGroup(reader->getString("Group_1.groupId")); });
    ASSERT_NO_THROW({ group_2 = groupApi->getGroup(reader->getString("Group_2.groupId")); });
    ASSERT_EQ(group_1.statusCode, 0);
    ASSERT_EQ(group_2.statusCode, 0);

    std::string kvdbId;
    EXPECT_NO_THROW({
        kvdbId = kvdbApi->createKvdb(
            reader->getString("Context_1.contextId"),
            std::vector<core::UserWithPubKey>{user(1)},
            std::vector<core::UserWithPubKey>{user(1)},
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
    ASSERT_FALSE(kvdbId.empty());

    kvdb::Kvdb k;
    EXPECT_NO_THROW({ k = kvdbApi->getKvdb(kvdbId); });
    EXPECT_EQ(k.statusCode, 0);
    EXPECT_EQ(k.groups.size(), 2);
    bool found1 = false, found2 = false;
    for (const auto& g : k.groups) {
        if (g.groupId == group_1.groupId && g.role == "user") found1 = true;
        if (g.groupId == group_2.groupId && g.role == "manager") found2 = true;
    }
    EXPECT_TRUE(found1);
    EXPECT_TRUE(found2);
}

TEST_F(KvdbUsingGroupsTest, createKvdb_without_groups_has_empty_groups_field) {
    std::string kvdbId;
    EXPECT_NO_THROW({
        kvdbId = kvdbApi->createKvdb(
            reader->getString("Context_1.contextId"),
            std::vector<core::UserWithPubKey>{user(1)},
            std::vector<core::UserWithPubKey>{user(1)},
            core::Buffer::from("no_groups_public"),
            core::Buffer::from("no_groups_private")
        );
    });
    ASSERT_FALSE(kvdbId.empty());

    kvdb::Kvdb k;
    EXPECT_NO_THROW({ k = kvdbApi->getKvdb(kvdbId); });
    EXPECT_EQ(k.statusCode, 0);
    EXPECT_EQ(k.groups.size(), 0);
}

TEST_F(KvdbUsingGroupsTest, updateKvdb_add_group) {
    std::string kvdbId;
    EXPECT_NO_THROW({
        kvdbId = kvdbApi->createKvdb(
            reader->getString("Context_1.contextId"),
            std::vector<core::UserWithPubKey>{user(1)},
            std::vector<core::UserWithPubKey>{user(1)},
            core::Buffer::from("before_group"),
            core::Buffer::from("before_group_private")
        );
    });
    ASSERT_FALSE(kvdbId.empty());

    kvdb::Kvdb k;
    EXPECT_NO_THROW({ k = kvdbApi->getKvdb(kvdbId); });
    EXPECT_EQ(k.groups.size(), 0);

    group::Group group_1;
    ASSERT_NO_THROW({ group_1 = groupApi->getGroup(reader->getString("Group_1.groupId")); });
    ASSERT_EQ(group_1.statusCode, 0);

    EXPECT_NO_THROW({
        kvdbApi->updateKvdb(
            kvdbId,
            std::vector<core::UserWithPubKey>{user(1)},
            std::vector<core::UserWithPubKey>{user(1)},
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

    kvdb::Kvdb updated;
    EXPECT_NO_THROW({ updated = kvdbApi->getKvdb(kvdbId); });
    EXPECT_EQ(updated.statusCode, 0);
    EXPECT_EQ(updated.publicMeta.stdString(), "after_group");
    EXPECT_EQ(updated.groups.size(), 1);
    if (updated.groups.size() == 1) {
        EXPECT_EQ(updated.groups[0].groupId, group_1.groupId);
        EXPECT_EQ(updated.groups[0].role, "user");
    }
}

TEST_F(KvdbUsingGroupsTest, updateKvdb_remove_group) {
    group::Group group_2;
    ASSERT_NO_THROW({ group_2 = groupApi->getGroup(reader->getString("Group_2.groupId")); });
    ASSERT_EQ(group_2.statusCode, 0);

    // policy.get="all" so user_2 can always call getKvdb without throwing; after group removal it
    // receives statusCode!=0 and empty privateMeta because it no longer holds the decryption key.
    core::ContainerPolicy policy;
    policy.get = "all";

    std::string kvdbId;
    EXPECT_NO_THROW({
        kvdbId = kvdbApi->createKvdb(
            reader->getString("Context_1.contextId"),
            std::vector<core::UserWithPubKey>{user(1)},
            std::vector<core::UserWithPubKey>{user(1)},
            core::Buffer::from("with_group"),
            core::Buffer::from("with_group_private"),
            policy,
            std::vector<core::GroupGrantWithKey>{core::GroupGrantWithKey{
                .groupId = group_2.groupId, .role = "user", .groupPubKey = group_2.groupPubKey
            }}
        );
    });
    ASSERT_FALSE(kvdbId.empty());

    disconnect();
    connectAs(2);
    kvdb::Kvdb beforeRemoval;
    EXPECT_NO_THROW({ beforeRemoval = kvdbApi->getKvdb(kvdbId); });
    EXPECT_EQ(beforeRemoval.statusCode, 0);
    EXPECT_FALSE(beforeRemoval.privateMeta.stdString().empty());

    disconnect();
    connectAs(1);
    EXPECT_NO_THROW({
        kvdbApi->updateKvdb(
            kvdbId,
            std::vector<core::UserWithPubKey>{user(1)},
            std::vector<core::UserWithPubKey>{user(1)},
            core::Buffer::from("no_group_now"),
            core::Buffer::from("no_group_private"),
            1,
            false,
            false,
            std::nullopt,
            std::vector<core::GroupGrantWithKey>{}
        );
    });

    kvdb::Kvdb updated;
    EXPECT_NO_THROW({ updated = kvdbApi->getKvdb(kvdbId); });
    EXPECT_EQ(updated.statusCode, 0);
    EXPECT_EQ(updated.groups.size(), 0);

    disconnect();
    connectAs(2);
    kvdb::Kvdb afterRemoval;
    EXPECT_NO_THROW({ afterRemoval = kvdbApi->getKvdb(kvdbId); });
    EXPECT_NE(afterRemoval.statusCode, 0);
    EXPECT_TRUE(afterRemoval.privateMeta.stdString().empty());
}

TEST_F(KvdbUsingGroupsTest, updateKvdb_change_group_role) {
    group::Group group_1;
    ASSERT_NO_THROW({ group_1 = groupApi->getGroup(reader->getString("Group_1.groupId")); });
    ASSERT_EQ(group_1.statusCode, 0);

    std::string kvdbId;
    ASSERT_NO_THROW({
        kvdbId = createKvdbWithGroups(
            reader->getString("Context_1.contextId"),
            std::vector<core::UserWithPubKey>{user(1)},
            std::vector<group::Group>{group_1}
        );
    });
    ASSERT_FALSE(kvdbId.empty());

    EXPECT_NO_THROW({
        kvdbApi->updateKvdb(
            kvdbId,
            std::vector<core::UserWithPubKey>{user(1)},
            std::vector<core::UserWithPubKey>{user(1)},
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

    kvdb::Kvdb updated;
    EXPECT_NO_THROW({ updated = kvdbApi->getKvdb(kvdbId); });
    EXPECT_EQ(updated.groups.size(), 1);
    if (updated.groups.size() == 1) {
        EXPECT_EQ(updated.groups[0].groupId, group_1.groupId);
        EXPECT_EQ(updated.groups[0].role, "manager");
    }
}

TEST_F(KvdbUsingGroupsTest, listKvdbs_includes_groups_field) {
    group::Group group_1;
    ASSERT_NO_THROW({ group_1 = groupApi->getGroup(reader->getString("Group_1.groupId")); });
    ASSERT_EQ(group_1.statusCode, 0);

    std::string kvdbId;
    ASSERT_NO_THROW({
        kvdbId = createKvdbWithGroups(
            reader->getString("Context_1.contextId"),
            std::vector<core::UserWithPubKey>{user(1)},
            std::vector<group::Group>{group_1}
        );
    });
    ASSERT_FALSE(kvdbId.empty());

    core::PagingList<kvdb::Kvdb> list;
    EXPECT_NO_THROW({
        list = kvdbApi->listKvdbs(
            reader->getString("Context_1.contextId"),
            core::PagingQuery{.skip = 0, .limit = 100, .sortOrder = "desc"}
        );
    });
    bool found = false;
    for (const auto& k : list.readItems) {
        if (k.kvdbId == kvdbId) {
            EXPECT_EQ(k.statusCode, 0);
            EXPECT_EQ(k.groups.size(), 1);
            if (k.groups.size() == 1) {
                EXPECT_EQ(k.groups[0].groupId, group_1.groupId);
                EXPECT_EQ(k.groups[0].role, "user");
            }
            found = true;
            break;
        }
    }
    EXPECT_TRUE(found);
}

TEST_F(KvdbUsingGroupsTest, createKvdb_with_invalid_group_pubkey_throws) {
    EXPECT_THROW({
        kvdbApi->createKvdb(
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

TEST_F(KvdbUsingGroupsTest, getEntry_via_group_grant) {
    // Kvdb_4 and KvdbEntry_3 come from the dataset, so this reads bytes an earlier build wrote. user_2 holds no
    // entry in Kvdb_4's own roster: the group grant is the only route to the key.
    disconnect();
    connectAs(2);
    kvdb::KvdbEntry entry;
    EXPECT_NO_THROW({
        entry = kvdbApi->getEntry(reader->getString("Kvdb_4.kvdbId"), reader->getString("KvdbEntry_3.info_key"));
    });
    EXPECT_EQ(entry.statusCode, 0);
    EXPECT_EQ(
        entry.privateMeta.stdString(), privmx::utils::Hex::toString(reader->getString("KvdbEntry_3.privateMeta_inHex"))
    );
    EXPECT_EQ(entry.data.stdString(), privmx::utils::Hex::toString(reader->getString("KvdbEntry_3.data_inHex")));
}

TEST_F(KvdbUsingGroupsTest, listEntries_via_group_grant) {
    // Kvdb_4 is seeded with KvdbEntry_3 and KvdbEntry_4, so the paging path has more than one row to return.
    disconnect();
    connectAs(2);
    core::PagingList<kvdb::KvdbEntry> list;
    EXPECT_NO_THROW({
        list = kvdbApi->listEntries(
            reader->getString("Kvdb_4.kvdbId"), core::PagingQuery{.skip = 0, .limit = 10, .sortOrder = "desc"}
        );
    });
    EXPECT_EQ(list.totalAvailable, 2);
    for (const auto& entry : list.readItems) {
        EXPECT_EQ(entry.statusCode, 0);
        EXPECT_FALSE(entry.privateMeta.stdString().empty());
        EXPECT_FALSE(entry.data.stdString().empty());
    }
}

TEST_F(KvdbUsingGroupsTest, entries_accessible_by_all_group_members) {
    // Kvdb_4 is granted to Group_4 (user_1, user_2) and Group_6 (all three), so user_2 reaches it through
    // either and user_3 only through Group_6. Neither holds a direct roster entry.
    const std::string kvdbId = reader->getString("Kvdb_4.kvdbId");
    const std::string key = reader->getString("KvdbEntry_3.info_key");
    const std::string data = privmx::utils::Hex::toString(reader->getString("KvdbEntry_3.data_inHex"));

    for (const int index : {2, 3}) {
        disconnect();
        connectAs(index);
        kvdb::KvdbEntry entry;
        EXPECT_NO_THROW({ entry = kvdbApi->getEntry(kvdbId, key); }) << "user_" << index << " could not read it";
        EXPECT_EQ(entry.statusCode, 0);
        EXPECT_EQ(entry.data.stdString(), data);
    }
}

TEST_F(KvdbUsingGroupsTest, getEntry_lost_after_group_removal) {
    group::Group group_2;
    ASSERT_NO_THROW({ group_2 = groupApi->getGroup(reader->getString("Group_2.groupId")); });
    ASSERT_EQ(group_2.statusCode, 0);

    std::string kvdbId;
    ASSERT_NO_THROW({
        kvdbId = createKvdbWithGroupPolicyReadAll(
            reader->getString("Context_1.contextId"),
            reader->getString("Login.user_1_id"),
            reader->getString("Login.user_1_pubKey"),
            group_2
        );
    });
    ASSERT_FALSE(kvdbId.empty());

    ASSERT_NO_THROW({ setNewEntry(kvdbId, "old_key", "old_public", "secret_private", "secret_data"); });

    disconnect();
    connectAs(2);
    kvdb::KvdbEntry beforeRemoval;
    EXPECT_NO_THROW({ beforeRemoval = kvdbApi->getEntry(kvdbId, "old_key"); });
    EXPECT_EQ(beforeRemoval.statusCode, 0);
    EXPECT_EQ(beforeRemoval.privateMeta.stdString(), "secret_private");

    disconnect();
    connectAs(1);
    EXPECT_NO_THROW({
        kvdbApi->updateKvdb(
            kvdbId,
            std::vector<core::UserWithPubKey>{user(1)},
            std::vector<core::UserWithPubKey>{user(1)},
            core::Buffer::from("no_group"),
            core::Buffer::from("no_group_private"),
            1, false, false,
            std::nullopt,
            std::vector<core::GroupGrantWithKey>{}
        );
    });

    ASSERT_NO_THROW({ setNewEntry(kvdbId, "new_key", "new_public", "new_private", "new_data"); });

    // Historical group key entries are preserved for old key versions, so user_2 can still decrypt the
    // entry written while the group had access - but not the one written after.
    disconnect();
    connectAs(2);
    kvdb::KvdbEntry afterRemoval;
    EXPECT_NO_THROW({ afterRemoval = kvdbApi->getEntry(kvdbId, "old_key"); });
    EXPECT_EQ(afterRemoval.statusCode, 0);
    EXPECT_EQ(afterRemoval.privateMeta.stdString(), "secret_private");

    kvdb::KvdbEntry newEntry;
    EXPECT_NO_THROW({ newEntry = kvdbApi->getEntry(kvdbId, "new_key"); });
    EXPECT_NE(newEntry.statusCode, 0);
    EXPECT_TRUE(newEntry.privateMeta.stdString().empty());
}

TEST_F(KvdbUsingGroupsTest, user_added_to_group_gains_access_to_kvdb_and_entries) {
    // Group_2 has user_1 + user_2; user_3 is not yet a member.
    group::Group group_2;
    ASSERT_NO_THROW({ group_2 = groupApi->getGroup(reader->getString("Group_2.groupId")); });
    ASSERT_EQ(group_2.statusCode, 0);

    std::string kvdbId;
    ASSERT_NO_THROW({
        kvdbId = createKvdbWithGroupPolicyReadAll(
            reader->getString("Context_1.contextId"),
            reader->getString("Login.user_1_id"),
            reader->getString("Login.user_1_pubKey"),
            group_2
        );
    });
    ASSERT_FALSE(kvdbId.empty());

    ASSERT_NO_THROW({ setNewEntry(kvdbId, "entry_key", "entry_pub", "entry_priv", "entry_data"); });

    disconnect();
    connectAs(3);
    kvdb::Kvdb kBefore;
    EXPECT_NO_THROW({ kBefore = kvdbApi->getKvdb(kvdbId); });
    EXPECT_NE(kBefore.statusCode, 0);
    kvdb::KvdbEntry eBefore;
    EXPECT_NO_THROW({ eBefore = kvdbApi->getEntry(kvdbId, "entry_key"); });
    EXPECT_NE(eBefore.statusCode, 0);

    // Seat user_3's leaf in the key tree - a metadata write would only re-wrap the group's metadata key.
    disconnect();
    connectAs(1);
    EXPECT_NO_THROW({
        groupApi->addGroupMembers(
            reader->getString("Group_2.groupId"),
            {group::GroupMemberToAdd{.user = user(3), .role = "user"}}
        );
    });

    disconnect();
    connectAs(3);
    kvdb::Kvdb kAfter;
    EXPECT_NO_THROW({ kAfter = kvdbApi->getKvdb(kvdbId); });
    EXPECT_EQ(kAfter.statusCode, 0);
    kvdb::KvdbEntry eAfter;
    EXPECT_NO_THROW({ eAfter = kvdbApi->getEntry(kvdbId, "entry_key"); });
    EXPECT_EQ(eAfter.statusCode, 0);
    EXPECT_EQ(eAfter.data.stdString(), "entry_data");
}

TEST_F(KvdbUsingGroupsTest, direct_member_of_granted_group_reads_and_updates) {
    // Every keyId opens from `keys`, so the group branch is skipped. `updateKvdb` is the interesting half:
    // `verifyKeysSecret` fails on any non-zero status, so an unresolved group entry throws instead of updating.
    group::Group group_1;
    ASSERT_NO_THROW({ group_1 = groupApi->getGroup(reader->getString("Group_1.groupId")); });
    ASSERT_EQ(group_1.statusCode, 0);

    std::string kvdbId;
    ASSERT_NO_THROW({
        kvdbId = createKvdbWithGroups(
            reader->getString("Context_1.contextId"),
            std::vector<core::UserWithPubKey>{user(1)},
            std::vector<group::Group>{group_1}
        );
    });
    ASSERT_FALSE(kvdbId.empty());

    ASSERT_NO_THROW({ setNewEntry(kvdbId, "direct_key", "direct_public", "direct_private", "direct_data"); });

    kvdb::Kvdb k;
    EXPECT_NO_THROW({ k = kvdbApi->getKvdb(kvdbId); });
    EXPECT_EQ(k.statusCode, 0);
    EXPECT_EQ(k.groups.size(), 1);

    kvdb::KvdbEntry entry;
    EXPECT_NO_THROW({ entry = kvdbApi->getEntry(kvdbId, "direct_key"); });
    EXPECT_EQ(entry.statusCode, 0);
    EXPECT_EQ(entry.data.stdString(), "direct_data");

    core::PagingList<kvdb::KvdbEntry> list;
    EXPECT_NO_THROW({
        list = kvdbApi->listEntries(kvdbId, core::PagingQuery{.skip = 0, .limit = 10, .sortOrder = "desc"});
    });
    EXPECT_EQ(list.totalAvailable, 1);

    EXPECT_NO_THROW({
        kvdbApi->updateKvdb(
            kvdbId,
            std::vector<core::UserWithPubKey>{user(1)},
            std::vector<core::UserWithPubKey>{user(1)},
            core::Buffer::from("direct_updated_public"),
            core::Buffer::from("direct_updated_private"),
            k.version,
            false,
            false,
            std::nullopt,
            std::vector<core::GroupGrantWithKey>{{
                .groupId = group_1.groupId, .role = "user", .groupPubKey = group_1.groupPubKey
            }}
        );
    });

    kvdb::Kvdb updated;
    EXPECT_NO_THROW({ updated = kvdbApi->getKvdb(kvdbId); });
    EXPECT_EQ(updated.statusCode, 0);
    EXPECT_EQ(updated.privateMeta.stdString(), "direct_updated_private");
}

TEST_F(KvdbUsingGroupsTest, caller_in_no_granted_group_reads_via_direct_key) {
    // user_2 is a direct member of Kvdb_5 and is in no grantee group - Group_7 holds user_1 alone - so the
    // bridge serves it `groupKeys: []` and the read has to come entirely from its own key wrap.
    disconnect();
    connectAs(2);

    const std::string kvdbId = reader->getString("Kvdb_5.kvdbId");
    kvdb::Kvdb k;
    EXPECT_NO_THROW({ k = kvdbApi->getKvdb(kvdbId); });
    EXPECT_EQ(k.statusCode, 0);
    // `groups` stays unnarrowed, so user_2 still sees the grant it is not part of.
    EXPECT_EQ(k.groups.size(), 1);

    kvdb::KvdbEntry entry;
    EXPECT_NO_THROW({ entry = kvdbApi->getEntry(kvdbId, reader->getString("KvdbEntry_5.info_key")); });
    EXPECT_EQ(entry.statusCode, 0);
    EXPECT_EQ(entry.data.stdString(), privmx::utils::Hex::toString(reader->getString("KvdbEntry_5.data_inHex")));
}

TEST_F(KvdbUsingGroupsTest, caller_in_two_granted_groups_reads) {
    // Kvdb_4 wraps its key to user_1 only and is granted to Group_4 and Group_6, both of which user_2 belongs
    // to: that leaves two entries at the same keyId, and with no direct wrap one of them has to carry the read.
    disconnect();
    connectAs(2);

    const std::string kvdbId = reader->getString("Kvdb_4.kvdbId");
    kvdb::Kvdb k;
    EXPECT_NO_THROW({ k = kvdbApi->getKvdb(kvdbId); });
    EXPECT_EQ(k.statusCode, 0);
    EXPECT_EQ(k.groups.size(), 2);

    kvdb::KvdbEntry entry;
    EXPECT_NO_THROW({ entry = kvdbApi->getEntry(kvdbId, reader->getString("KvdbEntry_3.info_key")); });
    EXPECT_EQ(entry.statusCode, 0);
    EXPECT_EQ(entry.data.stdString(), privmx::utils::Hex::toString(reader->getString("KvdbEntry_3.data_inHex")));
}

TEST_F(KvdbUsingGroupsTest, rotateKvdbKeys_covers_a_grantee_group_the_caller_did_not_name) {
    // user_2 re-keys naming no groups, so the grantee list comes from the KVDB. The caller must be in that
    // group: the default group policy hands a group's epoch and public key to members only.
    group::Group granteeGroup;
    ASSERT_NO_THROW({ granteeGroup = groupApi->getGroup(reader->getString("Group_2.groupId")); });
    ASSERT_EQ(granteeGroup.statusCode, 0);

    std::string kvdbId;
    ASSERT_NO_THROW({
        kvdbId = createKvdbWithGroups(
            reader->getString("Context_1.contextId"),
            std::vector<core::UserWithPubKey>{
                user(1), user(2)
            },
            std::vector<group::Group>{granteeGroup}
        );
    });
    ASSERT_FALSE(kvdbId.empty());

    kvdb::Kvdb before;
    ASSERT_NO_THROW({ before = kvdbApi->getKvdb(kvdbId); });
    ASSERT_EQ(before.statusCode, 0);

    disconnect();
    connectAs(2);
    EXPECT_NO_THROW({
        kvdbApi->rotateKvdbKeys(
            kvdbId,
            std::vector<core::UserWithPubKey>{
                user(1), user(2)
            },
            std::vector<core::UserWithPubKey>{
                user(1), user(2)
            },
            before.version,
            false,
            std::vector<core::GroupGrantWithKey>{}
        );
    });

    disconnect();
    connectAs(1);
    kvdb::Kvdb after;
    EXPECT_NO_THROW({ after = kvdbApi->getKvdb(kvdbId); });
    EXPECT_EQ(after.statusCode, 0);
    EXPECT_EQ(after.groups.size(), 1);
    if (after.groups.size() == 1) {
        EXPECT_EQ(after.groups[0].groupId, granteeGroup.groupId);
    }

    // An entry written under the new key is readable, proving the re-key produced a usable key.
    ASSERT_NO_THROW({ setNewEntry(kvdbId, "post_rekey", "post_pub", "post_priv", "post_data"); });
    kvdb::KvdbEntry entry;
    EXPECT_NO_THROW({ entry = kvdbApi->getEntry(kvdbId, "post_rekey"); });
    EXPECT_EQ(entry.statusCode, 0);
    EXPECT_EQ(entry.data.stdString(), "post_data");
}

TEST_F(KvdbUsingGroupsTest, rotateKvdbKeys_clears_staleGroups_after_the_group_advances_its_epoch) {
    // Removing a member advances G to epoch 2, leaving the KVDB's key wrapped to a superseded epoch - which
    // the bridge reports as `staleGroups`. A re-key re-wraps to the current epoch and must clear it.
    std::string groupId;
    ASSERT_NO_THROW({
        groupId = groupApi->createGroup(
            reader->getString("Context_1.contextId"),
            std::vector<core::UserWithPubKey>{
                user(1),
                user(2),
                user(3)
            },
            std::vector<core::UserWithPubKey>{user(1)},
            core::Buffer::from("grp_pub"),
            core::Buffer::from("grp_priv")
        );
    });
    ASSERT_FALSE(groupId.empty());

    group::Group group;
    ASSERT_NO_THROW({ group = groupApi->getGroup(groupId); });
    ASSERT_EQ(group.statusCode, 0);
    ASSERT_EQ(group.keyVersion, 1);

    std::string kvdbId;
    ASSERT_NO_THROW({
        kvdbId = createKvdbWithGroups(
            reader->getString("Context_1.contextId"),
            std::vector<core::UserWithPubKey>{user(1)},
            std::vector<group::Group>{group}
        );
    });
    ASSERT_FALSE(kvdbId.empty());

    ASSERT_NO_THROW({ setNewEntry(kvdbId, "old_epoch_key", "old_epoch_pub", "old_epoch_priv", "old_epoch_data"); });

    ASSERT_NO_THROW({
        groupApi->removeGroupMembers(groupId, {reader->getString("Login.user_3_id")});
    });

    group::Group rotatedGroup;
    ASSERT_NO_THROW({ rotatedGroup = groupApi->getGroup(groupId); });
    ASSERT_EQ(rotatedGroup.statusCode, 0);
    ASSERT_EQ(rotatedGroup.keyVersion, 2);

    kvdb::Kvdb stale;
    ASSERT_NO_THROW({ stale = kvdbApi->getKvdb(kvdbId); });
    ASSERT_EQ(stale.statusCode, 0);
    EXPECT_EQ(stale.staleGroups.size(), 1);
    if (stale.staleGroups.size() == 1) {
        EXPECT_EQ(stale.staleGroups[0], groupId);
    }

    EXPECT_NO_THROW({
        kvdbApi->rotateKvdbKeys(
            kvdbId,
            std::vector<core::UserWithPubKey>{user(1)},
            std::vector<core::UserWithPubKey>{user(1)},
            stale.version,
            false,
            std::vector<core::GroupGrantWithKey>{}
        );
    });

    kvdb::Kvdb fresh;
    EXPECT_NO_THROW({ fresh = kvdbApi->getKvdb(kvdbId); });
    EXPECT_EQ(fresh.statusCode, 0);
    EXPECT_EQ(fresh.staleGroups.size(), 0);
    EXPECT_EQ(fresh.groups.size(), 1);

    // user_2 is still in G at epoch 2 and was never a direct KVDB member, so this read can only be served
    // through the re-wrapped group entry.
    disconnect();
    connectAs(2);
    kvdb::KvdbEntry oldEpochEntry;
    EXPECT_NO_THROW({ oldEpochEntry = kvdbApi->getEntry(kvdbId, "old_epoch_key"); });
    EXPECT_EQ(oldEpochEntry.statusCode, 0);
    EXPECT_EQ(oldEpochEntry.privateMeta.stdString(), "old_epoch_priv");
}

TEST_F(KvdbUsingGroupsTest, setEntry_auto_rotates_a_stale_kvdb_key) {
    // The same ground as the test above, minus the `rotateKvdbKeys` call: a stale key is not the caller's
    // problem to notice. `setEntry` re-keys the KVDB with its own roster and writes under the new key.
    std::string groupId;
    ASSERT_NO_THROW({
        groupId = groupApi->createGroup(
            reader->getString("Context_1.contextId"),
            std::vector<core::UserWithPubKey>{
                user(1),
                user(2),
                user(3)
            },
            std::vector<core::UserWithPubKey>{user(1)},
            core::Buffer::from("auto_grp_pub"),
            core::Buffer::from("auto_grp_priv")
        );
    });
    ASSERT_FALSE(groupId.empty());

    group::Group group;
    ASSERT_NO_THROW({ group = groupApi->getGroup(groupId); });
    ASSERT_EQ(group.statusCode, 0);

    std::string kvdbId;
    ASSERT_NO_THROW({
        kvdbId = createKvdbWithGroups(
            reader->getString("Context_1.contextId"),
            std::vector<core::UserWithPubKey>{user(1)},
            std::vector<group::Group>{group}
        );
    });
    ASSERT_FALSE(kvdbId.empty());

    ASSERT_NO_THROW({
        groupApi->removeGroupMembers(groupId, {reader->getString("Login.user_3_id")});
    });

    kvdb::Kvdb stale;
    ASSERT_NO_THROW({ stale = kvdbApi->getKvdb(kvdbId); });
    ASSERT_EQ(stale.statusCode, 0);
    ASSERT_EQ(stale.staleGroups.size(), 1);
    ASSERT_EQ(stale.staleGroups[0], groupId);

    EXPECT_NO_THROW({ setNewEntry(kvdbId, "auto_key", "auto_pub", "auto_priv", "auto_data"); });

    kvdb::Kvdb rekeyed;
    ASSERT_NO_THROW({ rekeyed = kvdbApi->getKvdb(kvdbId); });
    EXPECT_EQ(rekeyed.statusCode, 0);
    EXPECT_TRUE(rekeyed.staleGroups.empty());
    // Exactly one re-key: a rotation appends one history entry and nothing else wrote to the KVDB.
    EXPECT_EQ(rekeyed.version, stale.version + 1);
    EXPECT_EQ(rekeyed.users, stale.users);
    EXPECT_EQ(rekeyed.managers, stale.managers);

    // user_2 is in G at its new epoch and holds no direct entry: reading proves the new key was wrapped to the
    // epoch G actually moved to, not the one the KVDB was stuck on.
    disconnect();
    connectAs(2);
    kvdb::KvdbEntry entry;
    EXPECT_NO_THROW({ entry = kvdbApi->getEntry(kvdbId, "auto_key"); });
    EXPECT_EQ(entry.statusCode, 0);
    EXPECT_EQ(entry.data.stdString(), "auto_data");
}
