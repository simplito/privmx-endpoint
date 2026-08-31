#include <gtest/gtest.h>
#include <algorithm>
#include "../../utils/BaseTest.hpp"
#include <privmx/endpoint/core/Exception.hpp>
#include <Poco/Util/IniFileConfiguration.h>
#include <privmx/endpoint/core/EventQueueImpl.hpp>
#include <privmx/utils/Utils.hpp>
#include <privmx/endpoint/core/VarSerializer.hpp>
#include <privmx/endpoint/core/Connection.hpp>
#include <privmx/endpoint/kvdb/KvdbApi.hpp>
#include <privmx/endpoint/lock/LockApi.hpp>
#include <privmx/endpoint/store/StoreApi.hpp>
#include <privmx/endpoint/search/SearchApi.hpp>
#include <privmx/endpoint/search/VarSerializer.hpp>
#include <privmx/endpoint/group/GroupApi.hpp>
#include <privmx/endpoint/group/VarSerializer.hpp>
#include <privmx/endpoint/core/ConvertedExceptions.hpp>
#include <privmx/endpoint/core/CoreException.hpp>
using namespace privmx::endpoint;

enum SRConnectionType {
    SRUser1,
    SRUser2,
    SRUser3
};

class SearchUsingGroupsTest : public privmx::test::BaseTest {
protected:
    SearchUsingGroupsTest() : BaseTest(privmx::test::BaseTestMode::online) {}
    void connectAs(SRConnectionType type) {
        std::string privKey;
        if (type == SRConnectionType::SRUser1) {
            privKey = reader->getString("Login.user_1_privKey");
        } else if (type == SRConnectionType::SRUser2) {
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
        searchApi.reset();
        kvdbApi.reset();
        storeApi.reset();
        lockApi.reset();
        groupApi.reset();
        connection.reset();
    }
    /**
     * An Index is a KVDB and a Store, so its group support comes from the APIs handed to `SearchApi::create` —
     * both are built with a GroupApi here, which is what lets a grantee group's member open the Index at all.
     */
    void buildApis() {
        groupApi = std::make_shared<group::GroupApi>(group::GroupApi::create(*connection));
        storeApi = std::make_shared<store::StoreApi>(store::StoreApi::create(*connection, *groupApi));
        kvdbApi = std::make_shared<kvdb::KvdbApi>(kvdb::KvdbApi::create(*connection, *groupApi));
        lockApi = std::make_shared<lock::LockApi>(lock::LockApi::create(*connection));
        searchApi = std::make_shared<search::SearchApi>(
            search::SearchApi::create(*connection, *storeApi, *kvdbApi, *lockApi)
        );
    }
    /** One of the fixture's logins as a container names its members — id plus public key, from the same ini. */
    core::UserWithPubKey userOf(SRConnectionType type) {
        std::string n;
        if (type == SRConnectionType::SRUser1) {
            n = "1";
        } else if (type == SRConnectionType::SRUser2) {
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
        searchApi.reset();
        kvdbApi.reset();
        storeApi.reset();
        lockApi.reset();
        groupApi.reset();
        reader.reset();
        core::EventQueueImpl::getInstance()->clear();
    }
    /**
     * An Index whose direct member is user_1 alone and whose grantee groups are `groups`, each granted at `role`.
     *
     * The grants carry no epoch: leaving `groupEpoch` at 0 is what makes the endpoint resolve each group's
     * current epoch from the Bridge, which is the path these tests are about.
     *
     * `role` matters more here than it does for a plain container. Opening an Index writes to it — SQLite creates
     * its table and journal and takes locks before a single document is read — and the default item policy is
     * "itemOwner&user,manager". So a group whose members are expected to open the Index has to be granted
     * "manager"; "user" is enough only to read the Index's own metadata.
     */
    std::string createIndexWithGroups(
        const std::string& contextId,
        const std::vector<group::Group>& groups,
        const std::string& role = "manager",
        const search::IndexMode mode = search::IndexMode::WITH_CONTENT
    ) {
        std::vector<core::GroupGrantWithKey> grants;
        grants.reserve(groups.size());
        for (const auto& group : groups) {
            grants.push_back(
                core::GroupGrantWithKey{.groupId = group.groupId, .role = role, .groupPubKey = group.groupPubKey}
            );
        }
        return searchApi->createSearchIndex(
            contextId,
            std::vector<core::UserWithPubKey>{userOf(SRConnectionType::SRUser1)},
            std::vector<core::UserWithPubKey>{userOf(SRConnectionType::SRUser1)},
            core::Buffer::from("group_index_public"),
            core::Buffer::from("group_index_private"),
            mode,
            std::nullopt,
            grants
        );
    }
    /** Opens the Index, adds the given documents, closes it again. */
    void seedDocuments(const std::string& indexId, const std::vector<std::pair<std::string, std::string>>& docs) {
        int64_t handle = searchApi->openSearchIndex(indexId);
        for (const auto& doc : docs) {
            searchApi->addDocument(handle, doc.first, doc.second);
        }
        searchApi->closeSearchIndex(handle);
    }
    /** How many documents the Index returns for `query`, from a fresh open. */
    int64_t countMatches(const std::string& indexId, const std::string& query) {
        int64_t handle = searchApi->openSearchIndex(indexId);
        auto found = searchApi->searchDocuments(handle, query, {.skip = 0, .limit = 10, .sortOrder = "asc"});
        searchApi->closeSearchIndex(handle);
        return found.totalAvailable;
    }

    std::shared_ptr<core::Connection> connection;
    std::shared_ptr<store::StoreApi> storeApi;
    std::shared_ptr<kvdb::KvdbApi> kvdbApi;
    std::shared_ptr<lock::LockApi> lockApi;
    std::shared_ptr<search::SearchApi> searchApi;
    std::shared_ptr<group::GroupApi> groupApi;
    Poco::Util::IniFileConfiguration::Ptr reader;
    core::VarSerializer _serializer = core::VarSerializer({});
};

TEST_F(SearchUsingGroupsTest, createSearchIndex_with_group_grants) {
    group::Group group_1;
    ASSERT_NO_THROW({ group_1 = groupApi->getGroup(reader->getString("Group_1.groupId")); });
    ASSERT_EQ(group_1.statusCode, 0);
    ASSERT_FALSE(group_1.groupPubKey.empty());

    std::string indexId;
    EXPECT_NO_THROW({
        indexId = createIndexWithGroups(reader->getString("Context_1.contextId"), {group_1});
    });
    ASSERT_FALSE(indexId.empty());

    search::SearchIndex index;
    EXPECT_NO_THROW({ index = searchApi->getSearchIndex(indexId); });
    EXPECT_EQ(index.statusCode, 0);
    EXPECT_EQ(index.publicMeta.stdString(), "group_index_public");
    EXPECT_EQ(index.staleGroups.size(), 0);
    EXPECT_EQ(index.groups.size(), 1);
    if (index.groups.size() == 1) {
        EXPECT_EQ(index.groups[0].groupId, group_1.groupId);
        EXPECT_EQ(index.groups[0].role, "manager");
    }
}

TEST_F(SearchUsingGroupsTest, createSearchIndex_with_multiple_group_grants) {
    group::Group group_1, group_2;
    ASSERT_NO_THROW({ group_1 = groupApi->getGroup(reader->getString("Group_1.groupId")); });
    ASSERT_NO_THROW({ group_2 = groupApi->getGroup(reader->getString("Group_2.groupId")); });
    ASSERT_EQ(group_1.statusCode, 0);
    ASSERT_EQ(group_2.statusCode, 0);

    std::string indexId;
    EXPECT_NO_THROW({
        indexId = createIndexWithGroups(reader->getString("Context_1.contextId"), {group_1, group_2}, "user");
    });
    ASSERT_FALSE(indexId.empty());

    search::SearchIndex index;
    EXPECT_NO_THROW({ index = searchApi->getSearchIndex(indexId); });
    EXPECT_EQ(index.statusCode, 0);
    EXPECT_EQ(index.groups.size(), 2);
    bool found1 = false, found2 = false;
    for (const auto& g : index.groups) {
        if (g.groupId == group_1.groupId && g.role == "user") found1 = true;
        if (g.groupId == group_2.groupId && g.role == "user") found2 = true;
    }
    EXPECT_TRUE(found1);
    EXPECT_TRUE(found2);
}

TEST_F(SearchUsingGroupsTest, createSearchIndex_without_groups_has_empty_groups_field) {
    std::string indexId;
    EXPECT_NO_THROW({
        indexId = searchApi->createSearchIndex(
            reader->getString("Context_1.contextId"),
            std::vector<core::UserWithPubKey>{userOf(SRConnectionType::SRUser1)},
            std::vector<core::UserWithPubKey>{userOf(SRConnectionType::SRUser1)},
            core::Buffer::from("no_group_public"),
            core::Buffer::from("no_group_private"),
            search::IndexMode::WITH_CONTENT
        );
    });
    ASSERT_FALSE(indexId.empty());

    search::SearchIndex index;
    EXPECT_NO_THROW({ index = searchApi->getSearchIndex(indexId); });
    EXPECT_EQ(index.statusCode, 0);
    EXPECT_EQ(index.groups.size(), 0);
    EXPECT_EQ(index.staleGroups.size(), 0);
}

TEST_F(SearchUsingGroupsTest, createSearchIndex_with_invalid_group_pubkey_throws) {
    group::Group group_1;
    ASSERT_NO_THROW({ group_1 = groupApi->getGroup(reader->getString("Group_1.groupId")); });
    ASSERT_EQ(group_1.statusCode, 0);

    EXPECT_THROW({
        searchApi->createSearchIndex(
            reader->getString("Context_1.contextId"),
            std::vector<core::UserWithPubKey>{userOf(SRConnectionType::SRUser1)},
            std::vector<core::UserWithPubKey>{userOf(SRConnectionType::SRUser1)},
            core::Buffer::from("bad_key_public"),
            core::Buffer::from("bad_key_private"),
            search::IndexMode::WITH_CONTENT,
            std::nullopt,
            std::vector<core::GroupGrantWithKey>{core::GroupGrantWithKey{
                .groupId = group_1.groupId,
                .role = "user",
                .groupPubKey = "not_a_public_key"
            }}
        );
    }, core::Exception);
}

TEST_F(SearchUsingGroupsTest, listSearchIndexes_includes_groups_field) {
    group::Group group_2;
    ASSERT_NO_THROW({ group_2 = groupApi->getGroup(reader->getString("Group_2.groupId")); });
    ASSERT_EQ(group_2.statusCode, 0);

    std::string indexId;
    ASSERT_NO_THROW({
        indexId = createIndexWithGroups(reader->getString("Context_1.contextId"), {group_2}, "user");
    });
    ASSERT_FALSE(indexId.empty());

    core::PagingList<search::SearchIndex> list;
    EXPECT_NO_THROW({
        list = searchApi->listSearchIndexes(
            reader->getString("Context_1.contextId"),
            core::PagingQuery{.skip = 0, .limit = 100, .sortOrder = "desc"}
        );
    });
    auto found = std::find_if(list.readItems.begin(), list.readItems.end(), [&](const search::SearchIndex& i) {
        return i.indexId == indexId;
    });
    ASSERT_NE(found, list.readItems.end());
    EXPECT_EQ(found->statusCode, 0);
    ASSERT_EQ(found->groups.size(), 1);
    EXPECT_EQ(found->groups[0].groupId, group_2.groupId);
    EXPECT_EQ(found->groups[0].role, "user");
}

TEST_F(SearchUsingGroupsTest, updateSearchIndex_add_group) {
    group::Group group_1;
    ASSERT_NO_THROW({ group_1 = groupApi->getGroup(reader->getString("Group_1.groupId")); });
    ASSERT_EQ(group_1.statusCode, 0);

    std::string indexId;
    ASSERT_NO_THROW({
        indexId = searchApi->createSearchIndex(
            reader->getString("Context_1.contextId"),
            std::vector<core::UserWithPubKey>{userOf(SRConnectionType::SRUser1)},
            std::vector<core::UserWithPubKey>{userOf(SRConnectionType::SRUser1)},
            core::Buffer::from("add_group_public"),
            core::Buffer::from("add_group_private"),
            search::IndexMode::WITH_CONTENT
        );
    });
    ASSERT_FALSE(indexId.empty());

    search::SearchIndex before;
    ASSERT_NO_THROW({ before = searchApi->getSearchIndex(indexId); });
    ASSERT_EQ(before.groups.size(), 0);

    EXPECT_NO_THROW({
        searchApi->updateSearchIndex(
            indexId,
            std::vector<core::UserWithPubKey>{userOf(SRConnectionType::SRUser1)},
            std::vector<core::UserWithPubKey>{userOf(SRConnectionType::SRUser1)},
            core::Buffer::from("add_group_public_2"),
            core::Buffer::from("add_group_private_2"),
            before.version,
            false,
            false,
            std::nullopt,
            std::vector<core::GroupGrantWithKey>{core::GroupGrantWithKey{
                .groupId = group_1.groupId, .role = "user", .groupPubKey = group_1.groupPubKey
            }}
        );
    });

    search::SearchIndex after;
    EXPECT_NO_THROW({ after = searchApi->getSearchIndex(indexId); });
    EXPECT_EQ(after.statusCode, 0);
    EXPECT_EQ(after.publicMeta.stdString(), "add_group_public_2");
    ASSERT_EQ(after.groups.size(), 1);
    EXPECT_EQ(after.groups[0].groupId, group_1.groupId);
}

TEST_F(SearchUsingGroupsTest, updateSearchIndex_remove_group) {
    // The grant list an update carries is authoritative: an empty one revokes every grant the Index had.
    group::Group group_2;
    ASSERT_NO_THROW({ group_2 = groupApi->getGroup(reader->getString("Group_2.groupId")); });
    ASSERT_EQ(group_2.statusCode, 0);

    std::string indexId;
    ASSERT_NO_THROW({
        indexId = createIndexWithGroups(reader->getString("Context_1.contextId"), {group_2}, "user");
    });
    ASSERT_FALSE(indexId.empty());

    search::SearchIndex granted;
    ASSERT_NO_THROW({ granted = searchApi->getSearchIndex(indexId); });
    ASSERT_EQ(granted.groups.size(), 1);

    EXPECT_NO_THROW({
        searchApi->updateSearchIndex(
            indexId,
            std::vector<core::UserWithPubKey>{userOf(SRConnectionType::SRUser1)},
            std::vector<core::UserWithPubKey>{userOf(SRConnectionType::SRUser1)},
            core::Buffer::from("revoked_public"),
            core::Buffer::from("revoked_private"),
            granted.version,
            false,
            false,
            std::nullopt,
            std::vector<core::GroupGrantWithKey>{}
        );
    });

    search::SearchIndex revoked;
    EXPECT_NO_THROW({ revoked = searchApi->getSearchIndex(indexId); });
    EXPECT_EQ(revoked.statusCode, 0);
    EXPECT_EQ(revoked.groups.size(), 0);

    // user_2's only route into the Index was Group_2, and the revocation forced a new key.
    disconnect();
    connectAs(SRConnectionType::SRUser2);
    EXPECT_THROW({ searchApi->getSearchIndex(indexId); }, core::Exception);
}

TEST_F(SearchUsingGroupsTest, group_member_reads_index_metadata) {
    // "user" is enough for the Index's own metadata: that read is served by the KVDB half alone, and proves its
    // key was wrapped to the group.
    group::Group group_2;
    ASSERT_NO_THROW({ group_2 = groupApi->getGroup(reader->getString("Group_2.groupId")); });
    ASSERT_EQ(group_2.statusCode, 0);

    std::string indexId;
    ASSERT_NO_THROW({
        indexId = createIndexWithGroups(reader->getString("Context_1.contextId"), {group_2}, "user");
    });
    ASSERT_FALSE(indexId.empty());

    disconnect();
    connectAs(SRConnectionType::SRUser2);
    search::SearchIndex index;
    EXPECT_NO_THROW({ index = searchApi->getSearchIndex(indexId); });
    EXPECT_EQ(index.statusCode, 0);
    EXPECT_EQ(index.indexId, indexId);
    EXPECT_EQ(index.publicMeta.stdString(), "group_index_public");
    EXPECT_EQ(index.privateMeta.stdString(), "group_index_private");
    EXPECT_EQ(static_cast<int64_t>(index.mode), static_cast<int64_t>(search::IndexMode::WITH_CONTENT));
}

TEST_F(SearchUsingGroupsTest, group_member_searches_documents) {
    // The documents live in the Store half, so finding them proves that half was granted too — and every step
    // of the open (SQLite's table, its journal, its locks) went through the group grant.
    group::Group group_2;
    ASSERT_NO_THROW({ group_2 = groupApi->getGroup(reader->getString("Group_2.groupId")); });
    ASSERT_EQ(group_2.statusCode, 0);

    std::string indexId;
    ASSERT_NO_THROW({ indexId = createIndexWithGroups(reader->getString("Context_1.contextId"), {group_2}); });
    ASSERT_FALSE(indexId.empty());
    ASSERT_NO_THROW({
        seedDocuments(indexId, {{"doc-1", "alpha beta"}, {"doc-2", "gamma beta"}});
    });

    disconnect();
    connectAs(SRConnectionType::SRUser2);
    EXPECT_EQ(countMatches(indexId, "beta"), 2);
    EXPECT_EQ(countMatches(indexId, "alpha"), 1);
    EXPECT_EQ(countMatches(indexId, "delta"), 0);
}

TEST_F(SearchUsingGroupsTest, documents_added_by_group_member_are_visible_to_the_owner) {
    group::Group group_3;
    ASSERT_NO_THROW({ group_3 = groupApi->getGroup(reader->getString("Group_3.groupId")); });
    ASSERT_EQ(group_3.statusCode, 0);

    std::string indexId;
    ASSERT_NO_THROW({ indexId = createIndexWithGroups(reader->getString("Context_1.contextId"), {group_3}); });
    ASSERT_FALSE(indexId.empty());
    ASSERT_NO_THROW({ seedDocuments(indexId, {{"doc-owner", "owner wrote this"}}); });

    // user_3 is in Group_3 and is not a direct member of the Index.
    disconnect();
    connectAs(SRConnectionType::SRUser3);
    ASSERT_NO_THROW({ seedDocuments(indexId, {{"doc-member", "member wrote this"}}); });
    EXPECT_EQ(countMatches(indexId, "wrote"), 2);

    disconnect();
    connectAs(SRConnectionType::SRUser1);
    EXPECT_EQ(countMatches(indexId, "member"), 1);
    EXPECT_EQ(countMatches(indexId, "wrote"), 2);
}

TEST_F(SearchUsingGroupsTest, caller_in_no_granted_group_cannot_read_the_index) {
    // Group_2 holds user_1 and user_2; user_3 is in neither the Index's roster nor its grantee group.
    group::Group group_2;
    ASSERT_NO_THROW({ group_2 = groupApi->getGroup(reader->getString("Group_2.groupId")); });
    ASSERT_EQ(group_2.statusCode, 0);

    std::string indexId;
    ASSERT_NO_THROW({
        indexId = createIndexWithGroups(reader->getString("Context_1.contextId"), {group_2}, "user");
    });
    ASSERT_FALSE(indexId.empty());

    disconnect();
    connectAs(SRConnectionType::SRUser3);
    EXPECT_THROW({ searchApi->getSearchIndex(indexId); }, core::Exception);
    EXPECT_THROW({ searchApi->openSearchIndex(indexId); }, core::Exception);
}

TEST_F(SearchUsingGroupsTest, rotateSearchIndexKeys_clears_staleGroups_after_the_group_advances_its_epoch) {
    // Group G at epoch 1 is granted the Index. Removing a member advances G to epoch 2, which leaves the Index's
    // keys wrapped to a superseded epoch — the bridge reports that as `staleGroups`. A re-key re-wraps both of
    // the Index's containers to the current epoch and must clear it.
    std::string groupId;
    ASSERT_NO_THROW({
        groupId = groupApi->createGroup(
            reader->getString("Context_1.contextId"),
            std::vector<core::UserWithPubKey>{
                userOf(SRConnectionType::SRUser1),
                userOf(SRConnectionType::SRUser2),
                userOf(SRConnectionType::SRUser3)
            },
            std::vector<core::UserWithPubKey>{userOf(SRConnectionType::SRUser1)},
            core::Buffer::from("idx_grp_pub"),
            core::Buffer::from("idx_grp_priv")
        );
    });
    ASSERT_FALSE(groupId.empty());

    group::Group group;
    ASSERT_NO_THROW({ group = groupApi->getGroup(groupId); });
    ASSERT_EQ(group.statusCode, 0);
    ASSERT_EQ(group.keyVersion, 1);

    std::string indexId;
    ASSERT_NO_THROW({ indexId = createIndexWithGroups(reader->getString("Context_1.contextId"), {group}); });
    ASSERT_FALSE(indexId.empty());
    ASSERT_NO_THROW({ seedDocuments(indexId, {{"doc-1", "epoch one document"}}); });

    ASSERT_NO_THROW({
        groupApi->removeGroupMember(
            groupId,
            reader->getString("Login.user_3_id"),
            std::vector<core::UserWithPubKey>{
                userOf(SRConnectionType::SRUser1), userOf(SRConnectionType::SRUser2)
            },
            std::vector<core::UserWithPubKey>{userOf(SRConnectionType::SRUser1)},
            core::Buffer::from("idx_grp_removed_pub"),
            core::Buffer::from("idx_grp_removed_priv")
        );
    });

    group::Group rotatedGroup;
    ASSERT_NO_THROW({ rotatedGroup = groupApi->getGroup(groupId); });
    ASSERT_EQ(rotatedGroup.keyVersion, 2);

    // Nothing may write to the Index between the removal and this read: a write would re-key it on its own.
    search::SearchIndex stale;
    ASSERT_NO_THROW({ stale = searchApi->getSearchIndex(indexId); });
    ASSERT_EQ(stale.statusCode, 0);
    ASSERT_EQ(stale.staleGroups.size(), 1);
    EXPECT_EQ(stale.staleGroups[0], groupId);

    EXPECT_NO_THROW({
        searchApi->rotateSearchIndexKeys(
            indexId,
            std::vector<core::UserWithPubKey>{userOf(SRConnectionType::SRUser1)},
            std::vector<core::UserWithPubKey>{userOf(SRConnectionType::SRUser1)},
            stale.version,
            false,
            std::vector<core::GroupGrantWithKey>{}
        );
    });

    search::SearchIndex fresh;
    EXPECT_NO_THROW({ fresh = searchApi->getSearchIndex(indexId); });
    EXPECT_EQ(fresh.statusCode, 0);
    EXPECT_EQ(fresh.staleGroups.size(), 0);
    EXPECT_EQ(fresh.groups.size(), 1);

    // user_2 is still in G at epoch 2 and was never a direct member of the Index, so this read can only be
    // served through the re-wrapped group entries — of both halves, since it takes the KVDB to find the Store.
    //
    // A read, deliberately: a random-write file carries the key id it was opened under, and the Bridge refuses a
    // random write whose key id is not the Store's current one. Documents written before a re-key stay readable,
    // but an Index has to be re-keyed before it is opened, not while it is.
    disconnect();
    connectAs(SRConnectionType::SRUser2);
    EXPECT_EQ(countMatches(indexId, "epoch"), 1);
}
