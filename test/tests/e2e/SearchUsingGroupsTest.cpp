#include <gtest/gtest.h>
#include <algorithm>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <vector>
#include "../../utils/BaseTest.hpp"
#include <privmx/endpoint/core/Exception.hpp>
#include <Poco/Util/IniFileConfiguration.h>
#include <privmx/endpoint/core/EventQueueImpl.hpp>
#include <privmx/utils/Utils.hpp>
#include <privmx/utils/PrivmxException.hpp>
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

/**
 * Search Indexes granted to Groups. Two halves, and the fixture serves both.
 *
 * The grant itself: creating, listing, updating and re-keying an Index that names grantee groups, and who can
 * read it. One connection at a time, swapped with `connectAs`, because each of those asks a question about
 * server state that a cold session answers just as well.
 *
 * And somebody working in an *open* Index while access to it is changed underneath them. Those flows keep three
 * sessions live at once (`openClients`) so a handle taken before the change is still in hand after it — the only
 * way to ask whether losing access actually stops a writer, and whether keeping it lets one carry on. A
 * reconnect would throw away the warm key cache that is the point.
 *
 * See SearchGroupRejectedWriteTest for what a write the Bridge refuses does to the Index.
 */

enum SRConnectionType {
    SRUser1,
    SRUser2,
    SRUser3
};

class SearchUsingGroupsTest : public privmx::test::BaseTest {
protected:
    SearchUsingGroupsTest() : BaseTest(privmx::test::BaseTestMode::online) {}

    /** "1", "2" or "3" — the suffix each of the fixture's logins carries throughout the ini. */
    static std::string suffixOf(SRConnectionType type) {
        if (type == SRConnectionType::SRUser1) {
            return "1";
        } else if (type == SRConnectionType::SRUser2) {
            return "2";
        }
        return "3";
    }

    void connectAs(SRConnectionType type) {
        connection = connectWith(type);
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
    std::shared_ptr<core::Connection> connectWith(SRConnectionType type) {
        return std::make_shared<core::Connection>(
            core::Connection::connect(
                reader->getString("Login.user_" + suffixOf(type) + "_privKey"),
                reader->getString("Login.solutionId"),
                getPlatformUrl(reader->getString("Login.instanceUrl"))
            )
        );
    }
    /**
     * An Index is a KVDB and a Store, so its group support comes from the APIs handed to `SearchApi::create` —
     * both are built with a GroupApi here, which is what lets a grantee group's member open the Index at all.
     */
    void buildApis() {
        auto apis = apisOn(connection);
        groupApi = apis.groupApi;
        storeApi = apis.storeApi;
        kvdbApi = apis.kvdbApi;
        lockApi = apis.lockApi;
        searchApi = apis.searchApi;
    }
    /** One of the fixture's logins as a container names its members — id plus public key, from the same ini. */
    core::UserWithPubKey userOf(SRConnectionType type) {
        const std::string n = suffixOf(type);
        return core::UserWithPubKey{
            .userId = reader->getString("Login.user_" + n + "_id"),
            .pubKey = reader->getString("Login.user_" + n + "_pubKey")
        };
    }
    std::string contextId() {
        return reader->getString("Context_1.contextId");
    }
    void customSetUp() override {
        reader = new Poco::Util::IniFileConfiguration(INI_FILE_PATH);
        connection = connectWith(SRConnectionType::SRUser1);
        buildApis();
    }
    void customTearDown() override {
        for (Client* client : {&owner, &worker, &other}) {
            closeHandle(*client);
            resetClient(*client);
        }
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
     *
     * Goes through the fixture's own single connection, so it is for the single-session tests only.
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

    // ── Working in an open Index while its access list changes ─────────────────────────────────────────────────

    // Every document the multi-session flows write carries this word, so one search stands in for "read it all
    // back".
    static constexpr const char* SHARED_TERM = "shared";

    // One user's live session, with every API an Index needs, plus the handle it keeps open across a change.
    struct Client {
        std::shared_ptr<core::Connection> connection;
        std::shared_ptr<group::GroupApi> groupApi;
        std::shared_ptr<store::StoreApi> storeApi;
        std::shared_ptr<kvdb::KvdbApi> kvdbApi;
        std::shared_ptr<lock::LockApi> lockApi;
        std::shared_ptr<search::SearchApi> searchApi;
        int64_t handle = -1;
        std::string name;
    };

    /** Every API an Index needs, on one connection. */
    Client apisOn(const std::shared_ptr<core::Connection>& conn) {
        Client client;
        client.connection = conn;
        client.groupApi = std::make_shared<group::GroupApi>(group::GroupApi::create(*conn));
        client.storeApi = std::make_shared<store::StoreApi>(store::StoreApi::create(*conn, *client.groupApi));
        client.kvdbApi = std::make_shared<kvdb::KvdbApi>(kvdb::KvdbApi::create(*conn, *client.groupApi));
        client.lockApi = std::make_shared<lock::LockApi>(lock::LockApi::create(*conn));
        client.searchApi = std::make_shared<search::SearchApi>(
            search::SearchApi::create(*conn, *client.storeApi, *client.kvdbApi, *client.lockApi)
        );
        return client;
    }

    /**
     * Three sessions at once: `owner` (user_1) holds the Index and makes every change, `worker` (user_2) does the
     * indexing, `other` (user_3) is the third party who leaves or joins.
     *
     * The fixture's own connection steps aside first — one websocket carries at most one session per user key, so
     * user_1 cannot be both.
     */
    void openClients() {
        disconnect();
        owner = connectClientAs(SRUser1);
        worker = connectClientAs(SRUser2);
        other = connectClientAs(SRUser3);
    }

    Client connectClientAs(SRConnectionType type) {
        Client client = apisOn(connectWith(type));
        client.name = "user_" + suffixOf(type);
        return client;
    }

    // An Index whose caller lost the key makes closeSearchIndex throw as readily as everything else, and teardown
    // must not.
    void closeHandle(Client& client) {
        if (client.searchApi && client.handle != -1) {
            try {
                client.searchApi->closeSearchIndex(client.handle);
            } catch (...) {}
            client.handle = -1;
        }
    }

    void resetClient(Client& client) {
        client.searchApi.reset();
        client.lockApi.reset();
        client.kvdbApi.reset();
        client.storeApi.reset();
        client.groupApi.reset();
        client.connection.reset();
    }

    core::PagingQuery paging() {
        return core::PagingQuery{.skip = 0, .limit = 100, .sortOrder = "asc"};
    }

    /**
     * The message an operation failed with, or nullopt when it succeeded.
     *
     * Whose write gets turned away and why is half of what these flows measure, so every call that is allowed to
     * fail goes through here and its message ends up on the test's own output. A VFS failure otherwise reaches
     * the caller as a bare `disk I/O error`.
     */
    std::optional<std::string> tryCall(const std::function<void()>& fn) {
        try {
            fn();
            return std::nullopt;
        } catch (const core::Exception& e) {
            return e.getFull();
        } catch (const privmx::utils::PrivmxException& e) {
            return std::string(e.what()) + " | " + e.getData();
        } catch (const std::exception& e) {
            return std::string(e.what());
        }
    }

    /** A Group managed by user_1 alone, holding exactly `members`. */
    void createGroupOf(const std::string& tag, const std::vector<core::UserWithPubKey>& members,
                       std::string& groupId) {
        ASSERT_NO_THROW({
            groupId = owner.groupApi->createGroup(
                contextId(), members, std::vector<core::UserWithPubKey>{userOf(SRUser1)},
                core::Buffer::from(tag + "_grp_pub"), core::Buffer::from(tag + "_grp_priv")
            );
        });
        ASSERT_FALSE(groupId.empty());
    }

    group::Group groupNow(const std::string& groupId) {
        return owner.groupApi->getGroup(groupId);
    }

    /**
     * A grant of `group` at its current epoch, at "manager" for the reason `createIndexWithGroups` gives.
     *
     * The epoch is stated rather than left for the Bridge to resolve: these flows turn on which epoch the Index
     * was granted at, so it belongs in the test and not in a lookup.
     */
    std::vector<core::GroupGrantWithKey> grantsFor(const group::Group& group) {
        return std::vector<core::GroupGrantWithKey>{core::GroupGrantWithKey{
            .groupId = group.groupId,
            .role = "manager",
            .groupPubKey = group.groupPubKey,
            .groupEpoch = group.keyVersion
        }};
    }

    void createIndexGranting(const std::string& tag, const std::vector<core::UserWithPubKey>& users,
                             const std::vector<core::UserWithPubKey>& managers,
                             const std::vector<core::GroupGrantWithKey>& grants, std::string& indexId) {
        ASSERT_NO_THROW({
            indexId = owner.searchApi->createSearchIndex(
                contextId(), users, managers, core::Buffer::from(tag + "_idx_pub"),
                core::Buffer::from(tag + "_idx_priv"), search::IndexMode::WITH_CONTENT, std::nullopt, grants
            );
        });
        ASSERT_FALSE(indexId.empty());
    }

    /**
     * An updateSearchIndex that rewrites nothing but the access lists.
     *
     * `grants` is authoritative — a group left out of it is revoked — and dropping either a direct member or a
     * grant is what makes the endpoint mint a new key for both halves of the Index.
     */
    void setIndexAccess(const std::string& indexId, const std::vector<core::UserWithPubKey>& users,
                        const std::vector<core::UserWithPubKey>& managers,
                        const std::vector<core::GroupGrantWithKey>& grants) {
        search::SearchIndex current;
        ASSERT_NO_THROW({ current = owner.searchApi->getSearchIndex(indexId); });
        ASSERT_NO_THROW({
            owner.searchApi->updateSearchIndex(
                indexId, users, managers, current.publicMeta, current.privateMeta, current.version, false, false,
                std::nullopt, grants
            );
        });
    }

    /**
     * What actually made it into the Index, as opposed to what was attempted.
     *
     * Which writes the Bridge turns away is part of what is under test, so a write that fails is recorded rather
     * than fatal and only one that returned cleanly counts. That count is the number every later read by a caller
     * who never lost access has to agree with.
     */
    struct Ledger {
        int64_t committed = 0;
        std::vector<std::string> refusals;
    };

    void addDocument(Client& client, const std::string& name, const std::string& words, Ledger& ledger) {
        auto error = tryCall([&] {
            client.searchApi->addDocument(client.handle, name, words + " " + SHARED_TERM);
        });
        if (error.has_value()) {
            ledger.refusals.push_back(client.name + " " + name + " -> " + error.value());
        } else {
            ledger.committed += 1;
        }
    }

    void reportRefusals(const Ledger& ledger) {
        for (const auto& refusal : ledger.refusals) {
            GTEST_LOG_(INFO) << "refused: " << refusal;
        }
    }

    /** Opens the Index for `client` — the handle stays open — and writes `count` documents through it. */
    void openAndSeed(Client& client, const std::string& indexId, const std::string& prefix, int count,
                     Ledger& ledger) {
        ASSERT_NO_THROW({ client.handle = client.searchApi->openSearchIndex(indexId); });
        for (int i = 0; i < count; ++i) {
            addDocument(client, prefix + "-" + std::to_string(i), prefix, ledger);
        }
        ASSERT_EQ(ledger.committed, count) << "the seeding writes were refused before anything changed";
        ASSERT_EQ(searchThrough(client, SHARED_TERM), count) << client.name << " cannot read back its own writes";
    }

    /** How many documents `client` finds for `term` through the handle it already holds; -1 if the read fails. */
    int64_t searchThrough(Client& client, const std::string& term) {
        int64_t count = -1;
        auto error = tryCall([&] {
            count = client.searchApi->searchDocuments(client.handle, term, paging()).totalAvailable;
        });
        if (error.has_value()) {
            GTEST_LOG_(INFO) << client.name << " could not search through its open handle: " << error.value();
            return -1;
        }
        return count;
    }

    /** What a caller sees when they come to the Index with no handle in hand. */
    struct OpenProbe {
        bool opened = false;
        int64_t listed = -1;
        int64_t matched = -1;
        std::string error;
    };

    OpenProbe openAndRead(Client& client, const std::string& indexId) {
        OpenProbe probe;
        int64_t handle = -1;
        auto openError = tryCall([&] { handle = client.searchApi->openSearchIndex(indexId); });
        if (openError.has_value()) {
            probe.error = openError.value();
            return probe;
        }
        probe.opened = true;
        auto readError = tryCall([&] {
            probe.listed = client.searchApi->listDocuments(handle, paging()).totalAvailable;
            probe.matched = client.searchApi->searchDocuments(handle, SHARED_TERM, paging()).totalAvailable;
        });
        if (readError.has_value()) {
            probe.error = readError.value();
        }
        tryCall([&] { client.searchApi->closeSearchIndex(handle); });
        return probe;
    }

    /**
     * Everything a caller who lost their route to the Index must no longer be able to do: open it, decrypt its
     * metadata, or write through the handle they were already holding.
     *
     * The handle is used and then dropped — a refused write leaves the caller's SQLite state behind the server's,
     * so what that handle reads afterwards says nothing. What the Index really holds is read back through
     * `expectIntact` by somebody who never lost access.
     */
    void expectLockedOut(Client& client, const std::string& indexId) {
        auto probe = openAndRead(client, indexId);
        if (!probe.error.empty()) {
            GTEST_LOG_(INFO) << client.name << " was refused: " << probe.error;
        }
        EXPECT_FALSE(probe.opened) << client.name << " opened the Index after losing access to it, and read "
                                   << probe.listed << " documents out of it";

        search::SearchIndex index;
        auto metadataError = tryCall([&] { index = client.searchApi->getSearchIndex(indexId); });
        if (metadataError.has_value()) {
            GTEST_LOG_(INFO) << client.name << " cannot read the Index's metadata: " << metadataError.value();
        } else {
            EXPECT_NE(index.statusCode, 0)
                << client.name << " still decrypted the Index's metadata after losing access to it";
        }

        if (client.handle != -1) {
            auto writeError = tryCall([&] { client.searchApi->addDocument(client.handle, "after", "after shared"); });
            EXPECT_TRUE(writeError.has_value())
                << client.name << " wrote to the Index through a handle opened before it lost access";
            if (writeError.has_value()) {
                GTEST_LOG_(INFO) << client.name << "'s write was refused: " << writeError.value();
            }
            closeHandle(client);
        }
    }

    /**
     * Every committed document still there, seen by a caller who never lost access — and the Index still opens,
     * which is the part there is no recovery path from.
     */
    void expectIntact(Client& client, const std::string& indexId, int64_t committed) {
        auto probe = openAndRead(client, indexId);
        ASSERT_TRUE(probe.opened) << client.name << " can no longer open the Index at all: " << probe.error;
        EXPECT_EQ(probe.listed, committed) << "the Index lost documents that had been committed";
        EXPECT_EQ(probe.matched, committed) << "committed documents are in the Index but no longer searchable";
    }

    std::shared_ptr<core::Connection> connection;
    std::shared_ptr<store::StoreApi> storeApi;
    std::shared_ptr<kvdb::KvdbApi> kvdbApi;
    std::shared_ptr<lock::LockApi> lockApi;
    std::shared_ptr<search::SearchApi> searchApi;
    std::shared_ptr<group::GroupApi> groupApi;
    Client owner;
    Client worker;
    Client other;
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
        groupApi->removeGroupMembers(groupId, {reader->getString("Login.user_3_id")});
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

/**
 * ── the Index's access list, case 1: the grantee group user_2 belongs to is revoked ────────────────────────────
 *
 * The Group is untouched — user_2 is still a member of it, at the same epoch. What goes away is the Index's
 * grant, and with it the only route user_2 ever had to the Index's key. Revoking a grant mints a new key
 * (`doesGroupStateForceNewKey`), so a warm session's cached key is worth nothing afterwards.
 */
TEST_F(SearchUsingGroupsTest, revoking_the_grantee_group_locks_out_a_member_working_in_the_index) {
    openClients();

    std::string groupId, indexId;
    createGroupOf("revoke_grant", {userOf(SRUser2), userOf(SRUser3)}, groupId);
    group::Group group;
    ASSERT_NO_THROW({ group = groupNow(groupId); });
    ASSERT_EQ(group.statusCode, 0);
    createIndexGranting("revoke_grant", {userOf(SRUser1)}, {userOf(SRUser1)}, grantsFor(group), indexId);

    // user_2's whole working session: open once, write, read back, and keep the handle.
    Ledger ledger;
    openAndSeed(worker, indexId, "beta", 3, ledger);

    // user_1 revokes the grant. The Group still holds user_2; the Index no longer names the Group.
    setIndexAccess(indexId, {userOf(SRUser1)}, {userOf(SRUser1)}, {});
    search::SearchIndex revoked;
    ASSERT_NO_THROW({ revoked = owner.searchApi->getSearchIndex(indexId); });
    ASSERT_EQ(revoked.statusCode, 0);
    ASSERT_EQ(revoked.groups.size(), 0);
    EXPECT_EQ(revoked.staleGroups.size(), 0) << "an Index that grants no group cannot be stale against one";
    // Nothing happened to the Group itself — the lockout has to come from the grant alone.
    EXPECT_EQ(groupNow(groupId).keyVersion, group.keyVersion);

    expectLockedOut(worker, indexId);
    reportRefusals(ledger);
    expectIntact(owner, indexId, ledger.committed);
}

/**
 * ── the Index's access list, case 2: user_2 is dropped from the roster ─────────────────────────────────────────
 *
 * Here user_2's route is a direct membership rather than a group, and the grantee group belongs to somebody else.
 * Removing a user mints a new key too (`UsersKeysResolver`), and the update carries the surviving grant along —
 * so the same call that locks user_2 out has to re-wrap the new key to the Group. user_3 reading afterwards is
 * what proves it did.
 */
TEST_F(SearchUsingGroupsTest, removing_a_direct_member_locks_them_out_and_leaves_the_grant_working) {
    openClients();

    std::string groupId, indexId;
    createGroupOf("drop_user", {userOf(SRUser3)}, groupId);
    group::Group group;
    ASSERT_NO_THROW({ group = groupNow(groupId); });
    ASSERT_EQ(group.statusCode, 0);
    createIndexGranting(
        "drop_user", {userOf(SRUser1), userOf(SRUser2)}, {userOf(SRUser1), userOf(SRUser2)}, grantsFor(group),
        indexId
    );

    Ledger ledger;
    openAndSeed(worker, indexId, "beta", 3, ledger);

    // user_3, whose route is the group grant, sees user_2's work before the change.
    auto beforeChange = openAndRead(other, indexId);
    ASSERT_TRUE(beforeChange.opened) << "the grantee group's member cannot open the Index: " << beforeChange.error;
    ASSERT_EQ(beforeChange.listed, ledger.committed);

    // user_1 drops user_2 from both lists and restates the grant, which is how it survives the update.
    setIndexAccess(indexId, {userOf(SRUser1)}, {userOf(SRUser1)}, grantsFor(group));
    search::SearchIndex trimmed;
    ASSERT_NO_THROW({ trimmed = owner.searchApi->getSearchIndex(indexId); });
    ASSERT_EQ(trimmed.statusCode, 0);
    EXPECT_EQ(trimmed.users.size(), 1);
    ASSERT_EQ(trimmed.groups.size(), 1);
    EXPECT_EQ(trimmed.groups[0].groupId, groupId);
    EXPECT_EQ(trimmed.staleGroups.size(), 0) << "the update re-wrapped the new key to the group it kept";

    expectLockedOut(worker, indexId);
    reportRefusals(ledger);
    // The grant outlived the roster change: user_3's route still opens the Index and still reads every document.
    expectIntact(other, indexId, ledger.committed);
    expectIntact(owner, indexId, ledger.committed);
}

/**
 * ── the Group's membership, case 1: user_2 is removed from the Group ───────────────────────────────────────────
 *
 * Nothing about the Index changes. Removing a member advances the Group's epoch, which leaves the Index's key
 * wrapped to an epoch that no longer exists — reported as `staleGroups` — and a re-key is what actually closes
 * the door: until then user_2's warm session still holds the epoch-1 key it read with.
 *
 * So the re-key is part of the flow, and it is user_1 who performs it, without touching a single grant.
 */
TEST_F(SearchUsingGroupsTest, removing_the_worker_from_the_grantee_group_locks_them_out) {
    openClients();

    std::string groupId, indexId;
    createGroupOf("drop_member", {userOf(SRUser2), userOf(SRUser3)}, groupId);
    group::Group group;
    ASSERT_NO_THROW({ group = groupNow(groupId); });
    ASSERT_EQ(group.statusCode, 0);
    ASSERT_EQ(group.keyVersion, 1);
    createIndexGranting("drop_member", {userOf(SRUser1)}, {userOf(SRUser1)}, grantsFor(group), indexId);

    Ledger ledger;
    openAndSeed(worker, indexId, "beta", 3, ledger);

    ASSERT_NO_THROW({
        owner.groupApi->removeGroupMembers(groupId, {userOf(SRUser2).userId});
    });
    ASSERT_EQ(groupNow(groupId).keyVersion, 2);

    // Nothing may write to the Index between the removal and this read: a write re-keys it on its own.
    search::SearchIndex stale;
    ASSERT_NO_THROW({ stale = owner.searchApi->getSearchIndex(indexId); });
    ASSERT_EQ(stale.statusCode, 0);
    ASSERT_EQ(stale.staleGroups.size(), 1);
    EXPECT_EQ(stale.staleGroups[0], groupId);

    // The re-key changes no grants: the Group is still granted, at its new epoch.
    ASSERT_NO_THROW({
        owner.searchApi->rotateSearchIndexKeys(
            indexId, std::vector<core::UserWithPubKey>{userOf(SRUser1)},
            std::vector<core::UserWithPubKey>{userOf(SRUser1)}, stale.version, false,
            std::vector<core::GroupGrantWithKey>{}
        );
    });
    search::SearchIndex fresh;
    ASSERT_NO_THROW({ fresh = owner.searchApi->getSearchIndex(indexId); });
    EXPECT_EQ(fresh.staleGroups.size(), 0);
    ASSERT_EQ(fresh.groups.size(), 1);
    EXPECT_EQ(fresh.groups[0].groupId, groupId);

    expectLockedOut(worker, indexId);
    reportRefusals(ledger);

    // user_3 is what is left of the Group, and reads through the grant alone — never named on the Index.
    expectIntact(other, indexId, ledger.committed);
    expectIntact(owner, indexId, ledger.committed);
}

/**
 * ── the Group's membership, case 2: user_3 is removed, user_2 stays ────────────────────────────────────────────
 *
 * user_2 loses nothing and must notice nothing. The epoch still moves, so the Index is still stale against the
 * Group, and user_2's next write through the handle it has held all along is the interesting moment: the write
 * path has to notice the superseded key and re-key the Store itself (`StoreApiImpl::flushFile` retries through
 * `getCurrentFileEncKey`) rather than hand the caller the Bridge's refusal.
 *
 * `staleGroups` is read off the KVDB half alone, and a document only touches the Store, so it keeps naming the
 * Group until somebody re-keys the other half. That is why the re-key still happens here — and after it, the
 * member who left is out.
 */
TEST_F(SearchUsingGroupsTest, removing_another_member_from_the_grantee_group_keeps_the_worker_writing) {
    openClients();

    std::string groupId, indexId;
    createGroupOf("other_out", {userOf(SRUser2), userOf(SRUser3)}, groupId);
    group::Group group;
    ASSERT_NO_THROW({ group = groupNow(groupId); });
    ASSERT_EQ(group.statusCode, 0);
    ASSERT_EQ(group.keyVersion, 1);
    createIndexGranting("other_out", {userOf(SRUser1)}, {userOf(SRUser1)}, grantsFor(group), indexId);

    Ledger ledger;
    openAndSeed(worker, indexId, "beta", 3, ledger);

    ASSERT_NO_THROW({
        owner.groupApi->removeGroupMembers(groupId, {userOf(SRUser3).userId});
    });
    ASSERT_EQ(groupNow(groupId).keyVersion, 2);
    search::SearchIndex stale;
    ASSERT_NO_THROW({ stale = owner.searchApi->getSearchIndex(indexId); });
    ASSERT_EQ(stale.staleGroups.size(), 1);

    // The worker carries on through the handle it opened at epoch 1. Its route to the Index — the grant — is
    // unchanged, so the superseded key is the write path's problem to solve, not the caller's.
    const int64_t committedBefore = ledger.committed;
    addDocument(worker, "beta-3", "beta", ledger);
    reportRefusals(ledger);
    EXPECT_EQ(ledger.committed, committedBefore + 1)
        << "a member who kept their group could not write after the group's epoch moved; see the refusal above";
    EXPECT_EQ(searchThrough(worker, SHARED_TERM), ledger.committed);

    // And reading is unaffected too, from a cold start as much as through the open handle.
    auto asWorker = openAndRead(worker, indexId);
    ASSERT_TRUE(asWorker.opened) << "the remaining member can no longer open the Index: " << asWorker.error;
    EXPECT_EQ(asWorker.listed, ledger.committed);

    // The KVDB half is still wrapped to epoch 1 — only the Store half was re-keyed by the write above.
    ASSERT_NO_THROW({ stale = owner.searchApi->getSearchIndex(indexId); });
    ASSERT_NO_THROW({
        owner.searchApi->rotateSearchIndexKeys(
            indexId, std::vector<core::UserWithPubKey>{userOf(SRUser1)},
            std::vector<core::UserWithPubKey>{userOf(SRUser1)}, stale.version, false,
            std::vector<core::GroupGrantWithKey>{}
        );
    });
    search::SearchIndex rekeyed;
    ASSERT_NO_THROW({ rekeyed = owner.searchApi->getSearchIndex(indexId); });
    EXPECT_EQ(rekeyed.staleGroups.size(), 0);

    closeHandle(worker);
    expectIntact(worker, indexId, ledger.committed);
    expectIntact(owner, indexId, ledger.committed);
    // user_3's session was live throughout, and holds whatever it learned while it was a member — which is
    // nothing about this Index, and after the re-key there is no route left to learn it through either.
    expectLockedOut(other, indexId);
}

/**
 * ── the Group's membership, case 3: user_3 is added, user_2 stays ──────────────────────────────────────────────
 *
 * The cheap direction, and the one with a claim to check: adding a member to a tree-backed Group does not
 * advance its epoch, so no container the Group can read needs re-keying and nobody's open handle is disturbed.
 * The Index's own version must not move either — user_1 never calls anything on it.
 *
 * The new member then reads documents written before they joined, which is the other half of not moving the
 * epoch: the Index's key is still the one those documents were written under.
 */
TEST_F(SearchUsingGroupsTest, adding_a_member_to_the_grantee_group_disturbs_nothing) {
    openClients();

    std::string groupId, indexId;
    createGroupOf("other_in", {userOf(SRUser2)}, groupId);
    group::Group group;
    ASSERT_NO_THROW({ group = groupNow(groupId); });
    ASSERT_EQ(group.statusCode, 0);
    ASSERT_EQ(group.keyVersion, 1);
    createIndexGranting("other_in", {userOf(SRUser1)}, {userOf(SRUser1)}, grantsFor(group), indexId);

    Ledger ledger;
    openAndSeed(worker, indexId, "beta", 3, ledger);

    search::SearchIndex before;
    ASSERT_NO_THROW({ before = owner.searchApi->getSearchIndex(indexId); });
    ASSERT_EQ(before.statusCode, 0);
    ASSERT_EQ(before.staleGroups.size(), 0);

    // user_3 is outside the Group and outside the Index, and can reach neither.
    auto outsider = openAndRead(other, indexId);
    EXPECT_FALSE(outsider.opened) << "a caller in no granted group opened the Index";

    ASSERT_NO_THROW({
        owner.groupApi->addGroupMembers(
            groupId, {group::GroupMemberToAdd{.user = userOf(SRUser3), .role = "user"}}
        );
    });
    group::Group grown;
    ASSERT_NO_THROW({ grown = groupNow(groupId); });
    EXPECT_EQ(grown.keyVersion, 1) << "adding a member advanced the group's key epoch";

    search::SearchIndex after;
    ASSERT_NO_THROW({ after = owner.searchApi->getSearchIndex(indexId); });
    EXPECT_EQ(after.statusCode, 0);
    EXPECT_EQ(after.staleGroups.size(), 0) << "an addition left the Index needing a re-key";
    EXPECT_EQ(after.version, before.version) << "an addition changed the Index itself";

    // No re-key happened anywhere, so the handle user_2 opened before the addition is still the current key's.
    const int64_t committedBefore = ledger.committed;
    addDocument(worker, "beta-3", "beta", ledger);
    reportRefusals(ledger);
    EXPECT_EQ(ledger.committed, committedBefore + 1)
        << "adding somebody else to the group cost the existing member their write; see the refusal above";
    EXPECT_EQ(searchThrough(worker, SHARED_TERM), ledger.committed);

    // The new member reads the whole Index, including what predates their membership.
    expectIntact(other, indexId, ledger.committed);
    expectIntact(owner, indexId, ledger.committed);
}
