#include <chrono>
#include <functional>
#include <map>
#include <memory>
#include <string>
#include <thread>
#include <vector>

#include <gtest/gtest.h>
#include "../../utils/BaseTest.hpp"
#include <Poco/Util/IniFileConfiguration.h>
#include <privmx/endpoint/core/Connection.hpp>
#include <privmx/endpoint/core/CoreException.hpp>
#include <privmx/endpoint/core/EventQueue.hpp>
#include <privmx/endpoint/core/EventQueueImpl.hpp>
#include <privmx/endpoint/core/Exception.hpp>
#include <privmx/endpoint/core/Types.hpp>
#include <privmx/endpoint/group/GroupApi.hpp>
#include <privmx/endpoint/kvdb/KvdbApi.hpp>

using namespace privmx::endpoint;

/**
 * One long scenario, three sessions that stay connected the whole way through.
 *
 * A KVDB whose only non-manager readers come from a Group, a member removed from that Group halfway, and a set
 * of entries that ends up split across the two container keys the removal produces. The point of running it as
 * one flow rather than as separate cases is that each session's key caches carry over: what user_3 can still
 * read after being removed depends on what that session learned while it was still a member, and a reconnect
 * would erase exactly that.
 *
 * What this adds over the Thread scenario is the keyed, versioned item. A KVDB entry is addressed by its key
 * rather than by a server-assigned id and carries an optimistic-lock version, so overwriting one in place is
 * the module's own way of moving an item onto the current container key — and `deleteEntries` retires a whole
 * page of them in a single request.
 *
 * user_1 and user_2 hold subscriptions to every KVDB and Group event for the whole run, so the notification
 * path is exercised alongside the data path.
 */

class KvdbGroupScenarioTest : public privmx::test::BaseTest {
protected:
    KvdbGroupScenarioTest() : BaseTest(privmx::test::BaseTestMode::online) {}

    static constexpr int ENTRY_COUNT = 100;
    static constexpr int64_t PAGE_LIMIT = 10;

    // One user's live session.
    struct Client {
        std::shared_ptr<core::Connection> connection;
        std::shared_ptr<group::GroupApi> groupApi;
        std::shared_ptr<kvdb::KvdbApi> kvdbApi;
        int64_t connectionId = 0;
    };

    void customSetUp() override {
        reader = new Poco::Util::IniFileConfiguration(INI_FILE_PATH);
        user1 = connectAs(1);
        user2 = connectAs(2);
        user3 = connectAs(3);
    }

    void customTearDown() override {
        resetClient(user1);
        resetClient(user2);
        resetClient(user3);
        reader.reset();
        core::EventQueueImpl::getInstance()->clear();
    }

    Client connectAs(int index) {
        const std::string n = std::to_string(index);
        Client client;
        client.connection = std::make_shared<core::Connection>(
            core::Connection::connect(
                reader->getString("Login.user_" + n + "_privKey"), reader->getString("Login.solutionId"),
                getPlatformUrl(reader->getString("Login.instanceUrl"))
            )
        );
        client.groupApi = std::make_shared<group::GroupApi>(group::GroupApi::create(*client.connection));
        client.kvdbApi = std::make_shared<kvdb::KvdbApi>(kvdb::KvdbApi::create(*client.connection, *client.groupApi));
        client.connectionId = client.connection->getConnectionId();
        return client;
    }

    void resetClient(Client& client) {
        client.connection.reset();
        client.kvdbApi.reset();
        client.groupApi.reset();
    }

    core::UserWithPubKey user(int index) {
        const std::string n = std::to_string(index);
        return core::UserWithPubKey{
            .userId = reader->getString("Login.user_" + n + "_id"),
            .pubKey = reader->getString("Login.user_" + n + "_pubKey")
        };
    }

    std::string contextId() {
        return reader->getString("Context_1.contextId");
    }

    // Every event type both modules define, on the one selector that needs no container to exist yet.
    void subscribeToEverything(Client& client) {
        std::vector<std::string> kvdbQueries;
        for (const auto eventType :
             {kvdb::EventType::KVDB_CREATE, kvdb::EventType::KVDB_UPDATE, kvdb::EventType::KVDB_DELETE,
              kvdb::EventType::KVDB_STATS, kvdb::EventType::ENTRY_CREATE, kvdb::EventType::ENTRY_UPDATE,
              kvdb::EventType::ENTRY_DELETE, kvdb::EventType::COLLECTION_CHANGE}) {
            kvdbQueries.push_back(
                client.kvdbApi->buildSubscriptionQuery(eventType, kvdb::EventSelectorType::CONTEXT_ID, contextId())
            );
        }
        client.kvdbApi->subscribeFor(kvdbQueries);

        std::vector<std::string> groupQueries;
        for (const auto eventType :
             {group::EventType::GROUP_CREATE, group::EventType::GROUP_UPDATE, group::EventType::GROUP_DELETE}) {
            groupQueries.push_back(
                client.groupApi->buildSubscriptionQuery(eventType, group::EventSelectorType::CONTEXT_ID, contextId())
            );
        }
        client.groupApi->subscribeFor(groupQueries);
    }

    // The queue is process-wide and carries every session's events, and this scenario makes several hundred of
    // them, so they are tallied by (connectionId, type) instead of being waited for one at a time.
    void pumpEvents(const std::chrono::milliseconds& budget = std::chrono::milliseconds(500)) {
        const auto deadline = std::chrono::steady_clock::now() + budget;
        while (std::chrono::steady_clock::now() < deadline) {
            auto eventHolder = eventQueue.getEvent();
            if (!eventHolder.has_value()) {
                std::this_thread::sleep_for(std::chrono::milliseconds(25));
                continue;
            }
            auto event = eventHolder.value().get();
            if (event != nullptr) {
                _tally[event->connectionId][event->type]++;
            }
        }
    }

    void pumpUntil(const std::function<bool()>& done, const std::chrono::milliseconds& timeout) {
        const auto deadline = std::chrono::steady_clock::now() + timeout;
        while (std::chrono::steady_clock::now() < deadline && !done()) {
            pumpEvents(std::chrono::milliseconds(250));
        }
    }

    int eventsSeen(const Client& client, const std::string& type) {
        auto byConnection = _tally.find(client.connectionId);
        if (byConnection == _tally.end()) {
            return 0;
        }
        auto counted = byConnection->second.find(type);
        return counted == byConnection->second.end() ? 0 : counted->second;
    }

    // The container and its entries are downloadable context-wide, so a reader who loses the key keeps getting
    // the ciphertext. Who can decrypt it is a key question, not a policy one.
    core::ContainerPolicy readableByEveryone() {
        core::ContainerPolicy policy;
        policy.get = "all";
        core::ItemPolicy item;
        item.get = "all";
        item.listAll = "all";
        policy.item = item;
        policy.forwardSecrecy = "yes";
        return policy;
    }

    std::vector<core::GroupGrantWithKey> grantsFor(const group::Group& group) {
        return std::vector<core::GroupGrantWithKey>{core::GroupGrantWithKey{
            .groupId = group.groupId,
            .role = "user",
            .groupPubKey = group.groupPubKey,
            .groupEpoch = group.keyVersion
        }};
    }

    std::vector<kvdb::KvdbEntry> listAllEntries(Client& client, const std::string& kvdbId, int64_t limit) {
        std::vector<kvdb::KvdbEntry> all;
        for (int64_t skip = 0;; skip += limit) {
            auto page = client.kvdbApi->listEntries(
                kvdbId,
                core::PagingQuery{
                    .skip = skip,
                    .limit = limit,
                    .sortOrder = "asc",
                    .lastId = std::nullopt,
                    .sortBy = std::nullopt,
                    .queryAsJson = std::nullopt
                }
            );
            all.insert(all.end(), page.readItems.begin(), page.readItems.end());
            if (page.readItems.empty() || all.size() >= static_cast<size_t>(page.totalAvailable)) {
                break;
            }
        }
        return all;
    }

    std::map<std::string, kvdb::KvdbEntry> byEntryKey(const std::vector<kvdb::KvdbEntry>& entries) {
        std::map<std::string, kvdb::KvdbEntry> indexed;
        for (const auto& entry : entries) {
            indexed.emplace(entry.info.key, entry);
        }
        return indexed;
    }

    Client user1;
    Client user2;
    Client user3;
    Poco::Util::IniFileConfiguration::Ptr reader;
    core::EventQueue eventQueue = core::EventQueue::getInstance();

private:
    std::map<int64_t, std::map<std::string, int>> _tally;
};

TEST_F(KvdbGroupScenarioTest, kvdb_granted_to_a_group_across_a_member_removal) {
    subscribeToEverything(user1);
    subscribeToEverything(user2);

    // ── Group1: user_2 and user_3 are the members, user_1 only manages it ──────────────────────────────────
    std::string groupId;
    ASSERT_NO_THROW({
        groupId = user1.groupApi->createGroup(
            contextId(), std::vector<core::UserWithPubKey>{user(2), user(3)},
            std::vector<core::UserWithPubKey>{user(1)}, core::Buffer::from("group1_public"),
            core::Buffer::from("group1_private")
        );
    });
    ASSERT_FALSE(groupId.empty());
    group::Group group1;
    ASSERT_NO_THROW({ group1 = user1.groupApi->getGroup(groupId); });
    ASSERT_EQ(group1.statusCode, 0);
    ASSERT_EQ(group1.keyVersion, 1);

    // ── Kvdb1: user_1 manages it, Group1 reads it, anyone may download it ──────────────────────────────────
    std::string kvdbId;
    ASSERT_NO_THROW({
        kvdbId = user1.kvdbApi->createKvdb(
            contextId(), std::vector<core::UserWithPubKey>{user(1)}, std::vector<core::UserWithPubKey>{user(1)},
            core::Buffer::from("kvdb1_public"), core::Buffer::from("kvdb1_private"), readableByEveryone(),
            grantsFor(group1)
        );
    });
    ASSERT_FALSE(kvdbId.empty());

    // ── Entry1, written by user_2 — a Group member, named nowhere on the KVDB ──────────────────────────────
    ASSERT_NO_THROW({
        user2.kvdbApi->setEntry(
            kvdbId, "entry1", core::Buffer::from("entry1_public"), core::Buffer::from("entry1_private"),
            core::Buffer::from("entry1_data"), 0
        );
    });

    // user_3 reads it through the same grant
    kvdb::KvdbEntry entry1AsUser3;
    ASSERT_NO_THROW({ entry1AsUser3 = user3.kvdbApi->getEntry(kvdbId, "entry1"); });
    EXPECT_EQ(entry1AsUser3.statusCode, 0) << "a group member could not read an entry written by another one";
    EXPECT_EQ(entry1AsUser3.privateMeta.stdString(), "entry1_private");
    EXPECT_EQ(entry1AsUser3.data.stdString(), "entry1_data");
    EXPECT_EQ(entry1AsUser3.version, 1);

    // ── user_1 updates the KVDB, roster untouched ──────────────────────────────────────────────────────────
    kvdb::Kvdb beforeUpdate;
    ASSERT_NO_THROW({ beforeUpdate = user1.kvdbApi->getKvdb(kvdbId); });
    ASSERT_EQ(beforeUpdate.statusCode, 0);
    ASSERT_NO_THROW({
        // The grant has to be restated: an omitted `groups` means "no grantees", not "leave them alone".
        user1.kvdbApi->updateKvdb(
            kvdbId, std::vector<core::UserWithPubKey>{user(1)}, std::vector<core::UserWithPubKey>{user(1)},
            core::Buffer::from("kvdb1_public_v2"), core::Buffer::from("kvdb1_private_v2"), beforeUpdate.version,
            false, false, readableByEveryone(), grantsFor(group1)
        );
    });
    kvdb::Kvdb afterUpdate;
    ASSERT_NO_THROW({ afterUpdate = user1.kvdbApi->getKvdb(kvdbId); });
    EXPECT_EQ(afterUpdate.statusCode, 0);
    EXPECT_EQ(afterUpdate.publicMeta.stdString(), "kvdb1_public_v2");
    ASSERT_EQ(afterUpdate.groups.size(), 1);
    EXPECT_EQ(afterUpdate.groups[0].groupId, groupId);

    // ── ENTRY_COUNT entries by user_3, all under the KVDB key wrapped to the Group's epoch 1 ───────────────
    std::vector<std::string> user3EntryKeys;
    user3EntryKeys.reserve(ENTRY_COUNT);
    for (int i = 0; i < ENTRY_COUNT; ++i) {
        const std::string suffix = std::to_string(i);
        const std::string entryKey = "user3_key_" + suffix;
        ASSERT_NO_THROW({
            user3.kvdbApi->setEntry(
                kvdbId, entryKey, core::Buffer::from("user3_public_" + suffix),
                core::Buffer::from("user3_private_" + suffix), core::Buffer::from("user3_data_" + suffix), 0
            );
        }) << "user_3 could not set entry " << i;
        user3EntryKeys.push_back(entryKey);
    }
    ASSERT_EQ(user3EntryKeys.size(), static_cast<size_t>(ENTRY_COUNT));

    // user_3 reads them back while still a member. This is the step the last phase of the scenario rests on: it is
    // what puts the Group's epoch-1 grant key and the KVDB's key entries into this session's caches.
    auto asMember = byEntryKey(listAllEntries(user3, kvdbId, ENTRY_COUNT));
    for (int i = 0; i < ENTRY_COUNT; ++i) {
        const auto found = asMember.find(user3EntryKeys[i]);
        ASSERT_NE(found, asMember.end()) << "user_3's own entry " << i << " is missing from the listing";
        ASSERT_EQ(found->second.statusCode, 0) << "user_3 could not read their own entry " << i << " as a member";
        ASSERT_EQ(found->second.data.stdString(), "user3_data_" + std::to_string(i));
    }
    pumpEvents();

    // ── user_3 leaves Group1: the Group's epoch moves 1 → 2 ────────────────────────────────────────────────
    ASSERT_NO_THROW({
        user1.groupApi->removeGroupMembers(groupId, {user(3).userId});
    });
    group::Group rotatedGroup;
    ASSERT_NO_THROW({ rotatedGroup = user1.groupApi->getGroup(groupId); });
    ASSERT_EQ(rotatedGroup.keyVersion, 2);

    // ── Entry2 by user_2. The KVDB's key is still wrapped to the epoch the Group just left, so the write
    //    re-keys the KVDB first — that is what `staleGroups` on every read is there to drive ───────────────
    ASSERT_NO_THROW({
        user2.kvdbApi->setEntry(
            kvdbId, "entry2", core::Buffer::from("entry2_public"), core::Buffer::from("entry2_private"),
            core::Buffer::from("entry2_data"), 0
        );
    });
    kvdb::Kvdb rekeyedKvdb;
    ASSERT_NO_THROW({ rekeyedKvdb = user1.kvdbApi->getKvdb(kvdbId); });
    // Pins the forced auto re-key: a warm key cache whose staleGroups predates the rotation must not talk the
    // writer out of it (ModuleBaseApi::withKeyRefresh).
    EXPECT_TRUE(rekeyedKvdb.staleGroups.empty())
        << "writing after the group rotated should have re-keyed the kvdb to the new epoch";

    // ── user_1 overwrites Entry1 in place, which moves it onto the new key ─────────────────────────────────
    kvdb::KvdbEntry entry1BeforeOverwrite;
    ASSERT_NO_THROW({ entry1BeforeOverwrite = user1.kvdbApi->getEntry(kvdbId, "entry1"); });
    ASSERT_EQ(entry1BeforeOverwrite.statusCode, 0);
    ASSERT_NO_THROW({
        // The version is the optimistic lock: passing 0 for a key that already exists is rejected.
        user1.kvdbApi->setEntry(
            kvdbId, "entry1", core::Buffer::from("entry1_public_v2"), core::Buffer::from("entry1_private_v2"),
            core::Buffer::from("entry1_data_v2"), entry1BeforeOverwrite.version
        );
    });

    // ── What user_3 can see now: the re-encrypted entry is closed to them, its public half is not ──────────
    kvdb::KvdbEntry lostEntry;
    ASSERT_NO_THROW({ lostEntry = user3.kvdbApi->getEntry(kvdbId, "entry1"); });
    EXPECT_NE(lostEntry.statusCode, 0) << "a removed member decrypted content re-encrypted after their removal";
    EXPECT_EQ(lostEntry.publicMeta.stdString(), "entry1_public_v2")
        << "public metadata is not encrypted and has to survive the loss of the key";
    EXPECT_TRUE(lostEntry.privateMeta.stdString().empty());
    EXPECT_TRUE(lostEntry.data.stdString().empty());

    // ...and so is everything user_3 wrote before the removal, even though those entries were encrypted under
    // the KVDB key of the Group's epoch 1 and this session read them all while it still held that grant. The
    // next read after the re-key replaces the whole cache entry (ContainerKeyCache::set does insert_or_assign,
    // not a merge), and the group key resolver has no group left to recover epoch 1 from. Same expectation as
    // ThreadGroupScenarioTest.
    auto asUser3 = byEntryKey(listAllEntries(user3, kvdbId, ENTRY_COUNT));
    int unreadable = 0;
    for (int i = 0; i < ENTRY_COUNT; ++i) {
        const auto found = asUser3.find(user3EntryKeys[i]);
        ASSERT_NE(found, asUser3.end()) << "user_3's own entry " << i << " is gone from the listing";
        if (found->second.statusCode != 0) {
            ++unreadable;
        }
    }
    // Reported as a count rather than per entry: a regression here moves all hundred at once.
    EXPECT_EQ(unreadable, ENTRY_COUNT) << "user_3 can still decrypt " << (ENTRY_COUNT - unreadable)
                                       << " of their own pre-removal entries";
    // The listing still names them and their public halves survive — only the encrypted halves are gone.
    EXPECT_EQ(asUser3.at(user3EntryKeys[0]).publicMeta.stdString(), "user3_public_0");
    EXPECT_TRUE(asUser3.at(user3EntryKeys[0]).data.stdString().empty());

    // ── user_1 deletes everything user_3 wrote, ten at a time ──────────────────────────────────────────────
    int deleted = 0;
    for (int pass = 0; pass < ENTRY_COUNT; ++pass) {
        core::PagingList<kvdb::KvdbEntry> page{};
        ASSERT_NO_THROW({
            page = user1.kvdbApi->listEntries(
                kvdbId,
                core::PagingQuery{
                    .skip = 0,
                    .limit = PAGE_LIMIT,
                    .sortOrder = "asc",
                    .lastId = std::nullopt,
                    .sortBy = std::nullopt,
                    .queryAsJson = std::nullopt
                }
            );
        });
        std::vector<std::string> toDelete;
        for (const auto& entry : page.readItems) {
            if (entry.info.author == user(3).userId) {
                toDelete.push_back(entry.info.key);
            }
        }
        if (toDelete.empty()) {
            break;
        }
        std::map<std::string, bool> statuses;
        ASSERT_NO_THROW({ statuses = user1.kvdbApi->deleteEntries(kvdbId, toDelete); });
        for (const auto& entryKey : toDelete) {
            const auto status = statuses.find(entryKey);
            ASSERT_NE(status, statuses.end()) << "deleteEntries said nothing about " << entryKey;
            EXPECT_TRUE(status->second) << "deleteEntries failed on " << entryKey;
            if (status->second) {
                ++deleted;
            }
        }
    }
    EXPECT_EQ(deleted, ENTRY_COUNT);

    // ── user_2 sees Entry1 and Entry2, and nothing else ────────────────────────────────────────────────────
    auto remaining = listAllEntries(user2, kvdbId, PAGE_LIMIT);
    ASSERT_EQ(remaining.size(), 2);
    auto asUser2 = byEntryKey(remaining);
    ASSERT_NE(asUser2.find("entry1"), asUser2.end());
    ASSERT_NE(asUser2.find("entry2"), asUser2.end());
    EXPECT_EQ(asUser2.at("entry1").statusCode, 0);
    EXPECT_EQ(asUser2.at("entry1").data.stdString(), "entry1_data_v2");
    EXPECT_EQ(asUser2.at("entry1").version, 2);
    EXPECT_EQ(asUser2.at("entry2").statusCode, 0);
    EXPECT_EQ(asUser2.at("entry2").data.stdString(), "entry2_data");

    // ── Both watchers were told about all of it ────────────────────────────────────────────────────────────
    pumpUntil(
        [&] {
            return eventsSeen(user1, "kvdbEntryDeleted") >= ENTRY_COUNT &&
                eventsSeen(user2, "kvdbEntryDeleted") >= ENTRY_COUNT;
        },
        std::chrono::seconds(30)
    );
    for (const auto& watcher : {std::cref(user1), std::cref(user2)}) {
        const Client& client = watcher.get();
        EXPECT_GE(eventsSeen(client, "groupCreated"), 1);
        EXPECT_GE(eventsSeen(client, "groupUpdated"), 1) << "removing a member is a group update";
        EXPECT_GE(eventsSeen(client, "kvdbCreated"), 1);
        EXPECT_GE(eventsSeen(client, "kvdbUpdated"), 1);
        EXPECT_GE(eventsSeen(client, "kvdbNewEntry"), ENTRY_COUNT + 2);
        EXPECT_GE(eventsSeen(client, "kvdbEntryUpdated"), 1);
        EXPECT_GE(eventsSeen(client, "kvdbEntryDeleted"), ENTRY_COUNT);
    }
}
