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
#include <privmx/endpoint/inbox/InboxApi.hpp>
#include <privmx/endpoint/store/StoreApi.hpp>
#include <privmx/endpoint/thread/ThreadApi.hpp>

using namespace privmx::endpoint;

/**
 * One long scenario, three sessions that stay connected the whole way through.
 *
 * An Inbox whose only non-manager readers come from a Group, a member removed from that Group halfway, and an
 * explicit re-key in between. The point of running it as one flow rather than as separate cases is that each
 * session's key caches carry over, and a reconnect would erase exactly that.
 *
 * Two things make the Inbox unlike the Thread, Store and KVDB scenarios, and they are what this test is for:
 *
 *  - An Inbox is three containers. Entries live in an inner Thread and their files in an inner Store, and a
 *    grant has to reach all three or a group member reads the Inbox's metadata and none of its content.
 *  - Submitting an entry seals it to the Inbox's entries public key, taken from the public view, and never
 *    touches the container key. So no write auto-re-keys a stale Inbox the way sendMessage or setEntry does:
 *    `staleGroups` sits there until a manager calls rotateInboxKeys, and that is the only thing that moves the
 *    grants onto the Group's new epoch.
 *
 * user_1 and user_2 hold subscriptions to every Inbox and Group event for the whole run, so the notification
 * path is exercised alongside the data path.
 */

class InboxGroupScenarioTest : public privmx::test::BaseTest {
protected:
    InboxGroupScenarioTest() : BaseTest(privmx::test::BaseTestMode::online) {}

    // Lower than the Thread scenario's message count on purpose: one submission is prepareEntry + sendEntry and
    // lands a message in the inner Thread, so a hundred of them would dominate the suite's runtime.
    static constexpr int ENTRY_COUNT = 25;
    static constexpr int64_t PAGE_LIMIT = 10;

    // One user's live session. The Inbox API needs a Thread and a Store API built on the same GroupApi, or the
    // inner containers end up granted to the groups but unreadable through them.
    struct Client {
        std::shared_ptr<core::Connection> connection;
        std::shared_ptr<group::GroupApi> groupApi;
        std::shared_ptr<thread::ThreadApi> threadApi;
        std::shared_ptr<store::StoreApi> storeApi;
        std::shared_ptr<inbox::InboxApi> inboxApi;
        std::string privKey;
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
        client.privKey = reader->getString("Login.user_" + n + "_privKey");
        client.connection = std::make_shared<core::Connection>(
            core::Connection::connect(
                client.privKey, reader->getString("Login.solutionId"),
                getPlatformUrl(reader->getString("Login.instanceUrl"))
            )
        );
        client.groupApi = std::make_shared<group::GroupApi>(group::GroupApi::create(*client.connection));
        client.threadApi = std::make_shared<thread::ThreadApi>(
            thread::ThreadApi::create(*client.connection, *client.groupApi)
        );
        client.storeApi = std::make_shared<store::StoreApi>(
            store::StoreApi::create(*client.connection, *client.groupApi)
        );
        client.inboxApi = std::make_shared<inbox::InboxApi>(
            inbox::InboxApi::create(*client.connection, *client.threadApi, *client.storeApi, *client.groupApi)
        );
        client.connectionId = client.connection->getConnectionId();
        return client;
    }

    void resetClient(Client& client) {
        client.connection.reset();
        client.inboxApi.reset();
        client.storeApi.reset();
        client.threadApi.reset();
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
        std::vector<std::string> inboxQueries;
        for (const auto eventType :
             {inbox::EventType::INBOX_CREATE, inbox::EventType::INBOX_UPDATE, inbox::EventType::INBOX_DELETE,
              inbox::EventType::ENTRY_CREATE, inbox::EventType::ENTRY_DELETE,
              inbox::EventType::COLLECTION_CHANGE}) {
            inboxQueries.push_back(
                client.inboxApi->buildSubscriptionQuery(eventType, inbox::EventSelectorType::CONTEXT_ID, contextId())
            );
        }
        client.inboxApi->subscribeFor(inboxQueries);

        std::vector<std::string> groupQueries;
        for (const auto eventType :
             {group::EventType::GROUP_CREATE, group::EventType::GROUP_UPDATE, group::EventType::GROUP_DELETE}) {
            groupQueries.push_back(
                client.groupApi->buildSubscriptionQuery(eventType, group::EventSelectorType::CONTEXT_ID, contextId())
            );
        }
        client.groupApi->subscribeFor(groupQueries);
    }

    // The queue is process-wide and carries every session's events, and this scenario makes a few hundred of
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

    // The Inbox itself is downloadable context-wide, so a reader who loses the key keeps getting the ciphertext
    // and a status code instead of an exception. Its entries are not: an Inbox policy carries no item policy
    // (createInbox hands the inner Thread and Store `{policies, std::nullopt}`), so those stay at the default
    // `user` scope and the bridge refuses a non-grantee outright.
    core::ContainerPolicyWithoutItem inboxReadableByEveryone() {
        core::ContainerPolicyWithoutItem policy;
        policy.get = "all";
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

    // Submits one entry, signed with the sender's own key so the entry carries their public key rather than a
    // throwaway one.
    void submitEntry(Client& client, const std::string& inboxId, const std::string& data) {
        int64_t handle = client.inboxApi->prepareEntry(inboxId, core::Buffer::from(data), {}, client.privKey);
        client.inboxApi->sendEntry(handle);
    }

    // Submits one entry with a single attached file, which is what puts something in the inner Store.
    void submitEntryWithFile(
        Client& client,
        const std::string& inboxId,
        const std::string& data,
        const std::string& filePublicMeta,
        const std::string& filePrivateMeta,
        const std::string& fileData
    ) {
        int64_t fileHandle = client.inboxApi->createFileHandle(
            core::Buffer::from(filePublicMeta), core::Buffer::from(filePrivateMeta), (int64_t)fileData.size()
        );
        int64_t inboxHandle = client.inboxApi->prepareEntry(
            inboxId, core::Buffer::from(data), {fileHandle}, client.privKey
        );
        client.inboxApi->writeToFile(inboxHandle, fileHandle, core::Buffer::from(fileData));
        client.inboxApi->sendEntry(inboxHandle);
    }

    std::string downloadFile(Client& client, const std::string& fileId, int64_t size) {
        int64_t handle = client.inboxApi->openFile(fileId);
        auto data = client.inboxApi->readFromFile(handle, size).stdString();
        client.inboxApi->closeFile(handle);
        return data;
    }

    std::vector<inbox::InboxEntry> listAllEntries(Client& client, const std::string& inboxId, int64_t limit) {
        std::vector<inbox::InboxEntry> all;
        for (int64_t skip = 0;; skip += limit) {
            auto page = client.inboxApi->listEntries(
                inboxId,
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

    std::map<std::string, inbox::InboxEntry> byEntryData(const std::vector<inbox::InboxEntry>& entries) {
        std::map<std::string, inbox::InboxEntry> indexed;
        for (const auto& entry : entries) {
            indexed.emplace(entry.data.stdString(), entry);
        }
        return indexed;
    }

    static bool isBulkEntry(const inbox::InboxEntry& entry) {
        return entry.data.stdString().rfind("user3_data_", 0) == 0;
    }

    Client user1;
    Client user2;
    Client user3;
    Poco::Util::IniFileConfiguration::Ptr reader;
    core::EventQueue eventQueue = core::EventQueue::getInstance();

private:
    std::map<int64_t, std::map<std::string, int>> _tally;
};

TEST_F(InboxGroupScenarioTest, inbox_granted_to_a_group_across_a_member_removal_and_a_rekey) {
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

    // ── Inbox1: user_1 manages it, Group1 reads it, anyone may fetch it ────────────────────────────────────
    std::string inboxId;
    ASSERT_NO_THROW({
        inboxId = user1.inboxApi->createInbox(
            contextId(), std::vector<core::UserWithPubKey>{user(1)}, std::vector<core::UserWithPubKey>{user(1)},
            core::Buffer::from("inbox1_public"), core::Buffer::from("inbox1_private"), std::nullopt,
            inboxReadableByEveryone(), grantsFor(group1)
        );
    });
    ASSERT_FALSE(inboxId.empty());

    // ── Entry1 by user_2, with a file attached — a Group member, named nowhere on the Inbox ────────────────
    ASSERT_NO_THROW({
        submitEntryWithFile(user2, inboxId, "entry1_data", "file1_public", "file1_private", "file1_data");
    });

    // user_3 reads it through the same grant. This is the three-container assertion: the entry comes out of the
    // inner Thread and the attachment out of the inner Store, and neither names user_3 or Group1 directly.
    auto entriesAsUser3 = listAllEntries(user3, inboxId, PAGE_LIMIT);
    ASSERT_EQ(entriesAsUser3.size(), 1);
    const inbox::InboxEntry entry1AsUser3 = entriesAsUser3[0];
    EXPECT_EQ(entry1AsUser3.statusCode, 0) << "a group member could not read an entry submitted by another one";
    EXPECT_EQ(entry1AsUser3.data.stdString(), "entry1_data");
    ASSERT_EQ(entry1AsUser3.files.size(), 1);
    EXPECT_EQ(entry1AsUser3.files[0].statusCode, 0) << "the grant did not reach the Inbox's inner Store";
    EXPECT_EQ(entry1AsUser3.files[0].privateMeta.stdString(), "file1_private");
    std::string file1DataAsUser3;
    ASSERT_NO_THROW({
        file1DataAsUser3 = downloadFile(user3, entry1AsUser3.files[0].info.fileId, entry1AsUser3.files[0].size);
    });
    EXPECT_EQ(file1DataAsUser3, "file1_data");
    const std::string entry1Id = entry1AsUser3.entryId;

    // ── user_1 updates the Inbox, roster untouched ─────────────────────────────────────────────────────────
    inbox::Inbox beforeUpdate;
    ASSERT_NO_THROW({ beforeUpdate = user1.inboxApi->getInbox(inboxId); });
    ASSERT_EQ(beforeUpdate.statusCode, 0);
    ASSERT_NO_THROW({
        // The grant has to be restated: an omitted `groups` means "no grantees", not "leave them alone" — and
        // updateInbox applies whatever it is told to all three containers.
        user1.inboxApi->updateInbox(
            inboxId, std::vector<core::UserWithPubKey>{user(1)}, std::vector<core::UserWithPubKey>{user(1)},
            core::Buffer::from("inbox1_public_v2"), core::Buffer::from("inbox1_private_v2"), std::nullopt,
            beforeUpdate.version, false, false, inboxReadableByEveryone(), grantsFor(group1)
        );
    });
    inbox::Inbox afterUpdate;
    ASSERT_NO_THROW({ afterUpdate = user1.inboxApi->getInbox(inboxId); });
    EXPECT_EQ(afterUpdate.statusCode, 0);
    EXPECT_EQ(afterUpdate.publicMeta.stdString(), "inbox1_public_v2");
    ASSERT_EQ(afterUpdate.groups.size(), 1);
    EXPECT_EQ(afterUpdate.groups[0].groupId, groupId);

    // The update re-keyed all three containers, so the same read has to keep working for a group-only reader.
    inbox::InboxEntry entry1AfterUpdate;
    ASSERT_NO_THROW({ entry1AfterUpdate = user3.inboxApi->readEntry(entry1Id); });
    EXPECT_EQ(entry1AfterUpdate.statusCode, 0) << "updateInbox lost the grant on one of the inner containers";
    EXPECT_EQ(entry1AfterUpdate.data.stdString(), "entry1_data");

    // ── ENTRY_COUNT entries by user_3 ──────────────────────────────────────────────────────────────────────
    for (int i = 0; i < ENTRY_COUNT; ++i) {
        ASSERT_NO_THROW({ submitEntry(user3, inboxId, "user3_data_" + std::to_string(i)); })
            << "user_3 could not submit entry " << i;
    }

    // user_2, the other Group member, reads all of them.
    auto asUser2BeforeRemoval = byEntryData(listAllEntries(user2, inboxId, ENTRY_COUNT));
    for (int i = 0; i < ENTRY_COUNT; ++i) {
        const std::string data = "user3_data_" + std::to_string(i);
        const auto found = asUser2BeforeRemoval.find(data);
        ASSERT_NE(found, asUser2BeforeRemoval.end()) << "entry " << i << " is missing from the listing";
        ASSERT_EQ(found->second.statusCode, 0) << "user_2 could not read entry " << i;
    }
    pumpEvents();

    // ── user_3 leaves Group1: the Group's epoch moves 1 → 2 ────────────────────────────────────────────────
    ASSERT_NO_THROW({
        user1.groupApi->removeGroupMember(
            groupId, user(3).userId, std::vector<core::UserWithPubKey>{user(2)},
            std::vector<core::UserWithPubKey>{user(1)}, core::Buffer::from("group1_public"),
            core::Buffer::from("group1_private")
        );
    });
    group::Group rotatedGroup;
    ASSERT_NO_THROW({ rotatedGroup = user1.groupApi->getGroup(groupId); });
    ASSERT_EQ(rotatedGroup.keyVersion, 2);

    inbox::Inbox staleInbox;
    ASSERT_NO_THROW({ staleInbox = user1.inboxApi->getInbox(inboxId); });
    ASSERT_EQ(staleInbox.statusCode, 0);
    ASSERT_EQ(staleInbox.staleGroups.size(), 1);
    EXPECT_EQ(staleInbox.staleGroups[0], groupId);

    // ── Entry2, submitted while the Inbox is still stale ───────────────────────────────────────────────────
    // This is where the Inbox parts company with the other modules: the payload is sealed to the Inbox's
    // entries public key, so the send never reaches for the container key and nothing auto-re-keys.
    ASSERT_NO_THROW({ submitEntry(user2, inboxId, "entry2_data"); });
    inbox::Inbox stillStale;
    ASSERT_NO_THROW({ stillStale = user1.inboxApi->getInbox(inboxId); });
    EXPECT_EQ(stillStale.staleGroups.size(), 1)
        << "submitting an entry is not a container write and must not have re-keyed the inbox";

    // ── user_1 re-keys, which is the only thing that moves the grants onto epoch 2 ─────────────────────────
    ASSERT_NO_THROW({
        user1.inboxApi->rotateInboxKeys(
            inboxId, std::vector<core::UserWithPubKey>{user(1)}, std::vector<core::UserWithPubKey>{user(1)},
            stillStale.version, false, std::vector<core::GroupGrantWithKey>{}
        );
    });
    inbox::Inbox freshInbox;
    ASSERT_NO_THROW({ freshInbox = user1.inboxApi->getInbox(inboxId); });
    EXPECT_EQ(freshInbox.statusCode, 0);
    EXPECT_TRUE(freshInbox.staleGroups.empty()) << "rotateInboxKeys did not clear staleGroups";
    ASSERT_EQ(freshInbox.groups.size(), 1);
    EXPECT_EQ(freshInbox.groups[0].groupId, groupId);

    // ── Entry3, submitted after the re-key ─────────────────────────────────────────────────────────────────
    ASSERT_NO_THROW({ submitEntry(user2, inboxId, "entry3_data"); });

    // ── user_2 is still in Group1 at epoch 2, and everything is readable to them across both key epochs ────
    auto asUser2 = byEntryData(listAllEntries(user2, inboxId, ENTRY_COUNT + PAGE_LIMIT));
    ASSERT_NE(asUser2.find("entry1_data"), asUser2.end());
    EXPECT_EQ(asUser2.at("entry1_data").statusCode, 0) << "the re-key cost a remaining member the oldest entry";
    ASSERT_EQ(asUser2.at("entry1_data").files.size(), 1);
    EXPECT_EQ(
        downloadFile(user2, asUser2.at("entry1_data").files[0].info.fileId, asUser2.at("entry1_data").files[0].size),
        "file1_data"
    ) << "the re-key cost a remaining member the inner Store's contents";
    for (int i = 0; i < ENTRY_COUNT; ++i) {
        const std::string data = "user3_data_" + std::to_string(i);
        const auto found = asUser2.find(data);
        ASSERT_NE(found, asUser2.end()) << "entry " << i << " is gone from the listing";
        ASSERT_EQ(found->second.statusCode, 0) << "the re-key cost a remaining member entry " << i;
    }
    ASSERT_NE(asUser2.find("entry2_data"), asUser2.end());
    EXPECT_EQ(asUser2.at("entry2_data").statusCode, 0);
    ASSERT_NE(asUser2.find("entry3_data"), asUser2.end());
    EXPECT_EQ(asUser2.at("entry3_data").statusCode, 0);

    // ── What user_3 can see now ────────────────────────────────────────────────────────────────────────────
    // The public view needs no key and no membership at all, so it keeps working.
    inbox::InboxPublicView publicView;
    ASSERT_NO_THROW({ publicView = user3.inboxApi->getInboxPublicView(inboxId); });
    EXPECT_EQ(publicView.inboxId, inboxId);
    EXPECT_EQ(publicView.publicMeta.stdString(), "inbox1_public_v2");

    // The Inbox itself is still fetchable under `get: "all"`, but no longer decryptable.
    inbox::Inbox lostInbox;
    ASSERT_NO_THROW({ lostInbox = user3.inboxApi->getInbox(inboxId); });
    EXPECT_NE(lostInbox.statusCode, 0) << "a removed member still decrypts the inbox";
    EXPECT_EQ(lostInbox.publicMeta.stdString(), "inbox1_public_v2")
        << "public metadata is not encrypted and has to survive the loss of the key";
    EXPECT_TRUE(lostInbox.privateMeta.stdString().empty());

    // The entries are refused outright rather than returned undecryptable: they live in the inner Thread, which
    // has no item policy of its own, so a non-grantee is not allowed to read them at all.
    EXPECT_THROW(
        {
            user3.inboxApi->listEntries(
                inboxId,
                core::PagingQuery{
                    .skip = 0,
                    .limit = PAGE_LIMIT,
                    .sortOrder = "asc",
                    .lastId = std::nullopt,
                    .sortBy = std::nullopt,
                    .queryAsJson = std::nullopt
                }
            );
        },
        core::Exception
    ) << "a removed member listed the inbox's entries";
    EXPECT_THROW({ user3.inboxApi->readEntry(entry1Id); }, core::Exception)
        << "a removed member read an inbox entry";

    // ── user_1 deletes everything user_3 submitted, ten at a time ──────────────────────────────────────────
    int deleted = 0;
    for (int pass = 0; pass < ENTRY_COUNT; ++pass) {
        core::PagingList<inbox::InboxEntry> page{};
        ASSERT_NO_THROW({
            page = user1.inboxApi->listEntries(
                inboxId,
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
        bool deletedAny = false;
        for (const auto& entry : page.readItems) {
            if (!isBulkEntry(entry)) {
                continue;
            }
            ASSERT_NO_THROW({ user1.inboxApi->deleteEntry(entry.entryId); });
            ++deleted;
            deletedAny = true;
        }
        if (!deletedAny) {
            break;
        }
    }
    EXPECT_EQ(deleted, ENTRY_COUNT);

    // ── user_2 sees Entry1, Entry2 and Entry3, and nothing else ────────────────────────────────────────────
    auto remaining = listAllEntries(user2, inboxId, PAGE_LIMIT);
    ASSERT_EQ(remaining.size(), 3);
    auto remainingByData = byEntryData(remaining);
    EXPECT_NE(remainingByData.find("entry1_data"), remainingByData.end());
    EXPECT_NE(remainingByData.find("entry2_data"), remainingByData.end());
    EXPECT_NE(remainingByData.find("entry3_data"), remainingByData.end());

    // ── Both watchers were told about all of it ────────────────────────────────────────────────────────────
    pumpUntil(
        [&] {
            return eventsSeen(user1, "inboxEntryDeleted") >= ENTRY_COUNT &&
                eventsSeen(user2, "inboxEntryDeleted") >= ENTRY_COUNT;
        },
        std::chrono::seconds(30)
    );
    for (const auto& watcher : {std::cref(user1), std::cref(user2)}) {
        const Client& client = watcher.get();
        EXPECT_GE(eventsSeen(client, "groupCreated"), 1);
        EXPECT_GE(eventsSeen(client, "groupUpdated"), 1) << "removing a member is a group update";
        EXPECT_GE(eventsSeen(client, "inboxCreated"), 1);
        EXPECT_GE(eventsSeen(client, "inboxUpdated"), 1);
        EXPECT_GE(eventsSeen(client, "inboxEntryCreated"), ENTRY_COUNT + 3);
        EXPECT_GE(eventsSeen(client, "inboxEntryDeleted"), ENTRY_COUNT);
    }
}
