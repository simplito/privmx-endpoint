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
#include <privmx/endpoint/store/StoreApi.hpp>

using namespace privmx::endpoint;

/**
 * One long scenario, three sessions that stay connected the whole way through.
 *
 * A Store whose only non-manager readers come from a Group, a member removed from that Group halfway, and a set
 * of files that ends up split across the two container keys the removal produces. The point of running it as one
 * flow rather than as separate cases is that each session's key caches carry over: what user_3 can still read
 * after being removed depends on what that session learned while it was still a member, and a reconnect would
 * erase exactly that.
 *
 * The file half is what this adds over the Thread scenario. A file's bytes are encrypted under a key of their
 * own, and that key lives in the file's internal meta, wrapped to the Store key — so losing the Store key costs
 * a reader the metadata and the content in one step, through two different code paths (getFile decrypts the
 * meta and reports a status, openFile needs the internal meta and throws).
 *
 * user_1 and user_2 hold subscriptions to every Store and Group event for the whole run, so the notification
 * path is exercised alongside the data path.
 */

class StoreGroupScenarioTest : public privmx::test::BaseTest {
protected:
    StoreGroupScenarioTest() : BaseTest(privmx::test::BaseTestMode::online) {}

    // Lower than the Thread scenario's message count on purpose: one upload is createFile + writeToFile +
    // closeFile, so a hundred of them would dominate the suite's runtime without pinning anything more.
    static constexpr int FILE_COUNT = 25;
    static constexpr int64_t PAGE_LIMIT = 10;

    // One user's live session.
    struct Client {
        std::shared_ptr<core::Connection> connection;
        std::shared_ptr<group::GroupApi> groupApi;
        std::shared_ptr<store::StoreApi> storeApi;
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
        client.storeApi = std::make_shared<store::StoreApi>(
            store::StoreApi::create(*client.connection, *client.groupApi)
        );
        client.connectionId = client.connection->getConnectionId();
        return client;
    }

    void resetClient(Client& client) {
        client.connection.reset();
        client.storeApi.reset();
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
        std::vector<std::string> storeQueries;
        for (const auto eventType :
             {store::EventType::STORE_CREATE, store::EventType::STORE_UPDATE, store::EventType::STORE_DELETE,
              store::EventType::STORE_STATS, store::EventType::FILE_CREATE, store::EventType::FILE_UPDATE,
              store::EventType::FILE_DELETE, store::EventType::COLLECTION_CHANGE}) {
            storeQueries.push_back(
                client.storeApi->buildSubscriptionQuery(eventType, store::EventSelectorType::CONTEXT_ID, contextId())
            );
        }
        client.storeApi->subscribeFor(storeQueries);

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

    // The container and its files are downloadable context-wide, so a reader who loses the key keeps getting
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

    // Uploads one file in a single write and returns its id.
    std::string uploadFile(
        Client& client,
        const std::string& storeId,
        const std::string& publicMeta,
        const std::string& privateMeta,
        const std::string& data
    ) {
        int64_t handle = client.storeApi->createFile(
            storeId, core::Buffer::from(publicMeta), core::Buffer::from(privateMeta), (int64_t)data.size()
        );
        client.storeApi->writeToFile(handle, core::Buffer::from(data));
        return client.storeApi->closeFile(handle);
    }

    // Rewrites an existing file whole, which is what moves both its meta and its bytes onto the current key.
    void rewriteFile(
        Client& client,
        const std::string& fileId,
        const std::string& publicMeta,
        const std::string& privateMeta,
        const std::string& data
    ) {
        int64_t handle = client.storeApi->updateFile(
            fileId, core::Buffer::from(publicMeta), core::Buffer::from(privateMeta), (int64_t)data.size()
        );
        client.storeApi->writeToFile(handle, core::Buffer::from(data));
        client.storeApi->closeFile(handle);
    }

    std::string downloadFile(Client& client, const std::string& fileId, int64_t size) {
        int64_t handle = client.storeApi->openFile(fileId);
        auto data = client.storeApi->readFromFile(handle, size).stdString();
        client.storeApi->closeFile(handle);
        return data;
    }

    std::vector<store::File> listAllFiles(Client& client, const std::string& storeId, int64_t limit) {
        std::vector<store::File> all;
        for (int64_t skip = 0;; skip += limit) {
            auto page = client.storeApi->listFiles(
                storeId,
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

    std::map<std::string, store::File> byFileId(const std::vector<store::File>& files) {
        std::map<std::string, store::File> indexed;
        for (const auto& file : files) {
            indexed.emplace(file.info.fileId, file);
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

TEST_F(StoreGroupScenarioTest, store_granted_to_a_group_across_a_member_removal) {
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

    // ── Store1: user_1 manages it, Group1 reads it, anyone may download it ─────────────────────────────────
    std::string storeId;
    ASSERT_NO_THROW({
        storeId = user1.storeApi->createStore(
            contextId(), std::vector<core::UserWithPubKey>{user(1)}, std::vector<core::UserWithPubKey>{user(1)},
            core::Buffer::from("store1_public"), core::Buffer::from("store1_private"), readableByEveryone(),
            grantsFor(group1)
        );
    });
    ASSERT_FALSE(storeId.empty());

    // ── File1, uploaded by user_2 — a Group member, named nowhere on the Store ─────────────────────────────
    std::string file1Id;
    ASSERT_NO_THROW({
        file1Id = uploadFile(user2, storeId, "file1_public", "file1_private", "file1_data");
    });
    ASSERT_FALSE(file1Id.empty());

    // user_3 reads it through the same grant, metadata and bytes both
    store::File file1AsUser3;
    ASSERT_NO_THROW({ file1AsUser3 = user3.storeApi->getFile(file1Id); });
    EXPECT_EQ(file1AsUser3.statusCode, 0) << "a group member could not read a file uploaded by another one";
    EXPECT_EQ(file1AsUser3.privateMeta.stdString(), "file1_private");
    std::string file1DataAsUser3;
    ASSERT_NO_THROW({ file1DataAsUser3 = downloadFile(user3, file1Id, file1AsUser3.size); });
    EXPECT_EQ(file1DataAsUser3, "file1_data");

    // ── user_1 updates the Store, roster untouched ─────────────────────────────────────────────────────────
    store::Store beforeUpdate;
    ASSERT_NO_THROW({ beforeUpdate = user1.storeApi->getStore(storeId); });
    ASSERT_EQ(beforeUpdate.statusCode, 0);
    ASSERT_NO_THROW({
        // The grant has to be restated: an omitted `groups` means "no grantees", not "leave them alone".
        user1.storeApi->updateStore(
            storeId, std::vector<core::UserWithPubKey>{user(1)}, std::vector<core::UserWithPubKey>{user(1)},
            core::Buffer::from("store1_public_v2"), core::Buffer::from("store1_private_v2"), beforeUpdate.version,
            false, false, readableByEveryone(), grantsFor(group1)
        );
    });
    store::Store afterUpdate;
    ASSERT_NO_THROW({ afterUpdate = user1.storeApi->getStore(storeId); });
    EXPECT_EQ(afterUpdate.statusCode, 0);
    EXPECT_EQ(afterUpdate.publicMeta.stdString(), "store1_public_v2");
    ASSERT_EQ(afterUpdate.groups.size(), 1);
    EXPECT_EQ(afterUpdate.groups[0].groupId, groupId);

    // ── FILE_COUNT files by user_3, all under the Store key wrapped to the Group's epoch 1 ─────────────────
    std::vector<std::string> user3FileIds;
    user3FileIds.reserve(FILE_COUNT);
    for (int i = 0; i < FILE_COUNT; ++i) {
        const std::string suffix = std::to_string(i);
        std::string fileId;
        ASSERT_NO_THROW({
            fileId = uploadFile(
                user3, storeId, "user3_public_" + suffix, "user3_private_" + suffix, "user3_data_" + suffix
            );
        }) << "user_3 could not upload file " << i;
        user3FileIds.push_back(fileId);
    }
    ASSERT_EQ(user3FileIds.size(), static_cast<size_t>(FILE_COUNT));

    // user_3 reads them back while still a member. This is the step the last phase of the scenario rests on: it is
    // what puts the Group's epoch-1 grant key and the Store's key entries into this session's caches.
    auto asMember = byFileId(listAllFiles(user3, storeId, FILE_COUNT));
    for (int i = 0; i < FILE_COUNT; ++i) {
        const auto found = asMember.find(user3FileIds[i]);
        ASSERT_NE(found, asMember.end()) << "user_3's own file " << i << " is missing from the listing";
        ASSERT_EQ(found->second.statusCode, 0) << "user_3 could not read their own file " << i << " as a member";
    }
    // One full download to prove the caches cover the bytes too, not just the metadata.
    std::string firstDataAsMember;
    ASSERT_NO_THROW({
        firstDataAsMember = downloadFile(user3, user3FileIds[0], asMember.at(user3FileIds[0]).size);
    });
    EXPECT_EQ(firstDataAsMember, "user3_data_0");
    pumpEvents();

    // ── user_3 leaves Group1: the Group's epoch moves 1 → 2 ────────────────────────────────────────────────
    ASSERT_NO_THROW({
        user1.groupApi->removeGroupMembers(groupId, {user(3).userId});
    });
    group::Group rotatedGroup;
    ASSERT_NO_THROW({ rotatedGroup = user1.groupApi->getGroup(groupId); });
    ASSERT_EQ(rotatedGroup.keyVersion, 2);

    // ── File2 by user_2. The Store's key is still wrapped to the epoch the Group just left, so the upload
    //    re-keys the Store first — that is what `staleGroups` on every read is there to drive ──────────────
    std::string file2Id;
    ASSERT_NO_THROW({ file2Id = uploadFile(user2, storeId, "file2_public", "file2_private", "file2_data"); });
    store::Store rekeyedStore;
    ASSERT_NO_THROW({ rekeyedStore = user1.storeApi->getStore(storeId); });
    // Pins the forced auto re-key: a warm key cache whose staleGroups predates the rotation must not talk the
    // uploader out of it (ModuleBaseApi::withKeyRefresh, reached from closeFile).
    EXPECT_TRUE(rekeyedStore.staleGroups.empty())
        << "uploading after the group rotated should have re-keyed the store to the new epoch";

    // ── user_1 rewrites File1, which moves it onto the new key ─────────────────────────────────────────────
    ASSERT_NO_THROW({ rewriteFile(user1, file1Id, "file1_public_v2", "file1_private_v2", "file1_data_v2"); });

    // ── What user_3 can see now: the re-encrypted file is closed to them, its public half is not ───────────
    store::File lostFile;
    ASSERT_NO_THROW({ lostFile = user3.storeApi->getFile(file1Id); });
    EXPECT_NE(lostFile.statusCode, 0) << "a removed member decrypted a file re-encrypted after their removal";
    EXPECT_EQ(lostFile.publicMeta.stdString(), "file1_public_v2")
        << "public metadata is not encrypted and has to survive the loss of the key";
    EXPECT_TRUE(lostFile.privateMeta.stdString().empty());
    // The bytes go with it: the data key lives in the internal meta, which is wrapped to the Store key, so the
    // read handle cannot even be opened.
    EXPECT_THROW({ user3.storeApi->openFile(file1Id); }, core::Exception)
        << "a removed member opened a read handle on a file re-encrypted after their removal";

    // ...and so is everything user_3 wrote before the removal, even though those files were encrypted under the
    // Store key of the Group's epoch 1 and this session read them all while it still held that grant. The next
    // read after the re-key replaces the whole cache entry (ContainerKeyCache::set does insert_or_assign, not a
    // merge), and the group key resolver has no group left to recover epoch 1 from. Same expectation as
    // ThreadGroupScenarioTest.
    auto asUser3 = byFileId(listAllFiles(user3, storeId, FILE_COUNT));
    int unreadable = 0;
    for (int i = 0; i < FILE_COUNT; ++i) {
        const auto found = asUser3.find(user3FileIds[i]);
        ASSERT_NE(found, asUser3.end()) << "user_3's own file " << i << " is gone from the listing";
        if (found->second.statusCode != 0) {
            ++unreadable;
        }
    }
    // Reported as a count rather than per file: a regression here moves all of them at once.
    EXPECT_EQ(unreadable, FILE_COUNT) << "user_3 can still decrypt " << (FILE_COUNT - unreadable)
                                      << " of their own pre-removal files";
    // The listing still names them and their public halves survive — only the encrypted halves are gone.
    EXPECT_EQ(asUser3.at(user3FileIds[0]).publicMeta.stdString(), "user3_public_0");
    EXPECT_TRUE(asUser3.at(user3FileIds[0]).privateMeta.stdString().empty());
    EXPECT_THROW({ user3.storeApi->openFile(user3FileIds[0]); }, core::Exception)
        << "the bytes of a pre-removal file are still readable to the removed member";

    // ── user_1 deletes everything user_3 uploaded, ten at a time ───────────────────────────────────────────
    int deleted = 0;
    for (int pass = 0; pass < FILE_COUNT; ++pass) {
        core::PagingList<store::File> page{};
        ASSERT_NO_THROW({
            page = user1.storeApi->listFiles(
                storeId,
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
        for (const auto& file : page.readItems) {
            if (file.info.author != user(3).userId) {
                continue;
            }
            ASSERT_NO_THROW({ user1.storeApi->deleteFile(file.info.fileId); });
            ++deleted;
            deletedAny = true;
        }
        if (!deletedAny) {
            break;
        }
    }
    EXPECT_EQ(deleted, FILE_COUNT);

    // ── user_2 sees File1 and File2, and nothing else ──────────────────────────────────────────────────────
    auto remaining = listAllFiles(user2, storeId, PAGE_LIMIT);
    ASSERT_EQ(remaining.size(), 2);
    auto asUser2 = byFileId(remaining);
    ASSERT_NE(asUser2.find(file1Id), asUser2.end());
    ASSERT_NE(asUser2.find(file2Id), asUser2.end());
    EXPECT_EQ(asUser2.at(file1Id).statusCode, 0);
    EXPECT_EQ(asUser2.at(file1Id).privateMeta.stdString(), "file1_private_v2");
    EXPECT_EQ(downloadFile(user2, file1Id, asUser2.at(file1Id).size), "file1_data_v2");
    EXPECT_EQ(asUser2.at(file2Id).statusCode, 0);
    EXPECT_EQ(downloadFile(user2, file2Id, asUser2.at(file2Id).size), "file2_data");

    // ── Both watchers were told about all of it ────────────────────────────────────────────────────────────
    pumpUntil(
        [&] {
            return eventsSeen(user1, "storeFileDeleted") >= FILE_COUNT &&
                eventsSeen(user2, "storeFileDeleted") >= FILE_COUNT;
        },
        std::chrono::seconds(30)
    );
    for (const auto& watcher : {std::cref(user1), std::cref(user2)}) {
        const Client& client = watcher.get();
        EXPECT_GE(eventsSeen(client, "groupCreated"), 1);
        EXPECT_GE(eventsSeen(client, "groupUpdated"), 1) << "removing a member is a group update";
        EXPECT_GE(eventsSeen(client, "storeCreated"), 1);
        EXPECT_GE(eventsSeen(client, "storeUpdated"), 1);
        EXPECT_GE(eventsSeen(client, "storeFileCreated"), FILE_COUNT + 2);
        EXPECT_GE(eventsSeen(client, "storeFileUpdated"), 1);
        EXPECT_GE(eventsSeen(client, "storeFileDeleted"), FILE_COUNT);
    }
}
