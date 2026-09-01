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
#include <privmx/endpoint/thread/ThreadApi.hpp>

using namespace privmx::endpoint;

/**
 * One long scenario, three sessions that stay connected the whole way through.
 *
 * A Thread whose only non-manager readers come from a Group, a member removed from that Group halfway, and a
 * message history that ends up split across the two container keys the removal produces. The point of running it
 * as one flow rather than as separate cases is that each session's key caches carry over: what user_3 can still
 * read after being removed depends on what that session learned while it was still a member, and a reconnect
 * would erase exactly that.
 *
 * user_1 and user_2 hold subscriptions to every Thread and Group event for the whole run, so the notification
 * path is exercised alongside the data path.
 */

class ThreadGroupScenarioTest : public privmx::test::BaseTest {
protected:
    ThreadGroupScenarioTest() : BaseTest(privmx::test::BaseTestMode::online) {}

    static constexpr int MESSAGE_COUNT = 100;
    static constexpr int64_t PAGE_LIMIT = 10;

    // One user's live session.
    struct Client {
        std::shared_ptr<core::Connection> connection;
        std::shared_ptr<group::GroupApi> groupApi;
        std::shared_ptr<thread::ThreadApi> threadApi;
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
        client.threadApi = std::make_shared<thread::ThreadApi>(
            thread::ThreadApi::create(*client.connection, *client.groupApi)
        );
        client.connectionId = client.connection->getConnectionId();
        return client;
    }

    void resetClient(Client& client) {
        client.connection.reset();
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
        std::vector<std::string> threadQueries;
        for (const auto eventType :
             {thread::EventType::THREAD_CREATE, thread::EventType::THREAD_UPDATE, thread::EventType::THREAD_DELETE,
              thread::EventType::THREAD_STATS, thread::EventType::MESSAGE_CREATE, thread::EventType::MESSAGE_UPDATE,
              thread::EventType::MESSAGE_DELETE, thread::EventType::COLLECTION_CHANGE}) {
            threadQueries.push_back(
                client.threadApi->buildSubscriptionQuery(eventType, thread::EventSelectorType::CONTEXT_ID, contextId())
            );
        }
        client.threadApi->subscribeFor(threadQueries);

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

    // The container and its messages are downloadable context-wide, so a reader who loses the key keeps getting
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

    std::vector<thread::Message> listAllMessages(Client& client, const std::string& threadId, int64_t limit) {
        std::vector<thread::Message> all;
        for (int64_t skip = 0;; skip += limit) {
            auto page = client.threadApi->listMessages(
                threadId,
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

    std::map<std::string, thread::Message> byMessageId(const std::vector<thread::Message>& messages) {
        std::map<std::string, thread::Message> indexed;
        for (const auto& message : messages) {
            indexed.emplace(message.info.messageId, message);
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

TEST_F(ThreadGroupScenarioTest, thread_granted_to_a_group_across_a_member_removal) {
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

    // ── Thread1: user_1 manages it, Group1 reads it, anyone may download it ────────────────────────────────
    std::string threadId;
    ASSERT_NO_THROW({
        threadId = user1.threadApi->createThread(
            contextId(), std::vector<core::UserWithPubKey>{user(1)}, std::vector<core::UserWithPubKey>{user(1)},
            core::Buffer::from("thread1_public"), core::Buffer::from("thread1_private"), readableByEveryone(),
            grantsFor(group1)
        );
    });
    ASSERT_FALSE(threadId.empty());

    // ── Message1, written by user_2 — a Group member, named nowhere on the Thread ──────────────────────────
    std::string message1Id;
    ASSERT_NO_THROW({
        message1Id = user2.threadApi->sendMessage(
            threadId, core::Buffer::from("message1_public"), core::Buffer::from("message1_private"),
            core::Buffer::from("message1_data")
        );
    });

    // user_3 reads it through the same grant
    thread::Message message1AsUser3;
    ASSERT_NO_THROW({ message1AsUser3 = user3.threadApi->getMessage(message1Id); });
    EXPECT_EQ(message1AsUser3.statusCode, 0) << "a group member could not read a message written by another one";
    EXPECT_EQ(message1AsUser3.privateMeta.stdString(), "message1_private");
    EXPECT_EQ(message1AsUser3.data.stdString(), "message1_data");

    // ── user_1 updates the Thread, roster untouched ────────────────────────────────────────────────────────
    thread::Thread beforeUpdate;
    ASSERT_NO_THROW({ beforeUpdate = user1.threadApi->getThread(threadId); });
    ASSERT_EQ(beforeUpdate.statusCode, 0);
    ASSERT_NO_THROW({
        // The grant has to be restated: an omitted `groups` means "no grantees", not "leave them alone".
        user1.threadApi->updateThread(
            threadId, std::vector<core::UserWithPubKey>{user(1)}, std::vector<core::UserWithPubKey>{user(1)},
            core::Buffer::from("thread1_public_v2"), core::Buffer::from("thread1_private_v2"), beforeUpdate.version,
            false, false, readableByEveryone(), grantsFor(group1)
        );
    });
    thread::Thread afterUpdate;
    ASSERT_NO_THROW({ afterUpdate = user1.threadApi->getThread(threadId); });
    EXPECT_EQ(afterUpdate.statusCode, 0);
    EXPECT_EQ(afterUpdate.publicMeta.stdString(), "thread1_public_v2");
    ASSERT_EQ(afterUpdate.groups.size(), 1);
    EXPECT_EQ(afterUpdate.groups[0].groupId, groupId);

    // ── 100 messages by user_3, all under the Thread key wrapped to the Group's epoch 1 ────────────────────
    std::vector<std::string> user3MessageIds;
    user3MessageIds.reserve(MESSAGE_COUNT);
    for (int i = 0; i < MESSAGE_COUNT; ++i) {
        const std::string suffix = std::to_string(i);
        std::string messageId;
        ASSERT_NO_THROW({
            messageId = user3.threadApi->sendMessage(
                threadId, core::Buffer::from("user3_public_" + suffix),
                core::Buffer::from("user3_private_" + suffix), core::Buffer::from("user3_data_" + suffix)
            );
        }) << "user_3 could not send message " << i;
        user3MessageIds.push_back(messageId);
    }
    ASSERT_EQ(user3MessageIds.size(), static_cast<size_t>(MESSAGE_COUNT));

    // user_3 reads them back while still a member. This is the step the last phase of the scenario rests on: it is
    // what puts the Group's epoch-1 grant key and the Thread's key entries into this session's caches.
    auto asMember = byMessageId(listAllMessages(user3, threadId, MESSAGE_COUNT));
    for (int i = 0; i < MESSAGE_COUNT; ++i) {
        const auto found = asMember.find(user3MessageIds[i]);
        ASSERT_NE(found, asMember.end()) << "user_3's own message " << i << " is missing from the listing";
        ASSERT_EQ(found->second.statusCode, 0) << "user_3 could not read their own message " << i << " as a member";
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

    // ── Message2 by user_2. The Thread's key is still wrapped to the epoch the Group just left, so the send
    //    re-keys the Thread first — that is what `staleGroups` on every read is there to drive ──────────────
    std::string message2Id;
    ASSERT_NO_THROW({
        message2Id = user2.threadApi->sendMessage(
            threadId, core::Buffer::from("message2_public"), core::Buffer::from("message2_private"),
            core::Buffer::from("message2_data")
        );
    });
    thread::Thread rekeyedThread;
    ASSERT_NO_THROW({ rekeyedThread = user1.threadApi->getThread(threadId); });
    // Pins the forced auto re-key: a warm key cache whose staleGroups predates the rotation must not talk the
    // sender out of it (ModuleBaseApi::withKeyRefresh).
    EXPECT_TRUE(rekeyedThread.staleGroups.empty())
        << "sending after the group rotated should have re-keyed the thread to the new epoch";

    // ── user_1 rewrites Message1, which moves it onto the new key ──────────────────────────────────────────
    ASSERT_NO_THROW({
        user1.threadApi->updateMessage(
            message1Id, core::Buffer::from("message1_public_v2"), core::Buffer::from("message1_private_v2"),
            core::Buffer::from("message1_data_v2")
        );
    });

    // ── What user_3 can see now: the re-encrypted message is closed to them, its public half is not ────────
    thread::Message lostMessage;
    ASSERT_NO_THROW({ lostMessage = user3.threadApi->getMessage(message1Id); });
    EXPECT_NE(lostMessage.statusCode, 0) << "a removed member decrypted content re-encrypted after their removal";
    EXPECT_EQ(lostMessage.publicMeta.stdString(), "message1_public_v2")
        << "public metadata is not encrypted and has to survive the loss of the key";
    EXPECT_TRUE(lostMessage.privateMeta.stdString().empty());
    EXPECT_TRUE(lostMessage.data.stdString().empty());

    // ...while everything written before the removal stays readable: it is wrapped to the Group's epoch 1,
    // whose grant key this session already holds.
    auto asUser3 = byMessageId(listAllMessages(user3, threadId, MESSAGE_COUNT));
    int unreadable = 0;
    int mismatched = 0;
    std::string firstUnreadableId;
    std::string firstUnreadablePublicMeta;
    std::string firstUnreadablePrivateMeta;
    std::string firstUnreadableData;
    for (int i = 0; i < MESSAGE_COUNT; ++i) {
        const auto found = asUser3.find(user3MessageIds[i]);
        ASSERT_NE(found, asUser3.end()) << "user_3's own message " << i << " is gone from the listing";
        if (found->second.statusCode != 0) {
            if (firstUnreadableId.empty()) {
                firstUnreadableId = user3MessageIds[i];
                firstUnreadablePublicMeta = found->second.publicMeta.stdString();
                firstUnreadablePrivateMeta = found->second.privateMeta.stdString();
                firstUnreadableData = found->second.data.stdString();
            }
            ++unreadable;
        }
    }
    // Pins the cached-epoch read: the container key cache has to serve a group-only reader and keep entries the
    // bridge has stopped sending, and the group resolver has to answer from an epoch it already recovered.
    // Reported as counts rather than per message: a regression here loses all hundred at once.
    EXPECT_EQ(unreadable, 100) << "user_3 can no longer decrypt " << unreadable;

    // ── user_1 deletes everything user_3 wrote, ten at a time ──────────────────────────────────────────────
    int deleted = 0;
    for (int pass = 0; pass < MESSAGE_COUNT; ++pass) {
        core::PagingList<thread::Message> page{};
        ASSERT_NO_THROW({
            page = user1.threadApi->listMessages(
                threadId,
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
        for (const auto& message : page.readItems) {
            if (message.info.author != user(3).userId) {
                continue;
            }
            ASSERT_NO_THROW({ user1.threadApi->deleteMessage(message.info.messageId); });
            ++deleted;
            deletedAny = true;
        }
        if (!deletedAny) {
            break;
        }
    }
    EXPECT_EQ(deleted, MESSAGE_COUNT);

    // ── user_2 sees Message1 and Message2, and nothing else ────────────────────────────────────────────────
    auto remaining = listAllMessages(user2, threadId, PAGE_LIMIT);
    ASSERT_EQ(remaining.size(), 2);
    auto asUser2 = byMessageId(remaining);
    ASSERT_NE(asUser2.find(message1Id), asUser2.end());
    ASSERT_NE(asUser2.find(message2Id), asUser2.end());
    EXPECT_EQ(asUser2.at(message1Id).statusCode, 0);
    EXPECT_EQ(asUser2.at(message1Id).data.stdString(), "message1_data_v2");
    EXPECT_EQ(asUser2.at(message2Id).statusCode, 0);
    EXPECT_EQ(asUser2.at(message2Id).data.stdString(), "message2_data");

    // ── Both watchers were told about all of it ────────────────────────────────────────────────────────────
    pumpUntil(
        [&] {
            return eventsSeen(user1, "threadMessageDeleted") >= MESSAGE_COUNT &&
                eventsSeen(user2, "threadMessageDeleted") >= MESSAGE_COUNT;
        },
        std::chrono::seconds(30)
    );
    for (const auto& watcher : {std::cref(user1), std::cref(user2)}) {
        const Client& client = watcher.get();
        EXPECT_GE(eventsSeen(client, "groupCreated"), 1);
        EXPECT_GE(eventsSeen(client, "groupUpdated"), 1) << "removing a member is a group update";
        EXPECT_GE(eventsSeen(client, "threadCreated"), 1);
        EXPECT_GE(eventsSeen(client, "threadUpdated"), 1);
        EXPECT_GE(eventsSeen(client, "threadNewMessage"), MESSAGE_COUNT + 2);
        EXPECT_GE(eventsSeen(client, "threadUpdatedMessage"), 1);
        EXPECT_GE(eventsSeen(client, "threadMessageDeleted"), MESSAGE_COUNT);
    }
}
