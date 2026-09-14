/**
 * One test per thread event type, each asserting the envelope and the payload that event carries.
 *
 * unsubscribeFrom is one API function, so it is tested once per subscription channel rather than once per
 * event type: the thread channel and the per-thread messages channel are built differently, everything past
 * that is the same call. The seven "_disabled" tests this replaces differed only in which operation they
 * triggered afterwards.
 */
#include "BaseEndpointEventTest.hpp"
#include <privmx/endpoint/thread/ThreadApi.hpp>
#include <privmx/endpoint/thread/Events.hpp>
#include <privmx/endpoint/thread/ThreadException.hpp>
#include <privmx/endpoint/core/CoreException.hpp>
#include <privmx/crypto/Crypto.hpp>
#include <privmx/endpoint/core/VarSerializer.hpp>

using namespace privmx::endpoint;

class ThreadEventTest : public privmx::test::BaseEndpointEventTest {
protected:
    void setUpModuleApis() override {
        threadApi = std::make_shared<thread::ThreadApi>(
            thread::ThreadApi::create(*connection)
        );
    }
    void tearDownModuleApis() override {
        threadApi.reset();
    }

    core::UserWithPubKey user(int index) {
        const std::string n = std::to_string(index);
        return core::UserWithPubKey{
            .userId=reader->getString("Login.user_" + n + "_id"),
            .pubKey=reader->getString("Login.user_" + n + "_pubKey")
        };
    }

    std::vector<core::UserWithPubKey> users(std::initializer_list<int> indexes) {
        std::vector<core::UserWithPubKey> result;
        for(int index : indexes) {
            result.push_back(user(index));
        }
        return result;
    }

    std::string contextId() {
        return reader->getString("Context_1.contextId");
    }

    std::string threadId(int index) {
        return reader->getString("Thread_" + std::to_string(index) + ".threadId");
    }

    std::string messageId(int index) {
        return reader->getString("Message_" + std::to_string(index) + ".info_messageId");
    }

    std::string messagesChannel(int index) {
        return "thread/" + threadId(index) + "/messages";
    }

    std::vector<std::string> subscribe(
        thread::EventType type, thread::EventSelectorType selector, const std::string& selectorId
    ) {
        return threadApi->subscribeFor({threadApi->buildSubscriptionQuery(type, selector, selectorId)});
    }

    // The envelope every thread event shares. Returns the event so the caller can extract its payload, which
    // is why the guards are `if` rather than ASSERT_ - a helper returning a value cannot use those.
    std::shared_ptr<core::Event> expectEvent(const std::string& type, const std::string& channel) {
        auto eventHolder = waitForEvent(type, {connection->getConnectionId()});
        EXPECT_TRUE(eventHolder.has_value());
        if(!eventHolder.has_value()) {
            return nullptr;
        }
        auto event = eventHolder.value().get();
        EXPECT_NE(event, nullptr);
        if(event == nullptr) {
            return nullptr;
        }
        EXPECT_EQ(event->connectionId, connection->getConnectionId());
        EXPECT_EQ(event->type, type);
        EXPECT_EQ(event->channel, channel);
        EXPECT_EQ(event->subscriptions.size(), 1);
        return event;
    }

    void expectMembers(
        const thread::Thread& thread, std::initializer_list<int> userIndexes,
        std::initializer_list<int> managerIndexes
    ) {
        ASSERT_EQ(thread.users.size(), userIndexes.size());
        size_t i = 0;
        for(int index : userIndexes) {
            EXPECT_EQ(thread.users[i++], user(index).userId);
        }
        ASSERT_EQ(thread.managers.size(), managerIndexes.size());
        i = 0;
        for(int index : managerIndexes) {
            EXPECT_EQ(thread.managers[i++], user(index).userId);
        }
    }

    std::shared_ptr<thread::ThreadApi> threadApi;
};

TEST_F(ThreadEventTest, waitEvent_getEvent_threadCreated) {
    eventQueue.waitEvent();
    subscribe(thread::EventType::THREAD_CREATE, thread::EventSelectorType::CONTEXT_ID, contextId());
    threadApi->createThread(
        contextId(), users({1}), users({1}),
        core::Buffer::from("public"), core::Buffer::from("private")
    );
    auto event = expectEvent("threadCreated", "thread");
    ASSERT_NE(event, nullptr);
    ASSERT_TRUE(thread::Events::isThreadCreatedEvent(event));
    thread::Thread thread = thread::Events::extractThreadCreatedEvent(event).data;
    EXPECT_EQ(thread.contextId, contextId());
    EXPECT_EQ(thread.publicMeta.stdString(), "public");
    EXPECT_EQ(thread.privateMeta.stdString(), "private");
    expectMembers(thread, {1}, {1});
}

TEST_F(ThreadEventTest, waitEvent_getEvent_threadUpdated) {
    eventQueue.waitEvent();
    subscribe(thread::EventType::THREAD_UPDATE, thread::EventSelectorType::CONTEXT_ID, contextId());
    threadApi->updateThread(
        threadId(1), users({1}), users({1}),
        core::Buffer::from("public"), core::Buffer::from("private"), 1, true, true
    );
    auto event = expectEvent("threadUpdated", "thread");
    ASSERT_NE(event, nullptr);
    ASSERT_TRUE(thread::Events::isThreadUpdatedEvent(event));
    thread::Thread thread = thread::Events::extractThreadUpdatedEvent(event).data;
    EXPECT_EQ(thread.contextId, contextId());
    EXPECT_EQ(thread.publicMeta.stdString(), "public");
    EXPECT_EQ(thread.privateMeta.stdString(), "private");
    expectMembers(thread, {1}, {1});
}

TEST_F(ThreadEventTest, waitEvent_getEvent_threadDeleted) {
    eventQueue.waitEvent();
    subscribe(thread::EventType::THREAD_DELETE, thread::EventSelectorType::CONTEXT_ID, contextId());
    threadApi->deleteThread(threadId(1));
    auto event = expectEvent("threadDeleted", "thread");
    ASSERT_NE(event, nullptr);
    ASSERT_TRUE(thread::Events::isThreadDeletedEvent(event));
    thread::ThreadDeletedEventData threadDeleted = thread::Events::extractThreadDeletedEvent(event).data;
    EXPECT_EQ(threadDeleted.threadId, threadId(1));
}

TEST_F(ThreadEventTest, waitEvent_getEvent_threadStats) {
    eventQueue.waitEvent();
    subscribe(thread::EventType::THREAD_STATS, thread::EventSelectorType::CONTEXT_ID, contextId());
    threadApi->deleteMessage(messageId(1));
    auto event = expectEvent("threadStatsChanged", "thread");
    ASSERT_NE(event, nullptr);
    ASSERT_TRUE(thread::Events::isThreadStatsEvent(event));
    thread::ThreadStatsEventData threadStat = thread::Events::extractThreadStatsEvent(event).data;
    EXPECT_EQ(threadStat.threadId, threadId(1));
    EXPECT_EQ(threadStat.messagesCount, 1);
}

TEST_F(ThreadEventTest, waitEvent_getEvent_threadNewMessage) {
    eventQueue.waitEvent();
    subscribe(thread::EventType::MESSAGE_CREATE, thread::EventSelectorType::THREAD_ID, threadId(1));
    threadApi->sendMessage(
        threadId(1), core::Buffer::from("publicMeta"), core::Buffer::from("privateMeta"),
        core::Buffer::from("data")
    );
    auto event = expectEvent("threadNewMessage", messagesChannel(1));
    ASSERT_NE(event, nullptr);
    ASSERT_TRUE(thread::Events::isThreadNewMessageEvent(event));
    thread::Message message = thread::Events::extractThreadNewMessageEvent(event).data;
    EXPECT_EQ(message.publicMeta.stdString(), "publicMeta");
    EXPECT_EQ(message.privateMeta.stdString(), "privateMeta");
    EXPECT_EQ(message.data.stdString(), "data");
    EXPECT_EQ(message.info.threadId, threadId(1));
}

TEST_F(ThreadEventTest, waitEvent_getEvent_threadUpdatedMessage) {
    eventQueue.waitEvent();
    subscribe(thread::EventType::MESSAGE_UPDATE, thread::EventSelectorType::THREAD_ID, threadId(1));
    threadApi->updateMessage(
        messageId(1), core::Buffer::from("publicMeta"), core::Buffer::from("privateMeta"),
        core::Buffer::from("data")
    );
    auto event = expectEvent("threadUpdatedMessage", messagesChannel(1));
    ASSERT_NE(event, nullptr);
    ASSERT_TRUE(thread::Events::isThreadMessageUpdatedEvent(event));
    thread::Message message = thread::Events::extractThreadMessageUpdatedEvent(event).data;
    EXPECT_EQ(message.info.messageId, messageId(1));
    EXPECT_EQ(message.publicMeta.stdString(), "publicMeta");
    EXPECT_EQ(message.privateMeta.stdString(), "privateMeta");
    EXPECT_EQ(message.data.stdString(), "data");
    EXPECT_EQ(message.info.threadId, threadId(1));
}

TEST_F(ThreadEventTest, waitEvent_getEvent_threadDeletedMessage) {
    eventQueue.waitEvent();
    subscribe(thread::EventType::MESSAGE_DELETE, thread::EventSelectorType::THREAD_ID, threadId(1));
    threadApi->deleteMessage(messageId(1));
    auto event = expectEvent("threadMessageDeleted", messagesChannel(1));
    ASSERT_NE(event, nullptr);
    ASSERT_TRUE(thread::Events::isThreadMessageDeletedEvent(event));
    thread::ThreadDeletedMessageEventData deleted = thread::Events::extractThreadMessageDeletedEvent(event).data;
    EXPECT_EQ(deleted.messageId, messageId(1));
    EXPECT_EQ(deleted.threadId, threadId(1));
}

TEST_F(ThreadEventTest, unsubscribeFrom_silences_the_thread_channel) {
    eventQueue.waitEvent();
    auto ids = subscribe(thread::EventType::THREAD_CREATE, thread::EventSelectorType::CONTEXT_ID, contextId());
    threadApi->unsubscribeFrom(ids);
    threadApi->createThread(
        contextId(), users({1}), users({1}),
        core::Buffer::from("public"), core::Buffer::from("private")
    );
    assertNoEventReceived();
}

TEST_F(ThreadEventTest, unsubscribeFrom_silences_the_messages_channel) {
    eventQueue.waitEvent();
    auto ids = subscribe(thread::EventType::MESSAGE_CREATE, thread::EventSelectorType::THREAD_ID, threadId(1));
    threadApi->unsubscribeFrom(ids);
    threadApi->sendMessage(
        threadId(1), core::Buffer::from("publicMeta"), core::Buffer::from("privateMeta"),
        core::Buffer::from("data")
    );
    assertNoEventReceived();
}

TEST_F(ThreadEventTest, subscribeFor_query_from_other_module) {
    EXPECT_THROW({
        threadApi->subscribeFor({"treads/update|contextId=" + contextId()});
    }, core::InvalidSubscriptionQueryException);
    EXPECT_THROW({
        threadApi->subscribeFor({"store/update|contextId=" + contextId()});
    }, core::InvalidSubscriptionQueryException);
}

TEST_F(ThreadEventTest, subscribeFor_unsubscribeFor) {
    std::vector<std::string> valid_subscriptions;
    EXPECT_NO_THROW({
        valid_subscriptions =
            subscribe(thread::EventType::THREAD_CREATE, thread::EventSelectorType::CONTEXT_ID, contextId());
    });
    std::vector<std::string> invalid_subscriptions;
    EXPECT_NO_THROW({
        invalid_subscriptions =
            subscribe(thread::EventType::THREAD_CREATE, thread::EventSelectorType::CONTEXT_ID, "error");
    });
    EXPECT_NO_THROW({ threadApi->unsubscribeFrom(valid_subscriptions); });
    EXPECT_NO_THROW({ threadApi->unsubscribeFrom(invalid_subscriptions); });
}
