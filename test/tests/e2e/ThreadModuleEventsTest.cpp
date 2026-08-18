
#include "../../utils/BaseEndpointEventTest.hpp"
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
    std::shared_ptr<thread::ThreadApi> threadApi;
};

TEST_F(ThreadEventTest, waitEvent_getEvent_threadCreated_enabled) {
    eventQueue.waitEvent();
    threadApi->subscribeFor({
        threadApi->buildSubscriptionQuery(
            thread::EventType::THREAD_CREATE,
            thread::EventSelectorType::CONTEXT_ID,
            reader->getString("Context_1.contextId")
        )
    });
    threadApi->createThread(
        reader->getString("Context_1.contextId"),
        std::vector<core::UserWithPubKey>{core::UserWithPubKey{
            .userId=reader->getString("Login.user_1_id"),
            .pubKey=reader->getString("Login.user_1_pubKey")
        }},
        std::vector<core::UserWithPubKey>{core::UserWithPubKey{
            .userId=reader->getString("Login.user_1_id"),
            .pubKey=reader->getString("Login.user_1_pubKey")
        }},
        core::Buffer::from("public"),
        core::Buffer::from("private")
    );
    auto eventHolder = waitForEvent("threadCreated", {connection->getConnectionId()});
    ASSERT_TRUE(eventHolder.has_value());
    auto event = eventHolder.value().get();
    ASSERT_NE(event, nullptr);
    EXPECT_EQ(event->connectionId, connection->getConnectionId());
    EXPECT_EQ(event->type, "threadCreated");
    EXPECT_EQ(event->channel, "thread");
    ASSERT_TRUE(thread::Events::isThreadCreatedEvent(event));
    EXPECT_EQ(event->subscriptions.size(), 1);
    thread::Thread thread = thread::Events::extractThreadCreatedEvent(event).data;
    EXPECT_EQ(thread.contextId, reader->getString("Context_1.contextId"));
    EXPECT_EQ(thread.publicMeta.stdString(), "public");
    EXPECT_EQ(thread.privateMeta.stdString(), "private");
    EXPECT_EQ(thread.users.size(), 1);
    if(thread.users.size() == 1) {
        EXPECT_EQ(thread.users[0], reader->getString("Login.user_1_id"));
    }
    EXPECT_EQ(thread.managers.size(), 1);
    if(thread.managers.size() == 1) {
        EXPECT_EQ(thread.managers[0], reader->getString("Login.user_1_id"));
    }
}

TEST_F(ThreadEventTest, waitEvent_getEvent_threadCreated_disabled) {
    eventQueue.waitEvent();
    auto tmp = threadApi->subscribeFor({
        threadApi->buildSubscriptionQuery(
            thread::EventType::THREAD_CREATE,
            thread::EventSelectorType::CONTEXT_ID,
            reader->getString("Context_1.contextId")
        )
    });
    threadApi->unsubscribeFrom(tmp);
    threadApi->createThread(
        reader->getString("Context_1.contextId"),
        std::vector<core::UserWithPubKey>{core::UserWithPubKey{
            .userId=reader->getString("Login.user_1_id"),
            .pubKey=reader->getString("Login.user_1_pubKey")
        }},
        std::vector<core::UserWithPubKey>{core::UserWithPubKey{
            .userId=reader->getString("Login.user_1_id"),
            .pubKey=reader->getString("Login.user_1_pubKey")
        }},
        core::Buffer::from("public"),
        core::Buffer::from("private")
    );
    assertNoEventReceived();
}

TEST_F(ThreadEventTest, waitEvent_getEvent_threadUpdated_enabled) {
    eventQueue.waitEvent();
    threadApi->subscribeFor({
        threadApi->buildSubscriptionQuery(
            thread::EventType::THREAD_UPDATE,
            thread::EventSelectorType::CONTEXT_ID,
            reader->getString("Context_1.contextId")
        )
    });
    threadApi->updateThread(
        reader->getString("Thread_1.threadId"),
        std::vector<core::UserWithPubKey>{core::UserWithPubKey{
            .userId=reader->getString("Login.user_1_id"),
            .pubKey=reader->getString("Login.user_1_pubKey")
        }},
        std::vector<core::UserWithPubKey>{core::UserWithPubKey{
            .userId=reader->getString("Login.user_1_id"),
            .pubKey=reader->getString("Login.user_1_pubKey")
        }},
        core::Buffer::from("public"),
        core::Buffer::from("private"),
        1,
        true,
        true
    );
    auto eventHolder = waitForEvent("threadUpdated", {connection->getConnectionId()});
    ASSERT_TRUE(eventHolder.has_value());
    auto event = eventHolder.value().get();
    ASSERT_NE(event, nullptr);
    EXPECT_EQ(event->connectionId, connection->getConnectionId());
    EXPECT_EQ(event->type, "threadUpdated");
    EXPECT_EQ(event->channel, "thread");
    ASSERT_TRUE(thread::Events::isThreadUpdatedEvent(event));
    EXPECT_EQ(event->subscriptions.size(), 1);
    thread::Thread thread = thread::Events::extractThreadUpdatedEvent(event).data;
    EXPECT_EQ(thread.contextId, reader->getString("Context_1.contextId"));
    EXPECT_EQ(thread.publicMeta.stdString(), "public");
    EXPECT_EQ(thread.privateMeta.stdString(), "private");
    EXPECT_EQ(thread.users.size(), 1);
    if(thread.users.size() == 1) {
        EXPECT_EQ(thread.users[0], reader->getString("Login.user_1_id"));
    }
    EXPECT_EQ(thread.managers.size(), 1);
    if(thread.managers.size() == 1) {
        EXPECT_EQ(thread.managers[0], reader->getString("Login.user_1_id"));
    }
}

TEST_F(ThreadEventTest, waitEvent_getEvent_threadUpdated_disabled) {
    eventQueue.waitEvent();
    auto tmp = threadApi->subscribeFor({
        threadApi->buildSubscriptionQuery(
            thread::EventType::THREAD_UPDATE,
            thread::EventSelectorType::CONTEXT_ID,
            reader->getString("Context_1.contextId")
        )
    });
    threadApi->unsubscribeFrom(tmp);
    threadApi->updateThread(
        reader->getString("Thread_1.threadId"),
        std::vector<core::UserWithPubKey>{core::UserWithPubKey{
            .userId=reader->getString("Login.user_1_id"),
            .pubKey=reader->getString("Login.user_1_pubKey")
        }},
        std::vector<core::UserWithPubKey>{core::UserWithPubKey{
            .userId=reader->getString("Login.user_1_id"),
            .pubKey=reader->getString("Login.user_1_pubKey")
        }},
        core::Buffer::from("public"),
        core::Buffer::from("private"),
        1,
        true,
        true
    );
    assertNoEventReceived();
}

TEST_F(ThreadEventTest, waitEvent_getEvent_threadDeleted_enabled) {
    eventQueue.waitEvent();
    threadApi->subscribeFor({
        threadApi->buildSubscriptionQuery(
            thread::EventType::THREAD_DELETE,
            thread::EventSelectorType::CONTEXT_ID,
            reader->getString("Context_1.contextId")
        )
    });
    threadApi->deleteThread(
        reader->getString("Thread_1.threadId")
    );
    auto eventHolder = waitForEvent("threadDeleted", {connection->getConnectionId()});
    ASSERT_TRUE(eventHolder.has_value());
    auto event = eventHolder.value().get();
    ASSERT_NE(event, nullptr);
    EXPECT_EQ(event->connectionId, connection->getConnectionId());
    EXPECT_EQ(event->type, "threadDeleted");
    EXPECT_EQ(event->channel, "thread");
    ASSERT_TRUE(thread::Events::isThreadDeletedEvent(event));
    EXPECT_EQ(event->subscriptions.size(), 1);
    thread::ThreadDeletedEventData threadDeleted = thread::Events::extractThreadDeletedEvent(event).data;
    EXPECT_EQ(threadDeleted.threadId, reader->getString("Thread_1.threadId"));
}

TEST_F(ThreadEventTest, waitEvent_getEvent_threadDeleted_disabled) {
    eventQueue.waitEvent();
    auto tmp = threadApi->subscribeFor({
        threadApi->buildSubscriptionQuery(
            thread::EventType::THREAD_DELETE,
            thread::EventSelectorType::CONTEXT_ID,
            reader->getString("Context_1.contextId")
        )
    });
    threadApi->unsubscribeFrom(tmp);
    threadApi->deleteThread(
        reader->getString("Thread_1.threadId")
    );
    assertNoEventReceived();
}

TEST_F(ThreadEventTest, waitEvent_getEvent_threadStats_enabled) {
    eventQueue.waitEvent();
    threadApi->subscribeFor({
        threadApi->buildSubscriptionQuery(
            thread::EventType::THREAD_STATS,
            thread::EventSelectorType::CONTEXT_ID,
            reader->getString("Context_1.contextId")
        )
    });
    threadApi->deleteMessage(
        reader->getString("Message_1.info_messageId")
    );
    auto eventHolder = waitForEvent("threadStatsChanged", {connection->getConnectionId()});
    ASSERT_TRUE(eventHolder.has_value());
    auto event = eventHolder.value().get();
    ASSERT_NE(event, nullptr);
    EXPECT_EQ(event->connectionId, connection->getConnectionId());
    EXPECT_EQ(event->type, "threadStatsChanged");
    EXPECT_EQ(event->channel, "thread");
    ASSERT_TRUE(thread::Events::isThreadStatsEvent(event));
    EXPECT_EQ(event->subscriptions.size(), 1);
    thread::ThreadStatsEventData threadStat = thread::Events::extractThreadStatsEvent(event).data;
    EXPECT_EQ(threadStat.threadId, reader->getString("Thread_1.threadId"));
    EXPECT_EQ(threadStat.messagesCount, 1);
}

TEST_F(ThreadEventTest, waitEvent_getEvent_threadStats_disabled) {
    eventQueue.waitEvent();
    auto tmp = threadApi->subscribeFor({
        threadApi->buildSubscriptionQuery(
            thread::EventType::THREAD_STATS,
            thread::EventSelectorType::CONTEXT_ID,
            reader->getString("Context_1.contextId")
        )
    });
    threadApi->unsubscribeFrom(tmp);
    threadApi->deleteMessage(
        reader->getString("Message_1.info_messageId")
    );
    assertNoEventReceived();
}

TEST_F(ThreadEventTest, waitEvent_getEvent_threadNewMessage_enabled) {
    eventQueue.waitEvent();
    threadApi->subscribeFor({
        threadApi->buildSubscriptionQuery(
            thread::EventType::MESSAGE_CREATE,
            thread::EventSelectorType::THREAD_ID,
            reader->getString("Thread_1.threadId")
        )
    });
    threadApi->sendMessage(
        reader->getString("Thread_1.threadId"),
        core::Buffer::from("publicMeta"),
        core::Buffer::from("privateMeta"),
        core::Buffer::from("data")
    );
    auto eventHolder = waitForEvent("threadNewMessage", {connection->getConnectionId()});
    ASSERT_TRUE(eventHolder.has_value());
    auto event = eventHolder.value().get();
    ASSERT_NE(event, nullptr);
    EXPECT_EQ(event->connectionId, connection->getConnectionId());
    EXPECT_EQ(event->type, "threadNewMessage");
    EXPECT_EQ(event->channel, "thread/"+reader->getString("Thread_1.threadId")+"/messages");
    ASSERT_TRUE(thread::Events::isThreadNewMessageEvent(event));
    EXPECT_EQ(event->subscriptions.size(), 1);
    thread::Message message = thread::Events::extractThreadNewMessageEvent(event).data;
    EXPECT_EQ(message.publicMeta.stdString(), "publicMeta");
    EXPECT_EQ(message.privateMeta.stdString(), "privateMeta");
    EXPECT_EQ(message.data.stdString(), "data");
    EXPECT_EQ(message.info.threadId, reader->getString("Thread_1.threadId"));
}

TEST_F(ThreadEventTest, waitEvent_getEvent_threadNewMessage_disabled) {
    eventQueue.waitEvent();
    auto tmp = threadApi->subscribeFor({
        threadApi->buildSubscriptionQuery(
            thread::EventType::MESSAGE_CREATE,
            thread::EventSelectorType::THREAD_ID,
            reader->getString("Thread_1.threadId")
        )
    });
    threadApi->unsubscribeFrom(tmp);
    threadApi->sendMessage(
        reader->getString("Thread_1.threadId"),
        core::Buffer::from("publicMeta"),
        core::Buffer::from("privateMeta"),
        core::Buffer::from("data")
    );
    assertNoEventReceived();
}

TEST_F(ThreadEventTest, waitEvent_getEvent_threadUpdatedMessage_enabled) {
    eventQueue.waitEvent();
    threadApi->subscribeFor({
        threadApi->buildSubscriptionQuery(
            thread::EventType::MESSAGE_UPDATE,
            thread::EventSelectorType::THREAD_ID,
            reader->getString("Thread_1.threadId")
        )
    });
    threadApi->updateMessage(
        reader->getString("Message_1.info_messageId"),
        core::Buffer::from("publicMeta"),
        core::Buffer::from("privateMeta"),
        core::Buffer::from("data")
    );
    auto eventHolder = waitForEvent("threadUpdatedMessage", {connection->getConnectionId()});
    ASSERT_TRUE(eventHolder.has_value());
    auto event = eventHolder.value().get();
    ASSERT_NE(event, nullptr);
    EXPECT_EQ(event->connectionId, connection->getConnectionId());
    EXPECT_EQ(event->type, "threadUpdatedMessage");
    EXPECT_EQ(event->channel, "thread/"+reader->getString("Thread_1.threadId")+"/messages");
    ASSERT_TRUE(thread::Events::isThreadMessageUpdatedEvent(event));
    EXPECT_EQ(event->subscriptions.size(), 1);
    thread::Message message = thread::Events::extractThreadMessageUpdatedEvent(event).data;
    EXPECT_EQ(message.info.messageId, reader->getString("Message_1.info_messageId"));
    EXPECT_EQ(message.publicMeta.stdString(), "publicMeta");
    EXPECT_EQ(message.privateMeta.stdString(), "privateMeta");
    EXPECT_EQ(message.data.stdString(), "data");
    EXPECT_EQ(message.info.threadId, reader->getString("Thread_1.threadId"));
}

TEST_F(ThreadEventTest, waitEvent_getEvent_threadUpdatedMessage_disabled) {
    eventQueue.waitEvent();
    auto tmp = threadApi->subscribeFor({
        threadApi->buildSubscriptionQuery(
            thread::EventType::MESSAGE_UPDATE,
            thread::EventSelectorType::THREAD_ID,
            reader->getString("Thread_1.threadId")
        )
    });
    threadApi->unsubscribeFrom(tmp);
    threadApi->updateMessage(
        reader->getString("Message_1.info_messageId"),
        core::Buffer::from("publicMeta"),
        core::Buffer::from("privateMeta"),
        core::Buffer::from("data")
    );
    assertNoEventReceived();
}

TEST_F(ThreadEventTest, waitEvent_getEvent_threadDeletedMessage_enabled) {
    eventQueue.waitEvent();
    threadApi->subscribeFor({
        threadApi->buildSubscriptionQuery(
            thread::EventType::MESSAGE_DELETE,
            thread::EventSelectorType::THREAD_ID,
            reader->getString("Thread_1.threadId")
        )
    });
    threadApi->deleteMessage(
        reader->getString("Message_1.info_messageId")
    );
    auto eventHolder = waitForEvent("threadMessageDeleted", {connection->getConnectionId()});
    ASSERT_TRUE(eventHolder.has_value());
    auto event = eventHolder.value().get();
    ASSERT_NE(event, nullptr);
    EXPECT_EQ(event->connectionId, connection->getConnectionId());
    EXPECT_EQ(event->type, "threadMessageDeleted");
    EXPECT_EQ(event->channel, "thread/"+reader->getString("Thread_1.threadId")+"/messages");
    ASSERT_TRUE(thread::Events::isThreadMessageDeletedEvent(event));
    EXPECT_EQ(event->subscriptions.size(), 1);
    thread::ThreadDeletedMessageEventData threadDeletedMessage = thread::Events::extractThreadMessageDeletedEvent(event).data;
    EXPECT_EQ(threadDeletedMessage.messageId, reader->getString("Message_1.info_messageId"));
    EXPECT_EQ(threadDeletedMessage.threadId, reader->getString("Thread_1.threadId"));
}

TEST_F(ThreadEventTest, waitEvent_getEvent_threadDeletedMessage_disabled) {
    eventQueue.waitEvent();
    auto tmp = threadApi->subscribeFor({
        threadApi->buildSubscriptionQuery(
            thread::EventType::MESSAGE_DELETE,
            thread::EventSelectorType::THREAD_ID,
            reader->getString("Thread_1.threadId")
        )
    });
    threadApi->unsubscribeFrom(tmp);
    threadApi->deleteMessage(
        reader->getString("Message_1.info_messageId")
    );
    assertNoEventReceived();
}

TEST_F(ThreadEventTest, subscribeFor_query_from_other_module) {
    EXPECT_THROW({
        auto tmp = threadApi->subscribeFor({
            "treads/update|contextId="+reader->getString("Context_1.contextId")
        });
    }, core::InvalidSubscriptionQueryException);
    EXPECT_THROW({
        auto tmp = threadApi->subscribeFor({
            "store/update|contextId="+reader->getString("Context_1.contextId")
        });
    }, core::InvalidSubscriptionQueryException);
}

TEST_F(ThreadEventTest, subscribeFor_unsubscribeFor) {
    std::vector<std::string> valid_subscriptions;
    EXPECT_NO_THROW({
        valid_subscriptions = threadApi->subscribeFor({
            threadApi->buildSubscriptionQuery(
                thread::EventType::THREAD_CREATE,
                thread::EventSelectorType::CONTEXT_ID,
                reader->getString("Context_1.contextId")
            )
        });
    });
    std::vector<std::string> invalid_subscriptions;
    EXPECT_NO_THROW({
        invalid_subscriptions = threadApi->subscribeFor({
            threadApi->buildSubscriptionQuery(
                thread::EventType::THREAD_CREATE,
                thread::EventSelectorType::CONTEXT_ID,
                "error"
            )
        });
    });
    EXPECT_NO_THROW({
        threadApi->unsubscribeFrom({
            valid_subscriptions
        });
    });
    EXPECT_NO_THROW({
        threadApi->unsubscribeFrom({
            invalid_subscriptions
        });
    });
}
