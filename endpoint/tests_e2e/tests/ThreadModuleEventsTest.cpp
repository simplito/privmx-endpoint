
#include <gtest/gtest.h>
#include <chrono>
#include <thread>
#include "../utils/BaseTest.hpp"
#include <privmx/endpoint/core/Connection.hpp>
#include <privmx/endpoint/thread/ThreadApi.hpp>
#include <privmx/endpoint/thread/Events.hpp>
#include <privmx/endpoint/thread/ThreadException.hpp>
#include <Poco/Util/IniFileConfiguration.h>
#include <privmx/crypto/Crypto.hpp>
#include <privmx/endpoint/core/VarSerializer.hpp>
#include <privmx/endpoint/core/EventQueue.hpp>
#include <privmx/endpoint/core/EventQueueImpl.hpp>

using namespace privmx::endpoint;

class ThreadEventTest : public privmx::test::BaseTest {
protected:
    ThreadEventTest() : BaseTest(privmx::test::BaseTestMode::online) {}
    void customSetUp() override {
        std::string iniFile = std::getenv("INI_FILE_PATH");
        reader = new Poco::Util::IniFileConfiguration(iniFile);
        connection = std::make_shared<core::Connection>(
            core::Connection::connect(
                reader->getString("Login.user_1_privKey"), 
                reader->getString("Login.solutionId"), 
                getPlatformUrl(reader->getString("Login.instanceUrl"))
            )
        );
        threadApi = std::make_shared<thread::ThreadApi>(
            thread::ThreadApi::create(
                *connection
            )
        );
    }
    void customTearDown() override { // tmp segfault fix
        connection.reset();
        threadApi.reset();
        reader.reset();
        privmx::endpoint::core::EventQueueImpl::getInstance()->clear();
    }
    std::shared_ptr<core::Connection> connection;
    std::shared_ptr<thread::ThreadApi> threadApi;
    core::EventQueue eventQueue = core::EventQueue::getInstance();
    Poco::Util::IniFileConfiguration::Ptr reader;
};

TEST_F(ThreadEventTest, waitEvent_getEvent_threadCreated_enabled) {
    std::shared_ptr<privmx::endpoint::core::Event> event = nullptr;
    EXPECT_NO_THROW({
        eventQueue.waitEvent(); // pop libConnected form queue
    });
    EXPECT_NO_THROW({
        threadApi->subscribeFor({
            threadApi->buildSubscriptionQuery(
                thread::EventType::THREAD_CREATE, 
                thread::EventSelectorType::CONTEXT_ID,
                reader->getString("Context_1.contextId")
            )
        });
    });
    std::string threadId;
    EXPECT_NO_THROW({
        threadId = threadApi->createThread(
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
    });
    EXPECT_NO_THROW({
        std::this_thread::sleep_for(std::chrono::milliseconds(1500));
        std::optional<core::EventHolder> eventHolder = eventQueue.getEvent();
        if(eventHolder.has_value()) {
            event = eventHolder.value().get();
        } else {
            event = nullptr;
        }
    });
    if(event != nullptr) {
        EXPECT_EQ(event->connectionId, connection->getConnectionId());
        EXPECT_EQ(event->type, "threadCreated");
        EXPECT_EQ(event->channel, "thread");
        if(thread::Events::isThreadCreatedEvent(event)) {
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
        } else {
            FAIL();
        }
    } else {
        FAIL();
    }
}

TEST_F(ThreadEventTest, waitEvent_getEvent_threadCreated_disabled) {
    std::shared_ptr<privmx::endpoint::core::Event> event = nullptr;
    EXPECT_NO_THROW({
        eventQueue.waitEvent(); // pop libConnected form queue
    });
    EXPECT_NO_THROW({
        auto tmp = threadApi->subscribeFor({
            threadApi->buildSubscriptionQuery(
                thread::EventType::THREAD_CREATE, 
                thread::EventSelectorType::CONTEXT_ID,
                reader->getString("Context_1.contextId")
            )
        });
        threadApi->unsubscribeFrom(tmp);
    });

    std::string threadId;
    EXPECT_NO_THROW({
        threadId = threadApi->createThread(
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
    });
    EXPECT_NO_THROW({
        std::this_thread::sleep_for(std::chrono::milliseconds(1500));
        std::optional<core::EventHolder> eventHolder = eventQueue.getEvent();
        if(eventHolder.has_value()) {
            event = eventHolder.value().get();
        } else {
            event = nullptr;
        }
    });
    if(event == nullptr) {

    } else {
        std::cout << "Received Event with type " << event->type << std::endl;
        std::cout << "Expected null" << std::endl;
        FAIL();
    }
}

TEST_F(ThreadEventTest, waitEvent_getEvent_threadUpdated_enabled) {
    std::shared_ptr<privmx::endpoint::core::Event> event = nullptr;
    EXPECT_NO_THROW({
        eventQueue.waitEvent(); // pop libConnected form queue
    });
    EXPECT_NO_THROW({
        threadApi->subscribeFor({
            threadApi->buildSubscriptionQuery(
                thread::EventType::THREAD_UPDATE, 
                thread::EventSelectorType::CONTEXT_ID,
                reader->getString("Context_1.contextId")
            )
        });
    });
    

    EXPECT_NO_THROW({
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
    });
    EXPECT_NO_THROW({
        std::this_thread::sleep_for(std::chrono::milliseconds(1500));
        std::optional<core::EventHolder> eventHolder = eventQueue.getEvent();
        if(eventHolder.has_value()) {
            event = eventHolder.value().get();
        } else {
            event = nullptr;
        }
    });
    if(event != nullptr) {
        EXPECT_EQ(event->connectionId, connection->getConnectionId());
        EXPECT_EQ(event->type, "threadUpdated");
        EXPECT_EQ(event->channel, "thread");
        if(thread::Events::isThreadUpdatedEvent(event)) {
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
        } else {
            FAIL();
        }
    } else {
        FAIL();
    }
}

TEST_F(ThreadEventTest, waitEvent_getEvent_threadUpdated_disabled) {
    std::shared_ptr<privmx::endpoint::core::Event> event = nullptr;
    EXPECT_NO_THROW({
        eventQueue.waitEvent(); // pop libConnected form queue
    });
    EXPECT_NO_THROW({
        auto tmp = threadApi->subscribeFor({
            threadApi->buildSubscriptionQuery(
                thread::EventType::THREAD_UPDATE, 
                thread::EventSelectorType::CONTEXT_ID,
                reader->getString("Context_1.contextId")
            )
        });
        threadApi->unsubscribeFrom(tmp);
    });

    EXPECT_NO_THROW({
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
    });
    EXPECT_NO_THROW({
        std::this_thread::sleep_for(std::chrono::milliseconds(1500));
        std::optional<core::EventHolder> eventHolder = eventQueue.getEvent();
        if(eventHolder.has_value()) {
            event = eventHolder.value().get();
        } else {
            event = nullptr;
        }
    });
    if(event == nullptr) {

    } else {
        std::cout << "Received Event with type " << event->type << std::endl;
        std::cout << "Expected null" << std::endl;
        FAIL();
    }
}

TEST_F(ThreadEventTest, waitEvent_getEvent_threadDeleted_enabled) {
    std::shared_ptr<privmx::endpoint::core::Event> event = nullptr;
    EXPECT_NO_THROW({
        eventQueue.waitEvent(); // pop libConnected form queue
    });
    EXPECT_NO_THROW({
        threadApi->subscribeFor({
            threadApi->buildSubscriptionQuery(
                thread::EventType::THREAD_DELETE, 
                thread::EventSelectorType::CONTEXT_ID,
                reader->getString("Context_1.contextId")
            )
        });
    });

    EXPECT_NO_THROW({
        threadApi->deleteThread(
            reader->getString("Thread_1.threadId")
        );
    });
    EXPECT_NO_THROW({
        std::this_thread::sleep_for(std::chrono::milliseconds(1500));
        std::optional<core::EventHolder> eventHolder = eventQueue.getEvent();
        if(eventHolder.has_value()) {
            event = eventHolder.value().get();
        } else {
            event = nullptr;
        }
    });
    if(event != nullptr) {
        EXPECT_EQ(event->connectionId, connection->getConnectionId());
        EXPECT_EQ(event->type, "threadDeleted");
        EXPECT_EQ(event->channel, "thread");
        if(thread::Events::isThreadDeletedEvent(event)) {
            EXPECT_EQ(event->subscriptions.size(), 1);
            thread::ThreadDeletedEventData threadDeleted = thread::Events::extractThreadDeletedEvent(event).data;
            EXPECT_EQ(threadDeleted.threadId, reader->getString("Thread_1.threadId"));
        } else {
            FAIL();
        }
    } else {
        FAIL();
    }
}

TEST_F(ThreadEventTest, waitEvent_getEvent_threadDeleted_disabled) {
    std::shared_ptr<privmx::endpoint::core::Event> event = nullptr;
    EXPECT_NO_THROW({
        eventQueue.waitEvent(); // pop libConnected form queue
    });
    EXPECT_NO_THROW({
        auto tmp = threadApi->subscribeFor({
            threadApi->buildSubscriptionQuery(
                thread::EventType::THREAD_DELETE, 
                thread::EventSelectorType::CONTEXT_ID,
                reader->getString("Context_1.contextId")
            )
        });
        threadApi->unsubscribeFrom(tmp);
    });

    EXPECT_NO_THROW({
        threadApi->deleteThread(
            reader->getString("Thread_1.threadId")
        );
    });
    EXPECT_NO_THROW({
        std::this_thread::sleep_for(std::chrono::milliseconds(1500));
        std::optional<core::EventHolder> eventHolder = eventQueue.getEvent();
        if(eventHolder.has_value()) {
            event = eventHolder.value().get();
        } else {
            event = nullptr;
        }
    });
    if(event == nullptr) {

    } else {
        std::cout << "Received Event with type " << event->type << std::endl;
        std::cout << "Expected null" << std::endl;
        FAIL();
    }
}

TEST_F(ThreadEventTest, waitEvent_getEvent_threadStats_enabled) {
    std::shared_ptr<privmx::endpoint::core::Event> event = nullptr;
    EXPECT_NO_THROW({
        eventQueue.waitEvent(); // pop libConnected form queue
    });
    EXPECT_NO_THROW({
        threadApi->subscribeFor({
            threadApi->buildSubscriptionQuery(
                thread::EventType::THREAD_STATS, 
                thread::EventSelectorType::CONTEXT_ID,
                reader->getString("Context_1.contextId")
            )
        });
    });

    EXPECT_NO_THROW({
        threadApi->deleteMessage(
            reader->getString("Message_1.info_messageId")
        );
    });
    EXPECT_NO_THROW({
        std::this_thread::sleep_for(std::chrono::milliseconds(1500));
        std::optional<core::EventHolder> eventHolder = eventQueue.getEvent();
        if(eventHolder.has_value()) {
            event = eventHolder.value().get();
        } else {
            event = nullptr;
        }
    });
    if(event != nullptr) {
        EXPECT_EQ(event->connectionId, connection->getConnectionId());
        EXPECT_EQ(event->type, "threadStatsChanged");
        EXPECT_EQ(event->channel, "thread");
        if(thread::Events::isThreadStatsEvent(event)) {
            EXPECT_EQ(event->subscriptions.size(), 1);
            thread::ThreadStatsEventData threadStat = thread::Events::extractThreadStatsEvent(event).data;
            EXPECT_EQ(threadStat.threadId, reader->getString("Thread_1.threadId"));
            EXPECT_EQ(threadStat.messagesCount, 1);
        } else {
            FAIL();
        }
    } else {
        FAIL();
    }
}

TEST_F(ThreadEventTest, waitEvent_getEvent_threadStats_disabled) {
    std::shared_ptr<privmx::endpoint::core::Event> event = nullptr;
    EXPECT_NO_THROW({
        eventQueue.waitEvent(); // pop libConnected form queue
    });
    EXPECT_NO_THROW({
        auto tmp = threadApi->subscribeFor({
            threadApi->buildSubscriptionQuery(
                thread::EventType::THREAD_STATS, 
                thread::EventSelectorType::CONTEXT_ID,
                reader->getString("Context_1.contextId")
            )
        });
        threadApi->unsubscribeFrom(tmp);
    });

    EXPECT_NO_THROW({
        threadApi->deleteMessage(
            reader->getString("Message_1.info_messageId")
        );
    });
    EXPECT_NO_THROW({
        std::this_thread::sleep_for(std::chrono::milliseconds(1500));
        std::optional<core::EventHolder> eventHolder = eventQueue.getEvent();
        if(eventHolder.has_value()) {
            event = eventHolder.value().get();
        } else {
            event = nullptr;
        }
    });
    if(event == nullptr) {

    } else {
        std::cout << "Received Event with type " << event->type << std::endl;
        std::cout << "Expected null" << std::endl;
        FAIL();
    }
}

TEST_F(ThreadEventTest, waitEvent_getEvent_threadNewMessage_enabled) {
    std::shared_ptr<privmx::endpoint::core::Event> event = nullptr;
    EXPECT_NO_THROW({
        eventQueue.waitEvent(); // pop libConnected form queue
    });
    EXPECT_NO_THROW({
        threadApi->subscribeFor({
            threadApi->buildSubscriptionQuery(
                thread::EventType::MESSAGE_CREATE, 
                thread::EventSelectorType::THREAD_ID,
                reader->getString("Thread_1.threadId")
            )
        });
    });
    std::string messageId;
    EXPECT_NO_THROW({
        messageId = threadApi->sendMessage(
            reader->getString("Thread_1.threadId"),
            core::Buffer::from("publicMeta"),
            core::Buffer::from("privateMeta"),
            core::Buffer::from("data")
        );
    });
    EXPECT_NO_THROW({
        std::this_thread::sleep_for(std::chrono::milliseconds(1500));
        std::optional<core::EventHolder> eventHolder = eventQueue.getEvent();
        if(eventHolder.has_value()) {
            event = eventHolder.value().get();
        } else {
            event = nullptr;
        }
    });
    if(event != nullptr) {
        EXPECT_EQ(event->connectionId, connection->getConnectionId());
        EXPECT_EQ(event->type, "threadNewMessage");
        EXPECT_EQ(event->channel, "thread/"+reader->getString("Thread_1.threadId")+"/messages");
        if(thread::Events::isThreadNewMessageEvent(event)) {
            EXPECT_EQ(event->subscriptions.size(), 1);
            thread::Message message = thread::Events::extractThreadNewMessageEvent(event).data;
            EXPECT_EQ(message.publicMeta.stdString(), "publicMeta");
            EXPECT_EQ(message.privateMeta.stdString(), "privateMeta");
            EXPECT_EQ(message.data.stdString(), "data");
            EXPECT_EQ(message.info.threadId, reader->getString("Thread_1.threadId"));
        } else {
            FAIL();
        }
    } else {
        FAIL();
    }
}

TEST_F(ThreadEventTest, waitEvent_getEvent_threadNewMessage_disabled) {
    std::shared_ptr<privmx::endpoint::core::Event> event = nullptr;
    EXPECT_NO_THROW({
        eventQueue.waitEvent(); // pop libConnected form queue
    });
    EXPECT_NO_THROW({
        auto tmp = threadApi->subscribeFor({
            threadApi->buildSubscriptionQuery(
                thread::EventType::MESSAGE_CREATE, 
                thread::EventSelectorType::THREAD_ID,
                reader->getString("Thread_1.threadId")
            )
        });
        threadApi->unsubscribeFrom(tmp);
    });
    std::string messageId;
    EXPECT_NO_THROW({
        messageId = threadApi->sendMessage(
            reader->getString("Thread_1.threadId"),
            core::Buffer::from("publicMeta"),
            core::Buffer::from("privateMeta"),
            core::Buffer::from("data")
        );
    });
    EXPECT_NO_THROW({
        std::this_thread::sleep_for(std::chrono::milliseconds(1500));
        std::optional<core::EventHolder> eventHolder = eventQueue.getEvent();
        if(eventHolder.has_value()) {
            event = eventHolder.value().get();
        } else {
            event = nullptr;
        }
    });
    if(event == nullptr) {

    } else {
        std::cout << "Received Event with type " << event->type << std::endl;
        std::cout << "Expected null" << std::endl;
        FAIL();
    }
}

TEST_F(ThreadEventTest, waitEvent_getEvent_threadUpdatedMessage_enabled) {
    std::shared_ptr<privmx::endpoint::core::Event> event = nullptr;
    EXPECT_NO_THROW({
        eventQueue.waitEvent(); // pop libConnected form queue
    });
    EXPECT_NO_THROW({
        threadApi->subscribeFor({
            threadApi->buildSubscriptionQuery(
                thread::EventType::MESSAGE_UPDATE, 
                thread::EventSelectorType::THREAD_ID,
                reader->getString("Thread_1.threadId")
            )
        });
    });
    EXPECT_NO_THROW({
        threadApi->updateMessage(
            reader->getString("Message_1.info_messageId"),
            core::Buffer::from("publicMeta"),
            core::Buffer::from("privateMeta"),
            core::Buffer::from("data")
        );
    });
    EXPECT_NO_THROW({
        std::this_thread::sleep_for(std::chrono::milliseconds(1500));
        std::optional<core::EventHolder> eventHolder = eventQueue.getEvent();
        if(eventHolder.has_value()) {
            event = eventHolder.value().get();
        } else {
            event = nullptr;
        }
    });
    if(event != nullptr) {
        EXPECT_EQ(event->connectionId, connection->getConnectionId());
        EXPECT_EQ(event->type, "threadUpdatedMessage");
        EXPECT_EQ(event->channel, "thread/"+reader->getString("Thread_1.threadId")+"/messages");
        if(thread::Events::isThreadMessageUpdatedEvent(event)) {
            EXPECT_EQ(event->subscriptions.size(), 1);
            thread::Message message = thread::Events::extractThreadMessageUpdatedEvent(event).data;
            EXPECT_EQ(message.info.messageId, reader->getString("Message_1.info_messageId"));
            EXPECT_EQ(message.publicMeta.stdString(), "publicMeta");
            EXPECT_EQ(message.privateMeta.stdString(), "privateMeta");
            EXPECT_EQ(message.data.stdString(), "data");
            EXPECT_EQ(message.info.threadId, reader->getString("Thread_1.threadId"));
        } else {
            FAIL();
        }
    } else {
        FAIL();
    }
}

TEST_F(ThreadEventTest, waitEvent_getEvent_threadUpdatedMessage_disabled) {
    std::shared_ptr<privmx::endpoint::core::Event> event = nullptr;
    EXPECT_NO_THROW({
        eventQueue.waitEvent(); // pop libConnected form queue
    });
    EXPECT_NO_THROW({
        auto tmp = threadApi->subscribeFor({
            threadApi->buildSubscriptionQuery(
                thread::EventType::MESSAGE_UPDATE, 
                thread::EventSelectorType::THREAD_ID,
                reader->getString("Thread_1.threadId")
            )
        });
        threadApi->unsubscribeFrom(tmp);
    });
    EXPECT_NO_THROW({
        threadApi->updateMessage(
            reader->getString("Message_1.info_messageId"),
            core::Buffer::from("publicMeta"),
            core::Buffer::from("privateMeta"),
            core::Buffer::from("data")
        );
    });
    EXPECT_NO_THROW({
        std::this_thread::sleep_for(std::chrono::milliseconds(1500));
        std::optional<core::EventHolder> eventHolder = eventQueue.getEvent();
        if(eventHolder.has_value()) {
            event = eventHolder.value().get();
        } else {
            event = nullptr;
        }
    });
    if(event == nullptr) {

    } else {
        std::cout << "Received Event with type " << event->type << std::endl;
        std::cout << "Expected null" << std::endl;
        FAIL();
    }
}

TEST_F(ThreadEventTest, waitEvent_getEvent_threadDeletedMessage_enabled) {
    std::shared_ptr<privmx::endpoint::core::Event> event = nullptr;
    EXPECT_NO_THROW({
        eventQueue.waitEvent(); // pop libConnected form queue
    });
    EXPECT_NO_THROW({
        threadApi->subscribeFor({
            threadApi->buildSubscriptionQuery(
                thread::EventType::MESSAGE_DELETE, 
                thread::EventSelectorType::THREAD_ID,
                reader->getString("Thread_1.threadId")
            )
        });
    });
    EXPECT_NO_THROW({
        threadApi->deleteMessage(
            reader->getString("Message_1.info_messageId")
        );
    });
    EXPECT_NO_THROW({
        std::this_thread::sleep_for(std::chrono::milliseconds(1500));
        std::optional<core::EventHolder> eventHolder = eventQueue.getEvent();
        if(eventHolder.has_value()) {
            event = eventHolder.value().get();
        } else {
            event = nullptr;
        }
    });
    if(event != nullptr) {
        EXPECT_EQ(event->connectionId, connection->getConnectionId());
        EXPECT_EQ(event->type, "threadMessageDeleted");
        EXPECT_EQ(event->channel, "thread/"+reader->getString("Thread_1.threadId")+"/messages");
        if(thread::Events::isThreadMessageDeletedEvent(event)) {
            EXPECT_EQ(event->subscriptions.size(), 1);
            thread::ThreadDeletedMessageEventData threadDeletedMessage = thread::Events::extractThreadMessageDeletedEvent(event).data;
            EXPECT_EQ(threadDeletedMessage.messageId, reader->getString("Message_1.info_messageId"));
            EXPECT_EQ(threadDeletedMessage.threadId, reader->getString("Thread_1.threadId"));
        } else {
            FAIL();
        }
    } else {
        FAIL();
    }
}

TEST_F(ThreadEventTest, waitEvent_getEvent_threadDeletedMessage_disabled) {
    std::shared_ptr<privmx::endpoint::core::Event> event = nullptr;
    EXPECT_NO_THROW({
        eventQueue.waitEvent(); // pop libConnected form queue
    });
    
    EXPECT_NO_THROW({
        auto tmp = threadApi->subscribeFor({
            threadApi->buildSubscriptionQuery(
                thread::EventType::MESSAGE_DELETE, 
                thread::EventSelectorType::THREAD_ID,
                reader->getString("Thread_1.threadId")
            )
        });
        threadApi->unsubscribeFrom(tmp);
    });
    EXPECT_NO_THROW({
        threadApi->deleteMessage(
            reader->getString("Message_1.info_messageId")
        );
    });
    EXPECT_NO_THROW({
        std::this_thread::sleep_for(std::chrono::milliseconds(1500));
        std::optional<core::EventHolder> eventHolder = eventQueue.getEvent();
        if(eventHolder.has_value()) {
            event = eventHolder.value().get();
        } else {
            event = nullptr;
        }
    });
    if(event == nullptr) {

    } else {
        std::cout << "Received Event with type " << event->type << std::endl;
        std::cout << "Expected null" << std::endl;
        FAIL();
    }
}
