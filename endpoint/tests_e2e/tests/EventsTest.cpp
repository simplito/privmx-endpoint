
#include <gtest/gtest.h>
#include <chrono>
#include <thread>
#include "../utils/BaseTest.hpp"
#include <privmx/endpoint/core/Connection.hpp>
#include <privmx/endpoint/thread/ThreadApi.hpp>
#include <privmx/endpoint/thread/Events.hpp>
#include <privmx/endpoint/store/StoreApi.hpp>
#include <privmx/endpoint/store/Events.hpp>
#include <privmx/endpoint/inbox/InboxApi.hpp>
#include <privmx/endpoint/inbox/Events.hpp>
#include <privmx/endpoint/core/Exception.hpp>
#include <Poco/Util/IniFileConfiguration.h>
#include <privmx/crypto/Crypto.hpp>
#include <privmx/endpoint/core/VarSerializer.hpp>
#include <privmx/endpoint/core/EventQueue.hpp>
#include <privmx/endpoint/core/EventQueueImpl.hpp>

using namespace privmx::endpoint;

class CoreEventTest : public privmx::test::BaseTest {
protected:
    CoreEventTest() : BaseTest(privmx::test::BaseTestMode::online) {}
    void customSetUp() override {
        std::string iniFile = std::getenv("INI_FILE_PATH");
        reader = new Poco::Util::IniFileConfiguration(iniFile);
        connection = std::make_shared<core::Connection>(
            core::Connection::platformConnect(
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
        storeApi = std::make_shared<store::StoreApi>(
            store::StoreApi::create(
                *connection
            )
        );
        inboxApi = std::make_shared<inbox::InboxApi>(
            inbox::InboxApi::create(
                *connection,
                *threadApi,
                *storeApi
            )
        );
    }
    void customTearDown() override { // tmp segfault fix
        connection.reset();
        threadApi.reset();
        storeApi.reset();
        inboxApi.reset();
        reader.reset();
        privmx::endpoint::core::EventQueueImpl::getInstance()->clear();
    }
    std::shared_ptr<core::Connection> connection;
    std::shared_ptr<thread::ThreadApi> threadApi;
    std::shared_ptr<store::StoreApi> storeApi;
    std::shared_ptr<inbox::InboxApi> inboxApi;
    core::EventQueue eventQueue = core::EventQueue::getInstance();
    Poco::Util::IniFileConfiguration::Ptr reader;
};

TEST_F(CoreEventTest, getEvent_libConnected) {
    std::shared_ptr<privmx::endpoint::core::Event> event = nullptr;
    EXPECT_NO_THROW({
        eventQueue.waitEvent(); // pop libConnected form queue
    });
    
}

TEST_F(CoreEventTest, getEvent_libConnected_different_instances) {
    std::shared_ptr<privmx::endpoint::core::Event> event = nullptr;
    EXPECT_NO_THROW({
        eventQueue.waitEvent(); // pop libConnected form queue
    });
    std::shared_ptr<core::Connection> connection_2;
    EXPECT_NO_THROW({
        connection_2 = std::make_shared<core::Connection>(
            core::Connection::platformConnect(
                reader->getString("Login.user_2_privKey"), 
                reader->getString("Login.solutionId"), 
                getPlatformUrl(reader->getString("Login.instanceUrl"))
            )
        );
    });
    EXPECT_NO_THROW({
        std::optional<core::EventHolder> eventHolder = eventQueue.getEvent();
        if(eventHolder.has_value()) {
            event = eventHolder.value().get();
        } else {
            event = nullptr;
        }
    });
    if(event != nullptr) {
        EXPECT_EQ(event->connectionId, connection_2->getConnectionId());
        EXPECT_EQ(event->type, "libConnected");
        EXPECT_TRUE(core::Events::isLibConnectedEvent(event));
    } else {
        FAIL();
    }
}

TEST_F(CoreEventTest, waitEvent_getEvent_libDisconnected) {
    std::shared_ptr<privmx::endpoint::core::Event> event = nullptr;
    EXPECT_NO_THROW({
        eventQueue.waitEvent(); // pop libConnected form queue
    });
    EXPECT_NO_THROW({
        connection->disconnect();
    });
    EXPECT_NO_THROW({
        std::optional<core::EventHolder> eventHolder = eventQueue.getEvent();
        if(eventHolder.has_value()) {
            event = eventHolder.value().get();
        } else {
            event = nullptr;
        }
    });
    if(event != nullptr) {
        EXPECT_EQ(event->connectionId, connection->getConnectionId());
        EXPECT_EQ(event->type, "libDisconnected");
        EXPECT_TRUE(core::Events::isLibDisconnectedEvent(event));
    } else {
        FAIL();
    } 
}

TEST_F(CoreEventTest, waitEvent_getEvent_libPlatformDisconnected) {
    std::shared_ptr<privmx::endpoint::core::Event> event = nullptr;
    EXPECT_NO_THROW({
        eventQueue.waitEvent(); // pop libConnected form queue
    });
    EXPECT_NO_THROW({
        connection->disconnect();
    });
    EXPECT_NO_THROW({
        eventQueue.waitEvent(); // pop libDisconnected form queue
    });
    EXPECT_NO_THROW({
        std::optional<core::EventHolder> eventHolder = eventQueue.getEvent();
        if(eventHolder.has_value()) {
            event = eventHolder.value().get();
        } else {
            event = nullptr;
        }
    });
    if(event != nullptr) {
        EXPECT_EQ(event->connectionId, connection->getConnectionId());
        EXPECT_EQ(event->type, "libPlatformDisconnected");
        EXPECT_TRUE(core::Events::isLibPlatformDisconnectedEvent(event));
    } else {
        FAIL();
    }
}

TEST_F(CoreEventTest, waitEvent_getEvent_threadCreated_enabled) {
    std::shared_ptr<privmx::endpoint::core::Event> event = nullptr;
    EXPECT_NO_THROW({
        eventQueue.waitEvent(); // pop libConnected form queue
    });
    EXPECT_NO_THROW({
        threadApi->subscribeForThreadEvents();
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

TEST_F(CoreEventTest, waitEvent_getEvent_threadCreated_disabled) {
    std::shared_ptr<privmx::endpoint::core::Event> event = nullptr;
    EXPECT_NO_THROW({
        eventQueue.waitEvent(); // pop libConnected form queue
    });
    EXPECT_NO_THROW({
        threadApi->subscribeForThreadEvents();
        threadApi->unsubscribeFromThreadEvents();
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

TEST_F(CoreEventTest, waitEvent_getEvent_threadUpdated_enabled) {
    std::shared_ptr<privmx::endpoint::core::Event> event = nullptr;
    EXPECT_NO_THROW({
        eventQueue.waitEvent(); // pop libConnected form queue
    });
    EXPECT_NO_THROW({
        threadApi->subscribeForThreadEvents();
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

TEST_F(CoreEventTest, waitEvent_getEvent_threadUpdated_disabled) {
    std::shared_ptr<privmx::endpoint::core::Event> event = nullptr;
    EXPECT_NO_THROW({
        eventQueue.waitEvent(); // pop libConnected form queue
    });
    EXPECT_NO_THROW({
        threadApi->subscribeForThreadEvents();
        threadApi->unsubscribeFromThreadEvents();
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

TEST_F(CoreEventTest, waitEvent_getEvent_threadDeleted_enabled) {
    std::shared_ptr<privmx::endpoint::core::Event> event = nullptr;
    EXPECT_NO_THROW({
        eventQueue.waitEvent(); // pop libConnected form queue
    });
    EXPECT_NO_THROW({
        threadApi->subscribeForThreadEvents();
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
            thread::ThreadDeletedEventData threadDeleted = thread::Events::extractThreadDeletedEvent(event).data;
            EXPECT_EQ(threadDeleted.threadId, reader->getString("Thread_1.threadId"));
        } else {
            FAIL();
        }
    } else {
        FAIL();
    }
}

TEST_F(CoreEventTest, waitEvent_getEvent_threadDeleted_disabled) {
    std::shared_ptr<privmx::endpoint::core::Event> event = nullptr;
    EXPECT_NO_THROW({
        eventQueue.waitEvent(); // pop libConnected form queue
    });
    EXPECT_NO_THROW({
        threadApi->subscribeForThreadEvents();
        threadApi->unsubscribeFromThreadEvents();
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

TEST_F(CoreEventTest, waitEvent_getEvent_threadStats_enabled) {
    std::shared_ptr<privmx::endpoint::core::Event> event = nullptr;
    EXPECT_NO_THROW({
        eventQueue.waitEvent(); // pop libConnected form queue
    });
    EXPECT_NO_THROW({
        threadApi->subscribeForThreadEvents();
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

TEST_F(CoreEventTest, waitEvent_getEvent_threadStats_disabled) {
    std::shared_ptr<privmx::endpoint::core::Event> event = nullptr;
    EXPECT_NO_THROW({
        eventQueue.waitEvent(); // pop libConnected form queue
    });
    EXPECT_NO_THROW({
        threadApi->subscribeForThreadEvents();
        threadApi->unsubscribeFromThreadEvents();
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

TEST_F(CoreEventTest, waitEvent_getEvent_threadNewMessage_enabled) {
    std::shared_ptr<privmx::endpoint::core::Event> event = nullptr;
    EXPECT_NO_THROW({
        eventQueue.waitEvent(); // pop libConnected form queue
    });
    EXPECT_NO_THROW({
        threadApi->subscribeForMessageEvents(reader->getString("Thread_1.threadId"));
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

TEST_F(CoreEventTest, waitEvent_getEvent_threadNewMessage_disabled) {
    std::shared_ptr<privmx::endpoint::core::Event> event = nullptr;
    EXPECT_NO_THROW({
        eventQueue.waitEvent(); // pop libConnected form queue
    });
    EXPECT_NO_THROW({
        threadApi->subscribeForMessageEvents(reader->getString("Thread_1.threadId"));
        threadApi->unsubscribeFromMessageEvents(reader->getString("Thread_1.threadId"));
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

TEST_F(CoreEventTest, waitEvent_getEvent_threadUpdatedMessage_enabled) {
    std::shared_ptr<privmx::endpoint::core::Event> event = nullptr;
    EXPECT_NO_THROW({
        eventQueue.waitEvent(); // pop libConnected form queue
    });
    EXPECT_NO_THROW({
        threadApi->subscribeForMessageEvents(reader->getString("Thread_1.threadId"));
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

TEST_F(CoreEventTest, waitEvent_getEvent_threadUpdatedMessage_disabled) {
    std::shared_ptr<privmx::endpoint::core::Event> event = nullptr;
    EXPECT_NO_THROW({
        eventQueue.waitEvent(); // pop libConnected form queue
    });
    EXPECT_NO_THROW({
        threadApi->subscribeForMessageEvents(reader->getString("Thread_1.threadId"));
        threadApi->unsubscribeFromMessageEvents(reader->getString("Thread_1.threadId"));
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

TEST_F(CoreEventTest, waitEvent_getEvent_threadDeletedMessage_enabled) {
    std::shared_ptr<privmx::endpoint::core::Event> event = nullptr;
    EXPECT_NO_THROW({
        eventQueue.waitEvent(); // pop libConnected form queue
    });
    EXPECT_NO_THROW({
        threadApi->subscribeForMessageEvents(reader->getString("Thread_1.threadId"));
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
        if(thread::Events::isThreadDeletedMessageEvent(event)) {
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

TEST_F(CoreEventTest, waitEvent_getEvent_threadDeletedMessage_disabled) {
    std::shared_ptr<privmx::endpoint::core::Event> event = nullptr;
    EXPECT_NO_THROW({
        eventQueue.waitEvent(); // pop libConnected form queue
    });
    
    EXPECT_NO_THROW({
        threadApi->subscribeForMessageEvents(reader->getString("Thread_1.threadId"));
        threadApi->unsubscribeFromMessageEvents(reader->getString("Thread_1.threadId"));
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

TEST_F(CoreEventTest, waitEvent_getEvent_storeCreated_enabled) {
    std::shared_ptr<privmx::endpoint::core::Event> event = nullptr;
    EXPECT_NO_THROW({
        eventQueue.waitEvent(); // pop libConnected form queue
    });
    EXPECT_NO_THROW({
        storeApi->subscribeForStoreEvents();
    });
    std::string storeId;
    EXPECT_NO_THROW({
        storeId = storeApi->createStore(
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
        EXPECT_EQ(event->type, "storeCreated");
        EXPECT_EQ(event->channel, "store");
        if(store::Events::isStoreCreatedEvent(event)) {
            store::Store store = store::Events::extractStoreCreatedEvent(event).data;
            EXPECT_EQ(store.contextId, reader->getString("Context_1.contextId"));
            EXPECT_EQ(store.publicMeta.stdString(),"public");
            EXPECT_EQ(store.privateMeta.stdString(),"private");
            EXPECT_EQ(store.users.size(), 1);
            if(store.users.size() == 1) {
                EXPECT_EQ(store.users[0], reader->getString("Login.user_1_id"));
            }
            EXPECT_EQ(store.managers.size(), 1);
            if(store.managers.size() == 1) {
                EXPECT_EQ(store.managers[0], reader->getString("Login.user_1_id"));
            }
        } else {
            FAIL();
        }
    } else {
        FAIL();
    }
}

TEST_F(CoreEventTest, waitEvent_getEvent_storeCreated_disabled) {
    std::shared_ptr<privmx::endpoint::core::Event> event = nullptr;
    EXPECT_NO_THROW({
        eventQueue.waitEvent(); // pop libConnected form queue
    });
    EXPECT_NO_THROW({
        storeApi->subscribeForStoreEvents();
        storeApi->unsubscribeFromStoreEvents();
    });
    std::string storeId;
    EXPECT_NO_THROW({
        storeId = storeApi->createStore(
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

TEST_F(CoreEventTest, waitEvent_getEvent_storeUpdated_enabled) {
    std::shared_ptr<privmx::endpoint::core::Event> event = nullptr;
    EXPECT_NO_THROW({
        eventQueue.waitEvent(); // pop libConnected form queue
    });
    EXPECT_NO_THROW({
        storeApi->subscribeForStoreEvents();
    });
    EXPECT_NO_THROW({
        storeApi->updateStore(
            reader->getString("Store_1.storeId"),
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
        EXPECT_EQ(event->type, "storeUpdated");
        EXPECT_EQ(event->channel, "store");
        if(store::Events::isStoreUpdatedEvent(event)) {
            store::Store store = store::Events::extractStoreUpdatedEvent(event).data;
            EXPECT_EQ(store.contextId, reader->getString("Context_1.contextId"));
            EXPECT_EQ(store.publicMeta.stdString(),"public");
            EXPECT_EQ(store.privateMeta.stdString(),"private");
            EXPECT_EQ(store.users.size(), 1);
            if(store.users.size() == 1) {
                EXPECT_EQ(store.users[0], reader->getString("Login.user_1_id"));
            }
            EXPECT_EQ(store.managers.size(), 1);
            if(store.managers.size() == 1) {
                EXPECT_EQ(store.managers[0], reader->getString("Login.user_1_id"));
            }
        } else {
            FAIL();
        }
    } else {
        FAIL();
    }
}

TEST_F(CoreEventTest, waitEvent_getEvent_storeUpdated_disabled) {
    std::shared_ptr<privmx::endpoint::core::Event> event = nullptr;
    EXPECT_NO_THROW({
        eventQueue.waitEvent(); // pop libConnected form queue
    });
     EXPECT_NO_THROW({
        storeApi->subscribeForStoreEvents();
        storeApi->unsubscribeFromStoreEvents();
    });
    EXPECT_NO_THROW({
        storeApi->updateStore(
            reader->getString("Store_1.storeId"),
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

TEST_F(CoreEventTest, waitEvent_getEvent_storeDeleted_enabled) {
    std::shared_ptr<privmx::endpoint::core::Event> event = nullptr;
    EXPECT_NO_THROW({
        eventQueue.waitEvent(); // pop libConnected form queue
    });
    EXPECT_NO_THROW({
        storeApi->subscribeForStoreEvents();
    });
    EXPECT_NO_THROW({
        storeApi->deleteStore(
            reader->getString("Store_1.storeId")
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
        EXPECT_EQ(event->type, "storeDeleted");
        EXPECT_EQ(event->channel, "store");
        if(store::Events::isStoreDeletedEvent(event)) {
            store::StoreDeletedEventData storeDeleted = store::Events::extractStoreDeletedEvent(event).data;
            EXPECT_EQ(storeDeleted.storeId, reader->getString("Store_1.storeId"));
        } else {
            FAIL();
        }
    } else {
        FAIL();
    }
}

TEST_F(CoreEventTest, waitEvent_getEvent_storeDeleted_disabled) {
    std::shared_ptr<privmx::endpoint::core::Event> event = nullptr;
    EXPECT_NO_THROW({
        eventQueue.waitEvent(); // pop libConnected form queue
    });
     EXPECT_NO_THROW({
        storeApi->subscribeForStoreEvents();
        storeApi->unsubscribeFromStoreEvents();
    });
    EXPECT_NO_THROW({
        storeApi->deleteStore(
            reader->getString("Store_1.storeId")
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

TEST_F(CoreEventTest, waitEvent_getEvent_storeStatsChanged_enabled) {
    std::shared_ptr<privmx::endpoint::core::Event> event = nullptr;
    EXPECT_NO_THROW({
        eventQueue.waitEvent(); // pop libConnected form queue
    });
    EXPECT_NO_THROW({
        storeApi->subscribeForStoreEvents();
    });
    EXPECT_NO_THROW({
        storeApi->deleteFile(
            reader->getString("File_1.info_fileId")
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
        EXPECT_EQ(event->type, "storeStatsChanged");
        EXPECT_EQ(event->channel, "store");
        if(store::Events::isStoreStatsChangedEvent(event)) {
            store::StoreStatsChangedEventData storeStat = store::Events::extractStoreStatsChangedEvent(event).data;
            EXPECT_EQ(storeStat.storeId, reader->getString("Store_1.storeId"));
            EXPECT_EQ(storeStat.contextId, reader->getString("Context_1.contextId"));
            EXPECT_EQ(storeStat.filesCount, 1);
        } else {
            FAIL();
        }
    } else {
        FAIL();
    }
}

TEST_F(CoreEventTest, waitEvent_getEvent_storeStatsChanged_disabled) {
    std::shared_ptr<privmx::endpoint::core::Event> event = nullptr;
    EXPECT_NO_THROW({
        eventQueue.waitEvent(); // pop libConnected form queue
    });
    EXPECT_NO_THROW({
        storeApi->subscribeForStoreEvents();
        storeApi->unsubscribeFromStoreEvents();
    });
    EXPECT_NO_THROW({
        storeApi->deleteFile(
            reader->getString("File_1.info_fileId")
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

TEST_F(CoreEventTest, waitEvent_getEvent_storeFileCreated_enabled) {
    std::shared_ptr<privmx::endpoint::core::Event> event = nullptr;
    EXPECT_NO_THROW({
        eventQueue.waitEvent(); // pop libConnected form queue
    });
    EXPECT_NO_THROW({
        storeApi->subscribeForFileEvents(reader->getString("Store_1.storeId"));
    });
    int64_t handle;
    EXPECT_NO_THROW({
        handle = storeApi->createFile(
            reader->getString("Store_1.storeId"),
            privmx::endpoint::core::Buffer::from("publicMeta"),
            privmx::endpoint::core::Buffer::from("privateMeta"),
            0
        );
    });
    if(handle == 1) {
        std::string fileId;
        EXPECT_NO_THROW({
            fileId = storeApi->closeFile(handle);
        });
        if(fileId.empty()) {
            std::cout << "storeFileClose Failed" << std::endl;
            FAIL();
        }
    } else {
        std::cout << "storeFileCreate Failed" << std::endl;
        FAIL();
    }
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
        EXPECT_EQ(event->type, "storeFileCreated");
        EXPECT_EQ(event->channel, "store/" + reader->getString("Store_1.storeId") + "/files");
        if(store::Events::isStoreFileCreatedEvent(event)) {
            store::File storeFile = store::Events::extractStoreFileCreatedEvent(event).data;
            EXPECT_EQ(storeFile.info.storeId, reader->getString("Store_1.storeId"));
            EXPECT_EQ(storeFile.size, 0);
            EXPECT_EQ(storeFile.publicMeta.stdString(), "publicMeta");
            EXPECT_EQ(storeFile.privateMeta.stdString(), "privateMeta");
        } else {
            FAIL();
        }
    } else {
        FAIL();
    }
}

TEST_F(CoreEventTest, waitEvent_getEvent_storeFileCreated_disabled) {
    std::shared_ptr<privmx::endpoint::core::Event> event = nullptr;
    EXPECT_NO_THROW({
        eventQueue.waitEvent(); // pop libConnected form queue
    });
    EXPECT_NO_THROW({
        storeApi->subscribeForFileEvents(reader->getString("Store_1.storeId"));
        storeApi->unsubscribeFromFileEvents(reader->getString("Store_1.storeId"));
    });
    int64_t handle;
    EXPECT_NO_THROW({
        handle = storeApi->createFile(
            reader->getString("Store_1.storeId"),
            privmx::endpoint::core::Buffer::from("publicMeta"),
            privmx::endpoint::core::Buffer::from("privateMeta"),
            0
        );
    });
    if(handle == 1) {
        std::string fileId;
        EXPECT_NO_THROW({
            fileId = storeApi->closeFile(handle);
        });
        if(fileId.empty()) {
            std::cout << "storeFileClose Failed" << std::endl;
            FAIL();
        }
    } else {
        std::cout << "storeFileCreate Failed" << std::endl;
        FAIL();
    }
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

TEST_F(CoreEventTest, waitEvent_getEvent_storeFileUpdated_enabled) {
    std::shared_ptr<privmx::endpoint::core::Event> event = nullptr;
    EXPECT_NO_THROW({
        eventQueue.waitEvent(); // pop libConnected form queue
    });
    EXPECT_NO_THROW({
        storeApi->subscribeForFileEvents(reader->getString("Store_1.storeId"));
    });
    int64_t handle;
    EXPECT_NO_THROW({
        handle = storeApi->updateFile(
            reader->getString("File_1.info_fileId"),
            privmx::endpoint::core::Buffer::from("publicMeta"),
            privmx::endpoint::core::Buffer::from("privateMeta"),
            0
        );
    });
    if(handle == 1) {
        
        std::string fileId;
        EXPECT_NO_THROW({
            fileId = storeApi->closeFile(handle);
        });
        if(fileId.empty()) {
            std::cout << "storeFileClose Failed" << std::endl;
            FAIL();
        }
    } else {
        std::cout << "storeFileCreate Failed" << std::endl;
        FAIL();
    }
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
        EXPECT_EQ(event->type, "storeFileUpdated");
        EXPECT_EQ(event->channel, "store/" + reader->getString("Store_1.storeId") + "/files");
        if(store::Events::isStoreFileUpdatedEvent(event)) {
            store::File storeFile = store::Events::extractStoreFileUpdatedEvent(event).data;
            EXPECT_EQ(storeFile.info.storeId, reader->getString("Store_1.storeId"));
            EXPECT_EQ(storeFile.size, 0);
            EXPECT_EQ(storeFile.publicMeta.stdString(), "publicMeta");
            EXPECT_EQ(storeFile.privateMeta.stdString(), "privateMeta");
        } else {
            FAIL();
        }
    } else {
        FAIL();
    }
}

TEST_F(CoreEventTest, waitEvent_getEvent_storeFileUpdated_disabled) {
    std::shared_ptr<privmx::endpoint::core::Event> event = nullptr;
    EXPECT_NO_THROW({
        eventQueue.waitEvent(); // pop libConnected form queue
    });
    EXPECT_THROW({
        storeApi->unsubscribeFromFileEvents(reader->getString("Store_1.storeId"));
    }, core::Exception);
    int64_t handle;
    EXPECT_NO_THROW({
        handle = storeApi->updateFile(
            reader->getString("File_1.info_fileId"),
            privmx::endpoint::core::Buffer::from("publicMeta"),
            privmx::endpoint::core::Buffer::from("privateMeta"),
            0
        );
    });
    if(handle == 1) {
        
        std::string fileId;
        EXPECT_NO_THROW({
            fileId = storeApi->closeFile(handle);
        });
        if(fileId.empty()) {
            std::cout << "storeFileClose Failed" << std::endl;
            FAIL();
        }
    } else {
        std::cout << "storeFileCreate Failed" << std::endl;
        FAIL();
    }
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

TEST_F(CoreEventTest, waitEvent_getEvent_storeFileDeleted_enabled) {
    std::shared_ptr<privmx::endpoint::core::Event> event = nullptr;
    EXPECT_NO_THROW({
        eventQueue.waitEvent(); // pop libConnected form queue
    });
    EXPECT_NO_THROW({
        storeApi->subscribeForFileEvents(reader->getString("Store_1.storeId"));;
    });
    EXPECT_NO_THROW({
        storeApi->deleteFile(
            reader->getString("File_1.info_fileId")
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
        EXPECT_EQ(event->type, "storeFileDeleted");
        EXPECT_EQ(event->channel, "store/" + reader->getString("Store_1.storeId") + "/files");
        if(store::Events::isStoreFileDeletedEvent(event)) {
            store::StoreFileDeletedEventData storeFileDeleted = store::Events::extractStoreFileDeletedEvent(event).data;
            EXPECT_EQ(storeFileDeleted.fileId, reader->getString("File_1.info_fileId"));
            EXPECT_EQ(storeFileDeleted.storeId, reader->getString("File_1.info_storeId"));
            EXPECT_EQ(storeFileDeleted.contextId, reader->getString("Context_1.contextId"));
        } else {
            FAIL();
        }
    } else {
        FAIL();
    }
}

TEST_F(CoreEventTest, waitEvent_getEvent_storeFileDeleted_disabled) {
    std::shared_ptr<privmx::endpoint::core::Event> event = nullptr;
    EXPECT_NO_THROW({
        eventQueue.waitEvent(); // pop libConnected form queue
    });
    EXPECT_THROW({
        storeApi->unsubscribeFromFileEvents(reader->getString("Store_1.storeId"));
    }, core::Exception);
    EXPECT_NO_THROW({
        storeApi->deleteFile(
            reader->getString("File_1.info_fileId")
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

TEST_F(CoreEventTest, waitEvent_getEvent_inboxCreated_enabled) {
    std::shared_ptr<privmx::endpoint::core::Event> event = nullptr;
    EXPECT_NO_THROW({
        eventQueue.waitEvent(); // pop libConnected form queue
    });
    EXPECT_NO_THROW({
        inboxApi->subscribeForInboxEvents();
        threadApi->subscribeForThreadEvents();
        storeApi->subscribeForStoreEvents();
    });
    std::string inboxId;
    EXPECT_NO_THROW({
        inboxId = inboxApi->createInbox(
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
            core::Buffer::from("private"),
            std::nullopt
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
        EXPECT_EQ(event->type, "inboxCreated");
        EXPECT_EQ(event->channel, "inbox");
        if(inbox::Events::isInboxCreatedEvent(event)) {
            inbox::Inbox inbox = inbox::Events::extractInboxCreatedEvent(event).data;
            EXPECT_EQ(inbox.contextId, reader->getString("Context_1.contextId"));
            EXPECT_EQ(inbox.users.size(), 1);
            if(inbox.users.size() == 1) {
                EXPECT_EQ(inbox.users[0], reader->getString("Login.user_1_id"));
            }
            EXPECT_EQ(inbox.managers.size(), 1);
            if(inbox.managers.size() == 1) {
                EXPECT_EQ(inbox.managers[0], reader->getString("Login.user_1_id"));
            }
            EXPECT_EQ(inbox.publicMeta.stdString(), "public");
            EXPECT_EQ(inbox.privateMeta.stdString(), "private");
        } else {
            FAIL();
        }
    } else {
        FAIL();
    }
    EXPECT_NO_THROW({
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

TEST_F(CoreEventTest, waitEvent_getEvent_inboxCreated_disabled) {
    std::shared_ptr<privmx::endpoint::core::Event> event = nullptr;
    EXPECT_NO_THROW({
        eventQueue.waitEvent(); // pop libConnected form queue
    });
    EXPECT_NO_THROW({
        inboxApi->subscribeForInboxEvents();
        threadApi->subscribeForThreadEvents();
        storeApi->subscribeForStoreEvents();
        inboxApi->unsubscribeFromInboxEvents();
    });
    std::string inboxId;
    EXPECT_NO_THROW({
        inboxId = inboxApi->createInbox(
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
            core::Buffer::from("private"),
            std::nullopt
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

TEST_F(CoreEventTest, waitEvent_getEvent_inboxUpdated_enabled) {
    std::shared_ptr<privmx::endpoint::core::Event> event = nullptr;
    EXPECT_NO_THROW({
        eventQueue.waitEvent(); // pop libConnected form queue
    });
    EXPECT_NO_THROW({
        inboxApi->subscribeForInboxEvents();
        threadApi->subscribeForThreadEvents();
        storeApi->subscribeForStoreEvents();
    });
    EXPECT_NO_THROW({
        inboxApi->updateInbox(
            reader->getString("Inbox_1.inboxId"),
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
            std::nullopt,
            1,
            true,
            false
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
        EXPECT_EQ(event->type, "inboxUpdated");
        EXPECT_EQ(event->channel, "inbox");
        if(inbox::Events::isInboxUpdatedEvent(event)) {
            inbox::Inbox inbox = inbox::Events::extractInboxUpdatedEvent(event).data;
            EXPECT_EQ(inbox.contextId, reader->getString("Context_1.contextId"));
            EXPECT_EQ(inbox.users.size(), 1);
            if(inbox.users.size() == 1) {
                EXPECT_EQ(inbox.users[0], reader->getString("Login.user_1_id"));
            }
            EXPECT_EQ(inbox.managers.size(), 1);
            if(inbox.managers.size() == 1) {
                EXPECT_EQ(inbox.managers[0], reader->getString("Login.user_1_id"));
            }
            EXPECT_EQ(inbox.publicMeta.stdString(), "public");
            EXPECT_EQ(inbox.privateMeta.stdString(), "private");
        } else {
            FAIL();
        }
    } else {
        FAIL();
    }
    EXPECT_NO_THROW({
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

TEST_F(CoreEventTest, waitEvent_getEvent_inboxUpdated_disabled) {
    std::shared_ptr<privmx::endpoint::core::Event> event = nullptr;
    EXPECT_NO_THROW({
        eventQueue.waitEvent(); // pop libConnected form queue
    });
    EXPECT_NO_THROW({
        inboxApi->subscribeForInboxEvents();
        threadApi->subscribeForThreadEvents();
        storeApi->subscribeForStoreEvents();
        inboxApi->unsubscribeFromInboxEvents();
    });
    std::string inboxId;
    EXPECT_NO_THROW({
        inboxApi->updateInbox(
            reader->getString("Inbox_1.inboxId"),
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
            std::nullopt,
            1,
            true,
            false
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

TEST_F(CoreEventTest, waitEvent_getEvent_inboxDeleted_enabled) {
    std::shared_ptr<privmx::endpoint::core::Event> event = nullptr;
    EXPECT_NO_THROW({
        eventQueue.waitEvent(); // pop libConnected form queue
    });
    EXPECT_NO_THROW({
        inboxApi->subscribeForInboxEvents();
        threadApi->subscribeForThreadEvents();
        storeApi->subscribeForStoreEvents();
    });
    EXPECT_NO_THROW({
        inboxApi->deleteInbox(
            reader->getString("Inbox_1.inboxId")
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
        EXPECT_EQ(event->type, "inboxDeleted");
        EXPECT_EQ(event->channel, "inbox");
        if(inbox::Events::isInboxDeletedEvent(event)) {
            inbox::InboxDeletedEventData inboxDeletedEventData = inbox::Events::extractInboxDeletedEvent(event).data;
            EXPECT_EQ(inboxDeletedEventData.inboxId, reader->getString("Inbox_1.inboxId"));
        } else {
            FAIL();
        }
    } else {
        FAIL();
    }
    EXPECT_NO_THROW({
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

TEST_F(CoreEventTest, waitEvent_getEvent_inboxDeleted_disabled) {
    std::shared_ptr<privmx::endpoint::core::Event> event = nullptr;
    EXPECT_NO_THROW({
        eventQueue.waitEvent(); // pop libConnected form queue
    });
    EXPECT_NO_THROW({
        inboxApi->subscribeForInboxEvents();
        threadApi->subscribeForThreadEvents();
        storeApi->subscribeForStoreEvents();
        inboxApi->unsubscribeFromInboxEvents();
    });
    std::string inboxId;
    EXPECT_NO_THROW({
        inboxApi->deleteInbox(
            reader->getString("Inbox_1.inboxId")
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

TEST_F(CoreEventTest, waitEvent_getEvent_inboxEntryCreated_enabled) {
    std::shared_ptr<privmx::endpoint::core::Event> event = nullptr;
    EXPECT_NO_THROW({
        eventQueue.waitEvent(); // pop libConnected form queue
    });
    EXPECT_NO_THROW({
        inboxApi->subscribeForEntryEvents(reader->getString("Inbox_1.inboxId"));
    });
    int64_t fileHandle = 0;
    std::string file_total_data_send = "";
    EXPECT_NO_THROW({
        fileHandle = inboxApi->createFileHandle(
            privmx::endpoint::core::Buffer::from("publicMeta"),
            privmx::endpoint::core::Buffer::from("privateMeta"),
            0
        );
    });
    EXPECT_EQ(fileHandle, 1);
    if(fileHandle == 1) {
        int64_t inboxHandle = 0;
        EXPECT_NO_THROW({
            inboxHandle = inboxApi->prepareEntry(
                reader->getString("Inbox_1.inboxId"),
                core::Buffer::from("test_inboxSendCommit"),
                {fileHandle},
                reader->getString("Login.user_1_privKey")
            );
        });
        EXPECT_EQ(inboxHandle, 2);
        if(inboxHandle == 2) {
            EXPECT_NO_THROW({
                inboxApi->sendEntry(inboxHandle);
            });
        } else {
            std::cout << "inboxSendPrepare Failed" << std::endl;
            FAIL();
        }
    } else {
        std::cout << "inboxCreateFileHandle Failed" << std::endl;
        FAIL();
    }
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
        EXPECT_EQ(event->type, "inboxEntryCreated");
        EXPECT_EQ(event->channel, "inbox/" + reader->getString("Inbox_1.inboxId") + "/entries");
        if(inbox::Events::isInboxEntryCreatedEvent(event)) {
            inbox::InboxEntry inboxEntry = inbox::Events::extractInboxEntryCreatedEvent(event).data;
            EXPECT_EQ(inboxEntry.inboxId, reader->getString("Inbox_1.inboxId"));
            EXPECT_EQ(inboxEntry.data.stdString(), "test_inboxSendCommit");
            EXPECT_EQ(inboxEntry.files.size(), 1);
            if(inboxEntry.files.size() == 1) {
               EXPECT_EQ(inboxEntry.files[0].size, 0);
               EXPECT_EQ(inboxEntry.files[0].publicMeta.stdString(), "publicMeta");
               EXPECT_EQ(inboxEntry.files[0].privateMeta.stdString(), "privateMeta"); 
            }
        } else {
            FAIL();
        }
    } else {
        FAIL();
    }
}

TEST_F(CoreEventTest, waitEvent_getEvent_inboxEntryCreated_disabled) {
    std::shared_ptr<privmx::endpoint::core::Event> event = nullptr;
    EXPECT_NO_THROW({
        std::optional<core::EventHolder> eventHolder = eventQueue.getEvent();
        if(eventHolder.has_value()) {
            event = eventHolder.value().get();
        } else {
            event = nullptr;
        }
    });
    if(event != nullptr) {
        EXPECT_EQ(event->connectionId, connection->getConnectionId());
        EXPECT_EQ(event->type, "libConnected");
    } else {
        FAIL();
    }
    EXPECT_THROW({
        inboxApi->unsubscribeFromEntryEvents(reader->getString("Inbox_1.inboxId"));
    }, core::Exception);
    int64_t fileHandle = 0;
    std::string file_total_data_send = "";
    EXPECT_NO_THROW({
        fileHandle = inboxApi->createFileHandle(
            privmx::endpoint::core::Buffer::from("publicMeta"),
            privmx::endpoint::core::Buffer::from("privateMeta"),
            0
        );
    });
    EXPECT_EQ(fileHandle, 1);
    if(fileHandle == 1) {
        int64_t inboxHandle = 0;
        EXPECT_NO_THROW({
            inboxHandle = inboxApi->prepareEntry(
                reader->getString("Inbox_1.inboxId"),
                core::Buffer::from("test_inboxSendCommit"),
                {fileHandle},
                reader->getString("Login.user_1_privKey")
            );
        });
        EXPECT_EQ(inboxHandle, 2);
        if(inboxHandle == 2) {
            EXPECT_NO_THROW({
                inboxApi->sendEntry(inboxHandle);
            });
        } else {
            std::cout << "inboxSendPrepare Failed" << std::endl;
            FAIL();
        }
    } else {
        std::cout << "inboxCreateFileHandle Failed" << std::endl;
        FAIL();
    }
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

TEST_F(CoreEventTest, waitEvent_getEvent_inboxEntryDeleted_enabled) {
    std::shared_ptr<privmx::endpoint::core::Event> event = nullptr;
    EXPECT_NO_THROW({
        eventQueue.waitEvent(); // pop libConnected form queue
    });
    EXPECT_NO_THROW({
        inboxApi->subscribeForEntryEvents(reader->getString("Inbox_1.inboxId"));
    });
    EXPECT_NO_THROW({
        inboxApi->deleteEntry(
            reader->getString("Entry_1.entryId")
        );
    });
    EXPECT_NO_THROW({
        std::this_thread::sleep_for(std::chrono::milliseconds(5000));
        std::optional<core::EventHolder> eventHolder = eventQueue.getEvent();
        if(eventHolder.has_value()) {
            event = eventHolder.value().get();
        } else {
            event = nullptr;
        }
    });
    if(event != nullptr) {
        EXPECT_EQ(event->connectionId, connection->getConnectionId());
        EXPECT_EQ(event->type, "inboxEntryDeleted");
        EXPECT_EQ(event->channel, "inbox/" + reader->getString("Inbox_1.inboxId") + "/entries");
        if(inbox::Events::isInboxEntryDeletedEvent(event)) {
            inbox::InboxEntryDeletedEventData inboxEntryDeletedEventData = inbox::Events::extractInboxEntryDeletedEvent(event).data;
            EXPECT_EQ(inboxEntryDeletedEventData.inboxId, reader->getString("Inbox_1.inboxId"));
            EXPECT_EQ(inboxEntryDeletedEventData.entryId, reader->getString("Entry_1.entryId"));
        } else {
            FAIL();
        }
    } else {
        FAIL();
    }
}

TEST_F(CoreEventTest, waitEvent_getEvent_inboxEntryDeleted_disabled) {
    std::shared_ptr<privmx::endpoint::core::Event> event = nullptr;
    EXPECT_NO_THROW({
        std::optional<core::EventHolder> eventHolder = eventQueue.getEvent();
        if(eventHolder.has_value()) {
            event = eventHolder.value().get();
        } else {
            event = nullptr;
        }
    });
    if(event != nullptr) {
        EXPECT_EQ(event->connectionId, connection->getConnectionId());
        EXPECT_EQ(event->type, "libConnected");
    } else {
        FAIL();
    }
    EXPECT_THROW({
        inboxApi->unsubscribeFromEntryEvents(reader->getString("Inbox_1.inboxId"));
    }, core::Exception);
    EXPECT_NO_THROW({
        inboxApi->deleteEntry(
            reader->getString("Entry_1.entryId")
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