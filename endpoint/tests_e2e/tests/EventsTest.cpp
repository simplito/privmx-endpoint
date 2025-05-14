
#include <gtest/gtest.h>
#include <chrono>
#include <thread>
#include "../utils/BaseTest.hpp"
#include <privmx/endpoint/core/Connection.hpp>
#include <privmx/endpoint/event/EventApi.hpp>
#include <privmx/endpoint/event/Events.hpp>
#include <privmx/endpoint/event/EventException.hpp>
#include <privmx/endpoint/core/Exception.hpp>
#include <Poco/Util/IniFileConfiguration.h>
#include <privmx/crypto/Crypto.hpp>
#include <privmx/endpoint/core/VarSerializer.hpp>
#include <privmx/endpoint/core/EventQueue.hpp>
#include <privmx/endpoint/core/EventQueueImpl.hpp>

using namespace privmx::endpoint;

class EventTest : public privmx::test::BaseTest {
protected:
    EventTest() : BaseTest(privmx::test::BaseTestMode::online) {}
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
        eventApi = std::make_shared<event::EventApi>(
            event::EventApi::create(
                *connection
            )
        );
    }
    void customTearDown() override { // tmp segfault fix
        connection.reset();
        eventApi.reset();
        reader.reset();
        privmx::endpoint::core::EventQueueImpl::getInstance()->clear();
    }
    std::shared_ptr<core::Connection> connection;
    std::shared_ptr<event::EventApi> eventApi;
    core::EventQueue eventQueue = core::EventQueue::getInstance();
    Poco::Util::IniFileConfiguration::Ptr reader;
};

TEST_F(EventTest, waitEvent_getEvent_getCustom_event_enabled) {
    std::shared_ptr<privmx::endpoint::core::Event> event = nullptr;
    EXPECT_NO_THROW({
        std::optional<core::EventHolder> eventHolder = eventQueue.waitEvent();
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
        eventApi->subscribeForCustomEvents(reader->getString("Context_1.contextId"), "internal");
    }, core::Exception);
    EXPECT_NO_THROW({
        eventApi->subscribeForCustomEvents(reader->getString("Context_1.contextId"), "testing");
    });
    EXPECT_NO_THROW({
        std::vector<privmx::endpoint::core::UserWithPubKey> users;
        users.push_back(privmx::endpoint::core::UserWithPubKey{.userId=reader->getString("Login.user_1_id"), .pubKey=reader->getString("Login.user_1_pubKey")});
        eventApi->emitEvent(
            reader->getString("Context_1.contextId"),
            users,
            "testing", 
            core::Buffer::from("test event")
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
    EXPECT_NO_THROW({
        EXPECT_EQ(event->connectionId, connection->getConnectionId());
        EXPECT_EQ(event->type, "contextCustom");
        EXPECT_EQ(event->channel, "context/" + reader->getString("Context_1.contextId") + "/testing");
        if(event::Events::isContextCustomEvent(event)) {
            event::ContextCustomEvent customContextEvent = event::Events::extractContextCustomEvent(event);
            EXPECT_EQ(customContextEvent.data.contextId, reader->getString("Context_1.contextId"));
            EXPECT_EQ(customContextEvent.data.userId, reader->getString("Login.user_1_id"));
            EXPECT_EQ(customContextEvent.data.payload.stdString(), "test event");
        } else {
            FAIL();
        }
    });
}

TEST_F(EventTest, waitEvent_getEvent_getCustom_event_disabled) {
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
        eventApi->unsubscribeFromCustomEvents(reader->getString("Context_1.contextId"), "internal");
    }, event::ForbiddenChannelNameException);
    EXPECT_THROW({
        eventApi->unsubscribeFromCustomEvents(reader->getString("Context_1.contextId"), "testing");
    }, core::Exception);
    EXPECT_NO_THROW({
        std::vector<privmx::endpoint::core::UserWithPubKey> users;
        users.push_back(privmx::endpoint::core::UserWithPubKey{.userId=reader->getString("Login.user_1_id"), .pubKey=reader->getString("Login.user_1_pubKey")});
        eventApi->emitEvent(
            reader->getString("Context_1.contextId"),
            users,
            "testing", 
            core::Buffer::from("test event")
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

TEST_F(CoreEventTest, waitEvent_getEvent_getCustom_event_enabled) {
    std::shared_ptr<privmx::endpoint::core::Event> event = nullptr;
    EXPECT_NO_THROW({
        std::optional<core::EventHolder> eventHolder = eventQueue.waitEvent();
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
        eventApi->subscribeForCustomEvents(reader->getString("Context_1.contextId"), "internal");
    }, core::Exception);
    EXPECT_NO_THROW({
        eventApi->subscribeForCustomEvents(reader->getString("Context_1.contextId"), "testing");
    });
    EXPECT_NO_THROW({
        std::vector<privmx::endpoint::core::UserWithPubKey> users;
        users.push_back(privmx::endpoint::core::UserWithPubKey{.userId=reader->getString("Login.user_1_id"), .pubKey=reader->getString("Login.user_1_pubKey")});
        eventApi->emitEvent(
            reader->getString("Context_1.contextId"), 
            "testing", 
            core::Buffer::from("test event"), 
            users
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
    EXPECT_NO_THROW({
        EXPECT_EQ(event->connectionId, connection->getConnectionId());
        EXPECT_EQ(event->type, "contextCustom");
        EXPECT_EQ(event->channel, "context/" + reader->getString("Context_1.contextId") + "/testing");
        if(event::Events::isContextCustomEvent(event)) {
            event::ContextCustomEvent customContextEvent = event::Events::extractContextCustomEvent(event);
            EXPECT_EQ(customContextEvent.data.contextId, reader->getString("Context_1.contextId"));
            EXPECT_EQ(customContextEvent.data.userId, reader->getString("Login.user_1_id"));
            EXPECT_EQ(customContextEvent.data.payload.stdString(), "test event");
        } else {
            FAIL();
        }
    });
}

TEST_F(CoreEventTest, waitEvent_getEvent_getCustom_event_disabled) {
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
        eventApi->unsubscribeFromCustomEvents(reader->getString("Context_1.contextId"), "internal");
    }, event::ForbiddenChannelNameException);
    EXPECT_THROW({
        eventApi->unsubscribeFromCustomEvents(reader->getString("Context_1.contextId"), "testing");
    }, core::Exception);
    EXPECT_NO_THROW({
        std::vector<privmx::endpoint::core::UserWithPubKey> users;
        users.push_back(privmx::endpoint::core::UserWithPubKey{.userId=reader->getString("Login.user_1_id"), .pubKey=reader->getString("Login.user_1_pubKey")});
        eventApi->emitEvent(
            reader->getString("Context_1.contextId"), 
            "testing", 
            core::Buffer::from("test event"), 
            users
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

TEST_F(CoreEventTest, waitEvent_getEvent_thread_custom_event_enabled) {
    std::shared_ptr<privmx::endpoint::core::Event> event = nullptr;
    EXPECT_NO_THROW({
        std::optional<core::EventHolder> eventHolder = eventQueue.waitEvent();
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
        threadApi->subscribeForThreadCustomEvents(reader->getString("Thread_1.threadId"), "internal");
    }, thread::ForbiddenChannelNameException);
    EXPECT_NO_THROW({
        threadApi->subscribeForThreadCustomEvents(reader->getString("Thread_1.threadId"), "testing");
    });
    EXPECT_NO_THROW({
        threadApi->emitEvent(
            reader->getString("Thread_1.threadId"), 
            "testing", 
            core::Buffer::from("test event"), 
            {reader->getString("Login.user_1_id")}
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
    EXPECT_EQ(event->connectionId, connection->getConnectionId());
    EXPECT_EQ(event->type, "threadCustom");
    EXPECT_EQ(event->channel, "thread/" + reader->getString("Thread_1.threadId") + "/testing");
    if(thread::Events::isThreadCustomEvent(event)) {
        thread::ThreadCustomEvent threadCustomEvent = thread::Events::extractThreadCustomEvent(event);
        EXPECT_EQ(threadCustomEvent.threadId, reader->getString("Thread_1.threadId"));
        EXPECT_EQ(threadCustomEvent.userId, reader->getString("Login.user_1_id"));
        EXPECT_EQ(threadCustomEvent.data.stdString(), "test event");
    } else {
        FAIL();
    }
    // EXPECT_NO_THROW({
        
    // });
}

TEST_F(CoreEventTest, waitEvent_getEvent_get_thread_custom_event_disabled) {
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
        threadApi->unsubscribeFromThreadCustomEvents(reader->getString("Thread_1.threadId"), "internal");
    }, thread::ForbiddenChannelNameException);
    EXPECT_THROW({
        threadApi->unsubscribeFromThreadCustomEvents(reader->getString("Thread_1.threadId"), "testing");
    }, core::Exception);
    EXPECT_NO_THROW({
        threadApi->emitEvent(
            reader->getString("Thread_1.threadId"), 
            "testing", 
            core::Buffer::from("test event"), 
            {reader->getString("Login.user_1_id")}
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

TEST_F(CoreEventTest, waitEvent_getEvent_store_custom_event_enabled) {
    std::shared_ptr<privmx::endpoint::core::Event> event = nullptr;
    EXPECT_NO_THROW({
        std::optional<core::EventHolder> eventHolder = eventQueue.waitEvent();
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
        storeApi->subscribeForStoreCustomEvents(reader->getString("Store_1.storeId"), "internal");
    }, store::ForbiddenChannelNameException);
    EXPECT_NO_THROW({
        storeApi->subscribeForStoreCustomEvents(reader->getString("Store_1.storeId"), "testing");
    });
    EXPECT_NO_THROW({
        storeApi->emitEvent(
            reader->getString("Store_1.storeId"), 
            "testing", 
            core::Buffer::from("test event"), 
            {reader->getString("Login.user_1_id")}
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
    EXPECT_EQ(event->connectionId, connection->getConnectionId());
    EXPECT_EQ(event->type, "storeCustom");
    EXPECT_EQ(event->channel, "store/" + reader->getString("Store_1.storeId") + "/testing");
    if(store::Events::isStoreCustomEvent(event)) {
        store::StoreCustomEvent storeCustomEvent = store::Events::extractStoreCustomEvent(event);
        EXPECT_EQ(storeCustomEvent.storeId, reader->getString("Store_1.storeId"));
        EXPECT_EQ(storeCustomEvent.userId, reader->getString("Login.user_1_id"));
        EXPECT_EQ(storeCustomEvent.data.stdString(), "test event");
    } else {
        FAIL();
    }
    // EXPECT_NO_THROW({
        
    // });
}

TEST_F(CoreEventTest, waitEvent_getEvent_get_store_custom_event_disabled) {
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
        storeApi->unsubscribeFromStoreCustomEvents(reader->getString("Store_1.storeId"), "internal");
    }, store::ForbiddenChannelNameException);
    EXPECT_THROW({
        storeApi->unsubscribeFromStoreCustomEvents(reader->getString("Store_1.storeId"), "testing");
    }, core::Exception);
    EXPECT_NO_THROW({
        storeApi->emitEvent(
            reader->getString("Store_1.storeId"), 
            "testing", 
            core::Buffer::from("test event"), 
            {reader->getString("Login.user_1_id")}
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

TEST_F(CoreEventTest, waitEvent_getEvent_inbox_custom_event_enabled) {
    std::shared_ptr<privmx::endpoint::core::Event> event = nullptr;
    EXPECT_NO_THROW({
        std::optional<core::EventHolder> eventHolder = eventQueue.waitEvent();
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
        inboxApi->subscribeForInboxCustomEvents(reader->getString("Inbox_1.inboxId"), "internal");
    }, inbox::ForbiddenChannelNameException);
    EXPECT_NO_THROW({
        inboxApi->subscribeForInboxCustomEvents(reader->getString("Inbox_1.inboxId"), "testing");
    });
    EXPECT_NO_THROW({
        inboxApi->emitEvent(
            reader->getString("Inbox_1.inboxId"), 
            "testing", 
            core::Buffer::from("test event"), 
            {reader->getString("Login.user_1_id")}
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
    EXPECT_EQ(event->connectionId, connection->getConnectionId());
    EXPECT_EQ(event->type, "inboxCustom");
    EXPECT_EQ(event->channel, "inbox/" + reader->getString("Inbox_1.inboxId") + "/testing");
    if(inbox::Events::isInboxCustomEvent(event)) {
        inbox::InboxCustomEvent inboxCustomEvent = inbox::Events::extractInboxCustomEvent(event);
        EXPECT_EQ(inboxCustomEvent.inboxId, reader->getString("Inbox_1.inboxId"));
        EXPECT_EQ(inboxCustomEvent.userId, reader->getString("Login.user_1_id"));
        EXPECT_EQ(inboxCustomEvent.data.stdString(), "test event");
    } else {
        FAIL();
    }
    // EXPECT_NO_THROW({
        
    // });
}

TEST_F(CoreEventTest, waitEvent_getEvent_get_inbox_custom_event_disabled) {
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
        inboxApi->unsubscribeFromInboxCustomEvents(reader->getString("Inbox_1.inboxId"), "internal");
    }, inbox::ForbiddenChannelNameException);
    EXPECT_THROW({
        inboxApi->unsubscribeFromInboxCustomEvents(reader->getString("Inbox_1.inboxId"), "testing");
    }, core::Exception);
    EXPECT_NO_THROW({
        inboxApi->emitEvent(
            reader->getString("Inbox_1.inboxId"), 
            "testing", 
            core::Buffer::from("test event"), 
            {reader->getString("Login.user_1_id")}
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