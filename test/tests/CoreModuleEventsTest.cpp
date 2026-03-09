
#include <gtest/gtest.h>
#include <chrono>
#include <thread>
#include "../utils/BaseTest.hpp"
#include <privmx/endpoint/core/Connection.hpp>
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
        reader = new Poco::Util::IniFileConfiguration(INI_FILE_PATH);
        connection = std::make_shared<core::Connection>(
            core::Connection::connect(
                reader->getString("Login.user_1_privKey"), 
                reader->getString("Login.solutionId"), 
                getPlatformUrl(reader->getString("Login.instanceUrl"))
            )
        );
    }
    void customTearDown() override { // tmp segfault fix
        connection.reset();
        reader.reset();
        privmx::endpoint::core::EventQueueImpl::getInstance()->clear();
    }
    std::shared_ptr<core::Connection> connection;
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
            core::Connection::connect(
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


TEST_F(CoreEventTest, waitEvent_getEvent_ContextUsersStatusChangedEvent_enabled) {
    std::shared_ptr<privmx::endpoint::core::Event> event = nullptr;
    EXPECT_NO_THROW({
        eventQueue.waitEvent(); // pop libConnected form queue
    });
    std::shared_ptr<core::Connection> connection_2;
    EXPECT_NO_THROW({
        connection_2 = std::make_shared<core::Connection>(
            core::Connection::connect(
                reader->getString("Login.user_2_privKey"), 
                reader->getString("Login.solutionId"), 
                getPlatformUrl(reader->getString("Login.instanceUrl"))
            )
        );
    });
    EXPECT_NO_THROW({
        eventQueue.waitEvent(); // pop libConnected form queue
    });
    std::this_thread::sleep_for(std::chrono::milliseconds(1500));
    EXPECT_NO_THROW({
        connection->subscribeFor(
            {
                connection->buildSubscriptionQuery(
                    core::EventType::USER_STATUS, 
                    core::EventSelectorType::CONTEXT_ID,
                    reader->getString("Context_1.contextId")
                )
            }
        );
        connection_2->disconnect();
    });
    EXPECT_NO_THROW({
        eventQueue.waitEvent(); // pop libDisconnected form queue
    });
    EXPECT_NO_THROW({
        eventQueue.waitEvent(); // pop libPlatformDisconnected form queue
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
        EXPECT_EQ(event->type, "contextUserStatusChanged");
        EXPECT_EQ(event->channel, "context/userStatus");
        if(core::Events::isContextUsersStatusChangedEvent(event)) {
            EXPECT_EQ(event->subscriptions.size(), 1);
            core::ContextUsersStatusChangedEventData usersStatusChanged = core::Events::extractContextUsersStatusChangedEvent(event).data;
            EXPECT_EQ(usersStatusChanged.contextId, reader->getString("Context_1.contextId"));
            EXPECT_EQ(usersStatusChanged.users.size(), 1);
            if(usersStatusChanged.users.size() > 0) {
                auto userWithAction = usersStatusChanged.users[0];
                EXPECT_EQ(userWithAction.user.pubKey, reader->getString("Login.user_2_pubKey"));
                EXPECT_EQ(userWithAction.user.userId, reader->getString("Login.user_2_id"));
                EXPECT_EQ(userWithAction.action, "logout");
            }
        } else {
            FAIL();
        }
    } else {
        FAIL();
    }
}

TEST_F(CoreEventTest, waitEvent_getEvent_ContextUsersStatusChangedEvent_disabled) {
     std::shared_ptr<privmx::endpoint::core::Event> event = nullptr;
    EXPECT_NO_THROW({
        eventQueue.waitEvent(); // pop libConnected form queue
    });
    std::shared_ptr<core::Connection> connection_2;
    EXPECT_NO_THROW({
        connection_2 = std::make_shared<core::Connection>(
            core::Connection::connect(
                reader->getString("Login.user_2_privKey"), 
                reader->getString("Login.solutionId"), 
                getPlatformUrl(reader->getString("Login.instanceUrl"))
            )
        );
    });
    EXPECT_NO_THROW({
        eventQueue.waitEvent(); // pop libConnected form queue
    });
    EXPECT_NO_THROW({
        connection_2->disconnect();
    });
    EXPECT_NO_THROW({
        eventQueue.waitEvent(); // pop libDisconnected form queue
    });
    EXPECT_NO_THROW({
        eventQueue.waitEvent(); // pop libPlatformDisconnected form queue
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

TEST_F(CoreEventTest, subscribeFor_unsubscribeFor) {
    std::vector<std::string> valid_subscriptions;
    EXPECT_NO_THROW({
        valid_subscriptions = connection->subscribeFor({
            connection->buildSubscriptionQuery(  
                core::EventType::USER_ADD,  
                core::EventSelectorType::CONTEXT_ID,  
                reader->getString("Context_1.contextId")  
            )
        });
    });
    std::vector<std::string> invalid_subscriptions;
    EXPECT_NO_THROW({
        invalid_subscriptions = connection->subscribeFor({
            connection->buildSubscriptionQuery(  
                core::EventType::USER_ADD,  
                core::EventSelectorType::CONTEXT_ID,  
                "error"
            )
        });
    });
    EXPECT_NO_THROW({
        connection->unsubscribeFrom({
            valid_subscriptions 
        });
    });
    EXPECT_NO_THROW({
        connection->unsubscribeFrom({
            invalid_subscriptions 
        });
    });
}
