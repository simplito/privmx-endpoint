
#include <gtest/gtest.h>
#include <chrono>
#include <thread>
#include <iostream>
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
    auto connection2 = core::Connection::connect(
        reader->getString("Login.user_2_privKey"), 
        reader->getString("Login.solutionId"), 
        getPlatformUrl(reader->getString("Login.instanceUrl"))
    );
    auto eventApi2 = event::EventApi::create(connection2);

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
        EXPECT_EQ(event->type, "libConnected");
    } else {
        FAIL();
    }
    EXPECT_NO_THROW({
        std::optional<core::EventHolder> eventHolder = eventQueue.waitEvent();
        if(eventHolder.has_value()) {
            event = eventHolder.value().get();
        } else {
            event = nullptr;
        }
    });
    if(event != nullptr) {
        EXPECT_EQ(event->type, "libConnected");
    } else {
        FAIL();
    }
    EXPECT_NO_THROW({
        eventApi->subscribeForCustomEvents(reader->getString("Context_1.contextId"), "testing");
        eventApi2.subscribeForCustomEvents(reader->getString("Context_1.contextId"), "testing");
    });
    EXPECT_NO_THROW({
        std::vector<privmx::endpoint::core::UserWithPubKey> users;
        users.push_back(privmx::endpoint::core::UserWithPubKey{.userId=reader->getString("Login.user_1_id"), .pubKey=reader->getString("Login.user_1_pubKey")});
        users.push_back(privmx::endpoint::core::UserWithPubKey{.userId=reader->getString("Login.user_2_id"), .pubKey=reader->getString("Login.user_2_pubKey")});
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
            FAIL();
        }
    });
    EXPECT_NO_THROW({
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
    EXPECT_NO_THROW({
        std::optional<core::EventHolder> eventHolder = eventQueue.getEvent();
        if(eventHolder.has_value()) {
            event = eventHolder.value().get();
        } else {
            event = nullptr;
            FAIL();
        }
    });
    EXPECT_NO_THROW({
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