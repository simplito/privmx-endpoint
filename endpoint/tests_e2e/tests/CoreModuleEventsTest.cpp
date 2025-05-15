
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
        std::string iniFile = std::getenv("INI_FILE_PATH");
        reader = new Poco::Util::IniFileConfiguration(iniFile);
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
