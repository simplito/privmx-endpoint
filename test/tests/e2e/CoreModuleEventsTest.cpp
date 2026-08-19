
#include "../../utils/BaseEndpointEventTest.hpp"
#include <privmx/endpoint/core/Exception.hpp>
#include <privmx/crypto/Crypto.hpp>
#include <privmx/endpoint/core/VarSerializer.hpp>

using namespace privmx::endpoint;

class CoreEventTest : public privmx::test::BaseEndpointEventTest {
};

TEST_F(CoreEventTest, getEvent_libConnected) {
    eventQueue.waitEvent();
}

TEST_F(CoreEventTest, getEvent_libConnected_different_instances) {
    eventQueue.waitEvent();
    auto connection_2 = std::make_shared<core::Connection>(
        core::Connection::connect(
            reader->getString("Login.user_2_privKey"),
            reader->getString("Login.solutionId"),
            getPlatformUrl(reader->getString("Login.instanceUrl"))
        )
    );
    auto eventHolder = waitForEvent("libConnected", {connection_2->getConnectionId()});
    ASSERT_TRUE(eventHolder.has_value());
    auto event = eventHolder.value().get();
    ASSERT_NE(event, nullptr);
    EXPECT_EQ(event->connectionId, connection_2->getConnectionId());
    EXPECT_EQ(event->type, "libConnected");
    EXPECT_TRUE(core::Events::isLibConnectedEvent(event));
}

TEST_F(CoreEventTest, waitEvent_getEvent_libDisconnected) {
    eventQueue.waitEvent();
    connection->disconnect();
    auto eventHolder = waitForEvent("libDisconnected", {connection->getConnectionId()});
    ASSERT_TRUE(eventHolder.has_value());
    auto event = eventHolder.value().get();
    ASSERT_NE(event, nullptr);
    EXPECT_EQ(event->connectionId, connection->getConnectionId());
    EXPECT_EQ(event->type, "libDisconnected");
    EXPECT_TRUE(core::Events::isLibDisconnectedEvent(event));
}

TEST_F(CoreEventTest, waitEvent_getEvent_ContextUsersStatusChangedEvent_enabled) {
    eventQueue.waitEvent();
    auto connection_2 = std::make_shared<core::Connection>(
        core::Connection::connect(
            reader->getString("Login.user_2_privKey"),
            reader->getString("Login.solutionId"),
            getPlatformUrl(reader->getString("Login.instanceUrl"))
        )
    );
    eventQueue.waitEvent(); // pop libConnected for connection_2
    std::this_thread::sleep_for(std::chrono::milliseconds(1500));
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
    eventQueue.waitEvent(); // pop libDisconnected
    eventQueue.waitEvent(); // pop libPlatformDisconnected
    auto eventHolder = waitForEvent("contextUserStatusChanged", {connection->getConnectionId()});
    ASSERT_TRUE(eventHolder.has_value());
    auto event = eventHolder.value().get();
    ASSERT_NE(event, nullptr);
    EXPECT_EQ(event->connectionId, connection->getConnectionId());
    EXPECT_EQ(event->type, "contextUserStatusChanged");
    EXPECT_EQ(event->channel, "context/userStatus");
    ASSERT_TRUE(core::Events::isContextUsersStatusChangedEvent(event));
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
}

TEST_F(CoreEventTest, waitEvent_getEvent_ContextUsersStatusChangedEvent_disabled) {
    eventQueue.waitEvent();
    auto connection_2 = std::make_shared<core::Connection>(
        core::Connection::connect(
            reader->getString("Login.user_2_privKey"),
            reader->getString("Login.solutionId"),
            getPlatformUrl(reader->getString("Login.instanceUrl"))
        )
    );
    eventQueue.waitEvent(); // pop libConnected for connection_2
    connection_2->disconnect();
    eventQueue.waitEvent(); // pop libDisconnected
    eventQueue.waitEvent(); // pop libPlatformDisconnected
    assertNoEventReceived();
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
