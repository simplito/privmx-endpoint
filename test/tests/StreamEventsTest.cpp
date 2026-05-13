#include <chrono>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <thread>
#include <vector>
#include <gtest/gtest.h>
#include "../utils/BaseTest.hpp"
#include <Poco/Util/IniFileConfiguration.h>
#include <privmx/endpoint/core/Connection.hpp>
#include <privmx/endpoint/core/EventQueue.hpp>
#include <privmx/endpoint/core/EventQueueImpl.hpp>
#include <privmx/endpoint/core/Types.hpp>
#include <privmx/endpoint/event/EventApi.hpp>
#include <privmx/endpoint/stream/Events.hpp>
#include <privmx/endpoint/stream/StreamApi.hpp>

using namespace privmx::endpoint;

class ScopeExit {
public:
    explicit ScopeExit(std::function<void()> callback) : _callback(std::move(callback)) {}

    ~ScopeExit() {
        if(_callback) {
            _callback();
        }
    }

private:
    std::function<void()> _callback;
};

class StreamEventsTest : public privmx::test::BaseTest {
protected:
    struct StreamClient {
        std::string userId;
        std::string pubKey;
        std::string privKey;
        std::shared_ptr<core::Connection> connection;
        std::shared_ptr<event::EventApi> eventApi;
        std::shared_ptr<stream::StreamApi> streamApi;
        bool ownsConnection = true;

        void disconnect() {
            if(ownsConnection && connection) {
                connection->disconnect();
            }
            streamApi.reset();
            eventApi.reset();
            connection.reset();
        }
    };

    struct StreamRoomCreatedEventTriggerResult {
        StreamClient user1;
        StreamClient user2;
        std::string streamRoomId;
    };

    StreamEventsTest() : BaseTest(privmx::test::BaseTestMode::online) {}

    void customSetUp() override {
        reader = new Poco::Util::IniFileConfiguration(INI_FILE_PATH);
        connection = std::make_shared<core::Connection>(
            core::Connection::connect(
                reader->getString("Login.user_1_privKey"),
                reader->getString("Login.solutionId"),
                getPlatformUrl(reader->getString("Login.instanceUrl"))
            )
        );
        eventApi = std::make_shared<event::EventApi>(event::EventApi::create(*connection));
        streamApi = std::make_shared<stream::StreamApi>(
            stream::StreamApi::create(
                *connection,
                *eventApi
            )
        );
    }

    void customTearDown() override {
        streamApi.reset();
        eventApi.reset();
        connection.reset();
        reader.reset();
        core::EventQueueImpl::getInstance()->clear();
    }

    StreamClient createClient(const std::string& userId, const std::string& pubKey, const std::string& privKey) {
        StreamClient client;
        client.userId = userId;
        client.pubKey = pubKey;
        client.privKey = privKey;
        client.connection = std::make_shared<core::Connection>(
            core::Connection::connect(
                privKey,
                reader->getString("Login.solutionId"),
                getPlatformUrl(reader->getString("Login.instanceUrl"))
            )
        );

        client.eventApi = std::make_shared<event::EventApi>(
            event::EventApi::create(*client.connection)
        );

        client.streamApi = std::make_shared<stream::StreamApi>(
            stream::StreamApi::create(*client.connection, *client.eventApi)
        );

        return client;
    }

    std::optional<core::EventHolder> waitForNextEvent(const std::chrono::milliseconds& timeout) {
        const auto deadline = std::chrono::steady_clock::now() + timeout;
        while(std::chrono::steady_clock::now() < deadline) {
            auto eventHolder = eventQueue.getEvent();
            if(eventHolder.has_value()) {
                return eventHolder;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
        return std::nullopt;
    }

    void drainEventQueue(const std::chrono::milliseconds& quietPeriod = std::chrono::milliseconds(300)) {
        const auto deadline = std::chrono::steady_clock::now() + quietPeriod;
        while(std::chrono::steady_clock::now() < deadline) {
            if(eventQueue.getEvent().has_value()) {
                continue;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
        }
    }

    void assertStreamRoomCreatedEvent(
        const core::EventHolder& eventHolder,
        const StreamClient& client,
        const std::string& streamRoomId
    ) {
        auto event = eventHolder.get();
        ASSERT_NE(event, nullptr);
        EXPECT_EQ(event->connectionId, client.connection->getConnectionId());
        EXPECT_EQ(event->type, "streamRoomCreated");
        EXPECT_EQ(event->channel, "stream");

        ASSERT_TRUE(stream::Events::isStreamRoomCreatedEvent(eventHolder));
        auto streamRoomCreated = stream::Events::extractStreamRoomCreatedEvent(eventHolder);
        EXPECT_EQ(streamRoomCreated.data.streamRoomId, streamRoomId);
        EXPECT_EQ(streamRoomCreated.data.contextId, reader->getString("Context_1.contextId"));
    }

    std::shared_ptr<core::Connection> connection;
    std::shared_ptr<event::EventApi> eventApi;
    std::shared_ptr<stream::StreamApi> streamApi;
    core::EventQueue eventQueue = core::EventQueue::getInstance();
    Poco::Util::IniFileConfiguration::Ptr reader;
};

TEST_F(StreamEventsTest, waitEvent_getEvent_streamRoomCreated_two_users) {
    EXPECT_NO_THROW({
        eventQueue.waitEvent(); // pop fixture libConnected from queue
    });

    auto triggerStreamRoomCreatedEvent = [&]() -> std::optional<StreamRoomCreatedEventTriggerResult> {
        StreamRoomCreatedEventTriggerResult result;
        result.user1.userId = reader->getString("Login.user_1_id");
        result.user1.pubKey = reader->getString("Login.user_1_pubKey");
        result.user1.privKey = reader->getString("Login.user_1_privKey");
        result.user1.connection = connection;
        result.user1.eventApi = eventApi;
        result.user1.streamApi = streamApi;
        result.user1.ownsConnection = false;
        result.user2 = createClient(
            reader->getString("Login.user_2_id"),
            reader->getString("Login.user_2_pubKey"),
            reader->getString("Login.user_2_privKey")
        );

        drainEventQueue();

        auto subscriptionQuery = result.user1.streamApi->buildSubscriptionQuery(
            stream::EventType::STREAMROOM_CREATE,
            stream::EventSelectorType::CONTEXT_ID,
            reader->getString("Context_1.contextId")
        );
        result.user1.streamApi->subscribeFor({subscriptionQuery});
        result.user2.streamApi->subscribeFor({subscriptionQuery});

        result.streamRoomId = result.user1.streamApi->createStreamRoom(
            reader->getString("Context_1.contextId"),
            std::vector<core::UserWithPubKey>{
                core::UserWithPubKey{
                    .userId = result.user1.userId,
                    .pubKey = result.user1.pubKey
                },
                core::UserWithPubKey{
                    .userId = result.user2.userId,
                    .pubKey = result.user2.pubKey
                }
            },
            std::vector<core::UserWithPubKey>{
                core::UserWithPubKey{
                    .userId = result.user1.userId,
                    .pubKey = result.user1.pubKey
                }
            },
            core::Buffer::from("public"),
            core::Buffer::from("private"),
            std::nullopt
        );

        return result;
    };

    std::optional<StreamRoomCreatedEventTriggerResult> triggerResult;
    EXPECT_NO_THROW({
        triggerResult = triggerStreamRoomCreatedEvent();
    });
    ASSERT_TRUE(triggerResult.has_value());
    ASSERT_FALSE(triggerResult.value().streamRoomId.empty());
    ScopeExit cleanup([&triggerResult]() {
        triggerResult.value().user1.disconnect();
        triggerResult.value().user2.disconnect();
    });

    std::optional<core::EventHolder> user1Event;
    std::optional<core::EventHolder> user2Event;
    const auto user1ConnectionId = triggerResult.value().user1.connection->getConnectionId();
    const auto user2ConnectionId = triggerResult.value().user2.connection->getConnectionId();
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(10);

    while(std::chrono::steady_clock::now() < deadline && (!user1Event.has_value() || !user2Event.has_value())) {
        auto eventHolder = waitForNextEvent(std::chrono::milliseconds(500));
        if(!eventHolder.has_value()) {
            continue;
        }
        auto event = eventHolder.value().get();
        if(event == nullptr || event->type != "streamRoomCreated") {
            continue;
        }
        if(event->connectionId == user1ConnectionId && !user1Event.has_value()) {
            user1Event = eventHolder;
        } else if(event->connectionId == user2ConnectionId && !user2Event.has_value()) {
            user2Event = eventHolder;
        }
    }

    ASSERT_TRUE(user1Event.has_value()) << "User 1 did not receive streamRoomCreated";
    assertStreamRoomCreatedEvent(
        user1Event.value(),
        triggerResult.value().user1,
        triggerResult.value().streamRoomId
    );

    ASSERT_TRUE(user2Event.has_value()) << "User 2 did not receive streamRoomCreated";
    assertStreamRoomCreatedEvent(
        user2Event.value(),
        triggerResult.value().user2,
        triggerResult.value().streamRoomId
    );
}
