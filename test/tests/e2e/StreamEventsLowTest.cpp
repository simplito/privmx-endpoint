#include <chrono>
#include <string>
#include <thread>
#include <vector>
#include <gtest/gtest.h>
#include "../../utils/BaseEndpointEventTest.hpp"
#include <privmx/endpoint/core/Types.hpp>
#include <privmx/endpoint/stream/Events.hpp>
#include <privmx/endpoint/stream/StreamApiLow.hpp>
#include <privmx/endpoint/stream/WebRTCInterface.hpp>

using namespace privmx::endpoint;
using privmx::test::ScopeExit;

// Minimal WebRTC stub — returns empty strings so no real media session is needed.
class FakeWebRTC : public stream::WebRTCInterface {
public:
    virtual std::string createOfferAndSetLocalDescription(
        const std::string& streamRoomId,
        const std::string& connectionType
    ) override {
        return "";
    };
    virtual std::string createAnswerAndSetDescriptions(
        const std::string& streamRoomId,
        const std::string& sdp,
        const std::string& type,
        const std::string& connectionType
    ) override {
        return "";
    };
    virtual void setAnswerAndSetRemoteDescription(
        const std::string& streamRoomId,
        const std::string& sdp,
        const std::string& type,
        const std::string& connectionType
    ) override {
        return;
    };
    virtual void updateSessionId(
        const std::string& streamRoomId,
        const int64_t sessionId,
        const std::string& connectionType
    ) override {
        return;
    };
    virtual void closeAll(const std::string& streamRoomId) override {
        return;
    };
    virtual void close(const std::string& streamRoomId, const std::string& connectionType) override {
        return;
    };
    virtual void updateKeys(const std::string& streamRoomId, const std::vector<stream::Key>& keys) override {
        return;
    };
};

class StreamEventsLowTest : public privmx::test::BaseEndpointEventTest {
protected:
    struct StreamClient {
        std::string userId;
        std::string pubKey;
        std::string privKey;
        std::shared_ptr<core::Connection> connection;
        std::shared_ptr<stream::StreamApiLow> streamApi;
        bool ownsConnection = true;

        void disconnect() {
            if (ownsConnection && connection) {
                connection->disconnect();
            }
            streamApi.reset();
            connection.reset();
        }

        void joinStreamRoom(const std::string& streamRoomId) {
            streamApi->joinStreamRoom(streamRoomId, std::make_shared<FakeWebRTC>());
        }
    };

    void setUpModuleApis() override {
        streamApi = std::make_shared<stream::StreamApiLow>(
            stream::StreamApiLow::create(*connection)
        );
    }

    void tearDownModuleApis() override {
        streamApi.reset();
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
        client.streamApi = std::make_shared<stream::StreamApiLow>(
            stream::StreamApiLow::create(*client.connection)
        );
        return client;
    }

    std::vector<core::UserWithPubKey> usersFor(const StreamClient& u1, const StreamClient& u2) {
        return {
            core::UserWithPubKey{.userId = u1.userId, .pubKey = u1.pubKey},
            core::UserWithPubKey{.userId = u2.userId, .pubKey = u2.pubKey},
        };
    }

    StreamClient fixtureClient() {
        StreamClient client;
        client.userId = reader->getString("Login.user_1_id");
        client.pubKey = reader->getString("Login.user_1_pubKey");
        client.privKey = reader->getString("Login.user_1_privKey");
        client.connection = connection;
        client.streamApi = streamApi;
        client.ownsConnection = false;
        return client;
    }

    StreamClient user2Client() {
        return createClient(
            reader->getString("Login.user_2_id"),
            reader->getString("Login.user_2_pubKey"),
            reader->getString("Login.user_2_privKey")
        );
    }

    std::string createStreamRoomFor(const StreamClient& u1, const StreamClient& u2) {
        return u1.streamApi->createStreamRoom(
            reader->getString("Context_1.contextId"),
            usersFor(u1, u2),
            std::vector<core::UserWithPubKey>{{.userId = u1.userId, .pubKey = u1.pubKey}},
            core::Buffer::from("public"),
            core::Buffer::from("private"),
            std::nullopt
        );
    }

    void assertEventBasics(const core::EventHolder& eventHolder, const std::string& eventType) {
        auto event = eventHolder.get();
        ASSERT_NE(event, nullptr);
        EXPECT_EQ(event->type, eventType);
        EXPECT_EQ(event->channel, "stream");
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

    std::shared_ptr<stream::StreamApiLow> streamApi;
};

// ── StreamRoom lifecycle events ───────────────────────────────────────────────

TEST_F(StreamEventsLowTest, waitEvent_getEvent_streamRoomCreated_two_users) {
    eventQueue.waitEvent();

    auto user1 = fixtureClient();
    auto user2 = user2Client();
    ScopeExit cleanup([&user2]() { user2.disconnect(); });
    drainEventQueue();

    auto subscriptionQuery = user1.streamApi->buildSubscriptionQuery(
        stream::EventType::STREAMROOM_CREATE,
        stream::EventSelectorType::CONTEXT_ID,
        reader->getString("Context_1.contextId")
    );
    user1.streamApi->subscribeFor({subscriptionQuery});
    user2.streamApi->subscribeFor({subscriptionQuery});

    auto streamRoomId = user1.streamApi->createStreamRoom(
        reader->getString("Context_1.contextId"),
        usersFor(user1, user2),
        std::vector<core::UserWithPubKey>{{.userId = user1.userId, .pubKey = user1.pubKey}},
        core::Buffer::from("public"),
        core::Buffer::from("private"),
        std::nullopt
    );
    ASSERT_FALSE(streamRoomId.empty());

    const auto user1ConnectionId = user1.connection->getConnectionId();
    const auto user2ConnectionId = user2.connection->getConnectionId();
    auto events = waitForEvents("streamRoomCreated", {user1ConnectionId, user2ConnectionId}, 2);

    ASSERT_TRUE(events.count(user1ConnectionId)) << "User 1 did not receive streamRoomCreated";
    assertStreamRoomCreatedEvent(events.at(user1ConnectionId), user1, streamRoomId);
    ASSERT_TRUE(events.count(user2ConnectionId)) << "User 2 did not receive streamRoomCreated";
    assertStreamRoomCreatedEvent(events.at(user2ConnectionId), user2, streamRoomId);
}

TEST_F(StreamEventsLowTest, waitEvent_getEvent_streamRoomUpdated) {
    eventQueue.waitEvent();
    auto user1 = fixtureClient();
    auto user2 = user2Client();
    auto streamRoomId = createStreamRoomFor(user1, user2);
    ScopeExit cleanup([&user2]() { user2.disconnect(); });
    auto updateQuery = user1.streamApi->buildSubscriptionQuery(
        stream::EventType::STREAMROOM_UPDATE,
        stream::EventSelectorType::STREAMROOM_ID,
        streamRoomId
    );
    user1.streamApi->subscribeFor({updateQuery});
    user2.streamApi->subscribeFor({updateQuery});
    drainEventQueue();

    user1.streamApi->updateStreamRoom(
        streamRoomId,
        usersFor(user1, user2),
        std::vector<core::UserWithPubKey>{{.userId = user1.userId, .pubKey = user1.pubKey}},
        core::Buffer::from("public-updated"),
        core::Buffer::from("private-updated"),
        1, false, false, std::nullopt
    );
    auto eventHolder = waitForEvent("streamRoomUpdated", {user1.connection->getConnectionId(), user2.connection->getConnectionId()});
    ASSERT_TRUE(eventHolder.has_value());
    assertEventBasics(eventHolder.value(), "streamRoomUpdated");
    ASSERT_TRUE(stream::Events::isStreamRoomUpdatedEvent(eventHolder.value()));
    EXPECT_EQ(stream::Events::extractStreamRoomUpdatedEvent(eventHolder.value()).data.streamRoomId, streamRoomId);
}

TEST_F(StreamEventsLowTest, waitEvent_getEvent_streamRoomDeleted) {
    eventQueue.waitEvent();
    auto user1 = fixtureClient();
    auto user2 = user2Client();
    auto streamRoomId = createStreamRoomFor(user1, user2);
    ScopeExit cleanup([&user2]() { user2.disconnect(); });
    auto deleteQuery = user1.streamApi->buildSubscriptionQuery(
        stream::EventType::STREAMROOM_DELETE,
        stream::EventSelectorType::STREAMROOM_ID,
        streamRoomId
    );
    user1.streamApi->subscribeFor({deleteQuery});
    user2.streamApi->subscribeFor({deleteQuery});
    drainEventQueue();

    user1.streamApi->deleteStreamRoom(streamRoomId);
    auto eventHolder = waitForEvent("streamRoomDeleted", {user1.connection->getConnectionId(), user2.connection->getConnectionId()});
    ASSERT_TRUE(eventHolder.has_value());
    assertEventBasics(eventHolder.value(), "streamRoomDeleted");
    ASSERT_TRUE(stream::Events::isStreamRoomDeletedEvent(eventHolder.value()));
    EXPECT_EQ(stream::Events::extractStreamRoomDeletedEvent(eventHolder.value()).data.streamRoomId, streamRoomId);
}

TEST_F(StreamEventsLowTest, waitEvent_getEvent_streamRoomJoined) {
    eventQueue.waitEvent();
    auto user1 = fixtureClient();
    auto user2 = user2Client();
    auto streamRoomId = createStreamRoomFor(user1, user2);
    ScopeExit cleanup([&user2]() { user2.disconnect(); });
    auto joinQuery = user1.streamApi->buildSubscriptionQuery(
        stream::EventType::STREAMROOM_JOIN,
        stream::EventSelectorType::STREAMROOM_ID,
        streamRoomId
    );
    user1.streamApi->subscribeFor({joinQuery});
    user2.streamApi->subscribeFor({joinQuery});
    drainEventQueue();

    user2.joinStreamRoom(streamRoomId);
    auto eventHolder = waitForEvent("streamRoomJoined", {user1.connection->getConnectionId(), user2.connection->getConnectionId()});
    ASSERT_TRUE(eventHolder.has_value());
    assertEventBasics(eventHolder.value(), "streamRoomJoined");
    ASSERT_TRUE(stream::Events::isStreamRoomJoinedEvent(eventHolder.value()));
    EXPECT_EQ(stream::Events::extractStreamRoomJoinedEvent(eventHolder.value()).data.streamRoomId, streamRoomId);
    EXPECT_EQ(stream::Events::extractStreamRoomJoinedEvent(eventHolder.value()).data.userId, user2.userId);
}

TEST_F(StreamEventsLowTest, waitEvent_getEvent_streamRoomLeft) {
    eventQueue.waitEvent();
    auto user1 = fixtureClient();
    auto user2 = user2Client();
    auto streamRoomId = createStreamRoomFor(user1, user2);
    ScopeExit cleanup([&user2]() { user2.disconnect(); });
    auto leaveQuery = user1.streamApi->buildSubscriptionQuery(
        stream::EventType::STREAMROOM_LEAVE,
        stream::EventSelectorType::STREAMROOM_ID,
        streamRoomId
    );
    user1.streamApi->subscribeFor({leaveQuery});
    user2.streamApi->subscribeFor({leaveQuery});
    user2.joinStreamRoom(streamRoomId);
    drainEventQueue();

    user2.streamApi->leaveStreamRoom(streamRoomId);
    auto eventHolder = waitForEvent("streamRoomLeft", {user1.connection->getConnectionId()});
    ASSERT_TRUE(eventHolder.has_value());
    assertEventBasics(eventHolder.value(), "streamRoomLeft");
    ASSERT_TRUE(stream::Events::isStreamRoomLeftEvent(eventHolder.value()));
    EXPECT_EQ(stream::Events::extractStreamRoomLeftEvent(eventHolder.value()).data.streamRoomId, streamRoomId);
    EXPECT_EQ(stream::Events::extractStreamRoomLeftEvent(eventHolder.value()).data.userId, user2.userId);
}

TEST_F(StreamEventsLowTest, waitEvent_getEvent_streamRoomCreated_disabled) {
    auto user1 = fixtureClient();
    auto user2 = user2Client();
    ScopeExit cleanup([&user2]() { user2.disconnect(); });
    drainEventQueue();
    EXPECT_NO_THROW({
        auto tmp = user1.streamApi->subscribeFor({
            user1.streamApi->buildSubscriptionQuery(
                stream::EventType::STREAMROOM_CREATE,
                stream::EventSelectorType::CONTEXT_ID,
                reader->getString("Context_1.contextId")
            )
        });
        user1.streamApi->unsubscribeFrom(tmp);
    });
    EXPECT_NO_THROW({ createStreamRoomFor(user1, user2); });
    EXPECT_NO_THROW({ assertNoEventReceived(); });
}

TEST_F(StreamEventsLowTest, waitEvent_getEvent_streamRoomUpdated_disabled) {
    auto user1 = fixtureClient();
    auto user2 = user2Client();
    ScopeExit cleanup([&user2]() { user2.disconnect(); });
    auto streamRoomId = createStreamRoomFor(user1, user2);
    drainEventQueue();
    EXPECT_NO_THROW({
        auto tmp = user1.streamApi->subscribeFor({
            user1.streamApi->buildSubscriptionQuery(
                stream::EventType::STREAMROOM_UPDATE,
                stream::EventSelectorType::STREAMROOM_ID,
                streamRoomId
            )
        });
        user1.streamApi->unsubscribeFrom(tmp);
    });
    EXPECT_NO_THROW({
        user1.streamApi->updateStreamRoom(
            streamRoomId,
            usersFor(user1, user2),
            std::vector<core::UserWithPubKey>{{.userId = user1.userId, .pubKey = user1.pubKey}},
            core::Buffer::from("public"),
            core::Buffer::from("private"),
            1, false, false, std::nullopt
        );
    });
    EXPECT_NO_THROW({ assertNoEventReceived(); });
}

TEST_F(StreamEventsLowTest, waitEvent_getEvent_streamRoomDeleted_disabled) {
    auto user1 = fixtureClient();
    auto user2 = user2Client();
    ScopeExit cleanup([&user2]() { user2.disconnect(); });
    auto streamRoomId = createStreamRoomFor(user1, user2);
    drainEventQueue();
    EXPECT_NO_THROW({
        auto tmp = user1.streamApi->subscribeFor({
            user1.streamApi->buildSubscriptionQuery(
                stream::EventType::STREAMROOM_DELETE,
                stream::EventSelectorType::STREAMROOM_ID,
                streamRoomId
            )
        });
        user1.streamApi->unsubscribeFrom(tmp);
    });
    EXPECT_NO_THROW({ user1.streamApi->deleteStreamRoom(streamRoomId); });
    EXPECT_NO_THROW({ assertNoEventReceived(); });
}

// ── Diagnostic tests: isolate Bindings-vs-C++ failures ─────────────────────────────

TEST_F(StreamEventsLowTest, joinStreamRoom_second_join_throws) {
    auto user1 = fixtureClient();
    auto user2 = user2Client();
    ScopeExit cleanup([&user2]() { user2.disconnect(); });

    auto streamRoomId = createStreamRoomFor(user1, user2);

    EXPECT_NO_THROW({ user1.joinStreamRoom(streamRoomId); });
    EXPECT_THROW({ user1.joinStreamRoom(streamRoomId); }, core::Exception);
}

TEST_F(StreamEventsLowTest, subscribeFor_stream_subscribe_eventtype_noThrow) {
    auto user1 = fixtureClient();
    auto user2 = user2Client();
    ScopeExit cleanup([&user2]() { user2.disconnect(); });

    auto streamRoomId = createStreamRoomFor(user1, user2);

    EXPECT_NO_THROW({
        auto ids = user1.streamApi->subscribeFor({
            user1.streamApi->buildSubscriptionQuery(
                stream::EventType::STREAM_SUBSCRIBE,
                stream::EventSelectorType::STREAMROOM_ID,
                streamRoomId
            )
        });
        user1.streamApi->unsubscribeFrom(ids);
    });
}

TEST_F(StreamEventsLowTest, subscribeFor_stream_unsubscribe_eventtype_noThrow) {
    auto user1 = fixtureClient();
    auto user2 = user2Client();
    ScopeExit cleanup([&user2]() { user2.disconnect(); });

    auto streamRoomId = createStreamRoomFor(user1, user2);

    EXPECT_NO_THROW({
        auto ids = user1.streamApi->subscribeFor({
            user1.streamApi->buildSubscriptionQuery(
                stream::EventType::STREAM_UNSUBSCRIBE,
                stream::EventSelectorType::STREAMROOM_ID,
                streamRoomId
            )
        });
        user1.streamApi->unsubscribeFrom(ids);
    });
}

TEST_F(StreamEventsLowTest, subscribeFor_stream_update_eventtype_noThrow) {
    auto user1 = fixtureClient();
    auto user2 = user2Client();
    ScopeExit cleanup([&user2]() { user2.disconnect(); });

    auto streamRoomId = createStreamRoomFor(user1, user2);

    EXPECT_NO_THROW({
        auto ids = user1.streamApi->subscribeFor({
            user1.streamApi->buildSubscriptionQuery(
                stream::EventType::STREAM_UPDATE,
                stream::EventSelectorType::STREAMROOM_ID,
                streamRoomId
            )
        });
        user1.streamApi->unsubscribeFrom(ids);
    });
}
