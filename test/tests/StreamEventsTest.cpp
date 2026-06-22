#include <chrono>
#include <string>
#include <thread>
#include <vector>
#include <gtest/gtest.h>
#include "../utils/BaseEndpointEventTest.hpp"
#include <privmx/endpoint/core/Types.hpp>
#include <privmx/endpoint/event/EventApi.hpp>
#include <privmx/endpoint/stream/Events.hpp>
#include <privmx/endpoint/stream/StreamApi.hpp>
#include <privmx/endpoint/stream/StreamApiImpl.hpp>

using namespace privmx::endpoint;
using privmx::test::ScopeExit;

class StreamEventsTest : public privmx::test::BaseEndpointEventTest {
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

    void setUpModuleApis() override {
        eventApi = std::make_shared<event::EventApi>(event::EventApi::create(*connection));
        streamApi = std::make_shared<stream::StreamApi>(
            stream::StreamApi::create(*connection, *eventApi)
        );
    }

    void tearDownModuleApis() override {
        streamApi.reset();
        eventApi.reset();
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

    std::vector<core::UserWithPubKey> usersFor(const StreamClient& user1, const StreamClient& user2) {
        return std::vector<core::UserWithPubKey>{
            core::UserWithPubKey{.userId = user1.userId, .pubKey = user1.pubKey},
            core::UserWithPubKey{.userId = user2.userId, .pubKey = user2.pubKey}
        };
    }

    StreamClient fixtureClient() {
        StreamClient client;
        client.userId = reader->getString("Login.user_1_id");
        client.pubKey = reader->getString("Login.user_1_pubKey");
        client.privKey = reader->getString("Login.user_1_privKey");
        client.connection = connection;
        client.eventApi = eventApi;
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

    std::string createStreamRoomFor(const StreamClient& user1, const StreamClient& user2) {
        return user1.streamApi->createStreamRoom(
            reader->getString("Context_1.contextId"),
            usersFor(user1, user2),
            std::vector<core::UserWithPubKey>{core::UserWithPubKey{.userId = user1.userId, .pubKey = user1.pubKey}},
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

    stream::StreamHandle publishVideoStream(const StreamClient& client, const std::string& streamRoomId) {
        client.streamApi->joinStreamRoom(streamRoomId);
        auto handle = client.streamApi->createStream(streamRoomId);
        client.streamApi->getImpl()->addFakeVideoTrack(handle);
        client.streamApi->publishStream(handle);
        return handle;
    }

    std::vector<stream::StreamSubscription> streamSubscriptionsForPublishedStreams(
        const StreamClient& client,
        const std::string& streamRoomId
    ) {
        std::vector<stream::StreamSubscription> subscriptions;
        auto streamList = client.streamApi->listStreams(streamRoomId);
        for(const auto& streamInfo : streamList) {
            for(const auto& track : streamInfo.tracks) {
                subscriptions.push_back(stream::StreamSubscription{streamInfo.id, track.mid});
            }
        }
        return subscriptions;
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

    std::shared_ptr<event::EventApi> eventApi;
    std::shared_ptr<stream::StreamApi> streamApi;
};

TEST_F(StreamEventsTest, waitEvent_getEvent_streamRoomCreated_two_users) {
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
        std::vector<core::UserWithPubKey>{core::UserWithPubKey{.userId = user1.userId, .pubKey = user1.pubKey}},
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


TEST_F(StreamEventsTest, waitEvent_getEvent_streamRoomUpdated) {
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
        std::vector<core::UserWithPubKey>{core::UserWithPubKey{.userId = user1.userId, .pubKey = user1.pubKey}},
        core::Buffer::from("public-updated"),
        core::Buffer::from("private-updated"),
        1,
        false,
        false,
        std::nullopt
    );
    auto eventHolder = waitForEvent("streamRoomUpdated", {user1.connection->getConnectionId(), user2.connection->getConnectionId()});
    ASSERT_TRUE(eventHolder.has_value());
    assertEventBasics(eventHolder.value(), "streamRoomUpdated");
    ASSERT_TRUE(stream::Events::isStreamRoomUpdatedEvent(eventHolder.value()));
    EXPECT_EQ(stream::Events::extractStreamRoomUpdatedEvent(eventHolder.value()).data.streamRoomId, streamRoomId);
}

TEST_F(StreamEventsTest, waitEvent_getEvent_streamRoomDeleted) {
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

TEST_F(StreamEventsTest, waitEvent_getEvent_streamRoomJoined) {
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

    user2.streamApi->joinStreamRoom(streamRoomId);
    auto eventHolder = waitForEvent("streamRoomJoined", {user1.connection->getConnectionId(), user2.connection->getConnectionId()});
    ASSERT_TRUE(eventHolder.has_value());
    assertEventBasics(eventHolder.value(), "streamRoomJoined");
    ASSERT_TRUE(stream::Events::isStreamRoomJoinedEvent(eventHolder.value()));
    EXPECT_EQ(stream::Events::extractStreamRoomJoinedEvent(eventHolder.value()).data.streamRoomId, streamRoomId);
    EXPECT_EQ(stream::Events::extractStreamRoomJoinedEvent(eventHolder.value()).data.userId, user2.userId);
}

TEST_F(StreamEventsTest, waitEvent_getEvent_streamRoomLeft) {
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
    user2.streamApi->joinStreamRoom(streamRoomId);
    drainEventQueue();

    user2.streamApi->leaveStreamRoom(streamRoomId);
    auto eventHolder = waitForEvent("streamRoomLeft", {user1.connection->getConnectionId()});
    ASSERT_TRUE(eventHolder.has_value());
    assertEventBasics(eventHolder.value(), "streamRoomLeft");
    ASSERT_TRUE(stream::Events::isStreamRoomLeftEvent(eventHolder.value()));
    EXPECT_EQ(stream::Events::extractStreamRoomLeftEvent(eventHolder.value()).data.streamRoomId, streamRoomId);
    EXPECT_EQ(stream::Events::extractStreamRoomLeftEvent(eventHolder.value()).data.userId, user2.userId);
}

TEST_F(StreamEventsTest, waitEvent_getEvent_streamPublished) {
    eventQueue.waitEvent();
    auto user1 = fixtureClient();
    auto user2 = user2Client();
    auto streamRoomId = createStreamRoomFor(user1, user2);
    ScopeExit cleanup([&user2]() { user2.disconnect(); });
    auto publishQuery = user1.streamApi->buildSubscriptionQuery(
        stream::EventType::STREAM_PUBLISH,
        stream::EventSelectorType::STREAMROOM_ID,
        streamRoomId
    );
    user1.streamApi->subscribeFor({publishQuery});
    user2.streamApi->subscribeFor({publishQuery});
    drainEventQueue();

    auto handle = publishVideoStream(user2, streamRoomId);
    (void)handle;
    auto eventHolder = waitForEvent("streamPublished", {user1.connection->getConnectionId(), user2.connection->getConnectionId()});
    ASSERT_TRUE(eventHolder.has_value());
    assertEventBasics(eventHolder.value(), "streamPublished");
    ASSERT_TRUE(stream::Events::isStreamPublishedEvent(eventHolder.value()));
    EXPECT_EQ(stream::Events::extractStreamPublishedEvent(eventHolder.value()).data.streamRoomId, streamRoomId);
}

TEST_F(StreamEventsTest, waitEvent_getEvent_streamUpdated) {
    eventQueue.waitEvent();
    auto user1 = fixtureClient();
    auto user2 = user2Client();
    auto streamRoomId = createStreamRoomFor(user1, user2);
    ScopeExit cleanup([&user2]() { user2.disconnect(); });
    auto updateQuery = user1.streamApi->buildSubscriptionQuery(
        stream::EventType::STREAM_UPDATE,
        stream::EventSelectorType::STREAMROOM_ID,
        streamRoomId
    );
    user1.streamApi->subscribeFor({updateQuery});
    user2.streamApi->subscribeFor({updateQuery});
    auto handle = publishVideoStream(user1, streamRoomId);
    drainEventQueue();

    user1.streamApi->getImpl()->addFakeVideoTrack(handle);
    user1.streamApi->updateStream(handle);
    auto eventHolder = waitForEvent("streamUpdated", {user1.connection->getConnectionId(), user2.connection->getConnectionId()});
    ASSERT_TRUE(eventHolder.has_value());
    assertEventBasics(eventHolder.value(), "streamUpdated");
    ASSERT_TRUE(stream::Events::isStreamUpdatedEvent(eventHolder.value()));
    auto updated = stream::Events::extractStreamUpdatedEvent(eventHolder.value());
    EXPECT_EQ(updated.data.streamRoomId, streamRoomId);
    EXPECT_GT(updated.data.streamId, 0);
    EXPECT_FALSE(updated.data.userId.empty());
}

TEST_F(StreamEventsTest, waitEvent_getEvent_streamUnpublished) {
    eventQueue.waitEvent();
    auto user1 = fixtureClient();
    auto user2 = user2Client();
    auto streamRoomId = createStreamRoomFor(user1, user2);
    ScopeExit cleanup([&user2]() { user2.disconnect(); });
    auto unpublishQuery = user1.streamApi->buildSubscriptionQuery(
        stream::EventType::STREAM_UNPUBLISH,
        stream::EventSelectorType::STREAMROOM_ID,
        streamRoomId
    );
    user1.streamApi->subscribeFor({unpublishQuery});
    user2.streamApi->subscribeFor({unpublishQuery});
    auto handle = publishVideoStream(user1, streamRoomId);
    drainEventQueue();

    user1.streamApi->removeStream(handle);
    auto eventHolder = waitForEvent("streamUnpublished", {user1.connection->getConnectionId(), user2.connection->getConnectionId()});
    ASSERT_TRUE(eventHolder.has_value());
    assertEventBasics(eventHolder.value(), "streamUnpublished");
    ASSERT_TRUE(stream::Events::isStreamUnpublishedEvent(eventHolder.value()));
    EXPECT_EQ(stream::Events::extractStreamUnpublishedEvent(eventHolder.value()).data.streamRoomId, streamRoomId);
    EXPECT_GT(stream::Events::extractStreamUnpublishedEvent(eventHolder.value()).data.streamId, 0);
}

TEST_F(StreamEventsTest, waitEvent_getEvent_streamSubscribed) {
    eventQueue.waitEvent();
    auto user1 = fixtureClient();
    auto user2 = user2Client();
    auto streamRoomId = createStreamRoomFor(user1, user2);
    ScopeExit cleanup([&user2]() { user2.disconnect(); });
    auto subscribeQuery = user1.streamApi->buildSubscriptionQuery(
        stream::EventType::STREAM_SUBSCRIBE,
        stream::EventSelectorType::STREAMROOM_ID,
        streamRoomId
    );
    user1.streamApi->subscribeFor({subscribeQuery});
    user2.streamApi->subscribeFor({subscribeQuery});
    auto handle = publishVideoStream(user1, streamRoomId);
    user2.streamApi->joinStreamRoom(streamRoomId);
    auto feedSubscriptions = streamSubscriptionsForPublishedStreams(user2, streamRoomId);
    ASSERT_FALSE(feedSubscriptions.empty());
    drainEventQueue();
    user2.streamApi->createSubscriberStream(streamRoomId, feedSubscriptions);
    auto eventHolder = waitForEvent("streamSubscribed", {user1.connection->getConnectionId(), user2.connection->getConnectionId()});
    ASSERT_TRUE(eventHolder.has_value());
    assertEventBasics(eventHolder.value(), "streamSubscribed");
    ASSERT_TRUE(stream::Events::isStreamSubscribedEvent(eventHolder.value()));
    auto subscribed = stream::Events::extractStreamSubscribedEvent(eventHolder.value());
    EXPECT_EQ(subscribed.data.streamRoomId, streamRoomId);
    EXPECT_EQ(subscribed.data.userId, user2.userId);
    EXPECT_FALSE(subscribed.data.subscriptions.empty());

    EXPECT_NO_THROW({ user1.streamApi->leaveStreamRoom(streamRoomId); });
    (void)handle;
}

TEST_F(StreamEventsTest, waitEvent_getEvent_streamUnsubscribed) {
    eventQueue.waitEvent();
    auto user1 = fixtureClient();
    auto user2 = user2Client();
    auto streamRoomId = createStreamRoomFor(user1, user2);
    ScopeExit cleanup([&user2]() { user2.disconnect(); });
    auto handle = publishVideoStream(user1, streamRoomId);
    user2.streamApi->joinStreamRoom(streamRoomId);
    auto feedSubscriptions = streamSubscriptionsForPublishedStreams(user2, streamRoomId);
    ASSERT_FALSE(feedSubscriptions.empty());
    auto subscriberHandle = user2.streamApi->createSubscriberStream(streamRoomId, feedSubscriptions);

    auto unsubscribeQuery = user1.streamApi->buildSubscriptionQuery(
        stream::EventType::STREAM_UNSUBSCRIBE,
        stream::EventSelectorType::STREAMROOM_ID,
        streamRoomId
    );
    user1.streamApi->subscribeFor({unsubscribeQuery});
    user2.streamApi->subscribeFor({unsubscribeQuery});
    drainEventQueue();

    user2.streamApi->removeSubscriberStream(subscriberHandle);
    auto eventHolder = waitForEvent("streamUnsubscribed", {user1.connection->getConnectionId(), user2.connection->getConnectionId()});
    ASSERT_TRUE(eventHolder.has_value());
    assertEventBasics(eventHolder.value(), "streamUnsubscribed");
    ASSERT_TRUE(stream::Events::isStreamUnsubscribedEvent(eventHolder.value()));
    auto unsubscribed = stream::Events::extractStreamUnsubscribedEvent(eventHolder.value());
    EXPECT_EQ(unsubscribed.data.streamRoomId, streamRoomId);
    EXPECT_EQ(unsubscribed.data.userId, user2.userId);
    EXPECT_FALSE(unsubscribed.data.subscriptions.empty());

    EXPECT_NO_THROW({ user1.streamApi->leaveStreamRoom(streamRoomId); });
    (void)handle;
}

TEST_F(StreamEventsTest, waitEvent_getEvent_streamRoomCreated_disabled) {
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

    EXPECT_NO_THROW({
        createStreamRoomFor(user1, user2);
    });
    EXPECT_NO_THROW({ assertNoEventReceived(); });
}

TEST_F(StreamEventsTest, waitEvent_getEvent_streamRoomUpdated_disabled) {
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
            std::vector<core::UserWithPubKey>{core::UserWithPubKey{.userId = user1.userId, .pubKey = user1.pubKey}},
            core::Buffer::from("public"),
            core::Buffer::from("private"),
            1, false, false, std::nullopt
        );
    });
    EXPECT_NO_THROW({ assertNoEventReceived(); });
}

TEST_F(StreamEventsTest, waitEvent_getEvent_streamRoomDeleted_disabled) {
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

    EXPECT_NO_THROW({
        user1.streamApi->deleteStreamRoom(streamRoomId);
    });
    EXPECT_NO_THROW({ assertNoEventReceived(); });
}

TEST_F(StreamEventsTest, waitEvent_getEvent_streamPublished_disabled) {
    auto user1 = fixtureClient();
    auto user2 = user2Client();
    ScopeExit cleanup([&user2]() { user2.disconnect(); });
    auto streamRoomId = createStreamRoomFor(user1, user2);
    drainEventQueue();
    EXPECT_NO_THROW({
        auto tmp = user1.streamApi->subscribeFor({
            user1.streamApi->buildSubscriptionQuery(
                stream::EventType::STREAM_PUBLISH,
                stream::EventSelectorType::STREAMROOM_ID,
                streamRoomId
            )
        });
        user1.streamApi->unsubscribeFrom(tmp);
    });

    EXPECT_NO_THROW({
        publishVideoStream(user1, streamRoomId);
    });
    EXPECT_NO_THROW({ assertNoEventReceived(); });
    EXPECT_NO_THROW({
        user1.streamApi->leaveStreamRoom(streamRoomId);
    });
}

TEST_F(StreamEventsTest, streamPublished_emitted_again_after_republish) {
    eventQueue.waitEvent();
    auto user1 = fixtureClient();   
    auto user2 = user2Client();     
    auto streamRoomId = createStreamRoomFor(user1, user2);
    ScopeExit cleanup([&user2]() { user2.disconnect(); });

    auto publishQuery = user1.streamApi->buildSubscriptionQuery(
        stream::EventType::STREAM_PUBLISH,
        stream::EventSelectorType::STREAMROOM_ID,
        streamRoomId
    );
    user1.streamApi->subscribeFor({publishQuery});
    drainEventQueue();

    auto countPublished = [&](std::chrono::milliseconds window) {
        int count = 0;
        const auto deadline = std::chrono::steady_clock::now() + window;
        while(std::chrono::steady_clock::now() < deadline) {
            auto holder = waitForNextEvent(std::chrono::milliseconds(300));
            if(!holder.has_value()) continue;
            auto event = holder.value().get();
            if(event != nullptr && event->type == "streamPublished" &&
               stream::Events::isStreamPublishedEvent(holder.value()) &&
               stream::Events::extractStreamPublishedEvent(holder.value()).data.streamRoomId == streamRoomId) {
                ++count;
            }
        }
        return count;
    };

    user2.streamApi->joinStreamRoom(streamRoomId);
    auto handle1 = user2.streamApi->createStream(streamRoomId);
    user2.streamApi->getImpl()->addFakeVideoTrack(handle1);
    user2.streamApi->publishStream(handle1);
    EXPECT_EQ(countPublished(std::chrono::seconds(8)), 1);

    user2.streamApi->removeStream(handle1);
    std::this_thread::sleep_for(std::chrono::milliseconds(500));
    drainEventQueue();
    EXPECT_NO_THROW({
        auto handle2 = user2.streamApi->createStream(streamRoomId);
        user2.streamApi->getImpl()->addFakeVideoTrack(handle2);
        user2.streamApi->publishStream(handle2);
    });
    EXPECT_EQ(countPublished(std::chrono::seconds(8)), 1);
    EXPECT_NO_THROW({ user2.streamApi->leaveStreamRoom(streamRoomId); });
}
