/*
Offline tests of the aggregation, the grace period and the recovery policy which turn the states of a
Stream Room's PeerConnections into the StreamConnectionState the application receives.

The grace period and the attempt limit are shortened here so the tests stay fast. A connection which
reports a recovery as started stands for one the library can renegotiate, one which reports it as not
started stands for a connection whose Stream Room is already gone.
*/

#include <chrono>
#include <condition_variable>
#include <mutex>
#include <string>
#include <thread>
#include <vector>
#include <gtest/gtest.h>
#include <privmx/endpoint/stream/ConnectionStateTracker.hpp>

using namespace privmx::endpoint;

namespace {

constexpr auto GRACE_PERIOD = std::chrono::milliseconds(150);
constexpr int MAX_ATTEMPTS = 2;
const std::string ROOM_ID = "stream_room_1";

class Collector {
public:
    void onStateChanged(const std::string& streamRoomId, stream::StreamConnectionState state) {
        {
            std::lock_guard<std::mutex> lock(_mutex);
            _states.push_back({streamRoomId, state});
        }
        _condition.notify_all();
    }

    void onRecoveryNeeded(const std::string& streamRoomId, const std::string& connectionType) {
        {
            std::lock_guard<std::mutex> lock(_mutex);
            _recoveries.push_back({streamRoomId, connectionType});
        }
        _condition.notify_all();
    }

    bool waitForStates(size_t expectedCount, const std::chrono::milliseconds& timeout) {
        std::unique_lock<std::mutex> lock(_mutex);
        return _condition.wait_for(lock, timeout, [this, expectedCount]() {
            return _states.size() >= expectedCount;
        });
    }

    bool waitForRecoveries(size_t expectedCount, const std::chrono::milliseconds& timeout) {
        std::unique_lock<std::mutex> lock(_mutex);
        return _condition.wait_for(lock, timeout, [this, expectedCount]() {
            return _recoveries.size() >= expectedCount;
        });
    }

    std::vector<std::pair<std::string, stream::StreamConnectionState>> states() const {
        std::lock_guard<std::mutex> lock(_mutex);
        return _states;
    }

    std::vector<std::pair<std::string, std::string>> recoveries() const {
        std::lock_guard<std::mutex> lock(_mutex);
        return _recoveries;
    }

private:
    mutable std::mutex _mutex;
    std::condition_variable _condition;
    std::vector<std::pair<std::string, stream::StreamConnectionState>> _states;
    std::vector<std::pair<std::string, std::string>> _recoveries;
};

std::shared_ptr<stream::ConnectionStateTracker> makeTracker(
    const std::shared_ptr<Collector>& collector,
    bool recoveryStarts = true
) {
    return std::make_shared<stream::ConnectionStateTracker>(
        [collector](const std::string& streamRoomId, stream::StreamConnectionState state) {
            collector->onStateChanged(streamRoomId, state);
        },
        [collector, recoveryStarts](const std::string& streamRoomId, const std::string& connectionType) {
            collector->onRecoveryNeeded(streamRoomId, connectionType);
            return recoveryStarts;
        },
        GRACE_PERIOD, MAX_ATTEMPTS
    );
}

} // namespace

TEST(ConnectionStateTrackerTest, connectingAloneIsNotReported) {
    auto collector = std::make_shared<Collector>();
    auto tracker = makeTracker(collector);

    tracker->setConnectionState(ROOM_ID, "publisher", stream::PeerConnectionConnecting);

    EXPECT_FALSE(collector->waitForStates(1, GRACE_PERIOD * 3));
    EXPECT_TRUE(collector->states().empty());
}

TEST(ConnectionStateTrackerTest, connectedIsReportedImmediately) {
    auto collector = std::make_shared<Collector>();
    auto tracker = makeTracker(collector);

    tracker->setConnectionState(ROOM_ID, "publisher", stream::PeerConnectionConnecting);
    tracker->setConnectionState(ROOM_ID, "publisher", stream::PeerConnectionConnected);

    ASSERT_TRUE(collector->waitForStates(1, GRACE_PERIOD));
    auto states = collector->states();
    ASSERT_EQ(states.size(), 1);
    EXPECT_EQ(states[0].first, ROOM_ID);
    EXPECT_EQ(states[0].second, stream::StreamConnected);
}

TEST(ConnectionStateTrackerTest, flappingDisconnectIsNeitherReportedNorRecovered) {
    auto collector = std::make_shared<Collector>();
    auto tracker = makeTracker(collector);

    tracker->setConnectionState(ROOM_ID, "publisher", stream::PeerConnectionConnected);
    ASSERT_TRUE(collector->waitForStates(1, GRACE_PERIOD));

    // the connection comes back on its own well inside the grace period
    tracker->setConnectionState(ROOM_ID, "publisher", stream::PeerConnectionDisconnected);
    std::this_thread::sleep_for(GRACE_PERIOD / 3);
    tracker->setConnectionState(ROOM_ID, "publisher", stream::PeerConnectionConnected);

    EXPECT_FALSE(collector->waitForStates(2, GRACE_PERIOD * 3));
    EXPECT_EQ(collector->states().size(), 1);
    EXPECT_TRUE(collector->recoveries().empty());
}

TEST(ConnectionStateTrackerTest, failedStartsRecoveryAtOnceAndReportsReconnecting) {
    auto collector = std::make_shared<Collector>();
    auto tracker = makeTracker(collector);

    tracker->setConnectionState(ROOM_ID, "publisher", stream::PeerConnectionConnected);
    ASSERT_TRUE(collector->waitForStates(1, GRACE_PERIOD));

    const auto failedAt = std::chrono::steady_clock::now();
    tracker->setConnectionState(ROOM_ID, "publisher", stream::PeerConnectionFailed);
    ASSERT_TRUE(collector->waitForStates(2, GRACE_PERIOD));
    const auto reportedAfter = std::chrono::steady_clock::now() - failedAt;

    EXPECT_LT(reportedAfter, GRACE_PERIOD);
    EXPECT_EQ(collector->states()[1].second, stream::StreamReconnecting);
    ASSERT_TRUE(collector->waitForRecoveries(1, GRACE_PERIOD));
    EXPECT_EQ(collector->recoveries()[0].second, "publisher");
}

TEST(ConnectionStateTrackerTest, disconnectOutlivingTheGracePeriodStartsRecovery) {
    auto collector = std::make_shared<Collector>();
    auto tracker = makeTracker(collector);

    tracker->setConnectionState(ROOM_ID, "publisher", stream::PeerConnectionConnected);
    ASSERT_TRUE(collector->waitForStates(1, GRACE_PERIOD));

    tracker->setConnectionState(ROOM_ID, "publisher", stream::PeerConnectionDisconnected);

    ASSERT_TRUE(collector->waitForRecoveries(1, GRACE_PERIOD * 5));
    ASSERT_TRUE(collector->waitForStates(2, GRACE_PERIOD * 5));
    EXPECT_EQ(collector->states()[1].second, stream::StreamReconnecting);
}

TEST(ConnectionStateTrackerTest, connectionWhichCannotBeRecoveredIsReportedAsLost) {
    auto collector = std::make_shared<Collector>();
    auto tracker = makeTracker(collector, false);

    tracker->setConnectionState(ROOM_ID, "subscriber", stream::PeerConnectionConnected);
    ASSERT_TRUE(collector->waitForStates(1, GRACE_PERIOD));

    tracker->setConnectionState(ROOM_ID, "subscriber", stream::PeerConnectionFailed);

    ASSERT_TRUE(collector->waitForStates(2, GRACE_PERIOD * 3));
    EXPECT_EQ(collector->states().back().second, stream::StreamLost);
    // the one refused attempt settles it, there is no point in retrying
    EXPECT_EQ(collector->recoveries().size(), 1);
}

TEST(ConnectionStateTrackerTest, recoveryIsGivenUpOnAfterTheAttemptLimit) {
    auto collector = std::make_shared<Collector>();
    auto tracker = makeTracker(collector);

    tracker->setConnectionState(ROOM_ID, "publisher", stream::PeerConnectionConnected);
    ASSERT_TRUE(collector->waitForStates(1, GRACE_PERIOD));

    // the connection never comes back, so every attempt is spent before the Stream Room is given up on
    tracker->setConnectionState(ROOM_ID, "publisher", stream::PeerConnectionFailed);

    ASSERT_TRUE(collector->waitForStates(3, GRACE_PERIOD * 10));
    auto states = collector->states();
    EXPECT_EQ(states[1].second, stream::StreamReconnecting);
    EXPECT_EQ(states[2].second, stream::StreamLost);
    EXPECT_EQ(collector->recoveries().size(), static_cast<size_t>(MAX_ATTEMPTS));
}

TEST(ConnectionStateTrackerTest, roomRecoversBackToConnected) {
    auto collector = std::make_shared<Collector>();
    auto tracker = makeTracker(collector);

    tracker->setConnectionState(ROOM_ID, "publisher", stream::PeerConnectionConnected);
    ASSERT_TRUE(collector->waitForStates(1, GRACE_PERIOD));
    tracker->setConnectionState(ROOM_ID, "publisher", stream::PeerConnectionFailed);
    ASSERT_TRUE(collector->waitForStates(2, GRACE_PERIOD));

    // the ICE restart worked
    tracker->setConnectionState(ROOM_ID, "publisher", stream::PeerConnectionConnected);

    ASSERT_TRUE(collector->waitForStates(3, GRACE_PERIOD));
    EXPECT_EQ(collector->states().back().second, stream::StreamConnected);
}

TEST(ConnectionStateTrackerTest, oneBrokenConnectionDecidesForTheWholeRoom) {
    auto collector = std::make_shared<Collector>();
    auto tracker = makeTracker(collector, false);

    tracker->setConnectionState(ROOM_ID, "publisher", stream::PeerConnectionConnected);
    tracker->setConnectionState(ROOM_ID, "subscriber", stream::PeerConnectionConnected);
    ASSERT_TRUE(collector->waitForStates(1, GRACE_PERIOD));

    // even though the publisher keeps working, the Stream Room is reported as lost
    tracker->setConnectionState(ROOM_ID, "subscriber", stream::PeerConnectionFailed);

    ASSERT_TRUE(collector->waitForStates(2, GRACE_PERIOD * 3));
    EXPECT_EQ(collector->states().back().second, stream::StreamLost);
}

TEST(ConnectionStateTrackerTest, closedConnectionStopsCountingTowardsTheRoom) {
    auto collector = std::make_shared<Collector>();
    auto tracker = makeTracker(collector);

    tracker->setConnectionState(ROOM_ID, "publisher", stream::PeerConnectionConnected);
    tracker->setConnectionState(ROOM_ID, "subscriber", stream::PeerConnectionConnected);
    ASSERT_TRUE(collector->waitForStates(1, GRACE_PERIOD));
    const auto statesAfterConnect = collector->states().size();

    // unpublishing closes the publisher connection, which is no failure of the Stream Room
    tracker->setConnectionState(ROOM_ID, "publisher", stream::PeerConnectionClosed);

    EXPECT_FALSE(collector->waitForStates(statesAfterConnect + 1, GRACE_PERIOD * 3));
    EXPECT_TRUE(collector->recoveries().empty());
}

TEST(ConnectionStateTrackerTest, leavingTheRoomCancelsAPendingRecovery) {
    auto collector = std::make_shared<Collector>();
    auto tracker = makeTracker(collector);

    tracker->setConnectionState(ROOM_ID, "publisher", stream::PeerConnectionConnected);
    ASSERT_TRUE(collector->waitForStates(1, GRACE_PERIOD));

    // leaving the Stream Room while the grace period runs must neither report it nor recover it afterwards
    tracker->setConnectionState(ROOM_ID, "publisher", stream::PeerConnectionDisconnected);
    tracker->forgetRoom(ROOM_ID);

    EXPECT_FALSE(collector->waitForStates(2, GRACE_PERIOD * 3));
    EXPECT_TRUE(collector->recoveries().empty());
}
