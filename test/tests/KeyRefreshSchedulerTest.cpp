/*
Offline tests of the guard which decides when a Stream Room asks the Bridge for its encryption keys
again after frames or data channel messages failed to decrypt for want of a key.

The cooldown is shortened here so the tests stay fast. The handler stands for the blocking call into
StreamApiLow, so a handler which blocks stands for a refresh still in flight, and a throwing one for a
refresh which failed.
*/

#include <algorithm>
#include <chrono>
#include <condition_variable>
#include <memory>
#include <mutex>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>
#include <gtest/gtest.h>
#include <privmx/endpoint/stream/KeyRefreshScheduler.hpp>

using namespace privmx::endpoint;

namespace {

constexpr auto COOLDOWN = std::chrono::milliseconds(200);
const std::string ROOM_ID = "stream_room_1";
const std::string OTHER_ROOM_ID = "stream_room_2";

class Collector {
public:
    void onRefreshNeeded(const std::string& streamRoomId) {
        {
            std::lock_guard<std::mutex> lock(_mutex);
            _refreshes.push_back(streamRoomId);
            _running++;
        }
        _condition.notify_all();
        if (_blockFor.count() > 0) {
            std::this_thread::sleep_for(_blockFor);
        }
        {
            std::lock_guard<std::mutex> lock(_mutex);
            _running--;
        }
        _condition.notify_all();
        if (_throwing) {
            throw std::runtime_error("refreshing the keys failed");
        }
    }

    bool waitForRefreshes(size_t expectedCount, const std::chrono::milliseconds& timeout) {
        std::unique_lock<std::mutex> lock(_mutex);
        return _condition.wait_for(lock, timeout, [this, expectedCount]() {
            return _refreshes.size() >= expectedCount;
        });
    }

    bool waitUntilIdle(const std::chrono::milliseconds& timeout) {
        std::unique_lock<std::mutex> lock(_mutex);
        return _condition.wait_for(lock, timeout, [this]() { return _running == 0; });
    }

    std::vector<std::string> refreshes() const {
        std::lock_guard<std::mutex> lock(_mutex);
        return _refreshes;
    }

    size_t count() const {
        std::lock_guard<std::mutex> lock(_mutex);
        return _refreshes.size();
    }

    void blockFor(const std::chrono::milliseconds& duration) { _blockFor = duration; }
    void setThrowing(bool throwing) { _throwing = throwing; }

private:
    mutable std::mutex _mutex;
    std::condition_variable _condition;
    std::vector<std::string> _refreshes;
    int _running{0};
    std::chrono::milliseconds _blockFor{0};
    bool _throwing{false};
};

std::shared_ptr<stream::KeyRefreshScheduler> makeScheduler(const std::shared_ptr<Collector>& collector) {
    return std::make_shared<stream::KeyRefreshScheduler>(
        [collector](const std::string& streamRoomId) { collector->onRefreshNeeded(streamRoomId); }, COOLDOWN
    );
}

} // namespace

TEST(KeyRefreshSchedulerTest, firstRequestRefreshes) {
    auto collector = std::make_shared<Collector>();
    auto scheduler = makeScheduler(collector);

    scheduler->requestRefresh(ROOM_ID);

    ASSERT_TRUE(collector->waitForRefreshes(1, std::chrono::seconds(2)));
    EXPECT_EQ(collector->refreshes(), std::vector<std::string>{ROOM_ID});
}

TEST(KeyRefreshSchedulerTest, requestDoesNotBlockTheCaller) {
    auto collector = std::make_shared<Collector>();
    collector->blockFor(std::chrono::milliseconds(500));
    auto scheduler = makeScheduler(collector);

    auto before = std::chrono::steady_clock::now();
    scheduler->requestRefresh(ROOM_ID);
    auto elapsed = std::chrono::steady_clock::now() - before;

    EXPECT_LT(elapsed, std::chrono::milliseconds(100))
        << "the refresh ran on the thread which asked for it";
    ASSERT_TRUE(collector->waitForRefreshes(1, std::chrono::seconds(2)));
}

TEST(KeyRefreshSchedulerTest, requestsAreDroppedWhileOneIsInFlight) {
    auto collector = std::make_shared<Collector>();
    collector->blockFor(std::chrono::milliseconds(400));
    auto scheduler = makeScheduler(collector);

    scheduler->requestRefresh(ROOM_ID);
    ASSERT_TRUE(collector->waitForRefreshes(1, std::chrono::seconds(2)));
    for (int i = 0; i < 20; i++) {
        scheduler->requestRefresh(ROOM_ID);
    }

    ASSERT_TRUE(collector->waitUntilIdle(std::chrono::seconds(3)));
    EXPECT_EQ(collector->count(), 1u);
}

TEST(KeyRefreshSchedulerTest, requestsAreDroppedDuringTheCooldown) {
    auto collector = std::make_shared<Collector>();
    auto scheduler = makeScheduler(collector);

    scheduler->requestRefresh(ROOM_ID);
    ASSERT_TRUE(collector->waitForRefreshes(1, std::chrono::seconds(2)));
    ASSERT_TRUE(collector->waitUntilIdle(std::chrono::seconds(2)));
    scheduler->requestRefresh(ROOM_ID);
    scheduler->requestRefresh(ROOM_ID);

    std::this_thread::sleep_for(COOLDOWN / 2);
    EXPECT_EQ(collector->count(), 1u)
        << "a key the user will never be granted would keep the Bridge busy for as long as the Stream Room is open";
}

TEST(KeyRefreshSchedulerTest, requestIsHonouredAfterTheCooldown) {
    auto collector = std::make_shared<Collector>();
    auto scheduler = makeScheduler(collector);

    scheduler->requestRefresh(ROOM_ID);
    ASSERT_TRUE(collector->waitForRefreshes(1, std::chrono::seconds(2)));
    ASSERT_TRUE(collector->waitUntilIdle(std::chrono::seconds(2)));
    std::this_thread::sleep_for(COOLDOWN * 2);
    scheduler->requestRefresh(ROOM_ID);

    ASSERT_TRUE(collector->waitForRefreshes(2, std::chrono::seconds(2)));
}

TEST(KeyRefreshSchedulerTest, aFailedRefreshDoesNotBlockTheNextOne) {
    auto collector = std::make_shared<Collector>();
    collector->setThrowing(true);
    auto scheduler = makeScheduler(collector);

    scheduler->requestRefresh(ROOM_ID);
    ASSERT_TRUE(collector->waitForRefreshes(1, std::chrono::seconds(2)));
    std::this_thread::sleep_for(COOLDOWN * 2);
    scheduler->requestRefresh(ROOM_ID);

    ASSERT_TRUE(collector->waitForRefreshes(2, std::chrono::seconds(2)))
        << "the in-flight marker was left set by a refresh which threw";
}

TEST(KeyRefreshSchedulerTest, streamRoomsAreThrottledIndependently) {
    auto collector = std::make_shared<Collector>();
    auto scheduler = makeScheduler(collector);

    scheduler->requestRefresh(ROOM_ID);
    scheduler->requestRefresh(OTHER_ROOM_ID);

    ASSERT_TRUE(collector->waitForRefreshes(2, std::chrono::seconds(2)));
    auto refreshes = collector->refreshes();
    EXPECT_NE(std::find(refreshes.begin(), refreshes.end(), ROOM_ID), refreshes.end());
    EXPECT_NE(std::find(refreshes.begin(), refreshes.end(), OTHER_ROOM_ID), refreshes.end());
}

TEST(KeyRefreshSchedulerTest, forgettingARoomClearsItsCooldown) {
    auto collector = std::make_shared<Collector>();
    auto scheduler = makeScheduler(collector);

    scheduler->requestRefresh(ROOM_ID);
    ASSERT_TRUE(collector->waitForRefreshes(1, std::chrono::seconds(2)));
    ASSERT_TRUE(collector->waitUntilIdle(std::chrono::seconds(2)));
    scheduler->forgetRoom(ROOM_ID);
    scheduler->requestRefresh(ROOM_ID);

    ASSERT_TRUE(collector->waitForRefreshes(2, std::chrono::seconds(2)));
}

TEST(KeyRefreshSchedulerTest, destructionWaitsForTheRefreshInFlight) {
    auto collector = std::make_shared<Collector>();
    collector->blockFor(std::chrono::milliseconds(400));
    auto scheduler = makeScheduler(collector);

    scheduler->requestRefresh(ROOM_ID);
    ASSERT_TRUE(collector->waitForRefreshes(1, std::chrono::seconds(2)));
    scheduler.reset();

    EXPECT_TRUE(collector->waitUntilIdle(std::chrono::milliseconds(0)))
        << "the scheduler was destroyed while a refresh was still running";
}
