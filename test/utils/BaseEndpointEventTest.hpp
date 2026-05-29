#ifndef _PRIVMXLIB_TEST_BASEENDPOINTEVENTSTEST_HPP_
#define _PRIVMXLIB_TEST_BASEENDPOINTEVENTSTEST_HPP_

#include <algorithm>
#include <chrono>
#include <map>
#include <memory>
#include <optional>
#include <thread>
#include <vector>
#include <gtest/gtest.h>
#include "./BaseTest.hpp"
#include <Poco/Util/IniFileConfiguration.h>
#include <privmx/endpoint/core/Connection.hpp>
#include <privmx/endpoint/core/EventQueue.hpp>
#include <privmx/endpoint/core/EventQueueImpl.hpp>
#include <privmx/endpoint/core/Types.hpp>

namespace privmx {
namespace test {

class BaseEndpointEventTest : public BaseTest {
protected:
    BaseEndpointEventTest() : BaseTest(BaseTestMode::online) {}

    void customSetUp() override {
        reader = new Poco::Util::IniFileConfiguration(INI_FILE_PATH);
        connection = std::make_shared<privmx::endpoint::core::Connection>(
            privmx::endpoint::core::Connection::connect(
                reader->getString("Login.user_1_privKey"),
                reader->getString("Login.solutionId"),
                getPlatformUrl(reader->getString("Login.instanceUrl"))
            )
        );
        setUpModuleApis();
    }

    void customTearDown() override {
        tearDownModuleApis();
        connection.reset();
        reader.reset();
        privmx::endpoint::core::EventQueueImpl::getInstance()->clear();
    }

    virtual void setUpModuleApis() {}
    virtual void tearDownModuleApis() {}

    std::optional<privmx::endpoint::core::EventHolder> waitForNextEvent(
        const std::chrono::milliseconds& timeout
    ) {
        const auto deadline = std::chrono::steady_clock::now() + timeout;
        while(std::chrono::steady_clock::now() < deadline) {
            auto eventHolder = eventQueue.getEvent();
            if(eventHolder.has_value()) return eventHolder;
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
        return std::nullopt;
    }

    void drainEventQueue(
        const std::chrono::milliseconds& quietPeriod = std::chrono::milliseconds(300)
    ) {
        const auto deadline = std::chrono::steady_clock::now() + quietPeriod;
        while(std::chrono::steady_clock::now() < deadline) {
            if(eventQueue.getEvent().has_value()) continue;
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
        }
    }

    std::map<int64_t, privmx::endpoint::core::EventHolder> waitForEventsCore(
        const std::string& eventType,
        const std::vector<int64_t>& connectionIds,
        bool collectAll,
        size_t maxEvents,
        const std::chrono::milliseconds& timeout
    ) {
        std::map<int64_t, privmx::endpoint::core::EventHolder> results;
        const auto deadline = std::chrono::steady_clock::now() + timeout;
        size_t eventCount = 0;
        while(std::chrono::steady_clock::now() < deadline) {
            bool done = collectAll ? results.size() >= connectionIds.size() : !results.empty();
            if(done) break;
            auto eventHolder = waitForNextEvent(std::chrono::milliseconds(500));
            if(!eventHolder.has_value()) continue;
            if(++eventCount > maxEvents) {
                ADD_FAILURE() << "Exceeded maxEvents limit (" << maxEvents << ") while waiting for '" << eventType << "'";
                break;
            }
            auto event = eventHolder.value().get();
            if(event == nullptr) continue;
            if(event->type != eventType) {
                ADD_FAILURE() << "Received unexpected event type '" << event->type << "' while waiting for '" << eventType << "'";
                break;
            }
            bool connectionMatches = connectionIds.empty() ||
                std::find(connectionIds.begin(), connectionIds.end(), event->connectionId) != connectionIds.end();
            if(!connectionMatches) {
                ADD_FAILURE() << "Received event from unexpected connectionId " << event->connectionId;
                break;
            }
            if(results.find(event->connectionId) == results.end()) {
                results.emplace(event->connectionId, eventHolder.value());
            }
        }
        return results;
    }

    std::optional<privmx::endpoint::core::EventHolder> waitForEvent(
        const std::string& eventType,
        const std::vector<int64_t>& connectionIds,
        const std::chrono::milliseconds& timeout = std::chrono::seconds(10)
    ) {
        auto results = waitForEventsCore(eventType, connectionIds, false, SIZE_MAX, timeout);
        if(results.empty()) return std::nullopt;
        return results.begin()->second;
    }

    std::map<int64_t, privmx::endpoint::core::EventHolder> waitForEvents(
        const std::string& eventType,
        const std::vector<int64_t>& connectionIds,
        size_t maxEvents = 100,
        const std::chrono::milliseconds& timeout = std::chrono::seconds(10)
    ) {
        return waitForEventsCore(eventType, connectionIds, true, maxEvents, timeout);
    }

    void assertNoEventReceived(
        const std::chrono::milliseconds& quietPeriod = std::chrono::milliseconds(1500)
    ) {
        std::this_thread::sleep_for(quietPeriod);
        auto eventHolder = eventQueue.getEvent();
        if(eventHolder.has_value()) {
            auto event = eventHolder.value().get();
            FAIL() << "Expected no event but received type '" << (event ? event->type : "<null>") << "'";
        }
    }

    std::shared_ptr<privmx::endpoint::core::Connection> connection;
    privmx::endpoint::core::EventQueue eventQueue = privmx::endpoint::core::EventQueue::getInstance();
    Poco::Util::IniFileConfiguration::Ptr reader;
};

} // test
} // privmx

#endif // _PRIVMXLIB_TEST_BASEENDPOINTEVENTSTEST_HPP_
