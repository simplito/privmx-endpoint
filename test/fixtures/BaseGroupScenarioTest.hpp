#ifndef _PRIVMXLIB_TEST_BASEGROUPSCENARIOTEST_HPP_
#define _PRIVMXLIB_TEST_BASEGROUPSCENARIOTEST_HPP_

#include <chrono>
#include <functional>
#include <map>
#include <memory>
#include <string>
#include <thread>
#include <gtest/gtest.h>
#include "./BaseGroupTest.hpp"
#include <privmx/endpoint/core/Connection.hpp>
#include <privmx/endpoint/core/EventQueue.hpp>
#include <privmx/endpoint/group/GroupApi.hpp>

/**
 * Shared half of the multi-client group scenarios: fixtures that hold several sessions open at once for the
 * whole test, so each session's key caches carry over the way those scenarios need.
 *
 * A scenario derives its own Client from GroupSession and adds the module apis it drives, which keeps
 * `client.connection` and `client.threadApi` reachable through the one name. The base cannot own the clients
 * without knowing that type, so each scenario keeps its own connectAs() and lifecycle and calls openSession() /
 * closeSession() for the half that is always the same.
 *
 * The event tally lives here because it is what makes this family different: one process-wide queue carries
 * every session's events, and they are counted per (connectionId, type) rather than waited for one at a time.
 * The timeouts below are load-bearing for the long pumpUntil() waits in the scenarios - do not retune them.
 */

namespace privmx {
namespace test {

// The half of one user's live session every group scenario has: the connection, the GroupApi every module api
// is built on, and the key the session was opened with.
struct GroupSession {
    std::shared_ptr<privmx::endpoint::core::Connection> connection;
    std::shared_ptr<privmx::endpoint::group::GroupApi> groupApi;
    std::string privKey;
    int64_t connectionId = 0;
};

class BaseGroupScenarioTest : public BaseGroupIdentityTest {
protected:
    // Opens user_`index`'s session. The GroupApi comes first: every module api but LockApi is built on it, so a
    // caller fills in its own apis after this returns.
    void openSession(GroupSession& session, int index) {
        session.privKey = privKeyOf(index);
        session.connection = connectWith(session.privKey);
        session.groupApi = std::make_shared<privmx::endpoint::group::GroupApi>(
            privmx::endpoint::group::GroupApi::create(*session.connection)
        );
        session.connectionId = session.connection->getConnectionId();
    }

    // Releases what openSession() made. A caller drops its own module apis first: they were built on these.
    void closeSession(GroupSession& session) {
        session.groupApi.reset();
        session.connection.reset();
    }

    void pumpEvents(const std::chrono::milliseconds& budget = std::chrono::milliseconds(500)) {
        const auto deadline = std::chrono::steady_clock::now() + budget;
        while(std::chrono::steady_clock::now() < deadline) {
            auto eventHolder = eventQueue.getEvent();
            if(!eventHolder.has_value()) {
                std::this_thread::sleep_for(std::chrono::milliseconds(25));
                continue;
            }
            auto event = eventHolder.value().get();
            if(event != nullptr) {
                _tally[event->connectionId][event->type]++;
            }
        }
    }

    void pumpUntil(const std::function<bool()>& done, const std::chrono::milliseconds& timeout) {
        const auto deadline = std::chrono::steady_clock::now() + timeout;
        while(std::chrono::steady_clock::now() < deadline && !done()) {
            pumpEvents(std::chrono::milliseconds(250));
        }
    }

    int eventsSeen(const GroupSession& session, const std::string& type) {
        auto byConnection = _tally.find(session.connectionId);
        if(byConnection == _tally.end()) {
            return 0;
        }
        auto counted = byConnection->second.find(type);
        return counted == byConnection->second.end() ? 0 : counted->second;
    }

    privmx::endpoint::core::EventQueue eventQueue = privmx::endpoint::core::EventQueue::getInstance();

private:
    std::map<int64_t, std::map<std::string, int>> _tally;
};

} // test
} // privmx

#endif // _PRIVMXLIB_TEST_BASEGROUPSCENARIOTEST_HPP_
