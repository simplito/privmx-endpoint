#ifndef _PRIVMXLIB_TEST_BASEGROUPTEST_HPP_
#define _PRIVMXLIB_TEST_BASEGROUPTEST_HPP_

#include <memory>
#include <string>
#include <gtest/gtest.h>
#include "./BaseTest.hpp"
#include <Poco/Util/IniFileConfiguration.h>
#include <privmx/endpoint/core/Connection.hpp>
#include <privmx/endpoint/core/EventQueueImpl.hpp>
#include <privmx/endpoint/core/Types.hpp>
#include <privmx/endpoint/group/GroupApi.hpp>

/**
 * Shared lifecycle for the e2e fixtures that exercise Groups against a running bridge.
 *
 * BaseGroupIdentityTest is the half both families need: the dataset ini, the logins it holds, and a connection
 * opened from one of them. It defines no session of its own and leaves customSetUp/customTearDown pure, so a
 * multi-client fixture can derive from it without inheriting a session it does not want - see
 * BaseGroupScenarioTest.hpp.
 *
 * BaseGroupTest is the single-session half: one connection and one GroupApi, swapped by connectAs(). A subclass
 * declares its own module apis and builds them in setUpModuleApis(), which runs on every connect - a container
 * api is bound to the connection it was made from, so a swap that left them behind would hand the test a handle
 * onto a session that is gone.
 *
 * A websocket carries one session per user key, so a fixture that wants its own session for the login the base
 * already holds must disconnect() first.
 *
 * Group creation and container grants stay in the individual test files: what a group is for differs per module.
 */

namespace privmx {
namespace test {

class BaseGroupIdentityTest : public BaseTest {
protected:
    BaseGroupIdentityTest() : BaseTest(BaseTestMode::online) {}

    void openReader() {
        reader = new Poco::Util::IniFileConfiguration(INI_FILE_PATH);
    }

    std::string privKeyOf(int index) {
        return reader->getString("Login.user_" + std::to_string(index) + "_privKey");
    }

    std::string userId(int index) {
        return reader->getString("Login.user_" + std::to_string(index) + "_id");
    }

    // `user_N` as a roster entry - id plus public key, from the same ini.
    privmx::endpoint::core::UserWithPubKey user(int index) {
        const std::string n = std::to_string(index);
        return privmx::endpoint::core::UserWithPubKey{
            .userId = reader->getString("Login.user_" + n + "_id"),
            .pubKey = reader->getString("Login.user_" + n + "_pubKey")
        };
    }

    std::string contextId() {
        return reader->getString("Context_1.contextId");
    }

    // getPlatformUrl answers from BRIDGE_URL and ignores what it is handed; the ini key goes in for the record.
    std::shared_ptr<privmx::endpoint::core::Connection> connectWith(const std::string& privKey) {
        return std::make_shared<privmx::endpoint::core::Connection>(
            privmx::endpoint::core::Connection::connect(
                privKey,
                reader->getString("Login.solutionId"),
                getPlatformUrl(reader->getString("Login.instanceUrl"))
            )
        );
    }

    std::shared_ptr<privmx::endpoint::core::Connection> connect(int index) {
        return connectWith(privKeyOf(index));
    }

    Poco::Util::IniFileConfiguration::Ptr reader;
};

class BaseGroupTest : public BaseGroupIdentityTest {
protected:
    void customSetUp() override {
        openReader();
        connectAs(1);
    }

    void customTearDown() override {
        tearDownModuleApis();
        groupApi.reset();
        connection.reset();
        reader.reset();
        privmx::endpoint::core::EventQueueImpl::getInstance()->clear();
    }

    // Swaps the fixture's session for user_`index`'s. The GroupApi comes first: every module api but LockApi is
    // built on top of it.
    void connectAs(int index) {
        connection = connect(index);
        groupApi = std::make_shared<privmx::endpoint::group::GroupApi>(
            privmx::endpoint::group::GroupApi::create(*connection)
        );
        connectedUserIndex = index;
        setUpModuleApis();
    }

    void disconnect() {
        if(connection) connection->disconnect();
        tearDownModuleApis();
        groupApi.reset();
        connection.reset();
    }

    // Where a subclass builds the module apis it drives, on `connection` with `groupApi` already in hand.
    virtual void setUpModuleApis() {}
    virtual void tearDownModuleApis() {}

    std::shared_ptr<privmx::endpoint::core::Connection> connection;
    std::shared_ptr<privmx::endpoint::group::GroupApi> groupApi;
    // Which login the fixture's own session holds; 0 before the first connect. Survives disconnect(), so a probe
    // that steps the fixture aside can put it back.
    int connectedUserIndex = 0;
};

} // test
} // privmx

#endif // _PRIVMXLIB_TEST_BASEGROUPTEST_HPP_
