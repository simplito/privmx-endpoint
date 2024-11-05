
#include <gtest/gtest.h>
#include "../utils/BaseTest.hpp"
#include <privmx/endpoint/core/Connection.hpp>
#include <privmx/endpoint/core/Exception.hpp>
#include <Poco/Util/IniFileConfiguration.h>
#include <privmx/endpoint/core/VarSerializer.hpp>
#include <privmx/endpoint/core/EventQueueImpl.hpp>

using namespace privmx::endpoint;

enum ConnectionType {
    User1,
    User2,
    Public
};

class CoreTest : public privmx::test::BaseTest {
protected:
    CoreTest() : BaseTest(privmx::test::BaseTestMode::online) {}
    void connectAs(ConnectionType type) {
        if(type == ConnectionType::User1) {
            connection = std::make_shared<core::Connection>(
                core::Connection::connect(
                    reader->getString("Login.user_1_privKey"), 
                    reader->getString("Login.solutionId"), 
                    getPlatformUrl(reader->getString("Login.instanceUrl"))
                )
            );
        } else if(type == ConnectionType::User2) {
            connection = std::make_shared<core::Connection>(
                core::Connection::connect(
                    reader->getString("Login.user_2_privKey"), 
                    reader->getString("Login.solutionId"), 
                    getPlatformUrl(reader->getString("Login.instanceUrl"))
                )
            );
        } else if(type == ConnectionType::Public) {
            connection = std::make_shared<core::Connection>(
                core::Connection::connectPublic(
                    reader->getString("Login.solutionId"), 
                    getPlatformUrl(reader->getString("Login.instanceUrl"))
                )
            );
        }
    }
    void disconnect() {
        connection->disconnect();
        connection.reset();
    }
    void customSetUp() override {
        auto iniFile = std::getenv("INI_FILE_PATH");
        reader = new Poco::Util::IniFileConfiguration(iniFile);
        connectAs(ConnectionType::User1);
    }
    void customTearDown() override { // tmp segfault fix
        connection.reset();
        reader.reset();
        privmx::endpoint::core::EventQueueImpl::getInstance()->clear();
    }
    std::shared_ptr<core::Connection> connection;
    Poco::Util::IniFileConfiguration::Ptr reader;
    core::VarSerializer _serializer = core::VarSerializer({});
};


TEST_F(CoreTest, platformConnect_multiple_instances) {
    std::shared_ptr<core::Connection> connection_2;
    core::PagingList<core::Context> listContexts;
    // platformConnect to user_1 when connected to user_1
    EXPECT_THROW({
        connection_2 = std::make_shared<core::Connection>(
            core::Connection::connect(
                reader->getString("Login.user_1_privKey"), 
                reader->getString("Login.solutionId"), 
                getPlatformUrl(reader->getString("Login.instanceUrl"))
            )
        );
    }, core::Exception);
    // platformConnect to user_2
    EXPECT_NO_THROW({
        connection_2 = std::make_shared<core::Connection>(
            core::Connection::connect(
                reader->getString("Login.user_2_privKey"), 
                reader->getString("Login.solutionId"), 
                getPlatformUrl(reader->getString("Login.instanceUrl"))
            )
        );
    });
    // check connection using listContexts for user_1, user_2
    EXPECT_NO_THROW({
        listContexts = connection->listContexts(
            {
                .skip=0, 
                .limit=1, 
                .sortOrder="desc"
            }
        );
    });
    EXPECT_EQ(listContexts.totalAvailable, 2);
    EXPECT_EQ(listContexts.readItems.size(), 1);
    if(listContexts.readItems.size() >= 1) {
        auto context = listContexts.readItems[0];
        EXPECT_EQ(context.contextId, reader->getString("Context_2.contextId"));
    }
    EXPECT_NO_THROW({
        connection_2->listContexts(
            {
                .skip=0, 
                .limit=1, 
                .sortOrder="desc"
            }
        );
    });
    EXPECT_EQ(listContexts.totalAvailable, 2);
    EXPECT_EQ(listContexts.readItems.size(), 1);
    if(listContexts.readItems.size() >= 1) {
        auto context = listContexts.readItems[0];
        EXPECT_EQ(context.contextId, reader->getString("Context_2.contextId"));
    }
}

TEST_F(CoreTest, platformDisconnect) {
    std::shared_ptr<core::Connection> connection_2;
    core::PagingList<core::Context> listContexts;
    // platformConnect to user_2
    EXPECT_NO_THROW({
        connection_2 = std::make_shared<core::Connection>(
            core::Connection::connect(
                reader->getString("Login.user_2_privKey"), 
                reader->getString("Login.solutionId"), 
                getPlatformUrl(reader->getString("Login.instanceUrl"))
            )
        );
    });
    // check connection using listContexts for user_1, user_2
    EXPECT_NO_THROW({
        listContexts = connection->listContexts(
            {
                .skip=0, 
                .limit=1, 
                .sortOrder="desc"
            }
        );
    });
    EXPECT_EQ(listContexts.totalAvailable, 2);
    EXPECT_EQ(listContexts.readItems.size(), 1);
    if(listContexts.readItems.size() >= 1) {
        auto context = listContexts.readItems[0];
        EXPECT_EQ(context.contextId, reader->getString("Context_2.contextId"));
    }
    EXPECT_NO_THROW({
        connection_2->listContexts(
            {
                .skip=0, 
                .limit=1, 
                .sortOrder="desc"
            }
        );
    });
    EXPECT_EQ(listContexts.totalAvailable, 2);
    EXPECT_EQ(listContexts.readItems.size(), 1);
    if(listContexts.readItems.size() >= 1) {
        auto context = listContexts.readItems[0];
        EXPECT_EQ(context.contextId, reader->getString("Context_2.contextId"));
    }
    // platformDisconnect on user_2
    EXPECT_NO_THROW({
        connection_2->disconnect();
    });
    // check connection using listContexts for user_1, user_2
    EXPECT_NO_THROW({
        connection->listContexts(
            {
                .skip=0, 
                .limit=1, 
                .sortOrder="desc"
            }
        );
    });
    EXPECT_EQ(listContexts.totalAvailable, 2);
    EXPECT_EQ(listContexts.readItems.size(), 1);
    if(listContexts.readItems.size() >= 1) {
        auto context = listContexts.readItems[0];
        EXPECT_EQ(context.contextId, reader->getString("Context_2.contextId"));
    }
    EXPECT_THROW({
        listContexts = connection_2->listContexts(
            {
                .skip=0, 
                .limit=1, 
                .sortOrder="desc"
            }
        );
    }, core::Exception);
    // platformDisconnect on user_1
    EXPECT_NO_THROW({
        connection->disconnect();
    });
    // check connection using listContexts for user_1
    EXPECT_THROW({
        listContexts = connection->listContexts(
            {
                .skip=0, 
                .limit=1, 
                .sortOrder="desc"
            }
        );
    }, core::Exception);
    // platformDisconnect on user_1 (again)
    EXPECT_THROW({
        connection->disconnect();
    }, core::Exception);
    // platformConnect to user_2
    EXPECT_NO_THROW({
        connection_2 = std::make_shared<core::Connection>(
            core::Connection::connect(
                reader->getString("Login.user_2_privKey"), 
                reader->getString("Login.solutionId"), 
                getPlatformUrl(reader->getString("Login.instanceUrl"))
            )
        );
    });
}

TEST_F(CoreTest, platformConnectPublic) {
    disconnect();
    // platformConnectPublic
    connectAs(ConnectionType::Public);
    // check connection using listContexts
    EXPECT_THROW({
        connection->listContexts(
            {
                .skip=0, 
                .limit=1, 
                .sortOrder="desc"
            }
        );
    }, core::Exception);
}

TEST_F(CoreTest, listContexts_incorrect_input_data) {
    // limit < 0
    EXPECT_THROW({
        connection->listContexts(
            {
                .skip=0, 
                .limit=-1, 
                .sortOrder="desc"
            }
        );
    }, core::Exception);
    // limit == 0
    EXPECT_THROW({
        connection->listContexts(
            {
                .skip=0, 
                .limit=0, 
                .sortOrder="desc"
            }
        );
    }, core::Exception);
    // incorrect sortOrder
    EXPECT_THROW({
        connection->listContexts(
            {
                .skip=0, 
                .limit=1, 
                .sortOrder="BLACH"
            }
        );
    }, core::Exception);
    // incorrect lastId
    EXPECT_THROW({
        connection->listContexts(
            {
                .skip=0, 
                .limit=1, 
                .sortOrder="desc",
                .lastId=reader->getString("Thread_1.threadId")
            }
        );
    }, core::Exception);
}


TEST_F(CoreTest, listContexts_correct_data) {
    // {.skip=3, .limit=1, .sortOrder="desc"}
    core::PagingList<core::Context> listContexts;
    EXPECT_NO_THROW({
        listContexts = connection->listContexts(
            {
                .skip=3, 
                .limit=1, 
                .sortOrder="desc"
            }
        );
    });
    EXPECT_EQ(listContexts.totalAvailable, 2);
    EXPECT_EQ(listContexts.readItems.size(), 0);
    // {.skip=1, .limit=1, .sortOrder="desc"}
    EXPECT_NO_THROW({
        listContexts = connection->listContexts(
            {
                .skip=1, 
                .limit=1, 
                .sortOrder="desc"
            }
        );
    });
    EXPECT_EQ(listContexts.totalAvailable, 2);
    EXPECT_EQ(listContexts.readItems.size(), 1);
    if(listContexts.readItems.size() >= 1) {
        auto context = listContexts.readItems[0];
        EXPECT_EQ(context.contextId, reader->getString("Context_1.contextId"));
    }
    // {.skip=0, .limit=3, .sortOrder="asc"}
    EXPECT_NO_THROW({
        listContexts = connection->listContexts(
            {
                .skip=0, 
                .limit=3, 
                .sortOrder="asc"
            }
        );
    });
    EXPECT_EQ(listContexts.totalAvailable, 2);
    EXPECT_EQ(listContexts.readItems.size(), 2);
    if(listContexts.readItems.size() >= 1) {
        auto context = listContexts.readItems[0];
        EXPECT_EQ(context.contextId, reader->getString("Context_1.contextId"));
    }
    if(listContexts.readItems.size() >= 2) {
        auto context = listContexts.readItems[1];
        EXPECT_EQ(context.contextId, reader->getString("Context_2.contextId"));
    }
}