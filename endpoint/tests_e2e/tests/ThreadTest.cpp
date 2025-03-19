#include <gtest/gtest.h>
#include "../utils/BaseTest.hpp"
#include <privmx/endpoint/core/Exception.hpp>
#include <Poco/Util/IniFileConfiguration.h>
#include <privmx/endpoint/core/EventQueueImpl.hpp>
#include <privmx/crypto/Crypto.hpp>
#include <privmx/utils/Utils.hpp>
#include <privmx/endpoint/core/VarSerializer.hpp>
#include <privmx/endpoint/core/Connection.hpp>
#include <privmx/endpoint/thread/ThreadApi.hpp>
#include <privmx/endpoint/thread/ThreadVarSerializer.hpp>
using namespace privmx::endpoint;


enum ConnectionType {
    User1,
    User2,
    Public
};

class ThreadTest : public privmx::test::BaseTest {
protected:
    ThreadTest() : BaseTest(privmx::test::BaseTestMode::online) {}
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
        threadApi = std::make_shared<thread::ThreadApi>(
            thread::ThreadApi::create(
                *connection
            )
        );
    }
    void disconnect() {
        connection->disconnect();
        connection.reset();
        threadApi.reset();
    }
    void customSetUp() override {
        std::string iniFile = std::getenv("INI_FILE_PATH");
        reader = new Poco::Util::IniFileConfiguration(iniFile);
        connection = std::make_shared<core::Connection>(
            core::Connection::connect(
                reader->getString("Login.user_1_privKey"), 
                reader->getString("Login.solutionId"), 
                getPlatformUrl(reader->getString("Login.instanceUrl"))
            )
        );
        threadApi = std::make_shared<thread::ThreadApi>(
            thread::ThreadApi::create(
                *connection
            )
        );
    }
    void customTearDown() override { // tmp segfault fix
        connection.reset();
        threadApi.reset();
        reader.reset();
        core::EventQueueImpl::getInstance()->clear();
    }
    std::shared_ptr<core::Connection> connection;
    std::shared_ptr<thread::ThreadApi> threadApi;
    Poco::Util::IniFileConfiguration::Ptr reader;
    core::VarSerializer _serializer = core::VarSerializer({});
};


TEST_F(ThreadTest, getThread) {
    thread::Thread thread;
    // incorrect threadId
    EXPECT_THROW({
        threadApi->getThread(
            reader->getString("Context_1.contextId")
        );
    }, core::Exception);
    // correct threadId
    EXPECT_NO_THROW({
        thread = threadApi->getThread(
            reader->getString("Thread_1.threadId")
        );
    });
    EXPECT_EQ(thread.contextId, reader->getString("Thread_1.contextId"));
    EXPECT_EQ(thread.threadId, reader->getString("Thread_1.threadId"));
    EXPECT_EQ(thread.createDate, reader->getInt64("Thread_1.createDate"));
    EXPECT_EQ(thread.creator, reader->getString("Thread_1.creator"));
    EXPECT_EQ(thread.lastModificationDate, reader->getInt64("Thread_1.lastModificationDate"));
    EXPECT_EQ(thread.lastModifier, reader->getString("Thread_1.lastModifier"));
    EXPECT_EQ(thread.version, reader->getInt64("Thread_1.version"));
    EXPECT_EQ(thread.lastMsgDate, reader->getInt64("Thread_1.lastMsgDate"));
    EXPECT_EQ(thread.messagesCount, reader->getInt64("Thread_1.messagesCount"));
    EXPECT_EQ(thread.statusCode, 0);
    EXPECT_EQ(thread.publicMeta.stdString(), privmx::utils::Hex::toString(reader->getString("Thread_1.publicMeta_inHex")));
    EXPECT_EQ(thread.publicMeta.stdString(), privmx::utils::Hex::toString(reader->getString("Thread_1.uploaded_publicMeta_inHex")));
    EXPECT_EQ(thread.privateMeta.stdString(), privmx::utils::Hex::toString(reader->getString("Thread_1.privateMeta_inHex")));
    EXPECT_EQ(thread.privateMeta.stdString(), privmx::utils::Hex::toString(reader->getString("Thread_1.uploaded_privateMeta_inHex")));

    EXPECT_EQ(thread.version, 1);
    EXPECT_EQ(thread.creator, reader->getString("Login.user_1_id"));
    EXPECT_EQ(thread.lastModifier, reader->getString("Login.user_1_id"));
    EXPECT_EQ(thread.users.size(), 1);
    if(thread.users.size() == 1) {
        EXPECT_EQ(thread.users[0], reader->getString("Login.user_1_id"));
    }
    EXPECT_EQ(thread.managers.size(), 1);
    if(thread.managers.size() == 1) {
        EXPECT_EQ(thread.managers[0], reader->getString("Login.user_1_id"));
    }
}

TEST_F(ThreadTest, listThreads_incorrect_input_data) {
    // incorrect contextId
    EXPECT_THROW({
        threadApi->listThreads(
            reader->getString("Thread_1.threadId"),
            {
                .skip=0, 
                .limit=1, 
                .sortOrder="desc"
            }
        );
    }, core::Exception);
    // limit < 0
    EXPECT_THROW({
        threadApi->listThreads(
            reader->getString("Context_1.contextId"),
            {
                .skip=0, 
                .limit=-1, 
                .sortOrder="desc"
            }
        );
    }, core::Exception);
    // limit == 0
    EXPECT_THROW({
        threadApi->listThreads(
            reader->getString("Context_1.contextId"),
            {
                .skip=0, 
                .limit=0, 
                .sortOrder="desc"
            }
        );
    }, core::Exception);
    // incorrect sortOrder
    EXPECT_THROW({
        threadApi->listThreads(
            reader->getString("Context_1.contextId"),
            {
                .skip=0, 
                .limit=1, 
                .sortOrder="BLACH"
            }
        );
    }, core::Exception);
    // incorrect lastId
    EXPECT_THROW({
        threadApi->listThreads(
            reader->getString("Context_1.contextId"),
            {
                .skip=0, 
                .limit=1, 
                .sortOrder="desc",
                .lastId=reader->getString("Context_1.contextId")
            }
        );
    }, core::Exception);
}

TEST_F(ThreadTest, listThread_correct_input_data) {
    core::PagingList<thread::Thread> listThreads;
    // {.skip=4, .limit=1, .sortOrder="desc"}
    EXPECT_NO_THROW({
        listThreads = threadApi->listThreads(
            reader->getString("Context_1.contextId"),
            {
                .skip=4, 
                .limit=1, 
                .sortOrder="desc"
            }
        );
    });
    EXPECT_EQ(listThreads.totalAvailable, 3);
    EXPECT_EQ(listThreads.readItems.size(), 0);
    // {.skip=0, .limit=1, .sortOrder="asc"}
    EXPECT_NO_THROW({
        listThreads = threadApi->listThreads(
            reader->getString("Context_1.contextId"),
            {
                .skip=0, 
                .limit=1, 
                .sortOrder="desc"
            }
        );
    });
    EXPECT_EQ(listThreads.totalAvailable, 3);
    EXPECT_EQ(listThreads.readItems.size(), 1);
    if(listThreads.readItems.size() >= 1) {
        auto thread = listThreads.readItems[0];
        EXPECT_EQ(thread.contextId, reader->getString("Thread_3.contextId"));
        EXPECT_EQ(thread.threadId, reader->getString("Thread_3.threadId"));
        EXPECT_EQ(thread.createDate, reader->getInt64("Thread_3.createDate"));
        EXPECT_EQ(thread.creator, reader->getString("Thread_3.creator"));
        EXPECT_EQ(thread.lastModificationDate, reader->getInt64("Thread_3.lastModificationDate"));
        EXPECT_EQ(thread.lastModifier, reader->getString("Thread_3.lastModifier"));
        EXPECT_EQ(thread.version, reader->getInt64("Thread_3.version"));
        EXPECT_EQ(thread.lastMsgDate, reader->getInt64("Thread_3.lastMsgDate"));
        EXPECT_EQ(thread.messagesCount, reader->getInt64("Thread_3.messagesCount"));
        EXPECT_EQ(thread.statusCode, 0);
        EXPECT_EQ(thread.publicMeta.stdString(), privmx::utils::Hex::toString(reader->getString("Thread_3.publicMeta_inHex")));
        EXPECT_EQ(thread.publicMeta.stdString(), privmx::utils::Hex::toString(reader->getString("Thread_3.uploaded_publicMeta_inHex")));
        EXPECT_EQ(thread.privateMeta.stdString(), privmx::utils::Hex::toString(reader->getString("Thread_3.privateMeta_inHex")));
        EXPECT_EQ(thread.privateMeta.stdString(), privmx::utils::Hex::toString(reader->getString("Thread_3.uploaded_privateMeta_inHex")));
        EXPECT_EQ(thread.version, 1);
        EXPECT_EQ(thread.creator, reader->getString("Login.user_1_id"));
        EXPECT_EQ(thread.lastModifier, reader->getString("Login.user_1_id"));
        EXPECT_EQ(thread.users.size(), 2);
        if(thread.users.size() == 2) {
            EXPECT_EQ(thread.users[0], reader->getString("Login.user_1_id"));
            EXPECT_EQ(thread.users[1], reader->getString("Login.user_2_id"));
        }
        EXPECT_EQ(thread.managers.size(), 1);
        if(thread.managers.size() == 1) {
            EXPECT_EQ(thread.managers[0], reader->getString("Login.user_1_id"));
        }
    }
    // {.skip=1, .limit=3, .sortOrder="asc"}
    EXPECT_NO_THROW({
        listThreads = threadApi->listThreads(
            reader->getString("Context_1.contextId"),
            {
                .skip=1, 
                .limit=3, 
                .sortOrder="asc"
            }
        );
    });
    EXPECT_EQ(listThreads.totalAvailable, 3);
    EXPECT_EQ(listThreads.readItems.size(), 2);
    if(listThreads.readItems.size() >= 1) {
        auto thread = listThreads.readItems[0];
        EXPECT_EQ(thread.contextId, reader->getString("Thread_2.contextId"));
        EXPECT_EQ(thread.threadId, reader->getString("Thread_2.threadId"));
        EXPECT_EQ(thread.createDate, reader->getInt64("Thread_2.createDate"));
        EXPECT_EQ(thread.creator, reader->getString("Thread_2.creator"));
        EXPECT_EQ(thread.lastModificationDate, reader->getInt64("Thread_2.lastModificationDate"));
        EXPECT_EQ(thread.lastModifier, reader->getString("Thread_2.lastModifier"));
        EXPECT_EQ(thread.version, reader->getInt64("Thread_2.version"));
        EXPECT_EQ(thread.lastMsgDate, reader->getInt64("Thread_2.lastMsgDate"));
        EXPECT_EQ(thread.messagesCount, reader->getInt64("Thread_2.messagesCount"));
        EXPECT_EQ(thread.statusCode, 0);
        EXPECT_EQ(thread.publicMeta.stdString(), privmx::utils::Hex::toString(reader->getString("Thread_2.publicMeta_inHex")));
        EXPECT_EQ(thread.publicMeta.stdString(), privmx::utils::Hex::toString(reader->getString("Thread_2.uploaded_publicMeta_inHex")));
        EXPECT_EQ(thread.privateMeta.stdString(), privmx::utils::Hex::toString(reader->getString("Thread_2.privateMeta_inHex")));
        EXPECT_EQ(thread.privateMeta.stdString(), privmx::utils::Hex::toString(reader->getString("Thread_2.uploaded_privateMeta_inHex")));
        EXPECT_EQ(thread.version, 1);
        EXPECT_EQ(thread.creator, reader->getString("Login.user_1_id"));
        EXPECT_EQ(thread.lastModifier, reader->getString("Login.user_1_id"));
        EXPECT_EQ(thread.users.size(), 2);
        if(thread.users.size() == 2) {
            EXPECT_EQ(thread.users[0], reader->getString("Login.user_1_id"));
            EXPECT_EQ(thread.users[1], reader->getString("Login.user_2_id"));
        }
        EXPECT_EQ(thread.managers.size(), 2);
        if(thread.managers.size() == 2) {
            EXPECT_EQ(thread.managers[0], reader->getString("Login.user_1_id"));
            EXPECT_EQ(thread.managers[1], reader->getString("Login.user_2_id"));
        }
    }
    if(listThreads.readItems.size() >= 2) {
        auto thread = listThreads.readItems[1];
        EXPECT_EQ(thread.contextId, reader->getString("Thread_3.contextId"));
        EXPECT_EQ(thread.threadId, reader->getString("Thread_3.threadId"));
        EXPECT_EQ(thread.createDate, reader->getInt64("Thread_3.createDate"));
        EXPECT_EQ(thread.creator, reader->getString("Thread_3.creator"));
        EXPECT_EQ(thread.lastModificationDate, reader->getInt64("Thread_3.lastModificationDate"));
        EXPECT_EQ(thread.lastModifier, reader->getString("Thread_3.lastModifier"));
        EXPECT_EQ(thread.version, reader->getInt64("Thread_3.version"));
        EXPECT_EQ(thread.lastMsgDate, reader->getInt64("Thread_3.lastMsgDate"));
        EXPECT_EQ(thread.messagesCount, reader->getInt64("Thread_3.messagesCount"));
        EXPECT_EQ(thread.statusCode, 0);
        EXPECT_EQ(thread.publicMeta.stdString(), privmx::utils::Hex::toString(reader->getString("Thread_3.publicMeta_inHex")));
        EXPECT_EQ(thread.publicMeta.stdString(), privmx::utils::Hex::toString(reader->getString("Thread_3.uploaded_publicMeta_inHex")));
        EXPECT_EQ(thread.privateMeta.stdString(), privmx::utils::Hex::toString(reader->getString("Thread_3.privateMeta_inHex")));
        EXPECT_EQ(thread.privateMeta.stdString(), privmx::utils::Hex::toString(reader->getString("Thread_3.uploaded_privateMeta_inHex")));
        EXPECT_EQ(thread.version, 1);
        EXPECT_EQ(thread.creator, reader->getString("Login.user_1_id"));
        EXPECT_EQ(thread.lastModifier, reader->getString("Login.user_1_id"));
        EXPECT_EQ(thread.users.size(), 2);
        if(thread.users.size() == 2) {
            EXPECT_EQ(thread.users[0], reader->getString("Login.user_1_id"));
            EXPECT_EQ(thread.users[1], reader->getString("Login.user_2_id"));
        }
        EXPECT_EQ(thread.managers.size(), 1);
        if(thread.managers.size() == 1) {
            EXPECT_EQ(thread.managers[0], reader->getString("Login.user_1_id"));
        }
    }
    
}

TEST_F(ThreadTest, createThread) {
    // incorrect contextId
    EXPECT_THROW({
        threadApi->createThread(
            reader->getString("Thread_1.threadId"),
            std::vector<core::UserWithPubKey>{core::UserWithPubKey{
                .userId=reader->getString("Login.user_1_id"),
                .pubKey=reader->getString("Login.user_1_pubKey")
            }},
            std::vector<core::UserWithPubKey>{core::UserWithPubKey{
                .userId=reader->getString("Login.user_1_id"),
                .pubKey=reader->getString("Login.user_1_pubKey")
            }},
            core::Buffer::from("public"),
            core::Buffer::from("private")
        );
    }, core::Exception);
    // incorrect users
    EXPECT_THROW({
        threadApi->createThread(
            reader->getString("Context_1.contextId"),
            std::vector<core::UserWithPubKey>{core::UserWithPubKey{
                .userId=reader->getString("Login.user_1_id"),
                .pubKey=reader->getString("Login.user_2_pubKey")
            }},
            std::vector<core::UserWithPubKey>{core::UserWithPubKey{
                .userId=reader->getString("Login.user_1_id"),
                .pubKey=reader->getString("Login.user_1_pubKey")
            }},
            core::Buffer::from("public"),
            core::Buffer::from("private")
        );
    }, core::Exception);
    // incorrect managers
    EXPECT_THROW({
        threadApi->createThread(
            reader->getString("Context_1.contextId"),
            std::vector<core::UserWithPubKey>{core::UserWithPubKey{
                .userId=reader->getString("Login.user_1_id"),
                .pubKey=reader->getString("Login.user_1_pubKey")
            }},
            std::vector<core::UserWithPubKey>{core::UserWithPubKey{
                .userId=reader->getString("Login.user_1_id"),
                .pubKey=reader->getString("Login.user_2_pubKey")
            }},
            core::Buffer::from("public"),
            core::Buffer::from("private")
        );
    }, core::Exception);
    // no managers
    EXPECT_THROW({
        threadApi->createThread(
            reader->getString("Context_1.contextId"),
            std::vector<core::UserWithPubKey>{core::UserWithPubKey{
                .userId=reader->getString("Login.user_1_id"),
                .pubKey=reader->getString("Login.user_1_pubKey")
            }},
            std::vector<core::UserWithPubKey>{},
            core::Buffer::from("public"),
            core::Buffer::from("private")
        );
    }, core::Exception);
    // different users and managers
    std::string threadId;
    thread::Thread thread;
    EXPECT_NO_THROW({
        threadId = threadApi->createThread(
            reader->getString("Context_1.contextId"),
            std::vector<core::UserWithPubKey>{core::UserWithPubKey{
                .userId=reader->getString("Login.user_2_id"),
                .pubKey=reader->getString("Login.user_2_pubKey")
            }},
            std::vector<core::UserWithPubKey>{core::UserWithPubKey{
                .userId=reader->getString("Login.user_1_id"),
                .pubKey=reader->getString("Login.user_1_pubKey")
            }},
            core::Buffer::from("public"),
            core::Buffer::from("private")
        );
    });
    if(threadId.empty()) { 
        FAIL();
    }
    EXPECT_NO_THROW({
        thread = threadApi->getThread(
            threadId
        );
    });
    EXPECT_EQ(thread.statusCode, 0);
    EXPECT_EQ(thread.contextId, reader->getString("Context_1.contextId"));
    EXPECT_EQ(thread.publicMeta.stdString(), "public");
    EXPECT_EQ(thread.privateMeta.stdString(), "private");
    EXPECT_EQ(thread.users.size(), 1);
    if(thread.users.size() == 1) {
        EXPECT_EQ(thread.users[0], reader->getString("Login.user_2_id"));
    }
    EXPECT_EQ(thread.managers.size(), 1);
    if(thread.managers.size() == 1) {
        EXPECT_EQ(thread.managers[0], reader->getString("Login.user_1_id"));
    }
    // same users and managers
    EXPECT_NO_THROW({
        threadId = threadApi->createThread(
            reader->getString("Context_1.contextId"),
            std::vector<core::UserWithPubKey>{core::UserWithPubKey{
                .userId=reader->getString("Login.user_1_id"),
                .pubKey=reader->getString("Login.user_1_pubKey")
            }},
            std::vector<core::UserWithPubKey>{core::UserWithPubKey{
                .userId=reader->getString("Login.user_1_id"),
                .pubKey=reader->getString("Login.user_1_pubKey")
            }},
            core::Buffer::from("public"),
            core::Buffer::from("private")
        );
    });
    if(threadId.empty()) { 
        FAIL();
    }
    EXPECT_NO_THROW({
        thread = threadApi->getThread(
            threadId
        );
    });
    EXPECT_EQ(thread.statusCode, 0);
    EXPECT_EQ(thread.contextId, reader->getString("Context_1.contextId"));
    EXPECT_EQ(thread.publicMeta.stdString(), "public");
    EXPECT_EQ(thread.privateMeta.stdString(), "private");
    EXPECT_EQ(thread.users.size(), 1);
    if(thread.users.size() == 1) {
        EXPECT_EQ(thread.users[0], reader->getString("Login.user_1_id"));
    }
    EXPECT_EQ(thread.managers.size(), 1);
    if(thread.managers.size() == 1) {
        EXPECT_EQ(thread.managers[0], reader->getString("Login.user_1_id"));
    }
}

TEST_F(ThreadTest, updateThread_incorrect_data) {
    // incorrect threadId
    EXPECT_THROW({
        threadApi->updateThread(
            reader->getString("Context_1.contextId"),
            std::vector<core::UserWithPubKey>{core::UserWithPubKey{
                .userId=reader->getString("Login.user_1_id"),
                .pubKey=reader->getString("Login.user_1_pubKey")
            }},
            std::vector<core::UserWithPubKey>{core::UserWithPubKey{
                .userId=reader->getString("Login.user_1_id"),
                .pubKey=reader->getString("Login.user_1_pubKey")
            }},
            core::Buffer::from("public"),
            core::Buffer::from("private"),
            1,
            false,
            false
        );
    }, core::Exception);
    // incorrect users
    EXPECT_THROW({
        threadApi->updateThread(
            reader->getString("Thread_1.threadId"),
            std::vector<core::UserWithPubKey>{core::UserWithPubKey{
                .userId=reader->getString("Login.user_1_id"),
                .pubKey=reader->getString("Login.user_1_pubKey")
            }},
            std::vector<core::UserWithPubKey>{core::UserWithPubKey{
                .userId=reader->getString("Login.user_1_id"),
                .pubKey=reader->getString("Login.user_2_pubKey")
            }},
            core::Buffer::from("public"),
            core::Buffer::from("private"),
            1,
            false,
            false
        );
    }, core::Exception);
    // incorrect managers
    EXPECT_THROW({
        threadApi->updateThread(
            reader->getString("Thread_1.threadId"),
            std::vector<core::UserWithPubKey>{core::UserWithPubKey{
                .userId=reader->getString("Login.user_1_id"),
                .pubKey=reader->getString("Login.user_1_pubKey")
            }},
            std::vector<core::UserWithPubKey>{core::UserWithPubKey{
                .userId=reader->getString("Login.user_1_id"),
                .pubKey=reader->getString("Login.user_2_pubKey")
            }},
            core::Buffer::from("public"),
            core::Buffer::from("private"),
            1,
            false,
            false
        );
    }, core::Exception);
    // no managers
    EXPECT_THROW({
        threadApi->updateThread(
            reader->getString("Thread_1.threadId"),
            std::vector<core::UserWithPubKey>{core::UserWithPubKey{
                .userId=reader->getString("Login.user_1_id"),
                .pubKey=reader->getString("Login.user_1_pubKey")
            }},
            std::vector<core::UserWithPubKey>{},
            core::Buffer::from("public"),
            core::Buffer::from("private"),
            1,
            false,
            false
        );
    }, core::Exception);
    // incorrect version force false
    EXPECT_THROW({
        threadApi->updateThread(
            reader->getString("Thread_2.threadId"),
            std::vector<core::UserWithPubKey>{core::UserWithPubKey{
                .userId=reader->getString("Login.user_1_id"),
                .pubKey=reader->getString("Login.user_1_pubKey")
            }},
            std::vector<core::UserWithPubKey>{core::UserWithPubKey{
                .userId=reader->getString("Login.user_1_id"),
                .pubKey=reader->getString("Login.user_1_pubKey")
            }},
            core::Buffer::from("public"),
            core::Buffer::from("private"),
            99,
            false,
            false
        );
    }, core::Exception);
}

TEST_F(ThreadTest, updateThread_correct_data) {
    //enable cache
    EXPECT_NO_THROW({
        threadApi->subscribeForThreadEvents();
    });
    thread::Thread thread;
    // new users
    EXPECT_NO_THROW({
        threadApi->updateThread(
            reader->getString("Thread_1.threadId"),
            std::vector<core::UserWithPubKey>{
                core::UserWithPubKey{
                    .userId=reader->getString("Login.user_1_id"),
                    .pubKey=reader->getString("Login.user_1_pubKey")
                },
                core::UserWithPubKey{
                    .userId=reader->getString("Login.user_2_id"),
                    .pubKey=reader->getString("Login.user_2_pubKey")
                }
            },
            std::vector<core::UserWithPubKey>{
                core::UserWithPubKey{
                    .userId=reader->getString("Login.user_1_id"),
                    .pubKey=reader->getString("Login.user_1_pubKey")
                }
            },
            core::Buffer::from("public"),
            core::Buffer::from("private"),
            1,
            false,
            false
        );
    });
    EXPECT_NO_THROW({
        thread = threadApi->getThread(
            reader->getString("Thread_1.threadId")
        );
    });
    EXPECT_EQ(thread.statusCode, 0);    
    EXPECT_EQ(thread.contextId, reader->getString("Context_1.contextId"));
    EXPECT_EQ(thread.version, 2);
    EXPECT_EQ(thread.publicMeta.stdString(), "public");
    EXPECT_EQ(thread.privateMeta.stdString(), "private");
    EXPECT_EQ(thread.users.size(), 2);
    if(thread.users.size() == 2) {
        EXPECT_EQ(thread.users[0], reader->getString("Login.user_1_id"));
        EXPECT_EQ(thread.users[1], reader->getString("Login.user_2_id"));
    }
    EXPECT_EQ(thread.managers.size(), 1);
    if(thread.managers.size() == 1) {
        EXPECT_EQ(thread.managers[0], reader->getString("Login.user_1_id"));
    }
    // new managers
    EXPECT_NO_THROW({
        threadApi->updateThread(
            reader->getString("Thread_1.threadId"),
            std::vector<core::UserWithPubKey>{
                core::UserWithPubKey{
                    .userId=reader->getString("Login.user_1_id"),
                    .pubKey=reader->getString("Login.user_1_pubKey")
                }
            },
            std::vector<core::UserWithPubKey>{
                core::UserWithPubKey{
                    .userId=reader->getString("Login.user_1_id"),
                    .pubKey=reader->getString("Login.user_1_pubKey")
                },
                core::UserWithPubKey{
                    .userId=reader->getString("Login.user_2_id"),
                    .pubKey=reader->getString("Login.user_2_pubKey")
                }
            },
            core::Buffer::from("public"),
            core::Buffer::from("private"),
            2,
            false,
            false
        );
    });
    EXPECT_NO_THROW({
        thread = threadApi->getThread(
            reader->getString("Thread_1.threadId")
        );
    });
    EXPECT_EQ(thread.statusCode, 0);    
    EXPECT_EQ(thread.contextId, reader->getString("Context_1.contextId"));
    EXPECT_EQ(thread.version, 3);
    EXPECT_EQ(thread.publicMeta.stdString(), "public");
    EXPECT_EQ(thread.privateMeta.stdString(), "private");
    EXPECT_EQ(thread.users.size(), 1);
    if(thread.users.size() == 1) {
        EXPECT_EQ(thread.users[0], reader->getString("Login.user_1_id"));
    }
    EXPECT_EQ(thread.managers.size(), 2);
    if(thread.managers.size() == 2) {
        EXPECT_EQ(thread.managers[0], reader->getString("Login.user_1_id"));
        EXPECT_EQ(thread.managers[1], reader->getString("Login.user_2_id"));
    }
    // less users
    EXPECT_NO_THROW({
        threadApi->updateThread(
            reader->getString("Thread_2.threadId"),
            std::vector<core::UserWithPubKey>{
                core::UserWithPubKey{
                    .userId=reader->getString("Login.user_1_id"),
                    .pubKey=reader->getString("Login.user_1_pubKey")
                }
            },
            std::vector<core::UserWithPubKey>{
                core::UserWithPubKey{
                    .userId=reader->getString("Login.user_1_id"),
                    .pubKey=reader->getString("Login.user_1_pubKey")
                },
                core::UserWithPubKey{
                    .userId=reader->getString("Login.user_2_id"),
                    .pubKey=reader->getString("Login.user_2_pubKey")
                }
            },
            core::Buffer::from("public"),
            core::Buffer::from("private"),
            1,
            false,
            false
        );
    });
    EXPECT_NO_THROW({
        thread = threadApi->getThread(
            reader->getString("Thread_2.threadId")
        );
    });
    EXPECT_EQ(thread.statusCode, 0);    
    EXPECT_EQ(thread.contextId, reader->getString("Context_1.contextId"));
    EXPECT_EQ(thread.version, 2);
    EXPECT_EQ(thread.publicMeta.stdString(), "public");
    EXPECT_EQ(thread.privateMeta.stdString(), "private");
    EXPECT_EQ(thread.users.size(), 1);
    if(thread.users.size() == 1) {
        EXPECT_EQ(thread.users[0], reader->getString("Login.user_1_id"));
    }
    EXPECT_EQ(thread.managers.size(), 2);
    if(thread.managers.size() == 2) {
        EXPECT_EQ(thread.managers[0], reader->getString("Login.user_1_id"));
        EXPECT_EQ(thread.managers[1], reader->getString("Login.user_2_id"));
    }
    // less managers
    EXPECT_NO_THROW({
        threadApi->updateThread(
            reader->getString("Thread_2.threadId"),
            std::vector<core::UserWithPubKey>{
                core::UserWithPubKey{
                    .userId=reader->getString("Login.user_1_id"),
                    .pubKey=reader->getString("Login.user_1_pubKey")
                }
            },
            std::vector<core::UserWithPubKey>{
                core::UserWithPubKey{
                    .userId=reader->getString("Login.user_1_id"),
                    .pubKey=reader->getString("Login.user_1_pubKey")
                }
            },
            core::Buffer::from("public"),
            core::Buffer::from("private"),
            2,
            false,
            false
        );
    });
    EXPECT_NO_THROW({
        thread = threadApi->getThread(
            reader->getString("Thread_2.threadId")
        );
    });
    EXPECT_EQ(thread.statusCode, 0);    
    EXPECT_EQ(thread.contextId, reader->getString("Context_1.contextId"));
    EXPECT_EQ(thread.version, 3);
    EXPECT_EQ(thread.publicMeta.stdString(), "public");
    EXPECT_EQ(thread.privateMeta.stdString(), "private");
    EXPECT_EQ(thread.users.size(), 1);
    if(thread.users.size() == 1) {
        EXPECT_EQ(thread.users[0], reader->getString("Login.user_1_id"));
    }
    EXPECT_EQ(thread.managers.size(), 1);
    if(thread.managers.size() == 1) {
        EXPECT_EQ(thread.managers[0], reader->getString("Login.user_1_id"));
    }
    // incorrect version force true
    EXPECT_NO_THROW({
        threadApi->updateThread(
            reader->getString("Thread_3.threadId"),
            std::vector<core::UserWithPubKey>{core::UserWithPubKey{
                .userId=reader->getString("Login.user_1_id"),
                .pubKey=reader->getString("Login.user_1_pubKey")
            }},
            std::vector<core::UserWithPubKey>{core::UserWithPubKey{
                .userId=reader->getString("Login.user_1_id"),
                .pubKey=reader->getString("Login.user_1_pubKey")
            }},
            core::Buffer::from("public"),
            core::Buffer::from("private"),
            99,
            true,
            false
        );
    });
    EXPECT_NO_THROW({
        thread = threadApi->getThread(
            reader->getString("Thread_3.threadId")
        );
    });
    EXPECT_EQ(thread.statusCode, 0);    
    EXPECT_EQ(thread.contextId, reader->getString("Context_1.contextId"));
    EXPECT_EQ(thread.version, 2);
    EXPECT_EQ(thread.publicMeta.stdString(), "public");
    EXPECT_EQ(thread.privateMeta.stdString(), "private");
    EXPECT_EQ(thread.users.size(), 1);
    if(thread.users.size() == 1) {
        EXPECT_EQ(thread.users[0], reader->getString("Login.user_1_id"));
    }
    EXPECT_EQ(thread.managers.size(), 1);
    if(thread.managers.size() == 1) {
        EXPECT_EQ(thread.managers[0], reader->getString("Login.user_1_id"));
    }
}

TEST_F(ThreadTest, deleteThread) {
    // incorrect threadId
    EXPECT_THROW({
        threadApi->deleteThread(
            reader->getString("Context_1.contextId")
        );
    }, core::Exception);
    // as manager
     EXPECT_NO_THROW({
        threadApi->deleteThread(
            reader->getString("Thread_1.threadId")
        );
    });
    EXPECT_THROW({
        threadApi->getThread(
            reader->getString("Thread_1.threadId")
        );
    }, core::Exception);
    // as user
    disconnect();
    connectAs(ConnectionType::User2);
    EXPECT_THROW({
        threadApi->deleteThread(
            reader->getString("Thread_3.threadId")
        );
    }, core::Exception);
}

TEST_F(ThreadTest, getMessage) {
    // incorrect messageId
    EXPECT_THROW({
        threadApi->getMessage(
            reader->getString("Context_1.contextId")
        );
    }, core::Exception);
    // after force key generation on thread
    EXPECT_NO_THROW({
        threadApi->updateThread(
            reader->getString("Thread_1.threadId"),
            std::vector<core::UserWithPubKey>{
                core::UserWithPubKey{
                    .userId=reader->getString("Login.user_1_id"),
                    .pubKey=reader->getString("Login.user_1_pubKey")
                }
            },
            std::vector<core::UserWithPubKey>{
                core::UserWithPubKey{
                    .userId=reader->getString("Login.user_1_id"),
                    .pubKey=reader->getString("Login.user_1_pubKey")
                }
            },
            core::Buffer::from("public"),
            core::Buffer::from("private"),
            1,
            true,
            true
        );
    });
    thread::Message message;
    EXPECT_NO_THROW({
        message = threadApi->getMessage(
            reader->getString("Message_2.info_messageId")
        );
    });
    EXPECT_EQ(message.info.threadId, reader->getString("Message_2.info_threadId"));
    EXPECT_EQ(message.info.messageId, reader->getString("Message_2.info_messageId"));
    EXPECT_EQ(message.info.createDate, reader->getInt64("Message_2.info_createDate"));
    EXPECT_EQ(message.info.author, reader->getString("Message_2.info_author"));
    EXPECT_EQ(message.publicMeta.stdString(), privmx::utils::Hex::toString(reader->getString("Message_2.publicMeta_inHex")));
    EXPECT_EQ(message.privateMeta.stdString(), privmx::utils::Hex::toString(reader->getString("Message_2.privateMeta_inHex")));
    EXPECT_EQ(message.data.stdString(), privmx::utils::Hex::toString(reader->getString("Message_2.data_inHex")));
    EXPECT_EQ(message.statusCode, 0);
    EXPECT_EQ(
        privmx::utils::Utils::stringifyVar(_serializer.serialize(message)),
        reader->getString("Message_2.JSON_data")
    );
    EXPECT_EQ(message.publicMeta.stdString(), privmx::utils::Hex::toString(reader->getString("Message_2.uploaded_publicMeta_inHex")));
    EXPECT_EQ(message.privateMeta.stdString(), privmx::utils::Hex::toString(reader->getString("Message_2.uploaded_privateMeta_inHex")));
    EXPECT_EQ(message.data.stdString(), privmx::utils::Hex::toString(reader->getString("Message_2.uploaded_data_inHex")));
}

TEST_F(ThreadTest, listMessages_incorrect_input_data) {
    // incorrect threadId
    EXPECT_THROW({
        threadApi->listMessages(
            reader->getString("Message_2.info_messageId"),
            {
                .skip=0, 
                .limit=1, 
                .sortOrder="desc"
            }
        );
    }, core::Exception);
    // limit < 0
    EXPECT_THROW({
        threadApi->listMessages(
            reader->getString("Thread_1.threadId"),
            {
                .skip=0, 
                .limit=-1, 
                .sortOrder="desc"
            }
        );
    }, core::Exception);
    // limit == 0
    EXPECT_THROW({
        threadApi->listMessages(
            reader->getString("Thread_1.threadId"),
            {
                .skip=0, 
                .limit=0, 
                .sortOrder="desc"
            }
        );
    }, core::Exception);
    // incorrect sortOrder
    EXPECT_THROW({
        threadApi->listMessages(
            reader->getString("Thread_1.threadId"),
            {
                .skip=0, 
                .limit=1, 
                .sortOrder="BLACH"
            }
        );
    }, core::Exception);
    // incorrect lastId
    EXPECT_THROW({
        threadApi->listMessages(
            reader->getString("Thread_1.threadId"),
            {
                .skip=0, 
                .limit=1, 
                .sortOrder="BLACH",
                .lastId=reader->getString("Thread_1.threadId")
            }
        );
    }, core::Exception);
}

TEST_F(ThreadTest, listMessages_correct_input_data) {
    core::PagingList<thread::Message> listMessages;
    // {.skip=4, .limit=1, .sortOrder="desc"}
    EXPECT_NO_THROW({
        listMessages = threadApi->listMessages(
            reader->getString("Thread_1.threadId"),
            {
                .skip=4, 
                .limit=1, 
                .sortOrder="desc"
            }
        );
    });
    EXPECT_EQ(listMessages.totalAvailable, 2);
    EXPECT_EQ(listMessages.readItems.size(), 0);
    // {.skip=1, .limit=1, .sortOrder="desc"}
    EXPECT_NO_THROW({
        listMessages = threadApi->listMessages(
            reader->getString("Thread_1.threadId"),
            {
                .skip=1, 
                .limit=1, 
                .sortOrder="desc"
            }
        );
    });
    EXPECT_EQ(listMessages.totalAvailable, 2);
    EXPECT_EQ(listMessages.readItems.size(), 1);
    if(listMessages.readItems.size() >= 1) {
        auto message = listMessages.readItems[0];
        EXPECT_EQ(message.info.threadId, reader->getString("Message_1.info_threadId"));
        EXPECT_EQ(message.info.messageId, reader->getString("Message_1.info_messageId"));
        EXPECT_EQ(message.info.createDate, reader->getInt64("Message_1.info_createDate"));
        EXPECT_EQ(message.info.author, reader->getString("Message_1.info_author"));
        EXPECT_EQ(message.publicMeta.stdString(), privmx::utils::Hex::toString(reader->getString("Message_1.publicMeta_inHex")));
        EXPECT_EQ(message.privateMeta.stdString(), privmx::utils::Hex::toString(reader->getString("Message_1.privateMeta_inHex")));
        EXPECT_EQ(message.data.stdString(), privmx::utils::Hex::toString(reader->getString("Message_1.data_inHex")));
        EXPECT_EQ(message.statusCode, 0);
        EXPECT_EQ(
            privmx::utils::Utils::stringifyVar(_serializer.serialize(message)),
            reader->getString("Message_1.JSON_data")
        );
        EXPECT_EQ(message.publicMeta.stdString(), privmx::utils::Hex::toString(reader->getString("Message_1.uploaded_publicMeta_inHex")));
        EXPECT_EQ(message.privateMeta.stdString(), privmx::utils::Hex::toString(reader->getString("Message_1.uploaded_privateMeta_inHex")));
        EXPECT_EQ(message.data.stdString(), privmx::utils::Hex::toString(reader->getString("Message_1.uploaded_data_inHex")));
    }
    // {.skip=0, .limit=3, .sortOrder="asc"}, after force key generation on thread
    EXPECT_NO_THROW({
        threadApi->updateThread(
            reader->getString("Thread_1.threadId"),
            std::vector<core::UserWithPubKey>{
                core::UserWithPubKey{
                    .userId=reader->getString("Login.user_1_id"),
                    .pubKey=reader->getString("Login.user_1_pubKey")
                }
            },
            std::vector<core::UserWithPubKey>{
                core::UserWithPubKey{
                    .userId=reader->getString("Login.user_1_id"),
                    .pubKey=reader->getString("Login.user_1_pubKey")
                }
            },
            core::Buffer::from("public"),
            core::Buffer::from("private"),
            1,
            true,
            true
        );
    });
    EXPECT_NO_THROW({
        listMessages = threadApi->listMessages(
            reader->getString("Thread_1.threadId"),
            {
                .skip=0, 
                .limit=3, 
                .sortOrder="asc"
            }
        );
    });
    EXPECT_EQ(listMessages.totalAvailable, 2);
    EXPECT_EQ(listMessages.readItems.size(), 2);
    if(listMessages.readItems.size() >= 1) {
        auto message = listMessages.readItems[0];
        EXPECT_EQ(message.info.threadId, reader->getString("Message_1.info_threadId"));
        EXPECT_EQ(message.info.messageId, reader->getString("Message_1.info_messageId"));
        EXPECT_EQ(message.info.createDate, reader->getInt64("Message_1.info_createDate"));
        EXPECT_EQ(message.info.author, reader->getString("Message_1.info_author"));
        EXPECT_EQ(message.publicMeta.stdString(), privmx::utils::Hex::toString(reader->getString("Message_1.publicMeta_inHex")));
        EXPECT_EQ(message.privateMeta.stdString(), privmx::utils::Hex::toString(reader->getString("Message_1.privateMeta_inHex")));
        EXPECT_EQ(message.data.stdString(), privmx::utils::Hex::toString(reader->getString("Message_1.data_inHex")));
        EXPECT_EQ(message.statusCode, 0);
        EXPECT_EQ(
            privmx::utils::Utils::stringifyVar(_serializer.serialize(message)),
            reader->getString("Message_1.JSON_data")
        );
        EXPECT_EQ(message.publicMeta.stdString(), privmx::utils::Hex::toString(reader->getString("Message_1.uploaded_publicMeta_inHex")));
        EXPECT_EQ(message.privateMeta.stdString(), privmx::utils::Hex::toString(reader->getString("Message_1.uploaded_privateMeta_inHex")));
        EXPECT_EQ(message.data.stdString(), privmx::utils::Hex::toString(reader->getString("Message_1.uploaded_data_inHex")));
    }
    if(listMessages.readItems.size() >= 2) {
        auto message = listMessages.readItems[1];
        EXPECT_EQ(message.info.threadId, reader->getString("Message_2.info_threadId"));
        EXPECT_EQ(message.info.messageId, reader->getString("Message_2.info_messageId"));
        EXPECT_EQ(message.info.createDate, reader->getInt64("Message_2.info_createDate"));
        EXPECT_EQ(message.info.author, reader->getString("Message_2.info_author"));
        EXPECT_EQ(message.publicMeta.stdString(), privmx::utils::Hex::toString(reader->getString("Message_2.publicMeta_inHex")));
        EXPECT_EQ(message.privateMeta.stdString(), privmx::utils::Hex::toString(reader->getString("Message_2.privateMeta_inHex")));
        EXPECT_EQ(message.data.stdString(), privmx::utils::Hex::toString(reader->getString("Message_2.data_inHex")));
        EXPECT_EQ(message.statusCode, 0);
        EXPECT_EQ(
            privmx::utils::Utils::stringifyVar(_serializer.serialize(message)),
            reader->getString("Message_2.JSON_data")
        );
        EXPECT_EQ(message.publicMeta.stdString(), privmx::utils::Hex::toString(reader->getString("Message_2.uploaded_publicMeta_inHex")));
        EXPECT_EQ(message.privateMeta.stdString(), privmx::utils::Hex::toString(reader->getString("Message_2.uploaded_privateMeta_inHex")));
        EXPECT_EQ(message.data.stdString(), privmx::utils::Hex::toString(reader->getString("Message_2.uploaded_data_inHex")));
    }
    
}

TEST_F(ThreadTest, sendMessage) {
    // incorrect_threadId
    EXPECT_THROW({
        threadApi->sendMessage(
            reader->getString("Context_1.contextId"),
            core::Buffer::from("pubMeta"),
            core::Buffer::from("privMeta"),
            core::Buffer::from("data")
        );
    }, core::Exception);
    // msg total data bigger then 1MB
    std::string random_data = "";
    for(int i = 0; i < 1024; i++) {
        random_data += privmx::crypto::Crypto::randomBytes(1024);
    }
    EXPECT_THROW({
        threadApi->sendMessage(
            reader->getString("Thread_1.threadId"),
            core::Buffer::from(random_data),
            core::Buffer::from("privMeta"),
            core::Buffer::from("data")
        );
    }, core::Exception);
    // correct data
    std::string messageId;
    random_data = std::string();
    for(int i = 0; i < 8; i++) {
        random_data += privmx::crypto::Crypto::randomBytes(1024);
    }
    EXPECT_NO_THROW({
        messageId = threadApi->sendMessage(
            reader->getString("Thread_1.threadId"),
            core::Buffer::from("publicMeta"),
            core::Buffer::from("privateMeta"),
            core::Buffer::from(random_data)
        );
    });
    thread::Message message;
    EXPECT_NO_THROW({
        message = threadApi->getMessage(
            messageId
        );
    });
    EXPECT_EQ(message.data.stdString().length(), random_data.length());
    if(message.data.stdString().length() == random_data.length()) {
        EXPECT_EQ(message.data.stdString(), random_data);
    }
    EXPECT_EQ(message.privateMeta.stdString(), "privateMeta");
    EXPECT_EQ(message.publicMeta.stdString(), "publicMeta");
}

TEST_F(ThreadTest, updateMessage) {
    // incorrect messageId
    EXPECT_THROW({
        threadApi->updateMessage(
            reader->getString("Thread_1.threadId"),
            core::Buffer::from("pubMeta"),
            core::Buffer::from("privMeta"),
            core::Buffer::from("data")
        );
    }, core::Exception);
    // msg total data bigger then 1MB
    std::string random_data = "";
    for(int i = 0; i < 1024; i++) {
        random_data += privmx::crypto::Crypto::randomBytes(1024);
    }
    EXPECT_THROW({
        threadApi->updateMessage(
            reader->getString("Message_1.info_messageId"),
            core::Buffer::from(random_data),
            core::Buffer::from("privMeta"),
            core::Buffer::from("data")
        );
    }, core::Exception);
    // correct data
    random_data = std::string();
    for(int i = 0; i < 8; i++) {
        random_data += privmx::crypto::Crypto::randomBytes(1024);
    }
    EXPECT_NO_THROW({
        threadApi->updateMessage(
            reader->getString("Message_1.info_messageId"),
            core::Buffer::from("publicMeta"),
            core::Buffer::from("privateMeta"),
            core::Buffer::from(random_data)
        );
    });
    thread::Message message;
    EXPECT_NO_THROW({
        message = threadApi->getMessage(
            reader->getString("Message_1.info_messageId")
        );
    });
    EXPECT_EQ(message.data.stdString().length(), random_data.length());
    if(message.data.stdString().length() == random_data.length()) {
        EXPECT_EQ(message.data.stdString(), random_data);
    }
    EXPECT_EQ(message.privateMeta.stdString(), "privateMeta");
    EXPECT_EQ(message.publicMeta.stdString(), "publicMeta");
}

TEST_F(ThreadTest, deleteMessage) {
    // incorrect messageId
    EXPECT_THROW({
        threadApi->deleteMessage(
            reader->getString("Thread_1.threadId")
        );
    }, core::Exception);
    // change privileges
    EXPECT_NO_THROW({
        threadApi->updateThread(
            reader->getString("Thread_1.threadId"),
            std::vector<core::UserWithPubKey>{
                core::UserWithPubKey{
                    .userId=reader->getString("Login.user_1_id"),
                    .pubKey=reader->getString("Login.user_1_pubKey")
                },
                core::UserWithPubKey{
                    .userId=reader->getString("Login.user_2_id"),
                    .pubKey=reader->getString("Login.user_2_pubKey")
                },
            },
            std::vector<core::UserWithPubKey>{
                core::UserWithPubKey{
                    .userId=reader->getString("Login.user_1_id"),
                    .pubKey=reader->getString("Login.user_1_pubKey")
                },
            },
            core::Buffer::from("public"),
            core::Buffer::from("private"),
            1,
            true,
            false
        );
    });
    // as user not created by me
    disconnect();
    connectAs(ConnectionType::User2);
    EXPECT_THROW({
        threadApi->deleteMessage(
            reader->getString("Message_2.info_messageId")
        );
    }, core::Exception);
    // change privileges
    disconnect();
    connectAs(ConnectionType::User1);
    EXPECT_NO_THROW({
        threadApi->updateThread(
            reader->getString("Thread_1.threadId"),
            std::vector<core::UserWithPubKey>{
                core::UserWithPubKey{
                    .userId=reader->getString("Login.user_1_id"),
                    .pubKey=reader->getString("Login.user_1_pubKey")
                },
                core::UserWithPubKey{
                    .userId=reader->getString("Login.user_2_id"),
                    .pubKey=reader->getString("Login.user_2_pubKey")
                },
            },
            std::vector<core::UserWithPubKey>{
                core::UserWithPubKey{
                    .userId=reader->getString("Login.user_1_id"),
                    .pubKey=reader->getString("Login.user_1_pubKey")
                },
                core::UserWithPubKey{
                    .userId=reader->getString("Login.user_2_id"),
                    .pubKey=reader->getString("Login.user_2_pubKey")
                },
            },
            core::Buffer::from("public"),
            core::Buffer::from("private"),
            1,
            true,
            false
        );
    });
    disconnect();
    connectAs(ConnectionType::User2);
    EXPECT_NO_THROW({
        threadApi->updateThread(
            reader->getString("Thread_1.threadId"),
            std::vector<core::UserWithPubKey>{
                core::UserWithPubKey{
                    .userId=reader->getString("Login.user_1_id"),
                    .pubKey=reader->getString("Login.user_1_pubKey")
                },
                core::UserWithPubKey{
                    .userId=reader->getString("Login.user_2_id"),
                    .pubKey=reader->getString("Login.user_2_pubKey")
                },
            },
            std::vector<core::UserWithPubKey>{
                core::UserWithPubKey{
                    .userId=reader->getString("Login.user_2_id"),
                    .pubKey=reader->getString("Login.user_2_pubKey")
                }
            },
            core::Buffer::from("public"),
            core::Buffer::from("private"),
            1,
            true,
            false
        );
    });
    // as user created by me
    disconnect();
    connectAs(ConnectionType::User1);
    EXPECT_NO_THROW({
        threadApi->deleteMessage(
            reader->getString("Message_2.info_messageId")
        );
    });
    disconnect();
    connectAs(ConnectionType::User2);
    // as manager no created by me
    EXPECT_NO_THROW({
        threadApi->deleteMessage(
            reader->getString("Message_1.info_messageId")
        );
    });
}

TEST_F(ThreadTest, Access_denaid_not_in_users_or_managers) {
    disconnect();
    connectAs(ConnectionType::User2);
    // getThread
    EXPECT_THROW({
        threadApi->getThread(
            reader->getString("Thread_1.threadId")
        );
    }, core::Exception);
    // updateThread
    EXPECT_THROW({
        threadApi->updateThread(
            reader->getString("Thread_1.threadId"),
            std::vector<core::UserWithPubKey>{core::UserWithPubKey{
                .userId=reader->getString("Login.user_2_id"),
                .pubKey=reader->getString("Login.user_2_pubKey")
            }},
            std::vector<core::UserWithPubKey>{core::UserWithPubKey{
                .userId=reader->getString("Login.user_2_id"),
                .pubKey=reader->getString("Login.user_2_pubKey")
            }},
            core::Buffer::from("public"),
            core::Buffer::from("private"),
            1,
            false,
            false
        );
    }, core::Exception);
    // deleteThread
    EXPECT_THROW({
        threadApi->deleteThread(
            reader->getString("Thread_1.threadId")
        );
    }, core::Exception);
    // getMessage
    EXPECT_THROW({
        threadApi->getMessage(
            reader->getString("Message_1.info_messageId")
        );
    }, core::Exception);
    // listMessages
    EXPECT_THROW({
        threadApi->listMessages(
            reader->getString("Thread_1.threadId"),
            {
                .skip=0, 
                .limit=1, 
                .sortOrder="desc"
            }
        );
    }, core::Exception);
    // sendMessage
    EXPECT_THROW({
        threadApi->sendMessage(
            reader->getString("Thread_1.threadId"),
            core::Buffer::from("pubMeta"),
            core::Buffer::from("privMeta"),
            core::Buffer::from("data")
        );
    }, core::Exception);
    // sendMessage
    EXPECT_THROW({
        threadApi->updateMessage(
            reader->getString("Message_1.info_messageId"),
            core::Buffer::from("pubMeta"),
            core::Buffer::from("privMeta"),
            core::Buffer::from("data")
        );
    }, core::Exception);
    // deleteMessage
    EXPECT_THROW({
        threadApi->deleteMessage(
            reader->getString("Message_1.info_messageId")
        );
    }, core::Exception);
}

TEST_F(ThreadTest, Access_denaid_Public) {
    disconnect();
    connectAs(ConnectionType::Public);
    // getThread
    EXPECT_THROW({
        threadApi->getThread(
            reader->getString("Thread_1.threadId")
        );
    }, core::Exception);
    // getThread
    EXPECT_THROW({
        threadApi->listThreads(
            reader->getString("Context_1.contextId"),
            {
                .skip=0, 
                .limit=1, 
                .sortOrder="desc"
            }
        );
    }, core::Exception);
    // createThread
    EXPECT_THROW({
        threadApi->createThread(
            reader->getString("Context_1.contextId"),
            std::vector<core::UserWithPubKey>{core::UserWithPubKey{
                .userId=reader->getString("Login.user_2_id"),
                .pubKey=reader->getString("Login.user_2_pubKey")
            }},
            std::vector<core::UserWithPubKey>{core::UserWithPubKey{
                .userId=reader->getString("Login.user_2_id"),
                .pubKey=reader->getString("Login.user_2_pubKey")
            }},
            core::Buffer::from("public"),
            core::Buffer::from("private")
        );
    }, core::Exception);
    // updateThread
    EXPECT_THROW({
        threadApi->updateThread(
            reader->getString("Thread_1.threadId"),
            std::vector<core::UserWithPubKey>{core::UserWithPubKey{
                .userId=reader->getString("Login.user_2_id"),
                .pubKey=reader->getString("Login.user_2_pubKey")
            }},
            std::vector<core::UserWithPubKey>{core::UserWithPubKey{
                .userId=reader->getString("Login.user_2_id"),
                .pubKey=reader->getString("Login.user_2_pubKey")
            }},
            core::Buffer::from("public"),
            core::Buffer::from("private"),
            1,
            false,
            false
        );
    }, core::Exception);
    // deleteThread
    EXPECT_THROW({
        threadApi->deleteThread(
            reader->getString("Thread_1.threadId")
        );
    }, core::Exception);
    // getMessage
    EXPECT_THROW({
        threadApi->getMessage(
            reader->getString("Message_1.info_messageId")
        );
    }, core::Exception);
    // listMessages
    EXPECT_THROW({
        threadApi->listMessages(
            reader->getString("Thread_1.threadId"),
            {
                .skip=0, 
                .limit=1, 
                .sortOrder="desc"
            }
        );
    }, core::Exception);
    // sendMessage
    EXPECT_THROW({
        threadApi->sendMessage(
            reader->getString("Thread_1.threadId"),
            core::Buffer::from("pubMeta"),
            core::Buffer::from("privMeta"),
            core::Buffer::from("data")
        );
    }, core::Exception);
    // updateMessage
    EXPECT_THROW({
        threadApi->updateMessage(
            reader->getString("Message_1.info_messageId"),
            core::Buffer::from("pubMeta"),
            core::Buffer::from("privMeta"),
            core::Buffer::from("data")
        );
    }, core::Exception);
    // deleteMessage
    EXPECT_THROW({
        threadApi->deleteMessage(
            reader->getString("Message_1.info_messageId")
        );
    }, core::Exception);
}

TEST_F(ThreadTest, createThread_policy) {
    std::string threadId;
    privmx::endpoint::thread::Thread thread;
    core::ContainerPolicy policy = {};
    policy.item=core::ItemPolicy{
        .get="owner",
        .listMy="owner",
        .listAll="owner",
        .create="owner",
        .update="owner",
        .delete_="owner",
    };
    policy.get="owner";
    policy.update="owner";
    policy.delete_="owner";
    policy.updatePolicy="owner";
    policy.updaterCanBeRemovedFromManagers="no";
    policy.ownerCanBeRemovedFromManagers="no";
    EXPECT_NO_THROW({
        threadId = threadApi->createThread(
            reader->getString("Context_1.contextId"),
            std::vector<core::UserWithPubKey>{
                core::UserWithPubKey{
                    .userId=reader->getString("Login.user_1_id"),
                    .pubKey=reader->getString("Login.user_1_pubKey")
                },
                core::UserWithPubKey{
                    .userId=reader->getString("Login.user_2_id"),
                    .pubKey=reader->getString("Login.user_2_pubKey")
                }
            },
            std::vector<core::UserWithPubKey>{
                core::UserWithPubKey{
                    .userId=reader->getString("Login.user_1_id"),
                    .pubKey=reader->getString("Login.user_1_pubKey")
                },
                core::UserWithPubKey{
                    .userId=reader->getString("Login.user_2_id"),
                    .pubKey=reader->getString("Login.user_2_pubKey")
                }
            },
            core::Buffer::from("public"),
            core::Buffer::from("private"),
            policy
        );
    });
    if(threadId.empty()) { 
        FAIL();
    }
    EXPECT_NO_THROW({
        thread = threadApi->getThread(
            threadId
        );
    });
    EXPECT_EQ(thread.contextId, reader->getString("Context_1.contextId"));
    EXPECT_EQ(thread.publicMeta.stdString(), "public");
    EXPECT_EQ(thread.privateMeta.stdString(), "private");
    EXPECT_EQ(thread.users.size(), 2);
    if(thread.users.size() == 2) {
        EXPECT_EQ(thread.users[0], reader->getString("Login.user_1_id"));
        EXPECT_EQ(thread.users[1], reader->getString("Login.user_2_id"));
    }
    EXPECT_EQ(thread.managers.size(), 2);
    if(thread.managers.size() == 2) {
        EXPECT_EQ(thread.managers[0], reader->getString("Login.user_1_id"));
        EXPECT_EQ(thread.managers[1], reader->getString("Login.user_2_id"));
    }
    EXPECT_EQ(thread.policy.item.value().get, policy.item.value().get);
    EXPECT_EQ(thread.policy.item.value().listMy, policy.item.value().listMy);
    EXPECT_EQ(thread.policy.item.value().listAll, policy.item.value().listAll);
    EXPECT_EQ(thread.policy.item.value().create, policy.item.value().create);
    EXPECT_EQ(thread.policy.item.value().update, policy.item.value().update);
    EXPECT_EQ(thread.policy.item.value().delete_, policy.item.value().delete_);

    EXPECT_EQ(thread.policy.get, policy.get);
    EXPECT_EQ(thread.policy.update, policy.update);
    EXPECT_EQ(thread.policy.delete_, policy.delete_);
    EXPECT_EQ(thread.policy.updatePolicy, policy.updatePolicy);
    EXPECT_EQ(thread.policy.updaterCanBeRemovedFromManagers, policy.updaterCanBeRemovedFromManagers);
    EXPECT_EQ(thread.policy.ownerCanBeRemovedFromManagers, policy.ownerCanBeRemovedFromManagers);
    


    disconnect();
    connectAs(ConnectionType::User2);
    EXPECT_THROW({
        thread = threadApi->getThread(
            threadId
        );
    }, core::Exception);
}

TEST_F(ThreadTest, updateThread_policy) {
    std::string threadId = reader->getString("Thread_1.threadId");
    privmx::endpoint::thread::Thread thread;
    core::ContainerPolicy policy;
    policy.item=core::ItemPolicy{
            .get="owner",
            .listMy="owner",
            .listAll="owner",
            .create="owner",
            .update="owner",
            .delete_="owner",
        };
    policy.get="owner";
    policy.update="owner";
    policy.delete_="owner";
    policy.updatePolicy="owner";
    policy.updaterCanBeRemovedFromManagers="no";
    policy.ownerCanBeRemovedFromManagers="no";
    EXPECT_NO_THROW({
        threadApi->updateThread(
            threadId,
            std::vector<core::UserWithPubKey>{
                core::UserWithPubKey{
                    .userId=reader->getString("Login.user_1_id"),
                    .pubKey=reader->getString("Login.user_1_pubKey")
                },
                core::UserWithPubKey{
                    .userId=reader->getString("Login.user_2_id"),
                    .pubKey=reader->getString("Login.user_2_pubKey")
                }
            },
            std::vector<core::UserWithPubKey>{
                core::UserWithPubKey{
                    .userId=reader->getString("Login.user_1_id"),
                    .pubKey=reader->getString("Login.user_1_pubKey")
                },
                core::UserWithPubKey{
                    .userId=reader->getString("Login.user_2_id"),
                    .pubKey=reader->getString("Login.user_2_pubKey")
                }
            },
            core::Buffer::from("public"),
            core::Buffer::from("private"),
            1,
            true,
            true,
            policy
        );
    });
    if(threadId.empty()) { 
        FAIL();
    }
    EXPECT_NO_THROW({
        thread = threadApi->getThread(
            threadId
        );
    });
    EXPECT_EQ(thread.contextId, reader->getString("Context_1.contextId"));
    EXPECT_EQ(thread.publicMeta.stdString(), "public");
    EXPECT_EQ(thread.privateMeta.stdString(), "private");
    EXPECT_EQ(thread.users.size(), 2);
    if(thread.users.size() == 2) {
        EXPECT_EQ(thread.users[0], reader->getString("Login.user_1_id"));
        EXPECT_EQ(thread.users[1], reader->getString("Login.user_2_id"));
    }
    EXPECT_EQ(thread.managers.size(), 2);
    if(thread.managers.size() == 2) {
        EXPECT_EQ(thread.managers[0], reader->getString("Login.user_1_id"));
        EXPECT_EQ(thread.managers[1], reader->getString("Login.user_2_id"));
    }
    EXPECT_EQ(thread.policy.item.value().get, policy.item.value().get);
    EXPECT_EQ(thread.policy.item.value().listMy, policy.item.value().listMy);
    EXPECT_EQ(thread.policy.item.value().listAll, policy.item.value().listAll);
    EXPECT_EQ(thread.policy.item.value().create, policy.item.value().create);
    EXPECT_EQ(thread.policy.item.value().update, policy.item.value().update);
    EXPECT_EQ(thread.policy.item.value().delete_, policy.item.value().delete_);

    EXPECT_EQ(thread.policy.get, policy.get);
    EXPECT_EQ(thread.policy.update, policy.update);
    EXPECT_EQ(thread.policy.delete_, policy.delete_);
    EXPECT_EQ(thread.policy.updatePolicy, policy.updatePolicy);
    EXPECT_EQ(thread.policy.updaterCanBeRemovedFromManagers, policy.updaterCanBeRemovedFromManagers);
    EXPECT_EQ(thread.policy.ownerCanBeRemovedFromManagers, policy.ownerCanBeRemovedFromManagers);
    disconnect();
    connectAs(ConnectionType::User2);
    EXPECT_THROW({
        threadApi->getMessage(
            reader->getString("Message_1.info_messageId")
        );
    }, core::Exception);
}

TEST_F(ThreadTest, listThreads_query) {
    std::string threadId;
    core::PagingList<thread::Thread> listThreads;
    EXPECT_NO_THROW({
        threadId = threadApi->createThread(
            reader->getString("Context_1.contextId"),
            std::vector<core::UserWithPubKey>{
                core::UserWithPubKey{
                    .userId=reader->getString("Login.user_1_id"),
                    .pubKey=reader->getString("Login.user_1_pubKey")
                }
            },
            std::vector<core::UserWithPubKey>{
                core::UserWithPubKey{
                    .userId=reader->getString("Login.user_1_id"),
                    .pubKey=reader->getString("Login.user_1_pubKey")
                }
            },
            core::Buffer::from("{\"test\":1}"),
            core::Buffer::from("list_query_test"),
            std::nullopt
        );
    });
    if(threadId.empty()) { 
        FAIL();
    }
    EXPECT_NO_THROW({
        listThreads = threadApi->listThreads(
            reader->getString("Context_1.contextId"),
            core::PagingQuery{
                .skip=0,
                .limit=100,
                .sortOrder="asc",
                .queryAsJson="{\"test\":1}"
            }
        );
    });
    EXPECT_EQ(listThreads.totalAvailable, 1);
    EXPECT_EQ(listThreads.readItems.size(), 1);
    if(listThreads.readItems.size() >= 1) {
        auto thread = listThreads.readItems[0];
        EXPECT_EQ(thread.contextId, reader->getString("Context_1.contextId"));
        EXPECT_EQ(thread.threadId, threadId);
        EXPECT_EQ(thread.messagesCount, 0);
        EXPECT_EQ(thread.statusCode, 0);
        EXPECT_EQ(thread.publicMeta.stdString(), "{\"test\":1}");
        EXPECT_EQ(thread.privateMeta.stdString(), "list_query_test");
        EXPECT_EQ(thread.creator, reader->getString("Login.user_1_id"));
        EXPECT_EQ(thread.lastModifier, reader->getString("Login.user_1_id"));
        EXPECT_EQ(thread.users.size(), 1);
        if(thread.users.size() == 1) {
            EXPECT_EQ(thread.users[0], reader->getString("Login.user_1_id"));
        }
        EXPECT_EQ(thread.managers.size(), 1);
        if(thread.managers.size() == 1) {
            EXPECT_EQ(thread.managers[0], reader->getString("Login.user_1_id"));
        }
    }
}

TEST_F(ThreadTest, update_access_to_old_messages) {
    EXPECT_NO_THROW({
        threadApi->updateThread(
            reader->getString("Thread_1.threadId"),
            std::vector<core::UserWithPubKey>{
                core::UserWithPubKey{
                    .userId=reader->getString("Login.user_1_id"),
                    .pubKey=reader->getString("Login.user_1_pubKey")
                },
                core::UserWithPubKey{
                    .userId=reader->getString("Login.user_2_id"),
                    .pubKey=reader->getString("Login.user_2_pubKey")
                }
            },
            std::vector<core::UserWithPubKey>{
                core::UserWithPubKey{
                    .userId=reader->getString("Login.user_1_id"),
                    .pubKey=reader->getString("Login.user_1_pubKey")
                },
                core::UserWithPubKey{
                    .userId=reader->getString("Login.user_2_id"),
                    .pubKey=reader->getString("Login.user_2_pubKey")
                }
            },
            core::Buffer::from("public"),
            core::Buffer::from("private"),
            1,
            true,
            true
        );
    });
    disconnect();
    connectAs(User2);
    privmx::endpoint::thread::Message message;
    EXPECT_NO_THROW({
        message = threadApi->getMessage(
            reader->getString("Message_1.info_messageId")
        );
    });
    EXPECT_EQ(message.statusCode, 0);
}