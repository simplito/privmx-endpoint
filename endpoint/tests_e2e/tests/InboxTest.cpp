
#include <gtest/gtest.h>
#include "../utils/BaseTest.hpp"
#include <privmx/endpoint/core/Exception.hpp>
#include <Poco/Util/IniFileConfiguration.h>
#include <privmx/crypto/Crypto.hpp>
#include <privmx/endpoint/core/EventQueueImpl.hpp>
#include <privmx/endpoint/core/VarSerializer.hpp>
#include <privmx/endpoint/core/Connection.hpp>
#include <privmx/endpoint/store/StoreApi.hpp>
#include <privmx/endpoint/store/StoreVarSerializer.hpp>
#include <privmx/endpoint/thread/ThreadApi.hpp>
#include <privmx/endpoint/thread/ThreadVarSerializer.hpp>
#include <privmx/endpoint/inbox/InboxApi.hpp>
#include <privmx/endpoint/inbox/InboxVarSerializer.hpp>

using namespace privmx::endpoint;
using namespace privmx::utils;

enum ConnectionType {
    User1,
    User2,
    Public
};

class InboxTest : public privmx::test::BaseTest {
protected:
    InboxTest() : BaseTest(privmx::test::BaseTestMode::online) {}
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
        storeApi = std::make_shared<store::StoreApi>(
            store::StoreApi::create(
                *connection
            )
        );
        inboxApi = std::make_shared<inbox::InboxApi>(
            inbox::InboxApi::create(
                *connection,
                *threadApi,
                *storeApi
            )
        );
    }
    void disconnect() {
        connection->disconnect();
        connection.reset();
        threadApi.reset();
        storeApi.reset();
        inboxApi.reset();
    }
    void customSetUp() override {
        std::string iniFile = std::getenv("INI_FILE_PATH");
        reader = new Poco::Util::IniFileConfiguration(iniFile);
        connectAs(ConnectionType::User1);
    }
    void customTearDown() override { // tmp segfault fix
        connection.reset();
        threadApi.reset();
        storeApi.reset();
        inboxApi.reset();

        reader.reset();
        privmx::endpoint::core::EventQueueImpl::getInstance()->clear();
    }
    std::shared_ptr<core::Connection> connection;
    std::shared_ptr<thread::ThreadApi> threadApi;
    std::shared_ptr<store::StoreApi> storeApi;
    std::shared_ptr<inbox::InboxApi> inboxApi;
    Poco::Util::IniFileConfiguration::Ptr reader;
    core::VarSerializer _serializer = core::VarSerializer({});
};

TEST_F(InboxTest, getInbox) {
    inbox::Inbox inbox;
    // incorrect inboxId
    EXPECT_THROW({
        inboxApi->getInbox(
            reader->getString("Context_1.contextId")
        );
    }, core::Exception);
    // correct inboxId
    EXPECT_NO_THROW({
        inbox = inboxApi->getInbox(
            reader->getString("Inbox_1.inboxId")
        );
    });
    EXPECT_EQ(inbox.inboxId, reader->getString("Inbox_1.inboxId"));
    EXPECT_EQ(inbox.contextId, reader->getString("Inbox_1.contextId"));
    EXPECT_EQ(inbox.createDate, reader->getInt64("Inbox_1.createDate"));
    EXPECT_EQ(inbox.creator, reader->getString("Inbox_1.creator"));
    EXPECT_EQ(inbox.lastModificationDate, reader->getInt64("Inbox_1.lastModificationDate"));
    EXPECT_EQ(inbox.lastModifier, reader->getString("Inbox_1.lastModifier"));
    EXPECT_EQ(inbox.version, reader->getInt64("Inbox_1.version"));
    EXPECT_EQ(inbox.publicMeta.stdString(), Hex::toString(reader->getString("Inbox_1.publicMeta_inHex")));
    EXPECT_EQ(inbox.publicMeta.stdString(), Hex::toString(reader->getString("Inbox_1.uploaded_publicMeta_inHex")));
    EXPECT_EQ(inbox.privateMeta.stdString(), Hex::toString(reader->getString("Inbox_1.privateMeta_inHex")));
    EXPECT_EQ(inbox.privateMeta.stdString(), Hex::toString(reader->getString("Inbox_1.uploaded_privateMeta_inHex")));
    EXPECT_EQ(inbox.statusCode, 0);
    EXPECT_EQ(inbox.users.size(), 1);
    if(inbox.users.size() == 1) {
        EXPECT_EQ(inbox.users[0], reader->getString("Login.user_1_id"));
    }
    EXPECT_EQ(inbox.managers.size(), 1);
    if(inbox.managers.size() == 1) {
        EXPECT_EQ(inbox.managers[0], reader->getString("Login.user_1_id"));
    }
}

TEST_F(InboxTest, listInboxes_incorrect_input_data) {
    // incorrect contextId
    EXPECT_THROW({
        inboxApi->listInboxes(
            reader->getString("Inbox_1.inboxId"),
            {
                .skip=0, 
                .limit=1, 
                .sortOrder="desc"
            }
        );
    }, core::Exception);
    // limit < 0
    EXPECT_THROW({
        inboxApi->listInboxes(
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
        inboxApi->listInboxes(
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
        inboxApi->listInboxes(
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
        inboxApi->listInboxes(
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

TEST_F(InboxTest, listInboxes_correct_input_data) {
    core::PagingList<inbox::Inbox> listInboxes;
    inbox::Inbox inbox;
    // {.skip=4, .limit=1, .sortOrder="desc"}
    EXPECT_NO_THROW({
        listInboxes = inboxApi->listInboxes(
            reader->getString("Context_1.contextId"),
            {
                .skip=4, 
                .limit=1, 
                .sortOrder="desc"
            }
        );
    });
    // {.skip=0, .limit=1, .sortOrder="desc"}
    EXPECT_NO_THROW({
        listInboxes = inboxApi->listInboxes(
            reader->getString("Context_1.contextId"),
            {
                .skip=0, 
                .limit=1, 
                .sortOrder="desc"
            }
        );
    });
    EXPECT_EQ(listInboxes.totalAvailable, 3);
    EXPECT_EQ(listInboxes.readItems.size(), 1);
    if(listInboxes.readItems.size() >= 1) {
        inbox = listInboxes.readItems[0];
        EXPECT_EQ(inbox.inboxId, reader->getString("Inbox_3.inboxId"));
        EXPECT_EQ(inbox.contextId, reader->getString("Inbox_3.contextId"));
        EXPECT_EQ(inbox.createDate, reader->getInt64("Inbox_3.createDate"));
        EXPECT_EQ(inbox.creator, reader->getString("Inbox_3.creator"));
        EXPECT_EQ(inbox.lastModificationDate, reader->getInt64("Inbox_3.lastModificationDate"));
        EXPECT_EQ(inbox.lastModifier, reader->getString("Inbox_3.lastModifier"));
        EXPECT_EQ(inbox.version, reader->getInt64("Inbox_3.version"));
        EXPECT_EQ(inbox.publicMeta.stdString(), Hex::toString(reader->getString("Inbox_3.publicMeta_inHex")));
        EXPECT_EQ(inbox.publicMeta.stdString(), Hex::toString(reader->getString("Inbox_3.uploaded_publicMeta_inHex")));
        EXPECT_EQ(inbox.privateMeta.stdString(), Hex::toString(reader->getString("Inbox_3.privateMeta_inHex")));
        EXPECT_EQ(inbox.privateMeta.stdString(), Hex::toString(reader->getString("Inbox_3.uploaded_privateMeta_inHex")));
        EXPECT_EQ(inbox.statusCode, 0);
        EXPECT_EQ(inbox.users.size(), 2);
        if(inbox.users.size() == 2) {
            EXPECT_EQ(inbox.users[0], reader->getString("Login.user_1_id"));
            EXPECT_EQ(inbox.users[1], reader->getString("Login.user_2_id"));
        }
        EXPECT_EQ(inbox.managers.size(), 1);
        if(inbox.managers.size() == 1) {
            EXPECT_EQ(inbox.managers[0], reader->getString("Login.user_1_id"));
        }
    }
    // {.skip=1, .limit=3, .sortOrder="asc"}
    EXPECT_NO_THROW({
        listInboxes = inboxApi->listInboxes(
            reader->getString("Context_1.contextId"),
            {
                .skip=1, 
                .limit=3, 
                .sortOrder="asc"
            }
        );
    });
    EXPECT_EQ(listInboxes.totalAvailable, 3);
    EXPECT_EQ(listInboxes.readItems.size(), 2);
    if(listInboxes.readItems.size() >= 1) {
        inbox = listInboxes.readItems[0];
        EXPECT_EQ(inbox.inboxId, reader->getString("Inbox_2.inboxId"));
        EXPECT_EQ(inbox.contextId, reader->getString("Inbox_2.contextId"));
        EXPECT_EQ(inbox.createDate, reader->getInt64("Inbox_2.createDate"));
        EXPECT_EQ(inbox.creator, reader->getString("Inbox_2.creator"));
        EXPECT_EQ(inbox.lastModificationDate, reader->getInt64("Inbox_2.lastModificationDate"));
        EXPECT_EQ(inbox.lastModifier, reader->getString("Inbox_2.lastModifier"));
        EXPECT_EQ(inbox.version, reader->getInt64("Inbox_2.version"));
        EXPECT_EQ(inbox.publicMeta.stdString(), Hex::toString(reader->getString("Inbox_2.publicMeta_inHex")));
        EXPECT_EQ(inbox.publicMeta.stdString(), Hex::toString(reader->getString("Inbox_2.uploaded_publicMeta_inHex")));
        EXPECT_EQ(inbox.privateMeta.stdString(), Hex::toString(reader->getString("Inbox_2.privateMeta_inHex")));
        EXPECT_EQ(inbox.privateMeta.stdString(), Hex::toString(reader->getString("Inbox_2.uploaded_privateMeta_inHex")));
        EXPECT_EQ(inbox.statusCode, 0);
        EXPECT_EQ(inbox.users.size(), 2);
        if(inbox.users.size() == 2) {
            EXPECT_EQ(inbox.users[0], reader->getString("Login.user_1_id"));
            EXPECT_EQ(inbox.users[1], reader->getString("Login.user_2_id"));
        }
        EXPECT_EQ(inbox.managers.size(), 2);
        if(inbox.managers.size() == 2) {
            EXPECT_EQ(inbox.managers[0], reader->getString("Login.user_1_id"));
            EXPECT_EQ(inbox.managers[1], reader->getString("Login.user_2_id"));
        }
    }
    if(listInboxes.readItems.size() >= 2) {
        inbox = listInboxes.readItems[1];
        EXPECT_EQ(inbox.inboxId, reader->getString("Inbox_3.inboxId"));
        EXPECT_EQ(inbox.contextId, reader->getString("Inbox_3.contextId"));
        EXPECT_EQ(inbox.createDate, reader->getInt64("Inbox_3.createDate"));
        EXPECT_EQ(inbox.creator, reader->getString("Inbox_3.creator"));
        EXPECT_EQ(inbox.lastModificationDate, reader->getInt64("Inbox_3.lastModificationDate"));
        EXPECT_EQ(inbox.lastModifier, reader->getString("Inbox_3.lastModifier"));
        EXPECT_EQ(inbox.version, reader->getInt64("Inbox_3.version"));
        EXPECT_EQ(inbox.publicMeta.stdString(), Hex::toString(reader->getString("Inbox_3.publicMeta_inHex")));
        EXPECT_EQ(inbox.publicMeta.stdString(), Hex::toString(reader->getString("Inbox_3.uploaded_publicMeta_inHex")));
        EXPECT_EQ(inbox.privateMeta.stdString(), Hex::toString(reader->getString("Inbox_3.privateMeta_inHex")));
        EXPECT_EQ(inbox.privateMeta.stdString(), Hex::toString(reader->getString("Inbox_3.uploaded_privateMeta_inHex")));
        EXPECT_EQ(inbox.statusCode, 0);
        EXPECT_EQ(inbox.users.size(), 2);
        if(inbox.users.size() == 2) {
            EXPECT_EQ(inbox.users[0], reader->getString("Login.user_1_id"));
            EXPECT_EQ(inbox.users[1], reader->getString("Login.user_2_id"));
        }
        EXPECT_EQ(inbox.managers.size(), 1);
        if(inbox.managers.size() == 1) {
            EXPECT_EQ(inbox.managers[0], reader->getString("Login.user_1_id"));
        }
    }
}

TEST_F(InboxTest, createInbox) {
    std::string inboxId;
    inbox::Inbox inbox;
    // incorrect contextId
    EXPECT_THROW({
        inboxApi->createInbox(
            reader->getString("Inbox_1.inboxId"),
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
            std::nullopt
        );
    }, core::Exception);
    // incorrect users
    EXPECT_THROW({
        inboxApi->createInbox(
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
            core::Buffer::from("private"),
            std::nullopt
        );
    }, core::Exception);
    // incorrect managers
    EXPECT_THROW({
        inboxApi->createInbox(
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
            core::Buffer::from("private"),
            std::nullopt
        );
    }, core::Exception);
    // no managers
    EXPECT_THROW({
        inboxApi->createInbox(
            reader->getString("Context_1.contextId"),
            std::vector<core::UserWithPubKey>{core::UserWithPubKey{
                .userId=reader->getString("Login.user_1_id"),
                .pubKey=reader->getString("Login.user_1_pubKey")
            }},
            std::vector<core::UserWithPubKey>{},
            core::Buffer::from("public"),
            core::Buffer::from("private"),
            std::nullopt
        );
    }, core::Exception);
    // different users and managers
    EXPECT_NO_THROW({
        inboxId = inboxApi->createInbox(
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
            core::Buffer::from("private"),
            std::nullopt
        );
    });
    if(inboxId.empty()) { 
        FAIL();
    }
    EXPECT_NO_THROW({
        inbox = inboxApi->getInbox(
            inboxId
        );
    });
    EXPECT_EQ(inbox.contextId, reader->getString("Context_1.contextId"));
    EXPECT_EQ(inbox.publicMeta.stdString(), "public");
    EXPECT_EQ(inbox.privateMeta.stdString(), "private");
    EXPECT_EQ(inbox.users.size(), 1);
    if(inbox.users.size() == 1) {
        EXPECT_EQ(inbox.users[0], reader->getString("Login.user_2_id"));
    }
    EXPECT_EQ(inbox.managers.size(), 1);
    if(inbox.managers.size() == 1) {
        EXPECT_EQ(inbox.managers[0], reader->getString("Login.user_1_id"));
    }
    // same users and managers
    EXPECT_NO_THROW({
        inboxId = inboxApi->createInbox(
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
            std::nullopt
        );
    });
    if(inboxId.empty()) { 
        FAIL();
    }
    EXPECT_NO_THROW({
        inbox = inboxApi->getInbox(
            inboxId
        );
    });
    EXPECT_EQ(inbox.contextId, reader->getString("Context_1.contextId"));
    EXPECT_EQ(inbox.publicMeta.stdString(), "public");
    EXPECT_EQ(inbox.privateMeta.stdString(), "private");
    EXPECT_EQ(inbox.users.size(), 1);
    if(inbox.users.size() == 1) {
        EXPECT_EQ(inbox.users[0], reader->getString("Login.user_1_id"));
    }
    EXPECT_EQ(inbox.managers.size(), 1);
    if(inbox.managers.size() == 1) {
        EXPECT_EQ(inbox.managers[0], reader->getString("Login.user_1_id"));
    }
}

TEST_F(InboxTest, updateInbox_incorrect_data) {
    // incorrect inboxId
    EXPECT_THROW({
        inboxApi->updateInbox(
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
            std::nullopt,
            1,
            false,
            false
        );
    }, core::Exception);
    // incorrect users
    EXPECT_THROW({
        inboxApi->updateInbox(
            reader->getString("Inbox_1.inboxId"),
            std::vector<core::UserWithPubKey>{core::UserWithPubKey{
                .userId=reader->getString("Login.user_1_id"),
                .pubKey=reader->getString("Login.user_2_pubKey")
            }},
            std::vector<core::UserWithPubKey>{core::UserWithPubKey{
                .userId=reader->getString("Login.user_1_id"),
                .pubKey=reader->getString("Login.user_1_pubKey")
            }},
            core::Buffer::from("public"),
            core::Buffer::from("private"),
            std::nullopt,
            1,
            false,
            false
        );
    }, core::Exception);
    // incorrect managers
    EXPECT_THROW({
        inboxApi->updateInbox(
            reader->getString("Inbox_1.inboxId"),
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
            std::nullopt,
            1,
            false,
            false
        );
    }, core::Exception);
    // no managers
    EXPECT_THROW({
        inboxApi->updateInbox(
            reader->getString("Inbox_1.inboxId"),
            std::vector<core::UserWithPubKey>{core::UserWithPubKey{
                .userId=reader->getString("Login.user_1_id"),
                .pubKey=reader->getString("Login.user_1_pubKey")
            }},
            std::vector<core::UserWithPubKey>{},
            core::Buffer::from("public"),
            core::Buffer::from("private"),
            std::nullopt,
            1,
            false,
            false
        );
    }, core::Exception);
    // incorrect version force false
    EXPECT_THROW({
        inboxApi->updateInbox(
            reader->getString("Inbox_1.inboxId"),
            std::vector<core::UserWithPubKey>{core::UserWithPubKey{
                .userId=reader->getString("Login.user_1_id"),
                .pubKey=reader->getString("Login.user_1_pubKey")
            }},
            std::vector<core::UserWithPubKey>{},
            core::Buffer::from("public"),
            core::Buffer::from("private"),
            std::nullopt,
            2,
            false,
            false
        );
    }, core::Exception);
}

TEST_F(InboxTest, updateInbox_correct_data) {
    //enable cache
    EXPECT_NO_THROW({
        inboxApi->subscribeForInboxEvents();
    });
    inbox::Inbox inbox;
    // new users
    EXPECT_NO_THROW({
        inboxApi->updateInbox(
            reader->getString("Inbox_1.inboxId"),
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
            std::nullopt,
            1,
            false,
            false
        );
    });
    EXPECT_NO_THROW({
        inbox = inboxApi->getInbox(
            reader->getString("Inbox_1.inboxId")
        );
    });
    EXPECT_EQ(inbox.contextId, reader->getString("Context_1.contextId"));
    EXPECT_EQ(inbox.version, 2);
    EXPECT_EQ(inbox.publicMeta.stdString(), "public");
    EXPECT_EQ(inbox.privateMeta.stdString(), "private");
    EXPECT_EQ(inbox.users.size(), 2);
    if(inbox.users.size() == 2) {
        EXPECT_EQ(inbox.users[0], reader->getString("Login.user_1_id"));
        EXPECT_EQ(inbox.users[1], reader->getString("Login.user_2_id"));
    }
    EXPECT_EQ(inbox.managers.size(), 1);
    if(inbox.managers.size() == 1) {
        EXPECT_EQ(inbox.managers[0], reader->getString("Login.user_1_id"));
    }
    // new managers
    EXPECT_NO_THROW({
        inboxApi->updateInbox(
            reader->getString("Inbox_1.inboxId"),
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
            std::nullopt,
            2,
            false,
            false
        );
    });
    EXPECT_NO_THROW({
        inbox = inboxApi->getInbox(
            reader->getString("Inbox_1.inboxId")
        );
    });
    EXPECT_EQ(inbox.contextId, reader->getString("Context_1.contextId"));
    EXPECT_EQ(inbox.version, 3);
    EXPECT_EQ(inbox.publicMeta.stdString(), "public");
    EXPECT_EQ(inbox.privateMeta.stdString(), "private");
    EXPECT_EQ(inbox.users.size(), 1);
    if(inbox.users.size() == 1) {
        EXPECT_EQ(inbox.users[0], reader->getString("Login.user_1_id"));
    }
    EXPECT_EQ(inbox.managers.size(), 2);
    if(inbox.managers.size() == 2) {
        EXPECT_EQ(inbox.managers[0], reader->getString("Login.user_1_id"));
        EXPECT_EQ(inbox.managers[1], reader->getString("Login.user_2_id"));
    }
    // less users
    EXPECT_NO_THROW({
        inboxApi->updateInbox(
            reader->getString("Inbox_2.inboxId"),
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
            std::nullopt,
            1,
            false,
            false
        );
    });
    EXPECT_NO_THROW({
        inbox = inboxApi->getInbox(
            reader->getString("Inbox_2.inboxId")
        );
    });
    EXPECT_EQ(inbox.contextId, reader->getString("Context_1.contextId"));
    EXPECT_EQ(inbox.version, 2);
    EXPECT_EQ(inbox.publicMeta.stdString(), "public");
    EXPECT_EQ(inbox.privateMeta.stdString(), "private");
    EXPECT_EQ(inbox.users.size(), 2);
    if(inbox.users.size() == 2) {
        EXPECT_EQ(inbox.users[0], reader->getString("Login.user_1_id"));
        EXPECT_EQ(inbox.users[1], reader->getString("Login.user_2_id"));
    }
    EXPECT_EQ(inbox.managers.size(), 1);
    if(inbox.managers.size() == 1) {
        EXPECT_EQ(inbox.managers[0], reader->getString("Login.user_1_id"));
    }
    // less managers
    EXPECT_NO_THROW({
        inboxApi->updateInbox(
            reader->getString("Inbox_2.inboxId"),
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
            std::nullopt,
            2,
            false,
            false
        );
    });
    EXPECT_NO_THROW({
        inbox = inboxApi->getInbox(
            reader->getString("Inbox_2.inboxId")
        );
    });
    EXPECT_EQ(inbox.contextId, reader->getString("Context_1.contextId"));
    EXPECT_EQ(inbox.version, 3);
    EXPECT_EQ(inbox.publicMeta.stdString(), "public");
    EXPECT_EQ(inbox.privateMeta.stdString(), "private");
    EXPECT_EQ(inbox.users.size(), 1);
    if(inbox.users.size() == 1) {
        EXPECT_EQ(inbox.users[0], reader->getString("Login.user_1_id"));
    }
    EXPECT_EQ(inbox.managers.size(), 2);
    if(inbox.managers.size() == 2) {
        EXPECT_EQ(inbox.managers[0], reader->getString("Login.user_1_id"));
        EXPECT_EQ(inbox.managers[1], reader->getString("Login.user_2_id"));
    }
    // incorrect version force true
    EXPECT_NO_THROW({
        inboxApi->updateInbox(
            reader->getString("Inbox_3.inboxId"),
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
            std::nullopt,
            99,
            true,
            false
        );
    });
    EXPECT_NO_THROW({
        inbox = inboxApi->getInbox(
            reader->getString("Inbox_3.inboxId")
        );
    });
    EXPECT_EQ(inbox.contextId, reader->getString("Context_1.contextId"));
    EXPECT_EQ(inbox.version, 2);
    EXPECT_EQ(inbox.publicMeta.stdString(), "public");
    EXPECT_EQ(inbox.privateMeta.stdString(), "private");
    EXPECT_EQ(inbox.users.size(), 1);
    if(inbox.users.size() == 1) {
        EXPECT_EQ(inbox.users[0], reader->getString("Login.user_1_id"));
    }
    EXPECT_EQ(inbox.managers.size(), 1);
    if(inbox.managers.size() == 1) {
        EXPECT_EQ(inbox.managers[0], reader->getString("Login.user_1_id"));
    }
}

TEST_F(InboxTest, deleteInbox) {
    // incorrect inboxId
    EXPECT_THROW({
        inboxApi->deleteInbox(
            reader->getString("Context_1.contextId")
        );
    }, core::Exception);
    // as manager
    EXPECT_NO_THROW({
        inboxApi->deleteInbox(
            reader->getString("Inbox_1.inboxId")
        );
    });
    EXPECT_THROW({
        inboxApi->getInbox(
            reader->getString("Inbox_1.inboxId")
        );
    }, core::Exception);
    // as user
    disconnect();
    connectAs(ConnectionType::User2);
    EXPECT_THROW({
        inboxApi->deleteInbox(
            reader->getString("Inbox_3.inboxId")
        );
    }, core::Exception);
}

TEST_F(InboxTest, getInboxPublicView) {
    inbox::InboxPublicView inboxPublicView;
    // incorrect inboxId
    EXPECT_THROW({
        inboxApi->getInboxPublicView(
            reader->getString("Context_1.contextId")
        );
    }, core::Exception);

    // incorrect inboxId
    disconnect();
    connectAs(ConnectionType::Public);
    EXPECT_NO_THROW({
        inboxPublicView = inboxApi->getInboxPublicView(
            reader->getString("Inbox_1.inboxId")
        );
    });
    EXPECT_EQ(inboxPublicView.inboxId, reader->getString("Inbox_1.inboxId"));
    EXPECT_EQ(inboxPublicView.version, reader->getInt64("Inbox_1.version"));
    EXPECT_EQ(inboxPublicView.publicMeta.stdString(), Hex::toString(reader->getString("Inbox_1.publicMeta_inHex")));
    EXPECT_EQ(inboxPublicView.publicMeta.stdString(), Hex::toString(reader->getString("Inbox_1.uploaded_publicMeta_inHex")));
}

TEST_F(InboxTest, readEntry) {
    inbox::InboxEntry entry;
    // incorrect entryId
    EXPECT_THROW({
        inboxApi->readEntry(
            reader->getString("Context_1.contextId")
        );
    }, core::Exception);
    
    // after force key generation on inbox
    EXPECT_NO_THROW({
        inboxApi->updateInbox(
            reader->getString("Inbox_1.inboxId"),
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
            std::nullopt,
            1,
            true,
            true
        );
    });
    EXPECT_NO_THROW({
        entry = inboxApi->readEntry(
            reader->getString("Entry_1.entryId")
        );
    });
    EXPECT_EQ(entry.entryId, reader->getString("Entry_1.entryId"));
    EXPECT_EQ(entry.inboxId, reader->getString("Entry_1.inboxId"));
    EXPECT_EQ(entry.data.stdString(), Hex::toString(reader->getString("Entry_1.data_inHex")));
    EXPECT_EQ(entry.data.stdString(), Hex::toString(reader->getString("Entry_1.uploaded_data_inHex")));
    EXPECT_EQ(entry.authorPubKey, reader->getString("Entry_1.authorPubKey"));
    EXPECT_EQ(entry.createDate, reader->getInt64("Entry_1.createDate"));
    EXPECT_EQ(entry.statusCode, 0);
    EXPECT_EQ(entry.files.size(), 2);
    if(entry.files.size() >= 1) {
        store::File file = entry.files[0];
        EXPECT_EQ(file.info.storeId, reader->getString("Entry_1.file_0_info_storeId"));
        EXPECT_EQ(file.info.fileId, reader->getString("Entry_1.file_0_info_fileId"));
        EXPECT_EQ(file.info.createDate, reader->getInt64("Entry_1.file_0_info_createDate"));
        EXPECT_EQ(file.info.author, reader->getString("Entry_1.file_0_info_author"));
        EXPECT_EQ(file.authorPubKey, reader->getString("Entry_1.file_0_authorPubKey"));
        EXPECT_EQ(file.statusCode, 0);
        EXPECT_EQ(file.publicMeta.stdString(), Hex::toString(reader->getString("Entry_1.file_0_publicMeta_inHex")));
        EXPECT_EQ(file.publicMeta.stdString(), Hex::toString(reader->getString("Entry_1.uploaded_file_0_publicMeta_inHex")));
        EXPECT_EQ(file.privateMeta.stdString(), Hex::toString(reader->getString("Entry_1.file_0_privateMeta_inHex")));
        EXPECT_EQ(file.privateMeta.stdString(), Hex::toString(reader->getString("Entry_1.uploaded_file_0_privateMeta_inHex")));
        EXPECT_EQ(file.size, reader->getInt64("Entry_1.file_0_size"));
        EXPECT_EQ(file.size, reader->getInt64("Entry_1.uploaded_file_0_size"));
    }
    if(entry.files.size() >= 2) {
        store::File file = entry.files[1];
        EXPECT_EQ(file.info.storeId, reader->getString("Entry_1.file_1_info_storeId"));
        EXPECT_EQ(file.info.fileId, reader->getString("Entry_1.file_1_info_fileId"));
        EXPECT_EQ(file.info.createDate, reader->getInt64("Entry_1.file_1_info_createDate"));
        EXPECT_EQ(file.info.author, reader->getString("Entry_1.file_1_info_author"));
        EXPECT_EQ(file.authorPubKey, reader->getString("Entry_1.file_1_authorPubKey"));
        EXPECT_EQ(file.statusCode, 0);
        EXPECT_EQ(file.publicMeta.stdString(), Hex::toString(reader->getString("Entry_1.file_1_publicMeta_inHex")));
        EXPECT_EQ(file.publicMeta.stdString(), Hex::toString(reader->getString("Entry_1.uploaded_file_1_publicMeta_inHex")));
        EXPECT_EQ(file.privateMeta.stdString(), Hex::toString(reader->getString("Entry_1.file_1_privateMeta_inHex")));
        EXPECT_EQ(file.privateMeta.stdString(), Hex::toString(reader->getString("Entry_1.uploaded_file_1_privateMeta_inHex")));
        EXPECT_EQ(file.size, reader->getInt64("Entry_1.file_1_size"));
        EXPECT_EQ(file.size, reader->getInt64("Entry_1.uploaded_file_1_size"));
    }
}

TEST_F(InboxTest, listEntries_incorrect_input_data) {
    // incorrect inboxId
    EXPECT_THROW({
        inboxApi->listEntries(
            reader->getString("Context_1.contextId"),
            {
                .skip=0, 
                .limit=1, 
                .sortOrder="desc"
            }
        );
    }, core::Exception);
    // limit < 0
    EXPECT_THROW({
        inboxApi->listEntries(
            reader->getString("Inbox_1.inboxId"),
            {
                .skip=0, 
                .limit=-1, 
                .sortOrder="desc"
            }
        );
    }, core::Exception);
    // limit == 0
    EXPECT_THROW({
        inboxApi->listEntries(
            reader->getString("Inbox_1.inboxId"),
            {
                .skip=0, 
                .limit=0, 
                .sortOrder="desc"
            }
        );
    }, core::Exception);
    // incorrect sortOrder
    EXPECT_THROW({
        inboxApi->listEntries(
            reader->getString("Inbox_1.inboxId"),
            {
                .skip=0, 
                .limit=1, 
                .sortOrder="BLACH"
            }
        );
    }, core::Exception);
    // incorrect lastId
    EXPECT_THROW({
        inboxApi->listEntries(
            reader->getString("Inbox_1.inboxId"),
            {
                .skip=0, 
                .limit=1, 
                .sortOrder="desc",
                .lastId=reader->getString("Context_1.contextId")
            }
        );
    }, core::Exception);
}

TEST_F(InboxTest, listEntries_correct_input_data) {
    core::PagingList<inbox::InboxEntry> listEntries;
    inbox::InboxEntry entry;
    //{.skip=4, .limit=1, .sortOrder="desc"}
    EXPECT_NO_THROW({
        listEntries = inboxApi->listEntries(
            reader->getString("Inbox_1.inboxId"),
            {
                .skip=4, 
                .limit=1, 
                .sortOrder="desc"
            }
        );
    });

    EXPECT_EQ(listEntries.totalAvailable, 2);
    EXPECT_EQ(listEntries.readItems.size(), 0);
    //{.skip=1, .limit=1, .sortOrder="desc"}
    EXPECT_NO_THROW({
        listEntries = inboxApi->listEntries(
            reader->getString("Inbox_1.inboxId"),
            {
                .skip=1, 
                .limit=1, 
                .sortOrder="desc"
            }
        );
    });
    EXPECT_EQ(listEntries.totalAvailable, 2);
    EXPECT_EQ(listEntries.readItems.size(), 1);
    if(listEntries.readItems.size() >= 1) {
        entry = listEntries.readItems[0];
        EXPECT_EQ(entry.entryId, reader->getString("Entry_1.entryId"));
        EXPECT_EQ(entry.inboxId, reader->getString("Entry_1.inboxId"));
        EXPECT_EQ(entry.data.stdString(), Hex::toString(reader->getString("Entry_1.data_inHex")));
        EXPECT_EQ(entry.data.stdString(), Hex::toString(reader->getString("Entry_1.uploaded_data_inHex")));
        EXPECT_EQ(entry.authorPubKey, reader->getString("Entry_1.authorPubKey"));
        EXPECT_EQ(entry.createDate, reader->getInt64("Entry_1.createDate"));
        EXPECT_EQ(entry.statusCode, 0);
        EXPECT_EQ(entry.files.size(), 2);
        if(entry.files.size() >= 1) {
            store::File file = entry.files[0];
            EXPECT_EQ(file.info.storeId, reader->getString("Entry_1.file_0_info_storeId"));
            EXPECT_EQ(file.info.fileId, reader->getString("Entry_1.file_0_info_fileId"));
            EXPECT_EQ(file.info.createDate, reader->getInt64("Entry_1.file_0_info_createDate"));
            EXPECT_EQ(file.info.author, reader->getString("Entry_1.file_0_info_author"));
            EXPECT_EQ(file.authorPubKey, reader->getString("Entry_1.file_0_authorPubKey"));
            EXPECT_EQ(file.statusCode, 0);
            EXPECT_EQ(file.publicMeta.stdString(), Hex::toString(reader->getString("Entry_1.file_0_publicMeta_inHex")));
            EXPECT_EQ(file.publicMeta.stdString(), Hex::toString(reader->getString("Entry_1.uploaded_file_0_publicMeta_inHex")));
            EXPECT_EQ(file.privateMeta.stdString(), Hex::toString(reader->getString("Entry_1.file_0_privateMeta_inHex")));
            EXPECT_EQ(file.privateMeta.stdString(), Hex::toString(reader->getString("Entry_1.uploaded_file_0_privateMeta_inHex")));
            EXPECT_EQ(file.size, reader->getInt64("Entry_1.file_0_size"));
            EXPECT_EQ(file.size, reader->getInt64("Entry_1.uploaded_file_0_size"));
        }
        if(entry.files.size() >= 2) {
            store::File file = entry.files[1];
            EXPECT_EQ(file.info.storeId, reader->getString("Entry_1.file_1_info_storeId"));
            EXPECT_EQ(file.info.fileId, reader->getString("Entry_1.file_1_info_fileId"));
            EXPECT_EQ(file.info.createDate, reader->getInt64("Entry_1.file_1_info_createDate"));
            EXPECT_EQ(file.info.author, reader->getString("Entry_1.file_1_info_author"));
            EXPECT_EQ(file.authorPubKey, reader->getString("Entry_1.file_1_authorPubKey"));
            EXPECT_EQ(file.statusCode, 0);
            EXPECT_EQ(file.publicMeta.stdString(), Hex::toString(reader->getString("Entry_1.file_1_publicMeta_inHex")));
            EXPECT_EQ(file.publicMeta.stdString(), Hex::toString(reader->getString("Entry_1.uploaded_file_1_publicMeta_inHex")));
            EXPECT_EQ(file.privateMeta.stdString(), Hex::toString(reader->getString("Entry_1.file_1_privateMeta_inHex")));
            EXPECT_EQ(file.privateMeta.stdString(), Hex::toString(reader->getString("Entry_1.uploaded_file_1_privateMeta_inHex")));
            EXPECT_EQ(file.size, reader->getInt64("Entry_1.file_1_size"));
            EXPECT_EQ(file.size, reader->getInt64("Entry_1.uploaded_file_1_size"));
        }
    }
    // {.skip=0, .limit=3, .sortOrder="asc"}, after force key generation on inbox
    EXPECT_NO_THROW({
        inboxApi->updateInbox(
            reader->getString("Inbox_1.inboxId"),
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
            std::nullopt,
            1,
            true,
            true
        );
    });
    EXPECT_NO_THROW({
        listEntries = inboxApi->listEntries(
            reader->getString("Inbox_1.inboxId"),
            {
                .skip=0, 
                .limit=3, 
                .sortOrder="asc"
            }
        );
    });
    EXPECT_EQ(listEntries.totalAvailable, 2);
    EXPECT_EQ(listEntries.readItems.size(), 2);
    if(listEntries.readItems.size() >= 1) {
        entry = listEntries.readItems[0];
        EXPECT_EQ(entry.entryId, reader->getString("Entry_1.entryId"));
        EXPECT_EQ(entry.inboxId, reader->getString("Entry_1.inboxId"));
        EXPECT_EQ(entry.data.stdString(), Hex::toString(reader->getString("Entry_1.data_inHex")));
        EXPECT_EQ(entry.data.stdString(), Hex::toString(reader->getString("Entry_1.uploaded_data_inHex")));
        EXPECT_EQ(entry.authorPubKey, reader->getString("Entry_1.authorPubKey"));
        EXPECT_EQ(entry.createDate, reader->getInt64("Entry_1.createDate"));
        EXPECT_EQ(entry.statusCode, 0);
        EXPECT_EQ(entry.files.size(), 2);
        if(entry.files.size() >= 1) {
            store::File file = entry.files[0];
            EXPECT_EQ(file.info.storeId, reader->getString("Entry_1.file_0_info_storeId"));
            EXPECT_EQ(file.info.fileId, reader->getString("Entry_1.file_0_info_fileId"));
            EXPECT_EQ(file.info.createDate, reader->getInt64("Entry_1.file_0_info_createDate"));
            EXPECT_EQ(file.info.author, reader->getString("Entry_1.file_0_info_author"));
            EXPECT_EQ(file.authorPubKey, reader->getString("Entry_1.file_0_authorPubKey"));
            EXPECT_EQ(file.statusCode, 0);
            EXPECT_EQ(file.publicMeta.stdString(), Hex::toString(reader->getString("Entry_1.file_0_publicMeta_inHex")));
            EXPECT_EQ(file.publicMeta.stdString(), Hex::toString(reader->getString("Entry_1.uploaded_file_0_publicMeta_inHex")));
            EXPECT_EQ(file.privateMeta.stdString(), Hex::toString(reader->getString("Entry_1.file_0_privateMeta_inHex")));
            EXPECT_EQ(file.privateMeta.stdString(), Hex::toString(reader->getString("Entry_1.uploaded_file_0_privateMeta_inHex")));
            EXPECT_EQ(file.size, reader->getInt64("Entry_1.file_0_size"));
            EXPECT_EQ(file.size, reader->getInt64("Entry_1.uploaded_file_0_size"));
        }
        if(entry.files.size() >= 2) {
            store::File file = entry.files[1];
            EXPECT_EQ(file.info.storeId, reader->getString("Entry_1.file_1_info_storeId"));
            EXPECT_EQ(file.info.fileId, reader->getString("Entry_1.file_1_info_fileId"));
            EXPECT_EQ(file.info.createDate, reader->getInt64("Entry_1.file_1_info_createDate"));
            EXPECT_EQ(file.info.author, reader->getString("Entry_1.file_1_info_author"));
            EXPECT_EQ(file.authorPubKey, reader->getString("Entry_1.file_1_authorPubKey"));
            EXPECT_EQ(file.statusCode, 0);
            EXPECT_EQ(file.publicMeta.stdString(), Hex::toString(reader->getString("Entry_1.file_1_publicMeta_inHex")));
            EXPECT_EQ(file.publicMeta.stdString(), Hex::toString(reader->getString("Entry_1.uploaded_file_1_publicMeta_inHex")));
            EXPECT_EQ(file.privateMeta.stdString(), Hex::toString(reader->getString("Entry_1.file_1_privateMeta_inHex")));
            EXPECT_EQ(file.privateMeta.stdString(), Hex::toString(reader->getString("Entry_1.uploaded_file_1_privateMeta_inHex")));
            EXPECT_EQ(file.size, reader->getInt64("Entry_1.file_1_size"));
            EXPECT_EQ(file.size, reader->getInt64("Entry_1.uploaded_file_1_size"));
        }
    }
    if(listEntries.readItems.size() >= 2) {
        entry = listEntries.readItems[1];
        EXPECT_EQ(entry.entryId, reader->getString("Entry_2.entryId"));
        EXPECT_EQ(entry.inboxId, reader->getString("Entry_2.inboxId"));
        EXPECT_EQ(entry.data.stdString(), Hex::toString(reader->getString("Entry_2.data_inHex")));
        EXPECT_EQ(entry.data.stdString(), Hex::toString(reader->getString("Entry_2.uploaded_data_inHex")));
        EXPECT_EQ(entry.authorPubKey, reader->getString("Entry_2.authorPubKey"));
        EXPECT_EQ(entry.createDate, reader->getInt64("Entry_2.createDate"));
        EXPECT_EQ(entry.statusCode, 0);
        EXPECT_EQ(entry.files.size(), 0);
    }
}

TEST_F(InboxTest, deleteEntry) {
    // incorrect entryId
    EXPECT_THROW({
        inboxApi->deleteEntry(
            reader->getString("Inbox_1.inboxId")
        );
    }, core::Exception);
    // change privileges
    EXPECT_NO_THROW({
        inboxApi->updateInbox(
            reader->getString("Inbox_1.inboxId"),
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
            std::nullopt,
            1,
            true,
            false
        );
    });
    // as user not created by me
    disconnect();
    connectAs(ConnectionType::User2);
    EXPECT_THROW({
        inboxApi->deleteEntry(
            reader->getString("Entry_2.entryId")
        );
    }, core::Exception);
    // change privileges
    disconnect();
    connectAs(ConnectionType::User1);
    EXPECT_NO_THROW({
        inboxApi->updateInbox(
            reader->getString("Inbox_1.inboxId"),
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
                }
            },
            core::Buffer::from("public"),
            core::Buffer::from("private"),
            std::nullopt,
            2,
            true,
            false
        );
    });
    disconnect();
    connectAs(ConnectionType::User2);
    EXPECT_NO_THROW({
        inboxApi->updateInbox(
            reader->getString("Inbox_1.inboxId"),
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
            std::nullopt,
            2,
            true,
            false
        );
    });
    // as user created by me
    disconnect();
    connectAs(ConnectionType::User1);
    EXPECT_THROW({
        inboxApi->deleteEntry(
            reader->getString("Entry_2.entryId")
        );
    }, core::Exception);
    disconnect();
    connectAs(ConnectionType::User2);
    // as manager no created by me
    EXPECT_NO_THROW({
        inboxApi->deleteEntry(
            reader->getString("Entry_1.entryId")
        );
    });

}

TEST_F(InboxTest, openFile_readFromFile_seekInFile_incorrect_data) {
    // openFile incorrect fileId
    EXPECT_THROW({
        inboxApi->openFile(
            reader->getString("Entry_1.entryId")
        );
    }, core::Exception);
    // readFromFile incorrect handle (no exist)
    EXPECT_THROW({
        inboxApi->readFromFile(
            0,
            10
        );
    }, core::Exception);
    // seekInFile incorrect handle (no exist)
    EXPECT_THROW({
        inboxApi->seekInFile(
            0,
            10
        );
    }, core::Exception);

    // create write handle 
    int64_t fileHandle = 0;
    EXPECT_NO_THROW({
        fileHandle = inboxApi->createFileHandle(
            core::Buffer::from("public"),
            core::Buffer::from("private"),
            10
        );
    });
    if(fileHandle == 1) {
        // readFromFile incorrect handle (write)
        EXPECT_THROW({
            inboxApi->readFromFile(
                fileHandle,
                10
            );
        }, core::Exception);
        // seekInFile incorrect handle (write)
        EXPECT_THROW({
            inboxApi->seekInFile(
                fileHandle,
                10
            );
        }, core::Exception);
    } else {
        std::cout << "Failed to createFileHandle" << std::endl;
    }
    
}

TEST_F(InboxTest, openFile_readFromFile_seekInFile_closeFile) {
    int64_t fileHandle = 0;
    std::string fileData = ""; 
    EXPECT_NO_THROW({
        fileHandle = inboxApi->openFile(
            reader->getString("Entry_1.file_0_info_fileId")
        );
    });
    if(fileHandle == 1) {
        // seekInFile pos < 0
        EXPECT_THROW({
            inboxApi->seekInFile(
                fileHandle,
                -1
            );
        }, core::Exception);
        // seekInFile pos > file.size
        EXPECT_THROW({
            inboxApi->seekInFile(
                fileHandle,
                reader->getInt64("Entry_1.file_0_size")+1
            );
        }, core::Exception);
        // seekInFile pos == 50% file.size
        EXPECT_NO_THROW({
            inboxApi->seekInFile(
                fileHandle,
                reader->getInt64("Entry_1.file_0_size")/2
            );
        });
        // readFromFile length == file.size
        EXPECT_NO_THROW({
            fileData = inboxApi->readFromFile(
                fileHandle,
                reader->getInt64("Entry_1.file_0_size")
            ).stdString();
        });
        EXPECT_EQ(fileData.length(), (reader->getInt64("Entry_1.file_0_size")/2) + (reader->getInt64("Entry_1.file_0_size")%2));
        // seekInFile pos == 0
        EXPECT_NO_THROW({
            inboxApi->seekInFile(
                fileHandle,
                0
            );
        });
        // readFromFile length == 50% file.size
        EXPECT_NO_THROW({
            fileData = inboxApi->readFromFile(
                fileHandle,
                reader->getInt64("Entry_1.file_0_size")/2
            ).stdString() + fileData;
        });
        EXPECT_EQ(fileData.length(), reader->getInt64("Entry_1.file_0_size"));
        // closeFile
        EXPECT_NO_THROW({
            inboxApi->closeFile(
                fileHandle
            );
        });
        // validate
        EXPECT_EQ(fileData.length(), reader->getInt64("Entry_1.file_0_size"));
        EXPECT_EQ(fileData.length(), reader->getInt64("Entry_1.uploaded_file_0_size"));
        EXPECT_EQ(fileData, Hex::toString(reader->getString("Entry_1.uploaded_file_0_data_inHex")));

    } else {
        std::cout << "Failed to openFile" << std::endl;
    }
}

TEST_F(InboxTest, createFileHandle_prepareEntry_writeToFile_sendEntry_as_Public) {
    
    disconnect();
    connectAs(ConnectionType::Public);    
    int64_t fileHandle_1 = 0;
    int64_t fileHandle_2 = 0;
    // createFileHandle size = 0
    EXPECT_NO_THROW({
        fileHandle_1 = inboxApi->createFileHandle(
            privmx::endpoint::core::Buffer::from("publicMeta_1"),
            privmx::endpoint::core::Buffer::from("privateMeta_1"),
            0
        );
    });
    // createFileHandle size > 0
    EXPECT_NO_THROW({
        fileHandle_2 = inboxApi->createFileHandle(
            privmx::endpoint::core::Buffer::from("publicMeta_2"),
            privmx::endpoint::core::Buffer::from("privateMeta_2"),
            1024*128
        );
    });
    EXPECT_EQ(fileHandle_1, 1);
    EXPECT_EQ(fileHandle_2, 2);
    if(fileHandle_1 == 1 && fileHandle_2 == 2) {
        int64_t inboxHandle = 0;
        // prepareEntry with 1, 2
        EXPECT_NO_THROW({
            inboxHandle = inboxApi->prepareEntry(
                reader->getString("Inbox_2.inboxId"),
                core::Buffer::from("test_sendEntry"),
                {fileHandle_1, fileHandle_2},
                reader->getString("Login.user_1_privKey")
            );
        });
        EXPECT_EQ(inboxHandle, 3);
        if(inboxHandle == 3) {
            std::string total_data_send = "";
            EXPECT_THROW({
                inboxApi->closeFile(fileHandle_1);
            }, core::Exception);
            EXPECT_NO_THROW({
                for(int i = 0; i<64; i++) {
                    std::string random_data = privmx::crypto::Crypto::randomBytes(1024);
                    inboxApi->writeToFile(
                        inboxHandle,
                        fileHandle_2,
                        core::Buffer::from(random_data)
                    );
                    total_data_send += random_data;
                }
            });
            EXPECT_NO_THROW({
                for(int i = 0; i<64; i++) {
                    std::string random_data = privmx::crypto::Crypto::randomBytes(1024);
                    inboxApi->writeToFile(
                        inboxHandle,
                        fileHandle_2,
                        core::Buffer::from(random_data)
                    );
                    total_data_send += random_data;
                }
            });
            EXPECT_NO_THROW({
                inboxApi->sendEntry(inboxHandle);
            });
            disconnect();
            connectAs(ConnectionType::User1);
            auto entries = inboxApi->listEntries(
                reader->getString("Inbox_2.inboxId"),
                {
                    .skip=0, 
                    .limit=1, 
                    .sortOrder="asc"
                }
            );

            EXPECT_EQ(entries.totalAvailable, 1);
            EXPECT_EQ(entries.readItems.size(), 1);
            if(entries.readItems.size() >= 1) {
                auto entry = entries.readItems[0];
                EXPECT_EQ(entry.inboxId, reader->getString("Inbox_2.inboxId"));
                EXPECT_EQ(entry.data.stdString(), "test_sendEntry");
                EXPECT_EQ(entry.files.size(), 2);
                if(entry.files.size() >= 1) {
                    auto file = entry.files[0];
                    EXPECT_EQ(file.statusCode, 0);
                    EXPECT_EQ(file.publicMeta.stdString(), "publicMeta_1");
                    EXPECT_EQ(file.privateMeta.stdString(), "privateMeta_1");
                    EXPECT_EQ(file.size, 0);
                }
                if(entry.files.size() >= 2) {   
                    auto file = entry.files[1];
                    EXPECT_EQ(file.statusCode, 0);
                    EXPECT_EQ(file.publicMeta.stdString(), "publicMeta_2");
                    EXPECT_EQ(file.privateMeta.stdString(), "privateMeta_2");
                    EXPECT_EQ(file.size, 128*1024);
                    disconnect();
                    connectAs(ConnectionType::User1); 
                    int64_t readHandle = 0;
                    EXPECT_NO_THROW({
                        readHandle = inboxApi->openFile(file.info.fileId);
                    });
                    std::string total_data_read = "";
                    for(int i = 0; i < 128; i++) {
                        total_data_read += inboxApi->readFromFile(
                            readHandle,
                            1024
                        ).stdString();
                    }
                    EXPECT_EQ(total_data_read, total_data_send);
                }
            }
        } else {
            std::cout << "prepareEntry Failed" << std::endl;
            FAIL();
        }
    } else {
        std::cout << "createFileHandle Failed" << std::endl;
        FAIL();
    }
}

TEST_F(InboxTest, createFileHandle_prepareEntry_writeToFile_sendEntry_as_user) {
    int64_t fileHandle_1 = 0;
    int64_t fileHandle_2 = 0;
    // createFileHandle size = 0
    EXPECT_NO_THROW({
        fileHandle_1 = inboxApi->createFileHandle(
            privmx::endpoint::core::Buffer::from("publicMeta_1"),
            privmx::endpoint::core::Buffer::from("privateMeta_1"),
            0
        );
    });
    // createFileHandle size > 0
    EXPECT_NO_THROW({
        fileHandle_2 = inboxApi->createFileHandle(
            privmx::endpoint::core::Buffer::from("publicMeta_2"),
            privmx::endpoint::core::Buffer::from("privateMeta_2"),
            1024*128
        );
    });
    EXPECT_EQ(fileHandle_1, 1);
    EXPECT_EQ(fileHandle_2, 2);
    if(fileHandle_1 == 1 && fileHandle_2 == 2) {
        int64_t inboxHandle = 0;
        // prepareEntry with 1, 2
        EXPECT_NO_THROW({
            inboxHandle = inboxApi->prepareEntry(
                reader->getString("Inbox_2.inboxId"),
                core::Buffer::from("test_sendEntry"),
                {fileHandle_1, fileHandle_2},
                reader->getString("Login.user_1_privKey")
            );
        });
        EXPECT_EQ(inboxHandle, 3);
        if(inboxHandle == 3) {
            std::string total_data_send = "";
            EXPECT_THROW({
                inboxApi->closeFile(fileHandle_1);
            }, core::Exception);
            EXPECT_NO_THROW({
                for(int i = 0; i<64; i++) {
                    std::string random_data = privmx::crypto::Crypto::randomBytes(1024);
                    inboxApi->writeToFile(
                        inboxHandle,
                        fileHandle_2,
                        core::Buffer::from(random_data)
                    );
                    total_data_send += random_data;
                }
            });
            EXPECT_NO_THROW({
                for(int i = 0; i<64; i++) {
                    std::string random_data = privmx::crypto::Crypto::randomBytes(1024);
                    inboxApi->writeToFile(
                        inboxHandle,
                        fileHandle_2,
                        core::Buffer::from(random_data)
                    );
                    total_data_send += random_data;
                }
            });
            EXPECT_NO_THROW({
                inboxApi->sendEntry(inboxHandle);
            });
            auto entries = inboxApi->listEntries(
                reader->getString("Inbox_2.inboxId"),
                {
                    .skip=0, 
                    .limit=1, 
                    .sortOrder="asc"
                }
            );

            EXPECT_EQ(entries.totalAvailable, 1);
            EXPECT_EQ(entries.readItems.size(), 1);
            if(entries.readItems.size() >= 1) {
                auto entry = entries.readItems[0];
                EXPECT_EQ(entry.inboxId, reader->getString("Inbox_2.inboxId"));
                EXPECT_EQ(entry.data.stdString(), "test_sendEntry");
                EXPECT_EQ(entry.files.size(), 2);
                if(entry.files.size() >= 1) {
                    auto file = entry.files[0];
                    EXPECT_EQ(file.statusCode, 0);
                    EXPECT_EQ(file.publicMeta.stdString(), "publicMeta_1");
                    EXPECT_EQ(file.privateMeta.stdString(), "privateMeta_1");
                    EXPECT_EQ(file.size, 0);
                }
                if(entry.files.size() >= 2) {
                    auto file = entry.files[1];
                    EXPECT_EQ(file.statusCode, 0);
                    EXPECT_EQ(file.publicMeta.stdString(), "publicMeta_2");
                    EXPECT_EQ(file.privateMeta.stdString(), "privateMeta_2");
                    EXPECT_EQ(file.size, 128*1024);
                    int64_t readHandle = 0;
                    EXPECT_NO_THROW({
                        readHandle = inboxApi->openFile(file.info.fileId);
                    });
                    std::string total_data_read = "";
                    for(int i = 0; i < 128; i++) {
                        total_data_read += inboxApi->readFromFile(
                            readHandle,
                            1024
                        ).stdString();
                    }
                    EXPECT_EQ(total_data_read, total_data_send);
                }
            }
        } else {
            std::cout << "prepareEntry Failed" << std::endl;
            FAIL();
        }
    } else {
        std::cout << "createFileHandle Failed" << std::endl;
        FAIL();
    }
}

TEST_F(InboxTest, Access_denaid_not_in_users_or_managers) {
    disconnect();
    connectAs(ConnectionType::User2);
    // getInbox
    EXPECT_THROW({
        inboxApi->getInbox(
            reader->getString("Inbox_1.inboxId")
        );
    }, core::Exception);
    // updateInbox
    EXPECT_THROW({
        inboxApi->updateInbox(
            reader->getString("Inbox_1.inboxId"),
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
            std::nullopt,
            1,
            false,
            false
        );
    }, core::Exception);
    // deleteInbox
    EXPECT_THROW({
        inboxApi->deleteInbox(
            reader->getString("Inbox_1.inboxId")
        );
    }, core::Exception);
    // readEntry
    EXPECT_THROW({
        inboxApi->readEntry(
            reader->getString("Entry_1.entryId")
        );
    }, core::Exception);
    // listEntries
    EXPECT_THROW({
        inboxApi->listEntries(
            reader->getString("Inbox_1.inboxId"),
            {
                .skip=0, 
                .limit=1, 
                .sortOrder="asc"
            }
        );
    }, core::Exception);
    // openFile
    EXPECT_THROW({
        inboxApi->openFile(
            reader->getString("Entry_1.file_0_info_fileId")
        );
    }, core::Exception);
}

TEST_F(InboxTest, Access_denaid_Public) {
    disconnect();
    connectAs(ConnectionType::Public);
    // getInbox
    EXPECT_THROW({
        inboxApi->getInbox(
            reader->getString("Inbox_1.inboxId")
        );
    }, core::Exception);
    // listInboxes
    EXPECT_THROW({
        inboxApi->listInboxes(
            reader->getString("Context_1.contextId"),
            {
                .skip=0, 
                .limit=1, 
                .sortOrder="desc"
            }
        );
    }, core::Exception);
    // createInbox
    EXPECT_THROW({
        inboxApi->createInbox(
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
            std::nullopt
        );
    }, core::Exception);
    // updateInbox
    EXPECT_THROW({
        inboxApi->updateInbox(
            reader->getString("Inbox_1.inboxId"),
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
            std::nullopt,
            1,
            false,
            false
        );
    }, core::Exception);
    // deleteInbox
    EXPECT_THROW({
        inboxApi->deleteInbox(
            reader->getString("Inbox_1.inboxId")
        );
    }, core::Exception);
    // readEntry
    EXPECT_THROW({
        inboxApi->readEntry(
            reader->getString("Entry_1.entryId")
        );
    }, core::Exception);
    // listEntries
    EXPECT_THROW({
        inboxApi->listEntries(
            reader->getString("Inbox_1.inboxId"),
            {
                .skip=0, 
                .limit=1, 
                .sortOrder="asc"
            }
        );
    }, core::Exception);
    // openFile
    EXPECT_THROW({
        inboxApi->openFile(
            reader->getString("Entry_1.file_0_info_fileId")
        );
    }, core::Exception);
}

TEST_F(InboxTest, createInbox_policy) {
    std::string inboxId;
    privmx::endpoint::inbox::Inbox inbox;
    core::ContainerPolicy policy;
    policy.get="owner";
    policy.update="owner";
    policy.delete_="owner";
    policy.updatePolicy="owner";
    policy.updaterCanBeRemovedFromManagers="no";
    policy.ownerCanBeRemovedFromManagers="no";
    EXPECT_NO_THROW({
        inboxId = inboxApi->createInbox(
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
            std::nullopt,
            policy
        );
    });
    if(inboxId.empty()) { 
        FAIL();
    }
    EXPECT_NO_THROW({
        inbox = inboxApi->getInbox(
            inboxId
        );
    });
    EXPECT_EQ(inbox.contextId, reader->getString("Context_1.contextId"));
    EXPECT_EQ(inbox.publicMeta.stdString(), "public");
    EXPECT_EQ(inbox.privateMeta.stdString(), "private");
    EXPECT_EQ(inbox.users.size(), 2);
    if(inbox.users.size() == 2) {
        EXPECT_EQ(inbox.users[0], reader->getString("Login.user_1_id"));
        EXPECT_EQ(inbox.users[1], reader->getString("Login.user_2_id"));
    }
    EXPECT_EQ(inbox.managers.size(), 2);
    if(inbox.managers.size() == 2) {
        EXPECT_EQ(inbox.managers[0], reader->getString("Login.user_1_id"));
        EXPECT_EQ(inbox.managers[1], reader->getString("Login.user_2_id"));
    }
    EXPECT_EQ(inbox.policy.get, policy.get);
    EXPECT_EQ(inbox.policy.update, policy.update);
    EXPECT_EQ(inbox.policy.delete_, policy.delete_);
    EXPECT_EQ(inbox.policy.updatePolicy, policy.updatePolicy);
    EXPECT_EQ(inbox.policy.updaterCanBeRemovedFromManagers, policy.updaterCanBeRemovedFromManagers);
    EXPECT_EQ(inbox.policy.ownerCanBeRemovedFromManagers, policy.ownerCanBeRemovedFromManagers);
    disconnect();
    connectAs(ConnectionType::User2);
    EXPECT_THROW({
        inbox = inboxApi->getInbox(
            inboxId
        );
    }, core::Exception);
}

TEST_F(InboxTest, updateInbox_policy) {
    // same users and managers
    std::string inboxId = reader->getString("Inbox_1.inboxId");
    privmx::endpoint::inbox::Inbox inbox;
    core::ContainerPolicyWithoutItem policy;
    policy.get="owner";
    policy.update="owner";
    policy.delete_="owner";
    policy.updatePolicy="owner";
    policy.updaterCanBeRemovedFromManagers="no";
    policy.ownerCanBeRemovedFromManagers="no";
    EXPECT_NO_THROW({
        inboxApi->updateInbox(
            inboxId,
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
            std::nullopt,
            1,
            true,
            true,
            policy
        );
    });
    if(inboxId.empty()) { 
        FAIL();
    }
    EXPECT_NO_THROW({
        inbox = inboxApi->getInbox(
            inboxId
        );
    });
    EXPECT_EQ(inbox.contextId, reader->getString("Context_1.contextId"));
    EXPECT_EQ(inbox.publicMeta.stdString(), "public");
    EXPECT_EQ(inbox.privateMeta.stdString(), "private");
    EXPECT_EQ(inbox.users.size(), 2);
    if(inbox.users.size() == 2) {
        EXPECT_EQ(inbox.users[0], reader->getString("Login.user_1_id"));
        EXPECT_EQ(inbox.users[1], reader->getString("Login.user_2_id"));
    }
    EXPECT_EQ(inbox.managers.size(), 2);
    if(inbox.managers.size() == 2) {
        EXPECT_EQ(inbox.managers[0], reader->getString("Login.user_1_id"));
        EXPECT_EQ(inbox.managers[1], reader->getString("Login.user_2_id"));
    }
    EXPECT_EQ(inbox.policy.get, policy.get);
    EXPECT_EQ(inbox.policy.update, policy.update);
    EXPECT_EQ(inbox.policy.delete_, policy.delete_);
    EXPECT_EQ(inbox.policy.updatePolicy, policy.updatePolicy);
    EXPECT_EQ(inbox.policy.updaterCanBeRemovedFromManagers, policy.updaterCanBeRemovedFromManagers);
    EXPECT_EQ(inbox.policy.ownerCanBeRemovedFromManagers, policy.ownerCanBeRemovedFromManagers);
    disconnect();
    connectAs(ConnectionType::User2);
    EXPECT_THROW({
        inboxApi->getInbox(
            inboxId
        );
    }, core::Exception);
}


TEST_F(InboxTest, listInboxes_query) {
    std::string inboxId;
    core::PagingList<inbox::Inbox> listInboxes;
    EXPECT_NO_THROW({
        inboxId = inboxApi->createInbox(
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
            std::nullopt,
            std::nullopt
        );
    });
    if(inboxId.empty()) { 
        FAIL();
    }
    EXPECT_THROW({
        listInboxes = inboxApi->listInboxes(
            reader->getString("Context_1.contextId"),
            core::PagingQuery{
                .skip=0,
                .limit=100,
                .sortOrder="asc",
                .queryAsJson="{\"test\":1}"
            }
        );
    }, privmx::endpoint::inbox::InboxModuleDoesNotSupportQueriesYetException);
}

TEST_F(InboxTest, update_access_to_old_entries) {
    EXPECT_NO_THROW({
        inboxApi->updateInbox(
            reader->getString("Inbox_1.inboxId"),
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
            std::nullopt,
            1,
            true,
            true
        );
    });
    disconnect();
    connectAs(User2);
    privmx::endpoint::inbox::InboxEntry entry;
    EXPECT_NO_THROW({
        entry = inboxApi->readEntry(
            reader->getString("Entry_1.entryId")
        );
    });
    EXPECT_EQ(entry.statusCode, 0);
}