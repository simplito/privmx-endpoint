#include <gtest/gtest.h>
#include "../utils/BaseTest.hpp"
#include <privmx/endpoint/core/Exception.hpp>
#include <Poco/Util/IniFileConfiguration.h>
#include <privmx/endpoint/core/EventQueueImpl.hpp>
#include <privmx/crypto/Crypto.hpp>
#include <privmx/utils/Utils.hpp>
#include <privmx/endpoint/core/VarSerializer.hpp>
#include <privmx/endpoint/core/Connection.hpp>
#include <privmx/endpoint/kvdb/KvdbApi.hpp>
#include <privmx/endpoint/kvdb/KvdbVarSerializer.hpp>
#include <privmx/endpoint/core/CoreException.hpp>
using namespace privmx::endpoint;


enum ConnectionType {
    User1,
    User2,
    Public
};

class KvdbTest : public privmx::test::BaseTest {
protected:
    KvdbTest() : BaseTest(privmx::test::BaseTestMode::online) {}
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
        kvdbApi = std::make_shared<kvdb::KvdbApi>(
            kvdb::KvdbApi::create(
                *connection
            )
        );
    }
    void disconnect() {
        connection->disconnect();
        connection.reset();
        kvdbApi.reset();
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
        kvdbApi = std::make_shared<kvdb::KvdbApi>(
            kvdb::KvdbApi::create(
                *connection
            )
        );
    }
    void customTearDown() override { // tmp segfault fix
        connection.reset();
        kvdbApi.reset();
        reader.reset();
        core::EventQueueImpl::getInstance()->clear();
    }
    std::shared_ptr<core::Connection> connection;
    std::shared_ptr<kvdb::KvdbApi> kvdbApi;
    Poco::Util::IniFileConfiguration::Ptr reader;
    core::VarSerializer _serializer = core::VarSerializer({});
};


TEST_F(KvdbTest, getKvdb) {
    kvdb::Kvdb kvdb;
    // incorrect kvdbId
    EXPECT_THROW({
        kvdbApi->getKvdb(
            reader->getString("Context_1.contextId")
        );
    }, core::Exception);
    // correct kvdbId
    EXPECT_NO_THROW({
        kvdb = kvdbApi->getKvdb(
            reader->getString("Kvdb_1.kvdbId")
        );
    });
    EXPECT_EQ(kvdb.contextId, reader->getString("Kvdb_1.contextId"));
    EXPECT_EQ(kvdb.kvdbId, reader->getString("Kvdb_1.kvdbId"));
    EXPECT_EQ(kvdb.createDate, reader->getInt64("Kvdb_1.createDate"));
    EXPECT_EQ(kvdb.creator, reader->getString("Kvdb_1.creator"));
    EXPECT_EQ(kvdb.lastModificationDate, reader->getInt64("Kvdb_1.lastModificationDate"));
    EXPECT_EQ(kvdb.lastModifier, reader->getString("Kvdb_1.lastModifier"));
    EXPECT_EQ(kvdb.version, reader->getInt64("Kvdb_1.version"));
    EXPECT_EQ(kvdb.lastEntryDate, reader->getInt64("Kvdb_1.lastEntryDate"));
    EXPECT_EQ(kvdb.entries, reader->getInt64("Kvdb_1.entries"));
    EXPECT_EQ(kvdb.statusCode, 0);
    EXPECT_EQ(kvdb.publicMeta.stdString(), privmx::utils::Hex::toString(reader->getString("Kvdb_1.publicMeta_inHex")));
    EXPECT_EQ(kvdb.publicMeta.stdString(), privmx::utils::Hex::toString(reader->getString("Kvdb_1.uploaded_publicMeta_inHex")));
    EXPECT_EQ(kvdb.privateMeta.stdString(), privmx::utils::Hex::toString(reader->getString("Kvdb_1.privateMeta_inHex")));
    EXPECT_EQ(kvdb.privateMeta.stdString(), privmx::utils::Hex::toString(reader->getString("Kvdb_1.uploaded_privateMeta_inHex")));

    EXPECT_EQ(kvdb.version, 1);
    EXPECT_EQ(kvdb.creator, reader->getString("Login.user_1_id"));
    EXPECT_EQ(kvdb.lastModifier, reader->getString("Login.user_1_id"));
    EXPECT_EQ(kvdb.users.size(), 1);
    if(kvdb.users.size() == 1) {
        EXPECT_EQ(kvdb.users[0], reader->getString("Login.user_1_id"));
    }
    EXPECT_EQ(kvdb.managers.size(), 1);
    if(kvdb.managers.size() == 1) {
        EXPECT_EQ(kvdb.managers[0], reader->getString("Login.user_1_id"));
    }
}

TEST_F(KvdbTest, listKvdbs_incorrect_input_data) {
    // incorrect contextId
    EXPECT_THROW({
        kvdbApi->listKvdbs(
            reader->getString("Kvdb_1.kvdbId"),
            {
                .skip=0, 
                .limit=1, 
                .sortOrder="desc"
            }
        );
    }, core::Exception);
    // limit < 0
    EXPECT_THROW({
        kvdbApi->listKvdbs(
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
        kvdbApi->listKvdbs(
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
        kvdbApi->listKvdbs(
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
        kvdbApi->listKvdbs(
            reader->getString("Context_1.contextId"),
            {
                .skip=0, 
                .limit=1, 
                .sortOrder="desc",
                .lastId=reader->getString("Context_1.contextId")
            }
        );
    }, core::Exception);
    // incorrect queryAsJson
    EXPECT_THROW({
        kvdbApi->listKvdbs(
            reader->getString("Context_1.contextId"),
            {
                .skip=0, 
                .limit=1, 
                .sortOrder="desc",
                .lastId=std::nullopt,
                .queryAsJson="{BLACH,}"
            }
        );
    }, core::InvalidParamsException);
}

TEST_F(KvdbTest, listKvdbs_correct_input_data) {
    core::PagingList<kvdb::Kvdb> listKvdbs;
    // {.skip=4, .limit=1, .sortOrder="desc"}
    EXPECT_NO_THROW({
        listKvdbs = kvdbApi->listKvdbs(
            reader->getString("Context_1.contextId"),
            {
                .skip=4, 
                .limit=1, 
                .sortOrder="desc"
            }
        );
    });
    EXPECT_EQ(listKvdbs.totalAvailable, 3);
    EXPECT_EQ(listKvdbs.readItems.size(), 0);
    // {.skip=0, .limit=1, .sortOrder="asc"}
    EXPECT_NO_THROW({
        listKvdbs = kvdbApi->listKvdbs(
            reader->getString("Context_1.contextId"),
            {
                .skip=0, 
                .limit=1, 
                .sortOrder="desc"
            }
        );
    });
    EXPECT_EQ(listKvdbs.totalAvailable, 3);
    EXPECT_EQ(listKvdbs.readItems.size(), 1);
    if(listKvdbs.readItems.size() >= 1) {
        auto kvdb = listKvdbs.readItems[0];
        EXPECT_EQ(kvdb.contextId, reader->getString("Kvdb_3.contextId"));
        EXPECT_EQ(kvdb.kvdbId, reader->getString("Kvdb_3.kvdbId"));
        EXPECT_EQ(kvdb.createDate, reader->getInt64("Kvdb_3.createDate"));
        EXPECT_EQ(kvdb.creator, reader->getString("Kvdb_3.creator"));
        EXPECT_EQ(kvdb.lastModificationDate, reader->getInt64("Kvdb_3.lastModificationDate"));
        EXPECT_EQ(kvdb.lastModifier, reader->getString("Kvdb_3.lastModifier"));
        EXPECT_EQ(kvdb.version, reader->getInt64("Kvdb_3.version"));
        EXPECT_EQ(kvdb.lastEntryDate, reader->getInt64("Kvdb_3.lastEntryDate"));
        EXPECT_EQ(kvdb.entries, reader->getInt64("Kvdb_3.entries"));
        EXPECT_EQ(kvdb.statusCode, 0);
        EXPECT_EQ(kvdb.publicMeta.stdString(), privmx::utils::Hex::toString(reader->getString("Kvdb_3.publicMeta_inHex")));
        EXPECT_EQ(kvdb.publicMeta.stdString(), privmx::utils::Hex::toString(reader->getString("Kvdb_3.uploaded_publicMeta_inHex")));
        EXPECT_EQ(kvdb.privateMeta.stdString(), privmx::utils::Hex::toString(reader->getString("Kvdb_3.privateMeta_inHex")));
        EXPECT_EQ(kvdb.privateMeta.stdString(), privmx::utils::Hex::toString(reader->getString("Kvdb_3.uploaded_privateMeta_inHex")));
        EXPECT_EQ(kvdb.version, 1);
        EXPECT_EQ(kvdb.creator, reader->getString("Login.user_1_id"));
        EXPECT_EQ(kvdb.lastModifier, reader->getString("Login.user_1_id"));
        EXPECT_EQ(kvdb.users.size(), 2);
        if(kvdb.users.size() == 2) {
            EXPECT_EQ(kvdb.users[0], reader->getString("Login.user_1_id"));
            EXPECT_EQ(kvdb.users[1], reader->getString("Login.user_2_id"));
        }
        EXPECT_EQ(kvdb.managers.size(), 1);
        if(kvdb.managers.size() == 1) {
            EXPECT_EQ(kvdb.managers[0], reader->getString("Login.user_1_id"));
        }
    }
    // {.skip=1, .limit=3, .sortOrder="asc"}
    EXPECT_NO_THROW({
        listKvdbs = kvdbApi->listKvdbs(
            reader->getString("Context_1.contextId"),
            {
                .skip=1, 
                .limit=3, 
                .sortOrder="asc"
            }
        );
    });
    EXPECT_EQ(listKvdbs.totalAvailable, 3);
    EXPECT_EQ(listKvdbs.readItems.size(), 2);
    if(listKvdbs.readItems.size() >= 1) {
        auto kvdb = listKvdbs.readItems[0];
        EXPECT_EQ(kvdb.contextId, reader->getString("Kvdb_2.contextId"));
        EXPECT_EQ(kvdb.kvdbId, reader->getString("Kvdb_2.kvdbId"));
        EXPECT_EQ(kvdb.createDate, reader->getInt64("Kvdb_2.createDate"));
        EXPECT_EQ(kvdb.creator, reader->getString("Kvdb_2.creator"));
        EXPECT_EQ(kvdb.lastModificationDate, reader->getInt64("Kvdb_2.lastModificationDate"));
        EXPECT_EQ(kvdb.lastModifier, reader->getString("Kvdb_2.lastModifier"));
        EXPECT_EQ(kvdb.version, reader->getInt64("Kvdb_2.version"));
        EXPECT_EQ(kvdb.lastEntryDate, reader->getInt64("Kvdb_2.lastEntryDate"));
        EXPECT_EQ(kvdb.entries, reader->getInt64("Kvdb_2.entries"));
        EXPECT_EQ(kvdb.statusCode, 0);
        EXPECT_EQ(kvdb.publicMeta.stdString(), privmx::utils::Hex::toString(reader->getString("Kvdb_2.publicMeta_inHex")));
        EXPECT_EQ(kvdb.publicMeta.stdString(), privmx::utils::Hex::toString(reader->getString("Kvdb_2.uploaded_publicMeta_inHex")));
        EXPECT_EQ(kvdb.privateMeta.stdString(), privmx::utils::Hex::toString(reader->getString("Kvdb_2.privateMeta_inHex")));
        EXPECT_EQ(kvdb.privateMeta.stdString(), privmx::utils::Hex::toString(reader->getString("Kvdb_2.uploaded_privateMeta_inHex")));
        EXPECT_EQ(kvdb.version, 1);
        EXPECT_EQ(kvdb.creator, reader->getString("Login.user_1_id"));
        EXPECT_EQ(kvdb.lastModifier, reader->getString("Login.user_1_id"));
        EXPECT_EQ(kvdb.users.size(), 2);
        if(kvdb.users.size() == 2) {
            EXPECT_EQ(kvdb.users[0], reader->getString("Login.user_1_id"));
            EXPECT_EQ(kvdb.users[1], reader->getString("Login.user_2_id"));
        }
        EXPECT_EQ(kvdb.managers.size(), 2);
        if(kvdb.managers.size() == 2) {
            EXPECT_EQ(kvdb.managers[0], reader->getString("Login.user_1_id"));
            EXPECT_EQ(kvdb.managers[1], reader->getString("Login.user_2_id"));
        }
    }
    if(listKvdbs.readItems.size() >= 2) {
        auto kvdb = listKvdbs.readItems[1];
        EXPECT_EQ(kvdb.contextId, reader->getString("Kvdb_3.contextId"));
        EXPECT_EQ(kvdb.kvdbId, reader->getString("Kvdb_3.kvdbId"));
        EXPECT_EQ(kvdb.createDate, reader->getInt64("Kvdb_3.createDate"));
        EXPECT_EQ(kvdb.creator, reader->getString("Kvdb_3.creator"));
        EXPECT_EQ(kvdb.lastModificationDate, reader->getInt64("Kvdb_3.lastModificationDate"));
        EXPECT_EQ(kvdb.lastModifier, reader->getString("Kvdb_3.lastModifier"));
        EXPECT_EQ(kvdb.version, reader->getInt64("Kvdb_3.version"));
        EXPECT_EQ(kvdb.lastEntryDate, reader->getInt64("Kvdb_3.lastEntryDate"));
        EXPECT_EQ(kvdb.entries, reader->getInt64("Kvdb_3.entries"));
        EXPECT_EQ(kvdb.statusCode, 0);
        EXPECT_EQ(kvdb.publicMeta.stdString(), privmx::utils::Hex::toString(reader->getString("Kvdb_3.publicMeta_inHex")));
        EXPECT_EQ(kvdb.publicMeta.stdString(), privmx::utils::Hex::toString(reader->getString("Kvdb_3.uploaded_publicMeta_inHex")));
        EXPECT_EQ(kvdb.privateMeta.stdString(), privmx::utils::Hex::toString(reader->getString("Kvdb_3.privateMeta_inHex")));
        EXPECT_EQ(kvdb.privateMeta.stdString(), privmx::utils::Hex::toString(reader->getString("Kvdb_3.uploaded_privateMeta_inHex")));
        EXPECT_EQ(kvdb.version, 1);
        EXPECT_EQ(kvdb.creator, reader->getString("Login.user_1_id"));
        EXPECT_EQ(kvdb.lastModifier, reader->getString("Login.user_1_id"));
        EXPECT_EQ(kvdb.users.size(), 2);
        if(kvdb.users.size() == 2) {
            EXPECT_EQ(kvdb.users[0], reader->getString("Login.user_1_id"));
            EXPECT_EQ(kvdb.users[1], reader->getString("Login.user_2_id"));
        }
        EXPECT_EQ(kvdb.managers.size(), 1);
        if(kvdb.managers.size() == 1) {
            EXPECT_EQ(kvdb.managers[0], reader->getString("Login.user_1_id"));
        }
    }
    
}

TEST_F(KvdbTest, createKvdb) {
    // different users and managers
    std::string kvdbId;
    kvdb::Kvdb kvdb;
    EXPECT_NO_THROW({
        kvdbId = kvdbApi->createKvdb(
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
    if(kvdbId.empty()) { 
        FAIL();
    }
    EXPECT_NO_THROW({
        kvdb = kvdbApi->getKvdb(
            kvdbId
        );
    });
    EXPECT_EQ(kvdb.statusCode, 0);
    EXPECT_EQ(kvdb.contextId, reader->getString("Context_1.contextId"));
    EXPECT_EQ(kvdb.publicMeta.stdString(), "public");
    EXPECT_EQ(kvdb.privateMeta.stdString(), "private");
    EXPECT_EQ(kvdb.users.size(), 1);
    if(kvdb.users.size() == 1) {
        EXPECT_EQ(kvdb.users[0], reader->getString("Login.user_2_id"));
    }
    EXPECT_EQ(kvdb.managers.size(), 1);
    if(kvdb.managers.size() == 1) {
        EXPECT_EQ(kvdb.managers[0], reader->getString("Login.user_1_id"));
    }
    // same users and managers
    EXPECT_NO_THROW({
        kvdbId = kvdbApi->createKvdb(
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
    if(kvdbId.empty()) { 
        FAIL();
    }
    EXPECT_NO_THROW({
        kvdb = kvdbApi->getKvdb(
            kvdbId
        );
    });
    EXPECT_EQ(kvdb.statusCode, 0);
    EXPECT_EQ(kvdb.contextId, reader->getString("Context_1.contextId"));
    EXPECT_EQ(kvdb.publicMeta.stdString(), "public");
    EXPECT_EQ(kvdb.privateMeta.stdString(), "private");
    EXPECT_EQ(kvdb.users.size(), 1);
    if(kvdb.users.size() == 1) {
        EXPECT_EQ(kvdb.users[0], reader->getString("Login.user_1_id"));
    }
    EXPECT_EQ(kvdb.managers.size(), 1);
    if(kvdb.managers.size() == 1) {
        EXPECT_EQ(kvdb.managers[0], reader->getString("Login.user_1_id"));
    }
}

TEST_F(KvdbTest, updateKvdb_incorrect_data) {
    // incorrect kvdbId
    EXPECT_THROW({
        kvdbApi->updateKvdb(
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
        kvdbApi->updateKvdb(
            reader->getString("Kvdb_1.kvdbId"),
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
        kvdbApi->updateKvdb(
            reader->getString("Kvdb_1.kvdbId"),
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
        kvdbApi->updateKvdb(
            reader->getString("Kvdb_1.kvdbId"),
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
        kvdbApi->updateKvdb(
            reader->getString("Kvdb_2.kvdbId"),
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

TEST_F(KvdbTest, updateKvdb_correct_data) {
    //enable cache
    EXPECT_NO_THROW({
        kvdbApi->subscribeForKvdbEvents();
    });
    kvdb::Kvdb kvdb;
    // new users
    EXPECT_NO_THROW({
        kvdbApi->updateKvdb(
            reader->getString("Kvdb_1.kvdbId"),
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
        kvdb = kvdbApi->getKvdb(
            reader->getString("Kvdb_1.kvdbId")
        );
    });
    EXPECT_EQ(kvdb.statusCode, 0);    
    EXPECT_EQ(kvdb.contextId, reader->getString("Context_1.contextId"));
    EXPECT_EQ(kvdb.version, 2);
    EXPECT_EQ(kvdb.publicMeta.stdString(), "public");
    EXPECT_EQ(kvdb.privateMeta.stdString(), "private");
    EXPECT_EQ(kvdb.users.size(), 2);
    if(kvdb.users.size() == 2) {
        EXPECT_EQ(kvdb.users[0], reader->getString("Login.user_1_id"));
        EXPECT_EQ(kvdb.users[1], reader->getString("Login.user_2_id"));
    }
    EXPECT_EQ(kvdb.managers.size(), 1);
    if(kvdb.managers.size() == 1) {
        EXPECT_EQ(kvdb.managers[0], reader->getString("Login.user_1_id"));
    }
    // new managers
    EXPECT_NO_THROW({
        kvdbApi->updateKvdb(
            reader->getString("Kvdb_1.kvdbId"),
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
        kvdb = kvdbApi->getKvdb(
            reader->getString("Kvdb_1.kvdbId")
        );
    });
    EXPECT_EQ(kvdb.statusCode, 0);    
    EXPECT_EQ(kvdb.contextId, reader->getString("Context_1.contextId"));
    EXPECT_EQ(kvdb.version, 3);
    EXPECT_EQ(kvdb.publicMeta.stdString(), "public");
    EXPECT_EQ(kvdb.privateMeta.stdString(), "private");
    EXPECT_EQ(kvdb.users.size(), 1);
    if(kvdb.users.size() == 1) {
        EXPECT_EQ(kvdb.users[0], reader->getString("Login.user_1_id"));
    }
    EXPECT_EQ(kvdb.managers.size(), 2);
    if(kvdb.managers.size() == 2) {
        EXPECT_EQ(kvdb.managers[0], reader->getString("Login.user_1_id"));
        EXPECT_EQ(kvdb.managers[1], reader->getString("Login.user_2_id"));
    }
    // less users
    EXPECT_NO_THROW({
        kvdbApi->updateKvdb(
            reader->getString("Kvdb_2.kvdbId"),
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
        kvdb = kvdbApi->getKvdb(
            reader->getString("Kvdb_2.kvdbId")
        );
    });
    EXPECT_EQ(kvdb.statusCode, 0);    
    EXPECT_EQ(kvdb.contextId, reader->getString("Context_1.contextId"));
    EXPECT_EQ(kvdb.version, 2);
    EXPECT_EQ(kvdb.publicMeta.stdString(), "public");
    EXPECT_EQ(kvdb.privateMeta.stdString(), "private");
    EXPECT_EQ(kvdb.users.size(), 1);
    if(kvdb.users.size() == 1) {
        EXPECT_EQ(kvdb.users[0], reader->getString("Login.user_1_id"));
    }
    EXPECT_EQ(kvdb.managers.size(), 2);
    if(kvdb.managers.size() == 2) {
        EXPECT_EQ(kvdb.managers[0], reader->getString("Login.user_1_id"));
        EXPECT_EQ(kvdb.managers[1], reader->getString("Login.user_2_id"));
    }
    // less managers
    EXPECT_NO_THROW({
        kvdbApi->updateKvdb(
            reader->getString("Kvdb_2.kvdbId"),
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
        kvdb = kvdbApi->getKvdb(
            reader->getString("Kvdb_2.kvdbId")
        );
    });
    EXPECT_EQ(kvdb.statusCode, 0);    
    EXPECT_EQ(kvdb.contextId, reader->getString("Context_1.contextId"));
    EXPECT_EQ(kvdb.version, 3);
    EXPECT_EQ(kvdb.publicMeta.stdString(), "public");
    EXPECT_EQ(kvdb.privateMeta.stdString(), "private");
    EXPECT_EQ(kvdb.users.size(), 1);
    if(kvdb.users.size() == 1) {
        EXPECT_EQ(kvdb.users[0], reader->getString("Login.user_1_id"));
    }
    EXPECT_EQ(kvdb.managers.size(), 1);
    if(kvdb.managers.size() == 1) {
        EXPECT_EQ(kvdb.managers[0], reader->getString("Login.user_1_id"));
    }
    // incorrect version force true
    EXPECT_NO_THROW({
        kvdbApi->updateKvdb(
            reader->getString("Kvdb_3.kvdbId"),
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
        kvdb = kvdbApi->getKvdb(
            reader->getString("Kvdb_3.kvdbId")
        );
    });
    EXPECT_EQ(kvdb.statusCode, 0);    
    EXPECT_EQ(kvdb.contextId, reader->getString("Context_1.contextId"));
    EXPECT_EQ(kvdb.version, 2);
    EXPECT_EQ(kvdb.publicMeta.stdString(), "public");
    EXPECT_EQ(kvdb.privateMeta.stdString(), "private");
    EXPECT_EQ(kvdb.users.size(), 1);
    if(kvdb.users.size() == 1) {
        EXPECT_EQ(kvdb.users[0], reader->getString("Login.user_1_id"));
    }
    EXPECT_EQ(kvdb.managers.size(), 1);
    if(kvdb.managers.size() == 1) {
        EXPECT_EQ(kvdb.managers[0], reader->getString("Login.user_1_id"));
    }
}

TEST_F(KvdbTest, deleteKvdb) {
    // incorrect kvdbId
    EXPECT_THROW({
        kvdbApi->deleteKvdb(
            reader->getString("Context_1.contextId")
        );
    }, core::Exception);
    // as manager
     EXPECT_NO_THROW({
        kvdbApi->deleteKvdb(
            reader->getString("Kvdb_1.kvdbId")
        );
    });
    EXPECT_THROW({
        kvdbApi->getKvdb(
            reader->getString("Kvdb_1.kvdbId")
        );
    }, core::Exception);
    // as user
    disconnect();
    connectAs(ConnectionType::User2);
    EXPECT_THROW({
        kvdbApi->deleteKvdb(
            reader->getString("Kvdb_3.kvdbId")
        );
    }, core::Exception);
}

TEST_F(KvdbTest, getEntry) {
    // incorrect key
    EXPECT_THROW({
        kvdbApi->getEntry(
            reader->getString("Kvdb_1.kvdbId"),
            reader->getString("Context_1.contextId")
        );
    }, core::Exception);
    // after force key generation on kvdb
    EXPECT_NO_THROW({
        kvdbApi->updateKvdb(
            reader->getString("Kvdb_1.kvdbId"),
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
    kvdb::KvdbEntry entry;
    EXPECT_NO_THROW({
        entry = kvdbApi->getEntry(
            reader->getString("Kvdb_1.kvdbId"),
            reader->getString("KvdbEntry_2.info_key")
        );
    });
    EXPECT_EQ(entry.info.kvdbId, reader->getString("KvdbEntry_2.info_kvdbId"));
    EXPECT_EQ(entry.info.key, reader->getString("KvdbEntry_2.info_key"));
    EXPECT_EQ(entry.info.createDate, reader->getInt64("KvdbEntry_2.info_createDate"));
    EXPECT_EQ(entry.info.author, reader->getString("KvdbEntry_2.info_author"));
    EXPECT_EQ(entry.publicMeta.stdString(), privmx::utils::Hex::toString(reader->getString("KvdbEntry_2.publicMeta_inHex")));
    EXPECT_EQ(entry.privateMeta.stdString(), privmx::utils::Hex::toString(reader->getString("KvdbEntry_2.privateMeta_inHex")));
    EXPECT_EQ(entry.data.stdString(), privmx::utils::Hex::toString(reader->getString("KvdbEntry_2.data_inHex")));
    EXPECT_EQ(entry.statusCode, 0);
    EXPECT_EQ(
        privmx::utils::Utils::stringifyVar(_serializer.serialize(entry)),
        reader->getString("KvdbEntry_2.JSON_data")
    );
    EXPECT_EQ(entry.publicMeta.stdString(), privmx::utils::Hex::toString(reader->getString("KvdbEntry_2.uploaded_publicMeta_inHex")));
    EXPECT_EQ(entry.privateMeta.stdString(), privmx::utils::Hex::toString(reader->getString("KvdbEntry_2.uploaded_privateMeta_inHex")));
    EXPECT_EQ(entry.data.stdString(), privmx::utils::Hex::toString(reader->getString("KvdbEntry_2.uploaded_data_inHex")));
}

TEST_F(KvdbTest, hasEntry) {
    bool result;
    EXPECT_NO_THROW({
        result = kvdbApi->hasEntry(
            reader->getString("Kvdb_1.kvdbId"),
            reader->getString("Context_1.contextId")
        );
    });
    EXPECT_EQ(result, false);
    EXPECT_NO_THROW({
        result = kvdbApi->hasEntry(
            reader->getString("Kvdb_1.kvdbId"),
            reader->getString("KvdbEntry_2.info_key")
        );
    });
    EXPECT_EQ(result, true);
}

TEST_F(KvdbTest, listEntriesKeys_incorrect_input_data) {
    // incorrect kvdbId
    EXPECT_THROW({
        kvdbApi->listEntriesKeys(
            reader->getString("KvdbEntry_2.info_key"),
            {
                .skip=0, 
                .limit=1, 
                .sortOrder="desc"
            }
        );
    }, core::Exception);
    // limit < 0
    EXPECT_THROW({
        kvdbApi->listEntriesKeys(
            reader->getString("Kvdb_1.kvdbId"),
            {
                .skip=0, 
                .limit=-1, 
                .sortOrder="desc"
            }
        );
    }, core::Exception);
    // limit == 0
    EXPECT_THROW({
        kvdbApi->listEntriesKeys(
            reader->getString("Kvdb_1.kvdbId"),
            {
                .skip=0, 
                .limit=0, 
                .sortOrder="desc"
            }
        );
    }, core::Exception);
    // incorrect sortOrder
    EXPECT_THROW({
        kvdbApi->listEntriesKeys(
            reader->getString("Kvdb_1.kvdbId"),
            {
                .skip=0, 
                .limit=1, 
                .sortOrder="BLACH"
            }
        );
    }, core::Exception);
}

TEST_F(KvdbTest, listEntriesKeys_correct_input_data) {
    core::PagingList<std::string> listEntriesKeys;
    // {.skip=4, .limit=1, .sortOrder="desc"}
    EXPECT_NO_THROW({
        listEntriesKeys = kvdbApi->listEntriesKeys(
            reader->getString("Kvdb_1.kvdbId"),
            {
                .skip=4, 
                .limit=1, 
                .sortOrder="desc"
            }
        );
    });
    EXPECT_EQ(listEntriesKeys.totalAvailable, 2);
    EXPECT_EQ(listEntriesKeys.readItems.size(), 0);
    // {.skip=1, .limit=1, .sortOrder="desc"}
    EXPECT_NO_THROW({
        listEntriesKeys = kvdbApi->listEntriesKeys(
            reader->getString("Kvdb_1.kvdbId"),
            {
                .skip=1, 
                .limit=1, 
                .sortOrder="desc"
            }
        );
    });
    EXPECT_EQ(listEntriesKeys.totalAvailable, 2);
    EXPECT_EQ(listEntriesKeys.readItems.size(), 1);
    if(listEntriesKeys.readItems.size() >= 1) {
        auto entry = listEntriesKeys.readItems[0];
        EXPECT_EQ(entry, reader->getString("KvdbEntry_1.info_key"));
    }
    // {.skip=0, .limit=3, .sortOrder="asc"}, after force key generation on kvdb
    EXPECT_NO_THROW({
        kvdbApi->updateKvdb(
            reader->getString("Kvdb_1.kvdbId"),
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
        listEntriesKeys = kvdbApi->listEntriesKeys(
            reader->getString("Kvdb_1.kvdbId"),
            {
                .skip=0, 
                .limit=3, 
                .sortOrder="asc"
            }
        );
    });
    EXPECT_EQ(listEntriesKeys.totalAvailable, 2);
    EXPECT_EQ(listEntriesKeys.readItems.size(), 2);
    if(listEntriesKeys.readItems.size() >= 1) {
        auto entry = listEntriesKeys.readItems[0];
        EXPECT_EQ(entry, reader->getString("KvdbEntry_1.info_key"));
    }
    if(listEntriesKeys.readItems.size() >= 2) {
        auto entry = listEntriesKeys.readItems[1];
        EXPECT_EQ(entry, reader->getString("KvdbEntry_2.info_key"));
    }
}

TEST_F(KvdbTest, listEntries_incorrect_input_data) {
    // incorrect kvdbId
    EXPECT_THROW({
        kvdbApi->listEntries(
            reader->getString("KvdbEntry_2.info_key"),
            {
                .skip=0, 
                .limit=1, 
                .sortOrder="desc"
            }
        );
    }, core::Exception);
    // limit < 0
    EXPECT_THROW({
        kvdbApi->listEntries(
            reader->getString("Kvdb_1.kvdbId"),
            {
                .skip=0, 
                .limit=-1, 
                .sortOrder="desc"
            }
        );
    }, core::Exception);
    // limit == 0
    EXPECT_THROW({
        kvdbApi->listEntries(
            reader->getString("Kvdb_1.kvdbId"),
            {
                .skip=0, 
                .limit=0, 
                .sortOrder="desc"
            }
        );
    }, core::Exception);
    // incorrect sortOrder
    EXPECT_THROW({
        kvdbApi->listEntries(
            reader->getString("Kvdb_1.kvdbId"),
            {
                .skip=0, 
                .limit=1, 
                .sortOrder="BLACH"
            }
        );
    }, core::Exception);
    // incorrect queryAsJson
    EXPECT_THROW({
        kvdbApi->listEntries(
            reader->getString("Kvdb_1.kvdbId"),
            {
                .skip=0, 
                .limit=1, 
                .sortOrder="BLACH",
                .lastId=std::nullopt,
                .sortBy=std::nullopt,
                .queryAsJson="{BLACH,}"
            }
        );
    }, core::InvalidParamsException);
}

TEST_F(KvdbTest, listEntries_correct_input_data) {
    core::PagingList<kvdb::KvdbEntry> listEntries;
    // {.skip=4, .limit=1, .sortOrder="desc"}
    EXPECT_NO_THROW({
        listEntries = kvdbApi->listEntries(
            reader->getString("Kvdb_1.kvdbId"),
            {
                .skip=4, 
                .limit=1, 
                .sortOrder="desc"
            }
        );
    });
    EXPECT_EQ(listEntries.totalAvailable, 2);
    EXPECT_EQ(listEntries.readItems.size(), 0);
    // {.skip=1, .limit=1, .sortOrder="desc"}
    EXPECT_NO_THROW({
        listEntries = kvdbApi->listEntries(
            reader->getString("Kvdb_1.kvdbId"),
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
        auto entry = listEntries.readItems[0];
        EXPECT_EQ(entry.info.kvdbId, reader->getString("KvdbEntry_1.info_kvdbId"));
        EXPECT_EQ(entry.info.key, reader->getString("KvdbEntry_1.info_key"));
        EXPECT_EQ(entry.info.createDate, reader->getInt64("KvdbEntry_1.info_createDate"));
        EXPECT_EQ(entry.info.author, reader->getString("KvdbEntry_1.info_author"));
        EXPECT_EQ(entry.publicMeta.stdString(), privmx::utils::Hex::toString(reader->getString("KvdbEntry_1.publicMeta_inHex")));
        EXPECT_EQ(entry.privateMeta.stdString(), privmx::utils::Hex::toString(reader->getString("KvdbEntry_1.privateMeta_inHex")));
        EXPECT_EQ(entry.data.stdString(), privmx::utils::Hex::toString(reader->getString("KvdbEntry_1.data_inHex")));
        EXPECT_EQ(entry.statusCode, 0);
        EXPECT_EQ(
            privmx::utils::Utils::stringifyVar(_serializer.serialize(entry)),
            reader->getString("KvdbEntry_1.JSON_data")
        );
        EXPECT_EQ(entry.publicMeta.stdString(), privmx::utils::Hex::toString(reader->getString("KvdbEntry_1.uploaded_publicMeta_inHex")));
        EXPECT_EQ(entry.privateMeta.stdString(), privmx::utils::Hex::toString(reader->getString("KvdbEntry_1.uploaded_privateMeta_inHex")));
        EXPECT_EQ(entry.data.stdString(), privmx::utils::Hex::toString(reader->getString("KvdbEntry_1.uploaded_data_inHex")));
    }
    // {.skip=0, .limit=3, .sortOrder="asc"}, after force key generation on kvdb
    EXPECT_NO_THROW({
        kvdbApi->updateKvdb(
            reader->getString("Kvdb_1.kvdbId"),
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
        listEntries = kvdbApi->listEntries(
            reader->getString("Kvdb_1.kvdbId"),
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
        auto entry = listEntries.readItems[0];
        EXPECT_EQ(entry.info.kvdbId, reader->getString("KvdbEntry_1.info_kvdbId"));
        EXPECT_EQ(entry.info.key, reader->getString("KvdbEntry_1.info_key"));
        EXPECT_EQ(entry.info.createDate, reader->getInt64("KvdbEntry_1.info_createDate"));
        EXPECT_EQ(entry.info.author, reader->getString("KvdbEntry_1.info_author"));
        EXPECT_EQ(entry.publicMeta.stdString(), privmx::utils::Hex::toString(reader->getString("KvdbEntry_1.publicMeta_inHex")));
        EXPECT_EQ(entry.privateMeta.stdString(), privmx::utils::Hex::toString(reader->getString("KvdbEntry_1.privateMeta_inHex")));
        EXPECT_EQ(entry.data.stdString(), privmx::utils::Hex::toString(reader->getString("KvdbEntry_1.data_inHex")));
        EXPECT_EQ(entry.statusCode, 0);
        EXPECT_EQ(
            privmx::utils::Utils::stringifyVar(_serializer.serialize(entry)),
            reader->getString("KvdbEntry_1.JSON_data")
        );
        EXPECT_EQ(entry.publicMeta.stdString(), privmx::utils::Hex::toString(reader->getString("KvdbEntry_1.uploaded_publicMeta_inHex")));
        EXPECT_EQ(entry.privateMeta.stdString(), privmx::utils::Hex::toString(reader->getString("KvdbEntry_1.uploaded_privateMeta_inHex")));
        EXPECT_EQ(entry.data.stdString(), privmx::utils::Hex::toString(reader->getString("KvdbEntry_1.uploaded_data_inHex")));
    }
    if(listEntries.readItems.size() >= 2) {
        auto entry = listEntries.readItems[1];
        EXPECT_EQ(entry.info.kvdbId, reader->getString("KvdbEntry_2.info_kvdbId"));
        EXPECT_EQ(entry.info.key, reader->getString("KvdbEntry_2.info_key"));
        EXPECT_EQ(entry.info.createDate, reader->getInt64("KvdbEntry_2.info_createDate"));
        EXPECT_EQ(entry.info.author, reader->getString("KvdbEntry_2.info_author"));
        EXPECT_EQ(entry.publicMeta.stdString(), privmx::utils::Hex::toString(reader->getString("KvdbEntry_2.publicMeta_inHex")));
        EXPECT_EQ(entry.privateMeta.stdString(), privmx::utils::Hex::toString(reader->getString("KvdbEntry_2.privateMeta_inHex")));
        EXPECT_EQ(entry.data.stdString(), privmx::utils::Hex::toString(reader->getString("KvdbEntry_2.data_inHex")));
        EXPECT_EQ(entry.statusCode, 0);
        EXPECT_EQ(
            privmx::utils::Utils::stringifyVar(_serializer.serialize(entry)),
            reader->getString("KvdbEntry_2.JSON_data")
        );
        EXPECT_EQ(entry.publicMeta.stdString(), privmx::utils::Hex::toString(reader->getString("KvdbEntry_2.uploaded_publicMeta_inHex")));
        EXPECT_EQ(entry.privateMeta.stdString(), privmx::utils::Hex::toString(reader->getString("KvdbEntry_2.uploaded_privateMeta_inHex")));
        EXPECT_EQ(entry.data.stdString(), privmx::utils::Hex::toString(reader->getString("KvdbEntry_2.uploaded_data_inHex")));
    }
}

TEST_F(KvdbTest, deleteEntry) {
    // incorrect key
    EXPECT_THROW({
        kvdbApi->deleteEntry(
            reader->getString("Kvdb_1.kvdbId"),
            reader->getString("Kvdb_1.kvdbId")
        );
    }, core::Exception);
    // change privileges
    EXPECT_NO_THROW({
        kvdbApi->updateKvdb(
            reader->getString("Kvdb_1.kvdbId"),
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
        kvdbApi->deleteEntry(
            reader->getString("Kvdb_1.kvdbId"),
            reader->getString("KvdbEntry_2.info_key")
        );
    }, core::Exception);
    // change privileges
    disconnect();
    connectAs(ConnectionType::User1);
    EXPECT_NO_THROW({
        kvdbApi->updateKvdb(
            reader->getString("Kvdb_1.kvdbId"),
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
        kvdbApi->updateKvdb(
            reader->getString("Kvdb_1.kvdbId"),
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
        kvdbApi->deleteEntry(
            reader->getString("Kvdb_1.kvdbId"),
            reader->getString("KvdbEntry_2.info_key")
        );
    });
    disconnect();
    connectAs(ConnectionType::User2);
    // as manager no created by me
    EXPECT_NO_THROW({
        kvdbApi->deleteEntry(
            reader->getString("Kvdb_1.kvdbId"),
            reader->getString("KvdbEntry_1.info_key")
        );
    });
}

TEST_F(KvdbTest, setEntry) {
    kvdb::KvdbEntry entry;
    //Creating new entry
    EXPECT_NO_THROW({
        kvdbApi->setEntry(
            reader->getString("Kvdb_2.kvdbId"),
            "kvdb_entry_key",
            core::Buffer::from("kvdb_entry_1_publicMeta"),
            core::Buffer::from("kvdb_entry_1_privateMeta"),
            core::Buffer::from("kvdb_entry_1_data"),
            0
        );
    });
    EXPECT_NO_THROW({
        entry = kvdbApi->getEntry(
            reader->getString("Kvdb_2.kvdbId"),
            "kvdb_entry_key"
        );
    });
    EXPECT_EQ(entry.info.kvdbId, reader->getString("Kvdb_2.kvdbId"));
    EXPECT_EQ(entry.info.key, "kvdb_entry_key");
    EXPECT_EQ(entry.version, 1);
    EXPECT_EQ(entry.publicMeta.stdString(), "kvdb_entry_1_publicMeta");
    EXPECT_EQ(entry.privateMeta.stdString(), "kvdb_entry_1_privateMeta");
    EXPECT_EQ(entry.data.stdString(), "kvdb_entry_1_data");
    EXPECT_EQ(entry.statusCode, 0);

    //Updating existing entry
    //incorrect version number
    EXPECT_THROW({
        kvdbApi->setEntry(
            reader->getString("Kvdb_2.kvdbId"),
            "kvdb_entry_key",
            core::Buffer::from("kvdb_entry_1_publicMeta"),
            core::Buffer::from("kvdb_entry_1_privateMeta"),
            core::Buffer::from("kvdb_entry_1_data"),
            0
        );
    }, core::Exception);
    //correct version number
    EXPECT_NO_THROW({
        kvdbApi->setEntry(
            reader->getString("Kvdb_2.kvdbId"),
            "kvdb_entry_key",
            core::Buffer::from("kvdb_entry_1_publicMeta"),
            core::Buffer::from("kvdb_entry_1_privateMeta"),
            core::Buffer::from("kvdb_entry_1_data_v2"),
            1
        );
    });
    EXPECT_NO_THROW({
        entry = kvdbApi->getEntry(
            reader->getString("Kvdb_2.kvdbId"),
            "kvdb_entry_key"
        );
    });
    EXPECT_EQ(entry.info.kvdbId, reader->getString("Kvdb_2.kvdbId"));
    EXPECT_EQ(entry.info.key, "kvdb_entry_key");
    EXPECT_EQ(entry.version, 2);
    EXPECT_EQ(entry.publicMeta.stdString(), "kvdb_entry_1_publicMeta");
    EXPECT_EQ(entry.privateMeta.stdString(), "kvdb_entry_1_privateMeta");
    EXPECT_EQ(entry.data.stdString(), "kvdb_entry_1_data_v2");
    EXPECT_EQ(entry.statusCode, 0);
    // Modifing by other user
    disconnect();
    connectAs(ConnectionType::User2);
    //Access denied
    EXPECT_THROW({
        kvdbApi->setEntry(
            reader->getString("Kvdb_1.kvdbId"),
            reader->getString("KvdbEntry_1.info_key"),
            core::Buffer::from("kvdb_entry_1_publicMeta"),
            core::Buffer::from("kvdb_entry_1_privateMeta"),
            core::Buffer::from("kvdb_entry_1_data"),
            1
        );
    }, core::Exception);
    // User2 modifing User1 
    EXPECT_NO_THROW({
        kvdbApi->setEntry(
            reader->getString("Kvdb_2.kvdbId"),
            "kvdb_entry_key",
            core::Buffer::from("kvdb_entry_1_publicMeta"),
            core::Buffer::from("kvdb_entry_1_privateMeta"),
            core::Buffer::from("kvdb_entry_1_data_v3"),
            2
        );
    });
    EXPECT_NO_THROW({
        entry = kvdbApi->getEntry(
            reader->getString("Kvdb_2.kvdbId"),
            "kvdb_entry_key"
        );
    });
    EXPECT_EQ(entry.info.kvdbId, reader->getString("Kvdb_2.kvdbId"));
    EXPECT_EQ(entry.info.key, "kvdb_entry_key");
    EXPECT_EQ(entry.version, 3);
    EXPECT_EQ(entry.publicMeta.stdString(), "kvdb_entry_1_publicMeta");
    EXPECT_EQ(entry.privateMeta.stdString(), "kvdb_entry_1_privateMeta");
    EXPECT_EQ(entry.data.stdString(), "kvdb_entry_1_data_v3");
    EXPECT_EQ(entry.statusCode, 0);
}

TEST_F(KvdbTest, deleteEntries) {
    //nothing to delete
    EXPECT_NO_THROW({
        kvdbApi->deleteEntries(
            reader->getString("Kvdb_1.kvdbId"),
            std::vector<std::string>()
        );
    });
    //delete entries and one not exist
    std::map<std::string, bool> deleteResult;
    EXPECT_NO_THROW({
        deleteResult = kvdbApi->deleteEntries(
            reader->getString("Kvdb_1.kvdbId"),
            std::vector<std::string>({"Error", reader->getString("KvdbEntry_1.info_key"), reader->getString("KvdbEntry_2.info_key")})
        );
    });
    EXPECT_EQ(deleteResult["Error"], false);
    EXPECT_EQ(deleteResult[reader->getString("KvdbEntry_1.info_key")], true);
    EXPECT_EQ(deleteResult[reader->getString("KvdbEntry_2.info_key")], true);

    //check if entries not exist
    EXPECT_THROW({
        kvdbApi->getEntry(
            reader->getString("Kvdb_1.kvdbId"),
            reader->getString("KvdbEntry_1.info_key")
        );
    }, core::Exception);
    EXPECT_THROW({
        kvdbApi->getEntry(
            reader->getString("Kvdb_1.kvdbId"),
            reader->getString("KvdbEntry_2.info_key")
        );
    }, core::Exception);
}

TEST_F(KvdbTest, sendMessage_cacheManipulation) {
    // load kvdb to cache
    EXPECT_NO_THROW({
        kvdbApi->getKvdb(reader->getString("Kvdb_1.kvdbId"));
    });
    // update kvdb
    EXPECT_NO_THROW({
        kvdbApi->updateKvdb(
            reader->getString("Kvdb_1.kvdbId"),
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
    // correct data
    EXPECT_NO_THROW({
        kvdbApi->setEntry(
            reader->getString("Kvdb_1.kvdbId"),
            "test",
            core::Buffer::from("publicMeta"),
            core::Buffer::from("privateMeta"),
            core::Buffer::from("data"),
            0
        );
    });
    kvdb::KvdbEntry entry;
    EXPECT_NO_THROW({
        entry = kvdbApi->getEntry(
            reader->getString("Kvdb_1.kvdbId"),
            "test"
        );
    });
    EXPECT_EQ(entry.statusCode, 0);
    EXPECT_EQ(entry.data.stdString(), "data");
    EXPECT_EQ(entry.privateMeta.stdString(), "privateMeta");
    EXPECT_EQ(entry.publicMeta.stdString(), "publicMeta");
}
