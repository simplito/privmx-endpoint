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
    EXPECT_EQ(kvdb.lastItemDate, reader->getInt64("Kvdb_1.lastItemDate"));
    EXPECT_EQ(kvdb.items, reader->getInt64("Kvdb_1.items"));
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
}

TEST_F(KvdbTest, listKvdb_correct_input_data) {
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
        EXPECT_EQ(kvdb.lastItemDate, reader->getInt64("Kvdb_3.lastItemDate"));
        EXPECT_EQ(kvdb.items, reader->getInt64("Kvdb_3.items"));
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
        EXPECT_EQ(kvdb.lastItemDate, reader->getInt64("Kvdb_2.lastItemDate"));
        EXPECT_EQ(kvdb.items, reader->getInt64("Kvdb_2.items"));
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
        EXPECT_EQ(kvdb.lastItemDate, reader->getInt64("Kvdb_3.lastItemDate"));
        EXPECT_EQ(kvdb.items, reader->getInt64("Kvdb_3.items"));
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


TEST_F(KvdbTest, getItem) {
    // incorrect key
    EXPECT_THROW({
        kvdbApi->getItem(
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
    kvdb::Item item;
    EXPECT_NO_THROW({
        item = kvdbApi->getItem(
            reader->getString("Kvdb_1.kvdbId"),
            reader->getString("Item_2.info_key")
        );
    });
    EXPECT_EQ(item.info.kvdbId, reader->getString("Item_2.info_kvdbId"));
    EXPECT_EQ(item.info.key, reader->getString("Item_2.info_key"));
    EXPECT_EQ(item.info.createDate, reader->getInt64("Item_2.info_createDate"));
    EXPECT_EQ(item.info.author, reader->getString("Item_2.info_author"));
    EXPECT_EQ(item.publicMeta.stdString(), privmx::utils::Hex::toString(reader->getString("Item_2.publicMeta_inHex")));
    EXPECT_EQ(item.privateMeta.stdString(), privmx::utils::Hex::toString(reader->getString("Item_2.privateMeta_inHex")));
    EXPECT_EQ(item.data.stdString(), privmx::utils::Hex::toString(reader->getString("Item_2.data_inHex")));
    EXPECT_EQ(item.statusCode, 0);
    EXPECT_EQ(
        privmx::utils::Utils::stringifyVar(_serializer.serialize(item)),
        reader->getString("Item_2.JSON_data")
    );
    EXPECT_EQ(item.publicMeta.stdString(), privmx::utils::Hex::toString(reader->getString("Item_2.uploaded_publicMeta_inHex")));
    EXPECT_EQ(item.privateMeta.stdString(), privmx::utils::Hex::toString(reader->getString("Item_2.uploaded_privateMeta_inHex")));
    EXPECT_EQ(item.data.stdString(), privmx::utils::Hex::toString(reader->getString("Item_2.uploaded_data_inHex")));
}


TEST_F(KvdbTest, listItemsKey_incorrect_input_data) {
    // incorrect kvdbId
    EXPECT_THROW({
        kvdbApi->listItemsKey(
            reader->getString("Item_2.info_itemId"),
            {
                .skip=0, 
                .limit=1, 
                .sortOrder="desc"
            }
        );
    }, core::Exception);
    // limit < 0
    EXPECT_THROW({
        kvdbApi->listItemsKey(
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
        kvdbApi->listItemsKey(
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
        kvdbApi->listItemsKey(
            reader->getString("Kvdb_1.kvdbId"),
            {
                .skip=0, 
                .limit=1, 
                .sortOrder="BLACH"
            }
        );
    }, core::Exception);
}

TEST_F(KvdbTest, listItemsKey_correct_input_data) {
    core::PagingList<std::string> listItemsKey;
    // {.skip=4, .limit=1, .sortOrder="desc"}
    EXPECT_NO_THROW({
        listItemsKey = kvdbApi->listItemsKey(
            reader->getString("Kvdb_1.kvdbId"),
            {
                .skip=4, 
                .limit=1, 
                .sortOrder="desc"
            }
        );
    });
    EXPECT_EQ(listItemsKey.totalAvailable, 2);
    EXPECT_EQ(listItemsKey.readItems.size(), 0);
    // {.skip=1, .limit=1, .sortOrder="desc"}
    EXPECT_NO_THROW({
        listItemsKey = kvdbApi->listItemsKey(
            reader->getString("Kvdb_1.kvdbId"),
            {
                .skip=1, 
                .limit=1, 
                .sortOrder="desc"
            }
        );
    });
    EXPECT_EQ(listItemsKey.totalAvailable, 2);
    EXPECT_EQ(listItemsKey.readItems.size(), 1);
    if(listItemsKey.readItems.size() >= 1) {
        auto item = listItemsKey.readItems[0];
        EXPECT_EQ(item, reader->getString("Item_1.info_key"));
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
        listItemsKey = kvdbApi->listItemsKey(
            reader->getString("Kvdb_1.kvdbId"),
            {
                .skip=0, 
                .limit=3, 
                .sortOrder="asc"
            }
        );
    });
    EXPECT_EQ(listItemsKey.totalAvailable, 2);
    EXPECT_EQ(listItemsKey.readItems.size(), 2);
    if(listItemsKey.readItems.size() >= 1) {
        auto item = listItemsKey.readItems[0];
        EXPECT_EQ(item, reader->getString("Item_1.info_key"));
    }
    if(listItemsKey.readItems.size() >= 2) {
        auto item = listItemsKey.readItems[1];
        EXPECT_EQ(item, reader->getString("Item_2.info_key"));
    }
}

TEST_F(KvdbTest, listItems_incorrect_input_data) {
    // incorrect kvdbId
    EXPECT_THROW({
        kvdbApi->listItems(
            reader->getString("Item_2.info_itemId"),
            {
                .skip=0, 
                .limit=1, 
                .sortOrder="desc"
            }
        );
    }, core::Exception);
    // limit < 0
    EXPECT_THROW({
        kvdbApi->listItems(
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
        kvdbApi->listItems(
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
        kvdbApi->listItems(
            reader->getString("Kvdb_1.kvdbId"),
            {
                .skip=0, 
                .limit=1, 
                .sortOrder="BLACH"
            }
        );
    }, core::Exception);
}

TEST_F(KvdbTest, listItems_correct_input_data) {
    core::PagingList<kvdb::Item> listItems;
    // {.skip=4, .limit=1, .sortOrder="desc"}
    EXPECT_NO_THROW({
        listItems = kvdbApi->listItems(
            reader->getString("Kvdb_1.kvdbId"),
            {
                .skip=4, 
                .limit=1, 
                .sortOrder="desc"
            }
        );
    });
    EXPECT_EQ(listItems.totalAvailable, 2);
    EXPECT_EQ(listItems.readItems.size(), 0);
    // {.skip=1, .limit=1, .sortOrder="desc"}
    EXPECT_NO_THROW({
        listItems = kvdbApi->listItems(
            reader->getString("Kvdb_1.kvdbId"),
            {
                .skip=1, 
                .limit=1, 
                .sortOrder="desc"
            }
        );
    });
    EXPECT_EQ(listItems.totalAvailable, 2);
    EXPECT_EQ(listItems.readItems.size(), 1);
    if(listItems.readItems.size() >= 1) {
        auto item = listItems.readItems[0];
        EXPECT_EQ(item.info.kvdbId, reader->getString("Item_1.info_kvdbId"));
        EXPECT_EQ(item.info.key, reader->getString("Item_1.info_key"));
        EXPECT_EQ(item.info.createDate, reader->getInt64("Item_1.info_createDate"));
        EXPECT_EQ(item.info.author, reader->getString("Item_1.info_author"));
        EXPECT_EQ(item.publicMeta.stdString(), privmx::utils::Hex::toString(reader->getString("Item_1.publicMeta_inHex")));
        EXPECT_EQ(item.privateMeta.stdString(), privmx::utils::Hex::toString(reader->getString("Item_1.privateMeta_inHex")));
        EXPECT_EQ(item.data.stdString(), privmx::utils::Hex::toString(reader->getString("Item_1.data_inHex")));
        EXPECT_EQ(item.statusCode, 0);
        EXPECT_EQ(
            privmx::utils::Utils::stringifyVar(_serializer.serialize(item)),
            reader->getString("Item_1.JSON_data")
        );
        EXPECT_EQ(item.publicMeta.stdString(), privmx::utils::Hex::toString(reader->getString("Item_1.uploaded_publicMeta_inHex")));
        EXPECT_EQ(item.privateMeta.stdString(), privmx::utils::Hex::toString(reader->getString("Item_1.uploaded_privateMeta_inHex")));
        EXPECT_EQ(item.data.stdString(), privmx::utils::Hex::toString(reader->getString("Item_1.uploaded_data_inHex")));
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
        listItems = kvdbApi->listItems(
            reader->getString("Kvdb_1.kvdbId"),
            {
                .skip=0, 
                .limit=3, 
                .sortOrder="asc"
            }
        );
    });
    EXPECT_EQ(listItems.totalAvailable, 2);
    EXPECT_EQ(listItems.readItems.size(), 2);
    if(listItems.readItems.size() >= 1) {
        auto item = listItems.readItems[0];
        EXPECT_EQ(item.info.kvdbId, reader->getString("Item_1.info_kvdbId"));
        EXPECT_EQ(item.info.key, reader->getString("Item_1.info_key"));
        EXPECT_EQ(item.info.createDate, reader->getInt64("Item_1.info_createDate"));
        EXPECT_EQ(item.info.author, reader->getString("Item_1.info_author"));
        EXPECT_EQ(item.publicMeta.stdString(), privmx::utils::Hex::toString(reader->getString("Item_1.publicMeta_inHex")));
        EXPECT_EQ(item.privateMeta.stdString(), privmx::utils::Hex::toString(reader->getString("Item_1.privateMeta_inHex")));
        EXPECT_EQ(item.data.stdString(), privmx::utils::Hex::toString(reader->getString("Item_1.data_inHex")));
        EXPECT_EQ(item.statusCode, 0);
        EXPECT_EQ(
            privmx::utils::Utils::stringifyVar(_serializer.serialize(item)),
            reader->getString("Item_1.JSON_data")
        );
        EXPECT_EQ(item.publicMeta.stdString(), privmx::utils::Hex::toString(reader->getString("Item_1.uploaded_publicMeta_inHex")));
        EXPECT_EQ(item.privateMeta.stdString(), privmx::utils::Hex::toString(reader->getString("Item_1.uploaded_privateMeta_inHex")));
        EXPECT_EQ(item.data.stdString(), privmx::utils::Hex::toString(reader->getString("Item_1.uploaded_data_inHex")));
    }
    if(listItems.readItems.size() >= 2) {
        auto item = listItems.readItems[1];
        EXPECT_EQ(item.info.kvdbId, reader->getString("Item_2.info_kvdbId"));
        EXPECT_EQ(item.info.key, reader->getString("Item_2.info_key"));
        EXPECT_EQ(item.info.createDate, reader->getInt64("Item_2.info_createDate"));
        EXPECT_EQ(item.info.author, reader->getString("Item_2.info_author"));
        EXPECT_EQ(item.publicMeta.stdString(), privmx::utils::Hex::toString(reader->getString("Item_2.publicMeta_inHex")));
        EXPECT_EQ(item.privateMeta.stdString(), privmx::utils::Hex::toString(reader->getString("Item_2.privateMeta_inHex")));
        EXPECT_EQ(item.data.stdString(), privmx::utils::Hex::toString(reader->getString("Item_2.data_inHex")));
        EXPECT_EQ(item.statusCode, 0);
        EXPECT_EQ(
            privmx::utils::Utils::stringifyVar(_serializer.serialize(item)),
            reader->getString("Item_2.JSON_data")
        );
        EXPECT_EQ(item.publicMeta.stdString(), privmx::utils::Hex::toString(reader->getString("Item_2.uploaded_publicMeta_inHex")));
        EXPECT_EQ(item.privateMeta.stdString(), privmx::utils::Hex::toString(reader->getString("Item_2.uploaded_privateMeta_inHex")));
        EXPECT_EQ(item.data.stdString(), privmx::utils::Hex::toString(reader->getString("Item_2.uploaded_data_inHex")));
    }
}


TEST_F(KvdbTest, deleteItem) {
    // incorrect key
    EXPECT_THROW({
        kvdbApi->deleteItem(
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
        kvdbApi->deleteItem(
            reader->getString("Kvdb_1.kvdbId"),
            reader->getString("Item_2.info_key")
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
        kvdbApi->deleteItem(
            reader->getString("Kvdb_1.kvdbId"),
            reader->getString("Item_2.info_key")
        );
    });
    disconnect();
    connectAs(ConnectionType::User2);
    // as manager no created by me
    EXPECT_NO_THROW({
        kvdbApi->deleteItem(
            reader->getString("Kvdb_1.kvdbId"),
            reader->getString("Item_1.info_key")
        );
    });
}