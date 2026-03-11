#include <thread>
#include <gtest/gtest.h>
#include "../utils/BaseTest.hpp"
#include "../utils/FalseUserVerifierInterface.hpp"
#include <privmx/endpoint/core/Exception.hpp>
#include <Poco/Util/IniFileConfiguration.h>
#include <privmx/endpoint/core/EventQueueImpl.hpp>
#include <privmx/crypto/Crypto.hpp>
#include <privmx/utils/Utils.hpp>
#include <privmx/endpoint/core/VarSerializer.hpp>
#include <privmx/endpoint/core/Connection.hpp>
#include <privmx/endpoint/store/StoreApi.hpp>
#include <privmx/endpoint/store/VarSerializer.hpp>
#include <privmx/endpoint/kvdb/KvdbApi.hpp>
#include <privmx/endpoint/kvdb/VarSerializer.hpp>
#include <privmx/endpoint/sql/SqlApi.hpp>
#include <privmx/endpoint/core/CoreException.hpp>
#include <privmx/endpoint/core/UserVerifierInterface.hpp>

using namespace privmx::endpoint;

class FalseUserVerifierInterface: public virtual core::UserVerifierInterface {
public:
    std::vector<bool> verify(const std::vector<core::VerificationRequest>& request) override {
        return std::vector<bool>(request.size(), false);
    };
};

class TrueUserVerifierInterface: public virtual core::UserVerifierInterface {
public:
    std::vector<bool> verify(const std::vector<core::VerificationRequest>& request) override {
        return std::vector<bool>(request.size(), true);
    };
};

enum ConnectionType {
    User1,
    User2,
    Public
};

class SqlTest : public privmx::test::BaseTest {
protected:
    SqlTest() : BaseTest(privmx::test::BaseTestMode::online) {}
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
        storeApi = std::make_shared<store::StoreApi>(
            store::StoreApi::create(
                *connection
            )
        );
        kvdbApi = std::make_shared<kvdb::KvdbApi>(
            kvdb::KvdbApi::create(
                *connection
            )
        );
        sqlApi = std::make_shared<sql::SqlApi>(
            sql::SqlApi::create(
                *connection,
                *storeApi,
                *kvdbApi
            )
        );
    }
    void disconnect() {
        connection->disconnect();
        sqlApi.reset();
        kvdbApi.reset();
        storeApi.reset();
        connection.reset();
    }
    void customSetUp() override {
        reader = new Poco::Util::IniFileConfiguration(INI_FILE_PATH);
        connection = std::make_shared<core::Connection>(
            core::Connection::connect(
                reader->getString("Login.user_1_privKey"),
                reader->getString("Login.solutionId"),
                getPlatformUrl(reader->getString("Login.instanceUrl"))
            )
        );
        storeApi = std::make_shared<store::StoreApi>(
            store::StoreApi::create(
                *connection
            )
        );
        kvdbApi = std::make_shared<kvdb::KvdbApi>(
            kvdb::KvdbApi::create(
                *connection
            )
        );
        sqlApi = std::make_shared<sql::SqlApi>(
            sql::SqlApi::create(
                *connection,
                *storeApi,
                *kvdbApi
            )
        );
    }
    void customTearDown() override { // tmp segfault fix
        connection.reset();
        storeApi.reset();
        kvdbApi.reset();
        sqlApi.reset();
        reader.reset();
        core::EventQueueImpl::getInstance()->clear();
    }

    std::shared_ptr<core::Connection> connection;
    std::shared_ptr<store::StoreApi> storeApi;
    std::shared_ptr<kvdb::KvdbApi> kvdbApi;
    std::shared_ptr<sql::SqlApi> sqlApi;
    Poco::Util::IniFileConfiguration::Ptr reader;
    core::VarSerializer _serializer = core::VarSerializer({});
};

TEST_F(SqlTest, otherCannotReadSqlDatabase) {
    EXPECT_THROW({
        storeApi->getStore(
            reader->getString("SqlDatabase_1.sqlDatabaseId")
        );
    }, core::Exception);
    EXPECT_THROW({
        storeApi->getFile(
            reader->getString("SqlDatabase_1.sqlDatabaseId")
        );
    }, core::Exception);
    EXPECT_THROW({
        kvdbApi->getKvdb(
            reader->getString("SqlDatabase_1.sqlDatabaseId")
        );
    }, core::Exception);
    EXPECT_THROW({
        sqlApi->getSqlDatabase(
            reader->getString("SearchIndex_1.indexId")
        );
    }, core::Exception);
}

TEST_F(SqlTest, getSqlDatabase) {
    // incorrect id
    EXPECT_THROW({
        sqlApi->getSqlDatabase(
            reader->getString("SqlDatabase_1.contextId")
        );
    }, core::Exception);
     // correct SqlDatabaseId
    sql::SqlDatabase database;
    EXPECT_NO_THROW({
        database = sqlApi->getSqlDatabase(
            reader->getString("SqlDatabase_1.sqlDatabaseId")
        );
    });
    EXPECT_EQ(database.contextId, reader->getString("SqlDatabase_1.contextId"));
    EXPECT_EQ(database.sqlDatabaseId, reader->getString("SqlDatabase_1.sqlDatabaseId"));
    EXPECT_EQ(database.createDate, reader->getInt64("SqlDatabase_1.createDate"));
    EXPECT_EQ(database.creator, reader->getString("SqlDatabase_1.creator"));
    EXPECT_EQ(database.lastModificationDate, reader->getInt64("SqlDatabase_1.lastModificationDate"));
    EXPECT_EQ(database.lastModifier, reader->getString("SqlDatabase_1.lastModifier"));
    EXPECT_EQ(database.version, reader->getInt64("SqlDatabase_1.version"));
    EXPECT_EQ(database.statusCode, 0);
    EXPECT_EQ(database.publicMeta.stdString(), privmx::utils::Hex::toString(reader->getString("SqlDatabase_1.publicMeta_inHex")));
    EXPECT_EQ(database.publicMeta.stdString(), privmx::utils::Hex::toString(reader->getString("SqlDatabase_1.uploaded_publicMeta_inHex")));
    EXPECT_EQ(database.privateMeta.stdString(), privmx::utils::Hex::toString(reader->getString("SqlDatabase_1.privateMeta_inHex")));
    EXPECT_EQ(database.privateMeta.stdString(), privmx::utils::Hex::toString(reader->getString("SqlDatabase_1.uploaded_privateMeta_inHex")));

    EXPECT_EQ(database.version, 1);
    EXPECT_EQ(database.creator, reader->getString("Login.user_1_id"));
    EXPECT_EQ(database.lastModifier, reader->getString("Login.user_1_id"));
    EXPECT_EQ(database.users.size(), 1);
    if(database.users.size() == 1) {
        EXPECT_EQ(database.users[0], reader->getString("Login.user_1_id"));
    }
    EXPECT_EQ(database.managers.size(), 1);
    if(database.managers.size() == 1) {
        EXPECT_EQ(database.managers[0], reader->getString("Login.user_1_id"));
    }

    EXPECT_NO_THROW({
        database = sqlApi->getSqlDatabase(
            reader->getString("SqlDatabase_2.sqlDatabaseId")
        );
    });

    EXPECT_NO_THROW({
        database = sqlApi->getSqlDatabase(
            reader->getString("SqlDatabase_3.sqlDatabaseId")
        );
    });
}

TEST_F(SqlTest, listSqlDatabases_incorrect_input_data) {
    // incorrect contextId
    EXPECT_THROW({
        sqlApi->listSqlDatabases(
            reader->getString("SqlDatabase_1.sqlDatabaseId"),
            {
                .skip=0,
                .limit=1,
                .sortOrder="desc"
            }
        );
    }, core::Exception);
    // limit < 0
    EXPECT_THROW({
        sqlApi->listSqlDatabases(
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
        sqlApi->listSqlDatabases(
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
        sqlApi->listSqlDatabases(
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
        sqlApi->listSqlDatabases(
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
        sqlApi->listSqlDatabases(
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
    // incorrect sortBy
    EXPECT_THROW({
        sqlApi->listSqlDatabases(
            reader->getString("Context_1.contextId"),
            core::PagingQuery{
                .skip=0,
                .limit=1,
                .sortOrder="desc",
                .lastId=std::nullopt,
                .sortBy="blach",
                .queryAsJson=std::nullopt
            }
        );
    }, core::InvalidParamsException);
}

TEST_F(SqlTest, listSqlDatabases_correct_input_data) {
    core::PagingList<sql::SqlDatabase> listSqlDatabases;
    sql::SqlDatabase sqlDatabase;
    // {.skip=4, .limit=1, .sortOrder="desc"}
    EXPECT_NO_THROW({
        listSqlDatabases = sqlApi->listSqlDatabases(
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
        listSqlDatabases = sqlApi->listSqlDatabases(
            reader->getString("Context_1.contextId"),
            {
                .skip=0,
                .limit=1,
                .sortOrder="desc"
            }
        );
    });
    EXPECT_EQ(listSqlDatabases.totalAvailable, 3);
    EXPECT_EQ(listSqlDatabases.readItems.size(), 1);
    if(listSqlDatabases.readItems.size() >= 1) {
        sqlDatabase = listSqlDatabases.readItems[0];
        EXPECT_EQ(sqlDatabase.sqlDatabaseId, reader->getString("SqlDatabase_3.sqlDatabaseId"));
        EXPECT_EQ(sqlDatabase.contextId, reader->getString("SqlDatabase_3.contextId"));
        EXPECT_EQ(sqlDatabase.createDate, reader->getInt64("SqlDatabase_3.createDate"));
        EXPECT_EQ(sqlDatabase.creator, reader->getString("SqlDatabase_3.creator"));
        EXPECT_EQ(sqlDatabase.lastModificationDate, reader->getInt64("SqlDatabase_3.lastModificationDate"));
        EXPECT_EQ(sqlDatabase.lastModifier, reader->getString("SqlDatabase_3.lastModifier"));
        EXPECT_EQ(sqlDatabase.version, reader->getInt64("SqlDatabase_3.version"));
        EXPECT_EQ(sqlDatabase.statusCode, 0);
        EXPECT_EQ(sqlDatabase.publicMeta.stdString(), privmx::utils::Hex::toString(reader->getString("SqlDatabase_3.publicMeta_inHex")));
        EXPECT_EQ(sqlDatabase.publicMeta.stdString(), privmx::utils::Hex::toString(reader->getString("SqlDatabase_3.uploaded_publicMeta_inHex")));
        EXPECT_EQ(sqlDatabase.privateMeta.stdString(), privmx::utils::Hex::toString(reader->getString("SqlDatabase_3.privateMeta_inHex")));
        EXPECT_EQ(sqlDatabase.privateMeta.stdString(), privmx::utils::Hex::toString(reader->getString("SqlDatabase_3.uploaded_privateMeta_inHex")));
        EXPECT_EQ(sqlDatabase.users.size(), 2);
        if(sqlDatabase.users.size() == 2) {
            EXPECT_EQ(sqlDatabase.users[0], reader->getString("Login.user_1_id"));
            EXPECT_EQ(sqlDatabase.users[1], reader->getString("Login.user_2_id"));
        }
        EXPECT_EQ(sqlDatabase.managers.size(), 1);
        if(sqlDatabase.managers.size() == 1) {
            EXPECT_EQ(sqlDatabase.managers[0], reader->getString("Login.user_1_id"));
        }
    }
    // {.skip=1, .limit=3, .sortOrder="asc", .sortBy="createDate"}
    EXPECT_NO_THROW({
        listSqlDatabases = sqlApi->listSqlDatabases(
            reader->getString("Context_1.contextId"),
            {
                .skip=1,
                .limit=3,
                .sortOrder="asc"
            }
        );
    });
    EXPECT_EQ(listSqlDatabases.totalAvailable, 3);
    EXPECT_EQ(listSqlDatabases.readItems.size(), 2);
    if(listSqlDatabases.readItems.size() >= 1) {
        sqlDatabase = listSqlDatabases.readItems[0];
        EXPECT_EQ(sqlDatabase.sqlDatabaseId, reader->getString("SqlDatabase_2.sqlDatabaseId"));
        EXPECT_EQ(sqlDatabase.contextId, reader->getString("SqlDatabase_2.contextId"));
        EXPECT_EQ(sqlDatabase.createDate, reader->getInt64("SqlDatabase_2.createDate"));
        EXPECT_EQ(sqlDatabase.creator, reader->getString("SqlDatabase_2.creator"));
        EXPECT_EQ(sqlDatabase.lastModificationDate, reader->getInt64("SqlDatabase_2.lastModificationDate"));
        EXPECT_EQ(sqlDatabase.lastModifier, reader->getString("SqlDatabase_2.lastModifier"));
        EXPECT_EQ(sqlDatabase.version, reader->getInt64("SqlDatabase_2.version"));
        EXPECT_EQ(sqlDatabase.publicMeta.stdString(), privmx::utils::Hex::toString(reader->getString("SqlDatabase_2.publicMeta_inHex")));
        EXPECT_EQ(sqlDatabase.publicMeta.stdString(), privmx::utils::Hex::toString(reader->getString("SqlDatabase_2.uploaded_publicMeta_inHex")));
        EXPECT_EQ(sqlDatabase.privateMeta.stdString(), privmx::utils::Hex::toString(reader->getString("SqlDatabase_2.privateMeta_inHex")));
        EXPECT_EQ(sqlDatabase.privateMeta.stdString(), privmx::utils::Hex::toString(reader->getString("SqlDatabase_2.uploaded_privateMeta_inHex")));
        EXPECT_EQ(sqlDatabase.statusCode, 0);
        EXPECT_EQ(sqlDatabase.users.size(), 2);
        if(sqlDatabase.users.size() == 2) {
            EXPECT_EQ(sqlDatabase.users[0], reader->getString("Login.user_1_id"));
            EXPECT_EQ(sqlDatabase.users[1], reader->getString("Login.user_2_id"));
        }
        EXPECT_EQ(sqlDatabase.managers.size(), 2);
        if(sqlDatabase.managers.size() == 2) {
            EXPECT_EQ(sqlDatabase.managers[0], reader->getString("Login.user_1_id"));
            EXPECT_EQ(sqlDatabase.managers[1], reader->getString("Login.user_2_id"));
        }
    }
    if(listSqlDatabases.readItems.size() >= 2) {
        sqlDatabase = listSqlDatabases.readItems[1];
        EXPECT_EQ(sqlDatabase.sqlDatabaseId, reader->getString("SqlDatabase_3.sqlDatabaseId"));
        EXPECT_EQ(sqlDatabase.contextId, reader->getString("SqlDatabase_3.contextId"));
        EXPECT_EQ(sqlDatabase.createDate, reader->getInt64("SqlDatabase_3.createDate"));
        EXPECT_EQ(sqlDatabase.creator, reader->getString("SqlDatabase_3.creator"));
        EXPECT_EQ(sqlDatabase.lastModificationDate, reader->getInt64("SqlDatabase_3.lastModificationDate"));
        EXPECT_EQ(sqlDatabase.lastModifier, reader->getString("SqlDatabase_3.lastModifier"));
        EXPECT_EQ(sqlDatabase.version, reader->getInt64("SqlDatabase_3.version"));
        EXPECT_EQ(sqlDatabase.publicMeta.stdString(), privmx::utils::Hex::toString(reader->getString("SqlDatabase_3.publicMeta_inHex")));
        EXPECT_EQ(sqlDatabase.publicMeta.stdString(), privmx::utils::Hex::toString(reader->getString("SqlDatabase_3.uploaded_publicMeta_inHex")));
        EXPECT_EQ(sqlDatabase.privateMeta.stdString(), privmx::utils::Hex::toString(reader->getString("SqlDatabase_3.privateMeta_inHex")));
        EXPECT_EQ(sqlDatabase.privateMeta.stdString(), privmx::utils::Hex::toString(reader->getString("SqlDatabase_3.uploaded_privateMeta_inHex")));
        EXPECT_EQ(sqlDatabase.statusCode, 0);
        EXPECT_EQ(sqlDatabase.users.size(), 2);
        if(sqlDatabase.users.size() == 2) {
            EXPECT_EQ(sqlDatabase.users[0], reader->getString("Login.user_1_id"));
            EXPECT_EQ(sqlDatabase.users[1], reader->getString("Login.user_2_id"));
        }
        EXPECT_EQ(sqlDatabase.managers.size(), 1);
        if(sqlDatabase.managers.size() == 1) {
            EXPECT_EQ(sqlDatabase.managers[0], reader->getString("Login.user_1_id"));
        }
    }
}


TEST_F(SqlTest, createSqlDatabase) {
    // incorrect contextId
    EXPECT_THROW({
        sqlApi->createSqlDatabase(
            reader->getString("SqlDatabase_1.sqlDatabaseId"),
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
        sqlApi->createSqlDatabase(
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
        sqlApi->createSqlDatabase(
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
        sqlApi->createSqlDatabase(
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
    std::string sqlDatabaseId;
    sql::SqlDatabase sqlDatabase;
    EXPECT_NO_THROW({
        sqlDatabaseId = sqlApi->createSqlDatabase(
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
    if(sqlDatabaseId.empty()) {
        FAIL();
    }
    EXPECT_NO_THROW({
        sqlDatabase = sqlApi->getSqlDatabase(
            sqlDatabaseId
        );
    });
    EXPECT_EQ(sqlDatabase.statusCode, 0);
    EXPECT_EQ(sqlDatabase.contextId, reader->getString("Context_1.contextId"));
    EXPECT_EQ(sqlDatabase.publicMeta.stdString(), "public");
    EXPECT_EQ(sqlDatabase.privateMeta.stdString(), "private");
    EXPECT_EQ(sqlDatabase.users.size(), 1);
    if(sqlDatabase.users.size() == 1) {
        EXPECT_EQ(sqlDatabase.users[0], reader->getString("Login.user_2_id"));
    }
    EXPECT_EQ(sqlDatabase.managers.size(), 1);
    if(sqlDatabase.managers.size() == 1) {
        EXPECT_EQ(sqlDatabase.managers[0], reader->getString("Login.user_1_id"));
    }
    // same users and managers
    EXPECT_NO_THROW({
        sqlDatabaseId = sqlApi->createSqlDatabase(
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
    if(sqlDatabaseId.empty()) {
        FAIL();
    }
    EXPECT_NO_THROW({
        sqlDatabase = sqlApi->getSqlDatabase(
            sqlDatabaseId
        );
    });
    EXPECT_EQ(sqlDatabase.statusCode, 0);
    EXPECT_EQ(sqlDatabase.contextId, reader->getString("Context_1.contextId"));
    EXPECT_EQ(sqlDatabase.publicMeta.stdString(), "public");
    EXPECT_EQ(sqlDatabase.privateMeta.stdString(), "private");
    EXPECT_EQ(sqlDatabase.users.size(), 1);
    if(sqlDatabase.users.size() == 1) {
        EXPECT_EQ(sqlDatabase.users[0], reader->getString("Login.user_1_id"));
    }
    EXPECT_EQ(sqlDatabase.managers.size(), 1);
    if(sqlDatabase.managers.size() == 1) {
        EXPECT_EQ(sqlDatabase.managers[0], reader->getString("Login.user_1_id"));
    }
}

TEST_F(SqlTest, updateSqDatabase_incorrect_data) {
    // incorrect sqlDatabaseId
    EXPECT_THROW({
        sqlApi->updateSqlDatabase(
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
        sqlApi->updateSqlDatabase(
            reader->getString("SqlDatabase_1.sqlDatabaseId"),
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
        sqlApi->updateSqlDatabase(
            reader->getString("SqlDatabase_1.sqlDatabaseId"),
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
        sqlApi->updateSqlDatabase(
            reader->getString("SqlDatabase_1.sqlDatabaseId"),
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
        sqlApi->updateSqlDatabase(
            reader->getString("SqlDatabase_2.sqlDatabaseId"),
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

TEST_F(SqlTest, updateSqlDatabase_correct_data) {
    sql::SqlDatabase sqlDatabase;
    // new users
    EXPECT_NO_THROW({
        sqlApi->updateSqlDatabase(
            reader->getString("SqlDatabase_1.sqlDatabaseId"),
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
        sqlDatabase = sqlApi->getSqlDatabase(
            reader->getString("SqlDatabase_1.sqlDatabaseId")
        );
    });
    EXPECT_EQ(sqlDatabase.statusCode, 0);
    EXPECT_EQ(sqlDatabase.contextId, reader->getString("Context_1.contextId"));
    EXPECT_EQ(sqlDatabase.version, 2);
    EXPECT_EQ(sqlDatabase.publicMeta.stdString(), "public");
    EXPECT_EQ(sqlDatabase.privateMeta.stdString(), "private");
    EXPECT_EQ(sqlDatabase.users.size(), 2);
    if(sqlDatabase.users.size() == 2) {
        EXPECT_EQ(sqlDatabase.users[0], reader->getString("Login.user_1_id"));
        EXPECT_EQ(sqlDatabase.users[1], reader->getString("Login.user_2_id"));
    }
    EXPECT_EQ(sqlDatabase.managers.size(), 1);
    if(sqlDatabase.managers.size() == 1) {
        EXPECT_EQ(sqlDatabase.managers[0], reader->getString("Login.user_1_id"));
    }
    // new managers
    EXPECT_NO_THROW({
        sqlApi->updateSqlDatabase(
            reader->getString("SqlDatabase_1.sqlDatabaseId"),
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
        sqlDatabase = sqlApi->getSqlDatabase(
            reader->getString("SqlDatabase_1.sqlDatabaseId")
        );
    });
    EXPECT_EQ(sqlDatabase.statusCode, 0);
    EXPECT_EQ(sqlDatabase.contextId, reader->getString("Context_1.contextId"));
    EXPECT_EQ(sqlDatabase.version, 3);
    EXPECT_EQ(sqlDatabase.publicMeta.stdString(), "public");
    EXPECT_EQ(sqlDatabase.privateMeta.stdString(), "private");
    EXPECT_EQ(sqlDatabase.users.size(), 1);
    if(sqlDatabase.users.size() == 1) {
        EXPECT_EQ(sqlDatabase.users[0], reader->getString("Login.user_1_id"));
    }
    EXPECT_EQ(sqlDatabase.managers.size(), 2);
    if(sqlDatabase.managers.size() == 2) {
        EXPECT_EQ(sqlDatabase.managers[0], reader->getString("Login.user_1_id"));
        EXPECT_EQ(sqlDatabase.managers[1], reader->getString("Login.user_2_id"));
    }
    // less users
    EXPECT_NO_THROW({
        sqlApi->updateSqlDatabase(
            reader->getString("SqlDatabase_2.sqlDatabaseId"),
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
        sqlDatabase = sqlApi->getSqlDatabase(
            reader->getString("SqlDatabase_2.sqlDatabaseId")
        );
    });
    EXPECT_EQ(sqlDatabase.statusCode, 0);
    EXPECT_EQ(sqlDatabase.contextId, reader->getString("Context_1.contextId"));
    EXPECT_EQ(sqlDatabase.version, 2);
    EXPECT_EQ(sqlDatabase.publicMeta.stdString(), "public");
    EXPECT_EQ(sqlDatabase.privateMeta.stdString(), "private");
    EXPECT_EQ(sqlDatabase.users.size(), 1);
    if(sqlDatabase.users.size() == 1) {
        EXPECT_EQ(sqlDatabase.users[0], reader->getString("Login.user_1_id"));
    }
    EXPECT_EQ(sqlDatabase.managers.size(), 2);
    if(sqlDatabase.managers.size() == 2) {
        EXPECT_EQ(sqlDatabase.managers[0], reader->getString("Login.user_1_id"));
        EXPECT_EQ(sqlDatabase.managers[1], reader->getString("Login.user_2_id"));
    }
    // less managers
    EXPECT_NO_THROW({
        sqlApi->updateSqlDatabase(
            reader->getString("SqlDatabase_2.sqlDatabaseId"),
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
        sqlDatabase = sqlApi->getSqlDatabase(
            reader->getString("SqlDatabase_2.sqlDatabaseId")
        );
    });
    EXPECT_EQ(sqlDatabase.statusCode, 0);
    EXPECT_EQ(sqlDatabase.contextId, reader->getString("Context_1.contextId"));
    EXPECT_EQ(sqlDatabase.version, 3);
    EXPECT_EQ(sqlDatabase.publicMeta.stdString(), "public");
    EXPECT_EQ(sqlDatabase.privateMeta.stdString(), "private");
    EXPECT_EQ(sqlDatabase.users.size(), 1);
    if(sqlDatabase.users.size() == 1) {
        EXPECT_EQ(sqlDatabase.users[0], reader->getString("Login.user_1_id"));
    }
    EXPECT_EQ(sqlDatabase.managers.size(), 1);
    if(sqlDatabase.managers.size() == 1) {
        EXPECT_EQ(sqlDatabase.managers[0], reader->getString("Login.user_1_id"));
    }
    // incorrect version force true
    EXPECT_NO_THROW({
        sqlApi->updateSqlDatabase(
            reader->getString("SqlDatabase_3.sqlDatabaseId"),
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
        sqlDatabase = sqlApi->getSqlDatabase(
            reader->getString("SqlDatabase_3.sqlDatabaseId")
        );
    });
    EXPECT_EQ(sqlDatabase.statusCode, 0);
    EXPECT_EQ(sqlDatabase.contextId, reader->getString("Context_1.contextId"));
    EXPECT_EQ(sqlDatabase.version, 2);
    EXPECT_EQ(sqlDatabase.publicMeta.stdString(), "public");
    EXPECT_EQ(sqlDatabase.privateMeta.stdString(), "private");
    EXPECT_EQ(sqlDatabase.users.size(), 1);
    if(sqlDatabase.users.size() == 1) {
        EXPECT_EQ(sqlDatabase.users[0], reader->getString("Login.user_1_id"));
    }
    EXPECT_EQ(sqlDatabase.managers.size(), 1);
    if(sqlDatabase.managers.size() == 1) {
        EXPECT_EQ(sqlDatabase.managers[0], reader->getString("Login.user_1_id"));
    }
}

TEST_F(SqlTest, deleteSqlDatabase) {
    // incorrect sqlDatabaseId
    EXPECT_THROW({
        sqlApi->deleteSqlDatabase(
            reader->getString("Context_1.contextId")
        );
    }, core::Exception);
    // as manager
     EXPECT_NO_THROW({
        sqlApi->deleteSqlDatabase(
            reader->getString("SqlDatabase_1.sqlDatabaseId")
        );
    });
    EXPECT_THROW({
        sqlApi->deleteSqlDatabase(
            reader->getString("SqlDatabase_1.sqlDatabaseId")
        );
    }, core::Exception);
    // as user
    disconnect();
    connectAs(ConnectionType::User2);
    EXPECT_THROW({
        sqlApi->deleteSqlDatabase(
            reader->getString("SqlDatabase_3.sqlDatabaseId")
        );
    }, core::Exception);
}

TEST_F(SqlTest, sql_request_CREATE_TABLE) {
    auto handle = sqlApi->openSqlDatabase(reader->getString("SqlDatabase_2.sqlDatabaseId"));
    std::shared_ptr<sql::Query> queryResult;
    std::shared_ptr<sql::Row> row;
    EXPECT_NO_THROW({
        queryResult = handle->query(
            "CREATE TABLE tt_table (id INTEGER PRIMARY KEY AUTOINCREMENT, text_no_null TEXT NOT NULL UNIQUE, int INTEGER, date TEXT DEFAULT (datetime('now')));"
        );
        EXPECT_EQ(queryResult->step()->getStatus(), sql::EvaluationStatus::T_DONE);
        queryResult->finalize();
    });
    EXPECT_NO_THROW({
        queryResult = handle->query(
            "CREATE TABLE tt_table (id INTEGER PRIMARY KEY AUTOINCREMENT, text_no_null TEXT NOT NULL UNIQUE, int INTEGER, date TEXT DEFAULT (datetime('now')));"
        );
        EXPECT_EQ(queryResult->step()->getStatus(), sql::EvaluationStatus::T_ERROR);
        queryResult->finalize();
    });
    std::string sqlQuery = "SELECT * FROM tt_table";
    EXPECT_NO_THROW({
        queryResult = handle->query(
            sqlQuery
        );
        EXPECT_EQ(queryResult->step()->getStatus(), sql::EvaluationStatus::T_DONE);
        queryResult->finalize();
    });
}

TEST_F(SqlTest, sql_request_SELECT_INSERT) {
    auto handle = sqlApi->openSqlDatabase(reader->getString("SqlDatabase_1.sqlDatabaseId"));
    std::shared_ptr<sql::Query> queryResult;
    std::shared_ptr<sql::Row> row;
    std::string sqlQuery = 
        "SELECT * FROM "+reader->getString("SqlDatabase_1.table_1_name")+" "+
        "WHERE "+reader->getString("SqlDatabase_1.table_1_field_3")+" = "+reader->getString("SqlDatabase_1.table_1_entry_2_field_3")+" "+
        "ORDER BY ?";
    EXPECT_NO_THROW({
        queryResult = handle->query(
            sqlQuery
        );
        queryResult->bindText(1, reader->getString("SqlDatabase_1.table_1_field_1"));
    });
    EXPECT_NO_THROW({
        row = queryResult->step();
    });
    EXPECT_EQ(row->getStatus(), sql::EvaluationStatus::T_ROW);
    if(row->getStatus() != sql::EvaluationStatus::T_ROW) return;
    EXPECT_EQ(row->getColumnCount(), 3);
    if(row->getColumnCount() != 3) return;
    EXPECT_EQ(static_cast<int64_t>(row->getColumn(0)->getType()), reader->getInt64("SqlDatabase_1.table_1_field_1_type"));
    EXPECT_EQ(row->getColumn(0)->getInt64(), reader->getInt64("SqlDatabase_1.table_1_entry_2_field_1"));
    EXPECT_EQ(static_cast<int64_t>(row->getColumn(1)->getType()), reader->getInt64("SqlDatabase_1.table_1_field_2_type"));
    EXPECT_EQ(row->getColumn(1)->getText(),  reader->getString("SqlDatabase_1.table_1_entry_2_field_2"));
    EXPECT_EQ(static_cast<int64_t>(row->getColumn(2)->getType()), reader->getInt64("SqlDatabase_1.table_1_field_3_type"));
    EXPECT_EQ(row->getColumn(2)->getInt64(), reader->getInt64("SqlDatabase_1.table_1_entry_2_field_3"));
    EXPECT_NO_THROW({
        row = queryResult->step();
    });
    EXPECT_EQ(row->getStatus(), sql::EvaluationStatus::T_DONE);
    queryResult->finalize();
    sqlQuery = "INSERT INTO "+reader->getString("SqlDatabase_1.table_1_name")+"("+reader->getString("SqlDatabase_1.table_1_field_2")+", "+reader->getString("SqlDatabase_1.table_1_field_3")+") VALUES (?, 30);";
    EXPECT_NO_THROW({
        queryResult = handle->query(
            sqlQuery
        );
        std::cout << sqlQuery << std::endl;
        queryResult->bindText(1, "string_text_insert");
        EXPECT_EQ(queryResult->step()->getStatus(), sql::EvaluationStatus::T_DONE);
        queryResult->finalize();
    });
    sqlQuery = 
        "SELECT * FROM "+reader->getString("SqlDatabase_1.table_1_name")+" "+
        "WHERE "+reader->getString("SqlDatabase_1.table_1_field_3")+" = 30";
    EXPECT_NO_THROW({
        queryResult = handle->query(
            sqlQuery
        );
    });
    EXPECT_NO_THROW({
        row = queryResult->step();
    });
    EXPECT_EQ(row->getStatus(), sql::EvaluationStatus::T_ROW);
    if(row->getStatus() != sql::EvaluationStatus::T_ROW) return;
    EXPECT_EQ(row->getColumnCount(), 3);
    if(row->getColumnCount() != 3) return;
    EXPECT_EQ(static_cast<int64_t>(row->getColumn(0)->getType()), reader->getInt64("SqlDatabase_1.table_1_field_1_type"));
    EXPECT_EQ(row->getColumn(0)->getInt64(), reader->getInt64("SqlDatabase_1.table_1_entry_2_field_1")+1);
    EXPECT_EQ(static_cast<int64_t>(row->getColumn(1)->getType()), reader->getInt64("SqlDatabase_1.table_1_field_2_type"));
    EXPECT_EQ(row->getColumn(1)->getText(), "string_text_insert");
    EXPECT_EQ(static_cast<int64_t>(row->getColumn(2)->getType()), reader->getInt64("SqlDatabase_1.table_1_field_3_type"));
    EXPECT_EQ(row->getColumn(2)->getInt64(), 30);
    EXPECT_NO_THROW({
        row = queryResult->step();
    });
    EXPECT_EQ(row->getStatus(), sql::EvaluationStatus::T_DONE);
    queryResult->finalize();
}

TEST_F(SqlTest, sql_transaction) {
    auto handle = sqlApi->openSqlDatabase(reader->getString("SqlDatabase_1.sqlDatabaseId"));
    auto transactionHandle = handle->beginTransaction();
    std::shared_ptr<sql::Query> queryResult;
    std::shared_ptr<sql::Row> row;
    std::string sqlQuery;

    sqlQuery = 
        "SELECT * FROM "+reader->getString("SqlDatabase_1.table_1_name")+" "+
        "WHERE "+reader->getString("SqlDatabase_1.table_1_field_3")+" = 30";
    EXPECT_NO_THROW({
        queryResult = handle->query(
            sqlQuery
        );
    });
    EXPECT_NO_THROW({
        row = queryResult->step();
    });
    EXPECT_EQ(row->getStatus(), sql::EvaluationStatus::T_DONE);
    queryResult->finalize();

    sqlQuery = "INSERT INTO "+reader->getString("SqlDatabase_1.table_1_name")+"("+reader->getString("SqlDatabase_1.table_1_field_2")+", "+reader->getString("SqlDatabase_1.table_1_field_3")+") VALUES (?, 30);";
    EXPECT_NO_THROW({
        queryResult = transactionHandle->query(
            sqlQuery
        );
        std::cout << sqlQuery << std::endl;
        queryResult->bindText(1, "string_text_insert");
        EXPECT_EQ(queryResult->step()->getStatus(), sql::EvaluationStatus::T_DONE);
        queryResult->finalize();
    });
    sqlQuery = 
        "SELECT * FROM "+reader->getString("SqlDatabase_1.table_1_name")+" "+
        "WHERE "+reader->getString("SqlDatabase_1.table_1_field_3")+" = 30";
    EXPECT_NO_THROW({
        queryResult = transactionHandle->query(
            sqlQuery
        );
    });
    EXPECT_NO_THROW({
        row = queryResult->step();
    });
    EXPECT_EQ(row->getStatus(), sql::EvaluationStatus::T_ROW);
    if(row->getStatus() != sql::EvaluationStatus::T_ROW) return;
    EXPECT_EQ(row->getColumnCount(), 3);
    if(row->getColumnCount() != 3) return;
    EXPECT_EQ(static_cast<int64_t>(row->getColumn(0)->getType()), reader->getInt64("SqlDatabase_1.table_1_field_1_type"));
    EXPECT_EQ(row->getColumn(0)->getInt64(), reader->getInt64("SqlDatabase_1.table_1_entry_2_field_1")+1);
    EXPECT_EQ(static_cast<int64_t>(row->getColumn(1)->getType()), reader->getInt64("SqlDatabase_1.table_1_field_2_type"));
    EXPECT_EQ(row->getColumn(1)->getText(), "string_text_insert");
    EXPECT_EQ(static_cast<int64_t>(row->getColumn(2)->getType()), reader->getInt64("SqlDatabase_1.table_1_field_3_type"));
    EXPECT_EQ(row->getColumn(2)->getInt64(), 30);
    EXPECT_NO_THROW({
        row = queryResult->step();
    });
    EXPECT_EQ(row->getStatus(), sql::EvaluationStatus::T_DONE);
    queryResult->finalize();

    EXPECT_NO_THROW({
        transactionHandle->rollback();
    });

    sqlQuery = 
        "SELECT * FROM "+reader->getString("SqlDatabase_1.table_1_name")+" "+
        "WHERE "+reader->getString("SqlDatabase_1.table_1_field_3")+" = 30";
    EXPECT_NO_THROW({
        queryResult = handle->query(
            sqlQuery
        );
    });
    EXPECT_NO_THROW({
        row = queryResult->step();
    }); 
    EXPECT_EQ(row->getStatus(), sql::EvaluationStatus::T_DONE);
    queryResult->finalize();
}

TEST_F(SqlTest, sql_request_SELECT_INSERT_multiple_users) {
    EXPECT_NO_THROW({
        sqlApi->updateSqlDatabase(
            reader->getString("SqlDatabase_1.sqlDatabaseId"),
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
            true,
            false
        );
    });

    auto fun = [&](std::shared_ptr<sql::DatabaseHandle> handle, std::string insertSting) {
        std::shared_ptr<sql::Query> queryResult;
        std::shared_ptr<sql::Row> row;
        std::string sqlQuery;
        sqlQuery = "INSERT INTO "+reader->getString("SqlDatabase_1.table_1_name")+"("+reader->getString("SqlDatabase_1.table_1_field_2")+", "+reader->getString("SqlDatabase_1.table_1_field_3")+") VALUES ('"+insertSting+"', 30);";
        EXPECT_NO_THROW({
            queryResult = handle->query(
                sqlQuery
            );
            std::cout << sqlQuery << std::endl;
            EXPECT_EQ(queryResult->step()->getStatus(), sql::EvaluationStatus::T_DONE);
            queryResult->finalize();
        });
        sqlQuery = 
            "SELECT * FROM "+reader->getString("SqlDatabase_1.table_1_name")+" "+
            "WHERE "+reader->getString("SqlDatabase_1.table_1_field_3")+" = 30";
        EXPECT_NO_THROW({
            queryResult = handle->query(
                sqlQuery
            );
        });
        EXPECT_NO_THROW({
            row = queryResult->step();
        });
        bool insertedStringFound = false;
        while(row->getStatus() == sql::EvaluationStatus::T_ROW) {
            EXPECT_EQ(row->getStatus(), sql::EvaluationStatus::T_ROW);
            if(row->getStatus() != sql::EvaluationStatus::T_ROW) return;
            EXPECT_EQ(row->getColumnCount(), 3);
            if(row->getColumnCount() != 3) return;
            EXPECT_EQ(static_cast<int64_t>(row->getColumn(0)->getType()), reader->getInt64("SqlDatabase_1.table_1_field_1_type"));
            EXPECT_EQ(static_cast<int64_t>(row->getColumn(1)->getType()), reader->getInt64("SqlDatabase_1.table_1_field_2_type"));
            if(insertSting == row->getColumn(1)->getText()) insertedStringFound = true;
            EXPECT_EQ(static_cast<int64_t>(row->getColumn(2)->getType()), reader->getInt64("SqlDatabase_1.table_1_field_3_type"));
            EXPECT_EQ(row->getColumn(2)->getInt64(), 30);
            EXPECT_NO_THROW({
                row = queryResult->step();
            });
        }
        
        EXPECT_TRUE(insertedStringFound);
        EXPECT_EQ(row->getStatus(), sql::EvaluationStatus::T_DONE);
        queryResult->finalize();
        return;
    };
    auto connection_2 = std::make_shared<core::Connection>(
        core::Connection::connect(
            reader->getString("Login.user_2_privKey"),
            reader->getString("Login.solutionId"),
            getPlatformUrl(reader->getString("Login.instanceUrl"))
        )
    );
    auto storeApi_2 = std::make_shared<store::StoreApi>(
        store::StoreApi::create(
            *connection
        )
    );
    auto kvdbApi_2 = std::make_shared<kvdb::KvdbApi>(
        kvdb::KvdbApi::create(
            *connection
        )
    );
    auto sqlApi_2 = std::make_shared<sql::SqlApi>(
        sql::SqlApi::create(
            *connection,
            *storeApi,
            *kvdbApi
        )
    );
    auto user_1_handle = sqlApi->openSqlDatabase(reader->getString("SqlDatabase_1.sqlDatabaseId"));
    auto user_2_handle = sqlApi_2->openSqlDatabase(reader->getString("SqlDatabase_1.sqlDatabaseId"));
    std::thread user_1 = std::thread(fun, user_1_handle, "user_1_random_string");
    std::thread user_2 = std::thread(fun, user_2_handle, "user_2_random_string");
    user_1.join();
    user_2.join();
}

TEST_F(SqlTest, sql_transaction_multiple_users) {
    EXPECT_NO_THROW({
        sqlApi->updateSqlDatabase(
            reader->getString("SqlDatabase_1.sqlDatabaseId"),
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
            true,
            false
        );
    });

    auto fun = [&](std::shared_ptr<sql::Transaction> transactionHandle, std::string insertSting) {
        std::shared_ptr<sql::Query> queryResult;
        std::shared_ptr<sql::Row> row;
        std::string sqlQuery;
        sqlQuery = "INSERT INTO "+reader->getString("SqlDatabase_1.table_1_name")+"("+reader->getString("SqlDatabase_1.table_1_field_2")+", "+reader->getString("SqlDatabase_1.table_1_field_3")+") VALUES (?, 30);";
        EXPECT_NO_THROW({
            queryResult = transactionHandle->query(
                sqlQuery
            );
            queryResult->bindText(1, insertSting);

            EXPECT_EQ(queryResult->step()->getStatus(), sql::EvaluationStatus::T_DONE);
            queryResult->finalize();
        });
        sqlQuery = 
            "SELECT * FROM "+reader->getString("SqlDatabase_1.table_1_name")+" "+
            "WHERE "+reader->getString("SqlDatabase_1.table_1_field_3")+" = 30";
        EXPECT_NO_THROW({
            queryResult = transactionHandle->query(
                sqlQuery
            );
        });
        EXPECT_NO_THROW({
            row = queryResult->step();
        });
        bool insertedStringFound = false;
        EXPECT_EQ(row->getStatus(), sql::EvaluationStatus::T_ROW);
        if(row->getStatus() != sql::EvaluationStatus::T_ROW) return;
        EXPECT_EQ(row->getColumnCount(), 3);
        if(row->getColumnCount() != 3) return;
        EXPECT_EQ(static_cast<int64_t>(row->getColumn(0)->getType()), reader->getInt64("SqlDatabase_1.table_1_field_1_type"));
        EXPECT_EQ(static_cast<int64_t>(row->getColumn(1)->getType()), reader->getInt64("SqlDatabase_1.table_1_field_2_type"));
        EXPECT_EQ(insertSting, row->getColumn(1)->getText());
        EXPECT_EQ(static_cast<int64_t>(row->getColumn(2)->getType()), reader->getInt64("SqlDatabase_1.table_1_field_3_type"));
        EXPECT_EQ(row->getColumn(2)->getInt64(), 30);
        EXPECT_NO_THROW({
            row = queryResult->step();
        });
        EXPECT_EQ(row->getStatus(), sql::EvaluationStatus::T_DONE);
        queryResult->finalize();
        return;
    };
    auto connection_2 = std::make_shared<core::Connection>(
        core::Connection::connect(
            reader->getString("Login.user_2_privKey"),
            reader->getString("Login.solutionId"),
            getPlatformUrl(reader->getString("Login.instanceUrl"))
        )
    );
    auto storeApi_2 = std::make_shared<store::StoreApi>(
        store::StoreApi::create(
            *connection
        )
    );
    auto kvdbApi_2 = std::make_shared<kvdb::KvdbApi>(
        kvdb::KvdbApi::create(
            *connection
        )
    );
    auto sqlApi_2 = std::make_shared<sql::SqlApi>(
        sql::SqlApi::create(
            *connection,
            *storeApi,
            *kvdbApi
        )
    );
    auto user_1_handle = sqlApi->openSqlDatabase(reader->getString("SqlDatabase_1.sqlDatabaseId"));
    auto user_1_transactionHandle = user_1_handle->beginTransaction();
    auto user_2_handle = sqlApi_2->openSqlDatabase(reader->getString("SqlDatabase_1.sqlDatabaseId"));
    auto user_2_transactionHandle = user_2_handle->beginTransaction();
    std::thread user_1 = std::thread(fun, user_1_transactionHandle, "user_1_random_string");
    std::thread user_2 = std::thread(fun, user_2_transactionHandle, "user_2_random_string");
    user_1.join();
    user_2.join();
    user_1_transactionHandle->commit();
    user_2_transactionHandle->commit();
}