
#include <gtest/gtest.h>
#include "../utils/BaseTest.hpp"
#include "../utils/FalseUserVerifierInterface.hpp"
#include <privmx/endpoint/core/Exception.hpp>
#include <privmx/crypto/Crypto.hpp>
#include <Poco/Util/IniFileConfiguration.h>
#include <privmx/endpoint/core/EventQueueImpl.hpp>
#include <privmx/endpoint/core/VarSerializer.hpp>
#include <privmx/endpoint/core/Connection.hpp>
#include <privmx/endpoint/store/StoreApi.hpp>
#include <privmx/endpoint/store/VarSerializer.hpp>
#include <privmx/endpoint/store/StoreException.hpp>
#include <privmx/endpoint/core/CoreException.hpp>
#include <privmx/endpoint/core/UserVerifierInterface.hpp>

using namespace privmx::endpoint;

class FalseUserVerifierInterface: public virtual core::UserVerifierInterface {
public:
    std::vector<bool> verify(const std::vector<core::VerificationRequest>& request) override {
        return std::vector<bool>(request.size(), false);
    };
};

enum ConnectionType {
    User1,
    User2,
    Public
};

class StoreTest : public privmx::test::BaseTest {
protected:
    StoreTest() : BaseTest(privmx::test::BaseTestMode::online) {}
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
    }
    void disconnect() {
        connection->disconnect();
        connection.reset();
        storeApi.reset();
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
        storeApi = std::make_shared<store::StoreApi>(
            store::StoreApi::create(
                *connection
            )
        );
    }
    void customTearDown() override { // tmp segfault fix
        connection.reset();
        storeApi.reset();
        reader.reset();
        privmx::endpoint::core::EventQueueImpl::getInstance()->clear();
    }
    std::shared_ptr<core::Connection> connection;
    std::shared_ptr<store::StoreApi> storeApi;
    Poco::Util::IniFileConfiguration::Ptr reader;
    core::VarSerializer _serializer = core::VarSerializer({});
};

TEST_F(StoreTest, getStore) {
    store::Store store;
    // incorrect storeId
    EXPECT_THROW({
        storeApi->getStore(
            reader->getString("Context_1.contextId")
        );
    }, core::Exception);
    // correct storeId
    EXPECT_NO_THROW({
        store = storeApi->getStore(
            reader->getString("Store_1.storeId")
        );
    });
    EXPECT_EQ(store.contextId, reader->getString("Store_1.contextId"));
    EXPECT_EQ(store.storeId, reader->getString("Store_1.storeId"));
    EXPECT_EQ(store.createDate, reader->getInt64("Store_1.createDate"));
    EXPECT_EQ(store.creator, reader->getString("Store_1.creator"));
    EXPECT_EQ(store.lastModificationDate, reader->getInt64("Store_1.lastModificationDate"));
    EXPECT_EQ(store.lastFileDate, reader->getInt64("Store_1.lastFileDate"));
    EXPECT_EQ(store.lastModifier, reader->getString("Store_1.lastModifier"));
    EXPECT_EQ(store.version, reader->getInt64("Store_1.version"));
    EXPECT_EQ(store.filesCount, reader->getInt64("Store_1.filesCount"));
    EXPECT_EQ(store.statusCode, 0);
    EXPECT_EQ(store.publicMeta.stdString(), privmx::utils::Hex::toString(reader->getString("Store_1.publicMeta_inHex")));
    EXPECT_EQ(store.publicMeta.stdString(), privmx::utils::Hex::toString(reader->getString("Store_1.uploaded_publicMeta_inHex")));
    EXPECT_EQ(store.privateMeta.stdString(), privmx::utils::Hex::toString(reader->getString("Store_1.privateMeta_inHex")));
    EXPECT_EQ(store.privateMeta.stdString(), privmx::utils::Hex::toString(reader->getString("Store_1.uploaded_privateMeta_inHex")));

    EXPECT_EQ(store.version, 1);
    EXPECT_EQ(store.creator, reader->getString("Login.user_1_id"));
    EXPECT_EQ(store.lastModifier, reader->getString("Login.user_1_id"));
    EXPECT_EQ(store.users.size(), 1);
    if(store.users.size() == 1) {
        EXPECT_EQ(store.users[0], reader->getString("Login.user_1_id"));
    }
    EXPECT_EQ(store.managers.size(), 1);
    if(store.managers.size() == 1) {
        EXPECT_EQ(store.managers[0], reader->getString("Login.user_1_id"));
    }
}

TEST_F(StoreTest, listStores_incorrect_input_data) {
    // incorrect contextId
    EXPECT_THROW({
        storeApi->listStores(
            reader->getString("Store_1.storeId"),
            {
                .skip=0, 
                .limit=1, 
                .sortOrder="desc"
            }
        );
    }, core::Exception);
    // limit < 0
    EXPECT_THROW({
        storeApi->listStores(
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
        storeApi->listStores(
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
        storeApi->listStores(
            reader->getString("Context_1.contextId"),
            {
                .skip=0, 
                .limit=1, 
                .sortOrder="BLAH"
            }
        );
    }, core::Exception);
    // incorrect lastId
    EXPECT_THROW({
        storeApi->listStores(
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
        storeApi->listStores(
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
        storeApi->listStores(
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

TEST_F(StoreTest, listStores_correct_input_data) {
    core::PagingList<store::Store> listStores;
    // {.skip=4, .limit=1, .sortOrder="desc"}
    EXPECT_NO_THROW({
        listStores = storeApi->listStores(
            reader->getString("Context_1.contextId"),
            {
                .skip=4, 
                .limit=1, 
                .sortOrder="desc"
            }
        );
    });
    EXPECT_EQ(listStores.totalAvailable, 3);
    EXPECT_EQ(listStores.readItems.size(), 0);
    // {.skip=0, .limit=1, .sortOrder="desc"}
    EXPECT_NO_THROW({
        listStores = storeApi->listStores(
            reader->getString("Context_1.contextId"),
            {
                .skip=0, 
                .limit=1, 
                .sortOrder="desc"
            }
        );
    });
    EXPECT_EQ(listStores.totalAvailable, 3);
    EXPECT_EQ(listStores.readItems.size(), 1);
    if(listStores.readItems.size() >= 1) {
        auto store = listStores.readItems[0];
        EXPECT_EQ(store.contextId, reader->getString("Store_3.contextId"));
        EXPECT_EQ(store.storeId, reader->getString("Store_3.storeId"));
        EXPECT_EQ(store.createDate, reader->getInt64("Store_3.createDate"));
        EXPECT_EQ(store.creator, reader->getString("Store_3.creator"));
        EXPECT_EQ(store.lastModificationDate, reader->getInt64("Store_3.lastModificationDate"));
        EXPECT_EQ(store.lastFileDate, reader->getInt64("Store_3.lastFileDate"));
        EXPECT_EQ(store.lastModifier, reader->getString("Store_3.lastModifier"));
        EXPECT_EQ(store.version, reader->getInt64("Store_3.version"));
        EXPECT_EQ(store.filesCount, reader->getInt64("Store_3.filesCount"));
        EXPECT_EQ(store.statusCode, 0);
        EXPECT_EQ(store.publicMeta.stdString(), privmx::utils::Hex::toString(reader->getString("Store_3.publicMeta_inHex")));
        EXPECT_EQ(store.publicMeta.stdString(), privmx::utils::Hex::toString(reader->getString("Store_3.uploaded_publicMeta_inHex")));
        EXPECT_EQ(store.privateMeta.stdString(), privmx::utils::Hex::toString(reader->getString("Store_3.privateMeta_inHex")));
        EXPECT_EQ(store.privateMeta.stdString(), privmx::utils::Hex::toString(reader->getString("Store_3.uploaded_privateMeta_inHex")));
        EXPECT_EQ(store.version, 1);
        EXPECT_EQ(store.creator, reader->getString("Login.user_1_id"));
        EXPECT_EQ(store.lastModifier, reader->getString("Login.user_1_id"));
        EXPECT_EQ(store.users.size(), 2);
        if(store.users.size() == 2) {
            EXPECT_EQ(store.users[0], reader->getString("Login.user_1_id"));
            EXPECT_EQ(store.users[1], reader->getString("Login.user_2_id"));
        }
        EXPECT_EQ(store.managers.size(), 1);
        if(store.managers.size() == 1) {
            EXPECT_EQ(store.managers[0], reader->getString("Login.user_1_id"));
        }
    }
    // {.skip=1, .limit=3, .sortOrder="asc", .sortBy="createDate"}
    EXPECT_NO_THROW({
        listStores = storeApi->listStores(
            reader->getString("Context_1.contextId"),
            {
                .skip=1, 
                .limit=3, 
                .sortOrder="asc",
                .lastId=std::nullopt,
                .sortBy="createDate",
                .queryAsJson=std::nullopt
            }
        );
    });
    EXPECT_EQ(listStores.totalAvailable, 3);
    EXPECT_EQ(listStores.readItems.size(), 2);
    if(listStores.readItems.size() >= 1) {
        auto store = listStores.readItems[0];
        EXPECT_EQ(store.contextId, reader->getString("Store_2.contextId"));
        EXPECT_EQ(store.storeId, reader->getString("Store_2.storeId"));
        EXPECT_EQ(store.createDate, reader->getInt64("Store_2.createDate"));
        EXPECT_EQ(store.creator, reader->getString("Store_2.creator"));
        EXPECT_EQ(store.lastModificationDate, reader->getInt64("Store_2.lastModificationDate"));
        EXPECT_EQ(store.lastFileDate, reader->getInt64("Store_2.lastFileDate"));
        EXPECT_EQ(store.lastModifier, reader->getString("Store_2.lastModifier"));
        EXPECT_EQ(store.version, reader->getInt64("Store_2.version"));
        EXPECT_EQ(store.filesCount, reader->getInt64("Store_2.filesCount"));
        EXPECT_EQ(store.statusCode, 0);
        EXPECT_EQ(store.publicMeta.stdString(), privmx::utils::Hex::toString(reader->getString("Store_2.publicMeta_inHex")));
        EXPECT_EQ(store.publicMeta.stdString(), privmx::utils::Hex::toString(reader->getString("Store_2.uploaded_publicMeta_inHex")));
        EXPECT_EQ(store.privateMeta.stdString(), privmx::utils::Hex::toString(reader->getString("Store_2.privateMeta_inHex")));
        EXPECT_EQ(store.privateMeta.stdString(), privmx::utils::Hex::toString(reader->getString("Store_2.uploaded_privateMeta_inHex")));
        EXPECT_EQ(store.version, 1);
        EXPECT_EQ(store.creator, reader->getString("Login.user_1_id"));
        EXPECT_EQ(store.lastModifier, reader->getString("Login.user_1_id"));
        EXPECT_EQ(store.users.size(), 2);
        if(store.users.size() == 2) {
            EXPECT_EQ(store.users[0], reader->getString("Login.user_1_id"));
            EXPECT_EQ(store.users[1], reader->getString("Login.user_2_id"));
        }
        EXPECT_EQ(store.managers.size(), 2);
        if(store.managers.size() == 2) {
            EXPECT_EQ(store.managers[0], reader->getString("Login.user_1_id"));
            EXPECT_EQ(store.managers[1], reader->getString("Login.user_2_id"));
        }
    }
    if(listStores.readItems.size() >= 2) {
        auto store = listStores.readItems[1];
        EXPECT_EQ(store.contextId, reader->getString("Store_3.contextId"));
        EXPECT_EQ(store.storeId, reader->getString("Store_3.storeId"));
        EXPECT_EQ(store.createDate, reader->getInt64("Store_3.createDate"));
        EXPECT_EQ(store.creator, reader->getString("Store_3.creator"));
        EXPECT_EQ(store.lastModificationDate, reader->getInt64("Store_3.lastModificationDate"));
        EXPECT_EQ(store.lastFileDate, reader->getInt64("Store_3.lastFileDate"));
        EXPECT_EQ(store.lastModifier, reader->getString("Store_3.lastModifier"));
        EXPECT_EQ(store.version, reader->getInt64("Store_3.version"));
        EXPECT_EQ(store.filesCount, reader->getInt64("Store_3.filesCount"));
        EXPECT_EQ(store.statusCode, 0);
        EXPECT_EQ(store.publicMeta.stdString(), privmx::utils::Hex::toString(reader->getString("Store_3.publicMeta_inHex")));
        EXPECT_EQ(store.publicMeta.stdString(), privmx::utils::Hex::toString(reader->getString("Store_3.uploaded_publicMeta_inHex")));
        EXPECT_EQ(store.privateMeta.stdString(), privmx::utils::Hex::toString(reader->getString("Store_3.privateMeta_inHex")));
        EXPECT_EQ(store.privateMeta.stdString(), privmx::utils::Hex::toString(reader->getString("Store_3.uploaded_privateMeta_inHex")));
        EXPECT_EQ(store.version, 1);
        EXPECT_EQ(store.creator, reader->getString("Login.user_1_id"));
        EXPECT_EQ(store.lastModifier, reader->getString("Login.user_1_id"));
        EXPECT_EQ(store.users.size(), 2);
        if(store.users.size() == 2) {
            EXPECT_EQ(store.users[0], reader->getString("Login.user_1_id"));
            EXPECT_EQ(store.users[1], reader->getString("Login.user_2_id"));
        }
        EXPECT_EQ(store.managers.size(), 1);
        if(store.managers.size() == 1) {
            EXPECT_EQ(store.managers[0], reader->getString("Login.user_1_id"));
        }
    }
}

TEST_F(StoreTest, createStore) {
    std::string storeId;
    store::Store store;
    // incorrect contextId
    EXPECT_THROW({
        storeApi->createStore(
            reader->getString("Store_1.storeId"),
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
        storeApi->createStore(
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
        storeApi->createStore(
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
        storeApi->createStore(
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
    storeId = std::string();
    EXPECT_NO_THROW({
        storeId = storeApi->createStore(
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
    if(storeId.empty()) { 
        FAIL();
    }
    EXPECT_NO_THROW({
        store = storeApi->getStore(
            storeId
        );
    });
    EXPECT_EQ(store.statusCode, 0);
    EXPECT_EQ(store.contextId, reader->getString("Context_1.contextId"));
    EXPECT_EQ(store.publicMeta.stdString(), "public");
    EXPECT_EQ(store.privateMeta.stdString(), "private");
    EXPECT_EQ(store.users.size(), 1);
    if(store.users.size() == 1) {
        EXPECT_EQ(store.users[0], reader->getString("Login.user_2_id"));
    }
    EXPECT_EQ(store.managers.size(), 1);
    if(store.managers.size() == 1) {
        EXPECT_EQ(store.managers[0], reader->getString("Login.user_1_id"));
    }
    // same users and managers
    storeId = std::string();
    EXPECT_NO_THROW({
        storeId = storeApi->createStore(
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
    if(storeId.empty()) { 
        FAIL();
    }
    EXPECT_NO_THROW({
        store = storeApi->getStore(
            storeId
        );
    });
    EXPECT_EQ(store.statusCode, 0);
    EXPECT_EQ(store.contextId, reader->getString("Context_1.contextId"));
    EXPECT_EQ(store.publicMeta.stdString(), "public");
    EXPECT_EQ(store.privateMeta.stdString(), "private");
    EXPECT_EQ(store.users.size(), 1);
    if(store.users.size() == 1) {
        EXPECT_EQ(store.users[0], reader->getString("Login.user_1_id"));
    }
    EXPECT_EQ(store.managers.size(), 1);
    if(store.managers.size() == 1) {
        EXPECT_EQ(store.managers[0], reader->getString("Login.user_1_id"));
    }
}

TEST_F(StoreTest, updateStore_incorrect_data) {
    // incorrect storeId
    EXPECT_THROW({
        storeApi->updateStore(
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
        storeApi->updateStore(
            reader->getString("Store_1.storeId"),
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
            1,
            false,
            false
        );
    }, core::Exception);
    // incorrect managers
    EXPECT_THROW({
        storeApi->updateStore(
            reader->getString("Store_1.storeId"),
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
        storeApi->updateStore(
            reader->getString("Store_1.storeId"),
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
        storeApi->updateStore(
            reader->getString("Store_1.storeId"),
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
            2,
            false,
            false
        );
    }, core::Exception);

}

TEST_F(StoreTest, updateStore_correct_data) {
    store::Store store;
    // new users
    EXPECT_NO_THROW({
        storeApi->updateStore(
            reader->getString("Store_1.storeId"),
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
        store = storeApi->getStore(
            reader->getString("Store_1.storeId")
        );
    });
    EXPECT_EQ(store.statusCode, 0);
    EXPECT_EQ(store.storeId, reader->getString("Store_1.storeId"));
    EXPECT_EQ(store.contextId, reader->getString("Context_1.contextId"));
    EXPECT_EQ(store.version, 2);
    EXPECT_EQ(store.publicMeta.stdString(), "public");
    EXPECT_EQ(store.privateMeta.stdString(), "private");
    EXPECT_EQ(store.users.size(), 2);
    if(store.users.size() == 2) {
        EXPECT_EQ(store.users[0], reader->getString("Login.user_1_id"));
        EXPECT_EQ(store.users[1], reader->getString("Login.user_2_id"));
    }
    EXPECT_EQ(store.managers.size(), 1);
    if(store.managers.size() == 1) {
        EXPECT_EQ(store.managers[0], reader->getString("Login.user_1_id"));
    }
    // new managers
    EXPECT_NO_THROW({
        storeApi->updateStore(
            reader->getString("Store_1.storeId"),
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
            2,
            false,
            false
        );
    });
    EXPECT_NO_THROW({
        store = storeApi->getStore(
            reader->getString("Store_1.storeId")
        );
    });
    EXPECT_EQ(store.statusCode, 0);
    EXPECT_EQ(store.storeId, reader->getString("Store_1.storeId"));
    EXPECT_EQ(store.contextId, reader->getString("Context_1.contextId"));
    EXPECT_EQ(store.version, 3);
    EXPECT_EQ(store.publicMeta.stdString(), "public");
    EXPECT_EQ(store.privateMeta.stdString(), "private");
    EXPECT_EQ(store.users.size(), 2);
    if(store.users.size() == 2) {
        EXPECT_EQ(store.users[0], reader->getString("Login.user_1_id"));
        EXPECT_EQ(store.users[1], reader->getString("Login.user_2_id"));
    }
    EXPECT_EQ(store.managers.size(), 2);
    if(store.managers.size() == 2) {
        EXPECT_EQ(store.managers[0], reader->getString("Login.user_1_id"));
        EXPECT_EQ(store.managers[1], reader->getString("Login.user_2_id"));
    }
    // less users
    EXPECT_NO_THROW({
        storeApi->updateStore(
            reader->getString("Store_2.storeId"),
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
        store = storeApi->getStore(
            reader->getString("Store_2.storeId")
        );
    });
    EXPECT_EQ(store.statusCode, 0);
    EXPECT_EQ(store.storeId, reader->getString("Store_2.storeId"));
    EXPECT_EQ(store.contextId, reader->getString("Context_1.contextId"));
    EXPECT_EQ(store.version, 2);
    EXPECT_EQ(store.publicMeta.stdString(), "public");
    EXPECT_EQ(store.privateMeta.stdString(), "private");
    EXPECT_EQ(store.users.size(), 1);
    if(store.users.size() == 1) {
        EXPECT_EQ(store.users[0], reader->getString("Login.user_1_id"));
    }
    EXPECT_EQ(store.managers.size(), 2);
    if(store.managers.size() == 2) {
        EXPECT_EQ(store.managers[0], reader->getString("Login.user_1_id"));
        EXPECT_EQ(store.managers[1], reader->getString("Login.user_2_id"));
    }
    // less managers
    EXPECT_NO_THROW({
        storeApi->updateStore(
            reader->getString("Store_2.storeId"),
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
        store = storeApi->getStore(
            reader->getString("Store_2.storeId")
        );
    });
    EXPECT_EQ(store.statusCode, 0);
    EXPECT_EQ(store.storeId, reader->getString("Store_2.storeId"));
    EXPECT_EQ(store.contextId, reader->getString("Context_1.contextId"));
    EXPECT_EQ(store.version, 3);
    EXPECT_EQ(store.publicMeta.stdString(), "public");
    EXPECT_EQ(store.privateMeta.stdString(), "private");
    EXPECT_EQ(store.users.size(), 1);
    if(store.users.size() == 1) {
        EXPECT_EQ(store.users[0], reader->getString("Login.user_1_id"));
    }
    EXPECT_EQ(store.managers.size(), 1);
    if(store.managers.size() == 1) {
        EXPECT_EQ(store.managers[0], reader->getString("Login.user_1_id"));
    }
    // incorrect version force true
    EXPECT_NO_THROW({
        storeApi->updateStore(
            reader->getString("Store_3.storeId"),
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
            99,
            true,
            false
        );
    });
    EXPECT_NO_THROW({
        store = storeApi->getStore(
            reader->getString("Store_3.storeId")
        );
    });
    EXPECT_EQ(store.statusCode, 0);
    EXPECT_EQ(store.storeId, reader->getString("Store_3.storeId"));
    EXPECT_EQ(store.contextId, reader->getString("Context_1.contextId"));
    EXPECT_EQ(store.version, 2);
    EXPECT_EQ(store.publicMeta.stdString(), "public");
    EXPECT_EQ(store.privateMeta.stdString(), "private");
    EXPECT_EQ(store.users.size(), 1);
    if(store.users.size() == 1) {
        EXPECT_EQ(store.users[0], reader->getString("Login.user_1_id"));
    }
    EXPECT_EQ(store.managers.size(), 1);
    if(store.managers.size() == 1) {
        EXPECT_EQ(store.managers[0], reader->getString("Login.user_1_id"));
    }
}

TEST_F(StoreTest, deleteStore) {
   // incorrect store_id
    EXPECT_THROW({
        storeApi->deleteStore(
            reader->getString("Context_1.contextId")
        );
    }, core::Exception);
    // as manager
    EXPECT_NO_THROW({
        storeApi->deleteStore(
            reader->getString("Store_1.storeId")
        );
    });
    EXPECT_THROW({
        storeApi->getStore(
            reader->getString("Store_1.storeId")
        );
    }, core::Exception);
    // as user
    disconnect();
    connectAs(ConnectionType::User2);
    EXPECT_THROW({
        storeApi->deleteStore(
            reader->getString("Store_3.storeId")
        );
    }, core::Exception);
}

TEST_F(StoreTest, getFile) {
    privmx::endpoint::store::File file;
    // incorrect fileId
    EXPECT_THROW({
        storeApi->getFile(
            reader->getString("Context_1.contextId")
        );
    }, core::Exception);
    // after force key generation on store
    EXPECT_NO_THROW({
        storeApi->updateStore(
            reader->getString("Store_1.storeId"),
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
        file = storeApi->getFile(
            reader->getString("File_1.info_fileId")
        );
    });
    EXPECT_EQ(file.info.storeId, reader->getString("File_1.info_storeId"));
    EXPECT_EQ(file.info.fileId, reader->getString("File_1.info_fileId"));
    EXPECT_EQ(file.info.createDate, reader->getInt64("File_1.info_createDate"));
    EXPECT_EQ(file.info.author, reader->getString("File_1.info_author"));
    EXPECT_EQ(file.publicMeta.stdString(), privmx::utils::Hex::toString(reader->getString("File_1.publicMeta_inHex")));
    EXPECT_EQ(file.privateMeta.stdString(), privmx::utils::Hex::toString(reader->getString("File_1.privateMeta_inHex")));
    EXPECT_EQ(file.size, reader->getInt64("File_1.size"));
    EXPECT_EQ(file.authorPubKey, reader->getString("File_1.authorPubKey"));
    EXPECT_EQ(file.statusCode, 0);
    EXPECT_EQ(
        privmx::utils::Utils::stringifyVar(_serializer.serialize(file)),
        reader->getString("File_1.JSON_data")
    );
    EXPECT_EQ(file.publicMeta.stdString(), privmx::utils::Hex::toString(reader->getString("File_1.uploaded_publicMeta_inHex")));
    EXPECT_EQ(file.privateMeta.stdString(), privmx::utils::Hex::toString(reader->getString("File_1.uploaded_privateMeta_inHex")));
    EXPECT_EQ(file.size, reader->getInt64("File_1.uploaded_size"));
}

TEST_F(StoreTest, listFiles_incorrect_input_data) {
    // incorrect storeId
    EXPECT_THROW({
        storeApi->listFiles(
            reader->getString("File_1.info_fileId"),
            {
                .skip=0, 
                .limit=1, 
                .sortOrder="desc"
            }
        );
    }, core::Exception);
    // limit < 0
    EXPECT_THROW({
        storeApi->listFiles(
            reader->getString("Store_1.storeId"),
            {
                .skip=0, 
                .limit=-1, 
                .sortOrder="desc"
            }
        );
    }, core::Exception);
    // limit == 0
    EXPECT_THROW({
        storeApi->listFiles(
            reader->getString("Store_1.storeId"),
            {
                .skip=0, 
                .limit=0, 
                .sortOrder="desc"
            }
        );
    }, core::Exception);
    // incorrect sortOrder
    EXPECT_THROW({
        storeApi->listFiles(
            reader->getString("Store_1.storeId"),
            {
                .skip=0, 
                .limit=1, 
                .sortOrder="BLAH"
            }
        );
    }, core::Exception);
    // incorrect lastId
    EXPECT_THROW({
        storeApi->listFiles(
            reader->getString("Store_1.storeId"),
            {
                .skip=0, 
                .limit=1, 
                .sortOrder="desc",
                .lastId=reader->getString("Store_1.storeId")
            }
        );
    }, core::Exception);
    // incorrect queryAsJson
    EXPECT_THROW({
        storeApi->listFiles(
            reader->getString("Store_1.storeId"),
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
        storeApi->listFiles(
            reader->getString("Store_1.storeId"),
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

TEST_F(StoreTest, listFiles_correct_input_data) {
    core::PagingList<store::File> listFiles;
    // {.skip=4, .limit=1, .sortOrder="desc"}
    EXPECT_NO_THROW({
        listFiles = storeApi->listFiles(
            reader->getString("Store_1.storeId"),
            {
                .skip=4, 
                .limit=1, 
                .sortOrder="desc"
            }
        );
    });
    EXPECT_EQ(listFiles.totalAvailable, 2);
    EXPECT_EQ(listFiles.readItems.size(), 0);
    // {.skip=1, .limit=1, .sortOrder="desc"}
    EXPECT_NO_THROW({
        listFiles = storeApi->listFiles(
            reader->getString("Store_1.storeId"),
            {
                .skip=1, 
                .limit=1, 
                .sortOrder="desc"
            }
        );
    });
    EXPECT_EQ(listFiles.totalAvailable, 2);
    EXPECT_EQ(listFiles.readItems.size(), 1);
    if(listFiles.readItems.size() >= 1) {
        auto file = listFiles.readItems[0];
        EXPECT_EQ(file.info.storeId, reader->getString("File_1.info_storeId"));
        EXPECT_EQ(file.info.fileId, reader->getString("File_1.info_fileId"));
        EXPECT_EQ(file.info.createDate, reader->getInt64("File_1.info_createDate"));
        EXPECT_EQ(file.info.author, reader->getString("File_1.info_author"));
        EXPECT_EQ(file.publicMeta.stdString(), privmx::utils::Hex::toString(reader->getString("File_1.publicMeta_inHex")));
        EXPECT_EQ(file.privateMeta.stdString(), privmx::utils::Hex::toString(reader->getString("File_1.privateMeta_inHex")));
        EXPECT_EQ(file.size, reader->getInt64("File_1.size"));
        EXPECT_EQ(file.authorPubKey, reader->getString("File_1.authorPubKey"));
        EXPECT_EQ(file.statusCode, 0);
        EXPECT_EQ(
            privmx::utils::Utils::stringifyVar(_serializer.serialize(file)),
            reader->getString("File_1.JSON_data")
        );
        EXPECT_EQ(file.publicMeta.stdString(), privmx::utils::Hex::toString(reader->getString("File_1.uploaded_publicMeta_inHex")));
    }
    // {.skip=0, .limit=3, .sortOrder="asc", .sortBy="createDate"}, after force key generation on store
    EXPECT_NO_THROW({
        storeApi->updateStore(
            reader->getString("Store_1.storeId"),
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
            true,
            true
        );
    });
    EXPECT_NO_THROW({
        listFiles = storeApi->listFiles(
            reader->getString("Store_1.storeId"),
            {
                .skip=0, 
                .limit=3, 
                .sortOrder="asc",
                .lastId=std::nullopt,
                .sortBy="createDate",
                .queryAsJson=std::nullopt
            }
        );
    });
    EXPECT_EQ(listFiles.totalAvailable, 2);
    EXPECT_EQ(listFiles.readItems.size(), 2);
    if(listFiles.readItems.size() >= 1) {
        auto file = listFiles.readItems[0];
        EXPECT_EQ(file.info.storeId, reader->getString("File_1.info_storeId"));
        EXPECT_EQ(file.info.fileId, reader->getString("File_1.info_fileId"));
        EXPECT_EQ(file.info.createDate, reader->getInt64("File_1.info_createDate"));
        EXPECT_EQ(file.info.author, reader->getString("File_1.info_author"));
        EXPECT_EQ(file.publicMeta.stdString(), privmx::utils::Hex::toString(reader->getString("File_1.publicMeta_inHex")));
        EXPECT_EQ(file.privateMeta.stdString(), privmx::utils::Hex::toString(reader->getString("File_1.privateMeta_inHex")));
        EXPECT_EQ(file.size, reader->getInt64("File_1.size"));
        EXPECT_EQ(file.authorPubKey, reader->getString("File_1.authorPubKey"));
        EXPECT_EQ(file.statusCode, 0);
        EXPECT_EQ(
            privmx::utils::Utils::stringifyVar(_serializer.serialize(file)),
            reader->getString("File_1.JSON_data")
        );
        EXPECT_EQ(file.publicMeta.stdString(), privmx::utils::Hex::toString(reader->getString("File_1.uploaded_publicMeta_inHex")));
        EXPECT_EQ(file.privateMeta.stdString(), privmx::utils::Hex::toString(reader->getString("File_1.uploaded_privateMeta_inHex")));
        EXPECT_EQ(file.size, reader->getInt64("File_1.uploaded_size"));
    }
    if(listFiles.readItems.size() >= 2) {
        auto file = listFiles.readItems[1];
        EXPECT_EQ(file.info.storeId, reader->getString("File_2.info_storeId"));
        EXPECT_EQ(file.info.fileId, reader->getString("File_2.info_fileId"));
        EXPECT_EQ(file.info.createDate, reader->getInt64("File_2.info_createDate"));
        EXPECT_EQ(file.info.author, reader->getString("File_2.info_author"));
        EXPECT_EQ(file.publicMeta.stdString(), privmx::utils::Hex::toString(reader->getString("File_2.publicMeta_inHex")));
        EXPECT_EQ(file.privateMeta.stdString(), privmx::utils::Hex::toString(reader->getString("File_2.privateMeta_inHex")));
        EXPECT_EQ(file.size, reader->getInt64("File_2.size"));
        EXPECT_EQ(file.authorPubKey, reader->getString("File_2.authorPubKey"));
        EXPECT_EQ(file.statusCode, 0);
        EXPECT_EQ(
            privmx::utils::Utils::stringifyVar(_serializer.serialize(file)),
            reader->getString("File_2.JSON_data")
        );
        EXPECT_EQ(file.publicMeta.stdString(), privmx::utils::Hex::toString(reader->getString("File_2.uploaded_publicMeta_inHex")));
        EXPECT_EQ(file.privateMeta.stdString(), privmx::utils::Hex::toString(reader->getString("File_2.uploaded_privateMeta_inHex")));
        EXPECT_EQ(file.size, reader->getInt64("File_2.uploaded_size"));
    }
}

TEST_F(StoreTest, deleteFile) {
    // incorrect fileId
    EXPECT_THROW({
        storeApi->deleteFile(
            reader->getString("Store_1.storeId")
        );
    }, core::Exception);
    // change privileges
    EXPECT_NO_THROW({
        storeApi->updateStore(
            reader->getString("Store_1.storeId"),
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
        storeApi->deleteFile(
            reader->getString("File_2.info_fileId")
        );
    }, core::Exception);
    // change privileges
    disconnect();
    connectAs(ConnectionType::User1);
    EXPECT_NO_THROW({
        storeApi->updateStore(
            reader->getString("Store_1.storeId"),
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
            false
        );
    });
    disconnect();
    connectAs(ConnectionType::User2);
    EXPECT_NO_THROW({
        storeApi->updateStore(
            reader->getString("Store_1.storeId"),
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
        storeApi->deleteFile(
            reader->getString("File_2.info_fileId")
        );
    });
    disconnect();
    connectAs(ConnectionType::User2);
    // as manager no created by me
    EXPECT_NO_THROW({
        storeApi->deleteFile(
            reader->getString("File_1.info_fileId")
        );
    });
}

TEST_F(StoreTest, openFile_readFromFile_seekInFile_incorrect_data) {
    // openFile incorrect fileId
    EXPECT_THROW({
        storeApi->openFile(
            reader->getString("Store_1.storeId")
        );
    }, core::Exception);
    // readFromFile incorrect handle (no exist)
    EXPECT_THROW({
        storeApi->readFromFile(
            1, 2
        );
    }, core::Exception);
    // seekInFile incorrect handle (no exist)
    EXPECT_THROW({
        storeApi->seekInFile(
            1, 2
        );
    }, core::Exception);
    // create write handle
    int64_t handle = 0;
    EXPECT_NO_THROW({
        handle = storeApi->createFile(
            reader->getString("Store_1.storeId"),
            privmx::endpoint::core::Buffer::from("publicMeta"),
            privmx::endpoint::core::Buffer::from("privateMeta"),
            64
        );
    });
    if(handle == 1) {
        // readFromFile incorrect handle (write handle)
        EXPECT_THROW({
            storeApi->readFromFile(
                handle, 2
            );
        }, core::Exception);
        // seekInFile incorrect handle (write handle)
        EXPECT_THROW({
            storeApi->seekInFile(
                handle, 2
            );
        }, core::Exception);
    } else {
        std::cout << "create write handle using 'createFile' failed" << std::endl;
        FAIL();
    }
}

TEST_F(StoreTest, openFile_readFromFile_seekInFile_closeFile) {

    int64_t handle = 0;
    std::string data;
    // createFile correct file
    EXPECT_NO_THROW({
        handle = storeApi->openFile(
            reader->getString("File_1.info_fileId")
        );
    });
    // seekInFile pos < 0
    EXPECT_THROW({
        storeApi->seekInFile(
            handle,
            -1
        );
    }, core::Exception);
    // seekInFile pos > file.size
    EXPECT_THROW({
        storeApi->seekInFile(
            handle,
            reader->getInt64("File_1.size")+1
        );
    }, core::Exception);
    // seekInFile pos == 50% file.size
    EXPECT_NO_THROW({
        storeApi->seekInFile(
            handle,
            reader->getInt64("File_1.size")/2
        );
    });
    // readFromFile length == file.size
    EXPECT_NO_THROW({
        data = storeApi->readFromFile(
            handle,
            reader->getInt64("File_1.size")
        ).stdString();
    });
    // seekInFile pos == 0
    EXPECT_NO_THROW({
        storeApi->seekInFile(
            handle,
            0
        );
    });
    // readFromFile length == 50% file.size
    EXPECT_NO_THROW({
        data = storeApi->readFromFile(
            handle,
            reader->getInt64("File_1.size")/2
        ).stdString() + data;
    });
    // closeFile
    EXPECT_NO_THROW({
        storeApi->closeFile(
            handle
        );
    });
    // validate read data
    EXPECT_EQ(data, privmx::utils::Hex::toString(reader->getString("File_1.uploaded_data_inHex")));
}

TEST_F(StoreTest, createFile_updateFile_writeToFile_closeFile_incorrect_data) {
    // createFile incorrect storeId
    EXPECT_THROW({
        storeApi->createFile(
            reader->getString("Context_1.contextId"),
            privmx::endpoint::core::Buffer::from("publicMeta"),
            privmx::endpoint::core::Buffer::from("privateMeta"),
            64
        );
    }, core::Exception);
    // createFile size < 0
    EXPECT_THROW({
        storeApi->createFile(
            reader->getString("Store_1.storeId"),
            privmx::endpoint::core::Buffer::from("publicMeta"),
            privmx::endpoint::core::Buffer::from("privateMeta"),
            -1
        );
    }, core::Exception);
    // updateFile incorrect fileId
    EXPECT_THROW({
        storeApi->updateFile(
            reader->getString("Store_1.storeId"),
            privmx::endpoint::core::Buffer::from("publicMeta"),
            privmx::endpoint::core::Buffer::from("privateMeta"),
            64
        );
    }, core::Exception);
    // updateFile size < 0
    EXPECT_THROW({
        storeApi->updateFile(
            reader->getString("File_1.info_fileId"),
            privmx::endpoint::core::Buffer::from("publicMeta"),
            privmx::endpoint::core::Buffer::from("privateMeta"),
            -1
        );
    }, core::Exception);
    // writeToFile incorrect handle (no exist)
    EXPECT_THROW({
        storeApi->writeToFile(
            0,
            core::Buffer::from("BLACH")
        );
    }, core::Exception);

    // create read handle
    int64_t handle = 0;
    EXPECT_NO_THROW({
        handle = storeApi->openFile(
            reader->getString("File_1.info_fileId")
        );
    });
    // writeToFile incorrect handle (read handle)
    EXPECT_THROW({
        storeApi->writeToFile(
            handle,
            core::Buffer::from("BLAH")
        );
    }, core::Exception);
    // closeFile incorrect handle
    EXPECT_THROW({
        storeApi->closeFile(
            0
        );
    }, core::Exception);
}

TEST_F(StoreTest, createFile_writeToFile_closeFile) {
    // createFile with size = 128*1024*1024
    int64_t handle;
    EXPECT_NO_THROW({
        handle = storeApi->createFile(
            reader->getString("Store_1.storeId"),
            privmx::endpoint::core::Buffer::from("publicMeta"),
            privmx::endpoint::core::Buffer::from("privateMeta"),
            128*1024*1024
        );
    });
    EXPECT_EQ(handle, 1);
    if(handle == 1) {
        std::string fileId;
        std::string total_data_send = "";
        // writeToFile total.size < declared size
        EXPECT_NO_THROW({
            for(int i = 0; i < 1024*64; i++) {
                std::string random_data = privmx::crypto::Crypto::randomBytes(1024);
                storeApi->writeToFile(
                    handle,
                    core::Buffer::from(random_data)
                );
                total_data_send += random_data;
            }
        });
        // writeToFile total.size == declared
        EXPECT_NO_THROW({
            for(int i = 0; i < 64; i++) {
                std::string random_data = "";
                for(int j = 0; j < 1024; j++) {
                    random_data += privmx::crypto::Crypto::randomBytes(1024);
                }
                storeApi->writeToFile(
                    handle,
                    core::Buffer::from(random_data)
                );
                total_data_send += random_data;
            }
        });
        // writeToFile total.size > declared
        EXPECT_THROW({
            std::string random_data = privmx::crypto::Crypto::randomBytes(1);
            storeApi->writeToFile(
                handle,
                core::Buffer::from(random_data)
            );
        }, core::Exception);
        // closeFile size == declared size
        EXPECT_NO_THROW({
            fileId = storeApi->closeFile(handle);
        });
        // closeFile again
        EXPECT_THROW({
            storeApi->closeFile(handle);
        }, core::Exception);
        // validate uploaded data
        if(!fileId.empty()) {
            store::File file;
            EXPECT_NO_THROW({
                file = storeApi->getFile(fileId);
            });

            EXPECT_EQ(file.statusCode, 0);
            EXPECT_EQ(file.info.fileId, fileId);
            EXPECT_EQ(file.publicMeta.stdString(), "publicMeta");
            EXPECT_EQ(file.privateMeta.stdString(), "privateMeta");
            EXPECT_EQ(file.size, 1024*1024*128);
            int64_t readHandle = 0;
            EXPECT_NO_THROW({
                readHandle = storeApi->openFile(fileId);
            });
            if(readHandle != 0) {
                std::string total_data_read = "";
                for(int i = 0; i < 1024*128; i++) {
                    total_data_read += storeApi->readFromFile(
                        readHandle,
                        1024
                    ).stdString();
                }
                EXPECT_EQ(total_data_send.size(), total_data_read.size());
                if(total_data_send != total_data_read) {
                    std::cout << "data read and data send is different" << std::endl;
                    FAIL();
                }
            }
        } else {
            std::cout << "closeFile Failed" << std::endl;
            FAIL();
        }

    } else {
        std::cout << "createFile Failed" << std::endl;
        FAIL();
    }
}

TEST_F(StoreTest, updateFile_writeToFile_closeFile) {
    // updateFile with size = 128*1024*1024
    int64_t handle;
    EXPECT_NO_THROW({
        handle = storeApi->updateFile(
            reader->getString("File_1.info_fileId"),
            privmx::endpoint::core::Buffer::from("publicMeta"),
            privmx::endpoint::core::Buffer::from("privateMeta"),
            128*1024*1024
        );
    });
    EXPECT_EQ(handle, 1);
    if(handle == 1) {
        std::string fileId;
        std::string total_data_send = "";
        // writeToFile total.size < declared size
        EXPECT_NO_THROW({
            for(int i = 0; i < 1024*64; i++) {
                std::string random_data = privmx::crypto::Crypto::randomBytes(1024);
                storeApi->writeToFile(
                    handle,
                    core::Buffer::from(random_data)
                );
                total_data_send += random_data;
            }
        });
        // writeToFile total.size == declared
        EXPECT_NO_THROW({
            for(int i = 0; i < 64; i++) {
                std::string random_data = "";
                for(int j = 0; j < 1024; j++) {
                    random_data += privmx::crypto::Crypto::randomBytes(1024);
                }
                storeApi->writeToFile(
                    handle,
                    core::Buffer::from(random_data)
                );
                total_data_send += random_data;
            }
        });
        // writeToFile total.size > declared
        EXPECT_THROW({
            std::string random_data = privmx::crypto::Crypto::randomBytes(1024);
            storeApi->writeToFile(
                handle,
                core::Buffer::from(random_data)
            );
        }, core::Exception);
        // closeFile size == declared size
        EXPECT_NO_THROW({
            fileId = storeApi->closeFile(handle);
        });
        // closeFile again
        EXPECT_THROW({
            storeApi->closeFile(handle);
        }, core::Exception);
        // validate uploaded data
        if(!fileId.empty()) {
            store::File file;
            EXPECT_NO_THROW({
                file = storeApi->getFile(fileId);
            });
            
            EXPECT_EQ(file.statusCode, 0);
            EXPECT_EQ(file.info.fileId, fileId);
            EXPECT_EQ(file.publicMeta.stdString(), "publicMeta");
            EXPECT_EQ(file.privateMeta.stdString(), "privateMeta");
            EXPECT_EQ(file.size, 1024*1024*128);
            int64_t readHandle = 0;
            EXPECT_NO_THROW({
                readHandle = storeApi->openFile(fileId);
            });
            if(readHandle != 0) {
                std::string total_data_read = "";
                for(int i = 0; i < 1024*128; i++) {
                    total_data_read += storeApi->readFromFile(
                        readHandle,
                        1024
                    ).stdString();
                }
                EXPECT_EQ(total_data_send.size(), total_data_read.size());
                if(total_data_send != total_data_read) {
                    std::cout << "data read and data send is different" << std::endl;
                    FAIL();
                }
            }
        } else {
            std::cout << "closeFile Failed" << std::endl;
            FAIL();
        }

    } else {
        std::cout << "createFile Failed" << std::endl;
        FAIL();
    }
}

TEST_F(StoreTest, createFile_with_size_0) {
    // createFile with size = 0
    int64_t handle;
    EXPECT_NO_THROW({
        handle = storeApi->createFile(
            reader->getString("Store_1.storeId"),
            privmx::endpoint::core::Buffer::from("publicMeta"),
            privmx::endpoint::core::Buffer::from("privateMeta"),
            0
        );
    });
    EXPECT_EQ(handle, 1);
    if(handle == 1) {
        std::string fileId;
        // closeFile
        EXPECT_NO_THROW({
            fileId = storeApi->closeFile(handle);
        });
        // validate uploaded data
        if(!fileId.empty()) {
            store::File file;
            EXPECT_NO_THROW({
                file = storeApi->getFile(fileId);
            });
            EXPECT_EQ(file.statusCode, 0);
            EXPECT_EQ(file.info.fileId, fileId);
            EXPECT_EQ(file.publicMeta.stdString(), "publicMeta");
            EXPECT_EQ(file.privateMeta.stdString(), "privateMeta");
            EXPECT_EQ(file.size, 0);
        } else {
            std::cout << "closeFile Failed" << std::endl;
            FAIL();
        }

    } else {
        std::cout << "createFile Failed" << std::endl;
        FAIL();
    }
}

TEST_F(StoreTest, updateFile_with_size_0) {
    // updateFile with size = 0
    int64_t handle;
    EXPECT_NO_THROW({
        handle = storeApi->updateFile(
            reader->getString("File_1.info_fileId"),
            privmx::endpoint::core::Buffer::from("publicMeta"),
            privmx::endpoint::core::Buffer::from("privateMeta"),
            0
        );
    });
    EXPECT_EQ(handle, 1);
    if(handle == 1) {
        std::string fileId;
        // closeFile size
        EXPECT_NO_THROW({
            fileId = storeApi->closeFile(handle);
        });
        // validate uploaded data
        if(!fileId.empty()) {
            store::File file;
            EXPECT_NO_THROW({
                file = storeApi->getFile(fileId);
            });
            EXPECT_EQ(file.statusCode, 0);
            EXPECT_EQ(file.info.fileId, fileId);
            EXPECT_EQ(file.publicMeta.stdString(), "publicMeta");
            EXPECT_EQ(file.privateMeta.stdString(), "privateMeta");
            EXPECT_EQ(file.size, 0);
        } else {
            std::cout << "closeFile Failed" << std::endl;
            FAIL();
        }

    } else {
        std::cout << "createFile Failed" << std::endl;
        FAIL();
    }
}

TEST_F(StoreTest, updateFileMeta) {
    // incorrect fileId
    EXPECT_THROW({
        storeApi->updateFileMeta(
            reader->getString("Store_1.storeId"),
            privmx::endpoint::core::Buffer::from("publicMeta"),
            privmx::endpoint::core::Buffer::from("privateMeta")
        );
    }, core::Exception);
    // correct data
    EXPECT_NO_THROW({
        storeApi->updateFileMeta(
            reader->getString("File_1.info_fileId"),
            privmx::endpoint::core::Buffer::from("publicMeta"),
            privmx::endpoint::core::Buffer::from("privateMeta")
        );
    });
    store::File file;
    EXPECT_NO_THROW({
        file = storeApi->getFile(reader->getString("File_1.info_fileId"));
    });
    EXPECT_EQ(file.statusCode, 0);
    EXPECT_EQ(file.info.fileId, reader->getString("File_1.info_fileId"));
    EXPECT_EQ(file.publicMeta.stdString(), "publicMeta");
    EXPECT_EQ(file.privateMeta.stdString(), "privateMeta");
    EXPECT_EQ(file.size, reader->getInt64("File_1.size"));
}

TEST_F(StoreTest, Access_denaid_not_in_users_or_managers) {
    disconnect();
    connectAs(ConnectionType::User2);
    // getStore
    EXPECT_THROW({
        storeApi->getStore(
            reader->getString("Store_1.storeId")
        );
    } ,core::Exception);
    // updateStore
    EXPECT_THROW({
        storeApi->updateStore(
            reader->getString("Store_1.storeId"),
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
    } ,core::Exception);
    // deleteStore
    EXPECT_THROW({
        storeApi->deleteStore(
            reader->getString("Store_1.storeId")
        );
    } ,core::Exception);
    // getFile 
    EXPECT_THROW({
        storeApi->getFile(
            reader->getString("File_1.info_fileId")
        );
    } ,core::Exception);
    // listFiles
    EXPECT_THROW({
        storeApi->listFiles(
            reader->getString("Store_1.storeId"),
            {
                .skip=0, 
                .limit=1, 
                .sortOrder="desc"
            }
        );
    } ,core::Exception);
    // createFile 
    EXPECT_THROW({
        storeApi->createFile(
            reader->getString("Store_1.storeId"),
            privmx::endpoint::core::Buffer::from("publicMeta"),
            privmx::endpoint::core::Buffer::from("privateMeta"),
            64
        );
    } ,core::Exception);
    // updateFile 
    EXPECT_THROW({
        storeApi->updateFile(
            reader->getString("File_1.info_fileId"),
            privmx::endpoint::core::Buffer::from("publicMeta"),
            privmx::endpoint::core::Buffer::from("privateMeta"),
            64
        );
    } ,core::Exception);
    // openFile 
    EXPECT_THROW({
        storeApi->openFile(
            reader->getString("File_1.info_fileId")
        );
    } ,core::Exception);
}

TEST_F(StoreTest, Access_denaid_Public) {
    disconnect();
    connectAs(ConnectionType::Public);
    // getStore
    EXPECT_THROW({
        storeApi->getStore(
            reader->getString("Store_1.storeId")
        );
    } ,core::Exception);
    // listStores
    EXPECT_THROW({
        storeApi->listStores(
            reader->getString("Context_1.contextId"),
            {
                .skip=0, 
                .limit=1, 
                .sortOrder="desc"
            }
        );
    } ,core::Exception);
    // createStore
    EXPECT_THROW({
        storeApi->createStore(
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
    } ,core::Exception);
    // updateStore
    EXPECT_THROW({
        storeApi->updateStore(
            reader->getString("Store_1.storeId"),
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
    } ,core::Exception);
    // deleteStore
    EXPECT_THROW({
        storeApi->deleteStore(
            reader->getString("Store_1.storeId")
        );
    } ,core::Exception);
    // getFile 
    EXPECT_THROW({
        storeApi->getFile(
            reader->getString("File_1.info_fileId")
        );
    } ,core::Exception);
    // listFiles
    EXPECT_THROW({
        storeApi->listFiles(
            reader->getString("Store_1.storeId"),
            {
                .skip=0, 
                .limit=1, 
                .sortOrder="desc"
            }
        );
    } ,core::Exception);
    // createFile 
    EXPECT_THROW({
        storeApi->createFile(
            reader->getString("Store_1.storeId"),
            privmx::endpoint::core::Buffer::from("publicMeta"),
            privmx::endpoint::core::Buffer::from("privateMeta"),
            64
        );
    } ,core::Exception);
    // updateFile 
    EXPECT_THROW({
        storeApi->updateFile(
            reader->getString("File_1.info_fileId"),
            privmx::endpoint::core::Buffer::from("publicMeta"),
            privmx::endpoint::core::Buffer::from("privateMeta"),
            64
        );
    } ,core::Exception);
    // openFile 
    EXPECT_THROW({
        storeApi->openFile(
            reader->getString("File_1.info_fileId")
        );
    } ,core::Exception);
}

TEST_F(StoreTest, openFile_readFromFile_updateFile_closeFile_FileVersionMismatchHandleClosedException) {

    int64_t handle = 0;
    std::string data;
    // createFile correct file
    EXPECT_NO_THROW({
        handle = storeApi->openFile(
            reader->getString("File_1.info_fileId")
        );
    });

    int64_t updateHandle;
    EXPECT_NO_THROW({
        updateHandle = storeApi->updateFile(
            reader->getString("File_1.info_fileId"),
            privmx::endpoint::core::Buffer::from("publicMeta"),
            privmx::endpoint::core::Buffer::from("privateMeta"),
            0
        );
    });
    EXPECT_NO_THROW({
        storeApi->closeFile(updateHandle);
    });


    // FileVersionMismatchHandleClosedException
    EXPECT_THROW({
        storeApi->readFromFile(
            handle,
            reader->getInt64("File_1.size")
        );
    }, store::FileVersionMismatchException);

    EXPECT_NO_THROW({
        storeApi->closeFile(
            handle
        );
    });
}

TEST_F(StoreTest, createStore_policy) {
    std::string storeId;
    privmx::endpoint::store::Store store;
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
        storeId = storeApi->createStore(
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
    if(storeId.empty()) { 
        FAIL();
    }
    EXPECT_NO_THROW({
        store = storeApi->getStore(
            storeId
        );
    });
    EXPECT_EQ(store.contextId, reader->getString("Context_1.contextId"));
    EXPECT_EQ(store.publicMeta.stdString(), "public");
    EXPECT_EQ(store.privateMeta.stdString(), "private");
    EXPECT_EQ(store.users.size(), 2);
    if(store.users.size() == 2) {
        EXPECT_EQ(store.users[0], reader->getString("Login.user_1_id"));
        EXPECT_EQ(store.users[1], reader->getString("Login.user_2_id"));
    }
    EXPECT_EQ(store.managers.size(), 2);
    if(store.managers.size() == 2) {
        EXPECT_EQ(store.managers[0], reader->getString("Login.user_1_id"));
        EXPECT_EQ(store.managers[1], reader->getString("Login.user_2_id"));
    }
    EXPECT_EQ(store.policy.item.value().get, policy.item.value().get);
    EXPECT_EQ(store.policy.item.value().listMy, policy.item.value().listMy);
    EXPECT_EQ(store.policy.item.value().listAll, policy.item.value().listAll);
    EXPECT_EQ(store.policy.item.value().create, policy.item.value().create);
    EXPECT_EQ(store.policy.item.value().update, policy.item.value().update);
    EXPECT_EQ(store.policy.item.value().delete_, policy.item.value().delete_);

    EXPECT_EQ(store.policy.get, policy.get);
    EXPECT_EQ(store.policy.update, policy.update);
    EXPECT_EQ(store.policy.delete_, policy.delete_);
    EXPECT_EQ(store.policy.updatePolicy, policy.updatePolicy);
    EXPECT_EQ(store.policy.updaterCanBeRemovedFromManagers, policy.updaterCanBeRemovedFromManagers);
    EXPECT_EQ(store.policy.ownerCanBeRemovedFromManagers, policy.ownerCanBeRemovedFromManagers);
    disconnect();
    connectAs(ConnectionType::User2);
    EXPECT_THROW({
        store = storeApi->getStore(
            storeId
        );
    }, core::Exception);
}

TEST_F(StoreTest, updateStore_policy) {
    // same users and managers
    std::string storeId = reader->getString("Store_1.storeId");
    privmx::endpoint::store::Store store;
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
        storeApi->updateStore(
            storeId,
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
    if(storeId.empty()) { 
        FAIL();
    }
    EXPECT_NO_THROW({
        store = storeApi->getStore(
            storeId
        );
    });
    EXPECT_EQ(store.contextId, reader->getString("Context_1.contextId"));
    EXPECT_EQ(store.publicMeta.stdString(), "public");
    EXPECT_EQ(store.privateMeta.stdString(), "private");
    EXPECT_EQ(store.users.size(), 2);
    if(store.users.size() == 2) {
        EXPECT_EQ(store.users[0], reader->getString("Login.user_1_id"));
        EXPECT_EQ(store.users[1], reader->getString("Login.user_2_id"));
    }
    EXPECT_EQ(store.managers.size(), 2);
    if(store.managers.size() == 2) {
        EXPECT_EQ(store.managers[0], reader->getString("Login.user_1_id"));
        EXPECT_EQ(store.managers[1], reader->getString("Login.user_2_id"));
    }
    EXPECT_EQ(store.policy.item.value().get, policy.item.value().get);
    EXPECT_EQ(store.policy.item.value().listMy, policy.item.value().listMy);
    EXPECT_EQ(store.policy.item.value().listAll, policy.item.value().listAll);
    EXPECT_EQ(store.policy.item.value().create, policy.item.value().create);
    EXPECT_EQ(store.policy.item.value().update, policy.item.value().update);
    EXPECT_EQ(store.policy.item.value().delete_, policy.item.value().delete_);

    EXPECT_EQ(store.policy.get, policy.get);
    EXPECT_EQ(store.policy.update, policy.update);
    EXPECT_EQ(store.policy.delete_, policy.delete_);
    EXPECT_EQ(store.policy.updatePolicy, policy.updatePolicy);
    EXPECT_EQ(store.policy.updaterCanBeRemovedFromManagers, policy.updaterCanBeRemovedFromManagers);
    EXPECT_EQ(store.policy.ownerCanBeRemovedFromManagers, policy.ownerCanBeRemovedFromManagers);
    disconnect();
    connectAs(ConnectionType::User2);
    EXPECT_THROW({
        storeApi->getFile(
            reader->getString("File_1.info_fileId")
        );
    }, core::Exception);
}

TEST_F(StoreTest, listStores_query) {
    std::string storeId;
    core::PagingList<store::Store> listStores;
    EXPECT_NO_THROW({
        storeId = storeApi->createStore(
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
    if(storeId.empty()) { 
        FAIL();
    }
    EXPECT_NO_THROW({
        listStores = storeApi->listStores(
            reader->getString("Context_1.contextId"),
            core::PagingQuery{
                .skip=0,
                .limit=100,
                .sortOrder="asc",
                .queryAsJson="{\"test\":1}"
            }
        );
    });
    EXPECT_EQ(listStores.totalAvailable, 1);
    EXPECT_EQ(listStores.readItems.size(), 1);
    if(listStores.readItems.size() >= 1) {
        auto store = listStores.readItems[0];
        EXPECT_EQ(store.contextId, reader->getString("Context_1.contextId"));
        EXPECT_EQ(store.storeId, storeId);
        EXPECT_EQ(store.filesCount, 0);
        EXPECT_EQ(store.statusCode, 0);
        EXPECT_EQ(store.publicMeta.stdString(), "{\"test\":1}");
        EXPECT_EQ(store.privateMeta.stdString(), "list_query_test");
        EXPECT_EQ(store.creator, reader->getString("Login.user_1_id"));
        EXPECT_EQ(store.lastModifier, reader->getString("Login.user_1_id"));
        EXPECT_EQ(store.users.size(), 1);
        if(store.users.size() == 1) {
            EXPECT_EQ(store.users[0], reader->getString("Login.user_1_id"));
        }
        EXPECT_EQ(store.managers.size(), 1);
        if(store.managers.size() == 1) {
            EXPECT_EQ(store.managers[0], reader->getString("Login.user_1_id"));
        }
    }
}

TEST_F(StoreTest, updateStore_key_update_open_file) {
    std::string fileId;
    EXPECT_NO_THROW({
        storeApi->updateStore(
            reader->getString("Store_1.storeId"),
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
    int64_t read_handle = 0;
    std::string read_data;
    EXPECT_NO_THROW({
        read_handle = storeApi->openFile(
            reader->getString("File_1.info_fileId")
        );
    });
    EXPECT_NO_THROW({
        read_data = storeApi->readFromFile(
            read_handle,
            reader->getInt64("File_1.size")
        ).stdString();
    });
    EXPECT_NO_THROW({
        storeApi->closeFile(
            read_handle
        );
    });
       
}

TEST_F(StoreTest, update_access_to_old_files) {
    EXPECT_NO_THROW({
        storeApi->updateStore(
            reader->getString("Store_1.storeId"),
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
    privmx::endpoint::store::File file;
    EXPECT_NO_THROW({
        file = storeApi->getFile(
            reader->getString("File_1.info_fileId")
        );
    });
    EXPECT_EQ(file.statusCode, 0);
}

TEST_F(StoreTest, random_write_oneChunk) {
    int64_t rwFileHandle = 0;
    std::string fileId = "";
    store::File file;
    EXPECT_NO_THROW({
        auto t = storeApi->createFile(reader->getString("Store_2.storeId"), core::Buffer::from("RW_publicMeta"), core::Buffer::from("RW_privateMeta"), 0, true);
        fileId = storeApi->closeFile(t);
        rwFileHandle = storeApi->openFile(fileId);
    });
    EXPECT_EQ(rwFileHandle, 2);
    if(rwFileHandle != 2) {
        return;
    }
    EXPECT_NO_THROW({
        try {
        file = storeApi->getFile(fileId);
        } catch (const core::Exception& e) {
            std::cout << e.getFull() << std::endl;
            e.rethrow();
        }

    });
    EXPECT_EQ(file.statusCode, 0);
    EXPECT_EQ(file.publicMeta.stdString(), "RW_publicMeta");
    EXPECT_EQ(file.privateMeta.stdString(), "RW_privateMeta");
    EXPECT_EQ(file.size, 0);

    EXPECT_NO_THROW({
        storeApi->seekInFile(rwFileHandle,0);
        storeApi->writeToFile(rwFileHandle, core::Buffer::from("testing_rw"));
        storeApi->seekInFile(rwFileHandle,0);
        auto testWrite1 = storeApi->readFromFile(rwFileHandle, 20).stdString();
        EXPECT_EQ(testWrite1, "testing_rw");
    });

    EXPECT_NO_THROW({
        storeApi->seekInFile(rwFileHandle,2);
        storeApi->writeToFile(rwFileHandle, core::Buffer::from("testing_rw"));
        storeApi->seekInFile(rwFileHandle,0);
        auto testWrite = storeApi->readFromFile(rwFileHandle, 20).stdString();
        EXPECT_EQ(testWrite, "tetesting_rw");
    });

    EXPECT_NO_THROW({
        storeApi->seekInFile(rwFileHandle,3);
        storeApi->writeToFile(rwFileHandle, core::Buffer::from(""), true);
        storeApi->seekInFile(rwFileHandle,0);
        auto testWrite = storeApi->readFromFile(rwFileHandle, 20).stdString();
        EXPECT_EQ(testWrite, "tet");
    });

    EXPECT_NO_THROW({
        storeApi->seekInFile(rwFileHandle,1);
        storeApi->writeToFile(rwFileHandle, core::Buffer::from("t"));
        storeApi->seekInFile(rwFileHandle,0);
        auto testWrite = storeApi->readFromFile(rwFileHandle, 20).stdString();
        EXPECT_EQ(testWrite, "ttt");
        storeApi->closeFile(rwFileHandle);
    });
    std::string writtenData = "";
    EXPECT_NO_THROW({
        file = storeApi->getFile(fileId);
        rwFileHandle = storeApi->openFile(fileId);
        writtenData = storeApi->readFromFile(rwFileHandle, file.size).stdString();
    });
    EXPECT_EQ(file.statusCode, 0);
    EXPECT_EQ(file.publicMeta.stdString(), "RW_publicMeta");
    EXPECT_EQ(file.privateMeta.stdString(), "RW_privateMeta");
    EXPECT_EQ(file.size, 3);
    EXPECT_EQ(file.randomWrite, true);
    EXPECT_EQ(writtenData, "ttt");
}

TEST_F(StoreTest, random_write_multipleChunks) {
    int64_t rwFileHandle = 0;
    std::string fileId = "";
    EXPECT_NO_THROW({
        auto t = storeApi->createFile(reader->getString("Store_2.storeId"), core::Buffer::from("RW_publicMeta"), core::Buffer::from("RW_privateMeta"), 0, true);
        fileId = storeApi->closeFile(t);
        rwFileHandle = storeApi->openFile(fileId);
    });
    EXPECT_EQ(rwFileHandle, 2);
    if(rwFileHandle != 2) {
        return;
    }
    size_t blockSize = 1024*64;
    std::string Hx64k = std::string(blockSize, 'H');
    std::string Ix64k = std::string(blockSize, 'I');
    std::string Tx64k = std::string(blockSize, 'T');

    EXPECT_NO_THROW({
        storeApi->seekInFile(rwFileHandle,0);
        storeApi->writeToFile(rwFileHandle, core::Buffer::from(Hx64k+Hx64k+Hx64k+Hx64k));
        storeApi->seekInFile(rwFileHandle,0);
        auto testWrite = storeApi->readFromFile(rwFileHandle, blockSize*4+1).stdString();
        EXPECT_EQ(testWrite, Hx64k+Hx64k+Hx64k+Hx64k);
    });
    EXPECT_NO_THROW({
        storeApi->seekInFile(rwFileHandle, blockSize*1);
        storeApi->writeToFile(rwFileHandle, core::Buffer::from(Ix64k+Ix64k));
        storeApi->seekInFile(rwFileHandle,0);
        auto testWrite = storeApi->readFromFile(rwFileHandle, blockSize*4+1).stdString();
        EXPECT_EQ(testWrite, Hx64k+Ix64k+Ix64k+Hx64k);
    });
    EXPECT_NO_THROW({
        storeApi->seekInFile(rwFileHandle, blockSize*3);
        storeApi->writeToFile(rwFileHandle, core::Buffer::from(Tx64k+Tx64k+Tx64k));
        storeApi->seekInFile(rwFileHandle,0);
        auto testWrite = storeApi->readFromFile(rwFileHandle, blockSize*6+1).stdString();
        EXPECT_EQ(testWrite, Hx64k+Ix64k+Ix64k+Tx64k+Tx64k+Tx64k);
    });
    EXPECT_NO_THROW({
        // truncate
        storeApi->seekInFile(rwFileHandle, blockSize*1);
        storeApi->writeToFile(rwFileHandle, core::Buffer::from(Tx64k+Ix64k), true);
        storeApi->seekInFile(rwFileHandle,0);
        auto testWrite = storeApi->readFromFile(rwFileHandle, blockSize*6+1).stdString();
        EXPECT_EQ(testWrite, Hx64k+Tx64k+Ix64k);
    });
    EXPECT_NO_THROW({
        storeApi->seekInFile(rwFileHandle, 0);
        storeApi->writeToFile(rwFileHandle, core::Buffer::from(Ix64k));
        storeApi->seekInFile(rwFileHandle,0);
        auto testWrite = storeApi->readFromFile(rwFileHandle, blockSize*6+1).stdString();
        EXPECT_EQ(testWrite, Ix64k+Tx64k+Ix64k);
        storeApi->closeFile(rwFileHandle);
    });
    std::string writtenData = "";
    store::File file;
    EXPECT_NO_THROW({
        file = storeApi->getFile(fileId);
        rwFileHandle = storeApi->openFile(fileId);
        writtenData = storeApi->readFromFile(rwFileHandle, file.size).stdString();
    });
    EXPECT_EQ(file.statusCode, 0);
    EXPECT_EQ(file.publicMeta.stdString(), "RW_publicMeta");
    EXPECT_EQ(file.privateMeta.stdString(), "RW_privateMeta");
    EXPECT_EQ(file.size, blockSize*3);
    EXPECT_EQ(file.randomWrite, true);
    EXPECT_EQ(writtenData, Ix64k+Tx64k+Ix64k);
}

TEST_F(StoreTest, random_write_sync_oneChunk) {
    auto connection_user2 = std::make_shared<core::Connection>(
        core::Connection::connect(
            reader->getString("Login.user_2_privKey"), 
            reader->getString("Login.solutionId"), 
            getPlatformUrl(reader->getString("Login.instanceUrl"))
        )
    );
    auto storeApi_user2 = std::make_shared<store::StoreApi>(
        store::StoreApi::create(
            *connection_user2
        )
    );
    int64_t rwFileHandle = 0;
    int64_t rwFileHandle_2 = 0;
    std::string fileId = "";
    store::File file;
    EXPECT_NO_THROW({
        auto t = storeApi->createFile(reader->getString("Store_2.storeId"), core::Buffer::from("RW_publicMeta"), core::Buffer::from("RW_privateMeta"), 0, true);
        fileId = storeApi->closeFile(t);
        rwFileHandle = storeApi->openFile(fileId);
        rwFileHandle_2 = storeApi_user2->openFile(fileId);
    });
    EXPECT_EQ(rwFileHandle, 2);
    EXPECT_EQ(rwFileHandle_2, 1);
    if(rwFileHandle != 2 || rwFileHandle_2 != 1) {
        return;
    }
    EXPECT_NO_THROW({
        try {
        file = storeApi->getFile(fileId);
        } catch (const core::Exception& e) {
            std::cout << e.getFull() << std::endl;
            e.rethrow();
        }

    });
    EXPECT_EQ(file.statusCode, 0);
    EXPECT_EQ(file.publicMeta.stdString(), "RW_publicMeta");
    EXPECT_EQ(file.privateMeta.stdString(), "RW_privateMeta");
    EXPECT_EQ(file.size, 0);

    EXPECT_NO_THROW({
        storeApi->seekInFile(rwFileHandle,0);
        storeApi->writeToFile(rwFileHandle, core::Buffer::from("testing_rw"));
        storeApi->seekInFile(rwFileHandle,0);
        auto testWrite1 = storeApi->readFromFile(rwFileHandle, 20).stdString();
        EXPECT_EQ(testWrite1, "testing_rw");
    });

    EXPECT_NO_THROW({
        storeApi_user2->syncFile(rwFileHandle_2);
        storeApi_user2->seekInFile(rwFileHandle_2,0);
        auto testWrite = storeApi_user2->readFromFile(rwFileHandle_2, 20).stdString();
        EXPECT_EQ(testWrite, "testing_rw");
    });

    connection_user2->disconnect();
}

TEST_F(StoreTest, random_write_multipleSync_multipleChunks) {
    auto connection_user2 = std::make_shared<core::Connection>(
        core::Connection::connect(
            reader->getString("Login.user_2_privKey"), 
            reader->getString("Login.solutionId"), 
            getPlatformUrl(reader->getString("Login.instanceUrl"))
        )
    );
    auto storeApi_user2 = std::make_shared<store::StoreApi>(
        store::StoreApi::create(
            *connection_user2
        )
    );

    int64_t rwFileHandle = 0;
    int64_t rwFileHandle_2 = 0;
    EXPECT_NO_THROW({
        auto t = storeApi->createFile(reader->getString("Store_2.storeId"), core::Buffer::from("RW_publicMeta"), core::Buffer::from("RW_privateMeta"), 0, true);
        auto fileId = storeApi->closeFile(t);
        rwFileHandle = storeApi->openFile(fileId);
        rwFileHandle_2 = storeApi_user2->openFile(fileId);
    });
    EXPECT_EQ(rwFileHandle, 2);
    EXPECT_EQ(rwFileHandle_2, 1);
    if(rwFileHandle != 2 || rwFileHandle_2 != 1) {
        return;
    }
    size_t blockSize = 1024*64;
    std::string Hx64k = std::string(blockSize, 'H');
    std::string Ix64k = std::string(blockSize, 'I');
    std::string Tx64k = std::string(blockSize, 'T');

    EXPECT_NO_THROW({
        storeApi->seekInFile(rwFileHandle,0);
        storeApi->writeToFile(rwFileHandle, core::Buffer::from(Hx64k+Hx64k+Hx64k+Hx64k));
        storeApi->seekInFile(rwFileHandle,0);
        auto testWrite = storeApi->readFromFile(rwFileHandle, blockSize*4+1).stdString();
        EXPECT_EQ(testWrite, Hx64k+Hx64k+Hx64k+Hx64k);
    });
    EXPECT_NO_THROW({
        storeApi_user2->syncFile(rwFileHandle_2);
        storeApi_user2->seekInFile(rwFileHandle_2, blockSize*1);
        storeApi_user2->writeToFile(rwFileHandle_2, core::Buffer::from(Ix64k+Ix64k));
        storeApi_user2->seekInFile(rwFileHandle_2,0);
        auto testWrite = storeApi_user2->readFromFile(rwFileHandle_2, blockSize*4+1).stdString();
        EXPECT_EQ(testWrite, Hx64k+Ix64k+Ix64k+Hx64k);
    });
    EXPECT_NO_THROW({
        storeApi->syncFile(rwFileHandle);
        storeApi->seekInFile(rwFileHandle, blockSize*3);
        storeApi->writeToFile(rwFileHandle, core::Buffer::from(Tx64k+Tx64k+Tx64k));
        storeApi->seekInFile(rwFileHandle,0);
        auto testWrite = storeApi->readFromFile(rwFileHandle, blockSize*6+1).stdString();
        EXPECT_EQ(testWrite, Hx64k+Ix64k+Ix64k+Tx64k+Tx64k+Tx64k);
    });
    EXPECT_NO_THROW({
        // truncate
        storeApi->seekInFile(rwFileHandle, blockSize*1);
        storeApi->writeToFile(rwFileHandle, core::Buffer::from(Tx64k+Ix64k), true);
        storeApi->seekInFile(rwFileHandle,0);
        auto testWrite = storeApi->readFromFile(rwFileHandle, blockSize*6+1).stdString();
        EXPECT_EQ(testWrite, Hx64k+Tx64k+Ix64k);
    });
    EXPECT_NO_THROW({
        storeApi_user2->syncFile(rwFileHandle_2);
        storeApi_user2->seekInFile(rwFileHandle_2, 0);
        storeApi_user2->writeToFile(rwFileHandle_2, core::Buffer::from(Ix64k));
        storeApi_user2->seekInFile(rwFileHandle_2,0);
        auto testWrite = storeApi_user2->readFromFile(rwFileHandle_2, blockSize*6+1).stdString();
        EXPECT_EQ(testWrite, Ix64k+Tx64k+Ix64k);
    });
    connection_user2->disconnect();
}

TEST_F(StoreTest, random_write_bufferSize) {
    int64_t rwFileHandle = 0;
    std::string fileId = "";
    EXPECT_NO_THROW({
        auto t = storeApi->createFile(reader->getString("Store_2.storeId"), core::Buffer::from("RW_publicMeta"), core::Buffer::from("RW_privateMeta"), 0, true);
        fileId = storeApi->closeFile(t);
        rwFileHandle = storeApi->openFile(fileId);
    });
    EXPECT_EQ(rwFileHandle, 2);
    if(rwFileHandle != 2) {
        return;
    }
    EXPECT_THROW({
        storeApi->seekInFile(rwFileHandle,0);
        storeApi->writeToFile(rwFileHandle, core::Buffer::from(std::string(512*1025+1, 'H')));
    }, core::InvalidParamsException);
}

TEST_F(StoreTest, sendMessage_cacheManipulation) {
    // load store to cache
    EXPECT_NO_THROW({
        storeApi->getStore(reader->getString("Store_1.storeId"));
    });
    // update store
    EXPECT_NO_THROW({
        storeApi->updateStore(
            reader->getString("Store_1.storeId"),
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
    std::string fileId;
    EXPECT_NO_THROW({
        auto handle = storeApi->createFile(
            reader->getString("Store_1.storeId"),
            core::Buffer::from("publicMeta"),
            core::Buffer::from("privateMeta"),
            0
        );
        fileId = storeApi->closeFile(handle);
    });
    store::File file;
    EXPECT_NO_THROW({
        file = storeApi->getFile(
            fileId
        );
    });
    EXPECT_EQ(file.statusCode, 0);
    EXPECT_EQ(file.privateMeta.stdString(), "privateMeta");
    EXPECT_EQ(file.publicMeta.stdString(), "publicMeta");
    EXPECT_EQ(file.size, 0);
}

TEST_F(StoreTest, updateFile_cacheManipulation) {
    // load store to cache
    EXPECT_NO_THROW({
        storeApi->getStore(reader->getString("Store_1.storeId"));
    });
    // update store
    EXPECT_NO_THROW({
        storeApi->updateStore(
            reader->getString("Store_1.storeId"),
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
    std::string fileId;
    EXPECT_NO_THROW({
        auto handle = storeApi->updateFile(
            reader->getString("File_1.info_fileId"),
            core::Buffer::from("publicMeta"),
            core::Buffer::from("privateMeta"),
            0
        );
        fileId = storeApi->closeFile(handle);
    });
    store::File file;
    EXPECT_NO_THROW({
        file = storeApi->getFile(
            fileId
        );
    });
    EXPECT_EQ(file.statusCode, 0);
    EXPECT_EQ(file.privateMeta.stdString(), "privateMeta");
    EXPECT_EQ(file.publicMeta.stdString(), "publicMeta");
    EXPECT_EQ(file.size, 0);
}

TEST_F(StoreTest, updateFileMeta_cacheManipulation) {
    // load store to cache
    EXPECT_NO_THROW({
        storeApi->getStore(reader->getString("Store_1.storeId"));
    });
    // update store
    EXPECT_NO_THROW({
        storeApi->updateStore(
            reader->getString("Store_1.storeId"),
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
        storeApi->updateFileMeta(
            reader->getString("File_1.info_fileId"),
            core::Buffer::from("publicMeta"),
            core::Buffer::from("privateMeta")
        );
    });
    store::File file;
    EXPECT_NO_THROW({
        file = storeApi->getFile(
            reader->getString("File_1.info_fileId")
        );
    });
    EXPECT_EQ(file.statusCode, 0);
    EXPECT_EQ(file.privateMeta.stdString(), "privateMeta");
    EXPECT_EQ(file.publicMeta.stdString(), "publicMeta");
    EXPECT_EQ(file.size, reader->getInt("File_1.size"));
}

TEST_F(StoreTest, userValidator_false) {
    auto verifier = std::make_shared<core::FalseUserVerifierInterface>();
    connection->setUserVerifier(verifier);
    // getStore
    EXPECT_NO_THROW({
        auto store = storeApi->getStore(
            reader->getString("Store_1.storeId")
        );
        EXPECT_FALSE(store.statusCode == 0);
    });
    // listStore
    EXPECT_NO_THROW({
        auto stores = storeApi->listStores(
            reader->getString("Context_1.contextId"),
            {
                .skip=0, 
                .limit=1, 
                .sortOrder="desc"
            }
        );
        EXPECT_FALSE(stores.readItems[0].statusCode == 0);
    });
    // createStore
    EXPECT_THROW({
        storeApi->createStore(
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
    // updateStore
    EXPECT_THROW({
        storeApi->updateStore(
            reader->getString("Store_1.storeId"),
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
            true,
            true
        );
    }, core::Exception);
    // deleteStore
    EXPECT_NO_THROW({
        storeApi->deleteStore(
            reader->getString("Store_2.storeId")
        );
    });
    // getFile 
    EXPECT_NO_THROW({
        auto file = storeApi->getFile(
            reader->getString("File_1.info_fileId")
        );
        EXPECT_FALSE(file.statusCode == 0);
    });
    // listFiles
    EXPECT_NO_THROW({
        auto files = storeApi->listFiles(
            reader->getString("Store_1.storeId"),
            {
                .skip=0, 
                .limit=1, 
                .sortOrder="desc"
            }
        );
        EXPECT_FALSE(files.readItems[0].statusCode == 0);
    });
    // createFile 
    EXPECT_THROW({
        auto handle = storeApi->createFile(
            reader->getString("Store_1.storeId"),
            privmx::endpoint::core::Buffer::from("publicMeta"),
            privmx::endpoint::core::Buffer::from("privateMeta"),
            0
        );
        storeApi->closeFile(handle);
    }, core::Exception);
    // updateFile 
    EXPECT_THROW({
        auto handle = storeApi->updateFile(
            reader->getString("File_1.info_fileId"),
            privmx::endpoint::core::Buffer::from("publicMeta"),
            privmx::endpoint::core::Buffer::from("privateMeta"),
            0
        );
        storeApi->closeFile(handle);
    }, core::Exception);
    // openFile 
    EXPECT_THROW({
        storeApi->openFile(
            reader->getString("File_1.info_fileId")
        );
    }, core::Exception);
    // deleteStore
    EXPECT_NO_THROW({
        storeApi->deleteFile(
            reader->getString("File_2.info_fileId")
        );
    });
}

TEST_F(StoreTest, sync_file) {

    int64_t handle = 0;
    int64_t readHandle = 0;
    EXPECT_NO_THROW({
        readHandle = storeApi->openFile(reader->getString("File_1.info_fileId"));
    });
    EXPECT_NO_THROW({
        handle = storeApi->updateFile(
            reader->getString("File_1.info_fileId"),
            privmx::endpoint::core::Buffer::from("publicMeta"),
            privmx::endpoint::core::Buffer::from("privateMeta"),
            7
        );
    });
    if(handle != 0) {
        std::string fileId;
        storeApi->writeToFile(
            handle, 
            core::Buffer::from("testing")
        );
        // updateFile size
        EXPECT_NO_THROW({
            fileId = storeApi->closeFile(handle);
        });
    } else {
        std::cout << "updateFile Failed" << std::endl;
        FAIL();
    }
    
    if(readHandle != 0) {
        core::Buffer fileData;
        EXPECT_NO_THROW({
            try {
                fileData = storeApi->readFromFile(
                    readHandle,
                    7
                );
            } catch (const store::FileVersionMismatchException& e) {
                storeApi->syncFile(readHandle);
                fileData = storeApi->readFromFile(
                    readHandle,
                    7
                );
            }
        });
        EXPECT_EQ(fileData.stdString(), "testing");
    } else {
        std::cout << "openFile Failed" << std::endl;
        FAIL();
    }
}

TEST_F(StoreTest, read_file_size_0) {

    int64_t handle = 0;
    int64_t readHandle = 0;
    EXPECT_NO_THROW({
        handle = storeApi->updateFile(
            reader->getString("File_1.info_fileId"),
            privmx::endpoint::core::Buffer::from("publicMeta"),
            privmx::endpoint::core::Buffer::from("privateMeta"),
            0
        );
    });
    if(handle != 0) {
        std::string fileId;
        // updateFile size
        EXPECT_NO_THROW({
            fileId = storeApi->closeFile(handle);
        });
    } else {
        std::cout << "updateFile Failed" << std::endl;
        FAIL();
    }
    EXPECT_NO_THROW({
        readHandle = storeApi->openFile(reader->getString("File_1.info_fileId"));
    });
    if(readHandle != 0) {
        core::Buffer fileData;
        EXPECT_NO_THROW({
            fileData = storeApi->readFromFile(
                readHandle,
                0
            );
        });
        EXPECT_EQ(fileData.stdString(), "");
        EXPECT_NO_THROW({
            fileData = storeApi->readFromFile(
                readHandle,
                8
            );
        });
        EXPECT_EQ(fileData.stdString(), "");
    } else {
        std::cout << "openFile Failed" << std::endl;
        FAIL();
    }
}

TEST_F(StoreTest, falseUserVerifierInterface) {
    EXPECT_NO_THROW({
        storeApi->updateStore(
            reader->getString("Store_1.storeId"),
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
            false,
            false
        );
    });

    EXPECT_NO_THROW({
        std::shared_ptr<FalseUserVerifierInterface> falseUserVerifierInterface = std::make_shared<FalseUserVerifierInterface>();
        connection->setUserVerifier(falseUserVerifierInterface);
    });
    
    core::PagingList<store::Store> storeListResult;
    EXPECT_NO_THROW({
        storeListResult = storeApi->listStores(reader->getString("Context_1.contextId"),{.skip=0, .limit=1, .sortOrder="desc"});
    });
    if(storeListResult.readItems.size() == 1) {
        EXPECT_EQ(storeListResult.readItems[0].statusCode, core::UserVerificationFailureException().getCode());
    } else {
        FAIL();
    }

    core::PagingList<store::File> fileListResult;
    EXPECT_NO_THROW({
        fileListResult = storeApi->listFiles(reader->getString("Store_1.storeId"),{.skip=0, .limit=1, .sortOrder="desc"});
    });
    if(fileListResult.readItems.size() == 1) {
        EXPECT_EQ(fileListResult.readItems[0].statusCode, core::UserVerificationFailureException().getCode());
    } else {
        FAIL();
    }
}
