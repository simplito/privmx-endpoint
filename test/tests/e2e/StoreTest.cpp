/**
 * One test per StoreApi function, each covering that function's whole contract: rejected input, accepted
 * input, and the state it leaves behind. Every other StoreApi function is assumed to work, so getStore and
 * getFile are used freely as oracles without that counting as a second subject.
 *
 * Assertions come from the dataset wherever the dataset records the value - expectMatchesDataset compares a
 * whole Store or File against its ini section. Membership is not in the ini, so expectMembers spells it out.
 * Only the tests needing a container the dataset does not seed (a random-write file, a rotated store, a
 * json-publicMeta store) create one at runtime.
 *
 * The last three tests are the exception to one-function-per-test: each sweeps the whole API surface for one
 * caller class (non-member, public connection, failing user verifier), which is one subject, not ten.
 */
#include <gtest/gtest.h>
#include "../../utils/BaseTest.hpp"
#include "../../utils/FalseUserVerifierInterface.hpp"
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

using namespace privmx::endpoint;

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
        reader = new Poco::Util::IniFileConfiguration(INI_FILE_PATH);
        connectAs(ConnectionType::User1);
    }
    void customTearDown() override { // tmp segfault fix
        connection.reset();
        storeApi.reset();
        reader.reset();
        privmx::endpoint::core::EventQueueImpl::getInstance()->clear();
    }

    core::UserWithPubKey user(int index) {
        const std::string n = std::to_string(index);
        return core::UserWithPubKey{
            .userId=reader->getString("Login.user_" + n + "_id"),
            .pubKey=reader->getString("Login.user_" + n + "_pubKey")
        };
    }

    std::vector<core::UserWithPubKey> users(std::initializer_list<int> indexes) {
        std::vector<core::UserWithPubKey> result;
        for(int index : indexes) {
            result.push_back(user(index));
        }
        return result;
    }

    // user_1's id carrying user_2's key, which is what every "incorrect users" case sends.
    std::vector<core::UserWithPubKey> usersWithMismatchedKey() {
        return {core::UserWithPubKey{
            .userId=reader->getString("Login.user_1_id"),
            .pubKey=reader->getString("Login.user_2_pubKey")
        }};
    }

    std::string storeId(int index) {
        return reader->getString("Store_" + std::to_string(index) + ".storeId");
    }

    std::string fileId(int index) {
        return reader->getString("File_" + std::to_string(index) + ".info_fileId");
    }

    std::string contextId() {
        return reader->getString("Context_1.contextId");
    }

    // Every Store field the dataset records, so a caller asserts the whole shape in one line.
    void expectMatchesDataset(const store::Store& store, const std::string& section) {
        EXPECT_EQ(store.contextId, reader->getString(section + ".contextId"));
        EXPECT_EQ(store.storeId, reader->getString(section + ".storeId"));
        EXPECT_EQ(store.createDate, reader->getInt64(section + ".createDate"));
        EXPECT_EQ(store.creator, reader->getString(section + ".creator"));
        EXPECT_EQ(store.lastModificationDate, reader->getInt64(section + ".lastModificationDate"));
        EXPECT_EQ(store.lastFileDate, reader->getInt64(section + ".lastFileDate"));
        EXPECT_EQ(store.lastModifier, reader->getString(section + ".lastModifier"));
        EXPECT_EQ(store.version, reader->getInt64(section + ".version"));
        EXPECT_EQ(store.filesCount, reader->getInt64(section + ".filesCount"));
        EXPECT_EQ(store.statusCode, 0);
        EXPECT_EQ(
            store.publicMeta.stdString(),
            privmx::utils::Hex::toString(reader->getString(section + ".publicMeta_inHex"))
        );
        EXPECT_EQ(
            store.publicMeta.stdString(),
            privmx::utils::Hex::toString(reader->getString(section + ".uploaded_publicMeta_inHex"))
        );
        EXPECT_EQ(
            store.privateMeta.stdString(),
            privmx::utils::Hex::toString(reader->getString(section + ".privateMeta_inHex"))
        );
        EXPECT_EQ(
            store.privateMeta.stdString(),
            privmx::utils::Hex::toString(reader->getString(section + ".uploaded_privateMeta_inHex"))
        );
    }

    void expectMatchesDataset(const store::File& file, const std::string& section) {
        EXPECT_EQ(file.info.storeId, reader->getString(section + ".info_storeId"));
        EXPECT_EQ(file.info.fileId, reader->getString(section + ".info_fileId"));
        EXPECT_EQ(file.info.createDate, reader->getInt64(section + ".info_createDate"));
        EXPECT_EQ(file.info.author, reader->getString(section + ".info_author"));
        EXPECT_EQ(
            file.publicMeta.stdString(),
            privmx::utils::Hex::toString(reader->getString(section + ".publicMeta_inHex"))
        );
        EXPECT_EQ(
            file.privateMeta.stdString(),
            privmx::utils::Hex::toString(reader->getString(section + ".privateMeta_inHex"))
        );
        EXPECT_EQ(file.size, reader->getInt64(section + ".size"));
        EXPECT_EQ(file.authorPubKey, reader->getString(section + ".authorPubKey"));
        EXPECT_EQ(file.statusCode, 0);
        EXPECT_EQ(
            privmx::utils::Utils::stringifyVar(_serializer.serialize(file)),
            reader->getString(section + ".JSON_data")
        );
        EXPECT_EQ(
            file.publicMeta.stdString(),
            privmx::utils::Hex::toString(reader->getString(section + ".uploaded_publicMeta_inHex"))
        );
        EXPECT_EQ(
            file.privateMeta.stdString(),
            privmx::utils::Hex::toString(reader->getString(section + ".uploaded_privateMeta_inHex"))
        );
        EXPECT_EQ(file.size, reader->getInt64(section + ".uploaded_size"));
    }

    // The roster is not in the ini, so it is spelled out by user index.
    void expectMembers(
        const store::Store& store, std::initializer_list<int> userIndexes,
        std::initializer_list<int> managerIndexes
    ) {
        ASSERT_EQ(store.users.size(), userIndexes.size());
        size_t i = 0;
        for(int index : userIndexes) {
            EXPECT_EQ(store.users[i++], user(index).userId);
        }
        ASSERT_EQ(store.managers.size(), managerIndexes.size());
        i = 0;
        for(int index : managerIndexes) {
            EXPECT_EQ(store.managers[i++], user(index).userId);
        }
    }

    // Every policy field set to the same subject, which is the only shape these tests use.
    core::ContainerPolicy uniformPolicy(const std::string& who, const std::string& updaterCanBeRemoved) {
        core::ContainerPolicy policy;
        policy.item = core::ItemPolicy{
            .get=who,
            .listMy=who,
            .listAll=who,
            .create=who,
            .update=who,
            .delete_=who
        };
        policy.get = who;
        policy.update = who;
        policy.delete_ = who;
        policy.updatePolicy = who;
        policy.updaterCanBeRemovedFromManagers = updaterCanBeRemoved;
        policy.ownerCanBeRemovedFromManagers = "no";
        return policy;
    }

    void expectPolicy(const store::Store& store, const core::ContainerPolicy& policy) {
        ASSERT_TRUE(store.policy.item.has_value());
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
    }

    // Fills a write handle to exactly `size`, refuses one byte past it, closes it (twice, the second time
    // expecting a refusal), then reads the whole file back through a read handle and compares. `size` must be
    // a multiple of 1 KiB; the two write loops exercise 1 KiB and 1 MiB chunks.
    void expectWriteHandleRoundTrip(int64_t handle, int64_t size) {
        std::string sent;
        sent.reserve(size);
        // total.size < declared
        EXPECT_NO_THROW({
            for(int i = 0; i < 1024*64; i++) {
                std::string chunk = privmx::crypto::Crypto::randomBytes(1024);
                storeApi->writeToFile(handle, core::Buffer::from(chunk));
                sent += chunk;
            }
        });
        // total.size == declared
        EXPECT_NO_THROW({
            for(int i = 0; i < 64; i++) {
                std::string chunk;
                for(int j = 0; j < 1024; j++) {
                    chunk += privmx::crypto::Crypto::randomBytes(1024);
                }
                storeApi->writeToFile(handle, core::Buffer::from(chunk));
                sent += chunk;
            }
        });
        // total.size > declared, by a single byte
        EXPECT_THROW({
            storeApi->writeToFile(handle, core::Buffer::from(privmx::crypto::Crypto::randomBytes(1)));
        }, core::Exception);

        std::string closedId;
        EXPECT_NO_THROW({ closedId = storeApi->closeFile(handle); });
        EXPECT_THROW({ storeApi->closeFile(handle); }, core::Exception);
        ASSERT_FALSE(closedId.empty());

        store::File file;
        EXPECT_NO_THROW({ file = storeApi->getFile(closedId); });
        EXPECT_EQ(file.statusCode, 0);
        EXPECT_EQ(file.info.fileId, closedId);
        EXPECT_EQ(file.publicMeta.stdString(), "publicMeta");
        EXPECT_EQ(file.privateMeta.stdString(), "privateMeta");
        EXPECT_EQ(file.size, size);

        int64_t readHandle = 0;
        EXPECT_NO_THROW({ readHandle = storeApi->openFile(closedId); });
        ASSERT_NE(readHandle, 0);
        std::string read;
        read.reserve(size);
        for(int64_t i = 0; i < size / 1024; i++) {
            read += storeApi->readFromFile(readHandle, 1024).stdString();
        }
        EXPECT_EQ(sent.size(), read.size());
        EXPECT_TRUE(sent == read) << "data read back differs from data sent";
    }

    // A zero-length random-write file in Store_2, opened for reading and writing. The dataset seeds none.
    int64_t openRandomWriteFile(std::string& createdId) {
        int64_t handle = 0;
        EXPECT_NO_THROW({
            int64_t writeHandle = storeApi->createFile(
                storeId(2), core::Buffer::from("RW_publicMeta"), core::Buffer::from("RW_privateMeta"), 0, true
            );
            createdId = storeApi->closeFile(writeHandle);
            handle = storeApi->openFile(createdId);
        });
        return handle;
    }

    // Forces a new store key, which is what every cache-manipulation section needs before its write.
    void forceNewStoreKey(const std::string& id) {
        EXPECT_NO_THROW({
            storeApi->updateStore(
                id, users({1}), users({1}),
                core::Buffer::from("public"), core::Buffer::from("private"), 1, true, true
            );
        });
    }

    std::shared_ptr<core::Connection> connection;
    std::shared_ptr<store::StoreApi> storeApi;
    Poco::Util::IniFileConfiguration::Ptr reader;
    core::VarSerializer _serializer = core::VarSerializer({});
};

TEST_F(StoreTest, createStore) {
    // incorrect contextId
    EXPECT_THROW({
        storeApi->createStore(
            storeId(1), users({1}), users({1}),
            core::Buffer::from("public"), core::Buffer::from("private")
        );
    }, core::Exception);
    // incorrect users
    EXPECT_THROW({
        storeApi->createStore(
            contextId(), usersWithMismatchedKey(), users({1}),
            core::Buffer::from("public"), core::Buffer::from("private")
        );
    }, core::Exception);
    // incorrect managers
    EXPECT_THROW({
        storeApi->createStore(
            contextId(), users({1}), usersWithMismatchedKey(),
            core::Buffer::from("public"), core::Buffer::from("private")
        );
    }, core::Exception);
    // no managers
    EXPECT_THROW({
        storeApi->createStore(
            contextId(), users({1}), {},
            core::Buffer::from("public"), core::Buffer::from("private")
        );
    }, core::Exception);

    // different users and managers
    std::string createdId;
    store::Store store;
    EXPECT_NO_THROW({
        createdId = storeApi->createStore(
            contextId(), users({2}), users({1}),
            core::Buffer::from("public"), core::Buffer::from("private")
        );
    });
    ASSERT_FALSE(createdId.empty());
    EXPECT_NO_THROW({ store = storeApi->getStore(createdId); });
    EXPECT_EQ(store.statusCode, 0);
    EXPECT_EQ(store.contextId, contextId());
    EXPECT_EQ(store.publicMeta.stdString(), "public");
    EXPECT_EQ(store.privateMeta.stdString(), "private");
    expectMembers(store, {2}, {1});

    // same users and managers
    EXPECT_NO_THROW({
        createdId = storeApi->createStore(
            contextId(), users({1}), users({1}),
            core::Buffer::from("public"), core::Buffer::from("private")
        );
    });
    ASSERT_FALSE(createdId.empty());
    EXPECT_NO_THROW({ store = storeApi->getStore(createdId); });
    EXPECT_EQ(store.statusCode, 0);
    EXPECT_EQ(store.contextId, contextId());
    expectMembers(store, {1}, {1});

    // with a policy, which closes the container to everyone but its owner
    const core::ContainerPolicy policy = uniformPolicy("owner", "no");
    EXPECT_NO_THROW({
        createdId = storeApi->createStore(
            contextId(), users({1, 2}), users({1, 2}),
            core::Buffer::from("public"), core::Buffer::from("private"), policy
        );
    });
    ASSERT_FALSE(createdId.empty());
    EXPECT_NO_THROW({ store = storeApi->getStore(createdId); });
    expectMembers(store, {1, 2}, {1, 2});
    expectPolicy(store, policy);
    disconnect();
    connectAs(ConnectionType::User2);
    EXPECT_THROW({ storeApi->getStore(createdId); }, core::Exception);
}

TEST_F(StoreTest, updateStore) {
    // incorrect storeId
    EXPECT_THROW({
        storeApi->updateStore(
            contextId(), users({1}), users({1}),
            core::Buffer::from("public"), core::Buffer::from("private"), 1, false, false
        );
    }, core::Exception);
    // incorrect users
    EXPECT_THROW({
        storeApi->updateStore(
            storeId(1), usersWithMismatchedKey(), users({1}),
            core::Buffer::from("public"), core::Buffer::from("private"), 1, false, false
        );
    }, core::Exception);
    // incorrect managers
    EXPECT_THROW({
        storeApi->updateStore(
            storeId(1), users({1}), usersWithMismatchedKey(),
            core::Buffer::from("public"), core::Buffer::from("private"), 1, false, false
        );
    }, core::Exception);
    // no managers
    EXPECT_THROW({
        storeApi->updateStore(
            storeId(1), users({1}), {},
            core::Buffer::from("public"), core::Buffer::from("private"), 1, false, false
        );
    }, core::Exception);
    // incorrect version, force false
    EXPECT_THROW({
        storeApi->updateStore(
            storeId(1), users({1}), users({1}),
            core::Buffer::from("public"), core::Buffer::from("private"), 2, false, false
        );
    }, core::Exception);

    store::Store store;
    // new users
    EXPECT_NO_THROW({
        storeApi->updateStore(
            storeId(1), users({1, 2}), users({1}),
            core::Buffer::from("public"), core::Buffer::from("private"), 1, false, false
        );
    });
    EXPECT_NO_THROW({ store = storeApi->getStore(storeId(1)); });
    EXPECT_EQ(store.statusCode, 0);
    EXPECT_EQ(store.storeId, storeId(1));
    EXPECT_EQ(store.version, 2);
    EXPECT_EQ(store.publicMeta.stdString(), "public");
    EXPECT_EQ(store.privateMeta.stdString(), "private");
    expectMembers(store, {1, 2}, {1});

    // new managers
    EXPECT_NO_THROW({
        storeApi->updateStore(
            storeId(1), users({1, 2}), users({1, 2}),
            core::Buffer::from("public"), core::Buffer::from("private"), 2, false, false
        );
    });
    EXPECT_NO_THROW({ store = storeApi->getStore(storeId(1)); });
    EXPECT_EQ(store.version, 3);
    expectMembers(store, {1, 2}, {1, 2});

    // less users
    EXPECT_NO_THROW({
        storeApi->updateStore(
            storeId(2), users({1}), users({1, 2}),
            core::Buffer::from("public"), core::Buffer::from("private"), 1, false, false
        );
    });
    EXPECT_NO_THROW({ store = storeApi->getStore(storeId(2)); });
    EXPECT_EQ(store.version, 2);
    expectMembers(store, {1}, {1, 2});

    // less managers
    EXPECT_NO_THROW({
        storeApi->updateStore(
            storeId(2), users({1}), users({1}),
            core::Buffer::from("public"), core::Buffer::from("private"), 2, false, false
        );
    });
    EXPECT_NO_THROW({ store = storeApi->getStore(storeId(2)); });
    EXPECT_EQ(store.version, 3);
    expectMembers(store, {1}, {1});

    // incorrect version, force true
    EXPECT_NO_THROW({
        storeApi->updateStore(
            storeId(3), users({1}), users({1}),
            core::Buffer::from("public"), core::Buffer::from("private"), 99, true, false
        );
    });
    EXPECT_NO_THROW({ store = storeApi->getStore(storeId(3)); });
    EXPECT_EQ(store.statusCode, 0);
    EXPECT_EQ(store.version, 2);
    expectMembers(store, {1}, {1});
}

TEST_F(StoreTest, updateStore_rewraps_keys_for_a_newly_added_user) {
    // A member added by an update, with a forced key generation, must still reach files written before it.
    EXPECT_NO_THROW({
        storeApi->updateStore(
            storeId(1), users({1, 2}), users({1, 2}),
            core::Buffer::from("public"), core::Buffer::from("private"), 1, true, true
        );
    });
    disconnect();
    connectAs(ConnectionType::User2);
    store::File file;
    EXPECT_NO_THROW({ file = storeApi->getFile(fileId(1)); });
    EXPECT_EQ(file.statusCode, 0);
}

TEST_F(StoreTest, updateStore_policy) {
    const core::ContainerPolicy ownerOnly = uniformPolicy("owner", "no");
    EXPECT_NO_THROW({
        storeApi->updateStore(
            storeId(1), users({1, 2}), users({1, 2}),
            core::Buffer::from("public"), core::Buffer::from("private"), 1, true, true, ownerOnly
        );
    });
    store::Store store;
    EXPECT_NO_THROW({ store = storeApi->getStore(storeId(1)); });
    EXPECT_EQ(store.contextId, contextId());
    EXPECT_EQ(store.publicMeta.stdString(), "public");
    EXPECT_EQ(store.privateMeta.stdString(), "private");
    expectMembers(store, {1, 2}, {1, 2});
    expectPolicy(store, ownerOnly);
    // An owner-only item policy hides the files from the other manager.
    disconnect();
    connectAs(ConnectionType::User2);
    EXPECT_THROW({ storeApi->getFile(fileId(1)); }, core::Exception);
}

TEST_F(StoreTest, rotateStoreKeys) {
    // The dataset seeds no rotated store, so this one is built here.
    const std::vector<core::UserWithPubKey> user_1 = users({1});
    std::string createdId;
    ASSERT_NO_THROW({
        createdId = storeApi->createStore(
            contextId(), user_1, user_1,
            core::Buffer::from("rotated_public"), core::Buffer::from("rotated_private")
        );
    });
    ASSERT_FALSE(createdId.empty());

    const std::string fileData = "file_data";
    std::string createdFileId;
    ASSERT_NO_THROW({
        int64_t handle = storeApi->createFile(
            createdId, core::Buffer::from("file_public"), core::Buffer::from("file_private"),
            (int64_t)fileData.size()
        );
        storeApi->writeToFile(handle, core::Buffer::from(fileData));
        createdFileId = storeApi->closeFile(handle);
    });

    ASSERT_NO_THROW({ storeApi->rotateStoreKeys(createdId, user_1, user_1, 0, true); });
    store::Store afterFirstRotation;
    ASSERT_NO_THROW({ afterFirstRotation = storeApi->getStore(createdId); });
    ASSERT_EQ(afterFirstRotation.statusCode, 0); // a single rotation has always been readable

    ASSERT_NO_THROW({ storeApi->rotateStoreKeys(createdId, user_1, user_1, 0, true); });

    // Reconnect so ContainerKeyCache is empty - the reads below resolve purely from server state.
    disconnect();
    connectAs(ConnectionType::User1);

    store::Store store;
    EXPECT_NO_THROW({ store = storeApi->getStore(createdId); });
    EXPECT_EQ(store.statusCode, 0);
    EXPECT_EQ(store.publicMeta.stdString(), "rotated_public");
    EXPECT_EQ(store.privateMeta.stdString(), "rotated_private");

    // Same decrypt path, batched.
    core::PagingList<store::Store> storeListResult;
    EXPECT_NO_THROW({
        storeListResult = storeApi->listStores(contextId(), {.skip=0, .limit=100, .sortOrder="desc"});
    });
    bool foundInList = false;
    for(const auto& listed : storeListResult.readItems) {
        if(listed.storeId == createdId) {
            foundInList = true;
            EXPECT_EQ(listed.statusCode, 0);
            EXPECT_EQ(listed.privateMeta.stdString(), "rotated_private");
        }
    }
    EXPECT_TRUE(foundInList);

    // Control: a file carries its own keyId, so it must stay readable across the rotations.
    store::File file;
    EXPECT_NO_THROW({ file = storeApi->getFile(createdFileId); });
    EXPECT_EQ(file.statusCode, 0);
    EXPECT_NO_THROW({
        int64_t handle = storeApi->openFile(createdFileId);
        EXPECT_EQ(storeApi->readFromFile(handle, (int64_t)fileData.size()).stdString(), fileData);
        storeApi->closeFile(handle);
    });
}

TEST_F(StoreTest, deleteStore) {
    // incorrect storeId
    EXPECT_THROW({ storeApi->deleteStore(contextId()); }, core::Exception);
    // as manager
    EXPECT_NO_THROW({ storeApi->deleteStore(storeId(1)); });
    EXPECT_THROW({ storeApi->getStore(storeId(1)); }, core::Exception);
    // as user
    disconnect();
    connectAs(ConnectionType::User2);
    EXPECT_THROW({ storeApi->deleteStore(storeId(3)); }, core::Exception);
}

TEST_F(StoreTest, getStore) {
    // incorrect storeId
    EXPECT_THROW({ storeApi->getStore(contextId()); }, core::Exception);
    // correct storeId
    store::Store store;
    EXPECT_NO_THROW({ store = storeApi->getStore(storeId(1)); });
    expectMatchesDataset(store, "Store_1");
    expectMembers(store, {1}, {1});
}

TEST_F(StoreTest, listStores) {
    // incorrect contextId
    EXPECT_THROW({
        storeApi->listStores(storeId(1), {.skip=0, .limit=1, .sortOrder="desc"});
    }, core::Exception);
    // limit < 0
    EXPECT_THROW({
        storeApi->listStores(contextId(), {.skip=0, .limit=-1, .sortOrder="desc"});
    }, core::Exception);
    // limit == 0
    EXPECT_THROW({
        storeApi->listStores(contextId(), {.skip=0, .limit=0, .sortOrder="desc"});
    }, core::Exception);
    // incorrect sortOrder
    EXPECT_THROW({
        storeApi->listStores(contextId(), {.skip=0, .limit=1, .sortOrder="BLACH"});
    }, core::Exception);
    // incorrect lastId
    EXPECT_THROW({
        storeApi->listStores(
            contextId(), {.skip=0, .limit=1, .sortOrder="desc", .lastId=contextId()}
        );
    }, core::Exception);
    // incorrect queryAsJson
    EXPECT_THROW({
        storeApi->listStores(
            contextId(),
            {.skip=0, .limit=1, .sortOrder="desc", .lastId=std::nullopt, .queryAsJson="{BLACH,}"}
        );
    }, core::InvalidParamsException);
    // incorrect sortBy
    EXPECT_THROW({
        storeApi->listStores(
            contextId(),
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

    // skip past the end
    core::PagingList<store::Store> listStores;
    EXPECT_NO_THROW({
        listStores = storeApi->listStores(contextId(), {.skip=4, .limit=1, .sortOrder="desc"});
    });
    EXPECT_EQ(listStores.totalAvailable, 3);
    EXPECT_EQ(listStores.readItems.size(), 0);

    // newest first
    EXPECT_NO_THROW({
        listStores = storeApi->listStores(contextId(), {.skip=0, .limit=1, .sortOrder="desc"});
    });
    EXPECT_EQ(listStores.totalAvailable, 3);
    ASSERT_EQ(listStores.readItems.size(), 1);
    expectMatchesDataset(listStores.readItems[0], "Store_3");
    expectMembers(listStores.readItems[0], {1, 2}, {1});

    // paged by createDate, ascending
    EXPECT_NO_THROW({
        listStores = storeApi->listStores(
            contextId(),
            core::PagingQuery{
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
    ASSERT_EQ(listStores.readItems.size(), 2);
    expectMatchesDataset(listStores.readItems[0], "Store_2");
    expectMembers(listStores.readItems[0], {1, 2}, {1, 2});
    expectMatchesDataset(listStores.readItems[1], "Store_3");
    expectMembers(listStores.readItems[1], {1, 2}, {1});

    // queryAsJson matches on publicMeta, which no seeded store carries as json
    std::string createdId;
    EXPECT_NO_THROW({
        createdId = storeApi->createStore(
            contextId(), users({1}), users({1}),
            core::Buffer::from("{\"test\":1}"), core::Buffer::from("list_query_test")
        );
    });
    ASSERT_FALSE(createdId.empty());
    EXPECT_NO_THROW({
        listStores = storeApi->listStores(
            contextId(),
            core::PagingQuery{.skip=0, .limit=100, .sortOrder="asc", .queryAsJson="{\"test\":1}"}
        );
    });
    EXPECT_EQ(listStores.totalAvailable, 1);
    ASSERT_EQ(listStores.readItems.size(), 1);
    EXPECT_EQ(listStores.readItems[0].storeId, createdId);
    EXPECT_EQ(listStores.readItems[0].statusCode, 0);
    EXPECT_EQ(listStores.readItems[0].filesCount, 0);
    EXPECT_EQ(listStores.readItems[0].publicMeta.stdString(), "{\"test\":1}");
    EXPECT_EQ(listStores.readItems[0].privateMeta.stdString(), "list_query_test");
}

TEST_F(StoreTest, createFile) {
    // incorrect storeId
    EXPECT_THROW({
        storeApi->createFile(
            contextId(), core::Buffer::from("publicMeta"), core::Buffer::from("privateMeta"), 64
        );
    }, core::Exception);
    // size < 0
    EXPECT_THROW({
        storeApi->createFile(
            storeId(1), core::Buffer::from("publicMeta"), core::Buffer::from("privateMeta"), -1
        );
    }, core::Exception);

    // size = 0, closed without a single write
    int64_t handle = 0;
    EXPECT_NO_THROW({
        handle = storeApi->createFile(
            storeId(1), core::Buffer::from("publicMeta"), core::Buffer::from("privateMeta"), 0
        );
    });
    ASSERT_NE(handle, 0);
    std::string createdId;
    EXPECT_NO_THROW({ createdId = storeApi->closeFile(handle); });
    ASSERT_FALSE(createdId.empty());
    store::File file;
    EXPECT_NO_THROW({ file = storeApi->getFile(createdId); });
    EXPECT_EQ(file.statusCode, 0);
    EXPECT_EQ(file.info.fileId, createdId);
    EXPECT_EQ(file.publicMeta.stdString(), "publicMeta");
    EXPECT_EQ(file.privateMeta.stdString(), "privateMeta");
    EXPECT_EQ(file.size, 0);

    // with a stale store in the cache: the create below only succeeds if the new key is picked up
    EXPECT_NO_THROW({ storeApi->getStore(storeId(1)); });
    forceNewStoreKey(storeId(1));
    EXPECT_NO_THROW({
        handle = storeApi->createFile(
            storeId(1), core::Buffer::from("publicMeta"), core::Buffer::from("privateMeta"), 0
        );
        createdId = storeApi->closeFile(handle);
    });
    EXPECT_NO_THROW({ file = storeApi->getFile(createdId); });
    EXPECT_EQ(file.statusCode, 0);
    EXPECT_EQ(file.size, 0);

    // the full 128 MB round trip
    EXPECT_NO_THROW({
        handle = storeApi->createFile(
            storeId(1), core::Buffer::from("publicMeta"), core::Buffer::from("privateMeta"), 128*1024*1024
        );
    });
    ASSERT_NE(handle, 0);
    expectWriteHandleRoundTrip(handle, 128*1024*1024);
}

TEST_F(StoreTest, updateFile) {
    // incorrect fileId
    EXPECT_THROW({
        storeApi->updateFile(
            storeId(1), core::Buffer::from("publicMeta"), core::Buffer::from("privateMeta"), 64
        );
    }, core::Exception);
    // size < 0
    EXPECT_THROW({
        storeApi->updateFile(
            fileId(1), core::Buffer::from("publicMeta"), core::Buffer::from("privateMeta"), -1
        );
    }, core::Exception);

    // size = 0, closed without a single write
    int64_t handle = 0;
    EXPECT_NO_THROW({
        handle = storeApi->updateFile(
            fileId(1), core::Buffer::from("publicMeta"), core::Buffer::from("privateMeta"), 0
        );
    });
    ASSERT_NE(handle, 0);
    std::string closedId;
    EXPECT_NO_THROW({ closedId = storeApi->closeFile(handle); });
    ASSERT_FALSE(closedId.empty());
    store::File file;
    EXPECT_NO_THROW({ file = storeApi->getFile(closedId); });
    EXPECT_EQ(file.statusCode, 0);
    EXPECT_EQ(file.publicMeta.stdString(), "publicMeta");
    EXPECT_EQ(file.privateMeta.stdString(), "privateMeta");
    EXPECT_EQ(file.size, 0);

    // a read handle opened before the update must refuse to serve the stale version
    int64_t staleReadHandle = 0;
    EXPECT_NO_THROW({ staleReadHandle = storeApi->openFile(fileId(2)); });
    EXPECT_NO_THROW({
        int64_t updateHandle = storeApi->updateFile(
            fileId(2), core::Buffer::from("publicMeta"), core::Buffer::from("privateMeta"), 0
        );
        storeApi->closeFile(updateHandle);
    });
    EXPECT_THROW({
        storeApi->readFromFile(staleReadHandle, reader->getInt64("File_2.size"));
    }, store::FileVersionMismatchException);
    EXPECT_NO_THROW({ storeApi->closeFile(staleReadHandle); });

    // with a stale store in the cache: the update below only succeeds if the new key is picked up
    EXPECT_NO_THROW({ storeApi->getStore(storeId(1)); });
    forceNewStoreKey(storeId(1));
    EXPECT_NO_THROW({
        handle = storeApi->updateFile(
            fileId(1), core::Buffer::from("publicMeta"), core::Buffer::from("privateMeta"), 0
        );
        closedId = storeApi->closeFile(handle);
    });
    EXPECT_NO_THROW({ file = storeApi->getFile(closedId); });
    EXPECT_EQ(file.statusCode, 0);
    EXPECT_EQ(file.size, 0);

    // the full 128 MB round trip
    EXPECT_NO_THROW({
        handle = storeApi->updateFile(
            fileId(1), core::Buffer::from("publicMeta"), core::Buffer::from("privateMeta"), 128*1024*1024
        );
    });
    ASSERT_NE(handle, 0);
    expectWriteHandleRoundTrip(handle, 128*1024*1024);
}

TEST_F(StoreTest, updateFileMeta) {
    // incorrect fileId
    EXPECT_THROW({
        storeApi->updateFileMeta(
            storeId(1), core::Buffer::from("publicMeta"), core::Buffer::from("privateMeta")
        );
    }, core::Exception);

    // correct data - the payload is untouched, so `size` must survive
    EXPECT_NO_THROW({
        storeApi->updateFileMeta(
            fileId(1), core::Buffer::from("publicMeta"), core::Buffer::from("privateMeta")
        );
    });
    store::File file;
    EXPECT_NO_THROW({ file = storeApi->getFile(fileId(1)); });
    EXPECT_EQ(file.statusCode, 0);
    EXPECT_EQ(file.info.fileId, fileId(1));
    EXPECT_EQ(file.publicMeta.stdString(), "publicMeta");
    EXPECT_EQ(file.privateMeta.stdString(), "privateMeta");
    EXPECT_EQ(file.size, reader->getInt64("File_1.size"));

    // with a stale store in the cache: the write below only succeeds if the new key is picked up
    EXPECT_NO_THROW({ storeApi->getStore(storeId(1)); });
    forceNewStoreKey(storeId(1));
    EXPECT_NO_THROW({
        storeApi->updateFileMeta(
            fileId(1), core::Buffer::from("rekeyed_public"), core::Buffer::from("rekeyed_private")
        );
    });
    EXPECT_NO_THROW({ file = storeApi->getFile(fileId(1)); });
    EXPECT_EQ(file.statusCode, 0);
    EXPECT_EQ(file.publicMeta.stdString(), "rekeyed_public");
    EXPECT_EQ(file.privateMeta.stdString(), "rekeyed_private");
    EXPECT_EQ(file.size, reader->getInt64("File_1.size"));
}

TEST_F(StoreTest, deleteFile) {
    // incorrect fileId
    EXPECT_THROW({ storeApi->deleteFile(storeId(1)); }, core::Exception);
    // user_2 joins as a plain user and may not delete somebody else's file
    EXPECT_NO_THROW({
        storeApi->updateStore(
            storeId(1), users({1, 2}), users({1}),
            core::Buffer::from("public"), core::Buffer::from("private"), 1, true, false
        );
    });
    disconnect();
    connectAs(ConnectionType::User2);
    EXPECT_THROW({ storeApi->deleteFile(fileId(2)); }, core::Exception);

    // promoted to manager, it may
    disconnect();
    connectAs(ConnectionType::User1);
    EXPECT_NO_THROW({
        storeApi->updateStore(
            storeId(1), users({1, 2}), users({1, 2}),
            core::Buffer::from("public"), core::Buffer::from("private"), 1, true, false
        );
    });
    disconnect();
    connectAs(ConnectionType::User2);
    EXPECT_NO_THROW({
        storeApi->updateStore(
            storeId(1), users({1, 2}), users({2}),
            core::Buffer::from("public"), core::Buffer::from("private"), 1, true, false
        );
    });
    // as the author
    disconnect();
    connectAs(ConnectionType::User1);
    EXPECT_NO_THROW({ storeApi->deleteFile(fileId(2)); });
    // as a manager who did not write it
    disconnect();
    connectAs(ConnectionType::User2);
    EXPECT_NO_THROW({ storeApi->deleteFile(fileId(1)); });
}

TEST_F(StoreTest, getFile) {
    // incorrect fileId
    EXPECT_THROW({ storeApi->getFile(contextId()); }, core::Exception);
    // a forced key generation must not cost access to files written before it
    forceNewStoreKey(storeId(1));
    store::File file;
    EXPECT_NO_THROW({ file = storeApi->getFile(fileId(1)); });
    expectMatchesDataset(file, "File_1");
}

TEST_F(StoreTest, listFiles) {
    // incorrect storeId
    EXPECT_THROW({
        storeApi->listFiles(fileId(1), {.skip=0, .limit=1, .sortOrder="desc"});
    }, core::Exception);
    // limit < 0
    EXPECT_THROW({
        storeApi->listFiles(storeId(1), {.skip=0, .limit=-1, .sortOrder="desc"});
    }, core::Exception);
    // limit == 0
    EXPECT_THROW({
        storeApi->listFiles(storeId(1), {.skip=0, .limit=0, .sortOrder="desc"});
    }, core::Exception);
    // incorrect sortOrder
    EXPECT_THROW({
        storeApi->listFiles(storeId(1), {.skip=0, .limit=1, .sortOrder="BLACH"});
    }, core::Exception);
    // incorrect lastId
    EXPECT_THROW({
        storeApi->listFiles(
            storeId(1), {.skip=0, .limit=1, .sortOrder="BLACH", .lastId=storeId(1)}
        );
    }, core::Exception);
    // incorrect queryAsJson
    EXPECT_THROW({
        storeApi->listFiles(
            storeId(1),
            {.skip=0, .limit=1, .sortOrder="BLACH", .lastId=std::nullopt, .queryAsJson="{BLACH,}"}
        );
    }, core::InvalidParamsException);
    // incorrect sortBy
    EXPECT_THROW({
        storeApi->listFiles(
            storeId(1),
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

    // skip past the end
    core::PagingList<store::File> listFiles;
    EXPECT_NO_THROW({
        listFiles = storeApi->listFiles(storeId(1), {.skip=4, .limit=1, .sortOrder="desc"});
    });
    EXPECT_EQ(listFiles.totalAvailable, 2);
    EXPECT_EQ(listFiles.readItems.size(), 0);

    // oldest, reached by skipping the newest
    EXPECT_NO_THROW({
        listFiles = storeApi->listFiles(storeId(1), {.skip=1, .limit=1, .sortOrder="desc"});
    });
    EXPECT_EQ(listFiles.totalAvailable, 2);
    ASSERT_EQ(listFiles.readItems.size(), 1);
    expectMatchesDataset(listFiles.readItems[0], "File_1");

    // after a forced key generation, both files still decrypt
    forceNewStoreKey(storeId(1));
    EXPECT_NO_THROW({
        listFiles = storeApi->listFiles(
            storeId(1),
            core::PagingQuery{
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
    ASSERT_EQ(listFiles.readItems.size(), 2);
    expectMatchesDataset(listFiles.readItems[0], "File_1");
    expectMatchesDataset(listFiles.readItems[1], "File_2");
}

TEST_F(StoreTest, openFile_readFromFile_seekInFile_closeFile) {
    // openFile incorrect fileId
    EXPECT_THROW({ storeApi->openFile(storeId(1)); }, core::Exception);
    // readFromFile and seekInFile on a handle that does not exist
    EXPECT_THROW({ storeApi->readFromFile(1, 2); }, core::Exception);
    EXPECT_THROW({ storeApi->seekInFile(1, 2); }, core::Exception);
    // closeFile on a handle that does not exist
    EXPECT_THROW({ storeApi->closeFile(0); }, core::Exception);

    // readFromFile and seekInFile on a write handle
    int64_t writeHandle = 0;
    EXPECT_NO_THROW({
        writeHandle = storeApi->createFile(
            storeId(1), core::Buffer::from("publicMeta"), core::Buffer::from("privateMeta"), 64
        );
    });
    ASSERT_NE(writeHandle, 0);
    EXPECT_THROW({ storeApi->readFromFile(writeHandle, 2); }, core::Exception);
    EXPECT_THROW({ storeApi->seekInFile(writeHandle, 2); }, core::Exception);
    // writeToFile on a read handle
    int64_t readHandle = 0;
    EXPECT_NO_THROW({ readHandle = storeApi->openFile(fileId(1)); });
    ASSERT_NE(readHandle, 0);
    EXPECT_THROW({ storeApi->writeToFile(readHandle, core::Buffer::from("BLAH")); }, core::Exception);

    // seekInFile pos < 0
    EXPECT_THROW({ storeApi->seekInFile(readHandle, -1); }, core::Exception);
    // seekInFile pos > file.size
    EXPECT_THROW({
        storeApi->seekInFile(readHandle, reader->getInt64("File_1.size") + 1);
    }, core::Exception);

    // read the whole file, in two seeks, and reassemble it
    std::string data;
    EXPECT_NO_THROW({ storeApi->seekInFile(readHandle, reader->getInt64("File_1.size") / 2); });
    EXPECT_NO_THROW({
        data = storeApi->readFromFile(readHandle, reader->getInt64("File_1.size")).stdString();
    });
    EXPECT_NO_THROW({ storeApi->seekInFile(readHandle, 0); });
    EXPECT_NO_THROW({
        data = storeApi->readFromFile(readHandle, reader->getInt64("File_1.size") / 2).stdString() + data;
    });
    EXPECT_NO_THROW({ storeApi->closeFile(readHandle); });
    EXPECT_EQ(data, privmx::utils::Hex::toString(reader->getString("File_1.uploaded_data_inHex")));

    // a handle opened before a store re-key keeps reading
    forceNewStoreKey(storeId(1));
    EXPECT_NO_THROW({ readHandle = storeApi->openFile(fileId(1)); });
    EXPECT_NO_THROW({
        EXPECT_EQ(
            storeApi->readFromFile(readHandle, reader->getInt64("File_1.size")).stdString(),
            privmx::utils::Hex::toString(reader->getString("File_1.uploaded_data_inHex"))
        );
    });
    EXPECT_NO_THROW({ storeApi->closeFile(readHandle); });

    // reading an empty file yields an empty buffer whatever length is asked for
    EXPECT_NO_THROW({
        int64_t truncateHandle = storeApi->updateFile(
            fileId(1), core::Buffer::from("publicMeta"), core::Buffer::from("privateMeta"), 0
        );
        storeApi->closeFile(truncateHandle);
    });
    EXPECT_NO_THROW({ readHandle = storeApi->openFile(fileId(1)); });
    ASSERT_NE(readHandle, 0);
    EXPECT_NO_THROW({ EXPECT_EQ(storeApi->readFromFile(readHandle, 0).stdString(), ""); });
    EXPECT_NO_THROW({ EXPECT_EQ(storeApi->readFromFile(readHandle, 8).stdString(), ""); });
    EXPECT_NO_THROW({ storeApi->closeFile(readHandle); });
}

TEST_F(StoreTest, writeToFile_random_access) {
    // writeToFile on a handle that does not exist
    EXPECT_THROW({ storeApi->writeToFile(0, core::Buffer::from("BLACH")); }, core::Exception);

    // one chunk at a time, including an overwrite in the middle and a truncating write
    std::string createdId;
    int64_t handle = openRandomWriteFile(createdId);
    ASSERT_NE(handle, 0);
    store::File file;
    EXPECT_NO_THROW({ file = storeApi->getFile(createdId); });
    EXPECT_EQ(file.statusCode, 0);
    EXPECT_EQ(file.publicMeta.stdString(), "RW_publicMeta");
    EXPECT_EQ(file.privateMeta.stdString(), "RW_privateMeta");
    EXPECT_EQ(file.size, 0);

    EXPECT_NO_THROW({
        storeApi->seekInFile(handle, 0);
        storeApi->writeToFile(handle, core::Buffer::from("testing_rw"));
        storeApi->seekInFile(handle, 0);
        EXPECT_EQ(storeApi->readFromFile(handle, 20).stdString(), "testing_rw");
    });
    EXPECT_NO_THROW({
        storeApi->seekInFile(handle, 2);
        storeApi->writeToFile(handle, core::Buffer::from("testing_rw"));
        storeApi->seekInFile(handle, 0);
        EXPECT_EQ(storeApi->readFromFile(handle, 20).stdString(), "tetesting_rw");
    });
    EXPECT_NO_THROW({
        storeApi->seekInFile(handle, 3);
        storeApi->writeToFile(handle, core::Buffer::from(""), true);
        storeApi->seekInFile(handle, 0);
        EXPECT_EQ(storeApi->readFromFile(handle, 20).stdString(), "tet");
    });
    EXPECT_NO_THROW({
        storeApi->seekInFile(handle, 1);
        storeApi->writeToFile(handle, core::Buffer::from("t"));
        storeApi->seekInFile(handle, 0);
        EXPECT_EQ(storeApi->readFromFile(handle, 20).stdString(), "ttt");
        storeApi->closeFile(handle);
    });
    std::string writtenData;
    EXPECT_NO_THROW({
        file = storeApi->getFile(createdId);
        handle = storeApi->openFile(createdId);
        writtenData = storeApi->readFromFile(handle, file.size).stdString();
        storeApi->closeFile(handle);
    });
    EXPECT_EQ(file.statusCode, 0);
    EXPECT_EQ(file.size, 3);
    EXPECT_EQ(file.randomWrite, true);
    EXPECT_EQ(writtenData, "ttt");

    // multiple 64 KiB blocks, so a write spans more than one chunk boundary
    handle = openRandomWriteFile(createdId);
    ASSERT_NE(handle, 0);
    const size_t blockSize = 1024*64;
    const std::string Hx64k(blockSize, 'H');
    const std::string Ix64k(blockSize, 'I');
    const std::string Tx64k(blockSize, 'T');

    EXPECT_NO_THROW({
        storeApi->seekInFile(handle, 0);
        storeApi->writeToFile(handle, core::Buffer::from(Hx64k+Hx64k+Hx64k+Hx64k));
        storeApi->seekInFile(handle, 0);
        EXPECT_EQ(storeApi->readFromFile(handle, blockSize*4+1).stdString(), Hx64k+Hx64k+Hx64k+Hx64k);
    });
    EXPECT_NO_THROW({
        storeApi->seekInFile(handle, blockSize*1);
        storeApi->writeToFile(handle, core::Buffer::from(Ix64k+Ix64k));
        storeApi->seekInFile(handle, 0);
        EXPECT_EQ(storeApi->readFromFile(handle, blockSize*4+1).stdString(), Hx64k+Ix64k+Ix64k+Hx64k);
    });
    EXPECT_NO_THROW({
        storeApi->seekInFile(handle, blockSize*3);
        storeApi->writeToFile(handle, core::Buffer::from(Tx64k+Tx64k+Tx64k));
        storeApi->seekInFile(handle, 0);
        EXPECT_EQ(
            storeApi->readFromFile(handle, blockSize*6+1).stdString(),
            Hx64k+Ix64k+Ix64k+Tx64k+Tx64k+Tx64k
        );
    });
    EXPECT_NO_THROW({
        // truncate
        storeApi->seekInFile(handle, blockSize*1);
        storeApi->writeToFile(handle, core::Buffer::from(Tx64k+Ix64k), true);
        storeApi->seekInFile(handle, 0);
        EXPECT_EQ(storeApi->readFromFile(handle, blockSize*6+1).stdString(), Hx64k+Tx64k+Ix64k);
    });
    EXPECT_NO_THROW({
        storeApi->seekInFile(handle, 0);
        storeApi->writeToFile(handle, core::Buffer::from(Ix64k));
        storeApi->seekInFile(handle, 0);
        EXPECT_EQ(storeApi->readFromFile(handle, blockSize*6+1).stdString(), Ix64k+Tx64k+Ix64k);
        storeApi->closeFile(handle);
    });
    EXPECT_NO_THROW({
        file = storeApi->getFile(createdId);
        handle = storeApi->openFile(createdId);
        writtenData = storeApi->readFromFile(handle, file.size).stdString();
        storeApi->closeFile(handle);
    });
    EXPECT_EQ(file.statusCode, 0);
    EXPECT_EQ(file.size, (int64_t)(blockSize*3));
    EXPECT_EQ(file.randomWrite, true);
    EXPECT_EQ(writtenData, Ix64k+Tx64k+Ix64k);

    // a single write past the buffer ceiling
    handle = openRandomWriteFile(createdId);
    ASSERT_NE(handle, 0);
    EXPECT_THROW({
        storeApi->seekInFile(handle, 0);
        storeApi->writeToFile(handle, core::Buffer::from(std::string(512*1025+1, 'H')));
    }, core::InvalidParamsException);
}

TEST_F(StoreTest, syncFile_flushFile) {
    auto connection_user2 = std::make_shared<core::Connection>(
        core::Connection::connect(
            reader->getString("Login.user_2_privKey"),
            reader->getString("Login.solutionId"),
            getPlatformUrl(reader->getString("Login.instanceUrl"))
        )
    );
    auto storeApi_user2 = std::make_shared<store::StoreApi>(store::StoreApi::create(*connection_user2));

    // one chunk: user_1 flushes, user_2 syncs and sees it
    std::string createdId;
    int64_t handle = openRandomWriteFile(createdId);
    ASSERT_NE(handle, 0);
    int64_t handle_user2 = 0;
    EXPECT_NO_THROW({ handle_user2 = storeApi_user2->openFile(createdId); });
    ASSERT_NE(handle_user2, 0);

    EXPECT_NO_THROW({
        storeApi->seekInFile(handle, 0);
        storeApi->writeToFile(handle, core::Buffer::from("testing_rw"));
        storeApi->seekInFile(handle, 0);
        EXPECT_EQ(storeApi->readFromFile(handle, 20).stdString(), "testing_rw");
        storeApi->flushFile(handle);
    });
    EXPECT_NO_THROW({
        storeApi_user2->syncFile(handle_user2);
        storeApi_user2->seekInFile(handle_user2, 0);
        EXPECT_EQ(storeApi_user2->readFromFile(handle_user2, 20).stdString(), "testing_rw");
    });
    EXPECT_NO_THROW({
        storeApi->closeFile(handle);
        storeApi_user2->closeFile(handle_user2);
    });

    // multiple 64 KiB blocks, with both sides writing and syncing in turn
    handle = openRandomWriteFile(createdId);
    ASSERT_NE(handle, 0);
    EXPECT_NO_THROW({ handle_user2 = storeApi_user2->openFile(createdId); });
    ASSERT_NE(handle_user2, 0);
    const size_t blockSize = 1024*64;
    const std::string Hx64k(blockSize, 'H');
    const std::string Ix64k(blockSize, 'I');
    const std::string Tx64k(blockSize, 'T');

    EXPECT_NO_THROW({
        storeApi->seekInFile(handle, 0);
        storeApi->writeToFile(handle, core::Buffer::from(Hx64k+Hx64k+Hx64k+Hx64k));
        storeApi->seekInFile(handle, 0);
        EXPECT_EQ(storeApi->readFromFile(handle, blockSize*4+1).stdString(), Hx64k+Hx64k+Hx64k+Hx64k);
        storeApi->flushFile(handle);
    });
    EXPECT_NO_THROW({
        storeApi_user2->syncFile(handle_user2);
        storeApi_user2->seekInFile(handle_user2, blockSize*1);
        storeApi_user2->writeToFile(handle_user2, core::Buffer::from(Ix64k+Ix64k));
        storeApi_user2->seekInFile(handle_user2, 0);
        EXPECT_EQ(
            storeApi_user2->readFromFile(handle_user2, blockSize*4+1).stdString(),
            Hx64k+Ix64k+Ix64k+Hx64k
        );
        storeApi_user2->flushFile(handle_user2);
    });
    EXPECT_NO_THROW({
        storeApi->syncFile(handle);
        storeApi->seekInFile(handle, blockSize*3);
        storeApi->writeToFile(handle, core::Buffer::from(Tx64k+Tx64k+Tx64k));
        storeApi->flushFile(handle);
        storeApi->seekInFile(handle, 0);
        EXPECT_EQ(
            storeApi->readFromFile(handle, blockSize*6+1).stdString(),
            Hx64k+Ix64k+Ix64k+Tx64k+Tx64k+Tx64k
        );
    });
    EXPECT_NO_THROW({
        // truncate
        storeApi->seekInFile(handle, blockSize*1);
        storeApi->writeToFile(handle, core::Buffer::from(Tx64k+Ix64k), true);
        storeApi->flushFile(handle);
        storeApi->seekInFile(handle, 0);
        EXPECT_EQ(storeApi->readFromFile(handle, blockSize*6+1).stdString(), Hx64k+Tx64k+Ix64k);
    });
    EXPECT_NO_THROW({
        storeApi_user2->syncFile(handle_user2);
        storeApi_user2->seekInFile(handle_user2, 0);
        storeApi_user2->writeToFile(handle_user2, core::Buffer::from(Ix64k));
        storeApi_user2->flushFile(handle_user2);
        storeApi_user2->seekInFile(handle_user2, 0);
        EXPECT_EQ(
            storeApi_user2->readFromFile(handle_user2, blockSize*6+1).stdString(),
            Ix64k+Tx64k+Ix64k
        );
    });
    EXPECT_NO_THROW({
        storeApi->closeFile(handle);
        storeApi_user2->closeFile(handle_user2);
    });
    connection_user2->disconnect();

    // syncFile is also the recovery from a version mismatch on a plain, non-random-write file
    int64_t staleReadHandle = 0;
    EXPECT_NO_THROW({ staleReadHandle = storeApi->openFile(fileId(1)); });
    ASSERT_NE(staleReadHandle, 0);
    EXPECT_NO_THROW({
        int64_t writeHandle = storeApi->updateFile(
            fileId(1), core::Buffer::from("publicMeta"), core::Buffer::from("privateMeta"), 7
        );
        storeApi->writeToFile(writeHandle, core::Buffer::from("testing"));
        storeApi->closeFile(writeHandle);
    });
    core::Buffer fileData;
    EXPECT_NO_THROW({
        try {
            fileData = storeApi->readFromFile(staleReadHandle, 7);
        } catch (const store::FileVersionMismatchException& e) {
            storeApi->syncFile(staleReadHandle);
            fileData = storeApi->readFromFile(staleReadHandle, 7);
        }
    });
    EXPECT_EQ(fileData.stdString(), "testing");
    EXPECT_NO_THROW({ storeApi->closeFile(staleReadHandle); });
}

TEST_F(StoreTest, Access_denaid_not_in_users_or_managers) {
    disconnect();
    connectAs(ConnectionType::User2);
    EXPECT_THROW({ storeApi->getStore(storeId(1)); }, core::Exception);
    EXPECT_THROW({
        storeApi->updateStore(
            storeId(1), users({2}), users({2}),
            core::Buffer::from("public"), core::Buffer::from("private"), 1, false, false
        );
    }, core::Exception);
    EXPECT_THROW({ storeApi->deleteStore(storeId(1)); }, core::Exception);
    EXPECT_THROW({ storeApi->getFile(fileId(1)); }, core::Exception);
    EXPECT_THROW({
        storeApi->listFiles(storeId(1), {.skip=0, .limit=1, .sortOrder="desc"});
    }, core::Exception);
    EXPECT_THROW({
        storeApi->createFile(
            storeId(1), core::Buffer::from("publicMeta"), core::Buffer::from("privateMeta"), 64
        );
    }, core::Exception);
    EXPECT_THROW({
        storeApi->updateFile(
            fileId(1), core::Buffer::from("publicMeta"), core::Buffer::from("privateMeta"), 64
        );
    }, core::Exception);
    EXPECT_THROW({ storeApi->openFile(fileId(1)); }, core::Exception);
}

TEST_F(StoreTest, Access_denaid_Public) {
    disconnect();
    connectAs(ConnectionType::Public);
    EXPECT_THROW({ storeApi->getStore(storeId(1)); }, core::Exception);
    EXPECT_THROW({
        storeApi->listStores(contextId(), {.skip=0, .limit=1, .sortOrder="desc"});
    }, core::Exception);
    EXPECT_THROW({
        storeApi->createStore(
            contextId(), users({2}), users({2}),
            core::Buffer::from("public"), core::Buffer::from("private")
        );
    }, core::Exception);
    EXPECT_THROW({
        storeApi->updateStore(
            storeId(1), users({2}), users({2}),
            core::Buffer::from("public"), core::Buffer::from("private"), 1, false, false
        );
    }, core::Exception);
    EXPECT_THROW({ storeApi->deleteStore(storeId(1)); }, core::Exception);
    EXPECT_THROW({ storeApi->getFile(fileId(1)); }, core::Exception);
    EXPECT_THROW({
        storeApi->listFiles(storeId(1), {.skip=0, .limit=1, .sortOrder="desc"});
    }, core::Exception);
    EXPECT_THROW({
        storeApi->createFile(
            storeId(1), core::Buffer::from("publicMeta"), core::Buffer::from("privateMeta"), 64
        );
    }, core::Exception);
    EXPECT_THROW({
        storeApi->updateFile(
            fileId(1), core::Buffer::from("publicMeta"), core::Buffer::from("privateMeta"), 64
        );
    }, core::Exception);
    EXPECT_THROW({ storeApi->openFile(fileId(1)); }, core::Exception);
}

TEST_F(StoreTest, userValidator_false) {
    // A verifier that rejects everyone leaves reads succeeding but undecrypted, and blocks every write that
    // would have to trust a key it cannot verify.
    auto verifier = std::make_shared<core::FalseUserVerifierInterface>();
    connection->setUserVerifier(verifier);
    const auto failureCode = core::UserVerificationFailureException().getCode();

    EXPECT_NO_THROW({
        auto store = storeApi->getStore(storeId(1));
        EXPECT_EQ(store.statusCode, failureCode);
    });
    EXPECT_NO_THROW({
        auto stores = storeApi->listStores(contextId(), {.skip=0, .limit=1, .sortOrder="desc"});
        ASSERT_EQ(stores.readItems.size(), 1);
        EXPECT_EQ(stores.readItems[0].statusCode, failureCode);
    });
    EXPECT_THROW({
        storeApi->createStore(
            contextId(), users({2}), users({2}),
            core::Buffer::from("public"), core::Buffer::from("private")
        );
    }, core::Exception);
    EXPECT_THROW({
        storeApi->updateStore(
            storeId(1), users({2}), users({2}),
            core::Buffer::from("public"), core::Buffer::from("private"), 1, true, true
        );
    }, core::Exception);
    EXPECT_NO_THROW({ storeApi->deleteStore(storeId(2)); });
    EXPECT_NO_THROW({
        auto file = storeApi->getFile(fileId(1));
        EXPECT_EQ(file.statusCode, failureCode);
    });
    EXPECT_NO_THROW({
        auto files = storeApi->listFiles(storeId(1), {.skip=0, .limit=1, .sortOrder="desc"});
        ASSERT_EQ(files.readItems.size(), 1);
        EXPECT_EQ(files.readItems[0].statusCode, failureCode);
    });
    EXPECT_THROW({
        int64_t handle = storeApi->createFile(
            storeId(1), core::Buffer::from("publicMeta"), core::Buffer::from("privateMeta"), 0
        );
        storeApi->closeFile(handle);
    }, core::Exception);
    EXPECT_THROW({
        int64_t handle = storeApi->updateFile(
            fileId(1), core::Buffer::from("publicMeta"), core::Buffer::from("privateMeta"), 0
        );
        storeApi->closeFile(handle);
    }, core::Exception);
    EXPECT_THROW({ storeApi->openFile(fileId(1)); }, core::Exception);
    EXPECT_NO_THROW({ storeApi->deleteFile(fileId(2)); });
}
