/**
 * One test per KvdbApi function, each covering that function's whole contract: rejected input, accepted
 * input, and the state it leaves behind. Every other KvdbApi function is assumed to work, so getKvdb and
 * getEntry are used freely as oracles without that counting as a second subject.
 *
 * Assertions come from the dataset wherever the dataset records the value - expectMatchesDataset compares a
 * whole Kvdb or KvdbEntry against its ini section. Membership is not in the ini, so expectMembers spells it
 * out. Only rotateKvdbKeys, which the dataset seeds no fixture for, creates a container at runtime.
 *
 * Two gaps this file does not close, both pre-existing: findEntry has no test at all, and createKvdb checks
 * no rejected input where its Thread and Store counterparts check four cases.
 */
#include <gtest/gtest.h>
#include "BaseTest.hpp"
#include "FalseUserVerifierInterface.hpp"
#include <privmx/endpoint/core/Exception.hpp>
#include <Poco/Util/IniFileConfiguration.h>
#include <privmx/endpoint/core/EventQueueImpl.hpp>
#include <privmx/crypto/Crypto.hpp>
#include <privmx/utils/Utils.hpp>
#include <privmx/endpoint/core/VarSerializer.hpp>
#include <privmx/endpoint/core/Connection.hpp>
#include <privmx/endpoint/kvdb/KvdbApi.hpp>
#include <privmx/endpoint/kvdb/VarSerializer.hpp>
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
        reader = new Poco::Util::IniFileConfiguration(INI_FILE_PATH);
        connectAs(ConnectionType::User1);
    }
    void customTearDown() override { // tmp segfault fix
        connection.reset();
        kvdbApi.reset();
        reader.reset();
        core::EventQueueImpl::getInstance()->clear();
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

    std::string kvdbId(int index) {
        return reader->getString("Kvdb_" + std::to_string(index) + ".kvdbId");
    }

    std::string entryKey(int index) {
        return reader->getString("KvdbEntry_" + std::to_string(index) + ".info_key");
    }

    std::string contextId() {
        return reader->getString("Context_1.contextId");
    }

    // Every Kvdb field the dataset records, so a caller asserts the whole shape in one line.
    void expectMatchesDataset(const kvdb::Kvdb& kvdb, const std::string& section) {
        EXPECT_EQ(kvdb.contextId, reader->getString(section + ".contextId"));
        EXPECT_EQ(kvdb.kvdbId, reader->getString(section + ".kvdbId"));
        EXPECT_EQ(kvdb.createDate, reader->getInt64(section + ".createDate"));
        EXPECT_EQ(kvdb.creator, reader->getString(section + ".creator"));
        EXPECT_EQ(kvdb.lastModificationDate, reader->getInt64(section + ".lastModificationDate"));
        EXPECT_EQ(kvdb.lastModifier, reader->getString(section + ".lastModifier"));
        EXPECT_EQ(kvdb.version, reader->getInt64(section + ".version"));
        EXPECT_EQ(kvdb.lastEntryDate, reader->getInt64(section + ".lastEntryDate"));
        EXPECT_EQ(kvdb.entries, reader->getInt64(section + ".entries"));
        EXPECT_EQ(kvdb.statusCode, 0);
        EXPECT_EQ(
            kvdb.publicMeta.stdString(),
            privmx::utils::Hex::toString(reader->getString(section + ".publicMeta_inHex"))
        );
        EXPECT_EQ(
            kvdb.publicMeta.stdString(),
            privmx::utils::Hex::toString(reader->getString(section + ".uploaded_publicMeta_inHex"))
        );
        EXPECT_EQ(
            kvdb.privateMeta.stdString(),
            privmx::utils::Hex::toString(reader->getString(section + ".privateMeta_inHex"))
        );
        EXPECT_EQ(
            kvdb.privateMeta.stdString(),
            privmx::utils::Hex::toString(reader->getString(section + ".uploaded_privateMeta_inHex"))
        );
    }

    void expectMatchesDataset(const kvdb::KvdbEntry& entry, const std::string& section) {
        EXPECT_EQ(entry.info.kvdbId, reader->getString(section + ".info_kvdbId"));
        EXPECT_EQ(entry.info.key, reader->getString(section + ".info_key"));
        EXPECT_EQ(entry.info.createDate, reader->getInt64(section + ".info_createDate"));
        EXPECT_EQ(entry.info.author, reader->getString(section + ".info_author"));
        EXPECT_EQ(
            entry.publicMeta.stdString(),
            privmx::utils::Hex::toString(reader->getString(section + ".publicMeta_inHex"))
        );
        EXPECT_EQ(
            entry.privateMeta.stdString(),
            privmx::utils::Hex::toString(reader->getString(section + ".privateMeta_inHex"))
        );
        EXPECT_EQ(entry.data.stdString(), privmx::utils::Hex::toString(reader->getString(section + ".data_inHex")));
        EXPECT_EQ(entry.statusCode, 0);
        EXPECT_EQ(
            privmx::utils::Utils::stringifyVar(_serializer.serialize(entry)),
            reader->getString(section + ".JSON_data")
        );
        EXPECT_EQ(
            entry.publicMeta.stdString(),
            privmx::utils::Hex::toString(reader->getString(section + ".uploaded_publicMeta_inHex"))
        );
        EXPECT_EQ(
            entry.privateMeta.stdString(),
            privmx::utils::Hex::toString(reader->getString(section + ".uploaded_privateMeta_inHex"))
        );
        EXPECT_EQ(
            entry.data.stdString(),
            privmx::utils::Hex::toString(reader->getString(section + ".uploaded_data_inHex"))
        );
    }

    // The roster is not in the ini, so it is spelled out by user index.
    void expectMembers(
        const kvdb::Kvdb& kvdb, std::initializer_list<int> userIndexes,
        std::initializer_list<int> managerIndexes
    ) {
        ASSERT_EQ(kvdb.users.size(), userIndexes.size());
        size_t i = 0;
        for(int index : userIndexes) {
            EXPECT_EQ(kvdb.users[i++], user(index).userId);
        }
        ASSERT_EQ(kvdb.managers.size(), managerIndexes.size());
        i = 0;
        for(int index : managerIndexes) {
            EXPECT_EQ(kvdb.managers[i++], user(index).userId);
        }
    }

    // Forces a new kvdb key, which several tests need before reading or writing through the old one.
    void forceNewKvdbKey(const std::string& id) {
        EXPECT_NO_THROW({
            kvdbApi->updateKvdb(
                id, users({1}), users({1}),
                core::Buffer::from("public"), core::Buffer::from("private"), 1, true, true
            );
        });
    }

    std::shared_ptr<core::Connection> connection;
    std::shared_ptr<kvdb::KvdbApi> kvdbApi;
    Poco::Util::IniFileConfiguration::Ptr reader;
    core::VarSerializer _serializer = core::VarSerializer({});
};

TEST_F(KvdbTest, createKvdb) {
    // different users and managers
    std::string createdId;
    kvdb::Kvdb kvdb;
    EXPECT_NO_THROW({
        createdId = kvdbApi->createKvdb(
            contextId(), users({2}), users({1}),
            core::Buffer::from("public"), core::Buffer::from("private"), std::nullopt
        );
    });
    ASSERT_FALSE(createdId.empty());
    EXPECT_NO_THROW({ kvdb = kvdbApi->getKvdb(createdId); });
    EXPECT_EQ(kvdb.statusCode, 0);
    EXPECT_EQ(kvdb.contextId, contextId());
    EXPECT_EQ(kvdb.publicMeta.stdString(), "public");
    EXPECT_EQ(kvdb.privateMeta.stdString(), "private");
    expectMembers(kvdb, {2}, {1});

    // same users and managers
    EXPECT_NO_THROW({
        createdId = kvdbApi->createKvdb(
            contextId(), users({1}), users({1}),
            core::Buffer::from("public"), core::Buffer::from("private"), std::nullopt
        );
    });
    ASSERT_FALSE(createdId.empty());
    EXPECT_NO_THROW({ kvdb = kvdbApi->getKvdb(createdId); });
    EXPECT_EQ(kvdb.statusCode, 0);
    EXPECT_EQ(kvdb.contextId, contextId());
    EXPECT_EQ(kvdb.publicMeta.stdString(), "public");
    EXPECT_EQ(kvdb.privateMeta.stdString(), "private");
    expectMembers(kvdb, {1}, {1});
}

TEST_F(KvdbTest, updateKvdb) {
    // incorrect kvdbId
    EXPECT_THROW({
        kvdbApi->updateKvdb(
            contextId(), users({1}), users({1}),
            core::Buffer::from("public"), core::Buffer::from("private"), 1, false, false
        );
    }, core::Exception);
    // incorrect users - the old test sent a mismatched key as `managers` here, so this case never ran
    EXPECT_THROW({
        kvdbApi->updateKvdb(
            kvdbId(1), usersWithMismatchedKey(), users({1}),
            core::Buffer::from("public"), core::Buffer::from("private"), 1, false, false
        );
    }, core::Exception);
    // incorrect managers
    EXPECT_THROW({
        kvdbApi->updateKvdb(
            kvdbId(1), users({1}), usersWithMismatchedKey(),
            core::Buffer::from("public"), core::Buffer::from("private"), 1, false, false
        );
    }, core::Exception);
    // no managers
    EXPECT_THROW({
        kvdbApi->updateKvdb(
            kvdbId(1), users({1}), {},
            core::Buffer::from("public"), core::Buffer::from("private"), 1, false, false
        );
    }, core::Exception);
    // incorrect version, force false
    EXPECT_THROW({
        kvdbApi->updateKvdb(
            kvdbId(2), users({1}), users({1}),
            core::Buffer::from("public"), core::Buffer::from("private"), 99, false, false
        );
    }, core::Exception);

    kvdb::Kvdb kvdb;
    // new users
    EXPECT_NO_THROW({
        kvdbApi->updateKvdb(
            kvdbId(1), users({1, 2}), users({1}),
            core::Buffer::from("public"), core::Buffer::from("private"), 1, false, false
        );
    });
    EXPECT_NO_THROW({ kvdb = kvdbApi->getKvdb(kvdbId(1)); });
    EXPECT_EQ(kvdb.statusCode, 0);
    EXPECT_EQ(kvdb.version, 2);
    EXPECT_EQ(kvdb.publicMeta.stdString(), "public");
    EXPECT_EQ(kvdb.privateMeta.stdString(), "private");
    expectMembers(kvdb, {1, 2}, {1});

    // new managers
    EXPECT_NO_THROW({
        kvdbApi->updateKvdb(
            kvdbId(1), users({1}), users({1, 2}),
            core::Buffer::from("public"), core::Buffer::from("private"), 2, false, false
        );
    });
    EXPECT_NO_THROW({ kvdb = kvdbApi->getKvdb(kvdbId(1)); });
    EXPECT_EQ(kvdb.version, 3);
    expectMembers(kvdb, {1}, {1, 2});

    // less users
    EXPECT_NO_THROW({
        kvdbApi->updateKvdb(
            kvdbId(2), users({1}), users({1, 2}),
            core::Buffer::from("public"), core::Buffer::from("private"), 1, false, false
        );
    });
    EXPECT_NO_THROW({ kvdb = kvdbApi->getKvdb(kvdbId(2)); });
    EXPECT_EQ(kvdb.version, 2);
    expectMembers(kvdb, {1}, {1, 2});

    // less managers
    EXPECT_NO_THROW({
        kvdbApi->updateKvdb(
            kvdbId(2), users({1}), users({1}),
            core::Buffer::from("public"), core::Buffer::from("private"), 2, false, false
        );
    });
    EXPECT_NO_THROW({ kvdb = kvdbApi->getKvdb(kvdbId(2)); });
    EXPECT_EQ(kvdb.version, 3);
    expectMembers(kvdb, {1}, {1});

    // incorrect version, force true
    EXPECT_NO_THROW({
        kvdbApi->updateKvdb(
            kvdbId(3), users({1}), users({1}),
            core::Buffer::from("public"), core::Buffer::from("private"), 99, true, false
        );
    });
    EXPECT_NO_THROW({ kvdb = kvdbApi->getKvdb(kvdbId(3)); });
    EXPECT_EQ(kvdb.statusCode, 0);
    EXPECT_EQ(kvdb.version, 2);
    expectMembers(kvdb, {1}, {1});
}

TEST_F(KvdbTest, rotateKvdbKeys) {
    // The dataset seeds no rotated kvdb, so this one is built here.
    const std::vector<core::UserWithPubKey> user_1 = users({1});
    std::string createdId;
    ASSERT_NO_THROW({
        createdId = kvdbApi->createKvdb(
            contextId(), user_1, user_1,
            core::Buffer::from("rotated_public"), core::Buffer::from("rotated_private")
        );
    });
    ASSERT_FALSE(createdId.empty());

    ASSERT_NO_THROW({
        kvdbApi->setEntry(
            createdId, "rotated_entry", core::Buffer::from("entry_public"),
            core::Buffer::from("entry_private"), core::Buffer::from("entry_data"), 0
        );
    });

    ASSERT_NO_THROW({ kvdbApi->rotateKvdbKeys(createdId, user_1, user_1, 0, true); });
    kvdb::Kvdb afterFirstRotation;
    ASSERT_NO_THROW({ afterFirstRotation = kvdbApi->getKvdb(createdId); });
    ASSERT_EQ(afterFirstRotation.statusCode, 0); // a single rotation has always been readable

    ASSERT_NO_THROW({ kvdbApi->rotateKvdbKeys(createdId, user_1, user_1, 0, true); });

    // Reconnect so ContainerKeyCache is empty - the reads below resolve purely from server state.
    disconnect();
    connectAs(ConnectionType::User1);

    kvdb::Kvdb kvdb;
    EXPECT_NO_THROW({ kvdb = kvdbApi->getKvdb(createdId); });
    EXPECT_EQ(kvdb.statusCode, 0);
    EXPECT_EQ(kvdb.publicMeta.stdString(), "rotated_public");
    EXPECT_EQ(kvdb.privateMeta.stdString(), "rotated_private");

    // Same decrypt path, batched.
    core::PagingList<kvdb::Kvdb> kvdbListResult;
    EXPECT_NO_THROW({
        kvdbListResult = kvdbApi->listKvdbs(contextId(), {.skip=0, .limit=100, .sortOrder="desc"});
    });
    bool foundInList = false;
    for(const auto& listed : kvdbListResult.readItems) {
        if(listed.kvdbId == createdId) {
            foundInList = true;
            EXPECT_EQ(listed.statusCode, 0);
            EXPECT_EQ(listed.privateMeta.stdString(), "rotated_private");
        }
    }
    EXPECT_TRUE(foundInList);

    // Control: an entry carries its own keyId, so it must stay readable across the rotations.
    kvdb::KvdbEntry entry;
    EXPECT_NO_THROW({ entry = kvdbApi->getEntry(createdId, "rotated_entry"); });
    EXPECT_EQ(entry.statusCode, 0);
    EXPECT_EQ(entry.data.stdString(), "entry_data");
}

TEST_F(KvdbTest, deleteKvdb) {
    // incorrect kvdbId
    EXPECT_THROW({ kvdbApi->deleteKvdb(contextId()); }, core::Exception);
    // as manager
    EXPECT_NO_THROW({ kvdbApi->deleteKvdb(kvdbId(1)); });
    EXPECT_THROW({ kvdbApi->getKvdb(kvdbId(1)); }, core::Exception);
    // as user
    disconnect();
    connectAs(ConnectionType::User2);
    EXPECT_THROW({ kvdbApi->deleteKvdb(kvdbId(3)); }, core::Exception);
}

TEST_F(KvdbTest, getKvdb) {
    // incorrect kvdbId
    EXPECT_THROW({ kvdbApi->getKvdb(contextId()); }, core::Exception);
    // correct kvdbId
    kvdb::Kvdb kvdb;
    EXPECT_NO_THROW({ kvdb = kvdbApi->getKvdb(kvdbId(1)); });
    expectMatchesDataset(kvdb, "Kvdb_1");
    expectMembers(kvdb, {1}, {1});
}

TEST_F(KvdbTest, listKvdbs) {
    // incorrect contextId
    EXPECT_THROW({
        kvdbApi->listKvdbs(kvdbId(1), {.skip=0, .limit=1, .sortOrder="desc"});
    }, core::Exception);
    // limit < 0
    EXPECT_THROW({
        kvdbApi->listKvdbs(contextId(), {.skip=0, .limit=-1, .sortOrder="desc"});
    }, core::Exception);
    // limit == 0
    EXPECT_THROW({
        kvdbApi->listKvdbs(contextId(), {.skip=0, .limit=0, .sortOrder="desc"});
    }, core::Exception);
    // incorrect sortOrder
    EXPECT_THROW({
        kvdbApi->listKvdbs(contextId(), {.skip=0, .limit=1, .sortOrder="BLACH"});
    }, core::Exception);
    // incorrect lastId
    EXPECT_THROW({
        kvdbApi->listKvdbs(
            contextId(), {.skip=0, .limit=1, .sortOrder="desc", .lastId=contextId()}
        );
    }, core::Exception);
    // incorrect queryAsJson
    EXPECT_THROW({
        kvdbApi->listKvdbs(
            contextId(),
            {.skip=0, .limit=1, .sortOrder="desc", .lastId=std::nullopt, .queryAsJson="{BLACH,}"}
        );
    }, core::InvalidParamsException);
    // incorrect sortBy
    EXPECT_THROW({
        kvdbApi->listKvdbs(
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
    core::PagingList<kvdb::Kvdb> listKvdbs;
    EXPECT_NO_THROW({
        listKvdbs = kvdbApi->listKvdbs(contextId(), {.skip=4, .limit=1, .sortOrder="desc"});
    });
    EXPECT_EQ(listKvdbs.totalAvailable, 3);
    EXPECT_EQ(listKvdbs.readItems.size(), 0);

    // newest first
    EXPECT_NO_THROW({
        listKvdbs = kvdbApi->listKvdbs(contextId(), {.skip=0, .limit=1, .sortOrder="desc"});
    });
    EXPECT_EQ(listKvdbs.totalAvailable, 3);
    ASSERT_EQ(listKvdbs.readItems.size(), 1);
    expectMatchesDataset(listKvdbs.readItems[0], "Kvdb_3");
    expectMembers(listKvdbs.readItems[0], {1, 2}, {1});

    // paged, ascending
    EXPECT_NO_THROW({
        listKvdbs = kvdbApi->listKvdbs(contextId(), {.skip=1, .limit=3, .sortOrder="asc"});
    });
    EXPECT_EQ(listKvdbs.totalAvailable, 3);
    ASSERT_EQ(listKvdbs.readItems.size(), 2);
    expectMatchesDataset(listKvdbs.readItems[0], "Kvdb_2");
    expectMembers(listKvdbs.readItems[0], {1, 2}, {1, 2});
    expectMatchesDataset(listKvdbs.readItems[1], "Kvdb_3");
    expectMembers(listKvdbs.readItems[1], {1, 2}, {1});
}

TEST_F(KvdbTest, getEntry) {
    // incorrect key
    EXPECT_THROW({ kvdbApi->getEntry(kvdbId(1), contextId()); }, core::Exception);
    // a forced key generation must not cost access to entries written before it
    forceNewKvdbKey(kvdbId(1));
    kvdb::KvdbEntry entry;
    EXPECT_NO_THROW({ entry = kvdbApi->getEntry(kvdbId(1), entryKey(2)); });
    expectMatchesDataset(entry, "KvdbEntry_2");
}

TEST_F(KvdbTest, hasEntry) {
    bool result = true;
    EXPECT_NO_THROW({ result = kvdbApi->hasEntry(kvdbId(1), contextId()); });
    EXPECT_EQ(result, false);
    EXPECT_NO_THROW({ result = kvdbApi->hasEntry(kvdbId(1), entryKey(2)); });
    EXPECT_EQ(result, true);
}

TEST_F(KvdbTest, listEntriesKeys) {
    // incorrect kvdbId
    EXPECT_THROW({
        kvdbApi->listEntriesKeys(entryKey(2), {.skip=0, .limit=1, .sortOrder="desc"});
    }, core::Exception);
    // limit < 0
    EXPECT_THROW({
        kvdbApi->listEntriesKeys(kvdbId(1), {.skip=0, .limit=-1, .sortOrder="desc"});
    }, core::Exception);
    // limit == 0
    EXPECT_THROW({
        kvdbApi->listEntriesKeys(kvdbId(1), {.skip=0, .limit=0, .sortOrder="desc"});
    }, core::Exception);
    // incorrect sortOrder
    EXPECT_THROW({
        kvdbApi->listEntriesKeys(kvdbId(1), {.skip=0, .limit=1, .sortOrder="BLACH"});
    }, core::Exception);
    // incorrect sortBy
    EXPECT_THROW({
        kvdbApi->listEntriesKeys(
            kvdbId(1),
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
    core::PagingList<std::string> listEntriesKeys;
    EXPECT_NO_THROW({
        listEntriesKeys = kvdbApi->listEntriesKeys(kvdbId(1), {.skip=4, .limit=1, .sortOrder="desc"});
    });
    EXPECT_EQ(listEntriesKeys.totalAvailable, 2);
    EXPECT_EQ(listEntriesKeys.readItems.size(), 0);

    // oldest, reached by skipping the newest
    EXPECT_NO_THROW({
        listEntriesKeys = kvdbApi->listEntriesKeys(kvdbId(1), {.skip=1, .limit=1, .sortOrder="desc"});
    });
    EXPECT_EQ(listEntriesKeys.totalAvailable, 2);
    ASSERT_EQ(listEntriesKeys.readItems.size(), 1);
    EXPECT_EQ(listEntriesKeys.readItems[0], entryKey(1));

    // after a forced key generation, both keys still come back
    forceNewKvdbKey(kvdbId(1));
    EXPECT_NO_THROW({
        listEntriesKeys = kvdbApi->listEntriesKeys(
            kvdbId(1),
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
    EXPECT_EQ(listEntriesKeys.totalAvailable, 2);
    ASSERT_EQ(listEntriesKeys.readItems.size(), 2);
    EXPECT_EQ(listEntriesKeys.readItems[0], entryKey(1));
    EXPECT_EQ(listEntriesKeys.readItems[1], entryKey(2));
}

TEST_F(KvdbTest, listEntries) {
    // incorrect kvdbId
    EXPECT_THROW({
        kvdbApi->listEntries(entryKey(2), {.skip=0, .limit=1, .sortOrder="desc"});
    }, core::Exception);
    // limit < 0
    EXPECT_THROW({
        kvdbApi->listEntries(kvdbId(1), {.skip=0, .limit=-1, .sortOrder="desc"});
    }, core::Exception);
    // limit == 0
    EXPECT_THROW({
        kvdbApi->listEntries(kvdbId(1), {.skip=0, .limit=0, .sortOrder="desc"});
    }, core::Exception);
    // incorrect sortOrder
    EXPECT_THROW({
        kvdbApi->listEntries(kvdbId(1), {.skip=0, .limit=1, .sortOrder="BLACH"});
    }, core::Exception);
    // incorrect queryAsJson
    EXPECT_THROW({
        kvdbApi->listEntries(
            kvdbId(1),
            {.skip=0, .limit=1, .sortOrder="desc", .lastId=std::nullopt, .queryAsJson="{BLACH,}"}
        );
    }, core::InvalidParamsException);

    // skip past the end
    core::PagingList<kvdb::KvdbEntry> listEntries;
    EXPECT_NO_THROW({
        listEntries = kvdbApi->listEntries(kvdbId(1), {.skip=4, .limit=1, .sortOrder="desc"});
    });
    EXPECT_EQ(listEntries.totalAvailable, 2);
    EXPECT_EQ(listEntries.readItems.size(), 0);

    // oldest, reached by skipping the newest
    EXPECT_NO_THROW({
        listEntries = kvdbApi->listEntries(kvdbId(1), {.skip=1, .limit=1, .sortOrder="desc"});
    });
    EXPECT_EQ(listEntries.totalAvailable, 2);
    ASSERT_EQ(listEntries.readItems.size(), 1);
    expectMatchesDataset(listEntries.readItems[0], "KvdbEntry_1");

    // after a forced key generation, both entries still decrypt
    forceNewKvdbKey(kvdbId(1));
    EXPECT_NO_THROW({
        listEntries = kvdbApi->listEntries(
            kvdbId(1),
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
    EXPECT_EQ(listEntries.totalAvailable, 2);
    ASSERT_EQ(listEntries.readItems.size(), 2);
    expectMatchesDataset(listEntries.readItems[0], "KvdbEntry_1");
    expectMatchesDataset(listEntries.readItems[1], "KvdbEntry_2");
}

TEST_F(KvdbTest, setEntry) {
    kvdb::KvdbEntry entry;
    // a new key, at version 0
    EXPECT_NO_THROW({
        kvdbApi->setEntry(
            kvdbId(2), "kvdb_entry_key", core::Buffer::from("kvdb_entry_1_publicMeta"),
            core::Buffer::from("kvdb_entry_1_privateMeta"), core::Buffer::from("kvdb_entry_1_data"), 0
        );
    });
    EXPECT_NO_THROW({ entry = kvdbApi->getEntry(kvdbId(2), "kvdb_entry_key"); });
    EXPECT_EQ(entry.info.kvdbId, kvdbId(2));
    EXPECT_EQ(entry.info.key, "kvdb_entry_key");
    EXPECT_EQ(entry.version, 1);
    EXPECT_EQ(entry.publicMeta.stdString(), "kvdb_entry_1_publicMeta");
    EXPECT_EQ(entry.privateMeta.stdString(), "kvdb_entry_1_privateMeta");
    EXPECT_EQ(entry.data.stdString(), "kvdb_entry_1_data");
    EXPECT_EQ(entry.statusCode, 0);

    // overwriting it at a stale version is refused
    EXPECT_THROW({
        kvdbApi->setEntry(
            kvdbId(2), "kvdb_entry_key", core::Buffer::from("kvdb_entry_1_publicMeta"),
            core::Buffer::from("kvdb_entry_1_privateMeta"), core::Buffer::from("kvdb_entry_1_data"), 0
        );
    }, core::Exception);
    // at the current version it is not
    EXPECT_NO_THROW({
        kvdbApi->setEntry(
            kvdbId(2), "kvdb_entry_key", core::Buffer::from("kvdb_entry_1_publicMeta"),
            core::Buffer::from("kvdb_entry_1_privateMeta"), core::Buffer::from("kvdb_entry_1_data_v2"), 1
        );
    });
    EXPECT_NO_THROW({ entry = kvdbApi->getEntry(kvdbId(2), "kvdb_entry_key"); });
    EXPECT_EQ(entry.version, 2);
    EXPECT_EQ(entry.data.stdString(), "kvdb_entry_1_data_v2");
    EXPECT_EQ(entry.statusCode, 0);

    // a non-member may not write, a fellow member may overwrite somebody else's entry
    disconnect();
    connectAs(ConnectionType::User2);
    EXPECT_THROW({
        kvdbApi->setEntry(
            kvdbId(1), entryKey(1), core::Buffer::from("kvdb_entry_1_publicMeta"),
            core::Buffer::from("kvdb_entry_1_privateMeta"), core::Buffer::from("kvdb_entry_1_data"), 1
        );
    }, core::Exception);
    EXPECT_NO_THROW({
        kvdbApi->setEntry(
            kvdbId(2), "kvdb_entry_key", core::Buffer::from("kvdb_entry_1_publicMeta"),
            core::Buffer::from("kvdb_entry_1_privateMeta"), core::Buffer::from("kvdb_entry_1_data_v3"), 2
        );
    });
    EXPECT_NO_THROW({ entry = kvdbApi->getEntry(kvdbId(2), "kvdb_entry_key"); });
    EXPECT_EQ(entry.info.kvdbId, kvdbId(2));
    EXPECT_EQ(entry.info.key, "kvdb_entry_key");
    EXPECT_EQ(entry.version, 3);
    EXPECT_EQ(entry.publicMeta.stdString(), "kvdb_entry_1_publicMeta");
    EXPECT_EQ(entry.privateMeta.stdString(), "kvdb_entry_1_privateMeta");
    EXPECT_EQ(entry.data.stdString(), "kvdb_entry_1_data_v3");
    EXPECT_EQ(entry.statusCode, 0);

    // with a stale kvdb in the cache: the write below only succeeds if the new key is picked up
    disconnect();
    connectAs(ConnectionType::User1);
    EXPECT_NO_THROW({ kvdbApi->getKvdb(kvdbId(1)); });
    forceNewKvdbKey(kvdbId(1));
    EXPECT_NO_THROW({
        kvdbApi->setEntry(
            kvdbId(1), "test", core::Buffer::from("publicMeta"),
            core::Buffer::from("privateMeta"), core::Buffer::from("data"), 0
        );
    });
    EXPECT_NO_THROW({ entry = kvdbApi->getEntry(kvdbId(1), "test"); });
    EXPECT_EQ(entry.statusCode, 0);
    EXPECT_EQ(entry.data.stdString(), "data");
    EXPECT_EQ(entry.privateMeta.stdString(), "privateMeta");
    EXPECT_EQ(entry.publicMeta.stdString(), "publicMeta");
}

TEST_F(KvdbTest, deleteEntry) {
    // incorrect key
    EXPECT_THROW({ kvdbApi->deleteEntry(kvdbId(1), kvdbId(1)); }, core::Exception);
    // user_2 joins as a plain user and may not delete somebody else's entry
    EXPECT_NO_THROW({
        kvdbApi->updateKvdb(
            kvdbId(1), users({1, 2}), users({1}),
            core::Buffer::from("public"), core::Buffer::from("private"), 1, true, false
        );
    });
    disconnect();
    connectAs(ConnectionType::User2);
    EXPECT_THROW({ kvdbApi->deleteEntry(kvdbId(1), entryKey(2)); }, core::Exception);

    // promoted to manager, it may
    disconnect();
    connectAs(ConnectionType::User1);
    EXPECT_NO_THROW({
        kvdbApi->updateKvdb(
            kvdbId(1), users({1, 2}), users({1, 2}),
            core::Buffer::from("public"), core::Buffer::from("private"), 1, true, false
        );
    });
    disconnect();
    connectAs(ConnectionType::User2);
    EXPECT_NO_THROW({
        kvdbApi->updateKvdb(
            kvdbId(1), users({1, 2}), users({2}),
            core::Buffer::from("public"), core::Buffer::from("private"), 1, true, false
        );
    });
    // as the author
    disconnect();
    connectAs(ConnectionType::User1);
    EXPECT_NO_THROW({ kvdbApi->deleteEntry(kvdbId(1), entryKey(2)); });
    // as a manager who did not write it
    disconnect();
    connectAs(ConnectionType::User2);
    EXPECT_NO_THROW({ kvdbApi->deleteEntry(kvdbId(1), entryKey(1)); });
}

TEST_F(KvdbTest, deleteEntries) {
    // nothing to delete
    EXPECT_NO_THROW({ kvdbApi->deleteEntries(kvdbId(1), std::vector<std::string>()); });
    // a batch where one key does not exist: the result reports per key rather than throwing
    std::map<std::string, bool> deleteResult;
    EXPECT_NO_THROW({
        deleteResult = kvdbApi->deleteEntries(
            kvdbId(1), std::vector<std::string>({"Error", entryKey(1), entryKey(2)})
        );
    });
    EXPECT_EQ(deleteResult["Error"], false);
    EXPECT_EQ(deleteResult[entryKey(1)], true);
    EXPECT_EQ(deleteResult[entryKey(2)], true);

    EXPECT_THROW({ kvdbApi->getEntry(kvdbId(1), entryKey(1)); }, core::Exception);
    EXPECT_THROW({ kvdbApi->getEntry(kvdbId(1), entryKey(2)); }, core::Exception);
}

TEST_F(KvdbTest, userValidator_false) {
    // A verifier that rejects everyone leaves reads succeeding but undecrypted, and blocks every write that
    // would have to trust a key it cannot verify.
    auto verifier = std::make_shared<core::FalseUserVerifierInterface>();
    connection->setUserVerifier(verifier);
    const auto failureCode = core::UserVerificationFailureException().getCode();

    EXPECT_NO_THROW({
        auto kvdb = kvdbApi->getKvdb(kvdbId(1));
        EXPECT_EQ(kvdb.statusCode, failureCode);
    });
    EXPECT_NO_THROW({
        auto kvdbs = kvdbApi->listKvdbs(contextId(), {.skip=0, .limit=1, .sortOrder="desc"});
        ASSERT_EQ(kvdbs.readItems.size(), 1);
        EXPECT_EQ(kvdbs.readItems[0].statusCode, failureCode);
    });
    EXPECT_NO_THROW({
        kvdbApi->createKvdb(
            contextId(), users({1}), users({1}),
            core::Buffer::from("public"), core::Buffer::from("private")
        );
    });
    EXPECT_THROW({
        kvdbApi->updateKvdb(
            kvdbId(1), users({1}), users({1}),
            core::Buffer::from("public"), core::Buffer::from("private"), 1, true, true
        );
    }, core::Exception);
    EXPECT_NO_THROW({ kvdbApi->deleteKvdb(kvdbId(2)); });
    EXPECT_NO_THROW({
        auto entry = kvdbApi->getEntry(reader->getString("KvdbEntry_1.info_kvdbId"), entryKey(1));
        EXPECT_EQ(entry.statusCode, failureCode);
    });
    EXPECT_NO_THROW({
        auto entries = kvdbApi->listEntries(kvdbId(1), {.skip=0, .limit=1, .sortOrder="desc"});
        ASSERT_EQ(entries.readItems.size(), 1);
        EXPECT_EQ(entries.readItems[0].statusCode, failureCode);
    });
    EXPECT_THROW({
        kvdbApi->setEntry(
            kvdbId(1), "key", core::Buffer::from("pubMeta"),
            core::Buffer::from("privMeta"), core::Buffer::from("data")
        );
    }, core::Exception);
    EXPECT_NO_THROW({
        kvdbApi->deleteEntry(reader->getString("KvdbEntry_2.info_kvdbId"), entryKey(2));
    });
}
