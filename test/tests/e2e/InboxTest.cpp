/**
 * One test per InboxApi function, each covering that function's whole contract: rejected input, accepted
 * input, and the state it leaves behind. Every other InboxApi function is assumed to work, so getInbox and
 * listEntries are used freely as oracles without that counting as a second subject.
 *
 * Assertions come from the dataset wherever the dataset records the value - expectMatchesDataset compares a
 * whole Inbox or InboxEntry, files included, against its ini section. Membership is not in the ini, so
 * expectMembers spells it out.
 *
 * One gap this file does not close, pre-existing: rotateInboxKeys has no test, where the Thread, Store and
 * Kvdb modules each have one for their equivalent.
 */
#include <gtest/gtest.h>
#include "BaseTest.hpp"
#include <privmx/endpoint/core/Exception.hpp>
#include <Poco/Util/IniFileConfiguration.h>
#include <privmx/crypto/Crypto.hpp>
#include <privmx/endpoint/core/EventQueueImpl.hpp>
#include <privmx/endpoint/core/VarSerializer.hpp>
#include <privmx/endpoint/core/Connection.hpp>
#include <privmx/endpoint/store/StoreApi.hpp>
#include <privmx/endpoint/store/VarSerializer.hpp>
#include <privmx/endpoint/thread/ThreadApi.hpp>
#include <privmx/endpoint/thread/VarSerializer.hpp>
#include <privmx/endpoint/inbox/InboxApi.hpp>
#include <privmx/endpoint/inbox/VarSerializer.hpp>
#include <privmx/endpoint/inbox/InboxException.hpp>
#include <privmx/endpoint/core/CoreException.hpp>
#include <privmx/endpoint/core/UserVerifierInterface.hpp>

using namespace privmx::endpoint;
using namespace privmx::utils;

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
        reader = new Poco::Util::IniFileConfiguration(INI_FILE_PATH);
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

    std::string inboxId(int index) {
        return reader->getString("Inbox_" + std::to_string(index) + ".inboxId");
    }

    std::string entryId(int index) {
        return reader->getString("Entry_" + std::to_string(index) + ".entryId");
    }

    std::string contextId() {
        return reader->getString("Context_1.contextId");
    }

    // Every Inbox field the dataset records, so a caller asserts the whole shape in one line.
    void expectMatchesDataset(const inbox::Inbox& inbox, const std::string& section) {
        EXPECT_EQ(inbox.inboxId, reader->getString(section + ".inboxId"));
        EXPECT_EQ(inbox.contextId, reader->getString(section + ".contextId"));
        EXPECT_EQ(inbox.createDate, reader->getInt64(section + ".createDate"));
        EXPECT_EQ(inbox.creator, reader->getString(section + ".creator"));
        EXPECT_EQ(inbox.lastModificationDate, reader->getInt64(section + ".lastModificationDate"));
        EXPECT_EQ(inbox.lastModifier, reader->getString(section + ".lastModifier"));
        EXPECT_EQ(inbox.version, reader->getInt64(section + ".version"));
        EXPECT_EQ(inbox.publicMeta.stdString(), Hex::toString(reader->getString(section + ".publicMeta_inHex")));
        EXPECT_EQ(
            inbox.publicMeta.stdString(), Hex::toString(reader->getString(section + ".uploaded_publicMeta_inHex"))
        );
        EXPECT_EQ(inbox.privateMeta.stdString(), Hex::toString(reader->getString(section + ".privateMeta_inHex")));
        EXPECT_EQ(
            inbox.privateMeta.stdString(), Hex::toString(reader->getString(section + ".uploaded_privateMeta_inHex"))
        );
        EXPECT_EQ(inbox.statusCode, 0);
    }

    // `fileCount` is spelled out because the ini records the files by index but not how many there are.
    void expectMatchesDataset(const inbox::InboxEntry& entry, const std::string& section, size_t fileCount) {
        EXPECT_EQ(entry.entryId, reader->getString(section + ".entryId"));
        EXPECT_EQ(entry.inboxId, reader->getString(section + ".inboxId"));
        EXPECT_EQ(entry.data.stdString(), Hex::toString(reader->getString(section + ".data_inHex")));
        EXPECT_EQ(entry.data.stdString(), Hex::toString(reader->getString(section + ".uploaded_data_inHex")));
        EXPECT_EQ(entry.authorPubKey, reader->getString(section + ".authorPubKey"));
        EXPECT_EQ(entry.createDate, reader->getInt64(section + ".createDate"));
        EXPECT_EQ(entry.statusCode, 0);
        ASSERT_EQ(entry.files.size(), fileCount);
        for(size_t i = 0; i < fileCount; ++i) {
            const std::string p = section + ".file_" + std::to_string(i) + "_";
            const std::string up = section + ".uploaded_file_" + std::to_string(i) + "_";
            const store::File& file = entry.files[i];
            EXPECT_EQ(file.info.storeId, reader->getString(p + "info_storeId"));
            EXPECT_EQ(file.info.fileId, reader->getString(p + "info_fileId"));
            EXPECT_EQ(file.info.createDate, reader->getInt64(p + "info_createDate"));
            EXPECT_EQ(file.info.author, reader->getString(p + "info_author"));
            EXPECT_EQ(file.authorPubKey, reader->getString(p + "authorPubKey"));
            EXPECT_EQ(file.statusCode, 0);
            EXPECT_EQ(file.publicMeta.stdString(), Hex::toString(reader->getString(p + "publicMeta_inHex")));
            EXPECT_EQ(file.publicMeta.stdString(), Hex::toString(reader->getString(up + "publicMeta_inHex")));
            EXPECT_EQ(file.privateMeta.stdString(), Hex::toString(reader->getString(p + "privateMeta_inHex")));
            EXPECT_EQ(file.privateMeta.stdString(), Hex::toString(reader->getString(up + "privateMeta_inHex")));
            EXPECT_EQ(file.size, reader->getInt64(p + "size"));
            EXPECT_EQ(file.size, reader->getInt64(up + "size"));
        }
    }

    // The roster is not in the ini, so it is spelled out by user index.
    void expectMembers(
        const inbox::Inbox& inbox, std::initializer_list<int> userIndexes,
        std::initializer_list<int> managerIndexes
    ) {
        ASSERT_EQ(inbox.users.size(), userIndexes.size());
        size_t i = 0;
        for(int index : userIndexes) {
            EXPECT_EQ(inbox.users[i++], user(index).userId);
        }
        ASSERT_EQ(inbox.managers.size(), managerIndexes.size());
        i = 0;
        for(int index : managerIndexes) {
            EXPECT_EQ(inbox.managers[i++], user(index).userId);
        }
    }

    // An inbox carries no item policy, so this is the whole shape these tests use.
    core::ContainerPolicyWithoutItem ownerOnlyPolicy() {
        core::ContainerPolicyWithoutItem policy;
        policy.get = "owner";
        policy.update = "owner";
        policy.delete_ = "owner";
        policy.updatePolicy = "owner";
        policy.updaterCanBeRemovedFromManagers = "no";
        policy.ownerCanBeRemovedFromManagers = "no";
        return policy;
    }

    void expectPolicy(const inbox::Inbox& inbox, const core::ContainerPolicyWithoutItem& policy) {
        EXPECT_EQ(inbox.policy.get, policy.get);
        EXPECT_EQ(inbox.policy.update, policy.update);
        EXPECT_EQ(inbox.policy.delete_, policy.delete_);
        EXPECT_EQ(inbox.policy.updatePolicy, policy.updatePolicy);
        EXPECT_EQ(inbox.policy.updaterCanBeRemovedFromManagers, policy.updaterCanBeRemovedFromManagers);
        EXPECT_EQ(inbox.policy.ownerCanBeRemovedFromManagers, policy.ownerCanBeRemovedFromManagers);
    }

    // Forces a new inbox key, which several tests need before reading or writing through the old one.
    void forceNewInboxKey(const std::string& id) {
        EXPECT_NO_THROW({
            inboxApi->updateInbox(
                id, users({1}), users({1}),
                core::Buffer::from("public"), core::Buffer::from("private"), std::nullopt, 1, true, true
            );
        });
    }

    // Sends one entry carrying two files - one empty, one 128 KiB - and returns the bytes written into the
    // second, so the caller can compare them after reading that file back.
    std::string sendEntryWithTwoFiles(const std::string& id) {
        int64_t fileHandle_1 = 0;
        int64_t fileHandle_2 = 0;
        EXPECT_NO_THROW({
            fileHandle_1 = inboxApi->createFileHandle(
                core::Buffer::from("publicMeta_1"), core::Buffer::from("privateMeta_1"), 0
            );
        });
        EXPECT_NO_THROW({
            fileHandle_2 = inboxApi->createFileHandle(
                core::Buffer::from("publicMeta_2"), core::Buffer::from("privateMeta_2"), 1024*128
            );
        });
        EXPECT_NE(fileHandle_1, 0);
        EXPECT_NE(fileHandle_2, 0);

        int64_t inboxHandle = 0;
        EXPECT_NO_THROW({
            inboxHandle = inboxApi->prepareEntry(
                id, core::Buffer::from("test_sendEntry"), {fileHandle_1, fileHandle_2},
                reader->getString("Login.user_1_privKey")
            );
        });
        EXPECT_NE(inboxHandle, 0);
        // a file handle belonging to a prepared entry cannot be closed on its own
        EXPECT_THROW({ inboxApi->closeFile(fileHandle_1); }, core::Exception);

        std::string sent;
        EXPECT_NO_THROW({
            for(int i = 0; i < 128; i++) {
                std::string chunk = privmx::crypto::Crypto::randomBytes(1024);
                inboxApi->writeToFile(inboxHandle, fileHandle_2, core::Buffer::from(chunk));
                sent += chunk;
            }
        });
        EXPECT_NO_THROW({ inboxApi->sendEntry(inboxHandle); });
        return sent;
    }

    // Reads one entry back out of `id` and checks both its files, the 128 KiB payload included.
    void expectEntryWithTwoFiles(
        const std::string& id, const std::string& expectedFileData, int64_t expectedTotal,
        const std::string& sortOrder
    ) {
        core::PagingList<inbox::InboxEntry> entries;
        EXPECT_NO_THROW({
            entries = inboxApi->listEntries(id, {.skip=0, .limit=1, .sortOrder=sortOrder});
        });
        EXPECT_EQ(entries.totalAvailable, expectedTotal);
        ASSERT_EQ(entries.readItems.size(), 1);
        const inbox::InboxEntry entry = entries.readItems[0];
        EXPECT_EQ(entry.inboxId, id);
        EXPECT_EQ(entry.data.stdString(), "test_sendEntry");
        ASSERT_EQ(entry.files.size(), 2);
        EXPECT_EQ(entry.files[0].statusCode, 0);
        EXPECT_EQ(entry.files[0].publicMeta.stdString(), "publicMeta_1");
        EXPECT_EQ(entry.files[0].privateMeta.stdString(), "privateMeta_1");
        EXPECT_EQ(entry.files[0].size, 0);
        EXPECT_EQ(entry.files[1].statusCode, 0);
        EXPECT_EQ(entry.files[1].publicMeta.stdString(), "publicMeta_2");
        EXPECT_EQ(entry.files[1].privateMeta.stdString(), "privateMeta_2");
        EXPECT_EQ(entry.files[1].size, 128*1024);

        int64_t readHandle = 0;
        EXPECT_NO_THROW({ readHandle = inboxApi->openFile(entry.files[1].info.fileId); });
        ASSERT_NE(readHandle, 0);
        std::string read;
        for(int i = 0; i < 128; i++) {
            read += inboxApi->readFromFile(readHandle, 1024).stdString();
        }
        EXPECT_EQ(read, expectedFileData);
        EXPECT_NO_THROW({ inboxApi->closeFile(readHandle); });
    }

    std::shared_ptr<core::Connection> connection;
    std::shared_ptr<thread::ThreadApi> threadApi;
    std::shared_ptr<store::StoreApi> storeApi;
    std::shared_ptr<inbox::InboxApi> inboxApi;
    Poco::Util::IniFileConfiguration::Ptr reader;
    core::VarSerializer _serializer = core::VarSerializer({});
};

TEST_F(InboxTest, createInbox) {
    // incorrect contextId
    EXPECT_THROW({
        inboxApi->createInbox(
            inboxId(1), users({1}), users({1}),
            core::Buffer::from("public"), core::Buffer::from("private"), std::nullopt
        );
    }, core::Exception);
    // incorrect users
    EXPECT_THROW({
        inboxApi->createInbox(
            contextId(), usersWithMismatchedKey(), users({1}),
            core::Buffer::from("public"), core::Buffer::from("private"), std::nullopt
        );
    }, core::Exception);
    // incorrect managers
    EXPECT_THROW({
        inboxApi->createInbox(
            contextId(), users({1}), usersWithMismatchedKey(),
            core::Buffer::from("public"), core::Buffer::from("private"), std::nullopt
        );
    }, core::Exception);
    // no managers
    EXPECT_THROW({
        inboxApi->createInbox(
            contextId(), users({1}), {},
            core::Buffer::from("public"), core::Buffer::from("private"), std::nullopt
        );
    }, core::Exception);

    // different users and managers
    std::string createdId;
    inbox::Inbox inbox;
    EXPECT_NO_THROW({
        createdId = inboxApi->createInbox(
            contextId(), users({2}), users({1}),
            core::Buffer::from("public"), core::Buffer::from("private"), std::nullopt
        );
    });
    ASSERT_FALSE(createdId.empty());
    EXPECT_NO_THROW({ inbox = inboxApi->getInbox(createdId); });
    EXPECT_EQ(inbox.statusCode, 0);
    EXPECT_EQ(inbox.contextId, contextId());
    EXPECT_EQ(inbox.publicMeta.stdString(), "public");
    EXPECT_EQ(inbox.privateMeta.stdString(), "private");
    expectMembers(inbox, {2}, {1});

    // same users and managers
    EXPECT_NO_THROW({
        createdId = inboxApi->createInbox(
            contextId(), users({1}), users({1}),
            core::Buffer::from("public"), core::Buffer::from("private"), std::nullopt
        );
    });
    ASSERT_FALSE(createdId.empty());
    EXPECT_NO_THROW({ inbox = inboxApi->getInbox(createdId); });
    EXPECT_EQ(inbox.statusCode, 0);
    EXPECT_EQ(inbox.contextId, contextId());
    expectMembers(inbox, {1}, {1});

    // with a policy, which closes the container to everyone but its owner
    const core::ContainerPolicyWithoutItem policy = ownerOnlyPolicy();
    EXPECT_NO_THROW({
        createdId = inboxApi->createInbox(
            contextId(), users({1, 2}), users({1, 2}),
            core::Buffer::from("public"), core::Buffer::from("private"), std::nullopt, policy
        );
    });
    ASSERT_FALSE(createdId.empty());
    EXPECT_NO_THROW({ inbox = inboxApi->getInbox(createdId); });
    expectMembers(inbox, {1, 2}, {1, 2});
    expectPolicy(inbox, policy);
    disconnect();
    connectAs(ConnectionType::User2);
    EXPECT_THROW({ inboxApi->getInbox(createdId); }, core::Exception);
}

TEST_F(InboxTest, updateInbox) {
    // incorrect inboxId
    EXPECT_THROW({
        inboxApi->updateInbox(
            contextId(), users({1}), users({1}),
            core::Buffer::from("public"), core::Buffer::from("private"), std::nullopt, 1, false, false
        );
    }, core::Exception);
    // incorrect users
    EXPECT_THROW({
        inboxApi->updateInbox(
            inboxId(1), usersWithMismatchedKey(), users({1}),
            core::Buffer::from("public"), core::Buffer::from("private"), std::nullopt, 1, false, false
        );
    }, core::Exception);
    // incorrect managers
    EXPECT_THROW({
        inboxApi->updateInbox(
            inboxId(1), users({1}), usersWithMismatchedKey(),
            core::Buffer::from("public"), core::Buffer::from("private"), std::nullopt, 1, false, false
        );
    }, core::Exception);
    // no managers
    EXPECT_THROW({
        inboxApi->updateInbox(
            inboxId(1), users({1}), {},
            core::Buffer::from("public"), core::Buffer::from("private"), std::nullopt, 1, false, false
        );
    }, core::Exception);
    // incorrect version, force false - the old test sent no managers here too, so it never reached the
    // version check
    EXPECT_THROW({
        inboxApi->updateInbox(
            inboxId(1), users({1}), users({1}),
            core::Buffer::from("public"), core::Buffer::from("private"), std::nullopt, 99, false, false
        );
    }, core::Exception);

    inbox::Inbox inbox;
    // new users
    EXPECT_NO_THROW({
        inboxApi->updateInbox(
            inboxId(1), users({1, 2}), users({1}),
            core::Buffer::from("public"), core::Buffer::from("private"), std::nullopt, 1, false, false
        );
    });
    EXPECT_NO_THROW({ inbox = inboxApi->getInbox(inboxId(1)); });
    EXPECT_EQ(inbox.contextId, contextId());
    EXPECT_EQ(inbox.version, 2);
    EXPECT_EQ(inbox.publicMeta.stdString(), "public");
    EXPECT_EQ(inbox.privateMeta.stdString(), "private");
    expectMembers(inbox, {1, 2}, {1});

    // new managers
    EXPECT_NO_THROW({
        inboxApi->updateInbox(
            inboxId(1), users({1}), users({1, 2}),
            core::Buffer::from("public"), core::Buffer::from("private"), std::nullopt, 2, false, false
        );
    });
    EXPECT_NO_THROW({ inbox = inboxApi->getInbox(inboxId(1)); });
    EXPECT_EQ(inbox.version, 3);
    expectMembers(inbox, {1}, {1, 2});

    // less managers
    EXPECT_NO_THROW({
        inboxApi->updateInbox(
            inboxId(2), users({1, 2}), users({1}),
            core::Buffer::from("public"), core::Buffer::from("private"), std::nullopt, 1, false, false
        );
    });
    EXPECT_NO_THROW({ inbox = inboxApi->getInbox(inboxId(2)); });
    EXPECT_EQ(inbox.version, 2);
    expectMembers(inbox, {1, 2}, {1});

    // less users
    EXPECT_NO_THROW({
        inboxApi->updateInbox(
            inboxId(2), users({1}), users({1, 2}),
            core::Buffer::from("public"), core::Buffer::from("private"), std::nullopt, 2, false, false
        );
    });
    EXPECT_NO_THROW({ inbox = inboxApi->getInbox(inboxId(2)); });
    EXPECT_EQ(inbox.version, 3);
    expectMembers(inbox, {1}, {1, 2});

    // incorrect version, force true
    EXPECT_NO_THROW({
        inboxApi->updateInbox(
            inboxId(3), users({1}), users({1}),
            core::Buffer::from("public"), core::Buffer::from("private"), std::nullopt, 99, true, false
        );
    });
    EXPECT_NO_THROW({ inbox = inboxApi->getInbox(inboxId(3)); });
    EXPECT_EQ(inbox.version, 2);
    expectMembers(inbox, {1}, {1});
}

TEST_F(InboxTest, updateInbox_rewraps_keys_for_a_newly_added_user) {
    // A member added by an update, with a forced key generation, must still reach entries sent before it.
    EXPECT_NO_THROW({
        inboxApi->updateInbox(
            inboxId(1), users({1, 2}), users({1, 2}),
            core::Buffer::from("public"), core::Buffer::from("private"), std::nullopt, 1, true, true
        );
    });
    disconnect();
    connectAs(ConnectionType::User2);
    inbox::InboxEntry entry;
    EXPECT_NO_THROW({ entry = inboxApi->readEntry(entryId(1)); });
    EXPECT_EQ(entry.statusCode, 0);
}

TEST_F(InboxTest, updateInbox_policy) {
    const core::ContainerPolicyWithoutItem policy = ownerOnlyPolicy();
    EXPECT_NO_THROW({
        inboxApi->updateInbox(
            inboxId(1), users({1, 2}), users({1, 2}),
            core::Buffer::from("public"), core::Buffer::from("private"), std::nullopt, 1, true, true, policy
        );
    });
    inbox::Inbox inbox;
    EXPECT_NO_THROW({ inbox = inboxApi->getInbox(inboxId(1)); });
    EXPECT_EQ(inbox.contextId, contextId());
    EXPECT_EQ(inbox.publicMeta.stdString(), "public");
    EXPECT_EQ(inbox.privateMeta.stdString(), "private");
    expectMembers(inbox, {1, 2}, {1, 2});
    expectPolicy(inbox, policy);
    // An owner-only policy hides the inbox from the other manager.
    disconnect();
    connectAs(ConnectionType::User2);
    EXPECT_THROW({ inboxApi->getInbox(inboxId(1)); }, core::Exception);
}

TEST_F(InboxTest, deleteInbox) {
    // incorrect inboxId
    EXPECT_THROW({ inboxApi->deleteInbox(contextId()); }, core::Exception);
    // as manager
    EXPECT_NO_THROW({ inboxApi->deleteInbox(inboxId(1)); });
    EXPECT_THROW({ inboxApi->getInbox(inboxId(1)); }, core::Exception);
    // as user
    disconnect();
    connectAs(ConnectionType::User2);
    EXPECT_THROW({ inboxApi->deleteInbox(inboxId(3)); }, core::Exception);
}

TEST_F(InboxTest, getInbox) {
    // incorrect inboxId
    EXPECT_THROW({ inboxApi->getInbox(contextId()); }, core::Exception);
    // correct inboxId
    inbox::Inbox inbox;
    EXPECT_NO_THROW({ inbox = inboxApi->getInbox(inboxId(1)); });
    expectMatchesDataset(inbox, "Inbox_1");
    expectMembers(inbox, {1}, {1});
}

TEST_F(InboxTest, getInboxPublicView) {
    // incorrect inboxId
    EXPECT_THROW({ inboxApi->getInboxPublicView(contextId()); }, core::Exception);
    // a public connection sees the public half without holding any key
    disconnect();
    connectAs(ConnectionType::Public);
    inbox::InboxPublicView view;
    EXPECT_NO_THROW({ view = inboxApi->getInboxPublicView(inboxId(1)); });
    EXPECT_EQ(view.inboxId, inboxId(1));
    EXPECT_EQ(view.version, reader->getInt64("Inbox_1.version"));
    EXPECT_EQ(view.publicMeta.stdString(), Hex::toString(reader->getString("Inbox_1.publicMeta_inHex")));
    EXPECT_EQ(view.publicMeta.stdString(), Hex::toString(reader->getString("Inbox_1.uploaded_publicMeta_inHex")));
}

TEST_F(InboxTest, listInboxes) {
    // incorrect contextId
    EXPECT_THROW({
        inboxApi->listInboxes(inboxId(1), {.skip=0, .limit=1, .sortOrder="desc"});
    }, core::Exception);
    // limit < 0
    EXPECT_THROW({
        inboxApi->listInboxes(contextId(), {.skip=0, .limit=-1, .sortOrder="desc"});
    }, core::Exception);
    // limit == 0
    EXPECT_THROW({
        inboxApi->listInboxes(contextId(), {.skip=0, .limit=0, .sortOrder="desc"});
    }, core::Exception);
    // incorrect sortOrder
    EXPECT_THROW({
        inboxApi->listInboxes(contextId(), {.skip=0, .limit=1, .sortOrder="BLACH"});
    }, core::Exception);
    // incorrect lastId
    EXPECT_THROW({
        inboxApi->listInboxes(
            contextId(), {.skip=0, .limit=1, .sortOrder="desc", .lastId=contextId()}
        );
    }, core::Exception);
    // incorrect sortBy
    EXPECT_THROW({
        inboxApi->listInboxes(
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
    core::PagingList<inbox::Inbox> listInboxes;
    EXPECT_NO_THROW({
        listInboxes = inboxApi->listInboxes(contextId(), {.skip=4, .limit=1, .sortOrder="desc"});
    });
    EXPECT_EQ(listInboxes.totalAvailable, 3);
    EXPECT_EQ(listInboxes.readItems.size(), 0);

    // newest first
    EXPECT_NO_THROW({
        listInboxes = inboxApi->listInboxes(contextId(), {.skip=0, .limit=1, .sortOrder="desc"});
    });
    EXPECT_EQ(listInboxes.totalAvailable, 3);
    ASSERT_EQ(listInboxes.readItems.size(), 1);
    expectMatchesDataset(listInboxes.readItems[0], "Inbox_3");
    expectMembers(listInboxes.readItems[0], {1, 2}, {1});

    // paged by createDate, ascending
    EXPECT_NO_THROW({
        listInboxes = inboxApi->listInboxes(
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
    EXPECT_EQ(listInboxes.totalAvailable, 3);
    ASSERT_EQ(listInboxes.readItems.size(), 2);
    expectMatchesDataset(listInboxes.readItems[0], "Inbox_2");
    expectMembers(listInboxes.readItems[0], {1, 2}, {1, 2});
    expectMatchesDataset(listInboxes.readItems[1], "Inbox_3");
    expectMembers(listInboxes.readItems[1], {1, 2}, {1});

    // the inbox module refuses a json query outright, whatever is in the context
    EXPECT_THROW({
        inboxApi->listInboxes(
            contextId(),
            core::PagingQuery{.skip=0, .limit=100, .sortOrder="asc", .queryAsJson="{\"test\":1}"}
        );
    }, inbox::InboxModuleDoesNotSupportQueriesYetException);
}

TEST_F(InboxTest, prepareEntry_sendEntry) {
    // with a stale inbox in the cache: the send below only succeeds if the new key is picked up
    EXPECT_NO_THROW({ inboxApi->getInbox(inboxId(1)); });
    forceNewInboxKey(inboxId(1));
    int64_t inboxHandle = 0;
    EXPECT_NO_THROW({
        inboxHandle = inboxApi->prepareEntry(
            inboxId(2), core::Buffer::from("test_sendEntry"), {},
            reader->getString("Login.user_1_privKey")
        );
    });
    ASSERT_NE(inboxHandle, 0);
    EXPECT_NO_THROW({ inboxApi->sendEntry(inboxHandle); });
    core::PagingList<inbox::InboxEntry> entries;
    EXPECT_NO_THROW({
        entries = inboxApi->listEntries(inboxId(2), {.skip=0, .limit=1, .sortOrder="asc"});
    });
    EXPECT_EQ(entries.totalAvailable, 1);
    ASSERT_EQ(entries.readItems.size(), 1);
    EXPECT_EQ(entries.readItems[0].inboxId, inboxId(2));
    EXPECT_EQ(entries.readItems[0].data.stdString(), "test_sendEntry");
    EXPECT_EQ(entries.readItems[0].files.size(), 0);

    // a public connection may send an entry carrying files, and a member reads it back
    disconnect();
    connectAs(ConnectionType::Public);
    const std::string sentByPublic = sendEntryWithTwoFiles(inboxId(2));
    disconnect();
    connectAs(ConnectionType::User1);
    expectEntryWithTwoFiles(inboxId(2), sentByPublic, 2, "desc");

    // and so may a logged-in user
    const std::string sentByUser = sendEntryWithTwoFiles(inboxId(2));
    expectEntryWithTwoFiles(inboxId(2), sentByUser, 3, "desc");
}

TEST_F(InboxTest, readEntry) {
    // incorrect entryId
    EXPECT_THROW({ inboxApi->readEntry(contextId()); }, core::Exception);
    // a forced key generation must not cost access to entries sent before it
    forceNewInboxKey(inboxId(1));
    inbox::InboxEntry entry;
    EXPECT_NO_THROW({ entry = inboxApi->readEntry(entryId(1)); });
    expectMatchesDataset(entry, "Entry_1", 2);
}

TEST_F(InboxTest, listEntries) {
    // incorrect inboxId
    EXPECT_THROW({
        inboxApi->listEntries(contextId(), {.skip=0, .limit=1, .sortOrder="desc"});
    }, core::Exception);
    // limit < 0
    EXPECT_THROW({
        inboxApi->listEntries(inboxId(1), {.skip=0, .limit=-1, .sortOrder="desc"});
    }, core::Exception);
    // limit == 0
    EXPECT_THROW({
        inboxApi->listEntries(inboxId(1), {.skip=0, .limit=0, .sortOrder="desc"});
    }, core::Exception);
    // incorrect sortOrder
    EXPECT_THROW({
        inboxApi->listEntries(inboxId(1), {.skip=0, .limit=1, .sortOrder="BLACH"});
    }, core::Exception);
    // incorrect lastId
    EXPECT_THROW({
        inboxApi->listEntries(
            inboxId(1), {.skip=0, .limit=1, .sortOrder="desc", .lastId=contextId()}
        );
    }, core::Exception);
    // incorrect sortBy
    EXPECT_THROW({
        inboxApi->listEntries(
            inboxId(1),
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
    core::PagingList<inbox::InboxEntry> listEntries;
    EXPECT_NO_THROW({
        listEntries = inboxApi->listEntries(inboxId(1), {.skip=4, .limit=1, .sortOrder="desc"});
    });
    EXPECT_EQ(listEntries.totalAvailable, 2);
    EXPECT_EQ(listEntries.readItems.size(), 0);

    // oldest, reached by skipping the newest
    EXPECT_NO_THROW({
        listEntries = inboxApi->listEntries(inboxId(1), {.skip=1, .limit=1, .sortOrder="desc"});
    });
    EXPECT_EQ(listEntries.totalAvailable, 2);
    ASSERT_EQ(listEntries.readItems.size(), 1);
    expectMatchesDataset(listEntries.readItems[0], "Entry_1", 2);

    // after a forced key generation, both entries still decrypt
    forceNewInboxKey(inboxId(1));
    EXPECT_NO_THROW({
        listEntries = inboxApi->listEntries(
            inboxId(1),
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
    expectMatchesDataset(listEntries.readItems[0], "Entry_1", 2);
    expectMatchesDataset(listEntries.readItems[1], "Entry_2", 0);
}

TEST_F(InboxTest, deleteEntry) {
    // incorrect entryId
    EXPECT_THROW({ inboxApi->deleteEntry(inboxId(1)); }, core::Exception);
    // user_2 joins as a plain user and may not delete an entry
    EXPECT_NO_THROW({
        inboxApi->updateInbox(
            inboxId(1), users({1, 2}), users({1}),
            core::Buffer::from("public"), core::Buffer::from("private"), std::nullopt, 1, true, false
        );
    });
    disconnect();
    connectAs(ConnectionType::User2);
    EXPECT_THROW({ inboxApi->deleteEntry(entryId(2)); }, core::Exception);

    // promoted to manager, it may
    disconnect();
    connectAs(ConnectionType::User1);
    EXPECT_NO_THROW({
        inboxApi->updateInbox(
            inboxId(1), users({1, 2}), users({1, 2}),
            core::Buffer::from("public"), core::Buffer::from("private"), std::nullopt, 2, true, false
        );
    });
    disconnect();
    connectAs(ConnectionType::User2);
    EXPECT_NO_THROW({
        inboxApi->updateInbox(
            inboxId(1), users({1, 2}), users({2}),
            core::Buffer::from("public"), core::Buffer::from("private"), std::nullopt, 2, true, false
        );
    });
    // an inbox entry has no owner a plain user can claim, so user_1 is refused once it is no longer a manager
    disconnect();
    connectAs(ConnectionType::User1);
    EXPECT_THROW({ inboxApi->deleteEntry(entryId(2)); }, core::Exception);
    // the remaining manager may
    disconnect();
    connectAs(ConnectionType::User2);
    EXPECT_NO_THROW({ inboxApi->deleteEntry(entryId(1)); });
}

TEST_F(InboxTest, openFile_readFromFile_seekInFile_closeFile) {
    // openFile incorrect fileId
    EXPECT_THROW({ inboxApi->openFile(entryId(1)); }, core::Exception);
    // readFromFile and seekInFile on a handle that does not exist
    EXPECT_THROW({ inboxApi->readFromFile(0, 10); }, core::Exception);
    EXPECT_THROW({ inboxApi->seekInFile(0, 10); }, core::Exception);

    // readFromFile and seekInFile on a write handle
    int64_t writeHandle = 0;
    EXPECT_NO_THROW({
        writeHandle = inboxApi->createFileHandle(
            core::Buffer::from("public"), core::Buffer::from("private"), 10
        );
    });
    ASSERT_NE(writeHandle, 0);
    EXPECT_THROW({ inboxApi->readFromFile(writeHandle, 10); }, core::Exception);
    EXPECT_THROW({ inboxApi->seekInFile(writeHandle, 10); }, core::Exception);

    const int64_t size = reader->getInt64("Entry_1.file_0_size");
    int64_t readHandle = 0;
    EXPECT_NO_THROW({ readHandle = inboxApi->openFile(reader->getString("Entry_1.file_0_info_fileId")); });
    ASSERT_NE(readHandle, 0);
    // seekInFile pos < 0
    EXPECT_THROW({ inboxApi->seekInFile(readHandle, -1); }, core::Exception);
    // seekInFile pos > file.size
    EXPECT_THROW({ inboxApi->seekInFile(readHandle, size + 1); }, core::Exception);

    // read the whole file, in two seeks, and reassemble it
    std::string fileData;
    EXPECT_NO_THROW({ inboxApi->seekInFile(readHandle, size / 2); });
    EXPECT_NO_THROW({ fileData = inboxApi->readFromFile(readHandle, size).stdString(); });
    EXPECT_EQ(fileData.length(), (size / 2) + (size % 2));
    EXPECT_NO_THROW({ inboxApi->seekInFile(readHandle, 0); });
    EXPECT_NO_THROW({ fileData = inboxApi->readFromFile(readHandle, size / 2).stdString() + fileData; });
    EXPECT_NO_THROW({ inboxApi->closeFile(readHandle); });
    EXPECT_EQ(fileData.length(), size);
    EXPECT_EQ(fileData.length(), reader->getInt64("Entry_1.uploaded_file_0_size"));
    EXPECT_EQ(fileData, Hex::toString(reader->getString("Entry_1.uploaded_file_0_data_inHex")));
}

TEST_F(InboxTest, Access_denaid_not_in_users_or_managers) {
    disconnect();
    connectAs(ConnectionType::User2);
    EXPECT_THROW({ inboxApi->getInbox(inboxId(1)); }, core::Exception);
    EXPECT_THROW({
        inboxApi->updateInbox(
            inboxId(1), users({1}), users({1}),
            core::Buffer::from("public"), core::Buffer::from("private"), std::nullopt, 1, false, false
        );
    }, core::Exception);
    EXPECT_THROW({ inboxApi->deleteInbox(inboxId(1)); }, core::Exception);
    EXPECT_THROW({ inboxApi->readEntry(entryId(1)); }, core::Exception);
    EXPECT_THROW({
        inboxApi->listEntries(inboxId(1), {.skip=0, .limit=1, .sortOrder="asc"});
    }, core::Exception);
    EXPECT_THROW({
        inboxApi->openFile(reader->getString("Entry_1.file_0_info_fileId"));
    }, core::Exception);
}

TEST_F(InboxTest, Access_denaid_Public) {
    disconnect();
    connectAs(ConnectionType::Public);
    EXPECT_THROW({ inboxApi->getInbox(inboxId(1)); }, core::Exception);
    EXPECT_THROW({
        inboxApi->listInboxes(contextId(), {.skip=0, .limit=1, .sortOrder="desc"});
    }, core::Exception);
    EXPECT_THROW({
        inboxApi->createInbox(
            contextId(), users({1}), users({1}),
            core::Buffer::from("public"), core::Buffer::from("private"), std::nullopt
        );
    }, core::Exception);
    EXPECT_THROW({
        inboxApi->updateInbox(
            inboxId(1), users({1}), users({1}),
            core::Buffer::from("public"), core::Buffer::from("private"), std::nullopt, 1, false, false
        );
    }, core::Exception);
    EXPECT_THROW({ inboxApi->deleteInbox(inboxId(1)); }, core::Exception);
    EXPECT_THROW({ inboxApi->readEntry(entryId(1)); }, core::Exception);
    EXPECT_THROW({
        inboxApi->listEntries(inboxId(1), {.skip=0, .limit=1, .sortOrder="asc"});
    }, core::Exception);
    EXPECT_THROW({
        inboxApi->openFile(reader->getString("Entry_1.file_0_info_fileId"));
    }, core::Exception);
}

TEST_F(InboxTest, falseUserVerifierInterface) {
    // A verifier that rejects everyone leaves reads succeeding but undecrypted.
    EXPECT_NO_THROW({
        inboxApi->updateInbox(
            inboxId(1), users({1}), users({1}),
            core::Buffer::from("public"), core::Buffer::from("private"), std::nullopt, 1, false, false
        );
    });
    EXPECT_NO_THROW({
        connection->setUserVerifier(std::make_shared<FalseUserVerifierInterface>());
    });
    const auto failureCode = core::UserVerificationFailureException().getCode();

    core::PagingList<inbox::Inbox> inboxListResult;
    EXPECT_NO_THROW({
        inboxListResult = inboxApi->listInboxes(contextId(), {.skip=0, .limit=1, .sortOrder="desc"});
    });
    ASSERT_EQ(inboxListResult.readItems.size(), 1);
    EXPECT_EQ(inboxListResult.readItems[0].statusCode, failureCode);

    core::PagingList<inbox::InboxEntry> inboxEntriesListResult;
    EXPECT_NO_THROW({
        inboxEntriesListResult = inboxApi->listEntries(inboxId(1), {.skip=0, .limit=1, .sortOrder="desc"});
    });
    ASSERT_EQ(inboxEntriesListResult.readItems.size(), 1);
    EXPECT_EQ(inboxEntriesListResult.readItems[0].statusCode, failureCode);
}
