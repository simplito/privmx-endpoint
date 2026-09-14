/**
 * One test per ThreadApi function, each covering that function's whole contract: rejected input, accepted
 * input, and the state it leaves behind. Every other ThreadApi function is assumed to work, so getThread is
 * used freely as the oracle for createThread and updateThread without that counting as a second subject.
 *
 * Assertions come from the dataset wherever the dataset records the value - expectMatchesDataset compares a
 * whole Thread or Message against its ini section. Membership is not in the ini, so expectMembers spells it
 * out. Only the three tests that need a container the dataset does not seed create one at runtime.
 *
 * The last three tests are the exception to one-function-per-test: each sweeps the whole API surface for one
 * caller class (non-member, public connection, failing user verifier), which is one subject, not ten.
 */
#include <gtest/gtest.h>
#include "../../utils/BaseTest.hpp"
#include "../../utils/FalseUserVerifierInterface.hpp"
#include <privmx/endpoint/core/Exception.hpp>
#include <Poco/Util/IniFileConfiguration.h>
#include <privmx/endpoint/core/EventQueueImpl.hpp>
#include <privmx/crypto/Crypto.hpp>
#include <privmx/utils/Utils.hpp>
#include <privmx/endpoint/core/VarSerializer.hpp>
#include <privmx/endpoint/core/Connection.hpp>
#include <privmx/endpoint/thread/ThreadApi.hpp>
#include <privmx/endpoint/thread/VarSerializer.hpp>
#include <privmx/endpoint/core/CoreException.hpp>

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
        reader = new Poco::Util::IniFileConfiguration(INI_FILE_PATH);
        connectAs(ConnectionType::User1);
    }
    void customTearDown() override { // tmp segfault fix
        connection.reset();
        threadApi.reset();
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

    std::string threadId(int index) {
        return reader->getString("Thread_" + std::to_string(index) + ".threadId");
    }

    std::string messageId(int index) {
        return reader->getString("Message_" + std::to_string(index) + ".info_messageId");
    }

    std::string contextId() {
        return reader->getString("Context_1.contextId");
    }

    // Every Thread field the dataset records, so a caller asserts the whole shape in one line.
    void expectMatchesDataset(const thread::Thread& thread, const std::string& section) {
        EXPECT_EQ(thread.contextId, reader->getString(section + ".contextId"));
        EXPECT_EQ(thread.threadId, reader->getString(section + ".threadId"));
        EXPECT_EQ(thread.createDate, reader->getInt64(section + ".createDate"));
        EXPECT_EQ(thread.creator, reader->getString(section + ".creator"));
        EXPECT_EQ(thread.lastModificationDate, reader->getInt64(section + ".lastModificationDate"));
        EXPECT_EQ(thread.lastModifier, reader->getString(section + ".lastModifier"));
        EXPECT_EQ(thread.version, reader->getInt64(section + ".version"));
        EXPECT_EQ(thread.lastMsgDate, reader->getInt64(section + ".lastMsgDate"));
        EXPECT_EQ(thread.messagesCount, reader->getInt64(section + ".messagesCount"));
        EXPECT_EQ(thread.statusCode, 0);
        EXPECT_EQ(
            thread.publicMeta.stdString(),
            privmx::utils::Hex::toString(reader->getString(section + ".publicMeta_inHex"))
        );
        EXPECT_EQ(
            thread.publicMeta.stdString(),
            privmx::utils::Hex::toString(reader->getString(section + ".uploaded_publicMeta_inHex"))
        );
        EXPECT_EQ(
            thread.privateMeta.stdString(),
            privmx::utils::Hex::toString(reader->getString(section + ".privateMeta_inHex"))
        );
        EXPECT_EQ(
            thread.privateMeta.stdString(),
            privmx::utils::Hex::toString(reader->getString(section + ".uploaded_privateMeta_inHex"))
        );
    }

    void expectMatchesDataset(const thread::Message& message, const std::string& section) {
        EXPECT_EQ(message.info.threadId, reader->getString(section + ".info_threadId"));
        EXPECT_EQ(message.info.messageId, reader->getString(section + ".info_messageId"));
        EXPECT_EQ(message.info.createDate, reader->getInt64(section + ".info_createDate"));
        EXPECT_EQ(message.info.author, reader->getString(section + ".info_author"));
        EXPECT_EQ(
            message.publicMeta.stdString(),
            privmx::utils::Hex::toString(reader->getString(section + ".publicMeta_inHex"))
        );
        EXPECT_EQ(
            message.privateMeta.stdString(),
            privmx::utils::Hex::toString(reader->getString(section + ".privateMeta_inHex"))
        );
        EXPECT_EQ(message.data.stdString(), privmx::utils::Hex::toString(reader->getString(section + ".data_inHex")));
        EXPECT_EQ(message.statusCode, 0);
        EXPECT_EQ(
            privmx::utils::Utils::stringifyVar(_serializer.serialize(message)),
            reader->getString(section + ".JSON_data")
        );
        EXPECT_EQ(
            message.publicMeta.stdString(),
            privmx::utils::Hex::toString(reader->getString(section + ".uploaded_publicMeta_inHex"))
        );
        EXPECT_EQ(
            message.privateMeta.stdString(),
            privmx::utils::Hex::toString(reader->getString(section + ".uploaded_privateMeta_inHex"))
        );
        EXPECT_EQ(
            message.data.stdString(),
            privmx::utils::Hex::toString(reader->getString(section + ".uploaded_data_inHex"))
        );
    }

    // The roster is not in the ini, so it is spelled out by user index.
    void expectMembers(
        const thread::Thread& thread, std::initializer_list<int> userIndexes,
        std::initializer_list<int> managerIndexes
    ) {
        ASSERT_EQ(thread.users.size(), userIndexes.size());
        size_t i = 0;
        for(int index : userIndexes) {
            EXPECT_EQ(thread.users[i++], user(index).userId);
        }
        ASSERT_EQ(thread.managers.size(), managerIndexes.size());
        i = 0;
        for(int index : managerIndexes) {
            EXPECT_EQ(thread.managers[i++], user(index).userId);
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

    void expectPolicy(const thread::Thread& thread, const core::ContainerPolicy& policy) {
        ASSERT_TRUE(thread.policy.item.has_value());
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
    }

    std::shared_ptr<core::Connection> connection;
    std::shared_ptr<thread::ThreadApi> threadApi;
    Poco::Util::IniFileConfiguration::Ptr reader;
    core::VarSerializer _serializer = core::VarSerializer({});
};

TEST_F(ThreadTest, createThread) {
    // incorrect contextId
    EXPECT_THROW({
        threadApi->createThread(
            threadId(1), users({1}), users({1}),
            core::Buffer::from("public"), core::Buffer::from("private")
        );
    }, core::Exception);
    // incorrect users
    EXPECT_THROW({
        threadApi->createThread(
            contextId(), usersWithMismatchedKey(), users({1}),
            core::Buffer::from("public"), core::Buffer::from("private")
        );
    }, core::Exception);
    // incorrect managers
    EXPECT_THROW({
        threadApi->createThread(
            contextId(), users({1}), usersWithMismatchedKey(),
            core::Buffer::from("public"), core::Buffer::from("private")
        );
    }, core::Exception);
    // no managers
    EXPECT_THROW({
        threadApi->createThread(
            contextId(), users({1}), {},
            core::Buffer::from("public"), core::Buffer::from("private")
        );
    }, core::Exception);

    // different users and managers
    std::string createdId;
    thread::Thread thread;
    EXPECT_NO_THROW({
        createdId = threadApi->createThread(
            contextId(), users({2}), users({1}),
            core::Buffer::from("public"), core::Buffer::from("private")
        );
    });
    ASSERT_FALSE(createdId.empty());
    EXPECT_NO_THROW({ thread = threadApi->getThread(createdId); });
    EXPECT_EQ(thread.statusCode, 0);
    EXPECT_EQ(thread.contextId, contextId());
    EXPECT_EQ(thread.publicMeta.stdString(), "public");
    EXPECT_EQ(thread.privateMeta.stdString(), "private");
    expectMembers(thread, {2}, {1});

    // same users and managers
    EXPECT_NO_THROW({
        createdId = threadApi->createThread(
            contextId(), users({1}), users({1}),
            core::Buffer::from("public"), core::Buffer::from("private")
        );
    });
    ASSERT_FALSE(createdId.empty());
    EXPECT_NO_THROW({ thread = threadApi->getThread(createdId); });
    EXPECT_EQ(thread.statusCode, 0);
    EXPECT_EQ(thread.contextId, contextId());
    expectMembers(thread, {1}, {1});

    // with a policy, which closes the container to everyone but its owner
    const core::ContainerPolicy policy = uniformPolicy("owner", "no");
    EXPECT_NO_THROW({
        createdId = threadApi->createThread(
            contextId(), users({1, 2}), users({1, 2}),
            core::Buffer::from("public"), core::Buffer::from("private"), policy
        );
    });
    ASSERT_FALSE(createdId.empty());
    EXPECT_NO_THROW({ thread = threadApi->getThread(createdId); });
    expectMembers(thread, {1, 2}, {1, 2});
    expectPolicy(thread, policy);
    disconnect();
    connectAs(ConnectionType::User2);
    EXPECT_THROW({ threadApi->getThread(createdId); }, core::Exception);
}

TEST_F(ThreadTest, updateThread) {
    // incorrect threadId
    EXPECT_THROW({
        threadApi->updateThread(
            contextId(), users({1}), users({1}),
            core::Buffer::from("public"), core::Buffer::from("private"), 1, false, false
        );
    }, core::Exception);
    // incorrect users - the old test sent a mismatched key as `managers` here, so this case never ran
    EXPECT_THROW({
        threadApi->updateThread(
            threadId(1), usersWithMismatchedKey(), users({1}),
            core::Buffer::from("public"), core::Buffer::from("private"), 1, false, false
        );
    }, core::Exception);
    // incorrect managers
    EXPECT_THROW({
        threadApi->updateThread(
            threadId(1), users({1}), usersWithMismatchedKey(),
            core::Buffer::from("public"), core::Buffer::from("private"), 1, false, false
        );
    }, core::Exception);
    // no managers
    EXPECT_THROW({
        threadApi->updateThread(
            threadId(1), users({1}), {},
            core::Buffer::from("public"), core::Buffer::from("private"), 1, false, false
        );
    }, core::Exception);
    // incorrect version, force false
    EXPECT_THROW({
        threadApi->updateThread(
            threadId(2), users({1}), users({1}),
            core::Buffer::from("public"), core::Buffer::from("private"), 99, false, false
        );
    }, core::Exception);

    thread::Thread thread;
    // new users
    EXPECT_NO_THROW({
        threadApi->updateThread(
            threadId(1), users({1, 2}), users({1}),
            core::Buffer::from("public"), core::Buffer::from("private"), 1, false, false
        );
    });
    EXPECT_NO_THROW({ thread = threadApi->getThread(threadId(1)); });
    EXPECT_EQ(thread.statusCode, 0);
    EXPECT_EQ(thread.version, 2);
    EXPECT_EQ(thread.publicMeta.stdString(), "public");
    EXPECT_EQ(thread.privateMeta.stdString(), "private");
    expectMembers(thread, {1, 2}, {1});

    // new managers
    EXPECT_NO_THROW({
        threadApi->updateThread(
            threadId(1), users({1}), users({1, 2}),
            core::Buffer::from("public"), core::Buffer::from("private"), 2, false, false
        );
    });
    EXPECT_NO_THROW({ thread = threadApi->getThread(threadId(1)); });
    EXPECT_EQ(thread.version, 3);
    expectMembers(thread, {1}, {1, 2});

    // less users
    EXPECT_NO_THROW({
        threadApi->updateThread(
            threadId(2), users({1}), users({1, 2}),
            core::Buffer::from("public"), core::Buffer::from("private"), 1, false, false
        );
    });
    EXPECT_NO_THROW({ thread = threadApi->getThread(threadId(2)); });
    EXPECT_EQ(thread.version, 2);
    expectMembers(thread, {1}, {1, 2});

    // less managers
    EXPECT_NO_THROW({
        threadApi->updateThread(
            threadId(2), users({1}), users({1}),
            core::Buffer::from("public"), core::Buffer::from("private"), 2, false, false
        );
    });
    EXPECT_NO_THROW({ thread = threadApi->getThread(threadId(2)); });
    EXPECT_EQ(thread.version, 3);
    expectMembers(thread, {1}, {1});

    // incorrect version, force true
    EXPECT_NO_THROW({
        threadApi->updateThread(
            threadId(3), users({1}), users({1}),
            core::Buffer::from("public"), core::Buffer::from("private"), 99, true, false
        );
    });
    EXPECT_NO_THROW({ thread = threadApi->getThread(threadId(3)); });
    EXPECT_EQ(thread.statusCode, 0);
    EXPECT_EQ(thread.version, 2);
    expectMembers(thread, {1}, {1});
}

TEST_F(ThreadTest, updateThread_rewraps_keys_for_a_newly_added_user) {
    // A member added by an update, with a forced key generation, must still reach messages written before it.
    EXPECT_NO_THROW({
        threadApi->updateThread(
            threadId(1), users({1, 2}), users({1, 2}),
            core::Buffer::from("public"), core::Buffer::from("private"), 1, true, true
        );
    });
    disconnect();
    connectAs(ConnectionType::User2);
    thread::Message message;
    EXPECT_NO_THROW({ message = threadApi->getMessage(messageId(1)); });
    EXPECT_EQ(message.statusCode, 0);
}

TEST_F(ThreadTest, updateThread_policy) {
    const core::ContainerPolicy ownerOnly = uniformPolicy("owner", "no");
    EXPECT_NO_THROW({
        threadApi->updateThread(
            threadId(1), users({1, 2}), users({1, 2}),
            core::Buffer::from("public"), core::Buffer::from("private"), 1, true, true, ownerOnly
        );
    });
    thread::Thread thread;
    EXPECT_NO_THROW({ thread = threadApi->getThread(threadId(1)); });
    EXPECT_EQ(thread.contextId, contextId());
    expectMembers(thread, {1, 2}, {1, 2});
    expectPolicy(thread, ownerOnly);
    // An owner-only item policy hides the messages from the other manager.
    disconnect();
    connectAs(ConnectionType::User2);
    EXPECT_THROW({ threadApi->getMessage(messageId(1)); }, core::Exception);

    // An all-access policy lets a user added by that same update apply the next one.
    disconnect();
    connectAs(ConnectionType::User1);
    const core::ContainerPolicy openToAll = uniformPolicy("all", "yes");
    EXPECT_NO_THROW({
        threadApi->updateThread(
            threadId(2), users({1, 2}), users({1, 2}),
            core::Buffer::from("public"), core::Buffer::from("private"), 1, true, true, openToAll
        );
    });
    EXPECT_NO_THROW({ thread = threadApi->getThread(threadId(2)); });
    expectPolicy(thread, openToAll);
    disconnect();
    connectAs(ConnectionType::User2);
    EXPECT_NO_THROW({
        threadApi->updateThread(
            threadId(2), users({1, 2}), users({1, 2}),
            core::Buffer::from("public"), core::Buffer::from("private"), 1, true, true, openToAll
        );
    });
}

TEST_F(ThreadTest, rotateThreadKeys) {
    // The dataset seeds no rotated thread, so this one is built here.
    const std::vector<core::UserWithPubKey> user_1 = users({1});
    std::string createdId;
    ASSERT_NO_THROW({
        createdId = threadApi->createThread(
            contextId(), user_1, user_1,
            core::Buffer::from("rotated_public"), core::Buffer::from("rotated_private")
        );
    });
    ASSERT_FALSE(createdId.empty());

    std::string createdMessageId;
    ASSERT_NO_THROW({
        createdMessageId = threadApi->sendMessage(
            createdId, core::Buffer::from("msg_public"), core::Buffer::from("msg_private"),
            core::Buffer::from("msg_data")
        );
    });

    ASSERT_NO_THROW({ threadApi->rotateThreadKeys(createdId, user_1, user_1, 0, true); });
    thread::Thread afterFirstRotation;
    ASSERT_NO_THROW({ afterFirstRotation = threadApi->getThread(createdId); });
    ASSERT_EQ(afterFirstRotation.statusCode, 0); // a single rotation has always been readable

    ASSERT_NO_THROW({ threadApi->rotateThreadKeys(createdId, user_1, user_1, 0, true); });

    // Reconnect so ContainerKeyCache is empty - the reads below resolve purely from server state.
    disconnect();
    connectAs(ConnectionType::User1);

    thread::Thread thread;
    EXPECT_NO_THROW({ thread = threadApi->getThread(createdId); });
    EXPECT_EQ(thread.statusCode, 0);
    EXPECT_EQ(thread.publicMeta.stdString(), "rotated_public");
    EXPECT_EQ(thread.privateMeta.stdString(), "rotated_private");

    // Same decrypt path, batched.
    core::PagingList<thread::Thread> threadListResult;
    EXPECT_NO_THROW({
        threadListResult = threadApi->listThreads(contextId(), {.skip=0, .limit=100, .sortOrder="desc"});
    });
    bool foundInList = false;
    for(const auto& listed : threadListResult.readItems) {
        if(listed.threadId == createdId) {
            foundInList = true;
            EXPECT_EQ(listed.statusCode, 0);
            EXPECT_EQ(listed.privateMeta.stdString(), "rotated_private");
        }
    }
    EXPECT_TRUE(foundInList);

    // Control: a message carries its own keyId, so it must stay readable across the rotations.
    thread::Message message;
    EXPECT_NO_THROW({ message = threadApi->getMessage(createdMessageId); });
    EXPECT_EQ(message.statusCode, 0);
    EXPECT_EQ(message.data.stdString(), "msg_data");
}

TEST_F(ThreadTest, deleteThread) {
    // incorrect threadId
    EXPECT_THROW({ threadApi->deleteThread(contextId()); }, core::Exception);
    // as manager
    EXPECT_NO_THROW({ threadApi->deleteThread(threadId(1)); });
    EXPECT_THROW({ threadApi->getThread(threadId(1)); }, core::Exception);
    // as user
    disconnect();
    connectAs(ConnectionType::User2);
    EXPECT_THROW({ threadApi->deleteThread(threadId(3)); }, core::Exception);
}

TEST_F(ThreadTest, getThread) {
    // incorrect threadId
    EXPECT_THROW({ threadApi->getThread(contextId()); }, core::Exception);
    // correct threadId
    thread::Thread thread;
    EXPECT_NO_THROW({ thread = threadApi->getThread(threadId(1)); });
    expectMatchesDataset(thread, "Thread_1");
    expectMembers(thread, {1}, {1});
}

TEST_F(ThreadTest, listThreads) {
    // incorrect contextId
    EXPECT_THROW({
        threadApi->listThreads(threadId(1), {.skip=0, .limit=1, .sortOrder="desc"});
    }, core::Exception);
    // limit < 0
    EXPECT_THROW({
        threadApi->listThreads(contextId(), {.skip=0, .limit=-1, .sortOrder="desc"});
    }, core::Exception);
    // limit == 0
    EXPECT_THROW({
        threadApi->listThreads(contextId(), {.skip=0, .limit=0, .sortOrder="desc"});
    }, core::Exception);
    // incorrect sortOrder
    EXPECT_THROW({
        threadApi->listThreads(contextId(), {.skip=0, .limit=1, .sortOrder="BLACH"});
    }, core::Exception);
    // incorrect lastId
    EXPECT_THROW({
        threadApi->listThreads(
            contextId(), {.skip=0, .limit=1, .sortOrder="desc", .lastId=contextId()}
        );
    }, core::Exception);
    // incorrect queryAsJson
    EXPECT_THROW({
        threadApi->listThreads(
            contextId(),
            {.skip=0, .limit=1, .sortOrder="desc", .lastId=std::nullopt, .queryAsJson="{BLACH,}"}
        );
    }, core::InvalidParamsException);
    // incorrect sortBy
    EXPECT_THROW({
        threadApi->listThreads(
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
    core::PagingList<thread::Thread> listThreads;
    EXPECT_NO_THROW({
        listThreads = threadApi->listThreads(contextId(), {.skip=4, .limit=1, .sortOrder="desc"});
    });
    EXPECT_EQ(listThreads.totalAvailable, 3);
    EXPECT_EQ(listThreads.readItems.size(), 0);

    // newest first
    EXPECT_NO_THROW({
        listThreads = threadApi->listThreads(contextId(), {.skip=0, .limit=1, .sortOrder="desc"});
    });
    EXPECT_EQ(listThreads.totalAvailable, 3);
    ASSERT_EQ(listThreads.readItems.size(), 1);
    expectMatchesDataset(listThreads.readItems[0], "Thread_3");
    expectMembers(listThreads.readItems[0], {1, 2}, {1});

    // paged by createDate, ascending
    EXPECT_NO_THROW({
        listThreads = threadApi->listThreads(
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
    EXPECT_EQ(listThreads.totalAvailable, 3);
    ASSERT_EQ(listThreads.readItems.size(), 2);
    expectMatchesDataset(listThreads.readItems[0], "Thread_2");
    expectMembers(listThreads.readItems[0], {1, 2}, {1, 2});
    expectMatchesDataset(listThreads.readItems[1], "Thread_3");
    expectMembers(listThreads.readItems[1], {1, 2}, {1});

    // queryAsJson matches on publicMeta, which no seeded thread carries as json
    std::string createdId;
    EXPECT_NO_THROW({
        createdId = threadApi->createThread(
            contextId(), users({1}), users({1}),
            core::Buffer::from("{\"test\":1}"), core::Buffer::from("list_query_test")
        );
    });
    ASSERT_FALSE(createdId.empty());
    EXPECT_NO_THROW({
        listThreads = threadApi->listThreads(
            contextId(),
            core::PagingQuery{.skip=0, .limit=100, .sortOrder="asc", .queryAsJson="{\"test\":1}"}
        );
    });
    EXPECT_EQ(listThreads.totalAvailable, 1);
    ASSERT_EQ(listThreads.readItems.size(), 1);
    EXPECT_EQ(listThreads.readItems[0].threadId, createdId);
    EXPECT_EQ(listThreads.readItems[0].statusCode, 0);
    EXPECT_EQ(listThreads.readItems[0].publicMeta.stdString(), "{\"test\":1}");
    EXPECT_EQ(listThreads.readItems[0].privateMeta.stdString(), "list_query_test");
}

TEST_F(ThreadTest, getMessage) {
    // incorrect messageId
    EXPECT_THROW({ threadApi->getMessage(contextId()); }, core::Exception);
    // a forced key generation must not cost access to messages written before it
    EXPECT_NO_THROW({
        threadApi->updateThread(
            threadId(1), users({1}), users({1}),
            core::Buffer::from("public"), core::Buffer::from("private"), 1, true, true
        );
    });
    thread::Message message;
    EXPECT_NO_THROW({ message = threadApi->getMessage(messageId(2)); });
    expectMatchesDataset(message, "Message_2");
}

TEST_F(ThreadTest, listMessages) {
    // incorrect threadId
    EXPECT_THROW({
        threadApi->listMessages(messageId(2), {.skip=0, .limit=1, .sortOrder="desc"});
    }, core::Exception);
    // limit < 0
    EXPECT_THROW({
        threadApi->listMessages(threadId(1), {.skip=0, .limit=-1, .sortOrder="desc"});
    }, core::Exception);
    // limit == 0
    EXPECT_THROW({
        threadApi->listMessages(threadId(1), {.skip=0, .limit=0, .sortOrder="desc"});
    }, core::Exception);
    // incorrect sortOrder
    EXPECT_THROW({
        threadApi->listMessages(threadId(1), {.skip=0, .limit=1, .sortOrder="BLACH"});
    }, core::Exception);
    // incorrect lastId
    EXPECT_THROW({
        threadApi->listMessages(
            threadId(1), {.skip=0, .limit=1, .sortOrder="BLACH", .lastId=threadId(1)}
        );
    }, core::Exception);
    // incorrect queryAsJson
    EXPECT_THROW({
        threadApi->listMessages(
            threadId(1),
            {.skip=0, .limit=1, .sortOrder="BLACH", .lastId=std::nullopt, .queryAsJson="{BLACH,}"}
        );
    }, core::InvalidParamsException);
    // incorrect sortBy
    EXPECT_THROW({
        threadApi->listMessages(
            threadId(1),
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
    core::PagingList<thread::Message> listMessages;
    EXPECT_NO_THROW({
        listMessages = threadApi->listMessages(threadId(1), {.skip=4, .limit=1, .sortOrder="desc"});
    });
    EXPECT_EQ(listMessages.totalAvailable, 2);
    EXPECT_EQ(listMessages.readItems.size(), 0);

    // oldest, reached by skipping the newest
    EXPECT_NO_THROW({
        listMessages = threadApi->listMessages(threadId(1), {.skip=1, .limit=1, .sortOrder="desc"});
    });
    EXPECT_EQ(listMessages.totalAvailable, 2);
    ASSERT_EQ(listMessages.readItems.size(), 1);
    expectMatchesDataset(listMessages.readItems[0], "Message_1");

    // after a forced key generation, both messages still decrypt
    EXPECT_NO_THROW({
        threadApi->updateThread(
            threadId(1), users({1}), users({1}),
            core::Buffer::from("public"), core::Buffer::from("private"), 1, true, true
        );
    });
    EXPECT_NO_THROW({
        listMessages = threadApi->listMessages(
            threadId(1),
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
    EXPECT_EQ(listMessages.totalAvailable, 2);
    ASSERT_EQ(listMessages.readItems.size(), 2);
    expectMatchesDataset(listMessages.readItems[0], "Message_1");
    expectMatchesDataset(listMessages.readItems[1], "Message_2");
}

TEST_F(ThreadTest, sendMessage) {
    // incorrect threadId
    EXPECT_THROW({
        threadApi->sendMessage(
            contextId(), core::Buffer::from("pubMeta"), core::Buffer::from("privMeta"),
            core::Buffer::from("data")
        );
    }, core::Exception);
    // total data bigger than 1MB
    std::string random_data;
    for(int i = 0; i < 1024; i++) {
        random_data += privmx::crypto::Crypto::randomBytes(1024);
    }
    EXPECT_THROW({
        threadApi->sendMessage(
            threadId(1), core::Buffer::from(random_data), core::Buffer::from("privMeta"),
            core::Buffer::from("data")
        );
    }, core::Exception);

    // correct data
    random_data = std::string();
    for(int i = 0; i < 8; i++) {
        random_data += privmx::crypto::Crypto::randomBytes(1024);
    }
    std::string sentId;
    EXPECT_NO_THROW({
        sentId = threadApi->sendMessage(
            threadId(1), core::Buffer::from("publicMeta"), core::Buffer::from("privateMeta"),
            core::Buffer::from(random_data)
        );
    });
    thread::Message message;
    EXPECT_NO_THROW({ message = threadApi->getMessage(sentId); });
    EXPECT_EQ(message.statusCode, 0);
    EXPECT_EQ(message.data.stdString().length(), random_data.length());
    if(message.data.stdString().length() == random_data.length()) {
        EXPECT_EQ(message.data.stdString(), random_data);
    }
    EXPECT_EQ(message.privateMeta.stdString(), "privateMeta");
    EXPECT_EQ(message.publicMeta.stdString(), "publicMeta");

    // with a stale thread in the cache: the read below only succeeds if the new key is picked up
    EXPECT_NO_THROW({ threadApi->getThread(threadId(1)); });
    EXPECT_NO_THROW({
        threadApi->updateThread(
            threadId(1), users({1}), users({1}),
            core::Buffer::from("public"), core::Buffer::from("private"), 1, true, true
        );
    });
    EXPECT_NO_THROW({
        sentId = threadApi->sendMessage(
            threadId(1), core::Buffer::from("publicMeta"), core::Buffer::from("privateMeta"),
            core::Buffer::from("data")
        );
    });
    EXPECT_NO_THROW({ message = threadApi->getMessage(sentId); });
    EXPECT_EQ(message.statusCode, 0);
    EXPECT_EQ(message.data.stdString(), "data");
}

TEST_F(ThreadTest, updateMessage) {
    // incorrect messageId
    EXPECT_THROW({
        threadApi->updateMessage(
            threadId(1), core::Buffer::from("pubMeta"), core::Buffer::from("privMeta"),
            core::Buffer::from("data")
        );
    }, core::Exception);
    // total data bigger than 1MB
    std::string random_data;
    for(int i = 0; i < 1024; i++) {
        random_data += privmx::crypto::Crypto::randomBytes(1024);
    }
    EXPECT_THROW({
        threadApi->updateMessage(
            messageId(1), core::Buffer::from(random_data), core::Buffer::from("privMeta"),
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
            messageId(1), core::Buffer::from("publicMeta"), core::Buffer::from("privateMeta"),
            core::Buffer::from(random_data)
        );
    });
    thread::Message message;
    EXPECT_NO_THROW({ message = threadApi->getMessage(messageId(1)); });
    EXPECT_EQ(message.statusCode, 0);
    EXPECT_EQ(message.data.stdString().length(), random_data.length());
    if(message.data.stdString().length() == random_data.length()) {
        EXPECT_EQ(message.data.stdString(), random_data);
    }
    EXPECT_EQ(message.privateMeta.stdString(), "privateMeta");
    EXPECT_EQ(message.publicMeta.stdString(), "publicMeta");

    // with a stale thread in the cache: the update below only succeeds if the new key is picked up
    EXPECT_NO_THROW({ threadApi->getThread(threadId(1)); });
    EXPECT_NO_THROW({
        threadApi->updateThread(
            threadId(1), users({1}), users({1}),
            core::Buffer::from("public"), core::Buffer::from("private"), 1, true, true
        );
    });
    EXPECT_NO_THROW({
        threadApi->updateMessage(
            messageId(1), core::Buffer::from("publicMeta"), core::Buffer::from("privateMeta"),
            core::Buffer::from("data")
        );
    });
    EXPECT_NO_THROW({ message = threadApi->getMessage(messageId(1)); });
    EXPECT_EQ(message.statusCode, 0);
    EXPECT_EQ(message.data.stdString(), "data");
}

TEST_F(ThreadTest, deleteMessage) {
    // incorrect messageId
    EXPECT_THROW({ threadApi->deleteMessage(threadId(1)); }, core::Exception);
    // user_2 joins as a plain user and may not delete somebody else's message
    EXPECT_NO_THROW({
        threadApi->updateThread(
            threadId(1), users({1, 2}), users({1}),
            core::Buffer::from("public"), core::Buffer::from("private"), 1, true, false
        );
    });
    disconnect();
    connectAs(ConnectionType::User2);
    EXPECT_THROW({ threadApi->deleteMessage(messageId(2)); }, core::Exception);

    // promoted to manager, it may
    disconnect();
    connectAs(ConnectionType::User1);
    EXPECT_NO_THROW({
        threadApi->updateThread(
            threadId(1), users({1, 2}), users({1, 2}),
            core::Buffer::from("public"), core::Buffer::from("private"), 1, true, false
        );
    });
    disconnect();
    connectAs(ConnectionType::User2);
    EXPECT_NO_THROW({
        threadApi->updateThread(
            threadId(1), users({1, 2}), users({2}),
            core::Buffer::from("public"), core::Buffer::from("private"), 1, true, false
        );
    });
    // as the author
    disconnect();
    connectAs(ConnectionType::User1);
    EXPECT_NO_THROW({ threadApi->deleteMessage(messageId(2)); });
    // as a manager who did not write it
    disconnect();
    connectAs(ConnectionType::User2);
    EXPECT_NO_THROW({ threadApi->deleteMessage(messageId(1)); });
}

TEST_F(ThreadTest, Access_denaid_not_in_users_or_managers) {
    disconnect();
    connectAs(ConnectionType::User2);
    EXPECT_THROW({ threadApi->getThread(threadId(1)); }, core::Exception);
    EXPECT_THROW({
        threadApi->updateThread(
            threadId(1), users({2}), users({2}),
            core::Buffer::from("public"), core::Buffer::from("private"), 1, false, false
        );
    }, core::Exception);
    EXPECT_THROW({ threadApi->deleteThread(threadId(1)); }, core::Exception);
    EXPECT_THROW({ threadApi->getMessage(messageId(1)); }, core::Exception);
    EXPECT_THROW({
        threadApi->listMessages(threadId(1), {.skip=0, .limit=1, .sortOrder="desc"});
    }, core::Exception);
    EXPECT_THROW({
        threadApi->sendMessage(
            threadId(1), core::Buffer::from("pubMeta"), core::Buffer::from("privMeta"),
            core::Buffer::from("data")
        );
    }, core::Exception);
    EXPECT_THROW({
        threadApi->updateMessage(
            messageId(1), core::Buffer::from("pubMeta"), core::Buffer::from("privMeta"),
            core::Buffer::from("data")
        );
    }, core::Exception);
    EXPECT_THROW({ threadApi->deleteMessage(messageId(1)); }, core::Exception);
}

TEST_F(ThreadTest, Access_denaid_Public) {
    disconnect();
    connectAs(ConnectionType::Public);
    EXPECT_THROW({ threadApi->getThread(threadId(1)); }, core::Exception);
    EXPECT_THROW({
        threadApi->listThreads(contextId(), {.skip=0, .limit=1, .sortOrder="desc"});
    }, core::Exception);
    EXPECT_THROW({
        threadApi->createThread(
            contextId(), users({2}), users({2}),
            core::Buffer::from("public"), core::Buffer::from("private")
        );
    }, core::Exception);
    EXPECT_THROW({
        threadApi->updateThread(
            threadId(1), users({2}), users({2}),
            core::Buffer::from("public"), core::Buffer::from("private"), 1, false, false
        );
    }, core::Exception);
    EXPECT_THROW({ threadApi->deleteThread(threadId(1)); }, core::Exception);
    EXPECT_THROW({ threadApi->getMessage(messageId(1)); }, core::Exception);
    EXPECT_THROW({
        threadApi->listMessages(threadId(1), {.skip=0, .limit=1, .sortOrder="desc"});
    }, core::Exception);
    EXPECT_THROW({
        threadApi->sendMessage(
            threadId(1), core::Buffer::from("pubMeta"), core::Buffer::from("privMeta"),
            core::Buffer::from("data")
        );
    }, core::Exception);
    EXPECT_THROW({
        threadApi->updateMessage(
            messageId(1), core::Buffer::from("pubMeta"), core::Buffer::from("privMeta"),
            core::Buffer::from("data")
        );
    }, core::Exception);
    EXPECT_THROW({ threadApi->deleteMessage(messageId(1)); }, core::Exception);
}

TEST_F(ThreadTest, userValidator_false) {
    // A verifier that rejects everyone leaves reads succeeding but undecrypted, and blocks every write that
    // would have to trust a key it cannot verify.
    auto verifier = std::make_shared<core::FalseUserVerifierInterface>();
    connection->setUserVerifier(verifier);
    const auto failureCode = core::UserVerificationFailureException().getCode();

    EXPECT_NO_THROW({
        auto thread = threadApi->getThread(threadId(1));
        EXPECT_EQ(thread.statusCode, failureCode);
    });
    EXPECT_NO_THROW({
        auto threads = threadApi->listThreads(contextId(), {.skip=0, .limit=1, .sortOrder="desc"});
        ASSERT_EQ(threads.readItems.size(), 1);
        EXPECT_EQ(threads.readItems[0].statusCode, failureCode);
    });
    EXPECT_NO_THROW({
        threadApi->createThread(
            contextId(), users({1}), users({1}),
            core::Buffer::from("public"), core::Buffer::from("private")
        );
    });
    EXPECT_THROW({
        threadApi->updateThread(
            threadId(1), users({1}), users({1}),
            core::Buffer::from("public"), core::Buffer::from("private"), 1, true, true
        );
    }, core::Exception);
    EXPECT_NO_THROW({ threadApi->deleteThread(threadId(2)); });
    EXPECT_NO_THROW({
        auto message = threadApi->getMessage(messageId(1));
        EXPECT_EQ(message.statusCode, failureCode);
    });
    EXPECT_NO_THROW({
        auto messages = threadApi->listMessages(threadId(1), {.skip=0, .limit=1, .sortOrder="desc"});
        ASSERT_EQ(messages.readItems.size(), 1);
        EXPECT_EQ(messages.readItems[0].statusCode, failureCode);
    });
    EXPECT_THROW({
        threadApi->sendMessage(
            threadId(1), core::Buffer::from("pubMeta"), core::Buffer::from("privMeta"),
            core::Buffer::from("data")
        );
    }, core::Exception);
    EXPECT_THROW({
        threadApi->updateMessage(
            messageId(1), core::Buffer::from("pubMeta"), core::Buffer::from("privMeta"),
            core::Buffer::from("data")
        );
    }, core::Exception);
    EXPECT_NO_THROW({ threadApi->deleteMessage(messageId(2)); });
}
