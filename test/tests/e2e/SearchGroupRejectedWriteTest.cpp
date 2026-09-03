#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include <gtest/gtest.h>
#include "../../utils/BaseTest.hpp"
#include <Poco/Util/IniFileConfiguration.h>
#include <privmx/endpoint/core/Connection.hpp>
#include <privmx/endpoint/core/CoreException.hpp>
#include <privmx/endpoint/core/EventQueueImpl.hpp>
#include <privmx/endpoint/core/Exception.hpp>
#include <privmx/endpoint/core/Types.hpp>
#include <privmx/endpoint/group/GroupApi.hpp>
#include <privmx/endpoint/kvdb/KvdbApi.hpp>
#include <privmx/endpoint/lock/LockApi.hpp>
#include <privmx/endpoint/search/SearchApi.hpp>
#include <privmx/endpoint/store/StoreApi.hpp>
#include <privmx/utils/PrivmxException.hpp>

using namespace privmx::endpoint;

/**
 * A write the Bridge refuses must not destroy the Search Index.
 *
 * An Index is a SQLite database living in a Store file behind a custom VFS, and a random write carries the key id
 * its handle was opened under — the Bridge refuses one whose key id is not the Store's current key. A Group
 * membership change moves that key underneath handles that are already open, so a member who is removed and added
 * back has a handle whose next write gets refused. The refusal itself is expected; what is under test here is
 * that it stays a refusal instead of taking the whole Index down with it.
 *
 * Both sessions stay connected for the whole flow. The reported failure needs two handles open across the epoch
 * change, so a fixture that swaps one connection in and out cannot express it.
 *
 * See SearchUsingGroupsTest for the ordinary group-grant behaviour; this file only covers the refused write.
 */

class SearchGroupRejectedWriteTest : public privmx::test::BaseTest {
protected:
    SearchGroupRejectedWriteTest() : BaseTest(privmx::test::BaseTestMode::online) {}

    // One user's live session, with every API an Index needs.
    struct Client {
        std::shared_ptr<core::Connection> connection;
        std::shared_ptr<group::GroupApi> groupApi;
        std::shared_ptr<store::StoreApi> storeApi;
        std::shared_ptr<kvdb::KvdbApi> kvdbApi;
        std::shared_ptr<lock::LockApi> lockApi;
        std::shared_ptr<search::SearchApi> searchApi;
        int64_t handle = -1;
    };

    void customSetUp() override {
        reader = new Poco::Util::IniFileConfiguration(INI_FILE_PATH);
        alice = connectAs(1);
        bob = connectAs(2);
    }

    void customTearDown() override {
        closeHandle(alice);
        closeHandle(bob);
        resetClient(alice);
        resetClient(bob);
        reader.reset();
        core::EventQueueImpl::getInstance()->clear();
    }

    Client connectAs(int index) {
        const std::string n = std::to_string(index);
        Client client;
        client.connection = std::make_shared<core::Connection>(
            core::Connection::connect(
                reader->getString("Login.user_" + n + "_privKey"), reader->getString("Login.solutionId"),
                getPlatformUrl(reader->getString("Login.instanceUrl"))
            )
        );
        client.groupApi = std::make_shared<group::GroupApi>(group::GroupApi::create(*client.connection));
        client.storeApi = std::make_shared<store::StoreApi>(
            store::StoreApi::create(*client.connection, *client.groupApi)
        );
        client.kvdbApi = std::make_shared<kvdb::KvdbApi>(kvdb::KvdbApi::create(*client.connection, *client.groupApi));
        client.lockApi = std::make_shared<lock::LockApi>(lock::LockApi::create(*client.connection));
        client.searchApi = std::make_shared<search::SearchApi>(
            search::SearchApi::create(*client.connection, *client.storeApi, *client.kvdbApi, *client.lockApi)
        );
        return client;
    }

    // A corrupted Index makes closeSearchIndex throw as readily as everything else, and teardown must not.
    void closeHandle(Client& client) {
        if (client.searchApi && client.handle != -1) {
            try {
                client.searchApi->closeSearchIndex(client.handle);
            } catch (...) {}
            client.handle = -1;
        }
    }

    void resetClient(Client& client) {
        client.searchApi.reset();
        client.lockApi.reset();
        client.kvdbApi.reset();
        client.storeApi.reset();
        client.groupApi.reset();
        client.connection.reset();
    }

    core::UserWithPubKey user(int index) {
        const std::string n = std::to_string(index);
        return core::UserWithPubKey{
            .userId = reader->getString("Login.user_" + n + "_id"),
            .pubKey = reader->getString("Login.user_" + n + "_pubKey")
        };
    }

    std::string contextId() {
        return reader->getString("Context_1.contextId");
    }

    /**
     * The real cause of a VFS failure only ever reached the log: every underlying exception was flattened into
     * `disk I/O error`. Calls under test go through here so the message is on the test's own output, which is
     * what identifies the refusal the Bridge actually sent.
     */
    std::optional<std::string> tryCall(const std::function<void()>& fn) {
        try {
            fn();
            return std::nullopt;
        } catch (const core::Exception& e) {
            return e.getFull();
        } catch (const privmx::utils::PrivmxException& e) {
            return std::string(e.what()) + " | " + e.getData();
        } catch (const std::exception& e) {
            return std::string(e.what());
        }
    }

    /**
     * A Group holding alice and bob, and an Index whose only direct member is alice and whose sole grant is that
     * Group at "manager" — bob's every route into the Index is the group grant, so the epoch is the only thing
     * governing his access. Opening an Index writes to it, which is why "user" would not be enough.
     */
    void createGroupAndIndex(std::string& groupId, std::string& indexId) {
        ASSERT_NO_THROW({
            groupId = alice.groupApi->createGroup(
                contextId(), std::vector<core::UserWithPubKey>{user(1), user(2)},
                std::vector<core::UserWithPubKey>{user(1)}, core::Buffer::from("rejected_write_grp_pub"),
                core::Buffer::from("rejected_write_grp_priv")
            );
        });
        ASSERT_FALSE(groupId.empty());

        group::Group group;
        ASSERT_NO_THROW({ group = alice.groupApi->getGroup(groupId); });
        ASSERT_EQ(group.statusCode, 0);

        ASSERT_NO_THROW({
            indexId = alice.searchApi->createSearchIndex(
                contextId(), std::vector<core::UserWithPubKey>{user(1)},
                std::vector<core::UserWithPubKey>{user(1)}, core::Buffer::from("rejected_write_idx_pub"),
                core::Buffer::from("rejected_write_idx_priv"), search::IndexMode::WITH_CONTENT, std::nullopt,
                std::vector<core::GroupGrantWithKey>{
                    core::GroupGrantWithKey{
                        .groupId = groupId, .role = "manager", .groupPubKey = group.groupPubKey
                    }
                }
            );
        });
        ASSERT_FALSE(indexId.empty());
    }

    /**
     * What actually made it into the Index, as opposed to what was attempted.
     *
     * Every write in these flows is best-effort: which of them the Bridge refuses is the thing under
     * investigation, so a flow that stops at the first refusal never reaches the question of what the refusal
     * did to the data. Only a write that returned cleanly counts, and that count is the number every later read
     * has to agree with.
     */
    struct Ledger {
        int64_t committed = 0;
        std::vector<std::string> refusals;
    };

    void addDocument(Client& client, int64_t handle, const std::string& name, const std::string& content,
                     Ledger& ledger) {
        auto error = tryCall([&] { client.searchApi->addDocument(handle, name, content); });
        if (error.has_value()) {
            ledger.refusals.push_back(name + " -> " + error.value());
        } else {
            ledger.committed += 1;
        }
    }

    void reportRefusals(const Ledger& ledger) {
        for (const auto& refusal : ledger.refusals) {
            GTEST_LOG_(INFO) << "refused write: " << refusal;
        }
    }

    // Documents visible through a handle that is already open; -1 if that read fails outright.
    int64_t countThrough(Client& client, int64_t handle) {
        int64_t count = -1;
        auto error = tryCall([&] {
            count = client.searchApi
                        ->listDocuments(handle, core::PagingQuery{.skip = 0, .limit = 100, .sortOrder = "asc"})
                        .totalAvailable;
        });
        if (error.has_value()) {
            ADD_FAILURE() << "listDocuments through an open handle failed: " << error.value();
            return -1;
        }
        return count;
    }

    // Documents visible to a caller who opens the Index from scratch. Returns -1 if it cannot be opened at all.
    int64_t countFromFreshOpen(Client& client, const std::string& indexId) {
        int64_t handle = -1;
        auto openError = tryCall([&] { handle = client.searchApi->openSearchIndex(indexId); });
        if (openError.has_value()) {
            ADD_FAILURE() << "openSearchIndex failed: " << openError.value();
            return -1;
        }
        int64_t count = countThrough(client, handle);
        tryCall([&] { client.searchApi->closeSearchIndex(handle); });
        return count;
    }

    void removeBobFromGroup(const std::string& groupId) {
        ASSERT_NO_THROW({
            alice.groupApi->removeGroupMember(
                groupId, reader->getString("Login.user_2_id"), std::vector<core::UserWithPubKey>{user(1)},
                std::vector<core::UserWithPubKey>{user(1)}, core::Buffer::from("rejected_write_grp_pub"),
                core::Buffer::from("rejected_write_grp_priv")
            );
        });
    }

    void addBobToGroup(const std::string& groupId) {
        group::Group group;
        ASSERT_NO_THROW({ group = alice.groupApi->getGroup(groupId); });
        ASSERT_NO_THROW({
            alice.groupApi->addGroupMember(
                groupId, user(2), false, std::vector<core::UserWithPubKey>{user(1), user(2)},
                std::vector<core::UserWithPubKey>{user(1)}, group.publicMeta, group.privateMeta
            );
        });
    }

    Client alice;
    Client bob;
    Poco::Util::IniFileConfiguration::Ptr reader;
};

/**
 * The smallest form of the failure: one user, one handle, no re-add and nobody else writing.
 *
 * A random write carries the key id its handle was opened under, and a Group membership change rotates the
 * Index's key underneath it. `FileHandler::updateOnServer` keeps sending the old id, and
 * `StoreApiImpl::flushFile` is the only write path in the module with no `isRekeyNeeded` guard —
 * `updateFileMeta` and `storeFileFinalizeWrite` both re-key before writing. So alice, who is the Index's owner
 * and was never removed from anything, cannot write through her own open handle once the epoch moves.
 *
 * Everything else in this file is downstream of this.
 */
TEST_F(SearchGroupRejectedWriteTest, open_handle_can_still_write_after_the_group_epoch_changes) {
    std::string groupId, indexId;
    createGroupAndIndex(groupId, indexId);

    ASSERT_NO_THROW({ alice.handle = alice.searchApi->openSearchIndex(indexId); });
    ASSERT_NO_THROW({ alice.searchApi->addDocument(alice.handle, "a1", "alpha one"); });
    ASSERT_EQ(countThrough(alice, alice.handle), 1);

    // Removing bob advances the Group's epoch, which leaves the Index's key superseded. alice's handle is
    // otherwise untouched: same session, same handle, still the owner, still a manager.
    removeBobFromGroup(groupId);

    auto writeError = tryCall([&] { alice.searchApi->addDocument(alice.handle, "a2", "alpha two"); });
    EXPECT_FALSE(writeError.has_value()) << "the owner's own open handle could not write after the epoch moved: "
                                         << writeError.value_or("");
}

/**
 * The reported flow, and the invariant underneath it: a write the Bridge refuses must leave the Index exactly
 * as it was. Documents that were committed stay committed, and the Index still opens.
 *
 * Which of these writes gets refused is the open question, so none of them is asserted here — they are all
 * best-effort and the ledger counts only the ones that returned cleanly. That is deliberate: a flow that stops
 * at the first refusal never reaches the question of what the refusal did to everyone else's data, which is
 * where the severity actually is.
 */
TEST_F(SearchGroupRejectedWriteTest, committed_documents_survive_a_refused_write) {
    std::string groupId, indexId;
    createGroupAndIndex(groupId, indexId);
    Ledger ledger;

    // Both handles are taken while both are still members: bob's has to predate the epoch change.
    ASSERT_NO_THROW({ alice.handle = alice.searchApi->openSearchIndex(indexId); });
    ASSERT_NO_THROW({ bob.handle = bob.searchApi->openSearchIndex(indexId); });

    addDocument(alice, alice.handle, "a1", "alpha one", ledger);
    ASSERT_EQ(countThrough(alice, alice.handle), ledger.committed);

    removeBobFromGroup(groupId);
    addDocument(alice, alice.handle, "a2", "alpha two", ledger);
    addBobToGroup(groupId);

    tryCall([&] { bob.searchApi->closeSearchIndex(bob.handle); });
    bob.handle = -1;
    auto reopenError = tryCall([&] { bob.handle = bob.searchApi->openSearchIndex(indexId); });
    if (!reopenError.has_value()) {
        addDocument(bob, bob.handle, "b1", "bravo one", ledger);
    } else {
        GTEST_LOG_(INFO) << "bob could not reopen the Index: " << reopenError.value();
    }
    reportRefusals(ledger);

    // alice was never removed from the Group and her handle stayed open the whole way through, so a refused
    // write by anyone else may not cost her a single document.
    EXPECT_EQ(countThrough(alice, alice.handle), ledger.committed)
        << "a refused write destroyed committed data, seen through a handle whose owner never lost access";
    // And it may not leave the Index in a state that no longer opens: there is no recovery path from that.
    EXPECT_EQ(countFromFreshOpen(alice, indexId), ledger.committed) << "the Index no longer reads back correctly";
}

/**
 * The same cycle with nobody writing during the absence — reported to survive it, and measured here not to.
 *
 * Keeping it is what makes the condition list honest. The report has the write in the middle as required, but
 * that was measured against a build whose write path already refreshed a stale key, so alice's write there
 * succeeded and re-keyed the Index as a side effect. Without that refresh the epoch change alone is enough and
 * this flow loses the documents too, which says the write in the middle was never the trigger.
 */
TEST_F(SearchGroupRejectedWriteTest, readd_without_a_write_during_the_absence_survives) {
    std::string groupId, indexId;
    createGroupAndIndex(groupId, indexId);
    Ledger ledger;

    ASSERT_NO_THROW({ alice.handle = alice.searchApi->openSearchIndex(indexId); });
    ASSERT_NO_THROW({ bob.handle = bob.searchApi->openSearchIndex(indexId); });
    addDocument(alice, alice.handle, "a1", "alpha one", ledger);
    ASSERT_EQ(countThrough(alice, alice.handle), ledger.committed);

    removeBobFromGroup(groupId);
    addBobToGroup(groupId);

    tryCall([&] { bob.searchApi->closeSearchIndex(bob.handle); });
    bob.handle = -1;
    auto reopenError = tryCall([&] { bob.handle = bob.searchApi->openSearchIndex(indexId); });
    if (!reopenError.has_value()) {
        addDocument(bob, bob.handle, "b1", "bravo one", ledger);
    } else {
        GTEST_LOG_(INFO) << "bob could not reopen the Index: " << reopenError.value();
    }
    reportRefusals(ledger);

    EXPECT_EQ(countThrough(alice, alice.handle), ledger.committed);
    EXPECT_EQ(countFromFreshOpen(alice, indexId), ledger.committed);
}

/**
 * The report's own claim, kept separate because it is about access rather than about data: a member who is added
 * back is a full member again, so his write is supposed to go through.
 *
 * Reaching it needs alice's write during the absence to succeed first, which is the previous test's subject — so
 * this one stays red until the write path refreshes a stale key, and its refusal message says which of the two
 * writes is still being turned away.
 */
TEST_F(SearchGroupRejectedWriteTest, readd_member_can_write_again) {
    std::string groupId, indexId;
    createGroupAndIndex(groupId, indexId);
    Ledger ledger;

    ASSERT_NO_THROW({ alice.handle = alice.searchApi->openSearchIndex(indexId); });
    ASSERT_NO_THROW({ bob.handle = bob.searchApi->openSearchIndex(indexId); });
    addDocument(alice, alice.handle, "a1", "alpha one", ledger);

    removeBobFromGroup(groupId);
    addDocument(alice, alice.handle, "a2", "alpha two", ledger);
    addBobToGroup(groupId);

    tryCall([&] { bob.searchApi->closeSearchIndex(bob.handle); });
    bob.handle = -1;
    ASSERT_NO_THROW({ bob.handle = bob.searchApi->openSearchIndex(indexId); });

    addDocument(bob, bob.handle, "b1", "bravo one", ledger);
    reportRefusals(ledger);
    EXPECT_EQ(ledger.committed, 3) << "not every write went through; see the refusals above";
    EXPECT_EQ(countFromFreshOpen(alice, indexId), 3);
}
