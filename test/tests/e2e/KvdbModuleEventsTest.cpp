/**
 * One test per kvdb event type, each asserting the envelope and the payload that event carries.
 *
 * unsubscribeFrom is one API function, so it is tested once per subscription channel rather than once per
 * event type: the kvdb channel and the per-kvdb entries channel are built differently, everything past that
 * is the same call. The seven "_disabled" tests this replaces differed only in which operation they triggered.
 */
#include "../../utils/BaseEndpointEventTest.hpp"
#include <privmx/endpoint/kvdb/KvdbApi.hpp>
#include <privmx/endpoint/kvdb/Events.hpp>
#include <privmx/endpoint/kvdb/KvdbException.hpp>
#include <privmx/endpoint/core/CoreException.hpp>
#include <privmx/crypto/Crypto.hpp>
#include <privmx/endpoint/core/VarSerializer.hpp>

using namespace privmx::endpoint;

class KvdbEventTest : public privmx::test::BaseEndpointEventTest {
protected:
    void setUpModuleApis() override {
        kvdbApi = std::make_shared<kvdb::KvdbApi>(
            kvdb::KvdbApi::create(*connection)
        );
    }
    void tearDownModuleApis() override {
        kvdbApi.reset();
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

    std::string contextId() {
        return reader->getString("Context_1.contextId");
    }

    std::string kvdbId(int index) {
        return reader->getString("Kvdb_" + std::to_string(index) + ".kvdbId");
    }

    std::string entryKey(int index) {
        return reader->getString("KvdbEntry_" + std::to_string(index) + ".info_key");
    }

    std::string entriesChannel(int index) {
        return "kvdb/" + kvdbId(index) + "/entries";
    }

    std::vector<std::string> subscribe(
        kvdb::EventType type, kvdb::EventSelectorType selector, const std::string& selectorId
    ) {
        return kvdbApi->subscribeFor({kvdbApi->buildSubscriptionQuery(type, selector, selectorId)});
    }

    // The envelope every kvdb event shares. Returns the event so the caller can extract its payload, which
    // is why the guards are `if` rather than ASSERT_ - a helper returning a value cannot use those.
    std::shared_ptr<core::Event> expectEvent(const std::string& type, const std::string& channel) {
        auto eventHolder = waitForEvent(type, {connection->getConnectionId()});
        EXPECT_TRUE(eventHolder.has_value());
        if(!eventHolder.has_value()) {
            return nullptr;
        }
        auto event = eventHolder.value().get();
        EXPECT_NE(event, nullptr);
        if(event == nullptr) {
            return nullptr;
        }
        EXPECT_EQ(event->connectionId, connection->getConnectionId());
        EXPECT_EQ(event->type, type);
        EXPECT_EQ(event->channel, channel);
        EXPECT_EQ(event->subscriptions.size(), 1);
        return event;
    }

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

    std::shared_ptr<kvdb::KvdbApi> kvdbApi;
};

TEST_F(KvdbEventTest, waitEvent_getEvent_kvdbCreated) {
    eventQueue.waitEvent();
    subscribe(kvdb::EventType::KVDB_CREATE, kvdb::EventSelectorType::CONTEXT_ID, contextId());
    kvdbApi->createKvdb(
        contextId(), users({1}), users({1}),
        core::Buffer::from("public"), core::Buffer::from("private")
    );
    auto event = expectEvent("kvdbCreated", "kvdb");
    ASSERT_NE(event, nullptr);
    ASSERT_TRUE(kvdb::Events::isKvdbCreatedEvent(event));
    kvdb::Kvdb kvdb = kvdb::Events::extractKvdbCreatedEvent(event).data;
    EXPECT_EQ(kvdb.contextId, contextId());
    EXPECT_EQ(kvdb.publicMeta.stdString(), "public");
    EXPECT_EQ(kvdb.privateMeta.stdString(), "private");
    expectMembers(kvdb, {1}, {1});
}

TEST_F(KvdbEventTest, waitEvent_getEvent_kvdbUpdated) {
    eventQueue.waitEvent();
    subscribe(kvdb::EventType::KVDB_UPDATE, kvdb::EventSelectorType::CONTEXT_ID, contextId());
    kvdbApi->updateKvdb(
        kvdbId(1), users({1}), users({1}),
        core::Buffer::from("public"), core::Buffer::from("private"), 1, true, true
    );
    auto event = expectEvent("kvdbUpdated", "kvdb");
    ASSERT_NE(event, nullptr);
    ASSERT_TRUE(kvdb::Events::isKvdbUpdatedEvent(event));
    kvdb::Kvdb kvdb = kvdb::Events::extractKvdbUpdatedEvent(event).data;
    EXPECT_EQ(kvdb.contextId, contextId());
    EXPECT_EQ(kvdb.publicMeta.stdString(), "public");
    EXPECT_EQ(kvdb.privateMeta.stdString(), "private");
    expectMembers(kvdb, {1}, {1});
}

TEST_F(KvdbEventTest, waitEvent_getEvent_kvdbDeleted) {
    eventQueue.waitEvent();
    subscribe(kvdb::EventType::KVDB_DELETE, kvdb::EventSelectorType::CONTEXT_ID, contextId());
    kvdbApi->deleteKvdb(kvdbId(1));
    auto event = expectEvent("kvdbDeleted", "kvdb");
    ASSERT_NE(event, nullptr);
    ASSERT_TRUE(kvdb::Events::isKvdbDeletedEvent(event));
    kvdb::KvdbDeletedEventData kvdbDeleted = kvdb::Events::extractKvdbDeletedEvent(event).data;
    EXPECT_EQ(kvdbDeleted.kvdbId, kvdbId(1));
}

TEST_F(KvdbEventTest, waitEvent_getEvent_kvdbStats) {
    eventQueue.waitEvent();
    subscribe(kvdb::EventType::KVDB_STATS, kvdb::EventSelectorType::CONTEXT_ID, contextId());
    kvdbApi->deleteEntry(kvdbId(1), entryKey(1));
    auto event = expectEvent("kvdbStatsChanged", "kvdb");
    ASSERT_NE(event, nullptr);
    ASSERT_TRUE(kvdb::Events::isKvdbStatsEvent(event));
    kvdb::KvdbStatsEventData kvdbStat = kvdb::Events::extractKvdbStatsEvent(event).data;
    EXPECT_EQ(kvdbStat.kvdbId, kvdbId(1));
    EXPECT_EQ(kvdbStat.entries, 1);
}

TEST_F(KvdbEventTest, waitEvent_getEvent_kvdbNewEntry) {
    eventQueue.waitEvent();
    subscribe(kvdb::EventType::ENTRY_CREATE, kvdb::EventSelectorType::KVDB_ID, kvdbId(1));
    kvdbApi->setEntry(
        kvdbId(1), "key", core::Buffer::from("publicMeta"),
        core::Buffer::from("privateMeta"), core::Buffer::from("data"), 0
    );
    auto event = expectEvent("kvdbNewEntry", entriesChannel(1));
    ASSERT_NE(event, nullptr);
    ASSERT_TRUE(kvdb::Events::isKvdbNewEntryEvent(event));
    kvdb::KvdbEntry kvdbEntry = kvdb::Events::extractKvdbNewEntryEvent(event).data;
    EXPECT_EQ(kvdbEntry.publicMeta.stdString(), "publicMeta");
    EXPECT_EQ(kvdbEntry.privateMeta.stdString(), "privateMeta");
    EXPECT_EQ(kvdbEntry.data.stdString(), "data");
    EXPECT_EQ(kvdbEntry.info.kvdbId, kvdbId(1));
}

TEST_F(KvdbEventTest, waitEvent_getEvent_kvdbEntryUpdated) {
    eventQueue.waitEvent();
    subscribe(kvdb::EventType::ENTRY_UPDATE, kvdb::EventSelectorType::KVDB_ID, kvdbId(1));
    kvdbApi->setEntry(
        kvdbId(1), entryKey(1), core::Buffer::from("publicMeta"),
        core::Buffer::from("privateMeta"), core::Buffer::from("data"), 1
    );
    auto event = expectEvent("kvdbEntryUpdated", entriesChannel(1));
    ASSERT_NE(event, nullptr);
    ASSERT_TRUE(kvdb::Events::isKvdbEntryUpdatedEvent(event));
    kvdb::KvdbEntry kvdbEntry = kvdb::Events::extractKvdbEntryUpdatedEvent(event).data;
    EXPECT_EQ(kvdbEntry.info.key, entryKey(1));
    EXPECT_EQ(kvdbEntry.publicMeta.stdString(), "publicMeta");
    EXPECT_EQ(kvdbEntry.privateMeta.stdString(), "privateMeta");
    EXPECT_EQ(kvdbEntry.data.stdString(), "data");
    EXPECT_EQ(kvdbEntry.info.kvdbId, kvdbId(1));
}

TEST_F(KvdbEventTest, waitEvent_getEvent_kvdbEntryDeleted) {
    eventQueue.waitEvent();
    subscribe(kvdb::EventType::ENTRY_DELETE, kvdb::EventSelectorType::KVDB_ID, kvdbId(1));
    kvdbApi->deleteEntry(kvdbId(1), entryKey(1));
    auto event = expectEvent("kvdbEntryDeleted", entriesChannel(1));
    ASSERT_NE(event, nullptr);
    ASSERT_TRUE(kvdb::Events::isKvdbEntryDeletedEvent(event));
    kvdb::KvdbDeletedEntryEventData deleted = kvdb::Events::extractKvdbEntryDeletedEvent(event).data;
    EXPECT_EQ(deleted.kvdbEntryKey, entryKey(1));
    EXPECT_EQ(deleted.kvdbId, kvdbId(1));
}

TEST_F(KvdbEventTest, buildSubscriptionQueryForSelectedEntry) {
    // A query narrowed to one key still arrives on the whole kvdb's entries channel.
    eventQueue.waitEvent();
    kvdbApi->subscribeFor({
        kvdbApi->buildSubscriptionQueryForSelectedEntry(
            kvdb::EventType::ENTRY_UPDATE, kvdbId(1), entryKey(1)
        )
    });
    kvdbApi->setEntry(
        kvdbId(1), entryKey(1), core::Buffer::from("publicMeta"),
        core::Buffer::from("privateMeta"), core::Buffer::from("data"), 1
    );
    auto eventHolder = waitForEvent("kvdbEntryUpdated", {connection->getConnectionId()});
    ASSERT_TRUE(eventHolder.has_value());
    auto event = eventHolder.value().get();
    ASSERT_NE(event, nullptr);
    EXPECT_EQ(event->connectionId, connection->getConnectionId());
    EXPECT_EQ(event->type, "kvdbEntryUpdated");
    EXPECT_EQ(event->channel, entriesChannel(1));
    ASSERT_TRUE(kvdb::Events::isKvdbEntryUpdatedEvent(event));
    kvdb::KvdbEntry kvdbEntry = kvdb::Events::extractKvdbEntryUpdatedEvent(event).data;
    EXPECT_EQ(kvdbEntry.info.key, entryKey(1));
    EXPECT_EQ(kvdbEntry.publicMeta.stdString(), "publicMeta");
    EXPECT_EQ(kvdbEntry.privateMeta.stdString(), "privateMeta");
    EXPECT_EQ(kvdbEntry.data.stdString(), "data");
    EXPECT_EQ(kvdbEntry.info.kvdbId, kvdbId(1));
}

TEST_F(KvdbEventTest, unsubscribeFrom_silences_the_kvdb_channel) {
    eventQueue.waitEvent();
    auto ids = subscribe(kvdb::EventType::KVDB_CREATE, kvdb::EventSelectorType::CONTEXT_ID, contextId());
    kvdbApi->unsubscribeFrom(ids);
    kvdbApi->createKvdb(
        contextId(), users({1}), users({1}),
        core::Buffer::from("public"), core::Buffer::from("private")
    );
    assertNoEventReceived();
}

TEST_F(KvdbEventTest, unsubscribeFrom_silences_the_entries_channel) {
    eventQueue.waitEvent();
    auto ids = subscribe(kvdb::EventType::ENTRY_CREATE, kvdb::EventSelectorType::KVDB_ID, kvdbId(1));
    kvdbApi->unsubscribeFrom(ids);
    kvdbApi->setEntry(
        kvdbId(1), "key", core::Buffer::from("publicMeta"),
        core::Buffer::from("privateMeta"), core::Buffer::from("data"), 0
    );
    assertNoEventReceived();
}

TEST_F(KvdbEventTest, subscribeFor_query_from_other_module) {
    EXPECT_THROW({
        kvdbApi->subscribeFor({"kvdbs/update|contextId=" + contextId()});
    }, core::InvalidSubscriptionQueryException);
    EXPECT_THROW({
        kvdbApi->subscribeFor({"thread/update|contextId=" + contextId()});
    }, core::InvalidSubscriptionQueryException);
}

TEST_F(KvdbEventTest, subscribeFor_unsubscribeFor) {
    std::vector<std::string> valid_subscriptions;
    EXPECT_NO_THROW({
        valid_subscriptions =
            subscribe(kvdb::EventType::KVDB_CREATE, kvdb::EventSelectorType::CONTEXT_ID, contextId());
    });
    std::vector<std::string> invalid_subscriptions;
    EXPECT_NO_THROW({
        invalid_subscriptions =
            subscribe(kvdb::EventType::KVDB_CREATE, kvdb::EventSelectorType::CONTEXT_ID, "error");
    });
    EXPECT_NO_THROW({ kvdbApi->unsubscribeFrom(valid_subscriptions); });
    EXPECT_NO_THROW({ kvdbApi->unsubscribeFrom(invalid_subscriptions); });
}
