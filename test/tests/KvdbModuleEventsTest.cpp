
#include "../utils/BaseEndpointEventTest.hpp"
#include <privmx/endpoint/kvdb/KvdbApi.hpp>
#include <privmx/endpoint/kvdb/Events.hpp>
#include <privmx/endpoint/kvdb/KvdbException.hpp>
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
    std::shared_ptr<kvdb::KvdbApi> kvdbApi;
};

TEST_F(KvdbEventTest, waitEvent_getEvent_kvdbCreated_enabled) {
    eventQueue.waitEvent();
    kvdbApi->subscribeFor({
        kvdbApi->buildSubscriptionQuery(
            kvdb::EventType::KVDB_CREATE,
            kvdb::EventSelectorType::CONTEXT_ID,
            reader->getString("Context_1.contextId")
        )
    });
    kvdbApi->createKvdb(
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
    auto eventHolder = waitForEvent("kvdbCreated", {connection->getConnectionId()});
    ASSERT_TRUE(eventHolder.has_value());
    auto event = eventHolder.value().get();
    ASSERT_NE(event, nullptr);
    EXPECT_EQ(event->connectionId, connection->getConnectionId());
    EXPECT_EQ(event->type, "kvdbCreated");
    EXPECT_EQ(event->channel, "kvdb");
    ASSERT_TRUE(kvdb::Events::isKvdbCreatedEvent(event));
    EXPECT_EQ(event->subscriptions.size(), 1);
    kvdb::Kvdb kvdb = kvdb::Events::extractKvdbCreatedEvent(event).data;
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

TEST_F(KvdbEventTest, waitEvent_getEvent_kvdbCreated_disabled) {
    eventQueue.waitEvent();
    auto tmp = kvdbApi->subscribeFor({
        kvdbApi->buildSubscriptionQuery(
            kvdb::EventType::KVDB_CREATE,
            kvdb::EventSelectorType::CONTEXT_ID,
            reader->getString("Context_1.contextId")
        )
    });
    kvdbApi->unsubscribeFrom(tmp);
    kvdbApi->createKvdb(
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
    assertNoEventReceived();
}

TEST_F(KvdbEventTest, waitEvent_getEvent_kvdbUpdated_enabled) {
    eventQueue.waitEvent();
    kvdbApi->subscribeFor({
        kvdbApi->buildSubscriptionQuery(
            kvdb::EventType::KVDB_UPDATE,
            kvdb::EventSelectorType::CONTEXT_ID,
            reader->getString("Context_1.contextId")
        )
    });
    kvdbApi->updateKvdb(
        reader->getString("Kvdb_1.kvdbId"),
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
    auto eventHolder = waitForEvent("kvdbUpdated", {connection->getConnectionId()});
    ASSERT_TRUE(eventHolder.has_value());
    auto event = eventHolder.value().get();
    ASSERT_NE(event, nullptr);
    EXPECT_EQ(event->connectionId, connection->getConnectionId());
    EXPECT_EQ(event->type, "kvdbUpdated");
    EXPECT_EQ(event->channel, "kvdb");
    ASSERT_TRUE(kvdb::Events::isKvdbUpdatedEvent(event));
    EXPECT_EQ(event->subscriptions.size(), 1);
    kvdb::Kvdb kvdb = kvdb::Events::extractKvdbUpdatedEvent(event).data;
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

TEST_F(KvdbEventTest, waitEvent_getEvent_kvdbUpdated_disabled) {
    eventQueue.waitEvent();
    auto tmp = kvdbApi->subscribeFor({
        kvdbApi->buildSubscriptionQuery(
            kvdb::EventType::KVDB_UPDATE,
            kvdb::EventSelectorType::CONTEXT_ID,
            reader->getString("Context_1.contextId")
        )
    });
    kvdbApi->unsubscribeFrom(tmp);
    kvdbApi->updateKvdb(
        reader->getString("Kvdb_1.kvdbId"),
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
    assertNoEventReceived();
}

TEST_F(KvdbEventTest, waitEvent_getEvent_kvdbDeleted_enabled) {
    eventQueue.waitEvent();
    kvdbApi->subscribeFor({
        kvdbApi->buildSubscriptionQuery(
            kvdb::EventType::KVDB_DELETE,
            kvdb::EventSelectorType::CONTEXT_ID,
            reader->getString("Context_1.contextId")
        )
    });
    kvdbApi->deleteKvdb(
        reader->getString("Kvdb_1.kvdbId")
    );
    auto eventHolder = waitForEvent("kvdbDeleted", {connection->getConnectionId()});
    ASSERT_TRUE(eventHolder.has_value());
    auto event = eventHolder.value().get();
    ASSERT_NE(event, nullptr);
    EXPECT_EQ(event->connectionId, connection->getConnectionId());
    EXPECT_EQ(event->type, "kvdbDeleted");
    EXPECT_EQ(event->channel, "kvdb");
    ASSERT_TRUE(kvdb::Events::isKvdbDeletedEvent(event));
    EXPECT_EQ(event->subscriptions.size(), 1);
    kvdb::KvdbDeletedEventData kvdbDeleted = kvdb::Events::extractKvdbDeletedEvent(event).data;
    EXPECT_EQ(kvdbDeleted.kvdbId, reader->getString("Kvdb_1.kvdbId"));
}

TEST_F(KvdbEventTest, waitEvent_getEvent_kvdbDeleted_disabled) {
    eventQueue.waitEvent();
    auto tmp = kvdbApi->subscribeFor({
        kvdbApi->buildSubscriptionQuery(
            kvdb::EventType::KVDB_DELETE,
            kvdb::EventSelectorType::CONTEXT_ID,
            reader->getString("Context_1.contextId")
        )
    });
    kvdbApi->unsubscribeFrom(tmp);
    kvdbApi->deleteKvdb(
        reader->getString("Kvdb_1.kvdbId")
    );
    assertNoEventReceived();
}

TEST_F(KvdbEventTest, waitEvent_getEvent_kvdbStats_enabled) {
    eventQueue.waitEvent();
    kvdbApi->subscribeFor({
        kvdbApi->buildSubscriptionQuery(
            kvdb::EventType::KVDB_STATS,
            kvdb::EventSelectorType::CONTEXT_ID,
            reader->getString("Context_1.contextId")
        )
    });
    kvdbApi->deleteEntry(
        reader->getString("Kvdb_1.kvdbId"),
        reader->getString("KvdbEntry_1.info_key")
    );
    auto eventHolder = waitForEvent("kvdbStatsChanged", {connection->getConnectionId()});
    ASSERT_TRUE(eventHolder.has_value());
    auto event = eventHolder.value().get();
    ASSERT_NE(event, nullptr);
    EXPECT_EQ(event->connectionId, connection->getConnectionId());
    EXPECT_EQ(event->type, "kvdbStatsChanged");
    EXPECT_EQ(event->channel, "kvdb");
    ASSERT_TRUE(kvdb::Events::isKvdbStatsEvent(event));
    EXPECT_EQ(event->subscriptions.size(), 1);
    kvdb::KvdbStatsEventData kvdbStat = kvdb::Events::extractKvdbStatsEvent(event).data;
    EXPECT_EQ(kvdbStat.kvdbId, reader->getString("Kvdb_1.kvdbId"));
    EXPECT_EQ(kvdbStat.entries, 1);
}

TEST_F(KvdbEventTest, waitEvent_getEvent_kvdbStats_disabled) {
    eventQueue.waitEvent();
    auto tmp = kvdbApi->subscribeFor({
        kvdbApi->buildSubscriptionQuery(
            kvdb::EventType::KVDB_STATS,
            kvdb::EventSelectorType::CONTEXT_ID,
            reader->getString("Context_1.contextId")
        )
    });
    kvdbApi->unsubscribeFrom(tmp);
    kvdbApi->deleteEntry(
        reader->getString("Kvdb_1.kvdbId"),
        reader->getString("KvdbEntry_1.info_key")
    );
    assertNoEventReceived();
}

TEST_F(KvdbEventTest, waitEvent_getEvent_kvdbNewKvdbEntry_enabled) {
    eventQueue.waitEvent();
    kvdbApi->subscribeFor({
        kvdbApi->buildSubscriptionQuery(
            kvdb::EventType::ENTRY_CREATE,
            kvdb::EventSelectorType::KVDB_ID,
            reader->getString("Kvdb_1.kvdbId")
        )
    });
    kvdbApi->setEntry(
        reader->getString("Kvdb_1.kvdbId"),
        "key",
        core::Buffer::from("publicMeta"),
        core::Buffer::from("privateMeta"),
        core::Buffer::from("data"),
        0
    );
    auto eventHolder = waitForEvent("kvdbNewEntry", {connection->getConnectionId()});
    ASSERT_TRUE(eventHolder.has_value());
    auto event = eventHolder.value().get();
    ASSERT_NE(event, nullptr);
    EXPECT_EQ(event->connectionId, connection->getConnectionId());
    EXPECT_EQ(event->type, "kvdbNewEntry");
    EXPECT_EQ(event->channel, "kvdb/"+reader->getString("Kvdb_1.kvdbId")+"/entries");
    ASSERT_TRUE(kvdb::Events::isKvdbNewEntryEvent(event));
    EXPECT_EQ(event->subscriptions.size(), 1);
    kvdb::KvdbEntry kvdbEntry = kvdb::Events::extractKvdbNewEntryEvent(event).data;
    EXPECT_EQ(kvdbEntry.publicMeta.stdString(), "publicMeta");
    EXPECT_EQ(kvdbEntry.privateMeta.stdString(), "privateMeta");
    EXPECT_EQ(kvdbEntry.data.stdString(), "data");
    EXPECT_EQ(kvdbEntry.info.kvdbId, reader->getString("Kvdb_1.kvdbId"));
}

TEST_F(KvdbEventTest, waitEvent_getEvent_kvdbNewKvdbEntry_disabled) {
    eventQueue.waitEvent();
    auto tmp = kvdbApi->subscribeFor({
        kvdbApi->buildSubscriptionQuery(
            kvdb::EventType::ENTRY_CREATE,
            kvdb::EventSelectorType::KVDB_ID,
            reader->getString("Kvdb_1.kvdbId")
        )
    });
    kvdbApi->unsubscribeFrom(tmp);
    kvdbApi->setEntry(
        reader->getString("Kvdb_1.kvdbId"),
        "key",
        core::Buffer::from("publicMeta"),
        core::Buffer::from("privateMeta"),
        core::Buffer::from("data"),
        0
    );
    assertNoEventReceived();
}

TEST_F(KvdbEventTest, waitEvent_getEvent_kvdbUpdatedKvdbEntry_enabled) {
    eventQueue.waitEvent();
    kvdbApi->subscribeFor({
        kvdbApi->buildSubscriptionQuery(
            kvdb::EventType::ENTRY_UPDATE,
            kvdb::EventSelectorType::KVDB_ID,
            reader->getString("Kvdb_1.kvdbId")
        )
    });
    kvdbApi->setEntry(
        reader->getString("Kvdb_1.kvdbId"),
        reader->getString("KvdbEntry_1.info_key"),
        core::Buffer::from("publicMeta"),
        core::Buffer::from("privateMeta"),
        core::Buffer::from("data"),
        1
    );
    auto eventHolder = waitForEvent("kvdbEntryUpdated", {connection->getConnectionId()});
    ASSERT_TRUE(eventHolder.has_value());
    auto event = eventHolder.value().get();
    ASSERT_NE(event, nullptr);
    EXPECT_EQ(event->connectionId, connection->getConnectionId());
    EXPECT_EQ(event->type, "kvdbEntryUpdated");
    EXPECT_EQ(event->channel, "kvdb/"+reader->getString("Kvdb_1.kvdbId")+"/entries");
    ASSERT_TRUE(kvdb::Events::isKvdbEntryUpdatedEvent(event));
    EXPECT_EQ(event->subscriptions.size(), 1);
    kvdb::KvdbEntry kvdbEntry = kvdb::Events::extractKvdbEntryUpdatedEvent(event).data;
    EXPECT_EQ(kvdbEntry.info.key, reader->getString("KvdbEntry_1.info_key"));
    EXPECT_EQ(kvdbEntry.publicMeta.stdString(), "publicMeta");
    EXPECT_EQ(kvdbEntry.privateMeta.stdString(), "privateMeta");
    EXPECT_EQ(kvdbEntry.data.stdString(), "data");
    EXPECT_EQ(kvdbEntry.info.kvdbId, reader->getString("Kvdb_1.kvdbId"));
}

TEST_F(KvdbEventTest, waitEvent_getEvent_kvdbUpdatedKvdbEntry_disabled) {
    eventQueue.waitEvent();
    auto tmp = kvdbApi->subscribeFor({
        kvdbApi->buildSubscriptionQuery(
            kvdb::EventType::ENTRY_UPDATE,
            kvdb::EventSelectorType::KVDB_ID,
            reader->getString("Kvdb_1.kvdbId")
        )
    });
    kvdbApi->unsubscribeFrom(tmp);
    kvdbApi->setEntry(
        reader->getString("Kvdb_1.kvdbId"),
        reader->getString("KvdbEntry_1.info_key"),
        core::Buffer::from("publicMeta"),
        core::Buffer::from("privateMeta"),
        core::Buffer::from("data"),
        1
    );
    assertNoEventReceived();
}

TEST_F(KvdbEventTest, waitEvent_getEvent_kvdbDeletedKvdbEntry_enabled) {
    eventQueue.waitEvent();
    kvdbApi->subscribeFor({
        kvdbApi->buildSubscriptionQuery(
            kvdb::EventType::ENTRY_DELETE,
            kvdb::EventSelectorType::KVDB_ID,
            reader->getString("Kvdb_1.kvdbId")
        )
    });
    kvdbApi->deleteEntry(
        reader->getString("Kvdb_1.kvdbId"),
        reader->getString("KvdbEntry_1.info_key")
    );
    auto eventHolder = waitForEvent("kvdbEntryDeleted", {connection->getConnectionId()});
    ASSERT_TRUE(eventHolder.has_value());
    auto event = eventHolder.value().get();
    ASSERT_NE(event, nullptr);
    EXPECT_EQ(event->connectionId, connection->getConnectionId());
    EXPECT_EQ(event->type, "kvdbEntryDeleted");
    EXPECT_EQ(event->channel, "kvdb/"+reader->getString("Kvdb_1.kvdbId")+"/entries");
    ASSERT_TRUE(kvdb::Events::isKvdbEntryDeletedEvent(event));
    EXPECT_EQ(event->subscriptions.size(), 1);
    kvdb::KvdbDeletedEntryEventData kvdbDeletedKvdbEntry = kvdb::Events::extractKvdbEntryDeletedEvent(event).data;
    EXPECT_EQ(kvdbDeletedKvdbEntry.kvdbEntryKey, reader->getString("KvdbEntry_1.info_key"));
    EXPECT_EQ(kvdbDeletedKvdbEntry.kvdbId, reader->getString("Kvdb_1.kvdbId"));
}

TEST_F(KvdbEventTest, waitEvent_getEvent_kvdbDeletedKvdbEntry_disabled) {
    eventQueue.waitEvent();
    auto tmp = kvdbApi->subscribeFor({
        kvdbApi->buildSubscriptionQuery(
            kvdb::EventType::ENTRY_DELETE,
            kvdb::EventSelectorType::KVDB_ID,
            reader->getString("Kvdb_1.kvdbId")
        )
    });
    kvdbApi->unsubscribeFrom(tmp);
    kvdbApi->deleteEntry(
        reader->getString("Kvdb_1.kvdbId"),
        reader->getString("KvdbEntry_1.info_key")
    );
    assertNoEventReceived();
}

TEST_F(KvdbEventTest, Subscribe_for_singel_entry) {
    eventQueue.waitEvent();
    kvdbApi->subscribeFor({
        kvdbApi->buildSubscriptionQueryForSelectedEntry(
            kvdb::EventType::ENTRY_UPDATE,
            reader->getString("Kvdb_1.kvdbId"),
            reader->getString("KvdbEntry_1.info_key")
        )
    });
    kvdbApi->setEntry(
        reader->getString("Kvdb_1.kvdbId"),
        reader->getString("KvdbEntry_1.info_key"),
        core::Buffer::from("publicMeta"),
        core::Buffer::from("privateMeta"),
        core::Buffer::from("data"),
        1
    );
    auto eventHolder = waitForEvent("kvdbEntryUpdated", {connection->getConnectionId()});
    ASSERT_TRUE(eventHolder.has_value());
    auto event = eventHolder.value().get();
    ASSERT_NE(event, nullptr);
    EXPECT_EQ(event->connectionId, connection->getConnectionId());
    EXPECT_EQ(event->type, "kvdbEntryUpdated");
    EXPECT_EQ(event->channel, "kvdb/"+reader->getString("Kvdb_1.kvdbId")+"/entries");
    ASSERT_TRUE(kvdb::Events::isKvdbEntryUpdatedEvent(event));
    kvdb::KvdbEntry kvdbEntry = kvdb::Events::extractKvdbEntryUpdatedEvent(event).data;
    EXPECT_EQ(kvdbEntry.info.key, reader->getString("KvdbEntry_1.info_key"));
    EXPECT_EQ(kvdbEntry.publicMeta.stdString(), "publicMeta");
    EXPECT_EQ(kvdbEntry.privateMeta.stdString(), "privateMeta");
    EXPECT_EQ(kvdbEntry.data.stdString(), "data");
    EXPECT_EQ(kvdbEntry.info.kvdbId, reader->getString("Kvdb_1.kvdbId"));
}

TEST_F(KvdbEventTest, subscribeFor_query_from_other_module) {
    EXPECT_THROW({
        kvdbApi->subscribeFor({
            "kvdbs/update|contextId="+reader->getString("Context_1.contextId")
        });
    }, kvdb::InvalidSubscriptionQueryException);
    EXPECT_THROW({
        kvdbApi->subscribeFor({
            "thread/update|contextId="+reader->getString("Context_1.contextId")
        });
    }, kvdb::InvalidSubscriptionQueryException);
}

TEST_F(KvdbEventTest, subscribeFor_unsubscribeFor) {
    std::vector<std::string> valid_subscriptions;
    EXPECT_NO_THROW({
        valid_subscriptions = kvdbApi->subscribeFor({
            kvdbApi->buildSubscriptionQuery(
                kvdb::EventType::KVDB_CREATE,
                kvdb::EventSelectorType::CONTEXT_ID,
                reader->getString("Context_1.contextId")
            )
        });
    });
    std::vector<std::string> invalid_subscriptions;
    EXPECT_NO_THROW({
        invalid_subscriptions = kvdbApi->subscribeFor({
            kvdbApi->buildSubscriptionQuery(
                kvdb::EventType::KVDB_CREATE,
                kvdb::EventSelectorType::CONTEXT_ID,
                "error"
            )
        });
    });
    EXPECT_NO_THROW({
        kvdbApi->unsubscribeFrom({
            valid_subscriptions
        });
    });
    EXPECT_NO_THROW({
        kvdbApi->unsubscribeFrom({
            invalid_subscriptions
        });
    });
}
