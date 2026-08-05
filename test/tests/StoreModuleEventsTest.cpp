
#include "../utils/BaseEndpointEventTest.hpp"
#include <privmx/endpoint/store/StoreApi.hpp>
#include <privmx/endpoint/store/Events.hpp>
#include <privmx/endpoint/store/StoreException.hpp>
#include <privmx/endpoint/core/Exception.hpp>
#include <privmx/endpoint/core/CoreException.hpp>
#include <privmx/crypto/Crypto.hpp>
#include <privmx/endpoint/core/VarSerializer.hpp>

using namespace privmx::endpoint;

class StoreEventTest : public privmx::test::BaseEndpointEventTest {
protected:
    void setUpModuleApis() override {
        storeApi = std::make_shared<store::StoreApi>(
            store::StoreApi::create(*connection)
        );
    }
    void tearDownModuleApis() override {
        storeApi.reset();
    }
    std::shared_ptr<store::StoreApi> storeApi;
};

TEST_F(StoreEventTest, waitEvent_getEvent_storeCreated_enabled) {
    eventQueue.waitEvent();
    storeApi->subscribeFor({
        storeApi->buildSubscriptionQuery(
            store::EventType::STORE_CREATE,
            store::EventSelectorType::CONTEXT_ID,
            reader->getString("Context_1.contextId")
        )
    });
    storeApi->createStore(
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
    auto eventHolder = waitForEvent("storeCreated", {connection->getConnectionId()});
    ASSERT_TRUE(eventHolder.has_value());
    auto event = eventHolder.value().get();
    ASSERT_NE(event, nullptr);
    EXPECT_EQ(event->connectionId, connection->getConnectionId());
    EXPECT_EQ(event->type, "storeCreated");
    EXPECT_EQ(event->channel, "store");
    ASSERT_TRUE(store::Events::isStoreCreatedEvent(event));
    EXPECT_EQ(event->subscriptions.size(), 1);
    store::Store store = store::Events::extractStoreCreatedEvent(event).data;
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

TEST_F(StoreEventTest, waitEvent_getEvent_storeCreated_disabled) {
    eventQueue.waitEvent();
    auto tmp = storeApi->subscribeFor({
        storeApi->buildSubscriptionQuery(
            store::EventType::STORE_CREATE,
            store::EventSelectorType::CONTEXT_ID,
            reader->getString("Context_1.contextId")
        )
    });
    storeApi->unsubscribeFrom(tmp);
    storeApi->createStore(
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

TEST_F(StoreEventTest, waitEvent_getEvent_storeUpdated_enabled) {
    eventQueue.waitEvent();
    storeApi->subscribeFor({
        storeApi->buildSubscriptionQuery(
            store::EventType::STORE_UPDATE,
            store::EventSelectorType::CONTEXT_ID,
            reader->getString("Context_1.contextId")
        )
    });
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
    auto eventHolder = waitForEvent("storeUpdated", {connection->getConnectionId()});
    ASSERT_TRUE(eventHolder.has_value());
    auto event = eventHolder.value().get();
    ASSERT_NE(event, nullptr);
    EXPECT_EQ(event->connectionId, connection->getConnectionId());
    EXPECT_EQ(event->type, "storeUpdated");
    EXPECT_EQ(event->channel, "store");
    ASSERT_TRUE(store::Events::isStoreUpdatedEvent(event));
    EXPECT_EQ(event->subscriptions.size(), 1);
    store::Store store = store::Events::extractStoreUpdatedEvent(event).data;
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

TEST_F(StoreEventTest, waitEvent_getEvent_storeUpdated_disabled) {
    eventQueue.waitEvent();
    auto tmp = storeApi->subscribeFor({
        storeApi->buildSubscriptionQuery(
            store::EventType::STORE_UPDATE,
            store::EventSelectorType::CONTEXT_ID,
            reader->getString("Context_1.contextId")
        )
    });
    storeApi->unsubscribeFrom(tmp);
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
    assertNoEventReceived();
}

TEST_F(StoreEventTest, waitEvent_getEvent_storeDeleted_enabled) {
    eventQueue.waitEvent();
    storeApi->subscribeFor({
        storeApi->buildSubscriptionQuery(
            store::EventType::STORE_DELETE,
            store::EventSelectorType::CONTEXT_ID,
            reader->getString("Context_1.contextId")
        )
    });
    storeApi->deleteStore(
        reader->getString("Store_1.storeId")
    );
    auto eventHolder = waitForEvent("storeDeleted", {connection->getConnectionId()});
    ASSERT_TRUE(eventHolder.has_value());
    auto event = eventHolder.value().get();
    ASSERT_NE(event, nullptr);
    EXPECT_EQ(event->connectionId, connection->getConnectionId());
    EXPECT_EQ(event->type, "storeDeleted");
    EXPECT_EQ(event->channel, "store");
    ASSERT_TRUE(store::Events::isStoreDeletedEvent(event));
    EXPECT_EQ(event->subscriptions.size(), 1);
    store::StoreDeletedEventData storeDeleted = store::Events::extractStoreDeletedEvent(event).data;
    EXPECT_EQ(storeDeleted.storeId, reader->getString("Store_1.storeId"));
}

TEST_F(StoreEventTest, waitEvent_getEvent_storeDeleted_disabled) {
    eventQueue.waitEvent();
    auto tmp = storeApi->subscribeFor({
        storeApi->buildSubscriptionQuery(
            store::EventType::STORE_DELETE,
            store::EventSelectorType::CONTEXT_ID,
            reader->getString("Context_1.contextId")
        )
    });
    storeApi->unsubscribeFrom(tmp);
    storeApi->deleteStore(
        reader->getString("Store_1.storeId")
    );
    assertNoEventReceived();
}

TEST_F(StoreEventTest, waitEvent_getEvent_storeStatsChanged_enabled) {
    eventQueue.waitEvent();
    storeApi->subscribeFor({
        storeApi->buildSubscriptionQuery(
            store::EventType::STORE_STATS,
            store::EventSelectorType::CONTEXT_ID,
            reader->getString("Context_1.contextId")
        )
    });
    storeApi->deleteFile(
        reader->getString("File_1.info_fileId")
    );
    auto eventHolder = waitForEvent("storeStatsChanged", {connection->getConnectionId()});
    ASSERT_TRUE(eventHolder.has_value());
    auto event = eventHolder.value().get();
    ASSERT_NE(event, nullptr);
    EXPECT_EQ(event->connectionId, connection->getConnectionId());
    EXPECT_EQ(event->type, "storeStatsChanged");
    EXPECT_EQ(event->channel, "store");
    ASSERT_TRUE(store::Events::isStoreStatsChangedEvent(event));
    EXPECT_EQ(event->subscriptions.size(), 1);
    store::StoreStatsChangedEventData storeStat = store::Events::extractStoreStatsChangedEvent(event).data;
    EXPECT_EQ(storeStat.storeId, reader->getString("Store_1.storeId"));
    EXPECT_EQ(storeStat.contextId, reader->getString("Context_1.contextId"));
    EXPECT_EQ(storeStat.filesCount, 1);
}

TEST_F(StoreEventTest, waitEvent_getEvent_storeStatsChanged_disabled) {
    eventQueue.waitEvent();
    auto tmp = storeApi->subscribeFor({
        storeApi->buildSubscriptionQuery(
            store::EventType::STORE_STATS,
            store::EventSelectorType::CONTEXT_ID,
            reader->getString("Context_1.contextId")
        )
    });
    storeApi->unsubscribeFrom(tmp);
    storeApi->deleteFile(
        reader->getString("File_1.info_fileId")
    );
    assertNoEventReceived();
}

TEST_F(StoreEventTest, waitEvent_getEvent_storeFileCreated_enabled) {
    eventQueue.waitEvent();
    storeApi->subscribeFor({
        storeApi->buildSubscriptionQuery(
            store::EventType::FILE_CREATE,
            store::EventSelectorType::STORE_ID,
            reader->getString("Store_1.storeId")
        )
    });
    int64_t handle = storeApi->createFile(
        reader->getString("Store_1.storeId"),
        privmx::endpoint::core::Buffer::from("publicMeta"),
        privmx::endpoint::core::Buffer::from("privateMeta"),
        0
    );
    ASSERT_EQ(handle, 1) << "storeFileCreate Failed";
    std::string fileId = storeApi->closeFile(handle);
    ASSERT_FALSE(fileId.empty()) << "storeFileClose Failed";
    auto eventHolder = waitForEvent("storeFileCreated", {connection->getConnectionId()});
    ASSERT_TRUE(eventHolder.has_value());
    auto event = eventHolder.value().get();
    ASSERT_NE(event, nullptr);
    EXPECT_EQ(event->connectionId, connection->getConnectionId());
    EXPECT_EQ(event->type, "storeFileCreated");
    EXPECT_EQ(event->channel, "store/" + reader->getString("Store_1.storeId") + "/files");
    ASSERT_TRUE(store::Events::isStoreFileCreatedEvent(event));
    EXPECT_EQ(event->subscriptions.size(), 1);
    store::File storeFile = store::Events::extractStoreFileCreatedEvent(event).data;
    EXPECT_EQ(storeFile.info.storeId, reader->getString("Store_1.storeId"));
    EXPECT_EQ(storeFile.size, 0);
    EXPECT_EQ(storeFile.publicMeta.stdString(), "publicMeta");
    EXPECT_EQ(storeFile.privateMeta.stdString(), "privateMeta");
}

TEST_F(StoreEventTest, waitEvent_getEvent_storeFileCreated_disabled) {
    eventQueue.waitEvent();
    auto tmp = storeApi->subscribeFor({
        storeApi->buildSubscriptionQuery(
            store::EventType::FILE_CREATE,
            store::EventSelectorType::STORE_ID,
            reader->getString("Store_1.storeId")
        )
    });
    storeApi->unsubscribeFrom(tmp);
    int64_t handle = storeApi->createFile(
        reader->getString("Store_1.storeId"),
        privmx::endpoint::core::Buffer::from("publicMeta"),
        privmx::endpoint::core::Buffer::from("privateMeta"),
        0
    );
    ASSERT_EQ(handle, 1) << "storeFileCreate Failed";
    std::string fileId = storeApi->closeFile(handle);
    ASSERT_FALSE(fileId.empty()) << "storeFileClose Failed";
    assertNoEventReceived();
}

TEST_F(StoreEventTest, waitEvent_getEvent_storeFileUpdated_enabled) {
    eventQueue.waitEvent();
    storeApi->subscribeFor({
        storeApi->buildSubscriptionQuery(
            store::EventType::FILE_UPDATE,
            store::EventSelectorType::FILE_ID,
            reader->getString("File_1.info_fileId")
        )
    });
    int64_t handle = storeApi->updateFile(
        reader->getString("File_1.info_fileId"),
        privmx::endpoint::core::Buffer::from("publicMeta"),
        privmx::endpoint::core::Buffer::from("privateMeta"),
        0
    );
    ASSERT_EQ(handle, 1) << "storeFileCreate Failed";
    std::string fileId = storeApi->closeFile(handle);
    ASSERT_FALSE(fileId.empty()) << "storeFileClose Failed";
    auto eventHolder = waitForEvent("storeFileUpdated", {connection->getConnectionId()});
    ASSERT_TRUE(eventHolder.has_value());
    auto event = eventHolder.value().get();
    ASSERT_NE(event, nullptr);
    EXPECT_EQ(event->connectionId, connection->getConnectionId());
    EXPECT_EQ(event->type, "storeFileUpdated");
    EXPECT_EQ(event->channel, "store/" + reader->getString("Store_1.storeId") + "/files");
    ASSERT_TRUE(store::Events::isStoreFileUpdatedEvent(event));
    EXPECT_EQ(event->subscriptions.size(), 1);
    store::File storeFile = store::Events::extractStoreFileUpdatedEvent(event).data.file;
    EXPECT_EQ(storeFile.info.storeId, reader->getString("Store_1.storeId"));
    EXPECT_EQ(storeFile.size, 0);
    EXPECT_EQ(storeFile.publicMeta.stdString(), "publicMeta");
    EXPECT_EQ(storeFile.privateMeta.stdString(), "privateMeta");
}

TEST_F(StoreEventTest, waitEvent_getEvent_storeFileUpdated_disabled) {
    eventQueue.waitEvent();
    auto tmp = storeApi->subscribeFor({
        storeApi->buildSubscriptionQuery(
            store::EventType::FILE_UPDATE,
            store::EventSelectorType::FILE_ID,
            reader->getString("File_1.info_fileId")
        )
    });
    storeApi->unsubscribeFrom(tmp);
    int64_t handle = storeApi->updateFile(
        reader->getString("File_1.info_fileId"),
        privmx::endpoint::core::Buffer::from("publicMeta"),
        privmx::endpoint::core::Buffer::from("privateMeta"),
        0
    );
    ASSERT_EQ(handle, 1) << "storeFileCreate Failed";
    std::string fileId = storeApi->closeFile(handle);
    ASSERT_FALSE(fileId.empty()) << "storeFileClose Failed";
    assertNoEventReceived();
}

TEST_F(StoreEventTest, waitEvent_getEvent_storeFileDeleted_enabled) {
    eventQueue.waitEvent();
    storeApi->subscribeFor({
        storeApi->buildSubscriptionQuery(
            store::EventType::FILE_DELETE,
            store::EventSelectorType::STORE_ID,
            reader->getString("Store_1.storeId")
        )
    });
    storeApi->deleteFile(
        reader->getString("File_1.info_fileId")
    );
    auto eventHolder = waitForEvent("storeFileDeleted", {connection->getConnectionId()});
    ASSERT_TRUE(eventHolder.has_value());
    auto event = eventHolder.value().get();
    ASSERT_NE(event, nullptr);
    EXPECT_EQ(event->connectionId, connection->getConnectionId());
    EXPECT_EQ(event->type, "storeFileDeleted");
    EXPECT_EQ(event->channel, "store/" + reader->getString("Store_1.storeId") + "/files");
    ASSERT_TRUE(store::Events::isStoreFileDeletedEvent(event));
    EXPECT_EQ(event->subscriptions.size(), 1);
    store::StoreFileDeletedEventData storeFileDeleted = store::Events::extractStoreFileDeletedEvent(event).data;
    EXPECT_EQ(storeFileDeleted.fileId, reader->getString("File_1.info_fileId"));
    EXPECT_EQ(storeFileDeleted.storeId, reader->getString("File_1.info_storeId"));
    EXPECT_EQ(storeFileDeleted.contextId, reader->getString("Context_1.contextId"));
}

TEST_F(StoreEventTest, waitEvent_getEvent_storeFileDeleted_disabled) {
    eventQueue.waitEvent();
    auto tmp = storeApi->subscribeFor({
        storeApi->buildSubscriptionQuery(
            store::EventType::FILE_DELETE,
            store::EventSelectorType::STORE_ID,
            reader->getString("Store_1.storeId")
        )
    });
    storeApi->unsubscribeFrom(tmp);
    storeApi->deleteFile(
        reader->getString("File_1.info_fileId")
    );
    assertNoEventReceived();
}

TEST_F(StoreEventTest, waitEvent_getEvent_storeFileUpdated_changes) {
    eventQueue.waitEvent();
    storeApi->subscribeFor({
        storeApi->buildSubscriptionQuery(
            store::EventType::FILE_UPDATE,
            store::EventSelectorType::STORE_ID,
            reader->getString("Store_1.storeId")
        )
    });
    auto writeHandle = storeApi->createFile(reader->getString("Store_1.storeId"), core::Buffer::from("pub"), core::Buffer::from("priv"), 2*128*1024, true);
    storeApi->writeToFile(writeHandle, core::Buffer::from(std::string(2*128*1024, 'H')));
    std::string fileId = storeApi->closeFile(writeHandle);
    auto RWHandle = storeApi->openFile(fileId);
    storeApi->seekInFile(RWHandle, 128*1024);
    storeApi->writeToFile(RWHandle, core::Buffer::from(std::string(64*1024, 'J')), true);
    storeApi->closeFile(RWHandle);
    auto eventHolder = waitForEvent("storeFileUpdated", {connection->getConnectionId()});
    ASSERT_TRUE(eventHolder.has_value());
    auto event = eventHolder.value().get();
    ASSERT_NE(event, nullptr);
    EXPECT_EQ(event->connectionId, connection->getConnectionId());
    EXPECT_EQ(event->type, "storeFileUpdated");
    EXPECT_EQ(event->channel, "store/" + reader->getString("Store_1.storeId") + "/files");
    ASSERT_TRUE(store::Events::isStoreFileUpdatedEvent(event));
    EXPECT_EQ(event->subscriptions.size(), 1);
    auto eventData = store::Events::extractStoreFileUpdatedEvent(event).data;
    store::File storeFile = eventData.file;
    EXPECT_EQ(storeFile.info.storeId, reader->getString("Store_1.storeId"));
    EXPECT_EQ(storeFile.size, (128+64)*1024);
    EXPECT_EQ(storeFile.publicMeta.stdString(), "pub");
    EXPECT_EQ(storeFile.privateMeta.stdString(), "priv");
    ASSERT_GE(eventData.changes.size(), 1u);
    auto change = eventData.changes[0];
    EXPECT_EQ(change.pos, 128*1024);
    EXPECT_EQ(change.length, 64*1024);
    EXPECT_EQ(change.truncate, true);
}

TEST_F(StoreEventTest, subscribeFor_query_from_other_module) {
    EXPECT_THROW({
        storeApi->subscribeFor({
            "stores/update|contextId="+reader->getString("Context_1.contextId")
        });
    }, core::InvalidSubscriptionQueryException);
    EXPECT_THROW({
        storeApi->subscribeFor({
            "thread/update|contextId="+reader->getString("Context_1.contextId")
        });
    }, core::InvalidSubscriptionQueryException);
}

TEST_F(StoreEventTest, subscribeFor_unsubscribeFor) {
    std::vector<std::string> valid_subscriptions;
    EXPECT_NO_THROW({
        valid_subscriptions = storeApi->subscribeFor({
            storeApi->buildSubscriptionQuery(
                store::EventType::STORE_CREATE,
                store::EventSelectorType::CONTEXT_ID,
                reader->getString("Context_1.contextId")
            )
        });
    });
    std::vector<std::string> invalid_subscriptions;
    EXPECT_NO_THROW({
        invalid_subscriptions = storeApi->subscribeFor({
            storeApi->buildSubscriptionQuery(
                store::EventType::STORE_CREATE,
                store::EventSelectorType::CONTEXT_ID,
                "error"
            )
        });
    });
    EXPECT_NO_THROW({
        storeApi->unsubscribeFrom({
            valid_subscriptions
        });
    });
    EXPECT_NO_THROW({
        storeApi->unsubscribeFrom({
            invalid_subscriptions
        });
    });
}
