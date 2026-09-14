/**
 * One test per store event type, each asserting the envelope and the payload that event carries.
 *
 * unsubscribeFrom is one API function, so it is tested once per subscription channel rather than once per
 * event type: the store channel and the per-store files channel are built differently, everything past that
 * is the same call. The seven "_disabled" tests this replaces differed only in which operation they triggered.
 */
#include "../../utils/BaseEndpointEventTest.hpp"
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

    std::string storeId(int index) {
        return reader->getString("Store_" + std::to_string(index) + ".storeId");
    }

    std::string fileId(int index) {
        return reader->getString("File_" + std::to_string(index) + ".info_fileId");
    }

    std::string filesChannel(int index) {
        return "store/" + storeId(index) + "/files";
    }

    std::vector<std::string> subscribe(
        store::EventType type, store::EventSelectorType selector, const std::string& selectorId
    ) {
        return storeApi->subscribeFor({storeApi->buildSubscriptionQuery(type, selector, selectorId)});
    }

    // The envelope every store event shares. Returns the event so the caller can extract its payload, which
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

    // Creates an empty file and closes it, which is what the file events are triggered by.
    std::string addEmptyFile(const std::string& id) {
        int64_t handle = storeApi->createFile(
            id, core::Buffer::from("publicMeta"), core::Buffer::from("privateMeta"), 0
        );
        return storeApi->closeFile(handle);
    }

    std::shared_ptr<store::StoreApi> storeApi;
};

TEST_F(StoreEventTest, waitEvent_getEvent_storeCreated) {
    eventQueue.waitEvent();
    subscribe(store::EventType::STORE_CREATE, store::EventSelectorType::CONTEXT_ID, contextId());
    storeApi->createStore(
        contextId(), users({1}), users({1}),
        core::Buffer::from("public"), core::Buffer::from("private")
    );
    auto event = expectEvent("storeCreated", "store");
    ASSERT_NE(event, nullptr);
    ASSERT_TRUE(store::Events::isStoreCreatedEvent(event));
    store::Store store = store::Events::extractStoreCreatedEvent(event).data;
    EXPECT_EQ(store.contextId, contextId());
    EXPECT_EQ(store.publicMeta.stdString(), "public");
    EXPECT_EQ(store.privateMeta.stdString(), "private");
    expectMembers(store, {1}, {1});
}

TEST_F(StoreEventTest, waitEvent_getEvent_storeUpdated) {
    eventQueue.waitEvent();
    subscribe(store::EventType::STORE_UPDATE, store::EventSelectorType::CONTEXT_ID, contextId());
    storeApi->updateStore(
        storeId(1), users({1}), users({1}),
        core::Buffer::from("public"), core::Buffer::from("private"), 1, true, true
    );
    auto event = expectEvent("storeUpdated", "store");
    ASSERT_NE(event, nullptr);
    ASSERT_TRUE(store::Events::isStoreUpdatedEvent(event));
    store::Store store = store::Events::extractStoreUpdatedEvent(event).data;
    EXPECT_EQ(store.contextId, contextId());
    EXPECT_EQ(store.publicMeta.stdString(), "public");
    EXPECT_EQ(store.privateMeta.stdString(), "private");
    expectMembers(store, {1}, {1});
}

TEST_F(StoreEventTest, waitEvent_getEvent_storeDeleted) {
    eventQueue.waitEvent();
    subscribe(store::EventType::STORE_DELETE, store::EventSelectorType::CONTEXT_ID, contextId());
    storeApi->deleteStore(storeId(1));
    auto event = expectEvent("storeDeleted", "store");
    ASSERT_NE(event, nullptr);
    ASSERT_TRUE(store::Events::isStoreDeletedEvent(event));
    store::StoreDeletedEventData storeDeleted = store::Events::extractStoreDeletedEvent(event).data;
    EXPECT_EQ(storeDeleted.storeId, storeId(1));
}

TEST_F(StoreEventTest, waitEvent_getEvent_storeStatsChanged) {
    eventQueue.waitEvent();
    subscribe(store::EventType::STORE_STATS, store::EventSelectorType::CONTEXT_ID, contextId());
    storeApi->deleteFile(fileId(1));
    auto event = expectEvent("storeStatsChanged", "store");
    ASSERT_NE(event, nullptr);
    ASSERT_TRUE(store::Events::isStoreStatsChangedEvent(event));
    store::StoreStatsChangedEventData storeStat = store::Events::extractStoreStatsChangedEvent(event).data;
    EXPECT_EQ(storeStat.storeId, storeId(1));
    EXPECT_EQ(storeStat.contextId, contextId());
    EXPECT_EQ(storeStat.filesCount, 1);
}

TEST_F(StoreEventTest, waitEvent_getEvent_storeFileCreated) {
    eventQueue.waitEvent();
    subscribe(store::EventType::FILE_CREATE, store::EventSelectorType::STORE_ID, storeId(1));
    ASSERT_FALSE(addEmptyFile(storeId(1)).empty()) << "storeFileClose Failed";
    auto event = expectEvent("storeFileCreated", filesChannel(1));
    ASSERT_NE(event, nullptr);
    ASSERT_TRUE(store::Events::isStoreFileCreatedEvent(event));
    store::File storeFile = store::Events::extractStoreFileCreatedEvent(event).data;
    EXPECT_EQ(storeFile.info.storeId, storeId(1));
    EXPECT_EQ(storeFile.size, 0);
    EXPECT_EQ(storeFile.publicMeta.stdString(), "publicMeta");
    EXPECT_EQ(storeFile.privateMeta.stdString(), "privateMeta");
}

TEST_F(StoreEventTest, waitEvent_getEvent_storeFileUpdated) {
    eventQueue.waitEvent();
    subscribe(store::EventType::FILE_UPDATE, store::EventSelectorType::FILE_ID, fileId(1));
    int64_t handle = storeApi->updateFile(
        fileId(1), core::Buffer::from("publicMeta"), core::Buffer::from("privateMeta"), 0
    );
    ASSERT_FALSE(storeApi->closeFile(handle).empty()) << "storeFileClose Failed";
    auto event = expectEvent("storeFileUpdated", filesChannel(1));
    ASSERT_NE(event, nullptr);
    ASSERT_TRUE(store::Events::isStoreFileUpdatedEvent(event));
    store::File storeFile = store::Events::extractStoreFileUpdatedEvent(event).data.file;
    EXPECT_EQ(storeFile.info.storeId, storeId(1));
    EXPECT_EQ(storeFile.size, 0);
    EXPECT_EQ(storeFile.publicMeta.stdString(), "publicMeta");
    EXPECT_EQ(storeFile.privateMeta.stdString(), "privateMeta");
}

TEST_F(StoreEventTest, waitEvent_getEvent_storeFileUpdated_changes) {
    eventQueue.waitEvent();
    subscribe(store::EventType::FILE_UPDATE, store::EventSelectorType::STORE_ID, storeId(1));
    int64_t writeHandle = storeApi->createFile(
        storeId(1), core::Buffer::from("pub"), core::Buffer::from("priv"), 2*128*1024, true
    );
    storeApi->writeToFile(writeHandle, core::Buffer::from(std::string(2*128*1024, 'H')));
    std::string createdId = storeApi->closeFile(writeHandle);
    int64_t rwHandle = storeApi->openFile(createdId);
    storeApi->seekInFile(rwHandle, 128*1024);
    storeApi->writeToFile(rwHandle, core::Buffer::from(std::string(64*1024, 'J')), true);
    storeApi->closeFile(rwHandle);
    auto event = expectEvent("storeFileUpdated", filesChannel(1));
    ASSERT_NE(event, nullptr);
    ASSERT_TRUE(store::Events::isStoreFileUpdatedEvent(event));
    auto eventData = store::Events::extractStoreFileUpdatedEvent(event).data;
    EXPECT_EQ(eventData.file.info.storeId, storeId(1));
    EXPECT_EQ(eventData.file.size, (128+64)*1024);
    EXPECT_EQ(eventData.file.publicMeta.stdString(), "pub");
    EXPECT_EQ(eventData.file.privateMeta.stdString(), "priv");
    ASSERT_GE(eventData.changes.size(), 1u);
    EXPECT_EQ(eventData.changes[0].pos, 128*1024);
    EXPECT_EQ(eventData.changes[0].length, 64*1024);
    EXPECT_EQ(eventData.changes[0].truncate, true);
}

TEST_F(StoreEventTest, waitEvent_getEvent_storeFileDeleted) {
    eventQueue.waitEvent();
    subscribe(store::EventType::FILE_DELETE, store::EventSelectorType::STORE_ID, storeId(1));
    storeApi->deleteFile(fileId(1));
    auto event = expectEvent("storeFileDeleted", filesChannel(1));
    ASSERT_NE(event, nullptr);
    ASSERT_TRUE(store::Events::isStoreFileDeletedEvent(event));
    store::StoreFileDeletedEventData deleted = store::Events::extractStoreFileDeletedEvent(event).data;
    EXPECT_EQ(deleted.fileId, fileId(1));
    EXPECT_EQ(deleted.storeId, reader->getString("File_1.info_storeId"));
    EXPECT_EQ(deleted.contextId, contextId());
}

TEST_F(StoreEventTest, unsubscribeFrom_silences_the_store_channel) {
    eventQueue.waitEvent();
    auto ids = subscribe(store::EventType::STORE_CREATE, store::EventSelectorType::CONTEXT_ID, contextId());
    storeApi->unsubscribeFrom(ids);
    storeApi->createStore(
        contextId(), users({1}), users({1}),
        core::Buffer::from("public"), core::Buffer::from("private")
    );
    assertNoEventReceived();
}

TEST_F(StoreEventTest, unsubscribeFrom_silences_the_files_channel) {
    eventQueue.waitEvent();
    auto ids = subscribe(store::EventType::FILE_CREATE, store::EventSelectorType::STORE_ID, storeId(1));
    storeApi->unsubscribeFrom(ids);
    ASSERT_FALSE(addEmptyFile(storeId(1)).empty()) << "storeFileClose Failed";
    assertNoEventReceived();
}

TEST_F(StoreEventTest, subscribeFor_query_from_other_module) {
    EXPECT_THROW({
        storeApi->subscribeFor({"stores/update|contextId=" + contextId()});
    }, core::InvalidSubscriptionQueryException);
    EXPECT_THROW({
        storeApi->subscribeFor({"thread/update|contextId=" + contextId()});
    }, core::InvalidSubscriptionQueryException);
}

TEST_F(StoreEventTest, subscribeFor_unsubscribeFor) {
    std::vector<std::string> valid_subscriptions;
    EXPECT_NO_THROW({
        valid_subscriptions =
            subscribe(store::EventType::STORE_CREATE, store::EventSelectorType::CONTEXT_ID, contextId());
    });
    std::vector<std::string> invalid_subscriptions;
    EXPECT_NO_THROW({
        invalid_subscriptions =
            subscribe(store::EventType::STORE_CREATE, store::EventSelectorType::CONTEXT_ID, "error");
    });
    EXPECT_NO_THROW({ storeApi->unsubscribeFrom(valid_subscriptions); });
    EXPECT_NO_THROW({ storeApi->unsubscribeFrom(invalid_subscriptions); });
}
