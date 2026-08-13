
#include "../utils/BaseEndpointEventTest.hpp"
#include <privmx/endpoint/thread/ThreadApi.hpp>
#include <privmx/endpoint/thread/Events.hpp>
#include <privmx/endpoint/thread/ThreadException.hpp>
#include <privmx/endpoint/store/StoreApi.hpp>
#include <privmx/endpoint/store/Events.hpp>
#include <privmx/endpoint/store/StoreException.hpp>
#include <privmx/endpoint/inbox/InboxApi.hpp>
#include <privmx/endpoint/inbox/Events.hpp>
#include <privmx/endpoint/inbox/InboxException.hpp>
#include <privmx/endpoint/core/Exception.hpp>
#include <privmx/endpoint/core/CoreException.hpp>
#include <privmx/crypto/Crypto.hpp>
#include <privmx/endpoint/core/VarSerializer.hpp>

using namespace privmx::endpoint;

class InboxEventTest : public privmx::test::BaseEndpointEventTest {
protected:
    void setUpModuleApis() override {
        threadApi = std::make_shared<thread::ThreadApi>(
            thread::ThreadApi::create(*connection)
        );
        storeApi = std::make_shared<store::StoreApi>(
            store::StoreApi::create(*connection)
        );
        inboxApi = std::make_shared<inbox::InboxApi>(
            inbox::InboxApi::create(*connection, *threadApi, *storeApi)
        );
    }
    void tearDownModuleApis() override {
        inboxApi.reset();
        storeApi.reset();
        threadApi.reset();
    }
    std::shared_ptr<thread::ThreadApi> threadApi;
    std::shared_ptr<store::StoreApi> storeApi;
    std::shared_ptr<inbox::InboxApi> inboxApi;
};

TEST_F(InboxEventTest, waitEvent_getEvent_inboxCreated_enabled) {
    eventQueue.waitEvent();
    inboxApi->subscribeFor({
        inboxApi->buildSubscriptionQuery(
            inbox::EventType::INBOX_CREATE,
            inbox::EventSelectorType::CONTEXT_ID,
            reader->getString("Context_1.contextId")
        )
    });
    inboxApi->createInbox(
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
        std::nullopt
    );
    auto eventHolder = waitForEvent("inboxCreated", {connection->getConnectionId()});
    ASSERT_TRUE(eventHolder.has_value());
    auto event = eventHolder.value().get();
    ASSERT_NE(event, nullptr);
    EXPECT_EQ(event->connectionId, connection->getConnectionId());
    EXPECT_EQ(event->type, "inboxCreated");
    EXPECT_EQ(event->channel, "inbox");
    ASSERT_TRUE(inbox::Events::isInboxCreatedEvent(event));
    EXPECT_EQ(event->subscriptions.size(), 1);
    inbox::Inbox inbox = inbox::Events::extractInboxCreatedEvent(event).data;
    EXPECT_EQ(inbox.contextId, reader->getString("Context_1.contextId"));
    EXPECT_EQ(inbox.users.size(), 1);
    if(inbox.users.size() == 1) {
        EXPECT_EQ(inbox.users[0], reader->getString("Login.user_1_id"));
    }
    EXPECT_EQ(inbox.managers.size(), 1);
    if(inbox.managers.size() == 1) {
        EXPECT_EQ(inbox.managers[0], reader->getString("Login.user_1_id"));
    }
    EXPECT_EQ(inbox.publicMeta.stdString(), "public");
    EXPECT_EQ(inbox.privateMeta.stdString(), "private");
    assertNoEventReceived(std::chrono::milliseconds(0));
}

TEST_F(InboxEventTest, waitEvent_getEvent_inboxCreated_disabled) {
    eventQueue.waitEvent();
    auto tmp = inboxApi->subscribeFor({
        inboxApi->buildSubscriptionQuery(
            inbox::EventType::INBOX_CREATE,
            inbox::EventSelectorType::CONTEXT_ID,
            reader->getString("Context_1.contextId")
        )
    });
    inboxApi->unsubscribeFrom(tmp);
    inboxApi->createInbox(
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
        std::nullopt
    );
    assertNoEventReceived();
}

TEST_F(InboxEventTest, waitEvent_getEvent_inboxUpdated_enabled) {
    eventQueue.waitEvent();
    inboxApi->subscribeFor({
        inboxApi->buildSubscriptionQuery(
            inbox::EventType::INBOX_UPDATE,
            inbox::EventSelectorType::CONTEXT_ID,
            reader->getString("Context_1.contextId")
        )
    });
    inboxApi->updateInbox(
        reader->getString("Inbox_1.inboxId"),
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
        std::nullopt,
        1,
        true,
        false
    );
    auto eventHolder = waitForEvent("inboxUpdated", {connection->getConnectionId()});
    ASSERT_TRUE(eventHolder.has_value());
    auto event = eventHolder.value().get();
    ASSERT_NE(event, nullptr);
    EXPECT_EQ(event->connectionId, connection->getConnectionId());
    EXPECT_EQ(event->type, "inboxUpdated");
    EXPECT_EQ(event->channel, "inbox");
    ASSERT_TRUE(inbox::Events::isInboxUpdatedEvent(event));
    EXPECT_EQ(event->subscriptions.size(), 1);
    inbox::Inbox inbox = inbox::Events::extractInboxUpdatedEvent(event).data;
    EXPECT_EQ(inbox.contextId, reader->getString("Context_1.contextId"));
    EXPECT_EQ(inbox.users.size(), 1);
    if(inbox.users.size() == 1) {
        EXPECT_EQ(inbox.users[0], reader->getString("Login.user_1_id"));
    }
    EXPECT_EQ(inbox.managers.size(), 1);
    if(inbox.managers.size() == 1) {
        EXPECT_EQ(inbox.managers[0], reader->getString("Login.user_1_id"));
    }
    EXPECT_EQ(inbox.publicMeta.stdString(), "public");
    EXPECT_EQ(inbox.privateMeta.stdString(), "private");
    assertNoEventReceived(std::chrono::milliseconds(0));
}

TEST_F(InboxEventTest, waitEvent_getEvent_inboxUpdated_disabled) {
    eventQueue.waitEvent();
    auto tmp = inboxApi->subscribeFor({
        inboxApi->buildSubscriptionQuery(
            inbox::EventType::INBOX_UPDATE,
            inbox::EventSelectorType::CONTEXT_ID,
            reader->getString("Context_1.contextId")
        )
    });
    inboxApi->unsubscribeFrom(tmp);
    inboxApi->updateInbox(
        reader->getString("Inbox_1.inboxId"),
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
        std::nullopt,
        1,
        true,
        false
    );
    assertNoEventReceived();
}

TEST_F(InboxEventTest, waitEvent_getEvent_inboxDeleted_enabled) {
    eventQueue.waitEvent();
    inboxApi->subscribeFor({
        inboxApi->buildSubscriptionQuery(
            inbox::EventType::INBOX_DELETE,
            inbox::EventSelectorType::CONTEXT_ID,
            reader->getString("Context_1.contextId")
        )
    });
    inboxApi->deleteInbox(
        reader->getString("Inbox_1.inboxId")
    );
    auto eventHolder = waitForEvent("inboxDeleted", {connection->getConnectionId()});
    ASSERT_TRUE(eventHolder.has_value());
    auto event = eventHolder.value().get();
    ASSERT_NE(event, nullptr);
    EXPECT_EQ(event->connectionId, connection->getConnectionId());
    EXPECT_EQ(event->type, "inboxDeleted");
    EXPECT_EQ(event->channel, "inbox");
    ASSERT_TRUE(inbox::Events::isInboxDeletedEvent(event));
    EXPECT_EQ(event->subscriptions.size(), 1);
    inbox::InboxDeletedEventData inboxDeletedEventData = inbox::Events::extractInboxDeletedEvent(event).data;
    EXPECT_EQ(inboxDeletedEventData.inboxId, reader->getString("Inbox_1.inboxId"));
    assertNoEventReceived(std::chrono::milliseconds(0));
}

TEST_F(InboxEventTest, waitEvent_getEvent_inboxDeleted_disabled) {
    eventQueue.waitEvent();
    auto tmp = inboxApi->subscribeFor({
        inboxApi->buildSubscriptionQuery(
            inbox::EventType::INBOX_DELETE,
            inbox::EventSelectorType::CONTEXT_ID,
            reader->getString("Context_1.contextId")
        )
    });
    inboxApi->unsubscribeFrom(tmp);
    inboxApi->deleteInbox(
        reader->getString("Inbox_1.inboxId")
    );
    assertNoEventReceived();
}

TEST_F(InboxEventTest, waitEvent_getEvent_inboxEntryCreated_enabled) {
    eventQueue.waitEvent();
    inboxApi->subscribeFor({
        inboxApi->buildSubscriptionQuery(
            inbox::EventType::ENTRY_CREATE,
            inbox::EventSelectorType::INBOX_ID,
            reader->getString("Inbox_1.inboxId")
        )
    });
    int64_t fileHandle = inboxApi->createFileHandle(
        privmx::endpoint::core::Buffer::from("publicMeta"),
        privmx::endpoint::core::Buffer::from("privateMeta"),
        0
    );
    ASSERT_EQ(fileHandle, 1) << "inboxCreateFileHandle Failed";
    int64_t inboxHandle = inboxApi->prepareEntry(
        reader->getString("Inbox_1.inboxId"),
        core::Buffer::from("test_inboxSendCommit"),
        {fileHandle},
        reader->getString("Login.user_1_privKey")
    );
    ASSERT_EQ(inboxHandle, 2) << "inboxSendPrepare Failed";
    inboxApi->sendEntry(inboxHandle);
    auto eventHolder = waitForEvent("inboxEntryCreated", {connection->getConnectionId()});
    ASSERT_TRUE(eventHolder.has_value());
    auto event = eventHolder.value().get();
    ASSERT_NE(event, nullptr);
    EXPECT_EQ(event->connectionId, connection->getConnectionId());
    EXPECT_EQ(event->type, "inboxEntryCreated");
    EXPECT_EQ(event->channel, "inbox/" + reader->getString("Inbox_1.inboxId") + "/entries");
    ASSERT_TRUE(inbox::Events::isInboxEntryCreatedEvent(event));
    EXPECT_EQ(event->subscriptions.size(), 1);
    inbox::InboxEntry inboxEntry = inbox::Events::extractInboxEntryCreatedEvent(event).data;
    EXPECT_EQ(inboxEntry.inboxId, reader->getString("Inbox_1.inboxId"));
    EXPECT_EQ(inboxEntry.data.stdString(), "test_inboxSendCommit");
    EXPECT_EQ(inboxEntry.files.size(), 1);
    if(inboxEntry.files.size() == 1) {
        EXPECT_EQ(inboxEntry.files[0].size, 0);
        EXPECT_EQ(inboxEntry.files[0].publicMeta.stdString(), "publicMeta");
        EXPECT_EQ(inboxEntry.files[0].privateMeta.stdString(), "privateMeta");
    }
}

TEST_F(InboxEventTest, waitEvent_getEvent_inboxEntryCreated_disabled) {
    eventQueue.waitEvent();
    auto tmp = inboxApi->subscribeFor({
        inboxApi->buildSubscriptionQuery(
            inbox::EventType::ENTRY_CREATE,
            inbox::EventSelectorType::INBOX_ID,
            reader->getString("Inbox_1.inboxId")
        )
    });
    inboxApi->unsubscribeFrom(tmp);
    int64_t fileHandle = inboxApi->createFileHandle(
        privmx::endpoint::core::Buffer::from("publicMeta"),
        privmx::endpoint::core::Buffer::from("privateMeta"),
        0
    );
    ASSERT_EQ(fileHandle, 1) << "inboxCreateFileHandle Failed";
    int64_t inboxHandle = inboxApi->prepareEntry(
        reader->getString("Inbox_1.inboxId"),
        core::Buffer::from("test_inboxSendCommit"),
        {fileHandle},
        reader->getString("Login.user_1_privKey")
    );
    ASSERT_EQ(inboxHandle, 2) << "inboxSendPrepare Failed";
    inboxApi->sendEntry(inboxHandle);
    assertNoEventReceived();
}

TEST_F(InboxEventTest, waitEvent_getEvent_inboxEntryDeleted_enabled) {
    eventQueue.waitEvent();
    inboxApi->subscribeFor({
        inboxApi->buildSubscriptionQuery(
            inbox::EventType::ENTRY_DELETE,
            inbox::EventSelectorType::INBOX_ID,
            reader->getString("Inbox_1.inboxId")
        )
    });
    inboxApi->deleteEntry(
        reader->getString("Entry_1.entryId")
    );
    auto eventHolder = waitForEvent("inboxEntryDeleted", {connection->getConnectionId()});
    ASSERT_TRUE(eventHolder.has_value());
    auto event = eventHolder.value().get();
    ASSERT_NE(event, nullptr);
    EXPECT_EQ(event->connectionId, connection->getConnectionId());
    EXPECT_EQ(event->type, "inboxEntryDeleted");
    EXPECT_EQ(event->channel, "inbox/" + reader->getString("Inbox_1.inboxId") + "/entries");
    ASSERT_TRUE(inbox::Events::isInboxEntryDeletedEvent(event));
    EXPECT_EQ(event->subscriptions.size(), 1);
    inbox::InboxEntryDeletedEventData inboxEntryDeletedEventData = inbox::Events::extractInboxEntryDeletedEvent(event).data;
    EXPECT_EQ(inboxEntryDeletedEventData.inboxId, reader->getString("Inbox_1.inboxId"));
    EXPECT_EQ(inboxEntryDeletedEventData.entryId, reader->getString("Entry_1.entryId"));
}

TEST_F(InboxEventTest, waitEvent_getEvent_inboxEntryDeleted_disabled) {
    eventQueue.waitEvent();
    auto tmp = inboxApi->subscribeFor({
        inboxApi->buildSubscriptionQuery(
            inbox::EventType::ENTRY_DELETE,
            inbox::EventSelectorType::INBOX_ID,
            reader->getString("Inbox_1.inboxId")
        )
    });
    inboxApi->unsubscribeFrom(tmp);
    inboxApi->deleteEntry(
        reader->getString("Entry_1.entryId")
    );
    assertNoEventReceived();
}

TEST_F(InboxEventTest, subscribeFor_query_from_other_module) {
    EXPECT_THROW({
        inboxApi->subscribeFor({
            "inboxes/update|contextId="+reader->getString("Context_1.contextId")
        });
    }, core::InvalidSubscriptionQueryException);
    EXPECT_THROW({
        inboxApi->subscribeFor({
            "thread/update|contextId="+reader->getString("Context_1.contextId")
        });
    }, core::InvalidSubscriptionQueryException);
}

TEST_F(InboxEventTest, subscribeFor_unsubscribeFor) {
    std::vector<std::string> valid_subscriptions;
    EXPECT_NO_THROW({
        valid_subscriptions = inboxApi->subscribeFor({
            inboxApi->buildSubscriptionQuery(
                inbox::EventType::INBOX_CREATE,
                inbox::EventSelectorType::CONTEXT_ID,
                reader->getString("Context_1.contextId")
            )
        });
    });
    std::vector<std::string> invalid_subscriptions;
    EXPECT_NO_THROW({
        invalid_subscriptions = inboxApi->subscribeFor({
            inboxApi->buildSubscriptionQuery(
                inbox::EventType::INBOX_CREATE,
                inbox::EventSelectorType::CONTEXT_ID,
                "error"
            )
        });
    });
    EXPECT_NO_THROW({
        inboxApi->unsubscribeFrom({
            valid_subscriptions
        });
    });
    EXPECT_NO_THROW({
        inboxApi->unsubscribeFrom({
            invalid_subscriptions
        });
    });
}

TEST_F(InboxEventTest, waitEvent_getEvent_collectionChanged_enabled) {
    eventQueue.waitEvent();
    inboxApi->subscribeFor({
        inboxApi->buildSubscriptionQuery(
            inbox::EventType::COLLECTION_CHANGE,
            inbox::EventSelectorType::INBOX_ID,
            reader->getString("Inbox_1.inboxId")
        )
    });
    int64_t fileHandle = inboxApi->createFileHandle(
        privmx::endpoint::core::Buffer::from("publicMeta"),
        privmx::endpoint::core::Buffer::from("privateMeta"),
        0
    );
    ASSERT_EQ(fileHandle, 1) << "inboxCreateFileHandle Failed";
    int64_t inboxHandle = inboxApi->prepareEntry(
        reader->getString("Inbox_1.inboxId"),
        core::Buffer::from("test_inboxSendCommit"),
        {fileHandle},
        reader->getString("Login.user_1_privKey")
    );
    ASSERT_EQ(inboxHandle, 2) << "inboxSendPrepare Failed";
    inboxApi->sendEntry(inboxHandle);
    auto eventHolder = waitForEvent("collectionChanged", {connection->getConnectionId()});
    ASSERT_TRUE(eventHolder.has_value());
    auto event = eventHolder.value().get();
    ASSERT_NE(event, nullptr);
    EXPECT_EQ(event->connectionId, connection->getConnectionId());
    EXPECT_EQ(event->type, "collectionChanged");
    EXPECT_EQ(event->channel, "inbox/collectionChanged");
    ASSERT_TRUE(core::Events::isCollectionChangedEvent(event));
    EXPECT_EQ(event->subscriptions.size(), 1);
    core::CollectionChangedEventData collectionChanged = core::Events::extractCollectionChangedEvent(event).data;
    EXPECT_EQ(collectionChanged.moduleId, reader->getString("Inbox_1.inboxId"));
    EXPECT_EQ(collectionChanged.affectedItemsCount, 1);
}

TEST_F(InboxEventTest, waitEvent_getEvent_collectionChanged_disabled) {
    eventQueue.waitEvent();
    auto tmp = inboxApi->subscribeFor({
        inboxApi->buildSubscriptionQuery(
            inbox::EventType::ENTRY_CREATE,
            inbox::EventSelectorType::INBOX_ID,
            reader->getString("Inbox_1.inboxId")
        )
    });
    inboxApi->unsubscribeFrom(tmp);
    int64_t fileHandle = inboxApi->createFileHandle(
        privmx::endpoint::core::Buffer::from("publicMeta"),
        privmx::endpoint::core::Buffer::from("privateMeta"),
        0
    );
    ASSERT_EQ(fileHandle, 1) << "inboxCreateFileHandle Failed";
    int64_t inboxHandle = inboxApi->prepareEntry(
        reader->getString("Inbox_1.inboxId"),
        core::Buffer::from("test_inboxSendCommit"),
        {fileHandle},
        reader->getString("Login.user_1_privKey")
    );
    ASSERT_EQ(inboxHandle, 2) << "inboxSendPrepare Failed";
    inboxApi->sendEntry(inboxHandle);
    assertNoEventReceived();
}
