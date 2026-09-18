/**
 * One test per inbox event type, each asserting the envelope and the payload that event carries.
 *
 * unsubscribeFrom is one API function, so it is tested once per subscription channel rather than once per
 * event type: the inbox channel, the per-inbox entries channel and the collectionChanged channel are built
 * differently, everything past that is the same call. The six "_disabled" tests this replaces differed only
 * in which operation they triggered - and two of them were byte-identical, because the collectionChanged one
 * subscribed to ENTRY_CREATE instead of COLLECTION_CHANGE and so could never have failed.
 */
#include "BaseEndpointEventTest.hpp"
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

    std::string inboxId(int index) {
        return reader->getString("Inbox_" + std::to_string(index) + ".inboxId");
    }

    std::string entryId(int index) {
        return reader->getString("Entry_" + std::to_string(index) + ".entryId");
    }

    std::string entriesChannel(int index) {
        return "inbox/" + inboxId(index) + "/entries";
    }

    std::vector<std::string> subscribe(
        inbox::EventType type, inbox::EventSelectorType selector, const std::string& selectorId
    ) {
        return inboxApi->subscribeFor({inboxApi->buildSubscriptionQuery(type, selector, selectorId)});
    }

    // The envelope every inbox event shares. Returns the event so the caller can extract its payload, which
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

    // Sends one entry carrying a single empty file, which is what the entry events are triggered by.
    void sendEntryWithOneFile(const std::string& id) {
        int64_t fileHandle = inboxApi->createFileHandle(
            core::Buffer::from("publicMeta"), core::Buffer::from("privateMeta"), 0
        );
        ASSERT_NE(fileHandle, 0) << "inboxCreateFileHandle Failed";
        int64_t inboxHandle = inboxApi->prepareEntry(
            id, core::Buffer::from("test_inboxSendCommit"), {fileHandle},
            reader->getString("Login.user_1_privKey")
        );
        ASSERT_NE(inboxHandle, 0) << "inboxSendPrepare Failed";
        inboxApi->sendEntry(inboxHandle);
    }

    std::shared_ptr<thread::ThreadApi> threadApi;
    std::shared_ptr<store::StoreApi> storeApi;
    std::shared_ptr<inbox::InboxApi> inboxApi;
};

TEST_F(InboxEventTest, waitEvent_getEvent_inboxCreated) {
    eventQueue.waitEvent();
    subscribe(inbox::EventType::INBOX_CREATE, inbox::EventSelectorType::CONTEXT_ID, contextId());
    inboxApi->createInbox(
        contextId(), users({1}), users({1}),
        core::Buffer::from("public"), core::Buffer::from("private"), std::nullopt
    );
    auto event = expectEvent("inboxCreated", "inbox");
    ASSERT_NE(event, nullptr);
    ASSERT_TRUE(inbox::Events::isInboxCreatedEvent(event));
    inbox::Inbox inbox = inbox::Events::extractInboxCreatedEvent(event).data;
    EXPECT_EQ(inbox.contextId, contextId());
    expectMembers(inbox, {1}, {1});
    EXPECT_EQ(inbox.publicMeta.stdString(), "public");
    EXPECT_EQ(inbox.privateMeta.stdString(), "private");
    assertNoEventReceived(std::chrono::milliseconds(0));
}

TEST_F(InboxEventTest, waitEvent_getEvent_inboxUpdated) {
    eventQueue.waitEvent();
    subscribe(inbox::EventType::INBOX_UPDATE, inbox::EventSelectorType::CONTEXT_ID, contextId());
    inboxApi->updateInbox(
        inboxId(1), users({1}), users({1}),
        core::Buffer::from("public"), core::Buffer::from("private"), std::nullopt, 1, true, false
    );
    auto event = expectEvent("inboxUpdated", "inbox");
    ASSERT_NE(event, nullptr);
    ASSERT_TRUE(inbox::Events::isInboxUpdatedEvent(event));
    inbox::Inbox inbox = inbox::Events::extractInboxUpdatedEvent(event).data;
    EXPECT_EQ(inbox.contextId, contextId());
    expectMembers(inbox, {1}, {1});
    EXPECT_EQ(inbox.publicMeta.stdString(), "public");
    EXPECT_EQ(inbox.privateMeta.stdString(), "private");
    assertNoEventReceived(std::chrono::milliseconds(0));
}

TEST_F(InboxEventTest, waitEvent_getEvent_inboxDeleted) {
    eventQueue.waitEvent();
    subscribe(inbox::EventType::INBOX_DELETE, inbox::EventSelectorType::CONTEXT_ID, contextId());
    inboxApi->deleteInbox(inboxId(1));
    auto event = expectEvent("inboxDeleted", "inbox");
    ASSERT_NE(event, nullptr);
    ASSERT_TRUE(inbox::Events::isInboxDeletedEvent(event));
    inbox::InboxDeletedEventData deleted = inbox::Events::extractInboxDeletedEvent(event).data;
    EXPECT_EQ(deleted.inboxId, inboxId(1));
    assertNoEventReceived(std::chrono::milliseconds(0));
}

TEST_F(InboxEventTest, waitEvent_getEvent_inboxEntryCreated) {
    eventQueue.waitEvent();
    subscribe(inbox::EventType::ENTRY_CREATE, inbox::EventSelectorType::INBOX_ID, inboxId(1));
    sendEntryWithOneFile(inboxId(1));
    auto event = expectEvent("inboxEntryCreated", entriesChannel(1));
    ASSERT_NE(event, nullptr);
    ASSERT_TRUE(inbox::Events::isInboxEntryCreatedEvent(event));
    inbox::InboxEntry inboxEntry = inbox::Events::extractInboxEntryCreatedEvent(event).data;
    EXPECT_EQ(inboxEntry.inboxId, inboxId(1));
    EXPECT_EQ(inboxEntry.data.stdString(), "test_inboxSendCommit");
    ASSERT_EQ(inboxEntry.files.size(), 1);
    EXPECT_EQ(inboxEntry.files[0].size, 0);
    EXPECT_EQ(inboxEntry.files[0].publicMeta.stdString(), "publicMeta");
    EXPECT_EQ(inboxEntry.files[0].privateMeta.stdString(), "privateMeta");
}

TEST_F(InboxEventTest, waitEvent_getEvent_inboxEntryDeleted) {
    eventQueue.waitEvent();
    subscribe(inbox::EventType::ENTRY_DELETE, inbox::EventSelectorType::INBOX_ID, inboxId(1));
    inboxApi->deleteEntry(entryId(1));
    auto event = expectEvent("inboxEntryDeleted", entriesChannel(1));
    ASSERT_NE(event, nullptr);
    ASSERT_TRUE(inbox::Events::isInboxEntryDeletedEvent(event));
    inbox::InboxEntryDeletedEventData deleted = inbox::Events::extractInboxEntryDeletedEvent(event).data;
    EXPECT_EQ(deleted.inboxId, inboxId(1));
    EXPECT_EQ(deleted.entryId, entryId(1));
}

TEST_F(InboxEventTest, waitEvent_getEvent_collectionChanged) {
    eventQueue.waitEvent();
    subscribe(inbox::EventType::COLLECTION_CHANGE, inbox::EventSelectorType::INBOX_ID, inboxId(1));
    sendEntryWithOneFile(inboxId(1));
    auto event = expectEvent("collectionChanged", "inbox/collectionChanged");
    ASSERT_NE(event, nullptr);
    ASSERT_TRUE(core::Events::isCollectionChangedEvent(event));
    core::CollectionChangedEventData collectionChanged = core::Events::extractCollectionChangedEvent(event).data;
    EXPECT_EQ(collectionChanged.moduleId, inboxId(1));
    EXPECT_EQ(collectionChanged.affectedItemsCount, 1);
}

TEST_F(InboxEventTest, unsubscribeFrom_silences_the_inbox_channel) {
    eventQueue.waitEvent();
    auto ids = subscribe(inbox::EventType::INBOX_CREATE, inbox::EventSelectorType::CONTEXT_ID, contextId());
    inboxApi->unsubscribeFrom(ids);
    inboxApi->createInbox(
        contextId(), users({1}), users({1}),
        core::Buffer::from("public"), core::Buffer::from("private"), std::nullopt
    );
    assertNoEventReceived();
}

TEST_F(InboxEventTest, unsubscribeFrom_silences_the_entries_channel) {
    eventQueue.waitEvent();
    auto ids = subscribe(inbox::EventType::ENTRY_CREATE, inbox::EventSelectorType::INBOX_ID, inboxId(1));
    inboxApi->unsubscribeFrom(ids);
    sendEntryWithOneFile(inboxId(1));
    assertNoEventReceived();
}

TEST_F(InboxEventTest, unsubscribeFrom_silences_the_collectionChanged_channel) {
    eventQueue.waitEvent();
    auto ids = subscribe(inbox::EventType::COLLECTION_CHANGE, inbox::EventSelectorType::INBOX_ID, inboxId(1));
    inboxApi->unsubscribeFrom(ids);
    sendEntryWithOneFile(inboxId(1));
    assertNoEventReceived();
}

TEST_F(InboxEventTest, subscribeFor_query_from_other_module) {
    EXPECT_THROW({
        inboxApi->subscribeFor({"inboxes/update|contextId=" + contextId()});
    }, core::InvalidSubscriptionQueryException);
    EXPECT_THROW({
        inboxApi->subscribeFor({"thread/update|contextId=" + contextId()});
    }, core::InvalidSubscriptionQueryException);
}

TEST_F(InboxEventTest, subscribeFor_unsubscribeFor) {
    std::vector<std::string> valid_subscriptions;
    EXPECT_NO_THROW({
        valid_subscriptions =
            subscribe(inbox::EventType::INBOX_CREATE, inbox::EventSelectorType::CONTEXT_ID, contextId());
    });
    std::vector<std::string> invalid_subscriptions;
    EXPECT_NO_THROW({
        invalid_subscriptions =
            subscribe(inbox::EventType::INBOX_CREATE, inbox::EventSelectorType::CONTEXT_ID, "error");
    });
    EXPECT_NO_THROW({ inboxApi->unsubscribeFrom(valid_subscriptions); });
    EXPECT_NO_THROW({ inboxApi->unsubscribeFrom(invalid_subscriptions); });
}
