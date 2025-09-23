
#include <gtest/gtest.h>
#include <chrono>
#include <thread>
#include "../utils/BaseTest.hpp"
#include <privmx/endpoint/core/Connection.hpp>
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
#include <Poco/Util/IniFileConfiguration.h>
#include <privmx/crypto/Crypto.hpp>
#include <privmx/endpoint/core/VarSerializer.hpp>
#include <privmx/endpoint/core/EventQueue.hpp>
#include <privmx/endpoint/core/EventQueueImpl.hpp>

using namespace privmx::endpoint;

class InboxEventTest : public privmx::test::BaseTest {
protected:
    InboxEventTest() : BaseTest(privmx::test::BaseTestMode::online) {}
    void customSetUp() override {
        std::string iniFile = std::getenv("INI_FILE_PATH");
        reader = new Poco::Util::IniFileConfiguration(iniFile);
        connection = std::make_shared<core::Connection>(
            core::Connection::connect(
                reader->getString("Login.user_1_privKey"), 
                reader->getString("Login.solutionId"), 
                getPlatformUrl(reader->getString("Login.instanceUrl"))
            )
        );
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
    void customTearDown() override { // tmp segfault fix
        connection.reset();
        threadApi.reset();
        storeApi.reset();
        inboxApi.reset();
        reader.reset();
        privmx::endpoint::core::EventQueueImpl::getInstance()->clear();
    }
    std::shared_ptr<core::Connection> connection;
    std::shared_ptr<thread::ThreadApi> threadApi;
    std::shared_ptr<store::StoreApi> storeApi;
    std::shared_ptr<inbox::InboxApi> inboxApi;
    core::EventQueue eventQueue = core::EventQueue::getInstance();
    Poco::Util::IniFileConfiguration::Ptr reader;
};

TEST_F(InboxEventTest, waitEvent_getEvent_inboxCreated_enabled) {
    std::shared_ptr<privmx::endpoint::core::Event> event = nullptr;
    EXPECT_NO_THROW({
        eventQueue.waitEvent(); // pop libConnected form queue
    });
    EXPECT_NO_THROW({
        inboxApi->subscribeFor({
            inboxApi->buildSubscriptionQuery(
                inbox::EventType::INBOX_CREATE, 
                inbox::EventSelectorType::CONTEXT_ID,
                reader->getString("Context_1.contextId")
            )
        });
    });
    std::string inboxId;
    EXPECT_NO_THROW({
        inboxId = inboxApi->createInbox(
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
    });
    EXPECT_NO_THROW({
        std::this_thread::sleep_for(std::chrono::milliseconds(1500));
        std::optional<core::EventHolder> eventHolder = eventQueue.getEvent();
        if(eventHolder.has_value()) {
            event = eventHolder.value().get();
        } else {
            event = nullptr;
        }
    });
    if(event != nullptr) {
        EXPECT_EQ(event->connectionId, connection->getConnectionId());
        EXPECT_EQ(event->type, "inboxCreated");
        EXPECT_EQ(event->channel, "inbox");
        if(inbox::Events::isInboxCreatedEvent(event)) {
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
        } else {
            FAIL();
        }
    } else {
        FAIL();
    }
    EXPECT_NO_THROW({
        std::optional<core::EventHolder> eventHolder = eventQueue.getEvent();
        if(eventHolder.has_value()) {
            event = eventHolder.value().get();
        } else {
            event = nullptr;
        }
    });
    if(event == nullptr) {

    } else {
        std::cout << "Received Event with type " << event->type << std::endl;
        std::cout << "Expected null" << std::endl;
        FAIL();
    }
}

TEST_F(InboxEventTest, waitEvent_getEvent_inboxCreated_disabled) {
    std::shared_ptr<privmx::endpoint::core::Event> event = nullptr;
    EXPECT_NO_THROW({
        eventQueue.waitEvent(); // pop libConnected form queue
    });
    EXPECT_NO_THROW({
        auto tmp = inboxApi->subscribeFor({
            inboxApi->buildSubscriptionQuery(
                inbox::EventType::INBOX_CREATE, 
                inbox::EventSelectorType::CONTEXT_ID,
                reader->getString("Context_1.contextId")
            )
        });
        inboxApi->unsubscribeFrom(tmp);
    });
    std::string inboxId;
    EXPECT_NO_THROW({
        inboxId = inboxApi->createInbox(
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
    });
    EXPECT_NO_THROW({
        std::this_thread::sleep_for(std::chrono::milliseconds(1500));
        std::optional<core::EventHolder> eventHolder = eventQueue.getEvent();
        if(eventHolder.has_value()) {
            event = eventHolder.value().get();
        } else {
            event = nullptr;
        }
    });
    if(event == nullptr) {

    } else {
        std::cout << "Received Event with type " << event->type << std::endl;
        std::cout << "Expected null" << std::endl;
        FAIL();
    }
}

TEST_F(InboxEventTest, waitEvent_getEvent_inboxUpdated_enabled) {
    std::shared_ptr<privmx::endpoint::core::Event> event = nullptr;
    EXPECT_NO_THROW({
        eventQueue.waitEvent(); // pop libConnected form queue
    });
    EXPECT_NO_THROW({
        inboxApi->subscribeFor({
            inboxApi->buildSubscriptionQuery(
                inbox::EventType::INBOX_UPDATE, 
                inbox::EventSelectorType::CONTEXT_ID,
                reader->getString("Context_1.contextId")
            )
        });
    });
    EXPECT_NO_THROW({
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
    });
    EXPECT_NO_THROW({
        std::this_thread::sleep_for(std::chrono::milliseconds(1500));
        std::optional<core::EventHolder> eventHolder = eventQueue.getEvent();
        if(eventHolder.has_value()) {
            event = eventHolder.value().get();
        } else {
            event = nullptr;
        }
    });
    if(event != nullptr) {
        EXPECT_EQ(event->connectionId, connection->getConnectionId());
        EXPECT_EQ(event->type, "inboxUpdated");
        EXPECT_EQ(event->channel, "inbox");
        if(inbox::Events::isInboxUpdatedEvent(event)) {
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
        } else {
            FAIL();
        }
    } else {
        FAIL();
    }
    EXPECT_NO_THROW({
        std::optional<core::EventHolder> eventHolder = eventQueue.getEvent();
        if(eventHolder.has_value()) {
            event = eventHolder.value().get();
        } else {
            event = nullptr;
        }
    });
    if(event == nullptr) {

    } else {
        std::cout << "Received Event with type " << event->type << std::endl;
        std::cout << "Expected null" << std::endl;
        FAIL();
    }
}

TEST_F(InboxEventTest, waitEvent_getEvent_inboxUpdated_disabled) {
    std::shared_ptr<privmx::endpoint::core::Event> event = nullptr;
    EXPECT_NO_THROW({
        eventQueue.waitEvent(); // pop libConnected form queue
    });
    EXPECT_NO_THROW({
        auto tmp = inboxApi->subscribeFor({
            inboxApi->buildSubscriptionQuery(
                inbox::EventType::INBOX_UPDATE, 
                inbox::EventSelectorType::CONTEXT_ID,
                reader->getString("Context_1.contextId")
            )
        });
        inboxApi->unsubscribeFrom(tmp);
    });
    std::string inboxId;
    EXPECT_NO_THROW({
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
    });
    EXPECT_NO_THROW({
        std::this_thread::sleep_for(std::chrono::milliseconds(1500));
        std::optional<core::EventHolder> eventHolder = eventQueue.getEvent();
        if(eventHolder.has_value()) {
            event = eventHolder.value().get();
        } else {
            event = nullptr;
        }
    });
    if(event == nullptr) {

    } else {
        std::cout << "Received Event with type " << event->type << std::endl;
        std::cout << "Expected null" << std::endl;
        FAIL();
    }
}

TEST_F(InboxEventTest, waitEvent_getEvent_inboxDeleted_enabled) {
    std::shared_ptr<privmx::endpoint::core::Event> event = nullptr;
    EXPECT_NO_THROW({
        eventQueue.waitEvent(); // pop libConnected form queue
    });
    EXPECT_NO_THROW({
        inboxApi->subscribeFor({
            inboxApi->buildSubscriptionQuery(
                inbox::EventType::INBOX_DELETE, 
                inbox::EventSelectorType::CONTEXT_ID,
                reader->getString("Context_1.contextId")
            )
        });
    });
    EXPECT_NO_THROW({
        inboxApi->deleteInbox(
            reader->getString("Inbox_1.inboxId")
        );
    });
    EXPECT_NO_THROW({
        std::this_thread::sleep_for(std::chrono::milliseconds(1500));
        std::optional<core::EventHolder> eventHolder = eventQueue.getEvent();
        if(eventHolder.has_value()) {
            event = eventHolder.value().get();
        } else {
            event = nullptr;
        }
    });
    if(event != nullptr) {
        EXPECT_EQ(event->connectionId, connection->getConnectionId());
        EXPECT_EQ(event->type, "inboxDeleted");
        EXPECT_EQ(event->channel, "inbox");
        if(inbox::Events::isInboxDeletedEvent(event)) {
            EXPECT_EQ(event->subscriptions.size(), 1);
            inbox::InboxDeletedEventData inboxDeletedEventData = inbox::Events::extractInboxDeletedEvent(event).data;
            EXPECT_EQ(inboxDeletedEventData.inboxId, reader->getString("Inbox_1.inboxId"));
        } else {
            FAIL();
        }
    } else {
        FAIL();
    }
    EXPECT_NO_THROW({
        std::optional<core::EventHolder> eventHolder = eventQueue.getEvent();
        if(eventHolder.has_value()) {
            event = eventHolder.value().get();
        } else {
            event = nullptr;
        }
    });
    if(event == nullptr) {

    } else {
        std::cout << "Received Event with type " << event->type << std::endl;
        std::cout << "Expected null" << std::endl;
        FAIL();
    }
}

TEST_F(InboxEventTest, waitEvent_getEvent_inboxDeleted_disabled) {
    std::shared_ptr<privmx::endpoint::core::Event> event = nullptr;
    EXPECT_NO_THROW({
        eventQueue.waitEvent(); // pop libConnected form queue
    });
    EXPECT_NO_THROW({
        auto tmp = inboxApi->subscribeFor({
            inboxApi->buildSubscriptionQuery(
                inbox::EventType::INBOX_DELETE, 
                inbox::EventSelectorType::CONTEXT_ID,
                reader->getString("Context_1.contextId")
            )
        });
        inboxApi->unsubscribeFrom(tmp);
    });
    std::string inboxId;
    EXPECT_NO_THROW({
        inboxApi->deleteInbox(
            reader->getString("Inbox_1.inboxId")
        );
    });
    EXPECT_NO_THROW({
        std::this_thread::sleep_for(std::chrono::milliseconds(1500));
        std::optional<core::EventHolder> eventHolder = eventQueue.getEvent();
        if(eventHolder.has_value()) {
            event = eventHolder.value().get();
        } else {
            event = nullptr;
        }
    });
    if(event == nullptr) {

    } else {
        std::cout << "Received Event with type " << event->type << std::endl;
        std::cout << "Expected null" << std::endl;
        FAIL();
    }
}

TEST_F(InboxEventTest, waitEvent_getEvent_inboxEntryCreated_enabled) {
    std::shared_ptr<privmx::endpoint::core::Event> event = nullptr;
    EXPECT_NO_THROW({
        eventQueue.waitEvent(); // pop libConnected form queue
    });
    EXPECT_NO_THROW({
        inboxApi->subscribeFor({
            inboxApi->buildSubscriptionQuery(
                inbox::EventType::ENTRY_CREATE, 
                inbox::EventSelectorType::INBOX_ID,
                reader->getString("Inbox_1.inboxId")
            )
        });
    });
    int64_t fileHandle = 0;
    std::string file_total_data_send = "";
    EXPECT_NO_THROW({
        fileHandle = inboxApi->createFileHandle(
            privmx::endpoint::core::Buffer::from("publicMeta"),
            privmx::endpoint::core::Buffer::from("privateMeta"),
            0
        );
    });
    EXPECT_EQ(fileHandle, 1);
    if(fileHandle == 1) {
        int64_t inboxHandle = 0;
        EXPECT_NO_THROW({
            inboxHandle = inboxApi->prepareEntry(
                reader->getString("Inbox_1.inboxId"),
                core::Buffer::from("test_inboxSendCommit"),
                {fileHandle},
                reader->getString("Login.user_1_privKey")
            );
        });
        EXPECT_EQ(inboxHandle, 2);
        if(inboxHandle == 2) {
            EXPECT_NO_THROW({
                inboxApi->sendEntry(inboxHandle);
            });
        } else {
            std::cout << "inboxSendPrepare Failed" << std::endl;
            FAIL();
        }
    } else {
        std::cout << "inboxCreateFileHandle Failed" << std::endl;
        FAIL();
    }
    EXPECT_NO_THROW({
        std::this_thread::sleep_for(std::chrono::milliseconds(1500));
        std::optional<core::EventHolder> eventHolder = eventQueue.getEvent();
        if(eventHolder.has_value()) {
            event = eventHolder.value().get();
        } else {
            event = nullptr;
        }
    });
    if(event != nullptr) {
        EXPECT_EQ(event->connectionId, connection->getConnectionId());
        EXPECT_EQ(event->type, "inboxEntryCreated");
        EXPECT_EQ(event->channel, "inbox/" + reader->getString("Inbox_1.inboxId") + "/entries");
        if(inbox::Events::isInboxEntryCreatedEvent(event)) {
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
        } else {
            FAIL();
        }
    } else {
        FAIL();
    }
}

TEST_F(InboxEventTest, waitEvent_getEvent_inboxEntryCreated_disabled) {
    std::shared_ptr<privmx::endpoint::core::Event> event = nullptr;
    EXPECT_NO_THROW({
        eventQueue.waitEvent(); // pop libConnected form queue
    });
    EXPECT_NO_THROW({
        auto tmp = inboxApi->subscribeFor({
            inboxApi->buildSubscriptionQuery(
                inbox::EventType::ENTRY_CREATE, 
                inbox::EventSelectorType::INBOX_ID,
                reader->getString("Inbox_1.inboxId")
            )
        });
        inboxApi->unsubscribeFrom(tmp);
    });
    int64_t fileHandle = 0;
    std::string file_total_data_send = "";
    EXPECT_NO_THROW({
        fileHandle = inboxApi->createFileHandle(
            privmx::endpoint::core::Buffer::from("publicMeta"),
            privmx::endpoint::core::Buffer::from("privateMeta"),
            0
        );
    });
    EXPECT_EQ(fileHandle, 1);
    if(fileHandle == 1) {
        int64_t inboxHandle = 0;
        EXPECT_NO_THROW({
            inboxHandle = inboxApi->prepareEntry(
                reader->getString("Inbox_1.inboxId"),
                core::Buffer::from("test_inboxSendCommit"),
                {fileHandle},
                reader->getString("Login.user_1_privKey")
            );
        });
        EXPECT_EQ(inboxHandle, 2);
        if(inboxHandle == 2) {
            EXPECT_NO_THROW({
                inboxApi->sendEntry(inboxHandle);
            });
        } else {
            std::cout << "inboxSendPrepare Failed" << std::endl;
            FAIL();
        }
    } else {
        std::cout << "inboxCreateFileHandle Failed" << std::endl;
        FAIL();
    }
    EXPECT_NO_THROW({
        std::this_thread::sleep_for(std::chrono::milliseconds(1500));
        std::optional<core::EventHolder> eventHolder = eventQueue.getEvent();
        if(eventHolder.has_value()) {
            event = eventHolder.value().get();
        } else {
            event = nullptr;
        }
    });
    if(event == nullptr) {

    } else {
        std::cout << "Received Event with type " << event->type << std::endl;
        std::cout << "Expected null" << std::endl;
        FAIL();
    }
}

TEST_F(InboxEventTest, waitEvent_getEvent_inboxEntryDeleted_enabled) {
    std::shared_ptr<privmx::endpoint::core::Event> event = nullptr;
    EXPECT_NO_THROW({
        eventQueue.waitEvent(); // pop libConnected form queue
    });
    EXPECT_NO_THROW({
        inboxApi->subscribeFor({
            inboxApi->buildSubscriptionQuery(
                inbox::EventType::ENTRY_DELETE, 
                inbox::EventSelectorType::INBOX_ID,
                reader->getString("Inbox_1.inboxId")
            )
        });
    });
    EXPECT_NO_THROW({
        inboxApi->deleteEntry(
            reader->getString("Entry_1.entryId")
        );
    });
    EXPECT_NO_THROW({
        std::this_thread::sleep_for(std::chrono::milliseconds(1500));
        std::optional<core::EventHolder> eventHolder = eventQueue.getEvent();
        if(eventHolder.has_value()) {
            event = eventHolder.value().get();
        } else {
            event = nullptr;
        }
    });
    if(event != nullptr) {
        EXPECT_EQ(event->connectionId, connection->getConnectionId());
        EXPECT_EQ(event->type, "inboxEntryDeleted");
        EXPECT_EQ(event->channel, "inbox/" + reader->getString("Inbox_1.inboxId") + "/entries");
        if(inbox::Events::isInboxEntryDeletedEvent(event)) {
            EXPECT_EQ(event->subscriptions.size(), 1);
            inbox::InboxEntryDeletedEventData inboxEntryDeletedEventData = inbox::Events::extractInboxEntryDeletedEvent(event).data;
            EXPECT_EQ(inboxEntryDeletedEventData.inboxId, reader->getString("Inbox_1.inboxId"));
            EXPECT_EQ(inboxEntryDeletedEventData.entryId, reader->getString("Entry_1.entryId"));
        } else {
            FAIL();
        }
    } else {
        FAIL();
    }
}

TEST_F(InboxEventTest, waitEvent_getEvent_inboxEntryDeleted_disabled) {
    std::shared_ptr<privmx::endpoint::core::Event> event = nullptr;
    EXPECT_NO_THROW({
        eventQueue.waitEvent(); // pop libConnected form queue
    });
    EXPECT_NO_THROW({
        auto tmp = inboxApi->subscribeFor({
            inboxApi->buildSubscriptionQuery(
                inbox::EventType::ENTRY_DELETE, 
                inbox::EventSelectorType::INBOX_ID,
                reader->getString("Inbox_1.inboxId")
            )
        });
        inboxApi->unsubscribeFrom(tmp);
    });
    EXPECT_NO_THROW({
        inboxApi->deleteEntry(
            reader->getString("Entry_1.entryId")
        );
    });
    EXPECT_NO_THROW({
        std::this_thread::sleep_for(std::chrono::milliseconds(1500));
        std::optional<core::EventHolder> eventHolder = eventQueue.getEvent();
        if(eventHolder.has_value()) {
            event = eventHolder.value().get();
        } else {
            event = nullptr;
        }
    });
    if(event == nullptr) {

    } else {
        std::cout << "Received Event with type " << event->type << std::endl;
        std::cout << "Expected null" << std::endl;
        FAIL();
    }
}

TEST_F(InboxEventTest, subscribeFor_query_from_other_module) {
    EXPECT_THROW({
        inboxApi->subscribeFor({
            "inboxes/update|contextId="+reader->getString("Context_1.contextId")
        });
    }, inbox::InvalidSubscriptionQueryException);
    EXPECT_THROW({
        inboxApi->subscribeFor({
            "thread/update|contextId="+reader->getString("Context_1.contextId")
        });
    }, inbox::InvalidSubscriptionQueryException);
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
