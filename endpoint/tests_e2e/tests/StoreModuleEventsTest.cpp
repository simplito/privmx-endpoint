
#include <gtest/gtest.h>
#include <chrono>
#include <thread>
#include "../utils/BaseTest.hpp"
#include <privmx/endpoint/core/Connection.hpp>
#include <privmx/endpoint/store/StoreApi.hpp>
#include <privmx/endpoint/store/Events.hpp>
#include <privmx/endpoint/store/StoreException.hpp>
#include <privmx/endpoint/core/Exception.hpp>
#include <Poco/Util/IniFileConfiguration.h>
#include <privmx/crypto/Crypto.hpp>
#include <privmx/endpoint/core/VarSerializer.hpp>
#include <privmx/endpoint/core/EventQueue.hpp>
#include <privmx/endpoint/core/EventQueueImpl.hpp>

using namespace privmx::endpoint;

class StoreEventTest : public privmx::test::BaseTest {
protected:
    StoreEventTest() : BaseTest(privmx::test::BaseTestMode::online) {}
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
        storeApi = std::make_shared<store::StoreApi>(
            store::StoreApi::create(
                *connection
            )
        );
    }
    void customTearDown() override { // tmp segfault fix
        connection.reset();
        storeApi.reset();
        reader.reset();
        privmx::endpoint::core::EventQueueImpl::getInstance()->clear();
    }
    std::shared_ptr<core::Connection> connection;
    std::shared_ptr<store::StoreApi> storeApi;
    core::EventQueue eventQueue = core::EventQueue::getInstance();
    Poco::Util::IniFileConfiguration::Ptr reader;
};

TEST_F(StoreEventTest, waitEvent_getEvent_storeCreated_enabled) {
    std::shared_ptr<privmx::endpoint::core::Event> event = nullptr;
    EXPECT_NO_THROW({
        eventQueue.waitEvent(); // pop libConnected form queue
    });
    EXPECT_NO_THROW({
        storeApi->subscribeFor({
            storeApi->buildSubscriptionQuery(
                store::EventType::STORE_CREATE, 
                store::EventSelectorType::CONTEXT_ID,
                reader->getString("Context_1.contextId")
            )
        });
    });
    std::string storeId;
    EXPECT_NO_THROW({
        storeId = storeApi->createStore(
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
        EXPECT_EQ(event->type, "storeCreated");
        EXPECT_EQ(event->channel, "store");
        if(store::Events::isStoreCreatedEvent(event)) {
            EXPECT_EQ(event->subscriptions.size(), 1);
            store::Store store = store::Events::extractStoreCreatedEvent(event).data;
            EXPECT_EQ(store.contextId, reader->getString("Context_1.contextId"));
            EXPECT_EQ(store.publicMeta.stdString(),"public");
            EXPECT_EQ(store.privateMeta.stdString(),"private");
            EXPECT_EQ(store.users.size(), 1);
            if(store.users.size() == 1) {
                EXPECT_EQ(store.users[0], reader->getString("Login.user_1_id"));
            }
            EXPECT_EQ(store.managers.size(), 1);
            if(store.managers.size() == 1) {
                EXPECT_EQ(store.managers[0], reader->getString("Login.user_1_id"));
            }
        } else {
            FAIL();
        }
    } else {
        FAIL();
    }
}

TEST_F(StoreEventTest, waitEvent_getEvent_storeCreated_disabled) {
    std::shared_ptr<privmx::endpoint::core::Event> event = nullptr;
    EXPECT_NO_THROW({
        eventQueue.waitEvent(); // pop libConnected form queue
    });
    EXPECT_NO_THROW({
        auto tmp = storeApi->subscribeFor({
            storeApi->buildSubscriptionQuery(
                store::EventType::STORE_CREATE, 
                store::EventSelectorType::CONTEXT_ID,
                reader->getString("Context_1.contextId")
            )
        });
        storeApi->unsubscribeFrom(tmp);
    });
    std::string storeId;
    EXPECT_NO_THROW({
        storeId = storeApi->createStore(
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

TEST_F(StoreEventTest, waitEvent_getEvent_storeUpdated_enabled) {
    std::shared_ptr<privmx::endpoint::core::Event> event = nullptr;
    EXPECT_NO_THROW({
        eventQueue.waitEvent(); // pop libConnected form queue
    });
    EXPECT_NO_THROW({
        storeApi->subscribeFor({
            storeApi->buildSubscriptionQuery(
                store::EventType::STORE_UPDATE, 
                store::EventSelectorType::CONTEXT_ID,
                reader->getString("Context_1.contextId")
            )
        });
    });
    EXPECT_NO_THROW({
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
        EXPECT_EQ(event->type, "storeUpdated");
        EXPECT_EQ(event->channel, "store");
        if(store::Events::isStoreUpdatedEvent(event)) {
            EXPECT_EQ(event->subscriptions.size(), 1);
            store::Store store = store::Events::extractStoreUpdatedEvent(event).data;
            EXPECT_EQ(store.contextId, reader->getString("Context_1.contextId"));
            EXPECT_EQ(store.publicMeta.stdString(),"public");
            EXPECT_EQ(store.privateMeta.stdString(),"private");
            EXPECT_EQ(store.users.size(), 1);
            if(store.users.size() == 1) {
                EXPECT_EQ(store.users[0], reader->getString("Login.user_1_id"));
            }
            EXPECT_EQ(store.managers.size(), 1);
            if(store.managers.size() == 1) {
                EXPECT_EQ(store.managers[0], reader->getString("Login.user_1_id"));
            }
        } else {
            FAIL();
        }
    } else {
        FAIL();
    }
}

TEST_F(StoreEventTest, waitEvent_getEvent_storeUpdated_disabled) {
    std::shared_ptr<privmx::endpoint::core::Event> event = nullptr;
    EXPECT_NO_THROW({
        eventQueue.waitEvent(); // pop libConnected form queue
    });
    EXPECT_NO_THROW({
        auto tmp = storeApi->subscribeFor({
            storeApi->buildSubscriptionQuery(
                store::EventType::STORE_UPDATE, 
                store::EventSelectorType::CONTEXT_ID,
                reader->getString("Context_1.contextId")
            )
        });
        storeApi->unsubscribeFrom(tmp);
    });
    EXPECT_NO_THROW({
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

TEST_F(StoreEventTest, waitEvent_getEvent_storeDeleted_enabled) {
    std::shared_ptr<privmx::endpoint::core::Event> event = nullptr;
    EXPECT_NO_THROW({
        eventQueue.waitEvent(); // pop libConnected form queue
    });
    EXPECT_NO_THROW({
        storeApi->subscribeFor({
            storeApi->buildSubscriptionQuery(
                store::EventType::STORE_DELETE, 
                store::EventSelectorType::CONTEXT_ID,
                reader->getString("Context_1.contextId")
            )
        });
    });
    EXPECT_NO_THROW({
        storeApi->deleteStore(
            reader->getString("Store_1.storeId")
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
        EXPECT_EQ(event->type, "storeDeleted");
        EXPECT_EQ(event->channel, "store");
        if(store::Events::isStoreDeletedEvent(event)) {
            EXPECT_EQ(event->subscriptions.size(), 1);
            store::StoreDeletedEventData storeDeleted = store::Events::extractStoreDeletedEvent(event).data;
            EXPECT_EQ(storeDeleted.storeId, reader->getString("Store_1.storeId"));
        } else {
            FAIL();
        }
    } else {
        FAIL();
    }
}

TEST_F(StoreEventTest, waitEvent_getEvent_storeDeleted_disabled) {
    std::shared_ptr<privmx::endpoint::core::Event> event = nullptr;
    EXPECT_NO_THROW({
        eventQueue.waitEvent(); // pop libConnected form queue
    });
    EXPECT_NO_THROW({
        auto tmp = storeApi->subscribeFor({
            storeApi->buildSubscriptionQuery(
                store::EventType::STORE_DELETE, 
                store::EventSelectorType::CONTEXT_ID,
                reader->getString("Context_1.contextId")
            )
        });
        storeApi->unsubscribeFrom(tmp);
    });
    EXPECT_NO_THROW({
        storeApi->deleteStore(
            reader->getString("Store_1.storeId")
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

TEST_F(StoreEventTest, waitEvent_getEvent_storeStatsChanged_enabled) {
    std::shared_ptr<privmx::endpoint::core::Event> event = nullptr;
    EXPECT_NO_THROW({
        eventQueue.waitEvent(); // pop libConnected form queue
    });
    EXPECT_NO_THROW({
        storeApi->subscribeFor({
            storeApi->buildSubscriptionQuery(
                store::EventType::STORE_STATS, 
                store::EventSelectorType::CONTEXT_ID,
                reader->getString("Context_1.contextId")
            )
        });
    });
    EXPECT_NO_THROW({
        storeApi->deleteFile(
            reader->getString("File_1.info_fileId")
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
        EXPECT_EQ(event->type, "storeStatsChanged");
        EXPECT_EQ(event->channel, "store");
        if(store::Events::isStoreStatsChangedEvent(event)) {
            EXPECT_EQ(event->subscriptions.size(), 1);
            store::StoreStatsChangedEventData storeStat = store::Events::extractStoreStatsChangedEvent(event).data;
            EXPECT_EQ(storeStat.storeId, reader->getString("Store_1.storeId"));
            EXPECT_EQ(storeStat.contextId, reader->getString("Context_1.contextId"));
            EXPECT_EQ(storeStat.filesCount, 1);
        } else {
            FAIL();
        }
    } else {
        FAIL();
    }
}

TEST_F(StoreEventTest, waitEvent_getEvent_storeStatsChanged_disabled) {
    std::shared_ptr<privmx::endpoint::core::Event> event = nullptr;
    EXPECT_NO_THROW({
        eventQueue.waitEvent(); // pop libConnected form queue
    });
    EXPECT_NO_THROW({
        auto tmp = storeApi->subscribeFor({
            storeApi->buildSubscriptionQuery(
                store::EventType::STORE_STATS, 
                store::EventSelectorType::CONTEXT_ID,
                reader->getString("Context_1.contextId")
            )
        });
        storeApi->unsubscribeFrom(tmp);
    });
    EXPECT_NO_THROW({
        storeApi->deleteFile(
            reader->getString("File_1.info_fileId")
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

TEST_F(StoreEventTest, waitEvent_getEvent_storeFileCreated_enabled) {
    std::shared_ptr<privmx::endpoint::core::Event> event = nullptr;
    EXPECT_NO_THROW({
        eventQueue.waitEvent(); // pop libConnected form queue
    });
    EXPECT_NO_THROW({
        storeApi->subscribeFor({
            storeApi->buildSubscriptionQuery(
                store::EventType::FILE_CREATE, 
                store::EventSelectorType::STORE_ID,
                reader->getString("Store_1.storeId")
            )
        });
    });
    int64_t handle;
    EXPECT_NO_THROW({
        handle = storeApi->createFile(
            reader->getString("Store_1.storeId"),
            privmx::endpoint::core::Buffer::from("publicMeta"),
            privmx::endpoint::core::Buffer::from("privateMeta"),
            0
        );
    });
    if(handle == 1) {
        std::string fileId;
        EXPECT_NO_THROW({
            fileId = storeApi->closeFile(handle);
        });
        if(fileId.empty()) {
            std::cout << "storeFileClose Failed" << std::endl;
            FAIL();
        }
    } else {
        std::cout << "storeFileCreate Failed" << std::endl;
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
        EXPECT_EQ(event->type, "storeFileCreated");
        EXPECT_EQ(event->channel, "store/" + reader->getString("Store_1.storeId") + "/files");
        if(store::Events::isStoreFileCreatedEvent(event)) {
            EXPECT_EQ(event->subscriptions.size(), 1);
            store::File storeFile = store::Events::extractStoreFileCreatedEvent(event).data;
            EXPECT_EQ(storeFile.info.storeId, reader->getString("Store_1.storeId"));
            EXPECT_EQ(storeFile.size, 0);
            EXPECT_EQ(storeFile.publicMeta.stdString(), "publicMeta");
            EXPECT_EQ(storeFile.privateMeta.stdString(), "privateMeta");
        } else {
            FAIL();
        }
    } else {
        FAIL();
    }
}

TEST_F(StoreEventTest, waitEvent_getEvent_storeFileCreated_disabled) {
    std::shared_ptr<privmx::endpoint::core::Event> event = nullptr;
    EXPECT_NO_THROW({
        eventQueue.waitEvent(); // pop libConnected form queue
    });    
    EXPECT_NO_THROW({
        auto tmp = storeApi->subscribeFor({
            storeApi->buildSubscriptionQuery(
                store::EventType::FILE_CREATE, 
                store::EventSelectorType::STORE_ID,
                reader->getString("Store_1.storeId")
            )
        });
        storeApi->unsubscribeFrom(tmp);
    });
    int64_t handle;
    EXPECT_NO_THROW({
        handle = storeApi->createFile(
            reader->getString("Store_1.storeId"),
            privmx::endpoint::core::Buffer::from("publicMeta"),
            privmx::endpoint::core::Buffer::from("privateMeta"),
            0
        );
    });
    if(handle == 1) {
        std::string fileId;
        EXPECT_NO_THROW({
            fileId = storeApi->closeFile(handle);
        });
        if(fileId.empty()) {
            std::cout << "storeFileClose Failed" << std::endl;
            FAIL();
        }
    } else {
        std::cout << "storeFileCreate Failed" << std::endl;
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

TEST_F(StoreEventTest, waitEvent_getEvent_storeFileUpdated_enabled) {
    std::shared_ptr<privmx::endpoint::core::Event> event = nullptr;
    EXPECT_NO_THROW({
        eventQueue.waitEvent(); // pop libConnected form queue
    });
    EXPECT_NO_THROW({
        storeApi->subscribeFor({
            storeApi->buildSubscriptionQuery(
                store::EventType::FILE_UPDATE, 
                store::EventSelectorType::FILE_ID,
                reader->getString("File_1.info_fileId")
            )
        });
    });
    int64_t handle;
    EXPECT_NO_THROW({
        handle = storeApi->updateFile(
            reader->getString("File_1.info_fileId"),
            privmx::endpoint::core::Buffer::from("publicMeta"),
            privmx::endpoint::core::Buffer::from("privateMeta"),
            0
        );
    });
    if(handle == 1) {
        
        std::string fileId;
        EXPECT_NO_THROW({
            fileId = storeApi->closeFile(handle);
        });
        if(fileId.empty()) {
            std::cout << "storeFileClose Failed" << std::endl;
            FAIL();
        }
    } else {
        std::cout << "storeFileCreate Failed" << std::endl;
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
        EXPECT_EQ(event->type, "storeFileUpdated");
        EXPECT_EQ(event->channel, "store/" + reader->getString("Store_1.storeId") + "/files");
        if(store::Events::isStoreFileUpdatedEvent(event)) {
            EXPECT_EQ(event->subscriptions.size(), 1);
            store::File storeFile = store::Events::extractStoreFileUpdatedEvent(event).data.file;
            EXPECT_EQ(storeFile.info.storeId, reader->getString("Store_1.storeId"));
            EXPECT_EQ(storeFile.size, 0);
            EXPECT_EQ(storeFile.publicMeta.stdString(), "publicMeta");
            EXPECT_EQ(storeFile.privateMeta.stdString(), "privateMeta");
        } else {
            FAIL();
        }
    } else {
        FAIL();
    }
}

TEST_F(StoreEventTest, waitEvent_getEvent_storeFileUpdated_disabled) {
    std::shared_ptr<privmx::endpoint::core::Event> event = nullptr;
    EXPECT_NO_THROW({
        eventQueue.waitEvent(); // pop libConnected form queue
    });
    EXPECT_NO_THROW({
        auto tmp = storeApi->subscribeFor({
            storeApi->buildSubscriptionQuery(
                store::EventType::FILE_UPDATE, 
                store::EventSelectorType::FILE_ID,
                reader->getString("File_1.info_fileId")
            )
        });
        storeApi->unsubscribeFrom(tmp);
    });
    int64_t handle;
    EXPECT_NO_THROW({
        handle = storeApi->updateFile(
            reader->getString("File_1.info_fileId"),
            privmx::endpoint::core::Buffer::from("publicMeta"),
            privmx::endpoint::core::Buffer::from("privateMeta"),
            0
        );
    });
    if(handle == 1) {
        
        std::string fileId;
        EXPECT_NO_THROW({
            fileId = storeApi->closeFile(handle);
        });
        if(fileId.empty()) {
            std::cout << "storeFileClose Failed" << std::endl;
            FAIL();
        }
    } else {
        std::cout << "storeFileCreate Failed" << std::endl;
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

TEST_F(StoreEventTest, waitEvent_getEvent_storeFileDeleted_enabled) {
    std::shared_ptr<privmx::endpoint::core::Event> event = nullptr;
    EXPECT_NO_THROW({
        eventQueue.waitEvent(); // pop libConnected form queue
    });
    EXPECT_NO_THROW({
        storeApi->subscribeFor({
            storeApi->buildSubscriptionQuery(
                store::EventType::FILE_DELETE, 
                store::EventSelectorType::STORE_ID,
                reader->getString("Store_1.storeId")
            )
        });
    });
    EXPECT_NO_THROW({
        storeApi->deleteFile(
            reader->getString("File_1.info_fileId")
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
        EXPECT_EQ(event->type, "storeFileDeleted");
        EXPECT_EQ(event->channel, "store/" + reader->getString("Store_1.storeId") + "/files");
        if(store::Events::isStoreFileDeletedEvent(event)) {
            EXPECT_EQ(event->subscriptions.size(), 1);
            store::StoreFileDeletedEventData storeFileDeleted = store::Events::extractStoreFileDeletedEvent(event).data;
            EXPECT_EQ(storeFileDeleted.fileId, reader->getString("File_1.info_fileId"));
            EXPECT_EQ(storeFileDeleted.storeId, reader->getString("File_1.info_storeId"));
            EXPECT_EQ(storeFileDeleted.contextId, reader->getString("Context_1.contextId"));
        } else {
            FAIL();
        }
    } else {
        FAIL();
    }
}

TEST_F(StoreEventTest, waitEvent_getEvent_storeFileDeleted_disabled) {
    std::shared_ptr<privmx::endpoint::core::Event> event = nullptr;
    EXPECT_NO_THROW({
        eventQueue.waitEvent(); // pop libConnected form queue
    });
    EXPECT_NO_THROW({
        auto tmp = storeApi->subscribeFor({
            storeApi->buildSubscriptionQuery(
                store::EventType::FILE_DELETE, 
                store::EventSelectorType::STORE_ID,
                reader->getString("Store_1.storeId")
            )
        });
        storeApi->unsubscribeFrom(tmp);
    });
    EXPECT_NO_THROW({
        storeApi->deleteFile(
            reader->getString("File_1.info_fileId")
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

TEST_F(StoreEventTest, waitEvent_getEvent_storeFileUpdated_changes) {
    std::shared_ptr<privmx::endpoint::core::Event> event = nullptr;
    EXPECT_NO_THROW({
        eventQueue.waitEvent(); // pop libConnected form queue
    });
    EXPECT_NO_THROW({
        storeApi->subscribeFor({
            storeApi->buildSubscriptionQuery(
                store::EventType::FILE_UPDATE, 
                store::EventSelectorType::STORE_ID,
                reader->getString("Store_1.storeId")
            )
        });
    });
    std::string fileId;
    
    EXPECT_NO_THROW({
        auto writeHandle = storeApi->createFile(reader->getString("Store_1.storeId"), core::Buffer::from("pub"), core::Buffer::from("priv"), 2*128*1024, true);  
        storeApi->writeToFile(writeHandle, core::Buffer::from(std::string(2*128*1024, 'H')));
        fileId = storeApi->closeFile(writeHandle);
        auto RWHandle = storeApi->openFile(fileId);
        storeApi->seekInFile(RWHandle, 128*1024);
        storeApi->writeToFile(RWHandle, core::Buffer::from(std::string(64*1024, 'J')), true);
        storeApi->closeFile(RWHandle);
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
        EXPECT_EQ(event->type, "storeFileUpdated");
        EXPECT_EQ(event->channel, "store/" + reader->getString("Store_1.storeId") + "/files");
        if(store::Events::isStoreFileUpdatedEvent(event)) {
            EXPECT_EQ(event->subscriptions.size(), 1);
            auto eventData = store::Events::extractStoreFileUpdatedEvent(event).data;
            store::File storeFile = eventData.file;
            EXPECT_EQ(storeFile.info.storeId, reader->getString("Store_1.storeId"));
            EXPECT_EQ(storeFile.size, (128+64)*1024);
            EXPECT_EQ(storeFile.publicMeta.stdString(), "pub");
            EXPECT_EQ(storeFile.privateMeta.stdString(), "priv");
            EXPECT_EQ(eventData.changes.size(), 1);
            if(eventData.changes.size() >= 1) {
                auto change = eventData.changes[0];
                EXPECT_EQ(change.pos, 128*1024);
                EXPECT_EQ(change.length, 64*1024);
                EXPECT_EQ(change.truncate, true);
            } else {
                FAIL();
            }
        } else {
            FAIL();
        }
    } else {
        FAIL();
    }
}