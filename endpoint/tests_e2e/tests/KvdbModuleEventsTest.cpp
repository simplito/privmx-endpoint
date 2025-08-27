
#include <gtest/gtest.h>
#include <chrono>
#include <thread>
#include "../utils/BaseTest.hpp"
#include <privmx/endpoint/core/Connection.hpp>
#include <privmx/endpoint/kvdb/KvdbApi.hpp>
#include <privmx/endpoint/kvdb/Events.hpp>
#include <privmx/endpoint/kvdb/KvdbException.hpp>
#include <Poco/Util/IniFileConfiguration.h>
#include <privmx/crypto/Crypto.hpp>
#include <privmx/endpoint/core/VarSerializer.hpp>
#include <privmx/endpoint/core/EventQueue.hpp>
#include <privmx/endpoint/core/EventQueueImpl.hpp>

using namespace privmx::endpoint;

class KvdbEventTest : public privmx::test::BaseTest {
protected:
    KvdbEventTest() : BaseTest(privmx::test::BaseTestMode::online) {}
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
        kvdbApi = std::make_shared<kvdb::KvdbApi>(
            kvdb::KvdbApi::create(
                *connection
            )
        );
    }
    void customTearDown() override { // tmp segfault fix
        connection.reset();
        kvdbApi.reset();
        reader.reset();
        privmx::endpoint::core::EventQueueImpl::getInstance()->clear();
    }
    std::shared_ptr<core::Connection> connection;
    std::shared_ptr<kvdb::KvdbApi> kvdbApi;
    core::EventQueue eventQueue = core::EventQueue::getInstance();
    Poco::Util::IniFileConfiguration::Ptr reader;
};

TEST_F(KvdbEventTest, waitEvent_getEvent_kvdbCreated_enabled) {
    std::shared_ptr<privmx::endpoint::core::Event> event = nullptr;
    EXPECT_NO_THROW({
        eventQueue.waitEvent(); // pop libConnected form queue
    });
    EXPECT_NO_THROW({
        kvdbApi->subscribeFor({
            kvdbApi->buildSubscriptionQuery(
                kvdb::EventType::KVDB_CREATE, 
                kvdb::EventSelectorType::CONTEXT_ID,
                reader->getString("Context_1.contextId")
            )
        });
    });

    std::string kvdbId;
    EXPECT_NO_THROW({
        kvdbId = kvdbApi->createKvdb(
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
        EXPECT_EQ(event->type, "kvdbCreated");
        EXPECT_EQ(event->channel, "kvdb");
        if(kvdb::Events::isKvdbCreatedEvent(event)) {
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
        } else {
            FAIL();
        }
    } else {
        FAIL();
    }
}

TEST_F(KvdbEventTest, waitEvent_getEvent_kvdbCreated_disabled) {
    std::shared_ptr<privmx::endpoint::core::Event> event = nullptr;
    EXPECT_NO_THROW({
        eventQueue.waitEvent(); // pop libConnected form queue
    });
    EXPECT_NO_THROW({
        auto tmp = kvdbApi->subscribeFor({
            kvdbApi->buildSubscriptionQuery(
                kvdb::EventType::KVDB_CREATE, 
                kvdb::EventSelectorType::CONTEXT_ID,
                reader->getString("Context_1.contextId")
            )
        });
        kvdbApi->unsubscribeFrom(tmp);
    });

    std::string kvdbId;
    EXPECT_NO_THROW({
        kvdbId = kvdbApi->createKvdb(
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

TEST_F(KvdbEventTest, waitEvent_getEvent_kvdbUpdated_enabled) {
    std::shared_ptr<privmx::endpoint::core::Event> event = nullptr;
    EXPECT_NO_THROW({
        eventQueue.waitEvent(); // pop libConnected form queue
    });
    EXPECT_NO_THROW({
        kvdbApi->subscribeFor({
            kvdbApi->buildSubscriptionQuery(
                kvdb::EventType::KVDB_UPDATE, 
                kvdb::EventSelectorType::CONTEXT_ID,
                reader->getString("Context_1.contextId")
            )
        });
    });

    EXPECT_NO_THROW({
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
        EXPECT_EQ(event->type, "kvdbUpdated");
        EXPECT_EQ(event->channel, "kvdb");
        if(kvdb::Events::isKvdbUpdatedEvent(event)) {
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
        } else {
            FAIL();
        }
    } else {
        FAIL();
    }
}

TEST_F(KvdbEventTest, waitEvent_getEvent_kvdbUpdated_disabled) {
    std::shared_ptr<privmx::endpoint::core::Event> event = nullptr;
    EXPECT_NO_THROW({
        eventQueue.waitEvent(); // pop libConnected form queue
    });
    EXPECT_NO_THROW({
        auto tmp = kvdbApi->subscribeFor({
            kvdbApi->buildSubscriptionQuery(
                kvdb::EventType::KVDB_UPDATE, 
                kvdb::EventSelectorType::CONTEXT_ID,
                reader->getString("Context_1.contextId")
            )
        });
        kvdbApi->unsubscribeFrom(tmp);
    });

    EXPECT_NO_THROW({
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

TEST_F(KvdbEventTest, waitEvent_getEvent_kvdbDeleted_enabled) {
    std::shared_ptr<privmx::endpoint::core::Event> event = nullptr;
    EXPECT_NO_THROW({
        eventQueue.waitEvent(); // pop libConnected form queue
    });
    EXPECT_NO_THROW({
        kvdbApi->subscribeFor({
            kvdbApi->buildSubscriptionQuery(
                kvdb::EventType::KVDB_DELETE, 
                kvdb::EventSelectorType::CONTEXT_ID,
                reader->getString("Context_1.contextId")
            )
        });
    });

    EXPECT_NO_THROW({
        kvdbApi->deleteKvdb(
            reader->getString("Kvdb_1.kvdbId")
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
        EXPECT_EQ(event->type, "kvdbDeleted");
        EXPECT_EQ(event->channel, "kvdb");
        if(kvdb::Events::isKvdbDeletedEvent(event)) {
            kvdb::KvdbDeletedEventData kvdbDeleted = kvdb::Events::extractKvdbDeletedEvent(event).data;
            EXPECT_EQ(kvdbDeleted.kvdbId, reader->getString("Kvdb_1.kvdbId"));
        } else {
            FAIL();
        }
    } else {
        FAIL();
    }
}

TEST_F(KvdbEventTest, waitEvent_getEvent_kvdbDeleted_disabled) {
    std::shared_ptr<privmx::endpoint::core::Event> event = nullptr;
    EXPECT_NO_THROW({
        eventQueue.waitEvent(); // pop libConnected form queue
    });
    EXPECT_NO_THROW({
        auto tmp = kvdbApi->subscribeFor({
            kvdbApi->buildSubscriptionQuery(
                kvdb::EventType::KVDB_DELETE, 
                kvdb::EventSelectorType::CONTEXT_ID,
                reader->getString("Context_1.contextId")
            )
        });
        kvdbApi->unsubscribeFrom(tmp);
    });

    EXPECT_NO_THROW({
        kvdbApi->deleteKvdb(
            reader->getString("Kvdb_1.kvdbId")
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

TEST_F(KvdbEventTest, waitEvent_getEvent_kvdbStats_enabled) {
    std::shared_ptr<privmx::endpoint::core::Event> event = nullptr;
    EXPECT_NO_THROW({
        eventQueue.waitEvent(); // pop libConnected form queue
    });
    EXPECT_NO_THROW({
        kvdbApi->subscribeFor({
            kvdbApi->buildSubscriptionQuery(
                kvdb::EventType::KVDB_STATS, 
                kvdb::EventSelectorType::CONTEXT_ID,
                reader->getString("Context_1.contextId")
            )
        });
    });

    EXPECT_NO_THROW({
        kvdbApi->deleteEntry(
            reader->getString("Kvdb_1.kvdbId"),
            reader->getString("KvdbEntry_1.info_key")
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
        EXPECT_EQ(event->type, "kvdbStatsChanged");
        EXPECT_EQ(event->channel, "kvdb");
        if(kvdb::Events::isKvdbStatsEvent(event)) {
            kvdb::KvdbStatsEventData kvdbStat = kvdb::Events::extractKvdbStatsEvent(event).data;
            EXPECT_EQ(kvdbStat.kvdbId, reader->getString("Kvdb_1.kvdbId"));
            EXPECT_EQ(kvdbStat.entries, 1);
        } else {
            FAIL();
        }
    } else {
        FAIL();
    }
}

TEST_F(KvdbEventTest, waitEvent_getEvent_kvdbStats_disabled) {
    std::shared_ptr<privmx::endpoint::core::Event> event = nullptr;
    EXPECT_NO_THROW({
        eventQueue.waitEvent(); // pop libConnected form queue
    });
    EXPECT_NO_THROW({
        auto tmp = kvdbApi->subscribeFor({
            kvdbApi->buildSubscriptionQuery(
                kvdb::EventType::KVDB_STATS, 
                kvdb::EventSelectorType::CONTEXT_ID,
                reader->getString("Context_1.contextId")
            )
        });
        kvdbApi->unsubscribeFrom(tmp);
    });

    EXPECT_NO_THROW({
        kvdbApi->deleteEntry(
            reader->getString("Kvdb_1.kvdbId"),
            reader->getString("KvdbEntry_1.info_key")
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

TEST_F(KvdbEventTest, waitEvent_getEvent_kvdbNewKvdbEntry_enabled) {
    std::shared_ptr<privmx::endpoint::core::Event> event = nullptr;
    EXPECT_NO_THROW({
        eventQueue.waitEvent(); // pop libConnected form queue
    });
    EXPECT_NO_THROW({
        kvdbApi->subscribeFor({
            kvdbApi->buildSubscriptionQuery(
                kvdb::EventType::ENTRY_CREATE, 
                kvdb::EventSelectorType::KVDB_ID,
                reader->getString("Kvdb_1.kvdbId")
            )
        });
    });
    std::string key = "key";
    EXPECT_NO_THROW({
        kvdbApi->setEntry(
            reader->getString("Kvdb_1.kvdbId"),
            key,
            core::Buffer::from("publicMeta"),
            core::Buffer::from("privateMeta"),
            core::Buffer::from("data"),
            0
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
        EXPECT_EQ(event->type, "kvdbNewEntry");
        EXPECT_EQ(event->channel, "kvdb/"+reader->getString("Kvdb_1.kvdbId")+"/entries");
        if(kvdb::Events::isKvdbNewEntryEvent(event)) {
            kvdb::KvdbEntry kvdbEntry = kvdb::Events::extractKvdbNewEntryEvent(event).data;
            EXPECT_EQ(kvdbEntry.publicMeta.stdString(), "publicMeta");
            EXPECT_EQ(kvdbEntry.privateMeta.stdString(), "privateMeta");
            EXPECT_EQ(kvdbEntry.data.stdString(), "data");
            EXPECT_EQ(kvdbEntry.info.kvdbId, reader->getString("Kvdb_1.kvdbId"));
        } else {
            FAIL();
        }
    } else {
        FAIL();
    }
}

TEST_F(KvdbEventTest, waitEvent_getEvent_kvdbNewKvdbEntry_disabled) {
    std::shared_ptr<privmx::endpoint::core::Event> event = nullptr;
    EXPECT_NO_THROW({
        eventQueue.waitEvent(); // pop libConnected form queue
    });
    EXPECT_NO_THROW({
        auto tmp = kvdbApi->subscribeFor({
            kvdbApi->buildSubscriptionQuery(
                kvdb::EventType::ENTRY_CREATE, 
                kvdb::EventSelectorType::KVDB_ID,
                reader->getString("Kvdb_1.kvdbId")
            )
        });
        kvdbApi->unsubscribeFrom(tmp);
    });
    std::string key = "key";
    EXPECT_NO_THROW({
        kvdbApi->setEntry(
            reader->getString("Kvdb_1.kvdbId"),
            key,
            core::Buffer::from("publicMeta"),
            core::Buffer::from("privateMeta"),
            core::Buffer::from("data"),
            0
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

TEST_F(KvdbEventTest, waitEvent_getEvent_kvdbUpdatedKvdbEntry_enabled) {
    std::shared_ptr<privmx::endpoint::core::Event> event = nullptr;
    EXPECT_NO_THROW({
        eventQueue.waitEvent(); // pop libConnected form queue
    });
    EXPECT_NO_THROW({
        kvdbApi->subscribeFor({
            kvdbApi->buildSubscriptionQuery(
                kvdb::EventType::ENTRY_UPDATE, 
                kvdb::EventSelectorType::KVDB_ID,
                reader->getString("Kvdb_1.kvdbId")
            )
        });
    });
    EXPECT_NO_THROW({
        kvdbApi->setEntry(
            reader->getString("Kvdb_1.kvdbId"),
            reader->getString("KvdbEntry_1.info_key"),
            core::Buffer::from("publicMeta"),
            core::Buffer::from("privateMeta"),
            core::Buffer::from("data"),
            1
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
        EXPECT_EQ(event->type, "kvdbEntryUpdated");
        EXPECT_EQ(event->channel, "kvdb/"+reader->getString("Kvdb_1.kvdbId")+"/entries");
        if(kvdb::Events::isKvdbEntryUpdatedEvent(event)) {
            kvdb::KvdbEntry kvdbEntry = kvdb::Events::extractKvdbEntryUpdatedEvent(event).data;
            EXPECT_EQ(kvdbEntry.info.key, reader->getString("KvdbEntry_1.info_key"));
            EXPECT_EQ(kvdbEntry.publicMeta.stdString(), "publicMeta");
            EXPECT_EQ(kvdbEntry.privateMeta.stdString(), "privateMeta");
            EXPECT_EQ(kvdbEntry.data.stdString(), "data");
            EXPECT_EQ(kvdbEntry.info.kvdbId, reader->getString("Kvdb_1.kvdbId"));
        } else {
            FAIL();
        }
    } else {
        FAIL();
    }
}

TEST_F(KvdbEventTest, waitEvent_getEvent_kvdbUpdatedKvdbEntry_disabled) {
    std::shared_ptr<privmx::endpoint::core::Event> event = nullptr;
    EXPECT_NO_THROW({
        eventQueue.waitEvent(); // pop libConnected form queue
    });
    EXPECT_NO_THROW({
        auto tmp = kvdbApi->subscribeFor({
            kvdbApi->buildSubscriptionQuery(
                kvdb::EventType::ENTRY_UPDATE, 
                kvdb::EventSelectorType::KVDB_ID,
                reader->getString("Kvdb_1.kvdbId")
            )
        });
        kvdbApi->unsubscribeFrom(tmp);
    });
    EXPECT_NO_THROW({
        kvdbApi->setEntry(
            reader->getString("Kvdb_1.kvdbId"),
            reader->getString("KvdbEntry_1.info_key"),
            core::Buffer::from("publicMeta"),
            core::Buffer::from("privateMeta"),
            core::Buffer::from("data"),
            1
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

TEST_F(KvdbEventTest, waitEvent_getEvent_kvdbDeletedKvdbEntry_enabled) {
    std::shared_ptr<privmx::endpoint::core::Event> event = nullptr;
    EXPECT_NO_THROW({
        eventQueue.waitEvent(); // pop libConnected form queue
    });
    EXPECT_NO_THROW({
        kvdbApi->subscribeFor({
            kvdbApi->buildSubscriptionQuery(
                kvdb::EventType::ENTRY_DELETE, 
                kvdb::EventSelectorType::KVDB_ID,
                reader->getString("Kvdb_1.kvdbId")
            )
        });
    });
    EXPECT_NO_THROW({
        kvdbApi->deleteEntry(
            reader->getString("Kvdb_1.kvdbId"),
            reader->getString("KvdbEntry_1.info_key")
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
        EXPECT_EQ(event->type, "kvdbEntryDeleted");
        EXPECT_EQ(event->channel, "kvdb/"+reader->getString("Kvdb_1.kvdbId")+"/entries");
        if(kvdb::Events::isKvdbEntryDeletedEvent(event)) {
            kvdb::KvdbDeletedEntryEventData kvdbDeletedKvdbEntry = kvdb::Events::extractKvdbEntryDeletedEvent(event).data;
            EXPECT_EQ(kvdbDeletedKvdbEntry.kvdbEntryKey, reader->getString("KvdbEntry_1.info_key"));
            EXPECT_EQ(kvdbDeletedKvdbEntry.kvdbId, reader->getString("Kvdb_1.kvdbId"));
        } else {
            FAIL();
        }
    } else {
        FAIL();
    }
}

TEST_F(KvdbEventTest, waitEvent_getEvent_kvdbDeletedKvdbEntry_disabled) {
    std::shared_ptr<privmx::endpoint::core::Event> event = nullptr;
    EXPECT_NO_THROW({
        eventQueue.waitEvent(); // pop libConnected form queue
    });
    EXPECT_NO_THROW({
        auto tmp = kvdbApi->subscribeFor({
            kvdbApi->buildSubscriptionQuery(
                kvdb::EventType::ENTRY_DELETE, 
                kvdb::EventSelectorType::KVDB_ID,
                reader->getString("Kvdb_1.kvdbId")
            )
        });
        kvdbApi->unsubscribeFrom(tmp);
    });
    EXPECT_NO_THROW({
        kvdbApi->deleteEntry(
            reader->getString("Kvdb_1.kvdbId"),
            reader->getString("KvdbEntry_1.info_key")
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

TEST_F(KvdbEventTest, Subscribe_for_singel_entry) {
    std::shared_ptr<privmx::endpoint::core::Event> event = nullptr;
    EXPECT_NO_THROW({
        eventQueue.waitEvent(); // pop libConnected form queue
    });
    EXPECT_NO_THROW({
        kvdbApi->subscribeFor({
            kvdbApi->buildSubscriptionQuery(
                kvdb::EventType::ENTRY_UPDATE, 
                kvdb::EventSelectorType::ENTRY_ID,
                reader->getString("KvdbEntry_1.info_key"),
                reader->getString("Kvdb_1.kvdbId")
            )
        });
    });
    EXPECT_NO_THROW({
        kvdbApi->setEntry(
            reader->getString("Kvdb_1.kvdbId"),
            reader->getString("KvdbEntry_1.info_key"),
            core::Buffer::from("publicMeta"),
            core::Buffer::from("privateMeta"),
            core::Buffer::from("data"),
            1
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
        EXPECT_EQ(event->type, "kvdbEntryUpdated");
        EXPECT_EQ(event->channel, "kvdb/"+reader->getString("Kvdb_1.kvdbId")+"/entries");
        if(kvdb::Events::isKvdbEntryUpdatedEvent(event)) {
            kvdb::KvdbEntry kvdbEntry = kvdb::Events::extractKvdbEntryUpdatedEvent(event).data;
            EXPECT_EQ(kvdbEntry.info.key, reader->getString("KvdbEntry_1.info_key"));
            EXPECT_EQ(kvdbEntry.publicMeta.stdString(), "publicMeta");
            EXPECT_EQ(kvdbEntry.privateMeta.stdString(), "privateMeta");
            EXPECT_EQ(kvdbEntry.data.stdString(), "data");
            EXPECT_EQ(kvdbEntry.info.kvdbId, reader->getString("Kvdb_1.kvdbId"));
        } else {
            FAIL();
        }
    } else {
        FAIL();
    }
}