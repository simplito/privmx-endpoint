#include <gtest/gtest.h>
#include "../utils/BaseTest.hpp"
#include <Poco/Util/IniFileConfiguration.h>
#include <privmx/endpoint/core/Buffer.hpp>
#include <privmx/endpoint/core/Connection.hpp>
#include <privmx/endpoint/core/EventQueueImpl.hpp>
#include <privmx/endpoint/core/Exception.hpp>
#include <privmx/endpoint/core/VarSerializer.hpp>
#include <privmx/endpoint/lock/LockApi.hpp>
#include <privmx/endpoint/lock/LockException.hpp>
#include <privmx/endpoint/store/StoreApi.hpp>

using namespace privmx::endpoint;

enum ConnectionType {
    User1,
    User2
};

class LockTest : public privmx::test::BaseTest {
protected:
    LockTest() : BaseTest(privmx::test::BaseTestMode::online) {}
    void connectAs(ConnectionType type) {
        if(type == ConnectionType::User1) {
            connection = std::make_shared<core::Connection>(
                core::Connection::connect(
                    reader->getString("Login.user_1_privKey"),
                    reader->getString("Login.solutionId"),
                    getPlatformUrl(reader->getString("Login.instanceUrl"))
                )
            );
        } else if(type == ConnectionType::User2) {
            connection = std::make_shared<core::Connection>(
                core::Connection::connect(
                    reader->getString("Login.user_2_privKey"),
                    reader->getString("Login.solutionId"),
                    getPlatformUrl(reader->getString("Login.instanceUrl"))
                )
            );
        }
        storeApi = std::make_shared<store::StoreApi>(
            store::StoreApi::create(
                *connection
            )
        );
        lockApi = std::make_shared<lock::LockApi>(
            lock::LockApi::create(
                *connection
            )
        );
    }
    void disconnect() {
        connection->disconnect();
        connection.reset();
        storeApi.reset();
        lockApi.reset();
    }
    void customSetUp() override {
        reader = new Poco::Util::IniFileConfiguration(INI_FILE_PATH);
        connectAs(ConnectionType::User1);
    }
    void customTearDown() override { // tmp segfault fix
        connection.reset();
        storeApi.reset();
        lockApi.reset();
        reader.reset();
        core::EventQueueImpl::getInstance()->clear();
    }
    // only files with random write support can be locked
    std::string createLockableResource(const std::string& storeId) {
        auto handle = storeApi->createFile(
            storeId,
            core::Buffer::from("lock_test_publicMeta"),
            core::Buffer::from("lock_test_privateMeta"),
            0,
            true
        );
        return storeApi->closeFile(handle);
    }
    std::string newUuid() {
        return randomReadableString(32);
    }
    std::shared_ptr<core::Connection> connection;
    std::shared_ptr<store::StoreApi> storeApi;
    std::shared_ptr<lock::LockApi> lockApi;
    Poco::Util::IniFileConfiguration::Ptr reader;
    core::VarSerializer _serializer = core::VarSerializer({});
};

TEST_F(LockTest, lock_incorrect_input_data) {
    auto uuid = newUuid();
    // incorrect resourceId
    EXPECT_THROW({
        lockApi->lock(
            reader->getString("Context_1.contextId"),
            uuid,
            lock::LockLevel::SHARED
        );
    }, core::Exception);
    // resourceId out of the allowed charset
    EXPECT_THROW({
        lockApi->lock(
            "resource:id",
            uuid,
            lock::LockLevel::SHARED
        );
    }, core::Exception);
    // resourceId too long
    EXPECT_THROW({
        lockApi->lock(
            randomReadableString(61),
            uuid,
            lock::LockLevel::SHARED
        );
    }, core::Exception);
    // uuid out of the allowed charset
    EXPECT_THROW({
        lockApi->lock(
            reader->getString("File_1.info_fileId"),
            "uuid:1",
            lock::LockLevel::SHARED
        );
    }, core::Exception);
    // file without random write support
    EXPECT_THROW({
        lockApi->lock(
            reader->getString("File_1.info_fileId"),
            uuid,
            lock::LockLevel::SHARED
        );
    }, core::Exception);
    std::string resourceId;
    EXPECT_NO_THROW({
        resourceId = createLockableResource(reader->getString("Store_2.storeId"));
    });
    if(resourceId.empty()) {
        FAIL();
    }
    // lockLevel NONE - lock() only acquires, it never releases
    EXPECT_THROW({
        lockApi->lock(
            resourceId,
            uuid,
            lock::LockLevel::NONE
        );
    }, core::Exception);
    // lockLevel out of the enum
    EXPECT_THROW({
        lockApi->lock(
            resourceId,
            uuid,
            static_cast<lock::LockLevel>(99)
        );
    }, lock::InvalidLockLevelException);
    // as user without access to the store
    std::string privateResourceId;
    EXPECT_NO_THROW({
        privateResourceId = createLockableResource(reader->getString("Store_1.storeId"));
    });
    disconnect();
    connectAs(ConnectionType::User2);
    EXPECT_THROW({
        lockApi->lock(
            privateResourceId,
            uuid,
            lock::LockLevel::SHARED
        );
    }, core::Exception);
}

TEST_F(LockTest, lock_correct_input_data) {
    std::string resourceId;
    EXPECT_NO_THROW({
        resourceId = createLockableResource(reader->getString("Store_2.storeId"));
    });
    if(resourceId.empty()) {
        FAIL();
    }
    auto uuid = newUuid();
    lock::LockOperationResult result{false, lock::LockLevel::NONE};
    // NONE -> SHARED
    EXPECT_NO_THROW({
        result = lockApi->lock(
            resourceId,
            uuid,
            lock::LockLevel::SHARED
        );
    });
    EXPECT_TRUE(result.success);
    EXPECT_EQ(result.currentLevel, lock::LockLevel::SHARED);
    // SHARED again - renews the lease
    EXPECT_NO_THROW({
        result = lockApi->lock(
            resourceId,
            uuid,
            lock::LockLevel::SHARED
        );
    });
    EXPECT_TRUE(result.success);
    EXPECT_EQ(result.currentLevel, lock::LockLevel::SHARED);
    // SHARED -> RESERVED
    EXPECT_NO_THROW({
        result = lockApi->lock(
            resourceId,
            uuid,
            lock::LockLevel::RESERVED
        );
    });
    EXPECT_TRUE(result.success);
    EXPECT_EQ(result.currentLevel, lock::LockLevel::RESERVED);
    // RESERVED -> EXCLUSIVE, no other readers
    EXPECT_NO_THROW({
        result = lockApi->lock(
            resourceId,
            uuid,
            lock::LockLevel::EXCLUSIVE
        );
    });
    EXPECT_TRUE(result.success);
    EXPECT_EQ(result.currentLevel, lock::LockLevel::EXCLUSIVE);
    // weaker level - lock() never downgrades
    EXPECT_NO_THROW({
        result = lockApi->lock(
            resourceId,
            uuid,
            lock::LockLevel::SHARED
        );
    });
    EXPECT_TRUE(result.success);
    EXPECT_EQ(result.currentLevel, lock::LockLevel::EXCLUSIVE);
    EXPECT_NO_THROW({
        lockApi->unlock(
            resourceId,
            uuid,
            lock::LockLevel::NONE
        );
    });
}

TEST_F(LockTest, lock_multiple_holders) {
    std::string resourceId;
    EXPECT_NO_THROW({
        resourceId = createLockableResource(reader->getString("Store_2.storeId"));
    });
    if(resourceId.empty()) {
        FAIL();
    }
    auto writerUuid = newUuid();
    auto readerUuid = newUuid();
    auto otherReaderUuid = newUuid();
    lock::LockOperationResult result{false, lock::LockLevel::NONE};
    // RESERVED still admits new readers
    EXPECT_NO_THROW({
        result = lockApi->lock(
            resourceId,
            writerUuid,
            lock::LockLevel::RESERVED
        );
    });
    EXPECT_TRUE(result.success);
    EXPECT_EQ(result.currentLevel, lock::LockLevel::RESERVED);
    EXPECT_NO_THROW({
        result = lockApi->lock(
            resourceId,
            readerUuid,
            lock::LockLevel::SHARED
        );
    });
    EXPECT_TRUE(result.success);
    EXPECT_EQ(result.currentLevel, lock::LockLevel::SHARED);
    // EXCLUSIVE with a reader present - refused, but the writer parks on PENDING
    EXPECT_NO_THROW({
        result = lockApi->lock(
            resourceId,
            writerUuid,
            lock::LockLevel::EXCLUSIVE
        );
    });
    EXPECT_FALSE(result.success);
    EXPECT_EQ(result.currentLevel, lock::LockLevel::PENDING);
    // PENDING blocks new readers
    EXPECT_NO_THROW({
        result = lockApi->lock(
            resourceId,
            otherReaderUuid,
            lock::LockLevel::SHARED
        );
    });
    EXPECT_FALSE(result.success);
    EXPECT_EQ(result.currentLevel, lock::LockLevel::NONE);
    // the reader that was already in drains
    EXPECT_NO_THROW({
        result = lockApi->unlock(
            resourceId,
            readerUuid,
            lock::LockLevel::NONE
        );
    });
    EXPECT_TRUE(result.success);
    EXPECT_EQ(result.currentLevel, lock::LockLevel::NONE);
    // PENDING -> EXCLUSIVE
    EXPECT_NO_THROW({
        result = lockApi->lock(
            resourceId,
            writerUuid,
            lock::LockLevel::EXCLUSIVE
        );
    });
    EXPECT_TRUE(result.success);
    EXPECT_EQ(result.currentLevel, lock::LockLevel::EXCLUSIVE);
    EXPECT_NO_THROW({
        lockApi->unlock(
            resourceId,
            writerUuid,
            lock::LockLevel::NONE
        );
    });
}

TEST_F(LockTest, unlock_incorrect_input_data) {
    std::string resourceId;
    EXPECT_NO_THROW({
        resourceId = createLockableResource(reader->getString("Store_2.storeId"));
    });
    if(resourceId.empty()) {
        FAIL();
    }
    auto uuid = newUuid();
    // incorrect resourceId
    EXPECT_THROW({
        lockApi->unlock(
            reader->getString("Context_1.contextId"),
            uuid,
            lock::LockLevel::NONE
        );
    }, core::Exception);
    // lockLevel RESERVED - unlock() only downgrades to NONE or SHARED
    EXPECT_THROW({
        lockApi->unlock(
            resourceId,
            uuid,
            lock::LockLevel::RESERVED
        );
    }, core::Exception);
    // lockLevel PENDING
    EXPECT_THROW({
        lockApi->unlock(
            resourceId,
            uuid,
            lock::LockLevel::PENDING
        );
    }, core::Exception);
    // lockLevel EXCLUSIVE
    EXPECT_THROW({
        lockApi->unlock(
            resourceId,
            uuid,
            lock::LockLevel::EXCLUSIVE
        );
    }, core::Exception);
    // lockLevel out of the enum
    EXPECT_THROW({
        lockApi->unlock(
            resourceId,
            uuid,
            static_cast<lock::LockLevel>(99)
        );
    }, lock::InvalidLockLevelException);
}

TEST_F(LockTest, unlock_correct_input_data) {
    std::string resourceId;
    EXPECT_NO_THROW({
        resourceId = createLockableResource(reader->getString("Store_2.storeId"));
    });
    if(resourceId.empty()) {
        FAIL();
    }
    auto uuid = newUuid();
    auto unknownUuid = newUuid();
    lock::LockOperationResult result{false, lock::LockLevel::NONE};
    EXPECT_NO_THROW({
        result = lockApi->lock(
            resourceId,
            uuid,
            lock::LockLevel::EXCLUSIVE
        );
    });
    EXPECT_TRUE(result.success);
    EXPECT_EQ(result.currentLevel, lock::LockLevel::EXCLUSIVE);
    // EXCLUSIVE -> SHARED
    EXPECT_NO_THROW({
        result = lockApi->unlock(
            resourceId,
            uuid,
            lock::LockLevel::SHARED
        );
    });
    EXPECT_TRUE(result.success);
    EXPECT_EQ(result.currentLevel, lock::LockLevel::SHARED);
    // SHARED -> NONE
    EXPECT_NO_THROW({
        result = lockApi->unlock(
            resourceId,
            uuid,
            lock::LockLevel::NONE
        );
    });
    EXPECT_TRUE(result.success);
    EXPECT_EQ(result.currentLevel, lock::LockLevel::NONE);
    // already released - no-op, not an error
    EXPECT_NO_THROW({
        result = lockApi->unlock(
            resourceId,
            uuid,
            lock::LockLevel::NONE
        );
    });
    EXPECT_TRUE(result.success);
    EXPECT_EQ(result.currentLevel, lock::LockLevel::NONE);
    // uuid holding nothing - no-op
    EXPECT_NO_THROW({
        result = lockApi->unlock(
            resourceId,
            unknownUuid,
            lock::LockLevel::SHARED
        );
    });
    EXPECT_TRUE(result.success);
    EXPECT_EQ(result.currentLevel, lock::LockLevel::NONE);
}

TEST_F(LockTest, checkReservedLock) {
    std::string resourceId;
    EXPECT_NO_THROW({
        resourceId = createLockableResource(reader->getString("Store_2.storeId"));
    });
    if(resourceId.empty()) {
        FAIL();
    }
    auto holderUuid = newUuid();
    auto observerUuid = newUuid();
    lock::LockOperationResult result{false, lock::LockLevel::NONE};
    // incorrect resourceId
    EXPECT_THROW({
        lockApi->checkReservedLock(
            reader->getString("Context_1.contextId"),
            observerUuid
        );
    }, core::Exception);
    // nothing held
    EXPECT_NO_THROW({
        EXPECT_FALSE(lockApi->checkReservedLock(resourceId, observerUuid));
    });
    // SHARED is below RESERVED, it does not count
    EXPECT_NO_THROW({
        result = lockApi->lock(
            resourceId,
            holderUuid,
            lock::LockLevel::SHARED
        );
    });
    EXPECT_TRUE(result.success);
    EXPECT_NO_THROW({
        EXPECT_FALSE(lockApi->checkReservedLock(resourceId, observerUuid));
    });
    // RESERVED is reported to everyone but the holder itself
    EXPECT_NO_THROW({
        result = lockApi->lock(
            resourceId,
            holderUuid,
            lock::LockLevel::RESERVED
        );
    });
    EXPECT_TRUE(result.success);
    EXPECT_EQ(result.currentLevel, lock::LockLevel::RESERVED);
    EXPECT_NO_THROW({
        EXPECT_TRUE(lockApi->checkReservedLock(resourceId, observerUuid));
        EXPECT_FALSE(lockApi->checkReservedLock(resourceId, holderUuid));
    });
    // PENDING is above RESERVED, it counts
    EXPECT_NO_THROW({
        result = lockApi->lock(
            resourceId,
            holderUuid,
            lock::LockLevel::PENDING
        );
    });
    EXPECT_TRUE(result.success);
    EXPECT_EQ(result.currentLevel, lock::LockLevel::PENDING);
    EXPECT_NO_THROW({
        EXPECT_TRUE(lockApi->checkReservedLock(resourceId, observerUuid));
    });
    // EXCLUSIVE counts
    EXPECT_NO_THROW({
        result = lockApi->lock(
            resourceId,
            holderUuid,
            lock::LockLevel::EXCLUSIVE
        );
    });
    EXPECT_TRUE(result.success);
    EXPECT_EQ(result.currentLevel, lock::LockLevel::EXCLUSIVE);
    EXPECT_NO_THROW({
        EXPECT_TRUE(lockApi->checkReservedLock(resourceId, observerUuid));
    });
    // downgrade to SHARED clears the writer lock
    EXPECT_NO_THROW({
        result = lockApi->unlock(
            resourceId,
            holderUuid,
            lock::LockLevel::SHARED
        );
    });
    EXPECT_TRUE(result.success);
    EXPECT_EQ(result.currentLevel, lock::LockLevel::SHARED);
    EXPECT_NO_THROW({
        EXPECT_FALSE(lockApi->checkReservedLock(resourceId, observerUuid));
    });
    // full release
    EXPECT_NO_THROW({
        lockApi->unlock(
            resourceId,
            holderUuid,
            lock::LockLevel::NONE
        );
        EXPECT_FALSE(lockApi->checkReservedLock(resourceId, observerUuid));
    });
}

TEST_F(LockTest, lock_unlock_other_user) {
    // Store_2 is used because both user_1 and user_2 are its managers
    std::string resourceId;
    EXPECT_NO_THROW({
        resourceId = createLockableResource(reader->getString("Store_2.storeId"));
    });
    if(resourceId.empty()) {
        FAIL();
    }
    auto firstUuid = newUuid();
    auto secondUuid = newUuid();
    lock::LockOperationResult result{false, lock::LockLevel::NONE};
    // first holder takes EXCLUSIVE
    EXPECT_NO_THROW({
        result = lockApi->lock(
            resourceId,
            firstUuid,
            lock::LockLevel::EXCLUSIVE
        );
    });
    EXPECT_TRUE(result.success);
    EXPECT_EQ(result.currentLevel, lock::LockLevel::EXCLUSIVE);
    // lock is server side state, the other user sees it
    disconnect();
    connectAs(ConnectionType::User2);
    EXPECT_NO_THROW({
        EXPECT_TRUE(lockApi->checkReservedLock(resourceId, secondUuid));
    });
    // second holder is refused and stays at NONE
    EXPECT_NO_THROW({
        result = lockApi->lock(
            resourceId,
            secondUuid,
            lock::LockLevel::EXCLUSIVE
        );
    });
    EXPECT_FALSE(result.success);
    EXPECT_EQ(result.currentLevel, lock::LockLevel::NONE);
    // an EXCLUSIVE holder blocks readers too
    EXPECT_NO_THROW({
        result = lockApi->lock(
            resourceId,
            secondUuid,
            lock::LockLevel::SHARED
        );
    });
    EXPECT_FALSE(result.success);
    EXPECT_EQ(result.currentLevel, lock::LockLevel::NONE);
    // the first holder keeps its lock through the failed attempts, then releases
    disconnect();
    connectAs(ConnectionType::User1);
    EXPECT_NO_THROW({
        result = lockApi->lock(
            resourceId,
            firstUuid,
            lock::LockLevel::EXCLUSIVE
        );
    });
    EXPECT_TRUE(result.success);
    EXPECT_EQ(result.currentLevel, lock::LockLevel::EXCLUSIVE);
    EXPECT_NO_THROW({
        result = lockApi->unlock(
            resourceId,
            firstUuid,
            lock::LockLevel::NONE
        );
    });
    EXPECT_TRUE(result.success);
    EXPECT_EQ(result.currentLevel, lock::LockLevel::NONE);
    // now the second holder gets it
    disconnect();
    connectAs(ConnectionType::User2);
    EXPECT_NO_THROW({
        result = lockApi->lock(
            resourceId,
            secondUuid,
            lock::LockLevel::EXCLUSIVE
        );
    });
    EXPECT_TRUE(result.success);
    EXPECT_EQ(result.currentLevel, lock::LockLevel::EXCLUSIVE);
    // and the roles are reversed - the first uuid is the one being blocked now
    EXPECT_NO_THROW({
        EXPECT_TRUE(lockApi->checkReservedLock(resourceId, firstUuid));
        result = lockApi->lock(
            resourceId,
            firstUuid,
            lock::LockLevel::EXCLUSIVE
        );
    });
    EXPECT_FALSE(result.success);
    EXPECT_EQ(result.currentLevel, lock::LockLevel::NONE);
    EXPECT_NO_THROW({
        result = lockApi->unlock(
            resourceId,
            secondUuid,
            lock::LockLevel::NONE
        );
    });
    EXPECT_TRUE(result.success);
    EXPECT_EQ(result.currentLevel, lock::LockLevel::NONE);
}
