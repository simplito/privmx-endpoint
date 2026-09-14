/**
 * One test per LockApi function - lock, unlock, checkReservedLock - plus one for the whole surface seen from
 * a second user, since a lock is server-side state and that is the only way to observe it as such.
 *
 * A lock level is only ever asserted through expectLockGranted / expectLockRefused / expectUnlockTo, which
 * carry both the level asked for and the level the resource ends up at: those two differ exactly where the
 * API refuses to downgrade or parks the caller on PENDING, which is the interesting half of the contract.
 */
#include <gtest/gtest.h>
#include "BaseTest.hpp"
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

    // Store_2 is used throughout because both user_1 and user_2 are its managers.
    std::string lockableResource() {
        std::string resourceId;
        EXPECT_NO_THROW({ resourceId = createLockableResource(reader->getString("Store_2.storeId")); });
        EXPECT_FALSE(resourceId.empty());
        return resourceId;
    }

    std::string newUuid() {
        return randomReadableString(32);
    }

    void expectLockGranted(
        const std::string& resourceId, const std::string& uuid, lock::LockLevel want, lock::LockLevel after
    ) {
        lock::LockOperationResult result{false, lock::LockLevel::NONE};
        EXPECT_NO_THROW({ result = lockApi->lock(resourceId, uuid, want); });
        EXPECT_TRUE(result.success);
        EXPECT_EQ(result.currentLevel, after);
    }

    void expectLockRefused(
        const std::string& resourceId, const std::string& uuid, lock::LockLevel want, lock::LockLevel after
    ) {
        lock::LockOperationResult result{true, lock::LockLevel::NONE};
        EXPECT_NO_THROW({ result = lockApi->lock(resourceId, uuid, want); });
        EXPECT_FALSE(result.success);
        EXPECT_EQ(result.currentLevel, after);
    }

    void expectUnlockTo(
        const std::string& resourceId, const std::string& uuid, lock::LockLevel to, lock::LockLevel after
    ) {
        lock::LockOperationResult result{false, lock::LockLevel::NONE};
        EXPECT_NO_THROW({ result = lockApi->unlock(resourceId, uuid, to); });
        EXPECT_TRUE(result.success);
        EXPECT_EQ(result.currentLevel, after);
    }

    std::shared_ptr<core::Connection> connection;
    std::shared_ptr<store::StoreApi> storeApi;
    std::shared_ptr<lock::LockApi> lockApi;
    Poco::Util::IniFileConfiguration::Ptr reader;
    core::VarSerializer _serializer = core::VarSerializer({});
};

TEST_F(LockTest, lock) {
    // the ladder one holder can climb
    const std::string resourceId = lockableResource();
    ASSERT_FALSE(resourceId.empty());
    const std::string uuid = newUuid();
    expectLockGranted(resourceId, uuid, lock::LockLevel::SHARED, lock::LockLevel::SHARED);
    // SHARED again - renews the lease
    expectLockGranted(resourceId, uuid, lock::LockLevel::SHARED, lock::LockLevel::SHARED);
    expectLockGranted(resourceId, uuid, lock::LockLevel::RESERVED, lock::LockLevel::RESERVED);
    // RESERVED -> EXCLUSIVE, no other readers
    expectLockGranted(resourceId, uuid, lock::LockLevel::EXCLUSIVE, lock::LockLevel::EXCLUSIVE);
    // a weaker level - lock() never downgrades
    expectLockGranted(resourceId, uuid, lock::LockLevel::SHARED, lock::LockLevel::EXCLUSIVE);
    expectUnlockTo(resourceId, uuid, lock::LockLevel::NONE, lock::LockLevel::NONE);

    // what happens with more than one holder
    const std::string sharedResourceId = lockableResource();
    ASSERT_FALSE(sharedResourceId.empty());
    const std::string writerUuid = newUuid();
    const std::string readerUuid = newUuid();
    const std::string otherReaderUuid = newUuid();
    // RESERVED still admits new readers
    expectLockGranted(sharedResourceId, writerUuid, lock::LockLevel::RESERVED, lock::LockLevel::RESERVED);
    expectLockGranted(sharedResourceId, readerUuid, lock::LockLevel::SHARED, lock::LockLevel::SHARED);
    // EXCLUSIVE with a reader present - refused, but the writer parks on PENDING
    expectLockRefused(sharedResourceId, writerUuid, lock::LockLevel::EXCLUSIVE, lock::LockLevel::PENDING);
    // PENDING blocks new readers
    expectLockRefused(sharedResourceId, otherReaderUuid, lock::LockLevel::SHARED, lock::LockLevel::NONE);
    // the reader that was already in drains, and the writer gets its turn
    expectUnlockTo(sharedResourceId, readerUuid, lock::LockLevel::NONE, lock::LockLevel::NONE);
    expectLockGranted(sharedResourceId, writerUuid, lock::LockLevel::EXCLUSIVE, lock::LockLevel::EXCLUSIVE);
    expectUnlockTo(sharedResourceId, writerUuid, lock::LockLevel::NONE, lock::LockLevel::NONE);

    // input the api refuses outright
    const std::string rejectedUuid = newUuid();
    // incorrect resourceId
    EXPECT_THROW({
        lockApi->lock(reader->getString("Context_1.contextId"), rejectedUuid, lock::LockLevel::SHARED);
    }, core::Exception);
    // resourceId out of the allowed charset
    EXPECT_THROW({
        lockApi->lock("resource:id", rejectedUuid, lock::LockLevel::SHARED);
    }, core::Exception);
    // resourceId too long
    EXPECT_THROW({
        lockApi->lock(randomReadableString(61), rejectedUuid, lock::LockLevel::SHARED);
    }, core::Exception);
    // uuid out of the allowed charset
    EXPECT_THROW({
        lockApi->lock(reader->getString("File_1.info_fileId"), "uuid:1", lock::LockLevel::SHARED);
    }, core::Exception);
    // a file without random write support
    EXPECT_THROW({
        lockApi->lock(reader->getString("File_1.info_fileId"), rejectedUuid, lock::LockLevel::SHARED);
    }, core::Exception);
    // lockLevel NONE - lock() only acquires, it never releases
    EXPECT_THROW({
        lockApi->lock(resourceId, rejectedUuid, lock::LockLevel::NONE);
    }, core::Exception);
    // lockLevel out of the enum
    EXPECT_THROW({
        lockApi->lock(resourceId, rejectedUuid, static_cast<lock::LockLevel>(99));
    }, lock::InvalidLockLevelException);

    // as a user without access to the store - last, because it leaves the connection on user_2
    std::string privateResourceId;
    EXPECT_NO_THROW({ privateResourceId = createLockableResource(reader->getString("Store_1.storeId")); });
    disconnect();
    connectAs(ConnectionType::User2);
    EXPECT_THROW({
        lockApi->lock(privateResourceId, rejectedUuid, lock::LockLevel::SHARED);
    }, core::Exception);
}

TEST_F(LockTest, unlock) {
    const std::string resourceId = lockableResource();
    ASSERT_FALSE(resourceId.empty());
    const std::string uuid = newUuid();
    const std::string unknownUuid = newUuid();

    // incorrect resourceId
    EXPECT_THROW({
        lockApi->unlock(reader->getString("Context_1.contextId"), uuid, lock::LockLevel::NONE);
    }, core::Exception);
    // unlock() only downgrades to NONE or SHARED
    EXPECT_THROW({ lockApi->unlock(resourceId, uuid, lock::LockLevel::RESERVED); }, core::Exception);
    EXPECT_THROW({ lockApi->unlock(resourceId, uuid, lock::LockLevel::PENDING); }, core::Exception);
    EXPECT_THROW({ lockApi->unlock(resourceId, uuid, lock::LockLevel::EXCLUSIVE); }, core::Exception);
    // lockLevel out of the enum
    EXPECT_THROW({
        lockApi->unlock(resourceId, uuid, static_cast<lock::LockLevel>(99));
    }, lock::InvalidLockLevelException);

    // the ladder back down
    expectLockGranted(resourceId, uuid, lock::LockLevel::EXCLUSIVE, lock::LockLevel::EXCLUSIVE);
    expectUnlockTo(resourceId, uuid, lock::LockLevel::SHARED, lock::LockLevel::SHARED);
    expectUnlockTo(resourceId, uuid, lock::LockLevel::NONE, lock::LockLevel::NONE);
    // already released - a no-op, not an error
    expectUnlockTo(resourceId, uuid, lock::LockLevel::NONE, lock::LockLevel::NONE);
    // a uuid holding nothing - also a no-op
    expectUnlockTo(resourceId, unknownUuid, lock::LockLevel::SHARED, lock::LockLevel::NONE);
}

TEST_F(LockTest, checkReservedLock) {
    const std::string resourceId = lockableResource();
    ASSERT_FALSE(resourceId.empty());
    const std::string holderUuid = newUuid();
    const std::string observerUuid = newUuid();

    // incorrect resourceId
    EXPECT_THROW({
        lockApi->checkReservedLock(reader->getString("Context_1.contextId"), observerUuid);
    }, core::Exception);
    // nothing held
    EXPECT_NO_THROW({ EXPECT_FALSE(lockApi->checkReservedLock(resourceId, observerUuid)); });

    // SHARED is below RESERVED, it does not count
    expectLockGranted(resourceId, holderUuid, lock::LockLevel::SHARED, lock::LockLevel::SHARED);
    EXPECT_NO_THROW({ EXPECT_FALSE(lockApi->checkReservedLock(resourceId, observerUuid)); });

    // RESERVED is reported to everyone but the holder itself
    expectLockGranted(resourceId, holderUuid, lock::LockLevel::RESERVED, lock::LockLevel::RESERVED);
    EXPECT_NO_THROW({
        EXPECT_TRUE(lockApi->checkReservedLock(resourceId, observerUuid));
        EXPECT_FALSE(lockApi->checkReservedLock(resourceId, holderUuid));
    });

    // PENDING is above RESERVED, it counts
    expectLockGranted(resourceId, holderUuid, lock::LockLevel::PENDING, lock::LockLevel::PENDING);
    EXPECT_NO_THROW({ EXPECT_TRUE(lockApi->checkReservedLock(resourceId, observerUuid)); });

    // and so does EXCLUSIVE
    expectLockGranted(resourceId, holderUuid, lock::LockLevel::EXCLUSIVE, lock::LockLevel::EXCLUSIVE);
    EXPECT_NO_THROW({ EXPECT_TRUE(lockApi->checkReservedLock(resourceId, observerUuid)); });

    // downgrading to SHARED clears the writer lock
    expectUnlockTo(resourceId, holderUuid, lock::LockLevel::SHARED, lock::LockLevel::SHARED);
    EXPECT_NO_THROW({ EXPECT_FALSE(lockApi->checkReservedLock(resourceId, observerUuid)); });

    // full release
    EXPECT_NO_THROW({
        lockApi->unlock(resourceId, holderUuid, lock::LockLevel::NONE);
        EXPECT_FALSE(lockApi->checkReservedLock(resourceId, observerUuid));
    });
}

TEST_F(LockTest, lock_unlock_other_user) {
    const std::string resourceId = lockableResource();
    ASSERT_FALSE(resourceId.empty());
    const std::string firstUuid = newUuid();
    const std::string secondUuid = newUuid();

    // the first holder takes EXCLUSIVE
    expectLockGranted(resourceId, firstUuid, lock::LockLevel::EXCLUSIVE, lock::LockLevel::EXCLUSIVE);

    // a lock is server side state, so the other user sees it
    disconnect();
    connectAs(ConnectionType::User2);
    EXPECT_NO_THROW({ EXPECT_TRUE(lockApi->checkReservedLock(resourceId, secondUuid)); });
    // the second holder is refused and stays at NONE, readers included
    expectLockRefused(resourceId, secondUuid, lock::LockLevel::EXCLUSIVE, lock::LockLevel::NONE);
    expectLockRefused(resourceId, secondUuid, lock::LockLevel::SHARED, lock::LockLevel::NONE);

    // the first holder keeps its lock through the failed attempts, then releases
    disconnect();
    connectAs(ConnectionType::User1);
    expectLockGranted(resourceId, firstUuid, lock::LockLevel::EXCLUSIVE, lock::LockLevel::EXCLUSIVE);
    expectUnlockTo(resourceId, firstUuid, lock::LockLevel::NONE, lock::LockLevel::NONE);

    // now the second holder gets it, and the roles reverse
    disconnect();
    connectAs(ConnectionType::User2);
    expectLockGranted(resourceId, secondUuid, lock::LockLevel::EXCLUSIVE, lock::LockLevel::EXCLUSIVE);
    EXPECT_NO_THROW({ EXPECT_TRUE(lockApi->checkReservedLock(resourceId, firstUuid)); });
    expectLockRefused(resourceId, firstUuid, lock::LockLevel::EXCLUSIVE, lock::LockLevel::NONE);
    expectUnlockTo(resourceId, secondUuid, lock::LockLevel::NONE, lock::LockLevel::NONE);
}
