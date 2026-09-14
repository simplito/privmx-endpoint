#include <gtest/gtest.h>
#include "BaseGroupTest.hpp"
#include <Poco/Util/IniFileConfiguration.h>
#include <privmx/endpoint/core/Buffer.hpp>
#include <privmx/endpoint/core/Connection.hpp>
#include <privmx/endpoint/core/EventQueueImpl.hpp>
#include <privmx/endpoint/core/Exception.hpp>
#include <privmx/endpoint/core/VarSerializer.hpp>
#include <privmx/endpoint/group/GroupApi.hpp>
#include <privmx/endpoint/lock/LockApi.hpp>
#include <privmx/endpoint/store/StoreApi.hpp>

using namespace privmx::endpoint;

/**
 * LockApi itself knows nothing about groups - it locks a resource id and holds no keys. What it does inherit is
 * the Store's access check: a lock is only granted to a caller who may write the file, so whether a grantee
 * group's member can lock is decided by the same policy that decides whether they can write.
 */
class LockUsingGroupsTest : public privmx::test::BaseGroupTest {
protected:
    void setUpModuleApis() override {
        storeApi = std::make_shared<store::StoreApi>(store::StoreApi::create(*connection, *groupApi));
        lockApi = std::make_shared<lock::LockApi>(lock::LockApi::create(*connection));
    }
    void tearDownModuleApis() override {
        lockApi.reset();
        storeApi.reset();
    }
    // A Store whose only direct member is user_1, granted to `group` at `role`.
    std::string createStoreWithGroup(const group::Group& group, const std::string& role) {
        return storeApi->createStore(
            reader->getString("Context_1.contextId"),
            std::vector<core::UserWithPubKey>{user(1)},
            std::vector<core::UserWithPubKey>{user(1)},
            core::Buffer::from("lock_group_public"),
            core::Buffer::from("lock_group_private"),
            core::ContainerPolicy(),
            std::vector<core::GroupGrantWithKey>{
                core::GroupGrantWithKey{.groupId = group.groupId, .role = role, .groupPubKey = group.groupPubKey}
            }
        );
    }
    // Only files with random write support can be locked.
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

    void expectLockGranted(
        const std::string& resourceId, const std::string& uuid, lock::LockLevel want, lock::LockLevel after
    ) {
        lock::LockOperationResult result{false, lock::LockLevel::NONE};
        EXPECT_NO_THROW({ result = lockApi->lock(resourceId, uuid, want); });
        EXPECT_TRUE(result.success);
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

    // A Store whose only direct member is user_1, granted at `role` to Group_2 - which holds user_1 and user_2.
    std::string grantedStore(const std::string& role) {
        group::Group group_2;
        EXPECT_NO_THROW({ group_2 = groupApi->getGroup(reader->getString("Group_2.groupId")); });
        EXPECT_EQ(group_2.statusCode, 0);
        std::string storeId;
        EXPECT_NO_THROW({ storeId = createStoreWithGroup(group_2, role); });
        return storeId;
    }

    std::shared_ptr<store::StoreApi> storeApi;
    std::shared_ptr<lock::LockApi> lockApi;
};

TEST_F(LockUsingGroupsTest, lock_via_group_manager_grant) {
    // user_2 is not a direct member of the Store, so the lock can only be granted through the grant - the
    // check behind lockLock has to account for group membership.
    const std::string storeId = grantedStore("manager");
    ASSERT_FALSE(storeId.empty());
    std::string resourceId;
    ASSERT_NO_THROW({ resourceId = createLockableResource(storeId); });
    ASSERT_FALSE(resourceId.empty());

    disconnect();
    connectAs(2);
    const std::string uuid = newUuid();
    expectLockGranted(resourceId, uuid, lock::LockLevel::SHARED, lock::LockLevel::SHARED);
    expectLockGranted(resourceId, uuid, lock::LockLevel::EXCLUSIVE, lock::LockLevel::EXCLUSIVE);
    expectUnlockTo(resourceId, uuid, lock::LockLevel::NONE, lock::LockLevel::NONE);
}

TEST_F(LockUsingGroupsTest, lock_via_group_user_grant) {
    // "user" is the weaker grant and the default item policy is "itemOwner&user,manager", so it reaches a file
    // the caller wrote itself and nothing else. That is the policy talking, not the group - a direct member
    // with the same role fares the same.
    const std::string storeId = grantedStore("user");
    ASSERT_FALSE(storeId.empty());
    // written by user_1, so user_2 does not own it
    std::string othersResourceId;
    ASSERT_NO_THROW({ othersResourceId = createLockableResource(storeId); });
    ASSERT_FALSE(othersResourceId.empty());

    disconnect();
    connectAs(2);
    // someone else's file: neither half of "itemOwner&user,manager" is satisfied
    EXPECT_THROW({ lockApi->lock(othersResourceId, newUuid(), lock::LockLevel::SHARED); }, core::Exception);

    // its own file, in the same store: `itemOwner&user` is
    std::string ownResourceId;
    ASSERT_NO_THROW({ ownResourceId = createLockableResource(storeId); });
    ASSERT_FALSE(ownResourceId.empty());
    const std::string uuid = newUuid();
    expectLockGranted(ownResourceId, uuid, lock::LockLevel::EXCLUSIVE, lock::LockLevel::EXCLUSIVE);
    expectUnlockTo(ownResourceId, uuid, lock::LockLevel::NONE, lock::LockLevel::NONE);
}

TEST_F(LockUsingGroupsTest, checkReservedLock_via_group_grant) {
    const std::string storeId = grantedStore("manager");
    ASSERT_FALSE(storeId.empty());
    std::string resourceId;
    ASSERT_NO_THROW({ resourceId = createLockableResource(storeId); });
    ASSERT_FALSE(resourceId.empty());

    auto holderUuid = newUuid();
    lock::LockOperationResult result{false, lock::LockLevel::NONE};
    ASSERT_NO_THROW({ result = lockApi->lock(resourceId, holderUuid, lock::LockLevel::RESERVED); });
    ASSERT_TRUE(result.success);

    // The lock is server side state; the group member sees the direct member's writer lock and is held off.
    disconnect();
    connectAs(2);
    auto observerUuid = newUuid();
    EXPECT_NO_THROW({ EXPECT_TRUE(lockApi->checkReservedLock(resourceId, observerUuid)); });
    EXPECT_NO_THROW({ result = lockApi->lock(resourceId, observerUuid, lock::LockLevel::EXCLUSIVE); });
    EXPECT_FALSE(result.success);

    disconnect();
    connectAs(1);
    EXPECT_NO_THROW({ lockApi->unlock(resourceId, holderUuid, lock::LockLevel::NONE); });

    disconnect();
    connectAs(2);
    EXPECT_NO_THROW({ EXPECT_FALSE(lockApi->checkReservedLock(resourceId, observerUuid)); });
    EXPECT_NO_THROW({ result = lockApi->lock(resourceId, observerUuid, lock::LockLevel::EXCLUSIVE); });
    EXPECT_TRUE(result.success);
    EXPECT_EQ(result.currentLevel, lock::LockLevel::EXCLUSIVE);
    EXPECT_NO_THROW({ lockApi->unlock(resourceId, observerUuid, lock::LockLevel::NONE); });
}

TEST_F(LockUsingGroupsTest, lock_denied_for_caller_in_no_granted_group) {
    // user_3 is in neither the Store's roster nor Group_2.
    const std::string storeId = grantedStore("manager");
    ASSERT_FALSE(storeId.empty());
    std::string resourceId;
    ASSERT_NO_THROW({ resourceId = createLockableResource(storeId); });
    ASSERT_FALSE(resourceId.empty());

    disconnect();
    connectAs(3);
    auto uuid = newUuid();
    EXPECT_THROW({ lockApi->lock(resourceId, uuid, lock::LockLevel::SHARED); }, core::Exception);
    EXPECT_THROW({ lockApi->checkReservedLock(resourceId, uuid); }, core::Exception);
}

TEST_F(LockUsingGroupsTest, lock_lost_after_the_grant_is_revoked) {
    const std::string storeId = grantedStore("manager");
    ASSERT_FALSE(storeId.empty());
    std::string resourceId;
    ASSERT_NO_THROW({ resourceId = createLockableResource(storeId); });
    ASSERT_FALSE(resourceId.empty());

    disconnect();
    connectAs(2);
    auto uuid = newUuid();
    expectLockGranted(resourceId, uuid, lock::LockLevel::SHARED, lock::LockLevel::SHARED);
    expectUnlockTo(resourceId, uuid, lock::LockLevel::NONE, lock::LockLevel::NONE);

    disconnect();
    connectAs(1);
    store::Store granted;
    ASSERT_NO_THROW({ granted = storeApi->getStore(storeId); });
    ASSERT_EQ(granted.groups.size(), 1);
    ASSERT_NO_THROW({
        storeApi->updateStore(
            storeId,
            std::vector<core::UserWithPubKey>{user(1)},
            std::vector<core::UserWithPubKey>{user(1)},
            core::Buffer::from("lock_group_revoked_public"),
            core::Buffer::from("lock_group_revoked_private"),
            granted.version,
            false,
            false,
            std::nullopt,
            std::vector<core::GroupGrantWithKey>{}
        );
    });

    disconnect();
    connectAs(2);
    EXPECT_THROW({ lockApi->lock(resourceId, uuid, lock::LockLevel::SHARED); }, core::Exception);
}
