#include <gtest/gtest.h>
#include "../../utils/BaseTest.hpp"
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

enum LKConnectionType {
    LKUser1,
    LKUser2,
    LKUser3
};

/**
 * LockApi itself knows nothing about groups - it locks a resource id and holds no keys. What it does inherit is
 * the Store's access check: a lock is only granted to a caller who may write the file, so whether a grantee
 * group's member can lock is decided by the same policy that decides whether they can write.
 */
class LockUsingGroupsTest : public privmx::test::BaseTest {
protected:
    LockUsingGroupsTest() : BaseTest(privmx::test::BaseTestMode::online) {}
    void connectAs(LKConnectionType type) {
        std::string privKey;
        if (type == LKConnectionType::LKUser1) {
            privKey = reader->getString("Login.user_1_privKey");
        } else if (type == LKConnectionType::LKUser2) {
            privKey = reader->getString("Login.user_2_privKey");
        } else {
            privKey = reader->getString("Login.user_3_privKey");
        }
        connection = std::make_shared<core::Connection>(
            core::Connection::connect(
                privKey,
                reader->getString("Login.solutionId"),
                getPlatformUrl(reader->getString("Login.instanceUrl"))
            )
        );
        buildApis();
    }
    void buildApis() {
        groupApi = std::make_shared<group::GroupApi>(group::GroupApi::create(*connection));
        storeApi = std::make_shared<store::StoreApi>(store::StoreApi::create(*connection, *groupApi));
        lockApi = std::make_shared<lock::LockApi>(lock::LockApi::create(*connection));
    }
    void disconnect() {
        connection->disconnect();
        connection.reset();
        storeApi.reset();
        lockApi.reset();
        groupApi.reset();
    }
    core::UserWithPubKey userOf(LKConnectionType type) {
        std::string n;
        if (type == LKConnectionType::LKUser1) {
            n = "1";
        } else if (type == LKConnectionType::LKUser2) {
            n = "2";
        } else {
            n = "3";
        }
        return core::UserWithPubKey{
            .userId = reader->getString("Login.user_" + n + "_id"),
            .pubKey = reader->getString("Login.user_" + n + "_pubKey")
        };
    }
    void customSetUp() override {
        reader = new Poco::Util::IniFileConfiguration(INI_FILE_PATH);
        connection = std::make_shared<core::Connection>(
            core::Connection::connect(
                reader->getString("Login.user_1_privKey"),
                reader->getString("Login.solutionId"),
                getPlatformUrl(reader->getString("Login.instanceUrl"))
            )
        );
        buildApis();
    }
    void customTearDown() override {
        connection.reset();
        storeApi.reset();
        lockApi.reset();
        groupApi.reset();
        reader.reset();
        core::EventQueueImpl::getInstance()->clear();
    }
    // A Store whose only direct member is user_1, granted to `group` at `role`.
    std::string createStoreWithGroup(const group::Group& group, const std::string& role) {
        return storeApi->createStore(
            reader->getString("Context_1.contextId"),
            std::vector<core::UserWithPubKey>{userOf(LKConnectionType::LKUser1)},
            std::vector<core::UserWithPubKey>{userOf(LKConnectionType::LKUser1)},
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

    std::shared_ptr<core::Connection> connection;
    std::shared_ptr<store::StoreApi> storeApi;
    std::shared_ptr<lock::LockApi> lockApi;
    std::shared_ptr<group::GroupApi> groupApi;
    Poco::Util::IniFileConfiguration::Ptr reader;
    core::VarSerializer _serializer = core::VarSerializer({});
};

TEST_F(LockUsingGroupsTest, lock_via_group_manager_grant) {
    // Group_2 holds user_1 and user_2. user_2 is not a direct member of the Store, so the lock can only be
    // granted through the grant - the check behind lockLock has to account for group membership.
    group::Group group_2;
    ASSERT_NO_THROW({ group_2 = groupApi->getGroup(reader->getString("Group_2.groupId")); });
    ASSERT_EQ(group_2.statusCode, 0);

    std::string storeId;
    ASSERT_NO_THROW({ storeId = createStoreWithGroup(group_2, "manager"); });
    ASSERT_FALSE(storeId.empty());
    std::string resourceId;
    ASSERT_NO_THROW({ resourceId = createLockableResource(storeId); });
    ASSERT_FALSE(resourceId.empty());

    disconnect();
    connectAs(LKConnectionType::LKUser2);
    auto uuid = newUuid();
    lock::LockOperationResult result{false, lock::LockLevel::NONE};
    EXPECT_NO_THROW({ result = lockApi->lock(resourceId, uuid, lock::LockLevel::SHARED); });
    EXPECT_TRUE(result.success);
    EXPECT_EQ(result.currentLevel, lock::LockLevel::SHARED);

    EXPECT_NO_THROW({ result = lockApi->lock(resourceId, uuid, lock::LockLevel::EXCLUSIVE); });
    EXPECT_TRUE(result.success);
    EXPECT_EQ(result.currentLevel, lock::LockLevel::EXCLUSIVE);

    EXPECT_NO_THROW({ result = lockApi->unlock(resourceId, uuid, lock::LockLevel::NONE); });
    EXPECT_TRUE(result.success);
    EXPECT_EQ(result.currentLevel, lock::LockLevel::NONE);
}

TEST_F(LockUsingGroupsTest, lock_on_own_file_via_group_user_grant) {
    // "user" is the weaker grant, and the default item policy is "itemOwner&user,manager" - enough for the file
    // this caller created itself.
    group::Group group_2;
    ASSERT_NO_THROW({ group_2 = groupApi->getGroup(reader->getString("Group_2.groupId")); });
    ASSERT_EQ(group_2.statusCode, 0);

    std::string storeId;
    ASSERT_NO_THROW({ storeId = createStoreWithGroup(group_2, "user"); });
    ASSERT_FALSE(storeId.empty());

    disconnect();
    connectAs(LKConnectionType::LKUser2);
    std::string resourceId;
    ASSERT_NO_THROW({ resourceId = createLockableResource(storeId); });
    ASSERT_FALSE(resourceId.empty());

    auto uuid = newUuid();
    lock::LockOperationResult result{false, lock::LockLevel::NONE};
    EXPECT_NO_THROW({ result = lockApi->lock(resourceId, uuid, lock::LockLevel::EXCLUSIVE); });
    EXPECT_TRUE(result.success);
    EXPECT_EQ(result.currentLevel, lock::LockLevel::EXCLUSIVE);
    EXPECT_NO_THROW({ lockApi->unlock(resourceId, uuid, lock::LockLevel::NONE); });
}

TEST_F(LockUsingGroupsTest, lock_on_another_users_file_denied_for_group_user_grant) {
    // Same grant, someone else's file: "itemOwner&user,manager" is satisfied by neither half, so the lock is
    // refused. This is the policy talking, not the group - a direct member with the same role fares the same.
    group::Group group_2;
    ASSERT_NO_THROW({ group_2 = groupApi->getGroup(reader->getString("Group_2.groupId")); });
    ASSERT_EQ(group_2.statusCode, 0);

    std::string storeId;
    ASSERT_NO_THROW({ storeId = createStoreWithGroup(group_2, "user"); });
    ASSERT_FALSE(storeId.empty());
    std::string resourceId;
    ASSERT_NO_THROW({ resourceId = createLockableResource(storeId); });
    ASSERT_FALSE(resourceId.empty());

    disconnect();
    connectAs(LKConnectionType::LKUser2);
    EXPECT_THROW({ lockApi->lock(resourceId, newUuid(), lock::LockLevel::SHARED); }, core::Exception);
}

TEST_F(LockUsingGroupsTest, checkReservedLock_via_group_grant) {
    group::Group group_2;
    ASSERT_NO_THROW({ group_2 = groupApi->getGroup(reader->getString("Group_2.groupId")); });
    ASSERT_EQ(group_2.statusCode, 0);

    std::string storeId;
    ASSERT_NO_THROW({ storeId = createStoreWithGroup(group_2, "manager"); });
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
    connectAs(LKConnectionType::LKUser2);
    auto observerUuid = newUuid();
    EXPECT_NO_THROW({ EXPECT_TRUE(lockApi->checkReservedLock(resourceId, observerUuid)); });
    EXPECT_NO_THROW({ result = lockApi->lock(resourceId, observerUuid, lock::LockLevel::EXCLUSIVE); });
    EXPECT_FALSE(result.success);

    disconnect();
    connectAs(LKConnectionType::LKUser1);
    EXPECT_NO_THROW({ lockApi->unlock(resourceId, holderUuid, lock::LockLevel::NONE); });

    disconnect();
    connectAs(LKConnectionType::LKUser2);
    EXPECT_NO_THROW({ EXPECT_FALSE(lockApi->checkReservedLock(resourceId, observerUuid)); });
    EXPECT_NO_THROW({ result = lockApi->lock(resourceId, observerUuid, lock::LockLevel::EXCLUSIVE); });
    EXPECT_TRUE(result.success);
    EXPECT_EQ(result.currentLevel, lock::LockLevel::EXCLUSIVE);
    EXPECT_NO_THROW({ lockApi->unlock(resourceId, observerUuid, lock::LockLevel::NONE); });
}

TEST_F(LockUsingGroupsTest, lock_denied_for_caller_in_no_granted_group) {
    // user_3 is in neither the Store's roster nor Group_2.
    group::Group group_2;
    ASSERT_NO_THROW({ group_2 = groupApi->getGroup(reader->getString("Group_2.groupId")); });
    ASSERT_EQ(group_2.statusCode, 0);

    std::string storeId;
    ASSERT_NO_THROW({ storeId = createStoreWithGroup(group_2, "manager"); });
    ASSERT_FALSE(storeId.empty());
    std::string resourceId;
    ASSERT_NO_THROW({ resourceId = createLockableResource(storeId); });
    ASSERT_FALSE(resourceId.empty());

    disconnect();
    connectAs(LKConnectionType::LKUser3);
    auto uuid = newUuid();
    EXPECT_THROW({ lockApi->lock(resourceId, uuid, lock::LockLevel::SHARED); }, core::Exception);
    EXPECT_THROW({ lockApi->checkReservedLock(resourceId, uuid); }, core::Exception);
}

TEST_F(LockUsingGroupsTest, lock_lost_after_the_grant_is_revoked) {
    group::Group group_2;
    ASSERT_NO_THROW({ group_2 = groupApi->getGroup(reader->getString("Group_2.groupId")); });
    ASSERT_EQ(group_2.statusCode, 0);

    std::string storeId;
    ASSERT_NO_THROW({ storeId = createStoreWithGroup(group_2, "manager"); });
    ASSERT_FALSE(storeId.empty());
    std::string resourceId;
    ASSERT_NO_THROW({ resourceId = createLockableResource(storeId); });
    ASSERT_FALSE(resourceId.empty());

    disconnect();
    connectAs(LKConnectionType::LKUser2);
    auto uuid = newUuid();
    lock::LockOperationResult result{false, lock::LockLevel::NONE};
    ASSERT_NO_THROW({ result = lockApi->lock(resourceId, uuid, lock::LockLevel::SHARED); });
    ASSERT_TRUE(result.success);
    ASSERT_NO_THROW({ lockApi->unlock(resourceId, uuid, lock::LockLevel::NONE); });

    disconnect();
    connectAs(LKConnectionType::LKUser1);
    store::Store granted;
    ASSERT_NO_THROW({ granted = storeApi->getStore(storeId); });
    ASSERT_EQ(granted.groups.size(), 1);
    ASSERT_NO_THROW({
        storeApi->updateStore(
            storeId,
            std::vector<core::UserWithPubKey>{userOf(LKConnectionType::LKUser1)},
            std::vector<core::UserWithPubKey>{userOf(LKConnectionType::LKUser1)},
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
    connectAs(LKConnectionType::LKUser2);
    EXPECT_THROW({ lockApi->lock(resourceId, uuid, lock::LockLevel::SHARED); }, core::Exception);
}
