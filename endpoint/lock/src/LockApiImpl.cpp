/*
PrivMX Endpoint.
Copyright © 2026 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include "privmx/endpoint/lock/LockApiImpl.hpp"
#include "privmx/endpoint/lock/LockException.hpp"

using namespace privmx::endpoint::lock;

LockApiImpl::LockApiImpl(const privfs::RpcGateway::Ptr& gateway) : _serverApi(gateway) {}

LockOperationResult LockApiImpl::lock(const std::string& resourceId, const std::string& uuid, LockLevel lockLevel) {
    server::LockLockModel model;
    model.resourceId = resourceId;
    model.uuid = uuid;
    model.lockLevel = lockLevelToString(lockLevel);
    auto result = _serverApi.lockLock(model);
    return LockOperationResult{result.success, lockLevelFromString(result.currentLevel)};
}

LockOperationResult LockApiImpl::unlock(const std::string& resourceId, const std::string& uuid, LockLevel lockLevel) {
    server::LockUnlockModel model;
    model.resourceId = resourceId;
    model.uuid = uuid;
    model.lockLevel = lockLevelToString(lockLevel);
    auto result = _serverApi.lockUnlock(model);
    return LockOperationResult{result.success, lockLevelFromString(result.currentLevel)};
}

std::string LockApiImpl::lockLevelToString(LockLevel level) {
    switch (level) {
    case LockLevel::NONE:
        return "none";
    case LockLevel::SHARED:
        return "shared";
    case LockLevel::RESERVED:
        return "reserved";
    case LockLevel::PENDING:
        return "pending";
    case LockLevel::EXCLUSIVE:
        return "exclusive";
    }
    throw InvalidLockLevelException();
}

bool LockApiImpl::checkReservedLock(const std::string& resourceId, const std::string& uuid) {
    server::LockCheckReservedLockModel model;
    model.resourceId = resourceId;
    model.uuid = uuid;
    return _serverApi.lockCheckReservedLock(model).reserved;
}

LockLevel LockApiImpl::lockLevelFromString(const std::string& level) {
    if (level == "none")
        return LockLevel::NONE;
    if (level == "shared")
        return LockLevel::SHARED;
    if (level == "reserved")
        return LockLevel::RESERVED;
    if (level == "pending")
        return LockLevel::PENDING;
    if (level == "exclusive")
        return LockLevel::EXCLUSIVE;
    throw InvalidLockLevelException(level);
}
