#include "privmx/endpoint/search/LockSetLogic.hpp"

#include <Poco/UUIDGenerator.h>

using namespace privmx::endpoint;
using namespace privmx::endpoint::search;

LockSetLogic::LockSetLogic() {
    _lockId = generateId();
}

void LockSetLogic::deserializeAndSetLockSet(const core::Buffer& buffer) {
    _lockSet = utils::TypedObjectFactory::createObjectFromVar<dynamic::LockSet>(utils::Utils::parseJsonObject(buffer.stdString()));
    if (_lockSet.readerLocksEmpty()) _lockSet.readerLocks(utils::TypedObjectFactory::createNewMap<dynamic::Lock>());
}

void LockSetLogic::setEmptyLockSet() {
    auto lockSet = utils::TypedObjectFactory::createNewObject<dynamic::LockSet>();
    lockSet.readerLocks(utils::TypedObjectFactory::createNewMap<dynamic::Lock>());
    _lockSet = lockSet;
}

core::Buffer LockSetLogic::getAndSerializeLockSet() {
    return core::Buffer::from(utils::Utils::stringifyVar(_lockSet.asVar()));
}

LockSetLogic::LockResult LockSetLogic::lock(LockLevel level) {
    auto myLock = getMyLock();
    if (myLock.level() >= level) {
        return { true, false };
    }
    deleteTimeoutedLocks();
    switch (level) {
        case LockLevel::SHARED:
            {
                if (!_lockSet.writerLockEmpty() && _lockSet.writerLock().level() != LockLevel::RESERVED) {
                    return { false, false };
                }
                _lockSet.readerLocks().add(_lockId, createMyLock(level));
                return { true, true };
            }
        case LockLevel::RESERVED:
        case LockLevel::PENDING:
            {
                if (!_lockSet.writerLockEmpty() && _lockSet.writerLock().lockId() != _lockId) {
                    return { false, false };
                }
                deleteMyLocks();
                _lockSet.writerLock(createMyLock(level));
                return { true, true };
            }
        case LockLevel::EXCLUSIVE:
            {
                if (!_lockSet.writerLockEmpty() && _lockSet.writerLock().lockId() != _lockId) {
                    return { false, false };
                }
                deleteMyLocks();
                if (_lockSet.readerLocks().getKeys().size() > 0) {
                    if (myLock.level() == LockLevel::PENDING) {
                        return { false, false };
                    }
                    _lockSet.writerLock(createMyLock(LockLevel::PENDING));
                    return { false, true };
                }
                _lockSet.writerLock(createMyLock(level));
                return { true, true };
            }
        default:
            return { false, false };
    }
    return { false, false };
}

LockSetLogic::LockResult LockSetLogic::unlock(LockLevel level) {
    if (getMyLock().level() <= level) {
        return { true, false };
    }
    deleteTimeoutedLocks();
    switch (level) {
        case LockLevel::NONE:
            {
                deleteMyLocks();
                return { true, true };
            }
        case LockLevel::SHARED:
            {
                deleteMyLocks();
                if (!_lockSet.writerLockEmpty()) {
                    return { false, false };
                }
                _lockSet.readerLocks().add(_lockId, createMyLock(level));
                return { true, true };
            }
        default:
            return { false, false };
    }
    return { false, false };
}

bool LockSetLogic::checkReservedLock() {
    return !_lockSet.writerLockEmpty();
}

std::string LockSetLogic::generateId() {
    return Poco::UUIDGenerator::defaultGenerator().createRandom().toString();
}

void LockSetLogic::deleteTimeoutedLocks() {
    int64_t nowTimestamp = utils::Utils::getNowTimestamp();
    int64_t timeoutTimestamp = nowTimestamp - TIMEOUT_DELTA;
    if (!_lockSet.writerLockEmpty() && _lockSet.writerLock().timestamp() <= timeoutTimestamp) {
        _lockSet.writerLockClear();
    }
    auto oldMap = _lockSet.readerLocks();
    auto newMap = utils::TypedObjectFactory::createNewMap<dynamic::Lock>();
    for (auto lock : oldMap) {
        if (lock.second.timestamp() > timeoutTimestamp) {
            newMap.add(lock.first, lock.second);
        }
    }
    _lockSet.readerLocks(newMap);
}

void LockSetLogic::deleteMyLocks() {
    if (!_lockSet.writerLockEmpty() && _lockSet.writerLock().lockId() == _lockId) {
        _lockSet.writerLockClear();
    }
    if (_lockSet.readerLocks().hasKey(_lockId)) {
        _lockSet.readerLocks().remove(_lockId);
    }
}

dynamic::Lock LockSetLogic::getMyLock() {
    if (!_lockSet.writerLockEmpty() && _lockSet.writerLock().lockId() == _lockId) {
        return _lockSet.writerLock();
    }
    if (_lockSet.readerLocks().hasKey(_lockId)) {
        return _lockSet.readerLocks().get(_lockId);
    }
    return createMyLock(LockLevel::NONE);
}

dynamic::Lock LockSetLogic::createMyLock(LockLevel level) {
    auto lock = utils::TypedObjectFactory::createNewObject<dynamic::Lock>();
    lock.lockId(_lockId);
    lock.timestamp(utils::Utils::getNowTimestamp());
    lock.level(level);
    return lock;
}
