#include "privmx/endpoint/search/LockSession.hpp"

using namespace privmx::endpoint;
using namespace privmx::endpoint::search;

const std::string LockSession::_KVDB_PREFIX = "lock:";
const core::Buffer LockSession::_META = core::Buffer::from("{}");

LockSession::LockSession(kvdb::KvdbApi kvdbApi, const std::string& kvdbId, const std::string& filepath)
        : _kvdbApi(kvdbApi), _kvdbId(kvdbId), _filepath(filepath) {}


bool LockSession::lock(LockLevel level) {
    getLockSetFromKvdb();
    auto status = _lockSet.lock(level);
    if (status.save) {
        try {
        setLockSetInKvdb();
        } catch (...) {
            return false;
        }
    }
    return status.success;
}

bool LockSession::unlock(LockLevel level) {
    getLockSetFromKvdb();
    auto status = _lockSet.unlock(level);
    if (status.save) {
        try {
            setLockSetInKvdb();
        } catch (...) {
            return false;
        }
    }
    return status.success;
}

bool LockSession::checkReservedLock() {
    getLockSetFromKvdb();
    return _lockSet.checkReservedLock();
}

void LockSession::getLockSetFromKvdb() {
    try {
        auto entry = _kvdbApi.getEntry(_kvdbId, _KVDB_PREFIX + _filepath);
        _version = entry.version;
        _lockSet.deserializeAndSetLockSet(entry.data);
    } catch (...) {
        _version = 0;
        _lockSet.setEmptyLockSet();
    }
}

void LockSession::setLockSetInKvdb() {
    _kvdbApi.setEntry(_kvdbId, _KVDB_PREFIX + _filepath, _META, _META, _lockSet.getAndSerializeLockSet(), _version);
}
