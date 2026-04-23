#include "privmx/endpoint/search/PrivmxFS.hpp"

#include <algorithm>
#include <chrono>
#include <cstring>
#include <iostream>
#include <mutex>
#include <thread>
#include <privmx/utils/Logger.hpp>
#include <sstream>
#include <type_traits>
#include <unordered_map>

#include "privmx/endpoint/core/ConvertedExceptions.hpp"
#include "privmx/endpoint/core/ExceptionConverter.hpp"
#include "privmx/endpoint/search/DynamicTypes.hpp"
#include "privmx/endpoint/search/SearchException.hpp"

static const privmx::endpoint::core::Buffer META = privmx::endpoint::core::Buffer::from("{}");

using namespace privmx::endpoint::search;

namespace {

struct ScopedPathInfo {
    std::string sessionId;
    std::string path;
};

struct ScopedDbLockState {
    LockSession lockSession;
    std::uint64_t refCount = 0;
    bool locked = false;
};

std::mutex g_scopedDbLockMutex;
std::unordered_map<std::string, std::shared_ptr<ScopedDbLockState>> g_scopedDbLocks;
std::mutex g_sessionFilesystemMutex;
std::unordered_map<std::string, std::shared_ptr<PrivmxFS>> g_sessionFilesystems;

constexpr auto SCOPED_DB_LOCK_TIMEOUT = std::chrono::seconds(10);
constexpr auto SCOPED_DB_LOCK_RETRY_DELAY = std::chrono::milliseconds(50);
constexpr std::size_t STORE_RANDOM_WRITE_MAX_CHUNK_SIZE = 512 * 1024;

std::string makeScopedDbLockKey(const std::string& sessionId, const std::string& path) {
    return sessionId + ":" + path;
}

ScopedPathInfo parseScopedPath(const std::string& fullPath) {
    Poco::Path path;
    path.parse(fullPath);
    if (path.depth() >= 2 && path[0] == "pmx") {
        ScopedPathInfo result{.sessionId = path[1], .path = std::string()};
        path.popFrontDirectory();
        path.popFrontDirectory();
        result.path = path.toString();
        return result;
    }
    throw std::runtime_error("Invalid PrivmxFS scoped path: " + fullPath);
}

bool isScopedDbLockActive(const std::shared_ptr<PrivmxSession>& session, const std::string& path) {
    std::lock_guard<std::mutex> lock(g_scopedDbLockMutex);
    auto it = g_scopedDbLocks.find(makeScopedDbLockKey(session->id, path));
    return it != g_scopedDbLocks.end() && it->second->locked;
}

void cleanupScopedDbLockAttempt(const std::shared_ptr<ScopedDbLockState>& state) {
    try {
        state->lockSession.unlock(LockLevel::NONE);
    } catch (...) {
    }
}

std::shared_ptr<PrivmxFS> getOrCreateSessionFilesystem(const std::shared_ptr<PrivmxSession>& session) {
    std::lock_guard<std::mutex> lock(g_sessionFilesystemMutex);
    auto& entry = g_sessionFilesystems[session->id];
    if (!entry) {
        entry = std::make_shared<PrivmxFS>(session);
    }
    return entry;
}

void releaseSessionFilesystem(const std::string& sessionId) {
    std::lock_guard<std::mutex> lock(g_sessionFilesystemMutex);
    g_sessionFilesystems.erase(sessionId);
}

int64_t getDirtyRangeEnd(const std::pair<const int64_t, std::string>& range) {
    return range.first + static_cast<int64_t>(range.second.size());
}

void mergeDirtyRange(std::map<int64_t, std::string>& dirtyRanges, int64_t offset, const std::string& data) {
    if (data.empty()) {
        return;
    }

    int64_t mergedStart = offset;
    int64_t mergedEnd = offset + static_cast<int64_t>(data.size());
    std::vector<std::pair<int64_t, std::string>> overlappingRanges;

    auto it = dirtyRanges.lower_bound(offset);
    if (it != dirtyRanges.begin()) {
        auto prev = std::prev(it);
        if (getDirtyRangeEnd(*prev) >= offset) {
            it = prev;
        }
    }

    while (it != dirtyRanges.end()) {
        const auto existingStart = it->first;
        const auto existingEnd = getDirtyRangeEnd(*it);
        if (existingStart > mergedEnd) {
            break;
        }
        if (existingEnd >= mergedStart) {
            mergedStart = std::min(mergedStart, existingStart);
            mergedEnd = std::max(mergedEnd, existingEnd);
            overlappingRanges.emplace_back(it->first, it->second);
            it = dirtyRanges.erase(it);
            continue;
        }
        ++it;
    }

    std::string merged(static_cast<std::size_t>(mergedEnd - mergedStart), '\0');
    for (const auto& range : overlappingRanges) {
        std::memcpy(
            merged.data() + (range.first - mergedStart),
            range.second.data(),
            range.second.size()
        );
    }
    std::memcpy(
        merged.data() + (offset - mergedStart),
        data.data(),
        data.size()
    );
    dirtyRanges.emplace(mergedStart, std::move(merged));
}

void trimDirtyRanges(std::map<int64_t, std::string>& dirtyRanges, int64_t size) {
    auto it = dirtyRanges.begin();
    while (it != dirtyRanges.end()) {
        const auto rangeStart = it->first;
        const auto rangeEnd = getDirtyRangeEnd(*it);
        if (rangeStart >= size) {
            it = dirtyRanges.erase(it);
            continue;
        }
        if (rangeEnd > size) {
            it->second.resize(static_cast<std::size_t>(size - rangeStart));
        }
        ++it;
    }
}

bool isRangeFullyCoveredByDirtyRanges(
    const std::map<int64_t, std::string>& dirtyRanges,
    int64_t offset,
    int64_t size
) {
    if (size <= 0) {
        return true;
    }

    int64_t coveredUntil = offset;
    auto it = dirtyRanges.lower_bound(offset);
    if (it != dirtyRanges.begin()) {
        auto prev = std::prev(it);
        if (getDirtyRangeEnd(*prev) > offset) {
            it = prev;
        }
    }

    const int64_t requestedEnd = offset + size;
    while (it != dirtyRanges.end() && coveredUntil < requestedEnd) {
        const auto rangeStart = it->first;
        const auto rangeEnd = getDirtyRangeEnd(*it);
        if (rangeEnd <= coveredUntil) {
            ++it;
            continue;
        }
        if (rangeStart > coveredUntil) {
            return false;
        }
        coveredUntil = std::max(coveredUntil, rangeEnd);
        ++it;
    }

    return coveredUntil >= requestedEnd;
}

void overlayDirtyRanges(
    std::string& buffer,
    int64_t offset,
    const std::map<int64_t, std::string>& dirtyRanges
) {
    const int64_t readEnd = offset + static_cast<int64_t>(buffer.size());
    auto it = dirtyRanges.lower_bound(offset);
    if (it != dirtyRanges.begin()) {
        auto prev = std::prev(it);
        if (getDirtyRangeEnd(*prev) > offset) {
            it = prev;
        }
    }

    while (it != dirtyRanges.end()) {
        const auto rangeStart = it->first;
        const auto rangeEnd = getDirtyRangeEnd(*it);
        if (rangeStart >= readEnd) {
            break;
        }
        if (rangeEnd <= offset) {
            ++it;
            continue;
        }
        const auto copyStart = std::max(offset, rangeStart);
        const auto copyEnd = std::min(readEnd, rangeEnd);
        std::memcpy(
            buffer.data() + (copyStart - offset),
            it->second.data() + (copyStart - rangeStart),
            static_cast<std::size_t>(copyEnd - copyStart)
        );
        ++it;
    }
}

int64_t ensureRemoteSizeLoaded(
    const std::shared_ptr<PrivmxSession>& session,
    const std::string& fileId,
    const std::shared_ptr<PrivmxFile::BufferedFileState>& bufferedFileState
) {
    if (bufferedFileState->remoteSize.has_value()) {
        return *bufferedFileState->remoteSize;
    }
    auto fileInfo = session->storeApi.getFile(fileId);
    if (fileInfo.statusCode != 0) {
        throw MalformedInternalFileException();
    }
    bufferedFileState->remoteSize = fileInfo.size;
    return fileInfo.size;
}

void writeToStoreInChunks(
    const std::shared_ptr<PrivmxSession>& session,
    int64_t fh,
    int64_t offset,
    const std::string& data,
    bool truncateAtEnd = false
) {
    if (data.empty()) {
        session->storeApi.seekInFile(fh, offset);
        session->storeApi.writeToFile(fh, privmx::endpoint::core::Buffer::from("", 0), truncateAtEnd);
        return;
    }

    std::size_t written = 0;
    while (written < data.size()) {
        const auto chunkSize = std::min(STORE_RANDOM_WRITE_MAX_CHUNK_SIZE, data.size() - written);
        session->storeApi.seekInFile(fh, offset + static_cast<int64_t>(written));
        session->storeApi.writeToFile(
            fh,
            privmx::endpoint::core::Buffer::from(data.data() + written, chunkSize),
            truncateAtEnd && written + chunkSize == data.size()
        );
        written += chunkSize;
    }
}

} // namespace

std::shared_ptr<SessionManager> SessionManager::_singleton;

std::shared_ptr<SessionManager> SessionManager::get() {
    if (!_singleton) {
        _singleton = std::make_shared<SessionManager>();
    }
    return _singleton;
}
std::shared_ptr<PrivmxSession> SessionManager::addSession(
    const privmx::endpoint::core::Connection& connection,
    const privmx::endpoint::store::StoreApi& storeApi,
    const privmx::endpoint::kvdb::KvdbApi& kvdbApi,
    const std::string& kvdbId,
    const std::string& storeId
) {
    std::shared_ptr<PrivmxSession> session = std::make_shared<PrivmxSession>(PrivmxSession {
        .id = generateId(),
        .connection = connection,
        .storeApi = storeApi,
        .kvdbApi = kvdbApi,
        .kvdbId = kvdbId,
        .storeId = storeId
    });
    _sessions[session->id] = session;
    return session;
}
std::shared_ptr<PrivmxSession> SessionManager::getSession(const std::string& id) {
    return _sessions[id];
}

void SessionManager::removeSession(const std::string& id) {
    _sessions.erase(id);
}

std::string SessionManager::generateId() {
    return std::to_string(_lastId++);
}

Writer::Writer() : _buf(std::stringstream(std::ios::out | std::ios::binary)) {}

std::tuple<int64_t, std::string> Writer::write(int64_t offset, const std::string& data) {
    if (_offset == -1) {
        _offset = offset;
    }
    if (_offset + size() != offset || size() > 128*1024*2) {
        auto result = _buf.str();
        auto resultOffset = _offset;
        _buf.str(data);
        _offset = offset;
        return {resultOffset, result};
    }
    _buf.seekp(0, std::ios::end);
    _buf.write(data.data(), data.size());
    return {-1, {}};
}

int64_t Writer::size() {
    return _buf.str().length();
}

PrivmxFile::PrivmxFile(std::shared_ptr<PrivmxSession> session, const std::string& fileId, const std::string& path)
        : PrivmxFile(session, fileId, path, false, nullptr, nullptr) {}

PrivmxFile::PrivmxFile(
    std::shared_ptr<PrivmxSession> session,
    const std::string& fileId,
    const std::string& path,
    bool memoryOnly,
    std::shared_ptr<MemoryFileState> memoryFileState,
    std::shared_ptr<BufferedFileState> bufferedFileState
) : session(session),
    fileId(fileId),
    path(path),
    lockSession(session->kvdbApi, session->kvdbId, path),
    memoryOnly(memoryOnly),
    memoryFileState(memoryFileState),
    bufferedFileState(bufferedFileState) {}

void PrivmxFile::open() {
    if (memoryOnly) {
        std::lock_guard<std::mutex> lock(memoryFileState->mutex);
        ++memoryFileState->openHandleCount;
        if (memoryFileState->remoteBacked && memoryFileState->remoteFh == -1) {
            memoryFileState->remoteFh = session->storeApi.openFile(memoryFileState->remoteFileId);
        }
        return;
    }
    LOG_TRACE("PrivmxFile::open - ", fileId)
    fh = session->storeApi.openFile(fileId);
}

void PrivmxFile::close() {
    if (memoryOnly) {
        int64_t remoteFh = -1;
        {
            std::lock_guard<std::mutex> lock(memoryFileState->mutex);
            if (memoryFileState->openHandleCount > 0) {
                --memoryFileState->openHandleCount;
            }
            if (memoryFileState->remoteBacked && memoryFileState->openHandleCount == 0 && memoryFileState->remoteFh != -1) {
                remoteFh = memoryFileState->remoteFh;
                memoryFileState->remoteFh = -1;
            }
        }
        if (remoteFh != -1) {
            session->storeApi.closeFile(remoteFh);
        }
        return;
    }
    if (fh != -1) {
        session->storeApi.closeFile(fh);
        fh = -1;
    }
}

privmx::endpoint::core::Buffer PrivmxFile::read(int64_t size, int64_t offset) {
    if (memoryOnly) {
        std::lock_guard<std::mutex> lock(memoryFileState->mutex);
        if (offset < 0) {
            return privmx::endpoint::core::Buffer::from("", 0);
        }
        if (static_cast<std::size_t>(offset) >= memoryFileState->data.size()) {
            return privmx::endpoint::core::Buffer::from("", 0);
        }
        const auto availableSize = memoryFileState->data.size() - static_cast<std::size_t>(offset);
        const auto readSize = std::min<std::size_t>(static_cast<std::size_t>(size), availableSize);
        return privmx::endpoint::core::Buffer::from(memoryFileState->data.data() + offset, readSize);
    }
    if (offset < 0 || size <= 0 || !bufferedFileState) {
        return privmx::endpoint::core::Buffer::from("", 0);
    }

    std::string result;
    bool fullyCoveredByDirtyRanges = false;
    {
        std::lock_guard<std::mutex> lock(bufferedFileState->mutex);
        if (bufferedFileState->logicalSize.has_value() && offset >= *bufferedFileState->logicalSize) {
            return privmx::endpoint::core::Buffer::from("", 0);
        }

        int64_t readSize = size;
        if (bufferedFileState->logicalSize.has_value()) {
            readSize = std::min(readSize, *bufferedFileState->logicalSize - offset);
        }
        if (readSize <= 0) {
            return privmx::endpoint::core::Buffer::from("", 0);
        }

        result.assign(static_cast<std::size_t>(readSize), '\0');
        if (bufferedFileState->fullReadCache.has_value()) {
            const auto& cache = *bufferedFileState->fullReadCache;
            if (static_cast<std::size_t>(offset) < cache.size()) {
                const auto cacheOffset = static_cast<std::size_t>(offset);
                const auto availableSize = cache.size() - cacheOffset;
                const auto cachedReadSize = std::min(result.size(), availableSize);
                std::memcpy(result.data(), cache.data() + cacheOffset, cachedReadSize);
            }
            overlayDirtyRanges(result, offset, bufferedFileState->dirtyRanges);
            return privmx::endpoint::core::Buffer::from(result);
        }
        fullyCoveredByDirtyRanges = isRangeFullyCoveredByDirtyRanges(bufferedFileState->dirtyRanges, offset, readSize);
    }

    if (!fullyCoveredByDirtyRanges) {
        session->storeApi.seekInFile(fh, offset);
        auto remoteData = session->storeApi.readFromFile(fh, static_cast<int64_t>(result.size())).stdString();
        std::memcpy(result.data(), remoteData.data(), std::min(result.size(), remoteData.size()));
    }

    {
        std::lock_guard<std::mutex> lock(bufferedFileState->mutex);
        overlayDirtyRanges(result, offset, bufferedFileState->dirtyRanges);
    }

    return privmx::endpoint::core::Buffer::from(result);
}

void PrivmxFile::write(const privmx::endpoint::core::Buffer& data, int64_t offset) {
    if (memoryOnly) {
        int64_t remoteFh = -1;
        if (offset < 0) {
            throw std::runtime_error("Invalid write offset");
        }
        {
            std::lock_guard<std::mutex> lock(memoryFileState->mutex);
            const auto writeOffset = static_cast<std::size_t>(offset);
            if (memoryFileState->data.size() < writeOffset) {
                memoryFileState->data.resize(writeOffset, '\0');
            }
            const auto writeSize = data.size();
            if (memoryFileState->data.size() < writeOffset + writeSize) {
                memoryFileState->data.resize(writeOffset + writeSize, '\0');
            }
            std::memcpy(memoryFileState->data.data() + writeOffset, data.data(), writeSize);
            remoteFh = memoryFileState->remoteFh;
        }
        if (remoteFh != -1) {
            writeToStoreInChunks(session, remoteFh, offset, data.stdString());
        }
        return;
    }
    if (!bufferedFileState) {
        return;
    }

    std::lock_guard<std::mutex> lock(bufferedFileState->mutex);
    const auto dataString = data.stdString();
    const auto currentSize = ensureRemoteSizeLoaded(session, fileId, bufferedFileState);
    mergeDirtyRange(bufferedFileState->dirtyRanges, offset, dataString);
    bufferedFileState->logicalSize = std::max(currentSize, offset + static_cast<int64_t>(dataString.size()));
    if (bufferedFileState->fullReadCache.has_value()) {
        auto& cache = *bufferedFileState->fullReadCache;
        const auto writeOffset = static_cast<std::size_t>(offset);
        if (cache.size() < writeOffset) {
            cache.resize(writeOffset, '\0');
        }
        if (cache.size() < writeOffset + dataString.size()) {
            cache.resize(writeOffset + dataString.size(), '\0');
        }
        std::memcpy(cache.data() + writeOffset, dataString.data(), dataString.size());
    }
}

void PrivmxFile::truncate(int64_t size) {
    if (memoryOnly) {
        int64_t remoteFh = -1;
        if (size < 0) {
            throw std::runtime_error("Invalid truncate size");
        }
        {
            std::lock_guard<std::mutex> lock(memoryFileState->mutex);
            memoryFileState->data.resize(static_cast<std::size_t>(size), '\0');
            remoteFh = memoryFileState->remoteFh;
        }
        if (remoteFh != -1) {
            session->storeApi.seekInFile(remoteFh, size);
            session->storeApi.writeToFile(remoteFh, privmx::endpoint::core::Buffer::from("", 0), true);
        }
        return;
    }
    if (!bufferedFileState) {
        return;
    }

    std::lock_guard<std::mutex> lock(bufferedFileState->mutex);
    ensureRemoteSizeLoaded(session, fileId, bufferedFileState);
    bufferedFileState->logicalSize = size;
    trimDirtyRanges(bufferedFileState->dirtyRanges, size);
    if (bufferedFileState->fullReadCache.has_value()) {
        bufferedFileState->fullReadCache->resize(static_cast<std::size_t>(size), '\0');
    }
}

void PrivmxFile::sync() {
    if (memoryOnly) {
        int64_t remoteFh = -1;
        {
            std::lock_guard<std::mutex> lock(memoryFileState->mutex);
            remoteFh = memoryFileState->remoteFh;
        }
        if (remoteFh != -1) {
            session->storeApi.syncFile(remoteFh);
        }
        return;
    }
    if (!bufferedFileState) {
        return;
    }

    std::lock_guard<std::mutex> lock(bufferedFileState->mutex);
    if (
        bufferedFileState->dirtyRanges.empty() &&
        (
            !bufferedFileState->logicalSize.has_value() ||
            (
                bufferedFileState->remoteSize.has_value() &&
                *bufferedFileState->logicalSize == *bufferedFileState->remoteSize
            )
        )
    ) {
        return;
    }

    auto fs = getOrCreateSessionFilesystem(session);
    fs->materializeJournalForDb(path);

    const auto remoteSize = ensureRemoteSizeLoaded(session, fileId, bufferedFileState);
    auto newRemoteSize = remoteSize;

    for (const auto& range : bufferedFileState->dirtyRanges) {
        writeToStoreInChunks(session, fh, range.first, range.second);
        newRemoteSize = std::max(newRemoteSize, range.first + static_cast<int64_t>(range.second.size()));
    }
    bufferedFileState->dirtyRanges.clear();

    const auto targetSize = bufferedFileState->logicalSize.value_or(newRemoteSize);
    if (targetSize != newRemoteSize) {
        session->storeApi.seekInFile(fh, targetSize);
        session->storeApi.writeToFile(fh, privmx::endpoint::core::Buffer::from("", 0), true);
        newRemoteSize = targetSize;
    }

    bufferedFileState->remoteSize = newRemoteSize;
    bufferedFileState->logicalSize = newRemoteSize;
}

int64_t PrivmxFile::getFileSize() {
    if (memoryOnly) {
        return static_cast<int64_t>(memoryFileState->data.size());
    }
    if (!bufferedFileState) {
        return 0;
    }

    std::lock_guard<std::mutex> lock(bufferedFileState->mutex);
    if (bufferedFileState->logicalSize.has_value()) {
        return *bufferedFileState->logicalSize;
    }
    return ensureRemoteSizeLoaded(session, fileId, bufferedFileState);
}

bool PrivmxFile::lock(LockLevel level) {
    if (memoryOnly) {
        std::lock_guard<std::mutex> lock(memoryFileState->mutex);
        memoryFileState->lockLevel = level;
        memoryFileState->reservedLock = level >= LockLevel::RESERVED;
        return true;
    }
    if (isScopedDbLockActive(session, path)) {
        return true;
    }
    bool val = lockSession.lock(level);
    if (val) {
        session->storeApi.syncFile(fh);
    }
    return val;
}

bool PrivmxFile::unlock(LockLevel level) {
    if (memoryOnly) {
        std::lock_guard<std::mutex> lock(memoryFileState->mutex);
        memoryFileState->lockLevel = level;
        memoryFileState->reservedLock = level >= LockLevel::RESERVED;
        return true;
    }
    if (isScopedDbLockActive(session, path)) {
        return true;
    }
    return lockSession.unlock(level);
}

bool PrivmxFile::checkReservedLock() {
    if (memoryOnly) {
        std::lock_guard<std::mutex> lock(memoryFileState->mutex);
        return memoryFileState->reservedLock;
    }
    if (isScopedDbLockActive(session, path)) {
        return true;
    }
    return lockSession.checkReservedLock();
}

std::shared_ptr<PrivmxFS> PrivmxFS::create(
    std::shared_ptr<PrivmxSession> session
) {
    return getOrCreateSessionFilesystem(session);
}

void PrivmxFS::releaseSession(const std::string& fullPath) {
    const auto parsed = parseScopedPath(fullPath);
    releaseSessionFilesystem(parsed.sessionId);
    SessionManager::get()->removeSession(parsed.sessionId);
}

void PrivmxFS::beginDbOperation(const std::string& fullPath) {
    const auto parsed = parseScopedPath(fullPath);
    if (parsed.path.size() >= 8 && parsed.path.compare(parsed.path.size() - 8, 8, "-journal") == 0) {
        return;
    }

    const auto session = SessionManager::get()->getSession(parsed.sessionId);
    const auto key = makeScopedDbLockKey(parsed.sessionId, parsed.path);

    std::shared_ptr<ScopedDbLockState> state;
    bool shouldAcquire = false;
    {
        std::lock_guard<std::mutex> lock(g_scopedDbLockMutex);
        auto& entry = g_scopedDbLocks[key];
        if (!entry) {
            entry = std::make_shared<ScopedDbLockState>(ScopedDbLockState{
                .lockSession = LockSession(session->kvdbApi, session->kvdbId, parsed.path),
                .refCount = 0,
                .locked = false
            });
        }
        state = entry;
        shouldAcquire = state->refCount == 0;
        ++state->refCount;
    }

    if (!shouldAcquire) {
        return;
    }

    const auto deadline = std::chrono::steady_clock::now() + SCOPED_DB_LOCK_TIMEOUT;
    try {
        while (true) {
            if (state->lockSession.lock(LockLevel::EXCLUSIVE)) {
                break;
            }
            if (std::chrono::steady_clock::now() >= deadline) {
                throw std::runtime_error("Unable to acquire scoped db lock");
            }
            std::this_thread::sleep_for(SCOPED_DB_LOCK_RETRY_DELAY);
        }
        std::lock_guard<std::mutex> lock(g_scopedDbLockMutex);
        state->locked = true;
    } catch (...) {
        cleanupScopedDbLockAttempt(state);
        std::lock_guard<std::mutex> lock(g_scopedDbLockMutex);
        auto it = g_scopedDbLocks.find(key);
        if (it != g_scopedDbLocks.end()) {
            it->second->locked = false;
            if (it->second->refCount > 0) {
                --it->second->refCount;
            }
            if (it->second->refCount == 0) {
                g_scopedDbLocks.erase(it);
            }
        }
        throw;
    }
}

void PrivmxFS::endDbOperation(const std::string& fullPath) {
    const auto parsed = parseScopedPath(fullPath);
    if (parsed.path.size() >= 8 && parsed.path.compare(parsed.path.size() - 8, 8, "-journal") == 0) {
        return;
    }

    const auto key = makeScopedDbLockKey(parsed.sessionId, parsed.path);
    std::shared_ptr<ScopedDbLockState> state;
    bool shouldRelease = false;
    {
        std::lock_guard<std::mutex> lock(g_scopedDbLockMutex);
        auto it = g_scopedDbLocks.find(key);
        if (it == g_scopedDbLocks.end()) {
            return;
        }
        state = it->second;
        if (state->refCount > 0) {
            --state->refCount;
        }
        shouldRelease = state->refCount == 0 && state->locked;
        if (state->refCount == 0) {
            g_scopedDbLocks.erase(it);
        }
    }

    if (shouldRelease) {
        state->lockSession.unlock(LockLevel::NONE);
    }
}

void PrivmxFS::loadFileFully(const std::string& fullPath) {
    const auto parsed = parseScopedPath(fullPath);
    const auto session = SessionManager::get()->getSession(parsed.sessionId);
    if (!session) {
        throw std::runtime_error("PrivmxFS session not found: " + parsed.sessionId);
    }
    PrivmxFS::create(session)->loadFileFullyByPath(parsed.path);
}

std::shared_ptr<PrivmxFile::MemoryFileState> PrivmxFS::getOrCreateMemoryFileState(const std::string& path) {
    std::lock_guard<std::mutex> lock(_memoryFileMutex);
    auto& memoryFileState = _memoryFiles[path];
    if (!memoryFileState) {
        memoryFileState = std::make_shared<PrivmxFile::MemoryFileState>();
    }
    return memoryFileState;
}

std::shared_ptr<PrivmxFile::BufferedFileState> PrivmxFS::getOrCreateBufferedFileState(const std::string& path) {
    std::lock_guard<std::mutex> lock(_bufferedFileMutex);
    auto& bufferedFileState = _bufferedFiles[path];
    if (!bufferedFileState) {
        bufferedFileState = std::make_shared<PrivmxFile::BufferedFileState>();
    }
    return bufferedFileState;
}

void PrivmxFS::loadFileFullyByPath(const std::string& path) {
    if (isJournalPath(path)) {
        return;
    }

    const auto fileId = getCachedFileId(path);
    const auto bufferedFileState = getOrCreateBufferedFileState(path);
    const auto fileInfo = _session->storeApi.getFile(fileId);
    if (fileInfo.statusCode != 0) {
        throw MalformedInternalFileException();
    }

    std::string data;
    if (fileInfo.size > 0) {
        const auto fh = _session->storeApi.openFile(fileId);
        try {
            data = _session->storeApi.readFromFile(fh, fileInfo.size).stdString();
            _session->storeApi.closeFile(fh);
        } catch (...) {
            _session->storeApi.closeFile(fh);
            throw;
        }
    }
    data.resize(static_cast<std::size_t>(fileInfo.size), '\0');

    std::lock_guard<std::mutex> lock(bufferedFileState->mutex);
    bufferedFileState->fullReadCache = std::move(data);
    bufferedFileState->remoteSize = fileInfo.size;
    bufferedFileState->logicalSize = fileInfo.size;
    bufferedFileState->dirtyRanges.clear();
}

std::optional<std::string> PrivmxFS::tryGetExistingFileId(const std::string& name) {
    {
        std::lock_guard<std::mutex> lock(_fileIdCacheMutex);
        auto it = _fileIdCache.find(name);
        if (it != _fileIdCache.end()) {
            return it->second;
        }
    }

    try {
        privmx::endpoint::kvdb::KvdbEntry kvdbEntry = _session->kvdbApi.getEntry(_session->kvdbId, name);
        if (kvdbEntry.statusCode != 0) {
            throw MalformedInternalFileIdException();
        }
        const auto fileId = kvdbEntry.data.stdString();
        std::lock_guard<std::mutex> lock(_fileIdCacheMutex);
        _fileIdCache[name] = fileId;
        return fileId;
    } catch (const privmx::endpoint::server::KvdbEntryDoesNotExistException& e) {
        return std::nullopt;
    }
}

void PrivmxFS::ensureJournalLoadedFromRemote(
    const std::string& path,
    const std::shared_ptr<PrivmxFile::MemoryFileState>& memoryFileState
) {
    {
        std::lock_guard<std::mutex> lock(memoryFileState->mutex);
        if (memoryFileState->remoteBacked) {
            return;
        }
    }

    auto existingFileId = tryGetExistingFileId(path);
    if (!existingFileId.has_value()) {
        return;
    }

    const auto fileInfo = _session->storeApi.getFile(*existingFileId);
    if (fileInfo.statusCode != 0) {
        throw MalformedInternalFileException();
    }

    std::string data;
    if (fileInfo.size > 0) {
        const auto remoteFh = _session->storeApi.openFile(*existingFileId);
        try {
            _session->storeApi.seekInFile(remoteFh, 0);
            data = _session->storeApi.readFromFile(remoteFh, fileInfo.size).stdString();
            _session->storeApi.closeFile(remoteFh);
        } catch (...) {
            _session->storeApi.closeFile(remoteFh);
            throw;
        }
    }

    std::lock_guard<std::mutex> lock(memoryFileState->mutex);
    if (!memoryFileState->remoteBacked) {
        memoryFileState->data = std::move(data);
        memoryFileState->remoteBacked = true;
        memoryFileState->remoteFileId = *existingFileId;
    }
}

void PrivmxFS::materializeJournalForDb(const std::string& dbPath) {
    const auto journalPath = dbPath + "-journal";
    std::shared_ptr<PrivmxFile::MemoryFileState> memoryFileState;
    {
        std::lock_guard<std::mutex> lock(_memoryFileMutex);
        auto it = _memoryFiles.find(journalPath);
        if (it != _memoryFiles.end()) {
            memoryFileState = it->second;
        }
    }
    if (!memoryFileState) {
        auto existingFileId = tryGetExistingFileId(journalPath);
        if (!existingFileId.has_value()) {
            return;
        }
        memoryFileState = getOrCreateMemoryFileState(journalPath);
    }
    ensureJournalLoadedFromRemote(journalPath, memoryFileState);

    std::string dataSnapshot;
    int64_t remoteFh = -1;
    {
        std::lock_guard<std::mutex> lock(memoryFileState->mutex);
        if (!memoryFileState->remoteBacked && memoryFileState->data.empty()) {
            return;
        }
        if (!memoryFileState->remoteBacked) {
            memoryFileState->remoteFileId = getCachedFileId(journalPath);
            memoryFileState->remoteBacked = true;
        }
        if (memoryFileState->remoteFh == -1) {
            memoryFileState->remoteFh = _session->storeApi.openFile(memoryFileState->remoteFileId);
        }
        dataSnapshot = memoryFileState->data;
        remoteFh = memoryFileState->remoteFh;
    }

    writeToStoreInChunks(_session, remoteFh, 0, dataSnapshot, true);
    _session->storeApi.syncFile(remoteFh);
}

std::shared_ptr<PrivmxFile> PrivmxFS::openFile(const std::string& path) {
    if (isJournalPath(path)) {
        auto memoryFileState = getOrCreateMemoryFileState(path);
        ensureJournalLoadedFromRemote(path, memoryFileState);
        std::shared_ptr<PrivmxFile> result = std::make_shared<PrivmxFile>(_session, "", path, true, memoryFileState, nullptr);
        result->open();
        return result;
    }
    auto bufferedFileState = getOrCreateBufferedFileState(path);
    std::string fileId = getCachedFileId(path);
    std::shared_ptr<PrivmxFile> result = std::make_shared<PrivmxFile>(
        _session,
        fileId,
        path,
        false,
        nullptr,
        bufferedFileState
    );
    result->open();
    return result;
}

bool PrivmxFS::access(const std::string& path) {
    if (isJournalPath(path)) {
        {
            std::lock_guard<std::mutex> lock(_memoryFileMutex);
            auto it = _memoryFiles.find(path);
            if (it != _memoryFiles.end()) {
                std::lock_guard<std::mutex> stateLock(it->second->mutex);
                if (!it->second->data.empty() || it->second->remoteBacked) {
                    return true;
                }
            }
        }
        return _session->kvdbApi.hasEntry(_session->kvdbId, path);
    }
    LOG_TRACE("PrivmxFS::access - ", path, " | kvdbId: ",_session->kvdbId)
    return _session->kvdbApi.hasEntry(_session->kvdbId, path);
}

void PrivmxFS::deleteFile(const std::string& path) {
    if (isJournalPath(path)) {
        auto memoryFileState = getOrCreateMemoryFileState(path);
        std::optional<std::string> remoteFileId;
        int64_t remoteFh = -1;
        {
            std::lock_guard<std::mutex> lock(memoryFileState->mutex);
            if (memoryFileState->remoteBacked) {
                remoteFileId = memoryFileState->remoteFileId;
                remoteFh = memoryFileState->remoteFh;
                memoryFileState->remoteBacked = false;
                memoryFileState->remoteFileId.clear();
                memoryFileState->remoteFh = -1;
            }
            memoryFileState->data.clear();
            memoryFileState->lockLevel = LockLevel::NONE;
            memoryFileState->reservedLock = false;
        }
        if (!remoteFileId.has_value()) {
            remoteFileId = tryGetExistingFileId(path);
        }
        if (remoteFh != -1) {
            _session->storeApi.closeFile(remoteFh);
        }
        if (remoteFileId.has_value()) {
            if (_session->kvdbApi.hasEntry(_session->kvdbId, path)) {
                _session->kvdbApi.deleteEntry(_session->kvdbId, path);
            }
            _session->storeApi.deleteFile(*remoteFileId);
            LockSession::destroyLock(_session->kvdbApi, _session->kvdbId, path);
            std::lock_guard<std::mutex> lock(_fileIdCacheMutex);
            _fileIdCache.erase(path);
        }
        std::lock_guard<std::mutex> lock(_memoryFileMutex);
        _memoryFiles.erase(path);
        return;
    }
    LOG_TRACE("PrivmxFS::deleteFile - ", path, " | kvdbId: ",_session->kvdbId)
    privmx::endpoint::kvdb::KvdbEntry kvdbEntry = _session->kvdbApi.getEntry(_session->kvdbId, path);
    std::string fileId = "";
    if(kvdbEntry.statusCode == 0) {
        fileId = kvdbEntry.data.stdString();
    }
    _session->kvdbApi.deleteEntry(_session->kvdbId, path);
    _session->storeApi.deleteFile(fileId);
    LockSession::destroyLock(_session->kvdbApi, _session->kvdbId, path);
    {
        std::lock_guard<std::mutex> lock(_bufferedFileMutex);
        _bufferedFiles.erase(path);
    }
    std::lock_guard<std::mutex> lock(_fileIdCacheMutex);
    _fileIdCache.erase(path);
}
PrivmxFS::PrivmxFS(
    const std::shared_ptr<PrivmxSession>& session
) : _session(session) {}

bool PrivmxFS::isJournalPath(const std::string& path) const {
    return path.size() >= 8 && path.compare(path.size() - 8, 8, "-journal") == 0;
}

std::string PrivmxFS::getCachedFileId(const std::string& name) {
    {
        std::lock_guard<std::mutex> lock(_fileIdCacheMutex);
        auto it = _fileIdCache.find(name);
        if (it != _fileIdCache.end()) {
            return it->second;
        }
    }

    std::string fileId = getFileId(name);

    std::lock_guard<std::mutex> lock(_fileIdCacheMutex);
    _fileIdCache[name] = fileId;
    return fileId;
}

std::string PrivmxFS::getFileId(const std::string& name) {
    LOG_TRACE("PrivmxFS::getFileId - ", name, " | kvdbId: ",_session->kvdbId)
    try {
        privmx::endpoint::kvdb::KvdbEntry kvdbEntry = _session->kvdbApi.getEntry(_session->kvdbId, name);
        if(kvdbEntry.statusCode != 0) {
           throw MalformedInternalFileIdException();
        }
        std::string fileId = kvdbEntry.data.stdString();
        return fileId;
    } catch (const privmx::endpoint::server::KvdbEntryDoesNotExistException& e) {
        LOG_DEBUG("PrivmxFS::getFileId file not found, creating new file - ", name)
        int64_t fh = _session->storeApi.createFile(_session->storeId, META, META, 0, true);
        std::string fileId = _session->storeApi.closeFile(fh);
        _session->kvdbApi.setEntry(_session->kvdbId, name, META, META, privmx::endpoint::core::Buffer::from(fileId));
        return fileId;
    }
}

std::shared_ptr<PrivmxFile> PrivmxExtFS::openFile(const std::string& path) {
    auto parsed = parsePath(path);
    auto fs = getPrivmxFS(parsed);
    return fs->openFile(parsed.path);
}

bool PrivmxExtFS::access(const std::string& path) {
    auto parsed = parsePath(path);
    auto fs = getPrivmxFS(parsed);
    return fs->access(parsed.path);
}

void PrivmxExtFS::deleteFile(const std::string& path) {
    auto parsed = parsePath(path);
    auto fs = getPrivmxFS(parsed);
    return fs->deleteFile(parsed.path);
}

std::string PrivmxExtFS::fullPathname(const std::string& uri) {
    auto path = extractPath(uri);
    return sanitizeFilepath(path);
}

PrivmxExtFS::ParsedPath PrivmxExtFS::parsePath(const std::string& path2) {
    Poco::Path path;
    path.parse(path2);
    if (path[0] == "pmx") {
        ParsedPath parsed = ParsedPath {
            .sessionId = path[1],
            .path=std::string()
        };
        path.popFrontDirectory();
        path.popFrontDirectory();
        parsed.path = path.toString();
        return parsed;
    }
    throw 0;
}

std::shared_ptr<PrivmxFS> PrivmxExtFS::getPrivmxFS(const ParsedPath& parsed) {
    return PrivmxFS::create(SessionManager::get()->getSession(parsed.sessionId));
}

std::string PrivmxExtFS::extractPath(const std::string& uri) {
    std::string path2 = uri;
    if (path2.substr(0, 5) == "file:") {
        path2 = path2.substr(5);
    }
    return path2.substr(0, path2.find('?'));
}

std::string PrivmxExtFS::sanitizeFilepath(const std::string& filepath) {
    std::string result = filepath;
    for (char& c : result) {
        if (!(std::isalnum(c) || c == '/' || c == '_' || c == ':' || c == '-')) {
            c = '_';
        }
    }
    return result;
}
