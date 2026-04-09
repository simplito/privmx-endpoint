#include "privmx/endpoint/search/PrivmxFS.hpp"

#include <algorithm>
#include <chrono>
#include <cstring>
#include <iostream>
#include <mutex>
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

struct MethodDebugStat {
    std::uint64_t callCount = 0;
    long long totalDurationMs = 0;
};

std::mutex g_methodDebugStatsMutex;
std::unordered_map<std::string, MethodDebugStat> g_methodDebugStats;

void recordMethodDebugStat(const std::string& methodName, long long durationMs) {
    std::lock_guard<std::mutex> lock(g_methodDebugStatsMutex);
    auto& stat = g_methodDebugStats[methodName];
    ++stat.callCount;
    stat.totalDurationMs += durationMs;
}

template <typename Func>
decltype(auto) measureMethodCall(const std::string& methodName, Func&& func) {
    const auto start = std::chrono::steady_clock::now();
    try {
        if constexpr (std::is_void_v<std::invoke_result_t<Func>>) {
            std::forward<Func>(func)();
            const auto end = std::chrono::steady_clock::now();
            const auto durationMs = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
            recordMethodDebugStat(methodName, durationMs);
            return;
        } else {
            auto result = std::forward<Func>(func)();
            const auto end = std::chrono::steady_clock::now();
            const auto durationMs = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
            recordMethodDebugStat(methodName, durationMs);
            return result;
        }
    } catch (...) {
        const auto end = std::chrono::steady_clock::now();
        const auto durationMs = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
        recordMethodDebugStat(methodName, durationMs);
        throw;
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
        : PrivmxFile(session, fileId, path, false, nullptr) {}

PrivmxFile::PrivmxFile(
    std::shared_ptr<PrivmxSession> session,
    const std::string& fileId,
    const std::string& path,
    bool memoryOnly,
    std::shared_ptr<MemoryFileState> memoryFileState
) : session(session),
    fileId(fileId),
    path(path),
    lockSession(session->kvdbApi, session->kvdbId, path),
    memoryOnly(memoryOnly),
    memoryFileState(memoryFileState) {}

void PrivmxFile::open() {
    std::cout << "PrivmxFile::open" << std::endl;
    if (memoryOnly) {
        return;
    }
    LOG_TRACE("PrivmxFile::open - ", fileId)
    fh = session->storeApi.openFile(fileId);
}

void PrivmxFile::close() {
    std::cout << "PrivmxFile::close" << std::endl;
    return measureMethodCall("closeFile", [&]() {
        if (memoryOnly) {
            return;
        }
        if (fh != -1) {
            session->storeApi.closeFile(fh);
            fh = -1;
        }
    });
}

privmx::endpoint::core::Buffer PrivmxFile::read(int64_t size, int64_t offset) {
    std::cout << "PrivmxFile::read" << std::endl;
    return measureMethodCall("read", [&]() {
        if (memoryOnly) {
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
        sync();
        session->storeApi.seekInFile(fh, offset);
        auto res = session->storeApi.readFromFile(fh, size);
        return res;
    });
}

void PrivmxFile::write(const privmx::endpoint::core::Buffer& data, int64_t offset) {
    std::cout << "PrivmxFile::write" << std::endl;
    measureMethodCall("write", [&]() {
        if (memoryOnly) {
            if (offset < 0) {
                throw std::runtime_error("Invalid write offset");
            }
            const auto writeOffset = static_cast<std::size_t>(offset);
            if (memoryFileState->data.size() < writeOffset) {
                memoryFileState->data.resize(writeOffset, '\0');
            }
            const auto writeSize = data.size();
            if (memoryFileState->data.size() < writeOffset + writeSize) {
                memoryFileState->data.resize(writeOffset + writeSize, '\0');
            }
            std::memcpy(memoryFileState->data.data() + writeOffset, data.data(), writeSize);
            return;
        }
        int64_t of;
        std::string res;
        tie(of, res) = writer.write(offset, data.stdString());
        if (of != -1) {
            session->storeApi.seekInFile(fh, of);
            session->storeApi.writeToFile(fh, privmx::endpoint::core::Buffer::from(res));
        }
    });
}

void PrivmxFile::truncate(int64_t size) {
    std::cout << "PrivmxFile::truncate" << std::endl;
    measureMethodCall("truncate", [&]() {
        if (memoryOnly) {
            if (size < 0) {
                throw std::runtime_error("Invalid truncate size");
            }
            memoryFileState->data.resize(static_cast<std::size_t>(size), '\0');
            return;
        }
        session->storeApi.seekInFile(fh, size);
        session->storeApi.writeToFile(fh, privmx::endpoint::core::Buffer::from("", 0), true);
    });
}

void PrivmxFile::sync() {
    std::cout << "PrivmxFile::sync" << std::endl;
    measureMethodCall("sync", [&]() {
        if (memoryOnly) {
            return;
        }
        int64_t of;
        std::string res;
        tie(of, res) = writer.write(-1, "");
        if (of != -1) {
            session->storeApi.seekInFile(fh, of);
            session->storeApi.writeToFile(fh, privmx::endpoint::core::Buffer::from(res));
        }
    });
}

int64_t PrivmxFile::getFileSize() {
    std::cout << "PrivmxFile::getFileSize" << std::endl;
    return measureMethodCall("getFileSize", [&]() {
        if (memoryOnly) {
            return static_cast<int64_t>(memoryFileState->data.size());
        }
        auto fileInfo = session->storeApi.getFile(fileId);
        if(fileInfo.statusCode != 0) {
            throw MalformedInternalFileException(); 
        }
        return fileInfo.size;
    });
}

bool PrivmxFile::lock(LockLevel level) {
    std::cout << "PrivmxFile::lock" << std::endl;
    const std::string lockStatName = memoryOnly ? "lock_journal" : "lock_db";
    return measureMethodCall(lockStatName, [&]() {
        if (memoryOnly) {
            memoryFileState->lockLevel = level;
            memoryFileState->reservedLock = level >= LockLevel::RESERVED;
            return true;
        }
        bool val = lockSession.lock(level);
        if (val) {
            session->storeApi.syncFile(fh);
        }
        return val;
    });
}

bool PrivmxFile::unlock(LockLevel level) {
    std::cout << "PrivmxFile::unlock" << std::endl;
    return measureMethodCall("unlock", [&]() {
        if (memoryOnly) {
            memoryFileState->lockLevel = level;
            memoryFileState->reservedLock = level >= LockLevel::RESERVED;
            return true;
        }
        return lockSession.unlock(level);
    });
}

bool PrivmxFile::checkReservedLock() {
    std::cout << "PrivmxFile::checkReservedLock" << std::endl;
    if (memoryOnly) {
        return memoryFileState->reservedLock;
    }
    return lockSession.checkReservedLock();
}

std::shared_ptr<PrivmxFS> PrivmxFS::create(
    std::shared_ptr<PrivmxSession> session
) {
    std::cout << "PrivmxFS::create" << std::endl;
    std::shared_ptr<PrivmxFS> res = std::make_shared<PrivmxFS>(session);
    return res;
}

std::string PrivmxFS::getDebugStats() {
    std::cout << "PrivmxFS::getDebugStats" << std::endl;
    std::lock_guard<std::mutex> lock(g_methodDebugStatsMutex);
    std::ostringstream result;
    result << "PrivmxFS debug stats:";
    for (const auto& [methodName, stat] : g_methodDebugStats) {
        const double averageDurationMs = stat.callCount == 0 ? 0.0 : static_cast<double>(stat.totalDurationMs) / stat.callCount;
        result << "\n" << methodName
               << " calls=" << stat.callCount
               << " totalMs=" << stat.totalDurationMs
               << " avgMs=" << averageDurationMs;
    }
    return result.str();
}

std::shared_ptr<PrivmxFile> PrivmxFS::openFile(const std::string& path) {
    std::cout << "PrivmxFS::openFile" << std::endl;
    return measureMethodCall("openFile", [&]() {
        std::cout << "Opening file:" << path << std::endl;
        if (isJournalPath(path)) {
            std::lock_guard<std::mutex> lock(_memoryFileMutex);
            auto& memoryFileState = _memoryFiles[path];
            if (!memoryFileState) {
                memoryFileState = std::make_shared<PrivmxFile::MemoryFileState>();
            }
            std::shared_ptr<PrivmxFile> result = std::make_shared<PrivmxFile>(_session, "", path, true, memoryFileState);
            result->open();
            return result;
        }
        std::string fileId = getCachedFileId(path);
        std::shared_ptr<PrivmxFile> result = std::make_shared<PrivmxFile>(_session, fileId, path);
        result->open();
        return result;
    });
}

bool PrivmxFS::access(const std::string& path) {
    std::cout << "PrivmxFS::access" << std::endl;
    return measureMethodCall("access", [&]() {
        if (isJournalPath(path)) {
            std::lock_guard<std::mutex> lock(_memoryFileMutex);
            return _memoryFiles.find(path) != _memoryFiles.end();
        }
        LOG_TRACE("PrivmxFS::access - ", path, " | kvdbId: ",_session->kvdbId)
        return _session->kvdbApi.hasEntry(_session->kvdbId, path);
    });
}

void PrivmxFS::deleteFile(const std::string& path) {
    std::cout << "PrivmxFS::deleteFile: " << path << std::endl;
    if (isJournalPath(path)) {
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
    std::lock_guard<std::mutex> lock(_fileIdCacheMutex);
    _fileIdCache.erase(path);
}
PrivmxFS::PrivmxFS(
    const std::shared_ptr<PrivmxSession>& session
) : _session(session) {
    std::cout << "PrivmxFS::PrivmxFS" << std::endl;
}

bool PrivmxFS::isJournalPath(const std::string& path) const {
    return path.size() >= 8 && path.compare(path.size() - 8, 8, "-journal") == 0;
}

std::string PrivmxFS::getCachedFileId(const std::string& name) {
    std::cout << "PrivmxFS::getCachedFileId" << std::endl;
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
    std::cout << "PrivmxFS::getFileId" << std::endl;
    return measureMethodCall("getFileId", [&]() {
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
    });
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
