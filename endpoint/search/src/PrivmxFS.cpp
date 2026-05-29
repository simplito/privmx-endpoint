#include <string_view>
#include <Poco/UUIDGenerator.h>

#include "privmx/endpoint/search/PrivmxFS.hpp"
#include "privmx/endpoint/core/ConvertedExceptions.hpp"
#include "privmx/endpoint/core/ExceptionConverter.hpp"
#include "privmx/endpoint/search/DynamicTypes.hpp"
#include "privmx/endpoint/search/SearchException.hpp"
#include <privmx/utils/Logger.hpp>

static const privmx::endpoint::core::Buffer META = privmx::endpoint::core::Buffer::from("{}");

using namespace privmx::endpoint::search;

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
    const privmx::endpoint::lock::LockApi& lockApi,
    const std::string& kvdbId,
    const std::string& storeId
) {
    std::shared_ptr<PrivmxSession> session = std::make_shared<PrivmxSession>(PrivmxSession{
        .id = generateId(),
        .connection = connection,
        .storeApi = storeApi,
        .kvdbApi = kvdbApi,
        .lockApi = lockApi,
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

PrivmxFile::PrivmxFile(std::shared_ptr<PrivmxSession> session, const std::string& fileId, const std::string& path)
        : session(session), fileId(fileId), path(path),
          _uuid(Poco::UUIDGenerator::defaultGenerator().createRandom().toString()) {}

void PrivmxFile::open() {
    LOG_TRACE("PrivmxFile::open - ", fileId)
    fh = session->storeApi.openFile(fileId);
}

void PrivmxFile::close() {
    if (fh != -1) {
        session->storeApi.closeFile(fh);
        fh = -1;
    }
}

privmx::endpoint::core::Buffer PrivmxFile::read(int64_t size, int64_t offset) {
    session->storeApi.seekInFile(fh, offset);
    auto res = session->storeApi.readFromFile(fh, size);
    return res;
}

void PrivmxFile::write(const privmx::endpoint::core::Buffer& data, int64_t offset) {
    session->storeApi.seekInFile(fh, offset);
    session->storeApi.writeToFile(fh, data);
}

void PrivmxFile::truncate(int64_t size) {
    session->storeApi.seekInFile(fh, size);
    session->storeApi.writeToFile(fh, privmx::endpoint::core::Buffer::from("", 0), true);
}

void PrivmxFile::sync() {
    session->storeApi.flushFile(fh);
}

int64_t PrivmxFile::getFileSize() {
    return session->storeApi.getFileSize(fh);
}

bool PrivmxFile::lock(LockLevel level) {
    auto result = session->lockApi.lock(fileId, _uuid, static_cast<lock::LockLevel>(level));
    if (result.success) {
        session->storeApi.syncFile(fh);
    }
    return result.success;
}

bool PrivmxFile::unlock(LockLevel level) {
    auto result = session->lockApi.unlock(fileId, _uuid, static_cast<lock::LockLevel>(level));
    return result.success;
}

bool PrivmxFile::checkReservedLock() {
    return session->lockApi.checkReservedLock(fileId, _uuid);
}

std::shared_ptr<PrivmxFS> PrivmxFS::create(std::shared_ptr<PrivmxSession> session) {
    std::shared_ptr<PrivmxFS> res = std::make_shared<PrivmxFS>(session);
    return res;
}

std::shared_ptr<PrivmxFile> PrivmxFS::openFile(const std::string& path) {
    std::string fileId = getFileId(path);
    std::shared_ptr<PrivmxFile> result = std::make_shared<PrivmxFile>(_session, fileId, path);
    result->open();
    return result;
}

bool PrivmxFS::access(const std::string& path) {
    LOG_TRACE("PrivmxFS::access - ", path, " | kvdbId: ", _session->kvdbId)
    return _session->kvdbApi.findEntry(_session->kvdbId, path).has_value();
}

void PrivmxFS::deleteFile(const std::string& path) {
    LOG_TRACE("PrivmxFS::deleteFile - ", path, " | kvdbId: ", _session->kvdbId)
    privmx::endpoint::kvdb::KvdbEntry kvdbEntry = _session->kvdbApi.getEntry(_session->kvdbId, path);
    std::string fileId = "";
    if (kvdbEntry.statusCode == 0) {
        fileId = kvdbEntry.data.stdString();
    }
    _session->kvdbApi.deleteEntry(_session->kvdbId, path);
    _session->storeApi.deleteFile(fileId);
}
PrivmxFS::PrivmxFS(const std::shared_ptr<PrivmxSession>& session) : _session(session) {}

std::string PrivmxFS::getFileId(const std::string& name) {
    LOG_TRACE("PrivmxFS::getFileId - ", name, " | kvdbId: ", _session->kvdbId)
    auto entry = _session->kvdbApi.findEntry(_session->kvdbId, name);
    if (entry.has_value()) {
        if(entry->statusCode != 0) {
            throw MalformedInternalFileIdException();
        }
        return entry->data.stdString();
    }
    int64_t fh = _session->storeApi.createFile(_session->storeId, META, META, 0, true);
    std::string fileId = _session->storeApi.closeFile(fh);
    _session->kvdbApi.setEntry(_session->kvdbId, name, META, META, privmx::endpoint::core::Buffer::from(fileId));
    return fileId;
}

std::shared_ptr<PrivmxFile> PrivmxExtFS::openFile(const std::string& path) {
    auto parsed = parsePath(path);
    auto fs = getPrivmxFS(parsed);
    return fs->openFile(parsed.path);
}

bool PrivmxExtFS::access(const std::string& path) {
    if (_blockWalAccess) {
        std::string_view name(path);
        if (name.size() >= 4 && name.substr(name.size() - 4) == "-wal") {
            return false;
        }
    }
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
        std::string sessionId = path[1];
        path.popFrontDirectory();
        path.popFrontDirectory();
        return ParsedPath{.sessionId = sessionId, .path = path.toString()};
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
