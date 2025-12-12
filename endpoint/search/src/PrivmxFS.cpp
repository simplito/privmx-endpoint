#include "privmx/endpoint/search/PrivmxFS.hpp"
#include "privmx/endpoint/search/DynamicTypes.hpp"

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
        : session(session), fileId(fileId), path(path), lockSession(session->kvdbApi, session->kvdbId, path) {}

void PrivmxFile::open() {
    fh = session->storeApi.openFile(fileId);
}

void PrivmxFile::close() {
    if (fh != -1) {
        session->storeApi.closeFile(fh);
        fh = -1;
    }
}

privmx::endpoint::core::Buffer PrivmxFile::read(int64_t size, int64_t offset) {
    sync();
    session->storeApi.seekInFile(fh, offset);
    auto res = session->storeApi.readFromFile(fh, size);
    return res;
}

void PrivmxFile::write(const privmx::endpoint::core::Buffer& data, int64_t offset) {
    int64_t of;
    std::string res;
    tie(of, res) = writer.write(offset, data.stdString());
    if (of != -1) {
        session->storeApi.seekInFile(fh, of);
        session->storeApi.writeToFile(fh, privmx::endpoint::core::Buffer::from(res));
    }
}

void PrivmxFile::truncate(int64_t size) {
    session->storeApi.seekInFile(fh, size);
    session->storeApi.writeToFile(fh, privmx::endpoint::core::Buffer::from("", 0), true);
}

void PrivmxFile::sync() {
    int64_t of;
    std::string res;
    tie(of, res) = writer.write(-1, "");
    if (of != -1) {
        session->storeApi.seekInFile(fh, of);
        session->storeApi.writeToFile(fh, privmx::endpoint::core::Buffer::from(res));
    }
}

int64_t PrivmxFile::getFileSize() {
    return session->storeApi.getFile(fileId).size;
}

bool PrivmxFile::lock(LockLevel level) {
    bool val = lockSession.lock(level);
    if (val) {
        session->storeApi.syncFile(fh);
    }
    return val;
}

bool PrivmxFile::unlock(LockLevel level) {
    return lockSession.unlock(level);
}

bool PrivmxFile::checkReservedLock() {
    return lockSession.checkReservedLock();
}

std::shared_ptr<PrivmxFS> PrivmxFS::create(
    std::shared_ptr<PrivmxSession> session
) {
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
    return _session->kvdbApi.hasEntry(_session->kvdbId, path);
}

void PrivmxFS::deleteFile(const std::string& path) {
    std::string fileId = _session->kvdbApi.getEntry(_session->kvdbId, path).data.stdString();
    _session->kvdbApi.deleteEntry(_session->kvdbId, path);
    _session->storeApi.deleteFile(fileId);
}
PrivmxFS::PrivmxFS(
    const std::shared_ptr<PrivmxSession>& session
) : _session(session) {}

std::string PrivmxFS::getFileId(const std::string& name) {
    if (_session->kvdbApi.hasEntry(_session->kvdbId, name)) {
        std::string fileId = _session->kvdbApi.getEntry(_session->kvdbId, name).data.stdString();
        return fileId;
    } else {
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
            .sessionId = path[1]
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
