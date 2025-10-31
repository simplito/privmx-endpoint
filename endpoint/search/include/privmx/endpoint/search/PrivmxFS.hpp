/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/
#ifndef _PRIVMXLIB_ENDPOINT_SEARCH_PRIVMXFS_HPP_
#define _PRIVMXLIB_ENDPOINT_SEARCH_PRIVMXFS_HPP_

#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "privmx/endpoint/core/Connection.hpp"
#include "privmx/endpoint/store/StoreApi.hpp"
#include "privmx/endpoint/kvdb/KvdbApi.hpp"
#include "privmx/endpoint/core/Types.hpp"
#include "privmx/endpoint/search/Types.hpp"

#include <sqlite3.h>

#include <exception>
#include <stdexcept>
#include <iostream>


#include <Poco/Path.h>
#include "privmx/utils/Utils.hpp"

namespace privmx {
namespace endpoint {
namespace search {

static const std::string STORE_ID;
static const privmx::endpoint::core::Buffer META = privmx::endpoint::core::Buffer::from("META");

template<typename T1> void l(const T1& t1) { std::cerr << t1 << std::endl; }
template<typename T1, typename T2> void l(const T1& t1, const T2& t2) { std::cerr << t1 << " " << t2 << std::endl; }
template<typename T1, typename T2, typename T3> void l(const T1& t1, const T2& t2, const T3& t3) { std::cerr << t1 << " " << t2 << " " << t3 << std::endl; }
template<typename T1, typename T2, typename T3, typename T4> void l(const T1& t1, const T2& t2, const T3& t3, const T4& t4) { std::cerr << t1 << " " << t2 << " " << t3 << " " << t4 << std::endl; }


struct PrivmxSession
{
    std::string id;
    privmx::endpoint::core::Connection connection;
    privmx::endpoint::store::StoreApi storeApi;
    privmx::endpoint::kvdb::KvdbApi kvdbApi;
};

class SessionManager
{
public:
    static std::shared_ptr<SessionManager> get() {
        if (!_singleton) {
            _singleton = std::make_shared<SessionManager>();
        }
        return _singleton;
    }
    std::shared_ptr<PrivmxSession> addSession(const privmx::endpoint::core::Connection& connection, const privmx::endpoint::store::StoreApi& storeApi, const privmx::endpoint::kvdb::KvdbApi& kvdbApi) {
        std::shared_ptr<PrivmxSession> session = std::make_shared<PrivmxSession>(PrivmxSession {
            .id = generateId(),
            .connection = connection,
            .storeApi = storeApi,
            .kvdbApi = kvdbApi
        });
        _sessions[session->id] = session;
        return session;
    }
    std::shared_ptr<PrivmxSession> createSession(const std::string& userPrivKey, const std::string& solutionId, const std::string& bridgeUrl) {
        privmx::endpoint::core::Connection connection = privmx::endpoint::core::Connection::connect(userPrivKey, solutionId, bridgeUrl);
        return addSession(connection, privmx::endpoint::store::StoreApi::create(connection), privmx::endpoint::kvdb::KvdbApi::create(connection));
    }
    std::shared_ptr<PrivmxSession> getSession(const std::string& id) {
        return _sessions[id];
    }

private:
    std::string generateId() {
        return std::to_string(_lastId++);
    }

    static std::shared_ptr<SessionManager> _singleton;
    int _lastId = 1;
    std::unordered_map<std::string, std::shared_ptr<PrivmxSession>> _sessions;
};


class Writer
{
public:
    std::tuple<int64_t, std::string> write(int64_t offset, const std::string& data) {
        if (_offset == -1) {
            _offset = offset;
        }
        if (_offset + size() != offset) {
            auto result = _buf.str();
            auto resultOffset = _offset;
            _buf.str(data);
            _offset = offset;
            std::cerr << "CHANGE OFFSET " << resultOffset << " " << _offset << std::endl;
            return {resultOffset, result};
        }
        _buf.write(data.data(), data.size());
        return {-1, {}};
    }
    int64_t size() {
        return _buf.str().length();
    }

    std::stringstream _buf;
    int64_t _offset = -1;
};

class PrivmxFile
{
public:
    std::shared_ptr<PrivmxSession> session;
    std::string fileId = "";
    int64_t fh = -1;
    Writer writer;

    PrivmxFile(std::shared_ptr<PrivmxSession> session, const std::string& fileId) : session(session), fileId(fileId) {}

    // void open(const std::string& name) {
    //     connect();
    //     getFileId(name);
    //     openFile();
    //     l("Name:", name, fh);
    // }

    void open() {
        fh = session->storeApi.openFile(fileId);
    }

    void close() {
        if (fh != -1) {
            session->storeApi.closeFile(fh);
            fh = -1;
        }
    }

    privmx::endpoint::core::Buffer read(int64_t size, int64_t offset) {
        l("Read:", size, offset, fh);
        // session->storeApi.syncFile(fh);
        sync();
        session->storeApi.seekInFile(fh, offset);
        auto res = session->storeApi.readFromFile(fh, size);
        l("Read len:", res.size());
        return res;
    }

    void write(const privmx::endpoint::core::Buffer& data, int64_t offset) {
        l("Write:", data.size(), offset, fh);
        if (offset < 4096) l("\t\tWRITE HEADER");
        // sync?
        // session->storeApi.syncFile(fh);
        int64_t of;
        std::string res;
        tie(of, res) = writer.write(offset, data.stdString());
        if (of != -1) {
            l("Real write", of, of + res.size(), res.size());
            int64_t size = getFileSize();
            l("of size", of, size);
            if (of > size) {
                session->storeApi.seekInFile(fh, size);
                session->storeApi.writeToFile(fh, privmx::endpoint::core::Buffer::from(std::string(of-size, '\0')));
                int64_t size = getFileSize();
                l("\tof size", of, size);
            }
            session->storeApi.seekInFile(fh, of);
            session->storeApi.writeToFile(fh, privmx::endpoint::core::Buffer::from(res));
        }
        // session->storeApi.seekInFile(fh, offset);
        // session->storeApi.writeToFile(fh, data);
    }

    void truncate(int64_t size) {
        l("Truncate", size, fh);
        session->storeApi.seekInFile(fh, size);
        session->storeApi.writeToFile(fh, privmx::endpoint::core::Buffer::from("", 0), true);
    }

    void sync() {
        l("sync", fh);
        int64_t of;
        std::string res;
        tie(of, res) = writer.write(-1, "");
        if (of != -1) {
            l("Real write", of, of + res.size(), res.size());
            int64_t size = getFileSize();
            l("of size", of, size);
            if (of > size) {
                session->storeApi.seekInFile(fh, size);
                session->storeApi.writeToFile(fh, privmx::endpoint::core::Buffer::from(std::string(of-size, '\0')));
                int64_t size = getFileSize();
                l("\tof size", of, size);
            }
            session->storeApi.seekInFile(fh, of);
            session->storeApi.writeToFile(fh, privmx::endpoint::core::Buffer::from(res));
        }
    }

    int64_t getFileSize() {
        auto size = session->storeApi.getFile(fileId).size;
        l("FileSize", size, fh);
        return size; // TODO: getFileSize(fd);
    }

private:
    // void connect() {
    //     if (connected) return;
    //     connection = privmx::endpoint::core::Connection::connect(USER_PRIV_KEY, SOLUTION_ID, BRIDGE_URL);
    //     storeApi = privmx::endpoint::store::StoreApi::create(connection);
    //     kvdbApi = privmx::endpoint::kvdb::KvdbApi::create(connection);
    //     connected = true;
    //     auto list = kvdbApi.listEntriesKeys(KVDB_ID, PAGING_QUERY);
    //     for (auto item : list.readItems) {
    //         l("File:",item);
    //     }
    // }

    // std::string getFileId(const std::string& name) {
    //     // l("File name:", name);
    //     if (kvdbApi.hasEntry(KVDB_ID, name)) {
    //         fileId = kvdbApi.getEntry(KVDB_ID, name).data.stdString();
    //         return fileId;
    //     } else {
    //         int64_t fh = storeApi.createFile(STORE_ID, META, META, 0, true);
    //         fileId = storeApi.closeFile(fh);
    //         kvdbApi.setEntry(KVDB_ID, name, META, META, privmx::endpoint::core::Buffer::from(fileId));
    //         return fileId;
    //     }
    // }
};

class PrivmxFS
{
public:
    static std::shared_ptr<PrivmxFS> create(
        std::shared_ptr<PrivmxSession> session,
        const std::string& kvdbId
) {
        std::shared_ptr<PrivmxFS> res = std::make_shared<PrivmxFS>(session, kvdbId);
        return res;
    }

    std::shared_ptr<PrivmxFile> openFile(const std::string& path) {
        std::string fileId = getFileId(path);
        std::shared_ptr<PrivmxFile> result = std::make_shared<PrivmxFile>(_session, fileId);
        result->open();
        return result;
    }

    bool access(const std::string& path) {
        return _session->kvdbApi.hasEntry(_kvdbId, path);
    }

    void deleteFile(const std::string& path) {
        std::string fileId = _session->kvdbApi.getEntry(_kvdbId, path).data.stdString();
        _session->kvdbApi.deleteEntry(_kvdbId, path);
        _session->storeApi.deleteFile(fileId);
    }
    PrivmxFS(
        const std::shared_ptr<PrivmxSession>& session,
        const std::string& kvdbId
    ) : _session(session), _kvdbId(kvdbId) {}

private:

    std::string getFileId(const std::string& name) {
        // l("File name:", name);
        if (_session->kvdbApi.hasEntry(_kvdbId, name)) {
            std::string fileId = _session->kvdbApi.getEntry(_kvdbId, name).data.stdString();
            return fileId;
        } else {
            int64_t fh = _session->storeApi.createFile(STORE_ID, META, META, 0, true);
            std::string fileId = _session->storeApi.closeFile(fh);
            std::cerr << _kvdbId << std::endl;
            _session->kvdbApi.setEntry(_kvdbId, name, META, META, privmx::endpoint::core::Buffer::from(fileId));
            return fileId;
        }
    }


    std::shared_ptr<PrivmxSession> _session;
    std::string _kvdbId;
};

class PrivmxExtFS
{
public:

    std::shared_ptr<PrivmxFile> openFile(const std::string& path) {
        init();
        auto parsed = parsePath(path);
        auto fs = getPrivmxFS(parsed);
        return fs->openFile(parsed.path);
    }

    bool access(const std::string& path) {
        init();
        auto parsed = parsePath(path);
        auto fs = getPrivmxFS(parsed);
        return fs->access(parsed.path);
    }

    void deleteFile(const std::string& path) {
        l("deleteFile", path);
        init();
        auto parsed = parsePath(path);
        auto fs = getPrivmxFS(parsed);
        return fs->deleteFile(parsed.path);
    }

    std::string fullPathname(const std::string& path) {
        if (path.size() > 0 && path[0] != '/') return std::string();
        return path;
    }

    void init() {}

    // void init() {
    //     if (!connected) {
    //         std::shared_ptr<PrivmxSession> session = SessionManager::get()->createSession(USER_PRIV_KEY, SOLUTION_ID, BRIDGE_URL);
    //         std::cerr << "Created session: " << session->id << std::endl;
    //         connected = true;
    //     }
    // }


private:
    struct ParsedPath
    {
        std::string sessionId;
        std::string module;
        std::string moduleId;
        std::string path;
        std::string directory;
        std::string filename;
    };

    ParsedPath parsePath(const std::string& path2) { // "/pmx/1/kvdb/68dcf2bbed17034f64e18883/demo.db"
        Poco::Path path;
        path.parse(path2);
        std::cerr << path.toString() << std::endl;
        if (path[0] == "pmx") {
            ParsedPath parsed = ParsedPath {
                .sessionId = path[1],
                .module = path[2],
                .moduleId = path[3]
            };
            path.popFrontDirectory();
            path.popFrontDirectory();
            path.popFrontDirectory();
            path.popFrontDirectory();
            parsed.path = path.toString();
            parsed.filename = path.getFileName();
            std::cerr << parsed.moduleId << std::endl;
            return parsed;
        }
        throw 0;
    }

    std::shared_ptr<PrivmxFS> getPrivmxFS(const ParsedPath& parsed) {
        return PrivmxFS::create(SessionManager::get()->getSession(parsed.sessionId), parsed.moduleId);
    }
};


}  // namespace search
}  // namespace endpoint
}  // namespace privmx

#endif  // _PRIVMXLIB_ENDPOINT_SEARCH_PRIVMXFS_HPP_
