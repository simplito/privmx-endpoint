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
#include <cstdint>
#include <map>
#include <mutex>
#include <optional>
#include <string>
#include <unordered_map>
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
#include <fstream>


#include <Poco/Path.h>
#include "privmx/utils/Utils.hpp"

#include "privmx/endpoint/search/SearchTypes.hpp"
#include "privmx/endpoint/search/LockSession.hpp"

namespace privmx {
namespace endpoint {
namespace search {

class SessionManager
{
public:
    static std::shared_ptr<SessionManager> get();
    std::shared_ptr<PrivmxSession> addSession(
        const privmx::endpoint::core::Connection& connection,
        const privmx::endpoint::store::StoreApi& storeApi,
        const privmx::endpoint::kvdb::KvdbApi& kvdbApi,
        const std::string& kvdbId,
        const std::string& storeId
    );
    std::shared_ptr<PrivmxSession> getSession(const std::string& id);
    void removeSession(const std::string& id);

private:
    std::string generateId();

    static std::shared_ptr<SessionManager> _singleton;
    int _lastId = 1;
    std::unordered_map<std::string, std::shared_ptr<PrivmxSession>> _sessions;
};

class Writer
{
public:
    Writer();
    std::tuple<int64_t, std::string> write(int64_t offset, const std::string& data);
    int64_t size();

    std::stringstream _buf;
    int64_t _offset = -1;
};

class PrivmxFile
{
public:
    PrivmxFile(std::shared_ptr<PrivmxSession> session, const std::string& fileId, const std::string& path);
    struct MemoryFileState
    {
        std::mutex mutex;
        std::string data;
        LockLevel lockLevel = LockLevel::NONE;
        bool reservedLock = false;
        bool remoteBacked = false;
        std::string remoteFileId;
        int64_t remoteFh = -1;
        std::uint64_t openHandleCount = 0;
    };
    struct BufferedFileState
    {
        std::mutex mutex;
        std::map<int64_t, std::string> dirtyRanges;
        std::optional<int64_t> logicalSize;
        std::optional<int64_t> remoteSize;
    };

    PrivmxFile(
        std::shared_ptr<PrivmxSession> session,
        const std::string& fileId,
        const std::string& path,
        bool memoryOnly,
        std::shared_ptr<MemoryFileState> memoryFileState,
        std::shared_ptr<BufferedFileState> bufferedFileState
    );
    void open();
    void close();
    privmx::endpoint::core::Buffer read(int64_t size, int64_t offset);
    void write(const privmx::endpoint::core::Buffer& data, int64_t offset);
    void truncate(int64_t size);
    void sync();
    int64_t getFileSize();
    bool lock(LockLevel level);
    bool unlock(LockLevel level);
    bool checkReservedLock();

    std::shared_ptr<PrivmxSession> session;
    std::string fileId = "";
    std::string path;
    int64_t fh = -1;
    Writer writer;
    LockSession lockSession;
    bool memoryOnly = false;
    std::shared_ptr<MemoryFileState> memoryFileState;
    std::shared_ptr<BufferedFileState> bufferedFileState;
};

class PrivmxFS
{
public:
    static std::shared_ptr<PrivmxFS> create(std::shared_ptr<PrivmxSession> session);
    static void releaseSession(const std::string& fullPath);
    static void beginDbOperation(const std::string& fullPath);
    static void endDbOperation(const std::string& fullPath);
    PrivmxFS(const std::shared_ptr<PrivmxSession>& session);
    std::shared_ptr<PrivmxFile> openFile(const std::string& path);
    bool access(const std::string& path);
    void deleteFile(const std::string& path);
    void materializeJournalForDb(const std::string& dbPath);

private:
    bool isJournalPath(const std::string& path) const;
    std::string getCachedFileId(const std::string& name);
    std::string getFileId(const std::string& name);
    std::optional<std::string> tryGetExistingFileId(const std::string& name);
    std::shared_ptr<PrivmxFile::MemoryFileState> getOrCreateMemoryFileState(const std::string& path);
    void ensureJournalLoadedFromRemote(
        const std::string& path,
        const std::shared_ptr<PrivmxFile::MemoryFileState>& memoryFileState
    );

    std::shared_ptr<PrivmxSession> _session;
    mutable std::mutex _fileIdCacheMutex;
    std::unordered_map<std::string, std::string> _fileIdCache;
    mutable std::mutex _memoryFileMutex;
    std::unordered_map<std::string, std::shared_ptr<PrivmxFile::MemoryFileState>> _memoryFiles;
    mutable std::mutex _bufferedFileMutex;
    std::unordered_map<std::string, std::shared_ptr<PrivmxFile::BufferedFileState>> _bufferedFiles;
};

class PrivmxExtFS
{
public:
    std::shared_ptr<PrivmxFile> openFile(const std::string& path);
    bool access(const std::string& path);
    void deleteFile(const std::string& path);
    std::string fullPathname(const std::string& uri);

private:
    struct ParsedPath
    {
        std::string sessionId;
        std::string path;
    };

    ParsedPath parsePath(const std::string& path2);
    std::shared_ptr<PrivmxFS> getPrivmxFS(const ParsedPath& parsed);
    std::string extractPath(const std::string& uri);
    std::string sanitizeFilepath(const std::string& filepath);
};


}  // namespace search
}  // namespace endpoint
}  // namespace privmx

#endif  // _PRIVMXLIB_ENDPOINT_SEARCH_PRIVMXFS_HPP_
