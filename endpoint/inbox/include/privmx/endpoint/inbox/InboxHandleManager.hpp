/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_ENDPOINT_INBOX_INBOX_HANDLE_MANAGER_HPP_
#define _PRIVMXLIB_ENDPOINT_INBOX_INBOX_HANDLE_MANAGER_HPP_

#include <string>
#include <vector>

#include <privmx/utils/ThreadSaveMap.hpp>
#include <privmx/endpoint/core/HandleManager.hpp>
#include <privmx/endpoint/store/ChunkStreamer.hpp>
#include <privmx/endpoint/store/FileHandle.hpp>
#include "privmx/endpoint/inbox/InboxApi.hpp"


namespace privmx {
namespace endpoint {
namespace inbox {

struct CommitFileInfo {
    store::FileSizeResult fileSize;
    store::ChunksSentInfo fileSendResult;
    int64_t size;
    core::Buffer publicMeta;
    core::Buffer privateMeta;
};

struct CommitSendInfo {
    std::vector<CommitFileInfo> filesInfo;
};

struct InboxHandle {
    const int64_t id;
    std::string inboxId;
    std::string data;
    std::vector<std::shared_ptr<store::FileWriteHandle>> inboxFileHandles;
    std::optional<std::string> userPrivKey;
};


class InboxHandleManager
{
public:
    InboxHandleManager(std::shared_ptr<core::HandleManager> handleManager);
    std::shared_ptr<InboxHandle> createInboxHandle(
        const std::string& inboxId,
        const std::string& data,
        const std::vector<int64_t>& inboxFileHandles,
        std::optional<std::string> userPrivKey
    );
    std::shared_ptr<InboxHandle> getInboxHandle(const int64_t& id);
    bool hasInboxHandle(const int64_t& id);
    CommitSendInfo commitInboxHandle(const int64_t& id);
    void abortInboxHandle(const int64_t& id);

    std::shared_ptr<store::FileWriteHandle> createFileWriteHandle(
        const std::string& storeId,
        const std::string& fileId,
        uint64_t size,
        const core::Buffer& publicMeta,
        const core::Buffer& privateMeta,
        uint64_t chunkSize,
        uint64_t serverRequestChunkSize,
        std::shared_ptr<store::RequestApi> requestApi
    );
    std::shared_ptr<store::FileWriteHandle> getFileWriteHandle(int64_t fileHandleId);
    std::shared_ptr<store::FileReadHandle> createFileReadHandle(
        const std::string& fileId,
        uint64_t fileSize,
        uint64_t serverFileSize,
        size_t chunkSize,
        size_t serverChunkSize,
        int64_t fileVersion,
        const std::string& fileKey,
        const std::string& fileHmac,
        std::shared_ptr<store::ServerApi> server
    );
    std::shared_ptr<store::FileReadHandle> getFileReadHandle(int64_t fileHandleId);
    void removeFileHandle(int64_t fileHandleId);
private:
    std::shared_ptr<core::HandleManager> _handleManager;
    store::FileHandleManager _fileHandleManager;
    utils::ThreadSaveMap<int64_t, std::shared_ptr<InboxHandle>> _map;
    std::vector<int64_t> _fileHandlesUsedByInboxHandles;
};

} // inbox
} // endpoint
} // privmx

#endif // _PRIVMXLIB_ENDPOINT_INBOX_INBOX_HANDLE_MANAGER_HPP_
