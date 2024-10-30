#include "privmx/endpoint/inbox/InboxHandleManager.hpp"
#include "privmx/endpoint/inbox/InboxException.hpp"
#include <privmx/endpoint/core/CoreException.hpp>

using namespace privmx::endpoint;
using namespace privmx::endpoint::inbox;

InboxHandleManager::InboxHandleManager(std::shared_ptr<core::HandleManager> handleManager) :
   _handleManager(handleManager), _fileHandleManager(store::FileHandleManager(handleManager, "Inbox")) {}

std::tuple<int64_t, std::shared_ptr<InboxHandle>> InboxHandleManager::createInboxHandle() {
    std::shared_ptr<InboxHandle> result(new InboxHandle());
    int64_t id = _handleManager->createHandle("Inbox:FilesWrite");
    _map.set(id, result);
    return std::make_tuple(id, result);
}

std::shared_ptr<InboxHandle> InboxHandleManager::getInboxHandle(const int64_t& id) {
    auto inboxHandle = _map.get(id);
    if(!inboxHandle.has_value()) {
        throw UnknownInboxHandleException();
    }
    return inboxHandle.value();
}

bool InboxHandleManager::hasInboxHandle(const int64_t& id) {
    return _map.get(id).has_value();
}

CommitSendInfo InboxHandleManager::commitInboxHandle(const int64_t& id) {
    auto inboxHandle = _map.get(id);
    if(!inboxHandle.has_value()) throw UnknownInboxHandleException();
    CommitSendInfo result; 
    if(!inboxHandle.value()->inboxFileHandles.empty()) {
        for(auto file_handle : inboxHandle.value()->inboxFileHandles) {
            std::shared_ptr<store::FileWriteHandle> handle = _fileHandleManager.getFileWriteHandle(file_handle);
            if(!handle->isReadyToFinalize()) {
                throw core::DataDifferentThanDeclaredException();
            }
        }

        for(auto file_handle : inboxHandle.value()->inboxFileHandles) {
            CommitFileInfo file_info;
            std::shared_ptr<store::FileWriteHandle> handle = _fileHandleManager.getFileWriteHandle(file_handle);
            file_info.fileSendResult = handle->finalize();
            file_info.fileSize = handle->getEncryptedFileSize();
            file_info.size = handle->getSize();
            file_info.publicMeta = handle->getPublicMeta();
            file_info.privateMeta = handle->getPrivateMeta();
            result.filesInfo.push_back(file_info);
        }
    }
    _map.erase(id);
    return result;
}

std::tuple<int64_t, std::shared_ptr<store::FileWriteHandle>> InboxHandleManager::createFileWriteHandle(
        const std::string& storeId,
        const std::string& fileId,
        uint64_t size,
        const core::Buffer& publicMeta,
        const core::Buffer& privateMeta,
        uint64_t chunkSize,
        uint64_t serverRequestChunkSize,
        std::shared_ptr<store::RequestApi> requestApi
) {
    return _fileHandleManager.createFileWriteHandle(storeId, fileId, size, publicMeta, privateMeta, chunkSize, serverRequestChunkSize, requestApi);
}
std::shared_ptr<store::FileWriteHandle> InboxHandleManager::getFileWriteHandle(int64_t fileHandleId) {
    return _fileHandleManager.getFileWriteHandle(fileHandleId);
}
std::tuple<int64_t, std::shared_ptr<store::FileReadHandle>> InboxHandleManager::createFileReadHandle(
        const std::string& fileId,
        uint64_t fileSize,
        uint64_t serverFileSize,
        size_t chunkSize,
        size_t serverChunkSize,
        int64_t fileVersion,
        const std::string& fileKey,
        const std::string& fileHmac,
        std::shared_ptr<store::ServerApi> server
) {
    return _fileHandleManager.createFileReadHandle(fileId, fileSize, serverFileSize, chunkSize, serverChunkSize, fileVersion, fileKey, fileHmac, server);
}
std::shared_ptr<store::FileReadHandle> InboxHandleManager::getFileReadHandle(int64_t fileHandleId) {
    return _fileHandleManager.getFileReadHandle(fileHandleId);
}
void InboxHandleManager::removeFileReadHandle(int64_t fileHandleId) {
    _fileHandleManager.getFileReadHandle(fileHandleId); //only read
    return _fileHandleManager.removeHandle(fileHandleId);
}