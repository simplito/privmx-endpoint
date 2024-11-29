/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include "privmx/endpoint/inbox/InboxHandleManager.hpp"
#include "privmx/endpoint/inbox/InboxException.hpp"
#include "privmx/endpoint/inbox/Factory.hpp"
#include <privmx/endpoint/core/CoreException.hpp>

using namespace privmx::endpoint;
using namespace privmx::endpoint::inbox;

InboxHandleManager::InboxHandleManager(std::shared_ptr<core::HandleManager> handleManager) :
   _handleManager(handleManager), _fileHandleManager(store::FileHandleManager(handleManager, "Inbox")) {}

std::shared_ptr<InboxHandle> InboxHandleManager::createInboxHandle(
    const std::string& inboxId,
    const std::string& data,
    const std::vector<int64_t>& inboxFileHandles,
    std::optional<std::string> userPrivKey
) {
    std::vector<std::shared_ptr<store::FileWriteHandle>> fileHandles;
    for(auto inboxFileHandle: inboxFileHandles) {
        std::shared_ptr<store::FileWriteHandle> handle = _fileHandleManager.getFileWriteHandle(inboxFileHandle);
        fileHandles.push_back(handle);
        _fileHandlesUsedByInboxHandles.push_back(inboxFileHandle);
    }
    int64_t id = _handleManager->createHandle("Inbox:FilesWrite");
    std::shared_ptr<InboxHandle> result = std::make_shared<InboxHandle>(InboxHandle{
        .id=id, 
        .inboxId=inboxId, 
        .data=data, 
        .inboxFileHandles=fileHandles, 
        .userPrivKey=userPrivKey
    });
    _map.set(id, result);
    return result;
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
            if(!file_handle->isReadyToFinalize()) {
                throw core::DataDifferentThanDeclaredException();
            }
        }

        for(auto file_handle : inboxHandle.value()->inboxFileHandles) {
            CommitFileInfo file_info;
            file_info.fileSendResult = file_handle->finalize();
            file_info.fileSize = file_handle->getEncryptedFileSize();
            file_info.size = file_handle->getSize();
            file_info.publicMeta = file_handle->getPublicMeta();
            file_info.privateMeta = file_handle->getPrivateMeta();
            result.filesInfo.push_back(file_info);
        }
    }
    _map.erase(id);
    _handleManager->removeHandle(id);
    if(!inboxHandle.value()->inboxFileHandles.empty()) {
        for(auto file_handle : inboxHandle.value()->inboxFileHandles) {;
            removeFileHandle(file_handle->getId(), true);
        }
    }
    return result;
}

void InboxHandleManager::abortInboxHandle(const int64_t& id) {
    auto inboxHandle = _map.get(id);
    if(!inboxHandle.has_value()) throw UnknownInboxHandleException();
    _map.erase(id);
    _handleManager->removeHandle(id);
    if(!inboxHandle.value()->inboxFileHandles.empty()) {
        for(auto file_handle : inboxHandle.value()->inboxFileHandles) {;
           removeFileHandle(file_handle->getId(), true);
        }
    }
}

std::shared_ptr<store::FileWriteHandle> InboxHandleManager::createFileWriteHandle(
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

std::shared_ptr<store::FileReadHandle> InboxHandleManager::createFileReadHandle(
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
void InboxHandleManager::removeFileHandle(int64_t fileHandleId, bool force) {
    if(force) {
        _fileHandlesUsedByInboxHandles.erase(std::find(_fileHandlesUsedByInboxHandles.begin(),_fileHandlesUsedByInboxHandles.end(),fileHandleId));
    } else if ( std::find(_fileHandlesUsedByInboxHandles.begin(), _fileHandlesUsedByInboxHandles.end(), fileHandleId) != _fileHandlesUsedByInboxHandles.end() ) {
        throw HandleIsUsedInInboxHandleException();
    }
    return _fileHandleManager.removeHandle(fileHandleId);
}