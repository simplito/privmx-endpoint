/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_ENDPOINT_INBOX_INBOXAPIIMPL_HPP_
#define _PRIVMXLIB_ENDPOINT_INBOX_INBOXAPIIMPL_HPP_

#include <memory>
#include <optional>
#include <string>
#include <vector>

#include <privmx/utils/ThreadSaveMap.hpp>

#include <privmx/endpoint/core/Connection.hpp>
#include <privmx/endpoint/core/DataEncryptor.hpp>
#include <privmx/endpoint/core/KeyProvider.hpp>
#include <privmx/endpoint/core/EventMiddleware.hpp>
#include <privmx/endpoint/core/EventChannelManager.hpp>
#include <privmx/endpoint/core/Types.hpp>
#include <privmx/endpoint/thread/ServerTypes.hpp>
#include <privmx/endpoint/thread/ThreadApi.hpp>
#include <privmx/endpoint/store/StoreApi.hpp>
#include <privmx/endpoint/store/FileHandle.hpp>
#include <privmx/endpoint/store/DynamicTypes.hpp>
#include <privmx/endpoint/core/SubscriptionHelper.hpp>
#include <privmx/endpoint/store/FileMetaEncryptorV4.hpp>
#include "privmx/endpoint/inbox/InboxApi.hpp"
#include "privmx/endpoint/inbox/ServerTypes.hpp"
#include "privmx/endpoint/inbox/InboxEntriesDataEncryptorSerializer.hpp"
#include "privmx/endpoint/inbox/ServerApi.hpp"
#include "privmx/endpoint/inbox/InboxHandleManager.hpp"
#include "privmx/endpoint/inbox/MessageKeyIdFormatValidator.hpp"
#include "privmx/endpoint/inbox/FileKeyIdFormatValidator.hpp"
#include "privmx/endpoint/inbox/Events.hpp"
#include "privmx/endpoint/inbox/InboxDataProcessorV4.hpp"
#include "privmx/endpoint/inbox/Factory.hpp"
#include "privmx/endpoint/core/Factory.hpp"

namespace privmx {
namespace endpoint {
namespace inbox {

class InboxApiImpl
{
public:
    InboxApiImpl(
        const thread::ThreadApi& threadApi,
        const store::StoreApi& storeApi,
        const std::shared_ptr<core::KeyProvider>& keyProvider,
        const std::shared_ptr<inbox::ServerApi>& serverApi,
        const std::shared_ptr<store::RequestApi>& requestApi,
        const std::string& host,
        const privmx::crypto::PrivateKey& userPrivKey,
        const std::shared_ptr<core::EventMiddleware>& eventMiddleware,
        const std::shared_ptr<core::EventChannelManager>& eventChannelManager,
        const std::shared_ptr<core::HandleManager>& handleManager,
        size_t serverRequestChunkSize
    );

    ~InboxApiImpl();

    // inbox
    std::string createInbox(
        const std::string& contextId, const std::vector<core::UserWithPubKey>& users,
        const std::vector<core::UserWithPubKey>& managers, const core::Buffer& publicMeta, const core::Buffer& privateMeta,
        const std::optional<inbox::FilesConfig>& filesConfig,
        const std::optional<core::ContainerPolicyWithoutItem>& policies);

    void updateInbox(const std::string& inboxId, const std::vector<core::UserWithPubKey>& users,
                     const std::vector<core::UserWithPubKey>& managers,
                     const core::Buffer& publicMeta, const core::Buffer& privateMeta,
                     const std::optional<inbox::FilesConfig>& filesConfig, const int64_t version, const bool force,
                     const bool forceGenerateNewKey,
                     const std::optional<core::ContainerPolicyWithoutItem>& policies);

    inbox::Inbox getInbox(const std::string& inboxId);
    core::PagingList<inbox::Inbox> listInboxes(const std::string& contextId, const core::PagingQuery& query);
    inbox::InboxPublicView getInboxPublicView(const std::string& inboxId);
    void deleteInbox(const std::string& inboxId);
    
    int64_t/*inboxHandle*/ prepareEntry(
            const std::string& inboxId, 
            const core::Buffer& data,
            const std::vector<int64_t>& inboxFileHandles = std::vector<int64_t>(),
            const std::optional<std::string>& userPrivKey = std::nullopt
    );

    void sendEntry(const int64_t inboxHandle);
    inbox::InboxEntry readEntry(const std::string& inboxEntryId);
    core::PagingList<inbox::InboxEntry> listEntries(const std::string& inboxId, const core::PagingQuery& query);
    void deleteEntry(const std::string& inboxEntryId);
    int64_t/*inboxFileHandle*/ createFileHandle(const core::Buffer& publicMeta, const core::Buffer& privateMeta, const int64_t fileSize);
    void writeToFile(const int64_t inboxHandle, const int64_t inboxFileHandle, const core::Buffer& dataChunk);
    int64_t openFile(const std::string& fileId);
    core::Buffer readFromFile(const int64_t handle, const int64_t length);
    void seekInFile(const int64_t handle, const int64_t pos);
    std::string closeFile(const int64_t handle);

    void subscribeForInboxEvents();
    void unsubscribeFromInboxEvents();
    void subscribeForEntryEvents(const std::string& inboxId);
    void unsubscribeFromEntryEvents(const std::string& inboxId);

private:
    inbox::server::Inbox getInboxFromServerOrCache(const std::string& inboxId);
    inbox::FilesConfig getFilesConfigOptOrDefault(const std::optional<inbox::FilesConfig>& fileConfig);
    InboxDataResult decryptInbox(const inbox::server::Inbox& inboxRaw);
    InboxPublicViewAsResult getInboxPublicData(const std::string& inboxId);
    inbox::Inbox convertInbox(const inbox::server::Inbox& inboxRaw);
    inbox::server::InboxDataEntry getInboxDataEntry(const inbox::server::Inbox& inboxRaw);
    inbox::server::InboxMessageServer unpackInboxOrigMessage(const std::string& serialized);

    InboxEntryResult decryptInboxEntry(const inbox::server::Inbox& inbox, const thread::server::Message& message);
    inbox::InboxEntry convertInboxEntry(const privmx::endpoint::inbox::server::Inbox& inbox, const thread::server::Message& message);
    store::FileMetaToEncrypt prepareMeta(const inbox::CommitFileInfo& commitFileInfo);
    store::DecryptedFileMeta decryptInboxFileMetaV4(const store::server::File& file, const std::string& filesMetaKey);

    void processNotificationEvent(const std::string& type, const std::string& channel, const Poco::JSON::Object::Ptr& data);
    void processConnectedEvent();
    void processDisconnectedEvent();
    InboxDeletedEventData convertInboxDeletedEventData(const server::InboxDeletedEventData& data);

    store::File convertFileV4(const store::server::File& file, const store::DecryptedFileMeta& decryptedFileMeta);
    store::File tryDecryptAndConvertFileV4(const store::server::File& file, const std::string& filesMetaKey);
    store::File decryptAndConvertFileDataToFileInfo(const store::server::File& file, const std::string& filesMetaKey);
    int64_t createInboxFileHandleForRead(const store::server::File& file);

    std::string readInboxIdFromMessageKeyId(const std::string& keyId);
    std::string readMessageIdFromFileKeyId(const std::string& keyId);
    void deleteMessageAndFiles(const thread::server::Message& message);
    thread::server::Message getServerMessage(const std::string& messageId);
    InboxEntryResult getEmptyResultWithStatusCode(const int64_t statusCode);
    std::vector<std::string> getFilesIdsFromServerMessage(const privmx::endpoint::inbox::server::InboxMessageServer& serverMessage);

    template <typename T = std::string>
    static std::vector<T> listToVector(utils::List<T> list) {
        std::vector<T> ret {};
        for (auto x: list) {
            ret.push_back(x);
        }
        return ret;
    }
    static const Poco::Int64 _CHUNK_SIZE;

    endpoint::thread::ThreadApi _threadApi;
    endpoint::store::StoreApi _storeApi;
    std::shared_ptr<core::KeyProvider> _keyProvider;
    std::shared_ptr<ServerApi> _serverApi;
    std::shared_ptr<store::RequestApi> _requestApi;
    std::string _host;
    privmx::crypto::PrivateKey _userPrivKey;
    std::shared_ptr<core::EventMiddleware> _eventMiddleware;
    std::shared_ptr<core::HandleManager> _handleManager;
    InboxHandleManager _inboxHandleManager;
    MessageKeyIdFormatValidator _messageKeyIdFormatValidator;
    FileKeyIdFormatValidator _fileKeyIdFormatValidator;
    int _notificationListenerId, _connectedListenerId, _disconnectedListenerId;
    std::string _messageDecryptorId, _fileDecryptorId, _fileOpenerId, _fileSeekerId, _fileReaderId, _fileCloserId, _messageDeleterId;
    size_t _serverRequestChunkSize;
    store::FileMetaEncryptorV4 _fileMetaEncryptorV4;
    core::SubscriptionHelper _inboxSubscriptionHelper;
    core::SubscriptionHelperExt _threadSubscriptionHelper;
    
    InboxDataProcessorV4 _inboxDataProcessorV4;
    inline static const std::string INBOX_TYPE_FILTER_FLAG = "inbox";
};

} // inbox
} // endpoint
} // privmx

#endif // _PRIVMXLIB_ENDPOINT_INBOX_INBOXAPIIMPL_HPP_
