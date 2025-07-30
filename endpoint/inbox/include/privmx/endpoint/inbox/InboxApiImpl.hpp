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
#include <atomic>

#include <privmx/utils/ThreadSaveMap.hpp>

#include <privmx/endpoint/core/Connection.hpp>
#include <privmx/endpoint/core/encryptors/DataEncryptorV4.hpp>
#include <privmx/endpoint/core/KeyProvider.hpp>
#include <privmx/endpoint/core/EventMiddleware.hpp>
#include <privmx/endpoint/core/Types.hpp>
#include <privmx/endpoint/thread/ServerTypes.hpp>
#include <privmx/endpoint/thread/ThreadApi.hpp>
#include <privmx/endpoint/store/StoreApi.hpp>
#include <privmx/endpoint/store/FileHandle.hpp>
#include <privmx/endpoint/store/DynamicTypes.hpp>
#include <privmx/endpoint/store/encryptors/file/FileMetaEncryptorV4.hpp>
#include <privmx/endpoint/store/encryptors/file/FileMetaEncryptorV5.hpp>
#include <privmx/endpoint/core/ModuleBaseApi.hpp>
#include "privmx/endpoint/inbox/InboxApi.hpp"
#include "privmx/endpoint/inbox/ServerTypes.hpp"
#include "privmx/endpoint/inbox/InboxEntriesDataEncryptorSerializer.hpp"
#include "privmx/endpoint/inbox/ServerApi.hpp"
#include "privmx/endpoint/inbox/InboxHandleManager.hpp"
#include "privmx/endpoint/inbox/MessageKeyIdFormatValidator.hpp"
#include "privmx/endpoint/inbox/FileKeyIdFormatValidator.hpp"
#include "privmx/endpoint/inbox/Events.hpp"
#include "privmx/endpoint/inbox/encryptors/inbox/InboxDataProcessorV4.hpp"
#include "privmx/endpoint/inbox/encryptors/inbox/InboxDataProcessorV5.hpp"
#include "privmx/endpoint/inbox/Factory.hpp"
#include "privmx/endpoint/core/Factory.hpp"
#include "privmx/endpoint/inbox/Constants.hpp"
#include "privmx/endpoint/inbox/SubscriberImpl.hpp"
#include "privmx/endpoint/core/ModuleBaseApi.hpp"

namespace privmx {
namespace endpoint {
namespace inbox {

class InboxApiImpl : protected core::ModuleBaseApi
{
public:
    InboxApiImpl(
        const core::Connection& connection,
        const thread::ThreadApi& threadApi,
        const store::StoreApi& storeApi,
        const std::shared_ptr<core::KeyProvider>& keyProvider,
        const std::shared_ptr<inbox::ServerApi>& serverApi,
        const std::shared_ptr<store::RequestApi>& requestApi,
        const std::string& host,
        const privmx::crypto::PrivateKey& userPrivKey,
        const std::shared_ptr<core::EventMiddleware>& eventMiddleware,
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
    inbox::Inbox getInboxEx(const std::string& inboxId, const std::string& type);
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

    std::vector<std::string> subscribeFor(const std::vector<std::string>& subscriptionQueries);
    void unsubscribeFrom(const std::vector<std::string>& subscriptionIds);
    std::string buildSubscriptionQuery(EventType eventType, EventSelectorType selectorType, const std::string& selectorId);
private:
    inbox::server::Inbox getServerInbox(const std::string& inboxId, const std::optional<std::string>& type = std::nullopt);
    inbox::Inbox _getInboxEx(const std::string& inboxId, const std::string& type);
    inbox::FilesConfig getFilesConfigOptOrDefault(const std::optional<inbox::FilesConfig>& fileConfig);
    InboxPublicViewData getInboxPublicViewData(const std::string& inboxId);
    InboxDataResultV4 decryptInboxV4(inbox::server::InboxDataEntry inboxEntry, const core::DecryptedEncKey& encKey);
    InboxDataResultV5 decryptInboxV5(inbox::server::InboxDataEntry inboxEntry, const core::DecryptedEncKey& encKey);
    inbox::Inbox convertServerInboxToLibInbox(
        inbox::server::Inbox inbox,
        const core::Buffer& publicMeta = core::Buffer(),
        const core::Buffer& privateMeta = core::Buffer(),
        const std::optional<privmx::endpoint::inbox::FilesConfig>& filesConfig = std::nullopt,
        const int64_t& statusCode = 0,
        const int64_t& schemaVersion = InboxDataSchema::Version::UNKNOWN
    );
    inbox::Inbox convertInboxV4(inbox::server::Inbox inboxRaw, const InboxDataResultV4& inboxData);
    inbox::Inbox convertInboxV5(inbox::server::Inbox inboxRaw, const InboxDataResultV5& inboxData);
    InboxDataSchema::Version getInboxDataEntryStructureVersion(inbox::server::InboxDataEntry inboxEntry);
    std::tuple<inbox::Inbox, core::DataIntegrityObject> decryptAndConvertInboxDataToInbox(inbox::server::Inbox inbox, inbox::server::InboxDataEntry inboxEntry, const core::DecryptedEncKey& encKey);
    std::vector<Inbox> validateDecryptAndConvertInboxesDataToInboxes(utils::List<inbox::server::Inbox> inboxes);
    inbox::Inbox validateDecryptAndConvertInboxDataToInbox(inbox::server::Inbox inbox);
    InboxInternalMetaV5 decryptInboxInternalMeta(inbox::server::InboxDataEntry inboxEntry, const core::DecryptedEncKey& encKey);
    inbox::server::InboxDataEntry getInboxCurrentDataEntry(inbox::server::Inbox inbox);
    inbox::server::InboxMessageServer unpackInboxOrigMessage(const std::string& serialized);
    void assertInboxDataIntegrity(inbox::server::Inbox inbox);
    uint32_t validateInboxDataIntegrity(inbox::server::Inbox inbox);
    virtual std::pair<core::ModuleKeys, int64_t> getModuleKeysAndVersionFromServer(std::string moduleId) override;
    core::ModuleKeys inboxToModuleKeys(inbox::server::Inbox inbox);


    InboxEntryResult decryptInboxEntry(thread::server::Message message, const core::ModuleKeys& inboxKeys);
    inbox::InboxEntry convertInboxEntry(thread::server::Message message, const inbox::InboxEntryResult& inboxEntry);
    inbox::InboxEntry decryptAndConvertInboxEntryDataToInboxEntry(thread::server::Message message, const core::ModuleKeys& inboxKeys);
    store::FileMetaToEncryptV4 prepareMeta(const inbox::CommitFileInfo& commitFileInfo);
    core::ModuleKeys getEntryDecryptionKeys(thread::server::Message message);

    void processNotificationEvent(const std::string& type, const core::NotificationEvent& notification);
    void processConnectedEvent();
    void processDisconnectedEvent();
    InboxDeletedEventData convertInboxDeletedEventData(server::InboxDeletedEventData data);

    int64_t createInboxFileHandleForRead(const store::server::File& file);

    std::string readInboxIdFromMessageKeyId(const std::string& keyId);
    std::string readMessageIdFromFileKeyId(const std::string& keyId);
    void deleteMessageAndFiles(thread::server::Message message);
    thread::server::Message getServerMessage(const std::string& messageId);
    InboxEntryResult getEmptyResultWithStatusCode(const int64_t statusCode);
    std::vector<std::string> getFilesIdsFromServerMessage(inbox::server::InboxMessageServer serverMessage);
    void assertInboxExist(const std::string& inboxId);

    template <typename T = std::string>
    static std::vector<T> listToVector(utils::List<T> list) {
        std::vector<T> ret {};
        for (auto x: list) {
            ret.push_back(x);
        }
        return ret;
    }
    static const Poco::Int64 _CHUNK_SIZE;
    core::Connection _connection;
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
    store::FileMetaEncryptorV5 _fileMetaEncryptorV5;
    SubscriberImpl _subscriber;
    
    InboxDataProcessorV4 _inboxDataProcessorV4;
    InboxDataProcessorV5 _inboxDataProcessorV5;
    core::DataEncryptorV4 _eventDataEncryptorV4;
    std::vector<std::string> _forbiddenChannelsNames;
    inline static const std::string INBOX_TYPE_FILTER_FLAG = "inbox";
};

} // inbox
} // endpoint
} // privmx

#endif // _PRIVMXLIB_ENDPOINT_INBOX_INBOXAPIIMPL_HPP_
