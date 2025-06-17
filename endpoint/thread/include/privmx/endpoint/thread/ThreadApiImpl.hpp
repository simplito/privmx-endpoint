/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_ENDPOINT_THREAD_THREADAPIIMPL_HPP_
#define _PRIVMXLIB_ENDPOINT_THREAD_THREADAPIIMPL_HPP_

#include <memory>
#include <optional>
#include <string>
#include <atomic>

#include <privmx/endpoint/core/ConnectionImpl.hpp>
#include <privmx/endpoint/core/encryptors/DataEncryptorV4.hpp>
#include <privmx/endpoint/core/KeyProvider.hpp>
#include <privmx/utils/ThreadSaveMap.hpp>
#include <privmx/endpoint/core/EventMiddleware.hpp>
#include <privmx/endpoint/core/EventChannelManager.hpp>
#include <privmx/endpoint/core/SubscriptionHelper.hpp>
#include <privmx/endpoint/core/encryptors/container/ContainerDataEncryptorV4.hpp>
#include <privmx/endpoint/core/encryptors/container/ContainerDataEncryptorV5.hpp>

#include "privmx/endpoint/thread/ServerApi.hpp"
#include "privmx/endpoint/thread/DynamicTypes.hpp"
#include "privmx/endpoint/thread/encryptors/message/MessageDataEncryptor.hpp"
#include "privmx/endpoint/thread/ThreadApi.hpp"
#include "privmx/endpoint/thread/MessageKeyIdFormatValidator.hpp"
#include "privmx/endpoint/thread/encryptors/message/MessageDataEncryptorV4.hpp"
#include "privmx/endpoint/thread/encryptors/message/MessageDataEncryptorV5.hpp"
#include "privmx/endpoint/thread/Events.hpp"
#include "privmx/endpoint/core/Factory.hpp"
#include "privmx/endpoint/thread/ThreadProvider.hpp"
#include "privmx/endpoint/thread/Constants.hpp"
#include "privmx/endpoint/core/ModuleBaseApi.hpp"

namespace privmx {
namespace endpoint {
namespace thread {

class ThreadApiImpl : protected core::ModuleBaseApi
{
public:
    ThreadApiImpl(
        const privfs::RpcGateway::Ptr& gateway,
        const privmx::crypto::PrivateKey& userPrivKey,
        const std::shared_ptr<core::KeyProvider>& keyProvider,
        const std::string& host,
        const std::shared_ptr<core::EventMiddleware>& eventMiddleware,
        const std::shared_ptr<core::EventChannelManager>& eventChannelManager,
        const core::Connection& connection
    );
    ~ThreadApiImpl();
    std::string createThread(const std::string& contextId, const std::vector<core::UserWithPubKey>& users,
                             const std::vector<core::UserWithPubKey>& managers, const core::Buffer& publicMeta, const core::Buffer& privateMeta, const std::optional<core::ContainerPolicy>& policies);
    std::string createThreadEx(const std::string& contextId, const std::vector<core::UserWithPubKey>& users,
                             const std::vector<core::UserWithPubKey>& managers, const core::Buffer& publicMeta, const core::Buffer& privateMeta, const std::string& type, const std::optional<core::ContainerPolicy>& policies);

    void updateThread(const std::string& threadId, const std::vector<core::UserWithPubKey>& users,
                      const std::vector<core::UserWithPubKey>& managers, const core::Buffer& publicMeta, const core::Buffer& privateMeta,
                      const int64_t version, const bool force, const bool forceGenerateNewKey, const std::optional<core::ContainerPolicy>& policies);
    void deleteThread(const std::string& threadId);

    Thread getThread(const std::string& threadId);
    Thread getThreadEx(const std::string& threadId, const std::string& type);
    core::PagingList<Thread> listThreads(const std::string& contextId, const core::PagingQuery& pagingQuery);
    core::PagingList<Thread> listThreadsEx(const std::string& contextId, const core::PagingQuery& pagingQuery, const std::string& type);

    Message getMessage(const std::string& messageId);
    core::PagingList<Message> listMessages(const std::string& threadId, const core::PagingQuery& pagingQuery);
    std::string sendMessage(const std::string& threadId, const core::Buffer& publicMeta,
                            const core::Buffer& privateMeta, const core::Buffer& data);
    void deleteMessage(const std::string& messageId);
    void updateMessage(const std::string& messageId, const core::Buffer& publicMeta,
                            const core::Buffer& privateMeta, const core::Buffer& data);

    void subscribeForThreadEvents();
    void unsubscribeFromThreadEvents();
    void subscribeForMessageEvents(std::string threadId);
    void unsubscribeFromMessageEvents(std::string threadId);
private:
    std::string _createThreadEx(
        const std::string& contextId, 
        const std::vector<core::UserWithPubKey>& users, 
        const std::vector<core::UserWithPubKey>& managers,
        const core::Buffer& publicMeta,
        const core::Buffer& privateMeta,
        const std::string& type,
        const std::optional<core::ContainerPolicy>& policies
    );
    server::ThreadInfo getRawThreadFromCacheOrBridge(const std::string& threadId);
    Thread _getThreadEx(const std::string& threadId, const std::string& type);
    core::PagingList<Thread> _listThreadsEx(const std::string& contextId, const core::PagingQuery& pagingQuery, const std::string& type);

    void processNotificationEvent(const std::string& type, const core::NotificationEvent& notification);
    void processConnectedEvent();
    void processDisconnectedEvent();
    utils::List<std::string> mapUsers(const std::vector<core::UserWithPubKey>& users);
    dynamic::ThreadDataV1 decryptThreadV1(server::Thread2DataEntry threadEntry, const core::DecryptedEncKey& encKey);
    core::container::DecryptedContainerDataV4 decryptThreadV4(server::Thread2DataEntry threadEntry, const core::DecryptedEncKey& encKey);
    core::container::DecryptedContainerDataV5 decryptThreadV5(server::Thread2DataEntry threadEntry, const core::DecryptedEncKey& encKey);
    Thread convertServerThreadToLibThread(
        server::ThreadInfo threadInfo,
        const core::Buffer& publicMeta = core::Buffer(),
        const core::Buffer& privateMeta = core::Buffer(),
        const int64_t& statusCode = 0,
        const int64_t& schemaVersion = ThreadDataSchema::Version::UNKNOWN
    );
    Thread convertThreadDataV1ToThread(server::ThreadInfo threadInfo, dynamic::ThreadDataV1 threadData);
    Thread convertDecryptedThreadDataV4ToThread(server::ThreadInfo threadInfo, const core::container::DecryptedContainerDataV4& threadData);
    Thread convertDecryptedThreadDataV5ToThread(server::ThreadInfo threadInfo, const core::container::DecryptedContainerDataV5& threadData);
    ThreadDataSchema::Version getThreadEntryDataStructureVersion(server::Thread2DataEntry threadEntry);
    std::tuple<Thread, core::DataIntegrityObject> decryptAndConvertThreadDataToThread(server::ThreadInfo thread, server::Thread2DataEntry threadEntry, const core::DecryptedEncKey& encKey);
    std::vector<Thread> decryptAndConvertThreadsDataToThreads(utils::List<server::ThreadInfo> threads);
    Thread decryptAndConvertThreadDataToThread(server::ThreadInfo thread);
    core::container::ContainerInternalMetaV5 decryptThreadInternalMeta(server::Thread2DataEntry threadEntry, const core::DecryptedEncKey& encKey);
    uint32_t validateThreadDataIntegrity(server::ThreadInfo thread);

    dynamic::MessageDataV2 decryptMessageDataV2(server::Message message, const core::DecryptedEncKey& encKey);
    dynamic::MessageDataV3 decryptMessageDataV3(server::Message message, const core::DecryptedEncKey& encKey);
    DecryptedMessageDataV4 decryptMessageDataV4(server::Message message, const core::DecryptedEncKey& encKey);
    DecryptedMessageDataV5 decryptMessageDataV5(server::Message message, const core::DecryptedEncKey& encKey);
    Message convertServerMessageToLibMessage(
        server::Message message,
        const core::Buffer& publicMeta = core::Buffer(),
        const core::Buffer& privateMeta = core::Buffer(),
        const core::Buffer& data = core::Buffer(),
        const std::string& authorPubKey = std::string(),
        const int64_t& statusCode = 0,
        const int64_t& schemaVersion = MessageDataSchema::Version::UNKNOWN
    );
    Message convertMessageDataV2ToMessage(server::Message message, dynamic::MessageDataV2 messageData);
    Message convertMessageDataV3ToMessage(server::Message message, dynamic::MessageDataV3 messageData);
    Message convertDecryptedMessageDataV4ToMessage(server::Message message, DecryptedMessageDataV4 messageData);
    Message convertDecryptedMessageDataV5ToMessage(server::Message message, DecryptedMessageDataV5 messageData);
    MessageDataSchema::Version getMessagesDataStructureVersion(server::Message message);
    std::tuple<Message, core::DataIntegrityObject> decryptAndConvertMessageDataToMessage(server::Message message, const core::DecryptedEncKey& encKey);
    std::vector<Message> decryptAndConvertMessagesDataToMessages(server::ThreadInfo thread, utils::List<server::Message> messages);
    Message decryptAndConvertMessageDataToMessage(server::ThreadInfo thread, server::Message message);
    Message decryptAndConvertMessageDataToMessage(server::Message message);
    uint32_t validateMessageDataIntegrity(server::Message message, const std::string& threadResourceId);

    void assertThreadExist(const std::string& threadId);
    privfs::RpcGateway::Ptr _gateway;
    privmx::crypto::PrivateKey _userPrivKey;
    std::shared_ptr<core::KeyProvider> _keyProvider;
    std::string _host;
    std::shared_ptr<core::EventMiddleware> _eventMiddleware;
    core::Connection _connection;
    ServerApi _serverApi;
    core::DataEncryptor<dynamic::ThreadDataV1> _dataEncryptorThread;
    MessageDataV2Encryptor _messageDataV2Encryptor;
    MessageDataV3Encryptor _messageDataV3Encryptor;
    MessageKeyIdFormatValidator _messageKeyIdFormatValidator;
    ThreadProvider _threadProvider;
    std::atomic_bool _threadCache;
    core::SubscriptionHelper _threadSubscriptionHelper;

    int _notificationListenerId, _connectedListenerId, _disconnectedListenerId;
    std::string _messageDecryptorId, _messageDeleterId;
    MessageDataEncryptorV4 _messageDataEncryptorV4;
    core::container::ContainerDataEncryptorV4 _threadDataEncryptorV4;
    MessageDataEncryptorV5 _messageDataEncryptorV5;
    core::container::ContainerDataEncryptorV5 _threadDataEncryptorV5;
    core::DataEncryptorV4 _eventDataEncryptorV4;
    std::vector<std::string> _forbiddenChannelsNames;

    inline static const std::string THREAD_TYPE_FILTER_FLAG = "thread";
};

} // thread
} // endpoint
} // privmx

#endif // _PRIVMXLIB_ENDPOINT_THREAD_THREADAPIIMPL_HPP_
