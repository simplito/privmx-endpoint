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

#include <privmx/endpoint/core/ConnectionImpl.hpp>
#include <privmx/endpoint/core/DataEncryptor.hpp>
#include <privmx/endpoint/core/KeyProvider.hpp>
#include <privmx/utils/ThreadSaveMap.hpp>
#include <privmx/endpoint/core/EventMiddleware.hpp>
#include <privmx/endpoint/core/EventChannelManager.hpp>
#include <privmx/endpoint/core/SubscriptionHelper.hpp>

#include "privmx/endpoint/thread/ServerApi.hpp"
#include "privmx/endpoint/thread/DynamicTypes.hpp"
#include "privmx/endpoint/thread/MessageDataEncryptor.hpp"
#include "privmx/endpoint/thread/ThreadApi.hpp"
#include "privmx/endpoint/thread/MessageKeyIdFormatValidator.hpp"
#include "privmx/endpoint/thread/MessageDataEncryptorV4.hpp"
#include "privmx/endpoint/thread/ThreadDataEncryptorV4.hpp"
#include "privmx/endpoint/thread/Events.hpp"
#include "privmx/endpoint/core/Factory.hpp"
#include "privmx/endpoint/thread/ThreadProvider.hpp"

namespace privmx {
namespace endpoint {
namespace thread {

class ThreadApiImpl
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
    Thread _getThreadEx(const std::string& threadId, const std::string& type);
    core::PagingList<Thread> _listThreadsEx(const std::string& contextId, const core::PagingQuery& pagingQuery, const std::string& type);

    void processNotificationEvent(const std::string& type, const std::string& channel, const Poco::JSON::Object::Ptr& data);
    void processConnectedEvent();
    void processDisconnectedEvent();
    utils::List<std::string> mapUsers(const std::vector<core::UserWithPubKey>& users);
    dynamic::ThreadDataV1 decryptThreadV1(const server::ThreadInfo& thread);
    DecryptedThreadData decryptThreadV4(const server::ThreadInfo& thread);
    Thread convertThreadDataV1ToThread(const server::ThreadInfo& threadInfo, dynamic::ThreadDataV1 threadData);
    Thread convertDecryptedThreadDataToThread(const server::ThreadInfo& threadInfo, const DecryptedThreadData& threadData);
    Thread decryptAndConvertThreadDataToThread(const server::ThreadInfo& thread);

    core::EncKey getThreadEncKey(const server::ThreadInfo& thread);

    dynamic::MessageDataV2 decryptMessageDataV2(const server::ThreadInfo& thread, const server::Message& message);
    dynamic::MessageDataV3 decryptMessageDataV3(const server::ThreadInfo& thread, const server::Message& message);
    DecryptedMessageData decryptMessageDataV4(const server::ThreadInfo& thread, const server::Message& message);
    Message convertMessageDataV2ToMessage(const server::Message& message, dynamic::MessageDataV2 messageData);
    Message convertMessageDataV3ToMessage(const server::Message& message, dynamic::MessageDataV3 messageData);
    Message convertDecryptedMessageDataToMessage(const server::Message& message, DecryptedMessageData messageData);
    Message decryptAndConvertMessageDataToMessage(const server::ThreadInfo& thread, const server::Message& message);
    

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
    bool _subscribeForThread;
    core::SubscriptionHelper _threadSubscriptionHelper;

    int _notificationListenerId, _connectedListenerId, _disconnectedListenerId;
    std::string _messageDecryptorId, _messageDeleterId;
    MessageDataEncryptorV4 _messageDataEncryptorV4;
    ThreadDataEncryptorV4 _threadDataEncryptorV4;

    inline static const std::string THREAD_TYPE_FILTER_FLAG = "thread";
};

} // thread
} // endpoint
} // privmx

#endif // _PRIVMXLIB_ENDPOINT_THREAD_THREADAPIIMPL_HPP_
