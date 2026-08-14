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

#include <atomic>
#include <memory>
#include <optional>
#include <string>
#include <unordered_map>

#include <privmx/endpoint/core/ConnectionImpl.hpp>
#include <privmx/endpoint/core/EventMiddleware.hpp>

#include "privmx/endpoint/core/ContainerKeyCache.hpp"
#include "privmx/endpoint/core/Factory.hpp"
#include "privmx/endpoint/core/ModuleBaseApi.hpp"
#include "privmx/endpoint/group/GroupApi.hpp"
#include "privmx/endpoint/thread/Constants.hpp"
#include "privmx/endpoint/thread/Events.hpp"
#include "privmx/endpoint/thread/ServerApi.hpp"
#include "privmx/endpoint/thread/SubscriberImpl.hpp"
#include "privmx/endpoint/thread/ThreadApi.hpp"
#include "privmx/endpoint/thread/encryptors/message/MessageDataSchemaMapper.hpp"
#include "privmx/endpoint/thread/encryptors/thread/ThreadDataSchemaMapper.hpp"
#include <privmx/utils/ManualManagedClass.hpp>

namespace privmx {
namespace endpoint {
namespace thread {

class ThreadApiImpl : public privmx::utils::ManualManagedClass<ThreadApiImpl>, protected core::ModuleBaseApi {
public:
    ThreadApiImpl(
        const privfs::RpcGateway::Ptr& gateway,
        const privmx::crypto::PrivateKey& userPrivKey,
        const std::shared_ptr<core::KeyProvider>& keyProvider,
        const std::string& host,
        const std::shared_ptr<core::EventMiddleware>& eventMiddleware,
        const core::Connection& connection,
        const group::GroupApi& groupApi = group::GroupApi()
    );
    ~ThreadApiImpl();
    std::string createThread(
        const std::string& contextId,
        const std::vector<core::UserWithPubKey>& users,
        const std::vector<core::UserWithPubKey>& managers,
        const core::Buffer& publicMeta,
        const core::Buffer& privateMeta,
        const std::optional<core::ContainerPolicy>& policies,
        const std::string& type = THREAD_TYPE_FILTER_FLAG,
        const std::vector<core::GroupGrantWithKey>& groups = {}
    );

    void updateThread(
        const std::string& threadId,
        const std::vector<core::UserWithPubKey>& users,
        const std::vector<core::UserWithPubKey>& managers,
        const core::Buffer& publicMeta,
        const core::Buffer& privateMeta,
        const int64_t version,
        const bool force,
        const bool forceGenerateNewKey,
        const std::optional<core::ContainerPolicy>& policies,
        const std::vector<core::GroupGrantWithKey>& groups = {}
    );
    void rotateThreadKeys(
        const std::string& threadId,
        const std::vector<core::UserWithPubKey>& users,
        const std::vector<core::UserWithPubKey>& managers,
        const int64_t version,
        const bool force,
        const std::vector<core::GroupGrantWithKey>& groups = {}
    );
    void deleteThread(const std::string& threadId);

    Thread getThread(const std::string& threadId, const std::string& type = THREAD_TYPE_FILTER_FLAG);
    core::PagingList<Thread> listThreads(
        const std::string& contextId,
        const core::PagingQuery& pagingQuery,
        const std::string& type = THREAD_TYPE_FILTER_FLAG
    );

    Message getMessage(const std::string& messageId);
    core::PagingList<Message> listMessages(const std::string& threadId, const core::PagingQuery& pagingQuery);
    std::string sendMessage(
        const std::string& threadId,
        const core::Buffer& publicMeta,
        const core::Buffer& privateMeta,
        const core::Buffer& data
    );
    void deleteMessage(const std::string& messageId);
    void updateMessage(
        const std::string& messageId,
        const core::Buffer& publicMeta,
        const core::Buffer& privateMeta,
        const core::Buffer& data
    );

    std::vector<std::string> subscribeFor(const std::vector<std::string>& subscriptionQueries);
    void unsubscribeFrom(const std::vector<std::string>& subscriptionIds);
    std::string buildSubscriptionQuery(
        EventType eventType,
        EventSelectorType selectorType,
        const std::string& selectorId
    );

private:
    void processNotificationEvent(const std::string& type, const core::NotificationEvent& notification);
    void processConnectedEvent();
    void processDisconnectedEvent();
    virtual std::pair<core::ModuleKeys, int64_t> getModuleKeysAndVersionFromServer(std::string moduleId) override;
    core::ModuleKeys threadToModuleKeys(server::ThreadInfo thread);

    core::ModuleKeys getMessageDecryptionKeys(server::Message message);
    Poco::Dynamic::Var encryptMessageData(
        const std::string& threadId,
        const std::string& resourceId,
        const core::Buffer& publicMeta,
        const core::Buffer& privateMeta,
        const core::Buffer& data,
        const core::ModuleKeys& threadKeys
    );
    std::string sendMessageRequest(
        const std::string& threadId,
        const core::Buffer& publicMeta,
        const core::Buffer& privateMeta,
        const core::Buffer& data,
        const core::ModuleKeys& keys
    );
    void updateMessageRequest(
        const std::string& messageId,
        const std::string& resourceId,
        const std::string& threadId,
        const core::Buffer& publicMeta,
        const core::Buffer& privateMeta,
        const core::Buffer& data,
        const core::ModuleKeys& keys
    );

    void assertThreadExist(const std::string& threadId);

    // EP-13: lazy re-key check. Returns true if any grantee group's epoch has advanced.
    // Also caches resolved current-epoch group info in groupCache (groupId → {keyVersion, groupPubKey}).
    struct GroupEpochInfo { int64_t keyVersion; std::string groupPubKey; };
    bool isRekeyNeeded(
        const server::ThreadInfo& thread,
        std::unordered_map<std::string, GroupEpochInfo>& groupCache
    );
    // If rekey is needed, performs updateThread with new keys only. Caller re-fetches thread after.
    void applyRekeyIfNeeded(const std::string& threadId, const server::ThreadInfo& thread);

    privfs::RpcGateway::Ptr _gateway;
    privmx::crypto::PrivateKey _userPrivKey;
    std::shared_ptr<core::KeyProvider> _keyProvider;
    std::string _host;
    std::shared_ptr<core::EventMiddleware> _eventMiddleware;
    core::Connection _connection;
    std::shared_ptr<group::GroupApiImpl> _groupApiImpl;
    core::KeyProvider::GroupPrivKeyResolver _groupPrivKeyResolver;
    ServerApi _serverApi;
    SubscriberImpl _subscriber;

    int _notificationListenerId, _connectedListenerId, _disconnectedListenerId;
    std::string _messageDecryptorId, _messageDeleterId;
    MessageDataSchemaMapper _messageDataSchemaMapper;
    std::shared_ptr<ThreadDataSchemaMapper> _threadDataSchemaMapper;
    core::DataEncryptorV4 _eventDataEncryptorV4;
    std::vector<std::string> _forbiddenChannelsNames;

    inline static const std::string THREAD_TYPE_FILTER_FLAG = "thread";
};

} // namespace thread
} // namespace endpoint
} // namespace privmx

#endif // _PRIVMXLIB_ENDPOINT_THREAD_THREADAPIIMPL_HPP_
