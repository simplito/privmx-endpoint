/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_ENDPOINT_CORE_CONNECTIONIMPL_HPP_
#define _PRIVMXLIB_ENDPOINT_CORE_CONNECTIONIMPL_HPP_

#include <exception>
#include <functional>
#include <memory>
#include <optional>
#include <privmx/crypto/Crypto.hpp>
#include <privmx/crypto/ecc/PrivateKey.hpp>
#include <privmx/privfs/gateway/RpcGateway.hpp>
#include <privmx/utils/NotificationQueue.hpp>
#include <string>
#include <vector>

#include "privmx/endpoint/core/Connection.hpp"
#include "privmx/endpoint/core/EventMiddleware.hpp"
#include "privmx/endpoint/core/HandleManager.hpp"
#include "privmx/endpoint/core/KeyProvider.hpp"
#include "privmx/endpoint/core/Types.hpp"
#include "privmx/endpoint/core/UserVerifierInterface.hpp"
#include "privmx/endpoint/core/UserVerifier.hpp"
#include "privmx/endpoint/core/DefaultUserVerifierInterface.hpp"
#include "privmx/endpoint/core/ContextProvider.hpp"
#include <mutex>
#include <shared_mutex>
#include "privmx/endpoint/core/SubscriberImpl.hpp"
#include <privmx/utils/GuardedExecutor.hpp>

namespace privmx {
namespace endpoint {
namespace core {

class ConnectionImpl {
public:
    ConnectionImpl();
    ~ConnectionImpl();
    void connect(
        const std::string& userPrivKey,
        const std::string& solutionId,
        const std::string& platformUrl,
        const PKIVerificationOptions& verificationOptions = PKIVerificationOptions()
    );
    void connectPublic(
        const std::string& solutionId,
        const std::string& platformUrl,
        const PKIVerificationOptions& verificationOptions = PKIVerificationOptions()
    );
    int64_t getConnectionId();
    core::PagingList<Context> listContexts(const PagingQuery& pagingQuery);
    PagingList<UserInfo> listContextUsers(const std::string& contextId, const PagingQuery& pagingQuery);
    std::vector<std::string> subscribeFor(const std::vector<std::string>& subscriptionQueries);
    void unsubscribeFrom(const std::vector<std::string>& subscriptionIds);
    std::string buildSubscriptionQuery(EventType eventType, EventSelectorType selectorType, const std::string& selectorId);
    void disconnect();
    const privfs::RpcGateway::Ptr& getGateway() const { return _gateway; }
    const privmx::crypto::PrivateKey& getUserPrivKey() const { return _userPrivKey; }
    const std::string& getHost() const { return _host; }
    const std::shared_ptr<KeyProvider>& getKeyProvider() const { return _keyProvider; }
    const std::shared_ptr<EventMiddleware>& getEventMiddleware() const { return _eventMiddleware; }
    const std::shared_ptr<HandleManager>& getHandleManager() const { return _handleManager; }

    const rpc::ServerConfig& getServerConfig() const { return _serverConfig; }

    void setUserVerifier(std::shared_ptr<UserVerifierInterface> verifier);
    const std::shared_ptr<UserVerifier> getUserVerifier() {
        std::shared_lock lock(_mutex);
        return _userVerifier;    
    }
    std::string getMyUserId(const std::string& contextId);
    DataIntegrityObject createDIO(
        const std::string& contextId, 
        const std::string& resourceId, 
        const std::optional<std::string>& containerId = std::nullopt,
        const std::optional<std::string>& containerResourceId = std::nullopt
    );
    DataIntegrityObject createPublicDIO(
        const std::string& contextId, 
        const std::string& resourceId,
        const crypto::PublicKey& pubKey,
        const std::optional<std::string>& containerId = std::nullopt, 
        const std::optional<std::string>& containerResourceId = std::nullopt
    );


private:
    void assertServerVersion();
    std::string generateDIORandomId();
    DataIntegrityObject createDIOExt(
        const std::string& contextId, 
        const std::string& resourceId, 
        const std::optional<std::string>& containerId, 
        const std::optional<std::string>& containerResourceId,
        const std::optional<std::string>& creatorUserId = std::nullopt,
        const std::optional<crypto::PublicKey>& creatorPublicKey = std::nullopt
    );
    int64_t generateConnectionId();
    NotificationEvent convertRpcNotificationEventToCoreNotificationEvent(const rpc::NotificationEvent& event);
    void processNotificationEvent(const std::string& type, const core::NotificationEvent& notification);

    const int64_t _connectionId;
    privfs::RpcGateway::Ptr _gateway;
    privmx::crypto::PrivateKey _userPrivKey;
    std::string _host;
    BridgeIdentity _bridgeIdentity;
    rpc::ServerConfig _serverConfig;
    std::shared_ptr<KeyProvider> _keyProvider;
    std::shared_ptr<EventMiddleware> _eventMiddleware;
    std::shared_ptr<HandleManager> _handleManager;
    std::shared_ptr<UserVerifier> _userVerifier;
    std::shared_ptr<ContextProvider> _contextProvider;
    std::shared_mutex _mutex;
    std::shared_ptr<SubscriberImpl> _subscriber;
    std::shared_ptr<privmx::utils::GuardedExecutor> _guardedExecutor;
    int _notificationListenerId;
};

}  // namespace core
}  // namespace endpoint
}  // namespace privmx

#endif  // _PRIVMXLIB_ENDPOINT_CORE_CONNECTIONIMPL_HPP_
