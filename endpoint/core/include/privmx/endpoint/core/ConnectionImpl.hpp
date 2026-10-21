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
#include <mutex>
#include <optional>
#include <map>
#include <shared_mutex>
#include <string>
#include <vector>

#include "privmx/endpoint/core/Connection.hpp"
#include "privmx/endpoint/core/ContextProvider.hpp"
#include "privmx/endpoint/core/DefaultUserVerifierInterface.hpp"
#include "privmx/endpoint/core/EventMiddleware.hpp"
#include "privmx/endpoint/core/HandleManager.hpp"
#include "privmx/endpoint/core/KeyProvider.hpp"
#include "privmx/endpoint/core/PinStoreInterface.hpp"
#include "privmx/endpoint/core/ServerApi.hpp"
#include "privmx/endpoint/core/SubscriberImpl.hpp"
#include "privmx/endpoint/core/Types.hpp"
#include "privmx/endpoint/core/UserVerifier.hpp"
#include "privmx/endpoint/core/UserVerifierInterface.hpp"
#include <privmx/crypto/Crypto.hpp>
#include <privmx/crypto/ecc/PrivateKey.hpp>
#include <privmx/privfs/gateway/RpcGateway.hpp>
#include <privmx/utils/GuardedExecutor.hpp>
#include <privmx/utils/NotificationQueue.hpp>

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
    // `connect` past opening the channel to the bridge: a unit test drives it over a gateway of its own (and names
    // the Bridge it stands for with `bridge`).
    void connectOver(
        const privfs::RpcGateway::Ptr& gateway,
        const crypto::PrivateKey& key,
        const std::optional<BridgeIdentity>& bridge = std::nullopt
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
    std::string buildSubscriptionQuery(
        EventType eventType,
        EventSelectorType selectorType,
        const std::string& selectorId
    );
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
    // 01: where the library keeps state between sessions; nullptr (the default, and always for `connectPublic`,
    // whose key is random) keeps it in memory only. A GroupApi reads it once, when created.
    void setPinStore(std::shared_ptr<PinStoreInterface> store);
    std::shared_ptr<PinStoreInterface> getPinStore();
    // hex(SHA256(lp(url) || lp(pubKey or "") || lp(instanceId or ""))) of the Bridge this connection reached: every
    // local-state slot is named and sealed under it, so a second Bridge reached with the same key has slots of its own.
    std::string localStateScope();
    // `<kind>/<scope>/<public key of identity>`.
    std::string localStateSlot(const std::string& kind, const crypto::PublicKey& identity);
    // 01: the group pins the store holds for `previous` (an identity key this user had before), opened with it and
    // kept for every GroupApi created afterwards to adopt. Nothing stored: nothing to adopt. Throws
    // LocalStateIntegrityException when the stored blob does not open (nothing is staged).
    void adoptPreviousIdentity(const crypto::PrivateKey& previous);
    // The bodies `adoptPreviousIdentity` staged, by previous public key.
    std::map<std::string, std::string> getStagedPinBodies();
    // The keys `adoptPreviousIdentity` was called with, other than the current one (stored pins or not): the only
    // knowledge of an identity key change this client has that the Bridge did not supply.
    std::vector<crypto::PrivateKey> previousIdentities();
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
    inline bool isConnected() { return _gateway->isConnected(); };

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
    NotificationEvent convertJanusEventToCoreNotificationEvent(const rpc::NotificationEvent& event);
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
    std::shared_ptr<PinStoreInterface> _pinStore; // under _mutex
    std::map<std::string, std::string> _stagedPinBodies; // under _mutex
    std::vector<crypto::PrivateKey> _previousIdentities; // under _mutex
    bool _public = false;
    std::shared_ptr<ContextProvider> _contextProvider;
    std::shared_mutex _mutex;
    std::shared_ptr<SubscriberImpl> _subscriber;
    std::optional<ServerApi> _serverApi;
    std::shared_ptr<privmx::utils::GuardedExecutor> _guardedExecutor;
    int _gatewayNotificationEventListener, _gatewayConnectedEventListener, _gatewayDisconnectedEventListener,
        _gatewaySessionLostEventListener;
    int _notificationListenerId;
};

} // namespace core
} // namespace endpoint
} // namespace privmx

#endif // _PRIVMXLIB_ENDPOINT_CORE_CONNECTIONIMPL_HPP_
