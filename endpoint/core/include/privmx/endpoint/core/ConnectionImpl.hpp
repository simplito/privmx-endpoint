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
#include "privmx/endpoint/core/EventChannelManager.hpp"
#include "privmx/endpoint/core/EventMiddleware.hpp"
#include "privmx/endpoint/core/HandleManager.hpp"
#include "privmx/endpoint/core/KeyProvider.hpp"
#include "privmx/endpoint/core/Types.hpp"
#include <privmx/endpoint/core/UserVerifierInterface.hpp>
#include <privmx/endpoint/core/DefaultUserVerifierInterface.hpp>
#include <mutex>
#include <shared_mutex>

namespace privmx {
namespace endpoint {
namespace core {

class ConnectionImpl {
public:
    ConnectionImpl();
    void connect(const std::string& userPrivKey, const std::string& solutionId, const std::string& platformUrl);
    void connectPublic(const std::string& solutionId, const std::string& platformUrl);
    int64_t getConnectionId();
    core::PagingList<Context> listContexts(const PagingQuery& pagingQuery);
    std::vector<UserInfo> getContextUsers(const std::string& contextId);
    void disconnect();
    const privfs::RpcGateway::Ptr& getGateway() const { return _gateway; }
    const privmx::crypto::PrivateKey& getUserPrivKey() const { return _userPrivKey; }
    const std::string& getHost() const { return _host; }
    const std::shared_ptr<KeyProvider>& getKeyProvider() const { return _keyProvider; }
    const std::shared_ptr<EventMiddleware>& getEventMiddleware() const { return _eventMiddleware; }
    const std::shared_ptr<EventChannelManager>& getEventChannelManager() const { return _eventChannelManager; }
    const std::shared_ptr<HandleManager>& getHandleManager() const { return _handleManager; }

    const rpc::ServerConfig& getServerConfig() const { return _serverConfig; }

    void setUserVerifier(std::shared_ptr<UserVerifierInterface> verifier);
    const std::shared_ptr<UserVerifierInterface> getUserVerifier() {
        std::shared_lock lock(_mutex);
        return _userVerifier;    
    }

private:
    int64_t generateConnectionId();

    const int64_t _connectionId;
    privfs::RpcGateway::Ptr _gateway;
    privmx::crypto::PrivateKey _userPrivKey;
    std::string _host;
    rpc::ServerConfig _serverConfig;
    std::shared_ptr<KeyProvider> _keyProvider;
    std::shared_ptr<EventMiddleware> _eventMiddleware;
    std::shared_ptr<EventChannelManager> _eventChannelManager;
    std::shared_ptr<HandleManager> _handleManager;
    std::shared_ptr<UserVerifierInterface> _userVerifier;
    std::shared_mutex _mutex;
};

}  // namespace core
}  // namespace endpoint
}  // namespace privmx

#endif  // _PRIVMXLIB_ENDPOINT_CORE_CONNECTIONIMPL_HPP_
