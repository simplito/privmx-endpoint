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
    void disconnect();
    const privfs::RpcGateway::Ptr& getGateway() const { return _gateway; }
    const privmx::crypto::PrivateKey& getUserPrivKey() const { return _userPrivKey; }
    const std::string& getHost() const { return _host; }
    const std::shared_ptr<KeyProvider>& getKeyProvider() const { return _keyProvider; }
    const std::shared_ptr<EventMiddleware>& getEventMiddleware() const { return _eventMiddleware; }
    const std::shared_ptr<EventChannelManager>& getEventChannelManager() const { return _eventChannelManager; }
    const std::shared_ptr<HandleManager>& getHandleManager() const { return _handleManager; }

    const rpc::ServerConfig& getServerConfig() const { return _serverConfig; }

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
};

}  // namespace core
}  // namespace endpoint
}  // namespace privmx

#endif  // _PRIVMXLIB_ENDPOINT_CORE_CONNECTIONIMPL_HPP_
