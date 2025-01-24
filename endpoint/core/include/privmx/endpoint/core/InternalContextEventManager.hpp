/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_ENDPOINT_CORE_INTERNAL_CONTEXT_EVENT_MANAGER_HPP_
#define _PRIVMXLIB_ENDPOINT_CORE_INTERNAL_CONTEXT_EVENT_MANAGER_HPP_

#include "privmx/endpoint/core/SubscriptionHelper.hpp"
#include "privmx/endpoint/core/ServerTypes.hpp"
#include "privmx/endpoint/core/DataEncryptorV4.hpp"
#include <privmx/crypto/ecc/PrivateKey.hpp>
#include <privmx/privfs/gateway/RpcGateway.hpp>

namespace privmx {
namespace endpoint {
namespace core {


class InternalContextEventManager {
public:
    InternalContextEventManager(
        const privmx::crypto::PrivateKey& userPrivKey,
        privfs::RpcGateway::Ptr gateway,
        std::shared_ptr<SubscriptionHelper> contextSubscriptionHelper
    );
    void sendEvent(const std::string& contextId, server::InternalContextEventData data, const std::vector<privmx::endpoint::core::UserWithPubKey>& users);
    bool isInternalContextEvent(const std::string& type, const std::string& channel, Poco::JSON::Object::Ptr eventData, const std::optional<std::string>& internalContextEventType = std::nullopt);
    server::InternalContextEventData extractEventData(const Poco::JSON::Object::Ptr& eventData);
    void subscribeFor(const std::string& contextId);
    void unsubscribeFrom(const std::string& contextId);

private:
    privfs::RpcGateway::Ptr _gateway;
    privmx::crypto::PrivateKey _userPrivKey;
    std::shared_ptr<SubscriptionHelper> _contextSubscriptionHelper;
    core::DataEncryptorV4 _dataEncryptor;
   
};

} // core
} // endpoint
} // privmx

#endif  // _PRIVMXLIB_ENDPOINT_CORE_INTERNAL_CONTEXT_EVENT_MANAGER_HPP_
