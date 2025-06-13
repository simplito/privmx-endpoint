/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_ENDPOINT_CORE_EVENT_CHANNEL_MANAGER_HPP_
#define _PRIVMXLIB_ENDPOINT_CORE_EVENT_CHANNEL_MANAGER_HPP_

#include <privmx/privfs/gateway/RpcGateway.hpp>
#include <privmx/utils/ThreadSaveMap.hpp>
#include <string>

#include "privmx/endpoint/core/EventMiddleware.hpp"

namespace privmx {
namespace endpoint {
namespace core {

#define INTERNAL_EVENT_CHANNEL_NAME "internal"

struct Subscription {
    std::string subscriptionId;
    std::string channel;
};

class EventChannelManager {

public:
    EventChannelManager(privfs::RpcGateway::Ptr gateway, std::shared_ptr<EventMiddleware> eventMiddleware);
    std::vector<Subscription> subscribeFor(const std::vector<std::string>& channels);
    void unsubscribeFrom(const std::vector<std::string>& channels);

private:
    struct SubscriptionCount {
        uint64_t count;
        std::string subscriptionId;
    };
    privfs::RpcGateway::Ptr _gateway;
    std::shared_ptr<EventMiddleware> _eventMiddleware;
    std::map<std::string, SubscriptionCount> _map;
    std::shared_mutex _map_mutex;
};

}  // namespace core
}  // namespace endpoint
}  // namespace privmx

#endif  // _PRIVMXLIB_ENDPOINT_CORE_EVENT_CHANNEL_MANAGER_HPP_