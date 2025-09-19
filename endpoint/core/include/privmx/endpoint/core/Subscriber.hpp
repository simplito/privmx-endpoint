/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_ENDPOINT_CORE_SUBSCRIBER_HPP_
#define _PRIVMXLIB_ENDPOINT_CORE_SUBSCRIBER_HPP_

#include <vector>
#include <map>
#include <string>
#include <mutex>
#include <shared_mutex>
#include <optional>
#include <privmx/privfs/gateway/RpcGateway.hpp>
#include "privmx/endpoint/core/ServerTypes.hpp"
#include "privmx/endpoint/core/EventMiddleware.hpp"

namespace privmx {
namespace endpoint {
namespace core {

#define INTERNAL_EVENT_CHANNEL_NAME "internal"

class Subscriber 
{
public:
    Subscriber(privmx::privfs::RpcGateway::Ptr gateway);
    std::vector<std::string> subscribeFor(const std::vector<std::string>& subscriptionQueries);
    void unsubscribeFrom(const std::vector<std::string>& subscriptionIds);
    void unsubscribeFromCurrentlySubscribed();
    std::optional<std::string> getSubscriptionQuery(const std::string& subscriptionId);
    std::optional<std::string> getSubscriptionQuery(const std::vector<std::string>& subscriptionIds);
private:
    virtual privmx::utils::List<std::string> transform(const std::vector<std::string>& subscriptionQueries) = 0;
    virtual void assertQuery(const std::vector<std::string>& subscriptionQueries) = 0;
    privmx::privfs::RpcGateway::Ptr _gateway;
    std::shared_mutex _map_mutex;
    std::map<std::string, std::string> _subscriptionIdToSubscriptionQuery;
};

} // core
} // endpoint
} // privmx


#endif  // _PRIVMXLIB_ENDPOINT_CORE_SUBSCRIBER_HPP_
