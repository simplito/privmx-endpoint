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
#include <string>
#include <privmx/privfs/gateway/RpcGateway.hpp>
#include "privmx/endpoint/core/ServerTypes.hpp"

namespace privmx {
namespace endpoint {
namespace core {

class Subscriber 
{
public:
    Subscriber(privmx::privfs::RpcGateway::Ptr gateway);
    std::vector<std::string> subscribeFor(const std::vector<std::string>& subscriptionQueries);
    void unsubscribeFrom(const std::vector<std::string>& subscriptionIds);
private:
    virtual std::string transform(const std::string& subscriptionQuery) = 0;
    virtual void assertQuery(const std::string& subscriptionQuery) = 0;
    privmx::privfs::RpcGateway::Ptr _gateway;
};

} // core
} // endpoint
} // privmx


#endif  // _PRIVMXLIB_ENDPOINT_CORE_SUBSCRIBER_HPP_
