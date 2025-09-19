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

class SubscriptionQueryObj {
public:
    struct QuerySelector {
        std::string selectorKey;
        std::string selectorValue;
    };

    SubscriptionQueryObj(const std::vector<std::string>& channelPath, const std::vector<SubscriptionQueryObj::QuerySelector>& selectors);
    SubscriptionQueryObj(const std::string& subscriptionQueryString);
    std::string toSubscriptionQueryString() const;
   
    inline std::vector<std::string> channelPath() const {return _channelPath;}
    inline void channelPath(const std::vector<std::string>& channelPath) {_channelPath = channelPath;}
    inline std::vector<SubscriptionQueryObj::QuerySelector> selectors() const {return _selectors;}
    inline void selectorsPushBack(const SubscriptionQueryObj::QuerySelector& selector) {_selectors.push_back(selector);}
    inline void selectors(const std::vector<SubscriptionQueryObj::QuerySelector>& selectors) {_selectors = selectors;}

private:
    std::vector<std::string> _channelPath;
    std::vector<QuerySelector> _selectors;

    constexpr static char QUERY_MAIN_SEPARATOR = '|';
    constexpr static size_t QUERY_PATH_POS = 0;
    constexpr static size_t SELECTOR_POS = 1;
    constexpr static size_t QUERY_MAIN_MAX_SIZE = 2;
    constexpr static char QUERY_PATH_SEPARATOR = '/';

    constexpr static char SELECTORS_SEPARATOR = ',';
    constexpr static char SELECTOR_SEPARATOR = '=';
    constexpr static size_t SELECTOR_TYPE_POS = 0;
    constexpr static size_t SELECTOR_ID_POS = 1;
    constexpr static size_t SELECTOR_SIZE = 2;
};

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
    

    virtual privmx::utils::List<std::string> transform(const std::vector<SubscriptionQueryObj>& subscriptionQueries) = 0;
    virtual void assertQuery(const std::vector<SubscriptionQueryObj>& subscriptionQueries) = 0;
    
    privmx::privfs::RpcGateway::Ptr _gateway;
    std::shared_mutex _map_mutex;
    std::map<std::string, std::string> _subscriptionIdToSubscriptionQuery;
};

} // core
} // endpoint
} // privmx


#endif  // _PRIVMXLIB_ENDPOINT_CORE_SUBSCRIBER_HPP_
