/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_ENDPOINT_EVENT_SUBSCRIBERIMPL_HPP_
#define _PRIVMXLIB_ENDPOINT_EVENT_SUBSCRIBERIMPL_HPP_

#include <privmx/endpoint/core/Subscriber.hpp>
#include "privmx/endpoint/event/Types.hpp"

namespace privmx {
namespace endpoint {
namespace event {

class SubscriberImpl : public privmx::endpoint::core::Subscriber
{
public:
    
    SubscriberImpl(privmx::privfs::RpcGateway::Ptr gateway) : Subscriber(gateway) {}
    static std::string buildQuery(const std::string& channelName, EventSelectorType selectorType, const std::string& selectorId, bool enableAllChannelNames = false);
private:
    virtual privmx::utils::List<std::string> transform(const std::vector<core::SubscriptionQueryObj>& subscriptionQueries);
    virtual void assertQuery(const std::vector<core::SubscriptionQueryObj>& subscriptionQueries);

    static std::vector<std::string> getChannelPath(const std::string& channelName);
    static std::vector<core::SubscriptionQueryObj::QuerySelector> getSelectors(EventSelectorType selectorType, const std::string& selectorId);
    static constexpr std::string_view _moduleName = "event";
    static constexpr std::string_view _itemName = "custom";
    static const std::map<EventSelectorType, std::string> _selectorTypeNames;
    static const std::set<std::string> _forbiddenChannelsNames;
    static const std::map<EventSelectorType, std::string> _readableSelectorType;
    constexpr static size_t MODULE_NAME_IN_QUERY_PATH = 0;
    constexpr static size_t ITEM_NAME_IN_QUERY_PATH = 1;
};

} // event
} // endpoint
} // privmx


#endif  // _PRIVMXLIB_ENDPOINT_EVENT_SUBSCRIBERIMPL_HPP_
