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
    static std::string buildQuery(const std::string& channelName, EventSelectorType selectorType, const std::string& selectorId);
private:
    virtual std::string transform(const std::string& subscriptionQuery);
    virtual void assertQuery(const std::string& subscriptionQuery);

    static std::string getChannel(const std::string& channelName);
    static std::string getSelector(EventSelectorType selectorType, const std::string& selectorId);
    static constexpr std::string_view _moduleName = "event";
    static const std::map<EventSelectorType, std::string> _selectorTypeNames;
    static const std::set<std::string> _forbiddenChannelsNames;
    static const std::map<EventSelectorType, std::string> _readableSelectorTyp;
};

} // event
} // endpoint
} // privmx


#endif  // _PRIVMXLIB_ENDPOINT_EVENT_SUBSCRIBERIMPL_HPP_
