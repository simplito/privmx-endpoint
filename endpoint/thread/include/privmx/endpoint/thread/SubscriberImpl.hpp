/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_ENDPOINT_THREAD_SUBSCRIBERIMPL_HPP_
#define _PRIVMXLIB_ENDPOINT_THREAD_SUBSCRIBERIMPL_HPP_

#include <privmx/endpoint/core/Subscriber.hpp>
#include "privmx/endpoint/thread/Types.hpp"

namespace privmx {
namespace endpoint {
namespace thread {

class SubscriberImpl : public privmx::endpoint::core::Subscriber
{
public:
    
    SubscriberImpl(privmx::privfs::RpcGateway::Ptr gateway) : Subscriber(gateway) {}
    static std::string buildQuery(EventType eventType, EventSelectorType selectorType, const std::string& selectorId);
private:
    virtual privmx::utils::List<std::string> transform(const std::vector<std::string>& subscriptionQueries);
    virtual void assertQuery(const std::vector<std::string>& subscriptionQueries);

    static std::string getChannel(EventType eventType);
    static std::string getSelector(EventSelectorType selectorType, const std::string& selectorId);
    static constexpr std::string_view _moduleName = "thread";
    static constexpr std::string_view _itemName = "messages";
    static const std::map<EventSelectorType, std::string> _selectorTypeNames;
    static const std::map<EventType, std::string> _eventTypeNames;
    static const std::map<EventType, std::set<EventSelectorType>> _eventTypeAllowedSelectorTypes;
    static const std::map<EventSelectorType, std::string> _readableSelectorType;
    static const std::map<EventType, std::string> _readableEventType;
};

} // thread
} // endpoint
} // privmx


#endif  // _PRIVMXLIB_ENDPOINT_THREAD_SUBSCRIBERIMPL_HPP_
