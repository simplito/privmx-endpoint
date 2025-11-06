/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_ENDPOINT_INBOX_SUBSCRIBERIMPL_HPP_
#define _PRIVMXLIB_ENDPOINT_INBOX_SUBSCRIBERIMPL_HPP_

#include <privmx/endpoint/core/Subscriber.hpp>
#include "privmx/endpoint/inbox/Types.hpp"
#include "privmx/endpoint/inbox/ServerApi.hpp"

namespace privmx {
namespace endpoint {
namespace inbox {

class SubscriberImpl : public privmx::endpoint::core::Subscriber
{
public:
    
    SubscriberImpl(privmx::privfs::RpcGateway::Ptr gateway, std::string typeFilterFlag) : Subscriber(gateway), _serverApi(gateway), _typeFilterFlag(typeFilterFlag) {}
    static std::string buildQuery(EventType eventType, EventSelectorType selectorType, const std::string& selectorId);
    std::optional<std::string> convertKnownThreadIdToInboxId(const std::string& threadId);
private:
    virtual privmx::utils::List<std::string> transform(const std::vector<core::SubscriptionQueryObj>& subscriptionQueries);
    virtual void assertQuery(const std::vector<core::SubscriptionQueryObj>& subscriptionQueries);
    static std::vector<std::string> getChannelPath(EventType eventType);
    static std::vector<core::SubscriptionQueryObj::QuerySelector> getSelectors(EventSelectorType selectorType, const std::string& selectorId);
    void updateSubscriptionQuerySelectors(core::SubscriptionQueryObj& query);
    
    ServerApi _serverApi;
    std::string _typeFilterFlag;
    static constexpr std::string_view _moduleName = "inbox";
    static constexpr std::string_view _itemName = "entries";
    static const std::map<EventSelectorType, std::string> _selectorTypeNames;
    static const std::map<EventType, std::string> _eventTypeNames;
    static const std::map<EventType, std::set<EventSelectorType>> _eventTypeAllowedSelectorTypes;
    static const std::map<EventSelectorType, std::string> _readableSelectorType;
    static const std::map<EventType, std::string> _readableEventType;
    std::map<std::string, std::string> _threadIdToInboxId;
    constexpr static size_t MODULE_NAME_IN_QUERY_PATH = 0;
    constexpr static size_t ITEM_NAME_IN_QUERY_PATH = 1;
};

} // inbox
} // endpoint
} // privmx


#endif  // _PRIVMXLIB_ENDPOINT_INBOX_SUBSCRIBERIMPL_HPP_
