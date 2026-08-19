#ifndef _PRIVMXLIB_ENDPOINT_GROUP_SUBSCRIBERIMPL_HPP_
#define _PRIVMXLIB_ENDPOINT_GROUP_SUBSCRIBERIMPL_HPP_

#include "privmx/endpoint/group/Types.hpp"
#include <privmx/endpoint/core/Subscriber.hpp>

namespace privmx {
namespace endpoint {
namespace group {

class SubscriberImpl : public privmx::endpoint::core::Subscriber {
public:
    SubscriberImpl(privmx::privfs::RpcGateway::Ptr gateway)
        : Subscriber(gateway) {}
    static std::string buildQuery(EventType eventType, EventSelectorType selectorType, const std::string& selectorId);

private:
    virtual std::vector<std::string> transform(const std::vector<core::SubscriptionQueryObj>& subscriptionQueries);
    virtual void assertQuery(const std::vector<core::SubscriptionQueryObj>& subscriptionQueries);

    static std::vector<std::string> getChannelPath(EventType eventType);
    static std::vector<core::SubscriptionQueryObj::QuerySelector> getSelectors(
        EventSelectorType selectorType,
        const std::string& selectorId
    );
    static constexpr std::string_view _moduleName = "context";
    static constexpr std::string_view _collectionName = "groups";
    static const std::map<EventSelectorType, std::string> _selectorTypeNames;
    static const std::map<EventType, std::string> _eventTypeNames;
    static const std::map<EventType, std::set<EventSelectorType>> _eventTypeAllowedSelectorTypes;
    static const std::map<EventSelectorType, std::string> _readableSelectorType;
    static const std::map<EventType, std::string> _readableEventType;
    constexpr static size_t MODULE_NAME_IN_QUERY_PATH = 0;
    constexpr static size_t COLLECTION_NAME_IN_QUERY_PATH = 1;
};

} // namespace group
} // namespace endpoint
} // namespace privmx

#endif // _PRIVMXLIB_ENDPOINT_GROUP_SUBSCRIBERIMPL_HPP_
