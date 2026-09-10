#ifndef _PRIVMXLIB_ENDPOINT_GROUP_SUBSCRIBERIMPL_HPP_
#define _PRIVMXLIB_ENDPOINT_GROUP_SUBSCRIBERIMPL_HPP_

#include "privmx/endpoint/group/Types.hpp"
#include <privmx/endpoint/core/Subscriber.hpp>

namespace privmx {
namespace endpoint {
namespace group {

class SubscriberImpl : public privmx::endpoint::core::Subscriber {
public:
    SubscriberImpl(privmx::privfs::RpcGateway::Ptr gateway) : Subscriber(gateway) {}
    static std::string buildQuery(EventType eventType, EventSelectorType selectorType, const std::string& selectorId);
    /**
     * A custom-event channel is named by the caller, so it cannot ride the `EventType` enum. Both selector
     * types are allowed: a whole Context's worth of Groups, or one Group.
     */
    static std::string buildCustomEventQuery(
        const std::string& channelName,
        EventSelectorType selectorType,
        const std::string& selectorId
    );
    /** Reads the channel name back out of a custom-event subscription query. */
    static std::string channelNameFromQuery(const std::string& subscriptionQuery);

private:
    virtual std::vector<std::string> transform(const std::vector<core::SubscriptionQueryObj>& subscriptionQueries);
    virtual void assertQuery(const std::vector<core::SubscriptionQueryObj>& subscriptionQueries);

    static std::vector<std::string> getChannelPath(EventType eventType);
    static std::vector<std::string> getCustomChannelPath(const std::string& channelName);
    static void assertChannelName(const std::string& channelName);
    static std::vector<core::SubscriptionQueryObj::QuerySelector> getSelectors(
        EventSelectorType selectorType,
        const std::string& selectorId
    );
    static constexpr std::string_view _moduleName = "context";
    static constexpr std::string_view _collectionName = "groups";
    static constexpr std::string_view _customItemName = "custom";
    static const std::map<EventSelectorType, std::string> _selectorTypeNames;
    static const std::map<EventType, std::string> _eventTypeNames;
    static const std::map<EventType, std::set<EventSelectorType>> _eventTypeAllowedSelectorTypes;
    static const std::map<EventSelectorType, std::string> _readableSelectorType;
    static const std::map<EventType, std::string> _readableEventType;
    constexpr static size_t MODULE_NAME_IN_QUERY_PATH = 0;
    constexpr static size_t COLLECTION_NAME_IN_QUERY_PATH = 1;
    constexpr static size_t CUSTOM_ITEM_NAME_IN_QUERY_PATH = 2;
    constexpr static size_t CHANNEL_NAME_IN_QUERY_PATH = 3;
    constexpr static size_t CHANGE_QUERY_PATH_SIZE = 3;
    constexpr static size_t CUSTOM_QUERY_PATH_SIZE = 4;
};

} // namespace group
} // namespace endpoint
} // namespace privmx

#endif // _PRIVMXLIB_ENDPOINT_GROUP_SUBSCRIBERIMPL_HPP_
