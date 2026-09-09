#include "privmx/endpoint/group/SubscriberImpl.hpp"
#include "privmx/endpoint/group/GroupException.hpp"
#include <privmx/endpoint/core/CoreException.hpp>
#include <privmx/endpoint/group/Types.hpp>

using namespace privmx::endpoint;
using namespace privmx::endpoint::group;

const std::map<EventSelectorType, std::string> SubscriberImpl::_selectorTypeNames = {
    {EventSelectorType::CONTEXT_ID, "contextId"},
    {EventSelectorType::GROUP_ID, "containerId"},
};
const std::map<EventType, std::string> SubscriberImpl::_eventTypeNames = {
    {EventType::GROUP_CREATE, "create"},
    {EventType::GROUP_UPDATE, "update"},
    {EventType::GROUP_DELETE, "delete"},
};
const std::map<EventType, std::set<EventSelectorType>> SubscriberImpl::_eventTypeAllowedSelectorTypes = {
    {EventType::GROUP_CREATE, {EventSelectorType::CONTEXT_ID}},
    {EventType::GROUP_UPDATE, {EventSelectorType::CONTEXT_ID, EventSelectorType::GROUP_ID}},
    {EventType::GROUP_DELETE, {EventSelectorType::CONTEXT_ID, EventSelectorType::GROUP_ID}},
};
const std::map<EventSelectorType, std::string> SubscriberImpl::_readableSelectorType = {
    {EventSelectorType::CONTEXT_ID, "CONTEXT_ID"},
    {EventSelectorType::GROUP_ID, "GROUP_ID"},
};
const std::map<EventType, std::string> SubscriberImpl::_readableEventType = {
    {EventType::GROUP_CREATE, "GROUP_CREATE"},
    {EventType::GROUP_UPDATE, "GROUP_UPDATE"},
    {EventType::GROUP_DELETE, "GROUP_DELETE"},
};

std::vector<std::string> SubscriberImpl::getChannelPath(EventType eventType) {
    switch (eventType) {
    case EventType::GROUP_CREATE:
    case EventType::GROUP_UPDATE:
    case EventType::GROUP_DELETE:
        return {std::string(_moduleName), std::string(_collectionName), _eventTypeNames.at(eventType)};
    }
    throw core::NotImplementedException(_readableEventType.at(eventType));
}

std::vector<std::string> SubscriberImpl::getCustomChannelPath(const std::string& channelName) {
    return {std::string(_moduleName), std::string(_collectionName), std::string(_customItemName), channelName};
}

/**
 * The channel name becomes one element of a subscription query, and the query is parsed by splitting on these
 * very characters. A name carrying one of them would not round-trip — worse, it would let a caller write extra
 * path elements or selectors into a query the bridge then honours. The bridge's own `wsChannelName` pattern
 * permits them, so this is the gate.
 */
void SubscriberImpl::assertChannelName(const std::string& channelName) {
    if (channelName.empty()) {
        throw core::InvalidParamsException("field:channelName must not be empty");
    }
    if (channelName.find_first_of("/|,=") != std::string::npos) {
        throw core::InvalidParamsException("field:channelName must not contain any of '/', '|', ',', '='");
    }
}

std::string SubscriberImpl::buildCustomEventQuery(
    const std::string& channelName,
    EventSelectorType selectorType,
    const std::string& selectorId
) {
    assertChannelName(channelName);
    return core::SubscriptionQueryObj(getCustomChannelPath(channelName), getSelectors(selectorType, selectorId))
        .toSubscriptionQueryString();
}

std::string SubscriberImpl::channelNameFromQuery(const std::string& subscriptionQuery) {
    auto path = core::SubscriptionQueryObj(subscriptionQuery).channelPath();
    if (path.size() != CUSTOM_QUERY_PATH_SIZE) {
        return "";
    }
    return path.at(CHANNEL_NAME_IN_QUERY_PATH);
}

std::vector<core::SubscriptionQueryObj::QuerySelector> SubscriberImpl::getSelectors(
    EventSelectorType selectorType,
    const std::string& selectorId
) {
    return {core::SubscriptionQueryObj::QuerySelector{
        .selectorKey = _selectorTypeNames.at(selectorType), .selectorValue = selectorId
    }};
}

std::string SubscriberImpl::buildQuery(
    EventType eventType,
    EventSelectorType selectorType,
    const std::string& selectorId
) {
    std::set<EventSelectorType> allowedEventSelectorTypes = _eventTypeAllowedSelectorTypes.at(eventType);
    std::set<EventSelectorType>::iterator it = allowedEventSelectorTypes.find(selectorType);
    if (it != allowedEventSelectorTypes.end()) {
        return core::SubscriptionQueryObj(getChannelPath(eventType), getSelectors(selectorType, selectorId))
            .toSubscriptionQueryString();
    }
    std::string allowedEventSelectorTypesString;
    for (auto allowedEventSelectorType : allowedEventSelectorTypes) {
        allowedEventSelectorTypesString += _readableSelectorType.at(allowedEventSelectorType) + " or ";
    }
    if (allowedEventSelectorTypes.size() > 0) {
        allowedEventSelectorTypesString = allowedEventSelectorTypesString.substr(
            0, allowedEventSelectorTypesString.size() - 4
        );
    }
    throw core::InvalidParamsException(
        ("Invalid EventSelectorType for EventType::" +
         _readableEventType.at(eventType) +
         ", expected " +
         allowedEventSelectorTypesString +
         ", received " +
         _readableSelectorType.at(selectorType))
    );
}

std::vector<std::string> SubscriberImpl::transform(const std::vector<core::SubscriptionQueryObj>& subscriptionQueries) {
    std::vector<std::string> result;
    for (auto s : subscriptionQueries) {
        result.push_back(s.toSubscriptionQueryString());
    }
    return result;
}

void SubscriberImpl::assertQuery(const std::vector<core::SubscriptionQueryObj>& subscriptionQueries) {
    for (auto& subscriptionQuery : subscriptionQueries) {
        if (subscriptionQuery.selectors().size() != 1) {
            throw InvalidSubscriptionQueryException();
        }
        const auto path = subscriptionQuery.channelPath();
        // Length first, and before anything indexes into it: the path was split out of a caller-supplied
        // string, so a short one is an ordinary input, not an impossibility. Three elements is a change event
        // (create/update/delete); four is a custom-event channel, whose fourth element the caller names.
        if (path.size() != CHANGE_QUERY_PATH_SIZE && path.size() != CUSTOM_QUERY_PATH_SIZE) {
            throw InvalidSubscriptionQueryException();
        }
        if (path[MODULE_NAME_IN_QUERY_PATH] != std::string(_moduleName) ||
            path[COLLECTION_NAME_IN_QUERY_PATH] != std::string(_collectionName)) {
            throw InvalidSubscriptionQueryException();
        }
        if (path.size() == CUSTOM_QUERY_PATH_SIZE) {
            if (path[CUSTOM_ITEM_NAME_IN_QUERY_PATH] != std::string(_customItemName)) {
                throw InvalidSubscriptionQueryException();
            }
            assertChannelName(path[CHANNEL_NAME_IN_QUERY_PATH]);
        }
    }
}
