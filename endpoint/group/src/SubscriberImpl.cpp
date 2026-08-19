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
        // The bridge addresses groups as a collection inside the context module — `context/groups/<event>`, the
        // same shape kvdb uses for its entries. A two-segment path matches nothing: the server compares the
        // subscription path against the event channel by equality or a prefix ending in a slash (BR-37).
        return {std::string(_moduleName), std::string(_collectionName), _eventTypeNames.at(eventType)};
    }
    throw core::NotImplementedException(_readableEventType.at(eventType));
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
        // `context/groups/<event>`: the module, the collection, the event. Three segments, like kvdb's entries —
        // a two-segment path is the shape that silently matched nothing before (BR-37/EP-24).
        if (subscriptionQuery.channelPath().size() != 3 ||
            subscriptionQuery.channelPath()[MODULE_NAME_IN_QUERY_PATH] != std::string(_moduleName) ||
            subscriptionQuery.channelPath()[COLLECTION_NAME_IN_QUERY_PATH] != std::string(_collectionName)) {
            throw InvalidSubscriptionQueryException();
        }
    }
}
