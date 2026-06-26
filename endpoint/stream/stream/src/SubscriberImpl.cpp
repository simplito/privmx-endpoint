#include "privmx/endpoint/stream/SubscriberImpl.hpp"
#include "privmx/endpoint/stream/StreamException.hpp"
#include <privmx/endpoint/core/CoreException.hpp>
#include <privmx/endpoint/stream/Types.hpp>
using namespace privmx::endpoint;
using namespace privmx::endpoint::stream;

const std::map<EventSelectorType, std::string> SubscriberImpl::_selectorTypeNames = {
    {EventSelectorType::CONTEXT_ID, "contextId"},
    {EventSelectorType::STREAMROOM_ID, "containerId"},
    {EventSelectorType::STREAM_ID, "itemId"}
};
const std::map<EventType, std::string> SubscriberImpl::_eventTypeNames = {
    {EventType::STREAMROOM_CREATE, "create"},       {EventType::STREAMROOM_UPDATE, "update"},
    {EventType::STREAMROOM_DELETE, "delete"},       {EventType::STREAMROOM_JOIN, "join"},
    {EventType::STREAMROOM_LEAVE, "leave"},         {EventType::STREAM_PUBLISH, "publish"},
    {EventType::STREAM_UNPUBLISH, "unpublish"},     {EventType::STREAM_SUBSCRIBE, "subscribe"},
    {EventType::STREAM_UNSUBSCRIBE, "unsubscribe"}, {EventType::STREAM_UPDATE, "update"}
};
const std::map<EventType, std::set<EventSelectorType>> SubscriberImpl::_eventTypeAllowedSelectorTypes = {
    {EventType::STREAMROOM_CREATE, {EventSelectorType::CONTEXT_ID}},
    {EventType::STREAMROOM_UPDATE, {EventSelectorType::CONTEXT_ID, EventSelectorType::STREAMROOM_ID}},
    {EventType::STREAMROOM_DELETE, {EventSelectorType::CONTEXT_ID, EventSelectorType::STREAMROOM_ID}},
    {EventType::STREAMROOM_JOIN, {EventSelectorType::CONTEXT_ID, EventSelectorType::STREAMROOM_ID}},
    {EventType::STREAMROOM_LEAVE, {EventSelectorType::CONTEXT_ID, EventSelectorType::STREAMROOM_ID}},
    {EventType::STREAM_PUBLISH, {EventSelectorType::CONTEXT_ID, EventSelectorType::STREAMROOM_ID}},
    {EventType::STREAM_UNPUBLISH, {EventSelectorType::CONTEXT_ID, EventSelectorType::STREAMROOM_ID}},
    {EventType::STREAM_SUBSCRIBE, {EventSelectorType::CONTEXT_ID, EventSelectorType::STREAMROOM_ID}},
    {EventType::STREAM_UNSUBSCRIBE, {EventSelectorType::CONTEXT_ID, EventSelectorType::STREAMROOM_ID}},
    {EventType::STREAM_UPDATE, {EventSelectorType::CONTEXT_ID, EventSelectorType::STREAMROOM_ID}}
};
const std::map<EventSelectorType, std::string> SubscriberImpl::_readableSelectorType = {
    {EventSelectorType::CONTEXT_ID, "CONTEXT_ID"},
    {EventSelectorType::STREAMROOM_ID, "STREAMROOM_ID"},
    {EventSelectorType::STREAM_ID, "STREAM_ID"}
};
const std::map<EventType, std::string> SubscriberImpl::_readableEventType = {
    {EventType::STREAMROOM_CREATE, "STREAMROOM_CREATE"},   {EventType::STREAMROOM_UPDATE, "STREAMROOM_UPDATE"},
    {EventType::STREAMROOM_DELETE, "STREAMROOM_DELETE"},   {EventType::STREAMROOM_JOIN, "STREAMROOM_JOIN"},
    {EventType::STREAMROOM_LEAVE, "STREAMROOM_LEAVE"},     {EventType::STREAM_PUBLISH, "STREAM_PUBLISH"},
    {EventType::STREAM_UNPUBLISH, "STREAM_UNPUBLISH"},     {EventType::STREAM_SUBSCRIBE, "STREAM_SUBSCRIBE"},
    {EventType::STREAM_UNSUBSCRIBE, "STREAM_UNSUBSCRIBE"}, {EventType::STREAM_UPDATE, "STREAM_UPDATE"}
};

std::string SubscriberImpl::getChannel(EventType eventType) {
    switch (eventType) {
    case EventType::STREAMROOM_CREATE:
    case EventType::STREAMROOM_UPDATE:
    case EventType::STREAMROOM_DELETE:
    case EventType::STREAMROOM_JOIN:
    case EventType::STREAMROOM_LEAVE:
        return std::string(_moduleName) + "/" + _eventTypeNames.at(eventType);
    case EventType::STREAM_PUBLISH:
    case EventType::STREAM_UNPUBLISH:
    case EventType::STREAM_UPDATE:
        return std::string(_moduleName) + "/" + std::string(_itemName) + "/" + _eventTypeNames.at(eventType);
    case EventType::STREAM_SUBSCRIBE:
    case EventType::STREAM_UNSUBSCRIBE:
        return std::string(_moduleName) + "/subscribers/" + _eventTypeNames.at(eventType);
    }
    throw NotImplementedException(_readableEventType.at(eventType));
}

std::string SubscriberImpl::getSelector(EventSelectorType selectorType, const std::string& selectorId) {
    return "|" + _selectorTypeNames.at(selectorType) + "=" + selectorId;
}

std::string SubscriberImpl::getInternalEventsSubscriptionQuery(const std::optional<std::string>& streamRoomId) {
    return std::string(_moduleName) +
        "/internal/reoffer" +
        (streamRoomId.has_value() ? getSelector(EventSelectorType::STREAMROOM_ID, streamRoomId.value()) : "");
}

std::string SubscriberImpl::buildQuery(
    EventType eventType,
    EventSelectorType selectorType,
    const std::string& selectorId
) {
    std::set<EventSelectorType> allowedEventSelectorTypes = _eventTypeAllowedSelectorTypes.at(eventType);
    std::set<EventSelectorType>::iterator it = allowedEventSelectorTypes.find(selectorType);
    if (it != allowedEventSelectorTypes.end()) {
        return getChannel(eventType) + getSelector(selectorType, selectorId);
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
        s.selectorsPushBack(
            core::SubscriptionQueryObj::QuerySelector{.selectorKey = "containerType", .selectorValue = _typeFilterFlag}
        );
        result.push_back(s.toSubscriptionQueryString());
    }
    return result;
}

void SubscriberImpl::assertQuery(const std::vector<core::SubscriptionQueryObj>& subscriptionQueries) {
    for (auto& subscriptionQuery : subscriptionQueries) {
        if (subscriptionQuery.selectors().size() != 1) {
            throw InvalidSubscriptionQueryException();
        }
        if (subscriptionQuery.channelPath().size() < 2 ||
            subscriptionQuery.channelPath().size() > 4 ||
            subscriptionQuery.channelPath()[MODULE_NAME_IN_QUERY_PATH] != std::string(_moduleName)) {
            throw InvalidSubscriptionQueryException();
        }
    }
}