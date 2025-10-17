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
    {EventType::STREAMROOM_CREATE, "create"},
    {EventType::STREAMROOM_UPDATE, "update"},
    {EventType::STREAMROOM_DELETE, "delete"},
    {EventType::STREAM_JOIN, "join"},
    {EventType::STREAM_LEAVE, "leave"},
    {EventType::STREAM_PUBLISH, "publish"},
    {EventType::STREAM_UNPUBLISH, "unpublish"}
};
const std::map<EventType, std::set<EventSelectorType>> SubscriberImpl::_eventTypeAllowedSelectorTypes = {
    {EventType::STREAMROOM_CREATE, {EventSelectorType::CONTEXT_ID}},
    {EventType::STREAMROOM_UPDATE, {EventSelectorType::CONTEXT_ID, EventSelectorType::STREAMROOM_ID}},
    {EventType::STREAMROOM_DELETE, {EventSelectorType::CONTEXT_ID, EventSelectorType::STREAMROOM_ID}},
    {EventType::STREAM_JOIN, {EventSelectorType::CONTEXT_ID, EventSelectorType::STREAMROOM_ID}},
    {EventType::STREAM_LEAVE, {EventSelectorType::CONTEXT_ID, EventSelectorType::STREAMROOM_ID}},
    {EventType::STREAM_PUBLISH, {EventSelectorType::CONTEXT_ID, EventSelectorType::STREAMROOM_ID}},
    {EventType::STREAM_UNPUBLISH, {EventSelectorType::CONTEXT_ID, EventSelectorType::STREAMROOM_ID}}
};
const std::map<EventSelectorType, std::string> SubscriberImpl::_readableSelectorType = {
    {EventSelectorType::CONTEXT_ID, "CONTEXT_ID"},
    {EventSelectorType::STREAMROOM_ID, "STREAMROOM_ID"},
    {EventSelectorType::STREAM_ID, "STREAM_ID"}
};
const std::map<EventType, std::string> SubscriberImpl::_readableEventType = {
    {EventType::STREAMROOM_CREATE, "STREAMROOM_CREATE"},
    {EventType::STREAMROOM_UPDATE, "STREAMROOM_UPDATE"},
    {EventType::STREAMROOM_DELETE, "STREAMROOM_DELETE"},
    {EventType::STREAM_JOIN, "STREAM_JOIN"},
    {EventType::STREAM_LEAVE, "STREAM_LEAVE"},
    {EventType::STREAM_PUBLISH, "STREAM_PUBLISH"},
    {EventType::STREAM_UNPUBLISH, "STREAM_UNPUBLISH"}
};

std::string SubscriberImpl::getChannel(EventType eventType) {
    switch (eventType) {
        case EventType::STREAMROOM_CREATE:
        case EventType::STREAMROOM_UPDATE:
        case EventType::STREAMROOM_DELETE:
            return std::string(_moduleName) + "/" + _eventTypeNames.at(eventType);
        case EventType::STREAM_JOIN:
        case EventType::STREAM_LEAVE:
        case EventType::STREAM_PUBLISH:
        case EventType::STREAM_UNPUBLISH:
            return std::string(_moduleName) + "/" + std::string(_itemName)+ "/" + _eventTypeNames.at(eventType);
    }
    throw NotImplementedException(_readableEventType.at(eventType));
}

std::string SubscriberImpl::getSelector(EventSelectorType selectorType, const std::string& selectorId) {
    return "|" + _selectorTypeNames.at(selectorType) + "=" + selectorId;
}

std::string SubscriberImpl::getInternalEventsSubscriptionQuery() {
    return std::string(_moduleName) + "/internal";
}

std::string SubscriberImpl::buildQuery(EventType eventType, EventSelectorType selectorType, const std::string& selectorId) {
    std::set<EventSelectorType> allowedEventSelectorTypes = _eventTypeAllowedSelectorTypes.at(eventType);
    std::set<EventSelectorType>::iterator it = allowedEventSelectorTypes.find(selectorType);
    if(it != allowedEventSelectorTypes.end()) {
        return getChannel(eventType) + getSelector(selectorType, selectorId);
    }
    std::string allowedEventSelectorTypesString;
    for(auto allowedEventSelectorType: allowedEventSelectorTypes) {
        allowedEventSelectorTypesString += _readableSelectorType.at(allowedEventSelectorType) + " or ";
    }
    if(allowedEventSelectorTypes.size() > 0) {
        allowedEventSelectorTypesString = allowedEventSelectorTypesString.substr(0, allowedEventSelectorTypesString.size()-4);
    }
    throw core::InvalidParamsException(
        ("Invalid EventSelectorType for EventType::"+_readableEventType.at(eventType)+", expected " +allowedEventSelectorTypesString+ ", received " + _readableSelectorType.at(selectorType))
    ); 
}

privmx::utils::List<std::string> SubscriberImpl::transform(const std::vector<std::string>& subscriptionQueries) {
    auto result = privmx::utils::TypedObjectFactory::createNewList<std::string>();
    for(auto& s: subscriptionQueries) {
        result.add(s);
    }
    return result;
}

void SubscriberImpl::assertQuery(const std::vector<std::string>& subscriptionQueries) {
    for(auto& subscriptionQuery : subscriptionQueries) {
        if (subscriptionQuery == "streamroom/internal") {
            continue;
        }
        auto tmp = privmx::utils::Utils::split(subscriptionQuery, "|");
        if(tmp.size() != 2) {
            throw InvalidSubscriptionQueryException();
        }
        auto selectorData = privmx::utils::Utils::split(tmp[1], "=");
        if(selectorData.size() != 2) {
            throw InvalidSubscriptionQueryException();
        }
        auto channelData = privmx::utils::Utils::split(tmp[0], "/");
        if(channelData.size() < 2 || channelData.size() > 3 || channelData[0] != std::string(_moduleName)) {
            throw InvalidSubscriptionQueryException();
        }
    }
}