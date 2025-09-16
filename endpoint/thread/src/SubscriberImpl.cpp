#include "privmx/endpoint/thread/SubscriberImpl.hpp"
#include "privmx/endpoint/thread/ThreadException.hpp"
#include <privmx/endpoint/core/CoreException.hpp>
#include <privmx/endpoint/thread/Types.hpp>
using namespace privmx::endpoint;
using namespace privmx::endpoint::thread;

const std::map<EventSelectorType, std::string> SubscriberImpl::_selectorTypeNames = {
    {EventSelectorType::CONTEXT_ID, "contextId"},
    {EventSelectorType::THREAD_ID, "containerId"},
    {EventSelectorType::MESSAGE_ID, "itemId"}
};
const std::map<EventType, std::string> SubscriberImpl::_eventTypeNames = {
    {EventType::THREAD_CREATE, "create"},
    {EventType::THREAD_UPDATE, "update"},
    {EventType::THREAD_DELETE, "delete"},
    {EventType::THREAD_STATS, "stats"},
    {EventType::MESSAGE_CREATE, "create"},
    {EventType::MESSAGE_UPDATE, "update"},
    {EventType::MESSAGE_DELETE, "delete"}
};
const std::map<EventType, std::set<EventSelectorType>> SubscriberImpl::_eventTypeAllowedSelectorTypes = {
    {EventType::THREAD_CREATE, {EventSelectorType::CONTEXT_ID}},
    {EventType::THREAD_UPDATE, {EventSelectorType::CONTEXT_ID, EventSelectorType::THREAD_ID}},
    {EventType::THREAD_DELETE, {EventSelectorType::CONTEXT_ID, EventSelectorType::THREAD_ID}},
    {EventType::THREAD_STATS, {EventSelectorType::CONTEXT_ID, EventSelectorType::THREAD_ID}},
    {EventType::MESSAGE_CREATE, {EventSelectorType::CONTEXT_ID, EventSelectorType::THREAD_ID}},
    {EventType::MESSAGE_UPDATE, {EventSelectorType::CONTEXT_ID, EventSelectorType::THREAD_ID, EventSelectorType::MESSAGE_ID}},
    {EventType::MESSAGE_DELETE, {EventSelectorType::CONTEXT_ID, EventSelectorType::THREAD_ID, EventSelectorType::MESSAGE_ID}},
    {EventType::COLLECTION_CHANGE, {EventSelectorType::CONTEXT_ID, EventSelectorType::THREAD_ID}}
};
const std::map<EventSelectorType, std::string> SubscriberImpl::_readableSelectorType = {
    {EventSelectorType::CONTEXT_ID, "CONTEXT_ID"},
    {EventSelectorType::THREAD_ID, "THREAD_ID"},
    {EventSelectorType::MESSAGE_ID, "MESSAGE_ID"}
};
const std::map<EventType, std::string> SubscriberImpl::_readableEventType = {
    {EventType::THREAD_CREATE, "THREAD_CREATE"},
    {EventType::THREAD_UPDATE, "THREAD_UPDATE"},
    {EventType::THREAD_DELETE, "THREAD_DELETE"},
    {EventType::THREAD_STATS, "THREAD_STATS"},
    {EventType::MESSAGE_CREATE, "MESSAGE_CREATE"},
    {EventType::MESSAGE_UPDATE, "MESSAGE_UPDATE"},
    {EventType::MESSAGE_DELETE, "MESSAGE_DELETE"},
    {EventType::COLLECTION_CHANGE, "COLLECTION_CHANGE"}
};

std::string SubscriberImpl::getChannel(EventType eventType) {
    switch (eventType) {
        case EventType::THREAD_CREATE:
        case EventType::THREAD_UPDATE:
        case EventType::THREAD_DELETE:
        case EventType::THREAD_STATS:
            return std::string(_moduleName) + "/" + _eventTypeNames.at(eventType);
        case EventType::MESSAGE_CREATE:
        case EventType::MESSAGE_UPDATE:
        case EventType::MESSAGE_DELETE:
            return std::string(_moduleName) + "/" + std::string(_itemName) + "/" + _eventTypeNames.at(eventType);
        case EventType::COLLECTION_CHANGE:
            return std::string(_moduleName) + "/collectionChanged";
    }
    throw NotImplementedException(_readableEventType.at(eventType));
}

std::string SubscriberImpl::getSelector(EventSelectorType selectorType, const std::string& selectorId) {
    return "|" + _selectorTypeNames.at(selectorType) + "=" + selectorId;
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