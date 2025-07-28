#include "privmx/endpoint/store/SubscriberImpl.hpp"
#include "privmx/endpoint/store/StoreException.hpp"
#include <privmx/endpoint/core/CoreException.hpp>
#include "privmx/endpoint/store/Types.hpp"
using namespace privmx::endpoint;
using namespace privmx::endpoint::store;

const std::map<EventSelectorType, std::string> SubscriberImpl::_selectorTypeNames = {
    {EventSelectorType::CONTEXT_ID, "contextId"},
    {EventSelectorType::STORE_ID, "containerId"},
    {EventSelectorType::FILE_ID, "itemId"}
};
const std::map<EventType, std::string> SubscriberImpl::_eventTypeNames = {
    {EventType::STORE_CREATE, "create"},
    {EventType::STORE_UPDATE, "update"},
    {EventType::STORE_DELETE, "delete"},
    {EventType::STORE_STATS, "stats"},
    {EventType::FILE_CREATE, "create"},
    {EventType::FILE_UPDATE, "update"},
    {EventType::FILE_DELETE, "delete"}
};
const std::map<EventType, std::set<EventSelectorType>> SubscriberImpl::_eventTypeAllowedSelectorTypes = {
    {EventType::STORE_CREATE, {EventSelectorType::CONTEXT_ID}},
    {EventType::STORE_UPDATE, {EventSelectorType::CONTEXT_ID, EventSelectorType::STORE_ID}},
    {EventType::STORE_DELETE, {EventSelectorType::CONTEXT_ID, EventSelectorType::STORE_ID}},
    {EventType::STORE_STATS, {EventSelectorType::CONTEXT_ID, EventSelectorType::STORE_ID}},
    {EventType::FILE_CREATE, {EventSelectorType::STORE_ID}},
    {EventType::FILE_UPDATE, {EventSelectorType::FILE_ID}},
    {EventType::FILE_DELETE, {EventSelectorType::STORE_ID, EventSelectorType::FILE_ID}}
};
const std::map<EventSelectorType, std::string> SubscriberImpl::_readableSelectorTyp = {
    {EventSelectorType::CONTEXT_ID, "CONTEXT_ID"},
    {EventSelectorType::STORE_ID, "STORE_ID"},
    {EventSelectorType::FILE_ID, "FILE_ID"}
};
const std::map<EventType, std::string> SubscriberImpl::_readableEventType = {
    {EventType::STORE_CREATE, "STORE_CREATE"},
    {EventType::STORE_UPDATE, "STORE_UPDATE"},
    {EventType::STORE_DELETE, "STORE_DELETE"},
    {EventType::STORE_STATS, "STORE_STATS"},
    {EventType::FILE_CREATE, "FILE_CREATE"},
    {EventType::FILE_UPDATE, "FILE_UPDATE"},
    {EventType::FILE_DELETE, "FILE_DELETE"}
};

std::string SubscriberImpl::getChannel(EventType eventType) {
    switch (eventType) {
        case EventType::STORE_CREATE:
        case EventType::STORE_UPDATE:
        case EventType::STORE_DELETE:
        case EventType::STORE_STATS:
            return std::string(_moduleName) + "/" + _eventTypeNames.at(eventType);
        case EventType::FILE_CREATE:
        case EventType::FILE_UPDATE:
        case EventType::FILE_DELETE:
            return std::string(_moduleName) + "/" + std::string(_itemName) + "/" + _eventTypeNames.at(eventType);
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
        allowedEventSelectorTypesString += _readableSelectorTyp.at(allowedEventSelectorType) + " or ";
    }
    if(allowedEventSelectorTypes.size() > 0) {
        allowedEventSelectorTypesString = allowedEventSelectorTypesString.substr(0, allowedEventSelectorTypesString.size()-4);
    }
    throw core::InvalidParamsException(
        ("Invalid EventSelectorType for EventType::"+_readableEventType.at(eventType)+", expected " +allowedEventSelectorTypesString+ ", received " + _readableSelectorTyp.at(selectorType))
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
