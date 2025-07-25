#include "privmx/endpoint/kvdb/SubscriberImpl.hpp"
#include "privmx/endpoint/kvdb/KvdbException.hpp"
#include <privmx/endpoint/core/CoreException.hpp>
#include "privmx/endpoint/kvdb/Types.hpp"
using namespace privmx::endpoint;
using namespace privmx::endpoint::kvdb;

const std::map<EventSelectorType, std::string> SubscriberImpl::_selectorTypeNames = {
    {EventSelectorType::CONTEXT_ID, "contextId"},
    {EventSelectorType::KVDB_ID, "containerId"},
    {EventSelectorType::ENTRY_ID, "itemId"}
};
const std::map<EventType, std::string> SubscriberImpl::_eventTypeNames = {
    {EventType::KVDB_CREATE, "create"},
    {EventType::KVDB_UPDATE, "update"},
    {EventType::KVDB_DELETE, "delete"},
    {EventType::KVDB_STATS, "stats"},
    {EventType::ENTRY_CREATE, "create"},
    {EventType::ENTRY_UPDATE, "update"},
    {EventType::ENTRY_DELETE, "delete"}
};
const std::map<EventType, std::set<EventSelectorType>> SubscriberImpl::_eventTypeAllowedSelectorTypes = {
    {EventType::KVDB_CREATE, {EventSelectorType::CONTEXT_ID}},
    {EventType::KVDB_UPDATE, {EventSelectorType::CONTEXT_ID, EventSelectorType::KVDB_ID}},
    {EventType::KVDB_DELETE, {EventSelectorType::CONTEXT_ID, EventSelectorType::KVDB_ID}},
    {EventType::KVDB_STATS, {EventSelectorType::CONTEXT_ID, EventSelectorType::KVDB_ID}},
    {EventType::ENTRY_CREATE, {EventSelectorType::KVDB_ID}},
    {EventType::ENTRY_UPDATE, {EventSelectorType::KVDB_ID, EventSelectorType::ENTRY_ID}},
    {EventType::ENTRY_DELETE, {EventSelectorType::KVDB_ID, EventSelectorType::ENTRY_ID}}
};
const std::map<EventSelectorType, std::string> SubscriberImpl::_readableSelectorTyp = {
    {EventSelectorType::CONTEXT_ID, "CONTEXT_ID"},
    {EventSelectorType::KVDB_ID, "KVDB_ID"},
    {EventSelectorType::ENTRY_ID, "ENTRY_ID"}
};
const std::map<EventType, std::string> SubscriberImpl::_readableEventType = {
    {EventType::KVDB_CREATE, "KVDB_CREATE"},
    {EventType::KVDB_UPDATE, "KVDB_UPDATE"},
    {EventType::KVDB_DELETE, "KVDB_DELETE"},
    {EventType::KVDB_STATS, "KVDB_STATS"},
    {EventType::ENTRY_CREATE, "ENTRY_CREATE"},
    {EventType::ENTRY_UPDATE, "ENTRY_UPDATE"},
    {EventType::ENTRY_DELETE, "ENTRY_DELETE"}
};

std::string SubscriberImpl::getChannel(EventType eventType) {
    switch (eventType) {
        case EventType::KVDB_CREATE:
        case EventType::KVDB_UPDATE:
        case EventType::KVDB_DELETE:
        case EventType::KVDB_STATS:
            return std::string(_moduleName) + "/" + _eventTypeNames.at(eventType);
        case EventType::ENTRY_CREATE:
        case EventType::ENTRY_UPDATE:
        case EventType::ENTRY_DELETE:
            return std::string(_moduleName) + "/" + std::string(_itemName) + "/" + _eventTypeNames.at(eventType);
    }
    throw NotImplementedException(_readableEventType.at(eventType));
}
std::string SubscriberImpl::getSelector(EventSelectorType selectorType, const std::string& selectorId) {
    return "|" + _selectorTypeNames.at(selectorType) + "=" + selectorId;
}
std::string SubscriberImpl::buildQuery(EventType eventType, EventSelectorType selectorType, const std::string& selectorId) {
    std::set<EventSelectorType> allowedSelectorTypes = _eventTypeAllowedSelectorTypes.at(eventType);
    std::set<EventSelectorType>::iterator it = allowedSelectorTypes.find(selectorType);
    if(it != allowedSelectorTypes.end()) {
        return getChannel(eventType) + getSelector(selectorType, selectorId);
    }
    std::string allowedSelectorTypesString;
    for(auto allowedSelectorType: allowedSelectorTypes) {
        allowedSelectorTypesString += _readableSelectorTyp.at(allowedSelectorType) + " or ";
    }
    if(allowedSelectorTypes.size() > 0) {
        allowedSelectorTypesString = allowedSelectorTypesString.substr(0, allowedSelectorTypesString.size()-4);
    }
    throw core::InvalidParamsException(
        ("Invalid SelectorType for EventType::"+_readableEventType.at(eventType)+", expected " +allowedSelectorTypesString+ ", received " + _readableSelectorTyp.at(selectorType))
    ); 
}

std::string SubscriberImpl::transform(const std::string& subscriptionQuery) {
    return subscriptionQuery;
}

void SubscriberImpl::assertQuery(const std::string& subscriptionQuery) {
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
