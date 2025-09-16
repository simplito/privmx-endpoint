#include "privmx/endpoint/kvdb/SubscriberImpl.hpp"
#include "privmx/endpoint/kvdb/KvdbException.hpp"
#include <privmx/endpoint/core/CoreException.hpp>
#include "privmx/endpoint/kvdb/Types.hpp"
using namespace privmx::endpoint;
using namespace privmx::endpoint::kvdb;

const std::map<SubscriberImpl::EventInternalSelectorType, std::string> SubscriberImpl::_selectorTypeNames = {
    {EventInternalSelectorType::CONTEXT_ID, "contextId"},
    {EventInternalSelectorType::KVDB_ID, "containerId"},
    {EventInternalSelectorType::ENTRY_ID, "itemId"}
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
const std::map<EventType, std::set<SubscriberImpl::EventInternalSelectorType>> SubscriberImpl::_eventTypeAllowedSelectorTypes = {
    {EventType::KVDB_CREATE, {EventInternalSelectorType::CONTEXT_ID}},
    {EventType::KVDB_UPDATE, {EventInternalSelectorType::CONTEXT_ID, EventInternalSelectorType::KVDB_ID}},
    {EventType::KVDB_DELETE, {EventInternalSelectorType::CONTEXT_ID, EventInternalSelectorType::KVDB_ID}},
    {EventType::KVDB_STATS, {EventInternalSelectorType::CONTEXT_ID, EventInternalSelectorType::KVDB_ID}},
    {EventType::ENTRY_CREATE, {EventInternalSelectorType::CONTEXT_ID, EventInternalSelectorType::KVDB_ID}},
    {EventType::ENTRY_UPDATE, {EventInternalSelectorType::CONTEXT_ID, EventInternalSelectorType::KVDB_ID, EventInternalSelectorType::ENTRY_ID}},
    {EventType::ENTRY_DELETE, {EventInternalSelectorType::CONTEXT_ID, EventInternalSelectorType::KVDB_ID, EventInternalSelectorType::ENTRY_ID}},
    {EventType::COLLECTION_CHANGE, {EventInternalSelectorType::CONTEXT_ID, EventInternalSelectorType::KVDB_ID}}
};
const std::map<SubscriberImpl::EventInternalSelectorType, std::string> SubscriberImpl::_readableSelectorType = {
    {EventInternalSelectorType::CONTEXT_ID, "CONTEXT_ID"},
    {EventInternalSelectorType::KVDB_ID, "KVDB_ID"},
    {EventInternalSelectorType::ENTRY_ID, "ENTRY_KEY"}
};
const std::map<EventType, std::string> SubscriberImpl::_readableEventType = {
    {EventType::KVDB_CREATE, "KVDB_CREATE"},
    {EventType::KVDB_UPDATE, "KVDB_UPDATE"},
    {EventType::KVDB_DELETE, "KVDB_DELETE"},
    {EventType::KVDB_STATS, "KVDB_STATS"},
    {EventType::ENTRY_CREATE, "ENTRY_CREATE"},
    {EventType::ENTRY_UPDATE, "ENTRY_UPDATE"},
    {EventType::ENTRY_DELETE, "ENTRY_DELETE"},
    {EventType::COLLECTION_CHANGE, "COLLECTION_CHANGE"}
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
        case EventType::COLLECTION_CHANGE:
            return std::string(_moduleName) + "/collectionChanged";
    }
    throw NotImplementedException(_readableEventType.at(eventType));
}
std::string SubscriberImpl::getSelector(EventInternalSelectorType selectorType, const std::string& selectorId, const std::optional<std::string>& extraSelectorData) {
    if(selectorType == EventInternalSelectorType::ENTRY_ID && extraSelectorData.has_value()) {
        return "|" + _selectorTypeNames.at(selectorType) + "=" + extraSelectorData.value() + ":" + selectorId;
    } else if(selectorType == EventInternalSelectorType::ENTRY_ID && !extraSelectorData.has_value()) {
        throw core::InvalidParamsException(
            ("EventInternalSelectorType::ENTRY_ID missing extraSelectorData")
        ); 
    }
    return "|" + _selectorTypeNames.at(selectorType) + "=" + selectorId;
}

std::string SubscriberImpl::buildQuery(EventType eventType, EventSelectorType selectorType, const std::string& selectorId) {
    SubscriberImpl::EventInternalSelectorType selectorTypeInternal;
    switch (selectorType) {
        case EventSelectorType::CONTEXT_ID:
            selectorTypeInternal = SubscriberImpl::EventInternalSelectorType::CONTEXT_ID;
            break;
        case EventSelectorType::KVDB_ID:
            selectorTypeInternal = SubscriberImpl::EventInternalSelectorType::KVDB_ID;
            break;
    }
    std::set<EventInternalSelectorType> allowedSelectorTypes = _eventTypeAllowedSelectorTypes.at(eventType);
    std::set<EventInternalSelectorType>::iterator it = allowedSelectorTypes.find(selectorTypeInternal);
    if(it != allowedSelectorTypes.end()) {
        return getChannel(eventType) + getSelector(selectorTypeInternal, selectorId);
    }
    std::string allowedSelectorTypesString;
    for(auto allowedSelectorType: allowedSelectorTypes) {
        allowedSelectorTypesString += _readableSelectorType.at(allowedSelectorType) + " or ";
    }
    if(allowedSelectorTypes.size() > 0) {
        allowedSelectorTypesString = allowedSelectorTypesString.substr(0, allowedSelectorTypesString.size()-4);
    }
    throw core::InvalidParamsException(
        ("Invalid SelectorType for EventType::"+_readableEventType.at(eventType)+", expected " +allowedSelectorTypesString+ ", received " + _readableSelectorType.at(selectorTypeInternal))
    );
}

std::string SubscriberImpl::buildQueryForSelectedEntry(EventType eventType, const std::string& kvdbId, const std::string& kvdbEntryId) {
    std::set<EventInternalSelectorType> allowedSelectorTypes = _eventTypeAllowedSelectorTypes.at(eventType);
    std::set<EventInternalSelectorType>::iterator it = allowedSelectorTypes.find(EventInternalSelectorType::ENTRY_ID);
    if(it != allowedSelectorTypes.end()) {
        return getChannel(eventType) + getSelector(EventInternalSelectorType::ENTRY_ID, kvdbEntryId, kvdbId);
    }
    std::string allowedSelectorTypesString;
    for(auto allowedSelectorType: allowedSelectorTypes) {
        allowedSelectorTypesString += _readableSelectorType.at(allowedSelectorType) + " or ";
    }
    if(allowedSelectorTypes.size() > 0) {
        allowedSelectorTypesString = allowedSelectorTypesString.substr(0, allowedSelectorTypesString.size()-4);
    }
    throw core::InvalidParamsException(
        ("Invalid SelectorType for EventType::"+_readableEventType.at(eventType)+", expected " +allowedSelectorTypesString+ ", received " + _readableSelectorType.at(EventInternalSelectorType::ENTRY_ID))
    );
}


privmx::utils::List<std::string> SubscriberImpl::transform(const std::vector<std::string>& subscriptionQueries) {
    auto result = privmx::utils::TypedObjectFactory::createNewList<std::string>();
    for(auto& s: subscriptionQueries) {
        result.add(s + ",containerType=" + _typeFilterFlag);
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
