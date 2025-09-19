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
    {EventType::FILE_DELETE, "delete"},
    {EventType::COLLECTION_CHANGE, "collectionChanged"}
};
const std::map<EventType, std::set<EventSelectorType>> SubscriberImpl::_eventTypeAllowedSelectorTypes = {
    {EventType::STORE_CREATE, {EventSelectorType::CONTEXT_ID}},
    {EventType::STORE_UPDATE, {EventSelectorType::CONTEXT_ID, EventSelectorType::STORE_ID}},
    {EventType::STORE_DELETE, {EventSelectorType::CONTEXT_ID, EventSelectorType::STORE_ID}},
    {EventType::STORE_STATS, {EventSelectorType::CONTEXT_ID, EventSelectorType::STORE_ID}},
    {EventType::FILE_CREATE, {EventSelectorType::CONTEXT_ID, EventSelectorType::STORE_ID}},
    {EventType::FILE_UPDATE, {EventSelectorType::CONTEXT_ID, EventSelectorType::STORE_ID, EventSelectorType::FILE_ID}},
    {EventType::FILE_DELETE, {EventSelectorType::CONTEXT_ID, EventSelectorType::STORE_ID, EventSelectorType::FILE_ID}},
    {EventType::COLLECTION_CHANGE, {EventSelectorType::CONTEXT_ID, EventSelectorType::STORE_ID}}
};
const std::map<EventSelectorType, std::string> SubscriberImpl::_readableSelectorType = {
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
    {EventType::FILE_DELETE, "FILE_DELETE"},
    {EventType::COLLECTION_CHANGE, "COLLECTION_CHANGE"}
};

std::vector<std::string> SubscriberImpl::getChannelPath(EventType eventType) {
    switch (eventType) {
        case EventType::STORE_CREATE:
        case EventType::STORE_UPDATE:
        case EventType::STORE_DELETE:
        case EventType::STORE_STATS:
        case EventType::COLLECTION_CHANGE:
            return {std::string(_moduleName), _eventTypeNames.at(eventType)};
        case EventType::FILE_CREATE:
        case EventType::FILE_UPDATE:
        case EventType::FILE_DELETE:
            return {std::string(_moduleName), std::string(_itemName), _eventTypeNames.at(eventType)};
    }
    throw NotImplementedException(_readableEventType.at(eventType));
}

std::vector<core::SubscriptionQueryObj::QuerySelector> SubscriberImpl::getSelectors(EventSelectorType selectorType, const std::string& selectorId) {
    return {core::SubscriptionQueryObj::QuerySelector{
        .selectorKey=_selectorTypeNames.at(selectorType), 
        .selectorValue=selectorId
    }};
}

std::string SubscriberImpl::buildQuery(EventType eventType, EventSelectorType selectorType, const std::string& selectorId) {
    std::set<EventSelectorType> allowedEventSelectorTypes = _eventTypeAllowedSelectorTypes.at(eventType);
    std::set<EventSelectorType>::iterator it = allowedEventSelectorTypes.find(selectorType);
    if(it != allowedEventSelectorTypes.end()) {
        return core::SubscriptionQueryObj(getChannelPath(eventType), getSelectors(selectorType, selectorId)).toSubscriptionQueryString();
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

privmx::utils::List<std::string> SubscriberImpl::transform(const std::vector<core::SubscriptionQueryObj>& subscriptionQueries) {
    auto result = privmx::utils::TypedObjectFactory::createNewList<std::string>();
    for(auto s: subscriptionQueries) {
        s.selectorsPushBack(core::SubscriptionQueryObj::QuerySelector{.selectorKey="containerType", .selectorValue=_typeFilterFlag});
        result.add(s.toSubscriptionQueryString());
    }
    return result;
}

void SubscriberImpl::assertQuery(const std::vector<core::SubscriptionQueryObj>& subscriptionQueries) {
    for(auto& subscriptionQuery : subscriptionQueries) {
        if(subscriptionQuery.selectors().size() != 1) {
            throw InvalidSubscriptionQueryException();
        }
        if(
            subscriptionQuery.channelPath().size() < 2 || 
            subscriptionQuery.channelPath().size() > 3 || 
            subscriptionQuery.channelPath()[MODULE_NAME_IN_QUERY_PATH] != std::string(_moduleName)
        ) {
            throw InvalidSubscriptionQueryException();
        }
    }
}