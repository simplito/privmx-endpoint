#include "privmx/endpoint/core/SubscriberImpl.hpp"
#include <privmx/endpoint/core/CoreException.hpp>
#include <privmx/endpoint/core/Types.hpp>
using namespace privmx::endpoint;
using namespace privmx::endpoint::core;

const std::map<EventSelectorType, std::string> SubscriberImpl::_selectorTypeNames = {
    {EventSelectorType::CONTEXT_ID, "contextId"}
};
const std::map<EventType, std::string> SubscriberImpl::_eventTypeNames = {
    {EventType::USER_ADD, "userAdded"},
    {EventType::USER_REMOVE, "userRemoved"},
    {EventType::USER_STATUS, "userStatus"}
};
const std::map<EventType, std::set<EventSelectorType>> SubscriberImpl::_eventTypeAllowedSelectorTypes = {
    {EventType::USER_ADD, {EventSelectorType::CONTEXT_ID}},
    {EventType::USER_REMOVE, {EventSelectorType::CONTEXT_ID}},
    {EventType::USER_STATUS, {EventSelectorType::CONTEXT_ID}}
};
const std::map<EventSelectorType, std::string> SubscriberImpl::_readableSelectorTyp = {
    {EventSelectorType::CONTEXT_ID, "CONTEXT_ID"}
};
const std::map<EventType, std::string> SubscriberImpl::_readableEventType = {
    {EventType::USER_ADD, "USER_ADD"},
    {EventType::USER_REMOVE, "USER_REMOVE"},
    {EventType::USER_STATUS, "USER_STATUS"}
};

std::vector<std::string> SubscriberImpl::getChannelPath(EventType eventType) {
    switch (eventType) {
        case EventType::USER_ADD:
        case EventType::USER_REMOVE:
        case EventType::USER_STATUS:
            return {std::string(_moduleName), _eventTypeNames.at(eventType)};
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
        allowedEventSelectorTypesString += _readableSelectorTyp.at(allowedEventSelectorType) + " or ";
    }
    if(allowedEventSelectorTypes.size() > 0) {
        allowedEventSelectorTypesString = allowedEventSelectorTypesString.substr(0, allowedEventSelectorTypesString.size()-4);
    }
    throw core::InvalidParamsException(
        ("Invalid EventSelectorType for EventType::"+_readableEventType.at(eventType)+", expected " +allowedEventSelectorTypesString+ ", received " + _readableSelectorTyp.at(selectorType))
    ); 
}

privmx::utils::List<std::string> SubscriberImpl::transform(const std::vector<core::SubscriptionQueryObj>& subscriptionQueries) {
    auto result = privmx::utils::TypedObjectFactory::createNewList<std::string>();
    for(auto s: subscriptionQueries) {
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