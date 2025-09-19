#include "privmx/endpoint/inbox/SubscriberImpl.hpp"
#include "privmx/endpoint/inbox/InboxException.hpp"
#include "privmx/endpoint/inbox/Factory.hpp"
#include <privmx/endpoint/core/CoreException.hpp>
using namespace privmx::endpoint;
using namespace privmx::endpoint::inbox;

const std::map<EventSelectorType, std::string> SubscriberImpl::_selectorTypeNames = {
    {EventSelectorType::CONTEXT_ID, "contextId"},
    {EventSelectorType::INBOX_ID, "containerId"},
    {EventSelectorType::ENTRY_ID, "itemId"}
};
const std::map<EventType, std::string> SubscriberImpl::_eventTypeNames = {
    {EventType::INBOX_CREATE, "create"},
    {EventType::INBOX_UPDATE, "update"},
    {EventType::INBOX_DELETE, "delete"},
    {EventType::ENTRY_CREATE, "create"},
    {EventType::ENTRY_DELETE, "delete"},
    {EventType::COLLECTION_CHANGE, "collectionChanged"}
};
const std::map<EventType, std::set<EventSelectorType>> SubscriberImpl::_eventTypeAllowedSelectorTypes = {
    {EventType::INBOX_CREATE, {EventSelectorType::CONTEXT_ID}},
    {EventType::INBOX_UPDATE, {EventSelectorType::CONTEXT_ID, EventSelectorType::INBOX_ID}},
    {EventType::INBOX_DELETE, {EventSelectorType::CONTEXT_ID, EventSelectorType::INBOX_ID}},
    {EventType::ENTRY_CREATE, {EventSelectorType::CONTEXT_ID, EventSelectorType::INBOX_ID}},
    {EventType::ENTRY_DELETE, {EventSelectorType::CONTEXT_ID, EventSelectorType::INBOX_ID, EventSelectorType::ENTRY_ID}},
    {EventType::COLLECTION_CHANGE, {EventSelectorType::CONTEXT_ID, EventSelectorType::INBOX_ID}}
};
const std::map<EventSelectorType, std::string> SubscriberImpl::_readableSelectorType = {
    {EventSelectorType::CONTEXT_ID, "CONTEXT_ID"},
    {EventSelectorType::INBOX_ID, "INBOX_ID"},
    {EventSelectorType::ENTRY_ID, "ENTRY_ID"}
};
const std::map<EventType, std::string> SubscriberImpl::_readableEventType = {
    {EventType::INBOX_CREATE, "INBOX_CREATE"},
    {EventType::INBOX_UPDATE, "INBOX_UPDATE"},
    {EventType::INBOX_DELETE, "INBOX_DELETE"},
    {EventType::ENTRY_CREATE, "ENTRY_CREATE"},
    {EventType::ENTRY_DELETE, "ENTRY_DELETE"},
    {EventType::COLLECTION_CHANGE, "COLLECTION_CHANGE"}
};

std::vector<std::string> SubscriberImpl::getChannelPath(EventType eventType) {
    switch (eventType) {
        case EventType::INBOX_CREATE:
        case EventType::INBOX_UPDATE:
        case EventType::INBOX_DELETE:
        case EventType::COLLECTION_CHANGE:
            return {std::string(_moduleName), _eventTypeNames.at(eventType)};
        case EventType::ENTRY_CREATE:
        case EventType::ENTRY_DELETE:
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
    std::map<std::string, std::string> inboxIdToThreadId;
    auto result = privmx::utils::TypedObjectFactory::createNewList<std::string>();
    for(auto subscriptionQuery: subscriptionQueries) {
        if(
            subscriptionQuery.channelPath().size() == 3 && 
            subscriptionQuery.channelPath()[MODULE_NAME_IN_QUERY_PATH] == std::string(_moduleName) && 
            subscriptionQuery.channelPath()[ITEM_NAME_IN_QUERY_PATH] == std::string(_itemName)
        ) {
            auto transformedChannelPath = subscriptionQuery.channelPath();
            transformedChannelPath[MODULE_NAME_IN_QUERY_PATH] = "thread";
            transformedChannelPath[ITEM_NAME_IN_QUERY_PATH] = "messages";
            subscriptionQuery.channelPath(transformedChannelPath);
            auto selectors = subscriptionQuery.selectors();
            size_t inboxSelectorPos;
            for(inboxSelectorPos = 0; inboxSelectorPos < selectors.size(); inboxSelectorPos++) {
                if(selectors[inboxSelectorPos].selectorKey == _selectorTypeNames.at(EventSelectorType::INBOX_ID)) {
                    break;
                }
            }
            if(inboxSelectorPos < selectors.size()) {
                //getInbox to get threadId
                auto inboxId = selectors[inboxSelectorPos].selectorValue;
                if(inboxIdToThreadId[inboxId] == "") {
                    auto model = Factory::createObject<server::InboxGetModel>();
                    model.id(inboxId);
                    auto inboxRaw = _serverApi.inboxGet(model).inbox();
                    auto threadId = inboxRaw.data().get(inboxRaw.data().size()-1).data().threadId();
                    inboxIdToThreadId[inboxId] = threadId;
                    _threadIdToInboxId[threadId] = inboxId;
                }
                std::string threadId = inboxIdToThreadId[inboxId];
                selectors[inboxSelectorPos].selectorValue = threadId;
                subscriptionQuery.selectors(selectors);
            } else {
                subscriptionQuery.selectorsPushBack(core::SubscriptionQueryObj::QuerySelector{.selectorKey="containerType", .selectorValue=_typeFilterFlag});
            }
        } else if (
            subscriptionQuery.channelPath().size() == 2 && 
            subscriptionQuery.channelPath()[MODULE_NAME_IN_QUERY_PATH] == std::string(_moduleName) && 
            subscriptionQuery.channelPath()[subscriptionQuery.channelPath().size()-1] == _eventTypeNames.at(EventType::COLLECTION_CHANGE)
        ) {
            subscriptionQuery.channelPath({"thread", _eventTypeNames.at(EventType::COLLECTION_CHANGE)});
            subscriptionQuery.selectorsPushBack(core::SubscriptionQueryObj::QuerySelector{.selectorKey="containerType", .selectorValue=_typeFilterFlag});
        }
        result.add(subscriptionQuery.toSubscriptionQueryString());
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

std::optional<std::string> SubscriberImpl::convertKnownThreadIdToInboxId(const std::string& threadId) {
    auto it = _threadIdToInboxId.find(threadId);
    if(it != _threadIdToInboxId.end()) {
        return it->second;
    }
    return std::nullopt;
}
