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
    {EventType::ENTRY_DELETE, "delete"}
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

std::string SubscriberImpl::getChannel(EventType eventType) {
    switch (eventType) {
        case EventType::INBOX_CREATE:
        case EventType::INBOX_UPDATE:
        case EventType::INBOX_DELETE:
            return std::string(_moduleName) + "/" + _eventTypeNames.at(eventType);
        case EventType::ENTRY_CREATE:
        case EventType::ENTRY_DELETE:
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
    std::map<std::string, std::string> inboxIdToThreadId;
    auto result = privmx::utils::TypedObjectFactory::createNewList<std::string>();
    for(auto subscriptionQuery: subscriptionQueries) {
        auto tmp = privmx::utils::Utils::split(subscriptionQuery, "|");
        auto selector = tmp[1];
        auto channelData = privmx::utils::Utils::split(tmp[0], "/");
        std::string transformedSubscriptionQuery = subscriptionQuery;
        if(channelData.size() >= 2 && channelData[1] == std::string(_itemName)) {
            std::string query = "thread/messages";
            for(auto it = channelData.begin()+2; it != channelData.end(); it+=1) {
                query += "/" + (*it);
            }
            auto selectorData =privmx::utils::Utils::split(selector, "=");
            if(selectorData[0] == _selectorTypeNames.at(EventSelectorType::INBOX_ID)) {
                //getInbox to get threadId
                auto inboxId = selectorData[1];
                if(inboxIdToThreadId[inboxId] == "") {
                    auto model = Factory::createObject<server::InboxGetModel>();
                    model.id(inboxId);
                    auto inboxRaw = _serverApi.inboxGet(model).inbox();
                    auto threadId = inboxRaw.data().get(inboxRaw.data().size()-1).data().threadId();
                    inboxIdToThreadId[inboxId] = threadId;
                    _threadIdToInboxId[threadId] = inboxId;
                }
                std::string threadId = inboxIdToThreadId[inboxId];
                inboxIdToThreadId.insert_or_assign(inboxId, threadId);
                result.add( query+"|"+selectorData[0]+"="+threadId);
            } else {
                transformedSubscriptionQuery = query+"|"+selector + ",containerType=" + _typeFilterFlag;
            }
        } else if (channelData.size() >= 2 && channelData[1] == "collectionChanged") {
            transformedSubscriptionQuery = "thread/collectionChanged|" + selector + ",containerType=" + _typeFilterFlag;
        }
        result.add(transformedSubscriptionQuery);
    }
    return result;        
}

void SubscriberImpl::assertQuery(const std::vector<std::string>& subscriptionQueries) {
    for(auto& subscriptionQuery: subscriptionQueries) {
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

std::optional<std::string> SubscriberImpl::convertKnownThreadIdToInboxId(const std::string& threadId) {
    auto it = _threadIdToInboxId.find(threadId);
    if(it != _threadIdToInboxId.end()) {
        return it->second;
    }
    return std::nullopt;
}
