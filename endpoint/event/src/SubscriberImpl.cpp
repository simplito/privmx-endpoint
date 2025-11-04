#include "privmx/endpoint/event/SubscriberImpl.hpp"
#include "privmx/endpoint/event/EventException.hpp"
#include <algorithm>
#include <privmx/endpoint/core/CoreConstants.hpp>

using namespace privmx::endpoint;
using namespace privmx::endpoint::event;

const std::map<EventSelectorType, std::string> SubscriberImpl::_selectorTypeNames = {
    {EventSelectorType::CONTEXT_ID, "contextId"}
};

const std::set<std::string> SubscriberImpl::_forbiddenChannelsNames {
    INTERNAL_EVENT_CHANNEL_NAME
};

const std::map<EventSelectorType, std::string> SubscriberImpl::_readableSelectorType = {
    {EventSelectorType::CONTEXT_ID, "CONTEXT_ID"}
};

std::vector<std::string> SubscriberImpl::getChannelPath(const std::string& channelName) {
    return {std::string(_moduleName), std::string(_itemName), channelName};
}

std::vector<core::SubscriptionQueryObj::QuerySelector> SubscriberImpl::getSelectors(EventSelectorType selectorType, const std::string& selectorId) {
    return {core::SubscriptionQueryObj::QuerySelector{
        .selectorKey=_selectorTypeNames.at(selectorType), 
        .selectorValue=selectorId
    }};
}

std::string SubscriberImpl::buildQuery(const std::string& channelName, EventSelectorType selectorType, const std::string& selectorId, bool enableAllChannelNames) {
    std::set<std::string>::iterator it = _forbiddenChannelsNames.find(channelName);
    if(it == _forbiddenChannelsNames.end() || enableAllChannelNames) {
        return core::SubscriptionQueryObj(getChannelPath(channelName), getSelectors(selectorType, selectorId)).toSubscriptionQueryString();
    }
    std::string forbiddenChannelsNamesString;
    for(auto forbiddenChannelsName: _forbiddenChannelsNames) {
        forbiddenChannelsNamesString += forbiddenChannelsName + ", ";
    }
    forbiddenChannelsNamesString = forbiddenChannelsNamesString.substr(0, forbiddenChannelsNamesString.size()-2);
    throw ForbiddenChannelNameException(
        ("Forbidden channelName. Forbidden channel names are: " + forbiddenChannelsNamesString + ". Received \""+channelName+"\"")
    ); 
}

privmx::utils::List<std::string> SubscriberImpl::transform(const std::vector<core::SubscriptionQueryObj>& subscriptionQueries) {
    auto result = privmx::utils::TypedObjectFactory::createNewList<std::string>();
    for(auto s: subscriptionQueries) {
        auto transformedChannelPath = s.channelPath();
        transformedChannelPath[MODULE_NAME_IN_QUERY_PATH] = "context";
        s.channelPath(transformedChannelPath);
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
            subscriptionQuery.channelPath().size() != 3 || 
            subscriptionQuery.channelPath()[MODULE_NAME_IN_QUERY_PATH] != std::string(_moduleName) || 
            subscriptionQuery.channelPath()[ITEM_NAME_IN_QUERY_PATH] != std::string(_itemName)
        ) {
            throw InvalidSubscriptionQueryException();
        }
    }
}