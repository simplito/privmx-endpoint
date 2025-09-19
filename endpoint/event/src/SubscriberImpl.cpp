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

std::string SubscriberImpl::getChannel(const std::string& channelName) {
    return std::string(_moduleName) + "/custom/" + channelName;
}

std::string SubscriberImpl::getSelector(EventSelectorType selectorType, const std::string& selectorId) {
    return "|" + _selectorTypeNames.at(selectorType) + "=" + selectorId;
}

std::string SubscriberImpl::buildQuery(const std::string& channelName, EventSelectorType selectorType, const std::string& selectorId, bool enableAllChannelNames) {
    std::set<std::string>::iterator it = _forbiddenChannelsNames.find(channelName);
    if(it == _forbiddenChannelsNames.end() || enableAllChannelNames) {
        return getChannel(channelName) + getSelector(selectorType, selectorId);
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

privmx::utils::List<std::string> SubscriberImpl::transform(const std::vector<std::string>& subscriptionQueries) {
    auto result = privmx::utils::TypedObjectFactory::createNewList<std::string>();
    for(auto& subscriptionQuery: subscriptionQueries) {
        auto tmp = privmx::utils::Utils::split(subscriptionQuery, "|");
        auto selectorData = tmp[1];
        auto channelData = privmx::utils::Utils::split(tmp[0], "/");
        std::string query = "context";
        for(auto it = channelData.begin()+1; it != channelData.end(); it+=1) {
            query += "/" + (*it);
        }
        result.add(query+"|"+selectorData);
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
        if(channelData.size() != 3 || channelData[0] != std::string(_moduleName) || channelData[1] != "custom") {
            throw InvalidSubscriptionQueryException();
        }
    }
}