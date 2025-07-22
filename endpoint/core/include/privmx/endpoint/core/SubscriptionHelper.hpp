/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/



#ifndef _PRIVMXLIB_ENDPOINT_CORE_SUBSCRIPTION_HELPER_HPP_
#define _PRIVMXLIB_ENDPOINT_CORE_SUBSCRIPTION_HELPER_HPP_

#include <string>
#include <privmx/utils/ThreadSaveMap.hpp>
#include "privmx/endpoint/core/EventChannelManager.hpp"

namespace privmx {
namespace endpoint {
namespace core {

class SubscriptionHelper {
public:
    SubscriptionHelper(
        std::shared_ptr<EventChannelManager> eventChannelManager, 
        const std::string& moduleName, 
        const std::string& entryName = "item"
    );
    bool hasSubscriptionForModule(const std::vector<std::string>& eventTypes = std::vector<std::string>());
    bool hasSubscriptionForModuleEntry(const std::string& moduleId, const std::vector<std::string>& eventTypes = std::vector<std::string>());
    bool hasSubscriptionForSingleModuleCustomChannel(const std::string& moduleId, const std::string& channelName);
    bool hasSubscriptionForChannel(const std::string& fullChannel);
    bool hasSubscription(const std::vector<std::string>& subscriptionIds);
    std::string getChannel(const std::vector<std::string>& subscriptionIds);

    void subscribeForModule(const std::vector<std::string>& eventTypes = std::vector<std::string>());
    void unsubscribeFromModule(const std::vector<std::string>& eventTypes = std::vector<std::string>());
    void subscribeForModuleEntry(const std::string& moduleId, const std::vector<std::string>& eventTypes = std::vector<std::string>());
    void unsubscribeFromModuleEntry(const std::string& moduleId, const std::vector<std::string>& eventTypes = std::vector<std::string>());
    void subscribeForSingleModuleCustomChannel(const std::string& moduleId, const std::string&  channelName);
    void unsubscribeFromSingleModuleCustomChannel(const std::string& moduleId, const std::string&  channelName);

    void processSubscriptionNotificationEvent(const std::string& type, const core::NotificationEvent& notification);
    
    std::string getModuleChannel(const std::optional<std::string>& eventType = std::nullopt);
    std::string getModuleCustomChannel(const std::string& channelName);
    std::string getModuleEntryChannel(const std::string& moduleId, const std::optional<std::string>& eventType = std::nullopt);
    std::string getSingleModuleCustomChannel(const std::string& moduleId, const std::string& channelName);
private:
    
    void subscribeFor(const std::vector<std::string>& channels);
    void unsubscribeFor(const std::vector<std::string>& channels);

    std::shared_ptr<EventChannelManager> _eventChannelManager;
    std::string _moduleName;
    std::string _entryName;

    // fast search
    utils::ThreadSaveMap<std::string, std::string> _channelSubscriptionMap; // channel -> subscriptionId 
    utils::ThreadSaveMap<std::string, std::string> _subscriptionMap;        // subscriptionId -> channel
};

class SubscriptionHelperExt {
public:
    SubscriptionHelperExt(
        std::shared_ptr<EventChannelManager> eventChannelManager, 
        const std::string& moduleName, 
        const std::string& entryName = "item"
    );
    bool hasSubscriptionForModuleEntry(const std::string& moduleId);
    bool hasSubscriptionForChannel(const std::string& fullChannel);
    bool hasSubscription(const std::vector<std::string>& subscriptionIds);
    std::string getChannel(const std::vector<std::string>& subscriptionIds);
    std::string getParentModuleEntryId(const std::string& moduleId);

    void subscribeForModuleEntry(const std::string& moduleId, const std::string& parentModuleEntryId);
    void unsubscribeFromModuleEntry(const std::string& moduleId);
private:

    SubscriptionHelper _subscriptionHelper;
    std::string _moduleName;
    std::string _entryName;
    utils::ThreadSaveMap<std::string, std::string> _map;
};


} // core
} // endpoint
} // privmx

#endif // _PRIVMXLIB_ENDPOINT_CORE_SUBSCRIPTION_HELPER_HPP_