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
        const std::string& entryName = "item",
        std::function<void()> onModuleSubscription = [](){},
        std::function<void()> onModuleUnsubscription = [](){}
    );
    bool hasSubscriptionForModule();
    bool hasSubscriptionForModuleEntry(const std::string& moduleId);
    bool hasSubscriptionForModuleEntryCustomChannel(const std::string& moduleId, const std::string& channelName);
    bool hasSubscriptionForChannel(const std::string& fullChannel);
    bool hasSubscription(const std::vector<std::string>& subscriptionIds);
    std::string getChannel(const std::vector<std::string>& subscriptionIds);

    void subscribeForModule();
    void unsubscribeFromModule();
    void subscribeForModuleEntry(const std::string& moduleId);
    void unsubscribeFromModuleEntry(const std::string& moduleId);
    void subscribeForModuleEntryCustomChannel(const std::string& moduleId, const std::string&  channelName);
    void unsubscribeFromModuleEntryCustomChannel(const std::string& moduleId, const std::string&  channelName);

    void processSubscriptionNotificationEvent(const std::string& type, const core::NotificationEvent& notification);
    
private:
    std::string getModuleEntryChannel(const std::string& moduleId);
    std::string getModuleEntryCustomChannel(const std::string& moduleId, const std::string& channelName);
    void subscribeFor(const std::vector<std::string>& channels);
    void unsubscribeFor(const std::vector<std::string>& channels);

    std::shared_ptr<EventChannelManager> _eventChannelManager;
    std::string _moduleName;
    std::string _entryName;

    bool _moduleCreateSubscription;
    bool _moduleUpdateSubscription;
    bool _moduleDeleteSubscription;
    bool _moduleStatsSubscription;
    std::function<void()> _onModuleSubscription;
    std::function<void()> _onModuleUnsubscription;
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
    bool hasSubscriptionForModuleEntryCustomChannel(const std::string& moduleId, const std::string& channelName);
    bool hasSubscriptionForChannel(const std::string& fullChannel);
    bool hasSubscription(const std::vector<std::string>& subscriptionIds);
    std::string getChannel(const std::vector<std::string>& subscriptionIds);
    std::string getParentModuleEntryId(const std::string& moduleId);

    void subscribeForModuleEntry(const std::string& moduleId, const std::string& parentModuleEntryId);
    void unsubscribeFromModuleEntry(const std::string& moduleId);
    void subscribeForModuleEntryCustomChannel(const std::string& moduleId, const std::string& parentModuleEntryId, const std::string& channelName);
    void unsubscribeFromModuleEntryCustomChannel(const std::string& moduleId, const std::string& channelName);
private:
    std::string getModuleEntryChannel(const std::string& moduleId);
    std::string getModuleEntryCustomChannel(const std::string& moduleId, const std::string& channelName);

    SubscriptionHelper _subscriptionHelper;
    std::string _moduleName;
    std::string _entryName;
    utils::ThreadSaveMap<std::string, std::string> _map;
    utils::ThreadSaveMap<std::string, std::string> _mapCustom;
};


} // core
} // endpoint
} // privmx

#endif // _PRIVMXLIB_ENDPOINT_CORE_SUBSCRIPTION_HELPER_HPP_