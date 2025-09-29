/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include "privmx/endpoint/core/EventMiddleware.hpp"
#include <algorithm>

using namespace privmx::endpoint::core;

EventMiddleware::EventMiddleware(std::shared_ptr<EventQueueImpl> queue, const int64_t& connectionId)
    : _queue(queue), _connectionId(connectionId) {}

int EventMiddleware::addNotificationEventListener(
    const std::function<void(const std::string& type, const NotificationEvent& notification)>& callback)
{
    int id = _id.fetch_add(1);
    _notificationsListeners.set(id, std::make_pair(callback, std::vector<std::string>()));
    return id;
}

int EventMiddleware::addConnectedEventListener(const std::function<void()>& callback) {
    int id = _id.fetch_add(1);
    _connectedListeners.set(id, callback);
    return id;
}

int EventMiddleware::addDisconnectedEventListener(const std::function<void()>& callback) {
    int id = _id.fetch_add(1);
    _disconnectedListeners.set(id, callback);
    return id;
}

void EventMiddleware::notificationEventListenerAddSubscriptionIds(int id, const std::vector<std::string>& subscriptionIds) {
    _notificationsListeners.updateValueIfExist(
        id, 
        [&](const std::pair<std::function<void(const std::string& type, const NotificationEvent& notification)>, std::vector<std::string>>& listener) {
            std::vector<std::string> newSubscriptionIds(listener.second);
            newSubscriptionIds.insert(newSubscriptionIds.end(), subscriptionIds.begin(), subscriptionIds.end());
            return std::make_pair(listener.first, newSubscriptionIds);
        }
    );
}

void EventMiddleware::notificationEventListenerRemoveSubscriptionIds(int id, const std::vector<std::string>& subscriptionIds) {
    _notificationsListeners.updateValueIfExist(
        id, 
        [&](const std::pair<std::function<void(const std::string& type, const NotificationEvent& notification)>, std::vector<std::string>>& listener) {
            std::vector<std::string> toRemove = subscriptionIds;
            std::vector<std::string> newSubscriptionIds;
            for(size_t i = 0; i < listener.second.size(); i++) {
                if(toRemove.size() > 0) {
                    auto it = std::find(toRemove.begin(), toRemove.end(), listener.second[i]);
                    if(it == toRemove.end()) {
                        toRemove.erase(it);
                    } else {
                        newSubscriptionIds.push_back(listener.second[i]);
                    }
                } else {
                    newSubscriptionIds.push_back(listener.second[i]);
                }
            } 
            return std::make_pair(listener.first, newSubscriptionIds);
        }
    );
}

void EventMiddleware::removeNotificationEventListener(int id) noexcept {
    try {
        _notificationsListeners.erase(id);
    } catch (...) {}
}

void EventMiddleware::removeConnectedEventListener(int id) noexcept {
    try {
        _connectedListeners.erase(id);
    } catch (...) {}
}

void EventMiddleware::removeDisconnectedEventListener(int id) noexcept {
    try {
        _disconnectedListeners.erase(id);
    } catch (...) {}
}

void EventMiddleware::emitNotificationEvent(const std::string& type, const NotificationEvent& notification) {
    
    _notificationsListeners.forAll(
        [&](
            [[maybe_unused]] const int& i, 
            const std::pair<std::function<void(const std::string& type, const NotificationEvent& notification)>, std::vector<std::string>>& listener
        ) {
            try {
                for(auto& s : notification.subscriptions) {
                   if(std::find(listener.second.begin(), listener.second.end(), s) != listener.second.end()) {
                        if(listener.first) {
                            std::cerr << "Pass event to listener... " << std::endl;
                            return listener.first(type, notification);
                        }
                   }
                }
            } catch (std::exception& e) {
                std::cerr << "Error on emitNotificationEvent:" << e.what() << std::endl;
            }
        });
}

void EventMiddleware::emitConnectedEvent() {
    _connectedListeners.forAll([&]([[maybe_unused]] const int& i, const std::function<void()>& listener) {
        try {
            if (listener) {
                listener();
            }
        } catch (...) {}
    });
}

void EventMiddleware::emitDisconnectedEvent() {
    _disconnectedListeners.forAll([&]([[maybe_unused]] const int& i, const std::function<void()>& listener) {
        try {
            if (listener) {
                listener();
            }
        } catch (...) {}
    });
}
