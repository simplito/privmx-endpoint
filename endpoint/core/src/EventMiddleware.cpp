#include "privmx/endpoint/core/EventMiddleware.hpp"

using namespace privmx::endpoint::core;

EventMiddleware::EventMiddleware(std::shared_ptr<EventQueueImpl> queue, const int64_t& connectionId)
    : _queue(queue), _connectionId(connectionId) {}

int EventMiddleware::addNotificationEventListener(
    const std::function<void(const std::string& type, const std::string& channel, const Poco::JSON::Object::Ptr& data)>&
        callback) {
    int id = _id.fetch_add(1);
    _notificationsListeners.set(id, callback);
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

void EventMiddleware::emitNotificationEvent(const std::string& type, const std::string& channel,
                                            const Poco::JSON::Object::Ptr& data) {
    _notificationsListeners.forAll(
        [&]([[maybe_unused]] const int& i, const std::function<void(const std::string& type, const std::string& channel,
                                                                    const Poco::JSON::Object::Ptr& data)>& listener) {
            try {
                if (listener) {
                    listener(type, channel, data);
                }
            } catch (...) {}
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
