/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_ENDPOINT_CORE_EVENTMIDDLEWARE_HPP_
#define _PRIVMXLIB_ENDPOINT_CORE_EVENTMIDDLEWARE_HPP_

#include <Poco/JSON/Object.h>

#include <atomic>
#include <functional>
#include <privmx/utils/NotificationQueue.hpp>
#include <privmx/utils/ThreadSaveMap.hpp>
#include <vector>

#include "privmx/endpoint/core/EventQueueImpl.hpp"

namespace privmx {
namespace endpoint {
namespace core {

class EventMiddleware {
public:
    EventMiddleware(std::shared_ptr<EventQueueImpl> queue, const int64_t& connectionId);
    int addNotificationEventListener(const std::function<void(const std::string& type, const std::string& channel,
                                                              const Poco::JSON::Object::Ptr& data)>& callback);
    int addConnectedEventListener(const std::function<void()>& callback);
    int addDisconnectedEventListener(const std::function<void()>& callback);
    void removeNotificationEventListener(int id) noexcept;
    void removeConnectedEventListener(int id) noexcept;
    void removeDisconnectedEventListener(int id) noexcept;
    void emitNotificationEvent(const std::string& type, const std::string& channel,
                               const Poco::JSON::Object::Ptr& data);
    void emitConnectedEvent();
    void emitDisconnectedEvent();
    void emitApiEvent(const std::shared_ptr<Event>& event);

private:
    std::shared_ptr<EventQueueImpl> _queue;
    int64_t _connectionId;
    utils::ThreadSaveMap<int, std::function<void(const std::string& type, const std::string& channel,
                                                 const Poco::JSON::Object::Ptr& data)>>
        _notificationsListeners;
    utils::ThreadSaveMap<int, std::function<void()>> _connectedListeners;
    utils::ThreadSaveMap<int, std::function<void()>> _disconnectedListeners;
    std::atomic_int _id = 0;
};

inline void EventMiddleware::emitApiEvent(const std::shared_ptr<Event>& event) {
    event->connectionId = _connectionId;
    _queue->emit(event);
}

}  // namespace core
}  // namespace endpoint
}  // namespace privmx

#endif  // _PRIVMXLIB_ENDPOINT_CORE_EVENTMIDDLEWARE_HPP_
