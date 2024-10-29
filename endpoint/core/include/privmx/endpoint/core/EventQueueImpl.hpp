#ifndef _PRIVMXLIB_ENDPOINT_CORE_EVENT_QUEUE_IMPL_HPP_
#define _PRIVMXLIB_ENDPOINT_CORE_EVENT_QUEUE_IMPL_HPP_

#include <atomic>
#include <functional>
#include <vector>
#include <Poco/JSON/Object.h>

#include <Poco/Notification.h>
#include <Poco/NotificationQueue.h>
#include <Poco/SharedPtr.h>

#include "privmx/endpoint/core/EventQueue.hpp"

namespace privmx {
namespace endpoint {
namespace core {

class EventQueueImpl
{
public:
    static std::shared_ptr<EventQueueImpl> getInstance();
    EventQueueImpl(const EventQueueImpl& obj) = delete; 
    void operator=(const EventQueueImpl &) = delete;

    void emit(const std::shared_ptr<Event>& event);
    void emitBreakEvent();
    EventHolder waitEvent();
    std::optional<EventHolder> getEvent();
    void clear();
protected:
    EventQueueImpl() {};

private:
    static std::shared_ptr<EventQueueImpl> impl;

    class Notification : public Poco::Notification
    {
    public:
        Notification(const std::shared_ptr<Event>& data) : _data(data) {}
        std::shared_ptr<Event> data() const {
            return _data;
        }

    private:
        std::shared_ptr<Event> _data;
    };
    Poco::NotificationQueue _queue;
};



} // core
} // endpoint
} // privmx

#endif // _PRIVMXLIB_ENDPOINT_CORE_EVENT_QUEUE_IMPL_HPP_
