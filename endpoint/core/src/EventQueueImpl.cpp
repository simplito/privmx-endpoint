/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include "privmx/endpoint/core/EventQueueImpl.hpp"
#include <privmx/utils/Logger.hpp>

using namespace privmx::endpoint::core;

std::shared_ptr<EventQueueImpl> EventQueueImpl::impl= nullptr;

std::shared_ptr<EventQueueImpl> EventQueueImpl::getInstance() {
    if(impl == nullptr) {
        impl = std::shared_ptr<EventQueueImpl>(new EventQueueImpl());
    }
    return impl;
}

void EventQueueImpl::freeInstance() {
    if(impl) {
        impl.reset();
    }
}

void EventQueueImpl::emit(const std::shared_ptr<Event>& event) {
    _queue.enqueueNotification(new Notification(event));
}

void EventQueueImpl::emitBreakEvent() {
    _queue.enqueueNotification(new Notification(std::make_shared<LibBreakEvent>()));
}

EventHolder EventQueueImpl::waitEvent() {
    Poco::AutoPtr<Poco::Notification> notification(_queue.waitDequeueNotification());
    return EventHolder(dynamic_cast<Notification*>(notification.get())->data());
}

std::optional<EventHolder> EventQueueImpl::getEvent() {
    Poco::AutoPtr<Poco::Notification> notification(_queue.dequeueNotification());
    auto ret {dynamic_cast<Notification*>(notification.get())};
    if (ret) {
        return EventHolder(ret->data());
    }
    else {
        return std::nullopt;
    }
}

void EventQueueImpl::clear() {
    _queue.clear();
}
