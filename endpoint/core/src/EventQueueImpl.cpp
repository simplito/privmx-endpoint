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
#include <privmx/utils/SingletonSlot.hpp>

using namespace privmx::endpoint::core;

namespace {
privmx::utils::SingletonSlot<EventQueueImpl> slot;
} // namespace

std::shared_ptr<EventQueueImpl> EventQueueImpl::getInstance() {
    if (slot.ref() == nullptr) {
        slot.ref() = std::shared_ptr<EventQueueImpl>(new EventQueueImpl());
    }
    return slot.ref();
}

void EventQueueImpl::freeInstance() {
    // Znacznik sprawdzamy przed dotknieciem slotu - patrz SingletonSlot.
    if (!privmx::utils::SingletonSlot<EventQueueImpl>::alive()) {
        return;
    }
    slot.ref().reset();
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
    auto ret{dynamic_cast<Notification*>(notification.get())};
    if (ret) {
        return EventHolder(ret->data());
    } else {
        return std::nullopt;
    }
}

void EventQueueImpl::clear() {
    _queue.clear();
}
