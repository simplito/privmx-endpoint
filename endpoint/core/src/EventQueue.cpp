/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include <string>
#include <Poco/AutoPtr.h>

#include "privmx/endpoint/core/EventQueue.hpp"
#include "privmx/endpoint/core/JsonSerializer.hpp"
#include "privmx/endpoint/core/EventQueueImpl.hpp"
#include "privmx/endpoint/core/EventVarSerializer.hpp"

using namespace privmx::endpoint::core;

Event::Event(const std::string& type) : type(type) {}

EventHolder::EventHolder(const std::shared_ptr<Event>& event) : _event(event) {}

const std::string& EventHolder::type() const {
    return _event->type;
}

const std::string& EventHolder::channel() const {
    return _event->channel;
}

std::string EventHolder::toJSON() const {
    return _event->toJSON();
}

const std::shared_ptr<Event>& EventHolder::get() const {
    return _event;
}

EventQueue EventQueue::getInstance() {
    return EventQueue(EventQueueImpl::getInstance());
}

void EventQueue::emitBreakEvent() {
    return _impl->emitBreakEvent();
}

EventHolder EventQueue::waitEvent() {
    return _impl->waitEvent();
}

std::optional<EventHolder> EventQueue::getEvent() {
    return _impl->getEvent();
}