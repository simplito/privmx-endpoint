/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include <privmx/endpoint/core/ExceptionConverter.hpp>
#include <privmx/endpoint/core/JsonSerializer.hpp>
#include <privmx/endpoint/core/EventVarSerializer.hpp>

#include "privmx/endpoint/inbox/Events.hpp"
#include "privmx/endpoint/inbox/InboxException.hpp"
#include "privmx/endpoint/inbox/InboxVarSerializer.hpp"
using namespace privmx::endpoint;
using namespace privmx::endpoint::inbox;

std::string InboxCreatedEvent::toJSON() const {
   return core::JsonSerializer<InboxCreatedEvent>::serialize(*this);
}

std::string InboxUpdatedEvent::toJSON() const {
   return core::JsonSerializer<InboxUpdatedEvent>::serialize(*this);
}

std::string InboxDeletedEvent::toJSON() const {
   return core::JsonSerializer<InboxDeletedEvent>::serialize(*this);
}

std::string InboxEntryCreatedEvent::toJSON() const {
   return core::JsonSerializer<InboxEntryCreatedEvent>::serialize(*this);
}

std::string InboxEntryDeletedEvent::toJSON() const {
   return core::JsonSerializer<InboxEntryDeletedEvent>::serialize(*this);
}

std::shared_ptr<core::SerializedEvent> InboxCreatedEvent::serialize() const {
   return std::make_shared<core::SerializedEvent>(core::SerializedEvent{core::EventVarSerializer::getInstance()->serialize(*this)});
}

std::shared_ptr<core::SerializedEvent> InboxUpdatedEvent::serialize() const {
   return std::make_shared<core::SerializedEvent>(core::SerializedEvent{core::EventVarSerializer::getInstance()->serialize(*this)});
}

std::shared_ptr<core::SerializedEvent> InboxDeletedEvent::serialize() const {
   return std::make_shared<core::SerializedEvent>(core::SerializedEvent{core::EventVarSerializer::getInstance()->serialize(*this)});
}

std::shared_ptr<core::SerializedEvent> InboxEntryCreatedEvent::serialize() const {
   return std::make_shared<core::SerializedEvent>(core::SerializedEvent{core::EventVarSerializer::getInstance()->serialize(*this)});
}

std::shared_ptr<core::SerializedEvent> InboxEntryDeletedEvent::serialize() const {
   return std::make_shared<core::SerializedEvent>(core::SerializedEvent{core::EventVarSerializer::getInstance()->serialize(*this)});
}


bool Events::isInboxCreatedEvent(const privmx::endpoint::core::EventHolder& eventHolder) {
    return eventHolder.type() == "inboxCreated";
}

InboxCreatedEvent Events::extractInboxCreatedEvent(const privmx::endpoint::core::EventHolder& eventHolder) {
    try {
        auto event = std::dynamic_pointer_cast<InboxCreatedEvent>(eventHolder.get());
        if (!event) {
            throw CannotExtractInboxCreatedEventException();
        }
        return *event;
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

bool Events::isInboxUpdatedEvent(const privmx::endpoint::core::EventHolder& eventHolder) {
    return eventHolder.type() == "inboxUpdated";
}

InboxUpdatedEvent Events::extractInboxUpdatedEvent(const privmx::endpoint::core::EventHolder& handler) {
    try {
        auto event = std::dynamic_pointer_cast<InboxUpdatedEvent>(handler.get());
        if (!event) {
            throw CannotExtractInboxUpdatedEventException();
        }
        return *event;
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

bool Events::isInboxDeletedEvent(const privmx::endpoint::core::EventHolder& eventHolder) {
    return eventHolder.type() == "inboxDeleted";
}

InboxDeletedEvent Events::extractInboxDeletedEvent(const privmx::endpoint::core::EventHolder& eventHolder) {
    try {
        auto event = std::dynamic_pointer_cast<InboxDeletedEvent>(eventHolder.get());
        if (!event) {
            throw CannotExtractInboxDeletedEventException();
        }
        return *event;
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

bool Events::isInboxEntryCreatedEvent(const core::EventHolder& eventHolder) {
    return eventHolder.type() == "inboxEntryCreated";
}

InboxEntryCreatedEvent Events::extractInboxEntryCreatedEvent(const core::EventHolder& eventHolder) {
    try {
        auto event = std::dynamic_pointer_cast<InboxEntryCreatedEvent>(eventHolder.get());
        if (!event) {
            throw CannotExtractInboxEntryCreatedEventException();
        }
        return *event;
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

bool Events::isInboxEntryDeletedEvent(const core::EventHolder& eventHolder) {
    return eventHolder.type() == "inboxEntryDeleted";
}

InboxEntryDeletedEvent Events::extractInboxEntryDeletedEvent(const core::EventHolder& eventHolder) {
    try {
        auto event = std::dynamic_pointer_cast<InboxEntryDeletedEvent>(eventHolder.get());
        if (!event) {
            throw CannotExtractInboxEntryDeletedException();
        }
        return *event;
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

