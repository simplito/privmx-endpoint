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

#include "privmx/endpoint/kvdb/Events.hpp"
#include "privmx/endpoint/kvdb/KvdbException.hpp"
#include "privmx/endpoint/kvdb/VarSerializer.hpp"

using namespace privmx::endpoint;
using namespace privmx::endpoint::kvdb;

std::string KvdbCreatedEvent::toJSON() const {
    return core::JsonSerializer<KvdbCreatedEvent>::serialize(*this);
}

std::string KvdbUpdatedEvent::toJSON() const {
    return core::JsonSerializer<KvdbUpdatedEvent>::serialize(*this);
}

std::string KvdbDeletedEvent::toJSON() const {
    return core::JsonSerializer<KvdbDeletedEvent>::serialize(*this);
}

std::string KvdbNewEntryEvent::toJSON() const {
    return core::JsonSerializer<KvdbNewEntryEvent>::serialize(*this);
}

std::string KvdbEntryUpdatedEvent::toJSON() const {
    return core::JsonSerializer<KvdbEntryUpdatedEvent>::serialize(*this);
}

std::string KvdbEntryDeletedEvent::toJSON() const {
    return core::JsonSerializer<KvdbEntryDeletedEvent>::serialize(*this);
}

std::string KvdbStatsChangedEvent::toJSON() const {
    return core::JsonSerializer<KvdbStatsChangedEvent>::serialize(*this);
}

std::shared_ptr<core::SerializedEvent> KvdbCreatedEvent::serialize() const {
    return std::make_shared<core::SerializedEvent>(core::SerializedEvent{core::EventVarSerializer::getInstance()->serialize(*this)});
}

std::shared_ptr<core::SerializedEvent> KvdbUpdatedEvent::serialize() const {
    return std::make_shared<core::SerializedEvent>(core::SerializedEvent{core::EventVarSerializer::getInstance()->serialize(*this)});
}

std::shared_ptr<core::SerializedEvent> KvdbDeletedEvent::serialize() const {
    return std::make_shared<core::SerializedEvent>(core::SerializedEvent{core::EventVarSerializer::getInstance()->serialize(*this)});
}

std::shared_ptr<core::SerializedEvent> KvdbNewEntryEvent::serialize() const {
    return std::make_shared<core::SerializedEvent>(core::SerializedEvent{core::EventVarSerializer::getInstance()->serialize(*this)});
}

std::shared_ptr<core::SerializedEvent> KvdbEntryUpdatedEvent::serialize() const {
    return std::make_shared<core::SerializedEvent>(core::SerializedEvent{core::EventVarSerializer::getInstance()->serialize(*this)});
}

std::shared_ptr<core::SerializedEvent> KvdbEntryDeletedEvent::serialize() const {
    return std::make_shared<core::SerializedEvent>(core::SerializedEvent{core::EventVarSerializer::getInstance()->serialize(*this)});
}

std::shared_ptr<core::SerializedEvent> KvdbStatsChangedEvent::serialize() const {
    return std::make_shared<core::SerializedEvent>(core::SerializedEvent{core::EventVarSerializer::getInstance()->serialize(*this)});
}
bool Events::isKvdbCreatedEvent(const core::EventHolder& handler) {
    return handler.type() == "kvdbCreated";
}

KvdbCreatedEvent Events::extractKvdbCreatedEvent(const core::EventHolder& handler) {
    try {
        auto event = std::dynamic_pointer_cast<KvdbCreatedEvent>(handler.get());
        if (!event) {
            throw CannotExtractKvdbCreatedEventException();
        }
        return *event;
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

bool Events::isKvdbUpdatedEvent(const core::EventHolder& handler) {
    return handler.type() == "kvdbUpdated";
}

KvdbUpdatedEvent Events::extractKvdbUpdatedEvent(const core::EventHolder& handler) {
    try {
        auto event = std::dynamic_pointer_cast<KvdbUpdatedEvent>(handler.get());
        if (!event) {
            throw CannotExtractKvdbUpdatedEventException();
        }
        return *event;
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

bool Events::isKvdbDeletedEvent(const core::EventHolder& handler) {
    return handler.type() == "kvdbDeleted";
}

KvdbDeletedEvent Events::extractKvdbDeletedEvent(const core::EventHolder& handler) {
    try {
        auto event = std::dynamic_pointer_cast<KvdbDeletedEvent>(handler.get());
        if (!event) {
            throw CannotExtractKvdbDeletedEventException();
        }
        return *event;
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

bool Events::isKvdbStatsEvent(const core::EventHolder& eventHolder) {
    return eventHolder.type() == "kvdbStatsChanged";
}

KvdbStatsChangedEvent Events::extractKvdbStatsEvent(const core::EventHolder& eventHolder) {
    try {
        auto event = std::dynamic_pointer_cast<KvdbStatsChangedEvent>(eventHolder.get());
        if (!event) {
            throw CannotExtractKvdbStatsEventException();
        }
        return *event;
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

bool Events::isKvdbNewEntryEvent(const core::EventHolder& handler) {
    return handler.type() == "kvdbNewEntry";
}

KvdbNewEntryEvent Events::extractKvdbNewEntryEvent(const core::EventHolder& handler) {
    try {
        auto event = std::dynamic_pointer_cast<KvdbNewEntryEvent>(handler.get());
        if (!event) {
            throw CannotExtractKvdbNewEntryEventException();
        }
        return *event;
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

bool Events::isKvdbEntryUpdatedEvent(const core::EventHolder& handler) {
    return handler.type() == "kvdbEntryUpdated";
}

KvdbEntryUpdatedEvent Events::extractKvdbEntryUpdatedEvent(const core::EventHolder& handler) {
    try {
        auto event = std::dynamic_pointer_cast<KvdbEntryUpdatedEvent>(handler.get());
        if (!event) {
            throw CannotExtractKvdbEntryUpdatedEventException();
        }
        return *event;
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

bool Events::isKvdbEntryDeletedEvent(const core::EventHolder& handler) {
    return handler.type() == "kvdbEntryDeleted";
}

KvdbEntryDeletedEvent Events::extractKvdbEntryDeletedEvent(const core::EventHolder& handler) {
    try {
        auto event = std::dynamic_pointer_cast<KvdbEntryDeletedEvent>(handler.get());
        if (!event) {
            throw CannotExtractKvdbDeletedEntryEventException();
        }
        return *event;
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

