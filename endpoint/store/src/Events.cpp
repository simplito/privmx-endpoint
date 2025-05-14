/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include <privmx/endpoint/core/ConnectionImpl.hpp>
#include <privmx/endpoint/store/StoreException.hpp>
#include <privmx/endpoint/core/JsonSerializer.hpp>
#include "privmx/endpoint/core/ExceptionConverter.hpp"

#include "privmx/endpoint/store/StoreApi.hpp"
#include "privmx/endpoint/store/StoreApiImpl.hpp"
#include "privmx/endpoint/store/StoreVarSerializer.hpp"
#include "privmx/endpoint/store/StoreValidator.hpp"
#include "privmx/endpoint/core/EventVarSerializer.hpp"

using namespace privmx::endpoint;
using namespace privmx::endpoint::store;

std::string StoreCreatedEvent::toJSON() const {
    return core::JsonSerializer<StoreCreatedEvent>::serialize(*this);
}

std::string StoreUpdatedEvent::toJSON() const {
    return core::JsonSerializer<StoreUpdatedEvent>::serialize(*this);
}

std::string StoreDeletedEvent::toJSON() const {
    return core::JsonSerializer<StoreDeletedEvent>::serialize(*this);
}

std::string StoreStatsChangedEvent::toJSON() const {
    return core::JsonSerializer<StoreStatsChangedEvent>::serialize(*this);
}

std::string StoreFileCreatedEvent::toJSON() const {
    return core::JsonSerializer<StoreFileCreatedEvent>::serialize(*this);
}

std::string StoreFileUpdatedEvent::toJSON() const {
    return core::JsonSerializer<StoreFileUpdatedEvent>::serialize(*this);
}

std::string StoreFileDeletedEvent::toJSON() const {
    return core::JsonSerializer<StoreFileDeletedEvent>::serialize(*this);
}

//
std::shared_ptr<core::SerializedEvent> StoreCreatedEvent::serialize() const {
    return std::make_shared<core::SerializedEvent>(core::SerializedEvent{core::EventVarSerializer::getInstance()->serialize(*this)});
}

std::shared_ptr<core::SerializedEvent> StoreUpdatedEvent::serialize() const {
    return std::make_shared<core::SerializedEvent>(core::SerializedEvent{core::EventVarSerializer::getInstance()->serialize(*this)});
}

std::shared_ptr<core::SerializedEvent> StoreDeletedEvent::serialize() const {
    return std::make_shared<core::SerializedEvent>(core::SerializedEvent{core::EventVarSerializer::getInstance()->serialize(*this)});
}

std::shared_ptr<core::SerializedEvent> StoreStatsChangedEvent::serialize() const {
    return std::make_shared<core::SerializedEvent>(core::SerializedEvent{core::EventVarSerializer::getInstance()->serialize(*this)});
}

std::shared_ptr<core::SerializedEvent> StoreFileCreatedEvent::serialize() const {
    return std::make_shared<core::SerializedEvent>(core::SerializedEvent{core::EventVarSerializer::getInstance()->serialize(*this)});
}

std::shared_ptr<core::SerializedEvent> StoreFileUpdatedEvent::serialize() const {
    return std::make_shared<core::SerializedEvent>(core::SerializedEvent{core::EventVarSerializer::getInstance()->serialize(*this)});
}

std::shared_ptr<core::SerializedEvent> StoreFileDeletedEvent::serialize() const {
    return std::make_shared<core::SerializedEvent>(core::SerializedEvent{core::EventVarSerializer::getInstance()->serialize(*this)});
}

//


bool Events::isStoreCreatedEvent(const core::EventHolder& handler) {
    return handler.type() == "storeCreated";
}

StoreCreatedEvent Events::extractStoreCreatedEvent(const core::EventHolder& handler) {
    try {
        auto event = std::dynamic_pointer_cast<StoreCreatedEvent>(handler.get());
        if (!event) {
            throw CannotExtractStoreCreatedEventException();
        }
        return *event;
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

bool Events::isStoreUpdatedEvent(const core::EventHolder& handler) {
    return handler.type() == "storeUpdated";
}

StoreUpdatedEvent Events::extractStoreUpdatedEvent(const core::EventHolder& handler) {
    try {
        auto event = std::dynamic_pointer_cast<StoreUpdatedEvent>(handler.get());
        if (!event) {
            throw CannotExtractStoreUpdatedEventException();
        }
        return *event;
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

bool Events::isStoreDeletedEvent(const core::EventHolder& handler) {
    return handler.type() == "storeDeleted";
}

StoreDeletedEvent Events::extractStoreDeletedEvent(const core::EventHolder& handler) {
    try {
        auto event = std::dynamic_pointer_cast<StoreDeletedEvent>(handler.get());
        if (!event) {
            throw CannotExtractStoreDeletedEventException();
        }
        return *event;
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

bool Events::isStoreStatsChangedEvent(const core::EventHolder& handler) {
    return handler.type() == "storeStatsChanged";
}

StoreStatsChangedEvent Events::extractStoreStatsChangedEvent(const core::EventHolder& handler) {
    try {
        auto event = std::dynamic_pointer_cast<StoreStatsChangedEvent>(handler.get());
        if (!event) {
            throw CannotExtractStoreStatsChangedEventException();
        }
        return *event;
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

bool Events::isStoreFileCreatedEvent(const core::EventHolder& handler) {
    return handler.type() == "storeFileCreated";
}

StoreFileCreatedEvent Events::extractStoreFileCreatedEvent(const core::EventHolder& handler) {
    try {
        auto event = std::dynamic_pointer_cast<StoreFileCreatedEvent>(handler.get());
        if (!event) {
            throw CannotExtractStoreFileCreatedEventException();
        }
        return *event;
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

bool Events::isStoreFileUpdatedEvent(const core::EventHolder& handler) {
    return handler.type() == "storeFileUpdated";
}

StoreFileUpdatedEvent Events::extractStoreFileUpdatedEvent(const core::EventHolder& handler) {
    try {
        auto event = std::dynamic_pointer_cast<StoreFileUpdatedEvent>(handler.get());
        if (!event) {
            throw CannotExtractStoreFileUpdatedEventException();
        }
        return *event;
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

bool Events::isStoreFileDeletedEvent(const core::EventHolder& handler) {
    return handler.type() == "storeFileDeleted";
}

StoreFileDeletedEvent Events::extractStoreFileDeletedEvent(const core::EventHolder& handler) {
    try {
        auto event = std::dynamic_pointer_cast<StoreFileDeletedEvent>(handler.get());
        if (!event) {
            throw CannotExtractStoreFileDeletedEventException();
        }
        return *event;
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}