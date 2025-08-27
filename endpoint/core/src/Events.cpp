/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include "privmx/endpoint/core/Events.hpp"

#include "privmx/endpoint/core/CoreException.hpp"
#include "privmx/endpoint/core/EventVarSerializer.hpp"
#include "privmx/endpoint/core/ExceptionConverter.hpp"
#include "privmx/endpoint/core/JsonSerializer.hpp"
#include "privmx/utils/PrivmxException.hpp"

using namespace privmx::endpoint::core;

std::string LibBreakEvent::toJSON() const {
    return core::JsonSerializer<LibBreakEvent>::serialize(*this);
}

std::string LibPlatformDisconnectedEvent::toJSON() const {
    return core::JsonSerializer<LibPlatformDisconnectedEvent>::serialize(*this);
}

std::string LibConnectedEvent::toJSON() const {
    return core::JsonSerializer<LibConnectedEvent>::serialize(*this);
}

std::string LibDisconnectedEvent::toJSON() const {
    return core::JsonSerializer<LibDisconnectedEvent>::serialize(*this);
}

std::string ContextUserAddedEvent::toJSON() const {
    return core::JsonSerializer<ContextUserAddedEvent>::serialize(*this);
}

std::string ContextUserRemovedEvent::toJSON() const {
    return core::JsonSerializer<ContextUserRemovedEvent>::serialize(*this);
}

std::string ContextUsersStatusChangeEvent::toJSON() const {
    return core::JsonSerializer<ContextUsersStatusChangeEvent>::serialize(*this);
}

std::shared_ptr<SerializedEvent> LibBreakEvent::serialize() const {
    return std::make_shared<SerializedEvent>(SerializedEvent{EventVarSerializer::getInstance()->serialize(*this)});
}

std::shared_ptr<SerializedEvent> LibPlatformDisconnectedEvent::serialize() const {
    return std::make_shared<SerializedEvent>(SerializedEvent{EventVarSerializer::getInstance()->serialize(*this)});
}

std::shared_ptr<SerializedEvent> LibConnectedEvent::serialize() const {
    return std::make_shared<SerializedEvent>(SerializedEvent{EventVarSerializer::getInstance()->serialize(*this)});
}

std::shared_ptr<SerializedEvent> LibDisconnectedEvent::serialize() const {
    return std::make_shared<SerializedEvent>(SerializedEvent{EventVarSerializer::getInstance()->serialize(*this)});
}

std::shared_ptr<SerializedEvent> ContextUserAddedEvent::serialize() const {
    return std::make_shared<SerializedEvent>(SerializedEvent{EventVarSerializer::getInstance()->serialize(*this)});
}

std::shared_ptr<SerializedEvent> ContextUserRemovedEvent::serialize() const {
    return std::make_shared<SerializedEvent>(SerializedEvent{EventVarSerializer::getInstance()->serialize(*this)});
}

std::shared_ptr<SerializedEvent> ContextUsersStatusChangeEvent::serialize() const {
    return std::make_shared<SerializedEvent>(SerializedEvent{EventVarSerializer::getInstance()->serialize(*this)});
}

bool Events::isLibBreakEvent(const core::EventHolder& handler) {
    return handler.type() == "libBreak";
}

LibBreakEvent Events::extractLibBreakEvent(const core::EventHolder& handler) {
    try {
        auto event = std::dynamic_pointer_cast<LibBreakEvent>(handler.get());
        if (!event) {
            throw CannotExtractLibBreakEventException();
        }
        return *event;
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

bool Events::isLibPlatformDisconnectedEvent(const core::EventHolder& handler) {
    return handler.type() == "libPlatformDisconnected";
}

LibPlatformDisconnectedEvent Events::extractLibPlatformDisconnectedEvent(const core::EventHolder& handler) {
    try {
        auto event = std::dynamic_pointer_cast<LibPlatformDisconnectedEvent>(handler.get());
        if (!event) {
            throw CannotExtractLibPlatformDisconnectedEventException();
        }
        return *event;
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

bool Events::isLibConnectedEvent(const core::EventHolder& handler) { return handler.type() == "libConnected"; }

LibConnectedEvent Events::extractLibConnectedEvent(const core::EventHolder& handler) {
    try {
        auto event = std::dynamic_pointer_cast<LibConnectedEvent>(handler.get());
        if (!event) {
            throw CannotExtractLibConnectedEventException();
        }
        return *event;
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

bool Events::isLibDisconnectedEvent(const core::EventHolder& handler) { return handler.type() == "libDisconnected"; }

LibDisconnectedEvent Events::extractLibDisconnectedEvent(const core::EventHolder& handler) {
    try {
        auto event = std::dynamic_pointer_cast<LibDisconnectedEvent>(handler.get());
        if (!event) {
            throw CannotExtractLibDisconnectedEventException();
        }
        return *event;
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

bool Events::isContextUserAddedEvent(const core::EventHolder& handler) { return handler.type() == "contextUserAdded"; }

ContextUserAddedEvent Events::extractContextUserAddedEvent(const core::EventHolder& handler) {
    try {
        auto event = std::dynamic_pointer_cast<ContextUserAddedEvent>(handler.get());
        if (!event) {
            throw CannotExtractContextUserAddedEventException();
        }
        return *event;
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

bool Events::isContextUserRemovedEvent(const core::EventHolder& handler) { return handler.type() == "contextUserRemoved"; }

ContextUserRemovedEvent Events::extractContextUserRemovedEvent(const core::EventHolder& handler) {
    try {
        auto event = std::dynamic_pointer_cast<ContextUserRemovedEvent>(handler.get());
        if (!event) {
            throw CannotExtractContextUserRemovedEventException();
        }
        return *event;
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

bool Events::isContextUsersStatusChangeEvent(const core::EventHolder& handler) { return handler.type() == "contextUserStatusChanged"; }

ContextUsersStatusChangeEvent Events::extractContextUsersStatusChangeEvent(const core::EventHolder& handler) {
    try {
        auto event = std::dynamic_pointer_cast<ContextUsersStatusChangeEvent>(handler.get());
        if (!event) {
            throw CannotExtractContextUsersStatusChangeEventException();
        }
        return *event;
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}