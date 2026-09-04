#include <privmx/endpoint/core/EventVarSerializer.hpp>
#include <privmx/endpoint/core/ExceptionConverter.hpp>
#include <privmx/endpoint/core/JsonSerializer.hpp>

#include "privmx/endpoint/group/Events.hpp"
#include "privmx/endpoint/group/GroupException.hpp"
#include "privmx/endpoint/group/VarSerializer.hpp"

using namespace privmx::endpoint;
using namespace privmx::endpoint::group;

std::string GroupCreatedEvent::toJSON() const {
    return core::JsonSerializer<GroupCreatedEvent>::serialize(*this);
}

std::string GroupUpdatedEvent::toJSON() const {
    return core::JsonSerializer<GroupUpdatedEvent>::serialize(*this);
}

std::string GroupDeletedEvent::toJSON() const {
    return core::JsonSerializer<GroupDeletedEvent>::serialize(*this);
}

std::shared_ptr<core::SerializedEvent> GroupCreatedEvent::serialize() const {
    return std::make_shared<core::SerializedEvent>(
        core::SerializedEvent{core::EventVarSerializer::getInstance()->serialize(*this)}
    );
}

std::shared_ptr<core::SerializedEvent> GroupUpdatedEvent::serialize() const {
    return std::make_shared<core::SerializedEvent>(
        core::SerializedEvent{core::EventVarSerializer::getInstance()->serialize(*this)}
    );
}

std::shared_ptr<core::SerializedEvent> GroupDeletedEvent::serialize() const {
    return std::make_shared<core::SerializedEvent>(
        core::SerializedEvent{core::EventVarSerializer::getInstance()->serialize(*this)}
    );
}

bool Events::isGroupCreatedEvent(const core::EventHolder& eventHolder) {
    return eventHolder.type() == "groupCreated";
}

GroupCreatedEvent Events::extractGroupCreatedEvent(const core::EventHolder& eventHolder) {
    try {
        auto event = std::dynamic_pointer_cast<GroupCreatedEvent>(eventHolder.get());
        if (!event) {
            throw CannotExtractGroupCreatedEventException();
        }
        return *event;
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

bool Events::isGroupUpdatedEvent(const core::EventHolder& eventHolder) {
    return eventHolder.type() == "groupUpdated";
}

GroupUpdatedEvent Events::extractGroupUpdatedEvent(const core::EventHolder& eventHolder) {
    try {
        auto event = std::dynamic_pointer_cast<GroupUpdatedEvent>(eventHolder.get());
        if (!event) {
            throw CannotExtractGroupUpdatedEventException();
        }
        return *event;
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

bool Events::isGroupDeletedEvent(const core::EventHolder& eventHolder) {
    return eventHolder.type() == "groupDeleted";
}

GroupDeletedEvent Events::extractGroupDeletedEvent(const core::EventHolder& eventHolder) {
    try {
        auto event = std::dynamic_pointer_cast<GroupDeletedEvent>(eventHolder.get());
        if (!event) {
            throw CannotExtractGroupDeletedEventException();
        }
        return *event;
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}
