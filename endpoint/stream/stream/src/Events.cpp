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

#include "privmx/endpoint/stream/Events.hpp"
#include "privmx/endpoint/stream/StreamException.hpp"
#include "privmx/endpoint/stream/StreamVarSerializer.hpp"
using namespace privmx::endpoint;
using namespace privmx::endpoint::stream;

std::string StreamRoomCreatedEvent::toJSON() const {
    return core::JsonSerializer<StreamRoomCreatedEvent>::serialize(*this);
}

std::string StreamRoomUpdatedEvent::toJSON() const {
    return core::JsonSerializer<StreamRoomUpdatedEvent>::serialize(*this);
}

std::string StreamRoomDeletedEvent::toJSON() const {
    return core::JsonSerializer<StreamRoomDeletedEvent>::serialize(*this);
}

std::string StreamPublishedEvent::toJSON() const {
    return core::JsonSerializer<StreamPublishedEvent>::serialize(*this);
}

std::string StreamJoinedEvent::toJSON() const {
    return core::JsonSerializer<StreamJoinedEvent>::serialize(*this);
}

std::string StreamUnpublishedEvent::toJSON() const {
    return core::JsonSerializer<StreamUnpublishedEvent>::serialize(*this);
}

std::string StreamLeftEvent::toJSON() const {
    return core::JsonSerializer<StreamLeftEvent>::serialize(*this);
}

std::shared_ptr<core::SerializedEvent> StreamRoomCreatedEvent::serialize() const {
    return std::make_shared<core::SerializedEvent>(core::SerializedEvent{core::EventVarSerializer::getInstance()->serialize(*this)});
}

std::shared_ptr<core::SerializedEvent> StreamRoomUpdatedEvent::serialize() const {
    return std::make_shared<core::SerializedEvent>(core::SerializedEvent{core::EventVarSerializer::getInstance()->serialize(*this)});
}

std::shared_ptr<core::SerializedEvent> StreamRoomDeletedEvent::serialize() const {
    return std::make_shared<core::SerializedEvent>(core::SerializedEvent{core::EventVarSerializer::getInstance()->serialize(*this)});
}

std::shared_ptr<core::SerializedEvent> StreamPublishedEvent::serialize() const {
    return std::make_shared<core::SerializedEvent>(core::SerializedEvent{core::EventVarSerializer::getInstance()->serialize(*this)});
}

std::shared_ptr<core::SerializedEvent> StreamJoinedEvent::serialize() const {
    return std::make_shared<core::SerializedEvent>(core::SerializedEvent{core::EventVarSerializer::getInstance()->serialize(*this)});
}

std::shared_ptr<core::SerializedEvent> StreamUnpublishedEvent::serialize() const {
    return std::make_shared<core::SerializedEvent>(core::SerializedEvent{core::EventVarSerializer::getInstance()->serialize(*this)});
}

std::shared_ptr<core::SerializedEvent> StreamLeftEvent::serialize() const {
    return std::make_shared<core::SerializedEvent>(core::SerializedEvent{core::EventVarSerializer::getInstance()->serialize(*this)});
}

bool Events::isStreamRoomCreatedEvent(const core::EventHolder& handler) {
    return handler.type() == "streamCreated";
}

StreamRoomCreatedEvent Events::extractStreamRoomCreatedEvent(const core::EventHolder& handler) {
    try {
        auto event = std::dynamic_pointer_cast<StreamRoomCreatedEvent>(handler.get());
        if (!event) {
            throw CannotExtractStreamRoomCreatedEventException();
        }
        return *event;
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

bool Events::isStreamRoomUpdatedEvent(const core::EventHolder& handler) {
    return handler.type() == "streamUpdated";
}

StreamRoomUpdatedEvent Events::extractStreamRoomUpdatedEvent(const core::EventHolder& handler) {
    try {
        auto event = std::dynamic_pointer_cast<StreamRoomUpdatedEvent>(handler.get());
        if (!event) {
            throw CannotExtractStreamRoomUpdatedEventException();
        }
        return *event;
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

bool Events::isStreamRoomDeletedEvent(const core::EventHolder& handler) {
    return handler.type() == "streamDeleted";
}

StreamRoomDeletedEvent Events::extractStreamRoomDeletedEvent(const core::EventHolder& handler) {
    try {
        auto event = std::dynamic_pointer_cast<StreamRoomDeletedEvent>(handler.get());
        if (!event) {
            throw CannotExtractStreamRoomDeletedEventException();
        }
        return *event;
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

bool Events::isStreamPublishedEvent(const core::EventHolder& handler) {
    return handler.type() == "streamPublished";
}

StreamPublishedEvent Events::extractStreamPublishedEvent(const core::EventHolder& handler) {
    try {
        auto event = std::dynamic_pointer_cast<StreamPublishedEvent>(handler.get());
        if (!event) {
            throw CannotExtractStreamPublishedEventException();
        }
        return *event;
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

bool Events::isStreamJoinedEvent(const core::EventHolder& handler) {
    return handler.type() == "streamUpdatedMessage";
}

StreamJoinedEvent Events::extractStreamJoinedEvent(const core::EventHolder& handler) {
    try {
        auto event = std::dynamic_pointer_cast<StreamJoinedEvent>(handler.get());
        if (!event) {
            throw CannotExtractStreamJoinedEventException();
        }
        return *event;
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

bool Events::isStreamUnpublishedEvent(const core::EventHolder& handler) {
    return handler.type() == "streamUnpublished";
}

StreamUnpublishedEvent Events::extractStreamUnpublishedEvent(const core::EventHolder& handler) {
    try {
        auto event = std::dynamic_pointer_cast<StreamUnpublishedEvent>(handler.get());
        if (!event) {
            throw CannotExtractStreamUnpublishedEventException();
        }
        return *event;
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

bool Events::isStreamLeftEvent(const core::EventHolder& handler) {
    return handler.type() == "streamCustom";
}

StreamLeftEvent Events::extractStreamLeftEvent(const core::EventHolder& handler) {
    try {
        auto event = std::dynamic_pointer_cast<StreamLeftEvent>(handler.get());
        if (!event) {
            throw CannotExtractStreamLeftEventException();
        }
        return *event;
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

