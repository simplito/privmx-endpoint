/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include <privmx/endpoint/core/EventVarSerializer.hpp>
#include <privmx/endpoint/core/ExceptionConverter.hpp>
#include <privmx/endpoint/core/JsonSerializer.hpp>

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

std::string StreamUpdatedEvent::toJSON() const {
    return core::JsonSerializer<StreamUpdatedEvent>::serialize(*this);
}

std::string StreamRoomJoinedEvent::toJSON() const {
    return core::JsonSerializer<StreamRoomJoinedEvent>::serialize(*this);
}

std::string StreamUnpublishedEvent::toJSON() const {
    return core::JsonSerializer<StreamUnpublishedEvent>::serialize(*this);
}

std::string StreamRoomLeftEvent::toJSON() const {
    return core::JsonSerializer<StreamRoomLeftEvent>::serialize(*this);
}

std::string StreamSubscribedEvent::toJSON() const {
    return core::JsonSerializer<StreamSubscribedEvent>::serialize(*this);
}

std::string StreamUnsubscribedEvent::toJSON() const {
    return core::JsonSerializer<StreamUnsubscribedEvent>::serialize(*this);
}

std::shared_ptr<core::SerializedEvent> StreamRoomCreatedEvent::serialize() const {
    return std::make_shared<core::SerializedEvent>(
        core::SerializedEvent{core::EventVarSerializer::getInstance()->serialize(*this)}
    );
}

std::shared_ptr<core::SerializedEvent> StreamRoomUpdatedEvent::serialize() const {
    return std::make_shared<core::SerializedEvent>(
        core::SerializedEvent{core::EventVarSerializer::getInstance()->serialize(*this)}
    );
}

std::shared_ptr<core::SerializedEvent> StreamRoomDeletedEvent::serialize() const {
    return std::make_shared<core::SerializedEvent>(
        core::SerializedEvent{core::EventVarSerializer::getInstance()->serialize(*this)}
    );
}

std::shared_ptr<core::SerializedEvent> StreamPublishedEvent::serialize() const {
    return std::make_shared<core::SerializedEvent>(
        core::SerializedEvent{core::EventVarSerializer::getInstance()->serialize(*this)}
    );
}

std::shared_ptr<core::SerializedEvent> StreamUpdatedEvent::serialize() const {
    return std::make_shared<core::SerializedEvent>(
        core::SerializedEvent{core::EventVarSerializer::getInstance()->serialize(*this)}
    );
}

std::shared_ptr<core::SerializedEvent> StreamRoomJoinedEvent::serialize() const {
    return std::make_shared<core::SerializedEvent>(
        core::SerializedEvent{core::EventVarSerializer::getInstance()->serialize(*this)}
    );
}

std::shared_ptr<core::SerializedEvent> StreamUnpublishedEvent::serialize() const {
    return std::make_shared<core::SerializedEvent>(
        core::SerializedEvent{core::EventVarSerializer::getInstance()->serialize(*this)}
    );
}

std::shared_ptr<core::SerializedEvent> StreamRoomLeftEvent::serialize() const {
    return std::make_shared<core::SerializedEvent>(
        core::SerializedEvent{core::EventVarSerializer::getInstance()->serialize(*this)}
    );
}

std::shared_ptr<core::SerializedEvent> StreamSubscribedEvent::serialize() const {
    return std::make_shared<core::SerializedEvent>(
        core::SerializedEvent{core::EventVarSerializer::getInstance()->serialize(*this)}
    );
}

std::shared_ptr<core::SerializedEvent> StreamUnsubscribedEvent::serialize() const {
    return std::make_shared<core::SerializedEvent>(
        core::SerializedEvent{core::EventVarSerializer::getInstance()->serialize(*this)}
    );
}

bool Events::isStreamRoomCreatedEvent(const core::EventHolder& handler) {
    return handler.type() == "streamRoomCreated";
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
    return handler.type() == "streamRoomUpdated";
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
    return handler.type() == "streamRoomDeleted";
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

bool Events::isStreamUpdatedEvent(const core::EventHolder& handler) {
    return handler.type() == "streamUpdated";
}

StreamUpdatedEvent Events::extractStreamUpdatedEvent(const core::EventHolder& handler) {
    try {
        auto event = std::dynamic_pointer_cast<StreamUpdatedEvent>(handler.get());
        if (!event) {
            throw CannotExtractStreamUpdatedEventException();
        }
        return *event;
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

bool Events::isStreamRoomJoinedEvent(const core::EventHolder& handler) {
    return handler.type() == "streamRoomJoined";
}

StreamRoomJoinedEvent Events::extractStreamRoomJoinedEvent(const core::EventHolder& handler) {
    try {
        auto event = std::dynamic_pointer_cast<StreamRoomJoinedEvent>(handler.get());
        if (!event) {
            throw CannotExtractStreamRoomJoinedEventException();
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

bool Events::isStreamRoomLeftEvent(const core::EventHolder& handler) {
    return handler.type() == "streamRoomLeft";
}

StreamRoomLeftEvent Events::extractStreamRoomLeftEvent(const core::EventHolder& handler) {
    try {
        auto event = std::dynamic_pointer_cast<StreamRoomLeftEvent>(handler.get());
        if (!event) {
            throw CannotExtractStreamRoomLeftEventException();
        }
        return *event;
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

bool Events::isStreamSubscribedEvent(const core::EventHolder& handler) {
    return handler.type() == "streamSubscribed";
}

StreamSubscribedEvent Events::extractStreamSubscribedEvent(const core::EventHolder& handler) {
    try {
        auto event = std::dynamic_pointer_cast<StreamSubscribedEvent>(handler.get());
        if (!event) {
            throw CannotExtractStreamSubscribedEventException();
        }
        return *event;
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

bool Events::isStreamUnsubscribedEvent(const core::EventHolder& handler) {
    return handler.type() == "streamUnsubscribed";
}

StreamUnsubscribedEvent Events::extractStreamUnsubscribedEvent(const core::EventHolder& handler) {
    try {
        auto event = std::dynamic_pointer_cast<StreamUnsubscribedEvent>(handler.get());
        if (!event) {
            throw CannotExtractStreamUnsubscribedEventException();
        }
        return *event;
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}