#include <privmx/endpoint/core/ExceptionConverter.hpp>
#include <privmx/endpoint/core/JsonSerializer.hpp>
#include <privmx/endpoint/core/EventVarSerializer.hpp>

#include "privmx/endpoint/thread/Events.hpp"
#include "privmx/endpoint/thread/ThreadException.hpp"
#include "privmx/endpoint/thread/ThreadVarSerializer.hpp"
using namespace privmx::endpoint;
using namespace privmx::endpoint::thread;

std::string ThreadCreatedEvent::toJSON() const {
    return core::JsonSerializer<ThreadCreatedEvent>::serialize(*this);
}

std::string ThreadUpdatedEvent::toJSON() const {
    return core::JsonSerializer<ThreadUpdatedEvent>::serialize(*this);
}

std::string ThreadDeletedEvent::toJSON() const {
    return core::JsonSerializer<ThreadDeletedEvent>::serialize(*this);
}

std::string ThreadNewMessageEvent::toJSON() const {
    return core::JsonSerializer<ThreadNewMessageEvent>::serialize(*this);
}

std::string ThreadMessageUpdatedEvent::toJSON() const {
    return core::JsonSerializer<ThreadMessageUpdatedEvent>::serialize(*this);
}

std::string ThreadMessageDeletedEvent::toJSON() const {
    return core::JsonSerializer<ThreadMessageDeletedEvent>::serialize(*this);
}

std::string ThreadStatsChangedEvent::toJSON() const {
    return core::JsonSerializer<ThreadStatsChangedEvent>::serialize(*this);
}

std::shared_ptr<core::SerializedEvent> ThreadCreatedEvent::serialize() const {
    return std::make_shared<core::SerializedEvent>(core::SerializedEvent{core::EventVarSerializer::getInstance()->serialize(*this)});
}

std::shared_ptr<core::SerializedEvent> ThreadUpdatedEvent::serialize() const {
    return std::make_shared<core::SerializedEvent>(core::SerializedEvent{core::EventVarSerializer::getInstance()->serialize(*this)});
}

std::shared_ptr<core::SerializedEvent> ThreadDeletedEvent::serialize() const {
    return std::make_shared<core::SerializedEvent>(core::SerializedEvent{core::EventVarSerializer::getInstance()->serialize(*this)});
}

std::shared_ptr<core::SerializedEvent> ThreadNewMessageEvent::serialize() const {
    return std::make_shared<core::SerializedEvent>(core::SerializedEvent{core::EventVarSerializer::getInstance()->serialize(*this)});
}

std::shared_ptr<core::SerializedEvent> ThreadMessageUpdatedEvent::serialize() const {
    return std::make_shared<core::SerializedEvent>(core::SerializedEvent{core::EventVarSerializer::getInstance()->serialize(*this)});
}

std::shared_ptr<core::SerializedEvent> ThreadMessageDeletedEvent::serialize() const {
    return std::make_shared<core::SerializedEvent>(core::SerializedEvent{core::EventVarSerializer::getInstance()->serialize(*this)});
}

std::shared_ptr<core::SerializedEvent> ThreadStatsChangedEvent::serialize() const {
    return std::make_shared<core::SerializedEvent>(core::SerializedEvent{core::EventVarSerializer::getInstance()->serialize(*this)});
}

bool Events::isThreadCreatedEvent(const core::EventHolder& handler) {
    return handler.type() == "threadCreated";
}

ThreadCreatedEvent Events::extractThreadCreatedEvent(const core::EventHolder& handler) {
    try {
        auto event = std::dynamic_pointer_cast<ThreadCreatedEvent>(handler.get());
        if (!event) {
            throw CannotExtractThreadCreatedEventException();
        }
        return *event;
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

bool Events::isThreadUpdatedEvent(const core::EventHolder& handler) {
    return handler.type() == "threadUpdated";
}

ThreadUpdatedEvent Events::extractThreadUpdatedEvent(const core::EventHolder& handler) {
    try {
        auto event = std::dynamic_pointer_cast<ThreadUpdatedEvent>(handler.get());
        if (!event) {
            throw CannotExtractThreadUpdatedEventException();
        }
        return *event;
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

bool Events::isThreadDeletedEvent(const core::EventHolder& handler) {
    return handler.type() == "threadDeleted";
}

ThreadDeletedEvent Events::extractThreadDeletedEvent(const core::EventHolder& handler) {
    try {
        auto event = std::dynamic_pointer_cast<ThreadDeletedEvent>(handler.get());
        if (!event) {
            throw CannotExtractThreadDeletedEventException();
        }
        return *event;
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

bool Events::isThreadStatsEvent(const core::EventHolder& eventHolder) {
    return eventHolder.type() == "threadStatsChanged";
}

ThreadStatsChangedEvent Events::extractThreadStatsEvent(const core::EventHolder& eventHolder) {
    try {
        auto event = std::dynamic_pointer_cast<ThreadStatsChangedEvent>(eventHolder.get());
        if (!event) {
            throw CannotExtractThreadStatsEventException();
        }
        return *event;
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

bool Events::isThreadNewMessageEvent(const core::EventHolder& handler) {
    return handler.type() == "threadNewMessage";
}

ThreadNewMessageEvent Events::extractThreadNewMessageEvent(const core::EventHolder& handler) {
    try {
        auto event = std::dynamic_pointer_cast<ThreadNewMessageEvent>(handler.get());
        if (!event) {
            throw CannotExtractThreadNewMessageEventException();
        }
        return *event;
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

bool Events::isThreadMessageUpdatedEvent(const core::EventHolder& handler) {
    return handler.type() == "threadUpdatedMessage";
}

ThreadMessageUpdatedEvent Events::extractThreadMessageUpdatedEvent(const core::EventHolder& handler) {
    try {
        auto event = std::dynamic_pointer_cast<ThreadMessageUpdatedEvent>(handler.get());
        if (!event) {
            throw CannotExtractThreadMessageUpdatedEventException();
        }
        return *event;
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

bool Events::isThreadDeletedMessageEvent(const core::EventHolder& handler) {
    return handler.type() == "threadMessageDeleted";
}

ThreadMessageDeletedEvent Events::extractThreadMessageDeletedEvent(const core::EventHolder& handler) {
    try {
        auto event = std::dynamic_pointer_cast<ThreadMessageDeletedEvent>(handler.get());
        if (!event) {
            throw CannotExtractThreadDeletedMessageEventException();
        }
        return *event;
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}


