/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include "privmx/endpoint/thread/ThreadValidator.hpp"
#include "privmx/endpoint/core/CoreException.hpp"

using namespace privmx::endpoint;
using namespace privmx::endpoint::core;

void StructValidator<thread::Thread>::validate(const thread::Thread& value, const std::string& stack_trace) {
    Validator::validateId(value.contextId, stack_trace + ".contextId");
    Validator::validateId(value.threadId, stack_trace + ".threadId");
    Validator::validateNumberNonNegative(value.version, stack_trace + ".version");
    Validator::validateNumberNonNegative(value.messagesCount, stack_trace + ".messagesCount");
}

void StructValidator<PagingList<thread::Thread>>::validate(const PagingList<thread::Thread>& value, const std::string& stack_trace) {
    Validator::validateNumberNonNegative(value.totalAvailable, stack_trace + ".totalAvailable");
    StructValidator<std::vector<thread::Thread>>::validate(value.readItems, stack_trace + ".readItems");
}

void StructValidator<thread::ServerMessageInfo>::validate(const thread::ServerMessageInfo& value, const std::string& stack_trace) {
    Validator::validateId(value.threadId, stack_trace + ".threadId");
    Validator::validateId(value.messageId, stack_trace + ".messageId");
}

void StructValidator<thread::Message>::validate(const thread::Message& value, const std::string& stack_trace) {
    Validator::validatePubKeyBase58DER(value.authorPubKey, stack_trace + ".authorPubKey");
    StructValidator<thread::ServerMessageInfo>::validate(value.info, stack_trace + ".info");
}

void StructValidator<core::PagingList<thread::Message>>::validate(const core::PagingList<thread::Message>& value, const std::string& stack_trace) {
    Validator::validateNumberPositive(value.totalAvailable, stack_trace + ".totalAvailable");
    StructValidator<std::vector<thread::Message>>::validate(value.readItems, stack_trace + ".readItems");
}

void StructValidator<thread::ThreadCreatedEvent>::validate(const thread::ThreadCreatedEvent& value, const std::string& stack_trace) {
    Validator::validateEventType(value, "threadCreated", stack_trace + ".type");
    StructValidator<thread::Thread>::validate(value.data, stack_trace + ".data");
}

void StructValidator<thread::ThreadUpdatedEvent>::validate(const thread::ThreadUpdatedEvent& value, const std::string& stack_trace) {
    Validator::validateEventType(value, "threadUpdated", stack_trace + ".type");
    StructValidator<thread::Thread>::validate(value.data, stack_trace + ".data");
}

void StructValidator<thread::ThreadDeletedEventData>::validate(const thread::ThreadDeletedEventData& value, const std::string& stack_trace) {
    Validator::validateId(value.threadId, stack_trace + ".threadId");
}

void StructValidator<thread::ThreadDeletedEvent>::validate(const thread::ThreadDeletedEvent& value, const std::string& stack_trace) {
    Validator::validateEventType(value, "threadDeleted", stack_trace + ".type");
    StructValidator<thread::ThreadDeletedEventData>::validate(value.data, stack_trace + ".data");
}

void StructValidator<thread::ThreadStatsEventData>::validate(const thread::ThreadStatsEventData& value, const std::string& stack_trace) {
    Validator::validateId(value.threadId, stack_trace + ".threadId");
}

void StructValidator<thread::ThreadStatsChangedEvent>::validate(const thread::ThreadStatsChangedEvent& value, const std::string& stack_trace) {
    Validator::validateEventType(value, "threadStatsChanged", stack_trace + ".type");
    StructValidator<thread::ThreadStatsEventData>::validate(value.data, stack_trace + ".data");
}

void StructValidator<thread::ThreadNewMessageEvent>::validate(const thread::ThreadNewMessageEvent& value, const std::string& stack_trace) {
    Validator::validateEventType(value, "threadNewMessage", stack_trace + ".type");
    StructValidator<thread::Message>::validate(value.data, stack_trace + ".data");
}

void StructValidator<thread::ThreadDeletedMessageEventData>::validate(const thread::ThreadDeletedMessageEventData& value, const std::string& stack_trace) {
    Validator::validateId(value.threadId, stack_trace + ".threadId");
    Validator::validateId(value.messageId, stack_trace + ".messageId");
}

void StructValidator<thread::ThreadMessageDeletedEvent>::validate(const thread::ThreadMessageDeletedEvent& value, const std::string& stack_trace) {
    Validator::validateEventType(value, "threadMessageDeleted", stack_trace + ".type");
    StructValidator<thread::ThreadDeletedMessageEventData>::validate(value.data, stack_trace + ".data");
}