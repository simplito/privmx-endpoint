/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include "privmx/endpoint/store/StoreValidator.hpp"
#include "privmx/endpoint/core/CoreException.hpp"

using namespace privmx::endpoint;
using namespace privmx::endpoint::core;

void StructValidator<store::Store>::validate(const store::Store& value, const std::string& stack_trace) {
    Validator::validateId(value.storeId, stack_trace + ".storeId");
    Validator::validateId(value.contextId, stack_trace + ".contextId");
}

void StructValidator<PagingList<store::Store>>::validate(const PagingList<store::Store>& value, const std::string& stack_trace) {
    Validator::validateNumberNonNegative(value.totalAvailable, stack_trace + ".totalAvailable");
    StructValidator<std::vector<store::Store>>::validate(value.readItems, stack_trace + ".readItems");
}

void StructValidator<store::StoreStatsChangedEventData>::validate(const store::StoreStatsChangedEventData& value, const std::string& stack_trace) {
    Validator::validateId(value.contextId, stack_trace + ".contextId");
    Validator::validateId(value.storeId, stack_trace + ".storeId");
}

void StructValidator<store::StoreFileDeletedEventData>::validate(const store::StoreFileDeletedEventData& value, const std::string& stack_trace) {
    Validator::validateId(value.contextId, stack_trace + ".contextId");
    Validator::validateId(value.storeId, stack_trace + ".storeId");
    Validator::validateId(value.fileId, stack_trace + ".fileId");
}

void StructValidator<store::StoreCreatedEvent>::validate(const store::StoreCreatedEvent& value, const std::string& stack_trace) {
    Validator::validateEventType(value, "storeCreated", stack_trace + ".type");
    StructValidator<store::Store>::validate(value.data, stack_trace + ".data");
}

void StructValidator<store::StoreUpdatedEvent>::validate(const store::StoreUpdatedEvent& value, const std::string& stack_trace) {
    Validator::validateEventType(value, "storeUpdated", stack_trace + ".type");
    StructValidator<store::Store>::validate(value.data, stack_trace + ".data");
}

void StructValidator<store::StoreStatsChangedEvent>::validate(const store::StoreStatsChangedEvent& value, const std::string& stack_trace) {
    Validator::validateEventType(value, "storeStatsChanged", stack_trace + ".type");
    StructValidator<store::StoreStatsChangedEventData>::validate(value.data, stack_trace + ".data");
}

void StructValidator<store::StoreFileCreatedEvent>::validate(const store::StoreFileCreatedEvent& value, const std::string& stack_trace) {
    Validator::validateEventType(value, "storeFileCreated", stack_trace + ".type");
    StructValidator<store::File>::validate(value.data, stack_trace + ".data");
}

void StructValidator<store::StoreFileUpdatedEvent>::validate(const store::StoreFileUpdatedEvent& value, const std::string& stack_trace) {
    Validator::validateEventType(value, "storeFileUpdated", stack_trace + ".type");
    StructValidator<store::File>::validate(value.data, stack_trace + ".data");
}

void StructValidator<store::StoreFileDeletedEvent>::validate(const store::StoreFileDeletedEvent& value, const std::string& stack_trace) {
    Validator::validateEventType(value, "storeFileDeleted", stack_trace + ".type");
    StructValidator<store::StoreFileDeletedEventData>::validate(value.data, stack_trace + ".data");
}

void StructValidator<store::File>::validate(const store::File& value, const std::string& stack_trace) {
    // StructValidator<store::ServerFileInfo>::validate(value.info, stack_trace + ".info");
    // StructValidator<core::Buffer>::validate(value.publicMeta, stack_trace + ".publicMeta");
    // StructValidator<core::Buffer>::validate(value.privateMeta, stack_trace + ".privateMeta");
    Validator::validateNumberNonNegative(value.size, stack_trace + ".size");
    Validator::validatePubKeyBase58DER(value.authorPubKey, stack_trace + ".authorPubKey");
}

void StructValidator<PagingList<store::File>>::validate(const PagingList<store::File>& value, const std::string& stack_trace) {
    Validator::validateNumberPositive(value.totalAvailable, stack_trace + ".totalAvailable");
    StructValidator<std::vector<store::File>>::validate(value.readItems, stack_trace + ".readItems");
}