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