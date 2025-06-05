/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include "privmx/endpoint/kvdb/KvdbValidator.hpp"
#include "privmx/endpoint/core/CoreException.hpp"

using namespace privmx::endpoint;
using namespace privmx::endpoint::core;

void StructValidator<kvdb::KvdbEntryPagingQuery>::validate(const kvdb::KvdbEntryPagingQuery& value, const std::string& stack_trace) {
    Validator::validateSortOrder(value.sortOrder, stack_trace + ".sortOrder");
    if (value.sortBy.has_value()) {
        if(value.sortBy != "createDate" && value.sortBy != "itemKey" && value.sortBy != "lastModificationDate") {
            throw InvalidParamsException(stack_trace + ".sortBy | " + ("Invalid sortBy, isn't 'createDate' or 'itemKey' or 'lastModificationDate', received '" + value.sortBy.value() + "'"));
        }
    }
    if (value.queryAsJson.has_value()) {
        Validator::validateJSON(value.queryAsJson.value(), stack_trace + ".queryAsJson");
    }
}

void StructValidator<kvdb::KvdbKeysPagingQuery>::validate(const kvdb::KvdbKeysPagingQuery& value, const std::string& stack_trace) {
    Validator::validateSortOrder(value.sortOrder, stack_trace + ".sortOrder");
    if (value.sortBy.has_value()) {
        if(value.sortBy != "createDate" && value.sortBy != "itemKey" && value.sortBy != "lastModificationDate") {
            throw InvalidParamsException(stack_trace + ".sortBy | " + ("Invalid sortBy, isn't 'createDate' or 'itemKey' or 'lastModificationDate', received '" + value.sortBy.value() + "'"));
        }
    }
}