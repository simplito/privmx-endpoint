/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include "privmx/endpoint/kvdb/Mapper.hpp"

using namespace privmx::endpoint::kvdb;

void Mapper::map(server::KvdbListEntriesModel obj, const KvdbEntryPagingQuery& listQuery) {
    obj.sortOrder(listQuery.sortOrder);
    obj.limit(listQuery.limit);
    obj.skip(listQuery.skip);
    if(listQuery.queryAsJson.has_value()) {
        obj.query(privmx::utils::Utils::parseJson(listQuery.queryAsJson.value()));
    }
    if(listQuery.lastKey.has_value()) {
        obj.lastKey(listQuery.lastKey.value());
    }
    if(listQuery.prefix.has_value()) {
        obj.prefix(listQuery.prefix.value());
    }
    if(listQuery.sortBy.has_value()) {
        obj.sortBy(listQuery.sortBy.value());
    }
}

void Mapper::map(server::KvdbListKeysModel obj, const KvdbKeysPagingQuery& listQuery) {
    obj.sortOrder(listQuery.sortOrder);
    obj.limit(listQuery.limit);
    obj.skip(listQuery.skip);
    if(listQuery.lastKey.has_value()) {
        obj.lastKey(listQuery.lastKey.value());
    }
    if(listQuery.prefix.has_value()) {
        obj.prefix(listQuery.prefix.value());
    }
    if(listQuery.sortBy.has_value()) {
        obj.sortBy(listQuery.sortBy.value());
    }
}

KvdbDeletedEventData Mapper::mapToKvdbDeletedEventData(const server::KvdbDeletedEventData& data) {
    return {.kvdbId = data.kvdbId()};
}

KvdbDeletedEntryEventData Mapper::mapToKvdbDeletedEntryEventData(const server::KvdbDeletedEntryEventData& data) {
    return {.kvdbId = data.kvdbId(), .kvdbEntryKey = data.kvdbEntryKey()};
}

KvdbStatsEventData Mapper::mapToKvdbStatsEventData(const server::KvdbStatsEventData& data) {
    return {.kvdbId = data.kvdbId(), .lastEntryDate = data.lastEntryDate(), .entries = data.entries()};
}
