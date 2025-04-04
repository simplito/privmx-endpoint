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

void Mapper::map(server::KvdbListItemsModel obj, const ItemsPagingQuery& listQuery) {
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

void Mapper::map(server::KvdbListKeysModel obj, const KeysPagingQuery& listQuery) {
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

KvdbDeletedItemEventData Mapper::mapToKvdbDeletedItemEventData(const server::KvdbDeletedItemEventData& data) {
    return {.kvdbId = data.kvdbId(), .kvdbItemKey = data.kvdbItemKey()};
}

KvdbStatsEventData Mapper::mapToKvdbStatsEventData(const server::KvdbStatsEventData& data) {
    return {.kvdbId = data.kvdbId(), .lastItemDate = data.lastItemDate(), .items = data.items()};
}
