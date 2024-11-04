/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include "privmx/endpoint/store/Mapper.hpp"

using namespace privmx::endpoint::store;

StoreDeletedEventData Mapper::mapToStoreDeletedEventData(const server::StoreDeletedEventData& data) {
    return {.storeId = data.storeId()};
}

StoreFileDeletedEventData Mapper::mapToStoreFileDeletedEventData(const server::StoreFileDeletedEventData& data) {
    return {.contextId = data.contextId(), .storeId = data.storeId(), .fileId = data.id()};
}

StoreStatsChangedEventData Mapper::mapToStoreStatsChangedEventData(const server::StoreStatsChangedEventData& data) {
    return {.contextId = data.contextId(),
            .storeId = data.id(),
            .lastFileDate = data.lastFileDate(),
            .filesCount = data.files()};
}
