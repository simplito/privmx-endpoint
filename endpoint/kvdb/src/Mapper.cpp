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

KvdbDeletedEventData Mapper::mapToKvdbDeletedEventData(const server::KvdbDeletedEventData& data) {
    return {.kvdbId = data.kvdbId()};
}

KvdbDeletedEntryEventData Mapper::mapToKvdbDeletedEntryEventData(const server::KvdbDeletedEntryEventData& data) {
    return {.kvdbId = data.kvdbId(), .kvdbEntryKey = data.kvdbEntryKey()};
}

KvdbStatsEventData Mapper::mapToKvdbStatsEventData(const server::KvdbStatsEventData& data) {
    return {.kvdbId = data.kvdbId(), .lastEntryDate = data.lastEntryDate(), .entries = data.entries()};
}
