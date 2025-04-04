/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_ENDPOINT_KVDB_MAPPER_HPP_
#define _PRIVMXLIB_ENDPOINT_KVDB_MAPPER_HPP_

#include "privmx/endpoint/kvdb/Events.hpp"
#include "privmx/endpoint/kvdb/Events.hpp"
#include "privmx/endpoint/kvdb/ServerTypes.hpp"

namespace privmx {
namespace endpoint {
namespace kvdb {

class Mapper {
public:
    static void map(server::KvdbListItemsModel obj, const ItemsPagingQuery& listQuery);
    static void map(server::KvdbListKeysModel obj, const KeysPagingQuery& listQuery);

    static KvdbDeletedEventData mapToKvdbDeletedEventData(const server::KvdbDeletedEventData& data);
    static KvdbDeletedItemEventData mapToKvdbDeletedItemEventData(const server::KvdbDeletedItemEventData& data);
    static KvdbStatsEventData mapToKvdbStatsEventData(const server::KvdbStatsEventData& data);
};

}  // namespace kvdb
}  // namespace endpoint
}  // namespace privmx

#endif  // _PRIVMXLIB_ENDPOINT_KVDB_MAPPER_HPP_
