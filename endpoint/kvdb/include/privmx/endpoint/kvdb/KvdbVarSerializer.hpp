/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_ENDPOINT_KVDB_KVDBVARSERIALIZER_HPP_
#define _PRIVMXLIB_ENDPOINT_KVDB_KVDBVARSERIALIZER_HPP_

#include <Poco/Dynamic/Var.h>

#include <privmx/endpoint/core/VarSerializer.hpp>
#include <string>

#include "privmx/endpoint/kvdb/Types.hpp"
#include "privmx/endpoint/kvdb/Events.hpp"

namespace privmx {
namespace endpoint {
namespace core {

template<>
Poco::Dynamic::Var VarSerializer::serialize<kvdb::Kvdb>(const kvdb::Kvdb& val);

template<>
Poco::Dynamic::Var VarSerializer::serialize<core::PagingList<kvdb::Kvdb>>(const core::PagingList<kvdb::Kvdb>& val);

template<>
Poco::Dynamic::Var VarSerializer::serialize<kvdb::ServerItemInfo>(const kvdb::ServerItemInfo& val);

template<>
Poco::Dynamic::Var VarSerializer::serialize<kvdb::Item>(const kvdb::Item& val);

template<>
Poco::Dynamic::Var VarSerializer::serialize<core::PagingList<kvdb::Item>>(const core::PagingList<kvdb::Item>& val);

template<>
Poco::Dynamic::Var VarSerializer::serialize<kvdb::KvdbDeletedEventData>(const kvdb::KvdbDeletedEventData& val);

template<>
Poco::Dynamic::Var VarSerializer::serialize<kvdb::KvdbStatsEventData>(const kvdb::KvdbStatsEventData& val);

template<>
Poco::Dynamic::Var VarSerializer::serialize<kvdb::KvdbDeletedItemEventData>(const kvdb::KvdbDeletedItemEventData& val);

template<>
Poco::Dynamic::Var VarSerializer::serialize<kvdb::KvdbCreatedEvent>(const kvdb::KvdbCreatedEvent& val);

template<>
Poco::Dynamic::Var VarSerializer::serialize<kvdb::KvdbUpdatedEvent>(const kvdb::KvdbUpdatedEvent& val);

template<>
Poco::Dynamic::Var VarSerializer::serialize<kvdb::KvdbDeletedEvent>(const kvdb::KvdbDeletedEvent& val);

template<>
Poco::Dynamic::Var VarSerializer::serialize<kvdb::KvdbStatsChangedEvent>(const kvdb::KvdbStatsChangedEvent& val);

template<>
Poco::Dynamic::Var VarSerializer::serialize<kvdb::KvdbNewItemEvent>(const kvdb::KvdbNewItemEvent& val);

template<>
Poco::Dynamic::Var VarSerializer::serialize<kvdb::KvdbItemUpdatedEvent>(const kvdb::KvdbItemUpdatedEvent& val);

template<>
Poco::Dynamic::Var VarSerializer::serialize<kvdb::KvdbItemDeletedEvent>(const kvdb::KvdbItemDeletedEvent& val);

}  // namespace core
}  // namespace endpoint
}  // namespace privmx

#endif  // _PRIVMXLIB_ENDPOINT_KVDB_KVDBVARSERIALIZER_HPP_
