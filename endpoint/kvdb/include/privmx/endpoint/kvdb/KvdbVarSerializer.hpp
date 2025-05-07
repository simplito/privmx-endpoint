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
Poco::Dynamic::Var VarSerializer::serialize<kvdb::ServerKvdbEntryInfo>(const kvdb::ServerKvdbEntryInfo& val);

template<>
Poco::Dynamic::Var VarSerializer::serialize<kvdb::KvdbEntry>(const kvdb::KvdbEntry & val);

template<>
Poco::Dynamic::Var VarSerializer::serialize<core::PagingList<kvdb::KvdbEntry>>(const core::PagingList<kvdb::KvdbEntry>& val);

template<>
Poco::Dynamic::Var VarSerializer::serialize<kvdb::KvdbDeletedEventData>(const kvdb::KvdbDeletedEventData& val);

template<>
Poco::Dynamic::Var VarSerializer::serialize<kvdb::KvdbStatsEventData>(const kvdb::KvdbStatsEventData& val);

template<>
Poco::Dynamic::Var VarSerializer::serialize<kvdb::KvdbDeletedEntryEventData>(const kvdb::KvdbDeletedEntryEventData& val);

template<>
Poco::Dynamic::Var VarSerializer::serialize<kvdb::KvdbCreatedEvent>(const kvdb::KvdbCreatedEvent& val);

template<>
Poco::Dynamic::Var VarSerializer::serialize<kvdb::KvdbUpdatedEvent>(const kvdb::KvdbUpdatedEvent& val);

template<>
Poco::Dynamic::Var VarSerializer::serialize<kvdb::KvdbDeletedEvent>(const kvdb::KvdbDeletedEvent& val);

template<>
Poco::Dynamic::Var VarSerializer::serialize<kvdb::KvdbStatsChangedEvent>(const kvdb::KvdbStatsChangedEvent& val);

template<>
Poco::Dynamic::Var VarSerializer::serialize<kvdb::KvdbNewEntryEvent>(const kvdb::KvdbNewEntryEvent& val);

template<>
Poco::Dynamic::Var VarSerializer::serialize<kvdb::KvdbEntryUpdatedEvent>(const kvdb::KvdbEntryUpdatedEvent& val);

template<>
Poco::Dynamic::Var VarSerializer::serialize<kvdb::KvdbEntryDeletedEvent>(const kvdb::KvdbEntryDeletedEvent& val);

template<>
Poco::Dynamic::Var VarSerializer::serialize<core::PagingList<std::string>>(const core::PagingList<std::string>& val);

}  // namespace core
}  // namespace endpoint
}  // namespace privmx

#endif  // _PRIVMXLIB_ENDPOINT_KVDB_KVDBVARSERIALIZER_HPP_
