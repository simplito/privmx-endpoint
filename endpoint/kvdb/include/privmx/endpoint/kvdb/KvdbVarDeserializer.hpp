/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_ENDPOINT_KVDB_KVDBVARDESERIALIZER_HPP_
#define _PRIVMXLIB_ENDPOINT_KVDB_KVDBVARDESERIALIZER_HPP_

#include <privmx/endpoint/core/VarDeserializer.hpp>
#include <string>

#include "privmx/endpoint/kvdb/Events.hpp"
#include "privmx/endpoint/kvdb/KvdbApi.hpp"
#include "privmx/endpoint/kvdb/Types.hpp"

namespace privmx {
namespace endpoint {
namespace core {

template<>
kvdb::KvdbEntryPagingQuery core::VarDeserializer::deserialize<kvdb::KvdbEntryPagingQuery>(const Poco::Dynamic::Var& val, const std::string& name);
template<>
kvdb::KvdbKeysPagingQuery core::VarDeserializer::deserialize<kvdb::KvdbKeysPagingQuery>(const Poco::Dynamic::Var& val, const std::string& name);


} // core
} // endpoint
} // privmx

#endif  // _PRIVMXLIB_ENDPOINT_KVDB_KVDBVARDESERIALIZER_HPP_
