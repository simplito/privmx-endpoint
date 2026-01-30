/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_ENDPOINT_SQL_VARSERIALIZER_HPP_
#define _PRIVMXLIB_ENDPOINT_SQL_VARSERIALIZER_HPP_

#include <Poco/Dynamic/Var.h>

#include <privmx/endpoint/core/VarSerializer.hpp>
#include <string>

#include "privmx/endpoint/sql/Types.hpp"
#include "privmx/endpoint/sql/DatabaseHandle.hpp"

namespace privmx {
namespace endpoint {
namespace core {


template<>
Poco::Dynamic::Var VarSerializer::serialize<core::PagingList<sql::SqlDatabase>>(const core::PagingList<sql::SqlDatabase>& val);

template<>
Poco::Dynamic::Var VarSerializer::serialize<sql::SqlDatabase>(const sql::SqlDatabase& val);

template<>
Poco::Dynamic::Var VarSerializer::serialize<sql::DataType>(const sql::DataType& val);

template<>
Poco::Dynamic::Var VarSerializer::serialize<sql::EvaluationStatus>(const sql::EvaluationStatus& val);


}  // namespace core
}  // namespace endpoint
}  // namespace privmx

#endif  // _PRIVMXLIB_ENDPOINT_SQL_VARSERIALIZER_HPP_
