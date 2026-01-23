/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_ENDPOINT_SEARCH_VARSERIALIZER_HPP_
#define _PRIVMXLIB_ENDPOINT_SEARCH_VARSERIALIZER_HPP_

#include <Poco/Dynamic/Var.h>

#include <privmx/endpoint/core/VarSerializer.hpp>
#include <string>

#include "privmx/endpoint/search/Types.hpp"

namespace privmx {
namespace endpoint {
namespace core {

template<>
Poco::Dynamic::Var VarSerializer::serialize<core::PagingList<search::SearchIndex>>(const core::PagingList<search::SearchIndex>& val);

template<>
Poco::Dynamic::Var VarSerializer::serialize<core::PagingList<search::Document>>(const core::PagingList<search::Document>& val);

template<>
Poco::Dynamic::Var VarSerializer::serialize<search::IndexMode>(const search::IndexMode& val);

template<>
Poco::Dynamic::Var VarSerializer::serialize<search::SearchIndex>(const search::SearchIndex& val);

template<>
Poco::Dynamic::Var VarSerializer::serialize<search::Document>(const search::Document& val);


}  // namespace core
}  // namespace endpoint
}  // namespace privmx

#endif  // _PRIVMXLIB_ENDPOINT_SEARCH_VARSERIALIZER_HPP_
