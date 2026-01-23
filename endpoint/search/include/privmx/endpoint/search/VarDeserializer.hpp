/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_ENDPOINT_SEARCH_VARDESERIALIZER_HPP_
#define _PRIVMXLIB_ENDPOINT_SEARCH_VARDESERIALIZER_HPP_

#include <Poco/Dynamic/Var.h>
#include <string>

#include "privmx/endpoint/core/VarDeserializer.hpp"
#include "privmx/endpoint/search/Types.hpp"

namespace privmx {
namespace endpoint {
namespace core {

template<>
search::IndexMode VarDeserializer::deserialize<search::IndexMode>(const Poco::Dynamic::Var& val, const std::string& name);

template<>
search::Document VarDeserializer::deserialize<search::Document>(const Poco::Dynamic::Var& val, const std::string& name);

}  // namespace core
}  // namespace endpoint
}  // namespace privmx

#endif  // _PRIVMXLIB_ENDPOINT_SEARCH_VARDESERIALIZER_HPP_
