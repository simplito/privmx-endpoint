/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_ENDPOINT_STORE_VARDESERIALIZER_HPP_
#define _PRIVMXLIB_ENDPOINT_STORE_VARDESERIALIZER_HPP_

#include <Poco/Dynamic/Var.h>

#include <privmx/endpoint/core/VarDeserializer.hpp>
#include <string>

#include "privmx/endpoint/store/Types.hpp"

namespace privmx {
namespace endpoint {
namespace core {

template<>
store::EventType VarDeserializer::deserialize<store::EventType>(const Poco::Dynamic::Var& val, const std::string& name);

template<>
store::EventSelectorType VarDeserializer::deserialize<store::EventSelectorType>(const Poco::Dynamic::Var& val, const std::string& name);

}  // namespace core
}  // namespace endpoint
}  // namespace privmx

#endif  // _PRIVMXLIB_ENDPOINT_STORE_VARDESERIALIZER_HPP_
