/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_ENDPOINT_INBOX_VARDESERIALIZER_HPP_
#define _PRIVMXLIB_ENDPOINT_INBOX_VARDESERIALIZER_HPP_

#include <Poco/Dynamic/Var.h>

#include <privmx/endpoint/core/VarDeserializer.hpp>
#include <string>

#include "privmx/endpoint/inbox/Types.hpp"

namespace privmx {
namespace endpoint {
namespace core {

template<>
inbox::FilesConfig VarDeserializer::deserialize<inbox::FilesConfig>(const Poco::Dynamic::Var& val, const std::string& name);

template<>
inbox::EventType VarDeserializer::deserialize<inbox::EventType>(const Poco::Dynamic::Var& val, const std::string& name);

template<>
inbox::EventSelectorType VarDeserializer::deserialize<inbox::EventSelectorType>(const Poco::Dynamic::Var& val, const std::string& name);

}  // namespace core
}  // namespace endpoint
}  // namespace privmx

#endif  // _PRIVMXLIB_ENDPOINT_INBOX_VARDESERIALIZER_HPP_
