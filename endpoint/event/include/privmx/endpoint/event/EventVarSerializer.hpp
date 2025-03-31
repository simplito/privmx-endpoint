/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_ENDPOINT_EVENT_EVENTVARSERIALIZER_HPP_
#define _PRIVMXLIB_ENDPOINT_EVENT_EVENTVARSERIALIZER_HPP_

#include <Poco/Dynamic/Var.h>

#include <privmx/endpoint/core/VarSerializer.hpp>
#include "privmx/endpoint/event/Events.hpp"
#include <string>

#include "privmx/endpoint/event/Types.hpp"
#include "privmx/endpoint/event/Events.hpp"

namespace privmx {
namespace endpoint {
namespace core {

template<>
Poco::Dynamic::Var VarSerializer::serialize<event::ContextCustomEvent>(const event::ContextCustomEvent& val);

template<>
Poco::Dynamic::Var VarSerializer::serialize<event::ContextCustomEventData>(const event::ContextCustomEventData& val);


}  // namespace core
}  // namespace endpoint
}  // namespace privmx

#endif  // _PRIVMXLIB_ENDPOINT_EVENT_EVENTVARSERIALIZER_HPP_
