/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_ENDPOINT_STREAM_STREAMVARDESERIALIZER_HPP_
#define _PRIVMXLIB_ENDPOINT_STREAM_STREAMVARDESERIALIZER_HPP_

#include <Poco/Dynamic/Var.h>

#include <privmx/endpoint/core/VarDeserializer.hpp>
#include <string>

#include "privmx/endpoint/stream/Types.hpp"

namespace privmx {
namespace endpoint {
namespace core {

template<>
stream::Settings VarDeserializer::deserialize<stream::Settings>(const Poco::Dynamic::Var& val, const std::string& name);

template<>
stream::EventType VarDeserializer::deserialize<stream::EventType>(const Poco::Dynamic::Var& val, const std::string& name);

template<>
stream::EventSelectorType VarDeserializer::deserialize<stream::EventSelectorType>(const Poco::Dynamic::Var& val, const std::string& name);

template<>
stream::VideoRoomStreamTrack VarDeserializer::deserialize<stream::VideoRoomStreamTrack>(const Poco::Dynamic::Var& val, const std::string& name);

template<>
stream::NewPublisherEvent VarDeserializer::deserialize<stream::NewPublisherEvent>(const Poco::Dynamic::Var& val, const std::string& name);

template<>
stream::CurrentPublishersData VarDeserializer::deserialize<stream::CurrentPublishersData>(const Poco::Dynamic::Var& val, const std::string& name);

}  // namespace core
}  // namespace endpoint
}  // namespace privmx

#endif  // _PRIVMXLIB_ENDPOINT_STREAM_STREAMVARDESERIALIZER_HPP_
