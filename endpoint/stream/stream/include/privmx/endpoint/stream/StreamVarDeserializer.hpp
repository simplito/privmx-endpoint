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
#include "privmx/endpoint/stream/Events.hpp"

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
stream::StreamTrackInfo VarDeserializer::deserialize<stream::StreamTrackInfo>(const Poco::Dynamic::Var& val, const std::string& name);

template<>
stream::StreamInfo VarDeserializer::deserialize<stream::StreamInfo>(const Poco::Dynamic::Var& val, const std::string& name);

template<>
stream::SdpWithTypeModel VarDeserializer::deserialize<stream::SdpWithTypeModel>(const Poco::Dynamic::Var& val, const std::string& name);

template<>
stream::NewStreams VarDeserializer::deserialize<stream::NewStreams>(const Poco::Dynamic::Var& val, const std::string& name);

template<>
stream::StreamsUpdatedDataInternal VarDeserializer::deserialize<stream::StreamsUpdatedDataInternal>(const Poco::Dynamic::Var& val, const std::string& name);

template<>
stream::StreamsUpdatedData VarDeserializer::deserialize<stream::StreamsUpdatedData>(const Poco::Dynamic::Var& val, const std::string& name);

template<>
stream::StreamSubscription VarDeserializer::deserialize<stream::StreamSubscription>(const Poco::Dynamic::Var& val, const std::string& name);

template<>
stream::StreamPublishedEventData VarDeserializer::deserialize<stream::StreamPublishedEventData>(const Poco::Dynamic::Var& val, const std::string& name);

template<>
stream::StreamUpdatedEventData VarDeserializer::deserialize<stream::StreamUpdatedEventData>(const Poco::Dynamic::Var& val, const std::string& name);

template<>
stream::StreamTrackModificationPair VarDeserializer::deserialize<stream::StreamTrackModificationPair>(const Poco::Dynamic::Var& val, const std::string& name);

template<>
stream::StreamTrackModification VarDeserializer::deserialize<stream::StreamTrackModification>(const Poco::Dynamic::Var& val, const std::string& name);

}  // namespace core
}  // namespace endpoint
}  // namespace privmx

#endif  // _PRIVMXLIB_ENDPOINT_STREAM_STREAMVARDESERIALIZER_HPP_
