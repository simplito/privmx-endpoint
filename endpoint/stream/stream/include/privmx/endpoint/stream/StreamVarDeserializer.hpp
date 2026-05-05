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
void VarDeserializer::deserialize<stream::Settings>(const Poco::Dynamic::Var& val, const std::string& name, stream::Settings& out);

template<>
void VarDeserializer::deserialize<stream::EventType>(const Poco::Dynamic::Var& val, const std::string& name, stream::EventType& out);

template<>
void VarDeserializer::deserialize<stream::EventSelectorType>(const Poco::Dynamic::Var& val, const std::string& name, stream::EventSelectorType& out);

template<>
void VarDeserializer::deserialize<stream::StreamTrackInfo>(const Poco::Dynamic::Var& val, const std::string& name, stream::StreamTrackInfo& out);

template<>
void VarDeserializer::deserialize<stream::StreamInfo>(const Poco::Dynamic::Var& val, const std::string& name, stream::StreamInfo& out);

template<>
void VarDeserializer::deserialize<stream::SdpWithTypeModel>(const Poco::Dynamic::Var& val, const std::string& name, stream::SdpWithTypeModel& out);

template<>
void VarDeserializer::deserialize<stream::NewStreams>(const Poco::Dynamic::Var& val, const std::string& name, stream::NewStreams& out);

template<>
void VarDeserializer::deserialize<stream::StreamsUpdatedDataInternal>(const Poco::Dynamic::Var& val, const std::string& name, stream::StreamsUpdatedDataInternal& out);

template<>
void VarDeserializer::deserialize<stream::StreamsUpdatedData>(const Poco::Dynamic::Var& val, const std::string& name, stream::StreamsUpdatedData& out);

template<>
void VarDeserializer::deserialize<stream::StreamSubscription>(const Poco::Dynamic::Var& val, const std::string& name, stream::StreamSubscription& out);

template<>
void VarDeserializer::deserialize<stream::StreamPublishedEventData>(const Poco::Dynamic::Var& val, const std::string& name, stream::StreamPublishedEventData& out);

template<>
void VarDeserializer::deserialize<stream::StreamUpdatedEventData>(const Poco::Dynamic::Var& val, const std::string& name, stream::StreamUpdatedEventData& out);

template<>
void VarDeserializer::deserialize<stream::StreamTrackModificationPair>(const Poco::Dynamic::Var& val, const std::string& name, stream::StreamTrackModificationPair& out);

template<>
void VarDeserializer::deserialize<stream::StreamTrackModification>(const Poco::Dynamic::Var& val, const std::string& name, stream::StreamTrackModification& out);

}  // namespace core
}  // namespace endpoint
}  // namespace privmx

#endif  // _PRIVMXLIB_ENDPOINT_STREAM_STREAMVARDESERIALIZER_HPP_
