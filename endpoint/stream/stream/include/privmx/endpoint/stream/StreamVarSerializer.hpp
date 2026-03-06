/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_ENDPOINT_STREAM_STREAMVARSERIALIZER_HPP_
#define _PRIVMXLIB_ENDPOINT_STREAM_STREAMVARSERIALIZER_HPP_

#include <Poco/Dynamic/Var.h>
#include <privmx/endpoint/core/VarSerializer.hpp>
#include <string>

#include "privmx/endpoint/stream/Events.hpp"
#include "privmx/endpoint/stream/Types.hpp"
#include "privmx/endpoint/stream/WebRTCInterface.hpp"

namespace privmx {
namespace endpoint {
namespace core {

template<>
Poco::Dynamic::Var VarSerializer::serialize<stream::Settings>(const stream::Settings& val);

template<>
Poco::Dynamic::Var VarSerializer::serialize<stream::TurnCredentials>(const stream::TurnCredentials& val);

template<>
Poco::Dynamic::Var VarSerializer::serialize<stream::Stream>(const stream::Stream& val);

template<>
Poco::Dynamic::Var VarSerializer::serialize<core::PagingList<stream::StreamRoom>>(const core::PagingList<stream::StreamRoom>& val);

template<>
Poco::Dynamic::Var VarSerializer::serialize<stream::StreamRoom>(const stream::StreamRoom& val);

template<>
Poco::Dynamic::Var VarSerializer::serialize<stream::StreamRoomDeletedEventData>(const stream::StreamRoomDeletedEventData& val);

template<>
Poco::Dynamic::Var VarSerializer::serialize<stream::StreamEventData>(const stream::StreamEventData& val);

template<>
Poco::Dynamic::Var VarSerializer::serialize<stream::StreamRoomCreatedEvent>(const stream::StreamRoomCreatedEvent& val);

template<>
Poco::Dynamic::Var VarSerializer::serialize<stream::StreamRoomUpdatedEvent>(const stream::StreamRoomUpdatedEvent& val);

template<>
Poco::Dynamic::Var VarSerializer::serialize<stream::StreamRoomDeletedEvent>(const stream::StreamRoomDeletedEvent& val);

template<>
Poco::Dynamic::Var VarSerializer::serialize<stream::StreamPublishedEvent>(const stream::StreamPublishedEvent& val);

template<>
Poco::Dynamic::Var VarSerializer::serialize<stream::StreamUpdatedEvent>(const stream::StreamUpdatedEvent& val);

template<>
Poco::Dynamic::Var VarSerializer::serialize<stream::StreamJoinedEvent>(const stream::StreamJoinedEvent& val);

template<>
Poco::Dynamic::Var VarSerializer::serialize<stream::StreamUnpublishedEventData>(const stream::StreamUnpublishedEventData& val);

template<>
Poco::Dynamic::Var VarSerializer::serialize<stream::StreamUnpublishedEvent>(const stream::StreamUnpublishedEvent& val);

template<>
Poco::Dynamic::Var VarSerializer::serialize<stream::StreamLeftEvent>(const stream::StreamLeftEvent& val);

template<>
Poco::Dynamic::Var VarSerializer::serialize<stream::SdpWithTypeModel>(const stream::SdpWithTypeModel& val);

template<>
Poco::Dynamic::Var VarSerializer::serialize<stream::SdpWithRoomModel>(const stream::SdpWithRoomModel& val);

template<>
Poco::Dynamic::Var VarSerializer::serialize<stream::UpdateSessionIdModel>(const stream::UpdateSessionIdModel& val);

template<>
Poco::Dynamic::Var VarSerializer::serialize<stream::RoomModel>(const stream::RoomModel& val);

template<>
Poco::Dynamic::Var VarSerializer::serialize<stream::StreamNewStreamsEvent>(const stream::StreamNewStreamsEvent& val);

template<>
Poco::Dynamic::Var VarSerializer::serialize<stream::NewStreams>(const stream::NewStreams& val);

template<>
Poco::Dynamic::Var VarSerializer::serialize<stream::StreamInfo>(const stream::StreamInfo& val);

template<>
Poco::Dynamic::Var VarSerializer::serialize<stream::StreamTrackInfo>(const stream::StreamTrackInfo& val);

template<>
Poco::Dynamic::Var VarSerializer::serialize<stream::StreamPublishResult>(const stream::StreamPublishResult& val);

template<>
Poco::Dynamic::Var VarSerializer::serialize<stream::StreamPublishedEventData>(const stream::StreamPublishedEventData& val);

template<>
Poco::Dynamic::Var VarSerializer::serialize<stream::StreamUpdatedEventData>(const stream::StreamUpdatedEventData& val);

template<>
Poco::Dynamic::Var VarSerializer::serialize<stream::StreamTrackModificationPair>(const stream::StreamTrackModificationPair& val);

template<>
Poco::Dynamic::Var VarSerializer::serialize<stream::StreamTrackModification>(const stream::StreamTrackModification& val);

template<>
Poco::Dynamic::Var VarSerializer::serialize<stream::UpdatedStreamData>(const stream::UpdatedStreamData& val);

template<>
Poco::Dynamic::Var VarSerializer::serialize<stream::StreamsUpdatedData>(const stream::StreamsUpdatedData& val);

template<>
Poco::Dynamic::Var VarSerializer::serialize<stream::StreamsUpdatedEvent>(const stream::StreamsUpdatedEvent& val);

template<>
Poco::Dynamic::Var VarSerializer::serialize<stream::Key>(const stream::Key& val);

template<>
Poco::Dynamic::Var VarSerializer::serialize<stream::StreamSubscription>(const stream::StreamSubscription& val);

template<>
Poco::Dynamic::Var VarSerializer::serialize<stream::KeyType>(const stream::KeyType& val);

template<>
Poco::Dynamic::Var VarSerializer::serialize<stream::RecordingEncKey>(const stream::RecordingEncKey& val);
}  // namespace core
}  // namespace endpoint
}  // namespace privmx

#endif  // _PRIVMXLIB_ENDPOINT_STREAM_STREAMVARSERIALIZER_HPP_
