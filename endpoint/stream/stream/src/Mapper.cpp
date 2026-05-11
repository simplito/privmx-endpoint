/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include "privmx/endpoint/stream/Mapper.hpp"

#include <algorithm>

using namespace privmx::endpoint::stream;

StreamTrackInfo Mapper::mapToStreamTrackInfo(const server::StreamTrackInfo& s) {
    return {
        .type        = s.type,
        .mindex      = s.mindex,
        .mid         = s.mid,
        .disabled    = s.disabled,
        .codec       = s.codec,
        .description = s.description,
        .moderated   = s.moderated,
        .simulcast   = s.simulcast,
        .talking     = s.talking,
    };
}

StreamInfo Mapper::mapToStreamInfo(const server::StreamInfo& s) {
    std::vector<StreamTrackInfo> tracks;
    tracks.reserve(s.tracks.size());
    for (const auto& t : s.tracks) {
        tracks.push_back(mapToStreamTrackInfo(t));
    }
    return {
        .id       = s.id,
        .userId   = s.userId,
        .metadata = s.metadata.has_value() ? std::make_optional(s.metadata.value().convert<std::string>()) : std::nullopt,
        .dummy    = s.dummy,
        .tracks   = std::move(tracks),
        .talking  = s.talking,
    };
}

StreamTrackModificationPair Mapper::mapToStreamTrackModificationPair(const server::StreamTrackModificationPair& s) {
    return {
        .before = s.before.has_value() ? std::make_optional(mapToStreamTrackInfo(s.before.value())) : std::nullopt,
        .after  = s.after.has_value()  ? std::make_optional(mapToStreamTrackInfo(s.after.value()))  : std::nullopt,
    };
}

StreamTrackModification Mapper::mapToStreamTrackModification(const server::StreamTrackModification& s) {
    std::vector<StreamTrackModificationPair> tracks;
    tracks.reserve(s.tracks.size());
    for (const auto& t : s.tracks) {
        tracks.push_back(mapToStreamTrackModificationPair(t));
    }
    return {
        .streamId = s.streamId,
        .tracks   = std::move(tracks),
    };
}

NewStreams Mapper::mapToNewStreams(const server::NewStreams& s) {
    std::vector<StreamInfo> streams;
    streams.reserve(s.streams.size());
    for (const auto& st : s.streams) {
        streams.push_back(mapToStreamInfo(st));
    }
    return {
        .room    = s.room,
        .streams = std::move(streams),
    };
}

PublishedStreamData Mapper::mapToPublishedStreamData(const server::StreamPublishedEventData& s) {
    return {
        .streamRoomId = s.streamRoomId,
        .stream       = mapToStreamInfo(s.stream),
        .userId       = s.userId,
    };
}

PublishedStreamData Mapper::mapToPublishedStreamData(const server::PublishedStreamData& s) {
    return {
        .streamRoomId = s.streamRoomId,
        .stream       = mapToStreamInfo(s.stream),
        .userId       = s.userId,
    };
}

StreamUpdatedEventData Mapper::mapToStreamUpdatedEventData(const server::StreamUpdatedEventData& s) {
    std::vector<StreamInfo> streamsAdded;
    streamsAdded.reserve(s.streamsAdded.size());
    for (const auto& st : s.streamsAdded) {
        streamsAdded.push_back(mapToStreamInfo(st));
    }
    std::vector<StreamInfo> streamsRemoved;
    streamsRemoved.reserve(s.streamsRemoved.size());
    for (const auto& st : s.streamsRemoved) {
        streamsRemoved.push_back(mapToStreamInfo(st));
    }
    std::vector<StreamTrackModification> streamsModified;
    streamsModified.reserve(s.streamsModified.size());
    for (const auto& m : s.streamsModified) {
        streamsModified.push_back(mapToStreamTrackModification(m));
    }
    return {
        .streamRoomId    = s.streamRoomId,
        .streamsAdded    = std::move(streamsAdded),
        .streamsRemoved  = std::move(streamsRemoved),
        .streamsModified = std::move(streamsModified),
    };
}

UpdatedStreamData Mapper::mapToUpdatedStreamData(const server::UpdatedStreamData& s) {
    return {
        .active         = s.active,
        .type           = s.type,
        .codec          = s.codec,
        .streamId       = s.feed_id,
        .streamMid      = s.feed_mid,
        .stream_display = s.feed_display,
        .mindex         = s.mindex,
        .mid            = s.mid,
        .send           = s.send,
        .ready          = s.ready,
    };
}

StreamsUpdatedData Mapper::mapToStreamsUpdatedData(const server::StreamsUpdatedData& s) {
    std::vector<UpdatedStreamData> streams;
    streams.reserve(s.streams.size());
    for (const auto& st : s.streams) {
        streams.push_back(mapToUpdatedStreamData(st));
    }
    return {
        .room    = s.room,
        .streams = std::move(streams),
    };
}
