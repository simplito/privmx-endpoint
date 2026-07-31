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
        .type = s.type,
        .mindex = s.mindex,
        .mid = s.mid,
        .disabled = s.disabled,
        .codec = s.codec,
        .description = s.description,
        .moderated = s.moderated,
        .simulcast = s.simulcast,
    };
}

StreamInfo Mapper::mapToStreamInfo(const server::StreamInfo& s) {
    std::vector<StreamTrackInfo> tracks;
    tracks.reserve(s.tracks.size());
    for (const auto& t : s.tracks) {
        tracks.push_back(mapToStreamTrackInfo(t));
    }
    return {
        .id = s.id,
        .userId = s.userId,
        .metadata = s.metadata.has_value() ? std::make_optional(s.metadata.value().convert<std::string>()) :
                                             std::nullopt,
        .dummy = s.dummy,
        .tracks = std::move(tracks),
    };
}

StreamTrackModificationPair Mapper::mapToStreamTrackModificationPair(const server::StreamTrackModificationPair& s) {
    return {
        .before = s.before.has_value() ? std::make_optional(mapToStreamTrackInfo(s.before.value())) : std::nullopt,
        .after = s.after.has_value() ? std::make_optional(mapToStreamTrackInfo(s.after.value())) : std::nullopt,
    };
}

PublishedStreamData Mapper::mapToPublishedStreamData(const server::StreamPublishedEventData& s) {
    return {
        .streamRoomId = s.streamRoomId,
        .stream = mapToStreamInfo(s.stream),
        .userId = s.userId,
    };
}

PublishedStreamData Mapper::mapToPublishedStreamData(const server::PublishedStreamData& s) {
    return {
        .streamRoomId = s.streamRoomId,
        .stream = mapToStreamInfo(s.stream),
        .userId = s.userId,
    };
}

StreamUpdatedEventData Mapper::mapToStreamUpdatedEventData(const server::StreamUpdatedEventData& s) {
    std::vector<StreamTrackInfo> tracksAdded;
    tracksAdded.reserve(s.tracksAdded.size());
    for (const auto& t : s.tracksAdded) {
        tracksAdded.push_back(mapToStreamTrackInfo(t));
    }
    std::vector<StreamTrackInfo> tracksRemoved;
    tracksRemoved.reserve(s.tracksRemoved.size());
    for (const auto& t : s.tracksRemoved) {
        tracksRemoved.push_back(mapToStreamTrackInfo(t));
    }
    std::vector<StreamTrackModificationPair> tracksModified;
    tracksModified.reserve(s.tracksModified.size());
    for (const auto& p : s.tracksModified) {
        tracksModified.push_back(mapToStreamTrackModificationPair(p));
    }
    return {
        .streamRoomId = s.streamRoomId,
        .streamId = s.streamId,
        .userId = s.userId,
        .tracksAdded = std::move(tracksAdded),
        .tracksRemoved = std::move(tracksRemoved),
        .tracksModified = std::move(tracksModified),
    };
}
StreamSubscriptionEventData Mapper::mapToStreamSubscriptionEventData(const server::StreamSubscriptionEventData& s) {
    std::vector<StreamSubscription> subscriptions;
    subscriptions.reserve(s.subscriptions.size());
    for (const auto& sub : s.subscriptions) {
        subscriptions.push_back(StreamSubscription{.streamId = sub.streamId, .streamTrackId = sub.streamTrackId});
    }
    return {
        .streamRoomId = s.streamRoomId,
        .userId = s.userId,
        .subscriptions = std::move(subscriptions),
    };
}

StreamSubscriber Mapper::mapToStreamSubscriber(const server::StreamSubscriber& s) {
    std::vector<StreamSubscription> subscriptions;
    subscriptions.reserve(s.subscriptions.size());
    for (const auto& sub : s.subscriptions) {
        subscriptions.push_back(StreamSubscription{.streamId = sub.streamId, .streamTrackId = sub.streamTrackId});
    }
    std::optional<StreamInfo> publishedStream;
    if (s.publishedStream.has_value()) {
        publishedStream = mapToStreamInfo(s.publishedStream.value());
    }
    return {
        .userId = s.userId,
        .subscriptions = std::move(subscriptions),
        .publishedStream = std::move(publishedStream),
    };
}
