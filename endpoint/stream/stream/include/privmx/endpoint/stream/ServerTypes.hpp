/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_ENDPOINT_STREAM_SERVERTYPES_HPP_
#define _PRIVMXLIB_ENDPOINT_STREAM_SERVERTYPES_HPP_

#include <privmx/endpoint/core/ServerTypes.hpp>
#include <privmx/endpoint/core/TypesMacros.hpp>
#include <string>

#include "privmx/utils/TypesMacros.hpp"

namespace privmx {
namespace endpoint {
namespace stream {
namespace server {

ENDPOINT_SERVER_TYPE(StreamRoomDataEntry)
    STRING_FIELD(keyId)
    VAR_FIELD(data)
TYPE_END

ENDPOINT_SERVER_TYPE(StreamRoomInfo)
    STRING_FIELD(id)
    STRING_FIELD(resourceId)
    STRING_FIELD(contextId)
    INT64_FIELD(createDate)
    STRING_FIELD(creator)
    INT64_FIELD(lastModificationDate)
    STRING_FIELD(lastModifier)
    LIST_FIELD(data, StreamRoomDataEntry)
    STRING_FIELD(keyId)
    LIST_FIELD(users, std::string)
    LIST_FIELD(managers, std::string)
    LIST_FIELD(keys, core::server::KeyEntry)
    INT64_FIELD(version)
    STRING_FIELD(type)
    VAR_FIELD(policy)
TYPE_END


ENDPOINT_SERVER_TYPE(StreamRoomCreateModel)
    STRING_FIELD(contextId)
    STRING_FIELD(resourceId)
    STRING_FIELD(keyId)
    VAR_FIELD(data)
    LIST_FIELD(users, std::string)
    LIST_FIELD(managers, std::string)
    LIST_FIELD(keys, core::server::KeyEntrySet)
    STRING_FIELD(privateMeta)
    STRING_FIELD(publicMeta)
    VAR_FIELD(policy)
TYPE_END

ENDPOINT_SERVER_TYPE(StreamRoomCreateResult)
    STRING_FIELD(streamRoomId)
TYPE_END

ENDPOINT_SERVER_TYPE(StreamRoomUpdateModel)
    STRING_FIELD(id)
    STRING_FIELD(resourceId)
    STRING_FIELD(keyId)
    VAR_FIELD(data)
    LIST_FIELD(users, std::string)
    LIST_FIELD(managers, std::string)
    LIST_FIELD(keys, core::server::KeyEntrySet)
    STRING_FIELD(privateMeta)
    STRING_FIELD(publicMeta)
    INT64_FIELD(version)
    BOOL_FIELD(force)
    VAR_FIELD(policy)
TYPE_END

ENDPOINT_SERVER_TYPE(StreamRoomGetModel)
    STRING_FIELD(id)
    STRING_FIELD(type)
TYPE_END

ENDPOINT_SERVER_TYPE(StreamRoomGetResult)
    OBJECT_FIELD(streamRoom, StreamRoomInfo)
TYPE_END

ENDPOINT_SERVER_TYPE_INHERIT(StreamRoomListModel, core::server::ListModel)
    STRING_FIELD(contextId)
    STRING_FIELD(type)
TYPE_END

ENDPOINT_SERVER_TYPE(StreamRoomListResult)
    LIST_FIELD(list, StreamRoomInfo)
    INT64_FIELD(count)
TYPE_END

ENDPOINT_SERVER_TYPE(StreamRoomDeleteModel)
    STRING_FIELD(id)
TYPE_END

ENDPOINT_SERVER_TYPE(StreamGetTurnCredentialsModel)
TYPE_END

ENDPOINT_SERVER_TYPE(TurnCredentials)
    STRING_FIELD(url)
    STRING_FIELD(username)
    STRING_FIELD(password)
    INT64_FIELD(expirationTime)
TYPE_END

ENDPOINT_SERVER_TYPE(StreamGetTurnCredentialsResult)
    LIST_FIELD(credentials, TurnCredentials)
TYPE_END

ENDPOINT_SERVER_TYPE(SessionDescription)
    STRING_FIELD(sdp)
    STRING_FIELD(type)
TYPE_END

ENDPOINT_SERVER_TYPE(StreamPublishModel)
    OBJECT_FIELD(offer, SessionDescription)
    STRING_FIELD(streamRoomId)
TYPE_END

ENDPOINT_SERVER_TYPE(StreamPublishResult)
    OBJECT_FIELD(answer, SessionDescription)
    INT64_FIELD(sessionId)
TYPE_END

// ENDPOINT_SERVER_TYPE(StreamJoinModel)
//     LIST_FIELD(streamIds, int64_t)
//     STRING_FIELD(streamRoomId)
// TYPE_END

// export interface StreamsSubscribeModel {
//     streamRoomId: types.stream.StreamRoomId;
//     subscriptionsToAdd: StreamSubscription[];
// }
//
// export interface StreamsUnsubscribeModel {
//     streamRoomId: types.stream.StreamRoomId;
//     subscriptionsToRemove: StreamSubscription[];
// }

// export interface StreamSubscribeResult {
//     offer?: {
//         type: "offer";
//         sdp: string;
//     }
// }

ENDPOINT_SERVER_TYPE(StreamSubscription)
    INT64_FIELD(streamId)
    STRING_FIELD(streamTrackId)
TYPE_END

ENDPOINT_SERVER_TYPE(StreamsSubscribeModel)
    STRING_FIELD(streamRoomId)
    LIST_FIELD(subscriptionsToAdd, StreamSubscription)
TYPE_END

ENDPOINT_SERVER_TYPE(StreamsModifySubscriptionsModel)
    STRING_FIELD(streamRoomId)
    LIST_FIELD(subscriptionsToAdd, StreamSubscription)
    LIST_FIELD(subscriptionsToRemove, StreamSubscription)
TYPE_END

ENDPOINT_SERVER_TYPE(StreamsUnsubscribeModel)
    STRING_FIELD(streamRoomId)
    LIST_FIELD(subscriptionsToRemove, StreamSubscription)
TYPE_END

ENDPOINT_SERVER_TYPE(StreamsSubscribeResult)
    OBJECT_FIELD(offer, SessionDescription)
    INT64_FIELD(sessionId)
TYPE_END

ENDPOINT_SERVER_TYPE(StreamRoomJoinModel)
    STRING_FIELD(streamRoomId)
TYPE_END

ENDPOINT_SERVER_TYPE(StreamRoomLeaveModel)
    STRING_FIELD(streamRoomId)
TYPE_END


ENDPOINT_SERVER_TYPE(StreamListModel)
    STRING_FIELD(streamRoomId)
TYPE_END

ENDPOINT_SERVER_TYPE(Stream)
    INT64_FIELD(streamId)
    STRING_FIELD(userId)
    VAR_FIELD(createStreamMeta)
    VAR_FIELD(remoteStreamInfo)
TYPE_END

ENDPOINT_SERVER_TYPE(StreamListResult)
    LIST_FIELD(list, Stream)
TYPE_END

ENDPOINT_SERVER_TYPE(StreamAcceptOfferModel)
    OBJECT_FIELD(answer, SessionDescription)
    INT64_FIELD(sessionId)
TYPE_END

ENDPOINT_SERVER_TYPE(StreamSendEventModel)
    LIST_FIELD(keys, privmx::endpoint::core::server::KeyEntrySet);
    STRING_FIELD(data)
TYPE_END

ENDPOINT_SERVER_TYPE(StreamRoomSendCustomEventModel)
    STRING_FIELD(streamRoomId)
    STRING_FIELD(channel)
    STRING_FIELD(keyId)
    VAR_FIELD(data)
    LIST_FIELD(users, std::string)
TYPE_END

ENDPOINT_SERVER_TYPE(StreamUnpublishModel)
    INT64_FIELD(sessionId)
TYPE_END

ENDPOINT_SERVER_TYPE(StreamTrickleModel)
    OBJECT_PTR_FIELD(candidate)
    INT64_FIELD(sessionId)
TYPE_END

ENDPOINT_CLIENT_TYPE(ContextGetUsersModel)
    STRING_FIELD(contextId)
TYPE_END

ENDPOINT_CLIENT_TYPE(ContextGetUserResult)
    LIST_FIELD(users, core::server::UserIdentity)
TYPE_END

// Events

ENDPOINT_SERVER_TYPE(StreamRoomDeletedEventData)
    STRING_FIELD(streamRoomId)
    STRING_FIELD(type)
TYPE_END

ENDPOINT_SERVER_TYPE(StreamEventData)
    STRING_FIELD(streamRoomId)
    LIST_FIELD(streamIds, int64_t)
    STRING_FIELD(userId)
TYPE_END

ENDPOINT_SERVER_TYPE(StreamUnpublishedEventData)
    STRING_FIELD(streamRoomId)
    INT64_FIELD(streamId)
TYPE_END
// JANUS events data

ENDPOINT_SERVER_TYPE(JanusEventData)
    STRING_FIELD(janus)
    INT64_FIELD(sender)
    INT64_FIELD(session_id)
TYPE_END

ENDPOINT_SERVER_TYPE(JanusJSEP)
    STRING_FIELD(sdp)
    STRING_FIELD(type)
TYPE_END

ENDPOINT_SERVER_TYPE(JanusVideoRoomStream)
    BOOL_FIELD(active)
    INT64_FIELD(mid)
    INT64_FIELD(mindex)
    BOOL_FIELD(ready)
    BOOL_FIELD(send)
    STRING_FIELD(type)
TYPE_END

ENDPOINT_SERVER_TYPE(JanusVideoRoom)
    STRING_FIELD(videoroom)
TYPE_END

ENDPOINT_SERVER_TYPE_INHERIT(JanusVideoRoomUpdated, JanusVideoRoom)
    STRING_FIELD(room)
    LIST_FIELD(streams, JanusVideoRoomStream)    
TYPE_END

ENDPOINT_SERVER_TYPE(JanusPluginDataEvent)
    VAR_FIELD(data)
    STRING_FIELD(plugin)
TYPE_END

ENDPOINT_SERVER_TYPE_INHERIT(JanusPluginEvent, JanusEventData)
    OBJECT_FIELD(jsep, JanusJSEP)
    OBJECT_FIELD(plugindata, JanusPluginDataEvent)
TYPE_END

ENDPOINT_SERVER_TYPE(VideoRoomStreamTrack)
    STRING_FIELD(type)
    STRING_FIELD(codec)
    STRING_FIELD(mid)
    INT64_FIELD(mindex)
TYPE_END

ENDPOINT_SERVER_TYPE(NewPublisherEvent)
    INT64_FIELD(id)
    STRING_FIELD(userId)
    STRING_FIELD(video_codec)
    LIST_FIELD(streams, VideoRoomStreamTrack)
TYPE_END

ENDPOINT_SERVER_TYPE(CurrentPublishersData)
    STRING_FIELD(room)
    LIST_FIELD(publishers, NewPublisherEvent)
TYPE_END

ENDPOINT_SERVER_TYPE(UpdatedStreamData)
    STRING_FIELD(type)
    INT64_FIELD(feed_id)
    INT64_FIELD(feed_mid)
    STRING_FIELD(feed_display)
    INT64_FIELD(mindex)
    STRING_FIELD(mid)
    BOOL_FIELD(send)
    BOOL_FIELD(ready)
TYPE_END

ENDPOINT_SERVER_TYPE(StreamsUpdatedData)
    STRING_FIELD(room)
    INT64_FIELD(sessionId)
    LIST_FIELD(streams, UpdatedStreamData)
    OBJECT_FIELD(jsep, JanusJSEP)
TYPE_END



} // server
} // stream
} // endpoint
} // privmx

#endif // _PRIVMXLIB_ENDPOINT_STREAM_SERVERTYPES_HPP_
