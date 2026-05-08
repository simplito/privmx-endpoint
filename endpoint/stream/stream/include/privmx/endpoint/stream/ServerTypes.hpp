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

#include <optional>
#include <string>
#include <vector>

#include <privmx/endpoint/core/ServerTypes.hpp>
#include <privmx/utils/JsonHelper.hpp>

namespace privmx {
namespace endpoint {
namespace stream {
namespace server {

#define STREAM_ROOM_DATA_ENTRY_FIELDS(F)\
    F(keyId, std::string)\
    F(data,  Poco::Dynamic::Var)
JSON_STRUCT(StreamRoomDataEntry, STREAM_ROOM_DATA_ENTRY_FIELDS);

#define STREAM_ROOM_INFO_FIELDS(F)\
    F(id,                   std::string)\
    F(resourceId,           std::optional<std::string>)\
    F(contextId,            std::string)\
    F(createDate,           int64_t)\
    F(creator,              std::string)\
    F(lastModificationDate, int64_t)\
    F(lastModifier,         std::string)\
    F(data,                 std::vector<StreamRoomDataEntry>)\
    F(keyId,                std::string)\
    F(users,                std::vector<std::string>)\
    F(managers,             std::vector<std::string>)\
    F(keys,                 std::vector<core::server::KeyEntry>)\
    F(version,              int64_t)\
    F(type,                 std::optional<std::string>)\
    F(policy,               Poco::Dynamic::Var)\
    F(closed,               std::optional<bool>)
JSON_STRUCT(StreamRoomInfo, STREAM_ROOM_INFO_FIELDS);

#define SESSION_DESCRIPTION_FIELDS(F)\
    F(sdp,  std::string)\
    F(type, std::string)
JSON_STRUCT(SessionDescription, SESSION_DESCRIPTION_FIELDS);

#define STREAM_ROOM_CREATE_MODEL_FIELDS(F)\
    F(contextId,   std::string)\
    F(resourceId,  std::string)\
    F(keyId,       std::string)\
    F(data,        Poco::Dynamic::Var)\
    F(users,       std::vector<std::string>)\
    F(managers,    std::vector<std::string>)\
    F(keys,        std::vector<core::server::KeyEntrySet>)\
    F(type,        std::string)\
    F(policy,      std::optional<Poco::Dynamic::Var>)
JSON_STRUCT(StreamRoomCreateModel, STREAM_ROOM_CREATE_MODEL_FIELDS);

#define STREAM_ROOM_CREATE_RESULT_FIELDS(F)\
    F(streamRoomId, std::string)
JSON_STRUCT(StreamRoomCreateResult, STREAM_ROOM_CREATE_RESULT_FIELDS);

#define STREAM_ROOM_UPDATE_MODEL_FIELDS(F)\
    F(id,          std::string)\
    F(resourceId,  std::string)\
    F(keyId,       std::string)\
    F(data,        Poco::Dynamic::Var)\
    F(users,       std::vector<std::string>)\
    F(managers,    std::vector<std::string>)\
    F(keys,        std::vector<core::server::KeyEntrySet>)\
    F(version,     int64_t)\
    F(force,       bool)\
    F(policy,      std::optional<Poco::Dynamic::Var>)
JSON_STRUCT(StreamRoomUpdateModel, STREAM_ROOM_UPDATE_MODEL_FIELDS);

#define STREAM_ROOM_GET_MODEL_FIELDS(F)\
    F(id,   std::string)\
    F(type, std::optional<std::string>)
JSON_STRUCT(StreamRoomGetModel, STREAM_ROOM_GET_MODEL_FIELDS);

#define STREAM_ROOM_GET_RESULT_FIELDS(F)\
    F(streamRoom, StreamRoomInfo)
JSON_STRUCT(StreamRoomGetResult, STREAM_ROOM_GET_RESULT_FIELDS);

#define STREAM_ROOM_LIST_MODEL_FIELDS(F)\
    F(contextId, std::string)\
    F(type,      std::optional<std::string>)
JSON_STRUCT_EXT(StreamRoomListModel, core::server::ListModel, STREAM_ROOM_LIST_MODEL_FIELDS);

#define STREAM_ROOM_LIST_RESULT_FIELDS(F)\
    F(list,  std::vector<StreamRoomInfo>)\
    F(count, int64_t)
JSON_STRUCT(StreamRoomListResult, STREAM_ROOM_LIST_RESULT_FIELDS);

#define STREAM_ROOM_DELETE_MODEL_FIELDS(F)\
    F(id, std::string)
JSON_STRUCT(StreamRoomDeleteModel, STREAM_ROOM_DELETE_MODEL_FIELDS);

#define TURN_CREDENTIALS_FIELDS(F)\
    F(url,            std::string)\
    F(username,       std::string)\
    F(password,       std::string)\
    F(expirationTime, int64_t)
JSON_STRUCT(TurnCredentials, TURN_CREDENTIALS_FIELDS);

#define STREAM_GET_TURN_CREDENTIALS_RESULT_FIELDS(F)\
    F(credentials, std::vector<TurnCredentials>)
JSON_STRUCT(StreamGetTurnCredentialsResult, STREAM_GET_TURN_CREDENTIALS_RESULT_FIELDS);

#define STREAM_PUBLISH_MODEL_FIELDS(F)\
    F(offer,        SessionDescription)\
    F(streamRoomId, std::string)
JSON_STRUCT(StreamPublishModel, STREAM_PUBLISH_MODEL_FIELDS);

#define STREAM_UPDATE_MODEL_FIELDS(F)\
    F(offer,        SessionDescription)\
    F(streamRoomId, std::string)
JSON_STRUCT(StreamUpdateModel, STREAM_UPDATE_MODEL_FIELDS);

#define STREAM_SUBSCRIPTION_FIELDS(F)\
    F(streamId,      int64_t)\
    F(streamTrackId, std::optional<std::string>)
JSON_STRUCT(StreamSubscription, STREAM_SUBSCRIPTION_FIELDS);

#define STREAMS_SUBSCRIBE_MODEL_FIELDS(F)\
    F(streamRoomId,       std::string)\
    F(subscriptionsToAdd, std::vector<StreamSubscription>)
JSON_STRUCT(StreamsSubscribeModel, STREAMS_SUBSCRIBE_MODEL_FIELDS);

#define STREAMS_MODIFY_SUBSCRIPTIONS_MODEL_FIELDS(F)\
    F(streamRoomId,          std::string)\
    F(subscriptionsToAdd,    std::vector<StreamSubscription>)\
    F(subscriptionsToRemove, std::vector<StreamSubscription>)
JSON_STRUCT(StreamsModifySubscriptionsModel, STREAMS_MODIFY_SUBSCRIPTIONS_MODEL_FIELDS);

#define STREAMS_UNSUBSCRIBE_MODEL_FIELDS(F)\
    F(streamRoomId,          std::string)\
    F(subscriptionsToRemove, std::vector<StreamSubscription>)
JSON_STRUCT(StreamsUnsubscribeModel, STREAMS_UNSUBSCRIBE_MODEL_FIELDS);

#define STREAMS_SUBSCRIBE_RESULT_FIELDS(F)\
    F(offer,     std::optional<SessionDescription>)\
    F(sessionId, int64_t)
JSON_STRUCT(StreamsSubscribeResult, STREAMS_SUBSCRIBE_RESULT_FIELDS);

#define STREAM_ROOM_JOIN_MODEL_FIELDS(F)\
    F(streamRoomId, std::string)
JSON_STRUCT(StreamRoomJoinModel, STREAM_ROOM_JOIN_MODEL_FIELDS);

#define STREAM_ROOM_LEAVE_MODEL_FIELDS(F)\
    F(streamRoomId, std::string)
JSON_STRUCT(StreamRoomLeaveModel, STREAM_ROOM_LEAVE_MODEL_FIELDS);

#define STREAM_ROOM_RECORDING_MODEL_FIELDS(F)\
    F(streamRoomId, std::string)
JSON_STRUCT(StreamRoomRecordingModel, STREAM_ROOM_RECORDING_MODEL_FIELDS);

#define STREAM_LIST_MODEL_FIELDS(F)\
    F(streamRoomId, std::string)
JSON_STRUCT(StreamListModel, STREAM_LIST_MODEL_FIELDS);

#define STREAM_TRACK_INFO_FIELDS(F)\
    F(type,        std::string)\
    F(mindex,      int64_t)\
    F(mid,         std::string)\
    F(disabled,    std::optional<bool>)\
    F(codec,       std::optional<std::string>)\
    F(description, std::optional<std::string>)\
    F(moderated,   std::optional<bool>)\
    F(simulcast,   std::optional<bool>)\
    F(talking,     std::optional<bool>)
JSON_STRUCT(StreamTrackInfo, STREAM_TRACK_INFO_FIELDS);

#define STREAM_INFO_FIELDS(F)\
    F(id,       int64_t)\
    F(userId,   std::string)\
    F(metadata, std::optional<Poco::Dynamic::Var>)\
    F(dummy,    std::optional<bool>)\
    F(tracks,   std::vector<StreamTrackInfo>)\
    F(talking,  std::optional<bool>)
JSON_STRUCT(StreamInfo, STREAM_INFO_FIELDS);

#define STREAM_PUBLISHED_EVENT_DATA_FIELDS(F)\
    F(streamRoomId, std::string)\
    F(stream,       StreamInfo)\
    F(userId,       std::string)
JSON_STRUCT(StreamPublishedEventData, STREAM_PUBLISHED_EVENT_DATA_FIELDS);

#define STREAM_TRACK_MODIFICATION_PAIR_FIELDS(F)\
    F(before, std::optional<StreamTrackInfo>)\
    F(after,  std::optional<StreamTrackInfo>)
JSON_STRUCT(StreamTrackModificationPair, STREAM_TRACK_MODIFICATION_PAIR_FIELDS);

#define STREAM_TRACK_MODIFICATION_FIELDS(F)\
    F(streamId, int64_t)\
    F(tracks,   std::vector<StreamTrackModificationPair>)
JSON_STRUCT(StreamTrackModification, STREAM_TRACK_MODIFICATION_FIELDS);

#define STREAM_UPDATED_EVENT_DATA_FIELDS(F)\
    F(streamRoomId,    std::string)\
    F(streamsAdded,    std::vector<StreamInfo>)\
    F(streamsRemoved,  std::vector<StreamInfo>)\
    F(streamsModified, std::vector<StreamTrackModification>)
JSON_STRUCT(StreamUpdatedEventData, STREAM_UPDATED_EVENT_DATA_FIELDS);

#define NEW_STREAMS_FIELDS(F)\
    F(room,    std::string)\
    F(streams, std::vector<StreamInfo>)
JSON_STRUCT(NewStreams, NEW_STREAMS_FIELDS);

#define STREAM_SET_NEW_OFFER_MODEL_FIELDS(F)\
    F(offer,     SessionDescription)\
    F(sessionId, int64_t)
JSON_STRUCT(StreamSetNewOfferModel, STREAM_SET_NEW_OFFER_MODEL_FIELDS);

#define STREAM_ACCEPT_OFFER_MODEL_FIELDS(F)\
    F(answer,    SessionDescription)\
    F(sessionId, int64_t)
JSON_STRUCT(StreamAcceptOfferModel, STREAM_ACCEPT_OFFER_MODEL_FIELDS);

#define STREAM_SEND_EVENT_MODEL_FIELDS(F)\
    F(keys, std::vector<core::server::KeyEntrySet>)\
    F(data, std::string)
JSON_STRUCT(StreamSendEventModel, STREAM_SEND_EVENT_MODEL_FIELDS);

#define STREAM_ROOM_SEND_CUSTOM_EVENT_MODEL_FIELDS(F)\
    F(streamRoomId, std::string)\
    F(channel,      std::string)\
    F(keyId,        std::string)\
    F(data,         Poco::Dynamic::Var)\
    F(users,        std::vector<std::string>)
JSON_STRUCT(StreamRoomSendCustomEventModel, STREAM_ROOM_SEND_CUSTOM_EVENT_MODEL_FIELDS);

#define STREAM_UNPUBLISH_MODEL_FIELDS(F)\
    F(sessionId, int64_t)
JSON_STRUCT(StreamUnpublishModel, STREAM_UNPUBLISH_MODEL_FIELDS);

#define STREAM_TRICKLE_MODEL_FIELDS(F)\
    F(rtcCandidate, Poco::Dynamic::Var)\
    F(sessionId,    int64_t)
JSON_STRUCT(StreamTrickleModel, STREAM_TRICKLE_MODEL_FIELDS);

#define CONTEXT_GET_USERS_MODEL_FIELDS(F)\
    F(contextId, std::string)
JSON_STRUCT(ContextGetUsersModel, CONTEXT_GET_USERS_MODEL_FIELDS);

#define CONTEXT_GET_USER_RESULT_FIELDS(F)\
    F(users, std::vector<core::server::UserIdentity>)
JSON_STRUCT(ContextGetUserResult, CONTEXT_GET_USER_RESULT_FIELDS);

#define PUBLISHED_STREAM_DATA_FIELDS(F)\
    F(streamRoomId, std::string)\
    F(stream,       StreamInfo)\
    F(userId,       std::string)
JSON_STRUCT(PublishedStreamData, PUBLISHED_STREAM_DATA_FIELDS);

#define STREAM_PUBLISH_RESULT_FIELDS(F)\
    F(answer,        std::optional<SessionDescription>)\
    F(sessionId,     int64_t)\
    F(publishedData, std::optional<PublishedStreamData>)
JSON_STRUCT(StreamPublishResult, STREAM_PUBLISH_RESULT_FIELDS);

// Events

#define STREAM_ROOM_DELETED_EVENT_DATA_FIELDS(F)\
    F(streamRoomId, std::string)\
    F(type,         std::optional<std::string>)
JSON_STRUCT(StreamRoomDeletedEventData, STREAM_ROOM_DELETED_EVENT_DATA_FIELDS);

#define STREAM_EVENT_DATA_FIELDS(F)\
    F(streamRoomId, std::string)\
    F(streamIds,    std::vector<int64_t>)\
    F(userId,       std::string)
JSON_STRUCT(StreamEventData, STREAM_EVENT_DATA_FIELDS);

#define STREAM_UNPUBLISHED_EVENT_DATA_FIELDS(F)\
    F(streamRoomId, std::string)\
    F(streamId,     int64_t)
JSON_STRUCT(StreamUnpublishedEventData, STREAM_UNPUBLISHED_EVENT_DATA_FIELDS);

#define STREAM_LEFT_EVENT_DATA_FIELDS(F)\
    F(streamRoomId, std::string)\
    F(streamId,     int64_t)\
    F(userId,       std::string)
JSON_STRUCT(StreamLeftEventData, STREAM_LEFT_EVENT_DATA_FIELDS);

#define JANUS_EVENT_DATA_FIELDS(F)\
    F(janus,      std::string)\
    F(sender,     int64_t)\
    F(session_id, int64_t)
JSON_STRUCT(JanusEventData, JANUS_EVENT_DATA_FIELDS);

#define JANUS_JSEP_FIELDS(F)\
    F(sdp,  std::string)\
    F(type, std::string)
JSON_STRUCT(JanusJSEP, JANUS_JSEP_FIELDS);

#define JANUS_VIDEO_ROOM_STREAM_FIELDS(F)\
    F(active,  bool)\
    F(mid,     int64_t)\
    F(mindex,  int64_t)\
    F(ready,   bool)\
    F(send,    bool)\
    F(type,    std::string)
JSON_STRUCT(JanusVideoRoomStream, JANUS_VIDEO_ROOM_STREAM_FIELDS);

#define JANUS_VIDEO_ROOM_FIELDS(F)\
    F(videoroom, std::string)
JSON_STRUCT(JanusVideoRoom, JANUS_VIDEO_ROOM_FIELDS);

#define JANUS_VIDEO_ROOM_UPDATED_FIELDS(F)\
    F(room,    std::string)\
    F(streams, std::vector<JanusVideoRoomStream>)
JSON_STRUCT_EXT(JanusVideoRoomUpdated, JanusVideoRoom, JANUS_VIDEO_ROOM_UPDATED_FIELDS);

#define JANUS_PLUGIN_DATA_EVENT_FIELDS(F)\
    F(data,   Poco::Dynamic::Var)\
    F(plugin, std::string)
JSON_STRUCT(JanusPluginDataEvent, JANUS_PLUGIN_DATA_EVENT_FIELDS);

#define JANUS_PLUGIN_EVENT_FIELDS(F)\
    F(jsep,       JanusJSEP)\
    F(plugindata, JanusPluginDataEvent)
JSON_STRUCT_EXT(JanusPluginEvent, JanusEventData, JANUS_PLUGIN_EVENT_FIELDS);

#define STREAM_LIST_RESULT_FIELDS(F)\
    F(list, std::vector<StreamInfo>)
JSON_STRUCT(StreamListResult, STREAM_LIST_RESULT_FIELDS);

#define UPDATED_STREAM_DATA_FIELDS(F)\
    F(active,       bool)\
    F(type,         std::string)\
    F(codec,        std::optional<std::string>)\
    F(feed_id,      std::optional<int64_t>)\
    F(feed_mid,     std::optional<std::string>)\
    F(feed_display, std::optional<std::string>)\
    F(mindex,       int64_t)\
    F(mid,          std::string)\
    F(send,         bool)\
    F(ready,        bool)
JSON_STRUCT(UpdatedStreamData, UPDATED_STREAM_DATA_FIELDS);

#define STREAMS_UPDATED_DATA_FIELDS(F)\
    F(room,      std::string)\
    F(sessionId, int64_t)\
    F(streams,   std::vector<UpdatedStreamData>)\
    F(jsep,      std::optional<JanusJSEP>)
JSON_STRUCT(StreamsUpdatedData, STREAMS_UPDATED_DATA_FIELDS);

} // server
} // stream
} // endpoint
} // privmx

#endif // _PRIVMXLIB_ENDPOINT_STREAM_SERVERTYPES_HPP_
