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
JSON_STRUCT(StreamRoomDataEntry_c_struct, STREAM_ROOM_DATA_ENTRY_FIELDS);

#define STREAM_ROOM_INFO_FIELDS(F)\
    F(id,                   std::string)\
    F(resourceId,           std::optional<std::string>)\
    F(contextId,            std::string)\
    F(createDate,           int64_t)\
    F(creator,              std::string)\
    F(lastModificationDate, int64_t)\
    F(lastModifier,         std::string)\
    F(data,                 std::vector<StreamRoomDataEntry_c_struct>)\
    F(keyId,                std::string)\
    F(users,                std::vector<std::string>)\
    F(managers,             std::vector<std::string>)\
    F(keys,                 std::vector<core::server::KeyEntry_c_struct>)\
    F(version,              int64_t)\
    F(type,                 std::optional<std::string>)\
    F(policy,               Poco::Dynamic::Var)\
    F(closed,               std::optional<bool>)
JSON_STRUCT(StreamRoomInfo_c_struct, STREAM_ROOM_INFO_FIELDS);

#define SESSION_DESCRIPTION_FIELDS(F)\
    F(sdp,  std::string)\
    F(type, std::string)
JSON_STRUCT(SessionDescription_c_struct, SESSION_DESCRIPTION_FIELDS);

#define STREAM_ROOM_CREATE_MODEL_FIELDS(F)\
    F(contextId,   std::string)\
    F(resourceId,  std::string)\
    F(keyId,       std::string)\
    F(data,        Poco::Dynamic::Var)\
    F(users,       std::vector<std::string>)\
    F(managers,    std::vector<std::string>)\
    F(keys,        std::vector<core::server::KeyEntrySet_c_struct>)\
    F(type,        std::string)\
    F(policy,      std::optional<Poco::Dynamic::Var>)
JSON_STRUCT(StreamRoomCreateModel_c_struct, STREAM_ROOM_CREATE_MODEL_FIELDS);

#define STREAM_ROOM_CREATE_RESULT_FIELDS(F)\
    F(streamRoomId, std::string)
JSON_STRUCT(StreamRoomCreateResult_c_struct, STREAM_ROOM_CREATE_RESULT_FIELDS);

#define STREAM_ROOM_UPDATE_MODEL_FIELDS(F)\
    F(id,          std::string)\
    F(resourceId,  std::string)\
    F(keyId,       std::string)\
    F(data,        Poco::Dynamic::Var)\
    F(users,       std::vector<std::string>)\
    F(managers,    std::vector<std::string>)\
    F(keys,        std::vector<core::server::KeyEntrySet_c_struct>)\
    F(version,     int64_t)\
    F(force,       bool)\
    F(policy,      std::optional<Poco::Dynamic::Var>)
JSON_STRUCT(StreamRoomUpdateModel_c_struct, STREAM_ROOM_UPDATE_MODEL_FIELDS);

#define STREAM_ROOM_GET_MODEL_FIELDS(F)\
    F(id,   std::string)\
    F(type, std::optional<std::string>)
JSON_STRUCT(StreamRoomGetModel_c_struct, STREAM_ROOM_GET_MODEL_FIELDS);

#define STREAM_ROOM_GET_RESULT_FIELDS(F)\
    F(streamRoom, StreamRoomInfo_c_struct)
JSON_STRUCT(StreamRoomGetResult_c_struct, STREAM_ROOM_GET_RESULT_FIELDS);

#define STREAM_ROOM_LIST_MODEL_FIELDS(F)\
    F(contextId, std::string)\
    F(type,      std::optional<std::string>)
JSON_STRUCT_EXT(StreamRoomListModel_c_struct, core::server::ListModel_c_struct, STREAM_ROOM_LIST_MODEL_FIELDS);

#define STREAM_ROOM_LIST_RESULT_FIELDS(F)\
    F(list,  std::vector<StreamRoomInfo_c_struct>)\
    F(count, int64_t)
JSON_STRUCT(StreamRoomListResult_c_struct, STREAM_ROOM_LIST_RESULT_FIELDS);

#define STREAM_ROOM_DELETE_MODEL_FIELDS(F)\
    F(id, std::string)
JSON_STRUCT(StreamRoomDeleteModel_c_struct, STREAM_ROOM_DELETE_MODEL_FIELDS);

#define TURN_CREDENTIALS_FIELDS(F)\
    F(url,            std::string)\
    F(username,       std::string)\
    F(password,       std::string)\
    F(expirationTime, int64_t)
JSON_STRUCT(TurnCredentials_c_struct, TURN_CREDENTIALS_FIELDS);

#define STREAM_GET_TURN_CREDENTIALS_RESULT_FIELDS(F)\
    F(credentials, std::vector<TurnCredentials_c_struct>)
JSON_STRUCT(StreamGetTurnCredentialsResult_c_struct, STREAM_GET_TURN_CREDENTIALS_RESULT_FIELDS);

#define STREAM_PUBLISH_MODEL_FIELDS(F)\
    F(offer,        SessionDescription_c_struct)\
    F(streamRoomId, std::string)
JSON_STRUCT(StreamPublishModel_c_struct, STREAM_PUBLISH_MODEL_FIELDS);

#define STREAM_UPDATE_MODEL_FIELDS(F)\
    F(offer,        SessionDescription_c_struct)\
    F(streamRoomId, std::string)
JSON_STRUCT(StreamUpdateModel_c_struct, STREAM_UPDATE_MODEL_FIELDS);

#define STREAM_SUBSCRIPTION_FIELDS(F)\
    F(streamId,      int64_t)\
    F(streamTrackId, std::optional<std::string>)
JSON_STRUCT(StreamSubscription_c_struct, STREAM_SUBSCRIPTION_FIELDS);

#define STREAMS_SUBSCRIBE_MODEL_FIELDS(F)\
    F(streamRoomId,       std::string)\
    F(subscriptionsToAdd, std::vector<StreamSubscription_c_struct>)
JSON_STRUCT(StreamsSubscribeModel_c_struct, STREAMS_SUBSCRIBE_MODEL_FIELDS);

#define STREAMS_MODIFY_SUBSCRIPTIONS_MODEL_FIELDS(F)\
    F(streamRoomId,          std::string)\
    F(subscriptionsToAdd,    std::vector<StreamSubscription_c_struct>)\
    F(subscriptionsToRemove, std::vector<StreamSubscription_c_struct>)
JSON_STRUCT(StreamsModifySubscriptionsModel_c_struct, STREAMS_MODIFY_SUBSCRIPTIONS_MODEL_FIELDS);

#define STREAMS_UNSUBSCRIBE_MODEL_FIELDS(F)\
    F(streamRoomId,          std::string)\
    F(subscriptionsToRemove, std::vector<StreamSubscription_c_struct>)
JSON_STRUCT(StreamsUnsubscribeModel_c_struct, STREAMS_UNSUBSCRIBE_MODEL_FIELDS);

#define STREAMS_SUBSCRIBE_RESULT_FIELDS(F)\
    F(offer,     std::optional<SessionDescription_c_struct>)\
    F(sessionId, int64_t)
JSON_STRUCT(StreamsSubscribeResult_c_struct, STREAMS_SUBSCRIBE_RESULT_FIELDS);

#define STREAM_ROOM_JOIN_MODEL_FIELDS(F)\
    F(streamRoomId, std::string)
JSON_STRUCT(StreamRoomJoinModel_c_struct, STREAM_ROOM_JOIN_MODEL_FIELDS);

#define STREAM_ROOM_LEAVE_MODEL_FIELDS(F)\
    F(streamRoomId, std::string)
JSON_STRUCT(StreamRoomLeaveModel_c_struct, STREAM_ROOM_LEAVE_MODEL_FIELDS);

#define STREAM_ROOM_RECORDING_MODEL_FIELDS(F)\
    F(streamRoomId, std::string)
JSON_STRUCT(StreamRoomRecordingModel_c_struct, STREAM_ROOM_RECORDING_MODEL_FIELDS);

#define STREAM_LIST_MODEL_FIELDS(F)\
    F(streamRoomId, std::string)
JSON_STRUCT(StreamListModel_c_struct, STREAM_LIST_MODEL_FIELDS);

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
JSON_STRUCT(StreamTrackInfo_c_struct, STREAM_TRACK_INFO_FIELDS);

#define STREAM_INFO_FIELDS(F)\
    F(id,       int64_t)\
    F(userId,   std::string)\
    F(metadata, std::optional<Poco::Dynamic::Var>)\
    F(dummy,    std::optional<bool>)\
    F(tracks,   std::vector<StreamTrackInfo_c_struct>)\
    F(talking,  std::optional<bool>)
JSON_STRUCT(StreamInfo_c_struct, STREAM_INFO_FIELDS);

#define STREAM_PUBLISHED_EVENT_DATA_FIELDS(F)\
    F(streamRoomId, std::string)\
    F(stream,       StreamInfo_c_struct)\
    F(userId,       std::string)
JSON_STRUCT(StreamPublishedEventData_c_struct, STREAM_PUBLISHED_EVENT_DATA_FIELDS);

#define STREAM_TRACK_MODIFICATION_PAIR_FIELDS(F)\
    F(before, std::optional<StreamTrackInfo_c_struct>)\
    F(after,  std::optional<StreamTrackInfo_c_struct>)
JSON_STRUCT(StreamTrackModificationPair_c_struct, STREAM_TRACK_MODIFICATION_PAIR_FIELDS);

#define STREAM_TRACK_MODIFICATION_FIELDS(F)\
    F(streamId, int64_t)\
    F(tracks,   std::vector<StreamTrackModificationPair_c_struct>)
JSON_STRUCT(StreamTrackModification_c_struct, STREAM_TRACK_MODIFICATION_FIELDS);

#define STREAM_UPDATED_EVENT_DATA_FIELDS(F)\
    F(streamRoomId,    std::string)\
    F(streamsAdded,    std::vector<StreamInfo_c_struct>)\
    F(streamsRemoved,  std::vector<StreamInfo_c_struct>)\
    F(streamsModified, std::vector<StreamTrackModification_c_struct>)
JSON_STRUCT(StreamUpdatedEventData_c_struct, STREAM_UPDATED_EVENT_DATA_FIELDS);

#define NEW_STREAMS_FIELDS(F)\
    F(room,    std::string)\
    F(streams, std::vector<StreamInfo_c_struct>)
JSON_STRUCT(NewStreams_c_struct, NEW_STREAMS_FIELDS);

#define STREAM_SET_NEW_OFFER_MODEL_FIELDS(F)\
    F(offer,     SessionDescription_c_struct)\
    F(sessionId, int64_t)
JSON_STRUCT(StreamSetNewOfferModel_c_struct, STREAM_SET_NEW_OFFER_MODEL_FIELDS);

#define STREAM_ACCEPT_OFFER_MODEL_FIELDS(F)\
    F(answer,    SessionDescription_c_struct)\
    F(sessionId, int64_t)
JSON_STRUCT(StreamAcceptOfferModel_c_struct, STREAM_ACCEPT_OFFER_MODEL_FIELDS);

#define STREAM_SEND_EVENT_MODEL_FIELDS(F)\
    F(keys, std::vector<core::server::KeyEntrySet_c_struct>)\
    F(data, std::string)
JSON_STRUCT(StreamSendEventModel_c_struct, STREAM_SEND_EVENT_MODEL_FIELDS);

#define STREAM_ROOM_SEND_CUSTOM_EVENT_MODEL_FIELDS(F)\
    F(streamRoomId, std::string)\
    F(channel,      std::string)\
    F(keyId,        std::string)\
    F(data,         Poco::Dynamic::Var)\
    F(users,        std::vector<std::string>)
JSON_STRUCT(StreamRoomSendCustomEventModel_c_struct, STREAM_ROOM_SEND_CUSTOM_EVENT_MODEL_FIELDS);

#define STREAM_UNPUBLISH_MODEL_FIELDS(F)\
    F(sessionId, int64_t)
JSON_STRUCT(StreamUnpublishModel_c_struct, STREAM_UNPUBLISH_MODEL_FIELDS);

#define STREAM_TRICKLE_MODEL_FIELDS(F)\
    F(rtcCandidate, Poco::Dynamic::Var)\
    F(sessionId,    int64_t)
JSON_STRUCT(StreamTrickleModel_c_struct, STREAM_TRICKLE_MODEL_FIELDS);

#define CONTEXT_GET_USERS_MODEL_FIELDS(F)\
    F(contextId, std::string)
JSON_STRUCT(ContextGetUsersModel_c_struct, CONTEXT_GET_USERS_MODEL_FIELDS);

#define CONTEXT_GET_USER_RESULT_FIELDS(F)\
    F(users, std::vector<core::server::UserIdentity_c_struct>)
JSON_STRUCT(ContextGetUserResult_c_struct, CONTEXT_GET_USER_RESULT_FIELDS);

#define PUBLISHED_STREAM_DATA_FIELDS(F)\
    F(streamRoomId, std::string)\
    F(stream,       StreamInfo_c_struct)\
    F(userId,       std::string)
JSON_STRUCT(PublishedStreamData_c_struct, PUBLISHED_STREAM_DATA_FIELDS);

#define STREAM_PUBLISH_RESULT_FIELDS(F)\
    F(answer,        std::optional<SessionDescription_c_struct>)\
    F(sessionId,     int64_t)\
    F(publishedData, std::optional<PublishedStreamData_c_struct>)
JSON_STRUCT(StreamPublishResult_c_struct, STREAM_PUBLISH_RESULT_FIELDS);

// Events

#define STREAM_ROOM_DELETED_EVENT_DATA_FIELDS(F)\
    F(streamRoomId, std::string)\
    F(type,         std::optional<std::string>)
JSON_STRUCT(StreamRoomDeletedEventData_c_struct, STREAM_ROOM_DELETED_EVENT_DATA_FIELDS);

#define STREAM_EVENT_DATA_FIELDS(F)\
    F(streamRoomId, std::string)\
    F(streamIds,    std::vector<int64_t>)\
    F(userId,       std::string)
JSON_STRUCT(StreamEventData_c_struct, STREAM_EVENT_DATA_FIELDS);

#define STREAM_UNPUBLISHED_EVENT_DATA_FIELDS(F)\
    F(streamRoomId, std::string)\
    F(streamId,     int64_t)
JSON_STRUCT(StreamUnpublishedEventData_c_struct, STREAM_UNPUBLISHED_EVENT_DATA_FIELDS);

#define STREAM_LEFT_EVENT_DATA_FIELDS(F)\
    F(streamRoomId, std::string)\
    F(streamId,     int64_t)\
    F(userId,       std::string)
JSON_STRUCT(StreamLeftEventData_c_struct, STREAM_LEFT_EVENT_DATA_FIELDS);

#define JANUS_EVENT_DATA_FIELDS(F)\
    F(janus,      std::string)\
    F(sender,     int64_t)\
    F(session_id, int64_t)
JSON_STRUCT(JanusEventData_c_struct, JANUS_EVENT_DATA_FIELDS);

#define JANUS_JSEP_FIELDS(F)\
    F(sdp,  std::string)\
    F(type, std::string)
JSON_STRUCT(JanusJSEP_c_struct, JANUS_JSEP_FIELDS);

#define JANUS_VIDEO_ROOM_STREAM_FIELDS(F)\
    F(active,  bool)\
    F(mid,     int64_t)\
    F(mindex,  int64_t)\
    F(ready,   bool)\
    F(send,    bool)\
    F(type,    std::string)
JSON_STRUCT(JanusVideoRoomStream_c_struct, JANUS_VIDEO_ROOM_STREAM_FIELDS);

#define JANUS_VIDEO_ROOM_FIELDS(F)\
    F(videoroom, std::string)
JSON_STRUCT(JanusVideoRoom_c_struct, JANUS_VIDEO_ROOM_FIELDS);

#define JANUS_VIDEO_ROOM_UPDATED_FIELDS(F)\
    F(room,    std::string)\
    F(streams, std::vector<JanusVideoRoomStream_c_struct>)
JSON_STRUCT_EXT(JanusVideoRoomUpdated_c_struct, JanusVideoRoom_c_struct, JANUS_VIDEO_ROOM_UPDATED_FIELDS);

#define JANUS_PLUGIN_DATA_EVENT_FIELDS(F)\
    F(data,   Poco::Dynamic::Var)\
    F(plugin, std::string)
JSON_STRUCT(JanusPluginDataEvent_c_struct, JANUS_PLUGIN_DATA_EVENT_FIELDS);

#define JANUS_PLUGIN_EVENT_FIELDS(F)\
    F(jsep,       JanusJSEP_c_struct)\
    F(plugindata, JanusPluginDataEvent_c_struct)
JSON_STRUCT_EXT(JanusPluginEvent_c_struct, JanusEventData_c_struct, JANUS_PLUGIN_EVENT_FIELDS);

#define STREAM_LIST_RESULT_FIELDS(F)\
    F(list, std::vector<StreamInfo_c_struct>)
JSON_STRUCT(StreamListResult_c_struct, STREAM_LIST_RESULT_FIELDS);

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
JSON_STRUCT(UpdatedStreamData_c_struct, UPDATED_STREAM_DATA_FIELDS);

#define STREAMS_UPDATED_DATA_FIELDS(F)\
    F(room,      std::string)\
    F(sessionId, int64_t)\
    F(streams,   std::vector<UpdatedStreamData_c_struct>)\
    F(jsep,      std::optional<JanusJSEP_c_struct>)
JSON_STRUCT(StreamsUpdatedData_c_struct, STREAMS_UPDATED_DATA_FIELDS);

} // server
} // stream
} // endpoint
} // privmx

#endif // _PRIVMXLIB_ENDPOINT_STREAM_SERVERTYPES_HPP_
