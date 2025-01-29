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

#include <string>

#include <privmx/endpoint/core/TypesMacros.hpp>


#include <privmx/endpoint/core/TypesMacros.hpp>
#include <privmx/endpoint/core/ServerTypes.hpp>

namespace privmx {
namespace endpoint {
namespace stream {
namespace server {

// ENDPOINT_SERVER_TYPE(VideoRoom)
//     INT64_FIELD(room)
//     STRING_FIELD(description)
//     BOOL_FIELD(pin_required)
//     BOOL_FIELD(is_private)
//     INT64_FIELD(max_publishers)
//     INT64_FIELD(bitrate)
//     INT64_FIELD(bitrate_cap)
//     INT64_FIELD(fir_freq)
//     BOOL_FIELD(require_pvtid)
//     BOOL_FIELD(require_e2ee)
//     BOOL_FIELD(dummy_publisher)
//     BOOL_FIELD(notify_joining)
//     STRING_FIELD(audiocodec)
//     STRING_FIELD(videocodec)
//     BOOL_FIELD(opus_fec)
//     BOOL_FIELD(opus_dtx)
//     BOOL_FIELD(record)
//     STRING_FIELD(rec_dir)
//     BOOL_FIELD(lock_record)
//     INT64_FIELD(num_participants)
//     BOOL_FIELD(audiolevel_ext)
//     BOOL_FIELD(audiolevel_event)
//     INT64_FIELD(audio_active_packets)
//     INT64_FIELD(audio_level_average)
//     BOOL_FIELD(videoorient_ext)
//     BOOL_FIELD(playoutdelay_ext)
//     BOOL_FIELD(transport_wide_cc_ext) 
// TYPE_END

ENDPOINT_SERVER_TYPE(StreamRoomDataEntry)
    STRING_FIELD(keyId)
    VAR_FIELD(data)
TYPE_END

ENDPOINT_SERVER_TYPE(StreamRoomInfo)
    STRING_FIELD(id)
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

// ENDPOINT_SERVER_TYPE(StreamTrackCreateMeta)
//     STRING_FIELD(mid)
//     STRING_FIELD(description)
// TYPE_END

// ENDPOINT_SERVER_TYPE(StreamCreateMeta)
//     STRING_FIELD(mid)
//     STRING_FIELD(description)
//     BOOL_FIELD(p2p)
//     LIST_FIELD(tracks, StreamTrackCreateMeta)
// TYPE_END

// ENDPOINT_SERVER_TYPE(VideoRoomStreamTrack)
//     STRING_FIELD(type)
//     STRING_FIELD(codec)
//     STRING_FIELD(mid)
//     INT64_FIELD(mindex)
// TYPE_END

// ENDPOINT_SERVER_TYPE(DataChannelMeta)
//     STRING_FIELD(name)
// TYPE_END

// ENDPOINT_SERVER_TYPE_INHERIT(TrackInfo, VideoRoomStreamTrack)
//     STRING_FIELD(type)
//     STRING_FIELD(streamRoomId)
//     INT64_FIELD(streamId)
//     OBJECT_FIELD(meta, DataChannelMeta)
//     STRING_FIELD(dataTrackId)
// TYPE_END

// ENDPOINT_SERVER_TYPE(StreamRemoteInfo)
//     INT64_FIELD(id)
//     LIST_FIELD(tracks, TrackInfo)
// TYPE_END

// ENDPOINT_SERVER_TYPE(Stream)
//     INT64_FIELD(streamId)
//     STRING_FIELD(streamRoomId)
//     BOOL_FIELD(remote)
//     OBJECT_FIELD(createStreamMeta, StreamCreateMeta)
//     OBJECT_FIELD(remoteStreamInfo, StreamRemoteInfo)
// TYPE_END

// ENDPOINT_SERVER_TYPE(MediaStreamTrack)
//     // MediaStreamTrack - object
// TYPE_END

// ENDPOINT_SERVER_TYPE(StreamTrackMeta)
//     // Track
//     OBJECT_FIELD(track, MediaStreamTrack)
//     // DataChannel
//     OBJECT_FIELD(dataChannel, DataChannelMeta)
// TYPE_END

// ENDPOINT_SERVER_TYPE(StreamAndTracksSelector)
//     STRING_FIELD(streamRoomId)
//     INT64_FIELD(streamId)
//     LIST_FIELD(tracks, std::string)
// TYPE_END

ENDPOINT_SERVER_TYPE(StreamRoomCreateModel)
    STRING_FIELD(contextId)
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

ENDPOINT_SERVER_TYPE(StreamRoomListModel)
    STRING_FIELD(contextId)
    INT64_FIELD(skip)
    INT64_FIELD(limit)
    STRING_FIELD(sortOrder)
    STRING_FIELD(lastId)
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
    STRING_FIELD(clientId)
TYPE_END

ENDPOINT_SERVER_TYPE(StreamGetTurnCredentialsResult)
    STRING_FIELD(username)
    STRING_FIELD(password)
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

ENDPOINT_SERVER_TYPE(StreamJoinModel)
    LIST_FIELD(streamIds, int64_t)
    STRING_FIELD(streamRoomId)
TYPE_END

ENDPOINT_SERVER_TYPE(StreamJoinResult)
    OBJECT_FIELD(offer, SessionDescription)
    INT64_FIELD(sessionId)
TYPE_END

ENDPOINT_SERVER_TYPE(StreamListModel)
    STRING_FIELD(streamRoomId)
TYPE_END

ENDPOINT_SERVER_TYPE(Stream)
    INT64_FIELD(streamId)
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

// ENDPOINT_SERVER_TYPE(StreamCreateModel)
//     STRING_FIELD(streamRoomId)
//     OBJECT_FIELD(meta, StreamCreateMeta)
// TYPE_END

// ENDPOINT_SERVER_TYPE(StreamCreateResult)
//     INT64_FIELD(streamId)
// TYPE_END

// ENDPOINT_SERVER_TYPE(StreamUpdateModel)
//     INT64_FIELD(streamId)
//     OBJECT_FIELD(meta, StreamCreateMeta)
// TYPE_END

// ENDPOINT_SERVER_TYPE(StreamListModel)
//     STRING_FIELD(streamRoomId)
//     INT64_FIELD(skip)
//     INT64_FIELD(limit)
//     STRING_FIELD(sortOrder)
//     STRING_FIELD(lastId)
//     STRING_FIELD(type)
// TYPE_END

// ENDPOINT_SERVER_TYPE(StreamListResult)
//     LIST_FIELD(streams, Stream)
//     INT64_FIELD(count)
// TYPE_END

// ENDPOINT_SERVER_TYPE(StreamGetModel)
//     STRING_FIELD(streamRoomId)
//     INT64_FIELD(streamId)
// TYPE_END

// ENDPOINT_SERVER_TYPE(StreamGetResult)
//     OBJECT_FIELD(stream, Stream)
// TYPE_END

// ENDPOINT_SERVER_TYPE(StreamDeleteModel)
//     STRING_FIELD(streamRoomId)
//     INT64_FIELD(streamId)
// TYPE_END

// ENDPOINT_SERVER_TYPE(StreamTrackAddModel)
//     STRING_FIELD(streamRoomId)
//     STRING_FIELD(streamTrackId)
//     INT64_FIELD(streamId)
//     OBJECT_FIELD(meta, DataChannelMeta)
// TYPE_END

// ENDPOINT_SERVER_TYPE(StreamTrackAddResult)
//     INT64_FIELD(streamId)
// TYPE_END

// ENDPOINT_SERVER_TYPE(StreamTrackRemoveModel)
//     INT64_FIELD(streamId)
//     STRING_FIELD(streamRoomId)
//     STRING_FIELD(streamTrackId)
// TYPE_END

// ENDPOINT_SERVER_TYPE(StreamTrackListModel)
//     INT64_FIELD(streamId)
//     STRING_FIELD(streamRoomId)
// TYPE_END

// ENDPOINT_SERVER_TYPE(StreamTrackListResult)
//     LIST_FIELD(tracks, TrackInfo)
//     INT64_FIELD(count)
// TYPE_END

// ENDPOINT_SERVER_TYPE(StreamTrackSendDataModel)
//     STRING_FIELD(streamTrackId)
//     VAR_FIELD(data)
// TYPE_END

// ENDPOINT_SERVER_TYPE(StreamPublishModel)
//     STRING_FIELD(streamRoomId)
//     INT64_FIELD(streamId)
//     OBJECT_FIELD(streamMeta, StreamCreateMeta)
//     VAR_FIELD(peerConnectionOffer)
// TYPE_END

// ENDPOINT_SERVER_TYPE(StreamUnpublishModel)
//     STRING_FIELD(streamRoomId)
//     INT64_FIELD(streamId)
// TYPE_END

// ENDPOINT_SERVER_TYPE(StreamJoinModel)
//     STRING_FIELD(streamRoomId)
//     OBJECT_FIELD(streamToJoin, StreamAndTracksSelector)
// TYPE_END

// ENDPOINT_SERVER_TYPE(StreamLeaveModel)
//     OBJECT_FIELD(streamToLeave, StreamAndTracksSelector)
// TYPE_END

// ENDPOINT_SERVER_TYPE(StreamDataChannelSendModel)
//     STRING_FIELD(streamRoomId)
//     INT64_FIELD(streamId)
//     STRING_FIELD(data)
// TYPE_END

ENDPOINT_CLIENT_TYPE(EncryptedStreamRoomDataV4)
    INT64_FIELD(version)
    STRING_FIELD(publicMeta)
    OBJECT_PTR_FIELD(publicMetaObject)
    STRING_FIELD(privateMeta)
    STRING_FIELD(internalMeta)
    STRING_FIELD(authorPubKey)
TYPE_END

ENDPOINT_CLIENT_TYPE(ContextGetUsersModel)
    STRING_FIELD(contextId)
TYPE_END

ENDPOINT_CLIENT_TYPE(ContextGetUserResult)
    LIST_FIELD(users, core::server::UserIdentity)
TYPE_END


} // server
} // stream
} // endpoint
} // privmx

#endif // _PRIVMXLIB_ENDPOINT_STREAM_SERVERTYPES_HPP_
