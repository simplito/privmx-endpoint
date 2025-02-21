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

ENDPOINT_SERVER_TYPE(StreamLeaveModel)
    INT64_FIELD(sessionId)
TYPE_END

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
