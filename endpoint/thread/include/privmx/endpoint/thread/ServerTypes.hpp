/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_ENDPOINT_THREAD_SERVERTYPES_HPP_
#define _PRIVMXLIB_ENDPOINT_THREAD_SERVERTYPES_HPP_

#include <string>

#include "privmx/endpoint/core/TypesMacros.hpp"
#include "privmx/endpoint/core/ServerTypes.hpp"

namespace privmx {
namespace endpoint {
namespace thread {
namespace server {

ENDPOINT_SERVER_TYPE(ThreadCreateModel)
    STRING_FIELD(threadId)
    STRING_FIELD(contextId)
    LIST_FIELD(users, std::string)
    LIST_FIELD(managers, std::string)
    VAR_FIELD(data)
    STRING_FIELD(keyId)
    LIST_FIELD(keys, core::server::KeyEntrySet)
    STRING_FIELD(type)
    VAR_FIELD(policy)
TYPE_END

ENDPOINT_SERVER_TYPE(ThreadUpdateModel)
    STRING_FIELD(id)
    LIST_FIELD(users, std::string)
    LIST_FIELD(managers, std::string)
    VAR_FIELD(data)
    STRING_FIELD(keyId)
    LIST_FIELD(keys, core::server::KeyEntrySet)
    INT64_FIELD(version)
    BOOL_FIELD(force)
    VAR_FIELD(policy)
TYPE_END

ENDPOINT_SERVER_TYPE(Thread2DataEntry)
    STRING_FIELD(keyId)
    VAR_FIELD(data)
TYPE_END

ENDPOINT_SERVER_TYPE(ThreadInfo)
    STRING_FIELD(id)
    STRING_FIELD(contextId)
    INT64_FIELD(createDate)
    STRING_FIELD(creator)
    INT64_FIELD(lastModificationDate)
    STRING_FIELD(lastModifier)
    LIST_FIELD(data, Thread2DataEntry)
    STRING_FIELD(keyId)
    LIST_FIELD(users, std::string)
    LIST_FIELD(managers, std::string)
    LIST_FIELD(keys, core::server::KeyEntry)
    INT64_FIELD(version)
    INT64_FIELD(lastMsgDate)
    INT64_FIELD(messages)
    STRING_FIELD(type)
    VAR_FIELD(policy)
TYPE_END

ENDPOINT_SERVER_TYPE(ThreadCreateResult)
    STRING_FIELD(threadId)
TYPE_END

ENDPOINT_SERVER_TYPE(ThreadDeleteModel)
    STRING_FIELD(threadId)
TYPE_END

ENDPOINT_SERVER_TYPE(ThreadGetModel)
    STRING_FIELD(threadId)
    STRING_FIELD(type)
TYPE_END

ENDPOINT_SERVER_TYPE_INHERIT(ThreadListModel, core::server::ListModel)
    STRING_FIELD(contextId)
    STRING_FIELD(type)
TYPE_END

ENDPOINT_SERVER_TYPE(ThreadGetResult)
    OBJECT_FIELD(thread, ThreadInfo)
TYPE_END

ENDPOINT_SERVER_TYPE(ThreadListResult)
    LIST_FIELD(threads, ThreadInfo)
    INT64_FIELD(count)
TYPE_END

ENDPOINT_SERVER_TYPE(ThreadMessageSendModel)
    STRING_FIELD(messageId)
    STRING_FIELD(threadId)
    VAR_FIELD(data)
    STRING_FIELD(keyId)
TYPE_END

ENDPOINT_SERVER_TYPE(ThreadMessageSendResult)
    STRING_FIELD(messageId)
TYPE_END

ENDPOINT_SERVER_TYPE(ThreadMessageDeleteModel)
    STRING_FIELD(messageId)
TYPE_END

ENDPOINT_SERVER_TYPE(MessageUpdate)
    INT64_FIELD(createDate)
    STRING_FIELD(author)
TYPE_END


ENDPOINT_SERVER_TYPE(Message)
    STRING_FIELD(id)
    INT64_FIELD(version)
    STRING_FIELD(contextId)
    STRING_FIELD(threadId)
    INT64_FIELD(createDate)
    STRING_FIELD(author)
    VAR_FIELD(data) // meta: unknown
    STRING_FIELD(keyId)
    LIST_FIELD(updates, MessageUpdate)
TYPE_END

ENDPOINT_SERVER_TYPE(ThreadMessageGetModel)
    STRING_FIELD(messageId)
TYPE_END

ENDPOINT_SERVER_TYPE_INHERIT(ThreadMessagesGetModel, core::server::ListModel)
    STRING_FIELD(threadId)
TYPE_END

ENDPOINT_SERVER_TYPE(ThreadMessageGetResult)
    OBJECT_FIELD(message, server::Message)
TYPE_END

ENDPOINT_SERVER_TYPE(ThreadMessagesGetResult)
    LIST_FIELD(messages, server::Message)
    INT64_FIELD(count)
TYPE_END

ENDPOINT_SERVER_TYPE(ThreadMessageUpdateModel)
    STRING_FIELD(messageId)
    VAR_FIELD(data)
    STRING_FIELD(keyId)
TYPE_END

ENDPOINT_SERVER_TYPE(ThreadDeletedEventData)
    STRING_FIELD(type)
    STRING_FIELD(threadId)
TYPE_END

ENDPOINT_SERVER_TYPE(ThreadDeletedMessageEventData)
    STRING_FIELD(messageId)
    STRING_FIELD(threadId)
TYPE_END

ENDPOINT_SERVER_TYPE(ThreadStatsEventData)
    STRING_FIELD(threadId)
    INT64_FIELD(lastMsgDate)
    INT64_FIELD(messages)
    STRING_FIELD(type)
TYPE_END

ENDPOINT_CLIENT_TYPE_INHERIT(EncryptedMessageDataV4, core::server::VersionedData)
    STRING_FIELD(publicMeta)
    OBJECT_PTR_FIELD(publicMetaObject)
    STRING_FIELD(privateMeta)
    STRING_FIELD(data)
    STRING_FIELD(internalMeta)
    STRING_FIELD(authorPubKey)
TYPE_END

ENDPOINT_CLIENT_TYPE_INHERIT(EncryptedMessageDataV5, core::server::VersionedData)
    STRING_FIELD(publicMeta)
    OBJECT_PTR_FIELD(publicMetaObject)
    STRING_FIELD(privateMeta)
    STRING_FIELD(data)
    STRING_FIELD(internalMeta)
    STRING_FIELD(authorPubKey)
    STRING_FIELD(dio)
TYPE_END

ENDPOINT_CLIENT_TYPE_INHERIT(EncryptedThreadDataV4, core::server::VersionedData)
    STRING_FIELD(publicMeta)
    OBJECT_PTR_FIELD(publicMetaObject)
    STRING_FIELD(privateMeta)
    STRING_FIELD(internalMeta)
    STRING_FIELD(authorPubKey)
TYPE_END

ENDPOINT_CLIENT_TYPE_INHERIT(EncryptedThreadDataV5, core::server::VersionedData)
    INT64_FIELD(version)
    STRING_FIELD(publicMeta)
    OBJECT_PTR_FIELD(publicMetaObject)
    STRING_FIELD(privateMeta)
    STRING_FIELD(internalMeta)
    STRING_FIELD(authorPubKey)
    STRING_FIELD(dio)
TYPE_END

} // server
} // thread
} // endpoint
} // privmx

#endif // _PRIVMXLIB_ENDPOINT_THREAD_SERVERTYPES_HPP_
