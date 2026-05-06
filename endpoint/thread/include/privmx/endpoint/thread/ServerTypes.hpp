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

#include "privmx/endpoint/core/ServerTypes.hpp"
#include <privmx/utils/JsonHelper.hpp>

namespace privmx {
namespace endpoint {
namespace thread {
namespace server {

#define THREAD_CREATE_MODEL_FIELDS(F)\
    F(resourceId, std::string)\
    F(contextId, std::string)\
    F(users, std::vector<std::string>)\
    F(managers, std::vector<std::string>)\
    F(data, Poco::Dynamic::Var)\
    F(keyId, std::string)\
    F(keys, std::vector<core::server::KeyEntrySet>)\
    F(type, std::string)\
    F(policy, std::optional<Poco::Dynamic::Var>)
JSON_STRUCT(ThreadCreateModel, THREAD_CREATE_MODEL_FIELDS);

#define THREAD_UPDATE_MODEL_FIELDS(F)\
    F(id, std::string)\
    F(resourceId, std::string)\
    F(users, std::vector<std::string>)\
    F(managers, std::vector<std::string>)\
    F(data, Poco::Dynamic::Var)\
    F(keyId, std::string)\
    F(keys, std::vector<core::server::KeyEntrySet>)\
    F(version, int64_t)\
    F(force, bool)\
    F(policy, std::optional<Poco::Dynamic::Var>)
JSON_STRUCT(ThreadUpdateModel, THREAD_UPDATE_MODEL_FIELDS);

#define THREAD2_DATA_ENTRY_FIELDS(F)\
    F(keyId, std::string)\
    F(data, Poco::Dynamic::Var)
JSON_STRUCT(Thread2DataEntry, THREAD2_DATA_ENTRY_FIELDS);

#define THREAD_INFO_FIELDS(F)\
    F(id, std::string)\
    F(resourceId, std::optional<std::string>)\
    F(contextId, std::string)\
    F(createDate, int64_t)\
    F(creator, std::string)\
    F(lastModificationDate, int64_t)\
    F(lastModifier, std::string)\
    F(data, std::vector<Thread2DataEntry>)\
    F(keyId, std::string)\
    F(users, std::vector<std::string>)\
    F(managers, std::vector<std::string>)\
    F(keys, std::vector<core::server::KeyEntry>)\
    F(version, int64_t)\
    F(lastMsgDate, int64_t)\
    F(messages, int64_t)\
    F(type, std::optional<std::string>)\
    F(policy, Poco::Dynamic::Var)
JSON_STRUCT(ThreadInfo, THREAD_INFO_FIELDS);

#define THREAD_CREATE_RESULT_FIELDS(F)\
    F(threadId, std::string)
JSON_STRUCT(ThreadCreateResult, THREAD_CREATE_RESULT_FIELDS);

#define THREAD_DELETE_MODEL_FIELDS(F)\
    F(threadId, std::string)
JSON_STRUCT(ThreadDeleteModel, THREAD_DELETE_MODEL_FIELDS);

#define THREAD_GET_MODEL_FIELDS(F)\
    F(threadId, std::string)\
    F(type, std::optional<std::string>)
JSON_STRUCT(ThreadGetModel, THREAD_GET_MODEL_FIELDS);

#define THREAD_LIST_MODEL_FIELDS(F)\
    F(contextId, std::string)\
    F(type, std::optional<std::string>)
JSON_STRUCT_EXT(ThreadListModel, core::server::ListModel, THREAD_LIST_MODEL_FIELDS);

#define THREAD_GET_RESULT_FIELDS(F)\
    F(thread, ThreadInfo)
JSON_STRUCT(ThreadGetResult, THREAD_GET_RESULT_FIELDS);

#define THREAD_LIST_RESULT_FIELDS(F)\
    F(threads, std::vector<ThreadInfo>)\
    F(count, int64_t)
JSON_STRUCT(ThreadListResult, THREAD_LIST_RESULT_FIELDS);

#define THREAD_MESSAGE_SEND_MODEL_FIELDS(F)\
    F(resourceId, std::string)\
    F(threadId, std::string)\
    F(data, Poco::Dynamic::Var)\
    F(keyId, std::string)
JSON_STRUCT(ThreadMessageSendModel, THREAD_MESSAGE_SEND_MODEL_FIELDS);

#define THREAD_MESSAGE_SEND_RESULT_FIELDS(F)\
    F(messageId, std::string)
JSON_STRUCT(ThreadMessageSendResult, THREAD_MESSAGE_SEND_RESULT_FIELDS);

#define THREAD_MESSAGE_DELETE_MODEL_FIELDS(F)\
    F(messageId, std::string)
JSON_STRUCT(ThreadMessageDeleteModel, THREAD_MESSAGE_DELETE_MODEL_FIELDS);

#define MESSAGE_UPDATE_FIELDS(F)\
    F(createDate, int64_t)\
    F(author, std::string)
JSON_STRUCT(MessageUpdate, MESSAGE_UPDATE_FIELDS);

#define MESSAGE_FIELDS(F)\
    F(id, std::string)\
    F(resourceId, std::string)\
    F(version, int64_t)\
    F(contextId, std::string)\
    F(threadId, std::string)\
    F(createDate, int64_t)\
    F(author, std::string)\
    F(data, Poco::Dynamic::Var)\
    F(keyId, std::string)\
    F(updates, std::vector<MessageUpdate>)
JSON_STRUCT(Message, MESSAGE_FIELDS);

#define THREAD_MESSAGE_GET_MODEL_FIELDS(F)\
    F(messageId, std::string)
JSON_STRUCT(ThreadMessageGetModel, THREAD_MESSAGE_GET_MODEL_FIELDS);

#define THREAD_MESSAGES_GET_MODEL_FIELDS(F)\
    F(threadId, std::string)
JSON_STRUCT_EXT(ThreadMessagesGetModel, core::server::ListModel, THREAD_MESSAGES_GET_MODEL_FIELDS);

#define THREAD_MESSAGE_GET_RESULT_FIELDS(F)\
    F(message, Message)
JSON_STRUCT(ThreadMessageGetResult, THREAD_MESSAGE_GET_RESULT_FIELDS);

#define THREAD_MESSAGES_GET_RESULT_FIELDS(F)\
    F(thread, ThreadInfo)\
    F(messages, std::vector<Message>)\
    F(count, int64_t)
JSON_STRUCT(ThreadMessagesGetResult, THREAD_MESSAGES_GET_RESULT_FIELDS);

#define THREAD_MESSAGE_UPDATE_MODEL_FIELDS(F)\
    F(messageId, std::string)\
    F(data, Poco::Dynamic::Var)\
    F(keyId, std::string)
JSON_STRUCT(ThreadMessageUpdateModel, THREAD_MESSAGE_UPDATE_MODEL_FIELDS);

#define THREAD_DELETED_EVENT_DATA_FIELDS(F)\
    F(type, std::optional<std::string>)\
    F(threadId, std::string)
JSON_STRUCT(ThreadDeletedEventData, THREAD_DELETED_EVENT_DATA_FIELDS);

#define THREAD_DELETED_MESSAGE_EVENT_DATA_FIELDS(F)\
    F(messageId, std::string)\
    F(threadId, std::string)\
    F(containerType, std::optional<std::string>)
JSON_STRUCT(ThreadDeletedMessageEventData, THREAD_DELETED_MESSAGE_EVENT_DATA_FIELDS);

#define THREAD_STATS_EVENT_DATA_FIELDS(F)\
    F(contextId, std::string)\
    F(threadId, std::string)\
    F(lastMsgDate, int64_t)\
    F(messages, int64_t)\
    F(type, std::optional<std::string>)
JSON_STRUCT(ThreadStatsEventData, THREAD_STATS_EVENT_DATA_FIELDS);

#define ENCRYPTED_MESSAGE_DATA_V4_FIELDS(F)\
    F(publicMeta, std::string)\
    F(publicMetaObject, Poco::Dynamic::Var)\
    F(privateMeta, std::string)\
    F(data, std::string)\
    F(internalMeta, std::optional<std::string>)\
    F(authorPubKey, std::string)
JSON_STRUCT_EXT(EncryptedMessageDataV4, core::dynamic::VersionedData, ENCRYPTED_MESSAGE_DATA_V4_FIELDS);


#define ENCRYPTED_MESSAGE_DATA_V5_FIELDS(F)\
    F(publicMeta, std::string)\
    F(publicMetaObject, Poco::Dynamic::Var)\
    F(privateMeta, std::string)\
    F(data, std::string)\
    F(internalMeta, std::optional<std::string>)\
    F(authorPubKey, std::string)\
    F(dio, std::string)
JSON_STRUCT_EXT(EncryptedMessageDataV5, core::dynamic::VersionedData, ENCRYPTED_MESSAGE_DATA_V5_FIELDS);

#define THREAD_MESSAGE_EVENT_DATA_FIELDS(F)\
    F(containerType, std::optional<std::string>)
JSON_STRUCT_EXT(ThreadMessageEventData, Message, THREAD_MESSAGE_EVENT_DATA_FIELDS);


} // server
} // thread
} // endpoint
} // privmx

#endif // _PRIVMXLIB_ENDPOINT_THREAD_SERVERTYPES_HPP_
