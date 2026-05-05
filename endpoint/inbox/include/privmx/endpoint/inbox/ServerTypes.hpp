/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_ENDPOINT_INBOX_SERVERTYPES_HPP_
#define _PRIVMXLIB_ENDPOINT_INBOX_SERVERTYPES_HPP_

#include <string>

#include <privmx/endpoint/core/ServerTypes.hpp>
#include <privmx/utils/JsonHelper.hpp>

namespace privmx {
namespace endpoint {
namespace inbox {
namespace server {

#define FILE_CONFIG_FIELDS(F)\
    F(minCount, int64_t)\
    F(maxCount, int64_t)\
    F(maxFileSize, int64_t)\
    F(maxWholeUploadSize, int64_t)
JSON_STRUCT(FileConfig_c_struct, FILE_CONFIG_FIELDS);

#define INBOX_DATA_FIELDS(F)\
    F(threadId, std::string)\
    F(storeId, std::string)\
    F(fileConfig, FileConfig_c_struct)\
    F(meta, Poco::Dynamic::Var)\
    F(publicData, Poco::Dynamic::Var)
JSON_STRUCT(InboxData_c_struct, INBOX_DATA_FIELDS);

#define INBOX_DATA_ENTRY_FIELDS(F)\
    F(keyId, std::string)\
    F(data, InboxData_c_struct)
JSON_STRUCT(InboxDataEntry_c_struct, INBOX_DATA_ENTRY_FIELDS);

#define INBOX_INFO_FIELDS(F)\
    F(id, std::string)\
    F(resourceId, std::optional<std::string>)\
    F(contextId, std::string)\
    F(createDate, int64_t)\
    F(creator, std::string)\
    F(lastModificationDate, int64_t)\
    F(lastModifier, std::string)\
    F(data, std::vector<InboxDataEntry_c_struct>)\
    F(keyId, std::string)\
    F(users, std::vector<std::string>)\
    F(managers, std::vector<std::string>)\
    F(keys, std::vector<core::server::KeyEntry_c_struct>)\
    F(version, int64_t)\
    F(type, std::optional<std::string>)\
    F(policy, Poco::Dynamic::Var)
JSON_STRUCT(InboxInfo_c_struct, INBOX_INFO_FIELDS);

#define PRIVATE_DATA_V4_FIELDS(F)\
    F(privateMeta, std::string)\
    F(internalMeta, std::optional<std::string>)\
    F(authorPubKey, std::string)
JSON_STRUCT_EXT(PrivateDataV4_c_struct, core::dynamic::VersionedData_c_struct, PRIVATE_DATA_V4_FIELDS);

#define PUBLIC_DATA_V4_FIELDS(F)\
    F(publicMeta, std::string)\
    F(publicMetaObject, Poco::Dynamic::Var)\
    F(authorPubKey, std::string)\
    F(inboxPubKey, std::string)\
    F(inboxKeyId, std::string)
JSON_STRUCT_EXT(PublicDataV4_c_struct, core::dynamic::VersionedData_c_struct, PUBLIC_DATA_V4_FIELDS);

#define PRIVATE_DATA_V5_FIELDS(F)\
    F(privateMeta, std::string)\
    F(internalMeta, std::string)\
    F(authorPubKey, std::string)\
    F(dio, std::string)
JSON_STRUCT_EXT(PrivateDataV5_c_struct, core::dynamic::VersionedData_c_struct, PRIVATE_DATA_V5_FIELDS);

#define PUBLIC_DATA_V5_FIELDS(F)\
    F(publicMeta, std::string)\
    F(publicMetaObject, Poco::Dynamic::Var)\
    F(authorPubKey, std::string)\
    F(inboxPubKey, std::string)\
    F(inboxKeyId, std::string)
JSON_STRUCT_EXT(PublicDataV5_c_struct, core::dynamic::VersionedData_c_struct, PUBLIC_DATA_V5_FIELDS);

/////////////// MODELS AND RESULTS ////////////////////////////

#define INBOX_CREATE_MODEL_FIELDS(F)\
    F(resourceId, std::string)\
    F(contextId, std::string)\
    F(users, std::vector<std::string>)\
    F(managers, std::vector<std::string>)\
    F(data, InboxData_c_struct)\
    F(keyId, std::string)\
    F(keys, std::vector<core::server::KeyEntrySet_c_struct>)\
    F(policy, std::optional<Poco::Dynamic::Var>)
JSON_STRUCT(InboxCreateModel_c_struct, INBOX_CREATE_MODEL_FIELDS);

#define INBOX_CREATE_RESULT_FIELDS(F)\
    F(inboxId, std::string)
JSON_STRUCT(InboxCreateResult_c_struct, INBOX_CREATE_RESULT_FIELDS);

#define INBOX_UPDATE_MODEL_FIELDS(F)\
    F(id, std::string)\
    F(resourceId, std::string)\
    F(users, std::vector<std::string>)\
    F(managers, std::vector<std::string>)\
    F(data, InboxData_c_struct)\
    F(keyId, std::string)\
    F(keys, std::vector<core::server::KeyEntrySet_c_struct>)\
    F(version, int64_t)\
    F(force, bool)\
    F(policy, std::optional<Poco::Dynamic::Var>)
JSON_STRUCT(InboxUpdateModel_c_struct, INBOX_UPDATE_MODEL_FIELDS);

#define INBOX_GET_MODEL_FIELDS(F)\
    F(id, std::string)\
    F(type, std::optional<std::string>)
JSON_STRUCT(InboxGetModel_c_struct, INBOX_GET_MODEL_FIELDS);

#define INBOX_GET_RESULT_FIELDS(F)\
    F(inbox, InboxInfo_c_struct)
JSON_STRUCT(InboxGetResult_c_struct, INBOX_GET_RESULT_FIELDS);

#define INBOX_LIST_MODEL_FIELDS(F)\
    F(contextId, std::string)\
    F(type, std::optional<std::string>)
JSON_STRUCT_EXT(InboxListModel_c_struct, core::server::ListModel_c_struct, INBOX_LIST_MODEL_FIELDS);

#define INBOX_LIST_RESULT_FIELDS(F)\
    F(inboxes, std::vector<InboxInfo_c_struct>)\
    F(count, int64_t)
JSON_STRUCT(InboxListResult_c_struct, INBOX_LIST_RESULT_FIELDS);

#define INBOX_FILE_FIELDS(F)\
    F(fileIndex, int64_t)\
    F(thumbIndex, std::optional<int64_t>)\
    F(meta, Poco::Dynamic::Var)\
    F(resourceId, std::string)
JSON_STRUCT(InboxFile_c_struct, INBOX_FILE_FIELDS);

#define INBOX_SEND_MODEL_FIELDS(F)\
    F(inboxId, std::string)\
    F(resourceId, std::string)\
    F(message, std::string)\
    F(requestId, std::optional<std::string>)\
    F(files, std::vector<InboxFile_c_struct>)\
    F(version, int64_t)
JSON_STRUCT(InboxSendModel_c_struct, INBOX_SEND_MODEL_FIELDS);

#define INBOX_MESSAGE_SERVER_FIELDS(F)\
    F(message, std::string)\
    F(store, std::string)\
    F(files, std::vector<std::string>)\
    F(version, int64_t)
JSON_STRUCT(InboxMessageServer_c_struct, INBOX_MESSAGE_SERVER_FIELDS);

#define INBOX_GET_PUBLIC_VIEW_RESULT_FIELDS(F)\
    F(inboxId, std::string)\
    F(version, int64_t)\
    F(publicData, Poco::Dynamic::Var)
JSON_STRUCT(InboxGetPublicViewResult_c_struct, INBOX_GET_PUBLIC_VIEW_RESULT_FIELDS);

#define INBOX_DELETED_EVENT_DATA_FIELDS(F)\
    F(inboxId, std::string)\
    F(type, std::optional<std::string>)
JSON_STRUCT(InboxDeletedEventData_c_struct, INBOX_DELETED_EVENT_DATA_FIELDS);

#define INBOX_DELETE_MODEL_FIELDS(F)\
    F(inboxId, std::string)
JSON_STRUCT(InboxDeleteModel_c_struct, INBOX_DELETE_MODEL_FIELDS);

#define INBOX_STAT_CHANGED_EVENT_DATA_FIELDS(F)\
    F(inboxId, std::string)\
    F(lastSubmitDate, int64_t)\
    F(submits, int64_t)\
    F(type, std::optional<std::string>)
JSON_STRUCT(InboxStatChangedEventData_c_struct, INBOX_STAT_CHANGED_EVENT_DATA_FIELDS);

} // server
} // inbox
} // endpoint
} // privmx

#endif // _PRIVMXLIB_ENDPOINT_INBOX_SERVERTYPES_HPP_
