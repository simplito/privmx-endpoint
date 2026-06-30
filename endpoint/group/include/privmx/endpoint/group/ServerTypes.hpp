#ifndef _PRIVMXLIB_ENDPOINT_GROUP_SERVERTYPES_HPP_
#define _PRIVMXLIB_ENDPOINT_GROUP_SERVERTYPES_HPP_

#include <string>

#include "privmx/endpoint/core/ServerTypes.hpp"
#include <privmx/utils/JsonHelper.hpp>

namespace privmx {
namespace endpoint {
namespace group {
namespace server {

#define GROUP_DATA_ENTRY_EXTRA_FIELDS(F)
JSON_STRUCT_EXT(GroupDataEntry, core::server::ContainerDataEntry, GROUP_DATA_ENTRY_EXTRA_FIELDS);

#define GROUP_HISTORY_ENTRY_INFO_FIELDS(F)                                                                             \
    F(keyId, std::string)                                                                                              \
    F(groupPubKey, std::string)                                                                                        \
    F(users, std::vector<std::string>)                                                                                 \
    F(managers, std::vector<std::string>)                                                                              \
    F(created, int64_t)                                                                                                \
    F(author, std::string)
JSON_STRUCT(GroupHistoryEntryInfo, GROUP_HISTORY_ENTRY_INFO_FIELDS);

// Compact per-epoch summary: epoch number → group public key used at that epoch.
// Populated by the bridge (BR-1); maps keyVersion → GroupPub_e for client-side verification.
#define GROUP_KEY_HISTORY_ENTRY_FIELDS(F)                                                                              \
    F(keyVersion, int64_t)                                                                                             \
    F(groupPubKey, std::string)
JSON_STRUCT(GroupKeyHistoryEntry, GROUP_KEY_HISTORY_ENTRY_FIELDS);

// GroupInfo — does NOT extend ContainerInfoBase because it has no top-level keyId
#define GROUP_INFO_FIELDS(F)                                                                                           \
    F(id, std::string)                                                                                                 \
    F(groupPubKey, std::string)                                                                                        \
    F(contextId, std::string)                                                                                          \
    F(resourceId, std::optional<std::string>)                                                                          \
    F(type, std::optional<std::string>)                                                                                \
    F(createDate, int64_t)                                                                                             \
    F(creator, std::string)                                                                                            \
    F(lastModificationDate, int64_t)                                                                                   \
    F(lastModifier, std::string)                                                                                       \
    F(data, std::vector<GroupDataEntry>)                                                                               \
    F(users, std::vector<std::string>)                                                                                 \
    F(managers, std::vector<std::string>)                                                                              \
    F(keys, std::vector<core::server::KeyEntry>)                                                                       \
    F(version, int64_t)                                                                                                \
    F(keyVersion, std::optional<int64_t>)                                                                              \
    F(keyHistory, std::optional<std::vector<GroupKeyHistoryEntry>>)                                                    \
    F(policy, Poco::Dynamic::Var)                                                                                      \
    F(history, std::vector<GroupHistoryEntryInfo>)
JSON_STRUCT(GroupInfo, GROUP_INFO_FIELDS);

#define GROUP_CREATE_MODEL_EXTRA_FIELDS(F) F(groupPubKey, std::string)
JSON_STRUCT_EXT(GroupCreateModel, core::server::ContainerCreateModelBase, GROUP_CREATE_MODEL_EXTRA_FIELDS);

#define GROUP_UPDATE_MODEL_EXTRA_FIELDS(F)                                                                             \
    F(groupPubKey, std::string)
JSON_STRUCT_EXT(GroupUpdateModel, core::server::ContainerUpdateModelBase, GROUP_UPDATE_MODEL_EXTRA_FIELDS);

#define GROUP_CREATE_RESULT_FIELDS(F) F(groupId, std::string)
JSON_STRUCT(GroupCreateResult, GROUP_CREATE_RESULT_FIELDS);

#define GROUP_DELETE_MODEL_FIELDS(F) F(groupId, std::string)
JSON_STRUCT(GroupDeleteModel, GROUP_DELETE_MODEL_FIELDS);

#define GROUP_GET_MODEL_FIELDS(F)                                                                                      \
    F(groupId, std::string)                                                                                            \
    F(type, std::optional<std::string>)
JSON_STRUCT(GroupGetModel, GROUP_GET_MODEL_FIELDS);

#define GROUP_LIST_MODEL_EXTRA_FIELDS(F)
JSON_STRUCT_EXT(GroupListModel, core::server::ContainerListModel, GROUP_LIST_MODEL_EXTRA_FIELDS);

#define GROUP_GET_RESULT_FIELDS(F) F(group, GroupInfo)
JSON_STRUCT(GroupGetResult, GROUP_GET_RESULT_FIELDS);

#define GROUP_LIST_RESULT_FIELDS(F)                                                                                    \
    F(groups, std::vector<GroupInfo>)                                                                                  \
    F(count, int64_t)
JSON_STRUCT(GroupListResult, GROUP_LIST_RESULT_FIELDS);

#define GROUP_DELETED_EVENT_DATA_FIELDS(F)                                                                             \
    F(groupId, std::string)                                                                                            \
    F(contextId, std::string)
JSON_STRUCT(GroupDeletedEventData, GROUP_DELETED_EVENT_DATA_FIELDS);

// generateNewGroupKey RPC (BR-2) — explicit forced group key rotation
#define GENERATE_NEW_GROUP_KEY_MODEL_FIELDS(F)                                                                         \
    F(id, std::string)                                                                                                 \
    F(keyId, std::string)                                                                                              \
    F(expectedKeyVersion, int64_t)                                                                                     \
    F(groupPubKey, std::string)                                                                                        \
    F(data, Poco::Dynamic::Var)                                                                                        \
    F(keys, std::vector<core::server::KeyEntrySet>)                                                                    \
    F(confirmationTag, std::string)
JSON_STRUCT(GenerateNewGroupKeyModel, GENERATE_NEW_GROUP_KEY_MODEL_FIELDS);

// Payload carried in ROTATED_ALREADY error (BR-3): the winner's key entry addressed to the caller.
#define ROTATED_ALREADY_PAYLOAD_FIELDS(F)                                                                              \
    F(keyVersion, int64_t)                                                                                             \
    F(groupPubKey, std::string)                                                                                        \
    F(winnerKeyEntry, core::server::KeyEntry)                                                                          \
    F(confirmationTag, std::string)
JSON_STRUCT(RotatedAlreadyPayload, ROTATED_ALREADY_PAYLOAD_FIELDS);

} // namespace server
} // namespace group
} // namespace endpoint
} // namespace privmx

#endif // _PRIVMXLIB_ENDPOINT_GROUP_SERVERTYPES_HPP_
