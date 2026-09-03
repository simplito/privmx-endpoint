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
    F(created, int64_t)                                                                                                \
    F(author, std::string)
JSON_STRUCT(GroupHistoryEntryInfo, GROUP_HISTORY_ENTRY_INFO_FIELDS);

#define GROUP_KEY_HISTORY_ENTRY_FIELDS(F)                                                                              \
    F(keyVersion, int64_t)                                                                                             \
    F(groupPubKey, std::string)
JSON_STRUCT(GroupKeyHistoryEntry, GROUP_KEY_HISTORY_ENTRY_FIELDS);

#define GROUP_TREE_NODE_FIELDS(F)                                                                                      \
    F(nodeIndex, int64_t)                                                                                              \
    F(generation, int64_t)                                                                                             \
    F(publicKey, std::string)
JSON_STRUCT(GroupTreeNode, GROUP_TREE_NODE_FIELDS);

#define GROUP_TREE_EDGE_FIELDS(F)                                                                                      \
    F(isGrantEdge, std::optional<bool>)                                                                                \
    F(parentIndex, std::optional<int64_t>)                                                                             \
    F(parentGeneration, int64_t)                                                                                       \
    F(childKind, std::string)                                                                                          \
    F(childIndex, std::optional<int64_t>)                                                                              \
    F(childGeneration, std::optional<int64_t>)                                                                         \
    F(childUserId, std::optional<std::string>)                                                                         \
    F(data, std::string)
JSON_STRUCT(GroupTreeEdge, GROUP_TREE_EDGE_FIELDS);

#define GROUP_TREE_STATE_FIELDS(F)                                                                                     \
    F(numLeaves, int64_t)                                                                                              \
    F(leafAssignment, std::vector<std::string>)                                                                        \
    F(nodes, std::vector<GroupTreeNode>)                                                                               \
    F(edges, std::vector<GroupTreeEdge>)
JSON_STRUCT(GroupTreeState, GROUP_TREE_STATE_FIELDS);

#define GROUP_TREE_REFRESHED_NODE_FIELDS(F)                                                                            \
    F(nodeIndex, int64_t)                                                                                              \
    F(fromGeneration, int64_t)                                                                                         \
    F(generation, int64_t)                                                                                             \
    F(publicKey, std::string)
JSON_STRUCT(GroupTreeRefreshedNode, GROUP_TREE_REFRESHED_NODE_FIELDS);

#define GROUP_TREE_TRANSITION_FIELDS(F)                                                                                \
    F(baseKeyVersion, int64_t)                                                                                         \
    F(blankedPositions, std::vector<int64_t>)                                                                          \
    F(refreshedNodes, std::vector<GroupTreeRefreshedNode>)                                                             \
    F(edges, std::vector<GroupTreeEdge>)
JSON_STRUCT(GroupTreeTransition, GROUP_TREE_TRANSITION_FIELDS);

#define GROUP_TREE_SEATED_NODE_FIELDS(F)                                                                               \
    F(nodeIndex, int64_t)                                                                                              \
    F(fromGeneration, std::optional<int64_t>)                                                                          \
    F(generation, int64_t)                                                                                             \
    F(publicKey, std::string)
JSON_STRUCT(GroupTreeSeatedNode, GROUP_TREE_SEATED_NODE_FIELDS);

#define GROUP_TREE_ADDITION_TRANSITION_FIELDS(F)                                                                       \
    F(baseKeyVersion, int64_t)                                                                                         \
    F(positions, std::vector<int64_t>)                                                                                 \
    F(seatedNodes, std::vector<GroupTreeSeatedNode>)                                                                   \
    F(edges, std::vector<GroupTreeEdge>)
JSON_STRUCT(GroupTreeAdditionTransition, GROUP_TREE_ADDITION_TRANSITION_FIELDS);

#define GROUP_ARCHIVE_RUNG_FIELDS(F)                                                                                   \
    F(atKeyVersion, int64_t)                                                                                           \
    F(targetKeyVersion, int64_t)                                                                                       \
    F(recipientKind, std::optional<std::string>)                                                                       \
    F(recipient, std::optional<std::string>)                                                                           \
    F(data, std::string)                                                                                               \
    F(author, std::optional<std::string>)
JSON_STRUCT(GroupArchiveRung, GROUP_ARCHIVE_RUNG_FIELDS);

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
    F(groupKeys, std::optional<std::vector<core::server::GroupKeysEntry>>)                                             \
    F(version, int64_t)                                                                                                \
    F(keyVersion, std::optional<int64_t>)                                                                              \
    F(keyHistory, std::optional<std::vector<GroupKeyHistoryEntry>>)                                                    \
    F(numLeaves, std::optional<int64_t>)                                                                               \
    F(leafAssignment, std::optional<std::vector<std::string>>)                                                         \
    F(ownLeafPosition, std::optional<int64_t>)                                                                         \
    F(subjectLeafPositions, std::optional<std::vector<int64_t>>)                                                       \
    F(nextFreeSeats, std::optional<std::vector<int64_t>>)                                                              \
    F(treeNodes, std::optional<std::vector<GroupTreeNode>>)                                                            \
    F(treeEdges, std::optional<std::vector<GroupTreeEdge>>)                                                            \
    F(eraFloor, std::optional<int64_t>)                                                                                \
    F(archivePrunedBelow, std::optional<int64_t>)                                                                      \
    F(policy, Poco::Dynamic::Var)                                                                                      \
    F(history, std::vector<GroupHistoryEntryInfo>)                                                                     \
    F(firstServedVersion, std::optional<int64_t>)
JSON_STRUCT(GroupInfo, GROUP_INFO_FIELDS);

#define GROUP_SUMMARY_FIELDS(F)                                                                                        \
    F(id, std::string)                                                                                                 \
    F(groupPubKey, std::string)                                                                                        \
    F(contextId, std::string)                                                                                          \
    F(resourceId, std::optional<std::string>)                                                                          \
    F(type, std::optional<std::string>)                                                                                \
    F(createDate, int64_t)                                                                                             \
    F(creator, std::string)                                                                                            \
    F(lastModificationDate, int64_t)                                                                                   \
    F(lastModifier, std::string)                                                                                       \
    F(users, std::vector<std::string>)                                                                                 \
    F(managers, std::vector<std::string>)                                                                              \
    F(version, int64_t)                                                                                                \
    F(keyVersion, int64_t)                                                                                             \
    F(policy, Poco::Dynamic::Var)
JSON_STRUCT(GroupSummary, GROUP_SUMMARY_FIELDS);

#define GROUP_KEY_ENTRY_SET_FOR_NEW_GROUP_FIELDS(F)                                                                    \
    F(keyId, std::string)                                                                                              \
    F(groupEpoch, int64_t)                                                                                             \
    F(data, Poco::Dynamic::Var)
JSON_STRUCT(GroupKeyEntrySetForNewGroup, GROUP_KEY_ENTRY_SET_FOR_NEW_GROUP_FIELDS);

#define GROUP_CREATE_MODEL_FIELDS(F)                                                                                   \
    F(resourceId, std::string)                                                                                         \
    F(contextId, std::string)                                                                                          \
    F(users, std::vector<std::string>)                                                                                 \
    F(managers, std::vector<std::string>)                                                                              \
    F(data, Poco::Dynamic::Var)                                                                                        \
    F(keyId, std::string)                                                                                              \
    F(type, std::string)                                                                                               \
    F(policy, std::optional<Poco::Dynamic::Var>)                                                                       \
    F(groupPubKey, std::string)                                                                                        \
    F(groupKeys, std::optional<GroupKeyEntrySetForNewGroup>)                                                           \
    F(tree, GroupTreeState)
JSON_STRUCT(GroupCreateModel, GROUP_CREATE_MODEL_FIELDS);

#define GROUP_UPDATE_MODEL_FIELDS(F)                                                                                   \
    F(id, std::string)                                                                                                 \
    F(resourceId, std::string)                                                                                         \
    F(data, Poco::Dynamic::Var)                                                                                        \
    F(keyId, std::string)                                                                                              \
    F(version, int64_t)                                                                                                \
    F(force, bool)                                                                                                     \
    F(policy, std::optional<Poco::Dynamic::Var>)
JSON_STRUCT(GroupUpdateModel, GROUP_UPDATE_MODEL_FIELDS);

#define GROUP_CREATE_RESULT_FIELDS(F) F(groupId, std::string)
JSON_STRUCT(GroupCreateResult, GROUP_CREATE_RESULT_FIELDS);

#define GROUP_DELETE_MODEL_FIELDS(F) F(groupId, std::string)
JSON_STRUCT(GroupDeleteModel, GROUP_DELETE_MODEL_FIELDS);

#define GROUP_GET_MODEL_FIELDS(F)                                                                                      \
    F(groupId, std::string)                                                                                            \
    F(type, std::optional<std::string>)                                                                                \
    F(scope, std::optional<std::string>)                                                                               \
    F(forUserIds, std::optional<std::vector<std::string>>)                                                             \
    F(forPosition, std::optional<int64_t>)                                                                             \
    F(forNewMembers, std::optional<int64_t>)                                                                           \
    F(fromVersion, std::optional<int64_t>)
JSON_STRUCT(GroupGetModel, GROUP_GET_MODEL_FIELDS);

#define GROUP_LIST_MODEL_EXTRA_FIELDS(F)
JSON_STRUCT_EXT(GroupListModel, core::server::ContainerListModel, GROUP_LIST_MODEL_EXTRA_FIELDS);

#define GROUP_GET_RESULT_FIELDS(F) F(group, GroupInfo)
JSON_STRUCT(GroupGetResult, GROUP_GET_RESULT_FIELDS);

#define GROUP_LIST_RESULT_FIELDS(F)                                                                                    \
    F(groups, std::vector<GroupSummary>)                                                                               \
    F(count, int64_t)
JSON_STRUCT(GroupListResult, GROUP_LIST_RESULT_FIELDS);

#define GROUP_DELETED_EVENT_DATA_FIELDS(F)                                                                             \
    F(groupId, std::string)                                                                                            \
    F(contextId, std::string)
JSON_STRUCT(GroupDeletedEventData, GROUP_DELETED_EVENT_DATA_FIELDS);
#define GROUP_CHANGED_EVENT_DATA_FIELDS(F)                                                                             \
    F(groupId, std::string)                                                                                            \
    F(contextId, std::string)                                                                                          \
    F(version, int64_t)                                                                                                \
    F(keyVersion, int64_t)                                                                                             \
    F(changeKind, std::string)
JSON_STRUCT(GroupChangedEventData, GROUP_CHANGED_EVENT_DATA_FIELDS);

// One newcomer. Their seat is `transition.positions[i]` — named in one place, so the two cannot disagree.
// A batch is not k additions sent together: the newcomers' paths overlap, so the delta re-keys their union once.
#define GROUP_ADD_MEMBER_ENTRY_FIELDS(F)                                                                               \
    F(userId, std::string)                                                                                             \
    F(role, std::string)
JSON_STRUCT(GroupAddMemberEntry, GROUP_ADD_MEMBER_ENTRY_FIELDS);

#define GROUP_ADD_MEMBERS_MODEL_FIELDS(F)                                                                              \
    F(id, std::string)                                                                                                 \
    F(members, std::vector<GroupAddMemberEntry>)                                                                       \
    F(keyId, std::string)                                                                                              \
    F(data, Poco::Dynamic::Var)                                                                                        \
    F(transition, GroupTreeAdditionTransition)                                                                         \
    F(expectedKeyVersion, int64_t)
JSON_STRUCT(GroupAddMembersModel, GROUP_ADD_MEMBERS_MODEL_FIELDS);

// Removing several at once is not a convenience: done one at a time each removal advances the epoch on its own,
// so every container the group can read goes stale k times and the rotation budget is charged k times.
#define GROUP_REMOVE_MEMBERS_MODEL_FIELDS(F)                                                                           \
    F(id, std::string)                                                                                                 \
    F(userIds, std::vector<std::string>)                                                                               \
    F(groupPubKey, std::string)                                                                                        \
    F(keyId, std::string)                                                                                              \
    F(data, Poco::Dynamic::Var)                                                                                        \
    F(transition, GroupTreeTransition)                                                                                 \
    F(rungs, std::vector<GroupArchiveRung>)                                                                            \
    F(groupKeys, std::optional<core::server::GroupKeyEntrySet>)                                                        \
    F(expectedKeyVersion, int64_t)                                                                                     \
    F(confirmationTag, std::optional<std::string>)
JSON_STRUCT(GroupRemoveMembersModel, GROUP_REMOVE_MEMBERS_MODEL_FIELDS);

#define GROUP_CUT_ERA_MODEL_FIELDS(F)                                                                                  \
    F(id, std::string)                                                                                                 \
    F(newFloor, int64_t)                                                                                               \
    F(expectedKeyVersion, int64_t)
JSON_STRUCT(GroupCutEraModel, GROUP_CUT_ERA_MODEL_FIELDS);

#define GROUP_PRUNE_ARCHIVE_MODEL_FIELDS(F)                                                                            \
    F(id, std::string)                                                                                                 \
    F(belowEpoch, int64_t)                                                                                             \
    F(expectedKeyVersion, int64_t)
JSON_STRUCT(GroupPruneArchiveModel, GROUP_PRUNE_ARCHIVE_MODEL_FIELDS);

#define GROUP_GET_KEY_ARCHIVE_MODEL_FIELDS(F)                                                                          \
    F(id, std::string)                                                                                                 \
    F(fromKeyVersion, std::optional<int64_t>)                                                                          \
    F(toKeyVersion, std::optional<int64_t>)
JSON_STRUCT(GroupGetKeyArchiveModel, GROUP_GET_KEY_ARCHIVE_MODEL_FIELDS);

#define GROUP_GET_KEY_ARCHIVE_RESULT_FIELDS(F)                                                                         \
    F(keyVersion, int64_t)                                                                                             \
    F(eraFloor, int64_t)                                                                                               \
    F(archivePrunedBelow, std::optional<int64_t>)                                                                      \
    F(keyHistory, std::vector<GroupKeyHistoryEntry>)                                                                   \
    F(rungs, std::vector<GroupArchiveRung>)
JSON_STRUCT(GroupGetKeyArchiveResult, GROUP_GET_KEY_ARCHIVE_RESULT_FIELDS);

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
