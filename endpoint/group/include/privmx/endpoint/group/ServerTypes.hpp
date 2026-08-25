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

// ── Hidden key tree (documents/nested_groups/09-hidden-key-tree.md) ─────────────────────────────────────────
// Everything below is optional at the wire level. A group served without these fields predates this client's
// tree-only creation path — this endpoint no longer creates such groups.

// Public state of one tree node. Nodes are never deleted, only refreshed into a new generation.
#define GROUP_TREE_NODE_FIELDS(F)                                                                                      \
    F(nodeIndex, int64_t)                                                                                              \
    F(generation, int64_t)                                                                                             \
    F(publicKey, std::string)
JSON_STRUCT(GroupTreeNode, GROUP_TREE_NODE_FIELDS);

// One edge: wrap(sk_parent -> pk_child). `isGrantEdge` marks the single edge joining the grant keypair to the
// tree root — the indirection that stops tree growth from advancing the epoch and staling every container.
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

// Complete public tree state. Sending it costs `O(n)` in each direction — see GroupTreeTransition for the shape
// a removal actually needs.
#define GROUP_TREE_STATE_FIELDS(F)                                                                                     \
    F(numLeaves, int64_t)                                                                                              \
    F(leafAssignment, std::vector<std::string>)                                                                        \
    F(nodes, std::vector<GroupTreeNode>)                                                                               \
    F(edges, std::vector<GroupTreeEdge>)
JSON_STRUCT(GroupTreeState, GROUP_TREE_STATE_FIELDS);

// One node a transition refreshes. `fromGeneration` is the generation it was read at — the precondition that lets
// the server apply a delta to a base it can confirm, and that makes a replayed transition a no-op.
#define GROUP_TREE_REFRESHED_NODE_FIELDS(F)                                                                            \
    F(nodeIndex, int64_t)                                                                                              \
    F(fromGeneration, int64_t)                                                                                         \
    F(generation, int64_t)                                                                                             \
    F(publicKey, std::string)
JSON_STRUCT(GroupTreeRefreshedNode, GROUP_TREE_REFRESHED_NODE_FIELDS);

// A removal as what it changes: the refreshed path and the edges around it. `O(log n)` where the whole state is
// `O(n)` — ~13 MB of edges at 16 384 members, in each direction, to change fourteen nodes.
#define GROUP_TREE_TRANSITION_FIELDS(F)                                                                                \
    F(baseKeyVersion, int64_t)                                                                                         \
    F(blankedPosition, int64_t)                                                                                        \
    F(refreshedNodes, std::vector<GroupTreeRefreshedNode>)                                                             \
    F(edges, std::vector<GroupTreeEdge>)
JSON_STRUCT(GroupTreeTransition, GROUP_TREE_TRANSITION_FIELDS);

// One node an addition re-keys. `fromGeneration` is absent when growth mints the node: there is no generation it
// was read at, and claiming one would be a claim about a node the server does not hold.
#define GROUP_TREE_SEATED_NODE_FIELDS(F)                                                                               \
    F(nodeIndex, int64_t)                                                                                              \
    F(fromGeneration, std::optional<int64_t>)                                                                          \
    F(generation, int64_t)                                                                                             \
    F(publicKey, std::string)
JSON_STRUCT(GroupTreeSeatedNode, GROUP_TREE_SEATED_NODE_FIELDS);

// An addition as what it changes: the new leaf's path re-keyed, at the **same** epoch. The epoch not moving is the
// whole point — every container wrap of the grant key stays valid, so nobody else has to act.
#define GROUP_TREE_ADDITION_TRANSITION_FIELDS(F)                                                                       \
    F(baseKeyVersion, int64_t)                                                                                         \
    F(position, int64_t)                                                                                               \
    F(seatedNodes, std::vector<GroupTreeSeatedNode>)                                                                   \
    F(edges, std::vector<GroupTreeEdge>)
JSON_STRUCT(GroupTreeAdditionTransition, GROUP_TREE_ADDITION_TRANSITION_FIELDS);

// ── Epoch Ladder (documents/epoch_key_archive/) ─────────────────────────────────────────────────────────────

// One rung: wrap(sk_targetKeyVersion -> pk_atKeyVersion). Always downward — `target < at` is the whole security
// guarantee of this layer, enforced by the bridge and re-checked here before any rung is traversed.
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
    F(keys, std::vector<core::server::KeyEntry>)                                                                       \
    F(groupKeys, std::optional<std::vector<core::server::GroupKeysEntry>>)                                             \
    F(version, int64_t)                                                                                                \
    F(keyVersion, std::optional<int64_t>)                                                                              \
    F(keyHistory, std::optional<std::vector<GroupKeyHistoryEntry>>)                                                    \
    F(numLeaves, std::optional<int64_t>)                                                                               \
    F(leafAssignment, std::optional<std::vector<std::string>>)                                                         \
    F(ownLeafPosition, std::optional<int64_t>)                                                                         \
    F(treeNodes, std::optional<std::vector<GroupTreeNode>>)                                                            \
    F(treeEdges, std::optional<std::vector<GroupTreeEdge>>)                                                            \
    F(eraFloor, std::optional<int64_t>)                                                                                \
    F(archivePrunedBelow, std::optional<int64_t>)                                                                      \
    F(policy, Poco::Dynamic::Var)                                                                                      \
    F(history, std::vector<GroupHistoryEntryInfo>)
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

#define GROUP_CREATE_MODEL_EXTRA_FIELDS(F)                                                                             \
    F(groupPubKey, std::string)                                                                                        \
    F(tree, std::optional<GroupTreeState>)
JSON_STRUCT_EXT(GroupCreateModel, core::server::ContainerCreateModelBase, GROUP_CREATE_MODEL_EXTRA_FIELDS);

#define GROUP_UPDATE_MODEL_EXTRA_FIELDS(F) F(groupPubKey, std::string)
JSON_STRUCT_EXT(GroupUpdateModel, core::server::ContainerUpdateModelBase, GROUP_UPDATE_MODEL_EXTRA_FIELDS);

#define GROUP_CREATE_RESULT_FIELDS(F) F(groupId, std::string)
JSON_STRUCT(GroupCreateResult, GROUP_CREATE_RESULT_FIELDS);

#define GROUP_DELETE_MODEL_FIELDS(F) F(groupId, std::string)
JSON_STRUCT(GroupDeleteModel, GROUP_DELETE_MODEL_FIELDS);

// `scope` picks how much of the tree the server sends: "path" (default) is the caller's own climb — their leaf
// edge, the edges above it, the grant edge, and the public keys of the path and the copath. "full" is the whole
// structure, which only an operation that submits a complete new state needs (BR-10/EP-07).
#define GROUP_GET_MODEL_FIELDS(F)                                                                                      \
    F(groupId, std::string)                                                                                            \
    F(type, std::optional<std::string>)                                                                                \
    F(scope, std::optional<std::string>)                                                                               \
    F(forUserId, std::optional<std::string>)                                                                           \
    F(forPosition, std::optional<int64_t>)
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

// What a groupCreated/groupUpdated notification carries (BR-03). Deliberately not a GroupInfo: the state used to
// travel in the event, converted once per recipient, which is why a group of a thousand shipped hundreds of
// megabytes for one membership change. Whoever needs the state calls getGroup.
#define GROUP_CHANGED_EVENT_DATA_FIELDS(F)                                                                             \
    F(groupId, std::string)                                                                                            \
    F(contextId, std::string)                                                                                          \
    F(version, int64_t)                                                                                                \
    F(keyVersion, int64_t)                                                                                             \
    F(changeKind, std::string)
JSON_STRUCT(GroupChangedEventData, GROUP_CHANGED_EVENT_DATA_FIELDS);

// ── Tree-backed membership + Epoch Ladder RPCs ──────────────────────────────────────────────────────────────
// The tree fields on GroupCreateModel/AddMember/RemoveMember are sent as one nested object, which is how the
// bridge validates them: a partially-submitted tree is not a thing the protocol allows.

// Adds one member without advancing the epoch — the operation the tree exists to make cheap.
#define GROUP_ADD_MEMBER_MODEL_FIELDS(F)                                                                               \
    F(id, std::string)                                                                                                 \
    F(userId, std::string)                                                                                             \
    F(role, std::string)                                                                                               \
    F(position, int64_t)                                                                                               \
    F(keyId, std::string)                                                                                              \
    F(data, Poco::Dynamic::Var)                                                                                        \
    F(transition, std::optional<GroupTreeAdditionTransition>)                                                          \
    F(tree, std::optional<GroupTreeState>)                                                                             \
    F(keys, std::vector<core::server::KeyEntrySet>)                                                                    \
    F(expectedKeyVersion, int64_t)
JSON_STRUCT(GroupAddMemberModel, GROUP_ADD_MEMBER_MODEL_FIELDS);

// Removes one member: blanks the leaf, refreshes its direct path, rotates the grant key, supplies the rungs.
#define GROUP_REMOVE_MEMBER_MODEL_FIELDS(F)                                                                            \
    F(id, std::string)                                                                                                 \
    F(userId, std::string)                                                                                             \
    F(groupPubKey, std::string)                                                                                        \
    F(keyId, std::string)                                                                                              \
    F(data, Poco::Dynamic::Var)                                                                                        \
    F(transition, std::optional<GroupTreeTransition>)                                                                  \
    F(tree, std::optional<GroupTreeState>)                                                                             \
    F(rungs, std::vector<GroupArchiveRung>)                                                                            \
    F(keys, std::vector<core::server::KeyEntrySet>)                                                                    \
    F(groupKeys, std::vector<core::server::GroupKeyEntrySet>)                                                          \
    F(expectedKeyVersion, int64_t)                                                                                     \
    F(confirmationTag, std::optional<std::string>)
JSON_STRUCT(GroupRemoveMemberModel, GROUP_REMOVE_MEMBER_MODEL_FIELDS);

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

// The archive is fetched separately from the group, because it grows with the whole history while a client
// needs it only when actually reaching for an older epoch.
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
