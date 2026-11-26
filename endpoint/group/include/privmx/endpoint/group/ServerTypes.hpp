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
    F(author, std::string)                                                                                             \
    F(version, int64_t)                                                                                                \
    F(keyVersion, int64_t)
JSON_STRUCT(GroupHistoryEntryInfo, GROUP_HISTORY_ENTRY_INFO_FIELDS);

// One metadata plane's entry. `keyVersion` is the epoch its key belongs to — how far a later reader descends.
// Instantiated twice, once per plane, and the two may legitimately sit at different epochs.
#define GROUP_META_ENTRY_FIELDS(F)                                                                                     \
    F(version, int64_t)                                                                                                \
    F(keyId, std::string)                                                                                              \
    F(keyVersion, int64_t)                                                                                             \
    F(data, Poco::Dynamic::Var)                                                                                        \
    F(created, int64_t)                                                                                                \
    F(author, std::string)
JSON_STRUCT(GroupMetaEntry, GROUP_META_ENTRY_FIELDS);

#define GROUP_KEY_HISTORY_ENTRY_FIELDS(F)                                                                              \
    F(keyVersion, int64_t)                                                                                             \
    F(groupPubKey, std::string)
JSON_STRUCT(GroupKeyHistoryEntry, GROUP_KEY_HISTORY_ENTRY_FIELDS);

// A keyed node's record. No `publicKey` is a blank node: it keeps its generation and waits for a self-update.
// `setBy` names the commit statement that set a filled node's key.
#define GROUP_TREE_NODE_FIELDS(F)                                                                                      \
    F(nodeIndex, int64_t)                                                                                              \
    F(generation, int64_t)                                                                                             \
    F(publicKey, std::optional<std::string>)                                                                           \
    F(setBy, std::optional<int64_t>)
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

#define GROUP_TREE_COMMIT_PATH_ENTRY_FIELDS(F)                                                                         \
    F(nodeIndex, int64_t)                                                                                              \
    F(generation, int64_t)                                                                                             \
    F(publicKey, std::string)                                                                                          \
    F(subtreeHash, std::string)
JSON_STRUCT(GroupTreeCommitPathEntry, GROUP_TREE_COMMIT_PATH_ENTRY_FIELDS);

// A commit statement as signed (keytree/TreeCommits.hpp). Hashes are lowercase hex, the signature base64.
#define GROUP_TREE_COMMIT_FIELDS(F)                                                                                    \
    F(seq, int64_t)                                                                                                    \
    F(prevDigest, std::string)                                                                                         \
    F(op, std::string)                                                                                                 \
    F(groupId, std::string)                                                                                            \
    F(treeVersion, int64_t)                                                                                            \
    F(date, int64_t)                                                                                                   \
    F(keyVersion, int64_t)                                                                                             \
    F(groupPubKey, std::string)                                                                                        \
    F(rosterVersion, int64_t)                                                                                          \
    F(rosterHash, std::string)                                                                                         \
    F(treeHash, std::string)                                                                                           \
    F(policyHash, std::string)                                                                                         \
    F(committer, std::string)                                                                                          \
    F(committerPubKey, std::string)                                                                                    \
    F(committerSeat, int64_t)                                                                                          \
    F(path, std::vector<GroupTreeCommitPathEntry>)                                                                     \
    F(addedUsers, std::vector<std::string>)                                                                            \
    F(addedManagers, std::vector<std::string>)                                                                         \
    F(removed, std::vector<std::string>)                                                                               \
    F(signature, std::string)                                                                                          \
    F(policy, std::optional<Poco::Dynamic::Var>)
JSON_STRUCT(GroupTreeCommit, GROUP_TREE_COMMIT_FIELDS);

#define GROUP_TREE_STATE_FIELDS(F)                                                                                     \
    F(numLeaves, int64_t)                                                                                              \
    F(leafAssignment, std::vector<std::string>)                                                                        \
    F(nodes, std::vector<GroupTreeNode>)                                                                               \
    F(edges, std::vector<GroupTreeEdge>)
JSON_STRUCT(GroupTreeState, GROUP_TREE_STATE_FIELDS);

// `fromGeneration` is the generation the node was read at, absent when it had no record.
#define GROUP_TREE_REFRESHED_NODE_FIELDS(F)                                                                            \
    F(nodeIndex, int64_t)                                                                                              \
    F(fromGeneration, std::optional<int64_t>)                                                                          \
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

#define GROUP_TREE_SELF_UPDATE_TRANSITION_FIELDS(F)                                                                    \
    F(baseKeyVersion, int64_t)                                                                                         \
    F(refreshedNodes, std::vector<GroupTreeRefreshedNode>)                                                             \
    F(edges, std::vector<GroupTreeEdge>)
JSON_STRUCT(GroupTreeSelfUpdateTransition, GROUP_TREE_SELF_UPDATE_TRANSITION_FIELDS);

#define GROUP_ARCHIVE_RUNG_FIELDS(F)                                                                                   \
    F(atKeyVersion, int64_t)                                                                                           \
    F(targetKeyVersion, int64_t)                                                                                       \
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
    F(publicMeta, GroupMetaEntry)                                                                                      \
    F(privateMeta, GroupMetaEntry)                                                                                     \
    F(publicMetaVersion, int64_t)                                                                                      \
    F(privateMetaVersion, int64_t)                                                                                     \
    F(rosterVersion, int64_t)                                                                                          \
    F(keyVersion, int64_t)                                                                                             \
    F(keyHistory, std::optional<std::vector<GroupKeyHistoryEntry>>)                                                    \
    F(treeVersion, std::optional<int64_t>)                                                                             \
    F(numLeaves, std::optional<int64_t>)                                                                               \
    F(leafAssignment, std::optional<std::vector<std::string>>)                                                         \
    F(ownLeafPosition, std::optional<int64_t>)                                                                         \
    F(subjectLeafPositions, std::optional<std::vector<int64_t>>)                                                       \
    F(nextFreeSeats, std::optional<std::vector<int64_t>>)                                                              \
    F(treeNodes, std::optional<std::vector<GroupTreeNode>>)                                                            \
    F(treeEdges, std::optional<std::vector<GroupTreeEdge>>)                                                            \
    F(treeCommit, std::optional<GroupTreeCommit>)                                                                      \
    F(treeCommits, std::optional<std::vector<GroupTreeCommit>>)                                                        \
    F(copathHashes, std::optional<std::vector<std::string>>)                                                           \
    F(eraFloor, std::optional<int64_t>)                                                                                \
    F(archivePrunedBelow, std::optional<int64_t>)                                                                      \
    F(policy, Poco::Dynamic::Var)                                                                                      \
    F(history, std::vector<GroupHistoryEntryInfo>)                                                                     \
    F(visibleTo, std::optional<std::string>)
JSON_STRUCT(GroupInfo, GROUP_INFO_FIELDS);

// What `groupGetPublicKey` serves somebody who may hold no seat: the identity key, the roster and the latest
// statement, which is what vouches for the key (TreeVerifier::verifyListed). No tree, no keys, no metadata.
#define GROUP_PUBLIC_INFO_FIELDS(F)                                                                                    \
    F(id, std::string)                                                                                                 \
    F(contextId, std::string)                                                                                          \
    F(resourceId, std::optional<std::string>)                                                                          \
    F(creator, std::string)                                                                                            \
    F(users, std::vector<std::string>)                                                                                 \
    F(managers, std::vector<std::string>)                                                                              \
    F(rosterVersion, int64_t)                                                                                          \
    F(keyVersion, int64_t)                                                                                             \
    F(groupPubKey, std::string)                                                                                        \
    F(policy, Poco::Dynamic::Var)                                                                                      \
    F(visibleTo, std::string)                                                                                          \
    F(treeCommit, GroupTreeCommit)
JSON_STRUCT(GroupPublicInfo, GROUP_PUBLIC_INFO_FIELDS);

#define GROUP_GET_PUBLIC_KEY_MODEL_FIELDS(F) F(groupId, std::string)
JSON_STRUCT(GroupGetPublicKeyModel, GROUP_GET_PUBLIC_KEY_MODEL_FIELDS);

#define GROUP_GET_PUBLIC_KEY_RESULT_FIELDS(F) F(group, GroupPublicInfo)
JSON_STRUCT(GroupGetPublicKeyResult, GROUP_GET_PUBLIC_KEY_RESULT_FIELDS);

#define GROUP_SET_VISIBILITY_MODEL_FIELDS(F)                                                                           \
    F(groupId, std::string)                                                                                            \
    F(visibleTo, std::string)
JSON_STRUCT(GroupSetVisibilityModel, GROUP_SET_VISIBILITY_MODEL_FIELDS);

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
    F(publicMetaVersion, int64_t)                                                                                      \
    F(privateMetaVersion, int64_t)                                                                                     \
    F(rosterVersion, int64_t)                                                                                          \
    F(keyVersion, int64_t)                                                                                             \
    F(policy, Poco::Dynamic::Var)                                                                                      \
    F(visibleTo, std::optional<std::string>)
// Constant size: no roster and no statement, so `groupPubKey` is unvouched (TreeVerifier::pinnedAt).
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
    F(publicMeta, Poco::Dynamic::Var)                                                                                  \
    F(privateMeta, Poco::Dynamic::Var)                                                                                 \
    F(keyId, std::string)                                                                                              \
    F(type, std::string)                                                                                               \
    F(groupPubKey, std::string)                                                                                        \
    F(groupKeys, std::optional<GroupKeyEntrySetForNewGroup>)                                                           \
    F(tree, GroupTreeState)                                                                                            \
    F(commit, GroupTreeCommit)                                                                                         \
    F(visibleTo, std::optional<std::string>)
JSON_STRUCT(GroupCreateModel, GROUP_CREATE_MODEL_FIELDS);

// The public metadata plane's write. CAS-guarded on `publicMetaVersion` and nothing else, so a concurrent
// private-metadata write commits a different counter and the two cannot strand each other.
#define GROUP_UPDATE_PUBLIC_META_MODEL_FIELDS(F)                                                                       \
    F(id, std::string)                                                                                                 \
    F(resourceId, std::string)                                                                                         \
    F(data, Poco::Dynamic::Var)                                                                                        \
    F(keyId, std::string)                                                                                              \
    F(version, int64_t)
JSON_STRUCT(GroupUpdatePublicMetaModel, GROUP_UPDATE_PUBLIC_META_MODEL_FIELDS);

// The private metadata plane's write, CAS-guarded on `privateMetaVersion`.
#define GROUP_UPDATE_PRIVATE_META_MODEL_FIELDS(F)                                                                      \
    F(id, std::string)                                                                                                 \
    F(resourceId, std::string)                                                                                         \
    F(data, Poco::Dynamic::Var)                                                                                        \
    F(keyId, std::string)                                                                                              \
    F(version, int64_t)
JSON_STRUCT(GroupUpdatePrivateMetaModel, GROUP_UPDATE_PRIVATE_META_MODEL_FIELDS);

// A rules change (op "policy") is a signed commit: the rules object travels as `commit.policy`, bound by its
// `policyHash` (the rulesHash), and lands under the same CAS as any commit. It touches neither metadata counter and appends no entry.
#define GROUP_UPDATE_POLICY_MODEL_FIELDS(F)                                                                            \
    F(id, std::string)                                                                                                 \
    F(commit, GroupTreeCommit)                                                                                         \
    F(expectedKeyVersion, int64_t)                                                                                     \
    F(expectedRosterVersion, int64_t)
JSON_STRUCT(GroupUpdatePolicyModel, GROUP_UPDATE_POLICY_MODEL_FIELDS);

#define GROUP_CREATE_RESULT_FIELDS(F) F(groupId, std::string)
JSON_STRUCT(GroupCreateResult, GROUP_CREATE_RESULT_FIELDS);

#define GROUP_DELETE_MODEL_FIELDS(F) F(groupId, std::string)
JSON_STRUCT(GroupDeleteModel, GROUP_DELETE_MODEL_FIELDS);

#define GROUP_GET_MODEL_FIELDS(F)                                                                                      \
    F(groupId, std::string)                                                                                            \
    F(type, std::optional<std::string>)                                                                                \
    F(scope, std::optional<std::string>)                                                                               \
    F(forUserIds, std::optional<std::vector<std::string>>)                                                             \
    F(forNewMembers, std::optional<int64_t>)                                                                           \
    F(fromRosterVersion, std::optional<int64_t>)
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
    F(publicMetaVersion, int64_t)                                                                                      \
    F(privateMetaVersion, int64_t)                                                                                     \
    F(rosterVersion, int64_t)                                                                                          \
    F(keyVersion, int64_t)                                                                                             \
    F(changeKind, std::string)
JSON_STRUCT(GroupChangedEventData, GROUP_CHANGED_EVENT_DATA_FIELDS);
// `spaceDeleted` carries the two ids only; the rest stays at its default.
#define SPACE_CHANGED_EVENT_DATA_FIELDS(F)                                                                             \
    F(spaceId, std::string)                                                                                            \
    F(contextId, std::string)                                                                                          \
    F(keyVersion, std::optional<int64_t>)                                                                              \
    F(publicMetaVersion, std::optional<int64_t>)                                                                       \
    F(privateMetaVersion, std::optional<int64_t>)                                                                      \
    F(changeKind, std::optional<std::string>)
JSON_STRUCT(SpaceChangedEventData, SPACE_CHANGED_EVENT_DATA_FIELDS);

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
    F(expectedKeyVersion, int64_t)                                                                                     \
    F(expectedRosterVersion, int64_t)                                                                                  \
    F(commit, GroupTreeCommit)
JSON_STRUCT(GroupAddMembersModel, GROUP_ADD_MEMBERS_MODEL_FIELDS);

// A change of role for members already in the group: a roster entry and a `roles` statement, no key.
#define GROUP_SET_ROLES_MODEL_FIELDS(F)                                                                                \
    F(id, std::string)                                                                                                 \
    F(changes, std::vector<GroupAddMemberEntry>)                                                                       \
    F(keyId, std::string)                                                                                              \
    F(data, Poco::Dynamic::Var)                                                                                        \
    F(commit, GroupTreeCommit)                                                                                         \
    F(expectedKeyVersion, int64_t)                                                                                     \
    F(expectedRosterVersion, int64_t)
JSON_STRUCT(GroupSetRolesModel, GROUP_SET_ROLES_MODEL_FIELDS);

// -- spaces: a key in versions, wrapped for several groups and users ---------------------------------------------------

// One of `groupId` and `userId` (with `pubKey`) is set.
#define SPACE_RECIPIENT_FIELDS(F)                                                                                      \
    F(groupId, std::optional<std::string>)                                                                             \
    F(userId, std::optional<std::string>)                                                                              \
    F(pubKey, std::optional<std::string>)                                                                              \
    F(role, std::string)
JSON_STRUCT(SpaceRecipient, SPACE_RECIPIENT_FIELDS);

#define SPACE_KEY_RECIPIENT_FIELDS(F)                                                                                  \
    F(groupId, std::optional<std::string>)                                                                             \
    F(groupKeyVersion, std::optional<int64_t>)                                                                         \
    F(userId, std::optional<std::string>)
JSON_STRUCT(SpaceKeyRecipient, SPACE_KEY_RECIPIENT_FIELDS);

// `data` and `signature` are the client's (base64); the Bridge checks only that every recipient has an entry.
#define SPACE_KEY_ENTRY_FIELDS(F)                                                                                      \
    F(keyVersion, int64_t)                                                                                             \
    F(recipient, SpaceKeyRecipient)                                                                                    \
    F(data, std::string)                                                                                               \
    F(signature, std::string)
JSON_STRUCT(SpaceKeyEntry, SPACE_KEY_ENTRY_FIELDS);

// `groupPubKey`: the group's identity key at `groupKeyVersion`, as the Space's statements pin it.
#define SPACE_GROUP_FIELDS(F)                                                                                          \
    F(groupId, std::string)                                                                                            \
    F(role, std::string)                                                                                               \
    F(groupKeyVersion, int64_t)                                                                                        \
    F(groupPubKey, std::optional<std::string>)
JSON_STRUCT(SpaceGroup, SPACE_GROUP_FIELDS);

#define SPACE_USER_FIELDS(F)                                                                                           \
    F(userId, std::string)                                                                                             \
    F(pubKey, std::string)                                                                                             \
    F(role, std::string)
JSON_STRUCT(SpaceUser, SPACE_USER_FIELDS);

// One signed statement of a Space's history. Hashes are hex, signatures base64. See keytree/SpaceLog.hpp.
#define SPACE_STATEMENT_FIELDS(F)                                                                                      \
    F(spaceId, std::string)                                                                                            \
    F(contextId, std::string)                                                                                          \
    F(seq, int64_t)                                                                                                    \
    F(prevDigest, std::string)                                                                                         \
    F(op, std::string)                                                                                                 \
    F(date, int64_t)                                                                                                   \
    F(keyVersion, int64_t)                                                                                             \
    F(keyCommit, std::string)                                                                                          \
    F(groups, std::vector<SpaceGroup>)                                                                                 \
    F(users, std::vector<SpaceUser>)                                                                                   \
    F(signer, std::string)                                                                                             \
    F(signerPubKey, std::string)                                                                                       \
    F(via, std::string)                                                                                                \
    F(signature, std::string)                                                                                          \
    F(viaSignature, std::string)
JSON_STRUCT(SpaceStatement, SPACE_STATEMENT_FIELDS);

#define SPACE_GET_STATEMENTS_MODEL_FIELDS(F)                                                                           \
    F(id, std::string)                                                                                                 \
    F(fromSeq, int64_t)                                                                                                \
    F(limit, int64_t)
JSON_STRUCT(SpaceGetStatementsModel, SPACE_GET_STATEMENTS_MODEL_FIELDS);

#define SPACE_GET_STATEMENTS_RESULT_FIELDS(F) F(statements, std::vector<SpaceStatement>)
JSON_STRUCT(SpaceGetStatementsResult, SPACE_GET_STATEMENTS_RESULT_FIELDS);

#define SPACE_INFO_FIELDS(F)                                                                                           \
    F(id, std::string)                                                                                                 \
    F(contextId, std::string)                                                                                          \
    F(creator, std::string)                                                                                            \
    F(createDate, int64_t)                                                                                             \
    F(lastModifier, std::string)                                                                                       \
    F(lastModificationDate, int64_t)                                                                                   \
    F(groups, std::vector<SpaceGroup>)                                                                                 \
    F(users, std::vector<SpaceUser>)                                                                                   \
    F(keyId, std::string)                                                                                              \
    F(keyVersion, int64_t)                                                                                             \
    F(keyIsStale, bool)                                                                                                \
    F(seq, int64_t)                                                                                                    \
    F(keys, std::vector<SpaceKeyEntry>)                                                                                \
    F(publicMeta, Poco::Dynamic::Var)                                                                                  \
    F(privateMeta, Poco::Dynamic::Var)                                                                                 \
    F(publicMetaVersion, int64_t)                                                                                      \
    F(privateMetaVersion, int64_t)
JSON_STRUCT(SpaceInfo, SPACE_INFO_FIELDS);

#define SPACE_CREATE_MODEL_FIELDS(F)                                                                                   \
    F(contextId, std::string)                                                                                          \
    F(resourceId, std::string)                                                                                         \
    F(recipients, std::vector<SpaceRecipient>)                                                                         \
    F(keyId, std::string)                                                                                              \
    F(keys, std::vector<SpaceKeyEntry>)                                                                                \
    F(statement, SpaceStatement)                                                                                       \
    F(publicMeta, Poco::Dynamic::Var)                                                                                  \
    F(privateMeta, Poco::Dynamic::Var)
JSON_STRUCT(SpaceCreateModel, SPACE_CREATE_MODEL_FIELDS);

#define SPACE_CREATE_RESULT_FIELDS(F) F(spaceId, std::string)
JSON_STRUCT(SpaceCreateResult, SPACE_CREATE_RESULT_FIELDS);

#define SPACE_ID_MODEL_FIELDS(F) F(id, std::string)
JSON_STRUCT(SpaceIdModel, SPACE_ID_MODEL_FIELDS);

#define SPACE_GET_RESULT_FIELDS(F) F(space, SpaceInfo)
JSON_STRUCT(SpaceGetResult, SPACE_GET_RESULT_FIELDS);

#define SPACE_LIST_MODEL_EXTRA_FIELDS(F)
JSON_STRUCT_EXT(SpaceListModel, core::server::ContainerListModel, SPACE_LIST_MODEL_EXTRA_FIELDS);

#define SPACE_LIST_RESULT_FIELDS(F)                                                                                    \
    F(spaces, std::vector<SpaceInfo>)                                                                                  \
    F(count, int64_t)
JSON_STRUCT(SpaceListResult, SPACE_LIST_RESULT_FIELDS);

#define SPACE_ADD_RECIPIENTS_MODEL_FIELDS(F)                                                                           \
    F(id, std::string)                                                                                                 \
    F(recipients, std::vector<SpaceRecipient>)                                                                         \
    F(keys, std::vector<SpaceKeyEntry>)                                                                                \
    F(statement, SpaceStatement)
JSON_STRUCT(SpaceAddRecipientsModel, SPACE_ADD_RECIPIENTS_MODEL_FIELDS);

// A rotation; with `groups` or `users`, a removal - which is a rotation those recipients are left out of.
#define SPACE_ROTATE_KEY_MODEL_FIELDS(F)                                                                               \
    F(id, std::string)                                                                                                 \
    F(keyId, std::string)                                                                                              \
    F(keys, std::vector<SpaceKeyEntry>)                                                                                \
    F(statement, SpaceStatement)                                                                                       \
    F(expectedKeyVersion, int64_t)                                                                                     \
    F(groups, std::optional<std::vector<std::string>>)                                                                 \
    F(users, std::optional<std::vector<std::string>>)
JSON_STRUCT(SpaceRotateKeyModel, SPACE_ROTATE_KEY_MODEL_FIELDS);

#define SPACE_ROTATE_KEY_RESULT_FIELDS(F) F(keyVersion, int64_t)
JSON_STRUCT(SpaceRotateKeyResult, SPACE_ROTATE_KEY_RESULT_FIELDS);

#define SPACE_UPDATE_META_MODEL_FIELDS(F)                                                                              \
    F(id, std::string)                                                                                                 \
    F(meta, Poco::Dynamic::Var)                                                                                        \
    F(version, int64_t)
JSON_STRUCT(SpaceUpdateMetaModel, SPACE_UPDATE_META_MODEL_FIELDS);

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
    F(expectedRosterVersion, int64_t)                                                                                  \
    F(commit, GroupTreeCommit)                                                                                         \
    F(abandonHistory, std::optional<bool>)
JSON_STRUCT(GroupRemoveMembersModel, GROUP_REMOVE_MEMBERS_MODEL_FIELDS);

// Advances the epoch without removing anybody: a fresh grant key on the one grant edge (to the unchanged root, or
// to the sole member of a one-leaf tree), the rungs down to the old epochs, and the roster republished under it.
#define GROUP_GENERATE_NEW_KEY_MODEL_FIELDS(F)                                                                         \
    F(id, std::string)                                                                                                 \
    F(groupPubKey, std::string)                                                                                        \
    F(data, Poco::Dynamic::Var)                                                                                        \
    F(keyId, std::string)                                                                                              \
    F(grantEdge, GroupTreeEdge)                                                                                        \
    F(commit, GroupTreeCommit)                                                                                         \
    F(rungs, std::vector<GroupArchiveRung>)                                                                            \
    F(groupKeys, std::optional<core::server::GroupKeyEntrySet>)                                                        \
    F(expectedKeyVersion, int64_t)                                                                                     \
    F(expectedRosterVersion, int64_t)
JSON_STRUCT(GroupGenerateNewKeyModel, GROUP_GENERATE_NEW_KEY_MODEL_FIELDS);

// Refills the caller's own keyed path: no epoch change, no roster change, nothing for anybody else to notice.
#define GROUP_SELF_UPDATE_MODEL_FIELDS(F)                                                                              \
    F(id, std::string)                                                                                                 \
    F(expectedKeyVersion, int64_t)                                                                                     \
    F(transition, GroupTreeSelfUpdateTransition)                                                                       \
    F(commit, GroupTreeCommit)
JSON_STRUCT(GroupSelfUpdateModel, GROUP_SELF_UPDATE_MODEL_FIELDS);

// The statements with `fromSeq < seq <= toSeq` (default: the latest), ascending, at most 256 per call.
#define GROUP_GET_TREE_COMMITS_MODEL_FIELDS(F)                                                                         \
    F(groupId, std::string)                                                                                            \
    F(fromSeq, int64_t)                                                                                                \
    F(toSeq, std::optional<int64_t>)
JSON_STRUCT(GroupGetTreeCommitsModel, GROUP_GET_TREE_COMMITS_MODEL_FIELDS);

// From seq 0, the roster seq 1 seats: unsigned, bound by seq 1's `rosterHash`.
#define GROUP_GET_TREE_COMMITS_RESULT_FIELDS(F)                                                                        \
    F(commits, std::vector<GroupTreeCommit>)                                                                           \
    F(genesisUsers, std::optional<std::vector<std::string>>)                                                           \
    F(genesisManagers, std::optional<std::vector<std::string>>)
JSON_STRUCT(GroupGetTreeCommitsResult, GROUP_GET_TREE_COMMITS_RESULT_FIELDS);

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

// One more rung for a span an epoch already published; the bridge records the caller as its author.
#define GROUP_REPAIR_RUNG_MODEL_FIELDS(F)                                                                              \
    F(id, std::string)                                                                                                 \
    F(rung, GroupArchiveRung)
JSON_STRUCT(GroupRepairRungModel, GROUP_REPAIR_RUNG_MODEL_FIELDS);

// One span of the Epoch Ladder: the rungs sealing epoch `target`'s grant key to epoch `at`'s.
#define GROUP_ARCHIVE_SPAN_FIELDS(F)                                                                                   \
    F(at, int64_t)                                                                                                     \
    F(target, int64_t)
JSON_STRUCT(GroupArchiveSpan, GROUP_ARCHIVE_SPAN_FIELDS);

// A closed window `[fromKeyVersion, toKeyVersion]`, or instead only the rungs of `spans` (at most 128): the one path a
// descent walks, O(log distance) spans rather than every rung in between.
#define GROUP_GET_KEY_ARCHIVE_MODEL_FIELDS(F)                                                                          \
    F(id, std::string)                                                                                                 \
    F(fromKeyVersion, std::optional<int64_t>)                                                                          \
    F(toKeyVersion, std::optional<int64_t>)                                                                            \
    F(spans, std::optional<std::vector<GroupArchiveSpan>>)
JSON_STRUCT(GroupGetKeyArchiveModel, GROUP_GET_KEY_ARCHIVE_MODEL_FIELDS);

// Past epochs by what an envelope names (at most 32 of each): `groupGet` serves only the current epoch and the ones
// the metadata heads sit at.
#define GROUP_GET_EPOCH_KEYS_MODEL_FIELDS(F)                                                                           \
    F(id, std::string)                                                                                                 \
    F(keyIds, std::optional<std::vector<std::string>>)                                                                 \
    F(groupPubKeys, std::optional<std::vector<std::string>>)
JSON_STRUCT(GroupGetEpochKeysModel, GROUP_GET_EPOCH_KEYS_MODEL_FIELDS);

// The epochs found, in `groupGet`'s shapes; `keyHistory` lists the current epoch too when it was asked for.
#define GROUP_GET_EPOCH_KEYS_RESULT_FIELDS(F)                                                                          \
    F(keyVersion, int64_t)                                                                                             \
    F(groupKeys, std::vector<core::server::GroupKeysEntry>)                                                            \
    F(keyHistory, std::vector<GroupKeyHistoryEntry>)
JSON_STRUCT(GroupGetEpochKeysResult, GROUP_GET_EPOCH_KEYS_RESULT_FIELDS);

#define GROUP_GET_KEY_ARCHIVE_RESULT_FIELDS(F)                                                                         \
    F(keyVersion, int64_t)                                                                                             \
    F(eraFloor, int64_t)                                                                                               \
    F(archivePrunedBelow, std::optional<int64_t>)                                                                      \
    F(keyHistory, std::vector<GroupKeyHistoryEntry>)                                                                   \
    F(rungs, std::vector<GroupArchiveRung>)
JSON_STRUCT(GroupGetKeyArchiveResult, GROUP_GET_KEY_ARCHIVE_RESULT_FIELDS);

// `data` is a base64 group envelope carrying its own keyId, so no `keyId` field and no key list: that keeps
// the request a fixed size, where `contextSendCustomEvent` grows a wrapped key per recipient.
#define GROUP_SEND_CUSTOM_EVENT_MODEL_FIELDS(F)                                                                        \
    F(groupId, std::string)                                                                                            \
    F(channel, std::string)                                                                                            \
    F(data, std::string)                                                                                               \
    F(users, std::optional<std::vector<std::string>>)
JSON_STRUCT(GroupSendCustomEventModel, GROUP_SEND_CUSTOM_EVENT_MODEL_FIELDS);

#define GROUP_CUSTOM_EVENT_DATA_FIELDS(F)                                                                              \
    F(id, std::string)                                                                                                 \
    F(eventData, std::string)                                                                                          \
    F(author, core::server::UserIdentity)
JSON_STRUCT(GroupCustomEventData, GROUP_CUSTOM_EVENT_DATA_FIELDS);

} // namespace server
} // namespace group
} // namespace endpoint
} // namespace privmx

#endif // _PRIVMXLIB_ENDPOINT_GROUP_SERVERTYPES_HPP_
