#ifndef _PRIVMXLIB_ENDPOINT_GROUP_SERVER_API_HPP_
#define _PRIVMXLIB_ENDPOINT_GROUP_SERVER_API_HPP_

#include "privmx/endpoint/group/ServerTypes.hpp"
#include <Poco/Dynamic/Var.h>
#include <map>
#include <mutex>
#include <privmx/endpoint/core/ServerTypes.hpp>
#include <privmx/privfs/gateway/RpcGateway.hpp>
#include <string>

namespace privmx {
namespace endpoint {
namespace group {

class ServerApi {
public:
    ServerApi(privmx::privfs::RpcGateway::Ptr gateway);

    server::GroupCreateResult groupCreate(server::GroupCreateModel model);
    // One RPC per metadata plane, plus the policy on its own — each with its own ACL entry on the bridge.
    void groupUpdatePublicMeta(server::GroupUpdatePublicMetaModel model);
    void groupUpdatePrivateMeta(server::GroupUpdatePrivateMetaModel model);
    void groupUpdatePolicy(server::GroupUpdatePolicyModel model);
    void groupDelete(server::GroupDeleteModel model);
    server::GroupGetResult groupGet(server::GroupGetModel model);
    server::GroupListResult groupList(server::GroupListModel model);
    // Reads `groupIds` in one request per 128 (`groupGetMany`) and keeps each group served: the next plain `groupGet`
    // of that id returns it instead of asking again, once. An id the bridge answered with an error keeps nothing, so
    // its `groupGet` asks, and throws what the bridge says. What is kept is what `groupGet` would have answered, and
    // goes through the same verification.
    void prefetchGroups(const std::vector<std::string>& groupIds);
    void dropPrefetched();
    // The identity key with what vouches for it, for a caller who may hold no seat in the group.
    server::GroupGetPublicKeyResult groupGetPublicKey(server::GroupGetPublicKeyModel model);
    void groupSetVisibility(server::GroupSetVisibilityModel model);

    // ── Tree-backed membership (documents/nested_groups/09-hidden-key-tree.md) ──
    void groupAddMembers(server::GroupAddMembersModel model);
    void groupRemoveMembers(server::GroupRemoveMembersModel model);
    // A removal's request under the `reseat` op: its `userIds` keep their seats.
    void groupReseat(server::GroupRemoveMembersModel model);
    void groupSetRoles(server::GroupSetRolesModel model);

    server::SpaceCreateResult spaceCreate(server::SpaceCreateModel model);
    server::SpaceGetResult spaceGet(server::SpaceIdModel model);
    server::SpaceGetKeyArchiveResult spaceGetKeyArchive(server::SpaceGetKeyArchiveModel model);
    server::SpaceListResult spaceList(server::SpaceListModel model);
    void spaceDelete(server::SpaceIdModel model);
    server::SpaceGetStatementsResult spaceGetStatements(server::SpaceGetStatementsModel model);
    void spaceAddRecipients(server::SpaceAddRecipientsModel model);
    // With `groups` or `users` set in the model this is `spaceRemoveRecipients`.
    server::SpaceRotateKeyResult spaceRotateKey(server::SpaceRotateKeyModel model);
    void spaceUpdatePublicMeta(server::SpaceUpdateMetaModel model);
    void spaceUpdatePrivateMeta(server::SpaceUpdateMetaModel model);
    void groupSelfUpdate(server::GroupSelfUpdateModel model);
    void groupGenerateNewKey(server::GroupGenerateNewKeyModel model);
    server::GroupGetTreeCommitsResult groupGetTreeCommits(server::GroupGetTreeCommitsModel model);
    // The Epoch Ladder, fetched only when a client is actually reaching for an older epoch.
    server::GroupGetKeyArchiveResult groupGetKeyArchive(server::GroupGetKeyArchiveModel model);
    // Past epochs' key entries and grant keys, looked up by keyId or grant key.
    server::GroupGetEpochKeysResult groupGetEpochKeys(server::GroupGetEpochKeysModel model);
    // Appends a repair rung: any seated member holding both keys of the span.
    void groupRepairRung(server::GroupRepairRungModel model);

    void groupSendCustomEvent(server::GroupSendCustomEventModel model);

private:
    template<typename T>
    T request(const std::string& method, Poco::JSON::Object::Ptr params);
    Poco::Dynamic::Var request(const std::string& method, Poco::JSON::Object::Ptr params);

    privfs::RpcGateway::Ptr _gateway;
    std::mutex _prefetchedMutex;
    std::map<std::string, server::GroupInfo> _prefetched;
};

} // namespace group
} // namespace endpoint
} // namespace privmx

#endif // _PRIVMXLIB_ENDPOINT_GROUP_SERVER_API_HPP_
