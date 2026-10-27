/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_ENDPOINT_GROUP_GROUPOPERATIONS_HPP_
#define _PRIVMXLIB_ENDPOINT_GROUP_GROUPOPERATIONS_HPP_

#include <functional>
#include <map>
#include <memory>
#include <optional>
#include <set>
#include <string>
#include <utility>
#include <vector>

#include <privmx/crypto/ecc/PrivateKey.hpp>
#include <privmx/endpoint/core/Connection.hpp>
#include <privmx/endpoint/core/KeyProvider.hpp>

#include "privmx/endpoint/group/CommitEngine.hpp"
#include "privmx/endpoint/group/DeferredWork.hpp"
#include "privmx/endpoint/group/GroupApiHooks.hpp"
#include "privmx/endpoint/group/GroupKeys.hpp"
#include "privmx/endpoint/group/GroupMetadata.hpp"
#include "privmx/endpoint/group/GroupSession.hpp"
#include "privmx/endpoint/group/ServerApi.hpp"
#include "privmx/endpoint/group/VerifiedGroup.hpp"
#include "privmx/endpoint/group/encryptors/group/GroupDataSchemaMapper.hpp"
#include "privmx/endpoint/group/keytree/TreeKeyCache.hpp"
#include "privmx/endpoint/group/keytree/TreeKeys.hpp"
#include "privmx/endpoint/group/keytree/TreeVerifier.hpp"

namespace privmx {
namespace endpoint {
namespace group {

// The tree operations of one GroupApiImpl. Each app operation is one attempt (`commitWithRetry` re-runs it from a fresh
// read): read and settle (CommitEngine), plan on the verified read (in the order its checks refuse; an unseated read is
// refused where the climb would be), then chain, sign and submit. References into the GroupApiImpl, for its lifetime;
// the closures an operation hands the engine capture copies and the units they use.
struct GroupOperations {
    const GroupDeps& deps;
    GroupDataSchemaMapper& mapper;
    const std::shared_ptr<core::KeyProvider>& keyProvider;
    // Resolves the group's grant keys for the key provider (the roster and metadata keys).
    const core::KeyProvider::GroupPrivKeyResolver& groupPrivKeyResolver;
    const GroupKeys& keys;
    DeferredWork& deferred;
    const GroupMetadata& metadata;
    const CommitEngine& engine;

    // The whole create: the group has no chain to settle or retry against yet. Returns the new group's id.
    std::string create(
        const std::string& contextId,
        const std::vector<core::UserWithPubKey>& users,
        const std::vector<core::UserWithPubKey>& managers,
        const core::Buffer& publicMeta,
        const core::Buffer& privateMeta,
        const std::optional<core::ContainerPolicy>& policies
    ) const;

    void add(const std::string& groupId, const std::vector<GroupMemberToAdd>& newMembers) const;
    // Returns whether the removal abandoned history (the caller held no current grant key); nullopt when an
    // earlier attempt of the same removal turned out to have landed (`settle` ran its metadata refresh then).
    // `prior` is what the attempt read, for `carryMetadataForward`.
    std::optional<bool> remove(const std::string& groupId, const std::vector<std::string>& userIds, PriorRole& prior)
        const;
    // `prior` is what the attempt read, for `carryMetadataForward`. False when an earlier attempt of a rotation turned
    // out to have landed (`settle` ran its metadata refresh then).
    bool rotate(const std::string& groupId, PriorRole& prior) const;
    // A self-update; with `previousKey`, the leaf renewal: no need gates, a climb with the previous key over a
    // call-local cache, signed with the session's (new) key. False when there was nothing to commit (no need, the
    // leaf already opens with the session's key, or deferred behind another commit).
    bool selfUpdate(
        const std::string& groupId,
        const privmx::crypto::PrivateKey* previousKey,
        const std::string& op,
        bool mayCompleteOther
    ) const;
    // `carry` is set when the change narrows `update` under a plane's author.
    void updatePolicy(
        const std::string& groupId,
        const core::ContainerPolicy& policies,
        std::optional<PendingCarry>& carry
    ) const;

    // `group` comes from a verified read at plan scope. `removing` (a removal of these users): a climb that fails on
    // the served edges (not on membership) is logged and the state returned anyway — a removal plans from public state
    // alone; but a leaf that does not open with the session's key and climbs with a previous identity key this
    // client was given (`climbsWithPreviousIdentity`) is refused, pointing at renewLeaf, unless history stays
    // reachable: renewLeaf fixes exactly that case, and nothing else.
    // `climbKey`: climb with it instead of the session's key, and schedule no self-update off the climb.
    keytree::TreeGroupState climbForPlanning(
        const VerifiedGroup& group,
        const std::shared_ptr<keytree::TreeKeyCache>& cache,
        const std::vector<std::string>* removing = nullptr,
        const privmx::crypto::PrivateKey* climbKey = nullptr
    ) const;
    // Whether one of the previous identity keys (ConnectionImpl::previousIdentities) climbs `state` to its grant
    // key. Climbs on a scratch cache, so nothing derived from a previous key reaches a reader.
    bool climbsWithPreviousIdentity(const keytree::TreeGroupState& state, const std::string& memberId) const;

    // The new epoch's rungs, each checked to open with `newGrantKey` to the key the chain (never the cache) names for
    // its target before anything is submitted. On failure the offending target is forgotten, so the next attempt
    // re-gathers it by a verified descent, and GroupDataIntegrityException is thrown.
    std::vector<keytree::ArchiveRung> buildRotationRungs(
        const VerifiedGroup& group,
        std::uint32_t newEpoch,
        const privmx::crypto::PrivateKey& newGrantKey,
        const std::optional<privmx::crypto::PrivateKey>& previousEpochKey,
        const std::string& author,
        keytree::TreeKeyCache& cache
    ) const;

    // The `UnresolvedCommit::landed` of a commit that opened `statement.keyVersion`: pins it before anything reads the
    // group again (the state it replaced is refused from then on) and keeps the new grant key, the epoch's published
    // one. `roster` is the one the statement signed. Captures copies and the units it uses.
    std::function<void()> landedEpoch(
        const std::string& contextId,
        const keytree::CommitStatement& statement,
        const RosterAfterChange& roster,
        const keytree::GroupRules& rules,
        const privmx::crypto::PrivateKey& grantKey
    ) const;

    // The long-term keys a commit wraps to: the caller's own from its key, newcomers' from the arguments (left out
    // here), everybody else's from the Context user list.
    std::map<std::string, std::string> commitRecipientKeys(
        const server::GroupInfo& group,
        const std::vector<std::string>& recipients,
        const std::string& ownUserId,
        const std::set<std::string>& newcomers = {}
    ) const;
};

} // namespace group
} // namespace endpoint
} // namespace privmx

#endif // _PRIVMXLIB_ENDPOINT_GROUP_GROUPOPERATIONS_HPP_
