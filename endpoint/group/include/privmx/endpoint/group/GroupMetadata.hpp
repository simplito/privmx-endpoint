/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_ENDPOINT_GROUP_GROUPMETADATA_HPP_
#define _PRIVMXLIB_ENDPOINT_GROUP_GROUPMETADATA_HPP_

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include <Poco/Dynamic/Var.h>
#include <privmx/endpoint/core/Connection.hpp>
#include <privmx/endpoint/core/CoreTypes.hpp>
#include <privmx/endpoint/core/KeyProvider.hpp>

#include "privmx/endpoint/group/GroupApiHooks.hpp"
#include "privmx/endpoint/group/GroupKeys.hpp"
#include "privmx/endpoint/group/GroupSession.hpp"
#include "privmx/endpoint/group/GroupTypes.hpp"
#include "privmx/endpoint/group/ServerApi.hpp"
#include "privmx/endpoint/group/VerifiedGroup.hpp"
#include "privmx/endpoint/group/encryptors/group/GroupDataSchemaMapper.hpp"

namespace privmx {
namespace endpoint {
namespace group {

// Which planes a carry-forward moves: after a removal or rotation, the planes behind the new epoch (or, with
// history abandoned, starts them over empty); after a narrowing policy commit, the planes whose author lost
// `update` (`losers`).
enum class CarryScope { NewEpoch, Policy };

// What a commit opening a new epoch publishes beside the tree, shared by removal and rotation: the roster under a
// fresh metadata key (a key never used before once history is abandoned), and that key wrapped once to the new
// grant key.
struct NewEpochRoster {
    std::string keyId;
    Poco::Dynamic::Var data;
    core::server::GroupKeyEntrySet groupKeys;
};

// `rosterTag` has to be computed over exactly the fields the block declares. One builder for all three
// roster writers, so the tag inputs and the declared values cannot drift apart.
dynamic::MembershipBlock buildMembershipBlock(
    const core::EncKey& key,
    const std::string& groupPubKey,
    int64_t keyVersion,
    int64_t rosterVersion,
    const std::vector<core::UserWithPubKey>& users,
    const std::vector<core::UserWithPubKey>& managers
);

// The attested roster, as bare ids — the update preparation diffs names, it does not wrap to them.
RosterAfterChange rosterFromUserIds(const std::vector<std::string>& users, const std::vector<std::string>& managers);

// The read's rules, roster and planes (a verified read's, but in a plan's prologue, see `rulesOf`).
PriorRole priorOf(const server::GroupInfo& group);

// The metadata writes of one GroupApiImpl, the roster a new epoch publishes, and the carry-forward of the planes
// after a commit. References into the GroupApiImpl, for its lifetime; no state but the sessions' pending carries.
struct GroupMetadata {
    const GroupDeps& deps;
    GroupDataSchemaMapper& mapper;
    const std::shared_ptr<core::KeyProvider>& keyProvider;
    const GroupKeys& keys;

    // The entire shared prologue of both metadata writes; neither plane reads the other's envelope.
    // Kept in one place so the epoch guard cannot drift between the two callers.
    // `currentGroup` comes from `readForKeys`.
    MetaWriteContext prepareMetaWrite(const VerifiedGroup& currentGroup) const;
    // One metadata plane (public or private) at `version + 1`, under the current epoch's key.
    void writeMeta(const VerifiedGroup& currentGroup, bool publicPlane, const core::Buffer& meta, int64_t version) const;

    // Called after a removal, rotation or narrowing commits, never as part of it: best-effort, re-signing under the
    // committer's name only an entry identical to the one it read before its own commit whose author held
    // `update` under that read's rules and roster (`prior`). Returns whether nothing is left to carry.
    bool carryMetadataForward(
        const std::string& groupId,
        CarryScope scope,
        bool historyAbandoned,
        const std::vector<std::string>& losers,
        const PriorRole& prior
    ) const;
    // Runs a narrowing's carry-forward; one that does not complete is kept for `retryPendingCarry`.
    void runPolicyCarry(const std::string& groupId, const PendingCarry& carry) const;
    void retryPendingCarry(const std::string& groupId) const;

    NewEpochRoster sealRosterForNewEpoch(
        const server::GroupInfo& currentGroup,
        const RosterAfterChange& roster,
        const std::string& newGroupPubKeyStr,
        int64_t newEpoch,
        int64_t newRosterVersion,
        bool abandonHistory
    ) const;
};

} // namespace group
} // namespace endpoint
} // namespace privmx

#endif // _PRIVMXLIB_ENDPOINT_GROUP_GROUPMETADATA_HPP_
