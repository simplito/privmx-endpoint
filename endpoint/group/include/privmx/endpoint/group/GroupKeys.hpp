/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_ENDPOINT_GROUP_GROUPKEYS_HPP_
#define _PRIVMXLIB_ENDPOINT_GROUP_GROUPKEYS_HPP_

#include <cstddef>
#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include <privmx/crypto/ecc/PrivateKey.hpp>
#include <privmx/endpoint/core/Connection.hpp>
#include <privmx/endpoint/core/CoreTypes.hpp>
#include <privmx/endpoint/core/KeyProvider.hpp>

#include "privmx/endpoint/group/GroupApiHooks.hpp"
#include "privmx/endpoint/group/GroupSession.hpp"
#include "privmx/endpoint/group/ServerApi.hpp"
#include "privmx/endpoint/group/VerifiedGroup.hpp"
#include "privmx/endpoint/group/keytree/GroupKeyResolver.hpp"
#include "privmx/endpoint/group/keytree/TreeKeyCache.hpp"
#include "privmx/endpoint/group/keytree/TreeVerifier.hpp"

namespace privmx {
namespace endpoint {
namespace group {

// " (wrapped by <who>)", or nothing without a culprit.
std::string blameSuffix(const std::optional<std::string>& who, const std::string& as = "wrapped by");

std::string describeResolveFailure(const keytree::ResolveResult& resolved);

// The floor nothing below may be reached or repaired: the higher of the era floor and the prune watermark. Never
// above `currentEpoch`, the verified epoch: a rotation would then build no rung at all, not even the unit rung, and
// cut every earlier epoch off.
std::uint32_t ladderFloorOf(
    std::int64_t eraFloor,
    const std::optional<std::int64_t>& prunedBelow,
    std::int64_t currentEpoch
);

// The newest epoch an archive answer may speak of: the verified group's, or a later one the archive was read at (a
// rotation since the group was read). A floor above both is a lie; one above the group's only is a race.
std::int64_t newestEpoch(const server::GroupInfo& group, const server::GroupGetKeyArchiveResult& archive);

// Narrowing the archive first keeps the key provider to one grant-key resolution per envelope opened,
// rather than one per key the group has ever held. Only the group's own routes: its key is wrapped to itself.
std::vector<core::server::GroupKeysEntry> filterToKeyId(
    const std::vector<core::server::GroupKeysEntry>& all,
    const std::string& groupId,
    const std::string& keyId
);

// Whether `wrappedBy` opened the epoch one of `routes` labels the key with (the group's creator or a remover,
// the only members who wrap an epoch's content key). Anybody in the context can wrap a key of their own to an
// epoch's public grant key; the opener, after `epochOpeners`, is a member's signed word.
bool wrappedByEpochOpener(
    const std::vector<core::server::GroupKeysEntry>& routes,
    const std::string& wrappedBy,
    const std::map<std::uint64_t, keytree::CommitStatement>& openers
);

class DeferredWork;

// A climb with another key over another cache (leaf renewal); nothing then reaches the epoch keys, the group's
// shared cache or the due-work records.
struct ClimbWith {
    std::shared_ptr<keytree::TreeKeyCache> cache;
    const privmx::crypto::PrivateKey* key;
};

// Resolution of the group keys of one GroupApiImpl: epoch grant keys by climb and ladder, envelope keys by id. The
// deferred work found on the way is recorded in the GroupApiImpl's, for its lifetime.
struct GroupKeys {
    const GroupDeps& deps;
    DeferredWork& deferred;

    // Spans per `groupGetKeyArchive` call the bridge serves.
    static constexpr std::size_t MAX_ARCHIVE_SPANS = 128;
    // Rungs per page of a windowed `groupGetKeyArchive`.
    static constexpr std::size_t ARCHIVE_RUNGS_PER_PAGE = 256;

    // The grant key of `epoch` (0: the current one). `seatedRead`: a read of this group the caller has already
    // verified; its own current epoch then resolves off it rather than off a second read that would verify the same
    // thing again. `with`: see ClimbWith.
    privmx::crypto::PrivateKey resolveGroupPrivKey(
        const std::string& groupId,
        int64_t epoch,
        const VerifiedGroup* seatedRead,
        const ClimbWith* with
    ) const;

    // The resolver the key provider is handed: `resolveGroupPrivKey`, with "no key" for anything refused but a
    // rollback. `seatedRead` and `with` must outlive it.
    core::KeyProvider::GroupPrivKeyResolver resolverOver(
        const VerifiedGroup* seatedRead,
        const ClimbWith* with = nullptr
    ) const;

    // The ladder between the two epochs, as the group's statements vouch for it (GroupKeyResolver::authenticated).
    server::GroupGetKeyArchiveResult fetchKeyArchive(
        const VerifiedGroup& group,
        int64_t targetEpoch,
        int64_t currentEpoch
    ) const;
    // Only the rungs of `spans`, authenticated the same way.
    server::GroupGetKeyArchiveResult fetchKeyArchive(
        const VerifiedGroup& group,
        const std::vector<keytree::RungSpan>& spans
    ) const;
    server::GroupGetKeyArchiveResult fetchKeyArchive(
        const VerifiedGroup& group,
        const server::GroupGetKeyArchiveModel& params
    ) const;

    // `resolver.resolve` for an epoch below the current one, fetching as little of the ladder as it can: first the
    // canonical descent path (LadderMath::canonicalDescent), then, if a rung on it fails, the ways round the epoch it
    // stopped at (LadderMath::detourSpans), and only then the closed window `[epoch, current]` as before. Every
    // attempt is verified exactly as one over the whole window; an era boundary or a prune ends it at once.
    keytree::ResolveResult resolveDescending(
        keytree::GroupKeyResolver& resolver,
        const VerifiedGroup& group,
        int64_t epoch,
        const privmx::crypto::PrivateKey& ownKey
    ) const;

    // Reaches back through the whole archive, however old the key is. A key past the cached head comes from
    // `groupGetEpochKeys` by its id, not from a re-read of the group (`groupGet` serves only the current epochs).
    // `moduleKeys`: the group's module keys, from the cache or (`fresh`) re-read; `resolver` opens their routes.
    core::DecryptedEncKeyV2 encKeyById(
        const std::string& groupId,
        const std::string& keyId,
        const std::function<core::ModuleKeys(bool fresh)>& moduleKeys,
        core::KeyProvider& keyProvider,
        const core::KeyProvider::GroupPrivKeyResolver& resolver
    ) const;

    // The sender only ever held a public key, so its epoch is recovered from the group's published history
    // (`groupGetEpochKeys` by that key) rather than carried on the wire.
    privmx::crypto::PrivateKey grantKeyForPubKey(
        const std::string& groupId,
        const std::string& groupPubKeyBase58
    ) const;
};

} // namespace group
} // namespace endpoint
} // namespace privmx

#endif // _PRIVMXLIB_ENDPOINT_GROUP_GROUPKEYS_HPP_
