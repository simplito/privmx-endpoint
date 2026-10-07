/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include "privmx/endpoint/group/keytree/GroupKeyResolver.hpp"

#include <algorithm>

#include <privmx/crypto/ecc/PublicKeyCache.hpp>

#include "privmx/endpoint/group/keytree/TreeMath.hpp"
#include "privmx/endpoint/group/keytree/TreeWire.hpp"

using namespace privmx::endpoint::group::keytree;

GroupKeyResolver::GroupKeyResolver(TreeKeyCache& cache) : _cache(cache) {}

bool GroupKeyResolver::hasTree(const server::GroupInfo& group) {
    return group.numLeaves.has_value() &&
        group.numLeaves.value() > 0 &&
        group.treeNodes.has_value() &&
        group.treeEdges.has_value() &&
        group.leafAssignment.has_value();
}

bool GroupKeyResolver::hasSupportedTree(const server::GroupInfo& group) {
    return group.treeVersion.value_or(0) == static_cast<std::int64_t>(TreeMath::TREE_VERSION);
}

TreeGroupState GroupKeyResolver::toTreeState(const server::GroupInfo& group) {
    return TreeWire::toRuntime(
        TreeWire::fromGroupInfo(group), static_cast<std::uint32_t>(group.keyVersion),
        privmx::crypto::PublicKeyCache::getInstance()->fromBase58DER(group.groupPubKey)
    );
}

namespace {

// Drops a rung that does not point downwards. The bridge enforces this too, but taking its word for it would trust
// the one party the threat model assumes may be hostile — an upward rung hands a removed member a later key.
std::optional<ArchiveRung> convertRung(const privmx::endpoint::group::server::GroupArchiveRung& rung) {
    if (rung.targetKeyVersion >= rung.atKeyVersion) {
        return std::nullopt;
    }
    ArchiveRung converted;
    converted.span = RungSpan{
        static_cast<std::uint32_t>(rung.atKeyVersion),
        static_cast<std::uint32_t>(rung.targetKeyVersion),
    };
    const std::string kind = rung.recipientKind.value_or("epoch");
    if (kind == "user") {
        converted.recipientKind = RungRecipientKind::User;
    } else if (kind == "group") {
        converted.recipientKind = RungRecipientKind::Group;
    } else {
        converted.recipientKind = RungRecipientKind::Epoch;
    }
    converted.recipientId = rung.recipient.value_or("");
    converted.blob = rung.data;
    converted.author = rung.author.value_or("");
    return converted;
}

} // namespace

std::vector<ArchiveRung> GroupKeyResolver::toDownwardRungs(const server::GroupGetKeyArchiveResult& archive) {
    std::vector<ArchiveRung> rungs;
    for (const server::GroupArchiveRung& rung : archive.rungs) {
        const auto converted = convertRung(rung);
        if (converted.has_value()) {
            rungs.push_back(converted.value());
        }
    }
    return rungs;
}

std::vector<EpochRegistryEntry> GroupKeyResolver::registryFromArchive(
    const server::GroupInfo& group,
    const server::GroupGetKeyArchiveResult& archive
) {
    std::vector<EpochRegistryEntry> registry;
    for (const server::GroupKeyHistoryEntry& entry : archive.keyHistory) {
        registry.push_back(
            EpochRegistryEntry{
                static_cast<std::uint32_t>(entry.keyVersion),
                privmx::crypto::PublicKeyCache::getInstance()->fromBase58DER(entry.groupPubKey),
            }
        );
    }
    registry.push_back(
        EpochRegistryEntry{
            static_cast<std::uint32_t>(group.keyVersion),
            privmx::crypto::PublicKeyCache::getInstance()->fromBase58DER(group.groupPubKey),
        }
    );
    return registry;
}

std::vector<EpochRegistryEntry> GroupKeyResolver::registryFromGroupHistory(const server::GroupInfo& group) {
    std::vector<EpochRegistryEntry> registry;
    // `keyHistory` holds the PAST epochs only; the current one lives in `groupPubKey`. Missing that distinction
    // would leave the newest epoch unverifiable, and an unverifiable key is one this client refuses to accept.
    if (group.keyHistory.has_value()) {
        for (const server::GroupKeyHistoryEntry& entry : group.keyHistory.value()) {
            registry.push_back(
                EpochRegistryEntry{
                    static_cast<std::uint32_t>(entry.keyVersion),
                    privmx::crypto::PublicKeyCache::getInstance()->fromBase58DER(entry.groupPubKey),
                }
            );
        }
    }
    registry.push_back(
        EpochRegistryEntry{
            static_cast<std::uint32_t>(group.keyVersion),
            privmx::crypto::PublicKeyCache::getInstance()->fromBase58DER(group.groupPubKey),
        }
    );
    return registry;
}

std::optional<std::string> GroupKeyResolver::ownUserId(const server::GroupInfo& group) {
    if (!group.ownLeafPosition.has_value() || !group.leafAssignment.has_value()) {
        return std::nullopt;
    }
    const std::int64_t position = group.ownLeafPosition.value();
    if (position < 0 || static_cast<std::size_t>(position) >= group.leafAssignment.value().size()) {
        return std::nullopt;
    }
    const std::string& userId = group.leafAssignment.value()[static_cast<std::size_t>(position)];
    if (userId.empty()) {
        return std::nullopt;
    }
    return userId;
}

bool GroupKeyResolver::ownPathHasBlanks(const server::GroupInfo& group) {
    if (!hasTree(group) || !ownUserId(group).has_value()) {
        return false;
    }
    const auto& records = group.treeNodes.value();
    for (const std::uint32_t node : TreeMath::keyedPath(
             static_cast<std::uint32_t>(group.ownLeafPosition.value()),
             static_cast<std::uint32_t>(group.numLeaves.value())
         )) {
        const auto record = std::find_if(records.begin(), records.end(), [&](const server::GroupTreeNode& served) {
            return served.nodeIndex == static_cast<std::int64_t>(node);
        });
        if (record == records.end() || record->publicKey.value_or("").empty()) {
            return true;
        }
    }
    return false;
}

// `rungs`, `registry`, `eraFloor` and `prunedBelow` are passed in rather than read off the group, which no longer
// carries them: the bridge serves the ladder separately, and the walk stays ignorant of where they came from.
ResolveResult GroupKeyResolver::resolveWith(
    const server::GroupInfo& group,
    std::int64_t epoch,
    const privmx::crypto::PrivateKey& ownUserKey,
    const std::vector<ArchiveRung>& rungs,
    const std::vector<EpochRegistryEntry>& registry,
    std::uint32_t eraFloor,
    const std::optional<std::uint32_t>& prunedBelow
) {
    ResolveResult result;
    if (!hasTree(group)) {
        result.failure = ResolveFailure::NoTree;
        return result;
    }
    if (!hasSupportedTree(group)) {
        // Read as the current layout, an older tree would climb fine and mean something else: its copath keys were
        // minted by whoever created or last re-keyed them, which is exactly what this layout exists to rule out.
        result.failure = ResolveFailure::UnsupportedTreeVersion;
        return result;
    }
    const auto identity = ownUserId(group);
    if (!identity.has_value()) {
        result.failure = ResolveFailure::ClimbFailed;
        result.climb = ClimbFailure::NotAMember;
        return result;
    }

    const TreeGroupState state = toTreeState(group);
    const std::uint32_t currentEpoch = state.epoch;
    const std::uint32_t wanted = epoch <= 0 ? currentEpoch : static_cast<std::uint32_t>(epoch);

    // Step 1: climb to the current epoch's grant key. Every recovered node key is verified against the public
    // key the server published for that node, so a corrupted edge fails loudly instead of yielding a wrong key.
    TreeKeys tree(_cache);
    const ClimbResult climb = tree.climbToGrantKey(state, identity.value(), ownUserKey);
    if (climb.failure != ClimbFailure::None || !climb.grantKey.has_value()) {
        result.failure = ResolveFailure::ClimbFailed;
        result.climb = climb.failure;
        return result;
    }
    if (wanted >= currentEpoch) {
        result.key = climb.grantKey;
        return result;
    }

    // Step 2: descend the ladder. Verification against the epoch registry happens at every hop.
    LadderKeys ladder(_cache);
    const DescentResult descent = ladder.descend(currentEpoch, wanted, rungs, registry, eraFloor, prunedBelow);
    if (descent.failure != DescentFailure::None || !descent.key.has_value()) {
        result.failure = ResolveFailure::DescentFailed;
        result.descent = descent.failure;
        result.blame = descent.blame;
        return result;
    }
    result.key = descent.key;
    return result;
}

ResolveResult GroupKeyResolver::resolve(
    const server::GroupInfo& group,
    std::int64_t epoch,
    const privmx::crypto::PrivateKey& ownUserKey,
    const server::GroupGetKeyArchiveResult& archive
) {
    const std::optional<std::uint32_t> prunedBelow = archive.archivePrunedBelow.has_value() ?
        std::optional<std::uint32_t>(static_cast<std::uint32_t>(archive.archivePrunedBelow.value())) :
        std::nullopt;
    return resolveWith(
        group, epoch, ownUserKey, toDownwardRungs(archive), registryFromArchive(group, archive),
        static_cast<std::uint32_t>(archive.eraFloor), prunedBelow
    );
}
