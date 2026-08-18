/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include "privmx/endpoint/group/keytree/GroupKeyResolver.hpp"

#include <privmx/crypto/ecc/PublicKey.hpp>

using namespace privmx::endpoint::group::keytree;

GroupKeyResolver::GroupKeyResolver(TreeKeyCache& cache) : _cache(cache) {}

bool GroupKeyResolver::hasTree(const server::GroupInfo& group) {
    return group.numLeaves.has_value() &&
        group.numLeaves.value() > 0 &&
        group.treeNodes.has_value() &&
        group.treeEdges.has_value() &&
        group.leafAssignment.has_value();
}

TreeGroupState GroupKeyResolver::toTreeState(const server::GroupInfo& group) {
    TreeGroupState state;
    state.numLeaves = static_cast<std::uint32_t>(group.numLeaves.value_or(0));
    state.epoch = static_cast<std::uint32_t>(group.keyVersion.value_or(1));
    state.grantPublicKey = privmx::crypto::PublicKey::fromBase58DER(group.groupPubKey);

    if (group.leafAssignment.has_value()) {
        for (const std::string& userId : group.leafAssignment.value()) {
            // The wire format uses an empty string for a blank leaf, so that the array needs no nullable
            // elements. Anything non-empty is an occupied position.
            if (userId.empty()) {
                state.leafAssignment.push_back(std::nullopt);
            } else {
                state.leafAssignment.push_back(userId);
            }
        }
    }

    if (group.treeNodes.has_value()) {
        for (const server::GroupTreeNode& node : group.treeNodes.value()) {
            state.nodes.push_back(
                TreeNodeState{
                    static_cast<std::uint32_t>(node.nodeIndex),
                    static_cast<std::uint32_t>(node.generation),
                    privmx::crypto::PublicKey::fromBase58DER(node.publicKey),
                }
            );
        }
    }

    if (group.treeEdges.has_value()) {
        for (const server::GroupTreeEdge& edge : group.treeEdges.value()) {
            TreeEdge converted;
            converted.isGrantEdge = edge.isGrantEdge.value_or(false);
            converted.parentIndex = static_cast<std::uint32_t>(edge.parentIndex.value_or(0));
            converted.parentGeneration = static_cast<std::uint32_t>(edge.parentGeneration);
            if (edge.childKind == "user") {
                converted.childKind = EdgeChildKind::User;
                converted.childUserId = edge.childUserId.value_or("");
            } else {
                converted.childKind = EdgeChildKind::Node;
                converted.childIndex = static_cast<std::uint32_t>(edge.childIndex.value_or(0));
                converted.childGeneration = static_cast<std::uint32_t>(edge.childGeneration.value_or(0));
            }
            converted.blob = edge.data;
            state.edges.push_back(converted);
        }
    }
    return state;
}

namespace {

/**
 * Converts one wire rung, dropping it when it does not point downwards.
 *
 * Re-checking the direction client-side is not redundancy for its own sake: the bridge enforces it, but taking
 * the server's word for it would mean trusting the one party the threat model assumes may be hostile — and an
 * upward rung is exactly the shape that hands a removed member a key from after their removal.
 */
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

std::vector<ArchiveRung> GroupKeyResolver::toRungs(const server::GroupGetKeyArchiveResult& archive) {
    std::vector<ArchiveRung> rungs;
    for (const server::GroupArchiveRung& rung : archive.rungs) {
        const auto converted = convertRung(rung);
        if (converted.has_value()) {
            rungs.push_back(converted.value());
        }
    }
    return rungs;
}

std::vector<EpochRegistryEntry> GroupKeyResolver::toRegistry(
    const server::GroupInfo& group,
    const server::GroupGetKeyArchiveResult& archive
) {
    std::vector<EpochRegistryEntry> registry;
    for (const server::GroupKeyHistoryEntry& entry : archive.keyHistory) {
        registry.push_back(
            EpochRegistryEntry{
                static_cast<std::uint32_t>(entry.keyVersion),
                privmx::crypto::PublicKey::fromBase58DER(entry.groupPubKey),
            }
        );
    }
    registry.push_back(
        EpochRegistryEntry{
            static_cast<std::uint32_t>(group.keyVersion.value_or(1)),
            privmx::crypto::PublicKey::fromBase58DER(group.groupPubKey),
        }
    );
    return registry;
}

std::vector<ArchiveRung> GroupKeyResolver::toRungs(const server::GroupInfo& group) {
    std::vector<ArchiveRung> rungs;
    if (!group.archiveRungs.has_value()) {
        return rungs;
    }
    for (const server::GroupArchiveRung& rung : group.archiveRungs.value()) {
        const auto converted = convertRung(rung);
        if (converted.has_value()) {
            rungs.push_back(converted.value());
        }
    }
    return rungs;
}

std::vector<EpochRegistryEntry> GroupKeyResolver::toRegistry(const server::GroupInfo& group) {
    std::vector<EpochRegistryEntry> registry;
    // `keyHistory` holds the PAST epochs only; the current one lives in `groupPubKey`. Missing that distinction
    // would leave the newest epoch unverifiable, and an unverifiable key is one this client refuses to accept.
    if (group.keyHistory.has_value()) {
        for (const server::GroupKeyHistoryEntry& entry : group.keyHistory.value()) {
            registry.push_back(
                EpochRegistryEntry{
                    static_cast<std::uint32_t>(entry.keyVersion),
                    privmx::crypto::PublicKey::fromBase58DER(entry.groupPubKey),
                }
            );
        }
    }
    registry.push_back(
        EpochRegistryEntry{
            static_cast<std::uint32_t>(group.keyVersion.value_or(1)),
            privmx::crypto::PublicKey::fromBase58DER(group.groupPubKey),
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

/**
 * Resolves through the tree, then through the ladder if an older epoch was asked for.
 *
 * `rungs`, `registry`, `eraFloor` and `prunedBelow` are passed in rather than read off the group so that both
 * public overloads — archive inline, archive fetched separately — share one code path, and so that the
 * verification at each hop is written once.
 */
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
    const privmx::crypto::PrivateKey& ownUserKey
) {
    const std::optional<std::uint32_t> prunedBelow = group.archivePrunedBelow.has_value() ?
        std::optional<std::uint32_t>(static_cast<std::uint32_t>(group.archivePrunedBelow.value())) :
        std::nullopt;
    return resolveWith(
        group, epoch, ownUserKey, toRungs(group), toRegistry(group),
        static_cast<std::uint32_t>(group.eraFloor.value_or(1)), prunedBelow
    );
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
        group, epoch, ownUserKey, toRungs(archive), toRegistry(group, archive),
        static_cast<std::uint32_t>(archive.eraFloor), prunedBelow
    );
}
