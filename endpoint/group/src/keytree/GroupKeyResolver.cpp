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
#include <limits>

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

namespace {

// The statements served with the group: the ones its filled nodes cite, and the latest.
std::vector<privmx::endpoint::group::server::GroupTreeCommit> statements(
    const privmx::endpoint::group::server::GroupInfo& group
) {
    auto all = group.treeCommits.value_or(std::vector<privmx::endpoint::group::server::GroupTreeCommit>{});
    if (group.treeCommit.has_value()) {
        all.push_back(group.treeCommit.value());
    }
    return all;
}

} // namespace

TreeGroupState GroupKeyResolver::toTreeState(const server::GroupInfo& group) {
    TreeGroupState state = TreeWire::toRuntime(
        TreeWire::fromGroupInfo(group), static_cast<std::uint32_t>(group.keyVersion),
        privmx::crypto::PublicKeyCache::getInstance()->fromBase58DER(group.groupPubKey)
    );
    if (group.treeCommit.has_value() && group.treeCommit->seq > 0) {
        state.commitSeq = static_cast<std::uint64_t>(group.treeCommit->seq);
    }
    for (const server::GroupTreeCommit& statement : statements(group)) {
        state.setters[static_cast<std::uint64_t>(statement.seq)] = statement.committer;
    }
    return state;
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

privmx::endpoint::group::server::GroupGetKeyArchiveResult GroupKeyResolver::authenticated(
    server::GroupGetKeyArchiveResult archive,
    const std::map<std::uint64_t, CommitStatement>& openers
) {
    archive.keyHistory.clear();
    for (const auto& [epoch, statement] : openers) {
        archive.keyHistory.push_back(server::GroupKeyHistoryEntry{
            .keyVersion = static_cast<std::int64_t>(epoch), .groupPubKey = statement.groupPubKey
        });
    }
    std::vector<server::GroupArchiveRung> rungs;
    for (server::GroupArchiveRung& rung : archive.rungs) {
        const auto opener = openers.find(static_cast<std::uint64_t>(rung.atKeyVersion));
        const auto sealer = TreeKeys::sealerOf(rung.data);
        if (opener == openers.end() || !sealer.has_value() ||
            sealer->toBase58DER() != opener->second.committerPubKey) {
            continue;
        }
        rung.author = opener->second.committer;
        rungs.push_back(rung);
    }
    archive.rungs = rungs;
    return archive;
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

bool GroupKeyResolver::healsFirst(const server::GroupInfo& group, std::uint32_t node) {
    // A node's left subtree is complete, so its lowest leaf is `2^level - 1` indices to the left of it.
    const std::uint32_t lowest = TreeMath::leafPosition(node - ((1u << TreeMath::level(node)) - 1));
    const auto& seats = group.leafAssignment.value();
    const auto own = static_cast<std::size_t>(group.ownLeafPosition.value());
    return std::all_of(seats.begin() + lowest, seats.begin() + own, [](const std::string& s) { return s.empty(); });
}

std::optional<std::uint32_t> GroupKeyResolver::nodeNeedingSelfUpdate(const server::GroupInfo& group) {
    if (!hasTree(group) || !ownUserId(group).has_value()) {
        return std::nullopt;
    }
    const auto& records = group.treeNodes.value();
    const auto vouchers = statements(group);
    const auto numLeaves = static_cast<std::uint32_t>(group.numLeaves.value());
    for (const std::uint32_t node :
         TreeMath::keyedPath(static_cast<std::uint32_t>(group.ownLeafPosition.value()), numLeaves)) {
        const auto record = std::find_if(records.begin(), records.end(), [&](const server::GroupTreeNode& served) {
            return served.nodeIndex == static_cast<std::int64_t>(node);
        });
        if (record == records.end() || record->publicKey.value_or("").empty()) {
            return node;
        }
        // Set from outside its subtree (by the creator or an adder): whoever set it keeps it, so heal it.
        const auto voucher = std::find_if(vouchers.begin(), vouchers.end(), [&](const server::GroupTreeCommit& s) {
            return record->setBy.has_value() && s.seq == record->setBy.value();
        });
        if (voucher == vouchers.end() || voucher->committerSeat < 0 ||
            voucher->committerSeat >= static_cast<std::int64_t>(numLeaves)) {
            return node;
        }
        const auto path = TreeMath::directPath(static_cast<std::uint32_t>(voucher->committerSeat), numLeaves);
        if (std::find(path.begin(), path.end(), node) == path.end()) {
            return node;
        }
    }
    return std::nullopt;
}

std::optional<std::string> GroupKeyResolver::tamperedBy(
    const server::GroupInfo& group,
    const std::optional<std::uint32_t>& tamperedNode
) {
    std::optional<std::int64_t> seq;
    if (!tamperedNode.has_value() && group.treeCommit.has_value()) {
        seq = group.treeCommit->seq;
    }
    for (const server::GroupTreeNode& node : group.treeNodes.value_or(std::vector<server::GroupTreeNode>{})) {
        if (tamperedNode.has_value() && node.nodeIndex == static_cast<std::int64_t>(tamperedNode.value())) {
            seq = node.setBy;
        }
    }
    for (const server::GroupTreeCommit& statement : statements(group)) {
        if (seq.has_value() && statement.seq == seq.value()) {
            return statement.committer;
        }
    }
    return std::nullopt;
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
        // Read as the current layout, an older tree would climb fine and mean something else: nothing in it says who
        // set a node, which is what a removal needs to blank everything the leaver could know.
        result.failure = ResolveFailure::UnsupportedTreeVersion;
        return result;
    }
    const auto identity = ownUserId(group);
    if (!identity.has_value()) {
        result.failure = ResolveFailure::ClimbFailed;
        result.climb = ClimbFailure::NotAMember;
        return result;
    }

    // 0 asks for the current epoch. Anything else is checked before it is narrowed: a negative or oversized value
    // must not wrap round into some real epoch, and an epoch past the current one has no key yet — answering it
    // with the current key would hand out a key under a name it does not have.
    if (epoch < 0 || epoch > static_cast<std::int64_t>(std::numeric_limits<std::uint32_t>::max())) {
        result.failure = ResolveFailure::InvalidEpoch;
        return result;
    }
    const TreeGroupState state = toTreeState(group);
    const std::uint32_t currentEpoch = state.epoch;
    const std::uint32_t wanted = epoch == 0 ? currentEpoch : static_cast<std::uint32_t>(epoch);
    if (wanted > currentEpoch) {
        result.failure = ResolveFailure::FutureEpoch;
        return result;
    }

    // Step 1: climb to the current epoch's grant key. Every recovered node key is verified against the public
    // key the server published for that node, so a corrupted edge fails loudly instead of yielding a wrong key.
    TreeKeys tree(_cache);
    const ClimbResult climb = tree.climbToGrantKey(state, identity.value(), ownUserKey);
    if (climb.failure != ClimbFailure::None || !climb.grantKey.has_value()) {
        result.failure = ResolveFailure::ClimbFailed;
        result.climb = climb.failure;
        if (climb.failure == ClimbFailure::Tampered || climb.failure == ClimbFailure::DecryptFailed) {
            result.blame = tamperedBy(group, climb.tamperedNode);
        }
        return result;
    }
    if (wanted == currentEpoch) {
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
