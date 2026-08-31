#include "privmx/endpoint/group/encryptors/group/GroupDataSchemaMapper.hpp"

#include <algorithm>
#include <set>

#include <Poco/JSON/Object.h>
#include <privmx/crypto/Crypto.hpp>
#include <privmx/crypto/ecc/PublicKey.hpp>
#include <privmx/endpoint/core/Factory.hpp>
#include <privmx/endpoint/core/TimestampValidator.hpp>
#include <privmx/endpoint/core/encryptors/DataSchemaMapperUtils.hpp>
#include <privmx/endpoint/core/encryptors/module/Constants.hpp>
#include <privmx/utils/Utils.hpp>

#include "privmx/endpoint/group/GroupException.hpp"
#include "privmx/endpoint/group/checkpoint/ChainCheckpoint.hpp"
#include "privmx/endpoint/group/checkpoint/ChainCheckpointRegistry.hpp"

using namespace privmx::endpoint;
using namespace privmx::endpoint::group;

GroupDataSchemaMapper::GroupDataSchemaMapper(
    const privmx::crypto::PrivateKey& userPrivKey,
    const core::Connection& connection
)
    : core::BaseModuleDataSchemaMapper(userPrivKey, connection) {
    _strategyV5 = std::make_shared<GroupDataSchemaStrategyV5>();
    _strategyMapper.registerStrategy(core::ModuleDataSchema::Version::VERSION_5, _strategyV5);
}

Poco::Dynamic::Var GroupDataSchemaMapper::encrypt(const GroupDataToEncryptV5& data, const std::string& key) {
    return _strategyV5->encrypt(data, _userPrivKey, key).toJSON();
}

std::tuple<Group, core::DataIntegrityObject> GroupDataSchemaMapper::decrypt(
    const server::GroupInfo& groupInfo,
    const core::DecryptedEncKey& encKey
) {
    return _strategyMapper.dispatch(
        static_cast<int64_t>(getDataStructureVersion(groupInfo.data.back())), groupInfo, encKey,
        [&]() -> std::tuple<Group, core::DataIntegrityObject> {
            return {
                toLibGroup(
                    groupInfo, {}, {}, UnknownGroupFormatException().getCode(), core::ModuleDataSchema::Version::UNKNOWN
                ),
                {}
            };
        }
    );
}

void GroupDataSchemaMapper::assertHeadMatchesVerifiedState(
    const server::GroupInfo& groupInfo,
    const std::set<std::string>& verifiedUsers,
    const std::set<std::string>& verifiedManagers,
    const std::string& verifiedGroupPubKey,
    int64_t verifiedKeyVersion
) {
    // Anchored to verified state, never to `history.back()`: once entries can be skipped, that field is
    // bridge-supplied plaintext this call may never have touched, and tampering it stays consistent.
    const auto headUsers = std::set<std::string>(groupInfo.users.begin(), groupInfo.users.end());
    const auto headManagers = std::set<std::string>(groupInfo.managers.begin(), groupInfo.managers.end());
    const bool bridgeEpochMismatch = groupInfo.keyVersion.has_value() &&
        groupInfo.keyVersion.value() != verifiedKeyVersion;
    if (verifiedUsers != headUsers ||
        verifiedManagers != headManagers ||
        groupInfo.groupPubKey != verifiedGroupPubKey ||
        bridgeEpochMismatch) {
        throw GroupDataIntegrityException();
    }
}

int64_t GroupDataSchemaMapper::verifiedVersion(const std::string& groupId) {
    const auto checkpoint = _chainCheckpoints.get(groupId)->get();
    return checkpoint.has_value() ? checkpoint->verifiedVersion : 0;
}

void GroupDataSchemaMapper::assertDataIntegrity(const server::GroupInfo& groupInfo) {
    // Where the served entries start. A server that knows nothing of windowing omits the field and always sends
    // from genesis, which is what 1 means — so an old server and a full response are the same case.
    const int64_t firstServed = groupInfo.firstServedVersion.value_or(1);
    if (firstServed < 1) {
        throw GroupDataIntegrityException();
    }
    if (groupInfo.data.empty()) {
        // An empty window is only meaningful as "you already have everything", and only when the head agrees
        // with what we verified. Anything else is a response with no chain in it.
        const auto onlyCheckpoint = _chainCheckpoints.get(groupInfo.id)->get();
        if (!onlyCheckpoint.has_value() ||
            firstServed != groupInfo.version + 1 ||
            onlyCheckpoint->verifiedVersion != groupInfo.version) {
            throw UnknownGroupFormatException();
        }
        assertHeadMatchesVerifiedState(
            groupInfo, onlyCheckpoint->verifiedUsers, onlyCheckpoint->verifiedManagers,
            onlyCheckpoint->groupPubKeyAtCheckpoint, onlyCheckpoint->keyVersionAtCheckpoint
        );
        return;
    }
    // The window has to end at the head: `firstServed` plus what was sent must land exactly on `version`.
    if (groupInfo.data.size() != groupInfo.history.size() ||
        firstServed - 1 + static_cast<int64_t>(groupInfo.data.size()) != groupInfo.version) {
        throw GroupDataIntegrityException();
    }

    // Resume from the last successfully-verified point instead of re-proving the whole chain from genesis on
    // every call.
    auto checkpointStore = _chainCheckpoints.get(groupInfo.id);
    auto checkpoint = checkpointStore->get();

    // Trust-on-first-use rollback pinning, before any per-entry check: a shorter response can be a validly signed
    // *past* state, which a from-genesis verify would accept on its own terms while hiding a since-revoked member.
    if (checkpoint.has_value() && groupInfo.version < checkpoint->verifiedVersion) {
        throw GroupHistoryForkException();
    }

    // A window that does not start at genesis is only verifiable from the checkpoint it chains into. Without one
    // there is no anchor, and accepting the window would mean trusting its first entry on the server's word.
    if (firstServed > 1 && (!checkpoint.has_value() || checkpoint->verifiedVersion != firstServed - 1)) {
        throw GroupDataIntegrityException();
    }

    size_t startIndex = 0;
    std::set<std::string> verifiedManagers;
    std::set<std::string> verifiedUsers;
    std::string runningPrevDioHashHex;
    int64_t prevKeyVersion = 0;
    std::string prevGroupPubKey;

    if (checkpoint.has_value()) {
        // Both are versions, so the skip is measured against what the window actually starts at: a full response
        // skips the verified prefix, a window that begins right above the checkpoint skips nothing.
        const int64_t alreadyVerifiedInWindow = checkpoint->verifiedVersion - (firstServed - 1);
        startIndex = static_cast<size_t>(std::max<int64_t>(0, alreadyVerifiedInWindow));
        verifiedManagers = checkpoint->verifiedManagers;
        verifiedUsers = checkpoint->verifiedUsers;
        runningPrevDioHashHex = checkpoint->lastEntryDioHashHex;
        prevKeyVersion = checkpoint->keyVersionAtCheckpoint;
        prevGroupPubKey = checkpoint->groupPubKeyAtCheckpoint;
    }

    // `i == 0` below only ever means true genesis: a resumed run's first new entry has `i == startIndex >= 1`, so
    // the existing genesis/non-genesis split already does the right thing without new branching.
    for (size_t i = startIndex; i < groupInfo.data.size(); ++i) {
        const auto& entry = groupInfo.data[i];
        const auto& histEntry = groupInfo.history[i];
        // Genesis is a property of the version, not of the array index: in a window, index 0 is whatever version
        // the window starts at, and only the true first entry may have no chain link and name its own signer.
        const bool isGenesis = (firstServed + static_cast<int64_t>(i) == 1);

        auto encData = dynamic::EncryptedGroupDataV5::fromJSON(entry.data);

        // A: DIO signature + field checksums
        core::DataIntegrityObject dio;
        try {
            dio = _strategyV5->getDIOAndAssertIntegrity(encData);
        } catch (...) { throw GroupDataIntegrityException(); }

        // A2: DIO metadata vs server plaintext
        if (dio.contextId != groupInfo.contextId ||
            dio.resourceId != groupInfo.resourceId.value_or("") ||
            dio.creatorUserId != histEntry.author) {
            throw GroupDataIntegrityException();
        }
        try {
            core::TimestampValidator::validate(dio.timestamp, histEntry.created);
        } catch (...) { throw GroupDataIntegrityException(); }

        // Decode membership (signed plaintext — no decryption key needed)
        auto authorPublicKey = privmx::crypto::PublicKey::fromBase58DER(encData.authorPubKey);
        core::Buffer membershipRaw;
        try {
            membershipRaw = _dataEncryptor.decodeAndVerify(encData.membership, authorPublicKey);
        } catch (...) { throw GroupMembershipMismatchException(); }
        dynamic::MembershipBlock membership;
        try {
            membership = dynamic::MembershipBlock::fromJSON(
                privmx::utils::Utils::parseJsonObject(membershipRaw.stdString())
            );
        } catch (...) { throw GroupMembershipMismatchException(); }

        // G1: chain link — on a resumed run `runningPrevDioHashHex` is the checkpoint's own anchor, so the first
        // new entry must chain into it exactly as it would in an uninterrupted full verification.
        if (isGenesis) {
            if (membership.prevEntryHash.has_value()) {
                throw GroupChainBrokenException();
            }
        } else {
            if (!membership.prevEntryHash.has_value() || membership.prevEntryHash.value() != runningPrevDioHashHex) {
                throw GroupChainBrokenException();
            }
        }

        // G2: manager authorization
        if (isGenesis) {
            if (membership.managers.end() ==
                std::find(membership.managers.begin(), membership.managers.end(), dio.creatorUserId)) {
                throw GroupUnauthorizedSignerException();
            }
        } else {
            if (verifiedManagers.find(dio.creatorUserId) == verifiedManagers.end()) {
                throw GroupUnauthorizedSignerException();
            }
        }
        verifiedManagers = std::set<std::string>(membership.managers.begin(), membership.managers.end());
        verifiedUsers = std::set<std::string>(membership.users.begin(), membership.users.end());

        // Member-set cross-check vs bridge plaintext
        auto histUsers = std::set<std::string>(histEntry.users.begin(), histEntry.users.end());
        auto histMgrs = std::set<std::string>(histEntry.managers.begin(), histEntry.managers.end());

        if (verifiedUsers != histUsers ||
            verifiedManagers != histMgrs ||
            membership.groupPubKey != histEntry.groupPubKey ||
            membership.keyId != histEntry.keyId) {
            throw GroupMembershipMismatchException();
        }

        // Epoch (keyVersion) monotonicity — backward compat: absent keyVersion treated as 0
        int64_t thisKeyVersion = membership.keyVersion.value_or(0);
        if (isGenesis) {
            // The genesis epoch is 0 for a flat group and 1 for a tree-backed one. Neither is freely chosen: the
            // head check below pins it to the bridge's own `keyVersion`, so anything above 1 is a fabrication.
            if (thisKeyVersion > 1)
                throw GroupDataIntegrityException();
        } else {
            // Non-decreasing and increments by at most 1 — `prevKeyVersion` is either the previous entry visited
            // in this call, or (for the first entry above a checkpoint) the checkpoint's own committed value.
            if (thisKeyVersion < prevKeyVersion || thisKeyVersion - prevKeyVersion > 1) {
                throw GroupDataIntegrityException();
            }
            // groupPubKey changes if and only if keyVersion increments
            bool pubKeyChanged = (membership.groupPubKey != prevGroupPubKey);
            bool epochBumped = (thisKeyVersion > prevKeyVersion);
            if (pubKeyChanged != epochBumped)
                throw GroupDataIntegrityException();
        }
        prevKeyVersion = thisKeyVersion;
        prevGroupPubKey = membership.groupPubKey;
        runningPrevDioHashHex = privmx::utils::Hex::from(privmx::crypto::Crypto::sha256(encData.dio));
    }

    // Unconditional and `O(1)`: the arguments are either freshly computed above or the checkpoint's own remembered
    // values, and deliberately never re-derived from `history.back()`, which this call may never have touched.
    assertHeadMatchesVerifiedState(groupInfo, verifiedUsers, verifiedManagers, prevGroupPubKey, prevKeyVersion);

    // keyVersion pinning against the freshly verified epoch, not a bridge-supplied claim. Today's checks already
    // make this unreachable; it stays explicit so a future change to them cannot silently reopen the gap.
    if (checkpoint.has_value() && prevKeyVersion < checkpoint->keyVersionAtCheckpoint) {
        throw GroupHistoryForkException();
    }

    checkpointStore->advance(
        checkpoint::ChainCheckpoint::Snapshot{
            .verifiedVersion = static_cast<int64_t>(groupInfo.data.size()),
            .lastEntryDioHashHex = runningPrevDioHashHex,
            .verifiedManagers = verifiedManagers,
            .verifiedUsers = verifiedUsers,
            .keyVersionAtCheckpoint = prevKeyVersion,
            .groupPubKeyAtCheckpoint = prevGroupPubKey
        }
    );
}

void GroupDataSchemaMapper::dropChainCheckpoint(const std::string& groupId) {
    _chainCheckpoints.drop(groupId);
}

void GroupDataSchemaMapper::dropAllChainCheckpoints() {
    _chainCheckpoints.dropAll();
}

std::optional<checkpoint::ChainCheckpoint::Snapshot> GroupDataSchemaMapper::peekChainCheckpoint(
    const std::string& groupId
) const {
    auto store = _chainCheckpoints.tryGet(groupId);
    return store ? store->get() : std::nullopt;
}

uint32_t GroupDataSchemaMapper::validateDataIntegrity(const server::GroupInfo& groupInfo) {
    return core::DataSchemaMapperUtils::toStatusCode([&] { assertDataIntegrity(groupInfo); });
}

Group GroupDataSchemaMapper::toLibGroup(
    const server::GroupInfo& info,
    const core::Buffer& publicMeta,
    const core::Buffer& privateMeta,
    int64_t statusCode,
    int64_t schemaVersion
) {
    return Group{
        .contextId = info.contextId,
        .groupId = info.id,
        .groupPubKey = info.groupPubKey,
        .createDate = info.createDate,
        .creator = info.creator,
        .lastModificationDate = info.lastModificationDate,
        .lastModifier = info.lastModifier,
        .users = info.users,
        .managers = info.managers,
        .version = info.version,
        .publicMeta = publicMeta,
        .privateMeta = privateMeta,
        .policy = core::Factory::parsePolicyServerObject(info.policy),
        .statusCode = statusCode,
        .schemaVersion = schemaVersion,
        .type = info.type,
        .keyVersion = info.keyVersion.value_or(0)
    };
}

GroupSummary GroupDataSchemaMapper::toLibGroupSummary(const server::GroupSummary& info) {
    return GroupSummary{
        .contextId = info.contextId,
        .groupId = info.id,
        .groupPubKey = info.groupPubKey,
        .createDate = info.createDate,
        .creator = info.creator,
        .lastModificationDate = info.lastModificationDate,
        .lastModifier = info.lastModifier,
        .users = info.users,
        .managers = info.managers,
        .version = info.version,
        .policy = core::Factory::parsePolicyServerObject(info.policy),
        .type = info.type,
        .keyVersion = info.keyVersion
    };
}

std::vector<Group> GroupDataSchemaMapper::validateDecryptAndConvertGroups(
    const std::vector<server::GroupInfo>& groups,
    const std::shared_ptr<core::KeyProvider>& keyProvider,
    const core::KeyProvider::GroupPrivKeyResolver& groupPrivKeyResolver
) {
    return core::DataSchemaMapperUtils::batchValidateDecryptVerifyContainers<Group>(
        groups, keyProvider, _connection, [&](const server::GroupInfo& g) { return validateDataIntegrity(g); },
        [](const server::GroupInfo& g) -> core::EncKeyLocation {
            return {.contextId = g.contextId, .resourceId = g.resourceId.value_or("")};
        },
        [&](const server::GroupInfo& g, const core::DecryptedEncKey& key) { return decrypt(g, key); },
        [](const server::GroupInfo& g, uint32_t code) {
            return toLibGroup(g, {}, {}, code, core::ModuleDataSchema::Version::UNKNOWN);
        },
        groupPrivKeyResolver
    );
}

core::ModuleInternalMetaV5 GroupDataSchemaMapper::decryptInternalMeta(
    const Poco::Dynamic::Var& data,
    const core::DecryptedEncKey& encKey
) {
    if (encKey.statusCode != 0)
        return {};
    try {
        auto encData = dynamic::EncryptedGroupDataV5::fromJSON(data);
        if (encData.version != core::ModuleDataSchema::Version::VERSION_5)
            return {};
        auto decrypted = _groupEncryptor.decrypt(encData, encKey.key);
        if (decrypted.statusCode != 0)
            return {};
        return decrypted.internalMeta;
    } catch (...) { return {}; }
}

Group GroupDataSchemaMapper::validateDecryptAndConvertGroup(
    const server::GroupInfo& groupInfo,
    const std::shared_ptr<core::KeyProvider>& keyProvider,
    const core::KeyProvider::GroupPrivKeyResolver& groupPrivKeyResolver
) {
    return validateDecryptAndConvertGroups({groupInfo}, keyProvider, groupPrivKeyResolver)[0];
}

std::string GroupDataSchemaMapper::getGroupPrivKey(
    const server::GroupInfo& groupInfo,
    const core::DecryptedEncKey& encKey
) {
    // Search all data entries for the one encrypted with encKey (by matching keyId).
    // Covers both the current entry and any historical epoch entry in group.keys[].
    for (const auto& dataEntry : groupInfo.data) {
        if (dataEntry.keyId == encKey.id) {
            auto encData = dynamic::EncryptedGroupDataV5::fromJSON(dataEntry.data);
            auto group = _groupEncryptor.decrypt(encData, encKey.key);
            return group.groupPrivKey;
        }
    }
    // Fallback to head if no match (e.g., old Phase-1 data without proper keyId tracking)
    auto encData = dynamic::EncryptedGroupDataV5::fromJSON(groupInfo.data.back().data);
    auto group = _groupEncryptor.decrypt(encData, encKey.key);
    return group.groupPrivKey;
}
