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
                toLibGroup(groupInfo, {}, {}, UnknownGroupFormatException().getCode(),
                           core::ModuleDataSchema::Version::UNKNOWN),
                {}
            };
        }
    );
}

void GroupDataSchemaMapper::assertDataIntegrity(const server::GroupInfo& groupInfo) {
    if (groupInfo.data.empty()) {
        throw UnknownGroupFormatException();
    }
    if (static_cast<size_t>(groupInfo.version) != groupInfo.data.size() ||
        groupInfo.data.size() != groupInfo.history.size()) {
        throw GroupDataIntegrityException();
    }

    std::set<std::string> verifiedManagers;
    std::string prevDioStr;
    int64_t prevKeyVersion = 0;
    std::string prevGroupPubKey;
    int64_t finalKeyVersion = 0;

    for (size_t i = 0; i < groupInfo.data.size(); ++i) {
        const auto& entry = groupInfo.data[i];
        const auto& histEntry = groupInfo.history[i];

        auto encData = dynamic::EncryptedGroupDataV5::fromJSON(entry.data);

        // A: DIO signature + field checksums
        core::DataIntegrityObject dio;
        try {
            dio = _strategyV5->getDIOAndAssertIntegrity(encData);
        } catch (...) {
            throw GroupDataIntegrityException();
        }

        // A2: DIO metadata vs server plaintext
        if (dio.contextId != groupInfo.contextId ||
            dio.resourceId != groupInfo.resourceId.value_or("") ||
            dio.creatorUserId != histEntry.author) {
            throw GroupDataIntegrityException();
        }
        try {
            core::TimestampValidator::validate(dio.timestamp, histEntry.created);
        } catch (...) {
            throw GroupDataIntegrityException();
        }

        // Decode membership (signed plaintext — no decryption key needed)
        auto authorPublicKey = privmx::crypto::PublicKey::fromBase58DER(encData.authorPubKey);
        core::Buffer membershipRaw;
        try {
            membershipRaw = _dataEncryptor.decodeAndVerify(encData.membership, authorPublicKey);
        } catch (...) {
            throw GroupMembershipMismatchException();
        }
        dynamic::MembershipBlock membership;
        try {
            membership = dynamic::MembershipBlock::fromJSON(
                privmx::utils::Utils::parseJsonObject(membershipRaw.stdString())
            );
        } catch (...) {
            throw GroupMembershipMismatchException();
        }

        // G1: chain link
        if (i == 0) {
            if (membership.prevEntryHash.has_value()) {
                throw GroupChainBrokenException();
            }
        } else {
            if (!membership.prevEntryHash.has_value() ||
                membership.prevEntryHash.value() != privmx::utils::Hex::from(privmx::crypto::Crypto::sha256(prevDioStr))) {
                throw GroupChainBrokenException();
            }
        }
        prevDioStr = encData.dio;

        // G2: manager authorization
        if (i == 0) {
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

        // Member-set cross-check vs bridge plaintext
        auto membershipUsers = std::set<std::string>(membership.users.begin(), membership.users.end());
        auto histUsers = std::set<std::string>(histEntry.users.begin(), histEntry.users.end());
        auto membershipMgrs = std::set<std::string>(membership.managers.begin(), membership.managers.end());
        auto histMgrs = std::set<std::string>(histEntry.managers.begin(), histEntry.managers.end());

        if (membershipUsers != histUsers || membershipMgrs != histMgrs ||
            membership.groupPubKey != histEntry.groupPubKey || membership.keyId != histEntry.keyId) {
            throw GroupMembershipMismatchException();
        }

        // EP-9: epoch (keyVersion) monotonicity — backward compat: absent keyVersion treated as 0
        int64_t thisKeyVersion = membership.keyVersion.value_or(0);
        if (i == 0) {
            // The genesis epoch is 0 for a flat group and 1 for a tree-backed one, whose grant key exists from
            // the moment of creation and whose Epoch Ladder counts from 1. Which of the two it is cannot be
            // chosen freely: the head check below pins the committed value to the bridge's own `keyVersion`, and
            // only the tree-backed creation path makes the bridge record 1. Anything above 1 is a fabrication.
            if (thisKeyVersion > 1) throw GroupDataIntegrityException();
        } else {
            // Non-decreasing and increments by at most 1
            if (thisKeyVersion < prevKeyVersion || thisKeyVersion - prevKeyVersion > 1) {
                throw GroupDataIntegrityException();
            }
            // groupPubKey changes if and only if keyVersion increments
            bool pubKeyChanged = (membership.groupPubKey != prevGroupPubKey);
            bool epochBumped = (thisKeyVersion > prevKeyVersion);
            if (pubKeyChanged != epochBumped) throw GroupDataIntegrityException();
        }
        prevKeyVersion = thisKeyVersion;
        prevGroupPubKey = membership.groupPubKey;
        finalKeyVersion = thisKeyVersion;
    }

    // Head consistency checks
    const auto& lastHist = groupInfo.history.back();
    auto finalUsers = std::set<std::string>(lastHist.users.begin(), lastHist.users.end());
    auto headUsers = std::set<std::string>(groupInfo.users.begin(), groupInfo.users.end());
    auto headManagers = std::set<std::string>(groupInfo.managers.begin(), groupInfo.managers.end());

    // EP-9: cross-check bridge's top-level keyVersion == head membership's committed keyVersion
    bool bridgeEpochMismatch = groupInfo.keyVersion.has_value() &&
                               groupInfo.keyVersion.value() != finalKeyVersion;
    if (finalUsers != headUsers || verifiedManagers != headManagers ||
        groupInfo.groupPubKey != lastHist.groupPubKey || bridgeEpochMismatch) {
        throw GroupDataIntegrityException();
    }
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

std::vector<Group> GroupDataSchemaMapper::validateDecryptAndConvertGroups(
    const std::vector<server::GroupInfo>& groups,
    const std::shared_ptr<core::KeyProvider>& keyProvider
) {
    return core::DataSchemaMapperUtils::batchValidateDecryptVerifyContainers<Group>(
        groups, keyProvider, _connection,
        [&](const server::GroupInfo& g) { return validateDataIntegrity(g); },
        [](const server::GroupInfo& g) -> core::EncKeyLocation {
            return {.contextId = g.contextId, .resourceId = g.resourceId.value_or("")};
        },
        [&](const server::GroupInfo& g, const core::DecryptedEncKey& key) { return decrypt(g, key); },
        [](const server::GroupInfo& g, uint32_t code) {
            return toLibGroup(g, {}, {}, code, core::ModuleDataSchema::Version::UNKNOWN);
        }
    );
}

core::ModuleInternalMetaV5 GroupDataSchemaMapper::decryptInternalMeta(
    const Poco::Dynamic::Var& data,
    const core::DecryptedEncKey& encKey
) {
    if (encKey.statusCode != 0) return {};
    try {
        auto encData = dynamic::EncryptedGroupDataV5::fromJSON(data);
        if (encData.version != core::ModuleDataSchema::Version::VERSION_5) return {};
        auto decrypted = _groupEncryptor.decrypt(encData, encKey.key);
        if (decrypted.statusCode != 0) return {};
        return decrypted.internalMeta;
    } catch (...) { return {}; }
}

Group GroupDataSchemaMapper::validateDecryptAndConvertGroup(
    const server::GroupInfo& groupInfo,
    const std::shared_ptr<core::KeyProvider>& keyProvider
) {
    return validateDecryptAndConvertGroups({groupInfo}, keyProvider)[0];
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
