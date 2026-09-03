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
    assertRosterIsAttested(groupInfo, encKey);
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

/**
 * The roster the bridge served is the one a member attested to.
 *
 * Checked here rather than in `assertDataIntegrity` because it needs the metadata key, and this is the path that
 * has one. A caller that only wants the group's keys does not need the roster and does not pay for this.
 */
void GroupDataSchemaMapper::assertRosterIsAttested(
    const server::GroupInfo& groupInfo,
    const core::DecryptedEncKey& encKey
) {
    if (encKey.statusCode != 0 || groupInfo.data.empty()) {
        return; // no key recovered: the caller is not a member here, and has nothing to check the tag against
    }
    auto encData = dynamic::EncryptedGroupDataV5::fromJSON(groupInfo.data.back().data);
    // Authentic by the DIO's field checksum, which `assertDataIntegrity` already verified against a signed DIO —
    // so the envelope is stripped, not re-verified.
    core::Buffer membershipRaw;
    try {
        membershipRaw = _dataEncryptor.decodeAndVerify(
            encData.membership, privmx::crypto::PublicKey::fromBase58DER(encData.authorPubKey)
        );
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
    if (membership.groupPubKey != groupInfo.groupPubKey || membership.keyId != groupInfo.data.back().keyId) {
        throw GroupMembershipMismatchException();
    }
    const std::string expected = rosterTag(
        encKey.key, membership.keyVersion.value_or(0), groupInfo.version,
        groupInfo.users, groupInfo.managers
    );
    if (expected != membership.rosterTag) {
        throw GroupMembershipMismatchException();
    }
    if (membership.keyVersion.value_or(0) != groupInfo.keyVersion.value_or(0)) {
        throw GroupDataIntegrityException();
    }
}

std::string GroupDataSchemaMapper::rosterTag(
    const std::string& key,
    int64_t keyVersion,
    int64_t version,
    const std::vector<std::string>& users,
    const std::vector<std::string>& managers
) {
    const auto appendList = [](std::string& out, std::vector<std::string> names) {
        std::sort(names.begin(), names.end());
        out += std::to_string(names.size());
        for (const std::string& name : names) {
            out += "\n" + name;
        }
        out += "\n";
    };
    std::string payload = std::to_string(keyVersion) + "\n" + std::to_string(version) + "\n";
    appendList(payload, users);
    appendList(payload, managers);
    return privmx::utils::Hex::from(privmx::crypto::Crypto::hmacSha256(key, payload));
}

int64_t GroupDataSchemaMapper::verifiedVersion(const std::string& groupId) {
    const auto checkpoint = _chainCheckpoints.get(groupId)->get();
    return checkpoint.has_value() ? checkpoint->verifiedVersion : 0;
}

/**
 * Head-entry integrity, and nothing about the roster.
 *
 * There is no chain to walk any more: a membership change commits `rosterTag`, which a reader checks against the
 * key it already holds. What is left here is what a reader needs before trusting the head's *content* — the DIO
 * signature and its field checksums — plus the monotone version pin, which is the one thing a per-entry tag
 * cannot do on its own: without it a bridge could serve an older, correctly tagged roster from the same epoch.
 */
void GroupDataSchemaMapper::assertDataIntegrity(const server::GroupInfo& groupInfo) {
    if (groupInfo.data.empty()) {
        throw UnknownGroupFormatException();
    }
    auto encData = dynamic::EncryptedGroupDataV5::fromJSON(groupInfo.data.back().data);
    core::DataIntegrityObject dio;
    try {
        dio = _strategyV5->getDIOAndAssertIntegrity(encData);
    } catch (...) {
        throw GroupDataIntegrityException();
    }
    if (dio.contextId != groupInfo.contextId || dio.resourceId != groupInfo.resourceId.value_or("")) {
        throw GroupDataIntegrityException();
    }

    auto pinStore = _chainCheckpoints.get(groupInfo.id);
    const auto pinned = pinStore->get();
    if (pinned.has_value() && groupInfo.version < pinned->verifiedVersion) {
        // A shorter answer than one already seen is a validly tagged *past* state — a rollback, not an error the
        // tag itself can catch, because that older tag was genuine when it was made.
        throw GroupHistoryForkException();
    }
    pinStore->advance(checkpoint::ChainCheckpoint::Snapshot{.verifiedVersion = groupInfo.version});
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
