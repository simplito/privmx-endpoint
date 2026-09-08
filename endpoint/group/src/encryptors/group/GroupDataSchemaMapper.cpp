#include "privmx/endpoint/group/encryptors/group/GroupDataSchemaMapper.hpp"

#include <algorithm>
#include <set>

#include <Poco/JSON/Object.h>
#include <privmx/crypto/Crypto.hpp>
#include <privmx/crypto/ecc/PublicKey.hpp>
#include <privmx/endpoint/core/ConnectionImpl.hpp>
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

Poco::Dynamic::Var GroupDataSchemaMapper::encryptMeta(const GroupMetaToEncryptV5& data, const std::string& key) {
    return _strategyV5->encryptMeta(data, _userPrivKey, key).toJSON();
}

Poco::Dynamic::Var GroupDataSchemaMapper::encryptRoster(const GroupRosterToEncryptV5& data, const std::string& key) {
    return _strategyV5->encryptRoster(data, _userPrivKey, key).toJSON();
}

std::tuple<Group, core::DataIntegrityObject> GroupDataSchemaMapper::decryptMetaPlane(
    const server::GroupInfo& groupInfo,
    const core::DecryptedEncKey& metaKey
) {
    return _strategyMapper.dispatch(
        static_cast<int64_t>(getDataStructureVersion(groupInfo.meta)), groupInfo, metaKey,
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
 * Checked here rather than in `assertDataIntegrity` because it needs the epoch's content key, and this is the
 * path that has one.
 *
 * A missing key is a failure, not a pass. It used to mean "the caller is not a member here and has nothing to
 * check against" — but the planes are separate now, and a member removed at epoch N may still hold the key to a
 * metadata entry written at epoch N while having no way to reach the current epoch's roster key. Returning
 * quietly would hand them a group reported as verified. If the metadata opened, the roster must attest.
 */
void GroupDataSchemaMapper::assertRosterIsAttested(
    const server::GroupInfo& groupInfo,
    const core::DecryptedEncKey& rosterKey
) {
    if (rosterKey.statusCode != 0 || groupInfo.data.empty()) {
        throw GroupMembershipMismatchException();
    }
    auto encData = dynamic::EncryptedGroupRosterV5::fromJSON(groupInfo.data.back().data);
    // Authentic by the DIO's field checksum, which `assertDataIntegrity` already verified against a signed DIO —
    // so the envelope is stripped, not re-verified.
    core::Buffer membershipRaw;
    try {
        membershipRaw = _dataEncryptor.decodeAndVerify(
            encData.membership, privmx::crypto::PublicKey::fromBase58DER(encData.authorPubKey)
        );
    } catch (...) { throw GroupMembershipMismatchException(); }
    dynamic::MembershipBlock membership;
    try {
        membership = dynamic::MembershipBlock::fromJSON(
            privmx::utils::Utils::parseJsonObject(membershipRaw.stdString())
        );
    } catch (...) { throw GroupMembershipMismatchException(); }
    if (membership.groupPubKey != groupInfo.groupPubKey || membership.keyId != groupInfo.data.back().keyId) {
        throw GroupMembershipMismatchException();
    }
    const std::string expected = rosterTag(
        rosterKey.key, membership.keyVersion.value_or(0), groupInfo.users, groupInfo.managers
    );
    if (expected != membership.rosterTag) {
        throw GroupMembershipMismatchException();
    }
    if (membership.keyVersion.value_or(0) != groupInfo.keyVersion.value_or(0)) {
        throw GroupDataIntegrityException();
    }
}

/**
 * The metadata entry the bridge served is the one an updater wrote, at the version they wrote it at.
 *
 * `keyVersion` may legitimately lag the group's current epoch — that is the point of leaving metadata where it
 * was written — but it can never lead it, which would name a key that does not exist yet.
 */
void GroupDataSchemaMapper::assertMetaIsAttested(
    const server::GroupInfo& groupInfo,
    const core::DecryptedEncKey& metaKey
) {
    if (metaKey.statusCode != 0) {
        throw GroupMembershipMismatchException();
    }
    auto encData = dynamic::EncryptedGroupMetaV5::fromJSON(groupInfo.meta.data);
    core::Buffer metaRaw;
    try {
        metaRaw = _dataEncryptor.decodeAndVerify(
            encData.meta, privmx::crypto::PublicKey::fromBase58DER(encData.authorPubKey)
        );
    } catch (...) { throw GroupMembershipMismatchException(); }
    dynamic::MetaBlock meta;
    try {
        meta = dynamic::MetaBlock::fromJSON(privmx::utils::Utils::parseJsonObject(metaRaw.stdString()));
    } catch (...) { throw GroupMembershipMismatchException(); }
    if (meta.keyId != groupInfo.meta.keyId ||
        meta.keyVersion.value_or(0) != groupInfo.meta.keyVersion ||
        meta.keyVersion.value_or(0) > groupInfo.keyVersion.value_or(0)) {
        throw GroupMembershipMismatchException();
    }
    const std::string expected = metaTag(metaKey.key, groupInfo.meta.keyVersion, groupInfo.meta.version);
    if (expected != meta.metaTag) {
        throw GroupMembershipMismatchException();
    }
    // Without this a bridge could serve a stale entry under a rising counter — a content downgrade the monotone
    // pin cannot see, because the counter it checks keeps going up.
    if (meta.metaVersion.value_or(0) != groupInfo.version) {
        throw GroupMembershipMismatchException();
    }
}

std::string GroupDataSchemaMapper::rosterTag(
    const std::string& key,
    int64_t keyVersion,
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
    std::string payload = std::to_string(keyVersion) + "\n";
    appendList(payload, users);
    appendList(payload, managers);
    return privmx::utils::Hex::from(privmx::crypto::Crypto::hmacSha256(key, payload));
}

std::string GroupDataSchemaMapper::metaTag(const std::string& key, int64_t keyVersion, int64_t metaVersion) {
    const std::string payload = "meta\n" + std::to_string(keyVersion) + "\n" + std::to_string(metaVersion) + "\n";
    return privmx::utils::Hex::from(privmx::crypto::Crypto::hmacSha256(key, payload));
}

/**
 * Head-entry integrity, and nothing about either tag.
 *
 * There is no chain to walk any more: a membership change commits `rosterTag`, which a reader checks against the
 * key it already holds. What is left here is what a reader needs before trusting the head's *content* — the DIO
 * signature and its field checksums — plus the monotone version pins, which are the one thing a per-entry tag
 * cannot do on its own: without them a bridge could serve an older, correctly tagged state.
 *
 * Two pins, because the counters move independently: a metadata update leaves `rosterVersion` alone and a
 * membership change leaves `version` alone, so a single pin over both would refuse legitimate states.
 */
void GroupDataSchemaMapper::assertDataIntegrity(const server::GroupInfo& groupInfo) {
    if (groupInfo.data.empty()) {
        throw UnknownGroupFormatException();
    }
    auto encData = dynamic::EncryptedGroupRosterV5::fromJSON(groupInfo.data.back().data);
    core::DataIntegrityObject dio;
    try {
        dio = _strategyV5->getRosterDIOAndAssertIntegrity(encData);
    } catch (...) { throw GroupDataIntegrityException(); }
    if (dio.contextId != groupInfo.contextId || dio.resourceId != groupInfo.resourceId.value_or("")) {
        throw GroupDataIntegrityException();
    }

    // Compare and store under one lock: two concurrent verifications must not both pass against the same stale
    // pin, or the later one could accept a version older than the one already verified.
    std::lock_guard lock(_pinMutex);
    auto& pinnedRoster = _verifiedRosterVersions[groupInfo.id];
    auto& pinnedMeta = _verifiedMetaVersions[groupInfo.id];
    if (groupInfo.rosterVersion < pinnedRoster || groupInfo.version < pinnedMeta) {
        // A shorter answer than one already seen is a validly tagged *past* state — a rollback, not an error the
        // tag itself can catch, because that older tag was genuine when it was made.
        throw GroupHistoryForkException();
    }
    pinnedRoster = groupInfo.rosterVersion;
    pinnedMeta = groupInfo.version;
}

void GroupDataSchemaMapper::dropVersionPin(const std::string& groupId) {
    std::lock_guard lock(_pinMutex);
    _verifiedRosterVersions.erase(groupId);
    _verifiedMetaVersions.erase(groupId);
}

void GroupDataSchemaMapper::dropAllVersionPins() {
    std::lock_guard lock(_pinMutex);
    _verifiedRosterVersions.clear();
    _verifiedMetaVersions.clear();
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
        .rosterVersion = info.rosterVersion,
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
        .rosterVersion = info.rosterVersion,
        .policy = core::Factory::parsePolicyServerObject(info.policy),
        .type = info.type,
        .keyVersion = info.keyVersion
    };
}

/**
 * Two keys and two identities per group, which is why this does not use `batchValidateDecryptVerifyContainers`.
 *
 * That helper hardcodes `data.back().keyId` as *the* key and issues one verification request against the
 * document's `lastModifier`. Both assumptions break here: the metadata entry has a key of its own, possibly at an
 * older epoch, and its author is whoever last called `updateGroup` — not necessarily whoever last touched the
 * document. Verifying the metadata DIO against `lastModifier` would fail for an honest group.
 *
 * One key request still covers both planes: `addGroupKeys` submits every epoch in `groupKeys`, and the resolver
 * descends the Epoch Ladder per candidate.
 */
std::vector<Group> GroupDataSchemaMapper::validateDecryptAndConvertGroups(
    const std::vector<server::GroupInfo>& groups,
    const std::shared_ptr<core::KeyProvider>& keyProvider,
    const core::KeyProvider::GroupPrivKeyResolver& groupPrivKeyResolver
) {
    if (groups.empty()) {
        return {};
    }
    const auto locationOf = [](const server::GroupInfo& g) -> core::EncKeyLocation {
        return {.contextId = g.contextId, .resourceId = g.resourceId.value_or("")};
    };
    const auto toError = [](const server::GroupInfo& g, uint32_t code) {
        return toLibGroup(g, {}, {}, code, core::ModuleDataSchema::Version::UNKNOWN);
    };

    std::vector<Group> result(groups.size());
    std::vector<core::DataIntegrityObject> metaDios(groups.size());
    std::vector<std::string> metaAuthors(groups.size());
    std::vector<int64_t> metaDates(groups.size());
    std::vector<core::DataIntegrityObject> rosterDios(groups.size());

    for (size_t i = 0; i < groups.size(); i++) {
        if (auto code = validateDataIntegrity(groups[i]); code != 0) {
            result[i] = toError(groups[i], code);
        }
    }

    core::KeyDecryptionAndVerificationRequest keyRequest;
    for (size_t i = 0; i < groups.size(); i++) {
        if (result[i].statusCode != 0) {
            continue;
        }
        keyRequest.addGroupKeys(groups[i].groupKeys, locationOf(groups[i]));
    }
    auto allKeys = keyProvider->getKeysAndVerify(keyRequest, groupPrivKeyResolver);
    std::set<std::string> seenRandomIds;

    for (size_t i = 0; i < groups.size(); i++) {
        if (result[i].statusCode != 0) {
            continue;
        }
        const server::GroupInfo& g = groups[i];
        try {
            auto it = allKeys.find(locationOf(g));
            if (it == allKeys.end()) {
                result[i] = toError(g, ENDPOINT_CORE_EXCEPTION_CODE);
                continue;
            }
            const core::DecryptedEncKey& rosterKey = it->second.at(g.data.back().keyId);
            const core::DecryptedEncKey& metaKey = it->second.at(g.meta.keyId);
            assertRosterIsAttested(g, rosterKey);
            assertMetaIsAttested(g, metaKey);

            // The roster envelope's own DIO, for the duplicate-randomId sweep the metadata plane also feeds.
            auto rosterEnc = dynamic::EncryptedGroupRosterV5::fromJSON(g.data.back().data);
            rosterDios[i] = _strategyV5->getRosterDIOAndAssertIntegrity(rosterEnc);

            auto [lib, dio] = decryptMetaPlane(g, metaKey);
            result[i] = lib;
            metaDios[i] = dio;
            metaAuthors[i] = g.meta.author;
            metaDates[i] = g.meta.created;
            if (dio.creatorUserId != g.meta.author || rosterDios[i].creatorUserId != g.lastModifier) {
                result[i] = toError(g, GroupDataIntegrityException().getCode());
                continue;
            }
            const auto seen = [&](const core::DataIntegrityObject& d) {
                return !seenRandomIds.insert(d.randomId + "-" + std::to_string(d.timestamp)).second;
            };
            if (seen(rosterDios[i]) || seen(metaDios[i])) {
                result[i].statusCode = core::DataIntegrityObjectDuplicatedException().getCode();
            }
        } catch (const core::Exception& e) {
            result[i] = toError(g, e.getCode());
        } catch (const privmx::utils::PrivmxException& e) {
            result[i] = toError(g, core::ExceptionConverter::convert(e).getCode());
        } catch (...) { result[i] = toError(g, ENDPOINT_CORE_EXCEPTION_CODE); }
    }

    // One request per plane per group: the roster entry answers for `lastModifier`, the metadata entry for
    // whoever last wrote metadata. Both must pass for the group to count as verified.
    std::vector<core::VerificationRequest> verifyReqs;
    std::vector<size_t> verifyIdxs;
    for (size_t i = 0; i < result.size(); i++) {
        if (result[i].statusCode != 0) {
            continue;
        }
        verifyReqs.push_back(
            {.contextId = result[i].contextId,
             .senderId = result[i].lastModifier,
             .senderPubKey = rosterDios[i].creatorPubKey,
             .date = result[i].lastModificationDate,
             .bridgeIdentity = rosterDios[i].bridgeIdentity}
        );
        verifyIdxs.push_back(i);
        verifyReqs.push_back(
            {.contextId = result[i].contextId,
             .senderId = metaAuthors[i],
             .senderPubKey = metaDios[i].creatorPubKey,
             .date = metaDates[i],
             .bridgeIdentity = metaDios[i].bridgeIdentity}
        );
        verifyIdxs.push_back(i);
    }
    auto verified = _connection.getImpl()->getUserVerifier()->verify(verifyReqs);
    for (size_t j = 0; j < verifyIdxs.size(); j++) {
        if (!verified[j]) {
            result[verifyIdxs[j]].statusCode = core::UserVerificationFailureException().getCode();
        }
    }
    return result;
}

core::ModuleInternalMetaV5 GroupDataSchemaMapper::decryptInternalMeta(
    const Poco::Dynamic::Var& data,
    const core::DecryptedEncKey& encKey
) {
    if (encKey.statusCode != 0)
        return {};
    try {
        // Either envelope: `internalMeta` is the one field both carry, under the same encoding.
        auto encData = dynamic::EncryptedGroupInternalMetaViewV5::fromJSON(data);
        if (encData.version != core::ModuleDataSchema::Version::VERSION_5)
            return {};
        auto raw = _dataEncryptor.decodeAndDecryptAndVerify(
            encData.internalMeta, privmx::crypto::PublicKey::fromBase58DER(encData.authorPubKey), encKey.key
        );
        auto parsed = core::dynamic::ModuleInternalMetaV5::fromJSON(
            privmx::utils::Utils::parseJsonObject(raw.stdString())
        );
        return core::ModuleInternalMetaV5{
            .secret = parsed.secret, .resourceId = parsed.resourceId, .randomId = parsed.randomId
        };
    } catch (...) { return {}; }
}

Group GroupDataSchemaMapper::validateDecryptAndConvertGroup(
    const server::GroupInfo& groupInfo,
    const std::shared_ptr<core::KeyProvider>& keyProvider,
    const core::KeyProvider::GroupPrivKeyResolver& groupPrivKeyResolver
) {
    return validateDecryptAndConvertGroups({groupInfo}, keyProvider, groupPrivKeyResolver)[0];
}

std::pair<std::vector<std::string>, std::vector<std::string>> GroupDataSchemaMapper::validateAndGetAttestedRoster(
    const server::GroupInfo& groupInfo,
    const std::shared_ptr<core::KeyProvider>& keyProvider,
    const core::KeyProvider::GroupPrivKeyResolver& groupPrivKeyResolver
) {
    assertDataIntegrity(groupInfo);
    const core::EncKeyLocation location{
        .contextId = groupInfo.contextId, .resourceId = groupInfo.resourceId.value_or("")
    };
    core::KeyDecryptionAndVerificationRequest keyRequest;
    keyRequest.addGroupKeys(groupInfo.groupKeys, location);
    auto allKeys = keyProvider->getKeysAndVerify(keyRequest, groupPrivKeyResolver);
    auto it = allKeys.find(location);
    if (it == allKeys.end() || groupInfo.data.empty()) {
        throw GroupMembershipMismatchException();
    }
    assertRosterIsAttested(groupInfo, it->second.at(groupInfo.data.back().keyId));
    return {groupInfo.users, groupInfo.managers};
}
