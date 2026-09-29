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
    : core::BaseModuleDataSchemaMapper(userPrivKey, connection) {}

Poco::Dynamic::Var GroupDataSchemaMapper::encryptPublicMeta(const GroupPublicMetaToEncryptV5& data) {
    return _groupEncryptor.encryptPublicMeta(data, _userPrivKey).toJSON();
}

Poco::Dynamic::Var GroupDataSchemaMapper::encryptPrivateMeta(
    const GroupPrivateMetaToEncryptV5& data,
    const std::string& key
) {
    return _groupEncryptor.encryptPrivateMeta(data, _userPrivKey, key).toJSON();
}

Poco::Dynamic::Var GroupDataSchemaMapper::encryptRoster(const GroupRosterToEncryptV5& data, const std::string& key) {
    return _groupEncryptor.encryptRoster(data, _userPrivKey, key).toJSON();
}

// No `VersionStrategyMapper` here, unlike every other container: it routes one envelope under one key, and a
// group needs two that may sit at different epochs. Its version guard is the explicit check below.
std::tuple<Group, core::DataIntegrityObject, core::DataIntegrityObject> GroupDataSchemaMapper::decryptMetaPlanes(
    const server::GroupInfo& groupInfo,
    const core::DecryptedEncKey& privateMetaKey
) {
    if (getDataStructureVersion(groupInfo.publicMeta) != core::ModuleDataSchema::Version::VERSION_5 ||
        getDataStructureVersion(groupInfo.privateMeta) != core::ModuleDataSchema::Version::VERSION_5) {
        return {
            toLibGroup(
                groupInfo, {}, {}, UnknownGroupFormatException().getCode(), core::ModuleDataSchema::Version::UNKNOWN
            ),
            {},
            {}
        };
    }
    // The public plane opens without a key — nothing in it is encrypted — so a caller who cannot reach the
    // private plane's key still gets `publicMeta` back, alongside the non-zero status that says so.
    auto publicPlane = _groupEncryptor.extractPublicMeta(
        dynamic::EncryptedGroupPublicMetaV5::fromJSON(groupInfo.publicMeta.data)
    );
    auto privatePlane = _groupEncryptor.decryptPrivateMeta(
        dynamic::EncryptedGroupPrivateMetaV5::fromJSON(groupInfo.privateMeta.data), privateMetaKey.key
    );
    // Either plane failing marks the whole Group unverified; the plane that did open still returns its buffer.
    const int64_t statusCode = publicPlane.statusCode != 0 ? publicPlane.statusCode : privatePlane.statusCode;
    return {
        toLibGroup(
            groupInfo, publicPlane.publicMeta, privatePlane.privateMeta, statusCode,
            core::ModuleDataSchema::Version::VERSION_5
        ),
        publicPlane.dio, privatePlane.dio
    };
}

// Checked here rather than in `assertDataIntegrity` because it needs the epoch's content key. A missing key
// is a failure, not a pass: if the metadata opened, the roster must attest.
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
        rosterKey.key, membership.keyVersion, membership.rosterVersion, groupInfo.users, groupInfo.managers
    );
    if (expected != membership.rosterTag) {
        throw GroupMembershipMismatchException();
    }
    if (membership.keyVersion != groupInfo.keyVersion) {
        throw GroupDataIntegrityException();
    }
    // The counter the monotone pin checks, tied to the roster it labels. Without it the bridge could serve the
    // current version beside an earlier same-epoch roster and conceal whoever was added in between.
    if (membership.rosterVersion != groupInfo.rosterVersion) {
        throw GroupMembershipMismatchException();
    }
}

// `keyVersion` may legitimately lag the group's current epoch, but never lead it. What keeps the other plane
// from being served here is the domain-separated tag, plus a parse that refuses an envelope with no `publicMeta`.
void GroupDataSchemaMapper::assertPublicMetaIsAttested(
    const server::GroupInfo& groupInfo,
    const core::DecryptedEncKey& publicMetaKey
) {
    if (publicMetaKey.statusCode != 0) {
        throw GroupMembershipMismatchException();
    }
    dynamic::EncryptedGroupPublicMetaV5 encData;
    try {
        encData = dynamic::EncryptedGroupPublicMetaV5::fromJSON(groupInfo.publicMeta.data);
    } catch (...) { throw GroupMembershipMismatchException(); }
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
    if (meta.keyId != groupInfo.publicMeta.keyId ||
        meta.keyVersion != groupInfo.publicMeta.keyVersion ||
        meta.keyVersion > groupInfo.keyVersion) {
        throw GroupMembershipMismatchException();
    }
    const std::string expected = publicMetaTag(
        publicMetaKey.key, groupInfo.publicMeta.keyVersion, groupInfo.publicMeta.version
    );
    if (expected != meta.metaTag) {
        throw GroupMembershipMismatchException();
    }
    // Without this a bridge could serve a stale entry under a rising counter — a content downgrade the monotone
    // pin cannot see, because the counter it checks keeps going up.
    if (meta.metaVersion != groupInfo.publicMetaVersion) {
        throw GroupMembershipMismatchException();
    }
    // Not checked, because a reader cannot: that the author still holds the group. Nothing inside epoch N
    // orders "written during N" against "written after N ended" — `refreshMetadataEpochAfterRemoval` is the fix.
}

// The private plane's counterpart, against its own entry, its own tag domain and its own counter. The epoch
// caveat documented at the end of `assertPublicMetaIsAttested` applies here unchanged.
void GroupDataSchemaMapper::assertPrivateMetaIsAttested(
    const server::GroupInfo& groupInfo,
    const core::DecryptedEncKey& privateMetaKey
) {
    if (privateMetaKey.statusCode != 0) {
        throw GroupMembershipMismatchException();
    }
    dynamic::EncryptedGroupPrivateMetaV5 encData;
    try {
        encData = dynamic::EncryptedGroupPrivateMetaV5::fromJSON(groupInfo.privateMeta.data);
    } catch (...) { throw GroupMembershipMismatchException(); }
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
    if (meta.keyId != groupInfo.privateMeta.keyId ||
        meta.keyVersion != groupInfo.privateMeta.keyVersion ||
        meta.keyVersion > groupInfo.keyVersion) {
        throw GroupMembershipMismatchException();
    }
    const std::string expected = privateMetaTag(
        privateMetaKey.key, groupInfo.privateMeta.keyVersion, groupInfo.privateMeta.version
    );
    if (expected != meta.metaTag) {
        throw GroupMembershipMismatchException();
    }
    // Without this a bridge could serve a stale entry under a rising counter — a content downgrade the monotone
    // pin cannot see, because the counter it checks keeps going up.
    if (meta.metaVersion != groupInfo.privateMetaVersion) {
        throw GroupMembershipMismatchException();
    }
}

std::string GroupDataSchemaMapper::rosterTag(
    const std::string& key,
    int64_t keyVersion,
    int64_t rosterVersion,
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
    std::string payload = std::to_string(keyVersion) + "\n" + std::to_string(rosterVersion) + "\n";
    appendList(payload, users);
    appendList(payload, managers);
    return privmx::utils::Hex::from(privmx::crypto::Crypto::hmacSha256(tagSubkey(key, "roster-tag"), payload));
}

std::string GroupDataSchemaMapper::metaPlaneTag(
    const char* domain,
    const std::string& key,
    int64_t keyVersion,
    int64_t metaVersion
) {
    // Each plane gets its own subkey, so separation does not rest on the preimages happening to be disjoint.
    // The domain prefix is redundant, and kept anyway: it makes the preimage say what it is.
    const std::string payload = std::string(domain) +
        "\n" +
        std::to_string(keyVersion) +
        "\n" +
        std::to_string(metaVersion) +
        "\n";
    return privmx::utils::Hex::from(
        privmx::crypto::Crypto::hmacSha256(tagSubkey(key, std::string(domain) + "-tag"), payload)
    );
}

std::string GroupDataSchemaMapper::tagSubkey(const std::string& contentKey, const std::string& purpose) {
    return privmx::crypto::Crypto::kdf(32, contentKey, "privmx/group/" + purpose);
}

std::string GroupDataSchemaMapper::publicMetaTag(const std::string& key, int64_t keyVersion, int64_t metaVersion) {
    return metaPlaneTag("publicMeta", key, keyVersion, metaVersion);
}

std::string GroupDataSchemaMapper::privateMetaTag(const std::string& key, int64_t keyVersion, int64_t metaVersion) {
    return metaPlaneTag("privateMeta", key, keyVersion, metaVersion);
}

// Head-entry integrity only: the DIO signature and field checksums, plus the monotone version pins that a
// per-entry tag cannot provide. Three pins, because the three counters move independently.
void GroupDataSchemaMapper::assertDataIntegrity(const server::GroupInfo& groupInfo) {
    // `history` is the same set of entries `data` is projected from, so the head of one is the head of the
    // other — and the roster plane's author comes out of `history`.
    if (groupInfo.data.empty() || groupInfo.history.empty()) {
        throw UnknownGroupFormatException();
    }
    auto encData = dynamic::EncryptedGroupRosterV5::fromJSON(groupInfo.data.back().data);
    core::DataIntegrityObject dio;
    try {
        dio = _groupEncryptor.getRosterDIOAndAssertIntegrity(encData);
    } catch (...) { throw GroupDataIntegrityException(); }
    if (dio.contextId != groupInfo.contextId || dio.resourceId != groupInfo.resourceId.value_or("")) {
        throw GroupDataIntegrityException();
    }

    // Compare and store under one lock: two concurrent verifications must not both pass against the same stale
    // pin, or the later one could accept a version older than the one already verified.
    std::lock_guard lock(_pinMutex);
    auto& pinnedRoster = _verifiedRosterVersions[groupInfo.id];
    auto& pinnedPublicMeta = _verifiedPublicMetaVersions[groupInfo.id];
    auto& pinnedPrivateMeta = _verifiedPrivateMetaVersions[groupInfo.id];
    if (groupInfo.rosterVersion < pinnedRoster ||
        groupInfo.publicMetaVersion < pinnedPublicMeta ||
        groupInfo.privateMetaVersion < pinnedPrivateMeta) {
        // A shorter answer than one already seen is a validly tagged *past* state — a rollback, not an error the
        // tag itself can catch, because that older tag was genuine when it was made.
        throw GroupHistoryForkException();
    }
    pinnedRoster = groupInfo.rosterVersion;
    pinnedPublicMeta = groupInfo.publicMetaVersion;
    pinnedPrivateMeta = groupInfo.privateMetaVersion;
}

void GroupDataSchemaMapper::dropVersionPin(const std::string& groupId) {
    std::lock_guard lock(_pinMutex);
    _verifiedRosterVersions.erase(groupId);
    _verifiedPublicMetaVersions.erase(groupId);
    _verifiedPrivateMetaVersions.erase(groupId);
}

void GroupDataSchemaMapper::dropAllVersionPins() {
    std::lock_guard lock(_pinMutex);
    _verifiedRosterVersions.clear();
    _verifiedPublicMetaVersions.clear();
    _verifiedPrivateMetaVersions.clear();
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
        .publicMetaVersion = info.publicMetaVersion,
        .privateMetaVersion = info.privateMetaVersion,
        .rosterVersion = info.rosterVersion,
        .publicMeta = publicMeta,
        .privateMeta = privateMeta,
        .policy = core::Factory::parsePolicyServerObject(info.policy),
        .statusCode = statusCode,
        .schemaVersion = schemaVersion,
        .type = info.type,
        .keyVersion = info.keyVersion
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
        .publicMetaVersion = info.publicMetaVersion,
        .privateMetaVersion = info.privateMetaVersion,
        .rosterVersion = info.rosterVersion,
        .policy = core::Factory::parsePolicyServerObject(info.policy),
        .type = info.type,
        .keyVersion = info.keyVersion
    };
}

// Three keys and three identities per group, so `batchValidateDecryptVerifyContainers` does not fit: it
// hardcodes one key and verifies against the document's `lastModifier`, which no plane here need match.
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
    std::vector<core::DataIntegrityObject> publicMetaDios(groups.size());
    std::vector<core::DataIntegrityObject> privateMetaDios(groups.size());
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
            // Three key lookups; the two metadata ones may resolve different epochs. `find` rather than `at`,
            // so an absent key is a legible status, not an out_of_range escaping as a bare internal error.
            const auto keyOf = [&](const std::string& keyId) -> const core::DecryptedEncKey* {
                auto found = it->second.find(keyId);
                return found == it->second.end() ? nullptr : &found->second;
            };
            const core::DecryptedEncKey* rosterKey = keyOf(g.data.back().keyId);
            const core::DecryptedEncKey* publicMetaKey = keyOf(g.publicMeta.keyId);
            const core::DecryptedEncKey* privateMetaKey = keyOf(g.privateMeta.keyId);
            if (rosterKey == nullptr || publicMetaKey == nullptr || privateMetaKey == nullptr) {
                result[i] = toError(g, GroupMembershipMismatchException().getCode());
                continue;
            }
            assertRosterIsAttested(g, *rosterKey);
            assertPublicMetaIsAttested(g, *publicMetaKey);
            assertPrivateMetaIsAttested(g, *privateMetaKey);

            // The roster envelope's own DIO, for the duplicate-randomId sweep both metadata planes also feed.
            auto rosterEnc = dynamic::EncryptedGroupRosterV5::fromJSON(g.data.back().data);
            rosterDios[i] = _groupEncryptor.getRosterDIOAndAssertIntegrity(rosterEnc);

            auto [lib, publicDio, privateDio] = decryptMetaPlanes(g, *privateMetaKey);
            result[i] = lib;
            publicMetaDios[i] = publicDio;
            privateMetaDios[i] = privateDio;
            // Each plane's DIO answers for whoever wrote that plane, so the roster's author is the head
            // entry's, not the document's `lastModifier`, which moves on any write.
            if (publicDio.creatorUserId != g.publicMeta.author ||
                privateDio.creatorUserId != g.privateMeta.author ||
                rosterDios[i].creatorUserId != g.history.back().author) {
                result[i] = toError(g, GroupDataIntegrityException().getCode());
                continue;
            }
            const auto seen = [&](const core::DataIntegrityObject& d) {
                return !seenRandomIds.insert(d.randomId + "-" + std::to_string(d.timestamp)).second;
            };
            // Three distinct signed objects, so `createGroup` must mint three distinct randomIds — otherwise a
            // group's own entries look like one entry served repeatedly.
            if (seen(rosterDios[i]) || seen(publicMetaDios[i]) || seen(privateMetaDios[i])) {
                result[i].statusCode = core::DataIntegrityObjectDuplicatedException().getCode();
            }
        } catch (const core::Exception& e) {
            result[i] = toError(g, e.getCode());
        } catch (const privmx::utils::PrivmxException& e) {
            result[i] = toError(g, core::ExceptionConverter::convert(e).getCode());
        } catch (...) { result[i] = toError(g, ENDPOINT_CORE_EXCEPTION_CODE); }
    }

    // One request per plane per group, each against the author of that plane's own head entry. All three must
    // pass for the group to count as verified.
    std::vector<core::VerificationRequest> verifyReqs;
    std::vector<size_t> verifyIdxs;
    for (size_t i = 0; i < result.size(); i++) {
        if (result[i].statusCode != 0) {
            continue;
        }
        const server::GroupInfo& g = groups[i];
        // The roster head's author and timestamp: `lastModifier`/`lastModificationDate` describe the document's
        // last write of any kind, so verifying against them asks the wrong identity after a metadata write.
        verifyReqs.push_back(
            {.contextId = result[i].contextId,
             .senderId = g.history.back().author,
             .senderPubKey = rosterDios[i].creatorPubKey,
             .date = g.history.back().created,
             .bridgeIdentity = rosterDios[i].bridgeIdentity}
        );
        verifyIdxs.push_back(i);
        verifyReqs.push_back(
            {.contextId = result[i].contextId,
             .senderId = g.publicMeta.author,
             .senderPubKey = publicMetaDios[i].creatorPubKey,
             .date = g.publicMeta.created,
             .bridgeIdentity = publicMetaDios[i].bridgeIdentity}
        );
        verifyIdxs.push_back(i);
        verifyReqs.push_back(
            {.contextId = result[i].contextId,
             .senderId = g.privateMeta.author,
             .senderPubKey = privateMetaDios[i].creatorPubKey,
             .date = g.privateMeta.created,
             .bridgeIdentity = privateMetaDios[i].bridgeIdentity}
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
        // The roster envelope: it is the only plane that carries `internalMeta`, and the only one every caller
        // of this hands over — a metadata entry has no module identity of its own to read.
        auto encData = dynamic::EncryptedGroupInternalMetaViewV5::fromJSON(data);
        if (encData.version != core::ModuleDataSchema::Version::VERSION_5)
            return {};
        // The signed DIO, not just a signature over the field: this yields the container's `secret`, which
        // must stay tied to the identity, context and resource the DIO commits to.
        auto dio = _DIOEncryptor.decodeAndVerify(encData.dio);
        if (dio.creatorPubKey != encData.authorPubKey ||
            dio.fieldChecksums.at("internalMeta") != privmx::crypto::Crypto::sha256(encData.internalMeta)) {
            return {};
        }
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
