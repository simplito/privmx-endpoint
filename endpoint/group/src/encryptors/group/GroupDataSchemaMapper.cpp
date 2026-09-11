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

/**
 * Both metadata planes, merged into one lib object.
 *
 * No `VersionStrategyMapper` here, unlike every other container: `core::TypedDataSchemaStrategyV5` routes one
 * envelope under one key and declares `decrypt` final, and a group needs two envelopes under two keys that may
 * sit at different epochs. The version guard it used to provide is the explicit check below, and it now covers
 * both entries rather than only the one the strategy was bound to.
 *
 * Its key-unavailable fallback is not reproduced, because for a group it was already unreachable: both planes
 * are attested before this runs, and attestation throws on a key it could not get.
 */
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
        rosterKey.key, membership.keyVersion, membership.rosterVersion, groupInfo.users, groupInfo.managers
    );
    if (expected != membership.rosterTag) {
        throw GroupMembershipMismatchException();
    }
    if (membership.keyVersion != groupInfo.keyVersion) {
        throw GroupDataIntegrityException();
    }
    // The counter the monotone pin checks, tied to the roster it labels. Without this the bridge could serve
    // the current version beside an earlier same-epoch roster — every one of which has a genuine tag, since an
    // addition only ever grows the roster — and conceal whoever was added in between.
    if (membership.rosterVersion != groupInfo.rosterVersion) {
        throw GroupMembershipMismatchException();
    }
}

/**
 * The public metadata entry the bridge served is the one an updater wrote, at the version they wrote it at.
 *
 * `keyVersion` may legitimately lag the group's current epoch — that is the point of leaving metadata where it
 * was written — but it can never lead it, which would name a key that does not exist yet.
 *
 * The two planes carry the same `MetaBlock` shape, so what keeps one from being served in the other's position
 * is the domain-separated tag, plus the parse below: the private plane's envelope has no `publicMeta` field and
 * deserialisation refuses it outright.
 */
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
    // What is NOT checked here, because a reader cannot check it: that the author still holds the group. This
    // goes for either metadata plane. A member removed at epoch N keeps the content key the entry sitting at
    // epoch N was tagged under, and a lagging `keyVersion` is legitimate, so with a colluding bridge they could
    // author a new entry at epoch N after leaving — the tag is genuine, `creatorUserId` matches `author` because
    // they signed the DIO, and the verifier still knows them as a context user. Checking `author` against the
    // current roster does not fix it: a former member is the *expected* author of an entry written before they
    // left, so that check would refuse honest groups (pinned by
    // `AMetadataEntryWrittenByASinceRemovedMemberStillVerifies`).
    //
    // Nothing inside epoch N can order "written during N" against "written after N ended". So the fix lives on
    // the write side instead: `refreshMetadataEpochAfterRemoval` moves both entries up to the new epoch once a
    // removal has committed, which puts their tags under a key the departed member never had. Best-effort, so a
    // lagging entry is still a state a reader must accept — it just stops being a state a removal leaves behind.
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
    // The domain prefix in the payload is therefore redundant, and kept anyway: it makes the preimage say what
    // it is without having to know which key signed it.
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

/**
 * Head-entry integrity, and nothing about either tag.
 *
 * There is no chain to walk any more: a membership change commits `rosterTag`, which a reader checks against the
 * key it already holds. What is left here is what a reader needs before trusting the head's *content* — the DIO
 * signature and its field checksums — plus the monotone version pins, which are the one thing a per-entry tag
 * cannot do on its own: without them a bridge could serve an older, correctly tagged state.
 *
 * Three pins, because the counters move independently: a public-metadata write moves only its own counter, and
 * so does each of the other two, so a single pin over all of them would refuse legitimate states.
 */
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

/**
 * Three keys and three identities per group, which is why this does not use
 * `batchValidateDecryptVerifyContainers`.
 *
 * That helper hardcodes `data.back().keyId` as *the* key and issues one verification request against the
 * document's `lastModifier`. Both assumptions break here: each metadata plane has a key of its own, possibly at
 * an older epoch and possibly not the same epoch as the other plane's, and each plane's author is whoever last
 * wrote *that* plane — not necessarily whoever last touched the document. Verifying a metadata DIO against
 * `lastModifier` would fail for an honest group.
 *
 * One key request still covers all three planes: `addGroupKeys` submits every epoch in `groupKeys`, and the
 * resolver descends the Epoch Ladder per candidate.
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
            // Three key lookups, and the two metadata ones may resolve different epochs at different ladder
            // depths. `find` rather than `at`: an absent key here is a legible status, not an out_of_range
            // escaping into the catch-all below as a bare internal error.
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
            // Each plane's DIO answers for whoever wrote *that* plane. The roster's author is the head entry's,
            // not the document's `lastModifier`: that field moves on any write, so once metadata has its own
            // methods a metadata write by anyone but the last roster author would fail this check on an
            // otherwise honest group. `history` is non-empty here — `assertDataIntegrity` refuses it otherwise.
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
        // The roster head's author and its own timestamp, for the same reason the integrity check above uses
        // them: `lastModifier`/`lastModificationDate` describe the document's last write of any kind, so
        // verifying the roster DIO against them asks the wrong identity as soon as a metadata write lands last.
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
        // The signed DIO, not just a signature over the field. What comes out of here is the container's
        // `secret` — `prepareContainerUpdate` feeds it to `verifyKeysSecret` and binds new key entries to it —
        // so it has to stay tied to the identity, context and resource the DIO commits to. Verifying only the
        // field against the envelope's own `authorPubKey` would let a holder of the epoch key restate it under
        // a keypair bound to nothing.
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
