/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include "privmx/endpoint/group/GroupMetadata.hpp"

#include <algorithm>
#include <mutex>

#include <privmx/endpoint/core/ConnectionImpl.hpp>
#include <privmx/endpoint/core/EndpointUtils.hpp>

#include "privmx/endpoint/group/CommitEngine.hpp"
#include "privmx/endpoint/group/GroupException.hpp"
#include "privmx/utils/Logger.hpp"

using namespace privmx::endpoint;
using namespace group;

dynamic::MembershipBlock group::buildMembershipBlock(
    const core::EncKey& key,
    const std::string& groupPubKey,
    int64_t keyVersion,
    int64_t rosterVersion,
    const std::vector<core::UserWithPubKey>& users,
    const std::vector<core::UserWithPubKey>& managers
) {
    return dynamic::MembershipBlock{
        .rosterTag = GroupDataSchemaMapper::rosterTag(
            key.key, keyVersion, rosterVersion, core::EndpointUtils::usersWithPubKeyToIds(users),
            core::EndpointUtils::usersWithPubKeyToIds(managers)
        ),
        .groupPubKey = groupPubKey,
        .keyId = key.id,
        .keyVersion = keyVersion,
        .rosterVersion = rosterVersion
    };
}

RosterAfterChange group::rosterFromUserIds(
    const std::vector<std::string>& users,
    const std::vector<std::string>& managers
) {
    const auto toBare = [](const std::vector<std::string>& ids) {
        std::vector<core::UserWithPubKey> bare;
        for (const std::string& id : ids) {
            bare.push_back(core::UserWithPubKey{.userId = id, .pubKey = std::string()});
        }
        return bare;
    };
    return RosterAfterChange{.users = toBare(users), .managers = toBare(managers)};
}

PriorRole group::priorOf(const server::GroupInfo& group) {
    return PriorRole{
        .rules = rulesOf(group),
        .users = group.users,
        .managers = group.managers,
        .publicMeta = group.publicMeta,
        .privateMeta = group.privateMeta
    };
}

NewEpochRoster GroupMetadata::sealRosterForNewEpoch(
    const server::GroupInfo& currentGroup,
    const RosterAfterChange& roster,
    const std::string& newGroupPubKeyStr,
    int64_t newEpoch,
    int64_t newRosterVersion,
    bool abandonHistory
) const {
    const std::string& groupId = currentGroup.id;
    const auto resourceId = currentGroup.resourceId.value_or(core::EndpointUtils::generateId());
    // Nothing old may stay readable once history is abandoned, and the old key and secret cannot be opened anyway:
    // both start fresh, as at creation.
    auto ctx = abandonHistory ?
        core::ContainerUpdateContext{
            .location = {.contextId = currentGroup.contextId, .resourceId = resourceId},
            .key = keyProvider->generateKey(),
            .dio = deps.connection.getImpl()->createDIO(currentGroup.contextId, resourceId),
            .secret = keyProvider->generateSecret(),
            .keyEntries = {}
        } :
        deps.facade.prepareUpdate(currentGroup, resourceId, roster, true);
    const auto selfAddressedKey = deps.facade.buildGroupKeyEntries(
        {core::GroupGrantWithKey{
            .groupId = groupId,
            .role = "manager",
            .groupPubKey = newGroupPubKeyStr,
            .groupEpoch = newEpoch,
        }},
        ctx.key, ctx.dio, currentGroup.contextId, resourceId, ctx.secret
    );

    // Roster plane only — the metadata entry is not part of this write. `carryMetadataForward`
    // carries it up to the new epoch once this has committed; see its header for why that is a second call.
    GroupRosterToEncryptV5 rosterToEncrypt{
        .internalMeta = core::
            ModuleInternalMetaV5{.secret = ctx.secret, .resourceId = resourceId, .randomId = ctx.dio.randomId},
        .dio = ctx.dio,
        .membership = buildMembershipBlock(
            ctx.key, newGroupPubKeyStr, newEpoch, newRosterVersion, roster.users, roster.managers
        )
    };

    return NewEpochRoster{
        .keyId = ctx.key.id,
        .data = mapper.encryptRoster(rosterToEncrypt, ctx.key.key),
        .groupKeys = selfAddressedKey.at(0)
    };
}

bool GroupMetadata::carryMetadataForward(
    const std::string& groupId,
    CarryScope scope,
    bool historyAbandoned,
    const std::vector<std::string>& losers,
    const PriorRole& prior
) const {
    try {
        // One verified answer decides both whether a plane is carried and what it says: re-signing metadata this
        // client has not attested would launder whatever the bridge served into an entry under the committer's name,
        // and an unverified epoch would let the bridge talk this out of running.
        const VerifiedGroup verified = deps.facade.readForKeys(groupId);
        const server::GroupInfo& group = *verified;
        bool carryPublic = false;
        bool carryPrivate = false;
        if (scope == CarryScope::NewEpoch) {
            // Per plane, because the two sit at epochs of their own: one may already have been carried up by a
            // concurrent write while the other is still behind.
            carryPublic = group.publicMeta.keyVersion < group.keyVersion;
            carryPrivate = group.privateMeta.keyVersion < group.keyVersion;
            if (historyAbandoned) {
                // A plane behind sits under a key nobody can reach any more, and what it says cannot be attested:
                // start it over, empty, in the new epoch rather than leave it unreadable for good.
                if (carryPublic) {
                    writeMeta(verified, true, core::Buffer(), group.publicMetaVersion);
                }
                if (carryPrivate) {
                    writeMeta(verified, false, core::Buffer(), group.privateMetaVersion);
                }
                return true;
            }
        } else {
            const auto lost = [&](const std::string& author) {
                return std::find(losers.begin(), losers.end(), author) != losers.end();
            };
            carryPublic = lost(group.publicMeta.author);
            carryPrivate = lost(group.privateMeta.author);
        }
        // On every carried plane: only the very entry read before the commit. One tagged since (by a member
        // removed meanwhile, or by a loser of a narrowing, which still holds the current key) is never re-signed.
        carryPublic = carryPublic && GroupDataSchemaMapper::sameEntry(group.publicMeta, prior.publicMeta);
        carryPrivate = carryPrivate && GroupDataSchemaMapper::sameEntry(group.privateMeta, prior.privateMeta);
        if (!carryPublic && !carryPrivate) {
            return true; // already current, or written over since: nothing of the read is left to carry
        }
        // The entries as read are judged by the read's rules and roster: a plane whose author lacked `update`
        // then is refused here too, so neither a removal nor a narrowing launders it.
        const Group opened = mapper.validateDecryptAndConvertGroup(
            group, keyProvider, keys.resolverOver(&verified), prior
        );
        if (opened.statusCode != 0) {
            return false;
        }
        // One write per carried plane, both off the one verified read: a metadata write moves neither the head nor
        // the epoch it is checked against.
        if (carryPublic) {
            writeMeta(verified, true, opened.publicMeta, opened.publicMetaVersion);
        }
        if (carryPrivate) {
            writeMeta(verified, false, opened.privateMeta, opened.privateMetaVersion);
        }
        return true;
    } catch (const std::exception& e) {
        // Best-effort by design. A failure leaves the planes where the commit left them, and the next metadata write
        // closes the window; throwing here would fail a commit that has already happened.
        LOG_WARN("[carryMetadataForward] group ", groupId, " metadata not carried forward: ", e.what())
        return false;
    } catch (...) {
        LOG_WARN("[carryMetadataForward] group ", groupId, " metadata not carried forward")
        return false;
    }
}

void GroupMetadata::runPolicyCarry(const std::string& groupId, const PendingCarry& carry) const {
    const bool done = carryMetadataForward(groupId, CarryScope::Policy, false, carry.losers, carry.prior);
    const auto session = deps.sessions.of(groupId);
    std::lock_guard<std::mutex> lock(session->mutex);
    if (done) {
        session->pendingCarry.reset();
    } else {
        session->pendingCarry = carry;
    }
}

void GroupMetadata::retryPendingCarry(const std::string& groupId) const {
    std::optional<PendingCarry> pending;
    {
        const auto session = deps.sessions.find(groupId);
        if (!session) {
            return;
        }
        std::lock_guard<std::mutex> lock(session->mutex);
        if (!session->pendingCarry.has_value()) {
            return;
        }
        pending = session->pendingCarry;
    }
    runPolicyCarry(groupId, pending.value());
}

MetaWriteContext GroupMetadata::prepareMetaWrite(const VerifiedGroup& verified) const {
    const server::GroupInfo& currentGroup = *verified;
    const auto& currentEntry = currentGroup.data.back();
    const auto resourceId = currentGroup.resourceId.value_or(core::EndpointUtils::generateId());
    const int64_t currentEpoch = currentGroup.keyVersion;

    // Names no diff, so `UsersKeysResolver` sees no reason to mint a key: the pub keys are deliberately empty
    // because nothing here is wrapped to anybody.
    const auto roster = rosterFromUserIds(currentGroup.users, currentGroup.managers);
    auto ctx = deps.facade.prepareUpdate(currentGroup, resourceId, roster, false);

    // The roster head always sits at the current epoch, so the key selected off it is the current epoch's.
    // Were that to stop holding, metadata would be written under a key a removed member still holds.
    if (ctx.key.id != currentEntry.keyId) {
        throw GroupDataIntegrityException("metadata write resolved a key that is not the current epoch's");
    }
    return MetaWriteContext{.resourceId = resourceId, .currentEpoch = currentEpoch, .ctx = ctx};
}

void GroupMetadata::writeMeta(
    const VerifiedGroup& currentGroup,
    bool publicPlane,
    const core::Buffer& meta,
    const int64_t version
) const {
    const auto w = prepareMetaWrite(currentGroup);
    // The same `version` feeds the CAS field below, so the version this commits to and the version the bridge checks
    // cannot disagree.
    const dynamic::MetaBlock block{
        .metaTag = (publicPlane ? GroupDataSchemaMapper::publicMetaTag : GroupDataSchemaMapper::privateMetaTag)(
            w.ctx.key.key, w.currentEpoch, version + 1
        ),
        .keyId = w.ctx.key.id,
        .keyVersion = w.currentEpoch,
        .metaVersion = version + 1
    };
    // No force field, unlike the other containers: the entry commits the version it lands at, so a write that
    // skipped the version check could only land a tag no reader will accept.
    const auto fill = [&](auto& model) {
        model.id = currentGroup->id;
        model.resourceId = w.resourceId;
        model.keyId = w.ctx.key.id;
        model.version = version;
    };
    // A metadata write is never answered with `ROTATED_ALREADY` (that is the commits'); a version conflict is the
    // caller's to re-read, like any other.
    if (publicPlane) {
        server::GroupUpdatePublicMetaModel model;
        fill(model);
        model.data = mapper.encryptPublicMeta(
            GroupPublicMetaToEncryptV5{.publicMeta = meta, .dio = w.ctx.dio, .meta = block}
        );
        deps.serverApi.groupUpdatePublicMeta(model);
    } else {
        server::GroupUpdatePrivateMetaModel model;
        fill(model);
        model.data = mapper.encryptPrivateMeta(
            GroupPrivateMetaToEncryptV5{.privateMeta = meta, .dio = w.ctx.dio, .meta = block}, w.ctx.key.key
        );
        deps.serverApi.groupUpdatePrivateMeta(model);
    }
    // Rotates nothing — not the content key, not the grant key, not the tree. Only the cached view is stale.
    deps.facade.invalidateModuleKeys(currentGroup->id);
}
