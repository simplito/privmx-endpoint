/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

// Spaces: one symmetric key, in versions, wrapped for several groups and users. The Bridge stores the wraps and
// nothing else; everything a reader relies on is checked here.
//
// What is and is not established:
// - A version of the key is taken only from a wrap signed by a user the UserVerifier vouches for, for this Space,
//   this version and this recipient. The Bridge cannot plant a key of its own.
// - The list of recipients is the Bridge's word, as a container's list of users is. Before a key is wrapped to a
//   recipient, a group's key is read off its latest verified statement and a user's key goes to the UserVerifier.
// - Whether an author still had access is not something the key shows: see `SpaceOrigin::authorAccess`.

#include <algorithm>
#include <set>

#include <privmx/crypto/Crypto.hpp>
#include <privmx/endpoint/core/CoreException.hpp>
#include <privmx/endpoint/core/EndpointUtils.hpp>
#include <privmx/utils/Utils.hpp>

#include "privmx/endpoint/core/ListQueryMapper.hpp"
#include "privmx/endpoint/core/Validator.hpp"
#include "privmx/endpoint/group/GroupApiImpl.hpp"
#include "privmx/endpoint/group/GroupException.hpp"
#include "privmx/endpoint/group/keytree/TreeCommits.hpp"
#include "privmx/utils/Logger.hpp"

using namespace privmx::endpoint;
using namespace privmx::endpoint::group;

namespace {

// A Space's private metadata is an envelope of the Space with a content kind of its own, bound to its version
// (`privateMetaVersion`) as a value is to its location: the pair (metadata, version) is served together or not at
// all, never one metadata under another's version. It does not stop the Bridge serving an older pair whole
// (freshness, which the Bridge is trusted for). `bindingOf` makes that kind for nobody, so no value the application
// writes can be put in its place.
EnvelopeBinding metaBinding(std::int64_t privateMetaVersion) {
    return EnvelopeBinding{
        .hasLocation = true,
        .locationDigest = privmx::crypto::Crypto::sha256(
            "privmx/space/privateMetaVersion:" + std::to_string(privateMetaVersion)
        ),
        .content = EnvelopeContent::SpaceMeta,
    };
}

Poco::Dynamic::Var toWire(const core::Buffer& bytes) {
    return Poco::Dynamic::Var(privmx::utils::Base64::from(bytes.stdString()));
}

core::Buffer fromWire(const Poco::Dynamic::Var& value) {
    if (value.isEmpty() || !value.isString()) {
        return core::Buffer();
    }
    return core::Buffer::from(privmx::utils::Base64::toString(value.convert<std::string>()));
}

void requireRole(const std::string& role) {
    if (role != "user" && role != "manager") {
        throw core::InvalidParamsException("a Space recipient's role is \"user\" or \"manager\"");
    }
}

} // namespace

std::string GroupApiImpl::deriveSpaceId(const std::string& contextId, const core::Buffer& idSeed) {
    return keytree::TreeCommits::spaceId(contextId, resourceIdOfSeed(idSeed));
}

// -- reading the Space and its key -----------------------------------------------------------------------

group::server::SpaceInfo GroupApiImpl::spaceInfo(const std::string& spaceId, bool fresh) {
    const std::int64_t now = privmx::utils::Utils::getNowTimestamp();
    const SpaceReadTicket ticket = spaceReadTicket(spaceId);
    if (!fresh) {
        const auto cached = _spaces.get(spaceId);
        if (cached.has_value() && now - cached->readAt < SPACE_CACHE_MS && cached->generation == ticket.generation) {
            return cached->info;
        }
    }
    group::server::SpaceIdModel model;
    model.id = spaceId;
    group::server::SpaceInfo info = _serverApi.spaceGet(model).space;
    core::EndpointUtils::assertServedId(spaceId, info.id);
    if (!keepSpaceRead(
            info, ticket, CachedSpace{.info = info, .readAt = now, .allVersions = true, .generation = ticket.generation}
        )) {
        // Sent before this process rotated the key or deleted the Space: asked again, and that answer is held to
        // what is known now (a delete: the Bridge says so; a lower version: a rollback).
        return spaceInfo(spaceId, true);
    }
    return info;
}

// An earlier version of the key is one a removed recipient still holds: served as the current one, the next write
// would be theirs to read. So a version this process has seen is never followed by a lower one.
// ponytail: kept in memory, for the life of the connection's GroupApi. Put it beside the group pins when a
// rollback across restarts has to be caught as well.
std::int64_t GroupApiImpl::seenKeyVersion(const std::string& spaceId) {
    std::lock_guard lock(_spaceKeyVersionsMutex);
    const auto seen = _spaceKeyVersions.find(spaceId);
    return seen == _spaceKeyVersions.end() ? 0 : seen->second;
}

GroupApiImpl::SpaceReadTicket GroupApiImpl::spaceReadTicket(const std::string& spaceId) {
    std::lock_guard lock(_spaceKeyVersionsMutex);
    const auto seen = _spaceKeyVersions.find(spaceId);
    const auto generation = _spaceGenerations.find(spaceId);
    return SpaceReadTicket{
        .seen = seen == _spaceKeyVersions.end() ? 0 : seen->second,
        .generation = generation == _spaceGenerations.end() ? 0 : generation->second,
    };
}

// Thrown on a version below the one seen when the request was issued: a rollback. A read in flight while this process
// rotated the key may answer with the version before that rotation, which is no rollback - but it is not kept either
// (false): nothing is written under a key this process already replaced. Nor is an answer to a request sent before
// this process deleted the Space. Kept: the mark moves up and `keep` is cached, both under the one lock.
bool GroupApiImpl::keepSpaceRead(
    const group::server::SpaceInfo& space,
    const SpaceReadTicket& ticket,
    const std::optional<CachedSpace>& keep
) {
    std::lock_guard lock(_spaceKeyVersionsMutex);
    if (space.keyVersion < ticket.seen) {
        throw GroupHistoryForkException(
            "Space " +
            space.id +
            " served at key version " +
            std::to_string(space.keyVersion) +
            ", seen at " +
            std::to_string(ticket.seen)
        );
    }
    const auto generation = _spaceGenerations.find(space.id);
    if ((generation == _spaceGenerations.end() ? 0 : generation->second) != ticket.generation) {
        return false;
    }
    std::int64_t& seen = _spaceKeyVersions[space.id];
    if (space.keyVersion < seen) {
        return false;
    }
    seen = space.keyVersion;
    if (keep.has_value()) {
        _spaces.set(space.id, keep.value());
    }
    return true;
}

void GroupApiImpl::forgetSpace(const std::string& spaceId) {
    _spaces.erase(spaceId);
}

void GroupApiImpl::dropSpace(const std::string& spaceId) {
    {
        // A new generation: an answer to a request sent before the delete is not kept. The version mark stays: a
        // Space that comes back under this id is held to it, unless this process creates it again (`createSpace`).
        std::lock_guard lock(_spaceKeyVersionsMutex);
        ++_spaceGenerations[spaceId];
    }
    forgetSpace(spaceId);
    std::vector<std::string> keys;
    _spaceKeys.forAll([&](const std::string& key, const SpaceKeyUse&) {
        if (key.rfind(spaceId + ":", 0) == 0) {
            keys.push_back(key);
        }
    });
    for (const std::string& key : keys) {
        _spaceKeys.erase(key);
    }
}

GroupApiImpl::SpaceKeyUse GroupApiImpl::spaceKeyAt(const group::server::SpaceInfo& space, std::int64_t keyVersion) {
    const std::string cacheKey = space.id + ":" + std::to_string(keyVersion);
    // A key cached from an entry this read no longer serves (a Space deleted and created again, a read from before
    // that) is not this read's key: unwrapped again.
    if (const auto cached = _spaceKeys.get(cacheKey); cached.has_value() &&
        std::any_of(space.keys.begin(), space.keys.end(), [&](const group::server::SpaceKeyEntry& entry) {
                                                          return entry.keyVersion == keyVersion &&
                                                              entry.data == cached->wrap;
                                                      })) {
        return cached.value();
    }
    const std::string ownUserId = _connection.getImpl()->getMyUserId(space.contextId);
    const std::string ownPubKey = _userPrivKey.getPublicKey().toBase58DER();
    std::exception_ptr lastFailure;
    // The caller's own entry first (no request), then the entries of the groups it is in.
    for (const bool wantGroup : {false, true}) {
        for (const group::server::SpaceKeyEntry& entry : space.keys) {
            const bool isGroup = entry.recipient.groupId.has_value();
            if (entry.keyVersion != keyVersion || isGroup != wantGroup) {
                continue;
            }
            if (!isGroup && entry.recipient.userId.value_or("") != ownUserId) {
                continue;
            }
            try {
                const GroupEnvelopeEncryptor::SpaceKeyWrap wrap{
                    .data = privmx::utils::Base64::toString(entry.data),
                    .signature = privmx::utils::Base64::toString(entry.signature),
                };
                const GroupEnvelopeEncryptor::SpaceKeySlot slot{
                    .spaceId = space.id,
                    .keyVersion = keyVersion,
                    .isGroup = isGroup,
                    .recipientId = isGroup ? entry.recipient.groupId.value() : ownUserId,
                    .groupKeyVersion = entry.recipient.groupKeyVersion.value_or(0),
                };
                const auto header = GroupEnvelopeEncryptor::peekSpaceKeyWrap(wrap.data);
                if (isGroup) {
                    core::Validator::validateId(slot.recipientId, "field:space.keys.groupId ");
                } else if (privmx::crypto::PublicKey::fromBase58DER(header.recipientPubKey).toBase58DER() !=
                           ownPubKey) {
                    continue; // wrapped to a key the caller had before, or never had
                }
                const std::string key = _envelopeEncryptor.unwrapSpaceKey(
                    wrap, slot,
                    isGroup ? _keys.grantKeyForPubKey(slot.recipientId, header.recipientPubKey) : _userPrivKey
                );
                // The wrap is signed by whoever made this version of the key. That has to be a user of the Context
                // the application knows, or the Bridge could have made the key itself.
                assertUserKeysVerified(
                    space.contextId,
                    {core::UserWithPubKey{.userId = header.signerUserId, .pubKey = header.signerPubKey}}
                );
                const SpaceKeyUse use{
                    .key = key, .via = isGroup ? slot.recipientId : std::string(), .wrap = entry.data
                };
                _spaceKeys.set(cacheKey, use);
                return use;
            } catch (const std::exception& e) {
                LOG_WARN(
                    "[spaceKeyAt] space ", space.id, " version ", keyVersion, ": an entry did not open: ", e.what()
                )
                lastFailure = std::current_exception();
            }
        }
    }
    if (lastFailure) {
        std::rethrow_exception(lastFailure);
    }
    throw EnvelopeNotARecipientException("no entry of the Space's key, version " + std::to_string(keyVersion));
}

// -- wrapping the key --------------------------------------------------------------------------------------

std::vector<GroupApiImpl::SpaceTarget> GroupApiImpl::spaceTargets(
    const std::string& contextId,
    const std::vector<std::string>& groupIds,
    const std::vector<core::UserWithPubKey>& users
) {
    std::vector<SpaceTarget> targets;
    if (!groupIds.empty()) {
        // Each group's key is its current one, read and verified now: one from before a removal cannot be used.
        const auto epochs = fetchGroupEpochs(contextId, groupIds);
        for (const std::string& groupId : groupIds) {
            const auto epoch = epochs.find(groupId);
            if (epoch == epochs.end()) {
                throw SpaceRecipientUnavailableException(groupId);
            }
            targets.push_back(
                SpaceTarget{
                    .isGroup = true,
                    .id = groupId,
                    .pubKey = privmx::crypto::PublicKey::fromBase58DER(epoch->second.groupPubKey).toBase58DER(),
                    .groupKeyVersion = epoch->second.keyVersion,
                }
            );
        }
    }
    if (!users.empty()) {
        assertUserKeysVerified(contextId, users);
        for (const core::UserWithPubKey& user : users) {
            targets.push_back(
                SpaceTarget{
                    .isGroup = false,
                    .id = user.userId,
                    .pubKey = privmx::crypto::PublicKey::fromBase58DER(user.pubKey).toBase58DER(),
                    .groupKeyVersion = 0,
                }
            );
        }
    }
    return targets;
}

std::vector<group::server::SpaceKeyEntry> GroupApiImpl::wrapSpaceKeyFor(
    const std::string& spaceId,
    const std::string& contextId,
    std::int64_t keyVersion,
    const std::string& spaceKey,
    const std::vector<SpaceTarget>& targets
) {
    const std::string ownUserId = _connection.getImpl()->getMyUserId(contextId);
    std::vector<group::server::SpaceKeyEntry> entries;
    entries.reserve(targets.size());
    for (const SpaceTarget& target : targets) {
        const auto wrap = _envelopeEncryptor.wrapSpaceKey(
            spaceKey,
            GroupEnvelopeEncryptor::SpaceKeySlot{
                .spaceId = spaceId,
                .keyVersion = keyVersion,
                .isGroup = target.isGroup,
                .recipientId = target.id,
                .groupKeyVersion = target.groupKeyVersion,
            },
            privmx::crypto::PublicKey::fromBase58DER(target.pubKey), ownUserId, _userPrivKey
        );
        group::server::SpaceKeyEntry entry;
        entry.keyVersion = keyVersion;
        if (target.isGroup) {
            entry.recipient.groupId = target.id;
            entry.recipient.groupKeyVersion = target.groupKeyVersion;
        } else {
            entry.recipient.userId = target.id;
        }
        entry.data = privmx::utils::Base64::from(wrap.data);
        entry.signature = privmx::utils::Base64::from(wrap.signature);
        entries.push_back(std::move(entry));
    }
    return entries;
}

// -- the Space itself ------------------------------------------------------------------------------------

std::string GroupApiImpl::createSpace(
    const std::string& contextId,
    const std::vector<SpaceRecipient>& recipients,
    const core::Buffer& publicMeta,
    const core::Buffer& privateMeta,
    const std::optional<core::Buffer>& idSeed
) {
    std::vector<std::string> groupIds;
    std::vector<core::UserWithPubKey> users;
    group::server::SpaceCreateModel model;
    for (const SpaceRecipient& recipient : recipients) {
        if (recipient.groupId.empty() == !recipient.user.has_value()) {
            throw core::InvalidParamsException("a Space recipient is one group or one user");
        }
        requireRole(recipient.role);
        group::server::SpaceRecipient wire;
        wire.role = recipient.role;
        if (recipient.user.has_value()) {
            users.push_back(recipient.user.value());
            wire.userId = recipient.user->userId;
            wire.pubKey = recipient.user->pubKey;
        } else {
            core::Validator::validateId(recipient.groupId, "field:recipients.groupId ");
            groupIds.push_back(recipient.groupId);
            wire.groupId = recipient.groupId;
        }
        model.recipients.push_back(std::move(wire));
    }
    const std::string resourceId = idSeed.has_value() ? resourceIdOfSeed(idSeed.value()) :
                                                        core::EndpointUtils::generateId();
    // Known before the request: every wrap is signed for this Space and no other.
    const std::string spaceId = keytree::TreeCommits::spaceId(contextId, resourceId);
    const std::string spaceKey = privmx::crypto::Crypto::randomBytes(32);

    model.contextId = contextId;
    model.resourceId = resourceId;
    model.keyId = privmx::utils::Hex::from(privmx::crypto::Crypto::randomBytes(16));
    model.keys = wrapSpaceKeyFor(spaceId, contextId, 1, spaceKey, spaceTargets(contextId, groupIds, users));
    model.publicMeta = toWire(publicMeta);
    model.privateMeta = toWire(_envelopeEncryptor.packSpaceEnvelope(
        spaceId, std::string(), privateMeta, _userPrivKey, spaceKey,
        EnvelopeSeal{
            .binding = metaBinding(1),
            .keyVersion = 1,
            .encryptedAt = privmx::utils::Utils::getNowTimestamp(),
            .authorUserId = _connection.getImpl()->getMyUserId(contextId),
        }
    ));
    core::EndpointUtils::assertServedId(spaceId, _serverApi.spaceCreate(model).spaceId);
    dropSpace(spaceId); // whatever is cached of an earlier Space under this id
    {
        // This process made it, at version 1: the only way a version mark of an earlier Space under this id resets.
        std::lock_guard lock(_spaceKeyVersionsMutex);
        _spaceKeyVersions[spaceId] = 1;
    }
    return spaceId;
}

SpaceState GroupApiImpl::toSpaceState(const group::server::SpaceInfo& space) {
    SpaceState state{
        .spaceId = space.id,
        .contextId = space.contextId,
        .createdBy = space.creator,
        .groups = {},
        .users = {},
        .keyVersion = space.keyVersion,
        .keyIsStale = space.keyIsStale,
        .publicMeta = fromWire(space.publicMeta),
        .privateMeta = core::Buffer(),
        .publicMetaVersion = space.publicMetaVersion,
        .privateMetaVersion = space.privateMetaVersion,
    };
    for (const group::server::SpaceGroup& group : space.groups) {
        state.groups.push_back(
            SpaceGroupRecipient{.groupId = group.groupId, .role = group.role, .keyVersion = group.groupKeyVersion}
        );
    }
    for (const group::server::SpaceUser& user : space.users) {
        state.users.push_back(SpaceUserRecipient{.userId = user.userId, .pubKey = user.pubKey, .role = user.role});
    }
    // The private metadata is an envelope of the Space, at a place of its own. Its version of the key may be an
    // earlier one: a rotation does not rewrite it.
    const core::Buffer sealed = fromWire(space.privateMeta);
    const EnvelopeRouting routing = _envelopeEncryptor.peek(sealed, EnvelopeContent::SpaceMeta);
    if (routing.spaceId != space.id) {
        throw EnvelopeWrongGroupException("private metadata of another Space");
    }
    group::server::SpaceInfo withKeys = space;
    if (std::none_of(space.keys.begin(), space.keys.end(), [&](const group::server::SpaceKeyEntry& entry) {
            return entry.keyVersion == routing.keyVersion;
        })) {
        withKeys = spaceInfo(space.id, true); // a listing carries the current version only
    }
    const OpenedEnvelope opened = _envelopeEncryptor.openSpaceEnvelope(
        sealed, spaceKeyAt(withKeys, routing.keyVersion).key, metaBinding(space.privateMetaVersion)
    );
    requireVerifiedWriter(
        space.contextId, opened, DecryptOptions{.expectedAuthor = {}, .anyAuthor = true, .currentEpochOnly = false}
    );
    state.privateMeta = opened.data;
    return state;
}

SpaceState GroupApiImpl::getSpace(const std::string& spaceId) {
    return toSpaceState(spaceInfo(spaceId, true));
}

core::PagingList<SpaceState> GroupApiImpl::listSpaces(
    const std::string& contextId,
    const core::PagingQuery& pagingQuery
) {
    group::server::SpaceListModel model;
    model.contextId = contextId;
    core::ListQueryMapper::map(model, pagingQuery);
    std::map<std::string, SpaceReadTicket> tickets;
    {
        std::lock_guard lock(_spaceKeyVersionsMutex);
        for (const auto& [id, seen] : _spaceKeyVersions) {
            tickets[id].seen = seen;
        }
        for (const auto& [id, generation] : _spaceGenerations) {
            tickets[id].generation = generation;
        }
    }
    const group::server::SpaceListResult result = _serverApi.spaceList(model);
    std::vector<SpaceState> spaces;
    spaces.reserve(result.spaces.size());
    for (const group::server::SpaceInfo& space : result.spaces) {
        // Throws on a rollback. An answer overtaken by a rotation, a delete or a create of this process is left out.
        if (keepSpaceRead(space, tickets[space.id], std::nullopt)) {
            spaces.push_back(toSpaceState(space));
        }
    }
    return core::PagingList<SpaceState>({.totalAvailable = result.count, .readItems = spaces});
}

void GroupApiImpl::deleteSpace(const std::string& spaceId) {
    group::server::SpaceIdModel model;
    model.id = spaceId;
    _serverApi.spaceDelete(model);
    dropSpace(spaceId);
}

void GroupApiImpl::addSpaceRecipients(const std::string& spaceId, const std::vector<SpaceRecipient>& recipients) {
    const group::server::SpaceInfo space = spaceInfo(spaceId, true);
    std::vector<std::string> groupIds;
    std::vector<core::UserWithPubKey> users;
    group::server::SpaceAddRecipientsModel model;
    model.id = spaceId;
    for (const SpaceRecipient& recipient : recipients) {
        if (recipient.groupId.empty() == !recipient.user.has_value()) {
            throw core::InvalidParamsException("a Space recipient is one group or one user");
        }
        requireRole(recipient.role);
        group::server::SpaceRecipient wire;
        wire.role = recipient.role;
        if (recipient.user.has_value()) {
            users.push_back(recipient.user.value());
            wire.userId = recipient.user->userId;
            wire.pubKey = recipient.user->pubKey;
        } else {
            core::Validator::validateId(recipient.groupId, "field:recipients.groupId ");
            groupIds.push_back(recipient.groupId);
            wire.groupId = recipient.groupId;
        }
        model.recipients.push_back(std::move(wire));
    }
    // Every version, so that they read what is already there. Each is wrapped to the recipient's current key.
    const std::vector<SpaceTarget> targets = spaceTargets(space.contextId, groupIds, users);
    for (std::int64_t version = 1; version <= space.keyVersion; ++version) {
        const auto entries = wrapSpaceKeyFor(
            spaceId, space.contextId, version, spaceKeyAt(space, version).key, targets
        );
        model.keys.insert(model.keys.end(), entries.begin(), entries.end());
    }
    _serverApi.spaceAddRecipients(model);
    forgetSpace(spaceId);
}

std::int64_t GroupApiImpl::replaceSpaceKey(
    const std::string& spaceId,
    const std::vector<std::string>& withoutGroups,
    const std::vector<std::string>& withoutUsers
) {
    const group::server::SpaceInfo space = spaceInfo(spaceId, true);
    const auto dropped = [](const std::vector<std::string>& list, const std::string& id) {
        return std::find(list.begin(), list.end(), id) != list.end();
    };
    std::vector<std::string> groupIds;
    for (const group::server::SpaceGroup& group : space.groups) {
        if (!dropped(withoutGroups, group.groupId)) {
            groupIds.push_back(group.groupId);
        }
    }
    std::vector<core::UserWithPubKey> users;
    for (const group::server::SpaceUser& user : space.users) {
        if (!dropped(withoutUsers, user.userId)) {
            users.push_back(core::UserWithPubKey{.userId = user.userId, .pubKey = user.pubKey});
        }
    }
    const std::int64_t next = space.keyVersion + 1;
    group::server::SpaceRotateKeyModel model;
    model.id = spaceId;
    model.keyId = privmx::utils::Hex::from(privmx::crypto::Crypto::randomBytes(16));
    model.keys = wrapSpaceKeyFor(
        spaceId, space.contextId, next, privmx::crypto::Crypto::randomBytes(32),
        spaceTargets(space.contextId, groupIds, users)
    );
    model.expectedKeyVersion = space.keyVersion;
    if (!withoutGroups.empty() || !withoutUsers.empty()) {
        model.groups = withoutGroups;
        model.users = withoutUsers;
    }
    const std::int64_t made = _serverApi.spaceRotateKey(model).keyVersion;
    forgetSpace(spaceId);
    if (made != next) {
        throw GroupHistoryForkException("Space " + spaceId + " rotated to another key version than was sent");
    }
    {
        std::lock_guard lock(_spaceKeyVersionsMutex);
        std::int64_t& seen = _spaceKeyVersions[spaceId];
        seen = std::max(seen, made);
    }
    return made;
}

std::int64_t GroupApiImpl::removeSpaceRecipients(
    const std::string& spaceId,
    const std::vector<SpaceRecipientRef>& recipients
) {
    std::vector<std::string> groups;
    std::vector<std::string> users;
    for (const SpaceRecipientRef& recipient : recipients) {
        if (recipient.groupId.empty() == recipient.userId.empty()) {
            throw core::InvalidParamsException("a recipient to remove is one group or one user");
        }
        (recipient.groupId.empty() ? users : groups)
            .push_back(recipient.groupId.empty() ? recipient.userId : recipient.groupId);
    }
    if (recipients.empty()) {
        throw core::InvalidParamsException("field:recipients cannot be empty");
    }
    return replaceSpaceKey(spaceId, groups, users);
}

std::int64_t GroupApiImpl::rotateSpaceKey(const std::string& spaceId) {
    return replaceSpaceKey(spaceId, {}, {});
}

void GroupApiImpl::updateSpacePublicMeta(const std::string& spaceId, const core::Buffer& meta, int64_t version) {
    group::server::SpaceUpdateMetaModel model;
    model.id = spaceId;
    model.meta = toWire(meta);
    model.version = version;
    _serverApi.spaceUpdatePublicMeta(model);
    forgetSpace(spaceId);
}

void GroupApiImpl::updateSpacePrivateMeta(const std::string& spaceId, const core::Buffer& meta, int64_t version) {
    group::server::SpaceUpdateMetaModel model;
    model.id = spaceId;
    model.meta = toWire(sealInSpace(spaceId, metaBinding(version + 1), meta)); // the version it is stored at
    model.version = version;
    _serverApi.spaceUpdatePrivateMeta(model);
    forgetSpace(spaceId);
}

// -- values ------------------------------------------------------------------------------------------------

core::Buffer GroupApiImpl::sealInSpace(
    const std::string& spaceId,
    const EnvelopeBinding& binding,
    const core::Buffer& content
) {
    group::server::SpaceInfo space = spaceInfo(spaceId);
    if (space.keyVersion < seenKeyVersion(spaceId)) {
        space = spaceInfo(spaceId, true); // a cached read from before this process moved the key on
    }
    if (spaceKeyIsStale(space)) {
        // Someone removed from a recipient group still holds this key: nothing more is written under it.
        try {
            replaceSpaceKey(spaceId, {}, {});
        } catch (const SpaceRecipientUnavailableException&) { throw; } catch (const GroupHistoryForkException&) {
            throw; // a history that does not hold is the answer, never a lost race
        } catch (const core::Exception&) {
            // Lost to another writer doing the same: fine if the key is fresh now.
            if (spaceKeyIsStale(spaceInfo(spaceId, true))) {
                throw;
            }
        }
        space = spaceInfo(spaceId, true);
    }
    const SpaceKeyUse use = spaceKeyAt(space, space.keyVersion);
    return _envelopeEncryptor.packSpaceEnvelope(
        spaceId, use.via, content, _userPrivKey, use.key,
        EnvelopeSeal{
            .binding = binding,
            .keyVersion = space.keyVersion,
            .encryptedAt = privmx::utils::Utils::getNowTimestamp(),
            .authorUserId = _connection.getImpl()->getMyUserId(space.contextId),
        }
    );
}

bool GroupApiImpl::spaceKeyIsStale(const group::server::SpaceInfo& space) {
    if (space.keyIsStale) {
        return true;
    }
    if (space.groups.empty()) {
        return false;
    }
    // The Bridge's "fresh" is only its word: each recipient group's epoch, as this client verifies it now, is held
    // against the one the group's entry was wrapped to - as a client that sees a member removed rotates by itself.
    // Checked once per cached read of the Space.
    if (const auto cached = _spaces.get(space.id);
        cached.has_value() && cached->groupsFresh && cached->info.keyVersion == space.keyVersion) {
        return false;
    }
    std::vector<std::string> groupIds;
    for (const group::server::SpaceGroup& group : space.groups) {
        groupIds.push_back(group.groupId);
    }
    const auto epochs = fetchGroupEpochs(space.contextId, groupIds);
    for (const group::server::SpaceGroup& group : space.groups) {
        const auto epoch = epochs.find(group.groupId);
        if (epoch == epochs.end() || epoch->second.keyVersion > group.groupKeyVersion) {
            return true; // a group with no verifiable epoch is refused as a target by the rotation, loudly
        }
    }
    _spaces.updateValueIfExist(space.id, [&](const CachedSpace& cached) {
        CachedSpace checked = cached;
        checked.groupsFresh = cached.info.keyVersion == space.keyVersion;
        return checked;
    });
    return false;
}

core::Buffer GroupApiImpl::encryptInSpace(const std::string& spaceId, const Path& location, const core::Buffer& data) {
    return sealInSpace(spaceId, bindingOf(location), data);
}

DecryptedSpaceEnvelope GroupApiImpl::decryptInSpace(
    const std::string& spaceId,
    const Path& location,
    const core::Buffer& envelope,
    const DecryptOptions& options,
    EnvelopeContent content
) {
    requireAuthorStated(options);
    const EnvelopeBinding binding = bindingOf(location, content);
    const EnvelopeRouting routing = _envelopeEncryptor.peek(envelope, content);
    if (routing.spaceId.empty()) {
        throw EnvelopeWrongKindException(kindOf(routing));
    }
    // Before any key is looked up: the caller names the Space, so an envelope cannot steer the read to another.
    if (routing.spaceId != spaceId) {
        throw EnvelopeWrongGroupException("envelope of another Space");
    }
    group::server::SpaceInfo space = spaceInfo(spaceId);
    if (routing.keyVersion > space.keyVersion) {
        space = spaceInfo(spaceId, true);
    }
    // The version in the header is signed, and the key used is the one at that version: a wrong claim does not open.
    const OpenedEnvelope opened = _envelopeEncryptor.openSpaceEnvelope(
        envelope, spaceKeyAt(space, routing.keyVersion).key, binding
    );
    if (options.currentEpochOnly && opened.keyVersion != space.keyVersion) {
        throw EnvelopeStaleEpochException();
    }
    requireVerifiedWriter(space.contextId, opened, options);

    // The key says the author held it once. Whether they are a recipient is read off the Space and the group.
    std::string access = "no";
    if (opened.groupId.empty()) {
        if (std::any_of(space.users.begin(), space.users.end(), [&](const group::server::SpaceUser& user) {
                return user.userId == opened.authorUserId;
            })) {
            access = "yes";
        }
    } else if (std::any_of(space.groups.begin(), space.groups.end(), [&](const group::server::SpaceGroup& group) {
                   return group.groupId == opened.groupId;
               })) {
        try {
            core::Validator::validateId(opened.groupId, "field:envelope.via ");
            access = rosterOf(opened.groupId).roleOf(opened.authorUserId).empty() ? "no" : "yes";
        } catch (const core::Exception&) {
            access = "unknown"; // a recipient group the caller is not in
        }
    }
    return DecryptedSpaceEnvelope{
        .data = opened.data,
        .origin =
            SpaceOrigin{
                .author = EnvelopeSender{.userId = opened.authorUserId, .pubKey = opened.authorPubKey},
                .via = opened.groupId.empty() ? "user" : opened.groupId,
                .authorAccess = access,
                .keyVersion = opened.keyVersion,
            },
        .encryptedAt = opened.encryptedAt,
    };
}

std::vector<SpaceDecryptResult> GroupApiImpl::decryptManyInSpace(
    const std::string& spaceId,
    const std::vector<DecryptItem>& items
) {
    std::vector<SpaceDecryptResult> results;
    results.reserve(items.size());
    for (const DecryptItem& item : items) {
        SpaceDecryptResult result{};
        try {
            result.envelope = decryptInSpace(spaceId, item.location, item.envelope, item.options);
        } catch (const core::Exception& e) {
            result.statusCode = e.getCode();
            try {
                const EnvelopeRouting routing = GroupEnvelopeEncryptor::peekAny(item.envelope);
                if (e.getCode() == EnvelopeWrongKindException::FULL_CODE) {
                    result.details.envelopeKind = kindOf(routing);
                } else if (e.getCode() == EnvelopeWrongAuthorException::FULL_CODE ||
                           e.getCode() == EnvelopeUnverifiedAuthorException::FULL_CODE) {
                    result.details.userId = routing.authorUserId;
                    result.details.pubKey = routing.authorPubKey;
                }
            } catch (...) {}
        } catch (...) { result.statusCode = ENDPOINT_CORE_EXCEPTION_CODE; }
        results.push_back(std::move(result));
    }
    return results;
}

// -- files and sequences ---------------------------------------------------------------------------------

FileHandle GroupApiImpl::beginFileEncryptionInSpace(const std::string& spaceId, const Path& location) {
    const EnvelopeBinding binding = bindingOf(location, EnvelopeContent::File);
    // Now, so that a caller who is no recipient learns it before the upload and not after.
    const group::server::SpaceInfo space = spaceInfo(spaceId);
    spaceKeyAt(space, space.keyVersion);
    return beginFileWrite([this, spaceId, binding](const core::Buffer& manifest) {
        return sealInSpace(spaceId, binding, manifest);
    });
}

FileHandle GroupApiImpl::beginFileDecryptionInSpace(
    const std::string& spaceId,
    const Path& location,
    const core::Buffer& envelope,
    const DecryptOptions& options
) {
    const DecryptedSpaceEnvelope opened = decryptInSpace(spaceId, location, envelope, options, EnvelopeContent::File);
    return beginFileRead(
        opened.data,
        DecryptedFileInfo{
            .author = std::nullopt,
            .sender = opened.origin.author,
            .homeGroupId = {},
            .senderMembership = opened.origin.authorAccess,
            .via = opened.origin.via,
            .sharedWith = {},
            .keyVersion = opened.origin.keyVersion,
            .size = 0,
            .complete = false,
        }
    );
}

SequenceHandle GroupApiImpl::beginSequenceInSpace(
    const std::string& spaceId,
    const Path& location,
    int64_t checkpointEvery
) {
    const EnvelopeBinding binding = bindingOf(location, EnvelopeContent::Sequence);
    return beginSequenceOver(
        [&](const core::Buffer& key) { return sealInSpace(spaceId, binding, key); },
        // A sequence belongs to one version of the Space's key, and ends when that one is replaced or goes stale.
        [&](const core::Buffer& header) -> std::function<void()> {
            return [this, spaceId, keyVersion = GroupEnvelopeEncryptor::peekAny(header).keyVersion]() {
                const group::server::SpaceInfo space = spaceInfo(spaceId);
                if (space.keyVersion != keyVersion || spaceKeyIsStale(space)) {
                    throw EnvelopeStaleEpochException();
                }
            };
        },
        checkpointEvery
    );
}

SequenceHandle GroupApiImpl::openSequenceInSpace(
    const std::string& spaceId,
    const Path& location,
    const core::Buffer& header,
    const DecryptOptions& options,
    const std::optional<core::Buffer>& resumeFrom
) {
    const DecryptedSpaceEnvelope opened = decryptInSpace(spaceId, location, header, options, EnvelopeContent::Sequence);
    return openSequenceOver(header, opened.data, opened.origin.author.pubKey, resumeFrom, opened.origin);
}

SpaceOrigin GroupApiImpl::getSpaceSequenceOrigin(SequenceHandle handle) {
    const auto sequence = sequenceOf(handle, true);
    if (!sequence->spaceOrigin.has_value()) {
        throw core::InvalidParamsException("field:sequence was not opened with openSequenceInSpace");
    }
    return sequence->spaceOrigin.value();
}
