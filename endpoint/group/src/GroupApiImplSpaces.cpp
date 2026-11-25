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
#include <cctype>
#include <set>
#include <sstream>

#include <privmx/crypto/Crypto.hpp>
#include <privmx/endpoint/core/CoreException.hpp>
#include <privmx/endpoint/core/EndpointUtils.hpp>
#include <privmx/endpoint/core/LocalSeal.hpp>
#include <privmx/utils/Utils.hpp>

#include "privmx/endpoint/core/ListQueryMapper.hpp"
#include "privmx/endpoint/core/Validator.hpp"
#include "privmx/endpoint/group/GroupApiImpl.hpp"
#include "privmx/endpoint/group/GroupException.hpp"
#include "privmx/endpoint/group/keytree/SpaceLog.hpp"
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
    const std::uint64_t generation = spaceGeneration(spaceId);
    if (!fresh) {
        const auto cached = _spaces.get(spaceId);
        if (cached.has_value() && now - cached->readAt < SPACE_CACHE_MS && cached->generation == generation) {
            return cached->info;
        }
    }
    group::server::SpaceIdModel model;
    model.id = spaceId;
    group::server::SpaceInfo info = _serverApi.spaceGet(model).space;
    core::EndpointUtils::assertServedId(spaceId, info.id);
    verifySpace(info);
    _spaces.set(spaceId, CachedSpace{.info = info, .readAt = now, .allVersions = true, .generation = generation});
    return info;
}

// -- the Space's signed history --------------------------------------------------------------------------
//
// What the Bridge serves about a Space - its recipients, its key version, who made it - is not taken from the
// Bridge. It is what the Space's signed statements add up to, replayed from the first one (or from where this
// process stopped), each checked by `SpaceLog::apply` and its signer by the UserVerifier.

std::vector<keytree::SpaceStatement> GroupApiImpl::spaceStatements(
    const std::string& spaceId,
    std::int64_t fromSeq,
    std::int64_t upToSeq
) {
    // As many as the head calls for and no more: how long this runs is not the Bridge's to decide.
    std::vector<keytree::SpaceStatement> statements;
    while (fromSeq + static_cast<std::int64_t>(statements.size()) < upToSeq) {
        group::server::SpaceGetStatementsModel model;
        model.id = spaceId;
        model.fromSeq = fromSeq + static_cast<std::int64_t>(statements.size());
        model.limit = std::min<std::int64_t>(100, upToSeq - model.fromSeq);
        const auto page = _serverApi.spaceGetStatements(model).statements;
        if (page.empty() || static_cast<std::int64_t>(page.size()) > model.limit) {
            throw GroupDataIntegrityException("Space " + spaceId + ": its statements do not reach the state served");
        }
        for (const auto& wire : page) {
            statements.push_back(keytree::SpaceLog::fromWire(wire));
        }
    }
    return statements;
}

// The device's memory of each Space: the last statement it verified. A Space served behind that, or with another
// statement at that place, is a history that was rolled back or rewritten.
// ponytail: the pin holds a position and a digest, not the state, so a new session replays the history from the
// start (about a millisecond a statement). Keep the state in the pin when Spaces grow histories of thousands.
std::map<std::string, std::pair<std::uint64_t, std::string>> GroupApiImpl::storedSpacePins() {
    std::map<std::string, std::pair<std::uint64_t, std::string>> pins;
    if (!_pinStore) {
        return pins;
    }
    const std::string slot = _connection.getImpl()->localStateSlot("space-pins", _userPrivKey.getPublicKey());
    const core::LocalSeal seal(_userPrivKey, "privmx/space/pins", 1, slot);
    try {
        const std::string blob = _pinStore->load(slot).stdString();
        const auto body = blob.empty() ? std::nullopt : seal.open(blob);
        std::istringstream lines(body.value_or(std::string()));
        std::string spaceId, digest;
        std::uint64_t seq = 0;
        while (lines >> spaceId >> seq >> digest) {
            pins[spaceId] = {seq, privmx::utils::Hex::toString(digest)};
        }
    } catch (const std::exception& e) { LOG_WARN("[space pins] the stored pins do not load: ", e.what()) }
    return pins;
}

void GroupApiImpl::storeSpacePin(const keytree::SpaceLogState& state) {
    if (!_pinStore || !std::all_of(state.spaceId.begin(), state.spaceId.end(), [](unsigned char c) {
            return std::isalnum(c) != 0;
        })) {
        return;
    }
    const std::string slot = _connection.getImpl()->localStateSlot("space-pins", _userPrivKey.getPublicKey());
    const core::LocalSeal seal(_userPrivKey, "privmx/space/pins", 1, slot);
    // What this process holds: the pins it loaded and every Space it verified since. A stored blob that does not
    // open (nothing stored, or corrupted) is rebuilt from these, not from the one Space at hand.
    std::map<std::string, std::pair<std::uint64_t, std::string>> held;
    {
        std::lock_guard lock(_spaceLogsMutex);
        for (const auto& [id, pin] : _spacePins) {
            held[id] = {pin.first, privmx::utils::Hex::from(pin.second)};
        }
        for (const auto& [id, log] : _spaceLogs) {
            if (log.seq >= held[id].first) {
                held[id] = {log.seq, privmx::utils::Hex::from(log.digest)};
            }
        }
    }
    const bool saved = seal.update(*_pinStore, [&](const std::optional<std::string>& body) {
        // One line a Space: "<id> <seq> <digest hex>". The higher position stays.
        std::map<std::string, std::pair<std::uint64_t, std::string>> pins = body.has_value() ? decltype(held)() : held;
        std::istringstream lines(body.value_or(std::string()));
        std::string spaceId, digest;
        std::uint64_t seq = 0;
        while (lines >> spaceId >> seq >> digest) {
            pins[spaceId] = {seq, digest};
        }
        auto& pin = pins[state.spaceId];
        if (state.seq >= pin.first) {
            pin = {state.seq, privmx::utils::Hex::from(state.digest)};
        }
        std::string out;
        for (const auto& [id, entry] : pins) {
            out += id + " " + std::to_string(entry.first) + " " + entry.second + "\n";
        }
        return out;
    });
    if (!saved) {
        LOG_WARN("[space pins] the store kept changing under the save of Space ", state.spaceId, "; not saved")
    }
}

std::optional<keytree::SpaceLogState> GroupApiImpl::spaceLogOf(const std::string& spaceId) {
    std::lock_guard lock(_spaceLogsMutex);
    const auto found = _spaceLogs.find(spaceId);
    return found == _spaceLogs.end() ? std::nullopt : std::optional<keytree::SpaceLogState>(found->second);
}

void GroupApiImpl::rememberSpaceLog(const keytree::SpaceLogState& state) {
    {
        // Only forward, under one lock: two reads racing must not leave the earlier state as the mark.
        std::lock_guard lock(_spaceLogsMutex);
        const auto found = _spaceLogs.find(state.spaceId);
        if (found != _spaceLogs.end() && found->second.seq >= state.seq) {
            return;
        }
        _spaceLogs[state.spaceId] = state;
    }
    // The Bridge has taken the change, or the read is done: a store that fails is logged, never the caller's error.
    // The next save carries this Space again.
    try {
        storeSpacePin(state);
    } catch (const std::exception& e) { LOG_WARN("[space pins] save dropped: ", e.what()) } catch (...) {
        LOG_WARN("[space pins] save dropped")
    }
}

keytree::SpaceLogState GroupApiImpl::verifySpace(group::server::SpaceInfo& space) {
    const auto fork = [&](const std::string& what) {
        return GroupHistoryForkException("Space " + space.id + ": " + what);
    };
    std::optional<keytree::SpaceLogState> state = spaceLogOf(space.id);
    std::optional<std::pair<std::uint64_t, std::string>> stored;
    if (!state.has_value()) {
        {
            std::lock_guard lock(_spaceLogsMutex);
            if (!_spacePinsLoaded) {
                _spacePins = storedSpacePins();
                _spacePinsLoaded = true;
            }
            if (const auto pin = _spacePins.find(space.id); pin != _spacePins.end()) {
                stored = pin->second;
            }
        }
        if (stored.has_value() && static_cast<std::uint64_t>(space.seq) < stored->first) {
            throw fork("served behind the history this device has verified");
        }
    } else if (static_cast<std::uint64_t>(space.seq) < state->seq) {
        throw fork("served behind the history this process has verified");
    }
    if (!state.has_value() || state->seq < static_cast<std::uint64_t>(space.seq)) {
        for (const keytree::SpaceStatement& statement :
             spaceStatements(space.id, state.has_value() ? static_cast<std::int64_t>(state->seq) : 0, space.seq)) {
            if (statement.spaceId != space.id || statement.contextId != space.contextId) {
                throw GroupDataIntegrityException("space statement: of another Space");
            }
            state = keytree::SpaceLog::apply(state, statement);
            // The statement names its signer's key; whether that user holds it is the application's to say.
            try {
                assertUserKeysVerified(
                    space.contextId,
                    {core::UserWithPubKey{.userId = statement.signer, .pubKey = statement.signerPubKey}}
                );
            } catch (const core::Exception& e) {
                throw GroupUnauthorizedSignerException("space statement " + std::to_string(statement.seq), e);
            }
            if (stored.has_value() && state->seq == stored->first && state->digest != stored->second) {
                throw fork("another statement where this device verified one");
            }
        }
    }
    if (!state.has_value() || state->seq != static_cast<std::uint64_t>(space.seq)) {
        throw GroupDataIntegrityException("Space " + space.id + ": its statements do not reach the state served");
    }
    rememberSpaceLog(state.value());

    // From here on the Space is what its statements say. The Bridge's own fields are replaced, not compared: a
    // caller of this never sees a recipient, a role or a creator that nobody signed.
    space.creator = state->creator;
    space.keyVersion = static_cast<std::int64_t>(state->keyVersion);
    space.groups.clear();
    for (const keytree::SpaceLogGroup& group : state->groups) {
        group::server::SpaceGroup entry;
        entry.groupId = group.groupId;
        entry.role = group.role;
        entry.groupKeyVersion = static_cast<std::int64_t>(group.groupKeyVersion);
        entry.groupPubKey = group.groupPubKey;
        space.groups.push_back(std::move(entry));
    }
    space.users.clear();
    for (const keytree::SpaceLogUser& user : state->users) {
        group::server::SpaceUser entry;
        entry.userId = user.userId;
        entry.pubKey = user.pubKey;
        entry.role = user.role;
        space.users.push_back(std::move(entry));
    }
    return state.value();
}

// A statement by the caller, in whichever standing they have: as a recipient themselves, or through a recipient
// group they are in - shown by signing with that group's key.
keytree::SpaceStatement GroupApiImpl::signSpaceStatement(
    keytree::SpaceStatement statement,
    const std::optional<keytree::SpaceLogState>& prior
) {
    statement.seq = prior.has_value() ? prior->seq + 1 : 1;
    statement.prevDigest = prior.has_value() ? prior->digest : std::string();
    statement.date = static_cast<std::uint64_t>(privmx::utils::Utils::getNowTimestamp());
    statement.signer = _connection.getImpl()->getMyUserId(statement.contextId);
    const std::string ownPubKey = _userPrivKey.getPublicKey().toBase58DER();
    const bool needManager = statement.op != keytree::SpaceOp::Rotate;
    const auto& users = prior.has_value() ? prior->users : statement.users;
    const auto& groups = prior.has_value() ? prior->groups : statement.groups;
    // Each standing the caller has is tried until the statement is one that may follow: a group's key, for one,
    // is refreshed by a manager or through that very group, so the first standing found is not always the one.
    std::optional<GroupUnauthorizedSignerException> refused;
    const auto follows = [&](const keytree::SpaceStatement& candidate) {
        try {
            keytree::SpaceLog::apply(prior, candidate);
            return true;
        } catch (const GroupUnauthorizedSignerException& e) {
            refused = e;
            return false;
        }
    };
    for (const keytree::SpaceLogUser& user : users) {
        if (user.userId == statement.signer && user.pubKey == ownPubKey && (!needManager || user.role == "manager")) {
            statement.via.clear();
            keytree::SpaceLog::sign(statement, _userPrivKey, std::nullopt);
            if (follows(statement)) {
                return statement;
            }
        }
    }
    for (const keytree::SpaceLogGroup& group : groups) {
        if (needManager && group.role != "manager") {
            continue;
        }
        std::optional<privmx::crypto::PrivateKey> groupKey;
        try {
            core::Validator::validateId(group.groupId, "field:space.groups.groupId ");
            groupKey = _keys.grantKeyForPubKey(group.groupId, group.groupPubKey);
        } catch (const core::Exception&) {
            continue; // not a group of the caller's
        }
        statement.via = group.groupId;
        keytree::SpaceLog::sign(statement, _userPrivKey, groupKey);
        if (follows(statement)) {
            return statement;
        }
    }
    if (refused.has_value()) {
        throw refused.value();
    }
    throw GroupUnauthorizedSignerException(
        needManager ? "only a manager of the Space changes its recipients" : "the caller is no recipient of the Space"
    );
}

core::PagingList<SpaceLogEntry> GroupApiImpl::getSpaceLog(
    const std::string& spaceId,
    const core::PagingQuery& pagingQuery
) {
    if (pagingQuery.skip < 0 ||
        pagingQuery.limit < 1 ||
        (pagingQuery.sortOrder != "asc" && pagingQuery.sortOrder != "desc")) {
        throw core::InvalidParamsException("skip >= 0, limit >= 1 and sortOrder \"asc\" or \"desc\" are required");
    }
    // The latest state first, verified: the history below is replayed up to exactly that statement.
    const std::uint64_t head = static_cast<std::uint64_t>(spaceInfo(spaceId, true).seq);
    std::vector<SpaceLogEntry> entries;
    std::optional<keytree::SpaceLogState> state;
    for (const keytree::SpaceStatement& statement : spaceStatements(spaceId, 0, static_cast<std::int64_t>(head))) {
        const keytree::SpaceLogState next = keytree::SpaceLog::apply(state, statement);
        SpaceLogEntry entry{
            .seq = static_cast<int64_t>(statement.seq),
            .kind = keytree::SpaceLog::opName(statement.op),
            .author = statement.signer,
            .authorPubKey = statement.signerPubKey,
            .via = statement.via.empty() ? "user" : statement.via,
            .date = static_cast<int64_t>(statement.date),
            .keyVersion = static_cast<int64_t>(statement.keyVersion),
            .addedGroups = {},
            .addedUsers = {},
            .removedGroups = {},
            .removedUsers = {},
        };
        for (const auto& group : next.groups) {
            if (!state.has_value() || state->group(group.groupId) == nullptr)
                entry.addedGroups.push_back(group.groupId);
        }
        for (const auto& user : next.users) {
            if (!state.has_value() || state->roleOfUser(user.userId).empty())
                entry.addedUsers.push_back(user.userId);
        }
        if (state.has_value()) {
            for (const auto& group : state->groups) {
                if (next.group(group.groupId) == nullptr)
                    entry.removedGroups.push_back(group.groupId);
            }
            for (const auto& user : state->users) {
                if (next.roleOfUser(user.userId).empty())
                    entry.removedUsers.push_back(user.userId);
            }
        }
        entries.push_back(std::move(entry));
        state = next;
    }
    const auto verified = spaceLogOf(spaceId);
    if (!state.has_value() ||
        !verified.has_value() ||
        state->seq != verified->seq ||
        state->digest != verified->digest) {
        throw GroupHistoryForkException("Space " + spaceId + ": its history changed while it was read");
    }
    if (pagingQuery.sortOrder == "desc") {
        std::reverse(entries.begin(), entries.end());
    }
    core::PagingList<SpaceLogEntry> result{.totalAvailable = static_cast<int64_t>(entries.size()), .readItems = {}};
    for (std::size_t i = static_cast<std::size_t>(pagingQuery.skip);
         i < entries.size() && result.readItems.size() < static_cast<std::size_t>(pagingQuery.limit); ++i) {
        result.readItems.push_back(entries[i]);
    }
    return result;
}

void GroupApiImpl::forgetSpace(const std::string& spaceId) {
    _spaces.erase(spaceId);
}

std::uint64_t GroupApiImpl::spaceGeneration(const std::string& spaceId) {
    std::lock_guard lock(_spaceLogsMutex);
    const auto generation = _spaceGenerations.find(spaceId);
    return generation == _spaceGenerations.end() ? 0 : generation->second;
}

void GroupApiImpl::dropSpace(const std::string& spaceId) {
    {
        // A new generation: an answer to a request sent before the delete is not kept. The verified history stays:
        // a Space that comes back under this id is held to it, unless this process creates it again (`createSpace`).
        std::lock_guard lock(_spaceLogsMutex);
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
                // The key itself: the one the statement that made this version committed to, or the Bridge has
                // stored a wrap of another.
                const auto log = spaceLogOf(space.id);
                const auto commit = log.has_value() ? log->keyCommits.find(static_cast<std::uint64_t>(keyVersion)) :
                                                      std::map<std::uint64_t, std::string>::const_iterator{};
                if (!log.has_value() ||
                    commit == log->keyCommits.end() ||
                    commit->second !=
                        keytree::SpaceLog::keyCommit(space.id, static_cast<std::uint64_t>(keyVersion), key)) {
                    throw GroupDataIntegrityException("not the key the Space's statements name for this version");
                }
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

// The new recipients of a statement: who the caller named, each group at the epoch and key its wrap was made for.
void GroupApiImpl::appendRecipients(
    keytree::SpaceStatement& statement,
    const std::vector<SpaceRecipient>& recipients,
    const std::vector<SpaceTarget>& targets
) {
    for (const SpaceRecipient& recipient : recipients) {
        if (recipient.user.has_value()) {
            statement.users.push_back(
                keytree::SpaceLogUser{
                    .userId = recipient.user->userId, .pubKey = recipient.user->pubKey, .role = recipient.role
                }
            );
            continue;
        }
        const auto target = std::find_if(targets.begin(), targets.end(), [&](const SpaceTarget& t) {
            return t.isGroup && t.id == recipient.groupId;
        });
        statement.groups.push_back(
            keytree::SpaceLogGroup{
                .groupId = recipient.groupId,
                .role = recipient.role,
                .groupKeyVersion = static_cast<std::uint64_t>(target->groupKeyVersion),
                .groupPubKey = target->pubKey,
            }
        );
    }
}

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
            throw core::InvalidParamsException("a Space recipient is one group, by its ID, or one user");
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
    const std::vector<SpaceTarget> targets = spaceTargets(contextId, groupIds, users);
    model.keys = wrapSpaceKeyFor(spaceId, contextId, 1, spaceKey, targets);
    keytree::SpaceStatement statement;
    statement.spaceId = spaceId;
    statement.contextId = contextId;
    statement.op = keytree::SpaceOp::Create;
    statement.keyVersion = 1;
    statement.keyCommit = keytree::SpaceLog::keyCommit(spaceId, 1, spaceKey);
    appendRecipients(statement, recipients, targets);
    statement = signSpaceStatement(std::move(statement), std::nullopt);
    const keytree::SpaceLogState created = keytree::SpaceLog::apply(std::nullopt, statement);
    model.statement = keytree::SpaceLog::toWire(statement);
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
        // This process made it: the only way the verified history of an earlier Space under this id is let go.
        std::lock_guard lock(_spaceLogsMutex);
        _spaceLogs.erase(spaceId);
        _spacePins.erase(spaceId);
    }
    rememberSpaceLog(created);
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
    const group::server::SpaceListResult result = _serverApi.spaceList(model);
    std::vector<SpaceState> spaces;
    spaces.reserve(result.spaces.size());
    for (const group::server::SpaceInfo& space : result.spaces) {
        group::server::SpaceInfo verified = space;
        verifySpace(verified);
        spaces.push_back(toSpaceState(verified));
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
            throw core::InvalidParamsException("a Space recipient is one group, by its ID, or one user");
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
    const auto prior = spaceLogOf(spaceId);
    keytree::SpaceStatement statement;
    statement.spaceId = spaceId;
    statement.contextId = space.contextId;
    statement.op = keytree::SpaceOp::Add;
    statement.keyVersion = prior.value().keyVersion;
    statement.keyCommit = prior->keyCommits.at(prior->keyVersion);
    statement.groups = prior->groups;
    statement.users = prior->users;
    appendRecipients(statement, recipients, targets);
    statement = signSpaceStatement(std::move(statement), prior);
    const keytree::SpaceLogState added = keytree::SpaceLog::apply(prior, statement);
    model.statement = keytree::SpaceLog::toWire(statement);
    _serverApi.spaceAddRecipients(model);
    forgetSpace(spaceId);
    rememberSpaceLog(added);
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
    const std::string spaceKey = privmx::crypto::Crypto::randomBytes(32);
    const std::vector<SpaceTarget> targets = spaceTargets(space.contextId, groupIds, users);
    group::server::SpaceRotateKeyModel model;
    model.id = spaceId;
    model.keyId = privmx::utils::Hex::from(privmx::crypto::Crypto::randomBytes(16));
    model.keys = wrapSpaceKeyFor(spaceId, space.contextId, next, spaceKey, targets);
    model.expectedKeyVersion = space.keyVersion;
    // Who stays, as the statements have them; each group at the epoch and key it was just wrapped for.
    const auto prior = spaceLogOf(spaceId);
    keytree::SpaceStatement statement;
    statement.spaceId = spaceId;
    statement.contextId = space.contextId;
    statement.op = withoutGroups.empty() && withoutUsers.empty() ? keytree::SpaceOp::Rotate : keytree::SpaceOp::Remove;
    statement.keyVersion = static_cast<std::uint64_t>(next);
    statement.keyCommit = keytree::SpaceLog::keyCommit(spaceId, static_cast<std::uint64_t>(next), spaceKey);
    for (const keytree::SpaceLogGroup& group : prior.value().groups) {
        const auto target = std::find_if(targets.begin(), targets.end(), [&](const SpaceTarget& t) {
            return t.isGroup && t.id == group.groupId;
        });
        if (target != targets.end()) {
            statement.groups.push_back(
                keytree::SpaceLogGroup{
                    .groupId = group.groupId,
                    .role = group.role,
                    .groupKeyVersion = static_cast<std::uint64_t>(target->groupKeyVersion),
                    .groupPubKey = target->pubKey,
                }
            );
        }
    }
    for (const keytree::SpaceLogUser& user : prior->users) {
        if (!dropped(withoutUsers, user.userId)) {
            statement.users.push_back(user);
        }
    }
    statement = signSpaceStatement(std::move(statement), prior);
    const keytree::SpaceLogState replaced = keytree::SpaceLog::apply(prior, statement);
    model.statement = keytree::SpaceLog::toWire(statement);
    if (!withoutGroups.empty() || !withoutUsers.empty()) {
        model.groups = withoutGroups;
        model.users = withoutUsers;
    }
    const std::int64_t made = _serverApi.spaceRotateKey(model).keyVersion;
    if (made != next) {
        forgetSpace(spaceId);
        throw GroupHistoryForkException("Space " + spaceId + " rotated to another key version than was sent");
    }
    rememberSpaceLog(replaced);
    forgetSpace(spaceId);
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
    if (spaceKeyIsStale(space)) {
        // Someone removed from a recipient group still holds this key: nothing more is written under it.
        try {
            replaceSpaceKey(spaceId, {}, {});
        } catch (const SpaceRecipientUnavailableException&) { throw; } catch (const GroupHistoryForkException&) {
            throw; // a history that does not hold is the answer, never a lost race
        } catch (const GroupUnauthorizedSignerException& e) {
            // Not this caller's to replace: a group's key is refreshed by a manager of the Space or by that group.
            // Nothing is written under a key a removed member holds; whoever may, replaces it first.
            throw EnvelopeStaleEpochException("the Space's key is stale and the caller may not replace it", e);
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
            // A recipient group the caller is not in: its roster shows only when it is visible to the Context.
            const auto roster = publicRosterOf(space.contextId, opened.groupId);
            access = !roster.has_value() ? "unknown" : roster->roleOf(opened.authorUserId).empty() ? "no" : "yes";
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

// -- subjects ----------------------------------------------------------------------------------------------

core::Buffer GroupApiImpl::encodePath(const Path& path) {
    if (path.empty()) {
        throw core::InvalidParamsException("a subject needs at least one segment");
    }
    for (const PathSegment& segment : path) {
        if (segment.value.size() == 0) {
            throw core::InvalidParamsException("a path segment cannot be empty");
        }
    }
    return core::Buffer::from(GroupEnvelopeEncryptor::canonicalPath(path));
}

// The device's own list of "this subject is that Group", sealed like the group pins and kept beside them. An entry
// is written once and never replaced: a second Group for a subject is what this is here to refuse.
void GroupApiImpl::pinGroupToSubject(const std::string& contextId, const Path& subject, const std::string& groupId) {
    // The pins are kept as lines of "<key> <group id>": an id with a space or a line break in it would write a pin
    // for another subject.
    if (groupId.empty() || groupId.size() > 128 || !std::all_of(groupId.begin(), groupId.end(), [](unsigned char c) {
            return std::isalnum(c) != 0 || c == '-' || c == '_';
        })) {
        throw core::InvalidParamsException("field:groupId is not a group id");
    }
    const std::string key = privmx::utils::Hex::from(
        privmx::crypto::Crypto::sha256(
            "privmx/group/subject" +
            std::string(1, '\0') +
            contextId +
            std::string(1, '\0') +
            encodePath(subject).stdString()
        )
    );
    if (!_pinStore) {
        // No store on this device: the pin lasts as long as this GroupApi does.
        std::lock_guard lock(_subjectPinsMutex);
        const auto [pin, added] = _subjectPins.emplace(key, groupId);
        if (!added && pin->second != groupId) {
            throw GroupSubjectReboundException("known as " + pin->second);
        }
        return;
    }
    const std::string slot = _connection.getImpl()->localStateSlot("group-subjects", _userPrivKey.getPublicKey());
    const core::LocalSeal seal(_userPrivKey, "privmx/group/subjects", 1, slot);
    std::string known;
    const bool saved = seal.update(*_pinStore, [&](const std::optional<std::string>& body) {
        // Lines of "<subject key> <group id>": both are hex, so a space and a newline separate them safely.
        std::string lines = body.value_or(std::string());
        const std::size_t at = lines.find(key + " ");
        if (at != std::string::npos && (at == 0 || lines[at - 1] == '\n')) {
            known = lines.substr(at + key.size() + 1, lines.find('\n', at) - at - key.size() - 1);
            return lines;
        }
        known = groupId;
        return lines + key + " " + groupId + "\n";
    });
    if (known != groupId) {
        throw GroupSubjectReboundException("known as " + known);
    }
    if (!saved) {
        throw core::InvalidParamsException("the pin store did not take the subject's pin");
    }
}
