/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

// Spaces: one symmetric key, in versions. The current version is wrapped for each recipient; every later version
// seals the earlier ones it skips to (the key ladder, `spaceRungsFor`), so an earlier version is read by descending
// from the current key. The Bridge stores the wraps and the rungs and nothing else; everything a reader relies on is
// checked here.
//
// What is and is not established:
// - A version of the key is taken only if it is the one the Space's signed statements commit to (keyCommit), and the
//   current one only from a wrap signed by a user the UserVerifier vouches for, for this Space, this version and
//   this recipient. The Bridge cannot plant a key of its own, and a rung it forges does not pass the commit.
// - The list of recipients is the Bridge's word, as a container's list of users is. Before a key is wrapped to a
//   recipient, a group's key is read off its latest verified statement and a user's key goes to the UserVerifier.
// - Whether an author still had access is not something the key shows: see `SpaceOrigin::authorAccess`.

#include <algorithm>
#include <cctype>
#include <set>
#include <sstream>

#include <privmx/crypto/Crypto.hpp>
#include <privmx/endpoint/core/ConvertedExceptions.hpp>
#include <privmx/endpoint/core/CoreException.hpp>
#include <privmx/endpoint/core/EndpointUtils.hpp>
#include <privmx/endpoint/core/LocalSeal.hpp>
#include <privmx/utils/Utils.hpp>

#include "privmx/endpoint/core/ListQueryMapper.hpp"
#include "privmx/endpoint/core/Validator.hpp"
#include "privmx/endpoint/group/GroupApiImpl.hpp"
#include "privmx/endpoint/group/GroupException.hpp"
#include "privmx/endpoint/group/keytree/LadderMath.hpp"
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

group::server::SpaceInfo GroupApiImpl::spaceInfo(const std::string& spaceId, bool fresh, keytree::SpaceLogState* log) {
    const std::int64_t now = privmx::utils::Utils::getNowTimestamp();
    const std::uint64_t generation = spaceGeneration(spaceId);
    if (!fresh) {
        const auto cached = _spaces.get(spaceId);
        if (cached.has_value() && now - cached->readAt < SPACE_CACHE_MS && cached->generation == generation) {
            if (log != nullptr) {
                *log = cached->log;
            }
            return cached->info;
        }
    }
    group::server::SpaceIdModel model;
    model.id = spaceId;
    const auto before = spaceLogOf(spaceId);
    group::server::SpaceInfo info = _serverApi.spaceGet(model).space;
    core::EndpointUtils::assertServedId(spaceId, info.id);
    if (spaceOvertaken(info, before.has_value() ? before->seq : 0)) {
        return spaceInfo(spaceId, true, log);
    }
    const keytree::SpaceLogState verified = verifySpace(info);
    if (spaceGeneration(spaceId) != generation) {
        return spaceInfo(spaceId, true, log); // sent before this process deleted or created the Space: not kept
    }
    _spaces.set(spaceId, CachedSpace{.info = info, .readAt = now, .generation = generation, .log = verified});
    if (log != nullptr) {
        *log = verified;
    }
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

// The device's memory of each Space: the whole state it last verified, so a new session verifies only the statements
// since. A Space served behind that, or with a statement after it that does not follow it, is a history that was
// rolled back or rewritten. Blob version 2 (`SpaceLog::encodeStates`); a version 1 blob (position and digest only)
// opens as nothing: first contact again.
// ponytail: one blob for every Space, rewritten whole on each save, ~250 B + 160 B a recipient + 32 B a key version
// per Space. Thousands of Spaces with long histories make each save megabytes; a slot per Space if that bites.
static constexpr std::uint8_t SPACE_PINS_VERSION = 2;

std::map<std::string, keytree::SpaceLogState> GroupApiImpl::storedSpacePins() {
    if (!_pinStore) {
        return {};
    }
    const std::string slot = _connection.getImpl()->localStateSlot("space-pins", _userPrivKey.getPublicKey());
    const core::LocalSeal seal(_userPrivKey, "privmx/space/pins", SPACE_PINS_VERSION, slot);
    try {
        const std::string blob = _pinStore->load(slot).stdString();
        const auto body = blob.empty() ? std::nullopt : seal.open(blob);
        if (body.has_value()) {
            if (auto states = keytree::SpaceLog::decodeStates(body.value()); states.has_value()) {
                return std::move(states.value());
            }
            LOG_WARN("[space pins] the stored pins do not decode")
        }
    } catch (const std::exception& e) { LOG_WARN("[space pins] the stored pins do not load: ", e.what()) }
    return {};
}

void GroupApiImpl::storeSpacePin(const keytree::SpaceLogState& state) {
    if (!_pinStore) {
        return;
    }
    const std::string slot = _connection.getImpl()->localStateSlot("space-pins", _userPrivKey.getPublicKey());
    const core::LocalSeal seal(_userPrivKey, "privmx/space/pins", SPACE_PINS_VERSION, slot);
    const bool saved = seal.update(*_pinStore, [&](const std::optional<std::string>& body) {
        // Every Space this process verified is merged into every save, so a save that failed earlier is made up by
        // the next one; the higher position stays. The states loaded at first use are not: the store may have moved
        // on since (another process sharing it). They only rebuild a stored blob that does not open (nothing
        // stored, of an earlier version, or corrupted).
        std::map<std::string, keytree::SpaceLogState> states;
        if (body.has_value()) {
            states = keytree::SpaceLog::decodeStates(body.value()).value_or(states);
        }
        const auto keep = [&](const keytree::SpaceLogState& next) {
            const auto found = states.find(next.spaceId);
            if (found == states.end() || next.seq >= found->second.seq) {
                states[next.spaceId] = next;
            }
        };
        std::lock_guard lock(_spaceLogsMutex);
        if (!body.has_value()) {
            for (const auto& [id, pinned] : _spacePins) {
                keep(pinned);
            }
        }
        for (const auto& [id, log] : _spaceLogs) {
            keep(log);
        }
        keep(state);
        return keytree::SpaceLog::encodeStates(states);
    });
    if (!saved) {
        LOG_WARN("[space pins] the store kept changing under the save of Space ", state.spaceId, "; not saved")
    }
}

// An answer behind the history this process holds now, but not behind what it held when the request was sent: a read
// in flight while this process changed the Space itself. No rollback, and nothing to keep or write under: asked again.
bool GroupApiImpl::spaceOvertaken(const group::server::SpaceInfo& space, std::uint64_t seqWhenSent) {
    const auto now = spaceLogOf(space.id);
    const auto served = static_cast<std::uint64_t>(std::max<std::int64_t>(space.seq, 0));
    return now.has_value() && served < now->seq && served >= seqWhenSent;
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
    // The id goes into the pin store's line format and into every cache key. A Space's id is a hash in hex: anything
    // else the Bridge serves (a space, a line break) is refused here, before it reaches either.
    if (space.id.empty() ||
        !std::all_of(space.id.begin(), space.id.end(), [](unsigned char c) { return std::isalnum(c) != 0; })) {
        throw GroupDataIntegrityException("a Space id is letters and digits only");
    }
    const auto fork = [&](const std::string& what) {
        return GroupHistoryForkException("Space " + space.id + ": " + what);
    };
    std::optional<keytree::SpaceLogState> state = spaceLogOf(space.id);
    std::optional<std::uint64_t> deviceSeq; // where the state taken from the device's store stops
    if (!state.has_value()) {
        // The state this device verified before, if any: the replay goes on from it, and its digest is what the next
        // statement must follow (`SpaceLog::apply`).
        {
            std::lock_guard lock(_spaceLogsMutex);
            if (!_spacePinsLoaded) {
                _spacePins = storedSpacePins();
                _spacePinsLoaded = true;
            }
            if (const auto pin = _spacePins.find(space.id); pin != _spacePins.end()) {
                state = pin->second;
                deviceSeq = state->seq;
            }
        }
        if (state.has_value() && static_cast<std::uint64_t>(space.seq) < state->seq) {
            throw fork("served behind the history this device has verified");
        }
    } else if (static_cast<std::uint64_t>(space.seq) < state->seq) {
        throw fork("served behind the history this process has verified");
    }
    if (state.has_value() && state->contextId != space.contextId) {
        throw GroupDataIntegrityException("Space " + space.id + ": served in another Context than it was verified in");
    }
    if (!state.has_value() || state->seq < static_cast<std::uint64_t>(space.seq)) {
        std::vector<core::UserWithPubKey> signers;
        std::vector<GroupKeyRefresh> refreshes;
        for (const keytree::SpaceStatement& statement :
             spaceStatements(space.id, state.has_value() ? static_cast<std::int64_t>(state->seq) : 0, space.seq)) {
            if (statement.spaceId != space.id || statement.contextId != space.contextId) {
                throw GroupDataIntegrityException("space statement: of another Space");
            }
            if (deviceSeq.has_value() &&
                statement.seq == deviceSeq.value() + 1 &&
                statement.prevDigest != state->digest) {
                throw fork("another statement where this device verified one");
            }
            state = keytree::SpaceLog::apply(state, statement);
            signers.push_back(core::UserWithPubKey{.userId = statement.signer, .pubKey = statement.signerPubKey});
            for (const keytree::SpaceLogGroup& group : statement.refreshedGroups) {
                refreshes.push_back(
                    GroupKeyRefresh{
                        .seq = statement.seq,
                        .groupId = group.groupId,
                        .groupKeyVersion = group.groupKeyVersion,
                        .groupPubKey = group.groupPubKey,
                    }
                );
            }
        }
        // The statements name their signers' keys; whether those users hold them is the application's to say. Asked
        // once for the replay.
        try {
            assertUserKeysVerified(space.contextId, core::EndpointUtils::uniqueListUserWithPubKey(signers, {}));
        } catch (const core::Exception& e) { throw GroupUnauthorizedSignerException("space statement signer", e); }
        requireGroupKeyRefreshesHold(space.contextId, refreshes);
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

// SECURITY: a group's pinned key in a Space's log is what "signed via that group" is checked against from then on,
// so a refresh of it is held to the group's own verified history, whoever signed it (any recipient may: the Bridge
// lets any recipient rotate). Whatever this client can verify, it does: one of the group's epoch keys for a member,
// its verified current key, or the key its verified chain of statements opened a past epoch with (the Bridge serves
// the chain to whoever may read the group's public info). A key shown wrong is refused; one nothing here can verify
// (a group hidden from this reader) is taken as signed.
void GroupApiImpl::requireGroupKeyRefreshesHold(
    const std::string& contextId,
    const std::vector<GroupKeyRefresh>& refreshes
) {
    if (refreshes.empty()) {
        return;
    }
    std::vector<std::string> groupIds;
    for (const GroupKeyRefresh& refresh : refreshes) {
        if (std::find(groupIds.begin(), groupIds.end(), refresh.groupId) == groupIds.end()) {
            groupIds.push_back(refresh.groupId);
        }
    }
    // Verified and pinned here, chain caught up included; a group refused for a fork or a pin it is behind gets no
    // key, and every refresh of it is then refused.
    const auto epochs = fetchGroupEpochs(contextId, groupIds);
    // Each group's grant key per past epoch, off its verified chain (`epochOpeners`: fetched once a group, only the
    // statements since on a later replay). A chain that fails to read throws: a failed read is never "nothing to
    // verify", which would take the refresh as signed.
    std::map<std::string, std::map<std::uint64_t, std::string>> chainKeys;
    const auto chainKeyAt = [&](const std::string& groupId, std::uint64_t epoch) -> std::optional<std::string> {
        auto chain = chainKeys.find(groupId);
        if (chain == chainKeys.end()) {
            std::map<std::uint64_t, std::string> keys;
            for (const auto& [at, opener] : _treeVerifier.epochOpeners(
                     groupId, contextId, VerifiedGroup::treeEnvironment(_serverApi, _connection, groupId)
                 )) {
                keys[at] = opener.groupPubKey;
            }
            chain = chainKeys.emplace(groupId, std::move(keys)).first;
        }
        const auto key = chain->second.find(epoch);
        return key == chain->second.end() ? std::nullopt : std::optional<std::string>(key->second);
    };
    // Whether the group shows this caller nothing: the Bridge says outright that it may not see it (a members-only
    // group it is not in) or that there is none. Any other failure is thrown, for the same reason as above.
    const auto hiddenFromCaller = [&](const std::string& groupId) {
        try {
            server::GroupGetPublicKeyModel model;
            model.groupId = groupId;
            _serverApi.groupGetPublicKey(model);
        } catch (const core::Exception& e) {
            if (e.getCode() == privmx::endpoint::server::GroupDoesNotExistException().getCode() ||
                e.getCode() == privmx::endpoint::server::AccessDeniedException().getCode()) {
                return true;
            }
            throw;
        }
        return false;
    };
    for (const GroupKeyRefresh& refresh : refreshes) {
        // The epoch the caller's own view of the group gives that key: only a member has one.
        std::optional<std::int64_t> memberEpoch;
        try {
            core::Validator::validateId(refresh.groupId, "field:space.groups.groupId ");
            std::int64_t epoch = 0;
            _keys.grantKeyForPubKey(refresh.groupId, refresh.groupPubKey, &epoch);
            memberEpoch = epoch;
        } catch (const GroupHistoryForkException&) {
            throw; // a history that does not hold is the answer, never "not a key of it"
        } catch (const GroupDataIntegrityException&) { throw; } catch (const std::exception&) {
        } // not a group of the caller's, or not a key of it
        const auto epoch = epochs.find(refresh.groupId);
        const std::optional<core::GroupEpochInfo> current = epoch == epochs.end() ?
            std::nullopt :
            std::optional<core::GroupEpochInfo>(epoch->second);
        const bool member = memberEpoch.has_value() && memberEpoch.value() > 0;
        // No verified epoch of a group the caller can see: its history did not verify (a fork, a pin it is behind),
        // so the key cannot be checked although it should be. Only a group that shows the caller nothing at all is
        // "cannot verify".
        if (!member && !current.has_value() && !hiddenFromCaller(refresh.groupId)) {
            throw GroupUnauthorizedSignerException(
                "space statement " +
                std::to_string(refresh.seq) +
                ": group " +
                refresh.groupId +
                " is visible to this caller but its key could not be verified"
            );
        }
        // A past epoch, below the group's verified current one, with no key of the caller's own to compare.
        const bool past = !(memberEpoch.has_value() && memberEpoch.value() > 0) &&
            current.has_value() &&
            refresh.groupKeyVersion < static_cast<std::uint64_t>(current->keyVersion);
        if (const auto why = refusedRefresh(
                refresh, memberEpoch, current,
                past ? chainKeyAt(refresh.groupId, refresh.groupKeyVersion) : std::nullopt
            )) {
            throw GroupUnauthorizedSignerException(
                "space statement " + std::to_string(refresh.seq) + ": group " + refresh.groupId + " " + why.value()
            );
        }
    }
}

std::optional<std::string> GroupApiImpl::refusedRefresh(
    const GroupKeyRefresh& refresh,
    std::optional<std::int64_t> memberEpoch,
    const std::optional<core::GroupEpochInfo>& current,
    const std::optional<std::string>& chainKey
) {
    if (memberEpoch.has_value() && memberEpoch.value() > 0) {
        return memberEpoch.value() == static_cast<std::int64_t>(refresh.groupKeyVersion) ?
            std::nullopt :
            std::optional<std::string>("had that key at another epoch");
    }
    const auto canonical = [](const std::string& key) {
        try {
            return privmx::crypto::PublicKey::fromBase58DER(key).toBase58DER();
        } catch (...) { return std::string(); }
    };
    if (current.has_value() && refresh.groupKeyVersion == static_cast<std::uint64_t>(current->keyVersion)) {
        return canonical(current->groupPubKey) == canonical(refresh.groupPubKey) &&
                !canonical(refresh.groupPubKey).empty() ?
            std::nullopt :
            std::optional<std::string>("has another key at that epoch");
    }
    if (current.has_value() && refresh.groupKeyVersion > static_cast<std::uint64_t>(current->keyVersion)) {
        return "is not at that epoch yet";
    }
    // A past epoch: the key the group's verified chain opened it with. Never "any key below the current epoch": a
    // removed member could then sign in a key of their own for an epoch the group has left.
    if (current.has_value() && chainKey.has_value()) {
        return canonical(chainKey.value()) == canonical(refresh.groupPubKey) &&
                !canonical(refresh.groupPubKey).empty() ?
            std::nullopt :
            std::optional<std::string>("had another key at that epoch");
    }
    // Nothing to hold it to (a group that shows this reader nothing, or an epoch its verified chain does not have): taken
    // from whichever recipient signed it. Owner decision 2026-11-27: what that leaves needs a lying Bridge and a
    // current member, and costs availability only.
    return std::nullopt;
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
    const auto& users = prior.has_value() ? prior->users : statement.addedUsers;
    const auto& groups = prior.has_value() ? prior->groups : statement.addedGroups;
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
    keytree::SpaceLogState verified;
    const std::uint64_t head = static_cast<std::uint64_t>(spaceInfo(spaceId, true, &verified).seq);
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
            .refreshedGroups = {},
        };
        for (const auto& group : statement.addedGroups) {
            entry.addedGroups.push_back(group.groupId);
        }
        for (const auto& user : statement.addedUsers) {
            entry.addedUsers.push_back(user.userId);
        }
        entry.removedGroups = statement.removedGroups;
        entry.removedUsers = statement.removedUsers;
        for (const auto& group : statement.refreshedGroups) {
            entry.refreshedGroups.push_back(
                SpaceGroupRecipient{
                    .groupId = group.groupId,
                    .role = next.group(group.groupId)->role,
                    .keyVersion = static_cast<int64_t>(group.groupKeyVersion),
                }
            );
        }
        entries.push_back(std::move(entry));
        state = next;
    }
    if (!state.has_value() || state->seq != verified.seq || state->digest != verified.digest) {
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
        // the Bridge never serves another Space under this id, so anything served under it is held to that history.
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

// The key of a version: the one the statement that made it committed to, or the Bridge has served another.
static bool spaceKeyCommitted(
    const std::optional<keytree::SpaceLogState>& log,
    const std::string& spaceId,
    std::int64_t keyVersion,
    const std::string& key
) {
    const auto commit = log.has_value() ? log->keyCommits.find(static_cast<std::uint64_t>(keyVersion)) :
                                          std::map<std::uint64_t, std::string>::const_iterator{};
    return log.has_value() &&
        commit != log->keyCommits.end() &&
        commit->second == keytree::SpaceLog::keyCommit(spaceId, static_cast<std::uint64_t>(keyVersion), key);
}

GroupApiImpl::SpaceKeyUse GroupApiImpl::spaceKeyAt(const group::server::SpaceInfo& space, std::int64_t keyVersion) {
    if (keyVersion < 1 || keyVersion > space.keyVersion) {
        throw EnvelopeNotARecipientException("no key of the Space at version " + std::to_string(keyVersion));
    }
    if (space.keyVersion > static_cast<std::int64_t>(UINT32_MAX)) {
        throw GroupDataIntegrityException("Space " + space.id + ": a key version past the ladder's range");
    }
    // A delete moves the generation: nothing opened before it is used after (`dropSpace`).
    const std::string prefix = space.id + ":" + std::to_string(spaceGeneration(space.id)) + ":";
    const std::string cacheKey = prefix + std::to_string(keyVersion);
    if (keyVersion < space.keyVersion) {
        if (const auto cached = _spaceKeys.get(cacheKey); cached.has_value()) {
            return cached.value(); // an earlier version, opened once already
        }
        // Down the ladder from the current key (LadderMath::walkDown, as a group's epochs), starting from the deepest
        // version already held on the canonical path. What is the Space's own: a rung is a symmetric seal
        // (`SpaceLog::openRung`), unsigned, so each key it gives is held to the version's keyCommit.
        const auto path = keytree::LadderMath::canonicalDescent(
            static_cast<std::uint32_t>(space.keyVersion), static_cast<std::uint32_t>(keyVersion), 1
        );
        std::uint32_t from = static_cast<std::uint32_t>(space.keyVersion);
        std::string key;
        for (std::size_t i = path.size(); i-- > 0 && key.empty();) {
            if (const auto cached = _spaceKeys.get(prefix + std::to_string(path[i].target)); cached.has_value()) {
                from = path[i].target;
                key = cached->key;
            }
        }
        if (key.empty()) {
            key = spaceKeyAt(space, space.keyVersion).key;
        }
        struct Rung {
            keytree::RungSpan span;
            std::string data; // base64, as served
        };
        const std::uint32_t goal = static_cast<std::uint32_t>(keyVersion);
        // What `spaceGetKeyArchive` served: each version's rungs (a version fetched is one key here, even with none),
        // and the caller's own wraps of earlier versions that still have them.
        std::map<std::uint32_t, std::vector<Rung>> served;
        std::vector<group::server::SpaceKeyEntry> ownWraps;
        const auto fetch = [&](std::uint32_t low, std::uint32_t high) {
            while (low <= high) {
                group::server::SpaceGetKeyArchiveModel model;
                model.id = space.id;
                model.fromKeyVersion = low;
                model.toKeyVersion = high;
                const auto page = _serverApi.spaceGetKeyArchive(model);
                const std::uint32_t pageEnd = page.nextKeyVersion.has_value() &&
                        page.nextKeyVersion.value() > low &&
                        page.nextKeyVersion.value() <= static_cast<std::int64_t>(high) ?
                    static_cast<std::uint32_t>(page.nextKeyVersion.value() - 1) :
                    high;
                for (std::uint32_t version = low; version <= pageEnd; ++version) {
                    served[version].clear();
                }
                for (const group::server::SpaceRung& rung : page.rungs) {
                    if (rung.targetKeyVersion > 0 &&
                        rung.targetKeyVersion < rung.atKeyVersion &&
                        rung.atKeyVersion >= low &&
                        rung.atKeyVersion <= pageEnd) {
                        served[static_cast<std::uint32_t>(rung.atKeyVersion)].push_back(
                            Rung{
                                .span =
                                    {static_cast<std::uint32_t>(rung.atKeyVersion),
                                     static_cast<std::uint32_t>(rung.targetKeyVersion)},
                                .data = rung.data,
                            }
                        );
                    }
                }
                ownWraps.insert(ownWraps.end(), page.keys.begin(), page.keys.end());
                if (pageEnd >= high) {
                    break;
                }
                low = pageEnd + 1;
            }
        };
        const auto log = spaceLogOf(space.id);
        const auto descend = [&](std::uint32_t start, const std::string& startKey) {
            return keytree::LadderMath::walkDown(
                start, goal, startKey, UINT32_MAX,
                [&](std::uint32_t at) -> const std::vector<Rung>& {
                    // Only this version's rungs: a descent of n versions asks about 2*log2(n) times, never the range.
                    if (served.count(at) == 0) {
                        fetch(at, at);
                    }
                    return served[at];
                },
                [&](const Rung& rung, const std::string& atKey) -> std::optional<std::string> {
                    try {
                        return keytree::SpaceLog::openRung(
                            space.id, rung.span.at, rung.span.target, atKey, privmx::utils::Base64::toString(rung.data)
                        );
                    } catch (...) { return std::nullopt; }
                },
                [&](std::uint32_t target, const std::string& targetKey) {
                    return spaceKeyCommitted(log, space.id, target, targetKey);
                },
                [&](const Rung& rung, bool opened) {
                    LOG_WARN(
                        "[spaceKeyAt] space ", space.id, " rung ", rung.span.at, "->", rung.span.target,
                        opened ? " opened to a key its version did not commit to" : " did not open"
                    )
                },
                [&](const Rung& rung, const std::string& targetKey) {
                    _spaceKeys.set(
                        prefix + std::to_string(rung.span.target), SpaceKeyUse{.key = targetKey, .via = {}, .wrap = {}}
                    );
                }
            );
        };
        const auto walk = descend(from, key);
        if (walk.end == keytree::LadderWalkEnd::Reached) {
            return SpaceKeyUse{.key = walk.key, .via = {}, .wrap = {}};
        }
        // A rung that does not lead on: any recipient may rotate, and the Bridge cannot check a symmetric rung, so a
        // rotation by someone who is no manager keeps the older wraps (the Bridge prunes them only after a manager's).
        // The caller's own wrap of `keyVersion`, or of a version between it and where the walk stopped from which the
        // ladder works, is the way round.
        fetch(goal, walk.reached - 1);
        for (std::uint32_t version = goal; version < walk.reached; ++version) {
            const auto atVersion = [&](const group::server::SpaceKeyEntry& entry) {
                return entry.keyVersion == version;
            };
            if (std::none_of(ownWraps.begin(), ownWraps.end(), atVersion)) {
                continue;
            }
            std::optional<SpaceKeyUse> use;
            try {
                use = unwrapOwnSpaceKey(space, version, ownWraps);
            } catch (const std::exception&) {
                continue; // logged; perhaps another version's opens
            }
            _spaceKeys.set(prefix + std::to_string(version), use.value());
            if (version == goal) {
                return use.value();
            }
            if (const auto again = descend(version, use->key); again.end == keytree::LadderWalkEnd::Reached) {
                return SpaceKeyUse{.key = again.key, .via = {}, .wrap = {}};
            }
        }
        throw GroupDataIntegrityException(
            "Space " +
            space.id +
            ": the key ladder does not lead from version " +
            std::to_string(walk.reached) +
            " to " +
            std::to_string(keyVersion) +
            ", and the caller has no wrap of a version on the way"
        );
    }
    if (const auto cached = _spaceKeys.get(cacheKey); cached.has_value() &&
        std::any_of(space.keys.begin(), space.keys.end(), [&](const group::server::SpaceKeyEntry& entry) {
                                                          return entry.keyVersion == keyVersion &&
                                                              entry.data == cached->wrap;
                                                      })) {
        return cached.value(); // still the entry the read serves
    }
    const SpaceKeyUse use = unwrapOwnSpaceKey(space, keyVersion, space.keys);
    _spaceKeys.set(cacheKey, use);
    return use;
}

GroupApiImpl::SpaceKeyUse GroupApiImpl::unwrapOwnSpaceKey(
    const group::server::SpaceInfo& space,
    std::int64_t keyVersion,
    const std::vector<group::server::SpaceKeyEntry>& entries
) {
    const std::string ownUserId = _connection.getImpl()->getMyUserId(space.contextId);
    const std::string ownPubKey = _userPrivKey.getPublicKey().toBase58DER();
    std::exception_ptr lastFailure;
    // The caller's own entry first (no request), then the entries of the groups it is in.
    for (const bool wantGroup : {false, true}) {
        for (const group::server::SpaceKeyEntry& entry : entries) {
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
                if (!spaceKeyCommitted(spaceLogOf(space.id), space.id, keyVersion, key)) {
                    throw GroupDataIntegrityException("not the key the Space's statements name for this version");
                }
                return SpaceKeyUse{.key = key, .via = isGroup ? slot.recipientId : std::string(), .wrap = entry.data};
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

std::vector<group::server::SpaceRung> GroupApiImpl::spaceRungsFor(
    const group::server::SpaceInfo& space,
    std::int64_t next,
    const std::string& nextKey
) {
    // The canonical set (LadderMath::buildRungSet, as a group's epochs), each a symmetric seal of an earlier key.
    return keytree::LadderMath::buildRungSet(
        static_cast<std::uint32_t>(next), 1, true, [&](const keytree::RungSpan& span) {
            group::server::SpaceRung rung;
            rung.atKeyVersion = span.at;
            rung.targetKeyVersion = span.target;
            rung.data = privmx::utils::Base64::from(
                keytree::SpaceLog::sealRung(space.id, span.at, span.target, nextKey, spaceKeyAt(space, span.target).key)
            );
            return rung;
        }
    );
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

// The recipients a statement adds: who the caller named, each group at the epoch and key its wrap was made for.
void GroupApiImpl::appendRecipients(
    keytree::SpaceStatement& statement,
    const std::vector<SpaceRecipient>& recipients,
    const std::vector<SpaceTarget>& targets
) {
    for (const SpaceRecipient& recipient : recipients) {
        if (recipient.user.has_value()) {
            statement.addedUsers.push_back(
                keytree::SpaceLogUser{
                    .userId = recipient.user->userId, .pubKey = recipient.user->pubKey, .role = recipient.role
                }
            );
            continue;
        }
        const auto target = std::find_if(targets.begin(), targets.end(), [&](const SpaceTarget& t) {
            return t.isGroup && t.id == recipient.groupId;
        });
        statement.addedGroups.push_back(
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
    statement.rosterHash = keytree::SpaceLog::rosterHash(statement.addedGroups, statement.addedUsers);
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
    // A new id: the Bridge never hands out a deleted Space's id again, so nothing of an earlier Space is held under it.
    core::EndpointUtils::assertServedId(spaceId, _serverApi.spaceCreate(model).spaceId);
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
    const OpenedEnvelope opened = _envelopeEncryptor.openSpaceEnvelope(
        sealed, spaceKeyAt(space, routing.keyVersion).key, metaBinding(space.privateMetaVersion)
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
    std::map<std::string, std::uint64_t> seqsWhenSent;
    std::map<std::string, std::uint64_t> generationsWhenSent;
    {
        std::lock_guard lock(_spaceLogsMutex);
        for (const auto& [id, log] : _spaceLogs) {
            seqsWhenSent[id] = log.seq;
        }
        generationsWhenSent = _spaceGenerations;
    }
    const group::server::SpaceListResult result = _serverApi.spaceList(model);
    std::vector<SpaceState> spaces;
    spaces.reserve(result.spaces.size());
    for (const group::server::SpaceInfo& space : result.spaces) {
        // Overtaken by a change, a delete or a create of this process while the listing was in flight: left out.
        if (spaceOvertaken(space, seqsWhenSent[space.id])) {
            continue;
        }
        group::server::SpaceInfo verified = space;
        verifySpace(verified);
        if (spaceGeneration(space.id) != generationsWhenSent[space.id]) {
            continue;
        }
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
    if (recipients.empty()) {
        throw core::InvalidParamsException("field:recipients cannot be empty");
    }
    keytree::SpaceLogState verified;
    const group::server::SpaceInfo space = spaceInfo(spaceId, true, &verified);
    // Checked against the verified history before anything is signed: a mistake is the caller's, never the Bridge's.
    // Every one already there as asked (a retry after a lost answer) is the addition done; some is a mistake.
    std::set<std::string> named;
    std::size_t present = 0;
    for (const SpaceRecipient& recipient : recipients) {
        const bool isUser = recipient.user.has_value();
        const std::string id = isUser ? recipient.user->userId : recipient.groupId;
        if (!named.insert((isUser ? "u:" : "g:") + id).second) {
            throw core::InvalidParamsException("recipient " + id + " is named twice");
        }
        const keytree::SpaceLogGroup* group = isUser ? nullptr : verified.group(id);
        const std::string role = isUser ? verified.roleOfUser(id) : (group != nullptr ? group->role : std::string());
        if (role.empty()) {
            continue;
        }
        const bool asAsked = role == recipient.role &&
            (!isUser || std::any_of(verified.users.begin(), verified.users.end(), [&](const keytree::SpaceLogUser& u) {
                                 return u.userId == id && u.pubKey == recipient.user->pubKey;
                             }));
        if (!asAsked) {
            throw core::InvalidParamsException("recipient " + id + " is already in the Space, in another role or key");
        }
        ++present;
    }
    if (present == recipients.size()) {
        return; // already done
    }
    if (present != 0) {
        throw core::InvalidParamsException("some of the recipients are already in the Space");
    }
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
    // The current version only: an earlier one is read down the key ladder from it, so they read what is already
    // there without a wrap per version.
    const std::vector<SpaceTarget> targets = spaceTargets(space.contextId, groupIds, users);
    model.keys = wrapSpaceKeyFor(
        spaceId, space.contextId, space.keyVersion, spaceKeyAt(space, space.keyVersion).key, targets
    );
    // The state of the same read the key above came from: a later one could commit to a newer key.
    const std::optional<keytree::SpaceLogState> prior = verified;
    keytree::SpaceStatement statement;
    statement.spaceId = spaceId;
    statement.contextId = space.contextId;
    statement.op = keytree::SpaceOp::Add;
    statement.keyVersion = prior.value().keyVersion;
    statement.keyCommit = prior->keyCommits.at(prior->keyVersion);
    appendRecipients(statement, recipients, targets);
    std::vector<keytree::SpaceLogGroup> rosterGroups = prior->groups;
    std::vector<keytree::SpaceLogUser> rosterUsers = prior->users;
    rosterGroups.insert(rosterGroups.end(), statement.addedGroups.begin(), statement.addedGroups.end());
    rosterUsers.insert(rosterUsers.end(), statement.addedUsers.begin(), statement.addedUsers.end());
    statement.rosterHash = keytree::SpaceLog::rosterHash(rosterGroups, rosterUsers);
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
    const std::vector<std::string>& withoutUsers,
    bool forStaleWrite
) {
    keytree::SpaceLogState verified;
    const group::server::SpaceInfo space = spaceInfo(spaceId, true, &verified);
    const auto dropped = [](const std::vector<std::string>& list, const std::string& id) {
        return std::find(list.begin(), list.end(), id) != list.end();
    };
    if (!withoutGroups.empty() || !withoutUsers.empty()) {
        // A removal, checked against the verified history before anything is signed: none of them still there (a
        // retry after a lost answer) is the removal done; some is the caller's mistake, and so is no manager left.
        std::size_t absent = 0;
        for (const std::string& id : withoutGroups) {
            absent += verified.group(id) == nullptr ? 1 : 0;
        }
        for (const std::string& id : withoutUsers) {
            absent += verified.roleOfUser(id).empty() ? 1 : 0;
        }
        if (absent == withoutGroups.size() + withoutUsers.size()) {
            return static_cast<std::int64_t>(verified.keyVersion); // already done
        }
        if (absent != 0) {
            throw core::InvalidParamsException("some of the recipients to remove are not in the Space");
        }
        const bool managerLeft = std::any_of(
                                     verified.groups.begin(), verified.groups.end(),
                                     [&](const keytree::SpaceLogGroup& g) {
                                         return g.role == "manager" && !dropped(withoutGroups, g.groupId);
                                     }
                                 ) ||
            std::any_of(verified.users.begin(), verified.users.end(), [&](const keytree::SpaceLogUser& u) {
                                     return u.role == "manager" && !dropped(withoutUsers, u.userId);
                                 });
        if (!managerLeft) {
            throw core::InvalidParamsException("a Space keeps at least one manager");
        }
    }
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
    // The new version's rungs: what every earlier version is read through from now on.
    model.rungs = spaceRungsFor(space, next, spaceKey);
    model.expectedKeyVersion = space.keyVersion;
    // Who stays, as the statements of the same read have them; each group at the epoch and key it was just wrapped
    // for.
    const std::optional<keytree::SpaceLogState> prior = verified;
    keytree::SpaceStatement statement;
    statement.spaceId = spaceId;
    statement.contextId = space.contextId;
    statement.op = withoutGroups.empty() && withoutUsers.empty() ? keytree::SpaceOp::Rotate : keytree::SpaceOp::Remove;
    statement.keyVersion = static_cast<std::uint64_t>(next);
    statement.keyCommit = keytree::SpaceLog::keyCommit(spaceId, static_cast<std::uint64_t>(next), spaceKey);
    std::vector<keytree::SpaceLogGroup> staying;
    for (const keytree::SpaceLogGroup& group : prior.value().groups) {
        const auto target = std::find_if(targets.begin(), targets.end(), [&](const SpaceTarget& t) {
            return t.isGroup && t.id == group.groupId;
        });
        if (target != targets.end()) {
            staying.push_back(
                keytree::SpaceLogGroup{
                    .groupId = group.groupId,
                    .role = group.role,
                    .groupKeyVersion = static_cast<std::uint64_t>(target->groupKeyVersion),
                    .groupPubKey = target->pubKey,
                }
            );
        }
    }
    std::vector<keytree::SpaceLogUser> stayingUsers;
    for (const keytree::SpaceLogUser& user : prior->users) {
        if (!dropped(withoutUsers, user.userId)) {
            stayingUsers.push_back(user);
        }
    }
    // As deltas on the verified state: the removed, and each staying group whose epoch moved since.
    keytree::SpaceLog::setRoster(statement, prior, staying, stayingUsers);
    try {
        statement = signSpaceStatement(std::move(statement), prior);
    } catch (const GroupUnauthorizedSignerException& e) {
        if (!forStaleWrite) {
            throw;
        }
        // Not this caller's to sign (no standing in the verified state).
        // Nothing is written under a key a removed member holds; whoever may, replaces it first.
        throw EnvelopeStaleEpochException("the Space's key is stale and the caller may not replace it", e);
    }
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
    if (const auto log = spaceLogOf(spaceId); log.has_value() && static_cast<std::uint64_t>(space.seq) < log->seq) {
        space = spaceInfo(spaceId, true); // a cached read from before a change this process has verified since
    }
    if (spaceKeyIsStale(space)) {
        // Someone removed from a recipient group still holds this key: nothing more is written under it.
        try {
            replaceSpaceKey(spaceId, {}, {}, true);
        } catch (const SpaceRecipientUnavailableException&) { throw; } catch (const EnvelopeStaleEpochException&) {
            throw; // the caller may not sign the replacement
        } catch (const GroupHistoryForkException&) {
            throw; // a history that does not hold is the answer, never a lost race
        } catch (const GroupUnauthorizedSignerException&) {
            throw; // a statement served that does not verify: what verifySpace found, not a lost race
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
        } catch (const core::Exception& e) {
            if (isForgedHistory(e)) {
                throw; // the group's history does not verify: the answer, not "a group the caller is not in"
            }
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
