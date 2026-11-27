/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include "privmx/endpoint/group/keytree/SpaceLog.hpp"

#include <algorithm>
#include <set>
#include <stdexcept>

#include <privmx/crypto/Crypto.hpp>
#include <privmx/crypto/ecc/PublicKey.hpp>
#include <privmx/endpoint/core/BigEndian.hpp>
#include <privmx/utils/Utils.hpp>

#include "privmx/endpoint/group/GroupException.hpp"
#include "privmx/endpoint/group/keytree/TreeCommits.hpp"

using namespace privmx::endpoint::group;
using namespace privmx::endpoint::group::keytree;
namespace be = privmx::endpoint::core::bigendian;

namespace {

std::string tag(const char* name) {
    return TreeCommits::tag(name);
}

bool isRole(const std::string& role) {
    return role == "user" || role == "manager";
}

bool verifies(const std::string& pubKeyBase58, const std::string& bytes, const std::string& signature) {
    try {
        return privmx::crypto::PublicKey::fromBase58DER(pubKeyBase58).verifyCompactSignatureWithHash(bytes, signature);
    } catch (...) { return false; }
}

void putGroup(std::string& out, const SpaceLogGroup& group) {
    be::putLp(out, group.groupId);
    be::putLp(out, group.role);
    be::putU64(out, group.groupKeyVersion);
    be::putLp(out, group.groupPubKey);
}

void putUser(std::string& out, const SpaceLogUser& user) {
    be::putLp(out, user.userId);
    be::putLp(out, user.pubKey);
    be::putLp(out, user.role);
}

template<typename T, typename Id>
std::vector<T> sortedBy(std::vector<T> values, Id id) {
    std::sort(values.begin(), values.end(), [&](const T& a, const T& b) { return id(a) < id(b); });
    return values;
}

const std::string& groupIdOf(const SpaceLogGroup& group) {
    return group.groupId;
}

const std::string& userIdOf(const SpaceLogUser& user) {
    return user.userId;
}

const std::string& itself(const std::string& id) {
    return id;
}

} // namespace

std::string SpaceLogState::roleOfUser(const std::string& userId) const {
    for (const SpaceLogUser& user : users) {
        if (user.userId == userId) {
            return user.role;
        }
    }
    return std::string();
}

const SpaceLogGroup* SpaceLogState::group(const std::string& groupId) const {
    for (const SpaceLogGroup& group : groups) {
        if (group.groupId == groupId) {
            return &group;
        }
    }
    return nullptr;
}

std::string SpaceLog::opName(SpaceOp op) {
    switch (op) {
    case SpaceOp::Create:
        return "create";
    case SpaceOp::Add:
        return "add";
    case SpaceOp::Remove:
        return "remove";
    case SpaceOp::Rotate:
        return "rotate";
    }
    throw std::invalid_argument("unknown space op");
}

std::string SpaceLog::rosterHash(std::vector<SpaceLogGroup> groups, std::vector<SpaceLogUser> users) {
    std::string preimage = tag("pmx-space-roster-v1");
    be::putU32(preimage, static_cast<std::uint32_t>(groups.size()));
    for (const SpaceLogGroup& group : sortedBy(std::move(groups), groupIdOf)) {
        putGroup(preimage, group);
    }
    be::putU32(preimage, static_cast<std::uint32_t>(users.size()));
    for (const SpaceLogUser& user : sortedBy(std::move(users), userIdOf)) {
        putUser(preimage, user);
    }
    return privmx::crypto::Crypto::sha256(preimage);
}

void SpaceLog::setRoster(
    SpaceStatement& statement,
    const std::optional<SpaceLogState>& prior,
    const std::vector<SpaceLogGroup>& groups,
    const std::vector<SpaceLogUser>& users
) {
    statement.addedGroups.clear();
    statement.addedUsers.clear();
    statement.removedGroups.clear();
    statement.removedUsers.clear();
    statement.refreshedGroups.clear();
    const std::vector<SpaceLogGroup> noGroups;
    const std::vector<SpaceLogUser> noUsers;
    const auto& priorGroups = prior.has_value() ? prior->groups : noGroups;
    const auto& priorUsers = prior.has_value() ? prior->users : noUsers;
    for (const SpaceLogGroup& was : priorGroups) {
        const auto now = std::find_if(groups.begin(), groups.end(), [&](const auto& g) {
            return g.groupId == was.groupId;
        });
        if (now == groups.end() || now->role != was.role) {
            statement.removedGroups.push_back(was.groupId);
        } else if (now->groupKeyVersion != was.groupKeyVersion || now->groupPubKey != was.groupPubKey) {
            statement.refreshedGroups.push_back(
                SpaceLogGroup{
                    .groupId = now->groupId,
                    .role = std::string(),
                    .groupKeyVersion = now->groupKeyVersion,
                    .groupPubKey = now->groupPubKey,
                }
            );
        }
    }
    for (const SpaceLogGroup& group : groups) {
        const auto was = std::find_if(priorGroups.begin(), priorGroups.end(), [&](const auto& g) {
            return g.groupId == group.groupId;
        });
        if (was == priorGroups.end() || was->role != group.role) {
            statement.addedGroups.push_back(group);
        }
    }
    for (const SpaceLogUser& was : priorUsers) {
        const auto now = std::find_if(users.begin(), users.end(), [&](const auto& u) {
            return u.userId == was.userId;
        });
        if (now == users.end() || now->role != was.role || now->pubKey != was.pubKey) {
            statement.removedUsers.push_back(was.userId);
        }
    }
    for (const SpaceLogUser& user : users) {
        const auto was = std::find_if(priorUsers.begin(), priorUsers.end(), [&](const auto& u) {
            return u.userId == user.userId;
        });
        if (was == priorUsers.end() || was->role != user.role || was->pubKey != user.pubKey) {
            statement.addedUsers.push_back(user);
        }
    }
    statement.rosterHash = rosterHash(groups, users);
}

std::string SpaceLog::keyCommit(const std::string& spaceId, std::uint64_t keyVersion, const std::string& key) {
    std::string preimage = tag("pmx-space-key");
    be::putLp(preimage, spaceId);
    be::putU64(preimage, keyVersion);
    return privmx::crypto::Crypto::sha256(preimage + key);
}

std::string SpaceLog::signedBytes(const SpaceStatement& statement) {
    if (statement.keyCommit.size() != 32 ||
        statement.rosterHash.size() != 32 ||
        statement.prevDigest.size() != (statement.seq == 1 ? 0u : 32u)) {
        throw std::invalid_argument("space statement hashes must be 32 bytes");
    }
    std::string bytes = tag("pmx-space-statement");
    be::putU8(bytes, 2);
    be::putLp(bytes, statement.spaceId);
    be::putLp(bytes, statement.contextId);
    be::putU64(bytes, statement.seq);
    be::putLp(bytes, statement.prevDigest);
    be::putU8(bytes, static_cast<std::uint8_t>(statement.op));
    be::putU64(bytes, statement.date);
    be::putU64(bytes, statement.keyVersion);
    bytes += statement.keyCommit;
    bytes += statement.rosterHash;
    // Each list by id, whatever order it came in.
    be::putU32(bytes, static_cast<std::uint32_t>(statement.addedGroups.size()));
    for (const SpaceLogGroup& group : sortedBy(statement.addedGroups, groupIdOf)) {
        putGroup(bytes, group);
    }
    be::putU32(bytes, static_cast<std::uint32_t>(statement.addedUsers.size()));
    for (const SpaceLogUser& user : sortedBy(statement.addedUsers, userIdOf)) {
        putUser(bytes, user);
    }
    TreeCommits::putList(bytes, sortedBy(statement.removedGroups, itself));
    TreeCommits::putList(bytes, sortedBy(statement.removedUsers, itself));
    be::putU32(bytes, static_cast<std::uint32_t>(statement.refreshedGroups.size()));
    for (const SpaceLogGroup& group : sortedBy(statement.refreshedGroups, groupIdOf)) {
        be::putLp(bytes, group.groupId);
        be::putU64(bytes, group.groupKeyVersion);
        be::putLp(bytes, group.groupPubKey);
    }
    be::putLp(bytes, statement.signer);
    be::putLp(bytes, statement.signerPubKey);
    be::putLp(bytes, statement.via);
    return bytes;
}

std::string SpaceLog::viaBytes(const SpaceStatement& statement) {
    return tag("pmx-space-via") + privmx::crypto::Crypto::sha256(signedBytes(statement));
}

std::string SpaceLog::digest(const SpaceStatement& statement) {
    return privmx::crypto::Crypto::sha256(signedBytes(statement) + statement.signature + statement.viaSignature);
}

void SpaceLog::sign(
    SpaceStatement& statement,
    const privmx::crypto::PrivateKey& signerKey,
    const std::optional<privmx::crypto::PrivateKey>& viaKey
) {
    if (statement.via.empty() == viaKey.has_value()) {
        throw std::invalid_argument("a statement through a group is signed with that group's key, and no other is");
    }
    statement.signerPubKey = signerKey.getPublicKey().toBase58DER();
    statement.signature = signerKey.signToCompactSignatureWithHash(signedBytes(statement));
    statement.viaSignature = viaKey.has_value() ? viaKey->signToCompactSignatureWithHash(viaBytes(statement)) :
                                                  std::string();
}

SpaceLogState SpaceLog::apply(const std::optional<SpaceLogState>& prior, const SpaceStatement& statement) {
    const auto broken = [](const std::string& what) { return GroupDataIntegrityException("space statement: " + what); };
    const std::uint64_t seq = prior.has_value() ? prior->seq + 1 : 1;
    if (statement.seq != seq) {
        throw broken("out of order");
    }
    if (statement.keyCommit.size() != 32 ||
        statement.rosterHash.size() != 32 ||
        statement.prevDigest.size() != (seq == 1 ? 0u : 32u)) {
        throw broken("malformed hashes");
    }
    if (prior.has_value() &&
        (statement.prevDigest != prior->digest ||
         statement.spaceId != prior->spaceId ||
         statement.contextId != prior->contextId)) {
        throw broken("does not follow the one before it");
    }
    if ((statement.op == SpaceOp::Create) != (seq == 1)) {
        throw broken("a Space is created once, by its first statement");
    }

    // The deltas, on their own: each id once across its kind's lists, each added entry with a role, and only the
    // lists its op has.
    std::set<std::string> groupIds;
    std::set<std::string> userIds;
    const auto once = [&](std::set<std::string>& ids, const std::string& id) {
        if (id.empty() || !ids.insert(id).second) {
            throw broken("a recipient named twice, or with no id");
        }
    };
    for (const SpaceLogGroup& group : statement.addedGroups) {
        once(groupIds, group.groupId);
        if (!isRole(group.role)) {
            throw broken("malformed recipients");
        }
    }
    for (const SpaceLogUser& user : statement.addedUsers) {
        once(userIds, user.userId);
        if (!isRole(user.role)) {
            throw broken("malformed recipients");
        }
    }
    for (const std::string& id : statement.removedGroups) {
        once(groupIds, id);
    }
    for (const std::string& id : statement.removedUsers) {
        once(userIds, id);
    }
    for (const SpaceLogGroup& group : statement.refreshedGroups) {
        once(groupIds, group.groupId);
    }
    const bool adds = !statement.addedGroups.empty() || !statement.addedUsers.empty();
    const bool removes = !statement.removedGroups.empty() || !statement.removedUsers.empty();
    const bool refreshes = !statement.refreshedGroups.empty();
    switch (statement.op) {
    case SpaceOp::Create:
        if (removes || refreshes) {
            throw broken("a creation only names its recipients");
        }
        break;
    case SpaceOp::Add:
        if (!adds || removes || refreshes) {
            throw broken("an addition only adds");
        }
        break;
    case SpaceOp::Remove:
        if (!removes || adds) {
            throw broken("a removal only removes");
        }
        break;
    case SpaceOp::Rotate:
        if (adds || removes) {
            throw broken("a rotation leaves the recipients as they are");
        }
        break;
    }

    // The signer's own signature, then their standing: among the recipients BEFORE this statement (a creation has
    // only its own list). Through a group, standing is shown by signing with that group's key - which every member
    // of it holds and nobody else - so a reader needs no sight of the group's roster.
    if (!verifies(statement.signerPubKey, signedBytes(statement), statement.signature)) {
        throw GroupUnauthorizedSignerException("space statement: the signature is not the signer's");
    }
    SpaceLogState standing;
    if (prior.has_value()) {
        standing = prior.value();
    } else {
        standing.groups = statement.addedGroups;
        standing.users = statement.addedUsers;
    }
    std::string role;
    if (statement.via.empty()) {
        if (!statement.viaSignature.empty()) {
            throw broken("a group's signature with no group named");
        }
        for (const SpaceLogUser& user : standing.users) {
            if (user.userId == statement.signer && user.pubKey == statement.signerPubKey) {
                role = user.role;
            }
        }
    } else if (const SpaceLogGroup* group = standing.group(statement.via); group != nullptr) {
        if (verifies(group->groupPubKey, viaBytes(statement), statement.viaSignature)) {
            role = group->role;
        }
    }
    if (role.empty()) {
        throw GroupUnauthorizedSignerException(
            "space statement: " + statement.signer + " is no recipient of the Space"
        );
    }
    if (statement.op != SpaceOp::Rotate && role != "manager") {
        throw GroupUnauthorizedSignerException("space statement: only a manager changes the recipients");
    }

    // The deltas on the recipients before it.
    std::vector<SpaceLogGroup> groups = prior.has_value() ? prior->groups : std::vector<SpaceLogGroup>{};
    std::vector<SpaceLogUser> users = prior.has_value() ? prior->users : std::vector<SpaceLogUser>{};
    for (const std::string& id : statement.removedGroups) {
        const auto found = std::find_if(groups.begin(), groups.end(), [&](const auto& g) { return g.groupId == id; });
        if (found == groups.end()) {
            throw broken("removes group " + id + ", which is no recipient");
        }
        groups.erase(found);
    }
    for (const std::string& id : statement.removedUsers) {
        const auto found = std::find_if(users.begin(), users.end(), [&](const auto& u) { return u.userId == id; });
        if (found == users.end()) {
            throw broken("removes user " + id + ", who is no recipient");
        }
        users.erase(found);
    }
    // A group's pinned epoch and key are what "through that group" is checked against from here on, and what the
    // next key is wrapped to. So they move only forward, to another key. Any recipient may move them, as the Bridge
    // lets any recipient rotate (a stale key must not wait for a manager): whether the new key is the group's is
    // not something the statement can show, so the reader checks it against the group's verified keys
    // (GroupApiImpl::requireGroupKeyRefreshesHold), and refuses one it cannot verify unless a manager of the Space
    // (who could replace the group anyway) or the group itself signed it.
    for (const SpaceLogGroup& refresh : statement.refreshedGroups) {
        const auto found = std::find_if(groups.begin(), groups.end(), [&](const auto& g) {
            return g.groupId == refresh.groupId;
        });
        if (found == groups.end()) {
            throw broken("refreshes group " + refresh.groupId + ", which is no recipient");
        }
        if (refresh.groupKeyVersion <= found->groupKeyVersion || refresh.groupPubKey == found->groupPubKey) {
            throw broken("a group's key is replaced by a later epoch's only");
        }
        found->groupKeyVersion = refresh.groupKeyVersion;
        found->groupPubKey = refresh.groupPubKey;
    }
    for (const SpaceLogGroup& group : statement.addedGroups) {
        if (prior.has_value() && prior->group(group.groupId) != nullptr) {
            throw broken("adds group " + group.groupId + ", which is a recipient already");
        }
        groups.push_back(group);
    }
    for (const SpaceLogUser& user : statement.addedUsers) {
        if (prior.has_value() && !prior->roleOfUser(user.userId).empty()) {
            throw broken("adds user " + user.userId + ", who is a recipient already");
        }
        users.push_back(user);
    }
    const bool hasManager = std::any_of(
                                groups.begin(), groups.end(), [](const auto& g) { return g.role == "manager"; }
                            ) ||
        std::any_of(users.begin(), users.end(), [](const auto& u) { return u.role == "manager"; });
    if (!hasManager) {
        throw broken("a Space keeps a manager");
    }
    if (rosterHash(groups, users) != statement.rosterHash) {
        throw broken("the recipients after it are not the ones its rosterHash names");
    }

    std::map<std::uint64_t, std::string> keyCommits;
    if (prior.has_value()) {
        keyCommits = prior->keyCommits;
        const bool newKey = statement.op != SpaceOp::Add;
        if (statement.keyVersion != prior->keyVersion + (newKey ? 1 : 0)) {
            throw broken("the key version moves by one, with a new key only");
        }
        if (!newKey && statement.keyCommit != prior->keyCommits.at(prior->keyVersion)) {
            throw broken("an addition keeps the key");
        }
    } else if (statement.keyVersion != 1) {
        throw broken("a Space starts at key version 1");
    }
    keyCommits[statement.keyVersion] = statement.keyCommit;

    return SpaceLogState{
        .spaceId = statement.spaceId,
        .contextId = statement.contextId,
        .creator = prior.has_value() ? prior->creator : statement.signer,
        .seq = seq,
        .digest = digest(statement),
        .keyVersion = statement.keyVersion,
        .groups = std::move(groups),
        .users = std::move(users),
        .keyCommits = std::move(keyCommits),
    };
}

namespace {

std::string rungAad(const std::string& spaceId, std::uint64_t at, std::uint64_t target) {
    std::string aad = tag("pmx-space-rung");
    be::putLp(aad, spaceId);
    be::putU64(aad, at);
    be::putU64(aad, target);
    return aad;
}

} // namespace

std::string SpaceLog::sealRung(
    const std::string& spaceId,
    std::uint64_t at,
    std::uint64_t target,
    const std::string& atKey,
    const std::string& targetKey
) {
    if (target >= at || atKey.size() != 32 || targetKey.size() != 32) {
        throw std::invalid_argument("a rung seals an earlier version's 32-byte key under a later one's");
    }
    const std::string iv = privmx::crypto::Crypto::randomBytes(12);
    return iv + privmx::crypto::Crypto::aes256GcmEncrypt(targetKey, atKey, iv, rungAad(spaceId, at, target));
}

std::string SpaceLog::openRung(
    const std::string& spaceId,
    std::uint64_t at,
    std::uint64_t target,
    const std::string& atKey,
    const std::string& sealed
) {
    std::string key;
    if (target < at && atKey.size() == 32 && sealed.size() == 12 + 32 + 16) {
        try {
            key = privmx::crypto::Crypto::aes256GcmDecrypt(
                sealed.substr(12), atKey, sealed.substr(0, 12), rungAad(spaceId, at, target)
            );
        } catch (...) { key.clear(); }
    }
    if (key.size() != 32) {
        throw GroupDataIntegrityException(
            "space rung " + std::to_string(at) + "->" + std::to_string(target) + " does not open"
        );
    }
    return key;
}

std::string SpaceLog::encodeStates(const std::map<std::string, SpaceLogState>& states) {
    std::string body;
    be::putU32(body, static_cast<std::uint32_t>(states.size()));
    for (const auto& [id, state] : states) {
        be::putLp(body, id);
        be::putLp(body, state.contextId);
        be::putLp(body, state.creator);
        be::putU64(body, state.seq);
        be::putLp(body, state.digest);
        be::putU64(body, state.keyVersion);
        be::putU32(body, static_cast<std::uint32_t>(state.groups.size()));
        for (const SpaceLogGroup& group : state.groups) {
            be::putLp(body, group.groupId);
            be::putLp(body, group.role);
            be::putU64(body, group.groupKeyVersion);
            be::putLp(body, group.groupPubKey);
        }
        be::putU32(body, static_cast<std::uint32_t>(state.users.size()));
        for (const SpaceLogUser& user : state.users) {
            be::putLp(body, user.userId);
            be::putLp(body, user.pubKey);
            be::putLp(body, user.role);
        }
        // Versions 1..keyVersion, each made by one statement: no gaps, so no version numbers.
        for (std::uint64_t version = 1; version <= state.keyVersion; ++version) {
            const auto commit = state.keyCommits.find(version);
            body += commit == state.keyCommits.end() ? std::string(32, '\0') : commit->second;
        }
    }
    return body;
}

std::optional<std::map<std::string, SpaceLogState>> SpaceLog::decodeStates(const std::string& body) {
    try {
        be::Reader in(body);
        std::map<std::string, SpaceLogState> states;
        const std::uint32_t count = in.u32();
        for (std::uint32_t i = 0; i < count; ++i) {
            SpaceLogState state;
            state.spaceId = in.lp();
            state.contextId = in.lp();
            state.creator = in.lp();
            state.seq = in.u64();
            state.digest = in.lp();
            state.keyVersion = in.u64();
            for (std::uint32_t n = in.u32(); n > 0; --n) {
                SpaceLogGroup group;
                group.groupId = in.lp();
                group.role = in.lp();
                group.groupKeyVersion = in.u64();
                group.groupPubKey = in.lp();
                state.groups.push_back(std::move(group));
            }
            for (std::uint32_t n = in.u32(); n > 0; --n) {
                SpaceLogUser user;
                user.userId = in.lp();
                user.pubKey = in.lp();
                user.role = in.lp();
                state.users.push_back(std::move(user));
            }
            if (state.seq == 0 || state.keyVersion == 0 || state.digest.size() != 32) {
                return std::nullopt;
            }
            for (std::uint64_t version = 1; version <= state.keyVersion; ++version) {
                std::string commit;
                for (int b = 0; b < 32; ++b) {
                    commit += static_cast<char>(in.u8());
                }
                state.keyCommits[version] = std::move(commit);
            }
            const std::string id = state.spaceId;
            if (!states.emplace(id, std::move(state)).second) {
                return std::nullopt;
            }
        }
        if (!in.done()) {
            return std::nullopt;
        }
        return states;
    } catch (const std::exception&) { return std::nullopt; }
}

server::SpaceStatement SpaceLog::toWire(const SpaceStatement& statement) {
    server::SpaceStatement wire;
    wire.spaceId = statement.spaceId;
    wire.contextId = statement.contextId;
    wire.seq = static_cast<std::int64_t>(statement.seq);
    wire.prevDigest = privmx::utils::Hex::from(statement.prevDigest);
    wire.op = opName(statement.op);
    wire.date = static_cast<std::int64_t>(statement.date);
    wire.keyVersion = static_cast<std::int64_t>(statement.keyVersion);
    wire.keyCommit = privmx::utils::Hex::from(statement.keyCommit);
    wire.rosterHash = privmx::utils::Hex::from(statement.rosterHash);
    for (const SpaceLogGroup& group : statement.addedGroups) {
        server::SpaceGroup entry;
        entry.groupId = group.groupId;
        entry.role = group.role;
        entry.groupKeyVersion = static_cast<std::int64_t>(group.groupKeyVersion);
        entry.groupPubKey = group.groupPubKey;
        wire.addedGroups.push_back(std::move(entry));
    }
    for (const SpaceLogUser& user : statement.addedUsers) {
        server::SpaceUser entry;
        entry.userId = user.userId;
        entry.pubKey = user.pubKey;
        entry.role = user.role;
        wire.addedUsers.push_back(std::move(entry));
    }
    wire.removedGroups = statement.removedGroups;
    wire.removedUsers = statement.removedUsers;
    for (const SpaceLogGroup& group : statement.refreshedGroups) {
        server::SpaceGroupKey entry;
        entry.groupId = group.groupId;
        entry.groupKeyVersion = static_cast<std::int64_t>(group.groupKeyVersion);
        entry.groupPubKey = group.groupPubKey;
        wire.refreshedGroups.push_back(std::move(entry));
    }
    wire.signer = statement.signer;
    wire.signerPubKey = statement.signerPubKey;
    wire.via = statement.via;
    wire.signature = privmx::utils::Base64::from(statement.signature);
    wire.viaSignature = privmx::utils::Base64::from(statement.viaSignature);
    return wire;
}

SpaceStatement SpaceLog::fromWire(const server::SpaceStatement& wire) {
    SpaceStatement statement;
    statement.spaceId = wire.spaceId;
    statement.contextId = wire.contextId;
    statement.seq = static_cast<std::uint64_t>(wire.seq);
    statement.prevDigest = privmx::utils::Hex::toString(wire.prevDigest);
    if (wire.op == "create") {
        statement.op = SpaceOp::Create;
    } else if (wire.op == "add") {
        statement.op = SpaceOp::Add;
    } else if (wire.op == "remove") {
        statement.op = SpaceOp::Remove;
    } else if (wire.op == "rotate") {
        statement.op = SpaceOp::Rotate;
    } else {
        throw GroupDataIntegrityException("space statement: unknown op");
    }
    statement.date = static_cast<std::uint64_t>(wire.date);
    statement.keyVersion = static_cast<std::uint64_t>(wire.keyVersion);
    statement.keyCommit = privmx::utils::Hex::toString(wire.keyCommit);
    statement.rosterHash = privmx::utils::Hex::toString(wire.rosterHash);
    for (const server::SpaceGroup& group : wire.addedGroups) {
        statement.addedGroups.push_back(
            SpaceLogGroup{
                .groupId = group.groupId,
                .role = group.role,
                .groupKeyVersion = static_cast<std::uint64_t>(group.groupKeyVersion),
                .groupPubKey = group.groupPubKey.value_or(std::string()),
            }
        );
    }
    for (const server::SpaceUser& user : wire.addedUsers) {
        statement.addedUsers.push_back(SpaceLogUser{.userId = user.userId, .pubKey = user.pubKey, .role = user.role});
    }
    statement.removedGroups = wire.removedGroups;
    statement.removedUsers = wire.removedUsers;
    for (const server::SpaceGroupKey& group : wire.refreshedGroups) {
        if (group.groupKeyVersion < 0) {
            throw GroupDataIntegrityException("space statement: a negative epoch");
        }
        statement.refreshedGroups.push_back(
            SpaceLogGroup{
                .groupId = group.groupId,
                .role = std::string(),
                .groupKeyVersion = static_cast<std::uint64_t>(group.groupKeyVersion),
                .groupPubKey = group.groupPubKey,
            }
        );
    }
    statement.signer = wire.signer;
    statement.signerPubKey = wire.signerPubKey;
    statement.via = wire.via;
    statement.signature = privmx::utils::Base64::toString(wire.signature);
    statement.viaSignature = privmx::utils::Base64::toString(wire.viaSignature);
    return statement;
}
