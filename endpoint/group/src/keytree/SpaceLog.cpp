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

using namespace privmx::endpoint::group;
using namespace privmx::endpoint::group::keytree;
namespace be = privmx::endpoint::core::bigendian;

namespace {

std::string tag(const char* name) {
    return std::string(name) + std::string(1, '\0');
}

bool isRole(const std::string& role) {
    return role == "user" || role == "manager";
}

bool verifies(const std::string& pubKeyBase58, const std::string& bytes, const std::string& signature) {
    try {
        return privmx::crypto::PublicKey::fromBase58DER(pubKeyBase58).verifyCompactSignatureWithHash(bytes, signature);
    } catch (...) { return false; }
}

// Who each recipient is and what they may do; a group's epoch and key are left out, since those may be refreshed.
std::map<std::string, std::string> rolesOf(
    const std::vector<SpaceLogGroup>& groups,
    const std::vector<SpaceLogUser>& users
) {
    std::map<std::string, std::string> roles;
    for (const SpaceLogGroup& group : groups) {
        roles["g\0" + group.groupId] = group.role;
    }
    for (const SpaceLogUser& user : users) {
        roles["u\0" + user.userId] = user.role + '\0' + user.pubKey;
    }
    return roles;
}

bool includes(const std::map<std::string, std::string>& whole, const std::map<std::string, std::string>& part) {
    return std::all_of(part.begin(), part.end(), [&](const auto& entry) {
        const auto found = whole.find(entry.first);
        return found != whole.end() && found->second == entry.second;
    });
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

std::string SpaceLog::recipientsHash(std::vector<SpaceLogGroup> groups, std::vector<SpaceLogUser> users) {
    std::sort(groups.begin(), groups.end(), [](const auto& a, const auto& b) { return a.groupId < b.groupId; });
    std::sort(users.begin(), users.end(), [](const auto& a, const auto& b) { return a.userId < b.userId; });
    std::string preimage = tag("pmx-space-recipients");
    be::putU32(preimage, static_cast<std::uint32_t>(groups.size()));
    for (const SpaceLogGroup& group : groups) {
        be::putLp(preimage, group.groupId);
        be::putLp(preimage, group.role);
        be::putU64(preimage, group.groupKeyVersion);
        be::putLp(preimage, group.groupPubKey);
    }
    be::putU32(preimage, static_cast<std::uint32_t>(users.size()));
    for (const SpaceLogUser& user : users) {
        be::putLp(preimage, user.userId);
        be::putLp(preimage, user.pubKey);
        be::putLp(preimage, user.role);
    }
    return privmx::crypto::Crypto::sha256(preimage);
}

std::string SpaceLog::keyCommit(const std::string& spaceId, std::uint64_t keyVersion, const std::string& key) {
    std::string preimage = tag("pmx-space-key");
    be::putLp(preimage, spaceId);
    be::putU64(preimage, keyVersion);
    return privmx::crypto::Crypto::sha256(preimage + key);
}

std::string SpaceLog::signedBytes(const SpaceStatement& statement) {
    if (statement.keyCommit.size() != 32 || statement.prevDigest.size() != (statement.seq == 1 ? 0u : 32u)) {
        throw std::invalid_argument("space statement hashes must be 32 bytes");
    }
    std::string bytes = tag("pmx-space-statement");
    be::putU8(bytes, 1);
    be::putLp(bytes, statement.spaceId);
    be::putLp(bytes, statement.contextId);
    be::putU64(bytes, statement.seq);
    be::putLp(bytes, statement.prevDigest);
    be::putU8(bytes, static_cast<std::uint8_t>(statement.op));
    be::putU64(bytes, statement.date);
    be::putU64(bytes, statement.keyVersion);
    bytes += statement.keyCommit;
    bytes += recipientsHash(statement.groups, statement.users);
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
    if (statement.keyCommit.size() != 32 || statement.prevDigest.size() != (seq == 1 ? 0u : 32u)) {
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

    // The recipients after it: each once, each with a role.
    std::set<std::string> ids;
    for (const SpaceLogGroup& group : statement.groups) {
        if (group.groupId.empty() || !isRole(group.role) || !ids.insert("g\0" + group.groupId).second) {
            throw broken("malformed recipients");
        }
    }
    for (const SpaceLogUser& user : statement.users) {
        if (user.userId.empty() || !isRole(user.role) || !ids.insert("u\0" + user.userId).second) {
            throw broken("malformed recipients");
        }
    }
    const bool hasManager = std::any_of(
                                statement.groups.begin(), statement.groups.end(),
                                [](const auto& g) { return g.role == "manager"; }
                            ) ||
        std::any_of(statement.users.begin(), statement.users.end(), [](const auto& u) { return u.role == "manager"; });
    if (!hasManager) {
        throw broken("a Space keeps a manager");
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
        standing.groups = statement.groups;
        standing.users = statement.users;
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

    // What its op lets it change.
    const auto after = rolesOf(statement.groups, statement.users);
    std::map<std::uint64_t, std::string> keyCommits;
    if (prior.has_value()) {
        const auto before = rolesOf(prior->groups, prior->users);
        keyCommits = prior->keyCommits;
        const bool newKey = statement.op != SpaceOp::Add;
        if (statement.keyVersion != prior->keyVersion + (newKey ? 1 : 0)) {
            throw broken("the key version moves by one, with a new key only");
        }
        if (!newKey && statement.keyCommit != prior->keyCommits.at(prior->keyVersion)) {
            throw broken("an addition keeps the key");
        }
        switch (statement.op) {
        case SpaceOp::Add:
            // Nobody already there is touched - a group's epoch and key included.
            if (after.size() <= before.size() ||
                !includes(after, before) ||
                recipientsHash(prior->groups, prior->users) !=
                    recipientsHash(
                        [&] {
                            std::vector<SpaceLogGroup> kept;
                            for (const auto& g : statement.groups) {
                                if (prior->group(g.groupId) != nullptr)
                                    kept.push_back(g);
                            }
                            return kept;
                        }(),
                        [&] {
                            std::vector<SpaceLogUser> kept;
                            for (const auto& u : statement.users) {
                                if (!prior->roleOfUser(u.userId).empty())
                                    kept.push_back(u);
                            }
                            return kept;
                        }()
                    )) {
                throw broken("an addition only adds");
            }
            break;
        case SpaceOp::Remove:
            if (after.size() >= before.size() || !includes(before, after)) {
                throw broken("a removal only removes");
            }
            break;
        case SpaceOp::Rotate:
            if (after != before) {
                throw broken("a rotation leaves the recipients as they are");
            }
            break;
        case SpaceOp::Create:
            break;
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
        .groups = statement.groups,
        .users = statement.users,
        .keyCommits = std::move(keyCommits),
    };
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
    for (const SpaceLogGroup& group : statement.groups) {
        server::SpaceGroup entry;
        entry.groupId = group.groupId;
        entry.role = group.role;
        entry.groupKeyVersion = static_cast<std::int64_t>(group.groupKeyVersion);
        entry.groupPubKey = group.groupPubKey;
        wire.groups.push_back(std::move(entry));
    }
    for (const SpaceLogUser& user : statement.users) {
        server::SpaceUser entry;
        entry.userId = user.userId;
        entry.pubKey = user.pubKey;
        entry.role = user.role;
        wire.users.push_back(std::move(entry));
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
    for (const server::SpaceGroup& group : wire.groups) {
        statement.groups.push_back(
            SpaceLogGroup{
                .groupId = group.groupId,
                .role = group.role,
                .groupKeyVersion = static_cast<std::uint64_t>(group.groupKeyVersion),
                .groupPubKey = group.groupPubKey.value_or(std::string()),
            }
        );
    }
    for (const server::SpaceUser& user : wire.users) {
        statement.users.push_back(SpaceLogUser{.userId = user.userId, .pubKey = user.pubKey, .role = user.role});
    }
    statement.signer = wire.signer;
    statement.signerPubKey = wire.signerPubKey;
    statement.via = wire.via;
    statement.signature = privmx::utils::Base64::toString(wire.signature);
    statement.viaSignature = privmx::utils::Base64::toString(wire.viaSignature);
    return statement;
}
