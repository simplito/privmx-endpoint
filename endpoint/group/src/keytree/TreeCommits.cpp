/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include "privmx/endpoint/group/keytree/TreeCommits.hpp"

#include <algorithm>
#include <limits>
#include <stdexcept>

#include <privmx/crypto/Crypto.hpp>
#include <privmx/utils/Utils.hpp>

#include "privmx/endpoint/group/keytree/TreeMath.hpp"

using namespace privmx::endpoint::group::keytree;
namespace server = privmx::endpoint::group::server;

std::string TreeCommits::tag(const char* name) {
    return std::string(name) + std::string(1, '\0');
}

void TreeCommits::putU32(std::string& out, std::uint32_t value) {
    for (int shift = 24; shift >= 0; shift -= 8) {
        out.push_back(static_cast<char>((value >> shift) & 0xFF));
    }
}

void TreeCommits::putLp(std::string& out, const std::string& value) {
    putU32(out, static_cast<std::uint32_t>(value.size()));
    out += value;
}

namespace {

void putU8(std::string& out, std::uint8_t value) {
    out.push_back(static_cast<char>(value));
}

void putU64(std::string& out, std::uint64_t value) {
    for (int shift = 56; shift >= 0; shift -= 8) {
        out.push_back(static_cast<char>((value >> shift) & 0xFF));
    }
}

void putList(std::string& out, const std::vector<std::string>& values) {
    TreeCommits::putU32(out, static_cast<std::uint32_t>(values.size()));
    for (const std::string& value : values) {
        TreeCommits::putLp(out, value);
    }
}

std::vector<std::string> sortedUnique(std::vector<std::string> values) {
    std::sort(values.begin(), values.end());
    values.erase(std::unique(values.begin(), values.end()), values.end());
    return values;
}

std::string fromHex32(const std::string& hex) {
    if (hex.size() != 64 ||
        !std::all_of(hex.begin(), hex.end(), [](char c) { return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'); })) {
        throw std::invalid_argument("not a lowercase hex SHA-256");
    }
    return privmx::utils::Hex::toString(hex);
}

const TreeNodeState* findRecord(const TreeGroupState& state, std::uint32_t nodeIndex) {
    for (const TreeNodeState& node : state.nodes) {
        if (node.nodeIndex == nodeIndex) {
            return &node;
        }
    }
    return nullptr;
}

std::string childHash(
    const TreeGroupState& state,
    std::uint32_t nodeIndex,
    std::map<std::uint32_t, std::string>* memo = nullptr
) {
    if (TreeMath::isLeaf(nodeIndex)) {
        const std::uint32_t position = TreeMath::leafPosition(nodeIndex);
        const bool known = position < state.leafAssignment.size();
        return TreeCommits::leafHash(position, known ? state.leafAssignment[position].value_or("") : "");
    }
    std::string hash = TreeCommits::nodeHash(
        nodeIndex, state.numLeaves, findRecord(state, nodeIndex),
        childHash(state, TreeMath::left(nodeIndex, state.numLeaves), memo),
        childHash(state, TreeMath::right(nodeIndex, state.numLeaves), memo)
    );
    if (memo != nullptr) {
        (*memo)[nodeIndex] = hash;
    }
    return hash;
}

std::string treeHashOver(std::uint32_t numLeaves, const std::string& rootHash) {
    std::string preimage = TreeCommits::tag("pmx-tree");
    TreeCommits::putU32(preimage, numLeaves);
    preimage += rootHash;
    return privmx::crypto::Crypto::sha256(preimage);
}

const char* opName(CommitOp op) {
    switch (op) {
    case CommitOp::Create:
        return "create";
    case CommitOp::Add:
        return "add";
    case CommitOp::Remove:
        return "remove";
    case CommitOp::SelfUpdate:
        return "selfUpdate";
    case CommitOp::Rotate:
        return "rotate";
    }
    return "";
}

template<typename T>
T inRange(std::int64_t value, const char* field) {
    if (value < 0 || static_cast<std::uint64_t>(value) > std::numeric_limits<T>::max()) {
        throw std::invalid_argument(std::string("commit statement field out of range: ") + field);
    }
    return static_cast<T>(value);
}

} // namespace

std::string TreeCommits::leafHash(std::uint32_t position, const std::string& userId) {
    std::string preimage = tag("pmx-tree-leaf");
    putU32(preimage, position);
    putLp(preimage, userId);
    return privmx::crypto::Crypto::sha256(preimage);
}

std::string TreeCommits::nodeHash(
    std::uint32_t nodeIndex,
    std::uint32_t numLeaves,
    const TreeNodeState* record,
    const std::string& leftHash,
    const std::string& rightHash
) {
    std::string preimage;
    if (TreeMath::isKeyed(nodeIndex, numLeaves)) {
        preimage = tag("pmx-tree-node");
        putU32(preimage, nodeIndex);
        putU8(preimage, record != nullptr ? 1 : 0);
        if (record != nullptr) {
            putU32(preimage, record->generation);
            putU8(preimage, record->publicKey.has_value() ? 1 : 0);
            if (record->publicKey.has_value()) {
                if (!record->setBy.has_value()) {
                    throw std::invalid_argument(
                        "filled node " + std::to_string(nodeIndex) + " names no statement that set its key"
                    );
                }
                putLp(preimage, record->publicKey->toBase58DER());
                putU64(preimage, record->setBy.value());
            }
        }
    } else {
        // A bucket node: whatever record a server attaches to it is not part of the tree, and not hashed.
        preimage = tag("pmx-tree-inner");
        putU32(preimage, nodeIndex);
    }
    preimage += leftHash;
    preimage += rightHash;
    return privmx::crypto::Crypto::sha256(preimage);
}

std::string TreeCommits::subtreeHash(const TreeGroupState& state, std::uint32_t nodeIndex) {
    return childHash(state, nodeIndex);
}

std::string TreeCommits::treeHash(const TreeGroupState& state, std::map<std::uint32_t, std::string>* subtreeHashes) {
    return treeHashOver(state.numLeaves, childHash(state, TreeMath::root(state.numLeaves), subtreeHashes));
}

std::string TreeCommits::treeHashAlongPath(
    const TreeGroupState& state,
    std::uint32_t position,
    const std::vector<std::string>& copathHashes,
    std::map<std::uint32_t, std::string>* subtreeHashes
) {
    const std::vector<std::uint32_t> path = TreeMath::directPath(position, state.numLeaves);
    if (copathHashes.size() != path.size()) {
        throw std::invalid_argument("copath hashes do not fit the tree");
    }
    std::uint32_t current = TreeMath::leafNode(position);
    const bool known = position < state.leafAssignment.size();
    std::string hash = leafHash(position, known ? state.leafAssignment[position].value_or("") : "");
    for (std::size_t i = 0; i < path.size(); ++i) {
        const std::string sibling = fromHex32(copathHashes[i]);
        const bool currentIsLeft = current < path[i];
        hash = nodeHash(
            path[i], state.numLeaves, findRecord(state, path[i]), currentIsLeft ? hash : sibling,
            currentIsLeft ? sibling : hash
        );
        if (subtreeHashes != nullptr) {
            (*subtreeHashes)[path[i]] = hash;
        }
        current = path[i];
    }
    return treeHashOver(state.numLeaves, hash);
}

std::string TreeCommits::rosterHash(std::vector<std::string> users, std::vector<std::string> managers) {
    std::string preimage = tag("pmx-tree-roster");
    putList(preimage, sortedUnique(std::move(users)));
    putList(preimage, sortedUnique(std::move(managers)));
    return privmx::crypto::Crypto::sha256(preimage);
}

std::string TreeCommits::groupId(const std::string& contextId, const std::string& resourceId) {
    std::string preimage = tag("pmx-group-id");
    putLp(preimage, contextId);
    putLp(preimage, resourceId);
    return privmx::utils::Hex::from(privmx::crypto::Crypto::sha256(preimage));
}

std::string TreeCommits::signedBytes(const CommitStatement& statement) {
    if (statement.rosterHash.size() != 32 || statement.treeHash.size() != 32 ||
        statement.prevDigest.size() != (statement.seq == 1 ? 0 : 32)) {
        throw std::invalid_argument("commit statement hashes must be 32 bytes");
    }
    std::string bytes = tag("pmx-tree-commit");
    putLp(bytes, statement.groupId);
    putU32(bytes, statement.treeVersion);
    putU64(bytes, statement.seq);
    putLp(bytes, statement.prevDigest);
    putU8(bytes, static_cast<std::uint8_t>(statement.op));
    putU64(bytes, statement.date);
    putU64(bytes, statement.keyVersion);
    putLp(bytes, statement.groupPubKey);
    putU64(bytes, statement.rosterVersion);
    bytes += statement.rosterHash;
    bytes += statement.treeHash;
    putLp(bytes, statement.committer);
    putLp(bytes, statement.committerPubKey);
    putU32(bytes, statement.committerSeat);
    putU32(bytes, static_cast<std::uint32_t>(statement.path.size()));
    for (const StatementNode& node : statement.path) {
        putU32(bytes, node.nodeIndex);
        putU32(bytes, node.generation);
        putLp(bytes, node.publicKey);
        if (node.subtreeHash.size() != 32) {
            throw std::invalid_argument("commit statement hashes must be 32 bytes");
        }
        bytes += node.subtreeHash;
    }
    putList(bytes, statement.addedUsers);
    putList(bytes, statement.addedManagers);
    putList(bytes, statement.removed);
    return bytes;
}

void TreeCommits::sign(CommitStatement& statement, const privmx::crypto::PrivateKey& key) {
    statement.committerPubKey = key.getPublicKey().toBase58DER();
    statement.signature = key.signToCompactSignatureWithHash(signedBytes(statement));
}

bool TreeCommits::verifySignature(const CommitStatement& statement, const privmx::crypto::PublicKey& key) {
    try {
        return key.verifyCompactSignatureWithHash(signedBytes(statement), statement.signature);
    } catch (...) { return false; }
}

std::string TreeCommits::digest(const CommitStatement& statement) {
    return privmx::crypto::Crypto::sha256(signedBytes(statement) + statement.signature);
}

CommitStatement TreeCommits::statementFor(
    const CommitPlan& plan,
    CommitOp op,
    const std::string& groupId,
    std::uint64_t date,
    std::uint64_t keyVersion,
    const std::string& groupPubKey,
    std::uint64_t rosterVersion,
    const std::vector<std::string>& users,
    const std::vector<std::string>& managers,
    const std::string& committer,
    std::vector<std::string> addedUsers,
    std::vector<std::string> addedManagers,
    std::vector<std::string> removed
) {
    CommitStatement statement;
    statement.seq = plan.seq;
    statement.op = op;
    statement.groupId = groupId;
    statement.treeVersion = TreeMath::TREE_VERSION;
    statement.date = date;
    statement.keyVersion = keyVersion;
    statement.groupPubKey = groupPubKey;
    statement.rosterVersion = rosterVersion;
    statement.rosterHash = rosterHash(users, managers);
    statement.treeHash = plan.treeHash;
    statement.committer = committer;
    statement.committerSeat = plan.shape.committerSeat;
    for (const RefreshedNode& refreshed : plan.refreshed) {
        statement.path.push_back(
            StatementNode{
                refreshed.nodeIndex, refreshed.generation, refreshed.key.getPublicKey().toBase58DER(),
                plan.subtreeHashes.at(refreshed.nodeIndex)
            }
        );
    }
    statement.addedUsers = sortedUnique(std::move(addedUsers));
    statement.addedManagers = sortedUnique(std::move(addedManagers));
    statement.removed = sortedUnique(std::move(removed));
    return statement;
}

server::GroupTreeCommit TreeCommits::toWire(const CommitStatement& statement) {
    server::GroupTreeCommit wire;
    wire.seq = static_cast<std::int64_t>(statement.seq);
    wire.prevDigest = privmx::utils::Hex::from(statement.prevDigest);
    wire.op = opName(statement.op);
    wire.groupId = statement.groupId;
    wire.treeVersion = statement.treeVersion;
    wire.date = static_cast<std::int64_t>(statement.date);
    wire.keyVersion = static_cast<std::int64_t>(statement.keyVersion);
    wire.groupPubKey = statement.groupPubKey;
    wire.rosterVersion = static_cast<std::int64_t>(statement.rosterVersion);
    wire.rosterHash = privmx::utils::Hex::from(statement.rosterHash);
    wire.treeHash = privmx::utils::Hex::from(statement.treeHash);
    wire.committer = statement.committer;
    wire.committerPubKey = statement.committerPubKey;
    wire.committerSeat = statement.committerSeat;
    for (const StatementNode& node : statement.path) {
        wire.path.push_back(
            server::GroupTreeCommitPathEntry{
                node.nodeIndex, node.generation, node.publicKey, privmx::utils::Hex::from(node.subtreeHash)
            }
        );
    }
    wire.addedUsers = statement.addedUsers;
    wire.addedManagers = statement.addedManagers;
    wire.removed = statement.removed;
    wire.signature = privmx::utils::Base64::from(statement.signature);
    return wire;
}

CommitStatement TreeCommits::fromWire(const server::GroupTreeCommit& wire) {
    CommitStatement statement;
    statement.seq = inRange<std::uint64_t>(wire.seq, "seq");
    statement.prevDigest = statement.seq == 1 ? "" : fromHex32(wire.prevDigest);
    if (statement.seq == 1 && !wire.prevDigest.empty()) {
        throw std::invalid_argument("a genesis statement follows no other");
    }
    bool knownOp = false;
    for (const CommitOp op :
         {CommitOp::Create, CommitOp::Add, CommitOp::Remove, CommitOp::SelfUpdate, CommitOp::Rotate}) {
        if (wire.op == opName(op)) {
            statement.op = op;
            knownOp = true;
        }
    }
    if (!knownOp) {
        throw std::invalid_argument("unknown commit statement op: " + wire.op);
    }
    statement.groupId = wire.groupId;
    statement.treeVersion = inRange<std::uint32_t>(wire.treeVersion, "treeVersion");
    statement.date = inRange<std::uint64_t>(wire.date, "date");
    statement.keyVersion = inRange<std::uint64_t>(wire.keyVersion, "keyVersion");
    statement.groupPubKey = wire.groupPubKey;
    statement.rosterVersion = inRange<std::uint64_t>(wire.rosterVersion, "rosterVersion");
    statement.rosterHash = fromHex32(wire.rosterHash);
    statement.treeHash = fromHex32(wire.treeHash);
    statement.committer = wire.committer;
    statement.committerPubKey = wire.committerPubKey;
    statement.committerSeat = inRange<std::uint32_t>(wire.committerSeat, "committerSeat");
    for (const server::GroupTreeCommitPathEntry& node : wire.path) {
        statement.path.push_back(
            StatementNode{
                inRange<std::uint32_t>(node.nodeIndex, "path.nodeIndex"),
                inRange<std::uint32_t>(node.generation, "path.generation"), node.publicKey,
                fromHex32(node.subtreeHash)
            }
        );
    }
    statement.addedUsers = wire.addedUsers;
    statement.addedManagers = wire.addedManagers;
    statement.removed = wire.removed;
    try {
        statement.signature = privmx::utils::Base64::toString(wire.signature);
    } catch (...) { throw std::invalid_argument("commit statement signature is not base64"); }
    if (statement.signature.size() != 65) {
        throw std::invalid_argument("commit statement signature is not 65 bytes");
    }
    return statement;
}
