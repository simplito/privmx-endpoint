/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_ENDPOINT_GROUP_KEYTREE_TREECOMMITS_HPP_
#define _PRIVMXLIB_ENDPOINT_GROUP_KEYTREE_TREECOMMITS_HPP_

#include <cstdint>
#include <map>
#include <string>
#include <vector>

#include <privmx/crypto/ecc/PrivateKey.hpp>
#include <privmx/crypto/ecc/PublicKey.hpp>

#include "privmx/endpoint/group/ServerTypes.hpp"
#include "privmx/endpoint/group/keytree/TreeTypes.hpp"

namespace privmx {
namespace endpoint {
namespace group {
namespace keytree {

enum class CommitOp : std::uint8_t {
    Create = 1,
    Add = 2,
    Remove = 3,
    SelfUpdate = 4,
    Rotate = 5, // the bridge-side `generateNewGroupKey`
};

struct StatementNode {
    std::uint32_t nodeIndex = 0;
    std::uint32_t generation = 0;
    std::string publicKey; // base58 DER
};

// What the tree, the roster and the grant key look like after one commit, signed by the committer. The bridge
// stores the statements and serves them; it cannot forge one, so a state it serves is only as good as the
// statement whose `treeHash` it matches. Hashes and the signature are raw bytes here, hex/base64 on the wire.
struct CommitStatement {
    std::uint64_t seq = 0;
    CommitOp op = CommitOp::Create;
    // The group's id — except at seq 1, where the group has none yet and this is the creator's resourceId.
    std::string groupId;
    std::uint32_t treeVersion = 0;
    std::uint64_t date = 0;
    std::uint64_t keyVersion = 0;
    std::string groupPubKey;
    std::uint64_t rosterVersion = 0;
    std::string rosterHash;
    std::string treeHash;
    std::string committer;
    // The committer's Context public key (base58 DER) at signing time; the signature verifies against it, and the
    // UserVerifier vouches for the pair.
    std::string committerPubKey;
    std::uint32_t committerSeat = 0;
    // The refreshed nodes, bottom-up, as the transition submitted them.
    std::vector<StatementNode> path;
    std::vector<std::string> addedUsers;
    std::vector<std::string> addedManagers;
    std::vector<std::string> removed;
    std::string signature;
};

// The hashes and signed bytes both sides compute byte for byte (SHA-256, big-endian integers, length-prefixed
// strings). A node's hash covers its record — generation, key and the statement that set it — and its children's
// hashes, so one tree hash pins every key and every seat at once.
class TreeCommits {
public:
    // `H("pmx-tree-leaf\0" || u32(p) || lp(userId))`, "" for a blank seat.
    static std::string leafHash(std::uint32_t position, const std::string& userId);

    // The hash of a node from its children's hashes; `record` is null when the node has none. Throws
    // std::invalid_argument on a filled record that names no statement.
    static std::string nodeHash(
        std::uint32_t nodeIndex,
        std::uint32_t numLeaves,
        const TreeNodeState* record,
        const std::string& leftHash,
        const std::string& rightHash
    );

    // `CH(x)`: a leaf's hash, or the node hash of the subtree under `x`, over a state holding its records. What the
    // bridge serves as `copathHashes`.
    static std::string subtreeHash(const TreeGroupState& state, std::uint32_t nodeIndex);

    // `H("pmx-tree\0" || u32(numLeaves) || CH(root))` over a state holding every record.
    static std::string treeHash(const TreeGroupState& state);

    // The same hash from one seat's view: its leaf, the records on its direct path (the others are absent from
    // `state.nodes` or ignored) and the hash of each copath node, aligned with `TreeMath::copath`. Throws
    // std::invalid_argument when the copath hashes do not fit the tree.
    static std::string treeHashAlongPath(
        const TreeGroupState& state,
        std::uint32_t position,
        const std::vector<std::string>& copathHashes
    );

    // Each list deduplicated and sorted bytewise first.
    static std::string rosterHash(std::vector<std::string> users, std::vector<std::string> managers);

    static std::string signedBytes(const CommitStatement& statement);

    // Sets `committerPubKey` to the signer's public key first, so the two cannot disagree.
    static void sign(CommitStatement& statement, const privmx::crypto::PrivateKey& key);

    static bool verifySignature(const CommitStatement& statement, const privmx::crypto::PublicKey& key);

    // Identity of a statement as signed, for caching and for comparing two copies.
    static std::string digest(const CommitStatement& statement);

    // A statement over the post state a plan describes. The roster lists are the post-commit roster; the deltas
    // are sorted here. Unsigned.
    static CommitStatement statementFor(
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
    );

    static server::GroupTreeCommit toWire(const CommitStatement& statement);

    // Throws std::invalid_argument on anything that does not decode: unknown op, bad hex or base64, a number out
    // of range.
    static CommitStatement fromWire(const server::GroupTreeCommit& wire);
};

} // namespace keytree
} // namespace group
} // namespace endpoint
} // namespace privmx

#endif // _PRIVMXLIB_ENDPOINT_GROUP_KEYTREE_TREECOMMITS_HPP_
