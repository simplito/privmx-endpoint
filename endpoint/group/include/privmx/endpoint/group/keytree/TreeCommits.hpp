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
#include <optional>
#include <set>
#include <string>
#include <vector>

#include <Poco/Dynamic/Var.h>

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
    Policy = 6, // a policy change: only `policyHash` moves (T4-10)
};

struct StatementNode {
    std::uint32_t nodeIndex = 0;
    std::uint32_t generation = 0;
    std::string publicKey; // base58 DER
    // `CH` of the node in the post state: pins the subtree the key was minted over, so a served node whose subtree
    // has changed since (a child re-keyed under a rolled-back parent) no longer matches its voucher. Raw bytes.
    std::string subtreeHash;
};

// What the tree, the roster and the grant key look like after one commit, signed by the committer. The bridge
// stores the statements and serves them; it cannot forge one, so a state it serves is only as good as the
// statement whose `treeHash` it matches. Hashes and the signature are raw bytes here, hex/base64 on the wire.
struct CommitStatement {
    std::uint64_t seq = 0;
    // `digest` of the statement at `seq - 1`, empty at seq 1: chains every statement to the history it extends, so
    // nothing below a verified statement can be swapped or forked. Raw bytes.
    std::string prevDigest;
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
    // `TreeCommits::rules(policy, creator).hash` of the group's policy after the commit: the rules that govern commits
    // and the creator the `owner` atom names, signed into every statement. Raw bytes.
    std::string policyHash;
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
    // Wire only, on `Create` and `Policy`: the group's whole policy after the commit. Not signed itself; it counts only
    // once it hashes to `policyHash`, and only its four commit rules do.
    std::optional<Poco::Dynamic::Var> policy;
};

// The part of a group's policy its statements sign: who may commit what, and who the owner is. Absent, "inherit"
// and "default" resolve to the frozen v3 defaults, never to the context policy, which only the bridge holds.
struct GroupRules {
    std::string creator, update, rotateKeys, updatePolicy, ownerCanBeRemovedFromManagers;
    std::string hash; // policyHash, raw
};

// The hashes and signed bytes both sides compute byte for byte (SHA-256, big-endian integers, length-prefixed
// strings). A node's hash covers its record — generation, key and the statement that set it — and its children's
// hashes, so one tree hash pins every key and every seat at once.
class TreeCommits {
public:
    // Clock skew a statement's `date` may show against the checker's clock, both ways: the bridge's
    // `CommitStatement.DATE_TOLERANCE_MS`. A reader allows a latest statement twice that ahead of its own clock, its
    // own skew on top. That bounds how far a member and a misbehaving bridge can push the chain's dates ahead of real
    // time, which matters because the UserVerifier is asked at each statement's date. It no longer bounds a freeze:
    // the bridge takes a commit dated exactly as the statement it extends, however far ahead that one is (N-1).
    static constexpr std::uint64_t DATE_TOLERANCE_MS = 10 * 60 * 1000;

    // The encoders of every preimage and sealed label in the key tree. A domain tag ends in a NUL byte, so no tag is a
    // prefix of another's preimage; integers are big-endian; `putLp` prefixes a string with its u32 length.
    static std::string tag(const char* name);
    // Forward to core/BigEndian.hpp, the codec of every local blob too.
    static void putU8(std::string& out, std::uint8_t value);
    static void putU32(std::string& out, std::uint32_t value);
    static void putU64(std::string& out, std::uint64_t value);
    static void putLp(std::string& out, const std::string& value);

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

    // `H("pmx-tree\0" || u32(numLeaves) || CH(root))` over a state holding every record. Every `CH` of an inner
    // node goes into `subtreeHashes` when given.
    static std::string treeHash(
        const TreeGroupState& state,
        std::map<std::uint32_t, std::string>* subtreeHashes = nullptr
    );

    // The same hash from one seat's view: its leaf, the records on its direct path (the others are absent from
    // `state.nodes` or ignored) and the hash of each copath node, aligned with `TreeMath::copath`. Throws
    // std::invalid_argument when the copath hashes do not fit the tree. The `CH` of each direct-path node goes into
    // `subtreeHashes` when given.
    static std::string treeHashAlongPath(
        const TreeGroupState& state,
        std::uint32_t position,
        const std::vector<std::string>& copathHashes,
        std::map<std::uint32_t, std::string>* subtreeHashes = nullptr
    );

    // Each list deduplicated and sorted bytewise first.
    static std::string rosterHash(std::vector<std::string> users, std::vector<std::string> managers);

    // A group's id, as the bridge derives it at creation: lowercase hex of
    // `H("pmx-group-id\0" || lp(contextId) || lp(resourceId))`. It ties the id to the resourceId the creator signs
    // at seq 1, so that statement cannot be served as another group's.
    static std::string groupId(const std::string& contextId, const std::string& resourceId);

    static std::string signedBytes(const CommitStatement& statement);

    // Sets `committerPubKey` to the signer's public key first, so the two cannot disagree.
    static void sign(CommitStatement& statement, const privmx::crypto::PrivateKey& key);

    static bool verifySignature(const CommitStatement& statement, const privmx::crypto::PublicKey& key);

    // Identity of a statement as signed, for caching and for comparing two copies.
    static std::string digest(const CommitStatement& statement);

    // A statement over the post state a plan describes. The roster lists are the post-commit roster; the deltas
    // are sorted and deduplicated here (at seq 1 empty: `rosterHash` binds the genesis roster). Unsigned.
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
        std::vector<std::string> removed,
        const std::string& policyHash
    );

    // `GroupRules` of a policy object (empty = `{}`) and its creator, with `hash` =
    // `H("pmx-group-policy\0" || lp(creator) || lp(update) || lp(rotateKeys) || lp(updatePolicy)
    // || lp(ownerCanBeRemovedFromManagers))`, each resolved against the frozen v3 defaults (manager, manager, manager,
    // yes) and hashed verbatim. Throws std::invalid_argument on a non-object policy, a non-string rule, or a rule outside
    // the bridge's group grammar (`none`, `all`, or unique alternatives of unique user/manager/owner atoms, no part
    // empty; `ownerCanBeRemovedFromManagers` yes/no): such a policy is never signed and, served, is an integrity error.
    static GroupRules rules(const Poco::Dynamic::Var& policy, const std::string& creator);

    // A policy rule for a member, exactly as the bridge's `PolicyService.userMeetsPolicy`: `,` separates
    // alternatives, `&` joins atoms that must all hold; `none` is false, `all` true, `user` a roster member, `manager`
    // a manager, `owner` the creator; `itemOwner` and any unknown atom false. Fails closed: an empty alternative or atom
    // admits nobody (the bridge sees atom "" and denies too).
    static bool allows(const std::string& rule, bool member, bool manager, bool owner);

    // The role column of the op-effect table (T4-10), on the rules and roster before `statement`: create none (the
    // committer is the creator), add `update`, remove `update` (and, removing the creator from the managers,
    // `ownerCanBeRemovedFromManagers` "yes"), rotate `rotateKeys`, selfUpdate a seat, policy `updatePolicy`. False for
    // an op without a row.
    static bool permits(
        const GroupRules& rules,
        const CommitStatement& statement,
        const std::set<std::string>& users,
        const std::set<std::string>& managers
    );

    // The roster-delta column of the op-effect table on the roster before `statement`: nullopt when the deltas fit the
    // op, else what is wrong. Only add and remove carry deltas; an addition names newcomers only (an existing member
    // cannot be promoted), once each; a removal names members, never its committer. Shared by `TreeVerifier`'s replay
    // and the check before this client signs.
    static std::optional<std::string> deltasProblem(
        const CommitStatement& statement,
        const std::set<std::string>& users,
        const std::set<std::string>& managers
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
