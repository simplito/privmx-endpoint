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
#include <limits>
#include <map>
#include <optional>
#include <set>
#include <stdexcept>
#include <string>
#include <vector>

#include <Poco/Dynamic/Var.h>
#include <Poco/JSON/Object.h>

#include <privmx/crypto/ecc/PrivateKey.hpp>
#include <privmx/crypto/ecc/PublicKey.hpp>

#include "privmx/endpoint/group/ServerTypes.hpp"
#include "privmx/endpoint/group/keytree/TreeTypes.hpp"

namespace privmx {
namespace endpoint {
namespace group {
namespace keytree {

// The hashes and signed bytes both sides compute byte for byte (SHA-256, big-endian integers, length-prefixed
// strings). A node's hash covers its record — generation, key and the statement that set it — and its children's
// hashes, so one tree hash pins every key and every seat at once.
class TreeCommits {
public:
    // Clock skew a statement's `date` may show against the checker's clock, both ways: the bridge's
    // `CommitStatement.DATE_TOLERANCE_MS`. A reader allows a latest statement twice that ahead of its own clock, its
    // own skew on top. That bounds how far a member and a misbehaving bridge can push the chain's dates ahead of real
    // time, which matters because the UserVerifier is asked at each statement's date. It does not bound a freeze:
    // the bridge takes a commit dated exactly as the statement it extends, however far ahead that one is.
    static constexpr std::uint64_t DATE_TOLERANCE_MS = 10 * 60 * 1000;

    // The domain tag of every preimage and sealed label in the key tree; the fields after it use core/BigEndian.hpp.
    // A tag ends in a NUL byte, so no tag is a prefix of another's preimage.
    static std::string tag(const char* name);

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
    // `hex(H("pmx-space-id\0" || lp(contextId) || lp(resourceId)))`: a Space's id, as the Bridge derives it.
    static std::string spaceId(const std::string& contextId, const std::string& resourceId);

    static std::string signedBytes(const CommitStatement& statement);

    // Sets `committerPubKey` to the signer's public key first, so the two cannot disagree.
    static void sign(CommitStatement& statement, const privmx::crypto::PrivateKey& key);

    static bool verifySignature(const CommitStatement& statement, const privmx::crypto::PublicKey& key);

    // Identity of a statement as signed, for caching and for comparing two copies.
    static std::string digest(const CommitStatement& statement);
    // Injective key of an operation a caller asked for (what a resend after an unknown outcome is matched by):
    // lp(kind) || lp(part)*, lp = u32 big-endian length || bytes, so no separator a user id could hold makes two
    // different operations equal.
    static std::string opKey(const std::string& kind, const std::vector<std::string>& parts = {});

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

    // The fields of a rules object, in hash order.
    static const std::vector<std::string>& ruleFields();

    // `GroupRules` of a rules object and its creator, with `hash` = `H("pmx-group-rules-v1\0" || lp(creator)
    // || lp(field)* in `ruleFields` order)`. Strict: an object with exactly those eight fields, each "managers",
    // "members" or "nobody"; anything else throws std::invalid_argument. Defaults are the signer's to fill,
    // so such an object is never signed and, served, is an integrity error.
    static GroupRules rules(const Poco::Dynamic::Var& policy, const std::string& creator);

    // The member of `rules` a field of `ruleFields` names. Throws std::invalid_argument on another name.
    static std::string& ruleOf(GroupRules& rules, const std::string& field);

    // A rule for a member: "managers" a manager, "members" anybody on the roster, "nobody" nobody.
    static bool allows(const std::string& rule, bool member, bool manager);

    // Whether `userId` is on either list of a served roster.
    static bool onRoster(
        const std::vector<std::string>& users,
        const std::vector<std::string>& managers,
        const std::string& userId
    );

    // The role column of the op-effect table, on the rules and roster before `statement`: every rule the op touches.
    // Create always (the committer is the creator); add `addMembers` (+ `changeRoles` seating a manager); remove
    // `removeMembers` (+ `changeRoles` removing a manager); reseat `replaceMemberKeys`; roles `changeRoles`; policy
    // `changeRules`; rotate and selfUpdate any member. A remove or roles statement that leaves a group that had
    // managers with none is refused. False for an op without a row.
    static bool permits(
        const GroupRules& rules,
        const CommitStatement& statement,
        const std::set<std::string>& users,
        const std::set<std::string>& managers
    );

    // The roster-delta column of the op-effect table on the roster before `statement`: nullopt when the deltas fit the
    // op, else what is wrong. Add, remove, reseat and roles carry deltas; an addition names newcomers only (an existing
    // member is promoted by a roles statement), once each; a removal or reseat names members, never its committer; a
    // role change names members, at least one of whom changes lists. Shared by `TreeVerifier`'s replay and the check
    // before this client signs.
    static std::optional<std::string> deltasProblem(
        const CommitStatement& statement,
        const std::set<std::string>& users,
        const std::set<std::string>& managers
    );

    static server::GroupTreeCommit toWire(const CommitStatement& statement);

    // Throws std::invalid_argument on anything that does not decode: unknown op, bad hex or base64, a number out
    // of range.
    static CommitStatement fromWire(const server::GroupTreeCommit& wire);

    // u32 count, then each value length-prefixed. Spaces' statements encode their id lists the same way.
    static void putList(std::string& out, const std::vector<std::string>& values);

private:
    static std::vector<std::string> sortedUnique(std::vector<std::string> values);

    // Throws std::invalid_argument on anything but 64 lowercase hex digits.
    static std::string fromHex32(const std::string& hex);

    // The leaf hash of a seat, blank when the state does not reach it.
    static std::string seatHash(const TreeGroupState& state, std::uint32_t position);

    // `CH(nodeIndex)` over the subtree under it; every inner node's hash goes into `memo` when given.
    static std::string childHash(
        const TreeGroupState& state,
        std::uint32_t nodeIndex,
        std::map<std::uint32_t, std::string>* memo = nullptr
    );

    static std::string treeHashOver(std::uint32_t numLeaves, const std::string& rootHash);

    // The wire spelling of an op, "" for one outside the enum.
    static const char* opName(CommitOp op);

    // Throws std::invalid_argument when a wire number does not fit `T`, naming `field`.
    template<typename T>
    static T inRange(std::int64_t value, const char* field) {
        if (value < 0 || static_cast<std::uint64_t>(value) > std::numeric_limits<T>::max()) {
            throw std::invalid_argument(std::string("commit statement field out of range: ") + field);
        }
        return static_cast<T>(value);
    }
};

} // namespace keytree
} // namespace group
} // namespace endpoint
} // namespace privmx

#endif // _PRIVMXLIB_ENDPOINT_GROUP_KEYTREE_TREECOMMITS_HPP_
