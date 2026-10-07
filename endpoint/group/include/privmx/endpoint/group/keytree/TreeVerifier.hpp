/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_ENDPOINT_GROUP_KEYTREE_TREEVERIFIER_HPP_
#define _PRIVMXLIB_ENDPOINT_GROUP_KEYTREE_TREEVERIFIER_HPP_

#include <cstdint>
#include <functional>
#include <map>
#include <mutex>
#include <set>
#include <string>
#include <vector>

#include <privmx/endpoint/core/UserVerifierInterface.hpp>

#include "privmx/endpoint/group/ServerTypes.hpp"
#include "privmx/endpoint/group/keytree/TreeCommits.hpp"

namespace privmx {
namespace endpoint {
namespace group {
namespace keytree {

// Checks a served tree against the commit statements members signed, before any key from it is used: the latest
// statement must be genuine and describe exactly the served roster, grant key and tree (by hash); every filled
// node must be vouched for by a genuine statement whose committer still sits under it; and the history since the
// last state this client verified must be an unbroken chain of statements by members. That closes a bridge
// substituting node or grant keys, seating outsiders, or rolling a node back — on its own.
//
// What it cannot close, by design:
//   - First contact (no pin for the group in this process; pins survive reconnects) trusts the latest validly
//     signed state: trust on first use, as for any delivery service.
//   - The bridge may withhold or delay commits.
//   - A member colluding with the bridge can sign a state that rolls a node in someone else's subtree back to an
//     older generation that a statement still validly vouches for, and that a former member knew. The node
//     generation pins catch it only for a client that has already seen the newer generation. It takes a member, the
//     bridge and a removed colluder at once.
//
// Failures throw GroupDataIntegrityException, rollbacks GroupHistoryForkException. Pins are kept per group in
// memory and only stored once a verification has passed completely.
class TreeVerifier {
public:
    // How much of the tree the response carries: one seat's path ("path", the default `groupGet`), or every
    // record ("plan"/"full").
    enum class Scope {
        Path,
        Plan
    };

    // What a verification needs from outside the served group.
    struct Environment {
        // The connection's UserVerifier; it vouches for each statement's committer and `committerPubKey`.
        std::function<std::vector<bool>(const std::vector<core::VerificationRequest>&)> verifyUsers;
        // The statements with `fromSeq < seq <= toSeq`, ascending.
        std::function<std::vector<server::GroupTreeCommit>(std::uint64_t fromSeq, std::uint64_t toSeq)> commitsBetween;
    };

    void verify(const server::GroupInfo& group, Scope scope, const Environment& environment);

    // A listed group, for a writer that may hold no seat in it: its latest statement is genuine and describes the
    // listed grant key, counters and roster, and its committer is on that roster. A pinned group must also continue
    // its pin (the pinned statement at its seq, a member-signed chain above it). No tree is checked and no pin moves.
    // Throws GroupDataIntegrityException.
    void verifyListed(const server::GroupSummary& summary, const Environment& environment);

    // P2: the members seated in the tree must be exactly the attested roster, or the next commit wraps to whoever
    // the bridge seated. Throws GroupDataIntegrityException.
    static void assertSeatsMatchRoster(
        const server::GroupInfo& group,
        const std::vector<std::string>& users,
        const std::vector<std::string>& managers
    );

    void forget(const std::string& groupId);

    // `seq` of the last state verified for the group, 0 if none.
    std::uint64_t pinnedSeq(const std::string& groupId);

private:
    // What a verified state leaves behind for the next read of the same group.
    struct Pin {
        std::uint64_t seq = 0;
        std::string treeHash;
        std::string digest; // of the latest statement
        std::set<std::string> users;
        std::set<std::string> managers;
        std::uint64_t keyVersion = 0;
        std::uint64_t rosterVersion = 0;
        // Highest generation seen per node index. A blank keeps its generation, so blanking never lowers it.
        std::map<std::uint32_t, std::uint32_t> generations;
    };

    // Signature by `committerPubKey`, that key accepted by the UserVerifier for the committer at the statement's
    // date, and naming this group and tree version. Results are cached per group and statement.
    void verifyStatements(
        const std::string& groupId,
        const std::string& resourceId,
        const std::string& contextId,
        const std::vector<CommitStatement>& statements,
        const Environment& environment
    );

    // The chain from the pin to `latest`: contiguous, each signed by a member of the roster before it, rosters
    // replayed through the deltas, counters never going back, ending exactly at `latest`.
    void verifyChain(
        const std::string& groupId,
        const std::string& resourceId,
        const std::string& contextId,
        const Pin& pin,
        const CommitStatement& latest,
        const Environment& environment
    );

    std::mutex _mutex;
    std::map<std::string, Pin> _pins;
    std::set<std::string> _verifiedStatements;
};

} // namespace keytree
} // namespace group
} // namespace endpoint
} // namespace privmx

#endif // _PRIVMXLIB_ENDPOINT_GROUP_KEYTREE_TREEVERIFIER_HPP_
