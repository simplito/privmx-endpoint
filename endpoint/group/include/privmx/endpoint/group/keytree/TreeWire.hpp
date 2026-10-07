/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_ENDPOINT_GROUP_KEYTREE_TREEWIRE_HPP_
#define _PRIVMXLIB_ENDPOINT_GROUP_KEYTREE_TREEWIRE_HPP_

#include <string>
#include <vector>

#include "privmx/endpoint/group/ServerTypes.hpp"
#include "privmx/endpoint/group/keytree/LadderTypes.hpp"
#include "privmx/endpoint/group/keytree/TreeTypes.hpp"

namespace privmx {
namespace endpoint {
namespace group {
namespace keytree {

// Turns commit plans into what the bridge expects: a whole tree for a new group, a transition for every later commit.
class TreeWire {
public:
    static server::GroupTreeNode toWire(const TreeNodeState& node);
    static server::GroupTreeEdge toWire(const TreeEdge& edge);
    static server::GroupArchiveRung toWire(const ArchiveRung& rung);
    static std::vector<server::GroupArchiveRung> toWire(const std::vector<ArchiveRung>& rungs);

    // The tree of a brand-new group: every member seated in order, the creator's keyed path at generation 0.
    static server::GroupTreeState toCreateTree(const CommitPlan& plan);

    static server::GroupTreeState fromGroupInfo(const server::GroupInfo& group);

    static TreeGroupState toRuntime(
        const server::GroupTreeState& tree,
        std::uint32_t epoch,
        const privmx::crypto::PublicKey& grantPublicKey
    );

    // The adder's refreshed path as `seatedNodes`, the grant edge re-issued at the unchanged epoch.
    static server::GroupTreeAdditionTransition toAdditionTransition(
        const CommitPlan& plan,
        std::int64_t baseKeyVersion
    );

    // The remover's refreshed path, the grant edge at the new epoch.
    static server::GroupTreeTransition toRemovalTransition(const CommitPlan& plan, std::int64_t baseKeyVersion);

    static server::GroupTreeSelfUpdateTransition toSelfUpdateTransition(
        const CommitPlan& plan,
        std::int64_t baseKeyVersion
    );

    // The whole state after a commit, by the bridge's storage rule: blanked nodes keep their generation and lose
    // their key, refreshed ones are replaced, and every edge hanging off either is replaced by the plan's. A record
    // growth pushed into a bucket (an old root at a low level) goes with its edges. The live path never needs this;
    // the conformance fixture and the tests do.
    static server::GroupTreeState afterCommit(const server::GroupTreeState& before, const CommitPlan& plan);
};

} // namespace keytree
} // namespace group
} // namespace endpoint
} // namespace privmx

#endif // _PRIVMXLIB_ENDPOINT_GROUP_KEYTREE_TREEWIRE_HPP_
