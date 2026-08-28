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

// Turns plans into the tree state the bridge expects. The server validates a whole submitted state rather than a
// delta — checking a delta would trust the client's account of what it started from — so the merging happens here.
class TreeWire {
public:
    static server::GroupTreeNode toWire(const TreeNodeState& node);
    static server::GroupTreeEdge toWire(const TreeEdge& edge);
    static server::GroupArchiveRung toWire(const ArchiveRung& rung);
    static std::vector<server::GroupArchiveRung> toWire(const std::vector<ArchiveRung>& rungs);

    // The state of a brand-new group: every member seated in order, epoch 1.
    static server::GroupTreeState fromBuildPlan(const BuildPlan& plan, const std::vector<TreeMember>& members);

    // The tree fields of a served group, gathered back into the one object the bridge expects to receive.
    static server::GroupTreeState fromGroupInfo(const server::GroupInfo& group);

    // Runtime view of a served state, so a plan can be computed against what the bridge currently holds.
    static TreeGroupState toRuntime(
        const server::GroupTreeState& tree,
        std::uint32_t epoch,
        const privmx::crypto::PublicKey& grantPublicKey
    );

    // The removal as a delta: the refreshed path with the generations it was planned against, the edges that
    // refresh owes, and the grant edge at the new epoch — `afterRemoval` minus what the server already holds.
    static server::GroupTreeTransition toTransition(
        const server::GroupTreeState& before,
        const RemovalPlan& plan,
        std::uint32_t position,
        std::int64_t baseKeyVersion
    );

    // The addition as a delta, the grant edge re-issued to the new root at the unchanged epoch.
    // `previousGenerations` says which nodes the server holds, so an advanced node reads differently from a minted one.
    static server::GroupTreeAdditionTransition toAdditionTransition(
        const AdditionPlan& plan,
        const std::map<std::uint32_t, std::uint32_t>& previousGenerations,
        std::int64_t baseKeyVersion
    );

    // Refreshed nodes replace their predecessors and the edges they invalidated are dropped. Nothing off the
    // removed leaf's direct path is touched, which is what the bridge checks.
    static server::GroupTreeState afterRemoval(
        const server::GroupTreeState& before,
        const RemovalPlan& plan,
        std::uint32_t position
    );

    // The epoch does not move, which is what keeps every container the group can read valid. Edges the plan
    // supersedes are dropped, as are edges growth re-parented — those would describe a topology no longer there.
    static server::GroupTreeState afterAddition(
        const server::GroupTreeState& before,
        const AdditionPlan& plan,
        const std::string& newMemberId
    );
};

} // namespace keytree
} // namespace group
} // namespace endpoint
} // namespace privmx

#endif // _PRIVMXLIB_ENDPOINT_GROUP_KEYTREE_TREEWIRE_HPP_
