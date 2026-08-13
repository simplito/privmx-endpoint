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

/**
 * Turns plans into the complete tree state the bridge expects to receive.
 *
 * The server validates a **whole** submitted state rather than a delta, and deliberately so: checking a delta
 * would mean trusting the client's account of what it started from, while checking a full state lets the bridge
 * compare against what it already holds. That puts the merging work here — a removal's refreshed nodes have to
 * replace their predecessors, the edges they invalidated have to go, and the rest has to come through untouched.
 *
 * Every rule the bridge applies to the result is mirrored by a unit test on both sides; this class is where the
 * client's side of that agreement is written down.
 */
class TreeWire {
public:
    static server::GroupTreeNode toWire(const TreeNodeState& node);
    static server::GroupTreeEdge toWire(const TreeEdge& edge);
    static server::GroupArchiveRung toWire(const ArchiveRung& rung);
    static std::vector<server::GroupArchiveRung> toWire(const std::vector<ArchiveRung>& rungs);

    /** The state of a brand-new group: every member seated in order, epoch 1. */
    static server::GroupTreeState fromBuildPlan(const BuildPlan& plan, const std::vector<TreeMember>& members);

    /** The tree fields of a served group, gathered back into the one object the bridge expects to receive. */
    static server::GroupTreeState fromGroupInfo(const server::GroupInfo& group);

    /** Runtime view of a served state, so a plan can be computed against what the bridge currently holds. */
    static TreeGroupState toRuntime(
        const server::GroupTreeState& tree,
        std::uint32_t epoch,
        const privmx::crypto::PublicKey& grantPublicKey
    );

    /**
     * The state after a removal: refreshed nodes replace their predecessors, the departing member's edge and
     * every edge a refresh invalidated are dropped, and the grant edge is re-linked at the new epoch.
     *
     * Nothing off the removed leaf's direct path is touched, which is exactly what the bridge checks — and what
     * keeps a removal proportional to the tree's depth rather than to its size.
     */
    static server::GroupTreeState afterRemoval(
        const server::GroupTreeState& before,
        const RemovalPlan& plan,
        std::uint32_t position
    );

    /**
     * The state after an addition: the newcomer takes a seat, new nodes appear if the tree grew, and no existing
     * node key changes. The epoch does not move — that is what keeps every container the group can read valid.
     */
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
