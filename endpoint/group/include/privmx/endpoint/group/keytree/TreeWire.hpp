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

#include <optional>
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

    // The tree of a brand-new group: every member seated in order, every keyed node at generation 0.
    static server::GroupTreeState toCreateTree(const CommitPlan& plan);

    static server::GroupTreeState fromGroupInfo(const server::GroupInfo& group);

    static TreeGroupState toRuntime(
        const server::GroupTreeState& tree,
        std::uint32_t epoch,
        const core::PublicKey& grantPublicKey
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

private:
    // A served counter or index as the runtime holds it: one out of range is the bridge's, never wrapped into
    // another. Throws GroupDataIntegrityException.
    static std::uint32_t served32(std::int64_t value);

    // A blank is spelled as an empty string: that is how the wire format says "nobody here" without a nullable
    // element.
    static std::vector<std::string> leafAssignmentToWire(const std::vector<std::optional<std::string>>& seats);

    // The plan's refreshed nodes, as whichever wire node the transition carries.
    template<typename TWireNode>
    static std::vector<TWireNode> refreshedToWire(const CommitPlan& plan) {
        std::vector<TWireNode> wire;
        for (const RefreshedNode& refreshed : plan.refreshed) {
            TWireNode node;
            node.nodeIndex = static_cast<std::int64_t>(refreshed.nodeIndex);
            // The generation the node was read at travels with the refresh: the server refuses the commit if the node
            // has moved since, rather than applying it to a base the client never saw.
            if (refreshed.fromGeneration.has_value()) {
                node.fromGeneration = static_cast<std::int64_t>(refreshed.fromGeneration.value());
            }
            node.generation = static_cast<std::int64_t>(refreshed.generation);
            node.publicKey = refreshed.key.getPublicKey().toBase58DER();
            wire.push_back(node);
        }
        return wire;
    }

    static std::vector<server::GroupTreeEdge> edgesToWire(const CommitPlan& plan);
};

} // namespace keytree
} // namespace group
} // namespace endpoint
} // namespace privmx

#endif // _PRIVMXLIB_ENDPOINT_GROUP_KEYTREE_TREEWIRE_HPP_
