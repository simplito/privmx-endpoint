/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

/**
 * Emits the tree states this client produces, as JSON, so the bridge's structural validator can be run against
 * them in its own test suite.
 *
 * The two sides of this design have to agree exactly: the client submits a complete tree state and the server
 * accepts or rejects it on structure alone. Unit tests on either side can only check each half against its own
 * idea of the rules. This dump closes that gap — real EC keys, real ECIES, real plans on this side; the actual
 * production validator on the other. A disagreement shows up as a rejected state rather than as a subtle
 * divergence discovered in production.
 *
 * Usage: keytree_state_dump > src/test/fixtures/keytree-states.json   (paths relative to the bridge repo)
 * See test/tools/README.md.
 */

#include <iostream>
#include <string>
#include <vector>

#include <privmx/crypto/Crypto.hpp>
#include <privmx/crypto/ecc/PrivateKey.hpp>
#include <privmx/utils/Utils.hpp>

#include <privmx/endpoint/group/keytree/LadderKeys.hpp>
#include <privmx/endpoint/group/keytree/TreeKeys.hpp>
#include <privmx/endpoint/group/keytree/TreeMath.hpp>
#include <privmx/endpoint/group/keytree/TreeWire.hpp>

using privmx::crypto::PrivateKey;
using namespace privmx::endpoint::group;
using namespace privmx::endpoint::group::keytree;

namespace {

struct Member {
    std::string userId;
    PrivateKey priv;
};

std::vector<Member> makeMembers(std::uint32_t count) {
    std::vector<Member> members;
    for (std::uint32_t i = 0; i < count; ++i) {
        members.push_back(Member{"u" + std::to_string(i), PrivateKey::generateRandom()});
    }
    return members;
}

std::vector<TreeMember> publicOf(const std::vector<Member>& members) {
    std::vector<TreeMember> result;
    for (const Member& member : members) {
        result.push_back(TreeMember{member.userId, member.priv.getPublicKey()});
    }
    return result;
}

/**
 * Reduces a wrapped blob to its length and a digest.
 *
 * The consumer of this dump is a *structural* validator: it checks that an edge carries a ciphertext, never what
 * is inside one, because the server cannot decrypt anything. Whole ECIES blobs would multiply the fixture's size
 * for no added coverage.
 *
 * A **prefix** would be worse than useless here, and was: the first 46 base64 characters of an ECIES blob are a
 * fixed header — version byte plus the signer's public key, which is the same for every edge one client writes —
 * so a truncated fixture showed the identical string on all 33 edges of a tree. A digest keeps the file small
 * while staying distinct per ciphertext, which lets the consumer assert that a state does not repeat one wrap
 * where it should carry many.
 */
std::string shorten(const std::string& blob) {
    return "b64:" + std::to_string(blob.size()) + ":"
        + privmx::utils::Hex::from(privmx::crypto::Crypto::sha256(blob)).substr(0, 16);
}

std::string quote(const std::string& value) {
    std::string out = "\"";
    for (const char c : value) {
        if (c == '"' || c == '\\') {
            out += '\\';
        }
        out += c;
    }
    return out + "\"";
}

std::string treeToJson(const server::GroupTreeState& tree) {
    std::string out = "{\"numLeaves\":" + std::to_string(tree.numLeaves) + ",\"leafAssignment\":[";
    for (std::size_t i = 0; i < tree.leafAssignment.size(); ++i) {
        out += (i ? "," : "") + quote(tree.leafAssignment[i]);
    }
    out += "],\"nodes\":[";
    for (std::size_t i = 0; i < tree.nodes.size(); ++i) {
        const server::GroupTreeNode& node = tree.nodes[i];
        out += std::string(i ? "," : "") + "{\"nodeIndex\":" + std::to_string(node.nodeIndex)
            + ",\"generation\":" + std::to_string(node.generation)
            + ",\"publicKey\":" + quote(node.publicKey) + "}";
    }
    out += "],\"edges\":[";
    for (std::size_t i = 0; i < tree.edges.size(); ++i) {
        const server::GroupTreeEdge& edge = tree.edges[i];
        out += std::string(i ? "," : "") + "{";
        if (edge.isGrantEdge.has_value() && edge.isGrantEdge.value()) {
            out += "\"isGrantEdge\":true,";
        }
        if (edge.parentIndex.has_value()) {
            out += "\"parentIndex\":" + std::to_string(edge.parentIndex.value()) + ",";
        }
        out += "\"parentGeneration\":" + std::to_string(edge.parentGeneration);
        out += ",\"childKind\":" + quote(edge.childKind);
        if (edge.childIndex.has_value()) {
            out += ",\"childIndex\":" + std::to_string(edge.childIndex.value());
        }
        if (edge.childGeneration.has_value()) {
            out += ",\"childGeneration\":" + std::to_string(edge.childGeneration.value());
        }
        if (edge.childUserId.has_value()) {
            out += ",\"childUserId\":" + quote(edge.childUserId.value());
        }
        out += ",\"data\":" + quote(shorten(edge.data)) + "}";
    }
    return out + "]}";
}

std::string membersToJson(const std::vector<std::string>& ids) {
    std::string out = "[";
    for (std::size_t i = 0; i < ids.size(); ++i) {
        out += (i ? "," : "") + quote(ids[i]);
    }
    return out + "]";
}

std::vector<std::string> idsOf(const std::vector<Member>& members) {
    std::vector<std::string> ids;
    for (const Member& member : members) {
        ids.push_back(member.userId);
    }
    return ids;
}

/** Builds a fresh tree-backed group and returns the state, keeping the store so plans can be computed. */
struct Group {
    std::vector<Member> members;
    server::GroupTreeState tree;
    TreeGroupState state;
    PrivateKey grantKey;
};

Group buildGroup(TreeKeyCache& store, std::uint32_t memberCount, std::uint32_t epoch) {
    Group group;
    group.members = makeMembers(memberCount);
    TreeKeys builder(store);
    const std::vector<TreeMember> members = publicOf(group.members);
    const BuildPlan plan = builder.build(members, group.members[0].priv);
    group.grantKey = plan.grantKey;
    group.tree = TreeWire::fromBuildPlan(plan, members);
    group.state = TreeWire::toRuntime(group.tree, epoch, plan.grantKey.getPublicKey());
    if (epoch != 1) {
        // The build wraps the grant edge at epoch 1; a fixture that claims a later epoch has to say so, since
        // that is exactly what the server checks the grant edge against.
        for (server::GroupTreeEdge& edge : group.tree.edges) {
            if (edge.isGrantEdge.value_or(false)) {
                edge.parentGeneration = static_cast<std::int64_t>(epoch);
            }
        }
        group.state = TreeWire::toRuntime(group.tree, epoch, plan.grantKey.getPublicKey());
    }
    store.putGrantKey(epoch, plan.grantKey);
    return group;
}

} // namespace

int main() {
    std::vector<std::string> cases;

    // ── creation, across sizes including the truncated ones ──
    for (const std::uint32_t count : {1u, 2u, 3u, 4u, 5u, 6u, 7u, 8u, 9u, 12u, 16u, 17u}) {
        TreeKeyCache store;
        const Group group = buildGroup(store, count, 1);
        cases.push_back(
            "{\"kind\":\"create\",\"epoch\":1,\"members\":" + membersToJson(idsOf(group.members))
            + ",\"tree\":" + treeToJson(group.tree) + "}"
        );
    }

    // ── removals, at every position of a few sizes ──
    for (const std::uint32_t count : {2u, 3u, 4u, 5u, 8u}) {
        for (std::uint32_t position = 0; position < count; ++position) {
            TreeKeyCache store;
            Group group = buildGroup(store, count, 5);
            if (count == 1) {
                continue;
            }
            // The remover must be able to climb, so use a member who is not the one leaving.
            const std::uint32_t remover = position == 0 ? 1 : 0;
            TreeKeys tree(store);
            tree.setMemberKeys(publicOf(group.members));
            const ClimbResult climb =
                tree.climbToGrantKey(group.state, group.members[remover].userId, group.members[remover].priv, false);
            if (climb.failure != ClimbFailure::None) {
                std::cerr << "climb failed for size " << count << " position " << position << "\n";
                return 1;
            }
            const RemovalPlan plan =
                tree.planRemoval(group.state, {group.members[position].userId}, group.members[remover].priv);
            const server::GroupTreeState after = TreeWire::afterRemoval(group.tree, plan);

            LadderKeys ladder(store);
            // Unit rung only: the fixture group is minted straight at epoch 5, so there is no epoch history behind
            // it and no archive to gather the aligned skip targets from. A real rotation owes the full set.
            const std::vector<ArchiveRung> rungs = ladder.buildRungs(
                plan.newEpoch, plan.newGrantKey.getPublicKey(), store.getGrantKey(5), 1,
                group.members[remover].userId, group.members[remover].priv, /*includeSkipRungs*/ false
            );
            std::string rungJson = "[";
            for (std::size_t i = 0; i < rungs.size(); ++i) {
                rungJson += std::string(i ? "," : "") + "{\"at\":" + std::to_string(rungs[i].span.at)
                    + ",\"target\":" + std::to_string(rungs[i].span.target) + "}";
            }
            rungJson += "]";

            std::vector<std::string> remaining;
            for (std::uint32_t i = 0; i < count; ++i) {
                if (i != position) {
                    remaining.push_back(group.members[i].userId);
                }
            }
            cases.push_back(
                "{\"kind\":\"remove\",\"beforeEpoch\":5,\"afterEpoch\":6,\"removed\":"
                + quote(group.members[position].userId) + ",\"position\":" + std::to_string(position)
                + ",\"members\":" + membersToJson(idsOf(group.members))
                + ",\"remaining\":" + membersToJson(remaining) + ",\"rungs\":" + rungJson
                + ",\"before\":" + treeToJson(group.tree) + ",\"after\":" + treeToJson(after) + "}"
            );
        }
    }

    // ── additions: filling a blank left by a removal, and appending (which may grow the tree) ──
    for (const std::uint32_t count : {2u, 3u, 4u, 5u, 8u}) {
        // (a) append
        {
            TreeKeyCache store;
            Group group = buildGroup(store, count, 5);
            TreeKeys tree(store);
            tree.setMemberKeys(publicOf(group.members));
            tree.climbToGrantKey(group.state, group.members[0].userId, group.members[0].priv, false);
            const Member newcomer{"newcomer", PrivateKey::generateRandom()};
            const AdditionPlan plan = tree.planAddition(
                group.state, std::vector<TreeMember>{TreeMember{newcomer.userId, newcomer.priv.getPublicKey()}},
                TreeKeys::choosePositions(group.state, 1), group.members[0].priv
            );
            const server::GroupTreeState after = TreeWire::afterAddition(group.tree, plan, {newcomer.userId});
            std::vector<std::string> after_members = idsOf(group.members);
            after_members.push_back(newcomer.userId);
            cases.push_back(
                "{\"kind\":\"add\",\"epoch\":5,\"added\":" + quote(newcomer.userId)
                + ",\"position\":" + std::to_string(plan.positions.at(0))
                + ",\"members\":" + membersToJson(idsOf(group.members))
                + ",\"after_members\":" + membersToJson(after_members)
                + ",\"before\":" + treeToJson(group.tree) + ",\"after\":" + treeToJson(after) + "}"
            );
        }
        // (b) remove someone, then seat a newcomer in the blank — the cheap case the design aims for
        if (count >= 4) {
            TreeKeyCache store;
            Group group = buildGroup(store, count, 5);
            TreeKeys tree(store);
            tree.setMemberKeys(publicOf(group.members));
            tree.climbToGrantKey(group.state, group.members[0].userId, group.members[0].priv, false);
            const std::uint32_t leaving = count - 1;
            const RemovalPlan removal =
                tree.planRemoval(group.state, {group.members[leaving].userId}, group.members[0].priv);
            server::GroupTreeState afterRemoval = TreeWire::afterRemoval(group.tree, removal);
            store.putGrantKey(removal.newEpoch, removal.newGrantKey);
            for (const NodeRefresh& refresh : removal.pathRefresh) {
                store.putNodeKey(refresh.nodeIndex, refresh.newGeneration, refresh.newKey);
            }
            const TreeGroupState stateAfterRemoval =
                TreeWire::toRuntime(afterRemoval, removal.newEpoch, removal.newGrantKey.getPublicKey());

            const Member newcomer{"newcomer", PrivateKey::generateRandom()};
            std::vector<TreeMember> remainingMembers;
            for (std::uint32_t i = 0; i < count; ++i) {
                if (i != leaving) {
                    remainingMembers.push_back(TreeMember{group.members[i].userId, group.members[i].priv.getPublicKey()});
                }
            }
            remainingMembers.push_back(TreeMember{newcomer.userId, newcomer.priv.getPublicKey()});
            TreeKeys tree2(store);
            tree2.setMemberKeys(remainingMembers);
            const AdditionPlan plan = tree2.planAddition(
                stateAfterRemoval, std::vector<TreeMember>{TreeMember{newcomer.userId, newcomer.priv.getPublicKey()}},
                TreeKeys::choosePositions(stateAfterRemoval, 1), group.members[0].priv
            );
            const server::GroupTreeState after = TreeWire::afterAddition(afterRemoval, plan, {newcomer.userId});

            std::vector<std::string> before_members;
            for (std::uint32_t i = 0; i < count; ++i) {
                if (i != leaving) {
                    before_members.push_back(group.members[i].userId);
                }
            }
            std::vector<std::string> after_members = before_members;
            after_members.push_back(newcomer.userId);
            cases.push_back(
                "{\"kind\":\"add\",\"epoch\":" + std::to_string(removal.newEpoch) + ",\"added\":"
                + quote(newcomer.userId) + ",\"position\":" + std::to_string(plan.positions.at(0))
                + ",\"members\":" + membersToJson(before_members)
                + ",\"after_members\":" + membersToJson(after_members)
                + ",\"before\":" + treeToJson(afterRemoval) + ",\"after\":" + treeToJson(after) + "}"
            );
        }
    }

    std::cout << "{\"cases\":[\n";
    for (std::size_t i = 0; i < cases.size(); ++i) {
        std::cout << (i ? ",\n" : "") << cases[i];
    }
    std::cout << "\n]}\n";
    return 0;
}
