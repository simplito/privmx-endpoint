/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

/**
 * Seeded random sequences of create / add / remove / self-update, committed by random members against a fake bridge
 * that stores what it is sent by the bridge's storage rule. After every commit:
 *
 *   - knowledge: every member's knowledge is what it minted plus everything reachable over the current edges from
 *     what it already knew — accumulated over the whole run, never forgotten, and computed for former members too.
 *     The TreeKEM invariant then has to hold: a filled node's key is known only to members seated under it;
 *   - removal: nobody unseated knows the current grant key, and every seated member climbs to it (real ECIES);
 *   - consistency: the stored edges are exactly the edges the filled nodes owe their children's resolution, plus
 *     one grant edge.
 *
 * The fake bridge derives what each commit may touch on its own, from the operation and the committer, and refuses
 * a refresh of anything else — the same rule the real one enforces.
 *
 * How the old design fails here: A creates {A, B, C, D} and mints every node key, including node 5 above C and D.
 * B removes A, which re-keyed only A's own direct path, so the refreshed root still wraps to node 5 at the
 * generation A minted. The knowledge check fails right after the create (A knows node 5, outside A's subtree), and
 * the removal check fails after B's commit (A opens the root through node 5, then the new grant key).
 *
 * Keys are real and random, so a run is reproducible in its operations (seeded), not in its key material.
 */

#include <gtest/gtest.h>

#include <algorithm>
#include <functional>
#include <iterator>
#include <map>
#include <optional>
#include <random>
#include <set>
#include <string>
#include <vector>

#include <privmx/crypto/ecc/PrivateKey.hpp>

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
    privmx::crypto::PublicKey publicKey;
    std::string pub;
};

const TreeNodeState* recordOf(const TreeGroupState& state, std::uint32_t nodeIndex) {
    for (const TreeNodeState& node : state.nodes) {
        if (node.nodeIndex == nodeIndex) {
            return &node;
        }
    }
    return nullptr;
}

std::optional<std::uint32_t> seatOf(const TreeGroupState& state, const std::string& userId) {
    for (std::size_t i = 0; i < state.leafAssignment.size(); ++i) {
        if (state.leafAssignment[i] == userId) {
            return static_cast<std::uint32_t>(i);
        }
    }
    return std::nullopt;
}

std::vector<TreeEdge> edgesOf(const std::vector<server::GroupTreeEdge>& wire) {
    server::GroupTreeState carrier;
    carrier.numLeaves = 1;
    carrier.edges = wire;
    return TreeWire::toRuntime(carrier, 0, PrivateKey::generateRandom().getPublicKey()).edges;
}

// The resolution, written again from the spec rather than borrowed from the code under test.
void resolve(const TreeGroupState& state, std::uint32_t node, std::vector<std::string>& out) {
    if (TreeMath::isLeaf(node)) {
        const auto& seat = state.leafAssignment[TreeMath::leafPosition(node)];
        if (seat.has_value()) {
            out.push_back("user:" + seat.value());
        }
        return;
    }
    const TreeNodeState* record = recordOf(state, node);
    if (TreeMath::isKeyed(node, state.numLeaves) && record != nullptr && record->publicKey.has_value()) {
        out.push_back("node:" + std::to_string(node) + "@" + std::to_string(record->generation));
        return;
    }
    for (const std::uint32_t child : TreeMath::children(node, state.numLeaves)) {
        resolve(state, child, out);
    }
}

std::string edgeIdentity(const TreeEdge& edge) {
    const std::string child = edge.childKind == EdgeChildKind::User ?
        "user:" + edge.childUserId :
        "node:" + std::to_string(edge.childIndex) + "@" + std::to_string(edge.childGeneration);
    if (edge.isGrantEdge) {
        return "grant@" + std::to_string(edge.parentGeneration) + ">" + child;
    }
    return std::to_string(edge.parentIndex) + "@" + std::to_string(edge.parentGeneration) + ">" + child;
}

// What the bridge holds, and the rule it stores a commit by.
class FakeBridge {
public:
    TreeGroupState state;

    enum class Op { Add, Remove, SelfUpdate };

    void create(const server::GroupTreeState& tree, const privmx::crypto::PublicKey& grant, const std::string& creator) {
        state = TreeWire::toRuntime(tree, 1, grant);
        const auto seat = seatOf(state, creator);
        ASSERT_TRUE(seat.has_value()) << "the creator holds no seat";
        std::vector<std::uint32_t> created;
        for (const TreeNodeState& node : state.nodes) {
            created.push_back(node.nodeIndex);
            EXPECT_EQ(node.generation, 0u);
        }
        std::sort(created.begin(), created.end());
        std::vector<std::uint32_t> path = TreeMath::keyedPath(seat.value(), state.numLeaves);
        std::sort(path.begin(), path.end());
        EXPECT_EQ(created, path) << "a create may key the creator's path and nothing else";
    }

    // `subjects` are the users added (with `positions`) or removed. Returns the nodes the commit blanked.
    void commit(
        Op op,
        const std::string& committer,
        const std::vector<std::string>& subjects,
        const std::vector<std::uint32_t>& positions,
        const std::vector<server::GroupTreeRefreshedNode>& refreshed,
        const std::vector<server::GroupTreeEdge>& edges,
        const std::optional<privmx::crypto::PublicKey>& newGrant
    ) {
        const auto committerSeat = seatOf(state, committer);
        ASSERT_TRUE(committerSeat.has_value()) << "only a seated member commits";
        std::uint32_t numLeaves = state.numLeaves;
        auto seats = state.leafAssignment;
        std::set<std::uint32_t> blanked;
        if (op == Op::Add) {
            numLeaves = TreeMath::numLeavesToSeatAll(positions, numLeaves);
            seats.resize(numLeaves);
            for (std::size_t i = 0; i < positions.size(); ++i) {
                ASSERT_FALSE(seats[positions[i]].has_value());
                seats[positions[i]] = subjects[i];
            }
            const auto own = TreeMath::keyedPath(committerSeat.value(), numLeaves);
            for (const std::uint32_t position : positions) {
                for (const std::uint32_t node : TreeMath::keyedPath(position, numLeaves)) {
                    if (std::find(own.begin(), own.end(), node) == own.end()) {
                        blanked.insert(node);
                    }
                }
            }
        } else if (op == Op::Remove) {
            for (const std::string& gone : subjects) {
                ASSERT_NE(gone, committer) << "self-removal must never reach the bridge";
                const auto seat = seatOf(state, gone);
                ASSERT_TRUE(seat.has_value());
                seats[seat.value()] = std::nullopt;
                for (const std::uint32_t node : TreeMath::keyedPath(seat.value(), numLeaves)) {
                    blanked.insert(node);
                }
            }
        }

        // Exactly the committer's keyed path, each node one generation on (or minted at 0), each with a new key.
        const std::vector<std::uint32_t> path = TreeMath::keyedPath(committerSeat.value(), numLeaves);
        ASSERT_EQ(refreshed.size(), path.size()) << "a commit refreshes the committer's keyed path, nothing else";
        std::map<std::uint32_t, TreeNodeState> records;
        for (const TreeNodeState& node : state.nodes) {
            records[node.nodeIndex] = node;
        }
        for (const server::GroupTreeRefreshedNode& node : refreshed) {
            const auto index = static_cast<std::uint32_t>(node.nodeIndex);
            ASSERT_NE(std::find(path.begin(), path.end(), index), path.end()) << "refreshes node " << index;
            const auto stored = records.find(index);
            if (stored == records.end()) {
                EXPECT_FALSE(node.fromGeneration.has_value());
                EXPECT_EQ(node.generation, 0);
            } else {
                EXPECT_EQ(node.fromGeneration, std::optional<std::int64_t>(stored->second.generation));
                EXPECT_EQ(node.generation, static_cast<std::int64_t>(stored->second.generation) + 1);
                if (stored->second.publicKey.has_value()) {
                    EXPECT_NE(node.publicKey, stored->second.publicKey->toBase58DER()) << "a key reused";
                }
            }
            ASSERT_FALSE(node.publicKey.empty());
        }

        // Storage: whatever hangs off a blanked, refreshed or no-longer-keyed node goes, and so does the grant edge.
        std::set<std::uint32_t> replaced(blanked.begin(), blanked.end());
        for (auto it = records.begin(); it != records.end();) {
            if (!TreeMath::isKeyed(it->first, numLeaves)) {
                replaced.insert(it->first);
                it = records.erase(it);
            } else {
                if (blanked.count(it->first) > 0) {
                    it->second.publicKey.reset();
                }
                ++it;
            }
        }
        for (const server::GroupTreeRefreshedNode& node : refreshed) {
            const auto index = static_cast<std::uint32_t>(node.nodeIndex);
            replaced.insert(index);
            records[index] = TreeNodeState{
                index, static_cast<std::uint32_t>(node.generation), NodePublicKey::fromBase58DER(node.publicKey)
            };
        }
        std::vector<TreeEdge> kept;
        for (const TreeEdge& edge : state.edges) {
            if (!edge.isGrantEdge && replaced.count(edge.parentIndex) == 0) {
                kept.push_back(edge);
            }
        }
        for (const TreeEdge& edge : edgesOf(edges)) {
            kept.push_back(edge);
        }

        state.numLeaves = numLeaves;
        state.leafAssignment = seats;
        state.nodes.clear();
        for (const auto& [index, record] : records) {
            state.nodes.push_back(record);
        }
        state.edges = kept;
        if (op == Op::Remove) {
            state.epoch += 1;
            state.grantPublicKey = newGrant.value();
        }
    }

    // `groupGet` with scope "plan": every record, the caller's climbing edges, the grant edge.
    TreeGroupState servePlan(const std::string& userId) const {
        TreeGroupState served = state;
        served.edges = climbingEdges(userId);
        return served;
    }

    // The default scope "path": records of the caller's keyed path only.
    TreeGroupState servePath(const std::string& userId) const {
        TreeGroupState served = servePlan(userId);
        const auto path = TreeMath::keyedPath(seatOf(state, userId).value(), state.numLeaves);
        served.nodes.clear();
        for (const TreeNodeState& node : state.nodes) {
            if (std::find(path.begin(), path.end(), node.nodeIndex) != path.end()) {
                served.nodes.push_back(node);
            }
        }
        return served;
    }

private:
    std::vector<TreeEdge> climbingEdges(const std::string& userId) const {
        const auto path = TreeMath::keyedPath(seatOf(state, userId).value(), state.numLeaves);
        std::vector<TreeEdge> climbing;
        for (const TreeEdge& edge : state.edges) {
            const bool toMe = edge.childKind == EdgeChildKind::User && edge.childUserId == userId;
            const bool toMyPath = edge.childKind == EdgeChildKind::Node &&
                std::find(path.begin(), path.end(), edge.childIndex) != path.end();
            if (edge.isGrantEdge || toMe || toMyPath) {
                climbing.push_back(edge);
            }
        }
        return climbing;
    }
};

class TreeInvariant : public testing::Test {
protected:
    FakeBridge bridge;
    std::vector<Member> everyone;
    // Public key (base58) -> private key, for every key minted or held: the oracle that checks each edge once.
    std::map<std::string, PrivateKey> privateOf;
    // Blob -> (recipient public key, carried public key), established by decrypting each edge as it arrives.
    std::map<std::string, std::pair<std::string, std::string>> wrapped;
    // What each member, current or former, can know: public keys of every private key reachable to it, ever.
    std::map<std::string, std::set<std::string>> knows;
    std::mt19937 random;
    std::uint32_t nextUser = 0;

    Member& newMember() {
        const PrivateKey priv = PrivateKey::generateRandom();
        everyone.push_back(
            Member{"m" + std::to_string(nextUser++), priv, priv.getPublicKey(), priv.getPublicKey().toBase58DER()}
        );
        privateOf[everyone.back().pub] = priv;
        knows[everyone.back().userId].insert(everyone.back().pub);
        return everyone.back();
    }

    const Member& member(const std::string& userId) const {
        return *std::find_if(everyone.begin(), everyone.end(), [&](const Member& m) { return m.userId == userId; });
    }

    std::vector<TreeMember> roster() const {
        std::vector<TreeMember> keys;
        for (const Member& m : everyone) {
            keys.push_back(TreeMember{m.userId, m.publicKey});
        }
        return keys;
    }

    std::vector<std::string> seated() const {
        std::vector<std::string> ids;
        for (const auto& seat : bridge.state.leafAssignment) {
            if (seat.has_value()) {
                ids.push_back(seat.value());
            }
        }
        return ids;
    }

    std::uint32_t pick(std::uint32_t bound) {
        return std::uniform_int_distribution<std::uint32_t>(0, bound - 1)(random);
    }

    // A live client's way in: a cold cache, the "plan" view, a climb, then the plan.
    CommitPlan planBy(const std::string& committer, const std::function<CommitPlan(TreeKeys&, const TreeGroupState&)>& plan) {
        const TreeGroupState served = bridge.servePlan(committer);
        TreeKeyCache cache;
        TreeKeys keys(cache);
        const ClimbResult climb = keys.climbToGrantKey(served, committer, member(committer).priv, false);
        EXPECT_EQ(climb.failure, ClimbFailure::None) << committer << " cannot climb to plan";
        keys.setMemberKeys(roster());
        return plan(keys, served);
    }

    // Records what every new edge carries to whom, from the plan, and opens the grant edge and a few random others
    // for real to hold the plan to it. Opening every one would be the honest maximum, but a successful unwrap costs
    // ~5 ms here and a commit to forty members brings forty edges; the climbs after each removal open the rest of
    // what matters for real.
    void learnPlan(const std::string& committer, const CommitPlan& plan) {
        for (const RefreshedNode& refreshed : plan.refreshed) {
            privateOf[refreshed.key.getPublicKey().toBase58DER()] = refreshed.key;
            knows[committer].insert(refreshed.key.getPublicKey().toBase58DER());
        }
        privateOf[plan.grantKey.getPublicKey().toBase58DER()] = plan.grantKey;
        knows[committer].insert(plan.grantKey.getPublicKey().toBase58DER());
        for (const TreeEdge& edge : plan.edges) {
            const std::string recipient = edge.childKind == EdgeChildKind::User ?
                member(edge.childUserId).pub :
                recordOf(bridge.state, edge.childIndex)->publicKey->toBase58DER();
            const std::string carried = edge.isGrantEdge ?
                plan.grantKey.getPublicKey().toBase58DER() :
                recordOf(bridge.state, edge.parentIndex)->publicKey->toBase58DER();
            if (edge.isGrantEdge || pick(10) == 0) {
                const auto opened = TreeKeys::unwrapKey(edge.blob, privateOf.at(recipient));
                ASSERT_TRUE(opened.has_value()) << "an edge does not open with the key it names";
                ASSERT_EQ(opened->getPublicKey().toBase58DER(), carried) << "an edge carries another key than it names";
            }
            wrapped[edge.blob] = {recipient, carried};
        }
    }

    void closeKnowledge() {
        for (auto& [userId, known] : knows) {
            for (bool grew = true; grew;) {
                grew = false;
                for (const TreeEdge& edge : bridge.state.edges) {
                    const auto& [recipient, carried] = wrapped.at(edge.blob);
                    if (known.count(recipient) > 0 && known.insert(carried).second) {
                        grew = true;
                    }
                }
            }
        }
    }

    void checkInvariants(bool afterRemoval) {
        const TreeGroupState& state = bridge.state;
        const std::string grant = state.grantPublicKey.toBase58DER();
        const std::vector<std::string> seatedIds = seated();

        // Knowledge: a filled node's key only under it; the grant key only for the seated.
        for (const TreeNodeState& node : state.nodes) {
            ASSERT_TRUE(TreeMath::isKeyed(node.nodeIndex, state.numLeaves)) << "a record on unkeyed " << node.nodeIndex;
            if (!node.publicKey.has_value()) {
                continue;
            }
            std::set<std::string> under;
            for (const std::uint32_t position : TreeMath::leavesUnder(node.nodeIndex, state.numLeaves)) {
                if (state.leafAssignment[position].has_value()) {
                    under.insert(state.leafAssignment[position].value());
                }
            }
            for (const auto& [userId, known] : knows) {
                if (known.count(node.publicKey->toBase58DER()) > 0) {
                    EXPECT_EQ(under.count(userId), 1u)
                        << userId << " knows node " << node.nodeIndex << " without being seated under it";
                }
            }
        }
        for (const auto& [userId, known] : knows) {
            const bool isSeated = std::find(seatedIds.begin(), seatedIds.end(), userId) != seatedIds.end();
            EXPECT_EQ(known.count(grant) > 0, isSeated)
                << userId << (isSeated ? " cannot reach" : " is not a member but reaches") << " the grant key";
        }

        // Consistency: the stored edges are exactly what the filled nodes owe, plus one grant edge.
        std::vector<std::string> required;
        for (const TreeNodeState& node : state.nodes) {
            if (!node.publicKey.has_value()) {
                continue;
            }
            for (const std::uint32_t child : TreeMath::children(node.nodeIndex, state.numLeaves)) {
                std::vector<std::string> resolved;
                resolve(state, child, resolved);
                for (const std::string& target : resolved) {
                    required.push_back(std::to_string(node.nodeIndex) + "@" + std::to_string(node.generation) + ">" +
                                       target);
                }
            }
        }
        if (state.numLeaves == 1) {
            required.push_back("grant@" + std::to_string(state.epoch) + ">user:" + state.leafAssignment[0].value());
        } else {
            const std::uint32_t root = TreeMath::root(state.numLeaves);
            ASSERT_NE(recordOf(state, root), nullptr);
            ASSERT_TRUE(recordOf(state, root)->publicKey.has_value()) << "the root is filled at rest";
            required.push_back("grant@" + std::to_string(state.epoch) + ">node:" + std::to_string(root) + "@" +
                               std::to_string(recordOf(state, root)->generation));
        }
        std::vector<std::string> stored;
        for (const TreeEdge& edge : state.edges) {
            stored.push_back(edgeIdentity(edge));
        }
        std::sort(required.begin(), required.end());
        std::sort(stored.begin(), stored.end());
        EXPECT_EQ(stored, required) << "the stored edges are not what the filled nodes owe";

        // After a removal, three of the seated climb the default view with real crypto. All of them reach the grant
        // key by the knowledge check above; this holds the climb itself and the "path" view to that.
        if (afterRemoval) {
            std::vector<std::string> climbers;
            std::sample(seatedIds.begin(), seatedIds.end(), std::back_inserter(climbers), 3, random);
            for (const std::string& userId : climbers) {
                TreeKeyCache cache;
                TreeKeys keys(cache);
                const ClimbResult climb = keys.climbToGrantKey(bridge.servePath(userId), userId, member(userId).priv);
                EXPECT_EQ(climb.failure, ClimbFailure::None) << userId << " cannot climb after the removal";
            }
        }
    }

    // The fake bridge's state, compared with what the client-side storage rule says it should be.
    void expectSameAsAfterCommit(const server::GroupTreeState& expected) {
        const TreeGroupState mine = TreeWire::toRuntime(expected, bridge.state.epoch, bridge.state.grantPublicKey);
        std::vector<std::string> a, b;
        for (const TreeEdge& edge : mine.edges) {
            a.push_back(edgeIdentity(edge) + edge.blob);
        }
        for (const TreeEdge& edge : bridge.state.edges) {
            b.push_back(edgeIdentity(edge) + edge.blob);
        }
        std::sort(a.begin(), a.end());
        std::sort(b.begin(), b.end());
        EXPECT_EQ(a, b) << "TreeWire::afterCommit disagrees with the storage rule";
        ASSERT_EQ(mine.nodes.size(), bridge.state.nodes.size());
        for (const TreeNodeState& node : mine.nodes) {
            const TreeNodeState* other = recordOf(bridge.state, node.nodeIndex);
            ASSERT_NE(other, nullptr);
            EXPECT_EQ(node.generation, other->generation);
            EXPECT_EQ(node.publicKey.has_value(), other->publicKey.has_value());
        }
    }

    server::GroupTreeState wireState() const {
        server::GroupTreeState tree;
        tree.numLeaves = bridge.state.numLeaves;
        for (const auto& seat : bridge.state.leafAssignment) {
            tree.leafAssignment.push_back(seat.value_or(""));
        }
        for (const TreeNodeState& node : bridge.state.nodes) {
            tree.nodes.push_back(TreeWire::toWire(node));
        }
        for (const TreeEdge& edge : bridge.state.edges) {
            tree.edges.push_back(TreeWire::toWire(edge));
        }
        return tree;
    }

    void create(std::uint32_t size, std::uint32_t creatorIndex) {
        std::vector<TreeMember> members;
        for (std::uint32_t i = 0; i < size; ++i) {
            const Member& m = newMember();
            members.push_back(TreeMember{m.userId, m.publicKey});
        }
        const std::string creator = members[creatorIndex].userId;
        TreeKeyCache cache;
        TreeKeys keys(cache);
        const CommitPlan plan = keys.planCreate(members, creator, member(creator).priv);
        bridge.create(TreeWire::toCreateTree(plan), plan.grantKey.getPublicKey(), creator);
        learnPlan(creator, plan);
        closeKnowledge();
        checkInvariants(false);
    }

    void add(const std::string& adder, std::uint32_t count) {
        std::vector<std::string> ids;
        // Former members come back now and then, carrying everything they ever knew.
        for (const Member& m : everyone) {
            if (ids.size() < count && pick(3) == 0 && !seatOf(bridge.state, m.userId).has_value()) {
                ids.push_back(m.userId);
            }
        }
        while (ids.size() < count) {
            ids.push_back(newMember().userId);
        }
        std::vector<TreeMember> newcomers;
        for (const std::string& id : ids) {
            newcomers.push_back(TreeMember{id, member(id).publicKey});
        }
        const auto positions = TreeKeys::choosePositions(bridge.state, count);
        const server::GroupTreeState before = wireState();
        const CommitPlan plan = planBy(adder, [&](TreeKeys& keys, const TreeGroupState& served) {
            return keys.planAddition(served, newcomers, positions, adder, member(adder).priv);
        });
        const auto wire = TreeWire::toAdditionTransition(plan, bridge.state.epoch);
        std::vector<server::GroupTreeRefreshedNode> refreshed;
        for (const server::GroupTreeSeatedNode& node : wire.seatedNodes) {
            refreshed.push_back(server::GroupTreeRefreshedNode{node.nodeIndex, node.fromGeneration, node.generation,
                                                               node.publicKey});
        }
        bridge.commit(FakeBridge::Op::Add, adder, ids, positions, refreshed, wire.edges, std::nullopt);
        expectSameAsAfterCommit(TreeWire::afterCommit(before, plan));
        learnPlan(adder, plan);
        closeKnowledge();
        checkInvariants(false);
    }

    void remove(const std::string& remover, const std::vector<std::string>& leaving) {
        const server::GroupTreeState before = wireState();
        const CommitPlan plan = planBy(remover, [&](TreeKeys& keys, const TreeGroupState& served) {
            return keys.planRemoval(served, leaving, remover, member(remover).priv);
        });
        const auto wire = TreeWire::toRemovalTransition(plan, bridge.state.epoch);
        bridge.commit(FakeBridge::Op::Remove, remover, leaving, {}, wire.refreshedNodes, wire.edges,
                      plan.grantKey.getPublicKey());
        expectSameAsAfterCommit(TreeWire::afterCommit(before, plan));
        learnPlan(remover, plan);
        closeKnowledge();
        checkInvariants(true);
    }

    void selfUpdate(const std::string& memberId) {
        const server::GroupTreeState before = wireState();
        const CommitPlan plan = planBy(memberId, [&](TreeKeys& keys, const TreeGroupState& served) {
            return keys.planSelfUpdate(served, memberId, member(memberId).priv);
        });
        const auto wire = TreeWire::toSelfUpdateTransition(plan, bridge.state.epoch);
        bridge.commit(FakeBridge::Op::SelfUpdate, memberId, {}, {}, wire.refreshedNodes, wire.edges, std::nullopt);
        expectSameAsAfterCommit(TreeWire::afterCommit(before, plan));
        learnPlan(memberId, plan);
        closeKnowledge();
        checkInvariants(false);
    }

    void runSequence(std::uint32_t seed, std::uint32_t operations) {
        random.seed(seed);
        // Odd seeds start above 32 seats, where the root is not the only keyed node; even ones anywhere from 1 to 32.
        const std::uint32_t size = seed % 2 == 1 ? 33 + pick(8) : 1 + pick(32);
        create(size, pick(size));
        for (std::uint32_t i = 0; i < operations && !HasFatalFailure(); ++i) {
            const std::vector<std::string> members = seated();
            const std::string committer = members[pick(static_cast<std::uint32_t>(members.size()))];
            const std::uint32_t roll = pick(10);
            if (roll < 3 && bridge.state.numLeaves < 48) {
                add(committer, 1 + pick(3));
            } else if (roll < 6 && members.size() > 1) {
                std::vector<std::string> others;
                for (const std::string& id : members) {
                    if (id != committer) {
                        others.push_back(id);
                    }
                }
                std::shuffle(others.begin(), others.end(), random);
                others.resize(std::min<std::size_t>(others.size(), 1 + pick(3)));
                remove(committer, others);
            } else if (bridge.state.numLeaves > 1) {
                selfUpdate(committer);
            }
        }
    }
};

} // namespace

TEST_F(TreeInvariant, TheC1Scenario) {
    // A creates {A, B, C, D}; B removes A. See the header for how the old design fails exactly here.
    create(4, 0);
    remove(everyone[1].userId, {everyone[0].userId});
    EXPECT_EQ(knows[everyone[0].userId].count(bridge.state.grantPublicKey.toBase58DER()), 0u);
}

TEST_F(TreeInvariant, TheC1ScenarioAboveTheBuckets) {
    // The same with two keyed levels: the creator held node 31 and the root; the remover sits outside node 31.
    create(40, 0);
    remove(everyone[35].userId, {everyone[0].userId});
    selfUpdate(everyone[7].userId);
    remove(everyone[7].userId, {everyone[36].userId, everyone[3].userId});
}

TEST_F(TreeInvariant, RandomSequencesKeepEveryInvariant) {
    // Six runs of 35 commits, half of them in groups past 32 seats; additions stop growing a group at 48.
    for (std::uint32_t seed = 1; seed <= 6 && !HasFatalFailure(); ++seed) {
        SCOPED_TRACE("seed " + std::to_string(seed));
        bridge = FakeBridge{};
        everyone.clear();
        privateOf.clear();
        wrapped.clear();
        knows.clear();
        runSequence(seed, 35);
    }
}
