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
 *     The invariant then has to hold: a filled node's key is known to a member only if the node is in its knowledge
 *     closure Know(u) — the ancestors of its seat and of every node it set (written again here from the spec);
 *     a former member's Know has no seat term, so after its removal it knows no current node at all;
 *   - removal: nobody unseated — whether removed just now or long ago — knows the current grant key, and every
 *     seated member climbs to it (real ECIES);
 *   - consistency: the stored edges are exactly the edges the filled nodes owe their children's resolution, plus
 *     one grant edge.
 *
 * The fake bridge derives what each commit may touch on its own, from the operation and the committer, and refuses
 * a refresh of anything else — the same rule the real one enforces.
 *
 * How a removal that blanks only the leaver's path fails here: A creates 64 seats and mints every node key,
 * including node 95 above seats 32..63. Seat 5 removes A, blanking A's path {31, 63} and re-keying its own — the same
 * two nodes — so the refreshed root still wraps to node 95 at the generation A minted, and A opens the new grant key
 * through it. The removal check fails right after that commit; the knowledge closure blanks 95 as well.
 *
 * Keys are real and random, so a run is reproducible in its operations (seeded), not in its key material.
 */

#include <gtest/gtest.h>

#include <algorithm>
#include <functional>
#include <iterator>
#include <map>
#include <memory>
#include <optional>
#include <random>
#include <set>
#include <string>
#include <vector>

#include <privmx/crypto/Crypto.hpp>
#include <privmx/crypto/ecc/PrivateKey.hpp>
#include <privmx/crypto/utils/Base58.hpp>
#include <privmx/endpoint/core/BigEndian.hpp>
#include <privmx/utils/Utils.hpp>

#include <privmx/endpoint/group/GroupException.hpp>
#include <privmx/endpoint/group/keytree/GroupKeyResolver.hpp>
#include <privmx/endpoint/group/keytree/PinBlob.hpp>
#include <privmx/endpoint/group/keytree/TreeCommits.hpp>
#include <privmx/endpoint/group/keytree/TreeKeys.hpp>
#include <privmx/endpoint/group/keytree/TreeMath.hpp>
#include <privmx/endpoint/group/keytree/TreeVerifier.hpp>
#include <privmx/endpoint/group/keytree/TreeWire.hpp>

#include "TreeTestOps.hpp"

#include "TreeFakeBridge.hpp"

using privmx::crypto::PrivateKey;
using privmx::crypto::PublicKey;
using namespace privmx::endpoint::group;
using namespace privmx::endpoint::group::keytree;

namespace {

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
    // Each member's own client: its pins and verified statements, as kept across reads in one session.
    std::map<std::string, TreeVerifier> verifiers;
    // The policy the next `create` signs.
    Poco::Dynamic::Var createPolicy = OPEN_POLICY;

    void SetUp() override { reset(); }

    void reset() {
        bridge = FakeBridge{};
        bridge.keyOf = [this](const std::string& userId) { return member(userId).publicKey; };
        everyone.clear();
        privateOf.clear();
        wrapped.clear();
        knows.clear();
        verifiers.clear();
        createPolicy = OPEN_POLICY;
    }

    TreeVerifier::Environment environment() const {
        TreeVerifier::Environment env;
        // The application's UserVerifier: it knows each user's real key.
        env.verifyUsers = [this](const std::vector<privmx::endpoint::core::VerificationRequest>& requests) {
            std::vector<bool> verified;
            for (const auto& request : requests) {
                const auto found = std::find_if(everyone.begin(), everyone.end(), [&](const Member& m) {
                    return m.userId == request.senderId;
                });
                verified.push_back(found != everyone.end() && found->pub == request.senderPubKey);
            }
            return verified;
        };
        env.commitsBetween = [this](std::uint64_t fromSeq, std::uint64_t toSeq) {
            return bridge.commitsBetween(fromSeq, toSeq);
        };
        return env;
    }

    TreeVerifier& verifierOf(const std::string& userId) { return verifiers[userId]; }

    // A member's read: what the bridge serves it, verified by its own client before anything is used.
    TreeGroupState verifiedRead(const std::string& userId, bool plan) {
        const server::GroupInfo info = bridge.serve(userId, plan);
        verifierOf(userId).verify(info, plan ? TreeVerifier::Scope::Plan : TreeVerifier::Scope::Path, environment());
        if (plan) {
            TreeVerifier::assertSeatsMatchRoster(info, info.users, info.managers);
        }
        return GroupKeyResolver::toTreeState(info);
    }

    // Signed as GroupApiImpl signs it: the post state's counters and roster (`members`, of whom the bridge's managers
    // minus the removed are managers; at creation the creator), the policy's hash, the committer's own key.
    server::GroupTreeCommit sign(
        const CommitPlan& plan,
        CommitOp op,
        const std::string& committer,
        std::uint64_t keyVersion,
        const privmx::crypto::PublicKey& grant,
        std::int64_t rosterVersion,
        const std::vector<std::string>& members,
        std::vector<std::string> added,
        std::vector<std::string> removed
    ) {
        std::set<std::string> managers = op == CommitOp::Create ? std::set<std::string>{committer} : bridge.managers;
        for (const std::string& gone : removed) {
            managers.erase(gone);
        }
        std::vector<std::string> users;
        for (const std::string& id : members) {
            if (managers.count(id) == 0) {
                users.push_back(id);
            }
        }
        const GroupRules rules =
            op == CommitOp::Create ? TreeCommits::rules(createPolicy, committer) : bridge.rules();
        CommitStatement statement = TreeCommits::statementFor(
            plan, op, op == CommitOp::Create ? std::string("res") : GROUP_ID, 1760000000000, keyVersion,
            grant.toBase58DER(), static_cast<std::uint64_t>(rosterVersion), users, {managers.begin(), managers.end()},
            committer, std::move(added), {}, std::move(removed), rules.hash
        );
        if (op == CommitOp::Create) {
            statement.policy = createPolicy;
        } else {
            statement.prevDigest = TreeCommits::digest(TreeCommits::fromWire(bridge.commits.back()));
        }
        TreeCommits::sign(statement, member(committer).priv);
        return TreeCommits::toWire(statement);
    }

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

    std::uint32_t pick(std::uint32_t bound) {
        return std::uniform_int_distribution<std::uint32_t>(0, bound - 1)(random);
    }

    // A live client's way in: a cold cache, the verified "plan" view, a climb, then the plan.
    CommitPlan planBy(const std::string& committer, const std::function<CommitPlan(TreeKeys&, const TreeGroupState&)>& plan) {
        const TreeGroupState served = verifiedRead(committer, true);
        TreeKeyCache cache;
        TreeKeys keys(cache);
        const ClimbResult climb = keys.climbToGrantKey(served, committer, member(committer).priv, false);
        EXPECT_EQ(climb.failure, ClimbFailure::None) << committer << " cannot climb to plan";
        treetest::setMemberKeys(keys, roster());
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
        const std::vector<std::string> seatedIds = seatedIn(bridge.state);

        // Knowledge: a filled node's key only within Know; the grant key only for the seated.
        std::map<std::string, std::set<std::uint32_t>> closures;
        for (const auto& [userId, known] : knows) {
            closures[userId] = bridge.know(userId);
        }
        for (const TreeNodeState& node : state.nodes) {
            ASSERT_TRUE(TreeMath::isKeyed(node.nodeIndex, state.numLeaves)) << "a record on unkeyed " << node.nodeIndex;
            if (!node.publicKey.has_value()) {
                continue;
            }
            for (const auto& [userId, known] : knows) {
                if (known.count(node.publicKey->toBase58DER()) > 0) {
                    EXPECT_EQ(closures[userId].count(node.nodeIndex), 1u)
                        << userId << " knows node " << node.nodeIndex << " outside its knowledge closure";
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
                const ClimbResult climb = keys.climbToGrantKey(verifiedRead(userId, false), userId, member(userId).priv);
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
        EXPECT_EQ(a, b) << "treetest::afterCommit disagrees with the storage rule";
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
        std::vector<std::string> ids;
        for (const TreeMember& m : members) {
            ids.push_back(m.userId);
        }
        // The creator a manager, under the open policy: every member may commit unless a test narrows it.
        bridge.create(
            TreeWire::toCreateTree(plan), plan.grantKey.getPublicKey(), creator,
            sign(plan, CommitOp::Create, creator, 1, plan.grantKey.getPublicKey(), 1, ids, {}, {}), {creator}
        );
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
        const auto positions = treetest::choosePositions(bridge.state, count);
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
        std::vector<std::string> after = seatedIn(bridge.state);
        after.insert(after.end(), ids.begin(), ids.end());
        bridge.commit(
            CommitOp::Add, adder, ids, positions, refreshed, wire.edges, std::nullopt,
            sign(plan, CommitOp::Add, adder, bridge.state.epoch, bridge.state.grantPublicKey, bridge.rosterVersion + 1,
                 after, ids, {})
        );
        expectSameAsAfterCommit(treetest::afterCommit(before, plan));
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
        std::vector<std::string> after;
        for (const std::string& id : seatedIn(bridge.state)) {
            if (std::find(leaving.begin(), leaving.end(), id) == leaving.end()) {
                after.push_back(id);
            }
        }
        bridge.commit(
            CommitOp::Remove, remover, leaving, {}, wire.refreshedNodes, wire.edges, plan.grantKey.getPublicKey(),
            sign(plan, CommitOp::Remove, remover, bridge.state.epoch + 1, plan.grantKey.getPublicKey(),
                 bridge.rosterVersion + 1, after, {}, leaving)
        );
        expectSameAsAfterCommit(treetest::afterCommit(before, plan));
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
        bridge.commit(
            CommitOp::SelfUpdate, memberId, {}, {}, wire.refreshedNodes, wire.edges, std::nullopt,
            sign(plan, CommitOp::SelfUpdate, memberId, bridge.state.epoch, bridge.state.grantPublicKey,
                 bridge.rosterVersion, seatedIn(bridge.state), {}, {})
        );
        expectSameAsAfterCommit(treetest::afterCommit(before, plan));
        learnPlan(memberId, plan);
        closeKnowledge();
        checkInvariants(false);
    }

    // A rotation as GroupApiImpl plans it (`TreeKeys::planRotation`), stored by the bridge's `generateNewGroupKey`.
    void rotate(const std::string& rotator) {
        const CommitPlan plan = planBy(rotator, [&](TreeKeys& keys, const TreeGroupState& served) {
            return keys.planRotation(served, rotator, member(rotator).priv);
        });
        ASSERT_TRUE(plan.refreshed.empty()) << "a rotation mints no node";
        ASSERT_EQ(plan.edges.size(), 1u) << "a rotation writes the grant edge alone";
        bridge.rotate(
            rotator, TreeWire::toWire(plan.edges[0]), plan.grantKey.getPublicKey(),
            sign(plan, CommitOp::Rotate, rotator, bridge.state.epoch + 1, plan.grantKey.getPublicKey(),
                 bridge.rosterVersion + 1, seatedIn(bridge.state), {}, {})
        );
        learnPlan(rotator, plan);
        closeKnowledge();
        checkInvariants(false);
    }

    // A cold climb of `userId`'s verified path view: the grant key it reaches, if any.
    ClimbResult coldClimb(const std::string& userId, TreeKeyCache& cache) {
        TreeKeys keys(cache);
        return keys.climbToGrantKey(verifiedRead(userId, false), userId, member(userId).priv, false);
    }

    void runSequence(std::uint32_t seed, std::uint32_t operations) {
        random.seed(seed);
        // Past 32 seats the root is not the only keyed node, past 64 there are keyed nodes off two levels: the
        // creator's and adders' off-path fills, and the closure a removal blanks, only matter there.
        const std::uint32_t size = seed % 3 == 0 ? 1 + pick(32) : seed % 3 == 1 ? 33 + pick(8) : 60 + pick(12);
        create(size, pick(size));
        for (std::uint32_t i = 0; i < operations && !HasFatalFailure(); ++i) {
            const std::vector<std::string> members = seatedIn(bridge.state);
            const std::string committer = members[pick(static_cast<std::uint32_t>(members.size()))];
            const std::uint32_t roll = pick(10);
            if (roll < 3 && bridge.state.numLeaves < 72) {
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

// What a forged statement says besides the state `change` leaves. Fields are only ever added, never parameters.
struct ForgeOptions {
    std::vector<StatementNode> path;
    std::vector<std::string> added; // addedUsers
    std::vector<std::string> addedManagers;
    std::vector<std::string> removed;
    std::int64_t rosterBump = 0;
    // An explicit op wins; else the one derivation rule: removed -> Remove, added -> Add, a new epoch -> Rotate,
    // anything else SelfUpdate.
    std::optional<CommitOp> op;
    std::optional<std::string> policyHash;    // default: the current one, or `policy`'s with the creator
    std::optional<Poco::Dynamic::Var> policy; // the wire policy (create/policy ops); becomes the bridge's
    // The post-state managers the rosterHash is computed over; default: the bridge's, less `removed`, plus
    // `addedManagers`.
    std::optional<std::vector<std::string>> managers;
};

// A client's verification against a bridge that lies, alone or with a member.
class TreeVerification : public TreeInvariant {
protected:
    void verify(const std::string& userId, bool plan) {
        verifierOf(userId).verify(
            bridge.serve(userId, plan), plan ? TreeVerifier::Scope::Plan : TreeVerifier::Scope::Path, environment()
        );
    }

    const std::string& id(std::size_t index) const { return everyone[index].userId; }

    std::vector<std::string> managersOf() const { return {bridge.managers.begin(), bridge.managers.end()}; }

    // Whether `check` is refused with GroupUnauthorizedSignerException.
    template<class F>
    static bool unauthorized(F check) {
        try {
            check();
            return false;
        } catch (const GroupUnauthorizedSignerException&) {
            return true;
        } catch (...) {
            return false;
        }
    }

    // The stored chain replayed from genesis, as `epochOpeners` replays it below a pin no read walked: "" when it
    // passes, "unauthorized" for a role failure, else the integrity refusal's description ("integrity" without one).
    std::string replay() {
        TreeVerifier own;
        own.pinCommitted(
            GROUP_ID, "ctx", TreeCommits::fromWire(bridge.commits.back()), bridge.users(), managersOf(), bridge.rules()
        );
        try {
            own.epochOpeners(GROUP_ID, "ctx", environment());
            return "";
        } catch (const GroupUnauthorizedSignerException&) {
            return "unauthorized";
        } catch (const GroupDataIntegrityException& e) {
            return e.getDescription().empty() ? "integrity" : e.getDescription();
        }
    }

    // Whether `check` is refused with GroupDataIntegrityException.
    template<class F>
    static bool refuses(F check) {
        try {
            check();
            return false;
        } catch (const GroupDataIntegrityException&) {
            return true;
        }
    }

    // A statement the bridge stores with none of its checks — what a malicious bridge, or a member colluding with
    // one, can put in front of a client. `change` edits the stored state; the statement then describes the result
    // exactly (counters, roster, tree hash) and is genuinely signed by `signer`.
    void forge(const std::string& signer, const std::function<void(TreeGroupState&)>& change, ForgeOptions options = {}) {
        TreeGroupState next = bridge.state;
        change(next);
        std::set<std::string> managers = bridge.managers;
        for (const std::string& gone : options.removed) {
            managers.erase(gone);
        }
        managers.insert(options.addedManagers.begin(), options.addedManagers.end());
        if (options.managers.has_value()) {
            managers = std::set<std::string>(options.managers->begin(), options.managers->end());
        }
        CommitStatement statement;
        statement.seq = bridge.commits.size() + 1;
        statement.prevDigest = TreeCommits::digest(TreeCommits::fromWire(bridge.commits.back()));
        statement.op = options.op.value_or(
            !options.removed.empty()                                        ? CommitOp::Remove :
            !options.added.empty() || !options.addedManagers.empty()        ? CommitOp::Add :
            next.epoch != bridge.state.epoch                                ? CommitOp::Rotate :
                                                                              CommitOp::SelfUpdate
        );
        statement.groupId = GROUP_ID;
        statement.treeVersion = TreeMath::TREE_VERSION;
        statement.date = 1760000000000;
        statement.keyVersion = next.epoch;
        statement.groupPubKey = next.grantPublicKey.toBase58DER();
        statement.rosterVersion = static_cast<std::uint64_t>(bridge.rosterVersion + options.rosterBump);
        statement.rosterHash = TreeCommits::rosterHash(bridge.usersOf(next, managers), {managers.begin(), managers.end()});
        statement.treeHash = TreeCommits::treeHash(next);
        statement.policyHash = options.policyHash.has_value() ? options.policyHash.value() :
            options.policy.has_value()                         ? TreeCommits::rules(options.policy.value(), bridge.creator).hash :
                                                                 bridge.rules().hash;
        statement.policy = options.policy;
        statement.committer = signer;
        statement.committerSeat = seatOf(next, signer).value();
        for (StatementNode& node : options.path) {
            node.subtreeHash = TreeCommits::subtreeHash(next, node.nodeIndex);
        }
        statement.path = std::move(options.path);
        statement.addedUsers = std::move(options.added);
        statement.addedManagers = std::move(options.addedManagers);
        statement.removed = std::move(options.removed);
        TreeCommits::sign(statement, member(signer).priv);
        bridge.state = next;
        bridge.managers = managers;
        bridge.rosterVersion += options.rosterBump;
        if (options.policy.has_value()) {
            bridge.policy = options.policy.value();
        }
        bridge.commits.push_back(TreeCommits::toWire(statement));
    }

    // 01: `userId`'s pins as the next session loads them: exported, through the blob codec, into a fresh verifier.
    // `compact`: without rosters and generations (what the blob keeps once its budget is spent).
    std::unique_ptr<TreeVerifier> imported(const std::string& userId, bool compact = false) {
        TreeVerifier::PinSet pins;
        pins.tree = verifierOf(userId).exportPins(true);
        if (compact) {
            for (auto& [groupId, pin] : pins.tree) {
                pin.hasRoster = false;
            }
        }
        const auto decoded = PinBlob::decode(PinBlob::encode(pins));
        EXPECT_TRUE(decoded.has_value());
        auto next = std::make_unique<TreeVerifier>();
        next->mergeStored(decoded.value_or(TreeVerifier::PinSet{}).tree);
        return next;
    }

    // A set holding one record, as a sibling instance stored it.
    static TreeVerifier::PinSet storedWith(const TreeVerifier::Pin& pin) {
        TreeVerifier::PinSet pins;
        pins.tree[GROUP_ID] = pin;
        return pins;
    }

    static void setRecord(TreeGroupState& state, const TreeNodeState& record) {
        for (TreeNodeState& node : state.nodes) {
            if (node.nodeIndex == record.nodeIndex) {
                node = record;
                return;
            }
        }
        state.nodes.push_back(record);
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

TEST_F(TreeInvariant, ARemovedCreatorLosesEveryNodeItSet) {
    // The header's case: the remover's path is the creator's, and node 95 is off both.
    create(64, 0);
    remove(everyone[5].userId, {everyone[0].userId});
    EXPECT_EQ(bridge.lastBlanked, (std::set<std::uint32_t>{95}));
    EXPECT_EQ(knows[everyone[0].userId].count(bridge.state.grantPublicKey.toBase58DER()), 0u);
}

TEST_F(TreeInvariant, ARemovedAdderLosesWhatItMintedForTheNewcomers) {
    // V8: seat 40 adds a member at seat 5 and so mints node 31; removing seat 40 blanks node 95, the rest of what it
    // could know, while the remover re-keys 31 and 63.
    create(64, 0);
    const std::string adder = everyone[40].userId; // a copy: adding grows `everyone`
    remove(adder, {everyone[5].userId});
    add(adder, 1);
    ASSERT_TRUE(bridge.state.leafAssignment[5].has_value()) << "the blank is reused";
    remove(everyone[0].userId, {adder});
    EXPECT_EQ(bridge.lastBlanked, (std::set<std::uint32_t>{95}));
}

TEST_F(TreeInvariant, ASelfUpdateHealsNodesSetFromOutside) {
    // Seat 40 sits under node 95, which the creator set: it self-updates over it, after which removing the creator
    // costs no blank at all (V3).
    create(64, 0);
    EXPECT_TRUE(GroupKeyResolver::nodeNeedingSelfUpdate(bridge.serve(everyone[40].userId, true)).has_value());
    EXPECT_FALSE(GroupKeyResolver::nodeNeedingSelfUpdate(bridge.serve(everyone[0].userId, true)).has_value());
    selfUpdate(everyone[40].userId);
    EXPECT_FALSE(GroupKeyResolver::nodeNeedingSelfUpdate(bridge.serve(everyone[40].userId, true)).has_value());
    EXPECT_FALSE(GroupKeyResolver::nodeNeedingSelfUpdate(bridge.serve(everyone[63].userId, true)).has_value());
    remove(everyone[5].userId, {everyone[0].userId});
    EXPECT_TRUE(bridge.lastBlanked.empty());
}

TEST_F(TreeInvariant, RandomSequencesKeepEveryInvariant) {
    // Six runs of 35 commits, from groups of under 32 seats to over 64; additions stop growing a group at 72.
    for (std::uint32_t seed = 1; seed <= 6 && !HasFatalFailure(); ++seed) {
        SCOPED_TRACE("seed " + std::to_string(seed));
        reset();
        runSequence(seed, 35);
    }
}

// rotation (T3-27)

TEST_F(TreeInvariant, AOneMemberGroupClimbsToTheGrantKeyOfARotatedEpoch) {
    // The one-leaf root is the member's leaf: the new grant key is wrapped straight to the member's own key.
    create(1, 0);
    const std::string sole = everyone[0].userId;
    rotate(sole);
    ASSERT_EQ(bridge.state.epoch, 2u);
    ASSERT_EQ(edgeIdentity(bridge.state.edges.at(0)), "grant@2>user:" + sole);
    TreeKeyCache cache;
    const ClimbResult climb = coldClimb(sole, cache);
    ASSERT_EQ(climb.failure, ClimbFailure::None);
    EXPECT_EQ(climb.grantKey->getPublicKey().toBase58DER(), bridge.state.grantPublicKey.toBase58DER());
}

TEST_F(TreeInvariant, SECURITY_AOneMemberRotationIsTakenOnlyUnderTheGrantKeyItsStatementSigns) {
    // The bridge serves the grant edge re-wrapped to a key of its own choosing. Anybody can wrap to the member's
    // public key; only the signed `groupPubKey` makes the member take the key inside.
    create(1, 0);
    const std::string sole = everyone[0].userId;
    rotate(sole);
    const PrivateKey planted = PrivateKey::generateRandom();
    for (TreeEdge& edge : bridge.state.edges) {
        ASSERT_TRUE(edge.isGrantEdge);
        edge.blob = TreeKeys::wrapKey(planted, member(sole).publicKey, PrivateKey::generateRandom());
    }
    TreeKeyCache cache;
    EXPECT_EQ(coldClimb(sole, cache).failure, ClimbFailure::Tampered);
    EXPECT_FALSE(cache.getGrantKey(2).has_value()) << "nothing is cached for the epoch";
}

TEST_F(TreeInvariant, ARotatedOneMemberGroupSeatsANewcomerAtTheRotatedEpoch) {
    // 1 -> 2 after a rotation: the grant edge moves from the member to node 1, still at the rotated epoch.
    create(1, 0);
    const std::string sole = everyone[0].userId;
    rotate(sole);
    add(sole, 1);
    const std::string newcomer = everyone.back().userId;
    ASSERT_EQ(bridge.state.epoch, 2u) << "an addition advances no epoch";
    std::vector<std::string> grants;
    for (const TreeEdge& edge : bridge.state.edges) {
        if (edge.isGrantEdge) {
            grants.push_back(edgeIdentity(edge));
        }
    }
    EXPECT_EQ(grants, std::vector<std::string>{"grant@2>node:1@" + std::to_string(recordOf(bridge.state, 1)->generation)});
    TreeKeyCache cache;
    const ClimbResult climb = coldClimb(newcomer, cache);
    ASSERT_EQ(climb.failure, ClimbFailure::None);
    EXPECT_EQ(climb.grantKey->getPublicKey().toBase58DER(), bridge.state.grantPublicKey.toBase58DER());
    // Create -> rotate -> add, as a chain from a pin before the rotation and on first contact.
    EXPECT_NO_THROW(verifiedRead(sole, false));
    const auto openers = verifierOf(newcomer).epochOpeners(GROUP_ID, "ctx", environment());
    ASSERT_EQ(openers.size(), 2u);
    EXPECT_EQ(openers.at(1).seq, 1u);
    EXPECT_EQ(openers.at(2).seq, 2u);
    EXPECT_EQ(openers.at(2).op, CommitOp::Rotate);
    EXPECT_EQ(openers.at(2).committer, sole);
}

TEST_F(TreeInvariant, ARotationOfALargerGroupGoesToTheRootAndKeepsEveryInvariant) {
    // n >= 2: wrapped to the root at its current generation, including right after a removal re-keyed it; a removed
    // member reaches none of the rotated keys (the knowledge check), every seated one climbs to them.
    create(40, 0);
    rotate(everyone[9].userId);
    remove(everyone[35].userId, {everyone[5].userId});
    rotate(everyone[0].userId);
    selfUpdate(everyone[7].userId);
    rotate(everyone[39].userId);
    EXPECT_EQ(bridge.state.epoch, 5u);
    EXPECT_EQ(knows[everyone[5].userId].count(bridge.state.grantPublicKey.toBase58DER()), 0u);
    for (const std::size_t seat : {0u, 9u, 33u}) {
        TreeKeyCache cache;
        EXPECT_EQ(coldClimb(everyone[seat].userId, cache).failure, ClimbFailure::None) << seat;
    }
}

TEST_F(TreeInvariant, ARotationIsPlannedOnlyByASeatedMember) {
    create(4, 0);
    const std::string removed = everyone[3].userId;
    remove(everyone[0].userId, {removed});
    TreeKeyCache cache;
    TreeKeys keys(cache);
    EXPECT_THROW(keys.planRotation(bridge.state, removed, member(removed).priv), std::invalid_argument);
}

// verification

TEST_F(TreeVerification, AcceptsHonestStatesInBothScopes) {
    create(40, 0);
    remove(id(35), {id(5)}); // node 31 blank
    selfUpdate(id(9));       // and refilled
    for (const std::size_t member : {0u, 9u, 33u, 39u}) {
        EXPECT_NO_THROW(verify(id(member), false)) << id(member);
        EXPECT_NO_THROW(verify(id(member), true)) << id(member);
    }
}

TEST_F(TreeVerification, SECURITY_RefusesASubstitutedNodeKey) {
    // P1: an honest committer would wrap the next root to a key the bridge chose.
    create(40, 0);
    for (const bool plan : {false, true}) {
        server::GroupInfo info = bridge.serve(id(9), plan);
        auto nodes = info.treeNodes.value();
        for (server::GroupTreeNode& node : nodes) {
            if (node.nodeIndex == 31) {
                node.publicKey = PrivateKey::generateRandom().getPublicKey().toBase58DER();
            }
        }
        info.treeNodes = nodes;
        TreeVerifier fresh;
        EXPECT_THROW(
            fresh.verify(info, plan ? TreeVerifier::Scope::Plan : TreeVerifier::Scope::Path, environment()),
            GroupDataIntegrityException
        ) << (plan ? "plan" : "path");
    }
}

TEST_F(TreeVerification, SECURITY_RefusesASubstitutedGrantKey) {
    create(40, 0);
    server::GroupInfo info = bridge.serve(id(9), false);
    info.groupPubKey = PrivateKey::generateRandom().getPublicKey().toBase58DER();
    EXPECT_THROW(verifierOf(id(9)).verify(info, TreeVerifier::Scope::Path, environment()), GroupDataIntegrityException);
}

TEST_F(TreeVerification, SECURITY_RefusesAnOutsiderSeated) {
    // P2: the next commit would wrap to whoever sits in the tree.
    create(40, 0);
    remove(id(35), {id(5)});
    server::GroupInfo info = bridge.serve(id(9), true);
    auto seats = info.leafAssignment.value();
    seats[5] = "mallory";
    info.leafAssignment = seats;
    TreeVerifier fresh;
    EXPECT_THROW(fresh.verify(info, TreeVerifier::Scope::Plan, environment()), GroupDataIntegrityException);
    EXPECT_THROW(TreeVerifier::assertSeatsMatchRoster(info, info.users, info.managers), GroupDataIntegrityException)
        << "the seats no longer match the attested roster";
    info.users.push_back("mallory");
    EXPECT_THROW(fresh.verify(info, TreeVerifier::Scope::Plan, environment()), GroupDataIntegrityException)
        << "nor the roster the statement signed";
}

TEST_F(TreeVerification, AcceptsANodeSetByTheCreatorOutsideItsSubtree) {
    // Seat 35 creates the group and so sets node 31, outside its own subtree: that is the design now.
    create(40, 35);
    EXPECT_NO_THROW(verify(id(9), false));
    EXPECT_NO_THROW(verify(id(9), true));
}

TEST_F(TreeVerification, SECURITY_RefusesANodeVouchedByAFormerMember) {
    // The creator is removed, which blanks node 31 (it set it). A colluding member and the bridge put the creator's
    // key back under the creator's own genuine statement; the state hashes right, but that voucher left the roster.
    create(40, 0);
    remove(id(35), {id(0)});
    ASSERT_FALSE(recordOf(bridge.state, 31)->publicKey.has_value());
    const server::GroupTreeCommitPathEntry original = bridge.commits[0].path[0];
    ASSERT_EQ(original.nodeIndex, 31);
    forge(id(9), [&](TreeGroupState& state) {
        setRecord(state, TreeNodeState{31, 0, NodePublicKey::fromBase58DER(original.publicKey), 1});
    });
    EXPECT_THROW(verify(id(10), true), GroupDataIntegrityException);
    EXPECT_THROW(verify(id(10), false), GroupDataIntegrityException);
}

TEST_F(TreeVerification, SECURITY_RefusesAStaleGenerationToAClientThatSawTheNewer) {
    // Node 31 rolled back to the generation the creator set — a key a since-removed member could have known —
    // under a genuine statement by a colluding member. Node 15 below it has been re-keyed since, so the subtree no
    // longer hashes to what the creator signed: refused by a client that saw generation 1 and by one that did not.
    create(40, 0);
    selfUpdate(id(1)); // node 31 at generation 1, set by statement 2
    ASSERT_NO_THROW(verify(id(2), false));
    const server::GroupTreeCommitPathEntry original = bridge.commits[0].path[0];
    ASSERT_EQ(original.nodeIndex, 31);
    forge(id(3), [&](TreeGroupState& state) {
        setRecord(state, TreeNodeState{31, 0, NodePublicKey::fromBase58DER(original.publicKey), 1});
    });
    EXPECT_THROW(verify(id(2), false), GroupDataIntegrityException);
    EXPECT_THROW(verify(id(4), false), GroupDataIntegrityException);
}

TEST_F(TreeVerification, SECURITY_RefusesARolledBackAncestorOverAHealedChild) {
    // AM-1: seat 100 self-updates, so node 191 (generation 1, its setter) wraps to node 159, which the creator
    // set: the creator learns 191. Seat 70 heals 159 and 191. The creator and the bridge serve 191 at generation 1
    // again under seat 100's genuine statement, and the creator re-keys the root over it in a commit of its own; seat
    // 100 is on the roster, so the creator's removal would not blank 191 and its fresh root would wrap to it. No
    // client may take that state, pinned or not, in either view.
    create(128, 0);
    selfUpdate(id(100));
    const std::vector<server::GroupTreeCommitPathEntry> healed = bridge.commits.back().path;
    const auto rolledBack = std::find_if(healed.begin(), healed.end(), [](const server::GroupTreeCommitPathEntry& e) {
        return e.nodeIndex == 191;
    });
    ASSERT_NE(rolledBack, healed.end());
    selfUpdate(id(70));
    ASSERT_GT(recordOf(bridge.state, 191)->generation, rolledBack->generation);
    const std::string root = PrivateKey::generateRandom().getPublicKey().toBase58DER();
    const std::uint32_t rootGeneration = recordOf(bridge.state, 127)->generation + 1;
    forge(id(0), [&](TreeGroupState& state) {
        setRecord(
            state, TreeNodeState{
                       191, static_cast<std::uint32_t>(rolledBack->generation),
                       NodePublicKey::fromBase58DER(rolledBack->publicKey), bridge.commits.size() - 1
                   }
        );
        setRecord(
            state, TreeNodeState{127, rootGeneration, NodePublicKey::fromBase58DER(root), bridge.commits.size() + 1}
        );
    }, {.path = {StatementNode{127, rootGeneration, root, ""}}});
    for (const bool plan : {false, true}) {
        TreeVerifier fresh;
        EXPECT_THROW(
            fresh.verify(
                bridge.serve(id(plan ? 40 : 100), plan), plan ? TreeVerifier::Scope::Plan : TreeVerifier::Scope::Path,
                environment()
            ),
            GroupDataIntegrityException
        ) << (plan ? "the remover's plan view" : "a path view under 191");
    }
}

TEST_F(TreeVerification, SECURITY_RefusesASecondRecordForOneNode) {
    // Node 31 is blank after the removal. Behind its genuine (hashed) blank record the bridge serves a second one,
    // filled with the key the creator set, vouched by the creator's own genuine statement. A plan view with it holds
    // more records than keyed nodes; a path view, which holds only its path's (3 of 7), gets as far as the duplicate.
    create(128, 0);
    remove(id(35), {id(5)});
    const auto& minted = bridge.commits[0].path;
    const auto original = *std::find_if(minted.begin(), minted.end(), [](const auto& e) { return e.nodeIndex == 31; });
    ASSERT_FALSE(recordOf(bridge.state, 31)->publicKey.has_value());
    for (const bool plan : {true, false}) {
        server::GroupInfo info = bridge.serve(id(9), plan);
        auto nodes = info.treeNodes.value();
        nodes.push_back(
            server::GroupTreeNode{
                .nodeIndex = 31, .generation = original.generation, .publicKey = original.publicKey, .setBy = 1
            }
        );
        info.treeNodes = nodes;
        auto cited = info.treeCommits.value_or(std::vector<server::GroupTreeCommit>{});
        cited.push_back(bridge.commits[0]);
        info.treeCommits = cited;
        TreeVerifier fresh;
        expectRefusal(
            [&] { fresh.verify(info, plan ? TreeVerifier::Scope::Plan : TreeVerifier::Scope::Path, environment()); },
            plan ? "more node records than the tree has" : "a second record for one node"
        );
    }
}

TEST_F(TreeVerification, SECURITY_RefusesPaddedNodeRecordsBeforeHashingThem) {
    // The hash looks every node up among the records: padding them would cost O(nodes x records) before any refusal.
    create(40, 0);
    server::GroupInfo info = bridge.serve(id(9), true);
    auto nodes = info.treeNodes.value();
    ASSERT_EQ(nodes.size(), TreeMath::keyedNodes(40).size()) << "the plan view serves every keyed node";
    nodes.push_back(nodes.front());
    info.treeNodes = nodes;
    TreeVerifier fresh;
    expectRefusal(
        [&] { fresh.verify(info, TreeVerifier::Scope::Plan, environment()); }, "more node records than the tree has"
    );
}

TEST_F(TreeVerification, SECURITY_RefusesARollbackBelowThePin) {
    create(40, 0);
    const FakeBridge before = bridge;
    selfUpdate(id(1));
    ASSERT_NO_THROW(verify(id(9), false));
    bridge = before; // a genuine, fully signed, earlier state
    EXPECT_THROW(verify(id(9), false), GroupHistoryForkException);
}

TEST_F(TreeVerification, SECURITY_RefusesARollbackAcrossARotationOrAPolicyCommit) {
    // Neither moves the tree, so no node generation tells the earlier state from the pinned one: only the seq does.
    for (const bool rotation : {true, false}) {
        reset();
        create(40, 0);
        const FakeBridge before = bridge;
        if (rotation) {
            rotate(id(1));
        } else {
            forge(id(0), [](TreeGroupState&) {}, {
                .op = CommitOp::Policy,
                .policy = std::optional<Poco::Dynamic::Var>(std::in_place, policyOf({{"update", "user"}}))
            });
        }
        ASSERT_NO_THROW(verify(id(9), false));
        bridge = before;
        EXPECT_THROW(verify(id(9), false), GroupHistoryForkException) << (rotation ? "rotation" : "policy");
        EXPECT_EQ(verifierOf(id(9)).pinnedSeq(GROUP_ID), 2u) << "the pin stays";
    }
}

TEST_F(TreeVerification, SECURITY_RefusesANodeServedBelowAGenerationAlreadySeen) {
    // A colluding member re-keys node 31 under a fresh key of its own but at the generation before the one this
    // client saw, and the root over it. Its statement vouches for both over the current subtree and extends the
    // chain, so every other check passes (a fresh client takes it): only the pinned generations tell it from new.
    create(40, 0);
    selfUpdate(id(1));
    ASSERT_NO_THROW(verify(id(2), false));
    const std::uint32_t seen = recordOf(bridge.state, 31)->generation;
    ASSERT_GT(seen, 0u);
    const std::uint32_t root = TreeMath::root(bridge.state.numLeaves);
    const std::uint32_t rootGeneration = recordOf(bridge.state, root)->generation + 1;
    const std::string node = PrivateKey::generateRandom().getPublicKey().toBase58DER();
    const std::string rootKey = PrivateKey::generateRandom().getPublicKey().toBase58DER();
    const std::uint64_t seq = bridge.commits.size() + 1;
    forge(id(3), [&](TreeGroupState& state) {
        setRecord(state, TreeNodeState{31, seen - 1, NodePublicKey::fromBase58DER(node), seq});
        setRecord(state, TreeNodeState{root, rootGeneration, NodePublicKey::fromBase58DER(rootKey), seq});
    }, {.path = {StatementNode{31, seen - 1, node, ""}, StatementNode{root, rootGeneration, rootKey, ""}}});
    EXPECT_NO_THROW(TreeVerifier().verify(bridge.serve(id(4), false), TreeVerifier::Scope::Path, environment()));
    EXPECT_THROW(verify(id(2), false), GroupHistoryForkException);
}

TEST_F(TreeVerification, AnAnswerBehindThePinIsTellableFromAForkAtThePin) {
    // A served seq below the pin (a concurrent read may have got further) is a fork until the read helper's re-read.
    create(40, 0);
    const server::GroupInfo older = bridge.serve(id(9), false);
    selfUpdate(id(1));
    ASSERT_NO_THROW(verify(id(9), false));
    EXPECT_EQ(verifierOf(id(9)).pinnedSeq(GROUP_ID), bridge.commits.size());
    EXPECT_THROW(verifierOf(id(9)).verify(older, TreeVerifier::Scope::Path, environment()), GroupHistoryForkException);
    EXPECT_LT(older.treeCommit->seq, static_cast<std::int64_t>(verifierOf(id(9)).pinnedSeq(GROUP_ID)));
    EXPECT_NO_THROW(verify(id(9), false)) << "the fresh read passes";
    EXPECT_EQ(TreeVerifier().pinnedSeq(GROUP_ID), 0u);
}

TEST_F(TreeVerification, SECURITY_RefusesAChainLinkSignedByANonMember) {
    // The bridge seats mallory and has her sign for it. Each statement is genuine and the state matches it; what
    // gives it away is that mallory was no member when she signed.
    create(40, 0);
    remove(id(35), {id(5)});
    ASSERT_NO_THROW(verify(id(9), false));
    const std::string mallory = newMember().userId;
    forge(mallory, [&](TreeGroupState& state) { state.leafAssignment[5] = mallory; }, {.added = {mallory}, .rosterBump = 1});
    EXPECT_THROW(verify(id(9), false), GroupDataIntegrityException);
    // First contact trusts the latest genuine statement by somebody on its roster, but seat 5 changed under the
    // root without the root being re-keyed: the root's voucher signed another subtree.
    EXPECT_THROW(verify(id(10), false), GroupDataIntegrityException);

    // With her path re-keyed the tree is vouched for, so only the chain gives her away.
    reset();
    create(40, 0);
    remove(id(35), {id(5)});
    ASSERT_NO_THROW(verify(id(9), false));
    const std::string intruder = newMember().userId;
    const std::uint64_t seq = bridge.commits.size() + 1;
    std::vector<StatementNode> rekeyed;
    for (const std::uint32_t node : TreeMath::keyedPath(5, bridge.state.numLeaves)) {
        const auto* record = recordOf(bridge.state, node);
        rekeyed.push_back(StatementNode{
            node, record != nullptr ? record->generation + 1 : 0,
            PrivateKey::generateRandom().getPublicKey().toBase58DER(), ""
        });
    }
    forge(intruder, [&](TreeGroupState& state) {
        state.leafAssignment[5] = intruder;
        for (const StatementNode& node : rekeyed) {
            setRecord(state, TreeNodeState{node.nodeIndex, node.generation, NodePublicKey::fromBase58DER(node.publicKey), seq});
        }
    }, {.path = rekeyed, .added = {intruder}, .rosterBump = 1});
    expectRefusal([&] { verify(id(9), false); }, "a statement by a non-member");
}

TEST_F(TreeVerification, FollowsAChainOfHonestCommits) {
    create(40, 0);
    ASSERT_NO_THROW(verify(id(9), false));
    remove(id(35), {id(5)});
    add(std::string(id(1)), 2); // a copy: adding grows `everyone`
    selfUpdate(id(9));
    EXPECT_NO_THROW(verify(id(9), false)) << "four statements past the pin";
    EXPECT_NO_THROW(verify(id(9), true));
}

TEST_F(TreeVerification, SECURITY_RefusesEveryLieInTheLatestStatement) {
    create(40, 0);
    const auto refusedWith = [&](const std::function<void(CommitStatement&)>& lie, bool resign) {
        server::GroupInfo info = bridge.serve(id(9), false);
        CommitStatement statement = TreeCommits::fromWire(info.treeCommit.value());
        lie(statement);
        if (resign) {
            TreeCommits::sign(statement, member(statement.committer).priv);
        }
        const server::GroupTreeCommit wire = TreeCommits::toWire(statement);
        info.treeCommit = wire;
        auto cited = info.treeCommits.value();
        for (server::GroupTreeCommit& entry : cited) {
            if (entry.seq == wire.seq) {
                entry = wire;
            }
        }
        info.treeCommits = cited;
        return refuses([&] { TreeVerifier().verify(info, TreeVerifier::Scope::Path, environment()); });
    };
    EXPECT_FALSE(refusedWith([](CommitStatement&) {}, true)) << "the honest statement re-signed must pass";
    EXPECT_TRUE(refusedWith([](CommitStatement& s) { s.groupId = "other"; }, true));
    EXPECT_TRUE(refusedWith([](CommitStatement& s) { s.treeVersion = 1; }, true));
    EXPECT_TRUE(refusedWith([](CommitStatement& s) { s.keyVersion += 1; }, true));
    EXPECT_TRUE(refusedWith([](CommitStatement& s) { s.groupPubKey = "other"; }, true));
    EXPECT_TRUE(refusedWith([](CommitStatement& s) { s.rosterVersion += 1; }, true));
    EXPECT_TRUE(refusedWith([](CommitStatement& s) { s.rosterHash[0] ^= 1; }, true));
    EXPECT_TRUE(refusedWith([](CommitStatement& s) { s.treeHash[0] ^= 1; }, true));
    EXPECT_TRUE(refusedWith([](CommitStatement& s) { s.committerSeat += 1; }, true));
    EXPECT_TRUE(refusedWith([&](CommitStatement& s) { s.committer = id(1); }, true)) << "not at that seat";
    EXPECT_TRUE(refusedWith([](CommitStatement& s) { s.path[0].generation += 1; }, true)) << "no longer vouches";
    EXPECT_TRUE(refusedWith([](CommitStatement& s) { s.date += 1; }, false)) << "signature no longer valid";
    EXPECT_TRUE(refusedWith([&](CommitStatement& s) {
        TreeCommits::sign(s, PrivateKey::generateRandom());
    }, false)) << "signed by a key that is not the committer's";

    // And a committer the application does not vouch for at that date.
    TreeVerifier fresh;
    TreeVerifier::Environment env = environment();
    env.verifyUsers = [](const std::vector<privmx::endpoint::core::VerificationRequest>& requests) {
        return std::vector<bool>(requests.size(), false);
    };
    EXPECT_THROW(fresh.verify(bridge.serve(id(9), false), TreeVerifier::Scope::Path, env), GroupDataIntegrityException);
}

TEST_F(TreeVerification, SECURITY_AGenesisStatementIsRefusedUnderAnotherGroupsId) {
    // T3-04: a group nobody has committed to since its creation, served as a group this client has never seen. Its
    // only statement is genuine and names its own resourceId, which the bridge serves alongside; the id it is served
    // under does not follow from that resourceId.
    create(40, 0);
    server::GroupInfo info = bridge.serve(id(9), false);
    EXPECT_NO_THROW(TreeVerifier().verify(info, TreeVerifier::Scope::Path, environment()));
    info.id = TreeCommits::groupId("ctx", "another-resource");
    EXPECT_THROW(TreeVerifier().verify(info, TreeVerifier::Scope::Path, environment()), GroupDataIntegrityException);
    info.id = TreeCommits::groupId("another-context", "res");
    EXPECT_THROW(TreeVerifier().verify(info, TreeVerifier::Scope::Path, environment()), GroupDataIntegrityException);
}

TEST_F(TreeVerification, SECURITY_AGroupIsVerifiedOnlyInTheContextItsIdFollowsFrom) {
    // T4-01: past seq 1 the statements name the id alone, so the served context counts only through the id. Served
    // in another context, a UserVerifier would vouch for that context's namesakes of the members.
    create(40, 0);
    remove(id(35), {id(5)});
    server::GroupInfo info = bridge.serve(id(9), false);
    info.contextId = "ctx-2";
    EXPECT_THROW(TreeVerifier().verify(info, TreeVerifier::Scope::Path, environment()), GroupDataIntegrityException);
    verify(id(9), false);
    EXPECT_THROW(
        verifierOf(id(9)).verify(info, TreeVerifier::Scope::Path, environment()), GroupDataIntegrityException
    ) << "nor once the client has verified it in the right one";
    EXPECT_THROW(verifierOf(id(9)).epochOpeners(GROUP_ID, "ctx-2", environment()), GroupDataIntegrityException);
}

TEST_F(TreeVerification, SECURITY_AChainLinkMustExtendTheStatementBeforeIt) {
    // T4-02/T4-17: a member's genuine statement that does not follow the pinned one is a fork, not a continuation.
    create(40, 0);
    remove(id(35), {id(5)});
    verify(id(9), false);
    forge(id(9), [](TreeGroupState&) {});
    CommitStatement statement = TreeCommits::fromWire(bridge.commits.back());
    statement.prevDigest = std::string(32, 'x');
    TreeCommits::sign(statement, member(id(9)).priv);
    bridge.commits.back() = TreeCommits::toWire(statement);
    EXPECT_THROW(verify(id(9), false), GroupDataIntegrityException);
}

TEST_F(TreeVerification, SECURITY_AChainLinkIsNeverDatedBeforeTheOneItExtends) {
    // T4-04: a key its owner has rotated away from is still vouched for at a date before the rotation.
    create(40, 0);
    remove(id(35), {id(5)});
    verify(id(9), false);
    forge(id(9), [](TreeGroupState&) {});
    CommitStatement statement = TreeCommits::fromWire(bridge.commits.back());
    statement.date -= 1;
    TreeCommits::sign(statement, member(id(9)).priv);
    bridge.commits.back() = TreeCommits::toWire(statement);
    EXPECT_THROW(verify(id(9), false), GroupDataIntegrityException);
}

TEST_F(TreeVerification, SECURITY_AStatementDatedAheadOfTheClockIsRefused) {
    // N-1: bounds how far ahead a chain's dates can be pushed; the bridge no longer freezes on it (it takes a
    // commit dated as the statement it extends), so this cap keeps the dates a UserVerifier is asked at near now.
    create(40, 0);
    remove(id(35), {id(5)});
    verify(id(9), false);
    forge(id(9), [](TreeGroupState&) {});
    CommitStatement statement = TreeCommits::fromWire(bridge.commits.back());
    const auto dated = [&](std::uint64_t ahead) {
        statement.date = static_cast<std::uint64_t>(privmx::utils::Utils::getNowTimestamp()) + ahead;
        TreeCommits::sign(statement, member(id(9)).priv);
        bridge.commits.back() = TreeCommits::toWire(statement);
    };
    // Twice the bridge's tolerance, no more: the committer's clock ahead of the bridge's, this one behind it (F4).
    dated(2 * TreeCommits::DATE_TOLERANCE_MS - 60 * 1000);
    EXPECT_NO_THROW(TreeVerifier().verify(bridge.serve(id(9), false), TreeVerifier::Scope::Path, environment()));
    dated(2 * TreeCommits::DATE_TOLERANCE_MS + 60 * 1000);
    EXPECT_THROW(verify(id(9), false), GroupDataIntegrityException);
    EXPECT_THROW(
        TreeVerifier().verify(bridge.serve(id(9), false), TreeVerifier::Scope::Path, environment()),
        GroupDataIntegrityException
    ) << "nor on first contact";
    EXPECT_THROW(TreeVerifier().verifyListed(bridge.serve(id(9), false), environment()), GroupDataIntegrityException);
}

TEST_F(TreeVerification, SECURITY_APinMovedOntoAnotherBranchMeanwhileIsNotOverwritten) {
    // N-4: a verification checks the chain from the pin it started at; a concurrent one moving the pin meanwhile, to a
    // statement this chain does not pass through, is a fork the store must not overwrite unseen.
    create(40, 0);
    verify(id(9), false); // seq 1
    remove(id(35), {id(5)});
    selfUpdate(id(1)); // seq 3 extends the honest seq 2
    CommitStatement other = TreeCommits::fromWire(bridge.commits[1]);
    other.date += 1; // another seq 2
    TreeCommits::sign(other, member(other.committer).priv);
    TreeVerifier& verifier = verifierOf(id(9));
    TreeVerifier::Environment env = environment();
    bool moved = false;
    env.commitsBetween = [&, inner = env.commitsBetween](std::uint64_t fromSeq, std::uint64_t toSeq) {
        if (!moved) {
            moved = true;
            verifier.pinCommitted(GROUP_ID, "ctx", other, bridge.users(), managersOf(), bridge.rules());
        }
        return inner(fromSeq, toSeq);
    };
    EXPECT_THROW(verifier.verify(bridge.serve(id(9), false), TreeVerifier::Scope::Path, env), EndpointGroupException);
    EXPECT_EQ(verifier.pinnedSeq(GROUP_ID), 2u);
}

TEST_F(TreeVerification, SECURITY_EpochOpenersRefuseAStatementByANonMemberBelowThePin) {
    // T4-02: mallory seats herself; a pin taken past her statement without walking the chain (first contact, an own
    // commit) must not make her the opener of anything.
    create(40, 0);
    remove(id(35), {id(5)});
    const std::string mallory = newMember().userId;
    forge(mallory, [&](TreeGroupState& state) { state.leafAssignment[5] = mallory; }, {.added = {mallory}, .rosterBump = 1});
    TreeVerifier own;
    own.pinCommitted(GROUP_ID, "ctx", TreeCommits::fromWire(bridge.commits.back()), bridge.users(), managersOf(), bridge.rules());
    EXPECT_THROW(own.epochOpeners(GROUP_ID, "ctx", environment()), GroupDataIntegrityException);
}

TEST_F(TreeVerification, SECURITY_AnotherStatementAtThePinnedSeqIsAFork) {
    // T3-22: the same tree re-signed at the pinned seq (another date) is another statement: a fork, not the pin.
    create(40, 0);
    remove(id(35), {id(5)});
    verify(id(9), false);
    CommitStatement resigned = TreeCommits::fromWire(bridge.commits.back());
    resigned.date += 1;
    TreeCommits::sign(resigned, member(resigned.committer).priv);
    bridge.commits.back() = TreeCommits::toWire(resigned);
    EXPECT_NO_THROW(TreeVerifier().verify(bridge.serve(id(9), false), TreeVerifier::Scope::Path, environment()));
    EXPECT_THROW(verify(id(9), false), GroupHistoryForkException);
}

TEST_F(TreeVerification, SECURITY_AListedStatementAtThePinnedSeqOtherThanThePinnedOneIsAFork) {
    // T4-18: a listing continues the pin at its own seq only as the pinned statement itself, never a re-signed one.
    create(40, 0);
    remove(id(35), {id(5)});
    verify(id(9), false);
    server::GroupInfo listed = bridge.serve(id(9), false);
    CommitStatement resigned = TreeCommits::fromWire(listed.treeCommit.value());
    resigned.date += 1;
    TreeCommits::sign(resigned, member(resigned.committer).priv);
    listed.treeCommit = TreeCommits::toWire(resigned);
    EXPECT_THROW(verifierOf(id(9)).verifyListed(listed, environment()), GroupHistoryForkException);
}

TEST_F(TreeVerification, SECURITY_EpochOpenersComeOnlyOffTheChainThatEndsAtThePin) {
    // T3-09: past grant keys and the authors of rungs are read off the statements, so only off the pinned chain.
    create(40, 0);
    remove(id(35), {id(5)});
    selfUpdate(id(9));
    TreeVerifier own;
    EXPECT_THROW(own.epochOpeners(GROUP_ID, "ctx", environment()), GroupDataIntegrityException) << "nothing pinned";
    own.verify(bridge.serve(id(9), false), TreeVerifier::Scope::Path, environment());
    const auto openers = own.epochOpeners(GROUP_ID, "ctx", environment());
    ASSERT_EQ(openers.size(), 2u);
    EXPECT_EQ(openers.at(1).seq, 1u);
    EXPECT_EQ(openers.at(2).seq, 2u);
    EXPECT_EQ(openers.at(2).committer, id(35));
    EXPECT_EQ(openers.at(2).groupPubKey, bridge.state.grantPublicKey.toBase58DER());

    const auto refusedWith = [&](const std::function<void(std::vector<server::GroupTreeCommit>&)>& lie) {
        TreeVerifier::Environment env = environment();
        env.commitsBetween = [&](std::uint64_t fromSeq, std::uint64_t toSeq) {
            auto answer = bridge.commitsBetween(fromSeq, toSeq);
            lie(answer.commits);
            return answer;
        };
        TreeVerifier fresh; // `own` answers from what it already checked
        fresh.verify(bridge.serve(id(9), false), TreeVerifier::Scope::Path, environment());
        return refuses([&] { fresh.epochOpeners(GROUP_ID, "ctx", env); });
    };
    EXPECT_FALSE(refusedWith([](std::vector<server::GroupTreeCommit>&) {}));
    EXPECT_TRUE(refusedWith([](std::vector<server::GroupTreeCommit>& c) { c.pop_back(); })) << "short of the pin";
    EXPECT_TRUE(refusedWith([](std::vector<server::GroupTreeCommit>& c) { c.erase(c.begin()); })) << "a gap";
    const std::string planted = PrivateKey::generateRandom().getPublicKey().toBase58DER();
    EXPECT_TRUE(refusedWith([&](std::vector<server::GroupTreeCommit>& c) {
        CommitStatement statement = TreeCommits::fromWire(c[1]);
        statement.groupPubKey = planted;
        TreeCommits::sign(statement, PrivateKey::generateRandom());
        c[1] = TreeCommits::toWire(statement);
    })) << "the bridge's own key for epoch 2, signed by nobody the UserVerifier vouches for";
    EXPECT_TRUE(refusedWith([&](std::vector<server::GroupTreeCommit>& c) {
        CommitStatement statement = TreeCommits::fromWire(c[1]);
        statement.groupPubKey = planted;
        TreeCommits::sign(statement, member(statement.committer).priv);
        c[1] = TreeCommits::toWire(statement);
    })) << "two grant keys for epoch 2";
    EXPECT_TRUE(refusedWith([&](std::vector<server::GroupTreeCommit>& c) {
        CommitStatement statement = TreeCommits::fromWire(c[0]);
        statement.groupPubKey = planted;
        TreeCommits::sign(statement, member(statement.committer).priv);
        c[0] = TreeCommits::toWire(statement);
    })) << "a genuine statement swapped in below the pin";
}

TEST_F(TreeVerification, EpochOpenersFetchOnlyTheStatementsSinceTheLastAnswer) {
    // M3: every old-epoch key and every removal reads the openers; a refetch from seq 1 grew with every commit.
    create(40, 0);
    remove(id(35), {id(5)});
    std::vector<std::pair<std::uint64_t, std::uint64_t>> fetched;
    TreeVerifier::Environment env = environment();
    env.commitsBetween = [&](std::uint64_t fromSeq, std::uint64_t toSeq) {
        fetched.emplace_back(fromSeq, toSeq);
        return bridge.commitsBetween(fromSeq, toSeq);
    };
    TreeVerifier own;
    own.verify(bridge.serve(id(9), false), TreeVerifier::Scope::Path, environment());
    own.epochOpeners(GROUP_ID, "ctx", env);
    own.epochOpeners(GROUP_ID, "ctx", env);
    remove(id(9), {id(6)});
    own.verify(bridge.serve(id(9), false), TreeVerifier::Scope::Path, environment());
    const auto openers = own.epochOpeners(GROUP_ID, "ctx", env);
    EXPECT_EQ(fetched, (std::vector<std::pair<std::uint64_t, std::uint64_t>>{{0, 2}, {2, 3}}));
    ASSERT_EQ(openers.size(), 3u);
    EXPECT_EQ(openers.at(3).committer, id(9));
}

TEST_F(TreeVerification, AsksTheUserVerifierOncePerStatementForTheKeyAndDateItWasSignedAt) {
    create(40, 0);
    std::vector<privmx::endpoint::core::VerificationRequest> asked;
    TreeVerifier::Environment env = environment();
    env.verifyUsers = [&](const std::vector<privmx::endpoint::core::VerificationRequest>& requests) {
        for (const auto& request : requests) {
            asked.push_back(request);
        }
        return std::vector<bool>(requests.size(), true);
    };
    TreeVerifier own;
    own.verify(bridge.serve(id(9), false), TreeVerifier::Scope::Path, env);
    ASSERT_EQ(asked.size(), 1u) << "one statement at its date (a first contact asks nothing for now)";
    EXPECT_EQ(asked[0].senderId, id(0));
    EXPECT_EQ(asked[0].senderPubKey, member(id(0)).pub);
    EXPECT_EQ(asked[0].date, 1760000000000);
    remove(id(35), {id(5)});
    asked.clear();
    own.verify(bridge.serve(id(9), false), TreeVerifier::Scope::Path, env);
    ASSERT_EQ(asked.size(), 2u) << "one statement moving the pin: at its date, and now";
    EXPECT_EQ(asked[0].senderId, id(35));
    EXPECT_EQ(asked[0].date, 1760000000000);
    EXPECT_EQ(asked[1].senderPubKey, member(id(35)).pub);
    EXPECT_GE(asked[1].date, privmx::utils::Utils::getNowTimestamp() - 60 * 1000);

    env.verifyUsers = [](const std::vector<privmx::endpoint::core::VerificationRequest>&) {
        return std::vector<bool>{};
    };
    EXPECT_THROW(
        TreeVerifier().verify(bridge.serve(id(9), false), TreeVerifier::Scope::Path, env), GroupDataIntegrityException
    ) << "an answer that does not cover every request";
}

TEST_F(TreeVerification, SECURITY_AKeyRevokedNowCannotMoveThePin) {
    // N-3: the committer signs any date it likes, and the UserVerifier truthfully vouches for its key at a date before
    // the revocation; only the key's standing now keeps it from extending the chain.
    create(40, 0);
    verify(id(9), false);
    const std::int64_t revokedAt = privmx::utils::Utils::getNowTimestamp() - 1000;
    TreeVerifier::Environment env = environment();
    using privmx::endpoint::core::VerificationRequest;
    env.verifyUsers = [&, vouch = env.verifyUsers](const std::vector<VerificationRequest>& requests) {
        std::vector<bool> verified = vouch(requests);
        for (std::size_t i = 0; i < requests.size(); ++i) {
            if (requests[i].senderId == id(9) && requests[i].date >= revokedAt) {
                verified[i] = false;
            }
        }
        return verified;
    };
    EXPECT_NO_THROW(verifierOf(id(9)).verify(bridge.serve(id(9), false), TreeVerifier::Scope::Path, env))
        << "an already pinned statement needs no answer for now";
    forge(id(9), [](TreeGroupState&) {}); // dated 1760000000000, before the revocation
    const server::GroupInfo served = bridge.serve(id(9), false);
    EXPECT_THROW(verifierOf(id(9)).verify(served, TreeVerifier::Scope::Path, env), GroupDataIntegrityException);
    // F1: a first contact takes the latest genuine statement on trust, or an honest committer who rotated their key
    // since would lock every fresh session out, and with it every commit that could move the group past it.
    EXPECT_NO_THROW(TreeVerifier().verify(served, TreeVerifier::Scope::Path, env)) << "a first contact";
    EXPECT_NO_THROW(TreeVerifier().verifyListed(bridge.serve(id(9), false), env)) << "a first contact";
    EXPECT_NO_THROW(verify(id(9), false)) << "the same statement while the key is still the committer's";
}

TEST_F(TreeVerification, SECURITY_AListedGroupIsTakenOnlyAsItsLatestStatementDescribesIt) {
    create(40, 0);
    remove(id(35), {id(5)}); // seq 2, so the statement names the group id rather than the resourceId
    const server::GroupInfo honest = bridge.serve(id(9), false);
    const auto refused = [&](const std::function<void(server::GroupInfo&)>& lie) {
        server::GroupInfo summary = honest;
        lie(summary);
        return refuses([&] { TreeVerifier().verifyListed(summary, environment()); });
    };
    EXPECT_FALSE(refused([](server::GroupInfo&) {}));
    EXPECT_TRUE(refused([](server::GroupInfo& s) { s.treeCommit.reset(); }));
    EXPECT_TRUE(refused([](server::GroupInfo& s) {
        s.groupPubKey = PrivateKey::generateRandom().getPublicKey().toBase58DER();
    })) << "a grant key the statement does not sign";
    EXPECT_TRUE(refused([](server::GroupInfo& s) { s.keyVersion += 1; }));
    EXPECT_TRUE(refused([](server::GroupInfo& s) { s.users.push_back("mallory"); })) << "another roster";
    EXPECT_TRUE(refused([](server::GroupInfo& s) { s.id = "other"; })) << "another group's statement";
    EXPECT_TRUE(refused([](server::GroupInfo& s) { s.contextId = "ctx-2"; })) << "a context not in its id";
    EXPECT_TRUE(refused([](server::GroupInfo& s) { s.resourceId.reset(); }));
    EXPECT_TRUE(refused([&](server::GroupInfo& s) {
        CommitStatement statement = TreeCommits::fromWire(s.treeCommit.value());
        TreeCommits::sign(statement, PrivateKey::generateRandom());
        s.treeCommit = TreeCommits::toWire(statement);
    })) << "signed by a key the UserVerifier does not vouch for";
    EXPECT_TRUE(refused([&](server::GroupInfo& s) {
        s.users.erase(std::remove(s.users.begin(), s.users.end(), id(35)), s.users.end());
        CommitStatement statement = TreeCommits::fromWire(s.treeCommit.value());
        statement.rosterHash = TreeCommits::rosterHash(s.users, s.managers);
        TreeCommits::sign(statement, member(id(35)).priv);
        s.treeCommit = TreeCommits::toWire(statement);
    })) << "a committer off the roster it signs";
}

TEST_F(TreeVerification, SECURITY_AListedGroupContinuesThePinOfAClientThatVerifiedIt) {
    create(40, 0);
    remove(id(35), {id(5)}); // seq 2: id(5) is out, but its key stays vouched
    verify(id(9), false);
    const server::GroupInfo honest = bridge.serve(id(9), false);
    EXPECT_NO_THROW(verifierOf(id(9)).verifyListed(honest, environment()));
    // The removed member signs itself back in, with its own grant key, at the pinned seq and past it.
    for (const std::int64_t bump : {0, 1}) {
        server::GroupInfo summary = honest;
        summary.users.push_back(id(5));
        summary.groupPubKey = member(id(5)).pub;
        CommitStatement statement = TreeCommits::fromWire(summary.treeCommit.value());
        statement.seq += bump;
        statement.committer = id(5);
        statement.groupPubKey = summary.groupPubKey;
        statement.rosterHash = TreeCommits::rosterHash(summary.users, summary.managers);
        TreeCommits::sign(statement, member(id(5)).priv);
        summary.treeCommit = TreeCommits::toWire(statement);
        EXPECT_NO_THROW(TreeVerifier().verifyListed(summary, environment())) << "the trust-on-first-use case";
        EXPECT_THROW(verifierOf(id(9)).verifyListed(summary, environment()), EndpointGroupException) << bump;
    }
}

TEST_F(TreeVerification, SECURITY_AnOwnCommitIsPinnedSoTheStateItReplacedIsRefused) {
    // T3-03: the remover reads, removes, and is then served the state from before its own removal — every statement
    // in it genuine. Without the commit pinned that state equals the pin and passes, leaver and all.
    create(40, 0);
    TreeVerifier own;
    own.verify(bridge.serve(id(1), false), TreeVerifier::Scope::Path, environment());
    const server::GroupInfo beforeRemoval = bridge.serve(id(1), false);
    remove(id(1), {id(5)});
    own.pinCommitted(GROUP_ID, "ctx", TreeCommits::fromWire(bridge.commits.back()), bridge.users(), managersOf(), bridge.rules());
    EXPECT_EQ(own.pinnedKeyVersion(GROUP_ID), bridge.state.epoch);
    EXPECT_THROW(own.verify(beforeRemoval, TreeVerifier::Scope::Path, environment()), GroupHistoryForkException);
    EXPECT_NO_THROW(own.verify(bridge.serve(id(1), false), TreeVerifier::Scope::Path, environment()))
        << "the committed state itself reads back";
    EXPECT_NO_THROW(own.verify(bridge.serve(id(1), true), TreeVerifier::Scope::Plan, environment()));
}

TEST_F(TreeVerification, SECURITY_AListedGroupIsPinnedOnFirstUse) {
    // T3-06: a writer outside the group is on trust on first use once, not on every listing: after seeing the
    // removal it takes the listing from before it only as "behind", and a later one only as a chain from its pin.
    create(40, 0);
    const server::GroupInfo beforeRemoval = bridge.serve(id(9), false);
    remove(id(35), {id(5)});
    TreeVerifier writer;
    writer.verifyListed(bridge.serve(id(9), false), environment());
    EXPECT_EQ(writer.pinnedSeq(GROUP_ID), 2u);
    EXPECT_EQ(writer.pinnedKeyVersion(GROUP_ID), bridge.state.epoch);
    EXPECT_NO_THROW(writer.verifyListed(beforeRemoval, environment()));
    EXPECT_EQ(writer.pinnedSeq(GROUP_ID), 2u) << "the older listing does not move the pin back";
    selfUpdate(id(9));
    EXPECT_NO_THROW(writer.verifyListed(bridge.serve(id(9), false), environment()));
    EXPECT_EQ(writer.pinnedSeq(GROUP_ID), 3u);
}

TEST_F(TreeVerification, SECURITY_AListingsGrantKeyIsTakenOnlyAtThePinnedState) {
    // A listing carries no roster and no statement, so its `groupPubKey` is vouched for by nothing: it is taken only
    // as exactly the epoch and key of the state a writer outside the group verified (`verifyListed`) and pinned.
    create(40, 0);
    TreeVerifier writer;
    const server::GroupInfo first = bridge.serve(id(9), false);
    EXPECT_FALSE(writer.pinnedAt(GROUP_ID, "ctx", first.keyVersion, first.groupPubKey)) << "nothing verified yet";
    writer.verifyListed(first, environment());
    EXPECT_TRUE(writer.pinnedAt(GROUP_ID, "ctx", first.keyVersion, first.groupPubKey));
    EXPECT_FALSE(writer.pinnedAt(GROUP_ID, "ctx-2", first.keyVersion, first.groupPubKey)) << "listed in another context";
    EXPECT_FALSE(writer.pinnedAt(GROUP_ID, "ctx", first.keyVersion + 1, first.groupPubKey));
    EXPECT_FALSE(writer.pinnedAt(GROUP_ID, "ctx", first.keyVersion, member(id(5)).pub)) << "a key the pin does not name";
    EXPECT_FALSE(writer.pinnedAt("other", "ctx", first.keyVersion, first.groupPubKey));
    remove(id(35), {id(5)});
    const server::GroupInfo second = bridge.serve(id(9), false);
    EXPECT_FALSE(writer.pinnedAt(GROUP_ID, "ctx", second.keyVersion, second.groupPubKey)) << "a new epoch is read first";
    writer.verifyListed(second, environment());
    EXPECT_TRUE(writer.pinnedAt(GROUP_ID, "ctx", second.keyVersion, second.groupPubKey));
    EXPECT_FALSE(writer.pinnedAt(GROUP_ID, "ctx", first.keyVersion, first.groupPubKey))
        << "nor the epoch before the removal";
}

TEST_F(TreeVerification, SECURITY_ACallersGrantKeyBehindThePinIsNotTaken) {
    // T4-09: a `GroupGrantWithKey` the application kept from before a removal names the epoch the removed member
    // still holds. Unpinned it is the caller's word; pinned, only the pinned epoch and key are.
    create(40, 0);
    TreeVerifier writer;
    const server::GroupInfo first = bridge.serve(id(9), false);
    EXPECT_TRUE(writer.agreesWithPin(GROUP_ID, "ctx", first.keyVersion, first.groupPubKey)) << "no pin, no verdict";
    remove(id(35), {id(5)});
    const server::GroupInfo second = bridge.serve(id(9), false);
    writer.verifyListed(second, environment());
    EXPECT_FALSE(writer.agreesWithPin(GROUP_ID, "ctx", first.keyVersion, first.groupPubKey));
    EXPECT_TRUE(writer.agreesWithPin(GROUP_ID, "ctx", second.keyVersion, second.groupPubKey));
}

TEST_F(TreeVerification, AListingIsPutToTheUserVerifierInOneCall) {
    // M4: `fetchGroupEpochs` verifies every group it reads; one UserVerifier call each made 100 grants cost 100 calls.
    create(40, 0);
    const server::GroupInfo first = bridge.serve(id(9), false);
    remove(id(35), {id(5)});
    const server::GroupInfo second = bridge.serve(id(9), false);
    server::GroupInfo forged = second;
    CommitStatement statement = TreeCommits::fromWire(forged.treeCommit.value());
    TreeCommits::sign(statement, PrivateKey::generateRandom()); // a key the UserVerifier vouches for nobody with
    forged.treeCommit = TreeCommits::toWire(statement);

    std::vector<std::size_t> calls;
    TreeVerifier::Environment env = environment();
    const auto vouch = env.verifyUsers;
    env.verifyUsers = [&](const std::vector<privmx::endpoint::core::VerificationRequest>& requests) {
        calls.push_back(requests.size());
        return vouch(requests);
    };
    TreeVerifier writer;
    writer.verifyListed(first, environment());
    writer.preverifyListed({first, forged, second}, env);
    EXPECT_EQ(calls, (std::vector<std::size_t>{4})) << "one call for the whole listing: two dates, two keys now";
    EXPECT_NO_THROW(writer.verifyListed(second, env));
    EXPECT_EQ(calls.size(), 1u) << "verifyListed found its statement checked";
    EXPECT_THROW(writer.verifyListed(forged, env), GroupDataIntegrityException) << "a failure stays verifyListed's";
}

TEST_F(TreeVerification, SECURITY_RefusesARecordOffThePathView) {
    // T3-14: a blank record off the served path is covered by no hash. Taken, its generation would reach the pins,
    // and the next plan read of the honest tree would look like a rollback for as long as the process lives.
    create(64, 0); // node 95 is keyed and off seat 9's path
    const std::uint32_t seat = seatOf(bridge.state, id(9)).value();
    const std::vector<std::uint32_t> onPath = TreeMath::keyedPath(seat, bridge.state.numLeaves);
    std::optional<std::uint32_t> offPath;
    for (const std::uint32_t node : TreeMath::keyedNodes(bridge.state.numLeaves)) {
        if (std::find(onPath.begin(), onPath.end(), node) == onPath.end()) {
            offPath = node;
        }
    }
    ASSERT_TRUE(offPath.has_value());
    server::GroupInfo info = bridge.serve(id(9), false);
    auto nodes = info.treeNodes.value();
    nodes.push_back(server::GroupTreeNode{.nodeIndex = offPath.value(), .generation = 0xFFFFFFFF});
    info.treeNodes = nodes;
    TreeVerifier own;
    EXPECT_THROW(own.verify(info, TreeVerifier::Scope::Path, environment()), GroupDataIntegrityException);
    EXPECT_NO_THROW(own.verify(bridge.serve(id(9), true), TreeVerifier::Scope::Plan, environment()));
}

TEST_F(TreeVerification, SECURITY_EpochOpenersReplayTheRosterFromGenesis) {
    // I-1: below a pin no read walked (first contact, an own commit), a member's statement whose roster hash its
    // deltas do not explain passed a replay back from the pin, which cannot tell a removed user from a manager.
    create(40, 0);
    forge(id(9), [](TreeGroupState&) {});
    CommitStatement lying = TreeCommits::fromWire(bridge.commits.back());
    std::vector<std::string> lyingManagers = managersOf();
    lyingManagers.push_back("mallory"); // a manager no delta seats
    lying.rosterHash = TreeCommits::rosterHash(bridge.users(), lyingManagers);
    TreeCommits::sign(lying, member(id(9)).priv);
    bridge.commits.back() = TreeCommits::toWire(lying);
    TreeVerifier own;
    own.pinCommitted(GROUP_ID, "ctx", lying, bridge.users(), lyingManagers, bridge.rules());
    EXPECT_THROW(own.epochOpeners(GROUP_ID, "ctx", environment()), GroupDataIntegrityException);

    // And the genesis roster, served unsigned beside the chain, must be the one seq 1's hash binds, even where the
    // deltas after it end at the pinned roster all the same.
    reset();
    create(40, 0);
    remove(id(35), {id(5)});
    bridge.genesis.erase(std::find(bridge.genesis.begin(), bridge.genesis.end(), id(5)));
    TreeVerifier fresh;
    fresh.pinCommitted(GROUP_ID, "ctx", TreeCommits::fromWire(bridge.commits.back()), bridge.users(), managersOf(), bridge.rules());
    EXPECT_THROW(fresh.epochOpeners(GROUP_ID, "ctx", environment()), GroupDataIntegrityException);
}

TEST_F(TreeVerification, SECURITY_AnOwnCommitIsPinnedOnlyWithTheRosterItSigned) {
    // An own commit pinned beside a roster the bridge served: the next catch-up replays from it, and a non-member the
    // bridge put there would pass as a committer.
    create(4, 0);
    const CommitStatement latest = TreeCommits::fromWire(bridge.commits.back());
    std::vector<std::string> users = bridge.users();
    users.push_back("mallory");
    TreeVerifier own;
    EXPECT_THROW(own.pinCommitted(GROUP_ID, "ctx", latest, users, managersOf(), bridge.rules()), GroupDataIntegrityException);
    EXPECT_EQ(own.pinnedSeq(GROUP_ID), 0u);
    EXPECT_NO_THROW(own.pinCommitted(GROUP_ID, "ctx", latest, bridge.users(), managersOf(), bridge.rules()));
}

TEST_F(TreeVerification, SECURITY_NoSecondStatementIsSignedAtASeqRefusedAsALostRace) {
    // T4-17: "a concurrent commit took that seq" is the bridge's word, and it may have applied the statement all the
    // same. A second statement at that seq would be a fork of the bridge's choosing.
    TreeVerifier own;
    own.refusedAsLostRace(GROUP_ID, 5);
    EXPECT_THROW(own.assertMaySignAt(GROUP_ID, 5), GroupDataIntegrityException) << "the read did not reach seq 5";
    EXPECT_THROW(own.assertMaySignAt(GROUP_ID, 4), GroupDataIntegrityException);
    EXPECT_NO_THROW(own.assertMaySignAt(GROUP_ID, 6)) << "a read past it: the seq was taken";
    EXPECT_NO_THROW(own.assertMaySignAt("other", 5));
    EXPECT_EQ(own.pinnedSeq(GROUP_ID), 0u) << "remembering it pins nothing";
}

TEST_F(TreeVerification, SECURITY_AChainIsCheckedPageByPageBeforeTheNextPageIsFetched) {
    // T4-15: a page nobody on the roster signed is refused before the next one is fetched, so a client never holds
    // more than a page of a chain however long the bridge makes it.
    create(40, 0);
    remove(id(35), {id(5)});
    selfUpdate(id(9));
    std::size_t pages = 0;
    TreeVerifier::Environment env = environment();
    env.commitsBetween = [&](std::uint64_t fromSeq, std::uint64_t) {
        ++pages;
        return bridge.commitsBetween(fromSeq, fromSeq + 1); // one statement a page
    };
    const auto openers = [&] {
        pages = 0;
        TreeVerifier own;
        own.pinCommitted(GROUP_ID, "ctx", TreeCommits::fromWire(bridge.commits.back()), bridge.users(), managersOf(), bridge.rules());
        return own.epochOpeners(GROUP_ID, "ctx", env);
    };
    EXPECT_NO_THROW(openers());
    EXPECT_EQ(pages, 3u);
    CommitStatement genesis = TreeCommits::fromWire(bridge.commits.front());
    TreeCommits::sign(genesis, PrivateKey::generateRandom()); // a key the UserVerifier does not vouch for
    bridge.commits.front() = TreeCommits::toWire(genesis);
    EXPECT_THROW(openers(), GroupDataIntegrityException);
    EXPECT_EQ(pages, 1u);
}

TEST_F(TreeVerification, SECURITY_ANewEpochUnderAnEarlierEpochsGrantKeyIsRefused) {
    // T4-24: a member republishing the grant key of an epoch before a removal reopens the new epoch to the leaver.
    // `uncompressed`: the key signed in its other base58 spelling, a different string for the same point.
    const auto opensUnder = [&](const std::function<PublicKey()>& grantKey, bool uncompressed = false) {
        reset();
        create(40, 0);
        remove(id(35), {id(5)});
        const PublicKey key = grantKey();
        // A rotation as its row has it (03): the epoch and roster version one on, no path, the tree unchanged.
        forge(id(9), [&](TreeGroupState& state) {
            state.epoch += 1;
            state.grantPublicKey = key;
        }, {.rosterBump = 1, .op = CommitOp::Rotate});
        if (uncompressed) {
            CommitStatement spelled = TreeCommits::fromWire(bridge.commits.back());
            spelled.groupPubKey = privmx::utils::Base58::encodeWithChecksum(key.getEcc().getPublicKey(false));
            EXPECT_NE(spelled.groupPubKey, key.toBase58DER());
            TreeCommits::sign(spelled, member(id(9)).priv);
            bridge.commits.back() = TreeCommits::toWire(spelled);
        }
        TreeVerifier own;
        own.pinCommitted(GROUP_ID, "ctx", TreeCommits::fromWire(bridge.commits.back()), bridge.users(), managersOf(), bridge.rules());
        try {
            own.epochOpeners(GROUP_ID, "ctx", environment());
            return std::string();
        } catch (const GroupDataIntegrityException& e) {
            return std::string(e.getDescription()) + "|"; // never empty, so a refusal tells from a pass
        }
    };
    EXPECT_EQ(opensUnder([] { return PrivateKey::generateRandom().getPublicKey(); }), "")
        << "a rotation to a fresh key is a valid row";
    EXPECT_EQ(opensUnder([&] {
        return PublicKey::fromBase58DER(TreeCommits::fromWire(bridge.commits.front()).groupPubKey);
    }), "a new epoch's grant key is an earlier epoch's|") << "epoch 1's key at epoch 3, refused by the grant-key rule";
    EXPECT_EQ(opensUnder([&] {
        return PublicKey::fromBase58DER(TreeCommits::fromWire(bridge.commits.front()).groupPubKey);
    }, true), "a new epoch's grant key is an earlier epoch's|") << "and in its uncompressed spelling too";
}

// signed policy (T4-10)

namespace {

std::optional<Poco::Dynamic::Var> wirePolicy(const Poco::Dynamic::Var& policy) {
    return std::optional<Poco::Dynamic::Var>(std::in_place, policy);
}

Poco::Dynamic::Var ownerRules() {
    return policyOf({{"update", "owner"}, {"updatePolicy", "owner"}});
}

} // namespace

TEST_F(TreeVerification, SECURITY_ARemovalByAMemberThePolicyDoesNotAllowIsRefused) {
    // AC 1: a member without `update` signs a removal, the bridge stores it; every pinned client refuses it.
    createPolicy = ownerRules();
    create(40, 0);
    verify(id(9), false);
    ASSERT_EQ(bridge.managers.count(id(0)), 1u);
    std::vector<std::string> before = bridge.users();
    remove(id(35), {id(5)});
    const CommitStatement removal = TreeCommits::fromWire(bridge.commits.back());
    EXPECT_FALSE(TreeCommits::deltasProblem(removal, {before.begin(), before.end()}, bridge.managers).has_value())
        << "a removal its row allows: only the role is wrong";
    EXPECT_EQ(removal.policyHash, bridge.rules().hash) << "and it signs the group's policy";
    EXPECT_THROW(verify(id(9), false), GroupUnauthorizedSignerException);
    EXPECT_EQ(replay(), "unauthorized");

    // The same chain with the owner's earlier policy statement letting every member update: it passes.
    reset();
    createPolicy = ownerRules();
    create(40, 0);
    verify(id(9), false);
    forge(id(0), [](TreeGroupState&) {}, {.op = CommitOp::Policy, .policy = wirePolicy(policyOf({{"update", "user"}, {"updatePolicy", "owner"}}))});
    remove(id(35), {id(5)});
    EXPECT_NO_THROW(verify(id(9), false));
    EXPECT_EQ(replay(), "");
}

TEST_F(TreeVerification, SECURITY_APolicyChangeByAMemberWithoutUpdatePolicyIsRefused) {
    // Granting itself the role does not help: a policy statement is judged under the rules it replaces.
    createPolicy = ownerRules();
    create(40, 0);
    verify(id(9), false);
    forge(id(35), [](TreeGroupState&) {}, {.op = CommitOp::Policy, .policy = wirePolicy(policyOf({{"update", "user"}, {"updatePolicy", "user"}}))});
    EXPECT_THROW(verify(id(9), false), GroupUnauthorizedSignerException);
    EXPECT_EQ(replay(), "unauthorized");
}

TEST_F(TreeVerification, SECURITY_ARuleWithAnEmptyAlternativeAdmitsNobody) {
    // R-POL-1: a malicious bridge stores rotateKeys ",manager", signed by a manager it colludes with; evaluated
    // fail-open, its empty alternative would admit any member. Hashed by hand: `rules` refuses to build it.
    createPolicy = Poco::Dynamic::Var();
    create(40, 0);
    verify(id(9), false);
    ASSERT_EQ(bridge.managers.count(id(35)), 0u);
    std::string preimage = TreeCommits::tag("pmx-group-policy");
    for (const std::string value : {id(0), std::string("manager"), std::string(",manager"), std::string("manager"), std::string("yes")}) {
        privmx::endpoint::core::bigendian::putLp(preimage, value);
    }
    const std::string openHash = privmx::crypto::Crypto::sha256(preimage);
    forge(id(0), [](TreeGroupState&) {}, {.op = CommitOp::Policy, .policyHash = openHash, .policy = wirePolicy(policyOf({{"rotateKeys", ",manager"}}))});
    const PublicKey grant = PrivateKey::generateRandom().getPublicKey();
    forge(id(35), [&](TreeGroupState& state) {
        state.epoch += 1;
        state.grantPublicKey = grant;
    }, {.rosterBump = 1, .op = CommitOp::Rotate, .policyHash = openHash});
    EXPECT_THROW(verify(id(9), false), GroupDataIntegrityException) << "a pinned member";
    EXPECT_THROW(verify(id(20), false), GroupDataIntegrityException) << "a first contact";
}

TEST_F(TreeVerification, SECURITY_ARemovalRelabelledAsSelfUpdateIsRefused) {
    // A selfUpdate needs no role, so it may move nothing but the tree. A plain user's honest-looking removal, signed
    // as a selfUpdate under the default (manager-only) policy.
    createPolicy = Poco::Dynamic::Var();
    create(40, 0);
    verify(id(9), false);
    remove(id(35), {id(5)});
    CommitStatement relabelled = TreeCommits::fromWire(bridge.commits.back());
    relabelled.op = CommitOp::SelfUpdate;
    TreeCommits::sign(relabelled, member(id(35)).priv);
    bridge.commits.back() = TreeCommits::toWire(relabelled);
    EXPECT_EQ(replay(), "a selfUpdate statement moves no member");
    EXPECT_THROW(verify(id(9), false), GroupDataIntegrityException);
}

TEST_F(TreeVerification, SECURITY_AnEpochOpenedUnderSelfUpdateIsRefused) {
    createPolicy = Poco::Dynamic::Var();
    create(40, 0);
    verify(id(9), false);
    const PublicKey grant = PrivateKey::generateRandom().getPublicKey();
    forge(id(35), [&](TreeGroupState& state) {
        state.epoch += 1;
        state.grantPublicKey = grant;
    }, {.op = CommitOp::SelfUpdate});
    EXPECT_EQ(replay(), "counters the op does not move that way");
    EXPECT_THROW(verify(id(9), false), GroupDataIntegrityException);
}

TEST_F(TreeVerification, SECURITY_AnAdditionSmuggledIntoAPolicyStatementIsRefused) {
    // id(35) may change the policy but not the roster; it names mallory in a policy statement.
    createPolicy = policyOf({{"update", "manager"}, {"updatePolicy", "user"}});
    create(40, 0);
    const std::string mallory = newMember().userId;
    forge(id(35), [](TreeGroupState&) {},
          {.added = {mallory}, .rosterBump = 1, .op = CommitOp::Policy, .policy = wirePolicy(policyOf({{"update", "manager"}, {"updatePolicy", "user"}}))});
    EXPECT_EQ(replay(), "a policy statement moves no member");
}

TEST_F(TreeVerification, SECURITY_TheOwnerRemovedInsideAnAddStatementIsRefused) {
    // The owner guard is reachable only through the remove row.
    createPolicy = policyOf({{"update", "user"}, {"ownerCanBeRemovedFromManagers", "no"}});
    create(40, 0);
    const std::string newcomer = newMember().userId;
    forge(id(35), [](TreeGroupState&) {}, {.added = {newcomer}, .removed = {id(0)}, .rosterBump = 1, .op = CommitOp::Add});
    EXPECT_EQ(replay(), "an addition adds members and removes none");
}

TEST_F(TreeVerification, SECURITY_AnAdditionThatPromotesAnExistingMemberIsRefused) {
    // `update` lets a user add, but not re-add itself as a manager to get the manager-only rules.
    createPolicy = policyOf({{"update", "user"}, {"updatePolicy", "manager"}});
    create(40, 0);
    forge(id(35), [](TreeGroupState&) {}, {.addedManagers = {id(35)}, .rosterBump = 1});
    EXPECT_EQ(TreeCommits::fromWire(bridge.commits.back()).op, CommitOp::Add);
    EXPECT_EQ(replay(), "user '" + id(35) + "' is already a member");
}

TEST_F(TreeVerification, SECURITY_ARotationThatMovesTheTreeIsRefused) {
    create(40, 0);
    verify(id(9), false);
    const PublicKey grant = PrivateKey::generateRandom().getPublicKey();
    const std::string root = PrivateKey::generateRandom().getPublicKey().toBase58DER();
    const std::uint32_t generation = recordOf(bridge.state, 63)->generation + 1;
    forge(id(35), [&](TreeGroupState& state) {
        state.epoch += 1;
        state.grantPublicKey = grant;
        setRecord(state, TreeNodeState{63, generation, NodePublicKey::fromBase58DER(root), bridge.commits.size() + 1});
    }, {.path = {StatementNode{63, generation, root, ""}}, .rosterBump = 1, .op = CommitOp::Rotate});
    EXPECT_EQ(replay(), "a rotation or policy statement that moves the tree");
    EXPECT_THROW(verify(id(9), false), GroupDataIntegrityException);
}

TEST_F(TreeVerification, SECURITY_AStatementThatChangesThePolicyHashOutsideAPolicyOpIsRefused) {
    // The bridge serves the policy this self-update signs, so only the row can tell.
    create(40, 0);
    verify(id(9), false);
    forge(id(35), [](TreeGroupState&) {}, {.op = CommitOp::SelfUpdate, .policy = wirePolicy(policyOf({{"update", "all"}}))});
    EXPECT_EQ(replay(), "a policyHash moved outside a policy statement");
    EXPECT_THROW(verify(id(9), false), GroupDataIntegrityException);
}

TEST_F(TreeVerification, SECURITY_APolicyStatementWhoseWirePolicyDoesNotHashToItsPolicyHashIsRefused) {
    create(40, 0);
    verify(id(9), false);
    const Poco::Dynamic::Var all = policyOf({{"update", "all"}, {"rotateKeys", "user"}, {"updatePolicy", "user"}});
    forge(id(35), [](TreeGroupState&) {},
          {.op = CommitOp::Policy, .policyHash = TreeCommits::rules(all, id(0)).hash, .policy = wirePolicy(OPEN_POLICY)});
    bridge.policy = all; // what the statement signs, served
    EXPECT_EQ(replay(), "a policy that does not hash to the policyHash signed");
    EXPECT_THROW(verify(id(9), false), GroupDataIntegrityException);
}

TEST_F(TreeVerification, SECURITY_AServedPolicyOtherThanTheLatestStatementSignsIsRefused) {
    create(40, 0);
    remove(id(35), {id(5)});
    const server::GroupInfo honest = bridge.serve(id(9), false);
    const auto lies = std::vector<std::function<void(server::GroupInfo&)>>{
        [](server::GroupInfo& g) { g.policy = policyOf({{"update", "all"}, {"rotateKeys", "user"}, {"updatePolicy", "user"}}); },
        [](server::GroupInfo& g) { g.policy = Poco::Dynamic::Var(); },
        [&](server::GroupInfo& g) { g.creator = id(9); },
        [](server::GroupInfo& g) { g.policy = Poco::Dynamic::Var("not an object"); },
    };
    EXPECT_NO_THROW(TreeVerifier().verify(honest, TreeVerifier::Scope::Path, environment()));
    EXPECT_NO_THROW(TreeVerifier().verifyListed(honest, environment()));
    for (std::size_t i = 0; i < lies.size(); ++i) {
        server::GroupInfo served = honest;
        lies[i](served);
        EXPECT_TRUE(refuses([&] { TreeVerifier().verify(served, TreeVerifier::Scope::Path, environment()); })) << i;
        EXPECT_TRUE(refuses([&] { TreeVerifier().verifyListed(served, environment()); })) << i;
    }
    // Fields the statements do not sign are the bridge's, and change nothing.
    server::GroupInfo unsignedFields = honest;
    Poco::JSON::Object::Ptr wider = policyOf({{"update", "user"}, {"rotateKeys", "user"}, {"updatePolicy", "user"}})
                                        .extract<Poco::JSON::Object::Ptr>();
    wider->set("get", "all");
    unsignedFields.policy = wider;
    EXPECT_NO_THROW(TreeVerifier().verify(unsignedFields, TreeVerifier::Scope::Path, environment()));
}

TEST_F(TreeVerification, SECURITY_EpochOpenersReplayThePolicyFromGenesis) {
    // An out-of-role statement below a pin no read walked (first contact, an own commit) is caught descending.
    createPolicy = ownerRules();
    create(40, 0);
    remove(id(35), {id(5)});
    selfUpdate(id(9));
    TreeVerifier own;
    own.pinCommitted(GROUP_ID, "ctx", TreeCommits::fromWire(bridge.commits.back()), bridge.users(), managersOf(), bridge.rules());
    EXPECT_THROW(own.epochOpeners(GROUP_ID, "ctx", environment()), GroupUnauthorizedSignerException);
}

TEST_F(TreeVerification, FollowsAChainWithPolicyChanges) {
    // The owner lets every member update, a plain member adds under the new rule, the owner narrows it back.
    createPolicy = ownerRules();
    create(40, 0);
    verify(id(9), false);
    forge(id(0), [](TreeGroupState&) {}, {.op = CommitOp::Policy, .policy = wirePolicy(policyOf({{"update", "user"}, {"updatePolicy", "owner"}}))});
    remove(id(35), {id(5)});
    add(std::string(id(35)), 1);
    forge(id(0), [](TreeGroupState&) {}, {.op = CommitOp::Policy, .policy = wirePolicy(ownerRules())});
    EXPECT_NO_THROW(verify(id(9), false));
    EXPECT_NO_THROW(verify(id(9), true));
    EXPECT_EQ(verifierOf(id(9)).epochOpeners(GROUP_ID, "ctx", environment()).size(), 2u);
    EXPECT_NO_THROW(TreeVerifier().verify(bridge.serve(id(10), false), TreeVerifier::Scope::Path, environment()));
    EXPECT_EQ(replay(), "");
}

TEST_F(TreeVerification, AFirstContactTakesThePolicyTheLatestStatementSigns) {
    // TOFU, as for the roster: a colluding signer's own policy hash, served to match, passes a client with no pin.
    createPolicy = ownerRules();
    create(40, 0);
    verify(id(9), false);
    const Poco::Dynamic::Var forged = policyOf({{"update", "all"}, {"updatePolicy", "all"}});
    forge(id(35), [](TreeGroupState&) {}, {.op = CommitOp::SelfUpdate, .policyHash = TreeCommits::rules(forged, id(0)).hash});
    bridge.policy = forged;
    EXPECT_NO_THROW(TreeVerifier().verify(bridge.serve(id(10), false), TreeVerifier::Scope::Path, environment()));
    EXPECT_NO_THROW(TreeVerifier().verifyListed(bridge.serve(id(10), false), environment()));
    EXPECT_THROW(verify(id(9), false), GroupDataIntegrityException) << "a pinned client replays and refuses it";
}

TEST_F(TreeVerification, ARoleFailureOnAForgedStatementIsReportedAsIntegrity) {
    // Out of role and signed by nobody the UserVerifier vouches for: the bridge's, so integrity, not a member's role.
    createPolicy = ownerRules();
    create(40, 0);
    remove(id(35), {id(5)});
    EXPECT_EQ(replay(), "unauthorized") << "genuinely signed";
    CommitStatement statement = TreeCommits::fromWire(bridge.commits.back());
    TreeCommits::sign(statement, PrivateKey::generateRandom());
    bridge.commits.back() = TreeCommits::toWire(statement);
    EXPECT_EQ(replay(), "a statement not genuine, or its committer's key not accepted");
}

TEST_F(TreeVerification, ARotationInTheMiddleOfANonAdjacentWalkChecksOnlyThePath) {
    // 09's milestone walk skips the self-updates between: `head.treeHash` is then an older statement's.
    create(40, 0);
    TreeVerifier::Head head;
    std::set<std::string> grantKeys;
    const CommitStatement genesis = TreeCommits::fromWire(bridge.commits.front());
    head.roster.users = std::set<std::string>(bridge.genesis.begin(), bridge.genesis.end());
    head.roster.managers = bridge.managers;
    ASSERT_EQ(TreeVerifier::step(head, genesis, TreeCommits::digest(genesis), grantKeys, true, true), TreeVerifier::Step::Ok);
    selfUpdate(id(9));
    rotate(id(9));
    const CommitStatement rotation = TreeCommits::fromWire(bridge.commits.back());
    ASSERT_NE(rotation.treeHash, head.treeHash);
    TreeVerifier::Head skipping = head;
    std::set<std::string> keys = grantKeys;
    EXPECT_EQ(TreeVerifier::step(skipping, rotation, TreeCommits::digest(rotation), keys, false, false), TreeVerifier::Step::Ok);
    EXPECT_EQ(skipping.seq, rotation.seq) << "step advances the head";
    TreeVerifier::Head adjacent = head;
    keys = grantKeys;
    EXPECT_THROW(TreeVerifier::step(adjacent, rotation, TreeCommits::digest(rotation), keys, false, true), GroupDataIntegrityException);
}

TEST_F(TreeVerification, SECURITY_TheVerifiersCachesStayBoundedHoweverManyGroupsTheBridgeServes) {
    // The bridge chooses how many distinct groups, statements and committers it serves. Each round: a group's genesis
    // replayed under a pin (an openers entry, a verified statement) and a listing past that pin by a committer not
    // seen before (a verified statement, a "now" answer). Enough rounds overfill every cap.
    create(4, 0);
    selfUpdate(id(1));
    const CommitStatement genesis = TreeCommits::fromWire(bridge.commits[0]);
    const CommitStatement next = TreeCommits::fromWire(bridge.commits[1]);
    TreeVerifier verifier;
    TreeVerifier::Environment env = environment();
    env.verifyUsers = [](const std::vector<privmx::endpoint::core::VerificationRequest>& requests) {
        return std::vector<bool>(requests.size(), true);
    };
    for (int i = 0; i < 2100; ++i) {
        const std::string resource = "r" + std::to_string(i);
        const std::string groupId = TreeCommits::groupId("ctx", resource);
        CommitStatement first = genesis;
        first.groupId = resource;
        TreeCommits::sign(first, member(id(0)).priv);
        verifier.pinCommitted(groupId, "ctx", first, bridge.users(), managersOf(), bridge.rules());
        env.commitsBetween = [&](std::uint64_t, std::uint64_t) {
            server::GroupGetTreeCommitsResult answer = bridge.commitsBetween(0, 1);
            answer.commits = {TreeCommits::toWire(first)};
            return answer;
        };
        ASSERT_EQ(verifier.epochOpeners(groupId, "ctx", env).size(), 1u);
        CommitStatement listed = next;
        listed.groupId = groupId;
        listed.committer = "committer" + std::to_string(i);
        TreeCommits::sign(listed, member(id(1)).priv);
        server::GroupInfo summary;
        summary.id = groupId;
        summary.contextId = "ctx";
        summary.treeCommit = TreeCommits::toWire(listed);
        verifier.preverifyListed({summary}, env);
    }
    EXPECT_EQ(verifier.cacheSizes(), (std::array<std::size_t, 3>{16, 4096, 1024}));
}

// 01: pins loaded from the store

TEST_F(TreeVerification, SECURITY_AnImportedPinRefusesAStateRolledBackBelowIt) {
    // R5: the next session of a member that verified seq 2 is served seq 1 again. Without the import it is a first
    // contact and takes it (the TOFU this closes).
    create(40, 0);
    const FakeBridge before = bridge;
    selfUpdate(id(1));
    ASSERT_NO_THROW(verify(id(9), false));
    const auto next = imported(id(9));
    EXPECT_EQ(next->pinnedSeq(GROUP_ID), 2u);
    bridge = before;
    const server::GroupInfo rolledBack = bridge.serve(id(9), false);
    EXPECT_THROW(next->verify(rolledBack, TreeVerifier::Scope::Path, environment()), GroupHistoryForkException);
    EXPECT_NO_THROW(TreeVerifier().verify(rolledBack, TreeVerifier::Scope::Path, environment()))
        << "a session without the import takes it";
}

TEST_F(TreeVerification, SECURITY_AnImportedPinRefusesAnotherStatementAtItsSeq) {
    // T3-22 across sessions: a genuinely signed second statement at the pinned seq.
    create(40, 0);
    const FakeBridge before = bridge;
    selfUpdate(id(1));
    ASSERT_NO_THROW(verify(id(9), false));
    const auto next = imported(id(9));
    bridge = before;
    forge(id(2), [](TreeGroupState&) {});
    EXPECT_THROW(
        next->verify(bridge.serve(id(9), false), TreeVerifier::Scope::Path, environment()), GroupHistoryForkException
    );
}

TEST_F(TreeVerification, SECURITY_AnImportedPinIsExtendedOnlyByAChainOfMembers) {
    create(40, 0);
    remove(id(35), {id(5)});
    ASSERT_NO_THROW(verify(id(9), false));
    const FakeBridge pinned = bridge;
    const std::string mallory = newMember().userId;
    forge(mallory, [&](TreeGroupState& state) { state.leafAssignment[5] = mallory; }, {.added = {mallory}, .rosterBump = 1});
    EXPECT_THROW(
        imported(id(9))->verify(bridge.serve(id(9), false), TreeVerifier::Scope::Path, environment()),
        GroupDataIntegrityException
    );
    bridge = pinned;
    forge(id(5 + 30), [](TreeGroupState&) {}, {.removed = {}}); // seat 35, a removed member's remover: a member
    const auto next = imported(id(9));
    EXPECT_NO_THROW(next->verify(bridge.serve(id(9), false), TreeVerifier::Scope::Path, environment()));
    EXPECT_EQ(next->pinnedSeq(GROUP_ID), bridge.commits.size()) << "an honest move moves it";
}

TEST_F(TreeVerification, SECURITY_ARosterlessPinIsReplayedFromGenesisBeforeItIsExtended) {
    create(40, 0);
    remove(id(35), {id(5)});
    ASSERT_NO_THROW(verify(id(9), false));
    const FakeBridge pinned = bridge;
    selfUpdate(id(1));
    // Compact: the roster to continue from is replayed from genesis, ending at the pinned statement.
    const auto next = imported(id(9), true);
    EXPECT_NO_THROW(next->verify(bridge.serve(id(9), false), TreeVerifier::Scope::Path, environment()));
    EXPECT_EQ(next->pinnedSeq(GROUP_ID), 3u);

    // The genesis roster, served unsigned beside the chain, swapped: seq 1's rosterHash refuses it.
    const auto swapped = imported(id(9), true);
    FakeBridge lying = bridge;
    lying.genesis.erase(std::find(lying.genesis.begin(), lying.genesis.end(), id(5)));
    std::swap(bridge, lying);
    EXPECT_THROW(
        swapped->verify(bridge.serve(id(9), false), TreeVerifier::Scope::Path, environment()), GroupDataIntegrityException
    );
    std::swap(bridge, lying);

    // A replay that does not end at the pinned state (the pin names another digest at its seq).
    TreeVerifier::PinSet pins;
    pins.tree = verifierOf(id(9)).exportPins(true);
    TreeVerifier::Pin& pin = pins.tree.at(GROUP_ID);
    pin.hasRoster = false;
    pin.seq = 2;
    pin.digest = std::string(32, 'x');
    TreeVerifier offChain;
    offChain.mergeStored(PinBlob::decode(PinBlob::encode(pins)).value().tree);
    EXPECT_THROW(
        offChain.verify(bridge.serve(id(9), false), TreeVerifier::Scope::Path, environment()), GroupDataIntegrityException
    );
    (void)pinned;
}

TEST_F(TreeVerification, SECURITY_ALoadedPinMovesOnlyUnderTheNowQuestion) {
    // N-3 on an imported pin: a key revoked now cannot move it on the first move of the new session.
    create(40, 0);
    verify(id(9), false);
    const auto next = imported(id(9));
    const std::int64_t revokedAt = privmx::utils::Utils::getNowTimestamp() - 1000;
    TreeVerifier::Environment env = environment();
    using privmx::endpoint::core::VerificationRequest;
    env.verifyUsers = [&, vouch = env.verifyUsers](const std::vector<VerificationRequest>& requests) {
        std::vector<bool> verified = vouch(requests);
        for (std::size_t i = 0; i < requests.size(); ++i) {
            if (requests[i].senderId == id(9) && requests[i].date >= revokedAt) {
                verified[i] = false;
            }
        }
        return verified;
    };
    forge(id(9), [](TreeGroupState&) {});
    EXPECT_THROW(next->verify(bridge.serve(id(9), false), TreeVerifier::Scope::Path, env), GroupDataIntegrityException);
}

TEST_F(TreeVerification, SECURITY_AHigherStoredRecordIsTakenAndReadsContinueFromIt) {
    // Another instance of this device verified further (seq 5) while this one stood at seq 3: its record is taken
    // as this device's verified state, and the next read is checked against it.
    create(40, 0);
    selfUpdate(id(1));
    selfUpdate(id(2));
    verify(id(9), false); // seq 3
    TreeVerifier& mine = verifierOf(id(9));
    selfUpdate(id(3));
    selfUpdate(id(4));
    TreeVerifier sibling;
    sibling.verify(bridge.serve(id(9), false), TreeVerifier::Scope::Path, environment()); // seq 5
    const server::GroupInfo served = bridge.serve(id(9), false);
    mine.mergeStored(storedWith(sibling.exportPins(true).at(GROUP_ID)).tree);
    EXPECT_EQ(mine.pinnedSeq(GROUP_ID), 5u);
    EXPECT_TRUE(mine.pinnedAt(GROUP_ID, "ctx", served.keyVersion, served.groupPubKey));
    selfUpdate(id(5));
    EXPECT_NO_THROW(mine.verify(bridge.serve(id(9), false), TreeVerifier::Scope::Path, environment()));
    EXPECT_EQ(mine.pinnedSeq(GROUP_ID), 6u);
}

TEST_F(TreeVerification, SECURITY_ARecordOfAnotherBranchMakesReadsFailNotPass) {
    // The fork boundary: two instances shown two branches are not reconciled. The higher record wins, and the branch
    // this instance is then served is refused as a rollback, never taken in silence.
    create(40, 0);
    selfUpdate(id(1));
    verify(id(9), false); // seq 2
    TreeVerifier& mine = verifierOf(id(9));
    TreeVerifier::Pin branch = mine.exportPins(true).at(GROUP_ID);
    branch.seq = 8;
    branch.digest = std::string(32, 'b');
    mine.mergeStored(storedWith(branch).tree);
    EXPECT_EQ(mine.pinnedSeq(GROUP_ID), 8u);
    selfUpdate(id(2));
    EXPECT_THROW(mine.verify(bridge.serve(id(9), false), TreeVerifier::Scope::Path, environment()), GroupHistoryForkException);
}

TEST_F(TreeVerification, AnImportedPinIsNeverLowered) {
    // The slot went back (local storage restored): memory keeps its verified pin.
    create(40, 0);
    verify(id(9), false);
    TreeVerifier::Pin old = verifierOf(id(9)).exportPins(true).at(GROUP_ID);
    selfUpdate(id(1));
    selfUpdate(id(2));
    verify(id(9), false);
    TreeVerifier& mine = verifierOf(id(9));
    mine.mergeStored(storedWith(old).tree);
    EXPECT_EQ(mine.pinnedSeq(GROUP_ID), 3u);
}

TEST_F(TreeVerification, ASeqZeroImportOnlyRaisesRefusedSeq) {
    create(40, 0);
    verify(id(9), false);
    TreeVerifier::Pin lostRace;
    lostRace.refusedSeq = 7;
    TreeVerifier& mine = verifierOf(id(9));
    mine.mergeStored(storedWith(lostRace).tree);
    EXPECT_EQ(mine.pinnedSeq(GROUP_ID), 1u);
    EXPECT_THROW(mine.assertMaySignAt(GROUP_ID, 7), GroupDataIntegrityException);
    EXPECT_NO_THROW(mine.assertMaySignAt(GROUP_ID, 8));
    TreeVerifier fresh;
    fresh.mergeStored(storedWith(lostRace).tree);
    EXPECT_EQ(fresh.pinnedSeq(GROUP_ID), 0u) << "no pin from a seq-0 record";
}

TEST_F(TreeVerification, ExportOfACleanPinIsCompactAndOfADirtyPinIsFull) {
    create(40, 0);
    int moves = 0;
    verifierOf(id(9)).onPinsMoved([&](bool) { ++moves; });
    verify(id(9), false);
    EXPECT_EQ(moves, 1);
    const TreeVerifier::Pin dirty = verifierOf(id(9)).exportPins(false).at(GROUP_ID);
    EXPECT_TRUE(dirty.hasRoster);
    EXPECT_FALSE(dirty.roster.users.empty());
    const TreeVerifier::Pin clean = verifierOf(id(9)).exportPins(false).at(GROUP_ID);
    EXPECT_FALSE(clean.hasRoster);
    EXPECT_TRUE(clean.roster.users.empty());
    verify(id(9), false);
    EXPECT_EQ(moves, 1) << "the same state again moves nothing";
}
