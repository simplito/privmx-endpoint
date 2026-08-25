/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include "privmx/endpoint/group/keytree/TreeKeys.hpp"

#include <stdexcept>

#include <privmx/crypto/EciesEncryptor.hpp>

#include "privmx/endpoint/group/keytree/TreeMath.hpp"

using namespace privmx::endpoint::group::keytree;

// ─────────────────────────────────────────────────────────────────────────────
// TreeKeys — primitives
// ─────────────────────────────────────────────────────────────────────────────

TreeKeys::TreeKeys(TreeKeyCache& cache) : _cache(cache) {}

std::string TreeKeys::wrapKey(
    const privmx::crypto::PrivateKey& keyToWrap,
    const privmx::crypto::PublicKey& to,
    const privmx::crypto::PrivateKey& signer
) {
    return privmx::crypto::EciesEncryptor::encryptToBase64(to, keyToWrap.toWIF(), signer);
}

std::optional<privmx::crypto::PrivateKey> TreeKeys::unwrapKey(
    const std::string& blob,
    const privmx::crypto::PrivateKey& with
) {
    try {
        const std::string wif = privmx::crypto::EciesEncryptor::decryptFromBase64(with, blob);
        return privmx::crypto::PrivateKey::fromWIF(wif);
    } catch (...) {
        // A blob that does not open, or does not carry a WIF, is a data problem for the caller to report.
        return std::nullopt;
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// TreeKeys — lookups
// ─────────────────────────────────────────────────────────────────────────────

const TreeEdge* TreeKeys::findEdgeFromNode(
    const TreeGroupState& state,
    std::uint32_t childIndex,
    std::uint32_t childGeneration
) {
    for (const TreeEdge& edge : state.edges) {
        if (edge.isGrantEdge) {
            continue;
        }
        if (edge.childKind == EdgeChildKind::Node &&
            edge.childIndex == childIndex &&
            edge.childGeneration == childGeneration) {
            return &edge;
        }
    }
    return nullptr;
}

const TreeEdge* TreeKeys::findEdgeFromUser(const TreeGroupState& state, const std::string& userId) {
    for (const TreeEdge& edge : state.edges) {
        if (edge.isGrantEdge) {
            continue;
        }
        if (edge.childKind == EdgeChildKind::User && edge.childUserId == userId) {
            return &edge;
        }
    }
    return nullptr;
}

const TreeEdge* TreeKeys::findGrantEdge(const TreeGroupState& state) {
    for (const TreeEdge& edge : state.edges) {
        if (edge.isGrantEdge) {
            return &edge;
        }
    }
    return nullptr;
}

const TreeNodeState* TreeKeys::findNode(const TreeGroupState& state, std::uint32_t nodeIndex) {
    for (const TreeNodeState& node : state.nodes) {
        if (node.nodeIndex == nodeIndex) {
            return &node;
        }
    }
    return nullptr;
}

std::optional<std::uint32_t> TreeKeys::positionOf(const TreeGroupState& state, const std::string& userId) {
    for (std::size_t i = 0; i < state.leafAssignment.size(); ++i) {
        if (state.leafAssignment[i].has_value() && state.leafAssignment[i].value() == userId) {
            return static_cast<std::uint32_t>(i);
        }
    }
    return std::nullopt;
}

std::uint32_t TreeKeys::choosePosition(const TreeGroupState& state) {
    // Lowest blank first, then append. Never move anyone: that invariant is what removes the need to track
    // which subtrees a member has ever occupied.
    for (std::size_t i = 0; i < state.leafAssignment.size(); ++i) {
        if (!state.leafAssignment[i].has_value()) {
            return static_cast<std::uint32_t>(i);
        }
    }
    return static_cast<std::uint32_t>(state.leafAssignment.size());
}

// ─────────────────────────────────────────────────────────────────────────────
// TreeKeys — climb
// ─────────────────────────────────────────────────────────────────────────────

ClimbResult TreeKeys::climbToGrantKey(
    const TreeGroupState& state,
    const std::string& ownUserId,
    const privmx::crypto::PrivateKey& ownUserKey,
    bool useCache
) {
    ClimbResult result;

    if (const auto cached = useCache ? _cache.getGrantKey(state.epoch) : std::nullopt; cached.has_value()) {
        if (state.grantPublicKey == cached.value().getPublicKey()) {
            result.grantKey = cached;
            result.reachedNode = TreeMath::root(state.numLeaves);
            return result;
        }
        // Not the key the server publishes for this epoch. Two things look like this: our own staleness, or a
        // server equivocating about an epoch we already verified. Do not decide here — evict and walk. The full
        // climb ends at the same check against `state.grantPublicKey` below, but on a key just recovered from the
        // server's own edges, so it reports `Tampered` on real evidence. Failing here instead would wedge the
        // group for good, because nothing else ever evicts a grant key.
        _cache.forgetGrantKey(state.epoch);
    }

    const auto position = positionOf(state, ownUserId);
    if (!position.has_value()) {
        result.failure = ClimbFailure::NotAMember;
        return result;
    }

    const std::uint32_t rootIndex = TreeMath::root(state.numLeaves);
    std::uint32_t currentNode = TreeMath::leafNode(position.value());
    privmx::crypto::PrivateKey currentKey = ownUserKey;

    // Step one is special: the edge is addressed to the member's long-term key, not to a node generation.
    if (currentNode != rootIndex) {
        const TreeEdge* edge = findEdgeFromUser(state, ownUserId);
        if (edge == nullptr) {
            result.failure = ClimbFailure::MissingEdge;
            result.reachedNode = currentNode;
            return result;
        }
        const auto recovered = unwrapKey(edge->blob, ownUserKey);
        if (!recovered.has_value()) {
            result.failure = ClimbFailure::DecryptFailed;
            result.reachedNode = currentNode;
            return result;
        }
        const TreeNodeState* node = findNode(state, edge->parentIndex);
        if (node == nullptr || !(node->publicKey == recovered.value().getPublicKey())) {
            result.failure = ClimbFailure::Tampered;
            result.reachedNode = currentNode;
            result.tamperedNode = edge->parentIndex;
            return result;
        }
        currentNode = edge->parentIndex;
        currentKey = recovered.value();
        _cache.putNodeKey(currentNode, node->generation, currentKey);
        result.reachedNode = currentNode;
    }

    // Then walk node to node until the root.
    while (currentNode != rootIndex) {
        const TreeNodeState* currentState = findNode(state, currentNode);
        if (currentState == nullptr) {
            result.failure = ClimbFailure::MissingEdge;
            return result;
        }
        const TreeEdge* edge = findEdgeFromNode(state, currentNode, currentState->generation);
        if (edge == nullptr) {
            result.failure = ClimbFailure::MissingEdge;
            return result;
        }
        const auto recovered = unwrapKey(edge->blob, currentKey);
        if (!recovered.has_value()) {
            result.failure = ClimbFailure::DecryptFailed;
            return result;
        }
        const TreeNodeState* parentState = findNode(state, edge->parentIndex);
        if (parentState == nullptr || !(parentState->publicKey == recovered.value().getPublicKey())) {
            result.failure = ClimbFailure::Tampered;
            result.tamperedNode = edge->parentIndex;
            return result;
        }
        currentNode = edge->parentIndex;
        currentKey = recovered.value();
        _cache.putNodeKey(currentNode, parentState->generation, currentKey);
        result.reachedNode = currentNode;
    }

    // Finally the grant edge, which hangs off the root.
    const TreeEdge* grantEdge = findGrantEdge(state);
    if (grantEdge == nullptr) {
        result.failure = ClimbFailure::MissingEdge;
        return result;
    }
    const auto grantKey = unwrapKey(grantEdge->blob, currentKey);
    if (!grantKey.has_value()) {
        result.failure = ClimbFailure::DecryptFailed;
        return result;
    }
    if (!(state.grantPublicKey == grantKey.value().getPublicKey())) {
        result.failure = ClimbFailure::Tampered;
        return result;
    }
    _cache.putGrantKey(state.epoch, grantKey.value());
    result.grantKey = grantKey;
    return result;
}

// ─────────────────────────────────────────────────────────────────────────────
// TreeKeys — build
// ─────────────────────────────────────────────────────────────────────────────

BuildPlan TreeKeys::build(const std::vector<TreeMember>& members, const privmx::crypto::PrivateKey& signer) {
    if (members.empty()) {
        throw std::invalid_argument("a group needs at least one member");
    }
    BuildPlan plan;
    plan.numLeaves = static_cast<std::uint32_t>(members.size());
    const std::uint32_t nodeCount = TreeMath::nodeCount(plan.numLeaves);
    const std::uint32_t rootIndex = TreeMath::root(plan.numLeaves);

    // Mint a fresh independent random keypair for every internal node. Never derived from anything.
    std::map<std::uint32_t, privmx::crypto::PrivateKey> nodeKeys;
    for (std::uint32_t node = 1; node < nodeCount; node += 2) {
        const privmx::crypto::PrivateKey key = privmx::crypto::PrivateKey::generateRandom();
        nodeKeys[node] = key;
        plan.nodes.push_back(TreeNodeState{node, 0, key.getPublicKey()});
        plan.nodeKeys.emplace_back(node, key);
    }

    // Edges: every internal node wraps its private key to each of its existing children.
    for (const auto& [node, key] : nodeKeys) {
        for (const std::uint32_t child : TreeMath::children(node, plan.numLeaves)) {
            TreeEdge edge;
            edge.parentIndex = node;
            edge.parentGeneration = 0;
            if (TreeMath::isLeaf(child)) {
                const std::uint32_t position = TreeMath::leafPosition(child);
                edge.childKind = EdgeChildKind::User;
                edge.childUserId = members[position].userId;
                edge.blob = wrapKey(key, members[position].publicKey, signer);
            } else {
                edge.childKind = EdgeChildKind::Node;
                edge.childIndex = child;
                edge.childGeneration = 0;
                edge.blob = wrapKey(key, nodeKeys.at(child).getPublicKey(), signer);
            }
            plan.edges.push_back(edge);
        }
    }

    // The grant keypair sits above the root, joined by a single edge. Keeping it separate is what stops tree
    // growth from advancing the epoch and invalidating every container granted to the group.
    plan.grantKey = privmx::crypto::PrivateKey::generateRandom();
    TreeEdge grantEdge;
    grantEdge.isGrantEdge = true;
    grantEdge.parentGeneration = 1; // epoch 1
    if (TreeMath::isLeaf(rootIndex)) {
        // Single-member group: the root is the member's own leaf.
        grantEdge.childKind = EdgeChildKind::User;
        grantEdge.childUserId = members[TreeMath::leafPosition(rootIndex)].userId;
        grantEdge.blob = wrapKey(plan.grantKey, members[TreeMath::leafPosition(rootIndex)].publicKey, signer);
    } else {
        grantEdge.childKind = EdgeChildKind::Node;
        grantEdge.childIndex = rootIndex;
        grantEdge.childGeneration = 0;
        grantEdge.blob = wrapKey(plan.grantKey, nodeKeys.at(rootIndex).getPublicKey(), signer);
    }
    plan.edges.push_back(grantEdge);

    plan.wrapCount = static_cast<std::uint32_t>(plan.edges.size());
    return plan;
}

// ─────────────────────────────────────────────────────────────────────────────
// TreeKeys — addition
// ─────────────────────────────────────────────────────────────────────────────

AdditionPlan TreeKeys::planAddition(
    const TreeGroupState& state,
    const TreeMember& newMember,
    const privmx::crypto::PrivateKey& signer
) {
    AdditionPlan plan;
    plan.position = choosePosition(state);
    plan.newNumLeaves = TreeMath::numLeavesToSeat(plan.position, state.numLeaves);

    const std::uint32_t oldRoot = TreeMath::root(state.numLeaves);
    const std::uint32_t newRoot = TreeMath::root(plan.newNumLeaves);
    const std::vector<std::uint32_t> newPath = TreeMath::directPath(plan.position, plan.newNumLeaves);

    // A fresh keypair for every node on the new leaf's path. Wrapping to an EXISTING parent key would be one
    // wrap instead of `log n`, and was the original design — but it requires holding that parent's private key,
    // and a caller only ever recovers keys by climbing from their own leaf. The only lowest-level node on that
    // climb is their own parent, so borrowing works for exactly one seat in the tree: the one beside them.
    // Minting instead means every wrap goes to a PUBLIC key, and the seat can be anywhere.
    std::map<std::uint32_t, privmx::crypto::PrivateKey> refreshed;
    std::map<std::uint32_t, std::uint32_t> generationOf;
    for (const std::uint32_t node : newPath) {
        const privmx::crypto::PrivateKey key = privmx::crypto::PrivateKey::generateRandom();
        const TreeNodeState* existing = findNode(state, node);
        const std::uint32_t generation = existing == nullptr ? 0 : existing->generation + 1;
        refreshed.emplace(node, key);
        generationOf[node] = generation;
        plan.nodes.push_back(TreeNodeState{node, generation, key.getPublicKey()});
        plan.nodeKeys.emplace_back(node, key);
    }

    for (const std::uint32_t node : newPath) {
        const privmx::crypto::PrivateKey& nodeKey = refreshed.at(node);
        for (const std::uint32_t child : TreeMath::children(node, plan.newNumLeaves)) {
            TreeEdge edge;
            edge.parentIndex = node;
            edge.parentGeneration = generationOf.at(node);
            if (TreeMath::isLeaf(child)) {
                const std::uint32_t position = TreeMath::leafPosition(child);
                if (position == plan.position) {
                    edge.childKind = EdgeChildKind::User;
                    edge.childUserId = newMember.userId;
                    edge.blob = wrapKey(nodeKey, newMember.publicKey, signer);
                } else {
                    // A sibling leaf: the refresh replaced the key their climb runs through, so they need an edge
                    // to the new one. Their public key is not part of the tree state — the leaf *is* their key,
                    // and only its holder publishes it — so it comes from the roster.
                    const bool seated = position < state.leafAssignment.size()
                        && state.leafAssignment[position].has_value();
                    if (!seated) {
                        continue; // blank leaf: nothing to wrap to
                    }
                    const auto memberPub = memberKey(state.leafAssignment[position].value());
                    if (!memberPub.has_value()) {
                        throw std::invalid_argument(
                            "seating a member re-keys the path and needs the public key of member " +
                            state.leafAssignment[position].value() + "; supply the roster first"
                        );
                    }
                    edge.childKind = EdgeChildKind::User;
                    edge.childUserId = state.leafAssignment[position].value();
                    edge.blob = wrapKey(nodeKey, memberPub.value(), signer);
                }
            } else {
                // On-path children carry their new public key; everything off the path keeps its current one, so
                // the subtree under it climbs into the refreshed path without re-keying anything of its own.
                const auto onPath = refreshed.find(child);
                if (onPath != refreshed.end()) {
                    edge.childKind = EdgeChildKind::Node;
                    edge.childIndex = child;
                    edge.childGeneration = generationOf.at(child);
                    edge.blob = wrapKey(nodeKey, onPath->second.getPublicKey(), signer);
                } else {
                    const TreeNodeState* existing = findNode(state, child);
                    if (existing == nullptr) {
                        throw std::invalid_argument("tree state is missing node " + std::to_string(child));
                    }
                    edge.childKind = EdgeChildKind::Node;
                    edge.childIndex = child;
                    edge.childGeneration = existing->generation;
                    edge.blob = wrapKey(nodeKey, existing->publicKey.parsed(), signer);
                }
            }
            plan.edges.push_back(edge);
        }
    }

    if (newRoot != oldRoot) {
        plan.newRoot = TreeNodeState{newRoot, generationOf.at(newRoot), refreshed.at(newRoot).getPublicKey()};
        plan.newRootKey = refreshed.at(newRoot);
    }

    // The root is on the path, so its key changed and the grant edge has to be re-issued to it — on growth and
    // when filling a blank alike. The grant keypair ITSELF is unchanged, `parentGeneration` stays at the current
    // epoch, and so no container holding a wrap of the grant key becomes stale. That is the whole economy of a
    // cheap addition, and it is why the grant keypair sits one indirection above the root.
    const auto grantKey = _cache.getGrantKey(state.epoch);
    if (!grantKey.has_value()) {
        throw std::invalid_argument("re-linking the grant edge needs the grant key; climb the tree first");
    }
    TreeEdge grantEdge;
    grantEdge.isGrantEdge = true;
    grantEdge.parentGeneration = state.epoch;
    grantEdge.childKind = EdgeChildKind::Node;
    grantEdge.childIndex = newRoot;
    grantEdge.childGeneration = generationOf.at(newRoot);
    grantEdge.blob = wrapKey(grantKey.value(), refreshed.at(newRoot).getPublicKey(), signer);
    plan.edges.push_back(grantEdge);

    plan.wrapCount = static_cast<std::uint32_t>(plan.edges.size());
    return plan;
}

// ─────────────────────────────────────────────────────────────────────────────
// TreeKeys — removal
// ─────────────────────────────────────────────────────────────────────────────

RemovalPlan TreeKeys::planRemoval(
    const TreeGroupState& state,
    const std::string& leavingUserId,
    const privmx::crypto::PrivateKey& signer
) {
    const auto position = positionOf(state, leavingUserId);
    if (!position.has_value()) {
        throw std::invalid_argument("member " + leavingUserId + " holds no leaf in this tree");
    }

    RemovalPlan plan;
    plan.newEpoch = state.epoch + 1;
    const std::uint32_t leavingLeaf = TreeMath::leafNode(position.value());
    const std::vector<std::uint32_t> path = TreeMath::directPath(position.value(), state.numLeaves);

    // Every node on the path gets a FRESH independent random keypair. Deriving it from the key it replaces
    // would let the removed member compute forward and defeat the whole construction; the server cannot detect
    // that, so it lives or dies on this line.
    std::map<std::uint32_t, privmx::crypto::PrivateKey> refreshed;
    for (const std::uint32_t node : path) {
        refreshed[node] = privmx::crypto::PrivateKey::generateRandom();
    }

    for (const std::uint32_t node : path) {
        const TreeNodeState* existing = findNode(state, node);
        if (existing == nullptr) {
            throw std::invalid_argument("tree state is missing node " + std::to_string(node));
        }
        NodeRefresh refresh;
        refresh.nodeIndex = node;
        refresh.newGeneration = existing->generation + 1;
        refresh.newKey = refreshed.at(node);

        for (const std::uint32_t child : TreeMath::children(node, state.numLeaves)) {
            if (child == leavingLeaf) {
                continue; // the blanked leaf gets no edge — that is the point of the whole operation
            }
            TreeEdge edge;
            edge.parentIndex = node;
            edge.parentGeneration = refresh.newGeneration;

            if (TreeMath::isLeaf(child)) {
                const std::uint32_t childPosition = TreeMath::leafPosition(child);
                if (!state.leafAssignment[childPosition].has_value()) {
                    continue; // blank leaf: nobody to wrap to
                }
                // A sibling leaf still occupied: its member's public key must come from the caller's roster.
                const auto memberPub = memberKey(state.leafAssignment[childPosition].value());
                if (!memberPub.has_value()) {
                    throw std::invalid_argument(
                        "removal needs the public key of member " + state.leafAssignment[childPosition].value() +
                        "; supply the roster first"
                    );
                }
                edge.childKind = EdgeChildKind::User;
                edge.childUserId = state.leafAssignment[childPosition].value();
                edge.blob = wrapKey(refresh.newKey, memberPub.value(), signer);
            } else {
                // On-path children carry their NEW public key; copath children keep their current one.
                const auto onPath = refreshed.find(child);
                const bool childOnPath = onPath != refreshed.end();
                const TreeNodeState* childState = findNode(state, child);
                if (childState == nullptr) {
                    throw std::invalid_argument("tree state is missing node " + std::to_string(child));
                }
                edge.childKind = EdgeChildKind::Node;
                edge.childIndex = child;
                edge.childGeneration = childOnPath ? childState->generation + 1 : childState->generation;
                edge.blob = childOnPath
                    ? wrapKey(refresh.newKey, onPath->second.getPublicKey(), signer)
                    : wrapKey(refresh.newKey, childState->publicKey.parsed(), signer);
            }
            refresh.edges.push_back(edge);
        }
        plan.wrapCount += static_cast<std::uint32_t>(refresh.edges.size());
        plan.pathRefresh.push_back(refresh);
    }

    // A fresh grant keypair, re-linked to the refreshed root. This is the epoch bump.
    plan.newGrantKey = privmx::crypto::PrivateKey::generateRandom();
    const std::uint32_t rootIndex = TreeMath::root(state.numLeaves);
    plan.grantEdge.isGrantEdge = true;
    plan.grantEdge.parentGeneration = plan.newEpoch;
    if (TreeMath::isLeaf(rootIndex)) {
        throw std::invalid_argument("cannot remove the only member of a group");
    }
    const TreeNodeState* rootState = findNode(state, rootIndex);
    plan.grantEdge.childKind = EdgeChildKind::Node;
    plan.grantEdge.childIndex = rootIndex;
    plan.grantEdge.childGeneration = rootState->generation + 1;
    plan.grantEdge.blob = wrapKey(plan.newGrantKey, refreshed.at(rootIndex).getPublicKey(), signer);
    plan.wrapCount += 1;

    return plan;
}

std::optional<privmx::crypto::PublicKey> TreeKeys::memberKey(const std::string& userId) {
    const auto parsed = _memberKeys.find(userId);
    if (parsed != _memberKeys.end()) {
        return parsed->second;
    }
    const auto raw = _memberKeyStrings.find(userId);
    if (raw == _memberKeyStrings.end()) {
        return std::nullopt;
    }
    const auto inserted = _memberKeys.emplace(userId, privmx::crypto::PublicKey::fromBase58DER(raw->second));
    return inserted.first->second;
}

void TreeKeys::setMemberKeyStrings(std::map<std::string, std::string> membersByUserId) {
    _memberKeys.clear();
    _memberKeyStrings = std::move(membersByUserId);
}

void TreeKeys::setMemberKeys(const std::vector<TreeMember>& members) {
    _memberKeys.clear();
    _memberKeyStrings.clear();
    for (const TreeMember& member : members) {
        _memberKeys.insert_or_assign(member.userId, member.publicKey);
    }
}
