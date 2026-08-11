/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include "privmx/endpoint/group/keytree/TreeKeys.hpp"

#include <algorithm>
#include <set>
#include <stdexcept>

#include <privmx/crypto/EciesEncryptor.hpp>

#include "privmx/endpoint/group/keytree/TreeMath.hpp"

using namespace privmx::endpoint::group::keytree;

// ─────────────────────────────────────────────────────────────────────────────
// TreeKeyStore
// ─────────────────────────────────────────────────────────────────────────────

void TreeKeyStore::putNodeKey(
    std::uint32_t nodeIndex,
    std::uint32_t generation,
    const privmx::crypto::PrivateKey& key
) {
    // `insert_or_assign`, not `operator[]`: subscripting default-constructs the value first, and a
    // default-constructed EC key **generates a fresh keypair** (`ECC::ECC()` calls `genPair()`). That is ~225 us
    // of thrown-away work per insertion — a thousand times the cost of the insertion itself.
    _nodeKeys.insert_or_assign(std::make_pair(nodeIndex, generation), key);
}

std::optional<privmx::crypto::PrivateKey> TreeKeyStore::getNodeKey(std::uint32_t nodeIndex, std::uint32_t generation)
    const {
    const auto it = _nodeKeys.find(std::make_pair(nodeIndex, generation));
    if (it == _nodeKeys.end()) {
        return std::nullopt;
    }
    return it->second;
}

void TreeKeyStore::putGrantKey(std::uint32_t epoch, const privmx::crypto::PrivateKey& key) {
    _grantKeys.insert_or_assign(epoch, key); // see putNodeKey: subscripting would mint a throwaway keypair
}

std::optional<privmx::crypto::PrivateKey> TreeKeyStore::getGrantKey(std::uint32_t epoch) const {
    const auto it = _grantKeys.find(epoch);
    if (it == _grantKeys.end()) {
        return std::nullopt;
    }
    return it->second;
}

std::size_t TreeKeyStore::nodeKeyCount() const {
    return _nodeKeys.size();
}

void TreeKeyStore::clear() {
    _nodeKeys.clear();
    _grantKeys.clear();
}

// ─────────────────────────────────────────────────────────────────────────────
// TreeKeys — primitives
// ─────────────────────────────────────────────────────────────────────────────

TreeKeys::TreeKeys(TreeKeyStore& store) : _store(store) {}

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
        if (edge.childKind == EdgeChildKind::Node && edge.childIndex == childIndex &&
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

    if (const auto cached = useCache ? _store.getGrantKey(state.epoch) : std::nullopt; cached.has_value()) {
        result.grantKey = cached;
        result.reachedNode = TreeMath::root(state.numLeaves);
        return result;
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
        if (node == nullptr || node->publicKeyBase58 != recovered.value().getPublicKey().toBase58DER()) {
            result.failure = ClimbFailure::Tampered;
            result.reachedNode = currentNode;
            result.tamperedNode = edge->parentIndex;
            return result;
        }
        currentNode = edge->parentIndex;
        currentKey = recovered.value();
        _store.putNodeKey(currentNode, node->generation, currentKey);
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
        if (parentState == nullptr
            || parentState->publicKeyBase58 != recovered.value().getPublicKey().toBase58DER()) {
            result.failure = ClimbFailure::Tampered;
            result.tamperedNode = edge->parentIndex;
            return result;
        }
        currentNode = edge->parentIndex;
        currentKey = recovered.value();
        _store.putNodeKey(currentNode, parentState->generation, currentKey);
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
    _store.putGrantKey(state.epoch, grantKey.value());
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
        nodeKeys.insert_or_assign(node, key); // subscripting would mint a throwaway keypair per node
        plan.nodes.push_back(TreeNodeState{node, 0, key.getPublicKey().toBase58DER()});
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
                edge.blob = wrapKey(key, members[position].publicKey(), signer);
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
        grantEdge.blob = wrapKey(plan.grantKey, members[TreeMath::leafPosition(rootIndex)].publicKey(), signer);
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
    const std::uint32_t leaf = TreeMath::leafNode(plan.position);

    if (plan.newNumLeaves == state.numLeaves) {
        // Filling a blank: the topology is unchanged, so one wrap suffices. The new member climbs on edges that
        // already exist, because every parent edge targets its child's current generation.
        const std::uint32_t parentIndex = TreeMath::parent(leaf, state.numLeaves);
        const TreeNodeState* parentState = findNode(state, parentIndex);
        if (parentState == nullptr) {
            throw std::invalid_argument("tree state is missing node " + std::to_string(parentIndex));
        }
        const auto parentKey = _store.getNodeKey(parentIndex, parentState->generation);
        if (!parentKey.has_value()) {
            throw std::invalid_argument(
                "adding a member needs the key of node " + std::to_string(parentIndex) + "; climb the tree first"
            );
        }
        TreeEdge edge;
        edge.parentIndex = parentIndex;
        edge.parentGeneration = parentState->generation;
        edge.childKind = EdgeChildKind::User;
        edge.childUserId = newMember.userId;
        edge.blob = wrapKey(parentKey.value(), newMember.publicKey(), signer);
        plan.edges.push_back(edge);
        plan.wrapCount = 1;
        return plan;
    }

    // Appending grows the tree. Growth is purely additive for keys — nothing rotates, because nobody loses
    // access — but it can change which children an existing node has, so those edges must be re-created.
    std::map<std::uint32_t, privmx::crypto::PrivateKey> mintedKeys;
    const std::vector<std::uint32_t> newPath = TreeMath::directPath(plan.position, plan.newNumLeaves);

    for (const std::uint32_t node : newPath) {
        if (findNode(state, node) == nullptr) {
            // A node that did not exist before: mint it.
            const privmx::crypto::PrivateKey key = privmx::crypto::PrivateKey::generateRandom();
            mintedKeys.insert_or_assign(node, key); // subscripting would mint a throwaway keypair
            plan.nodes.push_back(TreeNodeState{node, 0, key.getPublicKey().toBase58DER()});
        }
    }

    for (const std::uint32_t node : newPath) {
        privmx::crypto::PrivateKey nodeKey;
        std::uint32_t nodeGeneration = 0;
        if (const auto minted = mintedKeys.find(node); minted != mintedKeys.end()) {
            nodeKey = minted->second;
        } else {
            const TreeNodeState* existing = findNode(state, node);
            nodeGeneration = existing->generation;
            const auto held = _store.getNodeKey(node, nodeGeneration);
            if (!held.has_value()) {
                throw std::invalid_argument(
                    "growing the tree needs the key of existing node " + std::to_string(node) + "; climb the tree first"
                );
            }
            nodeKey = held.value();
        }

        for (const std::uint32_t child : TreeMath::children(node, plan.newNumLeaves)) {
            TreeEdge edge;
            edge.parentIndex = node;
            edge.parentGeneration = nodeGeneration;
            if (TreeMath::isLeaf(child)) {
                const std::uint32_t position = TreeMath::leafPosition(child);
                if (position == plan.position) {
                    edge.childKind = EdgeChildKind::User;
                    edge.childUserId = newMember.userId;
                    edge.blob = wrapKey(nodeKey, newMember.publicKey(), signer);
                } else {
                    // An existing leaf whose parent changed. Growth re-parents leaves at the truncated edge of
                    // the tree, and that member's climb now runs through a node that did not exist a moment ago,
                    // so the edge has to be created for them. Their public key is not part of the tree state —
                    // the leaf *is* their key, and only its holder publishes it — so it comes from the roster.
                    if (!state.leafAssignment[position].has_value()) {
                        continue; // blank leaf: nothing to wrap to
                    }
                    const auto memberPub = _memberKeys.find(state.leafAssignment[position].value());
                    if (memberPub == _memberKeys.end()) {
                        throw std::invalid_argument(
                            "growing the tree re-parents existing leaf " + std::to_string(position) +
                            " (member " + state.leafAssignment[position].value() +
                            "); call setMemberKeys with the full roster first"
                        );
                    }
                    edge.childKind = EdgeChildKind::User;
                    edge.childUserId = state.leafAssignment[position].value();
                    edge.blob = wrapKey(nodeKey, privmx::crypto::PublicKey::fromBase58DER(memberPub->second), signer);
                }
            } else {
                const privmx::crypto::PublicKey childPub = [&]() {
                    if (const auto minted = mintedKeys.find(child); minted != mintedKeys.end()) {
                        return minted->second.getPublicKey();
                    }
                    const TreeNodeState* existing = findNode(state, child);
                    if (existing == nullptr) {
                        throw std::invalid_argument("tree state is missing node " + std::to_string(child));
                    }
                    return existing->publicKey();
                }();
                edge.childKind = EdgeChildKind::Node;
                edge.childIndex = child;
                edge.childGeneration = [&]() -> std::uint32_t {
                    if (mintedKeys.count(child) > 0) {
                        return 0;
                    }
                    return findNode(state, child)->generation;
                }();
                edge.blob = wrapKey(nodeKey, childPub, signer);
            }
            plan.edges.push_back(edge);
        }
    }

    if (newRoot != oldRoot) {
        const auto rootKey = mintedKeys.find(newRoot);
        if (rootKey == mintedKeys.end()) {
            throw std::invalid_argument("expected the new root to be freshly minted");
        }
        plan.newRoot = TreeNodeState{newRoot, 0, rootKey->second.getPublicKey().toBase58DER()};
        plan.newRootKey = rootKey->second;

        // Re-link the grant edge to the new root. The grant keypair itself is UNCHANGED, so `grantPublicKey`
        // stays the same and no container becomes stale.
        const auto grantKey = _store.getGrantKey(state.epoch);
        if (!grantKey.has_value()) {
            throw std::invalid_argument("re-linking the grant edge needs the grant key; climb the tree first");
        }
        TreeEdge grantEdge;
        grantEdge.isGrantEdge = true;
        grantEdge.parentGeneration = state.epoch;
        grantEdge.childKind = EdgeChildKind::Node;
        grantEdge.childIndex = newRoot;
        grantEdge.childGeneration = 0;
        grantEdge.blob = wrapKey(grantKey.value(), rootKey->second.getPublicKey(), signer);
        plan.edges.push_back(grantEdge);
    }

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
        refreshed.insert_or_assign(node, privmx::crypto::PrivateKey::generateRandom());
    }

    for (const std::uint32_t node : path) {
        const TreeNodeState* existing = findNode(state, node);
        if (existing == nullptr) {
            throw std::invalid_argument("tree state is missing node " + std::to_string(node));
        }
        // Constructed in one step on purpose: declaring it and assigning afterwards would default-construct its
        // `PrivateKey`, and a default-constructed EC key mints a keypair that is then thrown away.
        NodeRefresh refresh{node, existing->generation + 1, refreshed.at(node), {}};

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
                const auto memberPub = _memberKeys.find(state.leafAssignment[childPosition].value());
                if (memberPub == _memberKeys.end()) {
                    throw std::invalid_argument(
                        "removal needs the public key of member " + state.leafAssignment[childPosition].value() +
                        "; call setMemberKeys first"
                    );
                }
                edge.childKind = EdgeChildKind::User;
                edge.childUserId = state.leafAssignment[childPosition].value();
                edge.blob =
                    wrapKey(refresh.newKey, privmx::crypto::PublicKey::fromBase58DER(memberPub->second), signer);
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
                edge.blob = wrapKey(
                    refresh.newKey, childOnPath ? onPath->second.getPublicKey() : childState->publicKey(), signer
                );
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

void TreeKeys::setMemberKeys(const std::vector<TreeMember>& members) {
    _memberKeys.clear();
    for (const TreeMember& member : members) {
        // The hot one: called on every addition and removal, once per member. With `operator[]` a 16 384-member
        // roster cost 3,7 s of generating keypairs that were immediately overwritten.
        _memberKeys.insert_or_assign(member.userId, member.publicKeyBase58);
    }
}
