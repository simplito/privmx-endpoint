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
#include <functional>
#include <set>
#include <stdexcept>

#include <privmx/crypto/EciesEncryptor.hpp>
#include <privmx/utils/Utils.hpp>

#include "privmx/endpoint/group/keytree/TreeCommits.hpp"
#include "privmx/endpoint/group/keytree/TreeMath.hpp"

using namespace privmx::endpoint::group::keytree;

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

std::optional<privmx::crypto::PublicKey> TreeKeys::sealerOf(const std::string& blob) {
    try {
        // `EciesEncryptor::encrypt`: 'e' || sender DER (33) || recipient DER (33) || ciphertext.
        const std::string raw = privmx::utils::Base64::toString(blob);
        if (raw.size() < 67 || raw.front() != 'e') {
            return std::nullopt;
        }
        return privmx::crypto::PublicKey::fromDER(raw.substr(1, 33));
    } catch (...) { return std::nullopt; }
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

std::vector<std::uint32_t> TreeKeys::choosePositions(const TreeGroupState& state, std::uint32_t count) {
    // Lowest blank first, then append. Never move anyone: that invariant is what removes the need to track
    // which subtrees a member has ever occupied.
    std::vector<std::uint32_t> seats;
    for (std::size_t i = 0; i < state.leafAssignment.size() && seats.size() < count; ++i) {
        if (!state.leafAssignment[i].has_value()) {
            seats.push_back(static_cast<std::uint32_t>(i));
        }
    }
    // Appends have to be contiguous: a skipped seat is one nothing can ever reuse, and the bridge refuses it.
    for (std::uint32_t position = static_cast<std::uint32_t>(state.leafAssignment.size()); seats.size() < count;
         ++position) {
        seats.push_back(position);
    }
    return seats;
}

namespace {

void resolveInto(const TreeGroupState& state, std::uint32_t nodeIndex, std::vector<std::uint32_t>& out) {
    if (TreeMath::isLeaf(nodeIndex)) {
        const std::uint32_t position = TreeMath::leafPosition(nodeIndex);
        if (position < state.leafAssignment.size() && state.leafAssignment[position].has_value()) {
            out.push_back(nodeIndex);
        }
        return;
    }
    if (TreeMath::isKeyed(nodeIndex, state.numLeaves)) {
        for (const TreeNodeState& node : state.nodes) {
            if (node.nodeIndex == nodeIndex && node.publicKey.has_value()) {
                out.push_back(nodeIndex);
                return;
            }
        }
    }
    for (const std::uint32_t child : TreeMath::children(nodeIndex, state.numLeaves)) {
        resolveInto(state, child, out);
    }
}

// The edge that carries an ancestor's key down to the node we stand on, as the current state describes it: from a
// filled node still on our path above us, at that node's current generation. A leftover edge of an older state
// fails one of those and is passed over rather than followed into a key that no longer verifies.
const TreeEdge* findClimbingEdge(
    const TreeGroupState& state,
    const std::function<bool(const TreeEdge&)>& addressedToUs,
    const std::vector<std::uint32_t>& above,
    const std::function<const TreeNodeState*(std::uint32_t)>& node
) {
    for (const TreeEdge& edge : state.edges) {
        if (edge.isGrantEdge || !addressedToUs(edge)) {
            continue;
        }
        if (std::find(above.begin(), above.end(), edge.parentIndex) == above.end()) {
            continue;
        }
        const TreeNodeState* parent = node(edge.parentIndex);
        if (parent != nullptr && parent->publicKey.has_value() && parent->generation == edge.parentGeneration) {
            return &edge;
        }
    }
    return nullptr;
}

// `node` if keyed, and every keyed ancestor of it up to the root: what a holder of `node`'s key can climb to.
void climbInto(std::uint32_t node, std::uint32_t numLeaves, std::set<std::uint32_t>& out) {
    const std::uint32_t root = TreeMath::root(numLeaves);
    for (;; node = TreeMath::parent(node, numLeaves)) {
        if (TreeMath::isKeyed(node, numLeaves)) {
            out.insert(node);
        }
        if (node == root) {
            return;
        }
    }
}

} // namespace

std::vector<std::uint32_t> TreeKeys::resolution(const TreeGroupState& state, std::uint32_t nodeIndex) {
    std::vector<std::uint32_t> resolved;
    resolveInto(state, nodeIndex, resolved);
    return resolved;
}

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
        // Not the key the server publishes for this epoch — our staleness or its equivocation, indistinguishable
        // here. Evict and walk: the same check below runs on a freshly recovered key, so `Tampered` is real evidence.
        _cache.forgetGrantKey(state.epoch);
    }

    const auto position = positionOf(state, ownUserId);
    if (!position.has_value()) {
        result.failure = ClimbFailure::NotAMember;
        return result;
    }

    const std::uint32_t rootIndex = TreeMath::root(state.numLeaves);
    const std::vector<std::uint32_t> path = TreeMath::directPath(position.value(), state.numLeaves);
    const auto node = [&](std::uint32_t nodeIndex) { return findNode(state, nodeIndex); };
    std::uint32_t currentNode = TreeMath::leafNode(position.value());
    privmx::crypto::PrivateKey currentKey = ownUserKey;
    result.reachedNode = currentNode;

    // Up the path one edge at a time. An edge may skip levels — its parent is the lowest filled keyed ancestor — but
    // it only ever leads further up our own path, so the walk ends at the root whatever the server serves.
    auto stillAbove = path.begin();
    while (currentNode != rootIndex) {
        const std::vector<std::uint32_t> above(stillAbove, path.end());
        const TreeNodeState* currentState = TreeMath::isLeaf(currentNode) ? nullptr : node(currentNode);
        const TreeEdge* edge = TreeMath::isLeaf(currentNode) ?
            findClimbingEdge(
                state,
                [&](const TreeEdge& e) { return e.childKind == EdgeChildKind::User && e.childUserId == ownUserId; },
                above, node
            ) :
            findClimbingEdge(
                state,
                [&](const TreeEdge& e) {
                    return e.childKind == EdgeChildKind::Node &&
                        e.childIndex == currentNode &&
                        e.childGeneration == currentState->generation;
                },
                above, node
            );
        if (edge == nullptr) {
            result.failure = ClimbFailure::MissingEdge;
            return result;
        }
        const auto recovered = unwrapKey(edge->blob, currentKey);
        if (!recovered.has_value()) {
            result.failure = TreeMath::isLeaf(currentNode) ? ClimbFailure::LeafDidNotOpen : ClimbFailure::DecryptFailed;
            result.tamperedNode = edge->parentIndex; // the parent's setter wrote its edges, garbled ones included
            return result;
        }
        const TreeNodeState* parentState = node(edge->parentIndex);
        if (!(parentState->publicKey.value() == recovered.value().getPublicKey())) {
            result.failure = ClimbFailure::Tampered;
            result.tamperedNode = edge->parentIndex;
            return result;
        }
        currentNode = edge->parentIndex;
        currentKey = recovered.value();
        stillAbove = std::find(stillAbove, path.end(), currentNode) + 1;
        result.reachedNode = currentNode;
    }

    // Finally the grant edge, which hangs off the root — or, in a one-leaf tree, off the member.
    const auto grantEdge = std::find_if(state.edges.begin(), state.edges.end(), [](const TreeEdge& edge) {
        return edge.isGrantEdge;
    });
    if (grantEdge == state.edges.end()) {
        result.failure = ClimbFailure::MissingEdge;
        return result;
    }
    const auto grantKey = unwrapKey(grantEdge->blob, currentKey);
    if (!grantKey.has_value()) {
        // Still at the leaf only in a one-leaf tree: the grant edge is then our own leaf edge.
        result.failure = TreeMath::isLeaf(currentNode) ? ClimbFailure::LeafDidNotOpen : ClimbFailure::DecryptFailed;
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

CommitShape TreeKeys::shapeCreate(const std::vector<std::string>& memberIds, const std::string& creatorId) {
    if (memberIds.empty()) {
        throw std::invalid_argument("a group needs at least one member");
    }
    CommitShape shape;
    shape.numLeaves = static_cast<std::uint32_t>(memberIds.size());
    std::set<std::string> named;
    for (const std::string& memberId : memberIds) {
        if (!named.insert(memberId).second) {
            throw std::invalid_argument("member " + memberId + " is named twice");
        }
        shape.leafAssignment.push_back(memberId);
    }
    const auto seat = std::find(memberIds.begin(), memberIds.end(), creatorId);
    if (seat == memberIds.end()) {
        throw std::invalid_argument("the creator " + creatorId + " must be a member of the group it creates");
    }
    shape.committerSeat = static_cast<std::uint32_t>(std::distance(memberIds.begin(), seat));
    // The creator fills every keyed node, so every later commit is already cheap. What it learns that way is what a
    // removal of the creator blanks (`setBy`); members heal it sooner by self-updating over it.
    const std::vector<std::uint32_t> own = TreeMath::keyedPath(shape.committerSeat, shape.numLeaves);
    for (const std::uint32_t node : TreeMath::keyedNodes(shape.numLeaves)) {
        if (std::find(own.begin(), own.end(), node) == own.end()) {
            shape.filledOffPath.insert(node);
        }
    }
    return shape;
}

CommitShape TreeKeys::shapeAddition(
    const TreeGroupState& state,
    const std::vector<std::string>& newMemberIds,
    const std::vector<std::uint32_t>& positions,
    const std::string& adderId
) {
    if (newMemberIds.empty()) {
        throw std::invalid_argument("an addition must name at least one member");
    }
    if (newMemberIds.size() != positions.size()) {
        // Parallel lists: a mismatch would seat somebody at another newcomer's coordinate.
        throw std::invalid_argument("every newcomer needs exactly one seat");
    }
    const auto adderSeat = positionOf(state, adderId);
    if (!adderSeat.has_value()) {
        throw std::invalid_argument("the adder " + adderId + " holds no leaf in this tree");
    }

    CommitShape shape;
    shape.numLeaves = TreeMath::numLeavesToSeatAll(positions, state.numLeaves);
    shape.leafAssignment = state.leafAssignment;
    shape.leafAssignment.resize(shape.numLeaves, std::nullopt);
    shape.committerSeat = adderSeat.value();
    shape.subjectSeats = positions;

    std::set<std::string> named;
    std::set<std::uint32_t> taken;
    for (std::size_t i = 0; i < positions.size(); ++i) {
        // Two seats for one userId would leave a second leaf nobody blanks: `positionOf` finds only the first.
        if (!named.insert(newMemberIds[i]).second) {
            throw std::invalid_argument("member " + newMemberIds[i] + " is named twice");
        }
        if (positionOf(state, newMemberIds[i]).has_value()) {
            throw std::invalid_argument("member " + newMemberIds[i] + " already holds a leaf in this tree");
        }
        if (!taken.insert(positions[i]).second) {
            throw std::invalid_argument("two newcomers cannot take the same seat");
        }
        if (shape.leafAssignment[positions[i]].has_value()) {
            throw std::invalid_argument("seat " + std::to_string(positions[i]) + " is not free");
        }
        shape.leafAssignment[positions[i]] = newMemberIds[i];
    }
    // The newcomers' paths below the adder's are minted by the adder, not left blank: the adder keeps those keys,
    // which is why a removal of the adder blanks every node it set (`shapeRemoval`).
    const std::vector<std::uint32_t> own = TreeMath::keyedPath(shape.committerSeat, shape.numLeaves);
    for (const std::uint32_t position : positions) {
        for (const std::uint32_t node : TreeMath::keyedPath(position, shape.numLeaves)) {
            if (std::find(own.begin(), own.end(), node) == own.end()) {
                shape.filledOffPath.insert(node);
            }
        }
    }
    return shape;
}

CommitShape TreeKeys::shapeRemoval(
    const TreeGroupState& state,
    const std::vector<std::string>& leavingUserIds,
    const std::string& removerId
) {
    if (leavingUserIds.empty()) {
        throw std::invalid_argument("a removal must name at least one member");
    }
    const auto removerSeat = positionOf(state, removerId);
    if (!removerSeat.has_value()) {
        throw std::invalid_argument("the remover " + removerId + " holds no leaf in this tree");
    }

    CommitShape shape;
    shape.numLeaves = state.numLeaves; // seats are never compacted
    shape.leafAssignment = state.leafAssignment;
    shape.committerSeat = removerSeat.value();

    std::set<std::string> named;
    std::set<std::uint32_t> known;
    for (const std::string& leavingUserId : leavingUserIds) {
        if (!named.insert(leavingUserId).second) {
            throw std::invalid_argument("member " + leavingUserId + " is named twice");
        }
        if (leavingUserId == removerId) {
            // The remover mints the next epoch's grant key, so removing yourself would hand you the key that is
            // meant to lock you out.
            throw std::invalid_argument("a member cannot remove themselves");
        }
        const auto seat = positionOf(state, leavingUserId);
        if (!seat.has_value()) {
            throw std::invalid_argument("member " + leavingUserId + " holds no leaf in this tree");
        }
        shape.subjectSeats.push_back(seat.value());
        shape.leafAssignment[seat.value()] = std::nullopt;
        climbInto(TreeMath::leafNode(seat.value()), shape.numLeaves, known);
    }
    // Everything the leavers could know: their paths, every key they minted, and every ancestor of those — a key
    // wrapped to one they know is one they know. Edges only ever lead up, so this closure is all of it.
    for (const TreeNodeState& node : state.nodes) {
        if (!node.publicKey.has_value() || !TreeMath::isKeyed(node.nodeIndex, shape.numLeaves)) {
            continue;
        }
        const auto setter = node.setBy.has_value() ? state.setters.find(node.setBy.value()) : state.setters.end();
        if (setter == state.setters.end()) {
            throw std::invalid_argument("node " + std::to_string(node.nodeIndex) + " names no known statement");
        }
        if (named.count(setter->second) > 0) {
            climbInto(node.nodeIndex, shape.numLeaves, known);
        }
    }
    // The remover's own path is re-keyed instead.
    for (const std::uint32_t node : TreeMath::keyedPath(shape.committerSeat, shape.numLeaves)) {
        known.erase(node);
    }
    shape.blanked = std::move(known);
    std::sort(shape.subjectSeats.begin(), shape.subjectSeats.end());
    return shape;
}

CommitShape TreeKeys::shapeSelfUpdate(const TreeGroupState& state, const std::string& memberId) {
    const auto seat = positionOf(state, memberId);
    if (!seat.has_value()) {
        throw std::invalid_argument("member " + memberId + " holds no leaf in this tree");
    }
    // A one-leaf tree has no node to refresh, but its grant edge is re-wrapped to the member: how a sole member
    // renews its leaf after an identity key change. The background self-update never selects such a tree.
    CommitShape shape;
    shape.numLeaves = state.numLeaves;
    shape.leafAssignment = state.leafAssignment;
    shape.committerSeat = seat.value();
    return shape;
}

TreeGroupState TreeKeys::postState(const TreeGroupState& state, const CommitShape& shape) {
    TreeGroupState post;
    post.numLeaves = shape.numLeaves;
    post.leafAssignment = shape.leafAssignment;
    for (const TreeNodeState& node : state.nodes) {
        if (!TreeMath::isKeyed(node.nodeIndex, shape.numLeaves)) {
            continue; // an old root that growth turned into a bucket node: it holds no key from here on
        }
        TreeNodeState kept = node;
        if (shape.blanked.count(node.nodeIndex) > 0) {
            kept.publicKey.reset();
            kept.setBy.reset();
        }
        post.nodes.push_back(kept);
    }
    return post;
}

std::vector<std::string> TreeKeys::recipients(const TreeGroupState& state, const CommitShape& shape) {
    const TreeGroupState post = postState(state, shape);
    const std::vector<std::uint32_t> path = TreeMath::keyedPath(shape.committerSeat, shape.numLeaves);
    std::set<std::uint32_t> minted(shape.filledOffPath);
    minted.insert(path.begin(), path.end());
    std::set<std::string> wanted;
    for (const std::uint32_t node : minted) {
        for (const std::uint32_t child : TreeMath::children(node, shape.numLeaves)) {
            // A minted child gets a node edge. Any other child has nothing minted below it (the minted set is closed
            // upwards), so its resolution never depends on what the commit mints.
            if (minted.count(child) > 0) {
                continue;
            }
            for (const std::uint32_t resolved : resolution(post, child)) {
                if (TreeMath::isLeaf(resolved)) {
                    wanted.insert(post.leafAssignment[TreeMath::leafPosition(resolved)].value());
                }
            }
        }
    }
    return std::vector<std::string>(wanted.begin(), wanted.end());
}

CommitPlan TreeKeys::commit(
    const TreeGroupState& state,
    CommitShape shape,
    std::uint32_t epoch,
    const privmx::crypto::PrivateKey& grantKey,
    const privmx::crypto::PrivateKey& signer
) {
    CommitPlan plan;
    plan.epoch = epoch;
    plan.grantKey = grantKey;
    plan.seq = state.commitSeq + 1;
    TreeGroupState post = postState(state, shape);

    // Step 1: a fresh, independent random keypair for every node the commit mints: the off-path fills, then the
    // committer's keyed path, root last. Deriving one from the key it replaces would let whoever held that key compute
    // forward, and the server cannot detect it — confidentiality lives or dies on this line.
    std::vector<std::uint32_t> toMint(shape.filledOffPath.begin(), shape.filledOffPath.end());
    const std::vector<std::uint32_t> path = TreeMath::keyedPath(shape.committerSeat, shape.numLeaves);
    toMint.insert(toMint.end(), path.begin(), path.end());
    std::map<std::uint32_t, privmx::crypto::PrivateKey> minted;
    for (const std::uint32_t node : toMint) {
        RefreshedNode refreshed;
        refreshed.nodeIndex = node;
        refreshed.key = privmx::crypto::PrivateKey::generateRandom();
        const auto record = std::find_if(post.nodes.begin(), post.nodes.end(), [&](const TreeNodeState& n) {
            return n.nodeIndex == node;
        });
        if (record == post.nodes.end()) {
            post.nodes.push_back(TreeNodeState{node, 0, refreshed.key.getPublicKey(), plan.seq});
        } else {
            refreshed.fromGeneration = record->generation;
            refreshed.generation = record->generation + 1;
            *record = TreeNodeState{node, refreshed.generation, refreshed.key.getPublicKey(), plan.seq};
        }
        minted.emplace(node, refreshed.key);
        plan.refreshed.push_back(refreshed);
    }

    // Step 2: each refreshed key wrapped to the resolution of its children on the state AFTER the commit — blanked
    // nodes resolve through to what lies below them, so a removed member's seat simply resolves to nobody.
    for (const RefreshedNode& refreshed : plan.refreshed) {
        for (const std::uint32_t child : TreeMath::children(refreshed.nodeIndex, shape.numLeaves)) {
            for (const std::uint32_t resolved : resolution(post, child)) {
                TreeEdge edge;
                edge.parentIndex = refreshed.nodeIndex;
                edge.parentGeneration = refreshed.generation;
                if (TreeMath::isLeaf(resolved)) {
                    const std::string& userId = post.leafAssignment[TreeMath::leafPosition(resolved)].value();
                    const auto memberPub = memberKey(userId);
                    if (!memberPub.has_value()) {
                        throw std::invalid_argument(
                            "the commit wraps to member " + userId + " and needs their public key; supply it first"
                        );
                    }
                    edge.childKind = EdgeChildKind::User;
                    edge.childUserId = userId;
                    edge.blob = wrapKey(refreshed.key, memberPub.value(), signer);
                } else {
                    const TreeNodeState* target = findNode(post, resolved);
                    edge.childKind = EdgeChildKind::Node;
                    edge.childIndex = resolved;
                    edge.childGeneration = target->generation;
                    const auto own = minted.find(resolved);
                    edge.blob = own != minted.end() ? wrapKey(refreshed.key, own->second.getPublicKey(), signer) :
                                                      wrapKey(refreshed.key, target->publicKey->parsed(), signer);
                }
                plan.edges.push_back(edge);
            }
        }
    }

    // The grant keypair sits above the root, joined by a single edge. Keeping it separate is what stops a commit
    // that is not a removal from advancing the epoch and invalidating every container granted to the group.
    TreeEdge grantEdge;
    grantEdge.isGrantEdge = true;
    grantEdge.parentGeneration = epoch;
    if (shape.numLeaves == 1) {
        const std::string& soleMember = shape.leafAssignment.at(0).value();
        const auto memberPub = memberKey(soleMember);
        if (!memberPub.has_value()) {
            throw std::invalid_argument("the grant edge needs the public key of member " + soleMember);
        }
        grantEdge.childKind = EdgeChildKind::User;
        grantEdge.childUserId = soleMember;
        grantEdge.blob = wrapKey(grantKey, memberPub.value(), signer);
    } else {
        const RefreshedNode& root = plan.refreshed.back();
        grantEdge.childKind = EdgeChildKind::Node;
        grantEdge.childIndex = root.nodeIndex;
        grantEdge.childGeneration = root.generation;
        grantEdge.blob = wrapKey(grantKey, root.key.getPublicKey(), signer);
    }
    plan.edges.push_back(grantEdge);
    // What the statement signs: the post state, every record of it — which is why planning reads them all.
    plan.treeHash = TreeCommits::treeHash(post, &plan.subtreeHashes);
    plan.shape = std::move(shape);
    return plan;
}

privmx::crypto::PrivateKey TreeKeys::currentGrantKey(const TreeGroupState& state) const {
    const auto grantKey = _cache.getGrantKey(state.epoch);
    if (!grantKey.has_value() || !(state.grantPublicKey == grantKey.value().getPublicKey())) {
        throw std::invalid_argument("re-linking the grant edge needs the current grant key; climb the tree first");
    }
    return grantKey.value();
}

CommitPlan TreeKeys::planCreate(
    const std::vector<TreeMember>& members,
    const std::string& creatorId,
    const privmx::crypto::PrivateKey& signer
) {
    std::vector<std::string> memberIds;
    for (const TreeMember& member : members) {
        memberIds.push_back(member.userId);
        _memberKeys.insert_or_assign(member.userId, member.publicKey);
    }
    CommitShape shape = shapeCreate(memberIds, creatorId);
    return commit(TreeGroupState{}, std::move(shape), 1, privmx::crypto::PrivateKey::generateRandom(), signer);
}

CommitPlan TreeKeys::planAddition(
    const TreeGroupState& state,
    const std::vector<TreeMember>& newMembers,
    const std::vector<std::uint32_t>& positions,
    const std::string& adderId,
    const privmx::crypto::PrivateKey& signer
) {
    std::vector<std::string> newMemberIds;
    for (const TreeMember& member : newMembers) {
        newMemberIds.push_back(member.userId);
    }
    CommitShape shape = shapeAddition(state, newMemberIds, positions, adderId);
    for (const TreeMember& member : newMembers) {
        _memberKeys.insert_or_assign(member.userId, member.publicKey);
    }
    return commit(state, std::move(shape), state.epoch, currentGrantKey(state), signer);
}

CommitPlan TreeKeys::planRemoval(
    const TreeGroupState& state,
    const std::vector<std::string>& leavingUserIds,
    const std::string& removerId,
    const privmx::crypto::PrivateKey& signer
) {
    CommitShape shape = shapeRemoval(state, leavingUserIds, removerId);
    // A fresh grant keypair: this is the epoch bump.
    return commit(state, std::move(shape), state.epoch + 1, privmx::crypto::PrivateKey::generateRandom(), signer);
}

CommitPlan TreeKeys::planRotation(
    const TreeGroupState& state,
    const std::string& rotatorId,
    const privmx::crypto::PrivateKey& signer
) {
    const auto seat = positionOf(state, rotatorId);
    if (!seat.has_value()) {
        throw std::invalid_argument("the rotator " + rotatorId + " holds no leaf in this tree");
    }
    CommitPlan plan;
    plan.shape.numLeaves = state.numLeaves;
    plan.shape.leafAssignment = state.leafAssignment;
    plan.shape.committerSeat = seat.value();
    plan.epoch = state.epoch + 1;
    // A fresh grant keypair, independent of the one it replaces: this is the epoch bump.
    plan.grantKey = privmx::crypto::PrivateKey::generateRandom();
    plan.seq = state.commitSeq + 1;
    TreeEdge grantEdge;
    grantEdge.isGrantEdge = true;
    grantEdge.parentGeneration = plan.epoch;
    const std::uint32_t root = TreeMath::root(state.numLeaves);
    if (TreeMath::isLeaf(root)) {
        // The one seat is the rotator's, so the edge goes to the rotator's own key, which `signer` is: nothing is
        // fetched from the directory (T3-27).
        grantEdge.childKind = EdgeChildKind::User;
        grantEdge.childUserId = rotatorId;
        grantEdge.blob = wrapKey(plan.grantKey, signer.getPublicKey(), signer);
    } else {
        const TreeNodeState* record = findNode(state, root);
        if (record == nullptr || !record->publicKey.has_value()) {
            throw std::invalid_argument("the root holds no key to wrap the new grant key to");
        }
        grantEdge.childKind = EdgeChildKind::Node;
        grantEdge.childIndex = root;
        grantEdge.childGeneration = record->generation;
        grantEdge.blob = wrapKey(plan.grantKey, record->publicKey->parsed(), signer);
    }
    plan.edges.push_back(grantEdge);
    plan.treeHash = TreeCommits::treeHash(state, &plan.subtreeHashes);
    return plan;
}

CommitPlan TreeKeys::planSelfUpdate(
    const TreeGroupState& state,
    const std::string& memberId,
    const privmx::crypto::PrivateKey& signer
) {
    CommitShape shape = shapeSelfUpdate(state, memberId);
    return commit(state, std::move(shape), state.epoch, currentGrantKey(state), signer);
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
