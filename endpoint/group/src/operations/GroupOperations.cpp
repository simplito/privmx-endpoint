/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include "privmx/endpoint/group/GroupOperations.hpp"

#include <algorithm>

#include <privmx/endpoint/core/ConnectionImpl.hpp>
#include <privmx/endpoint/core/CoreException.hpp>
#include <privmx/endpoint/core/EndpointUtils.hpp>
#include <privmx/endpoint/core/Factory.hpp>
#include <privmx/utils/Utils.hpp>

#include "privmx/endpoint/group/Constants.hpp"
#include "privmx/endpoint/group/GroupException.hpp"
#include "privmx/endpoint/group/keytree/GroupKeyResolver.hpp"
#include "privmx/endpoint/group/keytree/LadderKeys.hpp"
#include "privmx/endpoint/group/keytree/LadderMath.hpp"
#include "privmx/endpoint/group/keytree/TreeCommits.hpp"
#include "privmx/endpoint/group/keytree/TreeMath.hpp"
#include "privmx/endpoint/group/keytree/TreeWire.hpp"
#include "privmx/utils/Logger.hpp"

using namespace privmx::endpoint;
using namespace group;

namespace {

// A rotation's floor off an archive read after the group's. Past the group's epoch, another member's prune or era cut
// and rotation came in between: planned again on a fresh read, never signed with no rung at all, and not remembered.
std::uint32_t rotationFloorOf(
    const privmx::endpoint::group::server::GroupInfo& group,
    const privmx::endpoint::group::server::GroupGetKeyArchiveResult& archive
) {
    const std::uint32_t floor = ladderFloorOf(archive.eraFloor, archive.archivePrunedBelow, newestEpoch(group, archive));
    if (floor > group.keyVersion) {
        throw privmx::endpoint::group::StalePlan{};
    }
    return floor;
}

// The rules of a policy the caller asks to sign: one outside the group grammar is the caller's error.
keytree::GroupRules requestedRules(const Poco::Dynamic::Var& policy, const std::string& creator) {
    try {
        return keytree::TreeCommits::rules(policy, creator);
    } catch (const std::invalid_argument& e) {
        throw core::InvalidParamsException(e.what());
    }
}

// The verified read a plan climbs. An unseated one is refused, at the point of the plan where the climb would be: a
// group without a key tree, one with a tree this client does not support, or a caller without a seat.
const VerifiedGroup& planOn(const GroupRead& read) {
    if (read.verified.has_value()) {
        return read.verified.value();
    }
    if (!keytree::GroupKeyResolver::hasTree(read.unseated)) {
        throw core::EncryptionKeyValidationException("this group is not backed by a key tree");
    }
    if (!keytree::GroupKeyResolver::hasSupportedTree(read.unseated)) {
        keytree::ResolveResult asResolve;
        asResolve.failure = keytree::ResolveFailure::UnsupportedTreeVersion;
        throw core::EncryptionKeyValidationException(describeResolveFailure(asResolve));
    }
    throw core::EncryptionKeyValidationException("caller holds no leaf in this group's key tree");
}

// The keytree module reports impossible requests as `std::invalid_argument`, having no dependency on the endpoint's
// exception hierarchy. Letting one escape the SDK boundary would `std::terminate` a caller catching core::Exception.
template<typename TPlan>
TPlan planOrThrow(const std::function<TPlan()>& build) {
    try {
        return build();
    } catch (const std::invalid_argument& e) {
        throw core::EncryptionKeyValidationException(std::string("key tree operation is not possible: ") + e.what());
    }
}

std::vector<keytree::TreeMember> toTreeMembers(
    const std::vector<core::UserWithPubKey>& users,
    const std::vector<core::UserWithPubKey>& managers
) {
    std::vector<keytree::TreeMember> members;
    std::map<std::string, std::string> seen; // user id -> the key that took their leaf

    std::vector<core::UserWithPubKey> all;
    all.insert(all.end(), users.begin(), users.end());
    all.insert(all.end(), managers.begin(), managers.end());
    std::sort(all.begin(), all.end(), [](const core::UserWithPubKey& a, const core::UserWithPubKey& b) {
        return a.userId < b.userId;
    });
    for (const core::UserWithPubKey& user : all) {
        const auto inserted = seen.emplace(user.userId, user.pubKey);
        if (!inserted.second) {
            if (inserted.first->second != user.pubKey) {
                throw core::InvalidParamsException("user '" + user.userId + "' is listed with two different public keys");
            }
            continue; // a manager listed as a user too gets one leaf, not two
        }
        members.push_back(keytree::TreeMember{user.userId, privmx::crypto::PublicKey::fromBase58DER(user.pubKey)});
    }
    return members;
}

} // namespace

std::map<std::string, std::string> GroupOperations::commitRecipientKeys(
    const server::GroupInfo& group,
    const std::vector<std::string>& recipients,
    const std::string& ownUserId,
    const std::set<std::string>& newcomers
) const {
    std::vector<std::string> toResolve;
    for (const std::string& userId : recipients) {
        if (userId != ownUserId && newcomers.count(userId) == 0) {
            toResolve.push_back(userId);
        }
    }
    std::map<std::string, std::string> recipientKeys = deps.facade.resolveMemberKeys(group.contextId, toResolve);
    recipientKeys[ownUserId] = deps.userPrivKey.getPublicKey().toBase58DER();
    return recipientKeys;
}

bool GroupOperations::climbsWithPreviousIdentity(const keytree::TreeGroupState& state, const std::string& memberId) const {
    const std::vector<privmx::crypto::PrivateKey> previous = deps.connection.getImpl()->previousIdentities();
    return std::any_of(previous.begin(), previous.end(), [&](const privmx::crypto::PrivateKey& key) {
        keytree::TreeKeyCache scratch;
        return keytree::TreeKeys(scratch).climbToGrantKey(state, memberId, key, false).failure ==
            keytree::ClimbFailure::None;
    });
}

keytree::TreeGroupState GroupOperations::climbForPlanning(
    const VerifiedGroup& group,
    const std::shared_ptr<keytree::TreeKeyCache>& cache,
    const std::vector<std::string>* removing,
    const privmx::crypto::PrivateKey* climbKey
) const {
    // A verified read holds the caller's seat in a tree this client supports.
    const auto identity = keytree::GroupKeyResolver::ownUserId(group);
    const keytree::TreeGroupState state = keytree::GroupKeyResolver::toTreeState(group);
    keytree::TreeKeys tree(*cache);
    // Walk even when the grant key is already cached: a plan needs the node keys along the path, and the cache
    // would otherwise satisfy the request without ever recovering them.
    const keytree::ClimbResult climb = tree.climbToGrantKey(
        state, identity.value(), climbKey != nullptr ? *climbKey : deps.userPrivKey, false
    );
    if (climb.failure != keytree::ClimbFailure::None || !climb.grantKey.has_value()) {
        keytree::ResolveResult asResolve;
        asResolve.failure = keytree::ResolveFailure::ClimbFailed;
        asResolve.climb = climb.failure;
        if (climb.failure == keytree::ClimbFailure::Tampered || climb.failure == keytree::ClimbFailure::DecryptFailed ||
            climb.failure == keytree::ClimbFailure::LeafDidNotOpen) {
            asResolve.blame = keytree::GroupKeyResolver::tamperedBy(group, climb.tamperedNode);
        }
        if (climbKey != nullptr && climb.failure == keytree::ClimbFailure::LeafDidNotOpen) {
            // A renewal: the previous key does not open the leaf either, so renewLeaf cannot help here.
            throw core::EncryptionKeyValidationException(
                "Group key unavailable: the edge to your own leaf opens neither with your current key nor with the "
                "previous one; ask a manager to remove and re-add you, or remove the member that wrote it" +
                blameSuffix(asResolve.blame)
            );
        }
        // Garbled wraps must not let whoever garbled them block their own removal: the state is verified, and a
        // removal wraps only fresh keys to public ones, so it plans without the climb whatever the blame says. The one
        // exception uses no server data: a leaf that does not open with the session's key but climbs with a previous
        // identity key this client was given (adoptPreviousIdentity) is our own key change, and renewLeaf restores
        // it; planning on would abandon every member's history for nothing, unless the grant key is cached and
        // history stays reachable anyway (a landed renewal caches it, so a member re-wrapping the leaf edge to the
        // previous public key cannot bring the refusal back within the epoch). A garbled edge above the leaf opens with neither key, so renewLeaf cannot
        // fix it and the removal goes on; so does one after a key changed without adoptPreviousIdentity (base
        // behaviour: the removal abandons history).
        if (removing != nullptr && climb.failure != keytree::ClimbFailure::NotAMember) {
            const auto cachedGrantKey = cache->getGrantKey(keytree::GroupKeyResolver::epochOf(group->keyVersion));
            const bool historyStillReachable =
                cachedGrantKey.has_value() &&
                cachedGrantKey->getPublicKey().toBase58DER() == keytree::TreeVerifier::canonicalKey(group->groupPubKey);
            const bool ownKeyChange = climb.failure == keytree::ClimbFailure::LeafDidNotOpen &&
                !historyStillReachable && climbsWithPreviousIdentity(state, identity.value());
            if (!ownKeyChange) {
                LOG_WARN("[climbForPlanning] planning without the climb: ", describeResolveFailure(asResolve))
                return state;
            }
        }
        throw core::EncryptionKeyValidationException(describeResolveFailure(asResolve));
    }
    if (climbKey == nullptr) {
        deferred.scheduleSelfUpdateIfNeeded(group->id, group);
    }
    return state;
}

std::string GroupOperations::create(
    const std::string& contextId,
    const std::vector<core::UserWithPubKey>& users,
    const std::vector<core::UserWithPubKey>& managers,
    const core::Buffer& publicMeta,
    const core::Buffer& privateMeta,
    const std::optional<core::ContainerPolicy>& policies
) const {
    // The creator commits from a seat of its own, like any committer. Checked by
    // key first, which needs no request; the id the seat is planned under is checked again once it is known.
    const std::vector<keytree::TreeMember> members = toTreeMembers(users, managers);
    const privmx::crypto::PublicKey ownKey = deps.userPrivKey.getPublicKey();
    if (std::none_of(members.begin(), members.end(), [&](const keytree::TreeMember& m) {
            return m.publicKey == ownKey;
        })) {
        throw core::InvalidParamsException("the creator of a group must be one of its users or managers");
    }

    // Empty rosters: the metadata key is wrapped once to the group's own grant key, and members open it by climbing.
    auto ctx = deps.facade.prepareCreate(contextId);
    const std::string creatorId = ctx.dio.creatorUserId;
    if (std::none_of(members.begin(), members.end(), [&](const keytree::TreeMember& m) {
            return m.userId == creatorId && m.publicKey == ownKey;
        })) {
        throw core::InvalidParamsException("the creator of a group must be one of its users or managers");
    }
    // Each seat is filled to the key given for it, and those keys are as good as the listing they came from.
    deps.facade.assertUserKeysVerified(contextId, core::EndpointUtils::uniqueListUserWithPubKey(users, managers));
    keytree::TreeKeyCache scratch; // the group has no id yet
    keytree::TreeKeys builder(scratch);
    const keytree::CommitPlan plan = planOrThrow<keytree::CommitPlan>([&] {
        return builder.planCreate(members, creatorId, deps.userPrivKey);
    });
    const std::string groupPubKeyStr = plan.grantKey.getPublicKey().toBase58DER();

    // All three planes start at 1 under the same epoch-1 content key, with `internalMeta` on the roster only.
    // The three DIOs must not share a `randomId`, or a replay check sees them as one entry served three times.
    const core::ModuleInternalMetaV5 internalMeta{
        .secret = ctx.secret, .resourceId = ctx.resourceId, .randomId = ctx.dio.randomId
    };
    core::DataIntegrityObject publicMetaDio = ctx.dio;
    publicMetaDio.randomId = core::EndpointUtils::generateDIORandomId();
    core::DataIntegrityObject privateMetaDio = ctx.dio;
    privateMetaDio.randomId = core::EndpointUtils::generateDIORandomId();
    GroupRosterToEncryptV5 rosterToEncrypt{
        .internalMeta = internalMeta,
        .dio = ctx.dio,
        .membership = buildMembershipBlock(ctx.key, groupPubKeyStr, 1, 1, users, managers)
    };
    GroupPublicMetaToEncryptV5 publicMetaToEncrypt{
        .publicMeta = publicMeta,
        .dio = publicMetaDio,
        .meta = dynamic::MetaBlock{
            .metaTag = GroupDataSchemaMapper::publicMetaTag(ctx.key.key, 1, 1),
            .keyId = ctx.key.id,
            .keyVersion = 1,
            .metaVersion = 1
        }
    };
    GroupPrivateMetaToEncryptV5 privateMetaToEncrypt{
        .privateMeta = privateMeta,
        .dio = privateMetaDio,
        .meta = dynamic::MetaBlock{
            .metaTag = GroupDataSchemaMapper::privateMetaTag(ctx.key.key, 1, 1),
            .keyId = ctx.key.id,
            .keyVersion = 1,
            .metaVersion = 1
        }
    };

    server::GroupCreateModel model;
    model.resourceId = ctx.resourceId;
    model.contextId = contextId;
    model.keyId = ctx.key.id;
    model.data = mapper.encryptRoster(rosterToEncrypt, ctx.key.key);
    model.publicMeta = mapper.encryptPublicMeta(publicMetaToEncrypt);
    model.privateMeta = mapper.encryptPrivateMeta(privateMetaToEncrypt, ctx.key.key);
    model.users = core::EndpointUtils::usersWithPubKeyToIds(users);
    model.managers = core::EndpointUtils::usersWithPubKeyToIds(managers);
    model.groupPubKey = groupPubKeyStr;
    model.type = GROUP_TYPE_FILTER_FLAG;
    const auto selfAddressed = deps.facade.buildGroupKeyEntries(
        {core::GroupGrantWithKey{
            .groupId = std::string(),
            .role = "manager",
            .groupPubKey = groupPubKeyStr,
            .groupEpoch = 1,
        }},
        ctx.key, ctx.dio, contextId, ctx.resourceId, ctx.secret
    );
    model.groupKeys = server::GroupKeyEntrySetForNewGroup{
        .keyId = selfAddressed.at(0).keyId, .groupEpoch = 1, .data = selfAddressed.at(0).data
    };
    model.tree = keytree::TreeWire::toCreateTree(plan);
    // The policy is signed into the chain: the statement carries it, and every later one its hash.
    const Poco::Dynamic::Var policy = core::Factory::createPolicyServerObject(policies.value_or(core::ContainerPolicy{}));
    const keytree::GroupRules rules = requestedRules(policy, creatorId);
    // Commit B: a creator who could not write its own metadata would leave every member's read of the new group
    // refused. Refused before anything is signed.
    const std::vector<std::string> managerIds = core::EndpointUtils::usersWithPubKeyToIds(managers);
    const bool creatorManages = std::find(managerIds.begin(), managerIds.end(), creatorId) != managerIds.end();
    if (!keytree::TreeCommits::allows(rules.update, true, creatorManages, true)) {
        throw core::InvalidParamsException("the creator must hold update under the group's policy to write its metadata");
    }
    // The group has no id until the bridge stores it, so the first statement names the resourceId instead.
    keytree::CommitStatement statement = keytree::TreeCommits::statementFor(
        plan, keytree::CommitOp::Create, ctx.resourceId, commitDate(), 1, groupPubKeyStr, 1,
        core::EndpointUtils::usersWithPubKeyToIds(users), core::EndpointUtils::usersWithPubKeyToIds(managers),
        creatorId, {}, {}, {}, // the genesis roster is bound by rosterHash; the bridge serves it beside the chain
        rules.hash
    );
    statement.policy = policy;
    keytree::TreeCommits::sign(statement, deps.userPrivKey);
    model.commit = keytree::TreeCommits::toWire(statement);

    auto result = deps.serverApi.groupCreate(model);
    // The bridge derives the id from the signed resourceId; any other id is not the group this statement created.
    if (result.groupId != keytree::TreeCommits::groupId(contextId, ctx.resourceId)) {
        throw GroupDataIntegrityException("the new group's id does not follow from its resourceId");
    }
    deps.treeVerifier.pinCommitted(
        result.groupId, contextId, statement, core::EndpointUtils::usersWithPubKeyToIds(users),
        core::EndpointUtils::usersWithPubKeyToIds(managers), rules
    );
    deps.facade.savePins(); // an own commit is in the store before the call returns
    const auto cache = deps.sessions.of(result.groupId)->treeKeys();
    cache->putGrantKey(1, plan.grantKey);
    return result.groupId;
}

void GroupOperations::add(const std::string& groupId, const std::vector<GroupMemberToAdd>& newMembers) const {
    // What the caller asked for, as `settle` tells one op from another: each newcomer's id, role and key, by id.
    std::vector<const GroupMemberToAdd*> byId;
    for (const GroupMemberToAdd& newMember : newMembers) {
        byId.push_back(&newMember);
    }
    std::stable_sort(byId.begin(), byId.end(), [](const GroupMemberToAdd* a, const GroupMemberToAdd* b) {
        return a->user.userId < b->user.userId;
    });
    std::vector<std::string> opParts;
    for (const GroupMemberToAdd* newMember : byId) {
        opParts.insert(opParts.end(), {newMember->user.userId, newMember->role, newMember->user.pubKey});
    }
    const std::string op = keytree::TreeCommits::opKey("add", opParts);
    // One read, not two: the bridge holds the roster, so it allocates the seats and serves every node record the
    // plan resolves through in the same answer.
    const std::optional<GroupRead> settled = engine.readForCommit(
        planRead(groupId, std::nullopt, static_cast<std::int64_t>(newMembers.size())),
        keytree::TreeVerifier::Scope::Plan, op
    );
    if (!settled.has_value()) {
        return;
    }
    const GroupRead& read = settled.value();
    const server::GroupInfo& currentGroup = read.group();
    const auto resourceId = currentGroup.resourceId.value_or(core::EndpointUtils::generateId());
    const int64_t currentEpoch = currentGroup.keyVersion;
    // The bridge pins this in its compare-and-swap, so the entry lands here or the call is refused — which is
    // what lets the tag below commit to it.
    const int64_t newRosterVersion = currentGroup.rosterVersion + 1;

    // The roster this call signs has to be the one the head attests to, not one the caller restated or the bridge
    // asserted. Roster plane only — seating a member is not a metadata edit, so it does not open that entry.
    const auto [attestedUsers, attestedManagers] =
        mapper.validateAndGetAttestedRoster(currentGroup, keyProvider, groupPrivKeyResolver);
    keytree::TreeVerifier::assertSeatsMatchRoster(currentGroup, attestedUsers, attestedManagers);
    // And never anybody already on it: an addition cannot promote a member, and a seat cannot be planned twice.
    for (const GroupMemberToAdd& newMember : newMembers) {
        for (const auto* list : {&attestedUsers, &attestedManagers}) {
            if (std::find(list->begin(), list->end(), newMember.user.userId) != list->end()) {
                throw core::InvalidParamsException("user '" + newMember.user.userId + "' is already a member");
            }
        }
    }

    const auto& allocated = currentGroup.nextFreeSeats;
    if (!allocated.has_value() || allocated.value().size() != newMembers.size()) {
        throw core::Exception("bridge did not allocate a seat for every newcomer");
    }

    // Handle for the whole operation
    const auto cache = deps.sessions.of(groupId)->treeKeys();
    const VerifiedGroup& verified = planOn(read);
    const keytree::TreeGroupState state = climbForPlanning(verified, cache);
    // The bridge's seat numbers index the plan's arrays: each must be a free seat of the tree the newcomers grow (H2).
    const auto seatLimit = static_cast<std::int64_t>(state.numLeaves) + static_cast<std::int64_t>(newMembers.size());
    std::vector<std::uint32_t> positions;
    for (const std::int64_t seat : allocated.value()) {
        if (seat < 0 || seat >= seatLimit ||
            (seat < static_cast<std::int64_t>(state.numLeaves) && state.leafAssignment.at(seat).has_value())) {
            throw GroupDataIntegrityException("the bridge allocated a seat that is taken or out of range");
        }
        positions.push_back(static_cast<std::uint32_t>(seat));
    }
    const std::string adderId = keytree::GroupKeyResolver::ownUserId(currentGroup).value();

    // The roster after the change, derived rather than restated. Bare ids: nothing here wraps a key to them,
    // so the public keys the caller used to supply were never read.
    RosterAfterChange roster = rosterFromUserIds(attestedUsers, attestedManagers);
    server::GroupAddMembersModel model;
    std::vector<core::UserWithPubKey> newcomerKeys;
    std::vector<keytree::TreeMember> treeNewcomers;
    std::vector<std::string> newcomerIds;
    std::vector<std::string> addedUsers;
    std::vector<std::string> addedManagers;
    for (const GroupMemberToAdd& newMember : newMembers) {
        const std::string& id = newMember.user.userId;
        const bool manager = newMember.role == "manager";
        newcomerKeys.push_back(newMember.user);
        treeNewcomers.push_back(keytree::TreeMember{id, privmx::crypto::PublicKey::fromBase58DER(newMember.user.pubKey)});
        newcomerIds.push_back(id);
        (manager ? roster.managers : roster.users).push_back(core::UserWithPubKey{.userId = id, .pubKey = std::string()});
        (manager ? addedManagers : addedUsers).push_back(id);
        model.members.push_back(server::GroupAddMemberEntry{.userId = id, .role = newMember.role});
    }
    // The newcomers' paths are filled to these keys, as the caller's word for them; existing members' keys go through
    // the same check in `commitRecipientKeys`.
    deps.facade.assertUserKeysVerified(currentGroup.contextId, newcomerKeys);
    keytree::TreeKeys tree(*cache);
    // Only the members the minted nodes wrap to, which the buckets keep to a handful per node.
    tree.setMemberKeyStrings(commitRecipientKeys(
        currentGroup, planOrThrow<std::vector<std::string>>([&] {
            return keytree::TreeKeys::recipients(
                state, keytree::TreeKeys::shapeAddition(state, newcomerIds, positions, adderId)
            );
        }),
        adderId, std::set<std::string>(newcomerIds.begin(), newcomerIds.end())
    ));
    const keytree::CommitPlan plan = planOrThrow<keytree::CommitPlan>([&] {
        return tree.planAddition(state, treeNewcomers, positions, adderId, deps.userPrivKey);
    });

    // No new epoch
    auto ctx = deps.facade.prepareUpdate(currentGroup, resourceId, roster, false);
    // Roster only. The metadata entry is not read, not re-encrypted and not re-signed — that is the separation
    // that stops a concurrent metadata write from stranding this write at a version it never committed to.
    GroupRosterToEncryptV5 rosterToEncrypt{
        .internalMeta = core::
            ModuleInternalMetaV5{.secret = ctx.secret, .resourceId = resourceId, .randomId = ctx.dio.randomId},
        .dio = ctx.dio,
        .membership = buildMembershipBlock(
            ctx.key, currentGroup.groupPubKey, currentEpoch, newRosterVersion, roster.users, roster.managers
        )
    };

    model.id = groupId;
    model.keyId = ctx.key.id;
    model.data = mapper.encryptRoster(rosterToEncrypt, ctx.key.key);
    model.transition = keytree::TreeWire::toAdditionTransition(plan, currentEpoch);
    model.expectedKeyVersion = currentEpoch;
    model.expectedRosterVersion = currentGroup.rosterVersion;
    const keytree::GroupRules rules = rulesOf(verified);
    const std::vector<std::string> users = core::EndpointUtils::usersWithPubKeyToIds(roster.users);
    const std::vector<std::string> managers = core::EndpointUtils::usersWithPubKeyToIds(roster.managers);
    keytree::CommitStatement statement = keytree::TreeCommits::statementFor(
        plan, keytree::CommitOp::Add, groupId, commitDate(), static_cast<std::uint64_t>(currentEpoch),
        currentGroup.groupPubKey, static_cast<std::uint64_t>(newRosterVersion), users, managers, adderId, addedUsers,
        addedManagers, {}, rules.hash
    );
    engine.chainTo(statement, verified);
    keytree::TreeCommits::sign(statement, deps.userPrivKey);
    model.commit = keytree::TreeCommits::toWire(statement);
    const auto sent = std::make_shared<const server::GroupAddMembersModel>(std::move(model));
    engine.submit(
        groupId, statement,
        UnresolvedCommit{
            .op = op,
            .namesEndState = true,
            .kind = "add",
            .contextId = currentGroup.contextId,
            .newcomers = newcomerKeys,
            .send = [&serverApi = deps.serverApi, sent] { serverApi.groupAddMembers(*sent); },
            .landed =
                [&treeVerifier = deps.treeVerifier, invalidate = deps.facade.invalidateModuleKeys, groupId,
                 contextId = currentGroup.contextId, statement, users, managers, rules] {
                    treeVerifier.pinCommitted(groupId, contextId, statement, users, managers, rules);
                    invalidate(groupId);
                }
        }
    );
}

std::vector<keytree::ArchiveRung> GroupOperations::buildRotationRungs(
    const VerifiedGroup& group,
    std::uint32_t newEpoch,
    const privmx::crypto::PrivateKey& newGrantKey,
    const std::optional<privmx::crypto::PrivateKey>& previousEpochKey,
    const std::string& author,
    keytree::TreeKeyCache& cache
) const {
    keytree::LadderKeys ladder(cache);
    // Never a floor lower than one this session has seen: a bridge under-reporting it gets no rung below it.
    std::uint32_t floor = cache.raiseFloor(ladderFloorOf(group->eraFloor.value_or(1), group->archivePrunedBelow, group->keyVersion));
    // What the rungs are checked against before submitting: the chain, never the cache. Without skip targets that is
    // the verified group's own key (the unit rung's target); with them, the openers' keys (`fetchKeyArchive`).
    std::vector<keytree::EpochRegistryEntry> registry{
        {keytree::GroupKeyResolver::epochOf(group->keyVersion), privmx::crypto::PublicKey::fromBase58DER(group->groupPubKey)}
    };
    const std::vector<std::uint32_t> targets = keytree::LadderKeys::requiredSkipTargets(newEpoch, floor);
    if (!targets.empty()) {
        // The gather descends from the previous epoch through each target not held yet, nearest first: those
        // canonical paths are all it reads. Only if a rung on them fails is the whole window read, as before.
        std::vector<keytree::RungSpan> path;
        std::uint32_t from = newEpoch - 1;
        for (const std::uint32_t target : targets) {
            if (!cache.getGrantKey(target).has_value()) {
                const auto leg = keytree::LadderMath::canonicalDescent(from, target, floor);
                path.insert(path.end(), leg.begin(), leg.end());
            }
            from = target;
        }
        server::GroupGetKeyArchiveResult archive = keys.fetchKeyArchive(group, path);
        floor = cache.raiseFloor(rotationFloorOf(group, archive));
        registry = keytree::GroupKeyResolver::registryFromArchive(group, archive);
        keytree::RungKeyGathering gathered = ladder.gatherRungKeys(
            newEpoch, keytree::GroupKeyResolver::toDownwardRungs(archive), registry, floor
        );
        if (!gathered.complete) {
            archive = keys.fetchKeyArchive(group, static_cast<int64_t>(targets.back()), static_cast<int64_t>(newEpoch - 1));
            floor = cache.raiseFloor(rotationFloorOf(group, archive));
            registry = keytree::GroupKeyResolver::registryFromArchive(group, archive);
            gathered = ladder.gatherRungKeys(newEpoch, keytree::GroupKeyResolver::toDownwardRungs(archive), registry, floor);
        }
        LOG_DEBUG(
            "ladder gather for epoch ",
            std::to_string(newEpoch) +
                ": " +
                std::to_string(gathered.unwraps) +
                " unwraps for " +
                std::to_string(targets.size()) +
                " skip target(s)"
        )
        if (!gathered.complete) {
            throw IncompleteEpochLadderException();
        }
    }
    if (floor > group->keyVersion) {
        throw StalePlan{}; // a floor seen since by another read of this session: the same race
    }
    const std::vector<keytree::ArchiveRung> rungs = planOrThrow<std::vector<keytree::ArchiveRung>>([&] {
        return ladder.buildRungs(
            newEpoch, newGrantKey.getPublicKey(), previousEpochKey, floor, author, deps.userPrivKey
        );
    });
    // A rung is publishable only at its own epoch, so one sealing a wrong cached key (a client bug) would be a broken
    // rung forever. Nothing is submitted then; the target is forgotten so the next attempt re-gathers it by descent.
    if (const auto bad = keytree::LadderKeys::firstRungNotOpeningToTheChain(rungs, newGrantKey, registry)) {
        cache.forgetGrantKey(bad->target);
        throw GroupDataIntegrityException(
            "a rung of this commit does not open to its target's key: " +
            std::to_string(bad->at) + "->" + std::to_string(bad->target)
        );
    }
    return rungs;
}

std::optional<bool> GroupOperations::remove(
    const std::string& groupId,
    const std::vector<std::string>& userIds,
    PriorRole& prior
) const {
    // Every departing member's path, because one commit covers their union — and one epoch covers the batch, where
    // removing them one at a time would stale every container the group can read once per member.
    std::vector<std::string> leavingIds = userIds;
    std::sort(leavingIds.begin(), leavingIds.end());
    leavingIds.erase(std::unique(leavingIds.begin(), leavingIds.end()), leavingIds.end());
    const std::string op = keytree::TreeCommits::opKey("remove", leavingIds);
    const std::optional<GroupRead> settled = engine.readForCommit(
        planRead(groupId, userIds), keytree::TreeVerifier::Scope::Plan, op
    );
    if (!settled.has_value()) {
        return std::nullopt;
    }
    const GroupRead& read = settled.value();
    const server::GroupInfo& currentGroup = read.group();
    // The verified read's rules and roster judge the planes the removal carries (the removed with the role they had).
    prior = priorOf(currentGroup);
    // Refused before anything is planned: the remover mints the next epoch's grant key, so a member removing itself
    // would walk out holding the key meant to lock it out. The bridge refuses it too.
    const std::string self = deps.connection.getImpl()->getMyUserId(currentGroup.contextId);
    if (std::find(userIds.begin(), userIds.end(), self) != userIds.end()) {
        throw core::InvalidParamsException("a member cannot remove themselves from a group");
    }
    const int64_t currentEpoch = currentGroup.keyVersion;
    const int64_t newEpoch = currentEpoch + 1;
    const int64_t newRosterVersion = currentGroup.rosterVersion + 1;

    const auto cache = deps.sessions.of(groupId)->treeKeys();
    const VerifiedGroup& verified = planOn(read);
    const keytree::TreeGroupState state = climbForPlanning(verified, cache, &userIds);
    // Without the current grant key (a broken climb and nothing cached) the removal still goes through, and the
    // epochs before it become unreachable. A malicious bridge can force this by garbling edges (edges are not in
    // the tree hash) — it could destroy history anyway.
    auto currentGrantKey = cache->getGrantKey(keytree::GroupKeyResolver::epochOf(currentEpoch));
    if (currentGrantKey.has_value() &&
        currentGrantKey->getPublicKey().toBase58DER() != keytree::TreeVerifier::canonicalKey(currentGroup.groupPubKey)) {
        currentGrantKey.reset(); // not the epoch's key: wrapped into the unit rung it would cut history off anyway
    }
    const bool abandonHistory = !currentGrantKey.has_value();
    // Roster plane only: a removal must not wait on a metadata entry that may sit at an older epoch. With history
    // abandoned the entry cannot be opened; the served roster, bound to the signed latest statement by
    // `verifyTree`'s roster hash, stands in for it.
    const auto [attestedUsers, attestedManagers] = abandonHistory ?
        std::make_pair(currentGroup.users, currentGroup.managers) :
        mapper.validateAndGetAttestedRoster(currentGroup, keyProvider, groupPrivKeyResolver);
    keytree::TreeVerifier::assertSeatsMatchRoster(currentGroup, attestedUsers, attestedManagers);
    const std::string removerId = keytree::GroupKeyResolver::ownUserId(currentGroup).value();

    // Handle for the whole operation
    keytree::TreeKeys tree(*cache);
    // Only the members the remover's path wraps to — never the departing ones, whose seats resolve to nobody.
    tree.setMemberKeyStrings(commitRecipientKeys(
        currentGroup, planOrThrow<std::vector<std::string>>([&] {
            return keytree::TreeKeys::recipients(state, keytree::TreeKeys::shapeRemoval(state, userIds, removerId));
        }),
        removerId
    ));
    const keytree::CommitPlan plan = planOrThrow<keytree::CommitPlan>([&] {
        return tree.planRemoval(state, userIds, removerId, deps.userPrivKey);
    });
    const std::vector<keytree::ArchiveRung> rungs = abandonHistory ?
        std::vector<keytree::ArchiveRung>{} :
        buildRotationRungs(
            verified, keytree::GroupKeyResolver::epochOf(newEpoch), plan.grantKey, currentGrantKey, removerId, *cache
        );
    // The roster that remains, derived from the verified head rather than restated by the caller.
    const std::set<std::string> leaving(userIds.begin(), userIds.end());
    RosterAfterChange roster = rosterFromUserIds(attestedUsers, attestedManagers);
    const auto drop = [&](std::vector<core::UserWithPubKey>& list) {
        list.erase(
            std::remove_if(
                list.begin(), list.end(), [&](const core::UserWithPubKey& u) { return leaving.count(u.userId) > 0; }
            ),
            list.end()
        );
    };
    drop(roster.users);
    drop(roster.managers);

    const std::string newGroupPubKeyStr = plan.grantKey.getPublicKey().toBase58DER();
    const NewEpochRoster sealed = metadata.sealRosterForNewEpoch(
        currentGroup, roster, newGroupPubKeyStr, newEpoch, newRosterVersion, abandonHistory
    );

    // Seats come from the plan, which resolved them from the roster the bridge served. `subjectLeafPositions`
    // carries the same answer; keeping the plan as the single source stops the two from ever disagreeing.
    server::GroupRemoveMembersModel model;
    model.id = groupId;
    model.userIds = userIds;
    model.groupPubKey = newGroupPubKeyStr;
    model.keyId = sealed.keyId;
    model.data = sealed.data;
    model.transition = keytree::TreeWire::toRemovalTransition(plan, currentEpoch);
    model.rungs = keytree::TreeWire::toWire(rungs);
    if (abandonHistory) {
        model.abandonHistory = true;
    }
    model.groupKeys = sealed.groupKeys;
    model.expectedKeyVersion = currentEpoch;
    model.expectedRosterVersion = currentGroup.rosterVersion;
    const keytree::GroupRules rules = rulesOf(verified);
    keytree::CommitStatement statement = keytree::TreeCommits::statementFor(
        plan, keytree::CommitOp::Remove, groupId, commitDate(), static_cast<std::uint64_t>(newEpoch), newGroupPubKeyStr,
        static_cast<std::uint64_t>(newRosterVersion), core::EndpointUtils::usersWithPubKeyToIds(roster.users),
        core::EndpointUtils::usersWithPubKeyToIds(roster.managers), removerId, {}, {}, userIds, rules.hash
    );
    engine.chainTo(statement, verified);
    keytree::TreeCommits::sign(statement, deps.userPrivKey);
    model.commit = keytree::TreeCommits::toWire(statement);
    const auto sent = std::make_shared<const server::GroupRemoveMembersModel>(std::move(model));
    engine.submit(
        groupId, statement,
        UnresolvedCommit{
            .op = op,
            .namesEndState = true,
            .kind = "remove",
            .contextId = currentGroup.contextId,
            .send = [&serverApi = deps.serverApi, sent] { serverApi.groupRemoveMembers(*sent); },
            // Pinned before anything reads the group again, or the next read could be the state with the leaver
            // still in.
            .landed = landedEpoch(currentGroup.contextId, statement, roster, rules, plan.grantKey),
            .after =
                [&metadata = metadata, groupId, abandonHistory, userIds, prior] {
                    metadata.carryMetadataForward(groupId, CarryScope::NewEpoch, abandonHistory, userIds, prior);
                }
        }
    );
    return abandonHistory;
}

std::function<void()> GroupOperations::landedEpoch(
    const std::string& contextId,
    const keytree::CommitStatement& statement,
    const RosterAfterChange& roster,
    const keytree::GroupRules& rules,
    const privmx::crypto::PrivateKey& grantKey
) const {
    return [&treeVerifier = deps.treeVerifier, &sessions = deps.sessions, &deferred = deferred,
            invalidate = deps.facade.invalidateModuleKeys, contextId, statement,
            users = core::EndpointUtils::usersWithPubKeyToIds(roster.users),
            managers = core::EndpointUtils::usersWithPubKeyToIds(roster.managers), rules, grantKey] {
        const std::string& groupId = statement.groupId;
        treeVerifier.pinCommitted(groupId, contextId, statement, users, managers, rules);
        // Looked up now, not when planned: `settle` may run this long after, with the group's cache replaced meanwhile.
        const auto session = sessions.of(groupId);
        session->treeKeys()->putGrantKey(static_cast<std::uint32_t>(statement.keyVersion), grantKey);
        // Minted here and accepted at exactly this epoch (the CAS), so it is the epoch's published key: the metadata
        // refresh that follows opens it without a read.
        session->epochKeys.set(static_cast<int64_t>(statement.keyVersion), grantKey);
        // Its rungs passed the self-check against the chain (`buildRotationRungs`) before it was submitted: nothing
        // for the observed-rotation check to look at.
        deferred.markLadderChecked(groupId, static_cast<std::uint32_t>(statement.keyVersion));
        invalidate(groupId);
    };
}

bool GroupOperations::rotate(const std::string& groupId, PriorRole& prior) const {
    // Every record, because the statement signs the tree hash, which a rotation leaves as it is.
    const std::string op = keytree::TreeCommits::opKey("rotate");
    const std::optional<GroupRead> settled = engine.readForCommit(
        planRead(groupId), keytree::TreeVerifier::Scope::Plan, op
    );
    if (!settled.has_value()) {
        return false;
    }
    const GroupRead& read = settled.value();
    const server::GroupInfo& currentGroup = read.group();
    prior = priorOf(currentGroup);
    const int64_t currentEpoch = currentGroup.keyVersion;
    const int64_t newEpoch = currentEpoch + 1;
    const int64_t newRosterVersion = currentGroup.rosterVersion + 1;

    // Unlike a removal, a rotation never abandons history: the point is a new key for the same members, and the
    // climb (a verified root key and the current grant key) is what the rungs down to the old epochs are made from.
    const auto cache = deps.sessions.of(groupId)->treeKeys();
    const VerifiedGroup& verified = planOn(read);
    const keytree::TreeGroupState state = climbForPlanning(verified, cache);
    const auto currentGrantKey = cache->getGrantKey(keytree::GroupKeyResolver::epochOf(currentEpoch));
    if (!currentGrantKey.has_value() ||
        currentGrantKey->getPublicKey().toBase58DER() != keytree::TreeVerifier::canonicalKey(currentGroup.groupPubKey)) {
        throw core::EncryptionKeyValidationException("rotating the group key needs the current grant key");
    }
    const auto [attestedUsers, attestedManagers] =
        mapper.validateAndGetAttestedRoster(currentGroup, keyProvider, groupPrivKeyResolver);
    keytree::TreeVerifier::assertSeatsMatchRoster(currentGroup, attestedUsers, attestedManagers);
    const std::string rotatorId = keytree::GroupKeyResolver::ownUserId(currentGroup).value();

    keytree::TreeKeys tree(*cache);
    const keytree::CommitPlan plan = planOrThrow<keytree::CommitPlan>([&] {
        return tree.planRotation(state, rotatorId, deps.userPrivKey);
    });
    const std::vector<keytree::ArchiveRung> rungs = buildRotationRungs(
        verified, keytree::GroupKeyResolver::epochOf(newEpoch), plan.grantKey, currentGrantKey, rotatorId, *cache
    );
    const RosterAfterChange roster = rosterFromUserIds(attestedUsers, attestedManagers);
    const std::string newGroupPubKeyStr = plan.grantKey.getPublicKey().toBase58DER();
    const NewEpochRoster sealed = metadata.sealRosterForNewEpoch(
        currentGroup, roster, newGroupPubKeyStr, newEpoch, newRosterVersion, false
    );

    server::GroupGenerateNewKeyModel model;
    model.id = groupId;
    model.groupPubKey = newGroupPubKeyStr;
    model.keyId = sealed.keyId;
    model.data = sealed.data;
    model.grantEdge = keytree::TreeWire::toWire(plan.edges.at(0));
    model.rungs = keytree::TreeWire::toWire(rungs);
    model.groupKeys = sealed.groupKeys;
    model.expectedKeyVersion = currentEpoch;
    model.expectedRosterVersion = currentGroup.rosterVersion;
    const keytree::GroupRules rules = rulesOf(verified);
    keytree::CommitStatement statement = keytree::TreeCommits::statementFor(
        plan, keytree::CommitOp::Rotate, groupId, commitDate(), static_cast<std::uint64_t>(newEpoch), newGroupPubKeyStr,
        static_cast<std::uint64_t>(newRosterVersion), attestedUsers, attestedManagers, rotatorId, {}, {}, {}, rules.hash
    );
    engine.chainTo(statement, verified);
    keytree::TreeCommits::sign(statement, deps.userPrivKey);
    model.commit = keytree::TreeCommits::toWire(statement);
    const auto sent = std::make_shared<const server::GroupGenerateNewKeyModel>(std::move(model));
    engine.submit(
        groupId, statement,
        UnresolvedCommit{
            .op = op,
            .kind = "rotation",
            .contextId = currentGroup.contextId,
            .send = [&serverApi = deps.serverApi, sent] { serverApi.groupGenerateNewKey(*sent); },
            // Pinned before anything reads the group again: the state under the replaced key is refused from here on.
            .landed = landedEpoch(currentGroup.contextId, statement, roster, rules, plan.grantKey),
            .after = [&metadata = metadata, groupId,
                      prior] { metadata.carryMetadataForward(groupId, CarryScope::NewEpoch, false, {}, prior); }
        }
    );
    return true;
}

bool GroupOperations::selfUpdate(
    const std::string& groupId,
    const privmx::crypto::PrivateKey* previousKey,
    const std::string& op,
    bool mayCompleteOther
) const {
    const server::GroupGetModel getModel = planRead(groupId);
    std::optional<VerifiedGroup> read;
    keytree::TreeGroupState state;
    std::pair<std::vector<std::string>, std::vector<std::string>> roster;
    // What the plan climbs over: the group's shared cache, or the renewal's call-local one, so nothing derived from
    // the previous key ever reaches a reader, a deferred self-update or a failed renewal's next call.
    std::shared_ptr<keytree::TreeKeyCache> planCache = deps.sessions.of(groupId)->treeKeys();
    if (previousKey == nullptr) {
        // The need first, on the small path view: by now the node's healer, or anybody's commit through it, has most
        // likely refilled it, and the plan view carries every node record of the tree.
        const GroupRead pathView = deps.facade.read(pathRead(groupId), keytree::TreeVerifier::Scope::Path);
        if (!pathView.verified.has_value()) {
            return false;
        }
        // Before the need check: an unresolved self-update of ours is resent (or found landed), never planned again.
        switch (engine.settle(groupId, op, mayCompleteOther)) {
        case Settled::Proceed:
            break;
        case Settled::Deferred:
            LOG_DEBUG("[selfUpdate] deferred: an earlier commit of this client to the group has no known outcome yet")
            return false;
        default:
            return false;
        }
        if (!keytree::GroupKeyResolver::nodeNeedingSelfUpdate(pathView.group()).has_value()) {
            return false;
        }
        GroupRead planView = deps.facade.read(getModel, keytree::TreeVerifier::Scope::Plan);
        const server::GroupInfo& group = planView.group();
        // Re-checked on a fresh read: somebody's commit through the same nodes may have refilled them meanwhile.
        if (!keytree::GroupKeyResolver::hasTree(group) ||
            !keytree::GroupKeyResolver::hasSupportedTree(group) ||
            !keytree::GroupKeyResolver::nodeNeedingSelfUpdate(group).has_value()) {
            return false;
        }
        // A self-update wraps to whoever is seated, so it needs the seats proven against the roster like any commit.
        roster = mapper.validateAndGetAttestedRoster(group, keyProvider, groupPrivKeyResolver);
        keytree::TreeVerifier::assertSeatsMatchRoster(group, roster.first, roster.second);
        state = climbForPlanning(planOn(planView), planCache);
        read = std::move(planView.verified);
    } else {
        // Leaf renewal. No need gate: the need is the leaf not opening with the session's key, checked below.
        std::optional<GroupRead> renewalView =
            engine.readForCommit(getModel, keytree::TreeVerifier::Scope::Plan, op, mayCompleteOther, [] {
                throw core::EncryptionKeyValidationException("caller holds no leaf in this group's key tree");
            });
        if (!renewalView.has_value()) {
            return true;
        }
        read = std::move(renewalView->verified); // set: an unseated read was refused above
        const server::GroupInfo& group = **read;
        // Renewed already: a commit after the directory change wrapped the leaf to the session's key.
        const keytree::TreeGroupState current = keytree::GroupKeyResolver::toTreeState(group);
        keytree::TreeKeys sharedTree(*planCache);
        const std::string ownId = keytree::GroupKeyResolver::ownUserId(group).value();
        if (sharedTree.climbToGrantKey(current, ownId, deps.userPrivKey, false).failure ==
            keytree::ClimbFailure::None) {
            return false;
        }
        planCache = std::make_shared<keytree::TreeKeyCache>();
        const ClimbWith with{planCache, previousKey};
        state = climbForPlanning(read.value(), planCache, nullptr, previousKey);
        // After the climb (the roster key resolves only through the grant key it recovered) and on the same read, so
        // a concurrent epoch change cannot make it check a different state.
        roster = mapper.validateAndGetAttestedRoster(group, keyProvider, keys.resolverOver(&read.value(), &with));
        keytree::TreeVerifier::assertSeatsMatchRoster(group, roster.first, roster.second);
    }
    // `state` was climbed over `planCache`; `roster` is the attested one, proven against the seats.
    const VerifiedGroup& verified = read.value();
    const server::GroupInfo& group = *verified;
    const bool renewal = previousKey != nullptr;
    const auto& [attestedUsers, attestedManagers] = roster;
    const std::string memberId = keytree::GroupKeyResolver::ownUserId(group).value();

    keytree::TreeKeys tree(*planCache);
    // Own key: the session's, taken locally (`commitRecipientKeys`), never the directory's.
    tree.setMemberKeyStrings(commitRecipientKeys(
        group, keytree::TreeKeys::recipients(state, keytree::TreeKeys::shapeSelfUpdate(state, memberId)), memberId
    ));
    const keytree::CommitPlan plan = planOrThrow<keytree::CommitPlan>([&] {
        return tree.planSelfUpdate(state, memberId, deps.userPrivKey);
    });

    server::GroupSelfUpdateModel model;
    model.id = groupId;
    model.expectedKeyVersion = group.keyVersion;
    model.transition = keytree::TreeWire::toSelfUpdateTransition(plan, group.keyVersion);
    const keytree::GroupRules rules = rulesOf(verified);
    keytree::CommitStatement statement = keytree::TreeCommits::statementFor(
        plan, keytree::CommitOp::SelfUpdate, groupId, commitDate(), static_cast<std::uint64_t>(group.keyVersion),
        group.groupPubKey, static_cast<std::uint64_t>(group.rosterVersion), attestedUsers, attestedManagers, memberId,
        {}, {}, {}, rules.hash
    );
    engine.chainTo(statement, verified);
    keytree::TreeCommits::sign(statement, deps.userPrivKey);
    model.commit = keytree::TreeCommits::toWire(statement);
    const auto sent = std::make_shared<const server::GroupSelfUpdateModel>(std::move(model));
    engine.submit(
        groupId, statement,
        UnresolvedCommit{
            .op = op,
            // A renewal names its end state (the leaf opens with the session's key): found landed, it is done.
            .namesEndState = renewal,
            .kind = renewal ? "leaf renewal" : "self-update",
            .contextId = group.contextId,
            .send = [&serverApi = deps.serverApi, sent] { serverApi.groupSelfUpdate(*sent); },
            .landed =
                [&treeVerifier = deps.treeVerifier, &sessions = deps.sessions, groupId, contextId = group.contextId,
                 statement, users = attestedUsers, managers = attestedManagers, rules, grantKey = plan.grantKey] {
                    treeVerifier.pinCommitted(groupId, contextId, statement, users, managers, rules);
                    // The epoch's own grant key (a self-update keeps the epoch; the climb checked it against the
                    // verified state), now landed. A renewal planned on a scratch cache, so without this the next
                    // removal would ask the leaf again, and the edges name no recipient: a member wrapping it back to
                    // the previous public key would get the removal refused after every renewal.
                    sessions.of(groupId)->treeKeys()->putGrantKey(
                        static_cast<std::uint32_t>(statement.keyVersion), grantKey
                    );
                }
        }
    );
    return true;
}

void GroupOperations::updatePolicy(
    const std::string& groupId,
    const core::ContainerPolicy& policies,
    std::optional<PendingCarry>& carry
) const {
    // A signed commit like any other: the chain, the CAS and the role check. It moves no node, no epoch and
    // no roster, so the path view is enough to sign the tree hash as it stands.
    const server::GroupGetModel getModel = pathRead(groupId);
    GroupRead read = deps.facade.read(getModel, keytree::TreeVerifier::Scope::Path);
    if (!read.verified.has_value()) {
        throw core::InvalidParamsException("only a member of a group can change its policy");
    }
    VerifiedGroup verified = std::move(read.verified.value());
    const Poco::Dynamic::Var policy = core::Factory::createPolicyServerObject(policies);
    const keytree::GroupRules newRules = requestedRules(policy, verified->creator);
    // The whole wire policy, not only the signed rules: two calls differing in a Bridge-held field (`get`, `item.*`)
    // name different end states, and one must never return on the other.
    const std::string op = keytree::TreeCommits::opKey("policy", {privmx::utils::Utils::stringifyVar(policy)});
    switch (engine.settle(groupId, op, true)) {
    case Settled::Done:
        return;
    case Settled::Reread:
        verified = engine.rereadVerified(getModel, keytree::TreeVerifier::Scope::Path);
        break;
    default:
        break;
    }
    const server::GroupInfo& group = *verified;
    // Commit B: the planes as read, attested under the rules in force, and whose authors the new rules leave without
    // `update`. Those planes would be refused once this lands; somebody who keeps `update` must carry them.
    const PriorRole prior = priorOf(verified);
    std::vector<std::string> losers;
    const Group mapped = mapper.validateDecryptAndConvertGroup(group, keyProvider, keys.resolverOver(&verified), prior);
    const auto keepsUpdate = [&](const std::string& userId) {
        const bool manager = std::find(group.managers.begin(), group.managers.end(), userId) != group.managers.end();
        return keytree::TreeCommits::allows(newRules.update, true, manager, userId == group.creator);
    };
    if (mapped.statusCode == 0) {
        for (const server::GroupMetaEntry* entry : {&group.publicMeta, &group.privateMeta}) {
            if (!keepsUpdate(entry->author) && std::find(losers.begin(), losers.end(), entry->author) == losers.end()) {
                losers.push_back(entry->author);
            }
        }
    }
    const std::string self = keytree::GroupKeyResolver::ownUserId(group).value();
    if (!losers.empty() && !keepsUpdate(self)) {
        throw core::InvalidParamsException(
            "this policy would strand metadata whose author loses update, and the caller would lose it too"
        );
    }
    const keytree::CommitStatement latest = keytree::TreeCommits::fromWire(group.treeCommit.value());
    keytree::CommitStatement statement;
    statement.seq = latest.seq + 1;
    statement.op = keytree::CommitOp::Policy;
    statement.groupId = groupId;
    statement.treeVersion = keytree::TreeMath::TREE_VERSION;
    statement.date = commitDate();
    statement.keyVersion = latest.keyVersion;
    statement.groupPubKey = latest.groupPubKey;
    statement.rosterVersion = latest.rosterVersion;
    statement.rosterHash = latest.rosterHash;
    statement.treeHash = latest.treeHash;
    statement.policyHash = newRules.hash;
    statement.committer = self;
    statement.committerSeat = static_cast<std::uint32_t>(group.ownLeafPosition.value());
    statement.policy = policy;
    engine.chainTo(statement, verified);
    keytree::TreeCommits::sign(statement, deps.userPrivKey);
    const auto sent = std::make_shared<const server::GroupUpdatePolicyModel>(server::GroupUpdatePolicyModel{
        .id = groupId,
        .commit = keytree::TreeCommits::toWire(statement),
        .expectedKeyVersion = group.keyVersion,
        .expectedRosterVersion = group.rosterVersion
    });
    const PendingCarry pending{losers, prior};
    // Keys are untouched, so nothing is invalidated: the module key cache keys on `rosterVersion`, which stays.
    engine.submit(
        groupId, statement,
        UnresolvedCommit{
            .op = op,
            .namesEndState = true,
            .kind = "policy change",
            .contextId = group.contextId,
            .send = [&serverApi = deps.serverApi, sent] { serverApi.groupUpdatePolicy(*sent); },
            .landed =
                [&treeVerifier = deps.treeVerifier, groupId, contextId = group.contextId, statement,
                 users = group.users, managers = group.managers,
                 newRules] { treeVerifier.pinCommitted(groupId, contextId, statement, users, managers, newRules); },
            // Found landed by a later call's `settle`: the carry runs there.
            .after = losers.empty() ?
                std::function<void()>() :
                [&metadata = metadata, groupId, pending] { metadata.runPolicyCarry(groupId, pending); }
        }
    );
    if (!losers.empty()) {
        carry = pending;
    }
}
