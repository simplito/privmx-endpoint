#include <algorithm>
#include <random>

#include <privmx/crypto/Crypto.hpp>
#include <privmx/crypto/ecc/PrivateKey.hpp>
#include <privmx/endpoint/core/CoreException.hpp>
#include <privmx/endpoint/core/LocalSeal.hpp>
#include <privmx/utils/JsonHelper.hpp>
#include <privmx/utils/Utils.hpp>

#include <privmx/endpoint/core/CoreConstants.hpp>
#include <privmx/endpoint/core/EndpointUtils.hpp>
#include <privmx/endpoint/core/EventMiddleware.hpp>
#include <privmx/endpoint/core/ExceptionConverter.hpp>
#include <privmx/endpoint/core/TimestampValidator.hpp>
#include <privmx/endpoint/core/Types.hpp>
#include <privmx/endpoint/core/Utils.hpp>

#include "privmx/endpoint/core/EventBuilder.hpp"
#include "privmx/endpoint/core/ListQueryMapper.hpp"
#include "privmx/endpoint/core/Mapper.hpp"
#include "privmx/endpoint/core/Validator.hpp"
#include "privmx/endpoint/group/Constants.hpp"
#include "privmx/endpoint/group/GroupApiImpl.hpp"
#include "privmx/endpoint/group/GroupException.hpp"
#include "privmx/endpoint/group/Mapper.hpp"
#include "privmx/endpoint/group/ServerTypes.hpp"
#include "privmx/endpoint/group/keytree/LadderKeys.hpp"
#include "privmx/endpoint/group/keytree/PinBlob.hpp"
#include "privmx/endpoint/group/keytree/TreeCommits.hpp"
#include "privmx/endpoint/group/keytree/TreeMath.hpp"
#include "privmx/endpoint/group/keytree/TreeWire.hpp"
#include "privmx/utils/Logger.hpp"
#include <privmx/endpoint/core/ConvertedExceptions.hpp>

using namespace privmx::endpoint;
using namespace group;

namespace {

// `groupGet` in the default "path" scope, with nothing for anybody else.
group::server::GroupGetModel pathRead(const std::string& groupId) {
    return group::server::GroupGetModel{
        .groupId = groupId, .type = {}, .scope = {}, .forUserIds = {}, .forNewMembers = {}, .fromRosterVersion = {}
    };
}

// `groupGet` in the "plan" scope: every node record a plan resolves through, plus the departing members' paths
// (`forUserIds`) or seats for the newcomers (`forNewMembers`).
group::server::GroupGetModel planRead(
    const std::string& groupId,
    std::optional<std::vector<std::string>> forUserIds = std::nullopt,
    std::optional<std::int64_t> forNewMembers = std::nullopt
) {
    return group::server::GroupGetModel{
        .groupId = groupId,
        .type = {},
        .scope = std::string("plan"),
        .forUserIds = forUserIds,
        .forNewMembers = forNewMembers,
        .fromRosterVersion = {}
    };
}

// Bridge application error codes a commit can be refused with as a lost race.
enum BridgeError : unsigned int {
    ROTATED_ALREADY = 0x621C,
    GROUP_TREE_INVALID = 0x621E, // its data lists the problems found
    GROUP_ROSTER_VERSION_MISMATCH = 0x6224,
};

// Attempts of one app commit against a base that moved (`commitWithRetry`).
constexpr int MAX_COMMIT_ATTEMPTS = 3;

// How far a group's members spread their deferred work: this much per seat, within the bounds.
constexpr std::int64_t BACKGROUND_MS_PER_SEAT = 8;
constexpr std::int64_t BACKGROUND_WINDOW_MIN_MS = 1000;
constexpr std::int64_t BACKGROUND_WINDOW_MAX_MS = 120000;

// " (wrapped by <who>)", or nothing without a culprit.
std::string blameSuffix(const std::optional<std::string>& who, const std::string& as = "wrapped by") {
    return who.has_value() ? " (" + as + " " + who.value() + ")" : "";
}

// A uniform delay in `[0, windowMs]`, so a group's members do not all hit the bridge at once.
std::chrono::milliseconds jitter(std::int64_t windowMs) {
    static thread_local std::mt19937_64 random{std::random_device{}()};
    return std::chrono::milliseconds(std::uniform_int_distribution<std::int64_t>(0, windowMs)(random));
}

// The floor nothing below may be reached or repaired: the higher of the era floor and the prune watermark.
std::uint32_t ladderFloorOf(std::int64_t eraFloor, const std::optional<std::int64_t>& prunedBelow) {
    const std::int64_t floor = std::max<std::int64_t>({1, eraFloor, prunedBelow.value_or(1)});
    if (floor > static_cast<std::int64_t>(UINT32_MAX)) {
        throw GroupDataIntegrityException("a ladder floor past the last epoch");
    }
    return static_cast<std::uint32_t>(floor);
}

// The rules of a policy the caller asks to sign: one outside the group grammar is the caller's error.
keytree::GroupRules requestedRules(const Poco::Dynamic::Var& policy, const std::string& creator) {
    try {
        return keytree::TreeCommits::rules(policy, creator);
    } catch (const std::invalid_argument& e) {
        throw core::InvalidParamsException(e.what());
    }
}

} // namespace

GroupApiImpl::GroupApiImpl(
    const privfs::RpcGateway::Ptr& gateway,
    const privmx::crypto::PrivateKey& userPrivKey,
    const std::shared_ptr<core::KeyProvider>& keyProvider,
    const std::string& host,
    const std::shared_ptr<core::EventMiddleware>& eventMiddleware,
    const core::Connection& connection
)
    : ContainerBaseApi(userPrivKey, keyProvider, host, eventMiddleware, connection), _serverApi(ServerApi(gateway)),
      _subscriber(gateway), _groupDataSchemaMapper(std::make_shared<GroupDataSchemaMapper>(userPrivKey, connection)) {
    // A group opens its own metadata key by climbing its own tree, so it resolves its grant key for itself.
    initGroupPrivKeyResolver(resolverOver(nullptr));
    initModuleDataSchemaMapper(_groupDataSchemaMapper);
    _pinnedGroupEpoch = [this](const std::string& groupId) { return pinnedKeyVersion(groupId); };
    // The pins this identity saved on this Bridge (any instance, any session) before anything reads a group.
    // Loaded once; instances running side by side meet again in the slot at each save (`PinBlob::higher`).
    const auto connectionImpl = connection.getImpl();
    _pinStore = connectionImpl->getPinStore();
    if (_pinStore) {
        _pinStoreKey = connectionImpl->localStateSlot(core::localstate::GROUP_PINS, userPrivKey.getPublicKey());
        // Unreadable, corrupted or deleted: this instance starts as a first contact for every group (as without a store).
        loadPins();
        for (const auto& [previousPub, body] : connectionImpl->getStagedPinBodies()) {
            const auto adopted = keytree::PinBlob::decode(body);
            if (!adopted.has_value()) {
                LOG_WARN("[pins] the previous identity's pins do not parse; not adopted")
                continue;
            }
            try {
                adoptBody(adopted.value());
            } catch (const std::exception& e) {
                LOG_WARN("[pins] the previous identity's pins not adopted: ", e.what())
                continue;
            }
            std::lock_guard<std::mutex> lock(_pinSaveMutex);
            _adoptedIdentities.insert(previousPub);
        }
    }
    _treeVerifier.onPinsMoved([this](bool major) { pinsMoved(major); });
    _groupDataSchemaMapper->onPinsMoved([this](bool major) { pinsMoved(major); });
    _notificationListenerId = _eventMiddleware->addNotificationEventListener(
        std::bind(&GroupApiImpl::processNotificationEvent, this, std::placeholders::_1, std::placeholders::_2)
    );
    _connectedListenerId = _eventMiddleware->addConnectedEventListener(
        std::bind(&GroupApiImpl::processConnectedEvent, this)
    );
    _disconnectedListenerId = _eventMiddleware->addDisconnectedEventListener(
        std::bind(&GroupApiImpl::processDisconnectedEvent, this)
    );
}

GroupApiImpl::~GroupApiImpl() {
    _eventMiddleware->removeNotificationEventListener(_notificationListenerId);
    _eventMiddleware->removeConnectedEventListener(_connectedListenerId);
    _eventMiddleware->removeDisconnectedEventListener(_disconnectedListenerId);
    _guardedExecutor.reset();
    // Last: notification tasks may move pins until the executor is gone.
    if (_pinStore) {
        savePins();
    }
}

dynamic::MembershipBlock GroupApiImpl::buildMembershipBlock(
    const core::EncKey& key,
    const std::string& groupPubKey,
    int64_t keyVersion,
    int64_t rosterVersion,
    const std::vector<core::UserWithPubKey>& users,
    const std::vector<core::UserWithPubKey>& managers
) {
    return dynamic::MembershipBlock{
        .rosterTag = GroupDataSchemaMapper::rosterTag(
            key.key, keyVersion, rosterVersion, core::EndpointUtils::usersWithPubKeyToIds(users),
            core::EndpointUtils::usersWithPubKeyToIds(managers)
        ),
        .groupPubKey = groupPubKey,
        .keyId = key.id,
        .keyVersion = keyVersion,
        .rosterVersion = rosterVersion
    };
}

std::vector<keytree::TreeMember> GroupApiImpl::toTreeMembers(
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

// The attested roster, as bare ids — the update preparation diffs names, it does not wrap to them.
RosterAfterChange GroupApiImpl::rosterFromUserIds(
    const std::vector<std::string>& users,
    const std::vector<std::string>& managers
) {
    const auto toBare = [](const std::vector<std::string>& ids) {
        std::vector<core::UserWithPubKey> bare;
        for (const std::string& id : ids) {
            bare.push_back(core::UserWithPubKey{.userId = id, .pubKey = std::string()});
        }
        return bare;
    };
    return RosterAfterChange{.users = toBare(users), .managers = toBare(managers)};
}

// Public keys for exactly these members, from the Context user list. One listing round trip per 100 of them.
std::map<std::string, std::string> GroupApiImpl::resolveMemberKeys(
    const std::string& contextId,
    const std::vector<std::string>& userIds
) {
    if (userIds.empty()) {
        return {};
    }
    const ContainerRoster resolved = resolveRosterPubKeys(contextId, userIds, {});
    assertUserKeysVerified(contextId, resolved.users);
    std::map<std::string, std::string> keys;
    for (const core::UserWithPubKey& user : resolved.users) {
        keys.emplace(user.userId, user.pubKey);
    }
    return keys;
}

std::map<std::string, std::string> GroupApiImpl::commitRecipientKeys(
    const server::GroupInfo& group,
    const std::vector<std::string>& recipients,
    const std::string& ownUserId,
    const std::set<std::string>& newcomers
) {
    std::vector<std::string> toResolve;
    for (const std::string& userId : recipients) {
        if (userId != ownUserId && newcomers.count(userId) == 0) {
            toResolve.push_back(userId);
        }
    }
    std::map<std::string, std::string> keys = resolveMemberKeys(group.contextId, toResolve);
    keys[ownUserId] = _userPrivKey.getPublicKey().toBase58DER();
    return keys;
}

// The keytree module reports impossible requests as `std::invalid_argument`, having no dependency on the endpoint's
// exception hierarchy. Letting one escape the SDK boundary would `std::terminate` a caller catching core::Exception.
template<typename TPlan>
static TPlan planOrThrow(const std::function<TPlan()>& build) {
    try {
        return build();
    } catch (const std::invalid_argument& e) {
        throw core::EncryptionKeyValidationException(std::string("key tree operation is not possible: ") + e.what());
    }
}

bool GroupApiImpl::climbsWithPreviousIdentity(const keytree::TreeGroupState& state, const std::string& memberId) {
    const std::vector<privmx::crypto::PrivateKey> previous = _connection.getImpl()->previousIdentities();
    return std::any_of(previous.begin(), previous.end(), [&](const privmx::crypto::PrivateKey& key) {
        keytree::TreeKeyCache scratch;
        return keytree::TreeKeys(scratch).climbToGrantKey(state, memberId, key, false).failure ==
            keytree::ClimbFailure::None;
    });
}

keytree::TreeGroupState GroupApiImpl::climbForPlanning(
    const server::GroupInfo& group,
    const std::shared_ptr<keytree::TreeKeyCache>& cache,
    const std::vector<std::string>* removing,
    const privmx::crypto::PrivateKey* climbKey
) {
    if (!keytree::GroupKeyResolver::hasTree(group)) {
        throw core::EncryptionKeyValidationException("this group is not backed by a key tree");
    }
    if (!keytree::GroupKeyResolver::hasSupportedTree(group)) {
        keytree::ResolveResult asResolve;
        asResolve.failure = keytree::ResolveFailure::UnsupportedTreeVersion;
        throw core::EncryptionKeyValidationException(describeResolveFailure(asResolve));
    }
    const auto identity = keytree::GroupKeyResolver::ownUserId(group);
    if (!identity.has_value()) {
        throw core::EncryptionKeyValidationException("caller holds no leaf in this group's key tree");
    }
    const keytree::TreeGroupState state = keytree::GroupKeyResolver::toTreeState(group);
    keytree::TreeKeys tree(*cache);
    // Walk even when the grant key is already cached: a plan needs the node keys along the path, and the cache
    // would otherwise satisfy the request without ever recovering them.
    const keytree::ClimbResult climb =
        tree.climbToGrantKey(state, identity.value(), climbKey != nullptr ? *climbKey : _userPrivKey, false);
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
            const auto cachedGrantKey = cache->getGrantKey(static_cast<std::uint32_t>(group.keyVersion));
            const bool historyStillReachable =
                cachedGrantKey.has_value() && cachedGrantKey->getPublicKey().toBase58DER() == group.groupPubKey;
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
        scheduleSelfUpdateIfNeeded(group.id, group);
    }
    return state;
}

std::string GroupApiImpl::createGroup(
    const std::string& contextId,
    const std::vector<core::UserWithPubKey>& users,
    const std::vector<core::UserWithPubKey>& managers,
    const core::Buffer& publicMeta,
    const core::Buffer& privateMeta,
    const std::optional<core::ContainerPolicy>& policies
) {
    // The creator commits from a seat of its own, like any committer. Checked by
    // key first, which needs no request; the id the seat is planned under is checked again once it is known.
    const std::vector<keytree::TreeMember> members = toTreeMembers(users, managers);
    const privmx::crypto::PublicKey ownKey = _userPrivKey.getPublicKey();
    if (std::none_of(members.begin(), members.end(), [&](const keytree::TreeMember& m) {
            return m.publicKey == ownKey;
        })) {
        throw core::InvalidParamsException("the creator of a group must be one of its users or managers");
    }

    // Empty rosters: the metadata key is wrapped once to the group's own grant key, and members open it by climbing.
    auto ctx = prepareContainerCreate(contextId, {}, {});
    const std::string creatorId = ctx.dio.creatorUserId;
    if (std::none_of(members.begin(), members.end(), [&](const keytree::TreeMember& m) {
            return m.userId == creatorId && m.publicKey == ownKey;
        })) {
        throw core::InvalidParamsException("the creator of a group must be one of its users or managers");
    }
    // Each seat is filled to the key given for it, and those keys are as good as the listing they came from.
    assertUserKeysVerified(contextId, core::EndpointUtils::uniqueListUserWithPubKey(users, managers));
    keytree::TreeKeyCache scratch; // the group has no id yet
    keytree::TreeKeys builder(scratch);
    const keytree::CommitPlan plan = planOrThrow<keytree::CommitPlan>([&] {
        return builder.planCreate(members, creatorId, _userPrivKey);
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
    model.data = _groupDataSchemaMapper->encryptRoster(rosterToEncrypt, ctx.key.key);
    model.publicMeta = _groupDataSchemaMapper->encryptPublicMeta(publicMetaToEncrypt);
    model.privateMeta = _groupDataSchemaMapper->encryptPrivateMeta(privateMetaToEncrypt, ctx.key.key);
    model.users = core::EndpointUtils::usersWithPubKeyToIds(users);
    model.managers = core::EndpointUtils::usersWithPubKeyToIds(managers);
    model.groupPubKey = groupPubKeyStr;
    model.type = GROUP_TYPE_FILTER_FLAG;
    const auto selfAddressed = buildGroupKeyEntries(
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
    keytree::TreeCommits::sign(statement, _userPrivKey);
    model.commit = keytree::TreeCommits::toWire(statement);

    auto result = _serverApi.groupCreate(model);
    // The bridge derives the id from the signed resourceId; any other id is not the group this statement created.
    if (result.groupId != keytree::TreeCommits::groupId(contextId, ctx.resourceId)) {
        throw GroupDataIntegrityException("the new group's id does not follow from its resourceId");
    }
    _treeVerifier.pinCommitted(
        result.groupId, contextId, statement, core::EndpointUtils::usersWithPubKeyToIds(users),
        core::EndpointUtils::usersWithPubKeyToIds(managers), rules
    );
    savePins(); // an own commit is in the store before the call returns
    const auto cache = _treeKeyCaches.get(result.groupId);
    cache->putGrantKey(1, plan.grantKey);
    return result.groupId;
}

void GroupApiImpl::addGroupMembers(const std::string& groupId, const std::vector<GroupMemberToAdd>& newMembers) {
    // The op-effect table's add row names each newcomer once: refused here, before anything is read or signed.
    std::set<std::string> named;
    for (const GroupMemberToAdd& newMember : newMembers) {
        if (!named.insert(newMember.user.userId).second) {
            throw core::InvalidParamsException("user '" + newMember.user.userId + "' is listed twice");
        }
    }
    commitWithRetry([&] { addGroupMembersOnce(groupId, newMembers); });
    runDueWork(groupId);
}

void GroupApiImpl::addGroupMembersOnce(const std::string& groupId, const std::vector<GroupMemberToAdd>& newMembers) {
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
    const std::optional<server::GroupInfo> read = readForCommit(
        planRead(groupId, std::nullopt, static_cast<std::int64_t>(newMembers.size())), keytree::TreeVerifier::Scope::Plan,
        op
    );
    if (!read.has_value()) {
        return;
    }
    const server::GroupInfo& currentGroup = read.value();
    const auto& currentEntry = currentGroup.data.back();
    const auto resourceId = currentGroup.resourceId.value_or(core::EndpointUtils::generateId());
    const int64_t currentEpoch = currentGroup.keyVersion;
    // The bridge pins this in its compare-and-swap, so the entry lands here or the call is refused — which is
    // what lets the tag below commit to it.
    const int64_t newRosterVersion = currentGroup.rosterVersion + 1;

    // The roster this call signs has to be the one the head attests to, not one the caller restated or the bridge
    // asserted. Roster plane only — seating a member is not a metadata edit, so it does not open that entry.
    const auto [attestedUsers, attestedManagers] = _groupDataSchemaMapper->validateAndGetAttestedRoster(
        currentGroup, _keyProvider, _groupPrivKeyResolver
    );
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
    const auto cache = _treeKeyCaches.get(groupId);
    const keytree::TreeGroupState state = climbForPlanning(currentGroup, cache);
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
    assertUserKeysVerified(currentGroup.contextId, newcomerKeys);
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
        return tree.planAddition(state, treeNewcomers, positions, adderId, _userPrivKey);
    });

    // No new epoch
    auto ctx = prepareContainerUpdateWithoutKeyEntries(
        currentGroup, currentEntry, resourceId, roster.users, roster.managers, false
    );
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
    model.data = _groupDataSchemaMapper->encryptRoster(rosterToEncrypt, ctx.key.key);
    model.transition = keytree::TreeWire::toAdditionTransition(plan, currentEpoch);
    const keytree::GroupRules rules = rulesOf(currentGroup);
    keytree::CommitStatement statement = keytree::TreeCommits::statementFor(
        plan, keytree::CommitOp::Add, groupId, commitDate(), static_cast<std::uint64_t>(currentEpoch),
        currentGroup.groupPubKey, static_cast<std::uint64_t>(newRosterVersion),
        core::EndpointUtils::usersWithPubKeyToIds(roster.users),
        core::EndpointUtils::usersWithPubKeyToIds(roster.managers), adderId, addedUsers, addedManagers, {}, rules.hash
    );
    chainTo(statement, currentGroup);
    keytree::TreeCommits::sign(statement, _userPrivKey);
    model.commit = keytree::TreeCommits::toWire(statement);
    model.expectedKeyVersion = currentEpoch;
    model.expectedRosterVersion = currentGroup.rosterVersion;

    const auto sent = std::make_shared<const server::GroupAddMembersModel>(std::move(model));
    const std::string contextId = currentGroup.contextId;
    const std::vector<std::string> users = core::EndpointUtils::usersWithPubKeyToIds(roster.users);
    const std::vector<std::string> managers = core::EndpointUtils::usersWithPubKeyToIds(roster.managers);
    submit(
        groupId, statement,
        UnresolvedCommit{
            .op = op,
            .namesEndState = true,
            .kind = "add",
            .contextId = contextId,
            .newcomers = newcomerKeys,
            .send = [this, sent] { _serverApi.groupAddMembers(*sent); },
            .landed =
                [this, groupId, contextId, statement, users, managers, rules] {
                    _treeVerifier.pinCommitted(groupId, contextId, statement, users, managers, rules);
                    invalidateModuleKeysInCache(groupId);
                }
        }
    );
}

std::vector<keytree::ArchiveRung> GroupApiImpl::buildRotationRungs(
    const server::GroupInfo& group,
    std::uint32_t newEpoch,
    const privmx::crypto::PrivateKey& newGrantKey,
    const std::optional<privmx::crypto::PrivateKey>& previousEpochKey,
    const std::string& author,
    keytree::TreeKeyCache& cache
) {
    keytree::LadderKeys ladder(cache);
    // Never a floor lower than one this session has seen: a bridge under-reporting it gets no rung below it.
    std::uint32_t floor = cache.raiseFloor(ladderFloorOf(group.eraFloor.value_or(1), group.archivePrunedBelow));
    // What the rungs are checked against before submitting: the chain, never the cache. Without skip targets that is
    // the verified group's own key (the unit rung's target); with them, the openers' keys (`fetchKeyArchive`).
    std::vector<keytree::EpochRegistryEntry> registry{
        {static_cast<std::uint32_t>(group.keyVersion), privmx::crypto::PublicKey::fromBase58DER(group.groupPubKey)}
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
        server::GroupGetKeyArchiveResult archive = fetchKeyArchive(group, path);
        floor = cache.raiseFloor(ladderFloorOf(archive.eraFloor, archive.archivePrunedBelow));
        registry = keytree::GroupKeyResolver::registryFromArchive(group, archive);
        keytree::RungKeyGathering gathered = ladder.gatherRungKeys(
            newEpoch, keytree::GroupKeyResolver::toDownwardRungs(archive), registry, floor
        );
        if (!gathered.complete) {
            archive = fetchKeyArchive(group, static_cast<int64_t>(targets.back()), static_cast<int64_t>(newEpoch - 1));
            floor = cache.raiseFloor(ladderFloorOf(archive.eraFloor, archive.archivePrunedBelow));
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
    const std::vector<keytree::ArchiveRung> rungs = planOrThrow<std::vector<keytree::ArchiveRung>>([&] {
        return ladder.buildRungs(newEpoch, newGrantKey.getPublicKey(), previousEpochKey, floor, author, _userPrivKey);
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

void GroupApiImpl::removeGroupMembers(const std::string& groupId, const std::vector<std::string>& userIds) {
    // A narrowing's carry still to do runs first: after the removal its plane would be judged under the new rules.
    retryPendingCarry(groupId);
    std::optional<bool> historyAbandoned;
    PriorRole prior;
    commitWithRetry([&] { historyAbandoned = removeGroupMembersOnce(groupId, userIds, prior); });
    // The removal is committed; the metadata entry is now one epoch behind, under a key the departed member
    // still holds. Move it up. Outside the write above on purpose — see the header. Already done when an earlier
    // call's removal turned out to have landed (`settle`).
    if (historyAbandoned.has_value()) {
        carryMetadataForward(groupId, CarryScope::NewEpoch, historyAbandoned.value(), userIds, prior);
    }
    runDueWork(groupId);
}

std::optional<bool> GroupApiImpl::removeGroupMembersOnce(
    const std::string& groupId,
    const std::vector<std::string>& userIds,
    PriorRole& prior
) {
    // Every departing member's path, because one commit covers their union — and one epoch covers the batch, where
    // removing them one at a time would stale every container the group can read once per member.
    std::vector<std::string> leavingIds = userIds;
    std::sort(leavingIds.begin(), leavingIds.end());
    leavingIds.erase(std::unique(leavingIds.begin(), leavingIds.end()), leavingIds.end());
    const std::string op = keytree::TreeCommits::opKey("remove", leavingIds);
    const std::optional<server::GroupInfo> read =
        readForCommit(planRead(groupId, userIds), keytree::TreeVerifier::Scope::Plan, op);
    if (!read.has_value()) {
        return std::nullopt;
    }
    const server::GroupInfo& currentGroup = read.value();
    // The verified read's rules and roster judge the planes the removal carries (the removed with the role they had).
    prior = priorOf(currentGroup);
    // Refused before anything is planned: the remover mints the next epoch's grant key, so a member removing itself
    // would walk out holding the key meant to lock it out. The bridge refuses it too.
    const std::string self = _connection.getImpl()->getMyUserId(currentGroup.contextId);
    if (std::find(userIds.begin(), userIds.end(), self) != userIds.end()) {
        throw core::InvalidParamsException("a member cannot remove themselves from a group");
    }
    const int64_t currentEpoch = currentGroup.keyVersion;
    const int64_t newEpoch = currentEpoch + 1;
    const int64_t newRosterVersion = currentGroup.rosterVersion + 1;

    const auto cache = _treeKeyCaches.get(groupId);
    const keytree::TreeGroupState state = climbForPlanning(currentGroup, cache, &userIds);
    // Without the current grant key (a broken climb and nothing cached) the removal still goes through, and the
    // epochs before it become unreachable. A malicious bridge can force this by garbling edges (edges are not in
    // the tree hash) — it could destroy history anyway.
    auto currentGrantKey = cache->getGrantKey(static_cast<std::uint32_t>(currentEpoch));
    if (currentGrantKey.has_value() && currentGrantKey->getPublicKey().toBase58DER() != currentGroup.groupPubKey) {
        currentGrantKey.reset(); // not the epoch's key: wrapped into the unit rung it would cut history off anyway
    }
    const bool abandonHistory = !currentGrantKey.has_value();
    // Roster plane only: a removal must not wait on a metadata entry that may sit at an older epoch. With history
    // abandoned the entry cannot be opened; the served roster, bound to the signed latest statement by
    // `verifyTree`'s roster hash, stands in for it.
    const auto [attestedUsers, attestedManagers] = abandonHistory ?
        std::make_pair(currentGroup.users, currentGroup.managers) :
        _groupDataSchemaMapper->validateAndGetAttestedRoster(currentGroup, _keyProvider, _groupPrivKeyResolver);
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
        return tree.planRemoval(state, userIds, removerId, _userPrivKey);
    });
    const std::vector<keytree::ArchiveRung> rungs = abandonHistory ?
        std::vector<keytree::ArchiveRung>{} :
        buildRotationRungs(
            currentGroup, static_cast<std::uint32_t>(newEpoch), plan.grantKey, currentGrantKey, removerId, *cache
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
    const NewEpochRoster sealed = sealRosterForNewEpoch(
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
    const keytree::GroupRules rules = rulesOf(currentGroup);
    keytree::CommitStatement statement = keytree::TreeCommits::statementFor(
        plan, keytree::CommitOp::Remove, groupId, commitDate(), static_cast<std::uint64_t>(newEpoch), newGroupPubKeyStr,
        static_cast<std::uint64_t>(newRosterVersion), core::EndpointUtils::usersWithPubKeyToIds(roster.users),
        core::EndpointUtils::usersWithPubKeyToIds(roster.managers), removerId, {}, {}, userIds, rules.hash
    );
    chainTo(statement, currentGroup);
    keytree::TreeCommits::sign(statement, _userPrivKey);
    model.commit = keytree::TreeCommits::toWire(statement);
    model.rungs = keytree::TreeWire::toWire(rungs);
    if (abandonHistory) {
        model.abandonHistory = true;
    }
    model.groupKeys = sealed.groupKeys;
    model.expectedKeyVersion = currentEpoch;
    model.expectedRosterVersion = currentGroup.rosterVersion;

    const auto sent = std::make_shared<const server::GroupRemoveMembersModel>(std::move(model));
    submit(
        groupId, statement,
        UnresolvedCommit{
            .op = op,
            .namesEndState = true,
            .kind = "remove",
            .contextId = currentGroup.contextId,
            .send = [this, sent] { _serverApi.groupRemoveMembers(*sent); },
            // Pinned before anything reads the group again, or the next read could be the state with the leaver
            // still in.
            .landed = landedEpoch(currentGroup.contextId, statement, roster, rules, plan.grantKey),
            .after =
                [this, groupId, abandonHistory, userIds, prior] {
                    carryMetadataForward(groupId, CarryScope::NewEpoch, abandonHistory, userIds, prior);
                }
        }
    );
    return abandonHistory;
}

GroupApiImpl::NewEpochRoster GroupApiImpl::sealRosterForNewEpoch(
    const server::GroupInfo& currentGroup,
    const RosterAfterChange& roster,
    const std::string& newGroupPubKeyStr,
    int64_t newEpoch,
    int64_t newRosterVersion,
    bool abandonHistory
) {
    const std::string& groupId = currentGroup.id;
    const auto& currentEntry = currentGroup.data.back();
    const auto resourceId = currentGroup.resourceId.value_or(core::EndpointUtils::generateId());
    // Nothing old may stay readable once history is abandoned, and the old key and secret cannot be opened anyway:
    // both start fresh, as at creation.
    auto ctx = abandonHistory ?
        core::ContainerUpdateContext{
            .location = {.contextId = currentGroup.contextId, .resourceId = resourceId},
            .key = _keyProvider->generateKey(),
            .dio = _connection.getImpl()->createDIO(currentGroup.contextId, resourceId),
            .secret = _keyProvider->generateSecret(),
            .keyEntries = {}
        } :
        prepareContainerUpdateWithoutKeyEntries(
            currentGroup, currentEntry, resourceId, roster.users, roster.managers, true
        );
    const auto selfAddressedKey = buildGroupKeyEntries(
        {core::GroupGrantWithKey{
            .groupId = groupId,
            .role = "manager",
            .groupPubKey = newGroupPubKeyStr,
            .groupEpoch = newEpoch,
        }},
        ctx.key, ctx.dio, currentGroup.contextId, resourceId, ctx.secret
    );

    // Roster plane only — the metadata entry is not part of this write. `carryMetadataForward`
    // carries it up to the new epoch once this has committed; see its header for why that is a second call.
    GroupRosterToEncryptV5 rosterToEncrypt{
        .internalMeta = core::
            ModuleInternalMetaV5{.secret = ctx.secret, .resourceId = resourceId, .randomId = ctx.dio.randomId},
        .dio = ctx.dio,
        .membership = buildMembershipBlock(
            ctx.key, newGroupPubKeyStr, newEpoch, newRosterVersion, roster.users, roster.managers
        )
    };

    return NewEpochRoster{
        .keyId = ctx.key.id,
        .data = _groupDataSchemaMapper->encryptRoster(rosterToEncrypt, ctx.key.key),
        .groupKeys = selfAddressedKey.at(0)
    };
}

std::function<void()> GroupApiImpl::landedEpoch(
    const std::string& contextId,
    const keytree::CommitStatement& statement,
    const RosterAfterChange& roster,
    const keytree::GroupRules& rules,
    const privmx::crypto::PrivateKey& grantKey
) {
    return [this, contextId, statement, users = core::EndpointUtils::usersWithPubKeyToIds(roster.users),
            managers = core::EndpointUtils::usersWithPubKeyToIds(roster.managers), rules, grantKey] {
        const std::string& groupId = statement.groupId;
        _treeVerifier.pinCommitted(groupId, contextId, statement, users, managers, rules);
        // Looked up now, not when planned: `settle` may run this long after, with the group's cache replaced meanwhile.
        _treeKeyCaches.get(groupId)->putGrantKey(static_cast<std::uint32_t>(statement.keyVersion), grantKey);
        // Minted here and accepted at exactly this epoch (the CAS), so it is the epoch's published key: the metadata
        // refresh that follows opens it without a read.
        _epochKeys.set(memoKeyFor(groupId, std::to_string(statement.keyVersion)), grantKey);
        // Its rungs passed the self-check against the chain (`buildRotationRungs`) before it was submitted: nothing
        // for the observed-rotation check to look at.
        markLadderChecked(groupId, static_cast<std::uint32_t>(statement.keyVersion));
        invalidateModuleKeysInCache(groupId);
    };
}

void GroupApiImpl::rotateGroupKey(const std::string& groupId) {
    retryPendingCarry(groupId);
    bool committedHere = true;
    PriorRole prior;
    commitWithRetry([&] { committedHere = rotateGroupKeyOnce(groupId, prior); });
    // As after a removal: the metadata planes sit one epoch behind, under the key the rotation replaces. Nobody left,
    // so nobody is accepted as an author beyond the members. Already done when an earlier call's rotation turned out
    // to have landed (`settle`).
    if (committedHere) {
        carryMetadataForward(groupId, CarryScope::NewEpoch, false, {}, prior);
    }
    runDueWork(groupId);
}

bool GroupApiImpl::rotateGroupKeyOnce(const std::string& groupId, PriorRole& prior) {
    // Every record, because the statement signs the tree hash, which a rotation leaves as it is.
    const std::string op = keytree::TreeCommits::opKey("rotate");
    const std::optional<server::GroupInfo> read = readForCommit(planRead(groupId), keytree::TreeVerifier::Scope::Plan, op);
    if (!read.has_value()) {
        return false;
    }
    const server::GroupInfo& currentGroup = read.value();
    prior = priorOf(currentGroup);
    const int64_t currentEpoch = currentGroup.keyVersion;
    const int64_t newEpoch = currentEpoch + 1;
    const int64_t newRosterVersion = currentGroup.rosterVersion + 1;

    // Unlike a removal, a rotation never abandons history: the point is a new key for the same members, and the
    // climb (a verified root key and the current grant key) is what the rungs down to the old epochs are made from.
    const auto cache = _treeKeyCaches.get(groupId);
    const keytree::TreeGroupState state = climbForPlanning(currentGroup, cache);
    const auto currentGrantKey = cache->getGrantKey(static_cast<std::uint32_t>(currentEpoch));
    if (!currentGrantKey.has_value() || currentGrantKey->getPublicKey().toBase58DER() != currentGroup.groupPubKey) {
        throw core::EncryptionKeyValidationException("rotating the group key needs the current grant key");
    }
    const auto [attestedUsers, attestedManagers] =
        _groupDataSchemaMapper->validateAndGetAttestedRoster(currentGroup, _keyProvider, _groupPrivKeyResolver);
    keytree::TreeVerifier::assertSeatsMatchRoster(currentGroup, attestedUsers, attestedManagers);
    const std::string rotatorId = keytree::GroupKeyResolver::ownUserId(currentGroup).value();

    keytree::TreeKeys tree(*cache);
    const keytree::CommitPlan plan = planOrThrow<keytree::CommitPlan>([&] {
        return tree.planRotation(state, rotatorId, _userPrivKey);
    });
    const std::vector<keytree::ArchiveRung> rungs = buildRotationRungs(
        currentGroup, static_cast<std::uint32_t>(newEpoch), plan.grantKey, currentGrantKey, rotatorId, *cache
    );
    const RosterAfterChange roster = rosterFromUserIds(attestedUsers, attestedManagers);
    const std::string newGroupPubKeyStr = plan.grantKey.getPublicKey().toBase58DER();
    const NewEpochRoster sealed = sealRosterForNewEpoch(
        currentGroup, roster, newGroupPubKeyStr, newEpoch, newRosterVersion, false
    );

    server::GroupGenerateNewKeyModel model;
    model.id = groupId;
    model.groupPubKey = newGroupPubKeyStr;
    model.keyId = sealed.keyId;
    model.data = sealed.data;
    model.grantEdge = keytree::TreeWire::toWire(plan.edges.at(0));
    const keytree::GroupRules rules = rulesOf(currentGroup);
    keytree::CommitStatement statement = keytree::TreeCommits::statementFor(
        plan, keytree::CommitOp::Rotate, groupId, commitDate(), static_cast<std::uint64_t>(newEpoch), newGroupPubKeyStr,
        static_cast<std::uint64_t>(newRosterVersion), attestedUsers, attestedManagers, rotatorId, {}, {}, {}, rules.hash
    );
    chainTo(statement, currentGroup);
    keytree::TreeCommits::sign(statement, _userPrivKey);
    model.commit = keytree::TreeCommits::toWire(statement);
    model.rungs = keytree::TreeWire::toWire(rungs);
    model.groupKeys = sealed.groupKeys;
    model.expectedKeyVersion = currentEpoch;
    model.expectedRosterVersion = currentGroup.rosterVersion;

    const auto sent = std::make_shared<const server::GroupGenerateNewKeyModel>(std::move(model));
    submit(
        groupId, statement,
        UnresolvedCommit{
            .op = op,
            .kind = "rotation",
            .contextId = currentGroup.contextId,
            .send = [this, sent] { _serverApi.groupGenerateNewKey(*sent); },
            // Pinned before anything reads the group again: the state under the replaced key is refused from here on.
            .landed = landedEpoch(currentGroup.contextId, statement, roster, rules, plan.grantKey),
            .after = [this, groupId, prior] { carryMetadataForward(groupId, CarryScope::NewEpoch, false, {}, prior); }
        }
    );
    return true;
}

void GroupApiImpl::commitWithRetry(const std::function<void()>& attempt) {
    for (int attemptNo = 1;; ++attemptNo) {
        try {
            attempt();
            return;
        } catch (const StalePlan&) {
            // Another commit of this client to the group landed while this one was planned on the head before it.
            if (attemptNo < MAX_COMMIT_ATTEMPTS) {
                LOG_DEBUG("group commit planned behind this client's own commit, re-planning")
                continue;
            }
            throw RotatedAlreadyException();
        } catch (const privmx::utils::PrivmxException& e) {
            if (attemptNo < MAX_COMMIT_ATTEMPTS && isRetryableCommitRejection(e)) {
                LOG_DEBUG("group commit planned against a moved base, re-planning: ", e.what())
                continue;
            }
            core::ExceptionConverter::rethrowAsCoreException(e);
            throw core::Exception("ExceptionConverter rethrow error");
        }
    }
}

// A concurrent commit — most often a self-update, which every member under a blanked node runs on its own — moved
// the generations or versions this one was planned against. Nothing about the request was wrong, so a fresh read
// and a fresh plan are all it takes; anything else the bridge refuses is reported as it is.
bool GroupApiImpl::isRetryableCommitRejection(const privmx::utils::PrivmxException& e) {
    const unsigned int code = e.getCode();
    if ((code & 0xFFFF0000) != 0) {
        return false; // not a bridge application error
    }
    switch (code & 0x0000FFFF) {
    case ROTATED_ALREADY:
    case GROUP_ROSTER_VERSION_MISMATCH:
        return true;
    case GROUP_TREE_INVALID:
        // A rotation moves no node, so a self-update under it shows as its grant edge's stale child generation
        // (the root's); every other commit sees it as a stale base generation.
        return e.getData().find("\"STALE_BASE_GENERATION\"") != std::string::npos ||
               e.getData().find("\"STALE_CHILD_GENERATION\"") != std::string::npos;
    default:
        return false;
    }
}

void GroupApiImpl::scheduleSelfUpdateIfNeeded(const std::string& groupId, const server::GroupInfo& group) {
    const auto node = keytree::GroupKeyResolver::nodeNeedingSelfUpdate(group);
    if (!node.has_value()) {
        return;
    }
    scheduleSelfUpdate(groupId, backgroundWindowMs(group), keytree::GroupKeyResolver::healsFirst(group, node.value()));
}

std::int64_t GroupApiImpl::backgroundWindowMs(const server::GroupInfo& group) {
    // Limit: 8 ms per seat, 1-120 s. One window holds the first healers of a fresh 16k group (~n/32 commits) at
    // the bridge's ~5-10 commits/s only with retries; a per-group rate limit on the bridge is the upgrade path.
    return std::clamp<std::int64_t>(
        group.numLeaves.value_or(1) * BACKGROUND_MS_PER_SEAT, BACKGROUND_WINDOW_MIN_MS, BACKGROUND_WINDOW_MAX_MS
    );
}

void GroupApiImpl::scheduleSelfUpdate(
    const std::string& groupId,
    std::int64_t windowMs,
    bool healsFirst,
    int attempts
) {
    std::unique_lock<std::mutex> lock(_dueMutex);
    if (_selfUpdatePending.count(groupId) > 0) {
        return;
    }
    // The healer of a node commits within the window; everybody else under it waits the window out first and then
    // finds (on a path read) the node already refilled, unless that healer is gone. Jitter keeps the healers of
    // different nodes, and the stand-ins, from colliding on the generations they all refresh.
    const auto delay = std::chrono::milliseconds(healsFirst ? 0 : windowMs) + jitter(windowMs);
    _selfUpdatePending[groupId] = {std::chrono::steady_clock::now() + delay, windowMs, attempts};
}

void GroupApiImpl::scheduleLadderCheck(
    const std::string& groupId,
    const std::string& contextId,
    std::uint32_t at,
    std::int64_t windowMs
) {
    std::unique_lock<std::mutex> lock(_dueMutex);
    const std::string key = memoKeyFor(groupId, std::to_string(at));
    if (_ladderChecks.count(key) > 0) {
        return;
    }
    // Jittered so a group's online members do not all check at once; the bridge's serialisation of repairs, and the
    // re-check right before each one, are what keep concurrent repairs within the per-span cap.
    _ladderChecks[key] = {groupId, contextId, at, std::chrono::steady_clock::now() + jitter(windowMs)};
}

void GroupApiImpl::scheduleObservedRotation(
    const std::string& groupId,
    const std::string& contextId,
    std::uint32_t cur,
    std::int64_t windowMs
) {
    {
        // Several threads resolve keys at once: only the one that moves the mark queues the check.
        std::unique_lock<std::mutex> lock(_dueMutex);
        std::uint32_t& checked = _ladderCheckedAt[groupId];
        if (checked >= cur) {
            return;
        }
        checked = cur;
    }
    scheduleLadderCheck(groupId, contextId, cur, windowMs);
}

void GroupApiImpl::markLadderChecked(const std::string& groupId, std::uint32_t epoch) {
    std::unique_lock<std::mutex> lock(_dueMutex);
    std::uint32_t& checked = _ladderCheckedAt[groupId];
    checked = std::max(checked, epoch);
}

void GroupApiImpl::checkLadderAt(const std::string& groupId, const std::string& contextId, std::uint32_t at) {
    const auto cache = _treeKeyCaches.get(groupId);
    server::GroupGetKeyArchiveResult raw;
    // The rungs at `at` as served, and the floor (never lower than one seen before) nothing is repaired below.
    const auto unopened = [&]() {
        server::GroupGetKeyArchiveModel params;
        params.id = groupId;
        params.fromKeyVersion = at;
        params.toKeyVersion = at;
        raw = _serverApi.groupGetKeyArchive(params);
        const std::uint32_t floor = cache->raiseFloor(ladderFloorOf(raw.eraFloor, raw.archivePrunedBelow));
        return keytree::LadderKeys::unopenedSpans(at, keytree::GroupKeyResolver::toDownwardRungs(raw), *cache, floor);
    };
    // Cheap stage, the honest path: one fetch, one open per span, no statements read and no UserVerifier call.
    std::vector<keytree::RungSpan> spans = unopened();
    if (spans.empty()) {
        return;
    }
    // Something looks broken. The cache decided that, and the cache is not the chain: every key about to be sealed,
    // and the key it is sealed to, is checked against the epoch's opener first. A mismatch is forgotten, never sealed.
    const auto openers = _treeVerifier.epochOpeners(groupId, contextId, treeEnvironment(groupId));
    const auto matchesChain = [&](std::uint32_t epoch) {
        const auto key = cache->getGrantKey(epoch);
        const auto opener = openers.find(epoch);
        if (!key.has_value() || opener == openers.end()) {
            return false;
        }
        if (key->getPublicKey().toBase58DER() != opener->second.groupPubKey) {
            LOG_WARN("[ladder] a cached grant key is not its epoch's; forgotten: ", std::to_string(epoch))
            cache->forgetGrantKey(epoch);
            return false;
        }
        return true;
    };
    if (!matchesChain(at)) {
        return;
    }
    spans.erase(
        std::remove_if(spans.begin(), spans.end(), [&](const keytree::RungSpan& span) { return !matchesChain(span.target); }),
        spans.end()
    );
    for (const keytree::RungSpan& span : spans) {
        // Somebody may have repaired it meanwhile: re-checked right before, so the members who lost the race stop.
        const std::vector<keytree::RungSpan> still = unopened();
        if (std::none_of(still.begin(), still.end(), [&](const keytree::RungSpan& s) { return s.target == span.target; })) {
            continue;
        }
        const auto atKey = cache->getGrantKey(at);
        const auto targetKey = cache->getGrantKey(span.target);
        if (!atKey.has_value() || !targetKey.has_value()) {
            continue;
        }
        keytree::ArchiveRung rung;
        rung.span = span;
        rung.blob = keytree::LadderKeys::sealRung(targetKey.value(), span, atKey->getPublicKey(), _userPrivKey);
        try {
            _serverApi.groupRepairRung(server::GroupRepairRungModel{.id = groupId, .rung = keytree::TreeWire::toWire(rung)});
            LOG_INFO("[ladder] repaired rung ", std::to_string(span.at) + "->" + std::to_string(span.target))
        } catch (const privmx::utils::PrivmxException& e) {
            // SPAN_FULL, AUTHOR_HAS_RUNG, ROTATED_ALREADY, the budget: not retried; the next trigger re-checks.
            LOG_WARN("[ladder] repair refused: ", e.what())
        }
    }
}

void GroupApiImpl::runDueWork(const std::string& groupId) {
    if (_dueWorkOff) {
        return;
    }
    const auto now = std::chrono::steady_clock::now();
    std::vector<PendingLadderCheck> checks;
    std::optional<PendingSelfUpdate> update;
    {
        std::unique_lock<std::mutex> lock(_dueMutex);
        for (auto it = _ladderChecks.begin(); it != _ladderChecks.end();) {
            if (it->second.groupId == groupId && it->second.due <= now) {
                checks.push_back(it->second);
                it = _ladderChecks.erase(it);
            } else {
                ++it;
            }
        }
        if (const auto it = _selfUpdatePending.find(groupId); it != _selfUpdatePending.end() && it->second.due <= now) {
            update = it->second;
            _selfUpdatePending.erase(it);
        }
    }
    for (const PendingLadderCheck& check : checks) {
        try {
            checkLadderAt(check.groupId, check.contextId, check.at);
        } catch (const std::exception& e) {
            LOG_WARN("[ladder] check dropped: ", e.what())
        } catch (...) { LOG_WARN("[ladder] check dropped") }
    }
    if (update.has_value()) {
        bool lostRace = false;
        try {
            selfUpdate(groupId);
        } catch (const StalePlan&) {
            lostRace = true; // planned behind a commit of this client's own; re-plan like a lost race
        } catch (const privmx::utils::PrivmxException& e) {
            lostRace = isRetryableCommitRejection(e);
            if (!lostRace) {
                LOG_WARN("[selfUpdate] group key tree self-update dropped: ", e.what())
            }
        } catch (const std::exception& e) {
            LOG_WARN("[selfUpdate] group key tree self-update dropped: ", e.what())
        } catch (...) { LOG_WARN("[selfUpdate] group key tree self-update dropped") }
        {
            // What its own reads recorded meanwhile describes the state before its commit.
            std::unique_lock<std::mutex> lock(_dueMutex);
            _selfUpdatePending.erase(groupId);
        }
        // A lost race is recorded again with a fresh random delay, so the members that collided spread out.
        if (lostRace && update->attempts + 1 < MAX_SELF_UPDATE_ATTEMPTS) {
            scheduleSelfUpdate(groupId, update->windowMs, true, update->attempts + 1);
        } else if (lostRace) {
            LOG_WARN("[selfUpdate] group key tree self-update dropped after repeated concurrent commits")
        }
    }
    savePinsIfDue();
}

void GroupApiImpl::savePinsIfDue() noexcept {
    try {
        {
            std::unique_lock<std::mutex> lock(_dueMutex);
            if (!_pinsMovedMajor &&
                !(_pinsMoved && std::chrono::steady_clock::now() - _lastPinSave >= PIN_SAVE_IDLE_INTERVAL)) {
                return;
            }
        }
        savePins();
    } catch (const std::exception& e) {
        LOG_WARN("[pins] save dropped: ", e.what())
    } catch (...) { LOG_WARN("[pins] save dropped") }
}

void GroupApiImpl::selfUpdate(const std::string& groupId) {
    selfUpdateWith(groupId, nullptr, SELF_UPDATE_OP, false);
}

bool GroupApiImpl::renewLeaf(const std::string& groupId, const std::string& previousUserPrivKey) {
    std::optional<privmx::crypto::PrivateKey> previous;
    try {
        previous = privmx::crypto::PrivateKey::fromWIF(previousUserPrivKey);
    } catch (...) {
        throw core::InvalidParamsException("the previous key is not a private key in WIF");
    }
    if (previous->getPublicKey() == _userPrivKey.getPublicKey()) {
        throw core::InvalidParamsException("the previous key is the current key");
    }
    // The previous key's pins first, so the read the renewal plans on continues them (the app is meant to have
    // done this at connect with Connection::adoptPreviousIdentity; a second adoption is a no-op).
    adoptPreviousIdentity(previous.value());
    bool renewed = false;
    commitWithRetry([&] { renewed = selfUpdateWith(groupId, &previous.value(), RENEW_LEAF_OP, true); });
    runDueWork(groupId);
    return renewed;
}

bool GroupApiImpl::selfUpdateWith(
    const std::string& groupId,
    const privmx::crypto::PrivateKey* previousKey,
    const std::string& op,
    bool mayCompleteOther
) {
    const server::GroupGetModel getModel = planRead(groupId);
    server::GroupInfo group;
    keytree::TreeGroupState state;
    std::pair<std::vector<std::string>, std::vector<std::string>> roster;
    // What the plan climbs over: the group's shared cache, or the renewal's call-local one, so nothing derived from
    // the previous key ever reaches a reader, a deferred self-update or a failed renewal's next call.
    std::shared_ptr<keytree::TreeKeyCache> planCache = _treeKeyCaches.get(groupId);
    if (previousKey == nullptr) {
        // The need first, on the small path view: by now the node's healer, or anybody's commit through it, has most
        // likely refilled it, and the plan view carries every node record of the tree.
        const server::GroupGetModel pathModel = pathRead(groupId);
        auto pathView = _serverApi.groupGet(pathModel).group;
        if (!verifyTree(pathView, pathModel, keytree::TreeVerifier::Scope::Path)) {
            return false;
        }
        // Before the need check: an unresolved self-update of ours is resent (or found landed), never planned again.
        switch (settle(groupId, op, mayCompleteOther)) {
        case Settled::Proceed:
            break;
        case Settled::Deferred:
            LOG_DEBUG("[selfUpdate] deferred: an earlier commit of this client to the group has no known outcome yet")
            return false;
        default:
            return false;
        }
        if (!keytree::GroupKeyResolver::nodeNeedingSelfUpdate(pathView).has_value()) {
            return false;
        }
        group = _serverApi.groupGet(getModel).group;
        verifyTree(group, getModel, keytree::TreeVerifier::Scope::Plan);
        // Re-checked on a fresh read: somebody's commit through the same nodes may have refilled them meanwhile.
        if (!keytree::GroupKeyResolver::hasTree(group) ||
            !keytree::GroupKeyResolver::hasSupportedTree(group) ||
            !keytree::GroupKeyResolver::nodeNeedingSelfUpdate(group).has_value()) {
            return false;
        }
        // A self-update wraps to whoever is seated, so it needs the seats proven against the roster like any commit.
        roster = _groupDataSchemaMapper->validateAndGetAttestedRoster(group, _keyProvider, _groupPrivKeyResolver);
        keytree::TreeVerifier::assertSeatsMatchRoster(group, roster.first, roster.second);
        state = climbForPlanning(group, planCache);
    } else {
        // Leaf renewal. No need gate: the need is the leaf not opening with the session's key, checked below.
        std::optional<server::GroupInfo> read =
            readForCommit(getModel, keytree::TreeVerifier::Scope::Plan, op, mayCompleteOther, [] {
                throw core::EncryptionKeyValidationException("caller holds no leaf in this group's key tree");
            });
        if (!read.has_value()) {
            return true;
        }
        group = std::move(read.value());
        // Renewed already: a commit after the directory change wrapped the leaf to the session's key.
        const keytree::TreeGroupState current = keytree::GroupKeyResolver::toTreeState(group);
        keytree::TreeKeys sharedTree(*planCache);
        const std::string ownId = keytree::GroupKeyResolver::ownUserId(group).value();
        if (sharedTree.climbToGrantKey(current, ownId, _userPrivKey, false).failure == keytree::ClimbFailure::None) {
            return false;
        }
        planCache = std::make_shared<keytree::TreeKeyCache>();
        const ClimbWith with{planCache, previousKey};
        state = climbForPlanning(group, planCache, nullptr, previousKey);
        // After the climb (the roster key resolves only through the grant key it recovered) and on the same read, so
        // a concurrent epoch change cannot make it check a different state.
        roster = _groupDataSchemaMapper->validateAndGetAttestedRoster(group, _keyProvider, resolverOver(&group, &with));
        keytree::TreeVerifier::assertSeatsMatchRoster(group, roster.first, roster.second);
    }
    const auto& [attestedUsers, attestedManagers] = roster;
    const std::string memberId = keytree::GroupKeyResolver::ownUserId(group).value();

    keytree::TreeKeys tree(*planCache);
    // Own key: the session's, taken locally (`commitRecipientKeys`), never the directory's.
    tree.setMemberKeyStrings(commitRecipientKeys(
        group, keytree::TreeKeys::recipients(state, keytree::TreeKeys::shapeSelfUpdate(state, memberId)), memberId
    ));
    const keytree::CommitPlan plan = planOrThrow<keytree::CommitPlan>([&] {
        return tree.planSelfUpdate(state, memberId, _userPrivKey);
    });

    server::GroupSelfUpdateModel model;
    model.id = groupId;
    model.expectedKeyVersion = group.keyVersion;
    model.transition = keytree::TreeWire::toSelfUpdateTransition(plan, group.keyVersion);
    const keytree::GroupRules rules = rulesOf(group);
    keytree::CommitStatement statement = keytree::TreeCommits::statementFor(
        plan, keytree::CommitOp::SelfUpdate, groupId, commitDate(), static_cast<std::uint64_t>(group.keyVersion),
        group.groupPubKey, static_cast<std::uint64_t>(group.rosterVersion), attestedUsers, attestedManagers, memberId,
        {}, {}, {}, rules.hash
    );
    chainTo(statement, group);
    keytree::TreeCommits::sign(statement, _userPrivKey);
    model.commit = keytree::TreeCommits::toWire(statement);
    const auto sent = std::make_shared<const server::GroupSelfUpdateModel>(std::move(model));
    const std::string contextId = group.contextId;
    submit(
        groupId, statement,
        UnresolvedCommit{
            .op = op,
            // A renewal names its end state (the leaf opens with the session's key): found landed, it is done.
            .namesEndState = previousKey != nullptr,
            .kind = previousKey != nullptr ? "leaf renewal" : "self-update",
            .contextId = contextId,
            .send = [this, sent] { _serverApi.groupSelfUpdate(*sent); },
            .landed =
                [this, groupId, contextId, statement, users = attestedUsers, managers = attestedManagers, rules,
                 grantKey = plan.grantKey] {
                    _treeVerifier.pinCommitted(groupId, contextId, statement, users, managers, rules);
                    // The epoch's own grant key (a self-update keeps the epoch; the climb checked it against the
                    // verified state), now landed. A renewal planned on a scratch cache, so without this the next
                    // removal would ask the leaf again, and the edges name no recipient: a member wrapping it back to
                    // the previous public key would get the removal refused after every renewal.
                    _treeKeyCaches.get(groupId)->putGrantKey(static_cast<std::uint32_t>(statement.keyVersion), grantKey);
                }
        }
    );
    return true;
}

bool GroupApiImpl::carryMetadataForward(
    const std::string& groupId,
    CarryScope scope,
    bool historyAbandoned,
    const std::vector<std::string>& losers,
    const PriorRole& prior
) {
    try {
        // One verified answer decides both whether a plane is carried and what it says: re-signing metadata this
        // client has not attested would launder whatever the bridge served into an entry under the committer's name,
        // and an unverified epoch would let the bridge talk this out of running.
        const server::GroupInfo group = readGroupForKeys(groupId);
        bool carryPublic = false;
        bool carryPrivate = false;
        if (scope == CarryScope::NewEpoch) {
            // Per plane, because the two sit at epochs of their own: one may already have been carried up by a
            // concurrent write while the other is still behind.
            carryPublic = group.publicMeta.keyVersion < group.keyVersion;
            carryPrivate = group.privateMeta.keyVersion < group.keyVersion;
            if (historyAbandoned) {
                // A plane behind sits under a key nobody can reach any more, and what it says cannot be attested:
                // start it over, empty, in the new epoch rather than leave it unreadable for good.
                if (carryPublic) {
                    writeMeta(group, true, core::Buffer(), group.publicMetaVersion);
                }
                if (carryPrivate) {
                    writeMeta(group, false, core::Buffer(), group.privateMetaVersion);
                }
                return true;
            }
        } else {
            const auto lost = [&](const std::string& author) {
                return std::find(losers.begin(), losers.end(), author) != losers.end();
            };
            carryPublic = lost(group.publicMeta.author);
            carryPrivate = lost(group.privateMeta.author);
        }
        // On every carried plane: only the very entry read before the commit. One tagged since (by a member
        // removed meanwhile, or by a loser of a narrowing, which still holds the current key) is never re-signed.
        carryPublic = carryPublic && GroupDataSchemaMapper::sameEntry(group.publicMeta, prior.publicMeta);
        carryPrivate = carryPrivate && GroupDataSchemaMapper::sameEntry(group.privateMeta, prior.privateMeta);
        if (!carryPublic && !carryPrivate) {
            return true; // already current, or written over since: nothing of the read is left to carry
        }
        // The entries as read are judged by the read's rules and roster: a plane whose author lacked `update`
        // then is refused here too, so neither a removal nor a narrowing launders it.
        const Group verified =
            _groupDataSchemaMapper->validateDecryptAndConvertGroup(group, _keyProvider, resolverOver(&group), prior);
        if (verified.statusCode != 0) {
            return false;
        }
        // One write per carried plane, both off the one verified read: a metadata write moves neither the head nor
        // the epoch it is checked against.
        if (carryPublic) {
            writeMeta(group, true, verified.publicMeta, verified.publicMetaVersion);
        }
        if (carryPrivate) {
            writeMeta(group, false, verified.privateMeta, verified.privateMetaVersion);
        }
        return true;
    } catch (const std::exception& e) {
        // Best-effort by design. A failure leaves the planes where the commit left them, and the next metadata write
        // closes the window; throwing here would fail a commit that has already happened.
        LOG_WARN("[carryMetadataForward] group ", groupId, " metadata not carried forward: ", e.what())
        return false;
    } catch (...) {
        LOG_WARN("[carryMetadataForward] group ", groupId, " metadata not carried forward")
        return false;
    }
}

PriorRole GroupApiImpl::priorOf(const server::GroupInfo& group) {
    return PriorRole{
        .rules = rulesOf(group),
        .users = group.users,
        .managers = group.managers,
        .publicMeta = group.publicMeta,
        .privateMeta = group.privateMeta
    };
}

void GroupApiImpl::runPolicyCarry(const std::string& groupId, const PendingCarry& carry) {
    const bool done = carryMetadataForward(groupId, CarryScope::Policy, false, carry.losers, carry.prior);
    std::lock_guard<std::mutex> lock(_pendingCarryMutex);
    if (done) {
        _pendingCarry.erase(groupId);
    } else {
        _pendingCarry[groupId] = carry;
    }
}

void GroupApiImpl::retryPendingCarry(const std::string& groupId) {
    std::optional<PendingCarry> pending;
    {
        std::lock_guard<std::mutex> lock(_pendingCarryMutex);
        const auto it = _pendingCarry.find(groupId);
        if (it == _pendingCarry.end()) {
            return;
        }
        pending = it->second;
    }
    runPolicyCarry(groupId, pending.value());
}

MetaWriteContext GroupApiImpl::prepareMetaWrite(const server::GroupInfo& currentGroup) {
    const auto& currentEntry = currentGroup.data.back();
    const auto resourceId = currentGroup.resourceId.value_or(core::EndpointUtils::generateId());
    const int64_t currentEpoch = currentGroup.keyVersion;

    // Names no diff, so `UsersKeysResolver` sees no reason to mint a key: the pub keys are deliberately empty
    // because nothing here is wrapped to anybody.
    const auto roster = rosterFromUserIds(currentGroup.users, currentGroup.managers);
    auto ctx = prepareContainerUpdateWithoutKeyEntries(
        currentGroup, currentEntry, resourceId, roster.users, roster.managers, false
    );

    // The roster head always sits at the current epoch, so the key selected off it is the current epoch's.
    // Were that to stop holding, metadata would be written under a key a removed member still holds.
    if (ctx.key.id != currentEntry.keyId) {
        throw GroupDataIntegrityException("metadata write resolved a key that is not the current epoch's");
    }
    return MetaWriteContext{.resourceId = resourceId, .currentEpoch = currentEpoch, .ctx = ctx};
}

void GroupApiImpl::updateGroupPublicMeta(
    const std::string& groupId,
    const core::Buffer& publicMeta,
    const int64_t version
) {
    // The default path view is enough: this submits no tree and does not touch the roster at all.
    writeMeta(readGroupForKeys(groupId), true, publicMeta, version);
    // After, not before: the carry would move the counter this write is checked against. It skips a plane this
    // write replaced (no longer the entry it read).
    retryPendingCarry(groupId);
    runDueWork(groupId);
}

void GroupApiImpl::updateGroupPrivateMeta(
    const std::string& groupId,
    const core::Buffer& privateMeta,
    const int64_t version
) {
    writeMeta(readGroupForKeys(groupId), false, privateMeta, version);
    retryPendingCarry(groupId);
    runDueWork(groupId);
}

void GroupApiImpl::writeMeta(
    const server::GroupInfo& currentGroup,
    bool publicPlane,
    const core::Buffer& meta,
    const int64_t version
) {
    const auto w = prepareMetaWrite(currentGroup);
    // The same `version` feeds the CAS field below, so the version this commits to and the version the bridge checks
    // cannot disagree.
    const dynamic::MetaBlock block{
        .metaTag = (publicPlane ? GroupDataSchemaMapper::publicMetaTag : GroupDataSchemaMapper::privateMetaTag)(
            w.ctx.key.key, w.currentEpoch, version + 1
        ),
        .keyId = w.ctx.key.id,
        .keyVersion = w.currentEpoch,
        .metaVersion = version + 1
    };
    // No force field, unlike the other containers: the entry commits the version it lands at, so a write that
    // skipped the version check could only land a tag no reader will accept.
    const auto fill = [&](auto& model) {
        model.id = currentGroup.id;
        model.resourceId = w.resourceId;
        model.keyId = w.ctx.key.id;
        model.version = version;
    };
    // A metadata write is never answered with `ROTATED_ALREADY` (that is the commits'); a version conflict is the
    // caller's to re-read, like any other.
    if (publicPlane) {
        server::GroupUpdatePublicMetaModel model;
        fill(model);
        model.data = _groupDataSchemaMapper->encryptPublicMeta(
            GroupPublicMetaToEncryptV5{.publicMeta = meta, .dio = w.ctx.dio, .meta = block}
        );
        _serverApi.groupUpdatePublicMeta(model);
    } else {
        server::GroupUpdatePrivateMetaModel model;
        fill(model);
        model.data = _groupDataSchemaMapper->encryptPrivateMeta(
            GroupPrivateMetaToEncryptV5{.privateMeta = meta, .dio = w.ctx.dio, .meta = block}, w.ctx.key.key
        );
        _serverApi.groupUpdatePrivateMeta(model);
    }
    // Rotates nothing — not the content key, not the grant key, not the tree. Only the cached view is stale.
    invalidateModuleKeysInCache(currentGroup.id);
}

void GroupApiImpl::updateGroupPolicy(const std::string& groupId, const core::ContainerPolicy& policies) {
    retryPendingCarry(groupId);
    std::optional<PendingCarry> carry;
    commitWithRetry([&] {
        carry.reset();
        updateGroupPolicyOnce(groupId, policies, carry);
    });
    // A plane whose author lost `update` is refused from now on; carry it under the caller's name.
    if (carry.has_value()) {
        runPolicyCarry(groupId, carry.value());
    }
    runDueWork(groupId);
}

void GroupApiImpl::updateGroupPolicyOnce(
    const std::string& groupId,
    const core::ContainerPolicy& policies,
    std::optional<PendingCarry>& carry
) {
    // A signed commit like any other: the chain, the CAS and the role check. It moves no node, no epoch and
    // no roster, so the path view is enough to sign the tree hash as it stands.
    const server::GroupGetModel getModel = pathRead(groupId);
    auto group = _serverApi.groupGet(getModel).group;
    if (!verifyTree(group, getModel, keytree::TreeVerifier::Scope::Path)) {
        throw core::InvalidParamsException("only a member of a group can change its policy");
    }
    const Poco::Dynamic::Var policy = core::Factory::createPolicyServerObject(policies);
    const keytree::GroupRules newRules = requestedRules(policy, group.creator);
    // The whole wire policy, not only the signed rules: two calls differing in a Bridge-held field (`get`, `item.*`)
    // name different end states, and one must never return on the other.
    const std::string op = keytree::TreeCommits::opKey("policy", {privmx::utils::Utils::stringifyVar(policy)});
    switch (settle(groupId, op, true)) {
    case Settled::Done:
        return;
    case Settled::Reread:
        group = rereadVerified(getModel, keytree::TreeVerifier::Scope::Path);
        break;
    default:
        break;
    }
    // Commit B: the planes as read, attested under the rules in force, and whose authors the new rules leave without
    // `update`. Those planes would be refused once this lands; somebody who keeps `update` must carry them.
    const PriorRole prior = priorOf(group);
    std::vector<std::string> losers;
    const Group mapped =
        _groupDataSchemaMapper->validateDecryptAndConvertGroup(group, _keyProvider, resolverOver(&group), prior);
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
    chainTo(statement, group);
    keytree::TreeCommits::sign(statement, _userPrivKey);

    const auto sent = std::make_shared<const server::GroupUpdatePolicyModel>(server::GroupUpdatePolicyModel{
        .id = groupId,
        .commit = keytree::TreeCommits::toWire(statement),
        .expectedKeyVersion = group.keyVersion,
        .expectedRosterVersion = group.rosterVersion
    });
    // Keys are untouched, so nothing is invalidated: the module key cache keys on `rosterVersion`, which stays.
    submit(
        groupId, statement,
        UnresolvedCommit{
            .op = op,
            .namesEndState = true,
            .kind = "policy change",
            .contextId = group.contextId,
            .send = [this, sent] { _serverApi.groupUpdatePolicy(*sent); },
            .landed =
                [this, groupId, contextId = group.contextId, statement, users = group.users,
                 managers = group.managers, newRules] {
                    _treeVerifier.pinCommitted(groupId, contextId, statement, users, managers, newRules);
                },
            // Found landed by a later call's `settle`: the carry runs there.
            .after = losers.empty() ? std::function<void()>() :
                                      [this, groupId, pending = PendingCarry{losers, prior}] {
                                          runPolicyCarry(groupId, pending);
                                      }
        }
    );
    if (!losers.empty()) {
        carry = PendingCarry{losers, prior};
    }
}

void GroupApiImpl::deleteGroup(const std::string& groupId) {
    server::GroupDeleteModel model{.groupId = groupId};
    _serverApi.groupDelete(model);
    forgetGroupKeys(groupId);
    invalidateModuleKeysInCache(groupId);
}

Group GroupApiImpl::getGroup(const std::string& groupId) {
    retryPendingCarry(groupId);
    const server::GroupGetModel params = pathRead(groupId);
    // The head roster entry and the current metadata entry — two entries, whatever the group's age. The cache is
    // keyed on the roster version, because that is the plane key material moves with.
    auto group = _serverApi.groupGet(params).group;
    // The tree first, on this same answer: only the verified latest statement says which epoch is current. A caller
    // without a seat gets the group as before, with nothing cached.
    const bool seated = verifyTree(group, params, keytree::TreeVerifier::Scope::Path);
    // An unseated answer is bound to the chain (`verifyListed`: describes() binds policy, creator and roster; replay
    // from the pin when this process has one) before the mapper reads any of it; a rollback below the pin counts as
    // not attested.
    const bool attested = seated || hasVerifiedGrantKey(group);
    // An answer refused below as not attested must not move the version pins either, or the next honest answer
    // would look like a rollback.
    Group result = _groupDataSchemaMapper->validateDecryptAndConvertGroup(
        group, _keyProvider, seated ? resolverOver(&group) : _groupPrivKeyResolver, std::nullopt, attested
    );
    if (!attested) {
        // Outsiders seal anonymous envelopes to it: only as the latest statement vouches for it.
        result.groupPubKey.clear();
        if (result.statusCode == 0) {
            // Planes opened under keys the resolver found, on a policy and roster nobody signed: not handed out.
            result.statusCode = GroupDataIntegrityException().getCode();
            result.publicMeta = core::Buffer();
            result.privateMeta = core::Buffer();
        }
    }
    // Writes take their key from this cache, so only an answer that passed everything may fill it.
    if (seated && result.statusCode == 0) {
        assertHeadKeyAtEpoch(group);
        setNewModuleKeysInCache(group.id, groupToModuleKeys(group), group.rosterVersion);
    }
    runDueWork(groupId);
    return result;
}

core::PagingList<GroupSummary> GroupApiImpl::listGroups(
    const std::string& contextId,
    const core::PagingQuery& pagingQuery
) {
    server::GroupListModel model;
    model.contextId = contextId;
    core::ListQueryMapper::map(model, pagingQuery);
    auto groupsList = _serverApi.groupList(model);
    std::vector<GroupSummary> groups;
    groups.reserve(groupsList.groups.size());
    for (const auto& group : groupsList.groups) {
        groups.push_back(GroupDataSchemaMapper::toLibGroupSummary(group));
        // What an outsider would seal anonymous envelopes to. A listing carries no statement to vouch for it, so only
        // the key of a state this process has verified is handed out; `getGroup` verifies the rest.
        if (!_treeVerifier.pinnedAt(group.id, contextId, group.keyVersion, group.groupPubKey)) {
            groups.back().groupPubKey.clear();
        }
    }
    return core::PagingList<GroupSummary>({.totalAvailable = groupsList.count, .readItems = groups});
}

bool GroupApiImpl::hasVerifiedGrantKey(const server::GroupInfo& group) {
    const SaveDuePins saveAfter{*this};
    try {
        _treeVerifier.verifyListed(group, treeEnvironment(group.id));
    } catch (const std::exception& e) {
        LOG_WARN("[hasVerifiedGrantKey] group ", group.id, " failed verification: ", e.what())
        return false;
    }
    return group.treeCommit->seq >= static_cast<std::int64_t>(_treeVerifier.pinnedSeq(group.id));
}

std::unordered_map<std::string, core::GroupEpochInfo> GroupApiImpl::fetchGroupEpochs(
    const std::string& contextId,
    const std::vector<std::string>& groupIds
) {
    const SaveDuePins saveAfter{*this};
    std::unordered_map<std::string, core::GroupEpochInfo> epochs;
    // A container key is about to be wrapped to these grant keys, so each comes off the group's latest statement.
    // A writer outside the group trusts that the signer, vouched by the UserVerifier, is a member (TOFU on membership).
    // The listing (constant size) says which epoch is current; one this process has pinned is taken from the pin,
    // anything else is read with `groupGet` (roster and statement, which grow) and verified. Returns the ids served
    // behind the state this process has verified for them.
    const auto take = [&](const std::vector<std::string>& ids) {
        server::GroupListModel model;
        model.contextId = contextId;
        core::ListQueryMapper::map(model, pageOfIds("#id", ids));
        std::vector<std::string> behind;
        std::vector<server::GroupSummary> listed;
        try {
            listed = _serverApi.groupList(model).groups;
        } catch (const std::exception& e) { LOG_WARN("[fetchGroupEpochs] groupList by id unavailable: ", e.what()) }
        std::vector<server::GroupInfo> read;
        for (const auto& summary : listed) {
            // A listing for another context would have the UserVerifier vouch for the committer there.
            if (summary.contextId != contextId) {
                continue;
            }
            if (_treeVerifier.pinnedAt(summary.id, contextId, summary.keyVersion, summary.groupPubKey)) {
                epochs[summary.id] =
                    core::GroupEpochInfo{.keyVersion = summary.keyVersion, .groupPubKey = summary.groupPubKey};
                continue;
            }
            // Limit: one `groupGet` per unpinned group, the whole tree for a caller without a seat; a statement-and-
            // roster read would do if non-member writes to new or rotated groups get hot.
            try {
                read.push_back(_serverApi.groupGet(pathRead(summary.id)).group);
            } catch (const std::exception& e) {
                LOG_WARN("[fetchGroupEpochs] group ", summary.id, " unreadable: ", e.what())
            }
        }
        _treeVerifier.preverifyListed(read, treeEnvironment(std::string()));
        for (const auto& group : read) {
            // A group that fails verification gets no key at all, never the unverified one.
            if (group.contextId != contextId) {
                continue;
            }
            try {
                _treeVerifier.verifyListed(group, treeEnvironment(group.id));
            } catch (const std::exception& e) {
                LOG_WARN("[fetchGroupEpochs] group ", group.id, " failed verification: ", e.what())
                continue;
            }
            if (group.treeCommit->seq < static_cast<std::int64_t>(_treeVerifier.pinnedSeq(group.id))) {
                behind.push_back(group.id);
                continue;
            }
            epochs[group.id] = core::GroupEpochInfo{.keyVersion = group.keyVersion, .groupPubKey = group.groupPubKey};
        }
        return behind;
    };
    for (size_t offset = 0; offset < groupIds.size(); offset += BRIDGE_MAX_BATCH_SIZE) {
        const std::vector<std::string> behind = take(std::vector<std::string>(
            groupIds.begin() + offset, groupIds.begin() + std::min(offset + BRIDGE_MAX_BATCH_SIZE, groupIds.size())
        ));
        // Behind may be a read that lagged a concurrent one; read once more, and still behind gets no key.
        if (!behind.empty()) {
            take(behind);
        }
    }
    return epochs;
}

void GroupApiImpl::processNotificationEvent(const std::string& type, const core::NotificationEvent& notification) {
    auto subscriptionQuery = _subscriber.getSubscriptionQuery(notification.subscriptions);
    if (!subscriptionQuery.has_value()) {
        return;
    }
    _guardedExecutor->exec([&, type, notification, subscriptionQuery]() {
        if (type == "custom") {
            // The channel name is not in the notification — it is the fourth element of the query that matched.
            const std::string channelName = SubscriberImpl::channelNameFromQuery(subscriptionQuery.value());
            if (channelName.empty()) {
                return; // matched on a change-event subscription, so not ours to open
            }
            auto raw = server::GroupCustomEventData::fromJSON(notification.data);
            GroupCustomEventData data{
                .groupId = raw.id,
                .channelName = channelName,
                .userId = raw.author.id,
                .authorPubKey = {},
                .payload = {},
                .statusCode = 0
            };
            // A failure here is reported, never thrown: the event loop has nobody to throw to, and one
            // unreadable notification must not cost the caller the readable ones behind it.
            try {
                const core::Buffer envelope = core::Buffer::from(privmx::utils::Base64::toString(raw.eventData));
                // A member's event, for the group the bridge labels it with, under the current epoch's key: a removed
                // member holds only the earlier ones. The channel it was sealed for is checked once it is open.
                const auto routing = _envelopeEncryptor.peek(envelope);
                // A cached head behind the pinned epoch is no current key (as in `currentEncKey`).
                core::ModuleKeys keys = getModuleKeys(raw.id);
                if (routing.keyId != keys.currentKeyId || isRekeyNeeded(keys)) {
                    keys = getNewModuleKeysAndUpdateCache(raw.id);
                }
                if (routing.type != ENVELOPE_FROM_MEMBER || routing.groupId != raw.id ||
                    routing.keyId != keys.currentKeyId) {
                    throw InvalidEnvelopeFormatException("a custom event must be sealed by a member under the current key");
                }
                auto decrypted = decrypt(envelope);
                // The bridge names the sender; the application vouches that the key which signed is that user's.
                assertUserKeysVerified(
                    getModuleKeys(decrypted.groupId).contextId,
                    {core::UserWithPubKey{.userId = raw.author.id, .pubKey = decrypted.authorPubKey}}
                );
                const auto payload = SubscriberImpl::openOnChannel(channelName, decrypted.data.stdString());
                if (!payload.has_value()) {
                    throw InvalidEnvelopeFormatException("a custom event sealed for another channel");
                }
                data.payload = core::Buffer::from(payload.value());
                data.authorPubKey = decrypted.authorPubKey;
            } catch (const core::Exception& e) {
                data.statusCode = e.getCode();
            } catch (const privmx::utils::PrivmxException& e) {
                data.statusCode = core::ExceptionConverter::convert(e).getCode();
            } catch (...) { data.statusCode = ENDPOINT_CORE_EXCEPTION_CODE; }
            auto event = core::EventBuilder::buildEvent<GroupCustomEvent>(
                "group/" + raw.id + "/" + channelName, data, notification
            );
            _eventMiddleware->emitApiEvent(event);
        } else if (type == "groupCreated") {
            auto raw = server::GroupChangedEventData::fromJSON(notification.data);
            auto data = Mapper::mapToGroupChangedEventData(raw);
            auto event = core::EventBuilder::buildEvent<GroupCreatedEvent>("context", data, notification);
            _eventMiddleware->emitApiEvent(event);
        } else if (type == "groupUpdated") {
            auto raw = server::GroupChangedEventData::fromJSON(notification.data);
            invalidateModuleKeysInCache(raw.groupId);
            auto data = Mapper::mapToGroupChangedEventData(raw);
            auto event = core::EventBuilder::buildEvent<GroupUpdatedEvent>("context", data, notification);
            _eventMiddleware->emitApiEvent(event);
        } else if (type == "groupDeleted") {
            auto raw = server::GroupDeletedEventData::fromJSON(notification.data);
            // Key caches only. The pins stay as tombstones: the event is the bridge's word alone, and dropping them
            // would make the next read of the group a first contact the bridge could answer with any old state.
            forgetGroupKeys(raw.groupId);
            invalidateModuleKeysInCache(raw.groupId);
            auto data = Mapper::mapToGroupDeletedEventData(raw);
            auto event = core::EventBuilder::buildEvent<GroupDeletedEvent>("context", data, notification);
            _eventMiddleware->emitApiEvent(event);
        } else {
            LOG_ERROR("UNRESOLVED EVENT in CPP layer: '", type, "'");
        }
    });
}

// The tree and version pins stay across reconnects: they only ever move forward, and a new session is no reason
// to accept a state older than one this process has already verified.
void GroupApiImpl::processConnectedEvent() {
    {
        // Follows the key cache: what was checked is session state.
        std::unique_lock<std::mutex> lock(_dueMutex);
        _ladderCheckedAt.clear();
    }
    _treeKeyCaches.dropAll();
    dropEnvelopeState();
    invalidateModuleKeysInCache();
}

// `_unresolved` is kept on purpose: a dropped connection is the commonest unknown outcome of a commit, and the
// same call retried on the next connection must resend that statement, not be held back by it. So is `_pendingCarry`:
// the next mutating call retries it, and dropping it would leave the planes refused to readers.
void GroupApiImpl::processDisconnectedEvent() {
    {
        std::unique_lock<std::mutex> lock(_dueMutex);
        _selfUpdatePending.clear();
        _ladderChecks.clear();
        _ladderCheckedAt.clear();
    }
    savePins();
    _epochKeys.clear();
    _treeKeyCaches.dropAll();
    dropEnvelopeState();
    invalidateModuleKeysInCache();
}

void GroupApiImpl::dropEnvelopeState() {
    _envelopeKeys.clear();
    _envelopeGrantEpochs.clear();
    // Open file handles too: an `EnvelopeFileState` holds the group and file keys as plainly as `_envelopeKeys`
    // does. A handle used after this reports "not an open encrypted-file handle", which a reconnect made true.
    _envelopeFiles.clear();
}

void GroupApiImpl::forgetGroupKeys(const std::string& groupId) {
    _treeKeyCaches.drop(groupId);
    const std::string prefix = memoKeyFor(groupId, "");
    const auto erase = [&](auto& memo) {
        std::vector<std::string> stale;
        memo.forAllLockSave([&](const std::string& key, const auto&) {
            if (key.compare(0, prefix.size(), prefix) == 0) {
                stale.push_back(key);
            }
        });
        for (const std::string& key : stale) {
            memo.erase(key);
        }
    };
    erase(_epochKeys);
    erase(_envelopeKeys);
    erase(_envelopeGrantEpochs);
}

std::pair<core::ModuleKeys, int64_t> GroupApiImpl::getModuleKeysAndVersionFromServer(std::string moduleId) {
    const server::GroupInfo group = readGroupForKeys(moduleId);
    // Roster version: key material moves with that plane, so a metadata-only write must not stale the cache.
    return std::make_pair(groupToModuleKeys(group), group.rosterVersion);
}

group::server::GroupInfo GroupApiImpl::readGroupForKeys(const std::string& groupId) {
    const server::GroupGetModel params = pathRead(groupId);
    auto group = _serverApi.groupGet(params).group;
    // The tree pins `keyVersion` (never below what this client verified or committed itself); the head entry's
    // grant must be at exactly that epoch; the roster attestation binds the head to it and moves the version pins.
    if (!verifyTree(group, params, keytree::TreeVerifier::Scope::Path)) {
        throw core::EncryptionKeyValidationException("caller holds no verifiable seat in this group's key tree");
    }
    assertHeadKeyAtEpoch(group);
    _groupDataSchemaMapper->validateAndGetAttestedRoster(group, _keyProvider, resolverOver(&group));
    return group;
}

core::KeyProvider::GroupPrivKeyResolver GroupApiImpl::resolverOver(
    const server::GroupInfo* seatedRead,
    const ClimbWith* with
) {
    return [this, seatedRead, with](const std::string& groupId, int64_t epoch)
               -> std::optional<privmx::crypto::PrivateKey> {
        try {
            return resolveGroupPrivKey(groupId, epoch, seatedRead, with);
        } catch (const GroupHistoryForkException&) {
            throw; // a rollback is not "no key": it must reach the caller as itself
        } catch (...) {
            // caller holds no leaf in this group's tree at this epoch — skip
            return std::nullopt;
        }
    };
}

void GroupApiImpl::assertHeadKeyAtEpoch(const server::GroupInfo& group) {
    if (group.data.empty()) {
        throw GroupDataIntegrityException("group has no head entry");
    }
    bool found = false;
    for (const auto& entry : group.groupKeys.value_or(std::vector<core::server::GroupKeysEntry>{})) {
        for (const auto& key : entry.keys) {
            if (entry.group != group.id || key.keyId != group.data.back().keyId) {
                continue;
            }
            if (key.groupEpoch.value_or(0) != group.keyVersion) {
                throw GroupDataIntegrityException("the head entry's key is not the current epoch's");
            }
            found = true;
        }
    }
    if (!found) {
        throw GroupDataIntegrityException("the head entry's key is not published to the group");
    }
}

std::uint64_t GroupApiImpl::pinnedKeyVersion(const std::string& groupId) {
    return _treeVerifier.pinnedKeyVersion(groupId);
}

bool GroupApiImpl::agreesWithPin(
    const std::string& groupId,
    const std::string& contextId,
    std::int64_t keyVersion,
    const std::string& groupPubKey
) {
    return _treeVerifier.agreesWithPin(groupId, contextId, keyVersion, groupPubKey);
}

core::ModuleKeys GroupApiImpl::groupToModuleKeys(const server::GroupInfo& group) {
    return core::ModuleKeys{
        .keys = {},
        .groupKeys = group.groupKeys.value_or(std::vector<core::server::GroupKeysEntry>{}),
        .staleGroups = {},
        .currentKeyId = group.data.back().keyId,
        .moduleSchemaVersion = _groupDataSchemaMapper->getDataStructureVersion(group.data.back()),
        .moduleResourceId = group.resourceId.value_or(""),
        .contextId = group.contextId
    };
}

std::vector<std::string> GroupApiImpl::subscribeFor(const std::vector<std::string>& subscriptionQueries) {
    auto result = _subscriber.subscribeFor(subscriptionQueries);
    _eventMiddleware->notificationEventListenerAddSubscriptionIds(_notificationListenerId, result);
    return result;
}

void GroupApiImpl::unsubscribeFrom(const std::vector<std::string>& subscriptionIds) {
    _subscriber.unsubscribeFrom(subscriptionIds);
    _eventMiddleware->notificationEventListenerRemoveSubscriptionIds(_notificationListenerId, subscriptionIds);
}

std::string GroupApiImpl::buildSubscriptionQuery(
    EventType eventType,
    EventSelectorType selectorType,
    const std::string& selectorId
) {
    return SubscriberImpl::buildQuery(eventType, selectorType, selectorId);
}

std::string GroupApiImpl::buildCustomEventSubscriptionQuery(
    const std::string& channelName,
    EventSelectorType selectorType,
    const std::string& selectorId
) {
    return SubscriberImpl::buildCustomEventQuery(channelName, selectorType, selectorId);
}

privmx::crypto::PrivateKey GroupApiImpl::resolveGroupPrivKey(
    const std::string& groupId,
    int64_t epoch,
    const server::GroupInfo* seatedRead,
    const ClimbWith* with
) {
    // An epoch's key never changes: once resolved and matched to its published public key it is served from here,
    // with no read, no tree check, no climb and no ladder. 0 ("current") names no fixed epoch, so it always reads.
    if (epoch > 0 && with == nullptr) {
        if (auto cached = _epochKeys.get(memoKeyFor(groupId, std::to_string(epoch))); cached.has_value()) {
            return cached.value();
        }
    }
    // Only its own current epoch: any other one needs the archive, which this read decides nothing about.
    const bool reuse = seatedRead != nullptr && seatedRead->id == groupId && epoch == seatedRead->keyVersion;
    const server::GroupGetModel params = pathRead(groupId);
    std::optional<server::GroupInfo> fresh;
    if (!reuse) {
        fresh = _serverApi.groupGet(params).group;
    }
    // The served path checked against the latest statement before any key off it is used. A group without a
    // supported tree, or a caller without a seat, is left to the resolver, which refuses both without a key.
    const bool seated = reuse || verifyTree(fresh.value(), params, keytree::TreeVerifier::Scope::Path);
    const server::GroupInfo& group = reuse ? *seatedRead : fresh.value();

    const int64_t currentEpoch = group.keyVersion;
    const auto cache = with != nullptr ? with->cache : _treeKeyCaches.get(groupId);
    keytree::GroupKeyResolver resolver(*cache);
    const bool needsDescent = seated && epoch > 0 && epoch < currentEpoch;
    const privmx::crypto::PrivateKey& ownKey = with != nullptr ? *with->key : _userPrivKey;
    const keytree::ResolveResult resolved = needsDescent ?
        resolveDescending(resolver, group, epoch, ownKey) :
        resolver.resolve(group, epoch, ownKey, server::GroupGetKeyArchiveResult{});
    if (with != nullptr) {
        // A leaf renewal's previous-key climb: whatever it derived stays in its own cache and dies with the call.
        if (resolved.key.has_value()) {
            return resolved.key.value();
        }
        throw core::EncryptionKeyValidationException(describeResolveFailure(resolved));
    }
    // A descent that routed around, or stopped at, a broken rung: a holder of both keys can repair it.
    for (const keytree::RungSpan& span : resolved.brokenSpans) {
        scheduleLadderCheck(groupId, group.contextId, span.at, backgroundWindowMs(group));
    }
    if (resolved.key.has_value()) {
        // The climb to the current epoch went through, so the served path is the caller's to vouch for: refill
        // whatever blanks a removal left on it, and re-key what somebody outside it set. Only recorded here: it runs
        // at the end of a later GroupApi call on the group (`runDueWork`), never inside a container's key lookup.
        scheduleSelfUpdateIfNeeded(groupId, group);
        // A rotation this session saw happen: holding both keys, it can check (and repair) the new epoch's rungs.
        const auto cur = static_cast<std::uint32_t>(currentEpoch);
        if (cur > 1 && cache->getGrantKey(cur).has_value() && cache->getGrantKey(cur - 1).has_value()) {
            scheduleObservedRotation(groupId, group.contextId, cur, backgroundWindowMs(group));
        }
        // The resolver has checked the key against the epoch's published public key on the way here.
        _epochKeys.set(memoKeyFor(groupId, std::to_string(epoch == 0 ? currentEpoch : epoch)), resolved.key.value());
        return resolved.key.value();
    }
    if (resolved.failure == keytree::ResolveFailure::ClimbFailed &&
        resolved.climb == keytree::ClimbFailure::NotAMember) {
        _treeKeyCaches.drop(groupId);
    }
    throw core::EncryptionKeyValidationException(describeResolveFailure(resolved));
}

privmx::endpoint::group::server::GroupInfo GroupApiImpl::rereadVerified(
    const server::GroupGetModel& model,
    keytree::TreeVerifier::Scope scope
) {
    server::GroupInfo group = _serverApi.groupGet(model).group;
    if (!verifyTree(group, model, scope)) {
        throw GroupDataIntegrityException("the read after an earlier commit landed carries no tree this client checks");
    }
    return group;
}

std::optional<privmx::endpoint::group::server::GroupInfo> GroupApiImpl::readForCommit(
    const server::GroupGetModel& model,
    keytree::TreeVerifier::Scope scope,
    const std::string& op,
    bool mayCompleteOther,
    const std::function<void()>& refuseUnverified
) {
    server::GroupInfo group = _serverApi.groupGet(model).group;
    // Every record a plan reads and every node it wraps to, checked against the statements members signed. `settle`
    // only after a read that verified: it goes by the pin, and the bridge's unverified word moves nothing.
    if (!verifyTree(group, model, scope)) {
        if (refuseUnverified) {
            refuseUnverified();
        }
        return group; // planning on it refuses it (`climbForPlanning`)
    }
    switch (settle(model.groupId, op, mayCompleteOther)) {
    case Settled::Done:
        return std::nullopt;
    case Settled::Reread:
        return rereadVerified(model, scope);
    default:
        return group;
    }
}

bool GroupApiImpl::verifyTree(
    server::GroupInfo& group,
    const server::GroupGetModel& model,
    keytree::TreeVerifier::Scope scope
) {
    const SaveDuePins saveAfter{*this}; // whatever this verification moved, refusals included
    if (!keytree::GroupKeyResolver::hasTree(group) ||
        !keytree::GroupKeyResolver::hasSupportedTree(group) ||
        !keytree::GroupKeyResolver::ownUserId(group).has_value()) {
        return false;
    }
    // The hash binds the seat to a user id, not to this caller: every climb starts there and every commit signs as it.
    // Checked before `verify` stores anything, so a served group with somebody else's seat (an envelope may name any
    // group id) is never pinned; `verify` still proves the binding.
    const auto assertOwnSeat = [&] {
        if (keytree::GroupKeyResolver::ownUserId(group) != _connection.getImpl()->getMyUserId(group.contextId)) {
            throw GroupDataIntegrityException("the caller was served somebody else's seat");
        }
    };
    assertOwnSeat();
    const keytree::TreeVerifier::Environment environment = treeEnvironment(group.id);
    try {
        _treeVerifier.verify(group, scope, environment);
    } catch (const EndpointGroupException&) {
        // A torn read, or a concurrent read that pinned a newer state while this answer was in flight: a fresh read
        // settles both, and a real attack fails the second check too.
        group = _serverApi.groupGet(model).group;
        if (!keytree::GroupKeyResolver::ownUserId(group).has_value()) {
            throw GroupDataIntegrityException("the caller was served no seat");
        }
        assertOwnSeat();
        _treeVerifier.verify(group, scope, environment);
    }
    return true;
}

keytree::TreeVerifier::Environment GroupApiImpl::treeEnvironment(const std::string& groupId) {
    keytree::TreeVerifier::Environment environment;
    environment.verifyUsers = [this](const std::vector<core::VerificationRequest>& requests) {
        return _connection.getImpl()->getUserVerifier()->verify(requests);
    };
    // One page: the bridge answers at most 256 statements a call, and the verifier asks again from where it stopped.
    environment.commitsBetween = [this, groupId](std::uint64_t fromSeq, std::uint64_t toSeq) {
        return _serverApi
            .groupGetTreeCommits(
                server::GroupGetTreeCommitsModel{
                    .groupId = groupId,
                    .fromSeq = static_cast<std::int64_t>(fromSeq),
                    .toSeq = static_cast<std::int64_t>(toSeq)
                }
            );
    };
    return environment;
}

std::uint64_t GroupApiImpl::commitDate() {
    return static_cast<std::uint64_t>(privmx::utils::Utils::getNowTimestamp());
}

void GroupApiImpl::chainTo(keytree::CommitStatement& statement, const server::GroupInfo& group) {
    // Nothing is signed on pins this device cannot keep, or behind what a sibling instance saved meanwhile.
    _treeVerifier.assertMaySignAt(group.id, statement.seq);
    const keytree::CommitStatement previous = keytree::TreeCommits::fromWire(group.treeCommit.value());
    statement.prevDigest = keytree::TreeCommits::digest(previous);
    // A clock behind the last committer's signs its date. The bridge takes a date equal to the previous one even
    // past its tolerance, so this never freezes; keep the max: the exception is equality, not "anything later".
    statement.date = std::max(statement.date, previous.date);
    // What every reader will check, checked before this member signs it, on the verified read it was planned on
    // (`describes` bound group.policy, group.creator and the roster to the latest statement). Without it, a mistaken
    // app call by an honest member gives a malicious bridge a genuinely signed out-of-role statement to land.
    const std::set<std::string> users(group.users.begin(), group.users.end());
    const std::set<std::string> managers(group.managers.begin(), group.managers.end());
    if (const auto problem = keytree::TreeCommits::deltasProblem(statement, users, managers)) {
        throw core::InvalidParamsException(problem.value());
    }
    if (!keytree::TreeCommits::permits(rulesOf(group), statement, users, managers)) {
        throw GroupUnauthorizedSignerException(
            "the group's signed policy does not give this member the role this commit needs"
        );
    }
}

keytree::GroupRules GroupApiImpl::rulesOf(const server::GroupInfo& group) {
    try {
        return keytree::TreeCommits::rules(group.policy, group.creator);
    } catch (const std::invalid_argument&) {
        throw GroupDataIntegrityException("the group's policy does not parse");
    }
}

std::shared_ptr<std::mutex> GroupApiImpl::commitLock(const std::string& groupId) {
    std::lock_guard<std::mutex> lock(_unresolvedMutex);
    auto& mutex = _commitLocks[groupId];
    if (!mutex) {
        mutex = std::make_shared<std::mutex>();
    }
    return mutex;
}

void GroupApiImpl::forgetUnresolved(const std::string& groupId, const std::string& digest) {
    std::lock_guard<std::mutex> lock(_unresolvedMutex);
    const auto it = _unresolved.find(groupId);
    if (it != _unresolved.end() && it->second.digest == digest) {
        _unresolved.erase(it);
    }
}

void GroupApiImpl::submit(
    const std::string& groupId,
    const keytree::CommitStatement& statement,
    UnresolvedCommit commit
) {
    const auto mutex = commitLock(groupId);
    std::unique_lock<std::mutex> lock(*mutex);
    commit.digest = keytree::TreeCommits::digest(statement);
    commit.seq = statement.seq;
    commit.date = statement.date;
    if (statement.seq <= _treeVerifier.pinnedSeq(groupId)) {
        throw StalePlan{}; // planned behind a state this client verified (or committed) since
    }
    // Under the lock: a concurrent commit of ours may have been refused as a lost race since this was planned. That
    // is honest concurrency, so re-planned; a plan read that still serves no statement at that seq is refused there
    // (`chainTo`).
    if (!_treeVerifier.maySignAt(groupId, statement.seq)) {
        throw StalePlan{};
    }
    {
        std::lock_guard<std::mutex> guard(_unresolvedMutex);
        // Another commit of ours, released with no known outcome since this was planned, may land at this seq.
        // `settle` completes it on the re-plan. A deferred self-update yields instead.
        const auto it = _unresolved.find(groupId);
        if (it != _unresolved.end() && it->second.digest != commit.digest && it->second.seq >= statement.seq &&
            it->second.op != SELF_UPDATE_OP) {
            throw StalePlan{};
        }
        // Replaces a pending deferred self-update only now, when the op superseding it is actually released.
        _unresolved[groupId] = commit;
    }
    try {
        commit.send();
    } catch (const privmx::utils::PrivmxException& e) {
        // The bridge's word that a concurrent commit took this seq; it may have applied ours all the same.
        if (isRetryableCommitRejection(e)) {
            _treeVerifier.refusedAsLostRace(groupId, statement.seq);
        }
        throw; // any failure keeps the body: the bridge may have applied it, and a retry resends it
    }
    complete(groupId, commit);
}

void GroupApiImpl::complete(const std::string& groupId, const UnresolvedCommit& commit) {
    forgetUnresolved(groupId, commit.digest);
    commit.landed();
    if (commit.op != SELF_UPDATE_OP) {
        savePins(); // an own commit is in the store before the call returns
    }
}

GroupApiImpl::Settled GroupApiImpl::settle(const std::string& groupId, const std::string& op, bool mayCompleteOther) {
    std::optional<UnresolvedCommit> first;
    {
        std::lock_guard<std::mutex> lock(_unresolvedMutex);
        const auto it = _unresolved.find(groupId);
        if (it == _unresolved.end()) {
            return Settled::Proceed;
        }
        first = it->second;
    }
    // Landed and built upon since: on the verified chain below the pin. A read, so before the lock. First: a landed
    // add is no failure, whatever the UserVerifier says of its newcomers now.
    const bool landedBelowPin = _treeVerifier.pinnedSeq(groupId) > first->seq &&
        _treeVerifier.chainedToPin(groupId, first->seq, first->digest, treeEnvironment(groupId));
    // A resent add wraps to its newcomers' keys again: only while the UserVerifier still vouches for them. Outside
    // every lock of ours, like any verifier call.
    if (!landedBelowPin && !first->newcomers.empty() &&
        _treeVerifier.pinnedDigest(groupId) != first->digest &&
        (first->op == op || mayCompleteOther)) {
        try {
            assertUserKeysVerified(first->contextId, first->newcomers);
        } catch (...) {
            forgetUnresolved(groupId, first->digest);
            if (first->op == op) {
                throw;
            }
            return Settled::Proceed; // not resent to unvouched keys; this op plans afresh
        }
    }
    const auto mutex = commitLock(groupId);
    std::unique_lock<std::mutex> lock(*mutex);
    UnresolvedCommit pending;
    {
        std::lock_guard<std::mutex> guard(_unresolvedMutex);
        const auto it = _unresolved.find(groupId);
        if (it == _unresolved.end() || it->second.digest != first->digest) {
            return Settled::Proceed; // settled meanwhile
        }
        pending = it->second;
    }
    const auto finish = [&](Settled done) {
        complete(groupId, pending);
        lock.unlock();
        if (pending.after) {
            pending.after();
        }
        if (pending.op != op) {
            return done;
        }
        // An event op (a rotation) found landed past its window is an earlier call's: this call is a new request,
        // planned on a fresh read (`after` changed the group). Never Done then, or the key the caller wants replaced
        // stays current with the call returning success.
        return pending.namesEndState || commitDate() < pending.date + RELEASE_WINDOW_MS ? Settled::Done
                                                                                          : Settled::Reread;
    };
    // Landed only when a verified read pinned it, or a statement chained above it, never on what the bridge serves as
    // the head: a served head is unverified, and `landed` cannot refuse it (its `pinCommitted` passes over a statement
    // below the pin). Before the gate, which lets go of the entry once the pin reaches its seq.
    if (_treeVerifier.pinnedDigest(groupId) == pending.digest || landedBelowPin) {
        return finish(Settled::Proceed); // it landed; only the answer was lost
    }
    // Superseded (the pin passed its seq), or past its window (an honest bridge refuses it by its date by now).
    if (_treeVerifier.pinnedSeq(groupId) >= pending.seq || commitDate() >= pending.date + RELEASE_WINDOW_MS) {
        forgetUnresolved(groupId, pending.digest);
        return Settled::Proceed;
    }
    if (pending.op == SELF_UPDATE_OP && op != SELF_UPDATE_OP) {
        return Settled::Proceed; // yields; the body stays for a later self-update until this op is released
    }
    if (pending.op != op && !mayCompleteOther) {
        return Settled::Deferred;
    }
    _treeVerifier.assertMaySignAt(groupId, pending.seq);
    try {
        pending.send();
    } catch (const std::exception& e) {
        const auto* rejection = dynamic_cast<const privmx::utils::PrivmxException*>(&e);
        if (rejection != nullptr && isRetryableCommitRejection(*rejection)) {
            _treeVerifier.refusedAsLostRace(groupId, pending.seq);
            throw;
        }
        if (pending.op == op) {
            throw;
        }
        // Another op: one resend was tried; the earlier commit is dropped and this op plans afresh.
        LOG_WARN("[settle] an earlier ", pending.kind, " to group ", groupId, " is dropped unresolved: ", e.what())
        forgetUnresolved(groupId, pending.digest);
        return Settled::Proceed;
    }
    return finish(Settled::Reread);
}

privmx::endpoint::group::server::GroupGetKeyArchiveResult GroupApiImpl::fetchKeyArchive(
    const server::GroupInfo& group,
    int64_t targetEpoch,
    int64_t currentEpoch
) {
    server::GroupGetKeyArchiveModel params;
    params.id = group.id;
    params.fromKeyVersion = targetEpoch;
    params.toKeyVersion = currentEpoch;
    return fetchKeyArchive(group, params);
}

privmx::endpoint::group::server::GroupGetKeyArchiveResult GroupApiImpl::fetchKeyArchive(
    const server::GroupInfo& group,
    const std::vector<keytree::RungSpan>& spans
) {
    server::GroupGetKeyArchiveModel params;
    params.id = group.id;
    params.spans = std::vector<server::GroupArchiveSpan>{};
    for (const keytree::RungSpan& span : spans) {
        params.spans->push_back(server::GroupArchiveSpan{.at = span.at, .target = span.target});
    }
    return fetchKeyArchive(group, params);
}

keytree::ResolveResult GroupApiImpl::resolveDescending(
    keytree::GroupKeyResolver& resolver,
    const server::GroupInfo& group,
    int64_t epoch,
    const privmx::crypto::PrivateKey& ownKey
) {
    // Anything but a broken or missing rung is the answer: the whole window would refuse the same way.
    const auto settled = [](const keytree::ResolveResult& resolved) {
        return resolved.failure != keytree::ResolveFailure::DescentFailed ||
            resolved.descent == keytree::DescentFailure::EraBoundary ||
            resolved.descent == keytree::DescentFailure::Pruned;
    };
    const auto current = static_cast<std::uint32_t>(group.keyVersion);
    const std::uint32_t floor =
        _treeKeyCaches.get(group.id)->raiseFloor(ladderFloorOf(group.eraFloor.value_or(1), group.archivePrunedBelow));
    // Below the floor the descent ends at the floor whatever was fetched, so the path goes no lower.
    const std::uint32_t goal = std::max(static_cast<std::uint32_t>(epoch), floor);
    const std::vector<keytree::RungSpan> path = keytree::LadderMath::canonicalDescent(current, goal, floor);
    server::GroupGetKeyArchiveResult archive = fetchKeyArchive(group, path);
    keytree::ResolveResult resolved = resolver.resolve(group, epoch, ownKey, archive);
    if (settled(resolved)) {
        return resolved;
    }
    const std::vector<keytree::RungSpan> detour =
        keytree::LadderMath::detourSpans(std::max(resolved.reachedEpoch, goal), goal, floor, path);
    if (!detour.empty() && detour.size() <= MAX_ARCHIVE_SPANS) {
        const server::GroupGetKeyArchiveResult around = fetchKeyArchive(group, detour);
        archive.rungs.insert(archive.rungs.end(), around.rungs.begin(), around.rungs.end());
        archive.eraFloor = std::max(archive.eraFloor, around.eraFloor);
        if (around.archivePrunedBelow.has_value()) {
            archive.archivePrunedBelow = std::max(archive.archivePrunedBelow.value_or(1), around.archivePrunedBelow.value());
        }
        resolved = resolver.resolve(group, epoch, ownKey, archive);
        if (settled(resolved)) {
            return resolved;
        }
    }
    LOG_WARN("[ladder] the descent path to epoch ", std::to_string(epoch), " of ", group.id, " is broken; reading the whole window")
    return resolver.resolve(group, epoch, ownKey, fetchKeyArchive(group, epoch, group.keyVersion));
}

privmx::endpoint::group::server::GroupGetKeyArchiveResult GroupApiImpl::fetchKeyArchive(
    const server::GroupInfo& group,
    const server::GroupGetKeyArchiveModel& params
) {
    server::GroupGetKeyArchiveResult archive = _serverApi.groupGetKeyArchive(params);
    // A window comes a page of rungs at a time: read on from the last page's top epoch while pages come full. That
    // epoch's rungs come again whole on the next page, so they are dropped from this one first.
    server::GroupGetKeyArchiveModel next = params;
    for (std::size_t served = archive.rungs.size(); !params.spans.has_value() && served >= ARCHIVE_RUNGS_PER_PAGE;) {
        const std::int64_t top = archive.rungs.back().atKeyVersion;
        if (top <= next.fromKeyVersion.value_or(0)) {
            break; // a page that does not move on: what was served is all there is to try
        }
        next.fromKeyVersion = top;
        archive.rungs.erase(
            std::remove_if(archive.rungs.begin(), archive.rungs.end(), [&](const auto& rung) { return rung.atKeyVersion == top; }),
            archive.rungs.end()
        );
        const server::GroupGetKeyArchiveResult page = _serverApi.groupGetKeyArchive(next);
        archive.rungs.insert(archive.rungs.end(), page.rungs.begin(), page.rungs.end());
        served = page.rungs.size();
    }
    _treeKeyCaches.get(group.id)->raiseFloor(ladderFloorOf(archive.eraFloor, archive.archivePrunedBelow));
    // `keyHistory` and a rung's `author` are the bridge's word; the statements are the members'.
    return keytree::GroupKeyResolver::authenticated(
        std::move(archive), _treeVerifier.epochOpeners(group.id, group.contextId, treeEnvironment(group.id))
    );
}

std::shared_ptr<keytree::TreeKeyCache> GroupApiImpl::keyCacheOf(const std::string& groupId) {
    return _treeKeyCaches.get(groupId);
}

std::string GroupApiImpl::describeResolveFailure(const keytree::ResolveResult& resolved) {
    switch (resolved.failure) {
    case keytree::ResolveFailure::NoTree:
        return "Group key unavailable: group has no key tree";
    case keytree::ResolveFailure::UnsupportedTreeVersion:
        return "Group key unavailable: the group's key tree has a version this client does not support";
    case keytree::ResolveFailure::FutureEpoch:
        return "Group key unavailable: the requested epoch has not happened yet";
    case keytree::ResolveFailure::InvalidEpoch:
        return "Group key unavailable: the requested epoch is out of range";
    case keytree::ResolveFailure::ClimbFailed:
        if (resolved.climb == keytree::ClimbFailure::Tampered) {
            return "Group key tree verification failed: a node key does not match the published public key" +
                blameSuffix(resolved.blame);
        }
        if (resolved.climb == keytree::ClimbFailure::NotAMember) {
            return "Group key unavailable: caller holds no leaf in the key tree";
        }
        if (resolved.climb == keytree::ClimbFailure::LeafDidNotOpen) {
            // A changed identity key looks the same as a garbled leaf edge, so the setter is still named.
            return "Group key unavailable: the edge to your own leaf does not open with your current key. If you "
                   "changed your identity key, call renewLeaf with the previous key; without it, ask a manager to "
                   "remove and re-add you" +
                blameSuffix(resolved.blame);
        }
        if (resolved.climb == keytree::ClimbFailure::DecryptFailed) {
            return "Group key unavailable: a key tree edge does not open" + blameSuffix(resolved.blame);
        }
        return "Group key unavailable: the key tree could not be climbed";
    case keytree::ResolveFailure::DescentFailed:
        switch (resolved.descent) {
        case keytree::DescentFailure::EraBoundary:
            return "History before this era is not available to you";
        case keytree::DescentFailure::Pruned:
            return "History this old has been pruned and is no longer recoverable";
        case keytree::DescentFailure::Tampered:
            return "Epoch ladder verification failed" + blameSuffix(resolved.blame, "rung published by");
        default:
            return "Group key unavailable: the epoch ladder could not be descended";
        }
    default:
        return "Group key unavailable";
    }
}

// -- envelopes -------------------------------------------------------------------------------------------

std::vector<core::server::GroupKeysEntry> GroupApiImpl::filterToKeyId(
    const std::vector<core::server::GroupKeysEntry>& all,
    const std::string& groupId,
    const std::string& keyId
) {
    std::vector<core::server::GroupKeysEntry> filtered;
    for (const auto& entry : all) {
        if (entry.group != groupId) {
            continue;
        }
        core::server::GroupKeysEntry kept;
        kept.group = entry.group;
        for (const auto& key : entry.keys) {
            if (key.keyId == keyId) {
                kept.keys.push_back(key);
            }
        }
        if (!kept.keys.empty()) {
            filtered.push_back(kept);
        }
    }
    return filtered;
}

bool GroupApiImpl::wrappedByEpochOpener(
    const std::vector<core::server::GroupKeysEntry>& routes,
    const std::string& wrappedBy,
    const std::map<std::uint64_t, keytree::CommitStatement>& openers
) {
    for (const auto& route : routes) {
        for (const auto& key : route.keys) {
            const auto opener = openers.find(static_cast<std::uint64_t>(key.groupEpoch.value_or(0)));
            if (opener != openers.end() && opener->second.committer == wrappedBy) {
                return true;
            }
        }
    }
    return false;
}

std::string GroupApiImpl::memoKeyFor(const std::string& groupId, const std::string& suffix) {
    // Length-prefixed rather than joined by a separator: `validateId` bounds a groupId's length but not its
    // characters, so a plain join would let one pair collide with another under a different split.
    return std::to_string(groupId.size()) + ":" + groupId + suffix;
}

core::DecryptedEncKeyV2 GroupApiImpl::encKeyById(const std::string& groupId, const std::string& keyId) {
    const std::string memoKey = memoKeyFor(groupId, keyId);
    if (auto cached = _envelopeKeys.get(memoKey); cached.has_value()) {
        return cached.value();
    }

    // Whatever an earlier `getGroup` or `encrypt` on this group already put in the key cache. Reading it
    // costs nothing; only a keyId we have never seen forces a fetch.
    core::ModuleKeys moduleKeys = getModuleKeys(groupId);
    auto candidates = filterToKeyId(moduleKeys.groupKeys, groupId, keyId);
    if (candidates.empty()) {
        // `groupGet` serves only the current epochs, so a past epoch's key is looked up by its id. Its entry is the
        // bridge's word like any other: the DIO, the descent to its epoch and the opener check below decide.
        server::GroupGetEpochKeysModel lookup;
        lookup.id = groupId;
        lookup.keyIds = std::vector<std::string>{keyId};
        candidates = filterToKeyId(_serverApi.groupGetEpochKeys(lookup).groupKeys, groupId, keyId);
        // An epoch past the verified pin (a rotation this session has not read yet) has no opener to check its
        // wrapper against: read the group as before, which makes it the head key.
        const bool pastThePin = std::any_of(candidates.begin(), candidates.end(), [&](const auto& entry) {
            return std::any_of(entry.keys.begin(), entry.keys.end(), [&](const auto& key) {
                return key.groupEpoch.value_or(0) > static_cast<std::int64_t>(_treeVerifier.pinnedKeyVersion(groupId));
            });
        });
        if (candidates.empty() || pastThePin) {
            moduleKeys = getNewModuleKeysAndUpdateCache(groupId);
            candidates = filterToKeyId(moduleKeys.groupKeys, groupId, keyId);
        }
    }
    if (candidates.empty()) {
        throw core::EncryptionKeyValidationException("Group " + groupId + " publishes no key " + keyId);
    }

    core::KeyDecryptionAndVerificationRequest request;
    const auto location = core::EncKeyLocation{
        .contextId = moduleKeys.contextId, .resourceId = moduleKeys.moduleResourceId
    };
    request.addGroupKeys(candidates, location);
    const auto byLocation = _keyProvider->getKeysAndVerify(request, _groupPrivKeyResolver);

    const auto atLocation = byLocation.find(location);
    if (atLocation == byLocation.end() || atLocation->second.count(keyId) == 0) {
        throw core::EncryptionKeyValidationException("Group key " + keyId + " could not be resolved");
    }
    const core::DecryptedEncKeyV2 found = atLocation->second.at(keyId);
    if (found.statusCode != 0) {
        // `findEncKeyByKeyId` and friends hand back entries whose decryption failed; unchecked, the empty key
        // surfaces as a cipher length complaint instead of the real cause, usually an era boundary.
        throw core::EncryptionKeyValidationException(
            "Group key " + keyId + " could not be decrypted (status " + std::to_string(found.statusCode) + ")"
        );
    }
    // The id sealed inside the entry, not the label the bridge filed it under: another epoch's entry relabelled with
    // this keyId opens fine, and memoized it would stand in for the real key for the rest of the session.
    if (found.id != keyId) {
        throw core::EncryptionKeyValidationException("Group key " + keyId + " is served under another key's id");
    }
    // The head key's wrapper was checked against the roster by the verified read the module keys came from; an
    // earlier epoch's against who opened it, or a member envelope could come from anybody in the context.
    if (keyId != moduleKeys.currentKeyId &&
        !wrappedByEpochOpener(
            candidates, found.dio.creatorUserId,
            _treeVerifier.epochOpeners(groupId, moduleKeys.contextId, treeEnvironment(groupId))
        )) {
        throw core::EncryptionKeyValidationException("Group key " + keyId + " was not wrapped by its epoch's opener");
    }
    _envelopeKeys.set(memoKey, found);
    return found;
}

core::DecryptedEncKeyV2 GroupApiImpl::currentEncKey(const std::string& groupId) {
    core::ModuleKeys keys = getModuleKeys(groupId);
    // A cached head behind the epoch verified since (a read for a key, a commit of our own, a sibling instance's
    // save) is re-read, not refused.
    if (isRekeyNeeded(keys)) {
        keys = getNewModuleKeysAndUpdateCache(groupId);
    }
    return getAndValidateModuleCurrentEncKey(keys);
}

Envelope GroupApiImpl::encrypt(const std::string& groupId, const core::Buffer& content) {
    auto key = currentEncKey(groupId);
    return _envelopeEncryptor.packGroupKeyEnvelope(groupId, key.id, content, _userPrivKey, key.key);
}

// The notification is an ordinary member envelope: one `encrypt` under the group's current key, one request
// whatever the group's size. The recipients already hold the key, so there is no key list to build.
void GroupApiImpl::sendCustomEvent(
    const std::string& groupId,
    const std::string& channelName,
    const core::Buffer& eventData,
    const std::vector<std::string>& users
) {
    server::GroupSendCustomEventModel model;
    model.groupId = groupId;
    model.channel = channelName;
    model.data = privmx::utils::Base64::from(
        encrypt(groupId, core::Buffer::from(SubscriberImpl::sealOnChannel(channelName, eventData.stdString())))
            .stdString()
    );
    if (!users.empty()) {
        model.users = users;
    }
    _serverApi.groupSendCustomEvent(model);
}

DecryptedEnvelope GroupApiImpl::decrypt(const Envelope& envelope) {
    auto routing = _envelopeEncryptor.peek(envelope);
    // The group id comes off an envelope we have not authenticated yet. Validating it here keeps a hostile one
    // from steering us into a `groupGet` and a tree climb against an id of its choosing.
    core::Validator::validateId(routing.groupId, "field:envelope.groupId ");
    if (routing.type == ENVELOPE_FROM_MEMBER) {
        return _envelopeEncryptor.openGroupKeyEnvelope(envelope, encKeyById(routing.groupId, routing.keyId).key);
    }

    return _envelopeEncryptor.openAnonymousEnvelope(envelope, grantKeyForPubKey(routing.groupId, routing.groupPubKey));
}

privmx::crypto::PrivateKey GroupApiImpl::grantKeyForPubKey(
    const std::string& groupId,
    const std::string& groupPubKeyBase58
) {
    // A published grant public key's epoch is immutable, so the lookup is memoized like `_envelopeKeys`.
    // Without it every anonymous envelope pays a `groupGet` here on top of `resolveGroupPrivKey`'s.
    const std::string memoKey = memoKeyFor(groupId, groupPubKeyBase58);
    if (auto cached = _envelopeGrantEpochs.get(memoKey); cached.has_value()) {
        return resolveGroupPrivKey(groupId, cached.value());
    }

    auto target = privmx::crypto::PublicKey::fromBase58DER(groupPubKeyBase58);
    server::GroupGetEpochKeysModel lookup;
    lookup.id = groupId;
    lookup.groupPubKeys = std::vector<std::string>{target.toBase58DER()}; // as stored: compressed
    // `keyHistory` is the bridge's word: only an epoch whose own key turns out to be the target is remembered.
    for (const auto& entry : _serverApi.groupGetEpochKeys(lookup).keyHistory) {
        if (privmx::crypto::PublicKey::fromBase58DER(entry.groupPubKey) == target) {
            const privmx::crypto::PrivateKey key = resolveGroupPrivKey(groupId, entry.keyVersion);
            if (key.getPublicKey() == target) {
                _envelopeGrantEpochs.set(memoKey, entry.keyVersion);
                return key;
            }
        }
    }
    throw InvalidEnvelopeFormatException("envelope names a group key that is not in this group's history");
}

Envelope GroupApiImpl::encryptAnonymously(
    const std::string& groupId,
    const std::string& groupPubKey,
    const core::Buffer& content
) {
    // Public information only — no membership, no server call. That is the whole point: the sender is outside
    // the group and must stay able to write into it knowing nothing but its id and its identity key.
    return _envelopeEncryptor.packAnonymousEnvelope(
        groupId, privmx::crypto::PublicKey::fromBase58DER(groupPubKey), content
    );
}

// -- envelope files --------------------------------------------------------------------------------------

namespace {
constexpr const char* NOT_AN_OPEN_FILE_HANDLE = "field:fileHandle is not an open encrypted-file handle";

// For a call holding the handle's lock: a finish that won the lock first has closed it.
EnvelopeFileState& openState(EnvelopeFile& file) {
    if (file.state.closed) {
        throw core::InvalidParamsException(NOT_AN_OPEN_FILE_HANDLE);
    }
    return file.state;
}
} // namespace

// `reading` never changes after construction, so it is checked here without the handle's lock.
std::shared_ptr<EnvelopeFile> GroupApiImpl::getFileState(FileHandle fileHandle, bool wantReading) {
    auto file = _envelopeFiles.get(fileHandle);
    if (!file.has_value()) {
        throw core::InvalidParamsException(NOT_AN_OPEN_FILE_HANDLE);
    }
    if (file.value()->state.reading != wantReading) {
        throw core::InvalidParamsException(
            wantReading ? "field:fileHandle came from beginFileEncryption, not beginFileDecryption" :
                          "field:fileHandle came from beginFileDecryption, not beginFileEncryption"
        );
    }
    return file.value();
}

void GroupApiImpl::releaseFileHandle(FileHandle fileHandle) {
    _envelopeFiles.erase(fileHandle);
    // Both, always. Dropping only the local entry leaks the id in HandleManager's map for the process
    // lifetime — the pair Store's FileHandleManager keeps together for the same reason.
    _connection.getImpl()->getHandleManager()->removeHandle(fileHandle);
}

// A chunk's sealed length follows from the declared size, so both directions work at arbitrary caller-chosen
// block sizes. Declaring the size up front is what distinguishes a short final chunk from one still arriving.
core::Buffer GroupApiImpl::drainChunks(EnvelopeFileState& state) {
    const ByteCount chunks = GroupEnvelopeEncryptor::chunkCount(state.plainSize);
    std::string out;
    while (state.index < chunks) {
        const ByteCount plainLen = GroupEnvelopeEncryptor::plainChunkSizeAt(state.plainSize, state.index);
        const ByteCount need = state.reading ? encryptedChunkSizeFor(plainLen) : plainLen;
        if (state.buffer.size() < need) {
            break;
        }
        core::Buffer piece = core::Buffer::from(state.buffer.substr(0, need));
        std::string produced = (state.reading ? _envelopeEncryptor.decryptChunk(piece, state.fileKey, state.index) :
                                                _envelopeEncryptor.encryptChunk(piece, state.fileKey, state.index))
                                   .stdString();
        if (state.skipInChunk > 0) {
            // A seek can land mid-chunk, but a chunk only opens whole. Drop the head the caller did not ask
            // for, once, on the first chunk after the seek.
            produced.erase(0, std::min<std::size_t>(state.skipInChunk, produced.size()));
            state.skipInChunk = 0;
        }
        out.append(produced);
        state.buffer.erase(0, need);
        state.index++;
    }
    // Past the last chunk nothing drains, so leftovers only grow. Refused here rather than at the close, or a
    // long ciphertext against a short declared size buffers the whole remainder first. Seeked readers included.
    if (state.reading && state.index >= chunks && !state.buffer.empty()) {
        throw InvalidEnvelopeFormatException("more file data than the declared size accounts for");
    }
    return core::Buffer::from(out);
}

FileHandle GroupApiImpl::beginFileEncryption(const std::string& groupId, FileSize size) {
    auto key = currentEncKey(groupId);
    FileHandle handle = _connection.getImpl()->getHandleManager()->createHandle("GroupEnvelope:Encrypt");
    auto file = std::make_shared<EnvelopeFile>();
    file->state = EnvelopeFileState{
        .reading = false,
        .type = ENVELOPE_FROM_MEMBER,
        .groupId = groupId,
        .keyId = key.id,
        .groupKey = key.key,
        // Per file, so a chunk lifted from one file is useless in any other.
        .fileKey = privmx::crypto::Crypto::randomBytes(32),
        .index = 0,
        .plainSize = static_cast<ByteCount>(size),
    };
    _envelopeFiles.set(handle, file);
    return handle;
}

FileHandle GroupApiImpl::beginFileEncryptionAnonymously(
    const std::string& groupId,
    const std::string& groupPubKey,
    FileSize size
) {
    // No server call and no membership, exactly like `encryptAnonymously`. The public key is enough to seal
    // to, and the envelope is not built until the finish, so nothing here needs the group's own key.
    privmx::crypto::PublicKey::fromBase58DER(groupPubKey); // reject a malformed key now, not at the finish
    FileHandle handle = _connection.getImpl()->getHandleManager()->createHandle("GroupEnvelope:EncryptAnonymous");
    auto file = std::make_shared<EnvelopeFile>();
    file->state = EnvelopeFileState{
        .reading = false,
        .type = ENVELOPE_ANONYMOUS,
        .groupId = groupId,
        .groupPubKey = groupPubKey,
        .fileKey = privmx::crypto::Crypto::randomBytes(32),
        .index = 0,
        .plainSize = static_cast<ByteCount>(size),
    };
    _envelopeFiles.set(handle, file);
    return handle;
}

core::Buffer GroupApiImpl::encryptFileChunk(FileHandle fileHandle, const core::Buffer& plainChunk) {
    auto file = getFileState(fileHandle, false);
    std::lock_guard lock(file->mutex);
    EnvelopeFileState& state = openState(*file);
    if (state.written + plainChunk.size() > state.plainSize) {
        throw core::InvalidParamsException("field:plainChunk would exceed the declared file size");
    }
    state.written += plainChunk.size();
    state.buffer.append(plainChunk.stdString());
    return drainChunks(state);
}

FileHandle GroupApiImpl::beginFileDecryption(const Envelope& envelope) {
    auto routing = _envelopeEncryptor.peekFile(envelope);
    core::Validator::validateId(routing.groupId, "field:envelope.groupId ");

    // Both kinds open into the same reader: only the header is wrapped differently, the body is not.
    EnvelopeFileHeader header;
    std::string groupKey;
    if (routing.type == ENVELOPE_FROM_MEMBER) {
        groupKey = encKeyById(routing.groupId, routing.keyId).key;
        header = _envelopeEncryptor.unpackFileEnvelope(envelope, groupKey);
    } else {
        header = _envelopeEncryptor.unpackAnonymousFileEnvelope(
            envelope, grantKeyForPubKey(routing.groupId, routing.groupPubKey)
        );
    }

    FileHandle handle = _connection.getImpl()->getHandleManager()->createHandle("GroupEnvelope:Decrypt");
    auto file = std::make_shared<EnvelopeFile>();
    file->state = EnvelopeFileState{
        .reading = true,
        .type = header.type,
        .groupId = header.groupId,
        .keyId = header.keyId,
        .groupKey = groupKey,
        .groupPubKey = routing.groupPubKey,
        .authorPubKey = header.authorPubKey,
        .fileKey = header.fileKey,
        .index = 0,
        .plainSize = header.plainSize,
    };
    _envelopeFiles.set(handle, file);
    return handle;
}

core::Buffer GroupApiImpl::decryptFileChunk(FileHandle fileHandle, const core::Buffer& cipherChunk) {
    auto file = getFileState(fileHandle, true);
    std::lock_guard lock(file->mutex);
    EnvelopeFileState& state = openState(*file);
    state.buffer.append(cipherChunk.stdString());
    return drainChunks(state);
}

CipherOffset GroupApiImpl::seekInEncryptedFile(FileHandle fileHandle, FilePosition position) {
    auto file = getFileState(fileHandle, true);
    std::lock_guard lock(file->mutex);
    EnvelopeFileState& state = openState(*file);
    if (position < 0 || static_cast<ByteCount>(position) > state.plainSize) {
        throw core::InvalidParamsException("field:position is outside the file");
    }
    const ByteCount target = static_cast<ByteCount>(position);
    state.index = static_cast<ChunkIndex>(target / GroupEnvelopeEncryptor::CHUNK_SIZE);
    state.skipInChunk = target % GroupEnvelopeEncryptor::CHUNK_SIZE;
    // Whatever was half-collected belonged to the old position.
    state.buffer.clear();
    // From here on the caller decides what to read, so "did all of it arrive" is a question this handle can
    // no longer answer. `finishFileDecryption` reports that rather than pretending otherwise.
    state.seeked = true;
    return static_cast<int64_t>(GroupEnvelopeEncryptor::cipherOffsetOfChunk(state.index));
}

EnvelopeFileState GroupApiImpl::finishFile(FileHandle fileHandle, bool wantReading) {
    auto file = getFileState(fileHandle, wantReading);
    std::lock_guard lock(file->mutex);
    EnvelopeFileState& state = openState(*file);
    // Closed whatever the outcome, so neither a second finish nor a chunk call still waiting for the lock
    // touches the state after this one.
    state.closed = true;
    // Free the handle however this ends, rather than hold a key resident because a file turned out short.
    // `Release` takes only the map and HandleManager locks; nothing takes those and then a file lock.
    struct Release {
        GroupApiImpl* self;
        int64_t handle;
        // This destructor exists to run during exception unwinding, so it must not throw out of one.
        ~Release() {
            try {
                self->releaseFileHandle(handle);
            } catch (...) {}
        }
    } release{this, fileHandle};

    switch (GroupEnvelopeEncryptor::classifyRead(
        state.seeked, state.index, GroupEnvelopeEncryptor::chunkCount(state.plainSize), state.buffer.empty()
    )) {
    case GroupEnvelopeEncryptor::ReadOutcome::Truncated:
        // Every chunk authenticates itself, but nothing in chunk N says how many were meant to follow. The
        // declared size is the only place a dropped tail — or an unfinished write — shows up.
        throw EnvelopeTruncatedFileException();
    case GroupEnvelopeEncryptor::ReadOutcome::Overrun:
        // Every chunk the declared size called for arrived, and then more followed. `drainChunks` refuses
        // those as they arrive; this catches the caller who swallowed that and closed anyway.
        throw InvalidEnvelopeFormatException("more file data than the declared size accounts for");
    case GroupEnvelopeEncryptor::ReadOutcome::PartialRange:
    case GroupEnvelopeEncryptor::ReadOutcome::Complete:
        break;
    }
    // Moved, not copied, so the keys are not duplicated; `closed` (a bool, copied) stays set for anyone still
    // holding `file`.
    return std::move(state);
}

Envelope GroupApiImpl::finishFileEncryption(FileHandle fileHandle) {
    auto state = finishFile(fileHandle, false);
    if (state.type == ENVELOPE_ANONYMOUS) {
        return _envelopeEncryptor.packAnonymousFileEnvelope(
            state.groupId, privmx::crypto::PublicKey::fromBase58DER(state.groupPubKey), state.plainSize,
            state.fileKey
        );
    }
    return _envelopeEncryptor.packFileEnvelope(
        state.groupId, state.keyId, state.plainSize, state.fileKey, _userPrivKey, state.groupKey
    );
}

DecryptedFileInfo GroupApiImpl::finishFileDecryption(FileHandle fileHandle) {
    auto state = finishFile(fileHandle, true);
    return DecryptedFileInfo{
        .groupId = state.groupId,
        .authorPubKey = state.authorPubKey,
        .type = state.type,
        .complete = !state.seeked,
    };
}

void GroupApiImpl::loadPins() {
    std::string blob;
    try {
        blob = _pinStore->load(_pinStoreKey).stdString();
    } catch (const std::exception& e) {
        LOG_WARN("[pins] the pin store does not load: ", e.what())
        return;
    } catch (...) {
        LOG_WARN("[pins] the pin store does not load")
        return;
    }
    if (blob.empty()) {
        return;
    }
    const auto body =
        core::openLocal(_userPrivKey, keytree::PinBlob::LABEL, keytree::PinBlob::VERSION, _pinStoreKey, blob);
    const auto stored = body.has_value() ? keytree::PinBlob::decode(body.value()) : std::nullopt;
    if (!stored.has_value()) {
        // The same as a deleted blob: first contact for what it held (it is overwritten by the next save).
        LOG_WARN("[pins] the stored pins fail their integrity check; ignored")
        return;
    }
    _treeVerifier.mergeStored(stored->tree);
    _groupDataSchemaMapper->importVersionPins(stored->planes);
}

void GroupApiImpl::pinsMoved(bool major) {
    if (!_pinStore) {
        return;
    }
    std::unique_lock<std::mutex> lock(_dueMutex);
    _pinsMoved = true;
    _pinsMovedMajor = _pinsMovedMajor || major;
}

bool GroupApiImpl::savePins(bool all) {
    if (!_pinStore) {
        return true;
    }
    bool saved = false;
    {
        std::lock_guard<std::mutex> lock(_pinSaveMutex);
        {
            // Before the export: a move after it marks the pins again.
            std::unique_lock<std::mutex> dueLock(_dueMutex);
            _pinsMoved = _pinsMovedMajor = false;
        }
        keytree::TreeVerifier::PinSet mine;
        mine.tree = _treeVerifier.exportPins(all || _pinSaveFull);
        mine.planes = _groupDataSchemaMapper->exportVersionPins();
        std::optional<keytree::TreeVerifier::PinSet> stored;
        try {
            saved = core::updateSealed(
                *_pinStore, _userPrivKey, _pinStoreKey, keytree::PinBlob::LABEL, keytree::PinBlob::VERSION,
                [&](const std::optional<std::string>& body) {
                    stored = body.has_value() ? keytree::PinBlob::decode(body.value()) : std::nullopt;
                    if (stored.has_value()) {
                        return keytree::PinBlob::encode(keytree::PinBlob::mergeForSave(mine, stored.value()));
                    }
                    // Nothing stored, another version or a bad tag: overwritten with every pin in full.
                    if (body.has_value()) {
                        LOG_WARN("[pins] the stored pins do not parse; overwritten")
                    }
                    return keytree::PinBlob::encode(
                        all || _pinSaveFull ? mine
                                            : keytree::TreeVerifier::PinSet{_treeVerifier.exportPins(true), mine.planes}
                    );
                }
            );
        } catch (const std::exception& e) {
            LOG_WARN("[pins] the pin store does not save: ", e.what())
        } catch (...) { LOG_WARN("[pins] the pin store does not save") }
        if (saved) {
            // What another instance of this device saved meanwhile comes in too (`PinBlob::higher`).
            if (stored.has_value()) {
                _treeVerifier.mergeStored(stored->tree);
                _groupDataSchemaMapper->importVersionPins(stored->planes);
            }
            _pinSaveFull = false;
        } else {
            // Not fail-closed: the pins in memory still protect this instance; the slot is retried in full.
            _pinSaveFull = true;
        }
    }
    std::unique_lock<std::mutex> lock(_dueMutex);
    // A failure is retried as a minor move: once PIN_SAVE_IDLE_INTERVAL has passed, or at the next major move, own
    // commit, disconnect or destruction; not at every verification against a store that keeps refusing.
    _lastPinSave = std::chrono::steady_clock::now();
    _pinsMoved = _pinsMoved || !saved;
    return saved;
}

void GroupApiImpl::adoptPreviousIdentity(const privmx::crypto::PrivateKey& previous) {
    const std::string previousPub = previous.getPublicKey().toBase58DER();
    {
        std::lock_guard<std::mutex> lock(_pinSaveMutex);
        if (_adoptedIdentities.count(previousPub) > 0) {
            return;
        }
    }
    // The connection records the key (for `climbsWithPreviousIdentity`) and stages what its slot holds; it throws
    // when the slot does not open. The current key, or no store: nothing staged, nothing to adopt.
    const auto connectionImpl = _connection.getImpl();
    connectionImpl->adoptPreviousIdentity(previous);
    if (!_pinStore || previousPub == _userPrivKey.getPublicKey().toBase58DER()) {
        return;
    }
    const auto staged = connectionImpl->getStagedPinBodies();
    if (const auto it = staged.find(previousPub); it != staged.end()) {
        const auto adopted = keytree::PinBlob::decode(it->second);
        if (!adopted.has_value()) {
            // Never ignored: corrupting the slot must not be a way to turn adoption off.
            throw core::LocalStateIntegrityException("the previous identity's group pins do not open");
        }
        adoptBody(adopted.value());
    }
    std::lock_guard<std::mutex> lock(_pinSaveMutex);
    _adoptedIdentities.insert(previousPub);
}

void GroupApiImpl::adoptBody(const keytree::TreeVerifier::PinSet& adopted) {
    // Only for groups with no pin under the current key, and only as hints: whoever holds the previous key can write
    // its slot, so its records never replace or raise a pin, and are saved only once a read has verified them. Its
    // version pins are not taken at all: raised by such a record, they would refuse honest answers as rollbacks.
    _treeVerifier.mergeStored(adopted.tree, true);
}
