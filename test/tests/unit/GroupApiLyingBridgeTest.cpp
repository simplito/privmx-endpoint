/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

/**
 * GroupApiImpl's own wiring against a bridge that lies. Each client is a real GroupApiImpl on a real ConnectionImpl
 * (`connectOver`) whose gateway answers from one in-memory bridge: the key tree by the storage rule in
 * TreeFakeBridge.hpp, everything else stored as sent. A test then rolls the bridge back, swaps a group under the same
 * id, relabels an event or holds back a metadata entry, and checks what the client does with it.
 */

#include <gtest/gtest.h>

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <mutex>
#include <set>
#include <thread>

#include <privmx/endpoint/core/Connection.hpp>
#include <privmx/endpoint/core/ConnectionImpl.hpp>
#include <privmx/endpoint/core/CoreException.hpp>
#include <privmx/endpoint/core/EventQueueImpl.hpp>
#include <privmx/endpoint/core/UserVerifierInterface.hpp>
#include <privmx/endpoint/group/Events.hpp>
#include <privmx/endpoint/group/GroupApi.hpp>
#include <privmx/endpoint/group/GroupApiImpl.hpp>
#include <privmx/endpoint/group/GroupAwareModuleApi.hpp>
#include <privmx/endpoint/group/GroupException.hpp>
#include <privmx/endpoint/group/encryptors/envelope/GroupEnvelopeEncryptor.hpp>
#include <privmx/endpoint/group/keytree/GroupKeyResolver.hpp>
#include <privmx/endpoint/group/keytree/LadderKeys.hpp>
#include <privmx/endpoint/group/keytree/TreeKeys.hpp>
#include <privmx/privfs/gateway/RpcGateway.hpp>

#include <privmx/endpoint/core/LocalSeal.hpp>
#include <privmx/endpoint/group/keytree/PinBlob.hpp>

#include "GroupApiImplTestAccess.hpp"
#include "TreeTestOps.hpp"
#include "MemoryPinStore.hpp"
#include "TestHelpers.hpp"
#include "TreeFakeBridge.hpp"

namespace core = privmx::endpoint::core;
using privmx::crypto::PublicKey;
using privmx::endpoint::group::GroupApiImplTestAccess;

namespace {

const std::string CONTEXT = "ctx-lying";

// A policy as the API takes it.
core::ContainerPolicy policyWith(const std::map<std::string, std::string>& rules) {
    core::ContainerPolicy policy;
    for (const auto& [field, rule] : rules) {
        (field == "update" ? policy.update : field == "rotateKeys" ? policy.rotateKeys :
         field == "updatePolicy" ? policy.updatePolicy : policy.ownerCanBeRemovedFromManagers) = rule;
    }
    return policy;
}

// OPEN_POLICY as the API takes it.
const core::ContainerPolicy OPEN = policyWith({{"update", "user"}, {"rotateKeys", "user"}, {"updatePolicy", "user"}});

privmx::utils::PrivmxException archiveInvalid() {
    return privmx::utils::PrivmxException("GROUP_ARCHIVE_INVALID", privmx::utils::PrivmxException::RPC, 0x621F);
}

// One group's bridge, shared by every client. Every request is answered under one lock (`sync`), so the clients'
// threads never interleave inside it; a test touching the bridge while one may run takes it too. A copy shares the lock and never answers.
struct Bridge {
    struct Sync {
        std::mutex m;
        std::condition_variable cv; // notified on every plan read
    };
    std::shared_ptr<Sync> sync = std::make_shared<Sync>();
    std::map<std::string, PrivateKey> users; // the Context user list
    // Keys each user held before `changeUserKey`, with the time each was replaced (ms), for the Verifier.
    std::map<std::string, std::vector<std::pair<std::string, std::int64_t>>> retiredKeys;
    // What `contextListUsers` serves for a user instead of its key in `users` (a lying listing).
    std::map<std::string, PrivateKey> listedKeys;
    FakeBridge tree;
    server::GroupInfo rest; // everything but the tree, as sent
    std::vector<std::pair<std::string, server::GroupSendCustomEventModel>> events; // (sender, as sent)
    // Hooks run under the lock. `beforeRemoval` may wait on `sync->cv` with it; the others throw to refuse, `onAdd`
    // and `onSelfUpdate` before the commit is applied, `afterRemoval` after.
    std::function<void(std::unique_lock<std::mutex>&)> beforeRemoval = [](std::unique_lock<std::mutex>&) {};
    std::function<void()> afterRemoval = [] {};
    std::function<void()> beforeRotation = [] {}; // runs as a rotation arrives, before it is checked
    std::function<void()> afterRotation = [] {};  // runs once the rotation is applied; throws to lose the answer
    std::function<void()> onAdd = [] {};
    std::function<void()> onSelfUpdate = [] {};
    // Before a policy commit is applied; may release the lock (to let another client commit) and throw to refuse.
    std::function<void(std::unique_lock<std::mutex>&)> onPolicy = [](std::unique_lock<std::mutex>&) {};
    // Every statement a client sent with an add, a removal, a rotation or a self-update, in order, applied or not.
    std::vector<server::GroupTreeCommit> received;
    int planReads = 0; // `groupGet`s in the "plan" scope
    std::function<void(server::GroupInfo&)> onPlanRead = [](server::GroupInfo&) {}; // edits what a plan read serves
    // Edits what any `groupGet` serves `caller`.
    std::function<void(const std::string&, server::GroupInfo&)> onRead = [](const std::string&, server::GroupInfo&) {};
    std::function<void()> onMetaWrite = [] {}; // before a metadata write is stored; throws to refuse
    std::shared_ptr<std::atomic<int>> verifierCalls = std::make_shared<std::atomic<int>>(0);
    struct Call {
        std::string caller;
        std::string method;
        Poco::JSON::Object::Ptr params;
    };
    std::vector<Call> calls;
    // The Epoch Ladder as stored: author set to the caller of the operation that stored each rung, as the bridge does.
    std::vector<server::GroupArchiveRung> rungs;
    std::int64_t eraFloor = 1;

    std::size_t count(const std::string& caller, const std::string& method) const {
        return static_cast<std::size_t>(std::count_if(calls.begin(), calls.end(), [&](const Call& call) {
            return call.caller == caller && call.method == method;
        }));
    }

    server::GroupInfo serve(const std::string& userId, bool plan) const {
        server::GroupInfo info = tree.serve(userId, plan);
        info.type = rest.type;
        info.createDate = info.lastModificationDate = 1;
        info.data = rest.data;
        info.history = rest.history;
        info.groupKeys = rest.groupKeys;
        info.publicMeta = rest.publicMeta;
        info.privateMeta = rest.privateMeta;
        info.publicMetaVersion = rest.publicMetaVersion;
        info.privateMetaVersion = rest.privateMetaVersion;
        return info;
    }

    // The roster entry, history and self-addressed metadata key a removal or a rotation publishes for its epoch.
    template<typename Model>
    void storeNewEpoch(const std::string& caller, const Model& model) {
        for (server::GroupArchiveRung rung : model.rungs) {
            if (rung.author.has_value()) {
                throw archiveInvalid(); // not a field a client may send
            }
            rung.author = caller;
            rungs.push_back(rung);
        }
        server::GroupDataEntry head;
        head.keyId = model.keyId;
        head.data = model.data;
        rest.data.push_back(head);
        rest.history.push_back(
            {model.keyId, model.groupPubKey, privmx::utils::Utils::getNowTimestamp(), caller, tree.rosterVersion,
             static_cast<int64_t>(tree.state.epoch)}
        );
        rest.groupKeys->at(0).keys.push_back(
            {.keyId = model.groupKeys->keyId, .data = model.groupKeys->data, .groupEpoch = model.groupKeys->groupEpoch}
        );
    }

    // The registrar's `context/addUserToContext` upsert: one key per user, the old one replaced.
    void changeUserKey(const std::string& user, const PrivateKey& newKey) {
        std::unique_lock<std::mutex> lock(sync->m);
        retiredKeys[user].emplace_back(users.at(user).getPublicKey().toBase58DER(), privmx::utils::Utils::getNowTimestamp());
        users.at(user) = newKey;
    }

    // `sessionPub`: the key the caller's session logged in with. The bridge resolves the caller by it
    // (CloudAccessValidator), so a session of a key the Context no longer lists is refused everything.
    Poco::Dynamic::Var answer(
        const std::string& caller,
        const std::string& sessionPub,
        const std::string& method,
        Poco::JSON::Object::Ptr params
    ) {
        std::unique_lock<std::mutex> lock(sync->m);
        calls.push_back({caller, method, params});
        if (users.count(caller) == 0 || users.at(caller).getPublicKey().toBase58DER() != sessionPub) {
            throw privmx::utils::PrivmxException("ACCESS_DENIED", privmx::utils::PrivmxException::RPC, 0x0030);
        }
        const std::string group = method.substr(std::string("context.").size());
        if (method == "context.contextGet") {
            return core::server::ContextGetResult{.context = {.userId = caller, .contextId = CONTEXT}}.toJSON();
        }
        if (method == "context.contextListUsers") {
            core::server::ContextListUsersResult result;
            for (const auto& [id, key] : users) {
                core::server::UserIdentityWithStatusAndAction user;
                user.id = id;
                const auto listed = listedKeys.find(id);
                user.pub = (listed != listedKeys.end() ? listed->second : key).getPublicKey().toBase58DER();
                user.status = "inactive";
                result.users.push_back(user);
            }
            result.count = static_cast<int64_t>(result.users.size());
            return result.toJSON();
        }
        if (method == "subscribeToChannels") {
            core::server::SubscribeToChannelsResult result;
            for (const auto& channel : core::server::SubscribeToChannelsModel::fromJSON(params).channels) {
                result.subscriptions.push_back({.subscriptionId = "sub:" + channel, .channel = channel});
            }
            return result.toJSON();
        }
        if (group == "groupCreate") {
            const auto model = server::GroupCreateModel::fromJSON(params);
            tree = FakeBridge{};
            tree.keyOf = [this](const std::string& id) { return users.at(id).getPublicKey(); };
            tree.resourceId = model.resourceId;
            tree.contextId = model.contextId;
            tree.groupId = TreeCommits::groupId(model.contextId, model.resourceId);
            tree.create(
                model.tree, PublicKey::fromBase58DER(model.groupPubKey), caller, model.commit,
                std::set<std::string>(model.managers.begin(), model.managers.end())
            );
            rest = server::GroupInfo{};
            rest.type = model.type;
            rest.creator = caller;
            server::GroupDataEntry head;
            head.keyId = model.keyId;
            head.data = model.data;
            rest.data = {head};
            rest.history = {{model.keyId, model.groupPubKey, privmx::utils::Utils::getNowTimestamp(), caller, 1, 1}};
            rest.groupKeys = std::vector<core::server::GroupKeysEntry>{
                {.group = tree.groupId,
                 .keys = {{.keyId = model.groupKeys->keyId, .data = model.groupKeys->data, .groupEpoch = 1}}}
            };
            rest.publicMeta = {1, model.keyId, 1, model.publicMeta, 1, caller};
            rest.privateMeta = {1, model.keyId, 1, model.privateMeta, 1, caller};
            rest.publicMetaVersion = rest.privateMetaVersion = 1;
            return server::GroupCreateResult{.groupId = tree.groupId}.toJSON();
        }
        if (group == "groupGet") {
            const auto model = server::GroupGetModel::fromJSON(params);
            const bool plan = model.scope == std::optional<std::string>("plan");
            server::GroupInfo info = serve(caller, plan);
            if (model.forNewMembers.has_value()) {
                std::vector<std::int64_t> seats;
                for (const std::uint32_t seat :
                     treetest::choosePositions(tree.state, static_cast<std::uint32_t>(model.forNewMembers.value()))) {
                    seats.push_back(seat);
                }
                info.nextFreeSeats = seats;
            }
            onRead(caller, info);
            if (plan) {
                onPlanRead(info);
                ++planReads;
                sync->cv.notify_all();
            }
            return server::GroupGetResult{.group = info}.toJSON();
        }
        if (group == "groupGetTreeCommits") {
            const auto model = server::GroupGetTreeCommitsModel::fromJSON(params);
            return tree
                .commitsBetween(
                    static_cast<std::uint64_t>(model.fromSeq),
                    static_cast<std::uint64_t>(model.toSeq.value_or(INT64_MAX))
                )
                .toJSON();
        }
        if (group == "groupList") {
            const server::GroupInfo info = serve(tree.state.leafAssignment.at(0).value_or(caller), false);
            server::GroupSummary summary;
            summary.id = info.id;
            summary.groupPubKey = info.groupPubKey;
            summary.contextId = info.contextId;
            summary.resourceId = info.resourceId;
            summary.type = info.type;
            summary.creator = info.creator;
            summary.lastModifier = info.creator;
            summary.createDate = summary.lastModificationDate = 1;
            summary.publicMetaVersion = info.publicMetaVersion;
            summary.privateMetaVersion = info.privateMetaVersion;
            summary.rosterVersion = info.rosterVersion;
            summary.keyVersion = info.keyVersion;
            summary.policy = info.policy;
            return server::GroupListResult{.groups = {summary}, .count = 1}.toJSON();
        }
        if (group == "groupAddMembers") {
            const auto model = server::GroupAddMembersModel::fromJSON(params);
            received.push_back(model.commit);
            onAdd();
            std::vector<std::string> ids;
            std::vector<std::string> newManagers;
            for (const server::GroupAddMemberEntry& member : model.members) {
                ids.push_back(member.userId);
                if (member.role == "manager") {
                    newManagers.push_back(member.userId);
                }
            }
            std::vector<std::uint32_t> positions;
            for (const std::int64_t position : model.transition.positions) {
                positions.push_back(static_cast<std::uint32_t>(position));
            }
            std::vector<server::GroupTreeRefreshedNode> refreshed;
            for (const server::GroupTreeSeatedNode& node : model.transition.seatedNodes) {
                refreshed.push_back({node.nodeIndex, node.fromGeneration, node.generation, node.publicKey});
            }
            tree.commit(
                CommitOp::Add, caller, ids, positions, refreshed, model.transition.edges, std::nullopt, model.commit,
                newManagers
            );
            server::GroupDataEntry head;
            head.keyId = model.keyId;
            head.data = model.data;
            rest.data.push_back(head);
            rest.history.push_back(
                {model.keyId, rest.history.back().groupPubKey, privmx::utils::Utils::getNowTimestamp(), caller,
                 tree.rosterVersion, static_cast<int64_t>(tree.state.epoch)}
            );
            return Poco::Dynamic::Var();
        }
        if (group == "groupSelfUpdate") {
            const auto commit = server::GroupTreeCommit::fromJSON(params->getObject("commit"));
            received.push_back(commit);
            onSelfUpdate();
            // A key revocation (a later fix) sends no transition; every self-update here does.
            if (params->has("transition")) {
                const auto transition = server::GroupTreeSelfUpdateTransition::fromJSON(
                    params->getObject("transition")
                );
                tree.commit(
                    CommitOp::SelfUpdate, caller, {}, {}, transition.refreshedNodes, transition.edges, std::nullopt,
                    commit
                );
            }
            return Poco::Dynamic::Var();
        }
        if (group == "groupRemoveMembers") {
            const auto model = server::GroupRemoveMembersModel::fromJSON(params);
            received.push_back(model.commit);
            beforeRemoval(lock);
            tree.commit(
                CommitOp::Remove, caller, model.userIds, {}, model.transition.refreshedNodes,
                model.transition.edges, PublicKey::fromBase58DER(model.groupPubKey), model.commit
            );
            storeNewEpoch(caller, model);
            afterRemoval();
            return Poco::Dynamic::Var();
        }
        if (group == "groupGenerateNewKey") {
            const auto model = server::GroupGenerateNewKeyModel::fromJSON(params);
            received.push_back(model.commit);
            beforeRotation();
            tree.rotate(caller, model.grantEdge, PublicKey::fromBase58DER(model.groupPubKey), model.commit);
            storeNewEpoch(caller, model);
            afterRotation();
            return Poco::Dynamic::Var();
        }
        if (group == "groupUpdatePolicy") {
            const auto model = server::GroupUpdatePolicyModel::fromJSON(params);
            received.push_back(model.commit);
            onPolicy(lock);
            tree.changePolicy(caller, model.commit);
            return Poco::Dynamic::Var();
        }
        if (group == "groupUpdatePublicMeta" || group == "groupUpdatePrivateMeta") {
            const auto model = server::GroupUpdatePublicMetaModel::fromJSON(params);
            onMetaWrite();
            auto& plane = group == "groupUpdatePublicMeta" ? rest.publicMeta : rest.privateMeta;
            auto& version = group == "groupUpdatePublicMeta" ? rest.publicMetaVersion : rest.privateMetaVersion;
            version = model.version + 1;
            plane = {version, model.keyId, static_cast<int64_t>(tree.state.epoch), model.data, 1, caller};
            return Poco::Dynamic::Var();
        }
        if (group == "groupSendCustomEvent") {
            events.emplace_back(caller, server::GroupSendCustomEventModel::fromJSON(params));
            return Poco::Dynamic::Var();
        }
        if (group == "groupGetKeyArchive") {
            // `keyHistory` is left empty: the client takes past grant keys off the statements, never from here.
            const auto model = server::GroupGetKeyArchiveModel::fromJSON(params);
            server::GroupGetKeyArchiveResult result;
            result.keyVersion = static_cast<std::int64_t>(tree.state.epoch);
            result.eraFloor = eraFloor;
            for (const server::GroupArchiveRung& rung : rungs) {
                if (rung.atKeyVersion >= model.fromKeyVersion.value_or(1) &&
                    rung.atKeyVersion <= model.toKeyVersion.value_or(INT64_MAX) && rung.targetKeyVersion >= eraFloor) {
                    result.rungs.push_back(rung);
                }
            }
            return result.toJSON();
        }
        if (group == "groupRepairRung") {
            // The bridge's rules: a seated caller, a downward span at an existing epoch above the floor, one rung per
            // span per author, at most four per span.
            const auto model = server::GroupRepairRungModel::fromJSON(params);
            server::GroupArchiveRung rung = model.rung;
            if (!seatOf(tree.state, caller).has_value()) {
                throw privmx::utils::PrivmxException("ACCESS_DENIED", privmx::utils::PrivmxException::RPC, 0x0001);
            }
            if (rung.author.has_value() || rung.targetKeyVersion >= rung.atKeyVersion ||
                rung.atKeyVersion > static_cast<std::int64_t>(tree.state.epoch) || rung.targetKeyVersion < eraFloor) {
                throw archiveInvalid();
            }
            std::size_t inSpan = 0;
            for (const server::GroupArchiveRung& stored : rungs) {
                if (stored.atKeyVersion == rung.atKeyVersion && stored.targetKeyVersion == rung.targetKeyVersion) {
                    ++inSpan;
                    if (stored.author == std::optional<std::string>(caller)) {
                        throw archiveInvalid();
                    }
                }
            }
            if (inSpan >= 4) {
                throw archiveInvalid();
            }
            rung.author = caller;
            rungs.push_back(rung);
            return Poco::Dynamic::Var();
        }
        if (group == "groupDelete") {
            return Poco::Dynamic::Var();
        }
        throw std::runtime_error("the fake bridge has no " + method);
    }
};

class Gateway : public privmx::privfs::RpcGateway {
public:
    Gateway(Bridge& bridge, const std::string& userId, const PrivateKey& sessionKey)
        : RpcGateway(privmx::rpc::AuthorizedConnection::Ptr(), std::nullopt), _bridge(bridge), _userId(userId),
          _sessionPub(sessionKey.getPublicKey().toBase58DER()) {}

    Poco::Dynamic::Var request(
        const std::string& method,
        Poco::JSON::Object::Ptr params,
        privmx::rpc::MessageSendOptionsEx,
        privmx::utils::CancellationToken::Ptr
    ) override {
        const Poco::Dynamic::Var result = _bridge.answer(_userId, _sessionPub, method, overTheWire(params));
        return result.isEmpty() ? result : Poco::Dynamic::Var(overTheWire(result));
    }
    bool isConnected() override { return true; }

private:
    Bridge& _bridge;
    std::string _userId;
    std::string _sessionPub;
};

// The application's: each user's real key, nobody else's. A key replaced by `changeUserKey` still vouches for what
// it signed before it was replaced, and for nothing after (the date is capped at now).
class Verifier : public core::UserVerifierInterface {
public:
    explicit Verifier(const Bridge& bridge) : _bridge(bridge) {}
    std::vector<bool> verify(const std::vector<core::VerificationRequest>& requests) override {
        ++*_bridge.verifierCalls;
        const std::int64_t now = privmx::utils::Utils::getNowTimestamp();
        std::vector<bool> verified;
        for (const auto& request : requests) {
            const auto user = _bridge.users.find(request.senderId);
            bool ok = user != _bridge.users.end() && user->second.getPublicKey().toBase58DER() == request.senderPubKey;
            if (const auto retired = _bridge.retiredKeys.find(request.senderId); !ok && retired != _bridge.retiredKeys.end()) {
                for (const auto& [pub, until] : retired->second) {
                    ok = ok || (pub == request.senderPubKey && std::min(request.date, now) <= until);
                }
            }
            verified.push_back(ok);
        }
        return verified;
    }

private:
    const Bridge& _bridge;
};

struct Client {
    std::shared_ptr<core::ConnectionImpl> connectionImpl = std::make_shared<core::ConnectionImpl>();
    core::Connection connection;
    GroupApi groupApi;
    std::shared_ptr<GroupApiImpl> api;

    // 01: `store` set as the app sets it, right after connect; `identity` names the Bridge; `previous` is adopted
    // (Connection::adoptPreviousIdentity) before the GroupApi is created.
    Client(
        Bridge& bridge,
        const std::string& userId,
        const std::shared_ptr<core::PinStoreInterface>& store = nullptr,
        const std::optional<core::BridgeIdentity>& identity = std::nullopt,
        const std::optional<PrivateKey>& previous = std::nullopt
    ) {
        connectionImpl->setUserVerifier(std::make_shared<Verifier>(bridge));
        connectionImpl->connectOver(
            new Gateway(bridge, userId, bridge.users.at(userId)), bridge.users.at(userId), identity
        );
        connectionImpl->setPinStore(store);
        if (previous.has_value()) {
            connectionImpl->adoptPreviousIdentity(previous.value());
        }
        connection = ConnectionOf(connectionImpl);
        groupApi = GroupApi::create(connection);
        api = groupApi.getImpl();
    }

    std::string subscribe(const std::string& query) { return api->subscribeFor({query}).at(0); }

    void notify(const std::string& type, const Poco::Dynamic::Var& data, const std::string& subscription) {
        connectionImpl->getEventMiddleware()->emitNotificationEvent(
            type, core::NotificationEvent{
                      .source = core::EventSource::SERVER,
                      .type = type,
                      .data = overTheWire(data),
                      .version = 1,
                      .timestamp = 1,
                      .subscriptions = {subscription}
                  }
        );
    }
};

// Runs `body(i)` on `threads` threads released together, so their calls overlap as much as the scheduler allows.
void race(int threads, const std::function<void(int)>& body) {
    std::atomic<int> ready{0};
    std::vector<std::thread> running;
    for (int i = 0; i < threads; ++i) {
        running.emplace_back([&, i] {
            ready++;
            while (ready.load() < threads) {
                std::this_thread::yield();
            }
            body(i);
        });
    }
    for (auto& thread : running) {
        thread.join();
    }
}

std::string digestOf(const server::GroupTreeCommit& commit) {
    return TreeCommits::digest(TreeCommits::fromWire(commit));
}

std::string prevOf(const server::GroupTreeCommit& commit) {
    return TreeCommits::fromWire(commit).prevDigest;
}

// A bridge refusal that is not a lost race (`isRetryableCommitRejection`).
[[noreturn]] void refuse(const std::string& name = "ACCESS_DENIED", unsigned int code = 0x0030) {
    throw privmx::utils::PrivmxException(name, privmx::utils::PrivmxException::RPC, code);
}

// `call` refused with `E` for `reason` (a fragment of `what()`): a SECURITY test that only checks the type passes
// when a later check throws the same type for another reason, and so misses the check it is about going away.
template<typename E>
void expectRefusal(const std::function<void()>& call, const std::string& reason) {
    try {
        call();
        ADD_FAILURE() << "not refused; expected: " << reason;
    } catch (const E& e) {
        EXPECT_NE(std::string(e.what()).find(reason), std::string::npos) << "refused for another reason: " << e.what();
    }
}

// Exposes the grantee resolution every container module runs on a create or an update.
class GrantingModule : public GroupAwareModuleApi {
public:
    using GroupAwareModuleApi::GroupAwareModuleApi;
    using GroupAwareModuleApi::resolveGroupEpochs;

private:
    std::pair<core::ModuleKeys, int64_t> getModuleKeysAndVersionFromServer(std::string) override {
        throw std::logic_error("not a module of its own");
    }
};

class GroupApiLyingBridge : public testing::Test {
protected:
    Bridge bridge;
    std::map<std::string, std::unique_ptr<Client>> clients;
    bool quiet = false; // every client's flush point (`runDueWork`) turned off as it is created
    // 01: the device's store every client of this fixture gets (none by default), and the Bridge it names.
    std::shared_ptr<MemoryPinStore> store;
    std::optional<core::BridgeIdentity> bridgeIdentity;
    std::vector<std::unique_ptr<Client>> siblings; // further live clients of a user, on the same store

    void SetUp() override {
        for (const std::string id : {"alice", "bob", "carol"}) {
            bridge.users.emplace(id, PrivateKey::generateRandom());
        }
        core::EventQueueImpl::getInstance()->clear();
    }

    void TearDown() override {
        siblings.clear();
        clients.clear();
    }

    // 01: another live instance (a tab, a process) of `userId` on the fixture's store.
    GroupApiImpl& sibling(const std::string& userId) {
        siblings.push_back(std::make_unique<Client>(bridge, userId, store, bridgeIdentity));
        if (quiet) {
            GroupApiImplTestAccess::stopDueWork(*siblings.back()->api);
        }
        return *siblings.back()->api;
    }

    // A session gone without its destructor (a killed browser tab or mobile process): nothing saved on the way out.
    void kill(const std::string& userId) {
        (void)clients.at(userId).release();
        clients.erase(userId);
    }

    // The record `userId`'s slot (on the fixture's Bridge) holds for the group, opened with `key`.
    std::optional<TreeVerifier::Pin> storedPin(
        const std::string& groupId,
        const PrivateKey& key,
        const std::string& kind = "group-pins/"
    ) {
        const std::string slot = store->keyWith(kind, "/" + key.getPublicKey().toBase58DER());
        const auto body = core::openLocal(key, PinBlob::LABEL, PinBlob::VERSION, slot, store->get(slot));
        const auto pins = body.has_value() ? PinBlob::decode(body.value()) : std::nullopt;
        if (!pins.has_value() || pins->tree.count(groupId) == 0) {
            return std::nullopt;
        }
        return pins->tree.at(groupId);
    }

    std::size_t count(const std::string& caller, const std::string& method) {
        std::unique_lock<std::mutex> guard(bridge.sync->m);
        return bridge.count(caller, method);
    }

    int removeTwoOnOneHead(const std::string& groupId, const std::function<void()>& firstArrives);

    // Replaces every stored rung of the span with one that opens with no epoch's key.
    void corrupt(std::int64_t at, std::int64_t target) {
        std::unique_lock<std::mutex> guard(bridge.sync->m);
        for (server::GroupArchiveRung& rung : bridge.rungs) {
            if (rung.atKeyVersion == at && rung.targetKeyVersion == target) {
                rung.data = LadderKeys::sealRung(
                    PrivateKey::generateRandom(), RungSpan{static_cast<std::uint32_t>(at), static_cast<std::uint32_t>(target)},
                    PrivateKey::generateRandom().getPublicKey(), PrivateKey::generateRandom()
                );
            }
        }
    }

    // The group of four the repair tests start from, with bob holding epoch 1 and alice having removed dave since.
    std::string groupAtEpoch2WithBobHoldingEpoch1() {
        bridge.users.emplace("dave", PrivateKey::generateRandom());
        const std::string groupId = createGroup({"alice", "bob", "carol", "dave"});
        client("bob").resolveGroupPrivKey(groupId);
        client("alice").removeGroupMembers(groupId, {"dave"});
        return groupId;
    }

    GroupApiImpl& client(const std::string& userId) {
        auto& client = clients[userId];
        if (!client) {
            client = std::make_unique<Client>(bridge, userId, store, bridgeIdentity);
            if (quiet) {
                GroupApiImplTestAccess::stopDueWork(*client->api);
            }
        }
        return *client->api;
    }

    // 08a: a session of `userId` (whose identity key changed) that adopted `previous` right after connect
    // (Connection::adoptPreviousIdentity), replacing any session it had.
    GroupApiImpl& clientAdopting(const std::string& userId, const PrivateKey& previous) {
        auto& client = clients[userId];
        client = std::make_unique<Client>(bridge, userId, store, bridgeIdentity, previous);
        if (quiet) {
            GroupApiImplTestAccess::stopDueWork(*client->api);
        }
        return *client->api;
    }

    void addUsers(const std::vector<std::string>& ids) {
        for (const std::string& id : ids) {
            bridge.users.emplace(id, PrivateKey::generateRandom());
        }
    }

    // The bridge's state put back as it was at `snapshot` (the statement it took is gone).
    void rollBackTo(const Bridge& snapshot) {
        bridge.tree = snapshot.tree;
        bridge.rest = snapshot.rest;
    }

    // A member, other than the creator, whose own keyed path needs a self-update right after the group is created
    // (a node the creator set that it is not seated under). Empty if none.
    std::string memberNeedingSelfUpdate(const std::vector<std::string>& members) {
        for (const std::string& id : members) {
            if (id != "alice" && GroupKeyResolver::nodeNeedingSelfUpdate(bridge.serve(id, false)).has_value()) {
                return id;
            }
        }
        return {};
    }

    core::UserWithPubKey user(const std::string& id) {
        return {.userId = id, .pubKey = bridge.users.at(id).getPublicKey().toBase58DER()};
    }

    // Created by alice, a manager; the others users. Under the open policy unless a test says otherwise, so every
    // member may commit (03).
    std::string createGroup(
        const std::vector<std::string>& members,
        const std::optional<core::ContainerPolicy>& policy = OPEN,
        const std::vector<std::string>& managers = {"alice"}
    ) {
        std::vector<core::UserWithPubKey> users;
        std::vector<core::UserWithPubKey> managerKeys;
        for (const auto& id : members) {
            (std::find(managers.begin(), managers.end(), id) != managers.end() ? managerKeys : users).push_back(user(id));
        }
        return client("alice").createGroup(
            CONTEXT, users, managerKeys, core::Buffer::from("public"), core::Buffer::from("private"), policy
        );
    }

    // A self-update `committer` signs and the bridge stores: the next seq, with the epoch, roster and keys unchanged.
    void selfUpdateBy(const std::string& committer, std::optional<std::uint64_t> date = std::nullopt) {
        const PrivateKey& priv = bridge.users.at(committer);
        const TreeGroupState served = GroupKeyResolver::toTreeState(bridge.serve(committer, true));
        TreeKeyCache cache;
        TreeKeys keys(cache);
        ASSERT_EQ(keys.climbToGrantKey(served, committer, priv, false).failure, ClimbFailure::None);
        std::vector<TreeMember> members;
        for (const auto& [id, key] : bridge.users) {
            members.push_back(TreeMember{id, key.getPublicKey()});
        }
        treetest::setMemberKeys(keys, members);
        const CommitPlan plan = keys.planSelfUpdate(served, committer, priv);
        const auto wire = TreeWire::toSelfUpdateTransition(plan, bridge.tree.state.epoch);
        CommitStatement statement = TreeCommits::statementFor(
            plan, CommitOp::SelfUpdate, bridge.tree.groupId,
            date.value_or(static_cast<std::uint64_t>(privmx::utils::Utils::getNowTimestamp())), bridge.tree.state.epoch,
            bridge.tree.state.grantPublicKey.toBase58DER(), static_cast<std::uint64_t>(bridge.tree.rosterVersion),
            bridge.tree.users(), {bridge.tree.managers.begin(), bridge.tree.managers.end()}, committer, {}, {}, {},
            bridge.tree.rules().hash
        );
        statement.prevDigest = TreeCommits::digest(TreeCommits::fromWire(bridge.tree.commits.back()));
        TreeCommits::sign(statement, priv);
        bridge.tree.commit(
            CommitOp::SelfUpdate, committer, {}, {}, wire.refreshedNodes, wire.edges, std::nullopt,
            TreeCommits::toWire(statement)
        );
    }

    // A plan `committer` makes off the served plan view, as a client of its own would (no GroupApiImpl, so no check of
    // its role: a colluding member, or the bridge's own statement under a member's key).
    CommitPlan planBy(const std::string& committer, const std::function<CommitPlan(TreeKeys&, const TreeGroupState&)>& plan) {
        const PrivateKey& priv = bridge.users.at(committer);
        const TreeGroupState served = GroupKeyResolver::toTreeState(bridge.serve(committer, true));
        TreeKeyCache cache;
        TreeKeys keys(cache);
        EXPECT_EQ(keys.climbToGrantKey(served, committer, priv, false).failure, ClimbFailure::None);
        std::vector<TreeMember> members;
        for (const auto& [id, key] : bridge.users) {
            members.push_back(TreeMember{id, key.getPublicKey()});
        }
        treetest::setMemberKeys(keys, members);
        return plan(keys, served);
    }

    CommitStatement signedBy(const std::string& committer, CommitStatement statement) {
        statement.prevDigest = TreeCommits::digest(TreeCommits::fromWire(bridge.tree.commits.back()));
        TreeCommits::sign(statement, bridge.users.at(committer));
        return statement;
    }

    // A removal `committer` signs and the bridge stores (tree only), whatever the policy says.
    void removalBy(const std::string& committer, const std::vector<std::string>& leaving) {
        const CommitPlan plan = planBy(committer, [&](TreeKeys& keys, const TreeGroupState& served) {
            return keys.planRemoval(served, leaving, committer, bridge.users.at(committer));
        });
        std::set<std::string> managers = bridge.tree.managers;
        std::vector<std::string> users;
        for (const std::string& id : bridge.tree.users()) {
            if (std::find(leaving.begin(), leaving.end(), id) == leaving.end()) {
                users.push_back(id);
            }
        }
        for (const std::string& id : leaving) {
            managers.erase(id);
        }
        const CommitStatement statement = signedBy(committer, TreeCommits::statementFor(
            plan, CommitOp::Remove, bridge.tree.groupId, static_cast<std::uint64_t>(privmx::utils::Utils::getNowTimestamp()),
            bridge.tree.state.epoch + 1, plan.grantKey.getPublicKey().toBase58DER(),
            static_cast<std::uint64_t>(bridge.tree.rosterVersion + 1), users, {managers.begin(), managers.end()},
            committer, {}, {}, leaving, bridge.tree.rules().hash
        ));
        const auto wire = TreeWire::toRemovalTransition(plan, bridge.tree.state.epoch);
        bridge.tree.commit(
            CommitOp::Remove, committer, leaving, {}, wire.refreshedNodes, wire.edges, plan.grantKey.getPublicKey(),
            TreeCommits::toWire(statement)
        );
    }

    // A policy commit `committer` signs and the bridge stores, as `updateGroupPolicy` builds it.
    void policyBy(const std::string& committer, const Poco::Dynamic::Var& policy) {
        const CommitStatement latest = TreeCommits::fromWire(bridge.tree.commits.back());
        CommitStatement statement = latest;
        statement.seq = latest.seq + 1;
        statement.op = CommitOp::Policy;
        statement.groupId = bridge.tree.groupId;
        statement.date = std::max<std::uint64_t>(latest.date, privmx::utils::Utils::getNowTimestamp());
        statement.committer = committer;
        statement.committerSeat = seatOf(bridge.tree.state, committer).value();
        statement.path.clear();
        statement.policy = policy;
        statement.policyHash = TreeCommits::rules(policy, bridge.tree.creator).hash;
        bridge.tree.changePolicy(committer, TreeCommits::toWire(signedBy(committer, statement)));
    }

    // `sender`'s custom event as the bridge delivers it to alice's subscription on `channel`, under `author`.
    GroupCustomEventData deliver(
        const std::string& groupId,
        const std::string& channel,
        std::size_t sent,
        const std::string& author
    ) {
        client("alice");
        Client& alice = *clients.at("alice");
        const std::string subscription = alice.subscribe(
            alice.api->buildCustomEventSubscriptionQuery(channel, EventSelectorType::GROUP_ID, groupId)
        );
        alice.notify(
            "custom",
            server::GroupCustomEventData{
                .id = groupId,
                .eventData = bridge.events.at(sent).second.data,
                .author = {.id = author, .pub = bridge.users.at(author).getPublicKey().toBase58DER()}
            }
                .toJSON(),
            subscription
        );
        return Events::extractGroupCustomEvent(nextEvent("groupCustom")).data;
    }
};

} // namespace

TEST_F(GroupApiLyingBridge, SECURITY_EveryKeyReadRefusesAStateRolledBackBelowThePin) {
    // T3-02 wiring: `getGroup` and `readGroupForKeys` (under `encrypt`) verify the tree on the answer they use.
    const std::string groupId = createGroup({"alice", "bob"});
    const Bridge atSeq1 = bridge;
    selfUpdateBy("bob");
    client("alice").resolveGroupPrivKey(groupId); // reads seq 2, pins it
    bridge.tree = atSeq1.tree;
    EXPECT_THROW(client("alice").getGroup(groupId), GroupHistoryForkException);
    EXPECT_THROW(client("alice").encrypt(groupId, core::Buffer::from("x")), GroupHistoryForkException);
}

TEST_F(GroupApiLyingBridge, SECURITY_AKeyCachedBehindTheVerifiedEpochIsReadAgainBeforeSealing) {
    // `currentEncKey`: alice's cached head is from before carol's removal, which a later read of hers verified.
    const std::string groupId = createGroup({"alice", "bob", "carol"});
    client("alice").encrypt(groupId, core::Buffer::from("warm"));
    client("bob").removeGroupMembers(groupId, {"carol"});
    client("alice").resolveGroupPrivKey(groupId); // pins epoch 2
    const Envelope sealed = client("alice").encrypt(groupId, core::Buffer::from("after"));
    EXPECT_EQ(GroupEnvelopeEncryptor().peek(sealed).keyId, bridge.rest.data.back().keyId)
        << "sealed under the key carol still holds";
}

TEST_F(GroupApiLyingBridge, SECURITY_ADeletionEventLeavesThePinsInPlace) {
    // T3-08: `groupDeleted` is the bridge's word alone; after it, the state from before the pin is still a rollback.
    const std::string groupId = createGroup({"alice", "bob"});
    const Bridge atSeq1 = bridge;
    selfUpdateBy("bob");
    client("alice").resolveGroupPrivKey(groupId);
    Client& alice = *clients.at("alice");
    alice.notify(
        "groupDeleted", server::GroupDeletedEventData{.groupId = groupId, .contextId = CONTEXT}.toJSON(),
        alice.subscribe(alice.api->buildSubscriptionQuery(EventType::GROUP_DELETE, EventSelectorType::CONTEXT_ID, CONTEXT))
    );
    nextEvent("groupDeleted");
    bridge.tree = atSeq1.tree;
    EXPECT_THROW(client("alice").getGroup(groupId), GroupHistoryForkException);
}

TEST_F(GroupApiLyingBridge, SECURITY_ADeletedGroupsKeysAreNotServedToAGroupRecreatedUnderItsId) {
    // T4-14: a former member who knows the resourceId re-creates the id; alice's memoized epoch 1 key is not its key.
    const std::string groupId = createGroup({"alice", "bob"});
    client("alice").resolveGroupPrivKey(groupId, 1);
    client("alice").deleteGroup(groupId);
    FakeBridge recreated = bridge.tree;
    recreated.commits.clear();
    TreeKeyCache cache;
    TreeKeys keys(cache);
    const PrivateKey& bob = bridge.users.at("bob");
    const CommitPlan plan = keys.planCreate(
        {TreeMember{"alice", bridge.users.at("alice").getPublicKey()}, TreeMember{"bob", bob.getPublicKey()}}, "bob", bob
    );
    CommitStatement genesis = TreeCommits::statementFor(
        plan, CommitOp::Create, recreated.resourceId, privmx::utils::Utils::getNowTimestamp(), 1,
        plan.grantKey.getPublicKey().toBase58DER(), 1, {"alice", "bob"}, {}, "bob", {}, {}, {},
        TreeCommits::rules(OPEN_POLICY, "bob").hash
    );
    genesis.policy = OPEN_POLICY;
    TreeCommits::sign(genesis, bob);
    recreated.create(
        TreeWire::toCreateTree(plan), plan.grantKey.getPublicKey(), "bob", TreeCommits::toWire(genesis)
    );
    bridge.tree = recreated;
    EXPECT_THROW(client("alice").resolveGroupPrivKey(groupId, 1), GroupHistoryForkException);
}

TEST_F(GroupApiLyingBridge, SECURITY_AnEventIsTakenOnlyFromTheUserWhoseKeySignedIt) {
    // T3-12: the bridge names the sender; the UserVerifier must vouch for that name with the key that signed.
    const std::string groupId = createGroup({"alice", "bob"});
    client("bob").sendCustomEvent(groupId, "chat", core::Buffer::from("hi"), {});
    const GroupCustomEventData honest = deliver(groupId, "chat", 0, "bob");
    EXPECT_EQ(honest.statusCode, 0);
    EXPECT_EQ(honest.payload.stdString(), "hi");
    EXPECT_NE(deliver(groupId, "chat", 0, "carol").statusCode, 0) << "bob's event passed off as carol's";
}

TEST_F(GroupApiLyingBridge, SECURITY_AnEventIsTakenOnlyOnTheChannelItWasSealedFor) {
    // T4-07: the channel name is in the signed payload; the bridge moving an event to another channel is refused.
    const std::string groupId = createGroup({"alice", "bob"});
    client("bob").sendCustomEvent(groupId, "admin", core::Buffer::from("promote me"), {});
    EXPECT_NE(deliver(groupId, "chat", 0, "bob").statusCode, 0);
}

TEST_F(GroupApiLyingBridge, SECURITY_AnEventIsTakenOnlyUnderTheCurrentEpochsKey) {
    // T4-07: a removed member still holds the epoch it was removed from, and seals events with it.
    const std::string groupId = createGroup({"alice", "bob"});
    client("bob").encrypt(groupId, core::Buffer::from("warm")); // bob's client caches the epoch 1 key
    client("alice").removeGroupMembers(groupId, {"bob"});
    client("bob").sendCustomEvent(groupId, "chat", core::Buffer::from("still here"), {});
    EXPECT_NE(deliver(groupId, "chat", 0, "bob").statusCode, 0);
}

TEST_F(GroupApiLyingBridge, SECURITY_AnEventIsNotTakenUnderAKeyCachedBehindThePinnedEpoch) {
    // alice's cached head is from before carol removed bob, which a later read of hers verified (epoch 2); bob still
    // seals under epoch 1. The cache alone must not make that key current.
    const std::string groupId = createGroup({"alice", "bob", "carol"});
    client("alice").encrypt(groupId, core::Buffer::from("warm")); // alice caches epoch 1's head
    client("bob").encrypt(groupId, core::Buffer::from("warm"));   // and so does bob
    client("carol").removeGroupMembers(groupId, {"bob"});
    client("alice").resolveGroupPrivKey(groupId); // pins epoch 2; the cached head stays
    client("bob").sendCustomEvent(groupId, "chat", core::Buffer::from("still here"), {});
    EXPECT_NE(deliver(groupId, "chat", 0, "bob").statusCode, 0);
}

TEST_F(GroupApiLyingBridge, SECURITY_ACallersGrantKeyOtherThanThePinnedOneIsNotWrappedTo) {
    // T4-09: a module granting a container to a group takes the caller's grant key only exactly at the pin.
    const std::string groupId = createGroup({"alice", "bob"});
    Client& alice = *clients.at("alice");
    GrantingModule module(
        alice.connectionImpl->getUserPrivKey(), alice.connectionImpl->getKeyProvider(), "",
        alice.connectionImpl->getEventMiddleware(), alice.connection, alice.groupApi
    );
    std::vector<core::GroupGrantWithKey> grants{{
        .groupId = groupId,
        .role = "manager",
        .groupPubKey = PrivateKey::generateRandom().getPublicKey().toBase58DER(),
        .groupEpoch = 1,
    }};
    std::unordered_map<std::string, core::GroupEpochInfo> cache;
    module.resolveGroupEpochs(CONTEXT, grants, cache);
    EXPECT_EQ(grants.at(0).groupPubKey, bridge.tree.state.grantPublicKey.toBase58DER());
}

TEST_F(GroupApiLyingBridge, SECURITY_ARemovalDoesNotReSignAPlaneTheRemovedMemberTaggedSince) {
    // N-2: bob's entry v2 is what alice reads before removing him; v3, tagged by bob under the epoch 1 key he keeps,
    // is what the bridge serves her refresh. Re-signing it would launder bob's write into the new epoch.
    const std::string groupId = createGroup({"alice", "bob"});
    client("bob").updateGroupPublicMeta(groupId, core::Buffer::from("bob, a member"), 1);
    const server::GroupMetaEntry v2 = bridge.rest.publicMeta;
    client("bob").updateGroupPublicMeta(groupId, core::Buffer::from("bob, after the fact"), 2);
    const server::GroupMetaEntry v3 = bridge.rest.publicMeta;
    bridge.rest.publicMeta = v2;
    bridge.rest.publicMetaVersion = 2;
    bridge.afterRemoval = [&] {
        bridge.rest.publicMeta = v3;
        bridge.rest.publicMetaVersion = 3;
    };
    client("alice").removeGroupMembers(groupId, {"bob"});
    EXPECT_EQ(bridge.rest.publicMeta.author, "bob");
    EXPECT_EQ(bridge.rest.publicMeta.keyVersion, 1) << "alice re-signed bob's late entry under epoch 2";
}

TEST_F(GroupApiLyingBridge, SECURITY_NoSecondStatementIsSignedAtASeqTheBridgeCalledALostRace) {
    // T4-17 wiring: the bridge takes alice's removal at seq 2, calls it a lost race and serves seq 1 again. A retry
    // planned there would sign a second statement at seq 2, a fork of the bridge's choosing.
    const std::string groupId = createGroup({"alice", "bob", "carol"});
    const Bridge atSeq1 = bridge;
    int removals = 0;
    bridge.afterRemoval = [&] {
        ++removals;
        bridge.tree = atSeq1.tree;
        bridge.rest = atSeq1.rest;
        throw privmx::utils::PrivmxException("ROTATED_ALREADY", privmx::utils::PrivmxException::RPC, 0x621C);
    };
    EXPECT_THROW(client("alice").removeGroupMembers(groupId, {"carol"}), GroupDataIntegrityException);
    EXPECT_EQ(removals, 1);
}

TEST_F(GroupApiLyingBridge, SECURITY_ACommitAfterAStatementDatedAheadOfTheClockIsDatedAsIt) {
    // N-1, the client half: the bridge takes a date past its tolerance only when it equals the extended statement's,
    // so alice must sign exactly bob's forward date (chainTo's max), not her own clock and not anything later.
    const std::string groupId = createGroup({"alice", "bob", "carol"});
    const auto ahead = static_cast<std::uint64_t>(privmx::utils::Utils::getNowTimestamp()) + 15 * 60 * 1000;
    selfUpdateBy("bob", ahead);
    client("alice").removeGroupMembers(groupId, {"carol"});
    const CommitStatement removal = TreeCommits::fromWire(bridge.tree.commits.back());
    EXPECT_EQ(removal.seq, 3u);
    EXPECT_EQ(removal.date, ahead);
}

// T3-29. Without the handle's lock these race on one EnvelopeFileState: heap corruption, lost `written` updates,
// duplicate or skipped chunk indices, two envelopes from one handle. A plain build shows it in most runs; under
// ThreadSanitizer every run (configure a separate build dir with -DCMAKE_CXX_FLAGS="-fsanitize=thread -g -O1", as the
// commented-out lines at the top of CMakeLists.txt, and run --gtest_filter='*ConcurrentChunks*:*ConcurrentFinishes*').
TEST_F(GroupApiLyingBridge, SECURITY_ConcurrentChunksOnOneFileHandleSealOneWholeFile) {
    using E = GroupEnvelopeEncryptor;
    const std::string groupId = createGroup({"alice", "bob"});
    GroupApi& api = clients.at("alice")->groupApi;
    constexpr int THREADS = 8;
    constexpr int CALLS = 64;
    const core::Buffer piece = core::Buffer::from(std::string(E::CHUNK_SIZE / CALLS, 'x'));

    // Encrypt: 8 threads x 16 pieces fill exactly 8 chunks, whatever the interleaving.
    const FileHandle writer = api.beginFileEncryption(groupId, THREADS * E::CHUNK_SIZE);
    std::mutex outMutex;
    std::vector<std::string> outputs;
    race(THREADS, [&](int) {
        for (int i = 0; i < CALLS; ++i) {
            std::string sealed = api.encryptFileChunk(writer, piece).stdString();
            if (!sealed.empty()) {
                std::lock_guard lock(outMutex);
                outputs.push_back(std::move(sealed));
            }
        }
    });
    std::vector<std::string> chunks;
    for (const auto& out : outputs) {
        ASSERT_EQ(out.size() % E::ENCRYPTED_CHUNK_SIZE, 0u);
        for (std::size_t at = 0; at < out.size(); at += E::ENCRYPTED_CHUNK_SIZE) {
            chunks.push_back(out.substr(at, E::ENCRYPTED_CHUNK_SIZE));
        }
    }
    ASSERT_EQ(chunks.size(), static_cast<std::size_t>(THREADS));
    const Envelope envelope = api.finishFileEncryption(writer);

    // A chunk opens only at the index it was sealed at, so each one must open at exactly one k, all k distinct.
    std::set<int> indices;
    for (const auto& chunk : chunks) {
        std::vector<int> opensAt;
        for (int k = 0; k < THREADS; ++k) {
            const FileHandle reader = api.beginFileDecryption(envelope);
            api.seekInEncryptedFile(reader, k * E::CHUNK_SIZE);
            try {
                if (api.decryptFileChunk(reader, core::Buffer::from(chunk)).stdString() ==
                    std::string(E::CHUNK_SIZE, 'x')) {
                    opensAt.push_back(k);
                }
            } catch (const core::Exception&) {}
            try {
                api.finishFileDecryption(reader);
            } catch (const core::Exception&) {}
        }
        ASSERT_EQ(opensAt.size(), 1u);
        indices.insert(opensAt.at(0));
    }
    EXPECT_EQ(indices.size(), static_cast<std::size_t>(THREADS));

    // Decrypt: four threads push the chunks of a well-formed file from a shared cursor while a fifth seeks back.
    // Chunk and index can mismatch, so refusals are expected; what must not happen is a crash or a wrong plaintext.
    const FileHandle sealer = api.beginFileEncryption(groupId, THREADS * E::CHUNK_SIZE);
    const std::string whole =
        api.encryptFileChunk(sealer, core::Buffer::from(std::string(THREADS * E::CHUNK_SIZE, 'x'))).stdString();
    const Envelope ordered = api.finishFileEncryption(sealer);
    ASSERT_EQ(whole.size(), THREADS * E::ENCRYPTED_CHUNK_SIZE);
    const FileHandle reader = api.beginFileDecryption(ordered);
    std::atomic<int> cursor{0};
    std::atomic<int> wrong{0};
    race(5, [&](int thread) {
        if (thread == 4) {
            for (int i = 0; i < 4; ++i) {
                api.seekInEncryptedFile(reader, 0);
                std::this_thread::yield();
            }
            return;
        }
        for (int at = cursor++; at < THREADS; at = cursor++) {
            try {
                const core::Buffer chunk =
                    core::Buffer::from(whole.substr(at * E::ENCRYPTED_CHUNK_SIZE, E::ENCRYPTED_CHUNK_SIZE));
                const std::string plain = api.decryptFileChunk(reader, chunk).stdString();
                if (plain.size() > E::CHUNK_SIZE || plain.find_first_not_of('x') != std::string::npos) {
                    wrong++;
                }
            } catch (const core::Exception&) {}
        }
    });
    EXPECT_EQ(wrong.load(), 0);
    try {
        api.finishFileDecryption(reader);
    } catch (const core::Exception&) {}
}

TEST_F(GroupApiLyingBridge, SECURITY_ConcurrentFinishesCloseAFileHandleOnce) {
    // T3-29: the first finish closes the handle under its lock; the other is refused, never a second envelope.
    const std::string groupId = createGroup({"alice", "bob"});
    GroupApi& api = clients.at("alice")->groupApi;
    for (int iteration = 0; iteration < 2000; ++iteration) {
        const FileHandle handle = api.beginFileEncryption(groupId, 16);
        api.encryptFileChunk(handle, core::Buffer::from(std::string(16, 'x')));
        std::atomic<int> envelopes{0};
        std::atomic<int> refused{0};
        race(2, [&](int) {
            try {
                api.finishFileEncryption(handle);
                envelopes++;
            } catch (const core::InvalidParamsException&) {
                refused++;
            }
        });
        ASSERT_EQ(envelopes.load(), 1) << "iteration " << iteration;
        ASSERT_EQ(refused.load(), 1) << "iteration " << iteration;
    }
}

TEST_F(GroupApiLyingBridge, AOneMemberGroupRotatesOntoItsMembersOwnKeyAndReadsBack) {
    // T3-27: the one-leaf root is alice's own leaf, so the new grant key is wrapped to her own key; her metadata is
    // carried up to the new epoch, and a fresh client of hers, with nothing cached, reads the group.
    const std::string groupId = createGroup({"alice"});
    const std::string before = bridge.tree.state.grantPublicKey.toBase58DER();
    client("alice").rotateGroupKey(groupId);
    ASSERT_EQ(bridge.tree.state.epoch, 2u);
    EXPECT_NE(bridge.tree.state.grantPublicKey.toBase58DER(), before);
    ASSERT_EQ(bridge.tree.state.edges.size(), 1u);
    EXPECT_EQ(edgeIdentity(bridge.tree.state.edges[0]), "grant@2>user:alice");
    EXPECT_EQ(bridge.rest.privateMeta.keyVersion, 2) << "the metadata stayed under the replaced key";
    clients.erase("alice");
    const Group group = client("alice").getGroup(groupId);
    EXPECT_EQ(group.statusCode, 0);
    EXPECT_EQ(group.keyVersion, 2);
    EXPECT_EQ(group.privateMeta.stdString(), "private");
}

TEST_F(GroupApiLyingBridge, ARotationOfALargerGroupIsReadByEveryMember) {
    const std::string groupId = createGroup({"alice", "bob", "carol"});
    client("alice").rotateGroupKey(groupId);
    ASSERT_EQ(bridge.tree.state.epoch, 2u);
    for (const std::string id : {"bob", "carol"}) {
        const Group group = client(id).getGroup(groupId);
        EXPECT_EQ(group.statusCode, 0) << id;
        EXPECT_EQ(group.keyVersion, 2) << id;
    }
}

TEST_F(GroupApiLyingBridge, SECURITY_ARotationIsNotPlannedOnAStateRolledBackBelowThePin) {
    // The new grant key goes to the root the bridge serves: planned only on a state verified against the pin, or a
    // rolled-back root (a key a since-removed member may hold) would receive it.
    const std::string groupId = createGroup({"alice", "bob"});
    const Bridge atSeq1 = bridge;
    selfUpdateBy("bob");
    client("alice").resolveGroupPrivKey(groupId); // reads seq 2, pins it
    bridge.tree = atSeq1.tree;
    EXPECT_THROW(client("alice").rotateGroupKey(groupId), GroupHistoryForkException);
    EXPECT_EQ(bridge.tree.commits.size(), 1u) << "nothing was committed";
}

TEST_F(GroupApiLyingBridge, ARotationOvertakenByASelfUpdateIsPlannedAgain) {
    // bob's self-update re-keys the root between alice's read and her submit; keyVersion and rosterVersion stay, so
    // only the grant edge's child generation is stale. That is a lost race like any other: re-read, re-plan, commit.
    const std::string groupId = createGroup({"alice", "bob", "carol"});
    int rotations = 0;
    bridge.beforeRotation = [&] {
        if (++rotations == 1) {
            selfUpdateBy("bob");
        }
    };
    client("alice").rotateGroupKey(groupId);
    EXPECT_EQ(rotations, 2);
    ASSERT_EQ(bridge.tree.state.epoch, 2u);
    for (const std::string id : {"bob", "carol"}) {
        const Group group = client(id).getGroup(groupId);
        EXPECT_EQ(group.statusCode, 0) << id;
        EXPECT_EQ(group.keyVersion, 2) << id;
    }
}

// m2 (A5-F3): the client releases at most one statement per prevDigest while the first could still be applied. Each
// test turns the deferred self-updates off (`quiet`), so `received` holds only what the test's own calls sent.

TEST_F(GroupApiLyingBridge, SECURITY_AnErrorThatIsNotALostRaceMakesTheRetryResendTheSameStatement) {
    // The bridge takes the removal, then answers ACCESS_DENIED and serves seq 1 again. A retry planned there would be
    // a second statement at seq 2: a fork the bridge chose, with no concurrency needed.
    quiet = true;
    const std::string groupId = createGroup({"alice", "bob", "carol"});
    const Bridge atSeq1 = bridge;
    int removals = 0;
    bridge.afterRemoval = [&] {
        if (removals++ == 0) {
            rollBackTo(atSeq1);
            refuse();
        }
    };
    EXPECT_ANY_THROW(client("alice").removeGroupMembers(groupId, {"carol"}));
    EXPECT_NO_THROW(client("alice").removeGroupMembers(groupId, {"carol"}));
    ASSERT_EQ(bridge.received.size(), 2u);
    EXPECT_EQ(bridge.received[1].serialize(), bridge.received[0].serialize()) << "the retry signed a new statement at seq 2";
}

TEST_F(GroupApiLyingBridge, SECURITY_ADroppedAnswerIsNotSignedAgain) {
    // The removal is applied and the answer lost; the retry finds its own statement at the head and sends nothing.
    quiet = true;
    const std::string groupId = createGroup({"alice", "bob", "carol"});
    int removals = 0;
    bridge.afterRemoval = [&] {
        if (removals++ == 0) {
            throw std::runtime_error("connection dropped");
        }
    };
    EXPECT_ANY_THROW(client("alice").removeGroupMembers(groupId, {"carol"}));
    EXPECT_NO_THROW(client("alice").removeGroupMembers(groupId, {"carol"}));
    EXPECT_EQ(bridge.received.size(), 1u);
}

TEST_F(GroupApiLyingBridge, SECURITY_ADifferentCommitCompletesTheUnresolvedOneFirst) {
    quiet = true;
    const std::string groupId = createGroup({"alice", "bob", "carol"});
    const Bridge atSeq1 = bridge;
    int removals = 0;
    bridge.afterRemoval = [&] {
        if (removals++ == 0) {
            rollBackTo(atSeq1);
            refuse();
        }
    };
    EXPECT_ANY_THROW(client("alice").removeGroupMembers(groupId, {"carol"}));
    EXPECT_NO_THROW(client("alice").removeGroupMembers(groupId, {"bob"}));
    ASSERT_EQ(bridge.received.size(), 3u);
    EXPECT_EQ(bridge.received[1].serialize(), bridge.received[0].serialize()) << "carol's removal resent first";
    EXPECT_EQ(prevOf(bridge.received[2]), digestOf(bridge.received[0])) << "bob's removal extends it";
}

TEST_F(GroupApiLyingBridge, ADifferentCommitResendsTheUnresolvedOneOnceThenPlansAfresh) {
    // 13 (D2 removed): carol's removal has no known outcome and the bridge keeps refusing it. bob's removal resends it
    // once, byte for byte, then drops it and plans its own statement at the same head. Two statements at one prevDigest
    // are then possible: the fork boundary (a bridge able to do this can as well withhold the removal).
    quiet = true;
    const std::string groupId = createGroup({"alice", "bob", "carol"});
    const Bridge atSeq1 = bridge;
    const std::string atP = digestOf(bridge.tree.commits.back());
    bridge.afterRemoval = [&] {
        rollBackTo(atSeq1);
        refuse();
    };
    EXPECT_ANY_THROW(client("alice").removeGroupMembers(groupId, {"carol"}));
    EXPECT_ANY_THROW(client("alice").removeGroupMembers(groupId, {"bob"}));
    ASSERT_EQ(bridge.received.size(), 3u);
    EXPECT_EQ(bridge.received[1].serialize(), bridge.received[0].serialize()) << "carol's removal resent first";
    EXPECT_EQ(prevOf(bridge.received[2]), atP) << "bob's removal planned at the same head";
    EXPECT_NE(bridge.received[2].serialize(), bridge.received[0].serialize());
}

namespace {
// Each distinct statement the bridge received at its own prevDigest (a resend is the same statement).
bool noTwoStatementsShareAPrevDigest(const std::vector<server::GroupTreeCommit>& received) {
    std::map<std::string, std::string> prevByDigest;
    for (const server::GroupTreeCommit& commit : received) {
        prevByDigest[digestOf(commit)] = prevOf(commit);
    }
    std::set<std::string> prevs;
    for (const auto& [digest, prev] : prevByDigest) {
        prevs.insert(prev);
    }
    return prevs.size() == prevByDigest.size();
}
} // namespace

// Two threads of alice's client, removing bob and carol. Whichever reaches the bridge first waits there until the
// other has read the head it was planned on, then `firstArrives` runs (it may throw to refuse). Returns the failures.
int GroupApiLyingBridge::removeTwoOnOneHead(const std::string& groupId, const std::function<void()>& firstArrives) {
    GroupApiImpl& alice = client("alice");
    const int readsBefore = bridge.planReads;
    bool waited = false;
    bool bothRead = false;
    bridge.beforeRemoval = [&](std::unique_lock<std::mutex>& lock) {
        if (std::exchange(waited, true)) {
            return;
        }
        // Bounded only so that a regression fails rather than hangs: the other thread's read takes no lock of ours.
        bothRead = bridge.sync->cv.wait_for(lock, std::chrono::seconds(30), [&] {
            return bridge.planReads >= readsBefore + 2;
        });
        firstArrives();
    };
    std::atomic<int> failures{0};
    std::thread other([&] {
        try {
            alice.removeGroupMembers(groupId, {"bob"});
        } catch (...) { ++failures; }
    });
    try {
        alice.removeGroupMembers(groupId, {"carol"});
    } catch (...) { ++failures; }
    other.join();
    EXPECT_TRUE(bothRead) << "the second removal did not read the head the first was planned on";
    return failures.load();
}

TEST_F(GroupApiLyingBridge, SECURITY_TwoCommitsOfOneClientToOneGroupNeverShareAPrevDigest) {
    // The first removal lands; the second, planned on the same head, must not be released at it.
    quiet = true;
    addUsers({"dave"});
    const std::string groupId = createGroup({"alice", "bob", "carol", "dave"});
    EXPECT_EQ(removeTwoOnOneHead(groupId, [] {}), 0);
    EXPECT_TRUE(noTwoStatementsShareAPrevDigest(bridge.received));
}

TEST_F(GroupApiLyingBridge, SECURITY_ACommitPlannedBeforeAnotherWasLeftUnresolvedIsNotReleasedAtItsSeq) {
    // M3: the first removal is refused with no known outcome (it stays unresolved and may still land at seq 2). The
    // second was planned on the same head before that: released as planned it would be a second statement at seq 2.
    // It re-plans instead, resending the unresolved one first and extending it.
    quiet = true;
    addUsers({"dave"});
    const std::string groupId = createGroup({"alice", "bob", "carol", "dave"});
    EXPECT_EQ(removeTwoOnOneHead(groupId, [] { refuse(); }), 1);
    EXPECT_TRUE(noTwoStatementsShareAPrevDigest(bridge.received));
    EXPECT_EQ(bridge.tree.state.epoch, 3u) << "both removals landed, one after the other";
}

TEST_F(GroupApiLyingBridge, SECURITY_AnUnverifiedHeadShowingTheUnresolvedRemovalIsNotTakenAsItsLanding) {
    // The bridge keeps alice's removal of carol unapplied and refuses it. carol moves the chain on with two
    // self-updates, which alice's client verifies, so her pin passes the removal's seq on a branch without it. Then
    // the retry's plan read serves the removal's own statement as the head of a group that fails verification (no
    // tree version). Nothing there is verified: the removal must not be reported done, with carol still a member on
    // alice's own pinned chain and the removal's never-published grant key kept for the epoch.
    quiet = true;
    const std::string groupId = createGroup({"alice", "bob", "carol"});
    const Bridge atP = bridge;
    int removals = 0;
    bridge.afterRemoval = [&] {
        if (removals++ == 0) {
            rollBackTo(atP);
            refuse();
        }
    };
    EXPECT_ANY_THROW(client("alice").removeGroupMembers(groupId, {"carol"}));
    ASSERT_EQ(bridge.received.size(), 1u);
    selfUpdateBy("carol");
    selfUpdateBy("carol");
    client("alice").getGroup(groupId); // verifies P -> S_x -> S_y: the pin is past the removal's seq
    bridge.onPlanRead = [&](server::GroupInfo& info) {
        info.treeCommit = bridge.received[0];
        info.treeVersion = std::nullopt;
    };
    EXPECT_ANY_THROW(client("alice").removeGroupMembers(groupId, {"carol"}))
        << "a removal reported done on a head nothing verified";
    bridge.onPlanRead = [](server::GroupInfo&) {};
    const Group group = client("alice").getGroup(groupId);
    EXPECT_EQ(group.keyVersion, 1);
    EXPECT_NE(std::find(group.users.begin(), group.users.end(), "carol"), group.users.end());
}

TEST_F(GroupApiLyingBridge, SECURITY_ARotationCompletesAnUnresolvedRemovalFirst) {
    // The bridge takes the removal, then answers ACCESS_DENIED and serves the state before it. A rotation planned there
    // would be a second statement at the removal's prevDigest: the fork A5-F3 is about, through rotateGroupKey.
    quiet = true;
    const std::string groupId = createGroup({"alice", "bob", "carol"});
    const Bridge atP = bridge;
    int removals = 0;
    bridge.afterRemoval = [&] {
        if (removals++ == 0) {
            rollBackTo(atP);
            refuse();
        }
    };
    EXPECT_ANY_THROW(client("alice").removeGroupMembers(groupId, {"carol"}));
    EXPECT_NO_THROW(client("alice").rotateGroupKey(groupId));
    ASSERT_EQ(bridge.received.size(), 3u);
    EXPECT_EQ(bridge.received[1].serialize(), bridge.received[0].serialize()) << "carol's removal resent first";
    EXPECT_EQ(TreeCommits::fromWire(bridge.received[2]).op, CommitOp::Rotate);
    EXPECT_EQ(prevOf(bridge.received[2]), digestOf(bridge.received[0])) << "the rotation extends the removal";
    EXPECT_EQ(bridge.tree.state.epoch, 3u);
}

TEST_F(GroupApiLyingBridge, SECURITY_ARetriedRotationResendsTheSameStatement) {
    quiet = true;
    const std::string groupId = createGroup({"alice", "bob", "carol"});
    bridge.beforeRotation = [] { refuse(); };
    EXPECT_ANY_THROW(client("alice").rotateGroupKey(groupId));
    bridge.beforeRotation = [] {};
    EXPECT_NO_THROW(client("alice").rotateGroupKey(groupId));
    ASSERT_EQ(bridge.received.size(), 2u);
    EXPECT_EQ(bridge.received[1].serialize(), bridge.received[0].serialize()) << "the retry signed a new rotation";
    EXPECT_EQ(bridge.tree.state.epoch, 2u);
    EXPECT_EQ(bridge.rest.privateMeta.keyVersion, 2) << "the metadata stayed under the replaced key";
}

TEST_F(GroupApiLyingBridge, ARotationWhoseAnswerWasLostIsFoundLandedAndItsMetadataCarriedUp) {
    // Applied, answer lost: the retry finds its own statement pinned, sends nothing, and the metadata refresh the
    // first call never reached runs then.
    quiet = true;
    const std::string groupId = createGroup({"alice", "bob", "carol"});
    int rotations = 0;
    bridge.afterRotation = [&] {
        if (rotations++ == 0) {
            throw std::runtime_error("connection dropped");
        }
    };
    EXPECT_ANY_THROW(client("alice").rotateGroupKey(groupId));
    EXPECT_EQ(bridge.rest.privateMeta.keyVersion, 1);
    EXPECT_NO_THROW(client("alice").rotateGroupKey(groupId));
    EXPECT_EQ(bridge.received.size(), 1u);
    EXPECT_EQ(bridge.tree.state.epoch, 2u);
    EXPECT_EQ(bridge.rest.privateMeta.keyVersion, 2) << "the metadata stayed under the replaced key";
}

TEST_F(GroupApiLyingBridge, ARemovalWhoseAnswerWasLostAndThatWasBuiltUponIsFoundLanded) {
    // Applied, answer lost, then bob's self-update extends it and alice's read pins past it. The retry is not an
    // error ("not a member"): the removal is on the verified chain, so it is done and its metadata carried up.
    quiet = true;
    const std::string groupId = createGroup({"alice", "bob", "carol"});
    int removals = 0;
    bridge.afterRemoval = [&] {
        if (removals++ == 0) {
            throw std::runtime_error("connection dropped");
        }
    };
    EXPECT_ANY_THROW(client("alice").removeGroupMembers(groupId, {"carol"}));
    selfUpdateBy("bob");
    client("alice").getGroup(groupId); // pins seq 3, past the removal
    EXPECT_NO_THROW(client("alice").removeGroupMembers(groupId, {"carol"}));
    EXPECT_EQ(bridge.received.size(), 1u);
    EXPECT_EQ(bridge.rest.privateMeta.keyVersion, 2) << "the metadata stayed under the key carol holds";
}

TEST_F(GroupApiLyingBridge, SECURITY_ALandedRotationWhoseAnswerWasLostStandsInForALaterCallOnlyInsideTheWindow) {
    // Applied, answer lost, pinned by a read, and nobody commits after it. Past the window a call is a new request
    // (the key it replaced may have leaked since): it rotates again instead of returning on the old rotation.
    quiet = true;
    const std::string groupId = createGroup({"alice", "bob", "carol"});
    int rotations = 0;
    bridge.afterRotation = [&] {
        if (rotations++ == 0) {
            throw std::runtime_error("connection dropped");
        }
    };
    EXPECT_ANY_THROW(client("alice").rotateGroupKey(groupId));
    client("alice").getGroup(groupId); // pins the rotation at epoch 2
    GroupApiImplTestAccess::ageUnresolved(client("alice"), groupId, GroupApiImplTestAccess::RELEASE_WINDOW_MS);
    EXPECT_NO_THROW(client("alice").rotateGroupKey(groupId));
    EXPECT_EQ(bridge.received.size(), 2u) << "returned on the old rotation without sending one";
    EXPECT_EQ(bridge.tree.state.epoch, 3u);
    EXPECT_EQ(bridge.rest.privateMeta.keyVersion, 3);
}

namespace {
// 49 members: above the 16-seat buckets the tree keys the root and, over seats 32-48, a child of it the creator (seat
// 0) does not sit under but set. Whoever sits there has a real self-update need from the start.
std::vector<std::string> crowd() {
    std::vector<std::string> members = {"alice", "bob", "carol"};
    for (int i = 0; members.size() < 49; ++i) {
        members.push_back("member" + std::to_string(i));
    }
    return members;
}
const std::vector<std::string> CROWD = crowd();
} // namespace

TEST_F(GroupApiLyingBridge, SECURITY_ASelfUpdateNeverCompletesAnotherOpsUnresolvedCommit) {
    quiet = true;
    addUsers({CROWD.begin() + 3, CROWD.end()});
    const std::string groupId = createGroup(CROWD);
    const std::string member = memberNeedingSelfUpdate(CROWD);
    ASSERT_FALSE(member.empty()) << "no member with a self-update need";
    std::vector<std::string> others;
    for (const std::string& id : CROWD) {
        if (id != "alice" && id != member) {
            others.push_back(id);
        }
    }
    const Bridge atP = bridge;
    int removals = 0;
    bridge.afterRemoval = [&] {
        if (removals++ == 0) {
            rollBackTo(atP);
            refuse();
        }
    };
    EXPECT_ANY_THROW(client(member).removeGroupMembers(groupId, {others.at(0)}));
    ASSERT_EQ(bridge.received.size(), 1u);
    ASSERT_TRUE(GroupKeyResolver::nodeNeedingSelfUpdate(bridge.serve(member, false)).has_value());
    EXPECT_NO_THROW(GroupApiImplTestAccess::selfUpdate(client(member), groupId));
    EXPECT_EQ(bridge.received.size(), 1u) << "a self-update released at the removal's prevDigest";
    EXPECT_NO_THROW(client(member).removeGroupMembers(groupId, {others.at(1)}));
    ASSERT_EQ(bridge.received.size(), 3u);
    EXPECT_EQ(bridge.received[1].serialize(), bridge.received[0].serialize()) << "the unresolved removal is resent first";
    EXPECT_EQ(prevOf(bridge.received[2]), digestOf(bridge.received[0]));
}

TEST_F(GroupApiLyingBridge, SECURITY_ASecondSelfUpdateIsNeverReleasedAtOnePrevDigest) {
    quiet = true;
    addUsers({CROWD.begin() + 3, CROWD.end()});
    const std::string groupId = createGroup(CROWD);
    const std::string member = memberNeedingSelfUpdate(CROWD);
    ASSERT_FALSE(member.empty()) << "no member with a self-update need";
    bridge.onSelfUpdate = [] { refuse(); };
    EXPECT_ANY_THROW(GroupApiImplTestAccess::selfUpdate(client(member), groupId));
    ASSERT_EQ(bridge.received.size(), 1u);
    // An app op that passes `settle` (the self-update yields to it) and fails before it releases anything: eve's key
    // is not the one the UserVerifier vouches for.
    EXPECT_ANY_THROW(client(member).addGroupMembers(
        groupId,
        {GroupMemberToAdd{
            .user = {.userId = "eve", .pubKey = PrivateKey::generateRandom().getPublicKey().toBase58DER()},
            .role = "user"
        }}
    ));
    EXPECT_ANY_THROW(GroupApiImplTestAccess::selfUpdate(client(member), groupId));
    ASSERT_EQ(bridge.received.size(), 2u);
    EXPECT_EQ(bridge.received[1].serialize(), bridge.received[0].serialize()) << "a second self-update at one prevDigest";
}

TEST_F(GroupApiLyingBridge, SECURITY_ARefusedSelfUpdateNeverHoldsBackARemoval) {
    // T4-06 guard: a member draining the shared self-update budget must not hold back the remover's removal.
    quiet = true;
    addUsers({CROWD.begin() + 3, CROWD.end()});
    const std::string groupId = createGroup(CROWD);
    const std::string member = memberNeedingSelfUpdate(CROWD);
    ASSERT_FALSE(member.empty()) << "no member with a self-update need";
    const std::string atP = digestOf(bridge.tree.commits.back());
    bridge.onSelfUpdate = [] { refuse("GROUP_ROTATION_RATE_LIMIT", 0x621D); };
    EXPECT_ANY_THROW(GroupApiImplTestAccess::selfUpdate(client(member), groupId));
    const std::string leaver = member == "carol" ? "bob" : "carol";
    EXPECT_NO_THROW(client(member).removeGroupMembers(groupId, {leaver}));
    ASSERT_EQ(bridge.received.size(), 2u) << "the refused self-update was resent";
    EXPECT_EQ(TreeCommits::fromWire(bridge.received[1]).op, CommitOp::Remove);
    EXPECT_EQ(prevOf(bridge.received[1]), atP);
}

TEST_F(GroupApiLyingBridge, SECURITY_AnAddIsResentOnlyToKeysTheVerifierStillVouchesFor) {
    quiet = true;
    addUsers({"dave"});
    const std::string groupId = createGroup({"alice", "bob", "carol"});
    bridge.onAdd = [] { refuse(); };
    EXPECT_ANY_THROW(
        client("alice").addGroupMembers(groupId, {GroupMemberToAdd{.user = user("dave"), .role = "user"}})
    );
    bridge.onAdd = [] {};
    bridge.users["dave"] = PrivateKey::generateRandom(); // dave's key changed: the add's key is no longer vouched for
    EXPECT_NO_THROW(client("alice").removeGroupMembers(groupId, {"carol"})) << "the add is dropped, not resent";
    const auto adds = std::count_if(bridge.received.begin(), bridge.received.end(), [](const auto& commit) {
        return TreeCommits::fromWire(commit).op == CommitOp::Add;
    });
    EXPECT_EQ(adds, 1) << "the add was resent to a key the verifier no longer vouches for";
}

// ── repair rungs (L-1) ───────────────────────────────────────────────────────────────────────────────────────────

TEST_F(GroupApiLyingBridge, SECURITY_AMemberHoldingThePreviousKeyRepairsABrokenUnitRung) {
    // A broken unit rung (2,1) cuts epoch 1 off for everybody not holding it in session memory. Bob holds it, and
    // repairs the rung at his next call on the group once he has seen the rotation; a fresh session of carol's then
    // reads epoch 1.
    const std::string groupId = groupAtEpoch2WithBobHoldingEpoch1();
    corrupt(2, 1);
    client("bob").resolveGroupPrivKey(groupId);
    EXPECT_EQ(count("bob", "context.groupRepairRung"), 0u) << "a key lookup only records the check";
    GroupApiImplTestAccess::runDueWorkNow(client("bob"), groupId);
    ASSERT_EQ(count("bob", "context.groupRepairRung"), 1u);
    const PrivateKey epoch1 = client("carol").resolveGroupPrivKey(groupId, 1);
    EXPECT_EQ(epoch1.getPublicKey().toBase58DER(), bridge.rest.history.at(0).groupPubKey);
}

TEST_F(GroupApiLyingBridge, ARepairIsNotSentWhenTheLadderIsIntact) {
    // The honest path costs one archive fetch per observed rotation: no statements read, no UserVerifier call.
    const std::string groupId = groupAtEpoch2WithBobHoldingEpoch1();
    client("bob").resolveGroupPrivKey(groupId);
    const int verified = bridge.verifierCalls->load();
    const std::size_t commitReads = count("bob", "context.groupGetTreeCommits");
    GroupApiImplTestAccess::runDueWorkNow(client("bob"), groupId);
    EXPECT_EQ(GroupApiImplTestAccess::queuedLadderChecks(client("bob")), 0u);
    EXPECT_EQ(count("bob", "context.groupGetKeyArchive"), 1u);
    EXPECT_EQ(count("bob", "context.groupRepairRung"), 0u);
    EXPECT_EQ(count("bob", "context.groupGetTreeCommits"), commitReads);
    EXPECT_EQ(bridge.verifierCalls->load(), verified);
}

// A commit opening an epoch and the bridge call that submits it.
struct EpochCommit {
    std::string name;
    std::string method;
    std::function<void(GroupApiImpl&, const std::string& groupId, const std::string& member)> commit;
};

class GroupApiLyingBridgeEpochCommit : public GroupApiLyingBridge, public testing::WithParamInterface<EpochCommit> {};

TEST_P(GroupApiLyingBridgeEpochCommit, SECURITY_AClientRefusesToCommitARungThatDoesNotOpenToTheChain) {
    // A wrong key in the committer's cache (a client bug) would be sealed into a skip rung no later commit can replace.
    // A removal and a rotation seal skip rungs alike, so both go through the same self-check.
    const EpochCommit& op = GetParam();
    addUsers({"dave", "erin"});
    const std::string groupId = createGroup({"alice", "bob", "carol", "dave", "erin"});
    op.commit(client("alice"), groupId, "dave");
    op.commit(client("alice"), groupId, "erin");
    ASSERT_EQ(LadderKeys::requiredSkipTargets(4, 1), std::vector<std::uint32_t>{2});
    const auto cache = GroupApiImplTestAccess::keyCacheOf(client("alice"), groupId);
    ASSERT_TRUE(cache->getGrantKey(2).has_value());
    cache->putGrantKey(2, PrivateKey::generateRandom());
    const std::size_t sent = count("alice", op.method);
    EXPECT_THROW(op.commit(client("alice"), groupId, "carol"), GroupDataIntegrityException);
    EXPECT_EQ(count("alice", op.method), sent) << "nothing submitted";
    EXPECT_FALSE(cache->getGrantKey(2).has_value()) << "forgotten, to be re-gathered by a verified descent";
    op.commit(client("alice"), groupId, "carol");
    EXPECT_EQ(bridge.tree.state.epoch, 4u);
}

INSTANTIATE_TEST_SUITE_P(
    ,
    GroupApiLyingBridgeEpochCommit,
    testing::Values(
        EpochCommit{
            "Removal", "context.groupRemoveMembers",
            [](GroupApiImpl& api, const std::string& groupId, const std::string& member) {
                api.removeGroupMembers(groupId, {member});
            }
        },
        EpochCommit{
            "Rotation", "context.groupGenerateNewKey",
            [](GroupApiImpl& api, const std::string& groupId, const std::string&) { api.rotateGroupKey(groupId); }
        }
    ),
    [](const testing::TestParamInfo<EpochCommit>& info) { return info.param.name; }
);

TEST_F(GroupApiLyingBridge, SECURITY_ARepairNeverSealsAKeyTheChainDoesNotName) {
    bridge.users.emplace("dave", PrivateKey::generateRandom());
    const std::string groupId = createGroup({"alice", "bob", "carol", "dave"});
    client("bob").resolveGroupPrivKey(groupId);
    const auto cache = GroupApiImplTestAccess::keyCacheOf(client("bob"), groupId);
    cache->putGrantKey(1, PrivateKey::generateRandom()); // a client bug: not epoch 1's key
    client("alice").removeGroupMembers(groupId, {"dave"});
    corrupt(2, 1);
    client("bob").resolveGroupPrivKey(groupId);
    GroupApiImplTestAccess::runDueWorkNow(client("bob"), groupId);
    ASSERT_FALSE(cache->getGrantKey(1).has_value()) << "checked against the chain, forgotten";
    EXPECT_EQ(count("bob", "context.groupRepairRung"), 0u);
}

TEST_F(GroupApiLyingBridge, SECURITY_ARepairIsNotSentBelowAFloorThisSessionHasSeen) {
    // The floor is the bridge's word (T3-30). Lowering it after bob saw it must not make him seal a crossing rung.
    bridge.users.emplace("dave", PrivateKey::generateRandom());
    const std::string groupId = createGroup({"alice", "bob", "carol", "dave"});
    client("alice").removeGroupMembers(groupId, {"dave"});
    {
        std::unique_lock<std::mutex> guard(bridge.sync->m);
        bridge.eraFloor = 2;
    }
    EXPECT_ANY_THROW(client("bob").resolveGroupPrivKey(groupId, 1)) << "behind the era floor bob now remembers";
    {
        std::unique_lock<std::mutex> guard(bridge.sync->m);
        bridge.eraFloor = 1;
    }
    corrupt(2, 1);
    const PrivateKey epoch1 = GroupApiImplTestAccess::keyCacheOf(client("alice"), groupId)->getGrantKey(1).value();
    GroupApiImplTestAccess::keyCacheOf(client("bob"), groupId)->putGrantKey(1, epoch1);
    EXPECT_ANY_THROW(client("bob").resolveGroupPrivKey(groupId, 1)); // finds (2,1) broken, records a check
    GroupApiImplTestAccess::runDueWorkNow(client("bob"), groupId);
    ASSERT_GE(count("bob", "context.groupGetKeyArchive"), 3u) << "the check ran";
    EXPECT_EQ(count("bob", "context.groupRepairRung"), 0u);
}

TEST_F(GroupApiLyingBridge, ARotatorDoesNotCheckTheLadderOfItsOwnEpoch) {
    // Its rungs passed the self-check before submitting, as a remover's do: nothing for the observed-rotation check.
    const std::string groupId = createGroup({"alice", "bob", "carol"});
    client("alice").resolveGroupPrivKey(groupId);
    client("alice").rotateGroupKey(groupId);
    client("alice").resolveGroupPrivKey(groupId);
    EXPECT_EQ(GroupApiImplTestAccess::queuedLadderChecks(client("alice")), 0u);
    EXPECT_EQ(count("alice", "context.groupGetKeyArchive"), 0u);
}

// ── the signed group policy (T4-10) ──────────────────────────────────────────────────────────────────────────

TEST_F(GroupApiLyingBridge, SECURITY_ARemovalTheBridgeTookFromAMemberWithoutTheRoleIsRefused) {
    // Default policy: only managers update. bob, a plain user, colludes with the bridge and signs carol's removal;
    // an honest client would refuse to sign it, so the fixture signs it for him.
    const std::string groupId = createGroup({"alice", "bob", "carol"}, std::nullopt);
    client("alice").getGroup(groupId); // pinned
    removalBy("bob", {"carol"});
    EXPECT_THROW(client("alice").getGroup(groupId), GroupUnauthorizedSignerException);
    EXPECT_THROW(client("alice").updateGroupPublicMeta(groupId, core::Buffer::from("x"), 1), GroupUnauthorizedSignerException)
        << "readGroupForKeys";
}

TEST_F(GroupApiLyingBridge, APolicyChangeLosingTheRaceToAnAdditionIsPlannedAgain) {
    // AC 3: the bridge lands bob's addition under alice's first policy commit and answers the roster CAS.
    addUsers({"dave"});
    const std::string groupId = createGroup({"alice", "bob", "carol"});
    client("bob");
    bool first = true;
    bridge.onPolicy = [&](std::unique_lock<std::mutex>& lock) {
        if (!std::exchange(first, false)) {
            return;
        }
        lock.unlock();
        client("bob").addGroupMembers(groupId, {GroupMemberToAdd{.user = user("dave"), .role = "user"}});
        lock.lock();
        throw privmx::utils::PrivmxException("GROUP_ROSTER_VERSION_MISMATCH", privmx::utils::PrivmxException::RPC, 0x6224);
    };
    client("alice").updateGroupPolicy(groupId, policyWith({{"update", "manager"}}));
    const CommitStatement landed = TreeCommits::fromWire(bridge.tree.commits.back());
    EXPECT_EQ(landed.op, CommitOp::Policy);
    EXPECT_EQ(landed.seq, 3u) << "planned again on top of the addition";
    EXPECT_EQ(landed.rosterHash, TreeCommits::fromWire(bridge.tree.commits.at(1)).rosterHash);
    EXPECT_NO_THROW(client("carol").getGroup(groupId)) << "the chain verifies on another client";
}

TEST_F(GroupApiLyingBridge, APolicyChangeLosingTheRaceToASelfUpdateIsPlannedAgain) {
    // The shared lost-race check answers ROTATED_ALREADY for a statement not extending the stored latest.
    const std::string groupId = createGroup({"alice", "bob", "carol"});
    bool first = true;
    bridge.onPolicy = [&](std::unique_lock<std::mutex>&) {
        if (std::exchange(first, false)) {
            selfUpdateBy("bob");
        }
    };
    client("alice").updateGroupPolicy(groupId, policyWith({{"update", "manager"}}));
    EXPECT_EQ(TreeCommits::fromWire(bridge.tree.commits.back()).op, CommitOp::Policy);
    EXPECT_EQ(bridge.tree.commits.size(), 3u);
    EXPECT_EQ(bridge.received.size(), 2u) << "one lost race, one landed";
}

TEST_F(GroupApiLyingBridge, AnAdditionLosingTheRaceToAPolicyChangeIsPlannedAgain) {
    // The bridge lands bob's policy commit under alice's addition; the retry signs the new policyHash.
    addUsers({"dave"});
    const std::string groupId = createGroup({"alice", "bob", "carol"});
    const Poco::Dynamic::Var narrowed = policyOf({{"update", "manager"}, {"updatePolicy", "user"}});
    bool first = true;
    bridge.onAdd = [&] {
        if (std::exchange(first, false)) {
            policyBy("bob", narrowed);
        }
    };
    client("alice").addGroupMembers(groupId, {GroupMemberToAdd{.user = user("dave"), .role = "user"}});
    const CommitStatement landed = TreeCommits::fromWire(bridge.tree.commits.back());
    EXPECT_EQ(landed.op, CommitOp::Add);
    EXPECT_EQ(landed.seq, 3u);
    EXPECT_EQ(landed.policyHash, TreeCommits::rules(narrowed, "alice").hash) << "the new policy copied";
    EXPECT_NO_THROW(client("carol").getGroup(groupId));
}

TEST_F(GroupApiLyingBridge, SECURITY_TheServedPolicyIsTheOneTheChainSigned) {
    // The bridge widens the served policy without a statement: neither a pinned nor a fresh client takes it.
    const std::string groupId = createGroup({"alice", "bob", "carol"}, std::nullopt);
    client("alice").getGroup(groupId);
    bridge.tree.policy = policyOf({{"update", "all"}, {"rotateKeys", "all"}, {"updatePolicy", "all"}});
    EXPECT_THROW(client("alice").getGroup(groupId), GroupDataIntegrityException);
    EXPECT_THROW(client("carol").getGroup(groupId), GroupDataIntegrityException);
}

TEST_F(GroupApiLyingBridge, ANonMemberCannotChangeAGroupsPolicy) {
    addUsers({"dave"});
    const std::string groupId = createGroup({"alice", "bob"});
    EXPECT_THROW(client("dave").updateGroupPolicy(groupId, OPEN), core::InvalidParamsException);
    EXPECT_EQ(count("dave", "context.groupUpdatePolicy"), 0u);
}

TEST_F(GroupApiLyingBridge, SECURITY_AMemberWithoutTheRoleSignsNothing) {
    // A mistaken app call by an honest member gives a malicious bridge nothing genuinely signed to land.
    addUsers({"dave"});
    const std::string groupId = createGroup({"alice", "bob", "carol"}, std::nullopt);
    EXPECT_THROW(client("bob").removeGroupMembers(groupId, {"carol"}), GroupUnauthorizedSignerException);
    EXPECT_THROW(client("bob").updateGroupPolicy(groupId, OPEN), GroupUnauthorizedSignerException);
    EXPECT_THROW(
        client("bob").addGroupMembers(groupId, {GroupMemberToAdd{.user = user("dave"), .role = "user"}}),
        GroupUnauthorizedSignerException
    );
    EXPECT_EQ(count("bob", "context.groupRemoveMembers"), 0u);
    EXPECT_EQ(count("bob", "context.groupUpdatePolicy"), 0u);
    EXPECT_EQ(count("bob", "context.groupAddMembers"), 0u);
    EXPECT_TRUE(bridge.received.empty());
}

TEST_F(GroupApiLyingBridge, SECURITY_APolicyOutsideTheGroupGrammarIsNeverSigned) {
    // R-POL-1: ",manager" would admit anybody under a fail-open reader; the client refuses to sign it.
    EXPECT_THROW(createGroup({"alice", "bob"}, policyWith({{"update", ",manager"}})), core::InvalidParamsException);
    EXPECT_EQ(count("alice", "context.groupCreate"), 0u);
    const std::string groupId = createGroup({"alice", "bob"});
    EXPECT_THROW(
        client("alice").updateGroupPolicy(groupId, policyWith({{"rotateKeys", "manager,,user"}})), core::InvalidParamsException
    );
    EXPECT_EQ(count("alice", "context.groupUpdatePolicy"), 0u);
}

TEST_F(GroupApiLyingBridge, SECURITY_TheReadAfterCompletingAnUnresolvedCommitIsVerifiedBeforeSigning) {
    // bob's policy change completes his unresolved addition first and reads again. That answer, an unsupported tree
    // serving a policy that lets anybody change the policy, was taken unverified: bob signed outside his role.
    quiet = true;
    addUsers({"dave"});
    const std::string groupId = createGroup(
        {"alice", "bob", "carol"}, policyWith({{"update", "user"}, {"rotateKeys", "user"}, {"updatePolicy", "manager"}})
    );
    int adds = 0;
    bridge.onAdd = [&] {
        if (adds++ == 0) {
            refuse();
        }
    };
    EXPECT_ANY_THROW(client("bob").addGroupMembers(groupId, {GroupMemberToAdd{.user = user("dave"), .role = "user"}}));
    bridge.onRead = [&](const std::string& caller, server::GroupInfo& info) {
        if (caller == "bob" && adds == 2) {
            info.treeVersion = 2;
            info.policy = policyOf({{"update", "all"}, {"rotateKeys", "all"}, {"updatePolicy", "all"}});
        }
    };
    EXPECT_THROW(client("bob").updateGroupPolicy(groupId, policyWith({{"update", "manager"}})), GroupDataIntegrityException);
    EXPECT_EQ(adds, 2) << "the addition was not completed first";
    EXPECT_EQ(count("bob", "context.groupUpdatePolicy"), 0u);
}

TEST_F(GroupApiLyingBridge, APolicyChangeIsNotTakenForAnotherThatSignsTheSameRules) {
    // The op key named only the signed rules: a call differing in a Bridge-held field returned on the earlier one.
    quiet = true;
    const std::string groupId = createGroup({"alice", "bob", "carol"});
    int policies = 0;
    bridge.onPolicy = [&](std::unique_lock<std::mutex>&) {
        if (policies++ == 0) {
            refuse();
        }
    };
    core::ContainerPolicy first = OPEN;
    first.get = "all";
    core::ContainerPolicy second = OPEN;
    second.get = "manager";
    EXPECT_ANY_THROW(client("alice").updateGroupPolicy(groupId, first));
    EXPECT_NO_THROW(client("alice").updateGroupPolicy(groupId, second));
    ASSERT_GE(bridge.received.size(), 2u);
    const CommitStatement landed = TreeCommits::fromWire(bridge.tree.commits.back());
    EXPECT_EQ(landed.op, CommitOp::Policy);
    ASSERT_TRUE(landed.policy.has_value());
    EXPECT_NE(privmx::utils::Utils::stringifyVar(landed.policy.value()).find(R"("get":"manager")"), std::string::npos)
        << "the second call returned on the first one's policy";
}

TEST_F(GroupApiLyingBridge, SECURITY_ASeatTheBridgeAllocatesOutsideTheFreeSeatsIsRefusedBeforeSigning) {
    // H2: the seat numbers index the plan's arrays. -1 (0xFFFFFFFF as a seat) wrapped the leaf count to 0 and wrote
    // past the seats; a seat far out allocated gigabytes; a taken one would seat dave over a member.
    quiet = true;
    addUsers({"dave"});
    const std::string groupId = createGroup({"alice", "bob", "carol"});
    for (const std::int64_t seat : {std::int64_t{-1}, std::int64_t{0}, std::int64_t{3 + 1}, std::int64_t{1} << 31}) {
        bridge.onPlanRead = [seat](server::GroupInfo& info) { info.nextFreeSeats = std::vector<std::int64_t>{seat}; };
        expectRefusal<GroupDataIntegrityException>(
            [&] { client("alice").addGroupMembers(groupId, {GroupMemberToAdd{.user = user("dave"), .role = "user"}}); },
            "the bridge allocated a seat that is taken or out of range"
        );
    }
    EXPECT_TRUE(bridge.received.empty()) << "a statement was signed";
    bridge.onPlanRead = [](server::GroupInfo&) {};
    EXPECT_NO_THROW(client("alice").addGroupMembers(groupId, {GroupMemberToAdd{.user = user("dave"), .role = "user"}}));
}

TEST_F(GroupApiLyingBridge, AnAdditionOfAnExistingMemberIsRefusedBeforeSigning) {
    addUsers({"dave"});
    const std::string groupId = createGroup({"alice", "bob"});
    EXPECT_THROW(
        client("alice").addGroupMembers(groupId, {GroupMemberToAdd{.user = user("bob"), .role = "manager"}}),
        core::InvalidParamsException
    ) << "a promotion";
    EXPECT_THROW(
        client("alice").addGroupMembers(
            groupId, {GroupMemberToAdd{.user = user("dave"), .role = "user"}, GroupMemberToAdd{.user = user("dave"), .role = "user"}}
        ),
        core::InvalidParamsException
    ) << "one user twice";
    EXPECT_EQ(count("alice", "context.groupAddMembers"), 0u);
}

// ── commit B: the update role for metadata plane authors (T4-03) ─────────────────────────────────────────────

TEST_F(GroupApiLyingBridge, ANarrowingPolicyCarriesUpThePlanesOfAuthorsWhoLostTheRole) {
    // bob writes under the open policy; alice narrows `update` to managers and carries bob's plane in her name.
    const std::string groupId = createGroup({"alice", "bob", "carol"});
    client("bob").updateGroupPublicMeta(groupId, core::Buffer::from("bob's"), 1);
    client("alice").updateGroupPolicy(groupId, policyWith({{"update", "manager"}, {"updatePolicy", "manager"}}));
    EXPECT_EQ(bridge.rest.publicMeta.author, "alice");
    EXPECT_EQ(bridge.rest.privateMeta.author, "alice") << "the creator's own plane is not carried";
    const Group read = client("carol").getGroup(groupId);
    EXPECT_EQ(read.statusCode, 0);
    EXPECT_EQ(read.publicMeta.stdString(), "bob's");
}

TEST_F(GroupApiLyingBridge, SECURITY_ANarrowingDoesNotReSignAPlaneWrittenAfterItWasRead) {
    // N-2's analogue: bob still holds the current key after the narrowing (no epoch moves). The bridge serves alice's
    // carry a v3 bob tagged after she read v2; re-signing it would launder it into a plane bob may no longer write.
    const std::string groupId = createGroup({"alice", "bob", "carol"});
    client("bob").updateGroupPublicMeta(groupId, core::Buffer::from("v2"), 1);
    const server::GroupMetaEntry v2 = bridge.rest.publicMeta;
    client("bob").updateGroupPublicMeta(groupId, core::Buffer::from("v3"), 2);
    const server::GroupMetaEntry v3 = bridge.rest.publicMeta;
    bridge.rest.publicMeta = v2;
    bridge.rest.publicMetaVersion = 2;
    bridge.onPolicy = [&](std::unique_lock<std::mutex>&) {
        bridge.rest.publicMeta = v3;
        bridge.rest.publicMetaVersion = 3;
    };
    client("alice").updateGroupPolicy(groupId, policyWith({{"update", "manager"}}));
    EXPECT_EQ(bridge.rest.publicMeta.author, "bob");
    EXPECT_EQ(bridge.rest.publicMeta.version, 3) << "alice re-signed bob's late entry";
    EXPECT_NE(client("carol").getGroup(groupId).statusCode, 0);
}

TEST_F(GroupApiLyingBridge, SECURITY_ANarrowingDoesNotCarryALosersPlaneWrittenAfterTheRead) {
    // bob, still holding `update`, writes a fresh plane between alice's read and her commit; it is not what she read.
    const std::string groupId = createGroup({"alice", "bob", "carol"});
    client("bob").updateGroupPublicMeta(groupId, core::Buffer::from("before"), 1);
    bool first = true;
    bridge.onPolicy = [&](std::unique_lock<std::mutex>& lock) {
        if (!std::exchange(first, false)) {
            return;
        }
        lock.unlock();
        client("bob").updateGroupPublicMeta(groupId, core::Buffer::from("after the read"), 2);
        lock.lock();
    };
    client("alice").updateGroupPolicy(groupId, policyWith({{"update", "manager"}}));
    EXPECT_EQ(bridge.rest.publicMeta.author, "bob");
    EXPECT_EQ(bridge.rest.publicMeta.version, 3);
    EXPECT_NE(client("carol").getGroup(groupId).statusCode, 0) << "readers refuse it: bob lost update";
}

TEST_F(GroupApiLyingBridge, ANarrowingThatWouldStrandAPlaneIsRefusedBeforeSigning) {
    // bob may change the policy but would lose `update` himself: nobody would carry his plane.
    const std::string groupId = createGroup({"alice", "bob", "carol"});
    client("bob").updateGroupPublicMeta(groupId, core::Buffer::from("bob's"), 1);
    EXPECT_THROW(
        client("bob").updateGroupPolicy(groupId, policyWith({{"update", "manager"}, {"updatePolicy", "user"}})),
        core::InvalidParamsException
    );
    EXPECT_EQ(count("bob", "context.groupUpdatePolicy"), 0u);
    EXPECT_NO_THROW(client("alice").updateGroupPolicy(groupId, policyWith({{"update", "manager"}})))
        << "alice keeps update and carries it";
}

TEST_F(GroupApiLyingBridge, ACreationWhoseCreatorCannotUpdateIsRefusedBeforeSigning) {
    EXPECT_THROW(createGroup({"alice", "bob"}, policyWith({{"update", "none"}})), core::InvalidParamsException);
    EXPECT_THROW(
        createGroup({"alice", "bob"}, policyWith({{"update", "manager"}}), {}), core::InvalidParamsException
    ) << "the creator in users only";
    EXPECT_EQ(count("alice", "context.groupCreate"), 0u);
    EXPECT_NO_THROW(createGroup({"alice", "bob"}, policyWith({{"update", "manager"}}))) << "the creator a manager";
}

TEST_F(GroupApiLyingBridge, SECURITY_ARemovalDoesNotCarryAPlaneWrittenWithoutTheRole) {
    // bob, a plain user under `update: manager`, writes a plane the bridge stores and every reader refuses. Removing
    // bob must not launder it into the new epoch under alice's name.
    const std::string groupId = createGroup({"alice", "bob", "carol"}, policyWith({{"update", "manager"}}));
    client("bob").updateGroupPublicMeta(groupId, core::Buffer::from("no role"), 1);
    ASSERT_NE(client("carol").getGroup(groupId).statusCode, 0) << "refused already before the removal";
    client("alice").removeGroupMembers(groupId, {"bob"});
    EXPECT_EQ(bridge.rest.publicMeta.author, "bob") << "carried under alice's name";
    EXPECT_NE(client("carol").getGroup(groupId).statusCode, 0);
}

TEST_F(GroupApiLyingBridge, AFailedCarryIsRetriedByTheNextCall) {
    const std::string groupId = createGroup({"alice", "bob", "carol"});
    client("bob").updateGroupPublicMeta(groupId, core::Buffer::from("bob's"), 1);
    bool refuse = true;
    bridge.onMetaWrite = [&] {
        if (std::exchange(refuse, false)) {
            throw privmx::utils::PrivmxException("GROUP_VERSION_MISMATCH", privmx::utils::PrivmxException::RPC, 0x6211);
        }
    };
    EXPECT_NO_THROW(client("alice").updateGroupPolicy(groupId, policyWith({{"update", "manager"}})));
    EXPECT_EQ(bridge.rest.publicMeta.author, "bob");
    EXPECT_NE(client("carol").getGroup(groupId).statusCode, 0) << "until the carry completes";
    EXPECT_EQ(client("alice").getGroup(groupId).statusCode, 0) << "alice's next read retries it first";
    EXPECT_EQ(bridge.rest.publicMeta.author, "alice");
    EXPECT_EQ(client("carol").getGroup(groupId).statusCode, 0);
}

TEST_F(GroupApiLyingBridge, AFailedCarryIsRetriedAfterADisconnect) {
    const std::string groupId = createGroup({"alice", "bob", "carol"});
    client("bob").updateGroupPublicMeta(groupId, core::Buffer::from("bob's"), 1);
    bool refuse = true;
    bridge.onMetaWrite = [&] {
        if (std::exchange(refuse, false)) {
            throw privmx::utils::PrivmxException("GROUP_VERSION_MISMATCH", privmx::utils::PrivmxException::RPC, 0x6211);
        }
    };
    EXPECT_NO_THROW(client("alice").updateGroupPolicy(groupId, policyWith({{"update", "manager"}})));
    clients.at("alice")->connectionImpl->getEventMiddleware()->emitDisconnectedEvent();
    EXPECT_EQ(client("alice").getGroup(groupId).statusCode, 0);
    EXPECT_EQ(bridge.rest.publicMeta.author, "alice") << "the carry was dropped with the connection";
    EXPECT_EQ(client("carol").getGroup(groupId).statusCode, 0);
}

TEST_F(GroupApiLyingBridge, SECURITY_ASeatStrippedReadServingAWiderPolicyDoesNotAcceptANoRolePlane) {
    // R2-S2: an unseated answer is verified (verifyListed) before the mapper reads its policy and roster.
    const std::string groupId = createGroup({"alice", "bob", "carol"}, policyWith({{"update", "manager"}}));
    client("bob").updateGroupPublicMeta(groupId, core::Buffer::from("no role"), 1);
    client("carol").getGroup(groupId); // carol holds the epoch's key from an honest read
    const auto stripCarol = [&](const std::string& caller, server::GroupInfo& info) {
        if (caller != "carol") {
            return;
        }
        auto seats = info.leafAssignment.value();
        std::replace(seats.begin(), seats.end(), std::string("carol"), std::string());
        info.leafAssignment = seats;
        info.ownLeafPosition.reset();
    };
    bridge.onRead = [&](const std::string& caller, server::GroupInfo& info) {
        stripCarol(caller, info);
        if (caller == "carol") {
            info.policy = policyOf({{"update", "all"}, {"rotateKeys", "all"}, {"updatePolicy", "all"}});
        }
    };
    const Group widened = client("carol").getGroup(groupId);
    EXPECT_NE(widened.statusCode, 0);
    EXPECT_TRUE(widened.publicMeta.stdString().empty() && widened.privateMeta.stdString().empty()) << "no metadata";
    EXPECT_TRUE(widened.groupPubKey.empty());
    bridge.onRead = stripCarol;
    EXPECT_NE(client("carol").getGroup(groupId).statusCode, 0) << "the honest policy refuses bob's plane";
}

TEST_F(GroupApiLyingBridge, SECURITY_AnUnattestedReadMovesNoVersionPin) {
    // getGroup refuses an unseated answer whose statement is behind the pin as not attested; its metadata planes must
    // not move the version pins on the way (base: stored before the refusal, so a pin rose on a refused answer).
    quiet = true;
    const std::string groupId = createGroup({"alice", "bob", "carol"});
    client("carol").getGroup(groupId);
    const server::GroupTreeCommit atSeq1 = bridge.tree.commits.back();
    selfUpdateBy("bob");
    ASSERT_EQ(client("carol").getGroup(groupId).statusCode, 0); // pinned at seq 2
    const std::array<std::int64_t, 3> before = GroupApiImplTestAccess::versionPins(client("carol"), groupId);
    client("bob").updateGroupPublicMeta(groupId, core::Buffer::from("v2"), 1);
    bridge.onRead = [&](const std::string& caller, server::GroupInfo& info) {
        if (caller != "carol") {
            return;
        }
        auto seats = info.leafAssignment.value();
        std::replace(seats.begin(), seats.end(), std::string("carol"), std::string());
        info.leafAssignment = seats;
        info.ownLeafPosition.reset();
        info.treeCommit = atSeq1; // genuine, but behind carol's pin
    };
    EXPECT_NE(client("carol").getGroup(groupId).statusCode, 0);
    EXPECT_EQ(GroupApiImplTestAccess::versionPins(client("carol"), groupId), before);
    bridge.onRead = [](const std::string&, server::GroupInfo&) {};
    EXPECT_EQ(client("carol").getGroup(groupId).statusCode, 0);
    EXPECT_GT(GroupApiImplTestAccess::versionPins(client("carol"), groupId)[1], before[1]);
}


// ── leaf renewal after an identity key change (08a) ────────────────────────────────────────────────────────────

namespace {

// Bob's identity key changes in the Context; his session under the old key is dropped. Returns the old key.
PrivateKey changeKeyOf(Bridge& bridge, std::map<std::string, std::unique_ptr<Client>>& clients, const std::string& id) {
    const PrivateKey previous = bridge.users.at(id);
    bridge.changeUserKey(id, PrivateKey::generateRandom());
    clients.erase(id);
    return previous;
}

std::size_t sent(const Bridge& bridge) {
    return bridge.received.size();
}

} // namespace

TEST_F(GroupApiLyingBridge, SECURITY_ARenewalIsSignedWithTheNewKeyAndClimbsWithThePreviousOne) {
    quiet = true;
    // Bob creates the group, so statements under his previous key vouch for nodes the renewal does not re-key.
    const std::string groupId = client("bob").createGroup(
        CONTEXT, {user("bob"), user("carol")}, {user("alice")}, core::Buffer::from("public"),
        core::Buffer::from("private"), OPEN
    );
    const PrivateKey grant = client("alice").resolveGroupPrivKey(groupId); // alice and carol pin bob's statement
    client("carol").resolveGroupPrivKey(groupId);
    const PrivateKey previous = changeKeyOf(bridge, clients, "bob");
    EXPECT_THROW(client("bob").resolveGroupPrivKey(groupId), core::EncryptionKeyValidationException);

    EXPECT_TRUE(client("bob").renewLeaf(groupId, previous.toWIF()));
    ASSERT_EQ(sent(bridge), 1u);
    const CommitStatement renewal = TreeCommits::fromWire(bridge.received.back());
    EXPECT_EQ(renewal.op, CommitOp::SelfUpdate);
    EXPECT_EQ(renewal.committerPubKey, bridge.users.at("bob").getPublicKey().toBase58DER()) << "signed with the new key";
    EXPECT_EQ(renewal.keyVersion, 1u) << "no new epoch, nothing to re-key in containers";
    EXPECT_EQ(bridge.tree.commits.size(), 2u);

    clients.erase("bob"); // a fresh session of the new key: nothing cached from the renewal
    EXPECT_EQ(client("bob").resolveGroupPrivKey(groupId).getPublicKey(), grant.getPublicKey());
    EXPECT_EQ(client("alice").getGroup(groupId).statusCode, 0) << "alice's pin sits at bob's old-key statement";
    EXPECT_EQ(client("alice").resolveGroupPrivKey(groupId).getPublicKey(), grant.getPublicKey());
    EXPECT_EQ(client("carol").getGroup(groupId).statusCode, 0);
}

TEST_F(GroupApiLyingBridge, SECURITY_AfterRenewalThePreviousKeyOpensNoCurrentEdge) {
    quiet = true;
    const std::string groupId = createGroup({"alice", "bob", "carol"});
    const PrivateKey previous = changeKeyOf(bridge, clients, "bob");
    ASSERT_TRUE(client("bob").renewLeaf(groupId, previous.toWIF()));
    TreeKeyCache cache;
    TreeKeys keys(cache);
    const TreeGroupState served = GroupKeyResolver::toTreeState(bridge.serve("bob", true));
    EXPECT_EQ(keys.climbToGrantKey(served, "bob", previous, false).failure, ClimbFailure::LeafDidNotOpen);
}

namespace {

// The edge above `owner`'s leaf, which `garbler`'s commit wrote, now wraps a key nobody holds: `owner`'s climb fails
// with LeafDidNotOpen, exactly as after a change of `owner`'s identity key.
void garbleLeafEdgeOf(Bridge& bridge, const std::string& owner, const std::string& garbler) {
    std::size_t garbled = 0;
    for (TreeEdge& edge : bridge.tree.state.edges) {
        if (edge.childKind == EdgeChildKind::User && edge.childUserId == owner) {
            const PrivateKey somebodyElse = PrivateKey::generateRandom();
            edge.blob = TreeKeys::wrapKey(somebodyElse, somebodyElse.getPublicKey(), bridge.users.at(garbler));
            ++garbled;
        }
    }
    ASSERT_EQ(garbled, 1u);
}

// `wrapper` re-wraps the genuine key above `owner`'s leaf to `to` (a valid wrap, not garbage): the edges name no
// recipient key, so any member holding the parent can address `owner`'s edge to a key of its choice, e.g. `owner`'s
// previous public key. Needs `wrapper`'s own edge under the same parent (in up to 32 seats: the root).
void rewrapLeafEdgeOf(Bridge& bridge, const std::string& owner, const std::string& wrapper, const PublicKey& to) {
    const auto userEdge = [&](const std::string& id) {
        return std::find_if(bridge.tree.state.edges.begin(), bridge.tree.state.edges.end(), [&](const TreeEdge& e) {
            return e.childKind == EdgeChildKind::User && e.childUserId == id;
        });
    };
    const auto owners = userEdge(owner);
    const auto wrappers = userEdge(wrapper);
    ASSERT_NE(owners, bridge.tree.state.edges.end());
    ASSERT_NE(wrappers, bridge.tree.state.edges.end());
    ASSERT_EQ(owners->parentIndex, wrappers->parentIndex);
    const auto parent = TreeKeys::unwrapKey(wrappers->blob, bridge.users.at(wrapper));
    ASSERT_TRUE(parent.has_value());
    owners->blob = TreeKeys::wrapKey(parent.value(), to, bridge.users.at(wrapper));
}

void expectRemoved(const Bridge& bridge, const std::string& userId) {
    EXPECT_EQ(bridge.tree.state.epoch, 2u) << "the removal did not land";
    const auto users = bridge.tree.users();
    EXPECT_EQ(std::find(users.begin(), users.end(), userId), users.end()) << userId << " is still a member";
}

// alice changed key and, before renewLeaf, removes `leaving`.
void expectRefusedUntilRenewal(
    GroupApiImpl& alice,
    const Bridge& bridge,
    const std::string& groupId,
    const std::string& leaving
) {
    try {
        alice.removeGroupMembers(groupId, {leaving});
        ADD_FAILURE() << "the removal was not refused";
    } catch (const core::EncryptionKeyValidationException& e) {
        EXPECT_NE(std::string(e.what()).find("renewLeaf"), std::string::npos) << e.what();
    }
    EXPECT_EQ(bridge.tree.state.epoch, 1u) << "a removal landed, with abandonHistory";
}

} // namespace

// Final audit 05a rounds 2-3 and the coordinator rule: nothing the Bridge serves (the blame, the statements) decides
// whether a removal whose own leaf does not open goes through; only an own key change this client was told about
// (adoptPreviousIdentity) refuses it. 315acd70 refused the next four.
TEST_F(GroupApiLyingBridge, SECURITY_AMemberWhoGarblesAManagersLeafEdgeCannotBlockItsOwnRemoval) {
    // Three seats: only the root is keyed, bob's self-update rewrote it, and no statement of alice stays served.
    quiet = true;
    const std::string groupId = createGroup({"alice", "bob", "carol"});
    selfUpdateBy("bob");
    garbleLeafEdgeOf(bridge, "alice", "bob");
    clients.erase("alice"); // a fresh session: no grant key cached
    EXPECT_NO_THROW(client("alice").removeGroupMembers(groupId, {"bob"}));
    expectRemoved(bridge, "bob");
}

TEST_F(GroupApiLyingBridge, SECURITY_AMemberWhoGarblesTheLeafEdgeOfAManagerWhoNeverCommittedCannotBlockItsOwnRemoval) {
    quiet = true;
    const std::string groupId = client("carol").createGroup( // alice has no statement in this group at all
        CONTEXT, {user("bob")}, {user("alice"), user("carol")}, core::Buffer::from("public"),
        core::Buffer::from("private"), OPEN
    );
    selfUpdateBy("bob");
    garbleLeafEdgeOf(bridge, "alice", "bob");
    EXPECT_NO_THROW(client("alice").removeGroupMembers(groupId, {"bob"}));
    expectRemoved(bridge, "bob");
}

TEST_F(GroupApiLyingBridge, SECURITY_ARemovalWithAGarbledOwnLeafEdgeGoesThroughWhateverTheBlame) {
    // The blame names bob; alice removes carol. The removal does not ask who broke the edge.
    quiet = true;
    const std::string groupId = createGroup({"alice", "bob", "carol"});
    selfUpdateBy("bob");
    garbleLeafEdgeOf(bridge, "alice", "bob");
    clients.erase("alice");
    EXPECT_NO_THROW(client("alice").removeGroupMembers(groupId, {"carol"}));
    expectRemoved(bridge, "carol");
}

TEST_F(GroupApiLyingBridge, AManagerWhoChangedKeyWithoutAdoptingGetsTheBaseRemoval) {
    // Documented boundary (SECURITY-NOTES 08-A2): an app that changes the key without Connection::adoptPreviousIdentity
    // gives this client no way to tell its key change from a garbled edge, so the removal goes through as in the
    // base and abandons history: nobody can open epoch 1 afterwards.
    quiet = true;
    const std::string groupId = createGroup({"alice", "bob", "carol"});
    changeKeyOf(bridge, clients, "alice");
    EXPECT_NO_THROW(client("alice").removeGroupMembers(groupId, {"bob"}));
    expectRemoved(bridge, "bob");
    EXPECT_ANY_THROW(client("carol").resolveGroupPrivKey(groupId, 1)) << "history was kept";
}

TEST_F(GroupApiLyingBridge, SECURITY_AManagerWhoChangedKeyAndAdoptedCannotRemoveTheSiblingWhoHealedItsLeafEdge) {
    // Final audit 05a round 3 (08-A4): after a key change the node over alice's leaf was last set by an honest member
    // (the creator, an adder, here a healing sibling). Removing it must not abandon every member's history.
    quiet = true;
    const std::string groupId = createGroup({"alice", "bob", "carol"});
    selfUpdateBy("bob"); // bob, alice's sibling, now set the node above alice's leaf
    const PrivateKey previous = changeKeyOf(bridge, clients, "alice");
    GroupApiImpl& alice = clientAdopting("alice", previous);
    expectRefusedUntilRenewal(alice, bridge, groupId, "bob");
    expectRefusedUntilRenewal(alice, bridge, groupId, "carol");

    ASSERT_TRUE(alice.renewLeaf(groupId, previous.toWIF()));
    EXPECT_NO_THROW(alice.removeGroupMembers(groupId, {"bob"}));
    expectRemoved(bridge, "bob");
    EXPECT_NO_THROW(client("carol").resolveGroupPrivKey(groupId, 1)) << "the removal after renewing cut the history";
}

TEST_F(GroupApiLyingBridge, SECURITY_AManagerWhoChangedKeyAndAdoptedCannotRemoveTheCreatorBeforeRenewing) {
    quiet = true;
    const std::string groupId = client("bob").createGroup( // bob, the creator, set every node
        CONTEXT, {user("bob"), user("carol")}, {user("alice")}, core::Buffer::from("public"),
        core::Buffer::from("private"), OPEN
    );
    const PrivateKey previous = changeKeyOf(bridge, clients, "alice");
    expectRefusedUntilRenewal(clientAdopting("alice", previous), bridge, groupId, "bob");
}

// Final audit 05a round 5: an adopted key change refuses a removal only while renewLeaf can fix the leaf, i.e. while
// the previous key climbs it. A member that garbles the edge above the manager's leaf breaks it for both keys, so the
// removal goes through as in the base, in the session that adopted and after a renewal alike. 1d66831e refused both
// (a session-wide flag), and renewLeaf could not clear it.
TEST_F(GroupApiLyingBridge, SECURITY_AGarblerCannotBlockItsRemovalByAManagerThatAdoptedAndHasNotRenewed) {
    quiet = true;
    const std::string groupId = createGroup({"alice", "bob", "carol"});
    const PrivateKey previous = changeKeyOf(bridge, clients, "alice");
    GroupApiImpl& alice = clientAdopting("alice", previous);
    selfUpdateBy("bob");
    garbleLeafEdgeOf(bridge, "alice", "bob");
    EXPECT_NO_THROW(alice.removeGroupMembers(groupId, {"bob"}));
    expectRemoved(bridge, "bob");
}

TEST_F(GroupApiLyingBridge, SECURITY_AGarblerCannotBlockItsRemovalByAManagerThatRenewedInThisSession) {
    quiet = true;
    const std::string groupId = createGroup({"alice", "bob", "carol"});
    const PrivateKey previous = changeKeyOf(bridge, clients, "alice");
    GroupApiImpl& alice = clientAdopting("alice", previous);
    ASSERT_TRUE(alice.renewLeaf(groupId, previous.toWIF()));
    selfUpdateBy("bob");
    garbleLeafEdgeOf(bridge, "alice", "bob");
    EXPECT_NO_THROW(alice.removeGroupMembers(groupId, {"bob"}));
    expectRemoved(bridge, "bob");
}

// Final audit 05a round 6: the edges name no recipient key, so the garbler need not garble. After alice's renewal it
// wraps the genuine root to alice's PREVIOUS public key: the session key fails at the leaf, the previous key climbs,
// and ea7395ec refused the removal again ("call renewLeaf"), as often as bob re-wrapped after each renewal. A landed
// renewal now leaves the epoch's grant key in the group's cache, so the removal goes on with history kept.
TEST_F(GroupApiLyingBridge, SECURITY_AMemberCannotBlockItsRemovalByWrappingARenewedManagersLeafToThePreviousKey) {
    quiet = true;
    const std::string groupId = createGroup({"alice", "bob", "carol"});
    const PrivateKey previous = changeKeyOf(bridge, clients, "alice");
    GroupApiImpl& alice = clientAdopting("alice", previous);
    ASSERT_TRUE(alice.renewLeaf(groupId, previous.toWIF()));
    selfUpdateBy("bob");
    rewrapLeafEdgeOf(bridge, "alice", "bob", previous.getPublicKey());
    {
        TreeKeyCache cache;
        TreeKeys keys(cache);
        const TreeGroupState served = GroupKeyResolver::toTreeState(bridge.serve("alice", true));
        ASSERT_EQ(keys.climbToGrantKey(served, "alice", previous, false).failure, ClimbFailure::None)
            << "the previous key must climb, or this is the garbage case";
    }
    EXPECT_NO_THROW(alice.removeGroupMembers(groupId, {"bob"}));
    expectRemoved(bridge, "bob");
    EXPECT_NO_THROW(client("carol").resolveGroupPrivKey(groupId, 1)) << "the removal cut the history";
}

TEST_F(GroupApiLyingBridge, SECURITY_ARenewalWithAKeyThatDoesNotOpenTheLeafCommitsNothingAndCachesNothing) {
    quiet = true;
    const std::string groupId = createGroup({"alice", "bob", "carol"});
    changeKeyOf(bridge, clients, "bob");
    EXPECT_THROW(
        client("bob").renewLeaf(groupId, PrivateKey::generateRandom().toWIF()), core::EncryptionKeyValidationException
    );
    EXPECT_EQ(sent(bridge), 0u);
    try {
        client("bob").resolveGroupPrivKey(groupId, 1);
        FAIL() << "the leaf opened";
    } catch (const core::EncryptionKeyValidationException& e) {
        EXPECT_NE(std::string(e.what()).find("renewLeaf"), std::string::npos) << e.what();
    }
}

TEST_F(GroupApiLyingBridge, SECURITY_AFailedRenewalLeavesNoGrantKeyCached) {
    // The previous-key climb goes through; the commit then fails on a recipient key. Nothing it derived may serve
    // this session afterwards: not the shared cache, not the epoch memo.
    quiet = true;
    const std::string groupId = createGroup({"alice", "bob", "carol"});
    const PrivateKey previous = changeKeyOf(bridge, clients, "bob");
    bridge.listedKeys.emplace("carol", PrivateKey::generateRandom());
    EXPECT_THROW(client("bob").renewLeaf(groupId, previous.toWIF()), core::UserVerificationFailureException);
    EXPECT_EQ(sent(bridge), 0u);
    EXPECT_THROW(client("bob").resolveGroupPrivKey(groupId, 1), core::EncryptionKeyValidationException);
    EXPECT_THROW(client("bob").resolveGroupPrivKey(groupId), core::EncryptionKeyValidationException);
    EXPECT_ANY_THROW(client("bob").encrypt(groupId, core::Buffer::from("x")));
}

TEST_F(GroupApiLyingBridge, SECURITY_ARenewalWrapsOthersOnlyToKeysTheVerifierVouchesFor) {
    // The bridge lists a key of its own for carol; the renewal would wrap the fresh root to it.
    quiet = true;
    const std::string groupId = createGroup({"alice", "bob", "carol"});
    const PrivateKey previous = changeKeyOf(bridge, clients, "bob");
    bridge.listedKeys.emplace("carol", PrivateKey::generateRandom());
    EXPECT_THROW(client("bob").renewLeaf(groupId, previous.toWIF()), core::UserVerificationFailureException);
    EXPECT_EQ(bridge.tree.commits.size(), 1u) << "nothing committed";
    bridge.listedKeys.clear();
    EXPECT_TRUE(client("bob").renewLeaf(groupId, previous.toWIF()));
}

TEST_F(GroupApiLyingBridge, ARenewalOfALeafThatAlreadyOpensCommitsNothing) {
    // carol's self-update after the change wrapped bob's leaf to his new key already.
    quiet = true;
    const std::string groupId = createGroup({"alice", "bob", "carol"});
    const PrivateKey previous = changeKeyOf(bridge, clients, "bob");
    selfUpdateBy("carol");
    EXPECT_FALSE(client("bob").renewLeaf(groupId, previous.toWIF()));
    EXPECT_EQ(sent(bridge), 0u);
    EXPECT_EQ(bridge.tree.commits.size(), 2u);
}

TEST_F(GroupApiLyingBridge, ACommitBeforeTheDirectoryChangeIsOpenedByThePreviousKey) {
    quiet = true;
    const std::string groupId = createGroup({"alice", "bob", "carol"});
    selfUpdateBy("carol"); // wraps bob's leaf to the key he holds now
    const PrivateKey previous = changeKeyOf(bridge, clients, "bob");
    EXPECT_TRUE(client("bob").renewLeaf(groupId, previous.toWIF()));
    clients.erase("bob");
    EXPECT_NO_THROW(client("bob").resolveGroupPrivKey(groupId));
}

TEST_F(GroupApiLyingBridge, SECURITY_ARenewalRefusesAStateRolledBackBelowThePin) {
    quiet = true;
    const std::string groupId = createGroup({"alice", "bob", "carol"});
    const PrivateKey previous = changeKeyOf(bridge, clients, "bob");
    const Bridge beforeRenewal = bridge;
    ASSERT_TRUE(client("bob").renewLeaf(groupId, previous.toWIF())); // pins the renewal
    rollBackTo(beforeRenewal);
    EXPECT_THROW(client("bob").renewLeaf(groupId, previous.toWIF()), GroupHistoryForkException);
    EXPECT_EQ(sent(bridge), 1u) << "nothing committed on the rolled-back state";
}

TEST_F(GroupApiLyingBridge, SECURITY_AnOldKeySessionCannotRenewAfterTheDirectoryChange) {
    quiet = true;
    const std::string groupId = createGroup({"alice", "bob", "carol"});
    client("bob").resolveGroupPrivKey(groupId);
    const std::unique_ptr<Client> oldSession = std::move(clients.at("bob"));
    const PrivateKey previous = bridge.users.at("bob");
    bridge.changeUserKey("bob", PrivateKey::generateRandom());
    EXPECT_ANY_THROW(oldSession->api->renewLeaf(groupId, PrivateKey::generateRandom().toWIF()));
    EXPECT_ANY_THROW(oldSession->api->rotateGroupKey(groupId));
    EXPECT_EQ(sent(bridge), 0u) << "the bridge refused the old key's session before any commit";
    EXPECT_THROW(oldSession->api->renewLeaf(groupId, previous.toWIF()), core::InvalidParamsException)
        << "the previous key is the session's own";
}

TEST_F(GroupApiLyingBridge, AOneMemberGroupRenews) {
    quiet = true;
    const std::string groupId = client("bob").createGroup(
        CONTEXT, {user("bob")}, {}, core::Buffer::from("public"), core::Buffer::from("private"), OPEN
    );
    const PrivateKey grant = client("bob").resolveGroupPrivKey(groupId);
    const PrivateKey previous = changeKeyOf(bridge, clients, "bob");
    EXPECT_TRUE(client("bob").renewLeaf(groupId, previous.toWIF()));
    clients.erase("bob");
    EXPECT_EQ(client("bob").resolveGroupPrivKey(groupId).getPublicKey(), grant.getPublicKey());
    EXPECT_FALSE(client("bob").renewLeaf(groupId, previous.toWIF())) << "renewed already";
}

// 01: pins that outlive a GroupApi, through the application's PinStore

namespace {

// The group pinned past bob's removal of carol by alice's session, which then ends; the bridge is put back to before
// the removal. What every rollback test below starts from.
struct PinnedPastARemoval {
    std::string groupId;
    Bridge beforeRemoval;
};

} // namespace

TEST_F(GroupApiLyingBridge, SECURITY_APinSavedByOneSessionRefusesARollbackInTheNext) {
    // R5 (second half): a member restarted after a removal is served the pre-removal state, and would seal under the
    // key carol still holds. Base: the next session is a first contact and takes it.
    quiet = true;
    store = std::make_shared<MemoryPinStore>();
    const std::string groupId = createGroup({"alice", "bob", "carol"});
    const Bridge beforeRemoval = bridge;
    client("bob").removeGroupMembers(groupId, {"carol"});
    client("alice").resolveGroupPrivKey(groupId); // pins epoch 2
    clients.erase("alice");                       // the session ends (its destructor saves)
    rollBackTo(beforeRemoval);
    EXPECT_THROW(client("alice").getGroup(groupId), GroupHistoryForkException);
    EXPECT_THROW(client("alice").encrypt(groupId, core::Buffer::from("x")), GroupHistoryForkException);
}

TEST_F(GroupApiLyingBridge, WithoutAStoreEverySessionIsAFirstContact) {
    // The same flow with no store: what the test above closes.
    quiet = true;
    const std::string groupId = createGroup({"alice", "bob", "carol"});
    const Bridge beforeRemoval = bridge;
    client("bob").removeGroupMembers(groupId, {"carol"});
    client("alice").resolveGroupPrivKey(groupId);
    clients.erase("alice");
    rollBackTo(beforeRemoval);
    EXPECT_EQ(client("alice").getGroup(groupId).statusCode, 0);
}

TEST_F(GroupApiLyingBridge, SECURITY_AnOwnRemovalIsInTheStoreBeforeTheCallReturns) {
    // Saved synchronously: a session killed right after `removeGroupMembers` returns (no destructor) still
    // refuses the pre-removal state in the next one.
    quiet = true;
    store = std::make_shared<MemoryPinStore>();
    const std::string groupId = createGroup({"alice", "bob", "carol"});
    const Bridge beforeRemoval = bridge;
    client("alice").removeGroupMembers(groupId, {"carol"});
    const auto stored = storedPin(groupId, bridge.users.at("alice"));
    ASSERT_TRUE(stored.has_value());
    EXPECT_EQ(stored->seq, 2u) << "in the store before the call returned";
    kill("alice");
    rollBackTo(beforeRemoval);
    EXPECT_THROW(client("alice").getGroup(groupId), GroupHistoryForkException);
}

TEST_F(GroupApiLyingBridge, SECURITY_ALiveSiblingTakesTheRemovalAtItsNextSave) {
    // Two live instances of alice on one device. One verified the removal and saved it; the other meets that record
    // at its next save (they do not poll each other) and from then on refuses the pre-removal state.
    quiet = true;
    store = std::make_shared<MemoryPinStore>();
    const std::string groupId = createGroup({"alice", "bob", "carol"});
    GroupApiImpl& alice2 = sibling("alice");
    alice2.encrypt(groupId, core::Buffer::from("warm")); // caches the epoch 1 key
    const Bridge beforeRemoval = bridge;
    client("bob").removeGroupMembers(groupId, {"carol"});
    client("alice").resolveGroupPrivKey(groupId); // alice1 pins epoch 2
    ASSERT_TRUE(GroupApiImplTestAccess::savePins(client("alice")));
    rollBackTo(beforeRemoval);
    ASSERT_TRUE(GroupApiImplTestAccess::savePins(alice2));
    EXPECT_EQ(GroupApiImplTestAccess::pinnedSeq(alice2, groupId), 2u);
    EXPECT_THROW(alice2.encrypt(groupId, core::Buffer::from("x")), GroupHistoryForkException);
    EXPECT_EQ(storedPin(groupId, bridge.users.at("alice"))->seq, 2u);
}

TEST_F(GroupApiLyingBridge, ALongerBranchShownToASiblingWinsTheSlot_ForkBoundary) {
    // The fork boundary, stated: the bridge shows alice1 bob's removal (seq 2) and alice2 two self-updates of carol on
    // the state before it (seq 3). The higher record wins the slot; the instances are not reconciled. A bridge able to
    // do this can as well withhold the removal from every instance (SECURITY-NOTES, fork boundary).
    quiet = true;
    store = std::make_shared<MemoryPinStore>();
    const std::string groupId = createGroup({"alice", "bob", "carol"});
    GroupApiImpl& alice2 = sibling("alice");
    const Bridge atSeq1 = bridge;
    client("bob").removeGroupMembers(groupId, {"carol"});
    const Bridge honest = bridge;
    client("alice").resolveGroupPrivKey(groupId);
    rollBackTo(atSeq1);
    selfUpdateBy("carol");
    selfUpdateBy("carol");
    alice2.resolveGroupPrivKey(groupId);
    ASSERT_TRUE(GroupApiImplTestAccess::savePins(client("alice")));
    ASSERT_TRUE(GroupApiImplTestAccess::savePins(alice2));
    EXPECT_EQ(storedPin(groupId, bridge.users.at("alice"))->seq, 3u);
    rollBackTo(honest);
    EXPECT_THROW(alice2.getGroup(groupId), GroupHistoryForkException) << "the honest state is refused, not taken";
}

TEST_F(GroupApiLyingBridge, HonestSiblingsAtDifferentSeqsConvergeWithoutAFork) {
    quiet = true;
    store = std::make_shared<MemoryPinStore>();
    const std::string groupId = createGroup({"alice", "bob", "carol"});
    GroupApiImpl& alice2 = sibling("alice");
    selfUpdateBy("bob");
    client("alice").resolveGroupPrivKey(groupId); // seq 2
    selfUpdateBy("carol");
    selfUpdateBy("bob");
    alice2.resolveGroupPrivKey(groupId); // seq 4
    ASSERT_TRUE(GroupApiImplTestAccess::savePins(client("alice")));
    const std::size_t pagesBefore = count("alice", "context.groupGetTreeCommits");
    ASSERT_TRUE(GroupApiImplTestAccess::savePins(alice2));
    EXPECT_EQ(count("alice", "context.groupGetTreeCommits"), pagesBefore) << "a merge reads nothing";
    ASSERT_TRUE(GroupApiImplTestAccess::savePins(client("alice"))); // meets alice2's record
    EXPECT_EQ(GroupApiImplTestAccess::pinnedSeq(client("alice"), groupId), 4u);
    EXPECT_EQ(GroupApiImplTestAccess::pinnedSeq(alice2, groupId), 4u);
    EXPECT_EQ(client("alice").getGroup(groupId).statusCode, 0);
    EXPECT_EQ(alice2.getGroup(groupId).statusCode, 0);
}

TEST_F(GroupApiLyingBridge, SECURITY_AnOwnRemovalOverASiblingsFirstContactIsSavedBeforeTheCallReturns) {
    // bob2 took the group by first contact and never saved it; bob1 then saved its own first contact (seq 1). bob2's
    // removal of carol (seq 2) must be in the slot, and stay in bob2's memory, when the call returns.
    quiet = true;
    store = std::make_shared<MemoryPinStore>();
    const std::string groupId = createGroup({"alice", "bob", "carol"});
    const Bridge beforeRemoval = bridge;
    GroupApiImpl& bob2 = sibling("bob");
    bob2.getGroup(groupId); // first contact
    client("bob").getGroup(groupId);
    ASSERT_TRUE(GroupApiImplTestAccess::savePins(client("bob")));
    bob2.removeGroupMembers(groupId, {"carol"});
    EXPECT_EQ(GroupApiImplTestAccess::pinnedSeq(bob2, groupId), 2u) << "never below its own removal";
    const auto stored = storedPin(groupId, bridge.users.at("bob"));
    ASSERT_TRUE(stored.has_value());
    EXPECT_EQ(stored->seq, 2u) << "in the store before the call returned";
    rollBackTo(beforeRemoval);
    EXPECT_THROW(bob2.getGroup(groupId), GroupHistoryForkException);
    EXPECT_THROW(sibling("bob").getGroup(groupId), GroupHistoryForkException) << "and the next session";
}

TEST_F(GroupApiLyingBridge, SECURITY_AnOwnRemovalLinkedOverASiblingsSaveIsSavedBeforeTheCallReturns) {
    // alice2 saves bob's self-update (seq 2), alice1 then removes carol (seq 3): the higher record, written before the
    // call returns.
    quiet = true;
    store = std::make_shared<MemoryPinStore>();
    const std::string groupId = createGroup({"alice", "bob", "carol"});
    GroupApiImpl& alice2 = sibling("alice");
    selfUpdateBy("bob");
    const Bridge beforeRemoval = bridge;
    alice2.resolveGroupPrivKey(groupId);
    ASSERT_TRUE(GroupApiImplTestAccess::savePins(alice2));
    client("alice").removeGroupMembers(groupId, {"carol"});
    const auto stored = storedPin(groupId, bridge.users.at("alice"));
    ASSERT_TRUE(stored.has_value());
    EXPECT_EQ(stored->seq, 3u) << "in the store before the call returned";
    kill("alice");
    rollBackTo(beforeRemoval);
    EXPECT_THROW(sibling("alice").getGroup(groupId), GroupHistoryForkException);
}

TEST_F(GroupApiLyingBridge, SECURITY_AdoptionNeverLowersAPinThatMovedPastItsFirstContact) {
    // Under the new key alice took the group by first contact (seq 1), then verified bob's removal of carol (seq 2)
    // and saved it. The previous key's slot still holds seq 1; adopting it afterwards (renewLeaf adopts on every call)
    // must not bring the pin back below the removal.
    quiet = true;
    store = std::make_shared<MemoryPinStore>();
    const std::string groupId = createGroup({"alice", "bob", "carol"}); // seq 1 in the previous key's slot
    const PrivateKey previous = changeKeyOf(bridge, clients, "alice");
    const Bridge beforeRemoval = bridge;
    client("alice").getGroup(groupId); // the new key's first contact
    removalBy("bob", {"carol"});
    client("alice").getGroup(groupId); // seq 2, a verified step
    ASSERT_TRUE(GroupApiImplTestAccess::savePins(client("alice")));
    client("alice").adoptPreviousIdentity(previous);
    EXPECT_EQ(GroupApiImplTestAccess::pinnedSeq(client("alice"), groupId), 2u);
    EXPECT_EQ(storedPin(groupId, bridge.users.at("alice"))->seq, 2u) << "the current slot is not lowered";
    rollBackTo(beforeRemoval);
    EXPECT_THROW(client("alice").getGroup(groupId), GroupHistoryForkException);
}

TEST_F(GroupApiLyingBridge, ABrokenStoreDoesNotStopTheClientAndIsRetried) {
    // A store that refuses saves leaves the pins in memory (as without a store); nothing throws, and the next save
    // once the store recovers writes them in full.
    quiet = true;
    store = std::make_shared<MemoryPinStore>();
    const std::string groupId = createGroup({"alice", "bob", "carol"});
    store->failSaves = true;
    for (int i = 0; i < 3; ++i) {
        EXPECT_FALSE(GroupApiImplTestAccess::savePins(client("alice")));
    }
    EXPECT_NO_THROW(client("alice").encrypt(groupId, core::Buffer::from("x")));
    client("bob").removeGroupMembers(groupId, {"carol"});
    client("alice").resolveGroupPrivKey(groupId);
    store->failSaves = false;
    ASSERT_TRUE(GroupApiImplTestAccess::savePins(client("alice")));
    EXPECT_EQ(storedPin(groupId, bridge.users.at("alice"))->seq, 2u);
}

TEST_F(GroupApiLyingBridge, ARefusingStoreIsNotRetriedAtEveryVerification) {
    // A failed save is retried like a minor move (after the idle interval), not by every read that follows; an own
    // commit or a disconnect still saves at once.
    store = std::make_shared<MemoryPinStore>();
    const std::string groupId = createGroup({"alice", "bob", "carol"});
    store->failSaves = true;
    ASSERT_FALSE(GroupApiImplTestAccess::savePins(client("alice")));
    int attempts = 0;
    store->afterLoad = [&](const std::string&) { ++attempts; };
    for (int i = 0; i < 4; ++i) {
        selfUpdateBy(i % 2 == 0 ? "bob" : "carol");
        client("alice").getGroup(groupId);
    }
    store->afterLoad = [](const std::string&) {};
    EXPECT_EQ(attempts, 0) << "the refusing store was written at every verification";
    store->failSaves = false;
    clients.at("alice")->connectionImpl->getEventMiddleware()->emitDisconnectedEvent();
    const auto stored = storedPin(groupId, bridge.users.at("alice"));
    ASSERT_TRUE(stored.has_value());
    EXPECT_EQ(stored->seq, 5u);
}

TEST_F(GroupApiLyingBridge, SECURITY_AnEnvelopeNamingAGroupWithoutTheCallersSeatPinsNothing) {
    // The envelope's group id is unauthenticated. Served with somebody else's seat, the group is refused before the
    // verifier stores anything (base: pinned first, refused after).
    quiet = true;
    const std::string groupId = client("bob").createGroup(
        CONTEXT, {user("carol")}, {user("bob")}, core::Buffer::from("public"), core::Buffer::from("private"), OPEN
    );
    const Envelope sealed = client("bob").encrypt(groupId, core::Buffer::from("not for alice"));
    bridge.onRead = [&](const std::string& caller, server::GroupInfo& info) {
        if (caller == "alice") {
            info = bridge.serve("bob", false);
        }
    };
    EXPECT_THROW(client("alice").decrypt(sealed), GroupDataIntegrityException);
    EXPECT_EQ(GroupApiImplTestAccess::pinnedSeq(client("alice"), groupId), 0u);
}

TEST_F(GroupApiLyingBridge, SECURITY_AVersionPinSavedByOneSessionRefusesAnOlderMetadataPlaneInTheNext) {
    quiet = true;
    store = std::make_shared<MemoryPinStore>();
    const std::string groupId = createGroup({"alice", "bob"});
    const server::GroupMetaEntry v1 = bridge.rest.publicMeta;
    client("bob").updateGroupPublicMeta(groupId, core::Buffer::from("v2"), 1);
    ASSERT_EQ(client("alice").getGroup(groupId).statusCode, 0); // pins publicMetaVersion 2
    clients.erase("alice");
    bridge.rest.publicMeta = v1; // a genuinely tagged older entry
    bridge.rest.publicMetaVersion = 1;
    EXPECT_EQ(client("alice").getGroup(groupId).statusCode, GroupHistoryForkException().getCode())
        << "base: a first contact takes v1";
}

TEST_F(GroupApiLyingBridge, SECURITY_ARecreatedGroupIsAForkInTheNextSession) {
    // T4-14 across sessions: a former member who knows the resourceId re-creates the id.
    quiet = true;
    store = std::make_shared<MemoryPinStore>();
    const std::string groupId = createGroup({"alice", "bob"});
    client("alice").resolveGroupPrivKey(groupId, 1);
    clients.erase("alice");
    FakeBridge recreated = bridge.tree;
    recreated.commits.clear();
    TreeKeyCache cache;
    TreeKeys keys(cache);
    const PrivateKey& bob = bridge.users.at("bob");
    const CommitPlan plan = keys.planCreate(
        {TreeMember{"alice", bridge.users.at("alice").getPublicKey()}, TreeMember{"bob", bob.getPublicKey()}}, "bob", bob
    );
    CommitStatement genesis = TreeCommits::statementFor(
        plan, CommitOp::Create, recreated.resourceId, privmx::utils::Utils::getNowTimestamp(), 1,
        plan.grantKey.getPublicKey().toBase58DER(), 1, {"alice", "bob"}, {}, "bob", {}, {}, {},
        TreeCommits::rules(OPEN_POLICY, "bob").hash
    );
    genesis.policy = OPEN_POLICY;
    TreeCommits::sign(genesis, bob);
    recreated.create(TreeWire::toCreateTree(plan), plan.grantKey.getPublicKey(), "bob", TreeCommits::toWire(genesis));
    bridge.tree = recreated;
    EXPECT_THROW(client("alice").resolveGroupPrivKey(groupId, 1), GroupHistoryForkException);
}

TEST_F(GroupApiLyingBridge, SECURITY_ADeletionEventLeavesThePersistedPinsInPlace) {
    // T3-08: after `groupDeleted` (the bridge's word alone) and a restart, the state before the pin is a rollback.
    quiet = true;
    store = std::make_shared<MemoryPinStore>();
    const std::string groupId = createGroup({"alice", "bob"});
    const Bridge atSeq1 = bridge;
    selfUpdateBy("bob");
    client("alice").resolveGroupPrivKey(groupId);
    Client& alice = *clients.at("alice");
    alice.notify(
        "groupDeleted", server::GroupDeletedEventData{.groupId = groupId, .contextId = CONTEXT}.toJSON(),
        alice.subscribe(alice.api->buildSubscriptionQuery(EventType::GROUP_DELETE, EventSelectorType::CONTEXT_ID, CONTEXT))
    );
    nextEvent("groupDeleted");
    clients.erase("alice");
    bridge.tree = atSeq1.tree;
    EXPECT_THROW(client("alice").getGroup(groupId), GroupHistoryForkException);
}

TEST_F(GroupApiLyingBridge, SECURITY_AListingKeyIsHandedOutAcrossSessionsOnlyAtThePersistedState) {
    // T3-10: base hands out no listing key after a restart (no pin); with the store it does exactly at the pin.
    quiet = true;
    store = std::make_shared<MemoryPinStore>();
    const std::string groupId = createGroup({"alice", "bob", "carol"});
    const Bridge beforeRemoval = bridge;
    client("bob").removeGroupMembers(groupId, {"carol"});
    client("alice").resolveGroupPrivKey(groupId);
    clients.erase("alice");
    const auto listed = [&] { return client("alice").listGroups(CONTEXT, {.skip = 0, .limit = 10, .sortOrder = "asc"}); };
    EXPECT_EQ(listed().readItems.at(0).groupPubKey, bridge.tree.state.grantPublicKey.toBase58DER());
    clients.erase("alice");
    rollBackTo(beforeRemoval);
    EXPECT_TRUE(listed().readItems.at(0).groupPubKey.empty()) << "the key carol holds is not handed out";
}

TEST_F(GroupApiLyingBridge, SECURITY_PinsOfAnotherBridgeAreNotLoaded) {
    // One identity, one store, two Bridges: their slots are apart, so neither Bridge plants or erases the other's pins.
    quiet = true;
    store = std::make_shared<MemoryPinStore>();
    const core::BridgeIdentity a{.url = "https://a.example/api/v2.0", .pubKey = std::nullopt, .instanceId = "A"};
    const core::BridgeIdentity b{.url = "https://a.example/api/v2.0", .pubKey = std::nullopt, .instanceId = "B"};
    bridgeIdentity = a;
    const std::string groupId = createGroup({"alice", "bob"});
    const Bridge atSeq1 = bridge;
    selfUpdateBy("bob");
    client("alice").resolveGroupPrivKey(groupId);
    clients.erase("alice");
    rollBackTo(atSeq1);
    bridgeIdentity = b;
    EXPECT_EQ(client("alice").getGroup(groupId).statusCode, 0) << "a first contact through Bridge B";
    clients.erase("alice");
    bridgeIdentity = a;
    EXPECT_THROW(client("alice").getGroup(groupId), GroupHistoryForkException);
}

TEST_F(GroupApiLyingBridge, ACorruptedStoreStartsTheSessionAsAFirstContact) {
    quiet = true;
    store = std::make_shared<MemoryPinStore>();
    const std::string groupId = createGroup({"alice", "bob"});
    const Bridge atSeq1 = bridge;
    selfUpdateBy("bob");
    client("alice").resolveGroupPrivKey(groupId);
    clients.erase("alice");
    const std::string slot = store->keyWith("group-pins/", "/" + bridge.users.at("alice").getPublicKey().toBase58DER());
    std::string blob = store->get(slot);
    blob[blob.size() / 2] ^= 0x01;
    store->put(slot, blob);
    rollBackTo(atSeq1);
    EXPECT_EQ(client("alice").getGroup(groupId).statusCode, 0);
}

TEST_F(GroupApiLyingBridge, ADisconnectFlushesThePins) {
    // A self-update seen is a minor move (saved once the idle interval has passed); a disconnect saves at once.
    store = std::make_shared<MemoryPinStore>();
    const std::string groupId = createGroup({"alice", "bob"});
    selfUpdateBy("bob");
    client("alice").getGroup(groupId); // seq 2, minor
    EXPECT_EQ(storedPin(groupId, bridge.users.at("alice"))->seq, 1u) << "not before the idle interval";
    clients.at("alice")->connectionImpl->getEventMiddleware()->emitDisconnectedEvent();
    EXPECT_EQ(storedPin(groupId, bridge.users.at("alice"))->seq, 2u);
}

TEST_F(GroupApiLyingBridge, ASelfUpdateStormIsSavedAtTheIdleInterval) {
    // S6: a 16k group self-heals for minutes; each seen self-update must not rewrite the blob.
    store = std::make_shared<MemoryPinStore>();
    const std::string groupId = createGroup({"alice", "bob", "carol"});
    const std::string slot = store->keyWith("group-pins/", "/" + bridge.users.at("alice").getPublicKey().toBase58DER());
    const int before = store->savesOf(slot);
    for (int i = 0; i < 6; ++i) {
        selfUpdateBy(i % 2 == 0 ? "bob" : "carol");
        client("alice").getGroup(groupId); // each call ends at the flush point
    }
    EXPECT_EQ(store->savesOf(slot), before) << "no save before PIN_SAVE_IDLE_INTERVAL";
}

TEST_F(GroupApiLyingBridge, SECURITY_AMajorMoveSeenByAContainerKeyLookupIsSavedBeforeItReturns) {
    // A client that only uses containers resolves group keys and never calls GroupApi: a removal it verified there
    // must be in the store at once, so a session killed right after still refuses the pre-removal state.
    quiet = true;
    store = std::make_shared<MemoryPinStore>();
    const std::string groupId = createGroup({"alice", "bob", "carol"});
    const Bridge beforeRemoval = bridge;
    removalBy("bob", {"carol"});
    client("alice").resolveGroupPrivKey(groupId); // the container path (`_groupPrivKeyResolver`); a new epoch: major
    EXPECT_EQ(storedPin(groupId, bridge.users.at("alice"))->seq, 2u) << "saved before the lookup returned";
    kill("alice");
    rollBackTo(beforeRemoval);
    EXPECT_THROW(client("alice").resolveGroupPrivKey(groupId), GroupHistoryForkException);
}

TEST_F(GroupApiLyingBridge, AdoptPreviousIdentityCarriesThePinsToTheNewKey) {
    // After an identity-key change, Connection::adoptPreviousIdentity right after connect: the previous key's pins
    // keep refusing a rollback; without it the new key starts empty.
    quiet = true;
    store = std::make_shared<MemoryPinStore>();
    const std::string groupId = createGroup({"alice", "bob"});
    const Bridge atSeq1 = bridge;
    selfUpdateBy("bob");
    client("alice").resolveGroupPrivKey(groupId);
    const PrivateKey previous = changeKeyOf(bridge, clients, "alice");
    rollBackTo(atSeq1);
    EXPECT_EQ(GroupApiImplTestAccess::pinnedSeq(client("alice"), groupId), 0u) << "without adoption: nothing";
    clients.erase("alice");
    clients["alice"] = std::make_unique<Client>(bridge, "alice", store, bridgeIdentity, previous);
    GroupApiImplTestAccess::stopDueWork(*clients.at("alice")->api);
    EXPECT_EQ(GroupApiImplTestAccess::pinnedSeq(client("alice"), groupId), 2u);
    EXPECT_THROW(client("alice").getGroup(groupId), GroupHistoryForkException);
    EXPECT_EQ(storedPin(groupId, bridge.users.at("alice"))->seq, 2u) << "carried to the new key's slot";
}

TEST_F(GroupApiLyingBridge, AnAdoptedRecordNeverReplacesAFirstContactPin) {
    // The previous key's slot is writable by whoever holds that key: it only fills groups with no pin.
    quiet = true;
    store = std::make_shared<MemoryPinStore>();
    const std::string groupId = createGroup({"alice", "bob"});
    const Bridge atSeq1 = bridge;
    selfUpdateBy("bob");
    client("alice").resolveGroupPrivKey(groupId);
    const PrivateKey previous = changeKeyOf(bridge, clients, "alice");
    rollBackTo(atSeq1);
    client("alice").getGroup(groupId); // the new key's first contact: seq 1, on trust
    ASSERT_EQ(GroupApiImplTestAccess::pinnedSeq(client("alice"), groupId), 1u);
    client("alice").adoptPreviousIdentity(previous);
    EXPECT_EQ(GroupApiImplTestAccess::pinnedSeq(client("alice"), groupId), 1u) << "the first contact stays";
}

TEST_F(GroupApiLyingBridge, SECURITY_AnAdoptedRecordNeverRaisesAnExistingPin) {
    // The previous key is the one an attacker may hold: with it and the store it can plant records in the previous
    // slot. They never replace or raise a pin verified under the current key.
    quiet = true;
    store = std::make_shared<MemoryPinStore>();
    const std::string groupId = createGroup({"alice", "bob"});
    const PrivateKey previous = changeKeyOf(bridge, clients, "alice");
    selfUpdateBy("bob");
    client("alice").getGroup(groupId); // seq 2 under the new key
    clients.erase("alice");            // saved; the next session loads it (not a first contact)
    TreeVerifier::PinSet planted;
    TreeVerifier::Pin pin = storedPin(groupId, bridge.users.at("alice")).value();
    pin.seq = 9;
    pin.digest = std::string(32, 'p');
    planted.tree[groupId] = pin;
    planted.planes[groupId] = {99, 99, 99};
    const std::array<std::int64_t, 3> versionsBefore = GroupApiImplTestAccess::versionPins(client("alice"), groupId);
    const std::string current = store->keyWith("group-pins/", "/" + bridge.users.at("alice").getPublicKey().toBase58DER());
    const std::string previousSlot = current.substr(0, current.rfind('/') + 1) + previous.getPublicKey().toBase58DER();
    store->put(previousSlot, core::sealLocal(previous, PinBlob::LABEL, PinBlob::VERSION, previousSlot, PinBlob::encode(planted)));
    client("alice").adoptPreviousIdentity(previous);
    EXPECT_EQ(GroupApiImplTestAccess::pinnedSeq(client("alice"), groupId), 2u);
    EXPECT_EQ(storedPin(groupId, bridge.users.at("alice"))->seq, 2u) << "the current slot is not raised";
    EXPECT_EQ(GroupApiImplTestAccess::versionPins(client("alice"), groupId), versionsBefore) << "nor the version pins";
    EXPECT_EQ(client("alice").getGroup(groupId).statusCode, 0);
}

TEST_F(GroupApiLyingBridge, SECURITY_AnAdoptedRecordIsAHintNotAVerifiedState) {
    // M4: the thief of alice's previous key writes its slot: her real record for the group, but with a grant key of
    // its own and a lost-race seq that would block every commit. Adopted for a group with no pin, it must hand out no
    // grant key and keep no lost-race seq: only seq and digest, which the next read checks.
    quiet = true;
    store = std::make_shared<MemoryPinStore>();
    const std::string groupId = createGroup({"alice", "bob"});
    const PrivateKey previous = changeKeyOf(bridge, clients, "alice");
    const std::string thiefKey = PrivateKey::generateRandom().getPublicKey().toBase58DER();
    TreeVerifier::PinSet planted;
    TreeVerifier::Pin pin = storedPin(groupId, previous).value();
    pin.keyVersion = 7;
    pin.groupPubKey = thiefKey;
    pin.refusedSeq = 1000;
    planted.tree[groupId] = pin;
    const std::string slot = store->keyWith("group-pins/", "/" + previous.getPublicKey().toBase58DER());
    store->put(slot, core::sealLocal(previous, PinBlob::LABEL, PinBlob::VERSION, slot, PinBlob::encode(planted)));
    GroupApiImpl& alice = clientAdopting("alice", previous);
    EXPECT_EQ(GroupApiImplTestAccess::pinnedSeq(alice, groupId), 1u) << "the hint still refuses what lies below it";
    EXPECT_EQ(alice.pinnedKeyVersion(groupId), 0u);
    EXPECT_FALSE(alice.agreesWithPin(groupId, CONTEXT, 7, thiefKey));
    EXPECT_EQ(storedPin(groupId, bridge.users.at("alice"))->refusedSeq, 0u) << "the lost-race seq was adopted";
    Client& session = *clients.at("alice");
    GrantingModule module(
        session.connectionImpl->getUserPrivKey(), session.connectionImpl->getKeyProvider(), "",
        session.connectionImpl->getEventMiddleware(), session.connection, session.groupApi
    );
    std::vector<core::GroupGrantWithKey> grants{{.groupId = groupId, .role = "user", .groupPubKey = thiefKey, .groupEpoch = 7}};
    std::unordered_map<std::string, core::GroupEpochInfo> cache;
    module.resolveGroupEpochs(CONTEXT, grants, cache);
    EXPECT_EQ(grants.at(0).groupPubKey, bridge.tree.state.grantPublicKey.toBase58DER()) << "wrapped to the thief's key";
    EXPECT_EQ(grants.at(0).groupEpoch, 1);
    EXPECT_TRUE(alice.agreesWithPin(groupId, CONTEXT, 1, bridge.tree.state.grantPublicKey.toBase58DER()))
        << "the read that checked the hint pins the group";
}

TEST_F(GroupApiLyingBridge, SECURITY_ACorruptedPreviousIdentityBlobAbortsTheAdoption) {
    quiet = true;
    store = std::make_shared<MemoryPinStore>();
    const std::string groupId = createGroup({"alice", "bob"});
    selfUpdateBy("bob");
    client("alice").resolveGroupPrivKey(groupId);
    const PrivateKey previous = bridge.users.at("alice");
    clients.erase("alice");
    const std::string slot = store->keyWith("group-pins/", "/" + previous.getPublicKey().toBase58DER());
    const std::string good = store->get(slot);
    std::string bad = good;
    bad[bad.size() / 2] ^= 0x01;
    store->put(slot, bad);
    changeKeyOf(bridge, clients, "alice");
    EXPECT_THROW(client("alice").adoptPreviousIdentity(previous), core::LocalStateIntegrityException);
    EXPECT_EQ(GroupApiImplTestAccess::pinnedSeq(client("alice"), groupId), 0u) << "nothing adopted";
    EXPECT_TRUE(clients.at("alice")->connectionImpl->previousIdentities().empty()) << "the key recorded all the same";
    EXPECT_THROW(
        Client(bridge, "alice", store, bridgeIdentity, previous), core::LocalStateIntegrityException
    ) << "nor through the connection";
    store->put(slot, good);
    client("alice").adoptPreviousIdentity(previous);
    EXPECT_EQ(GroupApiImplTestAccess::pinnedSeq(client("alice"), groupId), 2u) << "a retry once the slot is fixed";
}

TEST_F(GroupApiLyingBridge, SECURITY_ARenewalAdoptsThePreviousKeysPinsFirst) {
    // 08a + 01: an app that skipped Connection::adoptPreviousIdentity still renews on the previous key's pins, so the
    // renewal is never planned on a state rolled back below what the previous key verified (base: it is).
    quiet = true;
    store = std::make_shared<MemoryPinStore>();
    const std::string groupId = createGroup({"alice", "bob", "carol"});
    const Bridge atSeq1 = bridge;
    selfUpdateBy("carol");
    client("bob").resolveGroupPrivKey(groupId); // pins seq 2 under bob's previous key
    clients.erase("bob");
    const PrivateKey previous = changeKeyOf(bridge, clients, "bob");
    rollBackTo(atSeq1);
    EXPECT_THROW(client("bob").renewLeaf(groupId, previous.toWIF()), GroupHistoryForkException);
    EXPECT_EQ(sent(bridge), 0u);
}

TEST_F(GroupApiLyingBridge, SECURITY_AdoptionNeverLowersAFirstContactToTheOlderRecord) {
    // bob's previous key pinned seq 1. Under the new key his first contact is alice's removal of carol (seq 3); then
    // the bridge serves the state before it (seq 2, carol's self-update), which continues seq 1. renewLeaf adopts
    // first: the older record must not replace the first contact. Base: it did, so seq 2 passed and the renewal was
    // planned and sent on a tree that still seats carol.
    quiet = true;
    store = std::make_shared<MemoryPinStore>();
    const std::string groupId = createGroup({"alice", "bob", "carol"});
    client("bob").resolveGroupPrivKey(groupId); // seq 1 under bob's previous key
    clients.erase("bob");
    const PrivateKey previous = changeKeyOf(bridge, clients, "bob");
    selfUpdateBy("carol"); // seq 2
    const Bridge beforeRemoval = bridge;
    client("alice").removeGroupMembers(groupId, {"carol"}); // seq 3
    client("bob").getGroup(groupId);                       // the new key's first contact
    ASSERT_EQ(GroupApiImplTestAccess::pinnedSeq(client("bob"), groupId), 3u);
    rollBackTo(beforeRemoval);
    const std::size_t before = sent(bridge);
    EXPECT_ANY_THROW(client("bob").renewLeaf(groupId, previous.toWIF()));
    EXPECT_EQ(sent(bridge), before) << "nothing planned on the pre-removal state";
    EXPECT_EQ(GroupApiImplTestAccess::pinnedSeq(client("bob"), groupId), 3u);
    const auto stored = storedPin(groupId, bridge.users.at("bob"));
    EXPECT_TRUE(!stored.has_value() || stored->seq == 3u) << "the slot is not lowered either";
}

TEST_F(GroupApiLyingBridge, AFirstContactAboveThePreviousKeysRecordStaysUsable) {
    // The same with an honest bridge: adoption leaves the first contact (seq 3) as it is, so the renewal and the reads
    // after it go on at seq 3.
    quiet = true;
    store = std::make_shared<MemoryPinStore>();
    const std::string groupId = createGroup({"alice", "bob", "carol"});
    client("bob").resolveGroupPrivKey(groupId);
    clients.erase("bob");
    const PrivateKey previous = changeKeyOf(bridge, clients, "bob");
    selfUpdateBy("carol");
    client("alice").removeGroupMembers(groupId, {"carol"});
    client("bob").getGroup(groupId);
    EXPECT_NO_THROW(client("bob").renewLeaf(groupId, previous.toWIF()));
    EXPECT_EQ(GroupApiImplTestAccess::pinnedSeq(client("bob"), groupId), 3u);
    EXPECT_EQ(client("bob").getGroup(groupId).statusCode, 0);
    ASSERT_TRUE(GroupApiImplTestAccess::savePins(client("bob")));
    EXPECT_EQ(storedPin(groupId, bridge.users.at("bob"))->seq, 3u);
}
