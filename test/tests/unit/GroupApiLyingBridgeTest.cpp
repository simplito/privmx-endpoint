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

#include "TreeFakeBridge.hpp"

namespace privmx::endpoint::group {
// What the wiring tests reach inside GroupApiImpl (a friend of it).
struct GroupApiImplTestAccess {
    static void selfUpdate(GroupApiImpl& api, const std::string& groupId) { api.selfUpdate(groupId); }
    // The destructor's own first steps: no background self-update is scheduled or run from here on, so what a test
    // counts never depends on the worker's random delay. Self-updates are then only the explicit `selfUpdate` above.
    static void stopBackgroundSelfUpdates(GroupApiImpl& api) {
        std::lock_guard<std::mutex> lock(api._selfUpdateMutex);
        api._selfUpdateStopping = true;
        api._selfUpdatePending.clear();
        api._selfUpdateWake.notify_all();
    }
    // As if the call that released the group's unresolved commit ran `ms` earlier: no clock to move in a unit test.
    static void ageUnresolved(GroupApiImpl& api, const std::string& groupId, std::uint64_t ms) {
        std::lock_guard<std::mutex> lock(api._unresolvedMutex);
        api._unresolved.at(groupId).date -= ms;
    }
};
} // namespace privmx::endpoint::group

namespace core = privmx::endpoint::core;
using privmx::crypto::PublicKey;
using privmx::endpoint::group::GroupApiImplTestAccess;

namespace {

const std::string CONTEXT = "ctx-lying";

Poco::JSON::Object::Ptr overTheWire(const Poco::Dynamic::Var& value) {
    return privmx::utils::Utils::parseJsonObject(privmx::utils::Utils::stringifyVar(value));
}

privmx::utils::PrivmxException archiveInvalid() {
    return privmx::utils::PrivmxException("GROUP_ARCHIVE_INVALID", privmx::utils::PrivmxException::RPC, 0x621F);
}

// One group's bridge, shared by every client. Every request is answered under one lock (`sync`), so the clients'
// threads and their background workers never interleave inside it; a test touching the bridge while one may run takes
// it too. A copy shares the lock and never answers.
struct Bridge {
    struct Sync {
        std::mutex m;
        std::condition_variable cv; // notified on every plan read
    };
    std::shared_ptr<Sync> sync = std::make_shared<Sync>();
    std::map<std::string, PrivateKey> users; // the Context user list
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
    // Every statement a client sent with an add, a removal, a rotation or a self-update, in order, applied or not.
    std::vector<server::GroupTreeCommit> received;
    int planReads = 0; // `groupGet`s in the "plan" scope
    std::function<void(server::GroupInfo&)> onPlanRead = [](server::GroupInfo&) {}; // edits what a plan read serves
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
        info.creator = rest.creator;
        info.createDate = info.lastModificationDate = 1;
        info.data = rest.data;
        info.history = rest.history;
        info.managers = {};
        info.groupKeys = rest.groupKeys;
        info.publicMeta = rest.publicMeta;
        info.privateMeta = rest.privateMeta;
        info.publicMetaVersion = rest.publicMetaVersion;
        info.privateMetaVersion = rest.privateMetaVersion;
        info.policy = Poco::JSON::Object::Ptr(new Poco::JSON::Object());
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

    Poco::Dynamic::Var answer(const std::string& caller, const std::string& method, Poco::JSON::Object::Ptr params) {
        std::unique_lock<std::mutex> lock(sync->m);
        calls.push_back({caller, method, params});
        const std::string group = method.substr(std::string("context.").size());
        if (method == "context.contextGet") {
            return core::server::ContextGetResult{.context = {.userId = caller, .contextId = CONTEXT}}.toJSON();
        }
        if (method == "context.contextListUsers") {
            core::server::ContextListUsersResult result;
            for (const auto& [id, key] : users) {
                core::server::UserIdentityWithStatusAndAction user;
                user.id = id;
                user.pub = key.getPublicKey().toBase58DER();
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
            tree.create(model.tree, PublicKey::fromBase58DER(model.groupPubKey), caller, model.commit);
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
                     TreeKeys::choosePositions(tree.state, static_cast<std::uint32_t>(model.forNewMembers.value()))) {
                    seats.push_back(seat);
                }
                info.nextFreeSeats = seats;
            }
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
            for (const server::GroupAddMemberEntry& member : model.members) {
                ids.push_back(member.userId);
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
                CommitOp::Add, caller, ids, positions, refreshed, model.transition.edges, std::nullopt, model.commit
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
        if (group == "groupUpdatePublicMeta" || group == "groupUpdatePrivateMeta") {
            const auto model = server::GroupUpdatePublicMetaModel::fromJSON(params);
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
    Gateway(Bridge& bridge, const std::string& userId)
        : RpcGateway(privmx::rpc::AuthorizedConnection::Ptr(), std::nullopt), _bridge(bridge), _userId(userId) {}

    Poco::Dynamic::Var request(
        const std::string& method,
        Poco::JSON::Object::Ptr params,
        privmx::rpc::MessageSendOptionsEx,
        privmx::utils::CancellationToken::Ptr
    ) override {
        const Poco::Dynamic::Var result = _bridge.answer(_userId, method, overTheWire(params));
        return result.isEmpty() ? result : Poco::Dynamic::Var(overTheWire(result));
    }
    bool isConnected() override { return true; }

private:
    Bridge& _bridge;
    std::string _userId;
};

// The application's: each user's real key, nobody else's.
class Verifier : public core::UserVerifierInterface {
public:
    explicit Verifier(const Bridge& bridge) : _bridge(bridge) {}
    std::vector<bool> verify(const std::vector<core::VerificationRequest>& requests) override {
        ++*_bridge.verifierCalls;
        std::vector<bool> verified;
        for (const auto& request : requests) {
            const auto user = _bridge.users.find(request.senderId);
            verified.push_back(
                user != _bridge.users.end() && user->second.getPublicKey().toBase58DER() == request.senderPubKey
            );
        }
        return verified;
    }

private:
    const Bridge& _bridge;
};

struct ConnectionOf : core::Connection {
    explicit ConnectionOf(const std::shared_ptr<core::ConnectionImpl>& impl) { _ptr = impl; }
};

struct Client {
    std::shared_ptr<core::ConnectionImpl> connectionImpl = std::make_shared<core::ConnectionImpl>();
    core::Connection connection;
    GroupApi groupApi;
    std::shared_ptr<GroupApiImpl> api;

    Client(Bridge& bridge, const std::string& userId) {
        connectionImpl->setUserVerifier(std::make_shared<Verifier>(bridge));
        connectionImpl->connectOver(new Gateway(bridge, userId), bridge.users.at(userId));
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

// The next event of `type` from the shared queue; the others are dropped.
core::EventHolder nextEvent(const std::string& type) {
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(10);
    while (std::chrono::steady_clock::now() < deadline) {
        if (const auto event = core::EventQueueImpl::getInstance()->getEvent(); event.has_value()) {
            if (event->type() == type) {
                return event.value();
            }
            continue;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }
    throw std::runtime_error("no " + type + " event");
}

// A statement exactly as sent, for byte-for-byte comparisons.
std::string bytesOf(const server::GroupTreeCommit& commit) {
    return commit.serialize();
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
    bool quiet = false; // every client's background self-updates stopped as it is created

    void SetUp() override {
        for (const std::string id : {"alice", "bob", "carol"}) {
            bridge.users.emplace(id, PrivateKey::generateRandom());
        }
        core::EventQueueImpl::getInstance()->clear();
    }

    void TearDown() override { clients.clear(); }

    // Polls `done` under the fixture lock until it holds or `timeout` passes; whether it held.
    bool waitUntil(const std::function<bool()>& done, std::chrono::milliseconds timeout = std::chrono::seconds(5)) {
        const auto deadline = std::chrono::steady_clock::now() + timeout;
        for (;;) {
            {
                std::unique_lock<std::mutex> guard(bridge.sync->m);
                if (done()) {
                    return true;
                }
            }
            if (std::chrono::steady_clock::now() > deadline) {
                return false;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(20));
        }
    }

    std::size_t count(const std::string& caller, const std::string& method) {
        std::unique_lock<std::mutex> guard(bridge.sync->m);
        return bridge.count(caller, method);
    }

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
            client = std::make_unique<Client>(bridge, userId);
            if (quiet) {
                GroupApiImplTestAccess::stopBackgroundSelfUpdates(*client->api);
            }
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

    std::string createGroup(const std::vector<std::string>& members) {
        std::vector<core::UserWithPubKey> users;
        for (const auto& id : members) {
            users.push_back(user(id));
        }
        return client("alice").createGroup(
            CONTEXT, users, {}, core::Buffer::from("public"), core::Buffer::from("private"), std::nullopt
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
        keys.setMemberKeys(members);
        const CommitPlan plan = keys.planSelfUpdate(served, committer, priv);
        const auto wire = TreeWire::toSelfUpdateTransition(plan, bridge.tree.state.epoch);
        CommitStatement statement = TreeCommits::statementFor(
            plan, CommitOp::SelfUpdate, bridge.tree.groupId,
            date.value_or(static_cast<std::uint64_t>(privmx::utils::Utils::getNowTimestamp())), bridge.tree.state.epoch,
            bridge.tree.state.grantPublicKey.toBase58DER(),
            static_cast<std::uint64_t>(bridge.tree.rosterVersion), seatedIn(bridge.tree.state), {}, committer, {}, {},
            {}
        );
        statement.prevDigest = TreeCommits::digest(TreeCommits::fromWire(bridge.tree.commits.back()));
        TreeCommits::sign(statement, priv);
        bridge.tree.commit(
            CommitOp::SelfUpdate, committer, {}, {}, wire.refreshedNodes, wire.edges, std::nullopt,
            TreeCommits::toWire(statement)
        );
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
        plan.grantKey.getPublicKey().toBase58DER(), 1, {"alice", "bob"}, {}, "bob", {}, {}, {}
    );
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
// test stops the background self-updates (`quiet`), so `received` holds only what the test's own calls sent.

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
    EXPECT_EQ(bytesOf(bridge.received[1]), bytesOf(bridge.received[0])) << "the retry signed a new statement at seq 2";
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
    EXPECT_EQ(bytesOf(bridge.received[1]), bytesOf(bridge.received[0])) << "carol's removal resent first";
    EXPECT_EQ(prevOf(bridge.received[2]), digestOf(bridge.received[0])) << "bob's removal extends it";
}

TEST_F(GroupApiLyingBridge, SECURITY_ADifferentCommitIsRefusedWhileTheUnresolvedOneKeepsBeingRefused) {
    quiet = true;
    const std::string groupId = createGroup({"alice", "bob", "carol"});
    const Bridge atSeq1 = bridge;
    const std::string atP = digestOf(bridge.tree.commits.back());
    bridge.afterRemoval = [&] {
        rollBackTo(atSeq1);
        refuse();
    };
    EXPECT_ANY_THROW(client("alice").removeGroupMembers(groupId, {"carol"}));
    try {
        client("alice").removeGroupMembers(groupId, {"bob"});
        ADD_FAILURE() << "a second removal was let through";
    } catch (const GroupCommitUnresolvedException& e) {
        EXPECT_NE(e.getDescription().find("remove"), std::string::npos) << e.getDescription();
    } catch (...) { ADD_FAILURE() << "not GroupCommitUnresolvedException"; }
    ASSERT_FALSE(bridge.received.empty());
    for (const server::GroupTreeCommit& commit : bridge.received) {
        if (prevOf(commit) == atP) {
            EXPECT_EQ(bytesOf(commit), bytesOf(bridge.received[0])) << "a second statement at seq 2";
        }
    }
}

TEST_F(GroupApiLyingBridge, SECURITY_TwoCommitsOfOneClientToOneGroupNeverShareAPrevDigest) {
    // Two threads of one client, one removal each. The first to reach the bridge waits there until the other has read
    // the same head; that one must not release a statement at it.
    quiet = true;
    addUsers({"dave"});
    const std::string groupId = createGroup({"alice", "bob", "carol", "dave"});
    GroupApiImpl& alice = client("alice");
    const int readsBefore = bridge.planReads;
    bool waited = false;
    bridge.beforeRemoval = [&](std::unique_lock<std::mutex>& lock) {
        if (std::exchange(waited, true)) {
            return;
        }
        bridge.sync->cv.wait_for(lock, std::chrono::seconds(1), [&] { return bridge.planReads >= readsBefore + 2; });
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
    EXPECT_EQ(failures.load(), 0);
    std::set<std::string> prevDigests;
    for (const server::GroupTreeCommit& commit : bridge.received) {
        prevDigests.insert(prevOf(commit));
    }
    EXPECT_EQ(prevDigests.size(), bridge.received.size()) << "two statements at one prevDigest";
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
    EXPECT_EQ(bytesOf(bridge.received[1]), bytesOf(bridge.received[0])) << "carol's removal resent first";
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
    EXPECT_EQ(bytesOf(bridge.received[1]), bytesOf(bridge.received[0])) << "the retry signed a new rotation";
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
    GroupApiImplTestAccess::ageUnresolved(client("alice"), groupId, GroupApiImpl::RELEASE_WINDOW_MS);
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
    EXPECT_EQ(bytesOf(bridge.received[1]), bytesOf(bridge.received[0])) << "the unresolved removal is resent first";
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
    EXPECT_EQ(bytesOf(bridge.received[1]), bytesOf(bridge.received[0])) << "a second self-update at one prevDigest";
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
    EXPECT_THROW(client("alice").removeGroupMembers(groupId, {"carol"}), GroupCommitUnresolvedException);
    const auto adds = std::count_if(bridge.received.begin(), bridge.received.end(), [](const auto& commit) {
        return TreeCommits::fromWire(commit).op == CommitOp::Add;
    });
    EXPECT_EQ(adds, 1) << "the add was resent to a key the verifier no longer vouches for";
}

// ── repair rungs (L-1) ───────────────────────────────────────────────────────────────────────────────────────────

TEST_F(GroupApiLyingBridge, SECURITY_AMemberHoldingThePreviousKeyRepairsABrokenUnitRung) {
    // A broken unit rung (2,1) cuts epoch 1 off for everybody not holding it in session memory. Bob holds it, and
    // repairs the rung in the background once he sees the rotation; a fresh session of carol's then reads epoch 1.
    const std::string groupId = groupAtEpoch2WithBobHoldingEpoch1();
    corrupt(2, 1);
    client("bob").resolveGroupPrivKey(groupId);
    ASSERT_TRUE(waitUntil([&] { return bridge.count("bob", "context.groupRepairRung") == 1; }));
    const PrivateKey epoch1 = client("carol").resolveGroupPrivKey(groupId, 1);
    EXPECT_EQ(epoch1.getPublicKey().toBase58DER(), bridge.rest.history.at(0).groupPubKey);
}

TEST_F(GroupApiLyingBridge, ARepairIsNotSentWhenTheLadderIsIntact) {
    // The honest path costs one archive fetch per observed rotation: no statements read, no UserVerifier call.
    const std::string groupId = groupAtEpoch2WithBobHoldingEpoch1();
    client("bob").resolveGroupPrivKey(groupId);
    const int verified = bridge.verifierCalls->load();
    const std::size_t commitReads = count("bob", "context.groupGetTreeCommits");
    ASSERT_TRUE(waitUntil([&] { return bridge.count("bob", "context.groupGetKeyArchive") >= 1; }));
    std::this_thread::sleep_for(std::chrono::milliseconds(300));
    EXPECT_EQ(count("bob", "context.groupGetKeyArchive"), 1u);
    EXPECT_EQ(count("bob", "context.groupRepairRung"), 0u);
    EXPECT_EQ(count("bob", "context.groupGetTreeCommits"), commitReads);
    EXPECT_EQ(bridge.verifierCalls->load(), verified);
}

TEST_F(GroupApiLyingBridge, SECURITY_AClientRefusesToCommitARungThatDoesNotOpenToTheChain) {
    // A wrong key in the remover's cache (a client bug) would be sealed into a skip rung no later commit can replace.
    bridge.users.emplace("dave", PrivateKey::generateRandom());
    bridge.users.emplace("erin", PrivateKey::generateRandom());
    const std::string groupId = createGroup({"alice", "bob", "carol", "dave", "erin"});
    client("alice").removeGroupMembers(groupId, {"dave"});
    client("alice").removeGroupMembers(groupId, {"erin"});
    ASSERT_EQ(LadderKeys::requiredSkipTargets(4, 1), std::vector<std::uint32_t>{2});
    const auto cache = client("alice").keyCacheOf(groupId);
    ASSERT_TRUE(cache->getGrantKey(2).has_value());
    cache->putGrantKey(2, PrivateKey::generateRandom());
    const std::size_t removals = count("alice", "context.groupRemoveMembers");
    EXPECT_THROW(client("alice").removeGroupMembers(groupId, {"carol"}), GroupDataIntegrityException);
    EXPECT_EQ(count("alice", "context.groupRemoveMembers"), removals) << "nothing submitted";
    EXPECT_FALSE(cache->getGrantKey(2).has_value()) << "forgotten, to be re-gathered by a verified descent";
    client("alice").removeGroupMembers(groupId, {"carol"});
    EXPECT_EQ(bridge.tree.state.epoch, 4u);
}

TEST_F(GroupApiLyingBridge, SECURITY_ARepairNeverSealsAKeyTheChainDoesNotName) {
    bridge.users.emplace("dave", PrivateKey::generateRandom());
    const std::string groupId = createGroup({"alice", "bob", "carol", "dave"});
    client("bob").resolveGroupPrivKey(groupId);
    const auto cache = client("bob").keyCacheOf(groupId);
    cache->putGrantKey(1, PrivateKey::generateRandom()); // a client bug: not epoch 1's key
    client("alice").removeGroupMembers(groupId, {"dave"});
    corrupt(2, 1);
    client("bob").resolveGroupPrivKey(groupId);
    ASSERT_TRUE(waitUntil([&] { return !cache->getGrantKey(1).has_value(); })) << "checked against the chain, forgotten";
    std::this_thread::sleep_for(std::chrono::milliseconds(300));
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
    client("bob").keyCacheOf(groupId)->putGrantKey(1, client("alice").keyCacheOf(groupId)->getGrantKey(1).value());
    EXPECT_ANY_THROW(client("bob").resolveGroupPrivKey(groupId, 1)); // finds (2,1) broken, queues a check
    ASSERT_TRUE(waitUntil([&] { return bridge.count("bob", "context.groupGetKeyArchive") >= 3; })) << "the check ran";
    std::this_thread::sleep_for(std::chrono::milliseconds(300));
    EXPECT_EQ(count("bob", "context.groupRepairRung"), 0u);
}

TEST_F(GroupApiLyingBridge, DestroyingAClientWithAQueuedLadderCheckJoinsCleanly) {
    const std::string groupId = groupAtEpoch2WithBobHoldingEpoch1();
    client("bob").resolveGroupPrivKey(groupId); // a check is now queued, due within a second
    clients.erase("bob");
    const std::size_t archiveReads = count("bob", "context.groupGetKeyArchive");
    std::this_thread::sleep_for(std::chrono::milliseconds(1500));
    EXPECT_EQ(count("bob", "context.groupGetKeyArchive"), archiveReads) << "nothing runs after destruction";
}

TEST_F(GroupApiLyingBridge, SECURITY_ARotationRefusesToCommitARungThatDoesNotOpenToTheChain) {
    // rotateGroupKey seals skip rungs exactly like a removal, so it goes through the same self-check.
    const std::string groupId = createGroup({"alice", "bob", "carol"});
    client("alice").rotateGroupKey(groupId);
    client("alice").rotateGroupKey(groupId);
    ASSERT_EQ(LadderKeys::requiredSkipTargets(4, 1), std::vector<std::uint32_t>{2});
    const auto cache = client("alice").keyCacheOf(groupId);
    ASSERT_TRUE(cache->getGrantKey(2).has_value());
    cache->putGrantKey(2, PrivateKey::generateRandom());
    const std::size_t rotations = count("alice", "context.groupGenerateNewKey");
    EXPECT_THROW(client("alice").rotateGroupKey(groupId), GroupDataIntegrityException);
    EXPECT_EQ(count("alice", "context.groupGenerateNewKey"), rotations) << "nothing submitted";
    EXPECT_FALSE(cache->getGrantKey(2).has_value()) << "forgotten, to be re-gathered by a verified descent";
    client("alice").rotateGroupKey(groupId);
    EXPECT_EQ(bridge.tree.state.epoch, 4u);
}

TEST_F(GroupApiLyingBridge, ARotatorDoesNotCheckTheLadderOfItsOwnEpoch) {
    // Its rungs passed the self-check before submitting, as a remover's do: nothing for the observed-rotation check.
    const std::string groupId = createGroup({"alice", "bob", "carol"});
    client("alice").resolveGroupPrivKey(groupId);
    client("alice").rotateGroupKey(groupId);
    client("alice").resolveGroupPrivKey(groupId);
    std::this_thread::sleep_for(std::chrono::milliseconds(1500)); // past a small group's 1 s check window
    EXPECT_EQ(count("alice", "context.groupGetKeyArchive"), 0u);
}
