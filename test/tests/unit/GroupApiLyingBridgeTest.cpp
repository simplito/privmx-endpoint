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
#include <privmx/endpoint/group/keytree/TreeKeys.hpp>
#include <privmx/privfs/gateway/RpcGateway.hpp>

#include "TreeFakeBridge.hpp"

namespace core = privmx::endpoint::core;
using privmx::crypto::PublicKey;

namespace {

const std::string CONTEXT = "ctx-lying";

Poco::JSON::Object::Ptr overTheWire(const Poco::Dynamic::Var& value) {
    return privmx::utils::Utils::parseJsonObject(privmx::utils::Utils::stringifyVar(value));
}

// One group's bridge, shared by every client.
struct Bridge {
    std::map<std::string, PrivateKey> users; // the Context user list
    FakeBridge tree;
    server::GroupInfo rest; // everything but the tree, as sent
    std::vector<std::pair<std::string, server::GroupSendCustomEventModel>> events; // (sender, as sent)
    std::function<void()> afterRemoval = [] {};

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
            return server::GroupGetResult{.group = serve(caller, model.scope == std::optional<std::string>("plan"))}
                .toJSON();
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
        if (group == "groupRemoveMembers") {
            const auto model = server::GroupRemoveMembersModel::fromJSON(params);
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
            tree.rotate(caller, model.grantEdge, PublicKey::fromBase58DER(model.groupPubKey), model.commit);
            storeNewEpoch(caller, model);
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

    void SetUp() override {
        for (const std::string id : {"alice", "bob", "carol"}) {
            bridge.users.emplace(id, PrivateKey::generateRandom());
        }
        core::EventQueueImpl::getInstance()->clear();
    }

    void TearDown() override { clients.clear(); }

    GroupApiImpl& client(const std::string& userId) {
        auto& client = clients[userId];
        if (!client) {
            client = std::make_unique<Client>(bridge, userId);
        }
        return *client->api;
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
