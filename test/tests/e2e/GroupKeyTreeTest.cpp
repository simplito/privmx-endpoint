#include <gtest/gtest.h>
#include <algorithm>
#include "BaseGroupTest.hpp"
#include <Poco/Util/IniFileConfiguration.h>
#include <privmx/endpoint/core/BackendRequester.hpp>
#include <privmx/endpoint/core/Connection.hpp>
#include <privmx/endpoint/core/ConnectionImpl.hpp>
#include <privmx/endpoint/core/CoreException.hpp>
#include <privmx/endpoint/core/EventQueueImpl.hpp>
#include <privmx/endpoint/core/Exception.hpp>
#include <privmx/endpoint/core/VarSerializer.hpp>
#include <privmx/endpoint/group/GroupApi.hpp>
#include <privmx/endpoint/group/GroupApiImpl.hpp>
#include <privmx/endpoint/group/GroupException.hpp>
#include <privmx/endpoint/group/VarSerializer.hpp>
#include <privmx/endpoint/group/keytree/LadderKeys.hpp>
#include <privmx/endpoint/group/keytree/TreeCommits.hpp>
#include <privmx/endpoint/thread/ThreadApi.hpp>
#include <privmx/crypto/ecc/PrivateKey.hpp>
#include <privmx/crypto/ecc/PublicKey.hpp>
#include <privmx/crypto/utils/Base58.hpp>
#include <privmx/utils/PrivmxException.hpp>
#include <privmx/utils/Utils.hpp>

using namespace privmx::endpoint;

/**
 * End-to-end tests for tree-backed groups, against a running bridge.
 *
 * The unit tests on either side each check one half of the contract: this client builds a state, the server
 * decides whether it is well-formed, and the conformance fixture proves the two agree on paper. What none of them
 * can show is that the whole round trip works - that a member removed here is really no longer served content
 * written afterwards, and that a member added later really can reach content written before they existed. That
 * needs a server, so it lives here.
 *
 * Tests named SECURITY assert that somebody *cannot* do something. They fail silently at runtime if the guard
 * regresses - nothing breaks, access simply persists where it should have ended - so they must not be deleted or
 * weakened into positive assertions.
 */


class GroupKeyTreeTest : public privmx::test::BaseGroupTest {
protected:
    void setUpModuleApis() override {
        threadApi = std::make_shared<thread::ThreadApi>(thread::ThreadApi::create(*connection, *groupApi));
    }

    void tearDownModuleApis() override {
        threadApi.reset();
    }

    // A tree-backed group with user_1 managing and the given users as members.
    std::string createTreeGroup(const std::vector<core::UserWithPubKey>& members) {
        return groupApi->createGroup(
            contextId(), members, std::vector<core::UserWithPubKey>{user(1)},
            core::Buffer::from("keytree_public"), core::Buffer::from("keytree_private")
        );
    }

    // A thread whose content key is wrapped to the group, so group membership decides who can read it.
    // `forwardSecrecy = "yes"` is what makes the bridge refuse content written under a superseded group epoch.
    std::string createThreadGrantedTo(const group::Group& group, const std::string& forwardSecrecy = "no") {
        core::ContainerPolicy policy;
        policy.get = "all";
        policy.forwardSecrecy = forwardSecrecy;
        policy.item = core::ItemPolicy{.get = "all", .listAll = "all"};
        return threadApi->createThread(
            contextId(),
            std::vector<core::UserWithPubKey>{user(1)},
            std::vector<core::UserWithPubKey>{user(1)},
            core::Buffer::from("kt_thread_public"),
            core::Buffer::from("kt_thread_private"),
            policy,
            std::vector<core::GroupGrantWithKey>{{
                .groupId = group.groupId,
                .role = "user",
                .groupPubKey = group.groupPubKey,
                .groupEpoch = group.keyVersion
            }}
        );
    }

    // As `createThreadGrantedTo`, with forward secrecy on and user_2 able to write but not to re-key: a caller
    // who may re-key never sees the stale window, because `sendMessage` repairs the key and retries.
    std::string createThreadGrantedToWithManagerOnlyRekey(const group::Group& group) {
        core::ContainerPolicy policy;
        policy.get = "all";
        policy.forwardSecrecy = "yes";
        policy.rotateKeys = "manager";
        policy.item = core::ItemPolicy{.get = "all", .listAll = "all"};
        return threadApi->createThread(
            contextId(),
            std::vector<core::UserWithPubKey>{user(1), user(2)},
            std::vector<core::UserWithPubKey>{user(1)},
            core::Buffer::from("kt_thread_public"),
            core::Buffer::from("kt_thread_private"),
            policy,
            std::vector<core::GroupGrantWithKey>{{
                .groupId = group.groupId,
                .role = "user",
                .groupPubKey = group.groupPubKey,
                .groupEpoch = group.keyVersion
            }}
        );
    }

    // A removal sent straight to the Bridge, valid in shape only. The Bridge checks the new key (reuse, encoding)
    // before it reads the transition or the statement's content, so the refusal text says which check fired.
    // "" = accepted. The unit rung `k+1 -> k` alone is the whole rung set at epoch 1 or right after a cut to `k`,
    // the only states it is called in.
    std::string rawRemovalRefusal(const std::string& groupId, const std::string& userId, const std::string& groupPubKey) {
        group::ServerApi api(connection->getImpl()->getGateway());
        const auto current = api.groupGet({.groupId = groupId, .scope = std::string("plan")}).group;
        const auto statement = nextStatement(api, groupId, groupPubKey);
        group::server::GroupRemoveMembersModel model;
        model.id = groupId;
        model.userIds = {userId};
        model.groupPubKey = groupPubKey;
        model.keyId = "m3-raw";
        model.data = Poco::Dynamic::Var(std::string("x"));
        model.transition = {.baseKeyVersion = current.keyVersion, .blankedPositions = {}, .refreshedNodes = {}, .edges = {}};
        model.rungs = {{.atKeyVersion = current.keyVersion + 1, .targetKeyVersion = current.keyVersion, .data = "x"}};
        model.expectedKeyVersion = current.keyVersion;
        model.expectedRosterVersion = current.rosterVersion;
        model.commit = statement;
        try {
            api.groupRemoveMembers(model);
        } catch (const privmx::utils::PrivmxException& e) {
            return std::string(e.what()) + " | " + e.getData();
        }
        return "";
    }

    // A rotation sent straight to the Bridge, valid in shape only (its grant edge is not).
    void sendRawRotation(const std::string& groupId) {
        group::ServerApi api(connection->getImpl()->getGateway());
        const auto current = api.groupGet({.groupId = groupId, .scope = std::string("plan")}).group;
        const auto groupPubKey = privmx::crypto::PrivateKey::generateRandom().getPublicKey().toBase58DER();
        group::server::GroupGenerateNewKeyModel model;
        model.id = groupId;
        model.groupPubKey = groupPubKey;
        model.data = Poco::Dynamic::Var(std::string("x"));
        model.keyId = "m3-raw";
        model.grantEdge = {.isGrantEdge = true, .parentIndex = 0, .parentGeneration = 0, .childKind = "node",
                           .childIndex = 0, .childGeneration = 0, .childUserId = std::nullopt, .data = "x"};
        model.commit = nextStatement(api, groupId, groupPubKey);
        model.rungs = {{.atKeyVersion = current.keyVersion + 1, .targetKeyVersion = current.keyVersion, .data = "x"}};
        model.expectedKeyVersion = current.keyVersion;
        model.expectedRosterVersion = current.rosterVersion;
        api.groupGenerateNewKey(model);
    }

    // The latest served statement, extended by one (anything else is a lost race, answered before the key is
    // looked at) and re-signed by this session: shape-valid; only its seq, link and key differ.
    group::server::GroupTreeCommit nextStatement(
        group::ServerApi& api,
        const std::string& groupId,
        const std::string& groupPubKey
    ) {
        auto latest = group::keytree::TreeCommits::fromWire(
            api.groupGetTreeCommits({.groupId = groupId, .fromSeq = 0}).commits.back()
        );
        group::keytree::CommitStatement next = latest;
        next.seq = latest.seq + 1;
        next.prevDigest = group::keytree::TreeCommits::digest(latest);
        next.groupId = groupId;
        next.policy.reset();
        next.groupPubKey = groupPubKey;
        group::keytree::TreeCommits::sign(next, connection->getImpl()->getUserPrivKey());
        return group::keytree::TreeCommits::toWire(next);
    }

    // ── the Epoch Ladder, raw: what the bridge accepts and serves, not what this client would send ──

    group::ServerApi raw() { return group::ServerApi(connection->getImpl()->getGateway()); }

    // `(at, target)` carrying the session's own epoch keys, sealed by its user key: what a repair sends.
    group::server::GroupArchiveRung sealedRung(const std::string& groupId, std::uint32_t at, std::uint32_t target) {
        const auto impl = groupApi->getImpl();
        const auto atKey = impl->resolveGroupPrivKey(groupId, at);
        const auto targetKey = impl->resolveGroupPrivKey(groupId, target);
        group::server::GroupArchiveRung rung;
        rung.atKeyVersion = at;
        rung.targetKeyVersion = target;
        rung.data = group::keytree::LadderKeys::sealRung(
            targetKey, {at, target}, atKey.getPublicKey(), connection->getImpl()->getUserPrivKey()
        );
        return rung;
    }

    // One a caller holding neither key can still send.
    static group::server::GroupArchiveRung garbageRung(std::uint32_t at, std::uint32_t target) {
        const auto random = privmx::crypto::PrivateKey::generateRandom();
        group::server::GroupArchiveRung rung;
        rung.atKeyVersion = at;
        rung.targetKeyVersion = target;
        rung.data = group::keytree::LadderKeys::sealRung(random, {at, target}, random.getPublicKey(), random);
        return rung;
    }

    void repair(const std::string& groupId, const group::server::GroupArchiveRung& rung) {
        raw().groupRepairRung(group::server::GroupRepairRungModel{.id = groupId, .rung = rung});
    }

    std::vector<group::server::GroupArchiveRung> rungsOfSpan(const std::string& groupId, std::int64_t at, std::int64_t target) {
        group::server::GroupGetKeyArchiveModel model;
        model.id = groupId;
        model.fromKeyVersion = at;
        model.toKeyVersion = at;
        std::vector<group::server::GroupArchiveRung> span;
        for (const auto& rung : raw().groupGetKeyArchive(model).rungs) {
            if (rung.targetKeyVersion == target) {
                span.push_back(rung);
            }
        }
        return span;
    }

    // The bridge's refusal of a raw call, as (code, data); nullopt when it was accepted.
    static std::optional<std::pair<unsigned int, std::string>> refusalOf(const std::function<void()>& call) {
        try {
            call();
            return std::nullopt;
        } catch (const privmx::utils::PrivmxException& e) {
            return std::make_pair(static_cast<unsigned int>(e.getCode()) & 0xFFFF, e.getData());
        } catch (const core::Exception& e) {
            return std::make_pair(e.getCode() & 0xFFFF, e.getFull());
        }
    }

    // A context user with a fresh key, seated nowhere.
    privmx::crypto::PrivateKey registerOutsider(const std::string& userId) {
        const auto key = privmx::crypto::PrivateKey::generateRandom();
        const std::string params = "{\"contextId\": \"" + contextId() + "\", \"userId\": \"" + userId +
            "\", \"userPubKey\": \"" + key.getPublicKey().toBase58DER() + "\"}";
        const std::string response = core::BackendRequester::backendRequest(
            getPlatformUrl(), reader->getString("Api.apiKeyId"), reader->getString("Api.apiKeySecret"), 0,
            "context/addUserToContext", params
        );
        EXPECT_EQ(response.find("\"error\""), std::string::npos) << response;
        return key;
    }

    // user_1 creates {user_1, user_2, user_3} and moves it to `epoch` by removing user_3 (re-added in between).
    std::string groupAtEpoch(int epoch) {
        const std::string groupId = createTreeGroup({user(1), user(2), user(3)});
        for (int at = 2; at <= epoch; ++at) {
            if (at > 2) {
                groupApi->addGroupMembers(groupId, {group::GroupMemberToAdd{.user = user(3), .role = "user"}});
            }
            groupApi->removeGroupMembers(groupId, {user(3).userId});
        }
        return groupId;
    }

    std::shared_ptr<thread::ThreadApi> threadApi;
};

static constexpr unsigned int ACCESS_DENIED = 0x0030;
static constexpr unsigned int GROUP_ROTATION_RATE_LIMIT = 0x621D;
static constexpr unsigned int GROUP_ARCHIVE_INVALID = 0x621F;

// -- creation --

TEST_F(GroupKeyTreeTest, createGroup_starts_at_epoch_one) {
    std::string groupId;
    ASSERT_NO_THROW({ groupId = createTreeGroup({user(1), user(2), user(3)}); });
    ASSERT_FALSE(groupId.empty());

    group::Group group;
    ASSERT_NO_THROW({ group = groupApi->getGroup(groupId); });
    EXPECT_EQ(group.statusCode, 0) << "the creator must be able to decrypt the group it just made";
    EXPECT_EQ(group.keyVersion, 1);
    EXPECT_FALSE(group.groupPubKey.empty());
    EXPECT_EQ(group.publicMeta.stdString(), "keytree_public");
    EXPECT_EQ(group.privateMeta.stdString(), "keytree_private");
}

TEST_F(GroupKeyTreeTest, every_member_can_read_a_tree_backed_group) {
    // The group's metadata key is wrapped once, to the group itself. Each member gets at it by climbing the tree,
    // which is the read path this whole design rests on - if it fails, nothing else works.
    std::string groupId;
    ASSERT_NO_THROW({ groupId = createTreeGroup({user(1), user(2), user(3)}); });
    disconnect();

    for (const int index : {2, 3}) {
        connectAs(index);
        group::Group group;
        ASSERT_NO_THROW({ group = groupApi->getGroup(groupId); });
        EXPECT_EQ(group.statusCode, 0) << "a member could not decrypt the group";
        EXPECT_EQ(group.privateMeta.stdString(), "keytree_private");
        disconnect();
    }
    connectAs(1);
}

TEST_F(GroupKeyTreeTest, SECURITY_a_non_member_cannot_read_a_tree_backed_group) {
    std::string groupId;
    ASSERT_NO_THROW({ groupId = createTreeGroup({user(1), user(2)}); });
    disconnect();

    // user_3 holds no leaf: no edge is addressed to them, so there is nothing to climb.
    connectAs(3);
    group::Group group;
    bool threw = false;
    try {
        group = groupApi->getGroup(groupId);
    } catch (const core::Exception&) {
        threw = true;
    }
    if (!threw) {
        EXPECT_NE(group.statusCode, 0) << "a non-member decrypted the group's metadata";
    }
    disconnect();
    connectAs(1);
}

// -- addition - the operation that must stay cheap --

TEST_F(GroupKeyTreeTest, addGroupMembers_does_not_advance_the_epoch) {
    // The heart of the economy: adding a member leaves the epoch alone, so no container the group can read goes
    // stale and nobody else re-keys anything.
    std::string groupId;
    ASSERT_NO_THROW({ groupId = createTreeGroup({user(1), user(2)}); });
    group::Group before;
    ASSERT_NO_THROW({ before = groupApi->getGroup(groupId); });

    ASSERT_NO_THROW({
        groupApi->addGroupMembers(groupId, {group::GroupMemberToAdd{.user = user(3), .role = "user"}});
    });

    group::Group after;
    ASSERT_NO_THROW({ after = groupApi->getGroup(groupId); });
    EXPECT_EQ(after.keyVersion, before.keyVersion) << "an addition rotated the group key";
    EXPECT_EQ(after.groupPubKey, before.groupPubKey) << "an addition replaced the grant key";
    EXPECT_NE(std::find(after.users.begin(), after.users.end(), user(3).userId), after.users.end());
}

TEST_F(GroupKeyTreeTest, an_added_member_can_read_the_group) {
    std::string groupId;
    ASSERT_NO_THROW({ groupId = createTreeGroup({user(1), user(2)}); });
    ASSERT_NO_THROW({
        groupApi->addGroupMembers(groupId, {group::GroupMemberToAdd{.user = user(3), .role = "user"}});
    });
    disconnect();

    connectAs(3);
    group::Group group;
    ASSERT_NO_THROW({ group = groupApi->getGroup(groupId); });
    EXPECT_EQ(group.statusCode, 0) << "the newly seated member cannot climb to the group key";
    EXPECT_EQ(group.privateMeta.stdString(), "keytree_private");
    disconnect();
    connectAs(1);
}

TEST_F(GroupKeyTreeTest, addGroupMembers_seats_a_whole_batch_at_the_same_epoch) {
    // Why the call takes a list: the newcomers' paths overlap, so one delta covers their union and lands under
    // a single compare-and-swap. The role travels per member, so a manager and a plain user can arrive together.
    std::string groupId;
    ASSERT_NO_THROW({ groupId = createTreeGroup({user(1)}); });
    group::Group before;
    ASSERT_NO_THROW({ before = groupApi->getGroup(groupId); });

    ASSERT_NO_THROW({
        groupApi->addGroupMembers(
            groupId,
            {
                group::GroupMemberToAdd{.user = user(2), .role = "user"},
                group::GroupMemberToAdd{.user = user(3), .role = "manager"}
            }
        );
    });

    group::Group after;
    ASSERT_NO_THROW({ after = groupApi->getGroup(groupId); });
    EXPECT_EQ(after.keyVersion, before.keyVersion) << "a batch addition rotated the group key";
    EXPECT_EQ(after.groupPubKey, before.groupPubKey) << "a batch addition replaced the grant key";
    EXPECT_NE(std::find(after.users.begin(), after.users.end(), user(2).userId), after.users.end());
    EXPECT_NE(std::find(after.managers.begin(), after.managers.end(), user(3).userId), after.managers.end()) <<
        "the role named with the member was not the role they got";
    disconnect();

    // Both newcomers hold a seat of their own, not one shared re-wrap that happens to open for whoever asks
    // first: each climbs to the group key from their own leaf, in a session of their own.
    connectAs(2);
    group::Group asUser2;
    ASSERT_NO_THROW({ asUser2 = groupApi->getGroup(groupId); });
    EXPECT_EQ(asUser2.statusCode, 0) << "the member seated first in the batch cannot climb";
    disconnect();

    connectAs(3);
    group::Group asUser3;
    ASSERT_NO_THROW({ asUser3 = groupApi->getGroup(groupId); });
    EXPECT_EQ(asUser3.statusCode, 0) << "the member seated second in the batch cannot climb";
    disconnect();
    connectAs(1);
}

// -- removal - the operation the whole design exists for --

TEST_F(GroupKeyTreeTest, removeGroupMembers_advances_the_epoch_and_replaces_the_grant_key) {
    std::string groupId;
    ASSERT_NO_THROW({ groupId = createTreeGroup({user(1), user(2), user(3)}); });
    group::Group before;
    ASSERT_NO_THROW({ before = groupApi->getGroup(groupId); });

    ASSERT_NO_THROW({
        groupApi->removeGroupMembers(groupId, {user(3).userId});
    });

    group::Group after;
    ASSERT_NO_THROW({ after = groupApi->getGroup(groupId); });
    EXPECT_EQ(after.keyVersion, before.keyVersion + 1) << "a removal must advance the epoch";
    EXPECT_NE(after.groupPubKey, before.groupPubKey) << "a removal must mint a new grant key";
    EXPECT_EQ(std::find(after.users.begin(), after.users.end(), user(3).userId), after.users.end());
    EXPECT_EQ(after.statusCode, 0) << "a remaining member cannot read the group it still belongs to";
}

TEST_F(GroupKeyTreeTest, removeGroupMembers_advances_the_epoch_once_for_the_whole_batch) {
    // Taking two members out one at a time costs two epochs, so every grantee container goes stale twice. One
    // call must cost exactly one epoch however many members leave - and all of them must actually be out.
    std::string groupId;
    ASSERT_NO_THROW({ groupId = createTreeGroup({user(1), user(2), user(3)}); });
    group::Group before;
    ASSERT_NO_THROW({ before = groupApi->getGroup(groupId); });

    ASSERT_NO_THROW({
        groupApi->removeGroupMembers(groupId, {user(2).userId, user(3).userId});
    });

    group::Group after;
    ASSERT_NO_THROW({ after = groupApi->getGroup(groupId); });
    EXPECT_EQ(after.keyVersion, before.keyVersion + 1) << "a batch removal advanced the epoch once per member";
    EXPECT_NE(after.groupPubKey, before.groupPubKey) << "a removal must mint a new grant key";
    EXPECT_EQ(std::find(after.users.begin(), after.users.end(), user(2).userId), after.users.end());
    EXPECT_EQ(std::find(after.users.begin(), after.users.end(), user(3).userId), after.users.end());
    EXPECT_EQ(after.statusCode, 0) << "the manager cannot read the group they still manage";
    disconnect();

    // Neither leaver climbs any more - a batch must not leave one of them holding a live path. The bridge may
    // refuse the read outright or serve something undecryptable, so both count as "cannot read".
    const auto stillReads = [&](int who) {
        connectAs(who);
        bool reads = false;
        try {
            reads = groupApi->getGroup(groupId).statusCode == 0;
        } catch (const core::Exception&) {
            reads = false;
        }
        disconnect();
        return reads;
    };
    EXPECT_FALSE(stillReads(2)) << "the member removed first still reads the group";
    EXPECT_FALSE(stillReads(3)) << "the member removed second still reads the group";
    connectAs(1);
}

TEST_F(GroupKeyTreeTest, remaining_members_can_still_read_after_a_removal) {
    std::string groupId;
    ASSERT_NO_THROW({ groupId = createTreeGroup({user(1), user(2), user(3)}); });
    ASSERT_NO_THROW({
        groupApi->removeGroupMembers(groupId, {user(3).userId});
    });
    disconnect();

    connectAs(2);
    group::Group group;
    ASSERT_NO_THROW({ group = groupApi->getGroup(groupId); });
    EXPECT_EQ(group.statusCode, 0) << "the refresh locked out a member who should have kept access";
    EXPECT_EQ(group.privateMeta.stdString(), "keytree_private");
    disconnect();
    connectAs(1);
}

TEST_F(GroupKeyTreeTest, SECURITY_a_removed_member_cannot_read_content_written_afterwards) {
    // Three conditions make this bite: `forwardSecrecy = "yes"` on the thread, an explicit re-key to the new
    // epoch, and a cold session for the probe. What ends is the route, not the safety of the epoch-1 ciphertext.
    std::string groupId;
    ASSERT_NO_THROW({ groupId = createTreeGroup({user(1), user(2), user(3)}); });
    group::Group group;
    ASSERT_NO_THROW({ group = groupApi->getGroup(groupId); });

    std::string threadId;
    ASSERT_NO_THROW({ threadId = createThreadGrantedTo(group, "yes"); });
    ASSERT_NO_THROW({
        threadApi->sendMessage(
            threadId, core::Buffer::from("pub_before"), core::Buffer::from("priv_before"),
            core::Buffer::from("data_before")
        );
    });

    ASSERT_NO_THROW({
        groupApi->removeGroupMembers(groupId, {user(3).userId});
    });

    // Until the thread is re-keyed no new content is accepted, so this step is what makes the removal bite.
    // Done explicitly rather than left to `sendMessage`'s automatic re-key.
    group::Group rotated;
    ASSERT_NO_THROW({ rotated = groupApi->getGroup(groupId); });
    ASSERT_NO_THROW({
        threadApi->updateThread(
            threadId, std::vector<core::UserWithPubKey>{user(1)}, std::vector<core::UserWithPubKey>{user(1)},
            core::Buffer::from("kt_thread_public"), core::Buffer::from("kt_thread_private"),
            1, true, true, std::nullopt,
            std::vector<core::GroupGrantWithKey>{{
                .groupId = groupId, .role = "user", .groupPubKey = rotated.groupPubKey,
                .groupEpoch = rotated.keyVersion
            }}
        );
    });
    std::string afterId;
    ASSERT_NO_THROW({
        afterId = threadApi->sendMessage(
            threadId, core::Buffer::from("pub_after"), core::Buffer::from("priv_after"),
            core::Buffer::from("data_after")
        );
    });
    disconnect();

    connectAs(3);
    thread::Message message;
    bool threw = false;
    try {
        message = threadApi->getMessage(afterId);
    } catch (const core::Exception&) {
        threw = true;
    }
    if (!threw) {
        EXPECT_NE(message.statusCode, 0)
            << "a removed member read content written after their removal";
        EXPECT_NE(message.data.stdString(), "data_after");
    }
    disconnect();
    connectAs(1);
}

// -- key cache --

TEST_F(GroupKeyTreeTest, SECURITY_two_groups_at_the_same_epoch_do_not_share_cached_keys) {
    // Every group starts at epoch 1, so a cache keyed on the epoch alone would hand the first group's grant key
    // back for the second. Only a reader going through a group grant climbs at all - hence user_2.
    std::string groupIdA, groupIdB;
    ASSERT_NO_THROW({ groupIdA = createTreeGroup({user(1), user(2)}); });
    ASSERT_NO_THROW({ groupIdB = createTreeGroup({user(1), user(2)}); });
    group::Group groupA, groupB;
    ASSERT_NO_THROW({ groupA = groupApi->getGroup(groupIdA); });
    ASSERT_NO_THROW({ groupB = groupApi->getGroup(groupIdB); });

    // Preconditions, so this cannot pass vacuously: the collision only exists at equal epochs, between groups
    // that really do have different grant keys.
    ASSERT_EQ(groupA.keyVersion, groupB.keyVersion);
    ASSERT_EQ(groupA.keyVersion, 1);
    ASSERT_NE(groupA.groupPubKey, groupB.groupPubKey);

    std::string threadIdA, threadIdB;
    ASSERT_NO_THROW({ threadIdA = createThreadGrantedTo(groupA); });
    ASSERT_NO_THROW({ threadIdB = createThreadGrantedTo(groupB); });
    std::string messageIdA, messageIdB;
    ASSERT_NO_THROW({
        messageIdA = threadApi->sendMessage(
            threadIdA, core::Buffer::from("pub_a"), core::Buffer::from("priv_a"), core::Buffer::from("data_A")
        );
    });
    ASSERT_NO_THROW({
        messageIdB = threadApi->sendMessage(
            threadIdB, core::Buffer::from("pub_b"), core::Buffer::from("priv_b"), core::Buffer::from("data_B")
        );
    });
    disconnect();

    connectAs(2);
    thread::Message fromA;
    ASSERT_NO_THROW({ fromA = threadApi->getMessage(messageIdA); });
    ASSERT_EQ(fromA.statusCode, 0);
    ASSERT_EQ(fromA.data.stdString(), "data_A");

    // Group A's epoch-1 key is cached now. Group B is also at epoch 1.
    thread::Message fromB;
    ASSERT_NO_THROW({ fromB = threadApi->getMessage(messageIdB); });
    EXPECT_EQ(fromB.statusCode, 0)
        << "reading group B after group A returned group A's cached grant key for epoch 1";
    EXPECT_EQ(fromB.data.stdString(), "data_B");

    // And back again, so the fix cannot be an eviction that merely swaps which group is broken.
    thread::Message fromAAgain;
    ASSERT_NO_THROW({ fromAAgain = threadApi->getMessage(messageIdA); });
    EXPECT_EQ(fromAAgain.statusCode, 0);
    EXPECT_EQ(fromAAgain.data.stdString(), "data_A");
    disconnect();
    connectAs(1);
}

TEST_F(GroupKeyTreeTest, removeGroupMembers_leaves_the_same_session_able_to_read_both_epochs) {
    // A removal drops the cached node keys, whose generations were just refreshed, and seeds the new epoch's
    // grant key. It must not drop the older grant keys: the ladder descent to pre-removal content needs them.
    std::string groupId;
    ASSERT_NO_THROW({ groupId = createTreeGroup({user(1), user(2), user(3)}); });
    group::Group group;
    ASSERT_NO_THROW({ group = groupApi->getGroup(groupId); });

    std::string threadId;
    ASSERT_NO_THROW({ threadId = createThreadGrantedTo(group, "yes"); });
    std::string beforeId;
    ASSERT_NO_THROW({
        beforeId = threadApi->sendMessage(
            threadId, core::Buffer::from("pub_before"), core::Buffer::from("priv_before"),
            core::Buffer::from("data_before")
        );
    });

    ASSERT_NO_THROW({
        groupApi->removeGroupMembers(groupId, {user(3).userId});
    });

    group::Group rotated;
    ASSERT_NO_THROW({ rotated = groupApi->getGroup(groupId); });
    ASSERT_EQ(rotated.keyVersion, 2);
    ASSERT_NO_THROW({
        threadApi->updateThread(
            threadId, std::vector<core::UserWithPubKey>{user(1)}, std::vector<core::UserWithPubKey>{user(1)},
            core::Buffer::from("kt_thread_public"), core::Buffer::from("kt_thread_private"),
            1, true, true, std::nullopt,
            std::vector<core::GroupGrantWithKey>{{
                .groupId = groupId, .role = "user", .groupPubKey = rotated.groupPubKey,
                .groupEpoch = rotated.keyVersion
            }}
        );
    });
    std::string afterId;
    ASSERT_NO_THROW({
        afterId = threadApi->sendMessage(
            threadId, core::Buffer::from("pub_after"), core::Buffer::from("priv_after"),
            core::Buffer::from("data_after")
        );
    });

    thread::Message after;
    ASSERT_NO_THROW({ after = threadApi->getMessage(afterId); });
    EXPECT_EQ(after.statusCode, 0) << "the new epoch's grant key was not usable after the removal";
    EXPECT_EQ(after.data.stdString(), "data_after");

    thread::Message before;
    ASSERT_NO_THROW({ before = threadApi->getMessage(beforeId); });
    EXPECT_EQ(before.statusCode, 0) << "the removal discarded the older epoch key the ladder descent needs";
    EXPECT_EQ(before.data.stdString(), "data_before");
}

TEST_F(GroupKeyTreeTest, a_resolved_epoch_key_is_not_fetched_again_in_the_same_connection) {
    // Every container key read resolves its grant's group epoch; once known, that epoch must cost no `groupGet` and
    // climb again. Shown by deleting the group first, after which any read of it fails. The delete goes straight to
    // the server: `deleteGroup` itself drops the group's cached keys, which is not what is measured here.
    std::string groupId;
    ASSERT_NO_THROW({ groupId = createTreeGroup({user(1), user(2)}); });
    const auto impl = groupApi->getImpl();
    std::optional<privmx::crypto::PrivateKey> first, again;
    ASSERT_NO_THROW({ first = impl->resolveGroupPrivKey(groupId, 1); });
    ASSERT_NO_THROW({ group::ServerApi(connection->getImpl()->getGateway()).groupDelete({.groupId = groupId}); });
    ASSERT_NO_THROW({ again = impl->resolveGroupPrivKey(groupId, 1); });
    EXPECT_EQ(again->getPublicKey().toBase58DER(), first->getPublicKey().toBase58DER());
}

TEST_F(GroupKeyTreeTest, reconnecting_rebuilds_the_key_cache_from_scratch) {
    // Connect and disconnect both empty the cache. A read after reconnecting has to climb again and succeed.
    std::string groupId;
    ASSERT_NO_THROW({ groupId = createTreeGroup({user(1), user(2)}); });
    group::Group group;
    ASSERT_NO_THROW({ group = groupApi->getGroup(groupId); });

    std::string threadId;
    ASSERT_NO_THROW({ threadId = createThreadGrantedTo(group); });
    std::string messageId;
    ASSERT_NO_THROW({
        messageId = threadApi->sendMessage(
            threadId, core::Buffer::from("pub"), core::Buffer::from("priv"), core::Buffer::from("data_x")
        );
    });
    disconnect();

    connectAs(2);
    thread::Message first;
    ASSERT_NO_THROW({ first = threadApi->getMessage(messageId); });
    ASSERT_EQ(first.statusCode, 0);
    disconnect();

    connectAs(2);
    thread::Message second;
    ASSERT_NO_THROW({ second = threadApi->getMessage(messageId); });
    EXPECT_EQ(second.statusCode, 0) << "the cache was emptied on reconnect and the re-climb failed";
    EXPECT_EQ(second.data.stdString(), "data_x");
    disconnect();
    connectAs(1);
}

TEST_F(GroupKeyTreeTest, ROTATE_REQUIRED_blocks_writes_until_the_container_catches_up) {
    // Lazy revocation: nothing can be written between a removal and the re-key. Enforcement is opt-in per
    // container (`forwardSecrecy`), and the writer must be one who cannot re-key - hence user_2, not user_1.
    std::string groupId;
    ASSERT_NO_THROW({ groupId = createTreeGroup({user(1), user(2), user(3)}); });
    group::Group group;
    ASSERT_NO_THROW({ group = groupApi->getGroup(groupId); });

    std::string threadId;
    ASSERT_NO_THROW({ threadId = createThreadGrantedToWithManagerOnlyRekey(group); });
    ASSERT_NO_THROW({
        threadApi->sendMessage(
            threadId, core::Buffer::from("p"), core::Buffer::from("p"), core::Buffer::from("before")
        );
    });

    ASSERT_NO_THROW({
        groupApi->removeGroupMembers(groupId, {user(3).userId});
    });

    thread::Thread beforeWrite;
    ASSERT_NO_THROW({ beforeWrite = threadApi->getThread(threadId); });
    ASSERT_EQ(beforeWrite.staleGroups.size(), 1);

    disconnect();
    connectAs(2);

    // The thread still holds a key wrapped to epoch 1 while the group is at epoch 2, and user_2 may not re-key.
    EXPECT_THROW({
        threadApi->sendMessage(
            threadId, core::Buffer::from("p"), core::Buffer::from("p"), core::Buffer::from("stale")
        );
    }, core::StaleKeyRekeyRequiredException) << "content was accepted under a superseded group epoch";

    // And the refused write left the thread exactly where it was - no partial re-key on the way out.
    thread::Thread afterWrite;
    ASSERT_NO_THROW({ afterWrite = threadApi->getThread(threadId); });
    EXPECT_EQ(afterWrite.version, beforeWrite.version);
    EXPECT_EQ(afterWrite.staleGroups.size(), 1);

    disconnect();
    connectAs(1);
}

// -- history - the Epoch Ladder, end to end --

TEST_F(GroupKeyTreeTest, a_remaining_member_reads_content_from_before_a_removal) {
    // Reaching the old message needs the *previous* epoch's grant key, which no longer exists in the tree. It is
    // recovered by descending the ladder - one rung - and this is the first place that path runs against a server.
    std::string groupId;
    ASSERT_NO_THROW({ groupId = createTreeGroup({user(1), user(2), user(3)}); });
    group::Group group;
    ASSERT_NO_THROW({ group = groupApi->getGroup(groupId); });

    std::string threadId;
    ASSERT_NO_THROW({ threadId = createThreadGrantedTo(group); });
    std::string oldMessageId;
    ASSERT_NO_THROW({
        oldMessageId = threadApi->sendMessage(
            threadId, core::Buffer::from("pub_old"), core::Buffer::from("priv_old"),
            core::Buffer::from("data_old")
        );
    });

    ASSERT_NO_THROW({
        groupApi->removeGroupMembers(groupId, {user(3).userId});
    });
    disconnect();

    connectAs(2);
    thread::Message message;
    ASSERT_NO_THROW({ message = threadApi->getMessage(oldMessageId); });
    EXPECT_EQ(message.statusCode, 0) << "a remaining member lost the group's history at the removal";
    EXPECT_EQ(message.data.stdString(), "data_old");
    disconnect();
    connectAs(1);
}

TEST_F(GroupKeyTreeTest, a_newcomer_reads_history_that_predates_them) {
    // The payoff of the Epoch Ladder: user_3 is seated *after* a removal bumped the epoch, and reads a message
    // written before they were a member - with nothing in the archive addressed to them personally.
    std::string groupId;
    ASSERT_NO_THROW({ groupId = createTreeGroup({user(1), user(2)}); });
    group::Group group;
    ASSERT_NO_THROW({ group = groupApi->getGroup(groupId); });

    std::string threadId;
    ASSERT_NO_THROW({ threadId = createThreadGrantedTo(group); });
    std::string oldMessageId;
    ASSERT_NO_THROW({
        oldMessageId = threadApi->sendMessage(
            threadId, core::Buffer::from("pub_hist"), core::Buffer::from("priv_hist"),
            core::Buffer::from("data_hist")
        );
    });

    // Rotate the epoch, so reaching the message requires a descent rather than the current key.
    ASSERT_NO_THROW({
        groupApi->removeGroupMembers(groupId, {user(2).userId});
    });
    // Then seat user_3, who has never held any key of this group.
    ASSERT_NO_THROW({
        groupApi->addGroupMembers(groupId, {group::GroupMemberToAdd{.user = user(3), .role = "user"}});
    });
    disconnect();

    connectAs(3);
    thread::Message message;
    ASSERT_NO_THROW({ message = threadApi->getMessage(oldMessageId); });
    EXPECT_EQ(message.statusCode, 0)
        << "a newcomer could not descend the ladder to content that predates them";
    EXPECT_EQ(message.data.stdString(), "data_hist");
    disconnect();
    connectAs(1);
}

TEST_F(GroupKeyTreeTest, several_removals_in_a_row_keep_the_whole_history_reachable) {
    // Each removal adds one rung. After three, reaching the oldest message means descending three of them, and
    // every hop is verified against the epoch registry on the way down.
    std::string groupId;
    ASSERT_NO_THROW({ groupId = createTreeGroup({user(1), user(2), user(3)}); });
    group::Group group;
    ASSERT_NO_THROW({ group = groupApi->getGroup(groupId); });

    std::string threadId;
    ASSERT_NO_THROW({ threadId = createThreadGrantedTo(group); });
    std::string oldestId;
    ASSERT_NO_THROW({
        oldestId = threadApi->sendMessage(
            threadId, core::Buffer::from("p"), core::Buffer::from("p"), core::Buffer::from("oldest")
        );
    });

    // remove user_3, then re-add and remove again, twice more - three epoch bumps in total.
    for (int round = 0; round < 3; round++) {
        ASSERT_NO_THROW({
            groupApi->removeGroupMembers(groupId, {user(3).userId});
        }) << "removal round " << round;
        if (round < 2) {
            ASSERT_NO_THROW({
                groupApi->addGroupMembers(groupId, {group::GroupMemberToAdd{.user = user(3), .role = "user"}});
            }) << "re-add round " << round;
        }
    }

    group::Group final_state;
    ASSERT_NO_THROW({ final_state = groupApi->getGroup(groupId); });
    EXPECT_EQ(final_state.keyVersion, 4) << "three removals should give epochs 1 -> 4";

    thread::Message message;
    ASSERT_NO_THROW({ message = threadApi->getMessage(oldestId); });
    EXPECT_EQ(message.statusCode, 0) << "the oldest message became unreachable after three epoch bumps";
    EXPECT_EQ(message.data.stdString(), "oldest");
}

// -- rotation without a membership change --

TEST_F(GroupKeyTreeTest, a_one_member_group_rotates_and_still_reads_its_history) {
    // The one-leaf tree's root is the member's own leaf: the new grant key goes straight to the member's key. Its
    // history stays readable through the rung down to epoch 1, to the member and to whoever joins later.
    std::string groupId;
    ASSERT_NO_THROW({ groupId = createTreeGroup({}); });
    group::Group before;
    ASSERT_NO_THROW({ before = groupApi->getGroup(groupId); });
    ASSERT_TRUE(before.users.empty());
    ASSERT_EQ(before.managers, std::vector<std::string>{user(1).userId}) << "user_1 alone, as the manager";

    std::string threadId;
    ASSERT_NO_THROW({ threadId = createThreadGrantedTo(before); });
    std::string oldMessageId;
    ASSERT_NO_THROW({
        oldMessageId = threadApi->sendMessage(
            threadId, core::Buffer::from("p"), core::Buffer::from("p"), core::Buffer::from("before_rotation")
        );
    });

    ASSERT_NO_THROW({ groupApi->rotateGroupKey(groupId); });

    group::Group after;
    ASSERT_NO_THROW({ after = groupApi->getGroup(groupId); });
    EXPECT_EQ(after.statusCode, 0) << "the sole member cannot read its own rotated group";
    EXPECT_EQ(after.keyVersion, 2);
    EXPECT_NE(after.groupPubKey, before.groupPubKey) << "a rotation must mint a new grant key";
    EXPECT_EQ(after.users, before.users);
    EXPECT_EQ(after.privateMeta.stdString(), "keytree_private");

    thread::Message message;
    ASSERT_NO_THROW({ message = threadApi->getMessage(oldMessageId); });
    EXPECT_EQ(message.statusCode, 0) << "the rotation cut the member off its own history";
    EXPECT_EQ(message.data.stdString(), "before_rotation");

    ASSERT_NO_THROW({
        groupApi->addGroupMembers(groupId, {group::GroupMemberToAdd{.user = user(2), .role = "user"}});
    });
    disconnect();
    connectAs(2);
    group::Group seen;
    ASSERT_NO_THROW({ seen = groupApi->getGroup(groupId); });
    EXPECT_EQ(seen.statusCode, 0) << "a newcomer cannot read a group grown out of a rotated one-member group";
    EXPECT_EQ(seen.keyVersion, 2) << "an addition advances no epoch";
    ASSERT_NO_THROW({ message = threadApi->getMessage(oldMessageId); });
    EXPECT_EQ(message.statusCode, 0);
    EXPECT_EQ(message.data.stdString(), "before_rotation");
    disconnect();
    connectAs(1);
}

TEST_F(GroupKeyTreeTest, rotateGroupKey_advances_the_epoch_for_the_same_members) {
    // n >= 2: the new grant key goes to the unchanged root. Granted containers go stale, as after a removal, and
    // are re-keyed by the next write of somebody allowed to; the history stays readable across the rotation and a
    // removal after it.
    std::string groupId;
    ASSERT_NO_THROW({ groupId = createTreeGroup({user(1), user(2), user(3)}); });
    group::Group before;
    ASSERT_NO_THROW({ before = groupApi->getGroup(groupId); });
    std::string threadId;
    ASSERT_NO_THROW({ threadId = createThreadGrantedTo(before); });
    std::string oldMessageId;
    ASSERT_NO_THROW({
        oldMessageId = threadApi->sendMessage(
            threadId, core::Buffer::from("p"), core::Buffer::from("p"), core::Buffer::from("epoch_one")
        );
    });

    ASSERT_NO_THROW({ groupApi->rotateGroupKey(groupId); });

    group::Group after;
    ASSERT_NO_THROW({ after = groupApi->getGroup(groupId); });
    EXPECT_EQ(after.statusCode, 0);
    EXPECT_EQ(after.keyVersion, 2);
    EXPECT_NE(after.groupPubKey, before.groupPubKey);
    EXPECT_EQ(after.users, before.users) << "a rotation removes nobody";
    thread::Thread stale;
    ASSERT_NO_THROW({ stale = threadApi->getThread(threadId); });
    EXPECT_EQ(stale.staleGroups.size(), 1) << "a granted container is not staled by the rotation";
    ASSERT_NO_THROW({
        threadApi->sendMessage(threadId, core::Buffer::from("p"), core::Buffer::from("p"), core::Buffer::from("epoch_two"));
    });
    thread::Thread rekeyed;
    ASSERT_NO_THROW({ rekeyed = threadApi->getThread(threadId); });
    EXPECT_TRUE(rekeyed.staleGroups.empty()) << "the write did not re-key the container onto the new epoch";

    ASSERT_NO_THROW({ groupApi->removeGroupMembers(groupId, {user(3).userId}); });
    disconnect();
    connectAs(2);
    group::Group seen;
    ASSERT_NO_THROW({ seen = groupApi->getGroup(groupId); });
    EXPECT_EQ(seen.statusCode, 0);
    EXPECT_EQ(seen.keyVersion, 3);
    thread::Message message;
    ASSERT_NO_THROW({ message = threadApi->getMessage(oldMessageId); });
    EXPECT_EQ(message.statusCode, 0) << "a member lost the history from before the rotation";
    EXPECT_EQ(message.data.stdString(), "epoch_one");
    disconnect();
    connectAs(1);
}

TEST_F(GroupKeyTreeTest, SECURITY_a_plain_member_cannot_rotate_the_group_key) {
    // A rotation stales every container granted to the group: the `rotateKeys` policy (managers, by default) gates
    // it on the bridge, whatever a member can compute.
    std::string groupId;
    ASSERT_NO_THROW({ groupId = createTreeGroup({user(1), user(2)}); });
    disconnect();
    connectAs(2);
    EXPECT_THROW({ groupApi->rotateGroupKey(groupId); }, core::Exception) << "a non-manager rotated the group key";
    // The client refuses that before sending anything; this is what the Bridge says to one sent anyway.
    auto refused = refusalOf([&] { sendRawRotation(groupId); });
    ASSERT_TRUE(refused.has_value()) << "the bridge let a non-manager rotate";
    EXPECT_EQ(refused->first, ACCESS_DENIED) << refused->second;
    group::Group after;
    ASSERT_NO_THROW({ after = groupApi->getGroup(groupId); });
    EXPECT_EQ(after.keyVersion, 1) << "nothing was committed";
    disconnect();
    connectAs(1);
    // Control: the same rotation from a manager gets past the policy gate, so the refusal above is about the caller.
    refused = refusalOf([&] { sendRawRotation(groupId); });
    ASSERT_TRUE(refused.has_value()) << "a shape-only rotation was accepted";
    EXPECT_NE(refused->first, ACCESS_DENIED) << refused->second;
}

// -- rejections the server owes us --

TEST_F(GroupKeyTreeTest, addGroupMembers_rejects_somebody_already_in_the_group) {
    std::string groupId;
    ASSERT_NO_THROW({ groupId = createTreeGroup({user(1), user(2)}); });
    EXPECT_THROW({
        groupApi->addGroupMembers(groupId, {group::GroupMemberToAdd{.user = user(2), .role = "user"}});
    }, core::Exception);
}

TEST_F(GroupKeyTreeTest, removeGroupMembers_rejects_somebody_who_is_not_a_member) {
    std::string groupId;
    ASSERT_NO_THROW({ groupId = createTreeGroup({user(1), user(2)}); });
    EXPECT_THROW({
        groupApi->removeGroupMembers(groupId, {user(3).userId});
    }, core::Exception);
}

TEST_F(GroupKeyTreeTest, SECURITY_removeGroupMembers_refuses_to_remove_the_caller) {
    // The remover mints the next epoch's grant key, so removing yourself would walk out holding the key meant to
    // lock you out. Refused client-side before anything is planned, and by the bridge besides.
    std::string groupId;
    ASSERT_NO_THROW({ groupId = createTreeGroup({user(1), user(2), user(3)}); });
    EXPECT_THROW({
        groupApi->removeGroupMembers(groupId, {user(2).userId, user(1).userId});
    }, core::InvalidParamsException);
    group::Group after;
    ASSERT_NO_THROW({ after = groupApi->getGroup(groupId); });
    EXPECT_EQ(after.keyVersion, 1) << "nothing was committed";
    EXPECT_NE(std::find(after.users.begin(), after.users.end(), user(2).userId), after.users.end());
}

TEST_F(GroupKeyTreeTest, createGroup_refuses_a_creator_outside_the_group) {
    // A creator commits its own path like anybody else, so it needs a seat to have one.
    EXPECT_THROW({
        groupApi->createGroup(
            contextId(), {user(2), user(3)}, std::vector<core::UserWithPubKey>{user(2)},
            core::Buffer::from("keytree_public"), core::Buffer::from("keytree_private")
        );
    }, core::InvalidParamsException);
}

TEST_F(GroupKeyTreeTest, SECURITY_a_plain_member_cannot_remove_anybody) {
    // Reaching the keys and being allowed to use them are different questions. Any member can climb, so any
    // member could *compute* a valid removal; the bridge's policy gate is what stops them submitting it.
    std::string groupId;
    ASSERT_NO_THROW({ groupId = createTreeGroup({user(1), user(2), user(3)}); });
    disconnect();

    connectAs(2);
    EXPECT_THROW({
        groupApi->removeGroupMembers(groupId, {user(3).userId});
    }, core::Exception) << "a non-manager removed a member";
    // The client refuses that before sending anything; this is what the Bridge says to one sent anyway.
    const auto fresh = privmx::crypto::PrivateKey::generateRandom().getPublicKey().toBase58DER();
    const auto refusal = rawRemovalRefusal(groupId, user(3).userId, fresh);
    EXPECT_NE(refusal.find("policy is not met"), std::string::npos) << "the bridge let a non-manager remove: " << refusal;
    disconnect();
    connectAs(1);
    // Control: the same removal from a manager gets past the policy gate, so the refusal above is about the caller.
    const auto control = rawRemovalRefusal(groupId, user(3).userId, fresh);
    EXPECT_FALSE(control.empty()) << "a shape-only removal was accepted";
    EXPECT_EQ(control.find("policy is not met"), std::string::npos) << control;
    group::Group after;
    ASSERT_NO_THROW({ after = groupApi->getGroup(groupId); });
    EXPECT_NE(std::find(after.users.begin(), after.users.end(), user(3).userId), after.users.end());
}


// -- grant key reuse --

TEST_F(GroupKeyTreeTest, SECURITY_a_new_epoch_under_a_key_from_below_the_era_floor_is_refused) {
    // Every member of an old epoch holds its grant key's private half, the ones removed since included. A cut drops
    // the old epochs' rows, so the Bridge must find the old keys in the statements, which no cut touches.
    std::string groupId;
    ASSERT_NO_THROW({ groupId = createTreeGroup({user(1), user(2), user(3)}); });
    std::string k1, k2;
    ASSERT_NO_THROW({ k1 = groupApi->getGroup(groupId).groupPubKey; });
    ASSERT_NO_THROW({ groupApi->removeGroupMembers(groupId, {user(3).userId}); });
    ASSERT_NO_THROW({ k2 = groupApi->getGroup(groupId).groupPubKey; });
    ASSERT_NO_THROW({ groupApi->addGroupMembers(groupId, {group::GroupMemberToAdd{.user = user(3), .role = "user"}}); });
    ASSERT_NO_THROW({ groupApi->removeGroupMembers(groupId, {user(3).userId}); });

    group::ServerApi api(connection->getImpl()->getGateway());
    ASSERT_NO_THROW({ api.groupCutEra({.id = groupId, .newFloor = 3, .expectedKeyVersion = 3}); });

    group::server::GroupGetTreeCommitsResult served;
    ASSERT_NO_THROW({ served = api.groupGetTreeCommits({.groupId = groupId, .fromSeq = 0}); });
    ASSERT_GE(served.commits.size(), 4u) << "create, remove, add, remove";
    EXPECT_EQ(served.commits.front().seq, 1) << "the cut took statements with it";
    EXPECT_EQ(static_cast<int64_t>(served.commits.size()), served.commits.back().seq) << "the statements are no longer contiguous";

    for (const auto& old : {k1, k2}) {
        const auto refusal = rawRemovalRefusal(groupId, user(2).userId, old);
        EXPECT_NE(refusal.find("groupPubKey of an earlier epoch"), std::string::npos)
            << "a key from below the era floor was not recognised: " << refusal;
    }
    // Control: the same model with a fresh key gets past the reuse check, so the refusal above is about the key.
    const auto fresh = privmx::crypto::PrivateKey::generateRandom().getPublicKey().toBase58DER();
    const auto control = rawRemovalRefusal(groupId, user(2).userId, fresh);
    EXPECT_FALSE(control.empty()) << "a shape-only removal was accepted";
    EXPECT_EQ(control.find("earlier epoch"), std::string::npos) << control;

    group::Group after;
    ASSERT_NO_THROW({ after = groupApi->getGroup(groupId); });
    EXPECT_EQ(after.keyVersion, 3);
    EXPECT_NE(std::find(after.users.begin(), after.users.end(), user(2).userId), after.users.end());
}

TEST_F(GroupKeyTreeTest, SECURITY_a_group_key_re_encoded_uncompressed_is_refused) {
    // Keys are compared as strings, so the current key spelled uncompressed would pass for a new one everywhere.
    std::string groupId;
    ASSERT_NO_THROW({ groupId = createTreeGroup({user(1), user(2), user(3)}); });
    std::string k1;
    ASSERT_NO_THROW({ k1 = groupApi->getGroup(groupId).groupPubKey; });
    const auto uncompressed = privmx::utils::Base58::encodeWithChecksum(
        privmx::crypto::PublicKey::fromBase58DER(k1).getEcc().getPublicKey(false)
    );
    ASSERT_NE(uncompressed, k1);

    const auto refusal = rawRemovalRefusal(groupId, user(3).userId, uncompressed);
    EXPECT_NE(refusal.find("compressed"), std::string::npos) << "a re-encoded key was taken for a new one: " << refusal;

    group::Group after;
    ASSERT_NO_THROW({ after = groupApi->getGroup(groupId); });
    EXPECT_EQ(after.keyVersion, 1);
}

// -- repair rungs: any seated member holding both keys may add one more rung to a span --

TEST_F(GroupKeyTreeTest, repairRung_from_another_member_is_served_beside_the_original) {
    std::string groupId;
    ASSERT_NO_THROW({ groupId = groupAtEpoch(2); });
    disconnect();
    connectAs(2);
    ASSERT_NO_THROW({ repair(groupId, sealedRung(groupId, 2, 1)); });
    std::vector<std::string> authors;
    for (const auto& rung : rungsOfSpan(groupId, 2, 1)) {
        authors.push_back(rung.author.value_or(""));
    }
    std::sort(authors.begin(), authors.end());
    EXPECT_EQ(authors, (std::vector<std::string>{user(1).userId, user(2).userId}))
        << "the remover's rung and bob's repair, each under the author the bridge recorded";
    disconnect();
    connectAs(1);
}

TEST_F(GroupKeyTreeTest, SECURITY_repairRung_from_outside_the_group_is_refused) {
    std::string groupId;
    ASSERT_NO_THROW({ groupId = groupAtEpoch(2); });
    disconnect();
    connectAs(3); // removed, still in the context
    auto refused = refusalOf([&] { repair(groupId, garbageRung(2, 1)); });
    ASSERT_TRUE(refused.has_value());
    EXPECT_EQ(refused->first, ACCESS_DENIED) << refused->second;
    disconnect();
    const auto outsider = registerOutsider("never_seated_" + privmx::utils::Utils::getNowTimestampStr());
    connection = connectWith(outsider.toWIF());
    groupApi = std::make_shared<group::GroupApi>(group::GroupApi::create(*connection));
    setUpModuleApis();
    refused = refusalOf([&] { repair(groupId, garbageRung(2, 1)); });
    ASSERT_TRUE(refused.has_value());
    EXPECT_EQ(refused->first, ACCESS_DENIED) << refused->second;
    disconnect();
    connectAs(1);
    EXPECT_EQ(rungsOfSpan(groupId, 2, 1).size(), 1u) << "nothing stored";
}

TEST_F(GroupKeyTreeTest, repairRung_refuses_a_second_rung_from_the_same_member) {
    std::string groupId;
    ASSERT_NO_THROW({ groupId = groupAtEpoch(2); });
    // The opener already has its rung for the span.
    auto refused = refusalOf([&] { repair(groupId, sealedRung(groupId, 2, 1)); });
    ASSERT_TRUE(refused.has_value());
    EXPECT_EQ(refused->first, GROUP_ARCHIVE_INVALID);
    EXPECT_NE(refused->second.find("AUTHOR_HAS_RUNG"), std::string::npos) << refused->second;
    disconnect();
    connectAs(2);
    ASSERT_NO_THROW({ repair(groupId, sealedRung(groupId, 2, 1)); });
    refused = refusalOf([&] { repair(groupId, sealedRung(groupId, 2, 1)); });
    ASSERT_TRUE(refused.has_value());
    EXPECT_NE(refused->second.find("AUTHOR_HAS_RUNG"), std::string::npos) << refused->second;
    disconnect();
    connectAs(1);
    EXPECT_EQ(rungsOfSpan(groupId, 2, 1).size(), 2u);
}

TEST_F(GroupKeyTreeTest, repairRung_budget_is_enforced) {
    // Every call is charged, accepted or refused, so probing the rules costs the caller its own budget (60/h).
    std::string groupId;
    ASSERT_NO_THROW({ groupId = groupAtEpoch(2); });
    disconnect();
    connectAs(2);
    group::server::GroupArchiveRung rung;
    ASSERT_NO_THROW({ rung = sealedRung(groupId, 2, 1); });
    ASSERT_NO_THROW({ repair(groupId, rung); });
    for (int call = 2; call <= 60; ++call) {
        const auto refused = refusalOf([&] { repair(groupId, rung); });
        ASSERT_TRUE(refused.has_value()) << "call " << call;
        ASSERT_EQ(refused->first, GROUP_ARCHIVE_INVALID) << "call " << call << ": " << refused->second;
    }
    const auto limited = refusalOf([&] { repair(groupId, rung); });
    ASSERT_TRUE(limited.has_value());
    EXPECT_EQ(limited->first, GROUP_ROTATION_RATE_LIMIT) << limited->second;
    disconnect();
    connectAs(1);
}

TEST_F(GroupKeyTreeTest, SECURITY_a_rung_naming_a_recipientKind_is_refused) {
    // An era link sealed to somebody's own key must not pass as an epoch's unit rung. The rung validator, the
    // same for commits and repairs, refuses the kind fields as unknown keys.
    std::string groupId;
    ASSERT_NO_THROW({ groupId = groupAtEpoch(2); });
    disconnect();
    connectAs(2);
    group::server::GroupArchiveRung rung;
    ASSERT_NO_THROW({ rung = sealedRung(groupId, 2, 1); });
    Poco::JSON::Object::Ptr wire = rung.toJSON();
    wire->set("recipientKind", "user");
    wire->set("recipient", user(2).userId);
    Poco::JSON::Object::Ptr params = new Poco::JSON::Object();
    params->set("id", groupId);
    params->set("rung", wire);
    privmx::privfs::RpcGateway::Ptr gateway = connection->getImpl()->getGateway();
    EXPECT_TRUE(refusalOf([&] { gateway->request("context.groupRepairRung", params); }).has_value());
    disconnect();
    connectAs(1);
    EXPECT_EQ(rungsOfSpan(groupId, 2, 1).size(), 1u);
}

TEST_F(GroupKeyTreeTest, the_key_archive_window_also_windows_keyHistory) {
    std::string groupId;
    ASSERT_NO_THROW({ groupId = groupAtEpoch(4); });
    const auto epochsServed = [&](std::int64_t from, std::int64_t to) {
        group::server::GroupGetKeyArchiveModel model;
        model.id = groupId;
        model.fromKeyVersion = from;
        model.toKeyVersion = to;
        std::vector<std::int64_t> epochs;
        for (const auto& entry : raw().groupGetKeyArchive(model).keyHistory) {
            epochs.push_back(entry.keyVersion);
        }
        return epochs;
    };
    EXPECT_EQ(epochsServed(2, 3), (std::vector<std::int64_t>{2, 3}));
    EXPECT_EQ(epochsServed(1, 9), (std::vector<std::int64_t>{1, 2, 3})) << "only the epochs behind the current one";
}

TEST_F(GroupKeyTreeTest, SECURITY_repairRung_below_a_cut_floor_is_refused) {
    std::string groupId;
    ASSERT_NO_THROW({ groupId = groupAtEpoch(3); });
    ASSERT_NO_THROW({ raw().groupCutEra({.id = groupId, .newFloor = 2, .expectedKeyVersion = 3}); });
    const auto refused = refusalOf([&] { repair(groupId, garbageRung(3, 1)); });
    ASSERT_TRUE(refused.has_value());
    EXPECT_EQ(refused->first, GROUP_ARCHIVE_INVALID);
    EXPECT_NE(refused->second.find("BELOW_ERA_FLOOR"), std::string::npos) << refused->second;
}

// ── the signed group policy ──

TEST_F(GroupKeyTreeTest, SECURITY_a_policy_change_is_a_signed_commit_every_member_follows) {
    // The manager lets every member update; a plain member then removes the manager; a third session, pinned before
    // either, replays both from its pin: the policy statement, then a removal its committer now holds the role for.
    std::string groupId;
    ASSERT_NO_THROW({ groupId = createTreeGroup({user(1), user(2), user(3)}); });
    const auto third = connect(3);
    group::GroupApi thirdGroups = group::GroupApi::create(*third);
    ASSERT_EQ(thirdGroups.getGroup(groupId).statusCode, 0);

    core::ContainerPolicy everyMember;
    everyMember.update = "user";
    ASSERT_NO_THROW({ groupApi->updateGroupPolicy(groupId, everyMember); });
    disconnect();
    connectAs(2);
    ASSERT_NO_THROW({ groupApi->removeGroupMembers(groupId, {user(1).userId}); });

    group::Group followed;
    ASSERT_NO_THROW({ followed = thirdGroups.getGroup(groupId); });
    EXPECT_EQ(followed.statusCode, 0);
    EXPECT_EQ(followed.keyVersion, 2);
    EXPECT_EQ(followed.policy.update.value_or(""), "user");
    EXPECT_EQ(followed.privateMeta.stdString(), "keytree_private") << "carried up by the new remover";
    const auto commits = group::ServerApi(connection->getImpl()->getGateway())
                             .groupGetTreeCommits({.groupId = groupId, .fromSeq = 0})
                             .commits;
    ASSERT_EQ(commits.size(), 3u);
    EXPECT_EQ(commits[1].op, "policy");
    EXPECT_EQ(commits[2].op, "remove");
    third->disconnect();
    disconnect();
    connectAs(1);
}

TEST_F(GroupKeyTreeTest, a_user_cannot_remove_under_the_default_policy) {
    // Only managers update by default. The client refuses before signing, so nothing reaches the Bridge and the
    // chain does not move. (The Bridge's own refusal of a hand-built statement is its test, not this one.)
    std::string groupId;
    ASSERT_NO_THROW({ groupId = createTreeGroup({user(1), user(2), user(3)}); });
    disconnect();
    connectAs(2);
    const auto seq = [&] {
        return group::ServerApi(connection->getImpl()->getGateway())
            .groupGetTreeCommits({.groupId = groupId, .fromSeq = 0})
            .commits.size();
    };
    const std::size_t before = seq();
    EXPECT_THROW({ groupApi->removeGroupMembers(groupId, {user(3).userId}); }, group::GroupUnauthorizedSignerException);
    EXPECT_THROW({ groupApi->updateGroupPolicy(groupId, core::ContainerPolicy{}); }, group::GroupUnauthorizedSignerException);
    EXPECT_EQ(seq(), before);
    disconnect();
    connectAs(1);
}

