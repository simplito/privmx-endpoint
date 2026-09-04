#include <gtest/gtest.h>
#include <algorithm>
#include <string>
#include <thread>
#include <vector>
#include "../../utils/BaseTest.hpp"
#include <Poco/Util/IniFileConfiguration.h>
#include <privmx/endpoint/core/BackendRequester.hpp>
#include <privmx/endpoint/core/Connection.hpp>
#include <privmx/endpoint/core/CoreException.hpp>
#include <privmx/endpoint/core/EventQueueImpl.hpp>
#include <privmx/endpoint/core/Exception.hpp>
#include <privmx/crypto/ecc/PrivateKey.hpp>
#include <privmx/endpoint/core/VarSerializer.hpp>
#include <privmx/endpoint/group/GroupApi.hpp>
#include <privmx/endpoint/group/VarSerializer.hpp>
#include <privmx/endpoint/thread/ThreadApi.hpp>

using namespace privmx::endpoint;

/**
 * A hostile client trying to break the group key tree, using nothing but the public API and one Bridge
 * management call — registering a context user, which any integrator running their own Bridge can make.
 *
 * Most of these attempts come down to one idea: a group's identity key is an ordinary ECC public key, so it can
 * be presented as if it belonged to a person and offered to anything that accepts a member's key — a container
 * roster, another group's tree.
 *
 * What a group's key is worth has to be read against the Epoch Ladder, which is the design's whole point and
 * also its sharpest edge: a member climbs the tree to the *current* epoch's grant key and descends the ladder
 * from there, so **whoever is a member now holds every epoch key the group has ever had**, down to its era
 * floor. That is by design — it is what lets a group read content written before the reader joined — but it
 * means a group's public key is not a revocable capability. Anything ever wrapped to it stays readable by the
 * group's entire present *and future* membership, and rotating the group's epoch does not take that back.
 *
 * So the negative assertions here are deliberately narrow. Where a test says a group key worn as a user key
 * "opens nothing", it means the endpoint does not *follow* that route — the userId decides which leaf a caller
 * may climb from, and nothing tries a group key against a user-addressed wrap. It does not mean the ciphertext
 * is safe: a client holding the group API can derive that key. `ladder_*` tests below pin the exposure that
 * follows from this, using only supported calls.
 *
 * Tests named SECURITY assert that something *cannot* happen. They fail silently at runtime if the guard
 * regresses — nothing breaks, access simply persists where it should have ended — so they must not be deleted
 * or weakened into positive assertions. The one exception is a premise the API has taken away — a test that can
 * no longer construct its own attack is dropped outright, with the reason in the commit that drops it, rather
 * than kept as a test that cannot fail. `removeGroupMembers` taking no roster retired one such test: the roster
 * lie it was built on has no field to live in any more.
 *
 * Where the fate of the abusive call itself is not part of the contract (the Bridge may refuse it outright, or
 * take it and leave the caller with a wrap the endpoint will not use), the test records which way it went and
 * asserts the invariant that has to hold either way.
 */

class GroupAbuseTest : public privmx::test::BaseTest {
protected:
    GroupAbuseTest() : BaseTest(privmx::test::BaseTestMode::online) {}

    void customSetUp() override {
        reader = new Poco::Util::IniFileConfiguration(INI_FILE_PATH);
        connectAs(1);
    }

    void customTearDown() override {
        connection.reset();
        threadApi.reset();
        groupApi.reset();
        reader.reset();
        core::EventQueueImpl::getInstance()->clear();
    }

    std::string contextId() {
        return reader->getString("Context_1.contextId");
    }

    core::UserWithPubKey user(int index) {
        const std::string n = std::to_string(index);
        return core::UserWithPubKey{
            .userId = reader->getString("Login.user_" + n + "_id"),
            .pubKey = reader->getString("Login.user_" + n + "_pubKey")
        };
    }

    std::shared_ptr<core::Connection> connectWith(const std::string& privKey) {
        return std::make_shared<core::Connection>(
            core::Connection::connect(
                privKey, reader->getString("Login.solutionId"),
                getPlatformUrl(reader->getString("Login.instanceUrl"))
            )
        );
    }

    std::shared_ptr<core::Connection> connect(int index) {
        return connectWith(reader->getString("Login.user_" + std::to_string(index) + "_privKey"));
    }

    void connectAs(int index) {
        connection = connect(index);
        groupApi = std::make_shared<group::GroupApi>(group::GroupApi::create(*connection));
        threadApi = std::make_shared<thread::ThreadApi>(thread::ThreadApi::create(*connection, *groupApi));
        fixtureUserIndex = index;
    }

    void disconnect() {
        connection->disconnect();
        connection.reset();
        threadApi.reset();
        groupApi.reset();
    }

    /** A tree-backed group with the given members, managed by the given managers (user_1 by default). */
    std::string createTreeGroup(
        const std::vector<core::UserWithPubKey>& members,
        const std::vector<core::UserWithPubKey>& managers = {}
    ) {
        return groupApi->createGroup(
            contextId(), members, managers.empty() ? std::vector<core::UserWithPubKey>{user(1)} : managers,
            core::Buffer::from("abuse_public"), core::Buffer::from("abuse_private")
        );
    }

    /** Everything readable by any context user, so a failed decryption shows up as a status and not as a refusal. */
    core::ContainerPolicy readableByEverybody() {
        core::ContainerPolicy policy;
        policy.get = "all";
        policy.item = core::ItemPolicy{.get = "all", .listAll = "all"};
        return policy;
    }

    /** A keypair nobody has ever used, for a member who joins a group after everything interesting happened. */
    struct Identity {
        std::string userId;
        std::string privKey;
        std::string pubKey;
    };
    Identity newIdentity(const std::string& userId) {
        const privmx::crypto::PrivateKey key = privmx::crypto::PrivateKey::generateRandom();
        return Identity{
            .userId = userId, .privKey = key.toWIF(), .pubKey = key.getPublicKey().toBase58DER()
        };
    }
    static core::UserWithPubKey asMember(const Identity& identity) {
        return core::UserWithPubKey{.userId = identity.userId, .pubKey = identity.pubKey};
    }

    /** A thread whose only direct member is user_1, readable by the group through a grant at its current epoch. */
    std::string createThreadGrantedTo(const group::Group& group) {
        return threadApi->createThread(
            contextId(), std::vector<core::UserWithPubKey>{user(1)}, std::vector<core::UserWithPubKey>{user(1)},
            core::Buffer::from("abuse_thread_public"), core::Buffer::from("abuse_thread_private"),
            readableByEverybody(),
            std::vector<core::GroupGrantWithKey>{{
                .groupId = group.groupId,
                .role = "user",
                .groupPubKey = group.groupPubKey,
                .groupEpoch = group.keyVersion
            }}
        );
    }

    /**
     * Rotates the thread's own content key and re-grants the group at its current epoch.
     *
     * Without this a group rotation changes nothing about a container: its one content key stays wrapped to the
     * epoch it was granted at, so every message would keep needing the same group key. Re-keying per epoch is
     * what makes each message depend on the epoch that was current when it was written.
     */
    void rekeyThreadForGroupEpoch(const std::string& threadId, const group::Group& group) {
        const thread::Thread current = threadApi->getThread(threadId);
        threadApi->updateThread(
            threadId, std::vector<core::UserWithPubKey>{user(1)}, std::vector<core::UserWithPubKey>{user(1)},
            current.publicMeta, current.privateMeta, current.version, false, true, readableByEverybody(),
            std::vector<core::GroupGrantWithKey>{{
                .groupId = group.groupId,
                .role = "user",
                .groupPubKey = group.groupPubKey,
                .groupEpoch = group.keyVersion
            }}
        );
    }

    /**
     * The Bridge management API key, which the dataset's ini carries in its `[Api]` section.
     *
     * Registering a context user is the one step in these scenarios that no client key can perform. A dataset
     * generated before that section existed simply cannot host those tests, hence the skip rather than a
     * failure.
     */
    bool hasManagementApi() {
        return reader->has("Api.apiKeyId") && reader->has("Api.apiKeySecret");
    }

    /** Registers `userId` in Context_1 holding `pubKey` — no proof of possession is asked for anywhere. */
    void registerContextUser(const std::string& userId, const std::string& pubKey) {
        const std::string params = "{\"contextId\": \"" + contextId() + "\", \"userId\": \"" + userId +
            "\", \"userPubKey\": \"" + pubKey + "\"}";
        std::string response;
        ASSERT_NO_THROW({
            response = core::BackendRequester::backendRequest(
                getPlatformUrl(), reader->getString("Api.apiKeyId"), reader->getString("Api.apiKeySecret"), 0,
                "context/addUserToContext", params
            );
        });
        ASSERT_EQ(response.find("\"error\""), std::string::npos) << response;
    }

    /**
     * Runs `body(groupApi, threadApi)` on a brand-new session for the given login.
     *
     * Whether somebody still has access has to be answered from the server's current state alone: a session
     * that was open while the tree changed keeps the keys it already recovered, and would answer "yes" long
     * after the answer became "no".
     *
     * One websocket carries at most one session per user key, and the endpoint shares a websocket per host, so
     * a second live session for the login the fixture already holds is refused ("Websocket already
     * authorized"). The fixture's session therefore steps aside for the probe and comes back afterwards —
     * which also leaves it cold, so a later assertion cannot be answered out of a cache either.
     */
    template <typename Body>
    void onFreshSessionWith(const std::string& privKey, Body body) {
        auto freshConnection = connectWith(privKey);
        privmx::test::ScopeExit closeIt([&] { freshConnection->disconnect(); });
        auto groups = group::GroupApi::create(*freshConnection);
        auto threads = thread::ThreadApi::create(*freshConnection, groups);
        body(groups, threads);
    }

    template <typename Body>
    void onFreshSession(int index, Body body) {
        const bool stepAside = index == fixtureUserIndex;
        if (stepAside) {
            disconnect();
        }
        privmx::test::ScopeExit restoreFixture([&] {
            if (stepAside) {
                connectAs(index);
            }
        });
        onFreshSessionWith(reader->getString("Login.user_" + std::to_string(index) + "_privKey"), body);
    }

    /**
     * Whether a probe produced a verified read.
     *
     * A read the Bridge refuses outright counts as no access just as a non-zero status does — both mean the
     * caller sees no plaintext. `lastReadError` holds why, for the expectations that wanted a yes.
     */
    template <typename Probe>
    bool decrypts(Probe probe) {
        lastReadError.clear();
        try {
            return probe() == 0;
        } catch (const core::Exception& e) {
            lastReadError = e.getFull();
        } catch (const std::exception& e) {
            lastReadError = e.what();
        }
        return false;
    }

    bool canReadGroup(int index, const std::string& groupId) {
        bool readable = false;
        onFreshSession(index, [&](group::GroupApi& groups, thread::ThreadApi&) {
            readable = decrypts([&] { return groups.getGroup(groupId).statusCode; });
        });
        return readable;
    }

    bool canReadThread(int index, const std::string& threadId) {
        bool readable = false;
        onFreshSession(index, [&](group::GroupApi&, thread::ThreadApi& threads) {
            readable = decrypts([&] { return threads.getThread(threadId).statusCode; });
        });
        return readable;
    }

    bool canReadMessage(int index, const std::string& messageId) {
        bool readable = false;
        onFreshSession(index, [&](group::GroupApi&, thread::ThreadApi& threads) {
            readable = decrypts([&] { return threads.getMessage(messageId).statusCode; });
        });
        return readable;
    }

    /** The same probes for a login the ini knows nothing about — a member registered during the test. */
    bool canReadGroupAs(const Identity& identity, const std::string& groupId) {
        bool readable = false;
        onFreshSessionWith(identity.privKey, [&](group::GroupApi& groups, thread::ThreadApi&) {
            readable = decrypts([&] { return groups.getGroup(groupId).statusCode; });
        });
        return readable;
    }

    bool canReadMessageAs(const Identity& identity, const std::string& messageId) {
        bool readable = false;
        onFreshSessionWith(identity.privKey, [&](group::GroupApi&, thread::ThreadApi& threads) {
            readable = decrypts([&] { return threads.getMessage(messageId).statusCode; });
        });
        return readable;
    }

    /**
     * As `canReadGroupAs`, for a key the Bridge may no longer recognise as anybody at all.
     *
     * A key that has been rotated away belongs to no context user, so the session itself can be refused rather
     * than just the read — which is still "no access", and has to be caught here instead of escaping as an
     * environment error.
     */
    bool canReadGroupWithRetiredKey(const Identity& identity, const std::string& groupId) {
        try {
            bool readable = false;
            onFreshSessionWith(identity.privKey, [&](group::GroupApi& groups, thread::ThreadApi&) {
                readable = decrypts([&] { return groups.getGroup(groupId).statusCode; });
            });
            return readable;
        } catch (const core::Exception& e) {
            lastReadError = e.getFull();
        } catch (const std::exception& e) {
            lastReadError = e.what();
        }
        return false;
    }

    /** The public key the Bridge currently reports for a context user, or empty when it knows no such user. */
    std::string pubKeyOnBridge(const std::string& userId) {
        const auto page = connection->listContextUsers(
            contextId(), core::PagingQuery{.skip = 0, .limit = 100, .sortOrder = "asc"}
        );
        for (const auto& info : page.readItems) {
            if (info.user.userId == userId) {
                return info.user.pubKey;
            }
        }
        return std::string();
    }

    static bool contains(const std::vector<std::string>& haystack, const std::string& needle) {
        return std::find(haystack.begin(), haystack.end(), needle) != haystack.end();
    }

    /** Why the last `canRead*` probe came back false, when it failed rather than just decrypting to nothing. */
    std::string lastReadError;
    /** Which login the fixture's own session holds — the one a probe has to make room for. */
    int fixtureUserIndex = 0;
    std::shared_ptr<core::Connection> connection;
    std::shared_ptr<group::GroupApi> groupApi;
    std::shared_ptr<thread::ThreadApi> threadApi;
    Poco::Util::IniFileConfiguration::Ptr reader;
    core::VarSerializer _serializer = core::VarSerializer({});
};

static constexpr const char* MANAGEMENT_API_MISSING =
    "dataset ini has no [Api] section; regenerate it with scripts/dataset.sh to run this test";

// ─────────────────────────────────────────────────────────────────────────────
// a group's key worn as a user's key
// ─────────────────────────────────────────────────────────────────────────────

TEST_F(GroupAbuseTest, SECURITY_a_group_key_worn_as_a_user_key_is_not_a_route_the_endpoint_follows) {
    if (!hasManagementApi()) {
        GTEST_SKIP() << MANAGEMENT_API_MISSING;
    }
    // G's members are user_1 and user_2, and its grant public key is then registered as a context user of its
    // own. From here on nothing in a roster distinguishes "the group G" from "a person".
    //
    // What this pins is that the endpoint will not follow the wrap: a caller climbs from the leaf its *userId*
    // is seated at, and no code path tries a group key against a user-addressed key entry. It is not a claim
    // that the ciphertext is protected — see `ladder_*` below for what a group's key is actually worth.
    std::string groupId;
    ASSERT_NO_THROW({ groupId = createTreeGroup({user(1), user(2)}); });
    group::Group g;
    ASSERT_NO_THROW({ g = groupApi->getGroup(groupId); });
    ASSERT_EQ(g.statusCode, 0);
    ASSERT_FALSE(g.groupPubKey.empty());

    const std::string wornAsUser = "group_worn_as_user";
    ASSERT_NO_FATAL_FAILURE(registerContextUser(wornAsUser, g.groupPubKey));

    // T wraps its content key to that "user" — that is, to G's epoch-1 grant key — while G is not a grantee of
    // T at all. Nothing about T records that a group is behind the seat, so T is never re-keyed when G rotates,
    // and the wrap stays addressed to an epoch key that G's whole membership can derive for good.
    const core::UserWithPubKey groupAsThreadMember{.userId = wornAsUser, .pubKey = g.groupPubKey};
    std::string threadId;
    try {
        threadId = threadApi->createThread(
            contextId(), std::vector<core::UserWithPubKey>{user(1), groupAsThreadMember},
            std::vector<core::UserWithPubKey>{user(1)}, core::Buffer::from("worn_key_public"),
            core::Buffer::from("worn_key_private"), readableByEverybody()
        );
    } catch (const core::Exception& e) {
        GTEST_SUCCEED() << "the Bridge refused a container member wearing a group's key: " << e.getFull();
        return;
    }
    ASSERT_FALSE(threadId.empty());
    std::string messageId;
    ASSERT_NO_THROW({
        messageId = threadApi->sendMessage(
            threadId, core::Buffer::from("worn_msg_public"), core::Buffer::from("worn_msg_private"),
            core::Buffer::from("worn_msg_data")
        );
    });

    // user_2 climbs G, so the key this wrap is addressed to is one they can derive. Through the endpoint it must
    // still buy them nothing: they are not a member of T and no group grant names G there.
    EXPECT_FALSE(canReadThread(2, threadId)) << "the endpoint opened a thread through a group key worn as a user key";
    EXPECT_FALSE(canReadMessage(2, messageId)) <<
        "the endpoint opened a message through a group key worn as a user key";

    // And G itself is untouched by the impersonation: same epoch, still readable, still removable-from.
    group::Group afterAbuse;
    ASSERT_NO_THROW({ afterAbuse = groupApi->getGroup(groupId); });
    EXPECT_EQ(afterAbuse.statusCode, 0);
    EXPECT_EQ(afterAbuse.keyVersion, g.keyVersion);
    EXPECT_NO_THROW({
        groupApi->removeGroupMembers(groupId, {user(2).userId});
    });
    group::Group afterRemoval;
    ASSERT_NO_THROW({ afterRemoval = groupApi->getGroup(groupId); });
    EXPECT_EQ(afterRemoval.statusCode, 0);
    EXPECT_EQ(afterRemoval.keyVersion, g.keyVersion + 1);
}

TEST_F(GroupAbuseTest, SECURITY_a_group_key_worn_as_a_user_key_is_not_a_route_into_another_group) {
    if (!hasManagementApi()) {
        GTEST_SKIP() << MANAGEMENT_API_MISSING;
    }
    // A = user_1 + user_2, B = user_1 + user_3. A's grant key is registered as a context user and then seated
    // in B's tree: a group nested inside a group, smuggled in as a person.
    //
    // The endpoint gives A's members nothing here, because which leaf a caller may climb from is decided by
    // their userId and nobody can authenticate as the seat. The ciphertext is another matter: the edge into that
    // leaf is wrapped to A's epoch-1 grant key, which every A member can derive for good, so seating a group's
    // key in a tree leaves a standing cryptographic bridge between the two groups that B can neither see nor
    // revoke. Removing the seat does not unpublish the edge either.
    std::string groupA, groupB;
    ASSERT_NO_THROW({ groupA = createTreeGroup({user(1), user(2)}); });
    ASSERT_NO_THROW({ groupB = createTreeGroup({user(1), user(3)}); });
    group::Group a, b;
    ASSERT_NO_THROW({ a = groupApi->getGroup(groupA); });
    ASSERT_NO_THROW({ b = groupApi->getGroup(groupB); });
    ASSERT_EQ(a.statusCode, 0);
    ASSERT_EQ(b.statusCode, 0);

    const std::string wornAsUser = "group_a_worn_as_user";
    ASSERT_NO_FATAL_FAILURE(registerContextUser(wornAsUser, a.groupPubKey));
    const core::UserWithPubKey nestedGroup{.userId = wornAsUser, .pubKey = a.groupPubKey};

    bool seated = true;
    std::string refusal;
    try {
        groupApi->addGroupMembers(groupB, {group::GroupMemberToAdd{.user = nestedGroup, .role = "user"}});
    } catch (const core::Exception& e) {
        seated = false;
        refusal = e.getFull();
    }

    // user_2 is a member of A and holds no seat of their own in B. Whether or not the seat was allowed, being
    // able to climb A must not become a way into B through the endpoint.
    EXPECT_FALSE(canReadGroup(2, groupB)) << "the endpoint let a member of A into B through A's key (seat " <<
        (seated ? "was accepted)" : "was refused: " + refusal + ")");

    // B's own members are unaffected, and B's tree still takes a removal: a rogue leaf must not wedge it.
    EXPECT_TRUE(canReadGroup(3, groupB)) << "a real member of B lost access; " << lastReadError;
    EXPECT_NO_THROW({
        groupApi->removeGroupMembers(groupB, {user(3).userId});
    }) << "B's tree stopped taking removals with a rogue leaf in it (seat " <<
        (seated ? "was accepted)" : "was refused)");
    group::Group afterRemoval;
    ASSERT_NO_THROW({ afterRemoval = groupApi->getGroup(groupB); });
    EXPECT_EQ(afterRemoval.statusCode, 0);
    EXPECT_EQ(afterRemoval.keyVersion, b.keyVersion + 1);
    EXPECT_TRUE(canReadGroup(1, groupB)) << "B's manager lost access to their own group; " << lastReadError;
    // B rotating does not retire A's epoch-1 key — A's members keep it via the ladder — so this has to keep
    // holding for the same reason as before: the route, not the key, is what B's rotation does not grant.
    EXPECT_FALSE(canReadGroup(2, groupB)) << "the endpoint let a member of A into B through A's key after B rotated";
}

TEST_F(GroupAbuseTest, SECURITY_a_group_cannot_be_seated_as_a_member_of_another_group) {
    // The straightforward reach for nested groups: name the group by its own id and its own public key. No
    // context user was registered for it, so there is no person behind the seat at all.
    std::string groupA, groupB;
    ASSERT_NO_THROW({ groupA = createTreeGroup({user(1), user(2)}); });
    ASSERT_NO_THROW({ groupB = createTreeGroup({user(1), user(3)}); });
    group::Group a, b;
    ASSERT_NO_THROW({ a = groupApi->getGroup(groupA); });
    ASSERT_NO_THROW({ b = groupApi->getGroup(groupB); });
    ASSERT_EQ(a.statusCode, 0);
    ASSERT_EQ(b.statusCode, 0);
    const core::UserWithPubKey groupAsMember{.userId = a.groupId, .pubKey = a.groupPubKey};

    EXPECT_THROW(
        {
            groupApi->addGroupMembers(groupB, {group::GroupMemberToAdd{.user = groupAsMember, .role = "user"}});
        },
        core::Exception
    );

    // The same through creation, where the group would be a founding member rather than an addition.
    EXPECT_THROW(
        {
            groupApi->createGroup(
                contextId(), std::vector<core::UserWithPubKey>{user(1), groupAsMember},
                std::vector<core::UserWithPubKey>{user(1)}, core::Buffer::from("abuse_public"),
                core::Buffer::from("abuse_private")
            );
        },
        core::Exception
    );

    // A refused addition must leave B exactly as it was — no half-applied transition, no epoch drift.
    group::Group afterAttempts;
    ASSERT_NO_THROW({ afterAttempts = groupApi->getGroup(groupB); });
    EXPECT_EQ(afterAttempts.statusCode, 0);
    EXPECT_EQ(afterAttempts.keyVersion, b.keyVersion);
    EXPECT_EQ(afterAttempts.users.size(), b.users.size());
    EXPECT_FALSE(contains(afterAttempts.users, a.groupId));
    EXPECT_FALSE(contains(afterAttempts.managers, a.groupId));
    EXPECT_TRUE(canReadGroup(3, groupB)) << "a real member of B lost access to a group that never changed; " <<
        lastReadError;
}

// ─────────────────────────────────────────────────────────────────────────────
// what a group's key is worth: the epoch ladder
// ─────────────────────────────────────────────────────────────────────────────

TEST_F(GroupAbuseTest, ladder_hands_a_newcomer_every_epoch_the_group_ever_read) {
    if (!hasManagementApi()) {
        GTEST_SKIP() << MANAGEMENT_API_MISSING;
    }
    // G starts as user_1 (manager) plus user_2 and user_3. T grants G and is re-keyed at every one of G's
    // epochs, so each message can only be opened with the group key of the epoch that was current when it was
    // sent — otherwise T's single content key would make all three messages one and the same test.
    std::string groupId;
    ASSERT_NO_THROW({ groupId = createTreeGroup({user(1), user(2), user(3)}); });
    group::Group atEpoch1;
    ASSERT_NO_THROW({ atEpoch1 = groupApi->getGroup(groupId); });
    ASSERT_EQ(atEpoch1.statusCode, 0);
    ASSERT_EQ(atEpoch1.keyVersion, 1);

    std::string threadId;
    ASSERT_NO_THROW({ threadId = createThreadGrantedTo(atEpoch1); });
    ASSERT_FALSE(threadId.empty());
    std::string firstEpochMessage;
    ASSERT_NO_THROW({
        firstEpochMessage = threadApi->sendMessage(
            threadId, core::Buffer::from("e1_public"), core::Buffer::from("e1_private"),
            core::Buffer::from("epoch_1_data")
        );
    });

    // user_2 out: epoch 2. T is re-keyed and re-granted there, so the next message needs the epoch-2 key.
    ASSERT_NO_THROW({
        groupApi->removeGroupMembers(groupId, {user(2).userId});
    });
    group::Group atEpoch2;
    ASSERT_NO_THROW({ atEpoch2 = groupApi->getGroup(groupId); });
    ASSERT_EQ(atEpoch2.keyVersion, 2);
    ASSERT_NO_THROW({ rekeyThreadForGroupEpoch(threadId, atEpoch2); });
    std::string secondEpochMessage;
    ASSERT_NO_THROW({
        secondEpochMessage = threadApi->sendMessage(
            threadId, core::Buffer::from("e2_public"), core::Buffer::from("e2_private"),
            core::Buffer::from("epoch_2_data")
        );
    });

    // user_3 out: epoch 3, same again.
    ASSERT_NO_THROW({
        groupApi->removeGroupMembers(groupId, {user(3).userId});
    });
    group::Group atEpoch3;
    ASSERT_NO_THROW({ atEpoch3 = groupApi->getGroup(groupId); });
    ASSERT_EQ(atEpoch3.keyVersion, 3);
    ASSERT_NO_THROW({ rekeyThreadForGroupEpoch(threadId, atEpoch3); });
    std::string thirdEpochMessage;
    ASSERT_NO_THROW({
        thirdEpochMessage = threadApi->sendMessage(
            threadId, core::Buffer::from("e3_public"), core::Buffer::from("e3_private"),
            core::Buffer::from("epoch_3_data")
        );
    });

    // A keypair generated just now, registered just now, seated in G at epoch 3 only. It has never held any
    // earlier epoch key, and its account did not exist when the first two messages were written.
    const Identity newcomer = newIdentity("group_newcomer");
    ASSERT_NO_FATAL_FAILURE(registerContextUser(newcomer.userId, newcomer.pubKey));
    ASSERT_NO_THROW({
        groupApi->addGroupMembers(groupId, {group::GroupMemberToAdd{.user = asMember(newcomer), .role = "user"}});
    });
    group::Group afterJoin;
    ASSERT_NO_THROW({ afterJoin = groupApi->getGroup(groupId); });
    EXPECT_EQ(afterJoin.keyVersion, 3) << "an addition must not advance the epoch";

    // The ladder hands them every epoch below the one they joined at. This is the design working as intended —
    // and it is also the finding: T's owner granted G once, at epoch 1, and G's manager can hand T's entire
    // history to an account created afterwards, without touching T and without T being able to tell.
    EXPECT_TRUE(canReadMessageAs(newcomer, thirdEpochMessage)) << "the newcomer cannot read their own epoch; " <<
        lastReadError;
    EXPECT_TRUE(canReadMessageAs(newcomer, secondEpochMessage)) << "the ladder did not reach epoch 2; " <<
        lastReadError;
    EXPECT_TRUE(canReadMessageAs(newcomer, firstEpochMessage)) << "the ladder did not reach epoch 1; " <<
        lastReadError;
    EXPECT_TRUE(canReadGroupAs(newcomer, groupId)) << "the newcomer cannot read the group itself; " << lastReadError;

    // The other direction is not symmetric, and that asymmetry is the point: a removed member loses the *route*,
    // so the endpoint will not serve them even the epoch they themselves were a member of. user_2 held the
    // epoch-1 key while it was current; a cold session of theirs cannot climb G at all any more. What that key
    // already opened it opened for good — these two probes say what is served, not what stays confidential.
    EXPECT_FALSE(canReadMessage(2, firstEpochMessage)) <<
        "a removed member is still served content from the epoch they were in";
    EXPECT_FALSE(canReadMessage(3, secondEpochMessage)) <<
        "a removed member is still served content from the epoch they were in";
}

TEST_F(GroupAbuseTest, ladder_gives_a_re_added_member_back_what_was_written_while_they_were_out) {
    // Removal looks like a durable act — the epoch moves, the member goes dark. It is not: re-seating them puts
    // the current epoch key back in their hands, and the ladder turns that into every earlier epoch too. So the
    // window in which they were excluded is handed back in full, including content written specifically while
    // they were out.
    std::string groupId;
    ASSERT_NO_THROW({ groupId = createTreeGroup({user(1), user(2)}); });
    group::Group atEpoch1;
    ASSERT_NO_THROW({ atEpoch1 = groupApi->getGroup(groupId); });
    ASSERT_EQ(atEpoch1.keyVersion, 1);

    std::string threadId;
    ASSERT_NO_THROW({ threadId = createThreadGrantedTo(atEpoch1); });
    std::string beforeRemoval;
    ASSERT_NO_THROW({
        beforeRemoval = threadApi->sendMessage(
            threadId, core::Buffer::from("before_public"), core::Buffer::from("before_private"),
            core::Buffer::from("before_removal_data")
        );
    });
    EXPECT_TRUE(canReadMessage(2, beforeRemoval)) << "a member could not read while they were in; " << lastReadError;

    // user_2 out: epoch 2, T re-keyed there, and one message written while they are excluded.
    ASSERT_NO_THROW({
        groupApi->removeGroupMembers(groupId, {user(2).userId});
    });
    group::Group atEpoch2;
    ASSERT_NO_THROW({ atEpoch2 = groupApi->getGroup(groupId); });
    ASSERT_EQ(atEpoch2.keyVersion, 2);
    ASSERT_NO_THROW({ rekeyThreadForGroupEpoch(threadId, atEpoch2); });
    std::string writtenWhileOut;
    ASSERT_NO_THROW({
        writtenWhileOut = threadApi->sendMessage(
            threadId, core::Buffer::from("gap_public"), core::Buffer::from("gap_private"),
            core::Buffer::from("written_while_out_data")
        );
    });

    // While out, both are closed to them — the group route is gone, and they were never a member of T.
    EXPECT_FALSE(canReadMessage(2, writtenWhileOut)) << "a removed member read content written after their removal";
    EXPECT_FALSE(canReadMessage(2, beforeRemoval)) << "a removed member kept the group route to older content";

    // Re-seated at epoch 2 — no new epoch, nothing about T touched.
    ASSERT_NO_THROW({
        groupApi->addGroupMembers(groupId, {group::GroupMemberToAdd{.user = user(2), .role = "user"}});
    });
    group::Group afterReadd;
    ASSERT_NO_THROW({ afterReadd = groupApi->getGroup(groupId); });
    EXPECT_EQ(afterReadd.keyVersion, 2);

    // And the exclusion window is handed back: the message written while they were out, and the older one too.
    EXPECT_TRUE(canReadMessage(2, writtenWhileOut)) <<
        "expected the re-added member to regain the gap (that is what the ladder does); " << lastReadError;
    EXPECT_TRUE(canReadMessage(2, beforeRemoval)) << "the ladder did not reach back to epoch 1; " << lastReadError;
}

/**
 * An epoch rotation is not post-compromise security: it does not take access back from a stolen member key.
 *
 * A removal refreshes the departing member's path and mints a new grant key, and every refreshed key is wrapped
 * to the *unchanged* long-term keys of the members who stay. So whoever holds user_2's private key climbs the new
 * epoch exactly as user_2 does, and reads content written after the rotation. That is intended — the tree cannot
 * tell a thief from the member, and nothing in the API rotates a member's own key — and the test exists so that
 * nobody makes it look fixed: should the first expectation below ever turn red, the reason had better be a real
 * re-seating of that member, not a refreshed path wrapped to the same stolen key.
 *
 * And removing that member ends less than it appears to. It closes the route to *new* epochs and nothing more:
 * the ladder's premise is that holding epoch N yields every epoch below it, so whatever a stolen key reached
 * before the removal, it reached for good — no rotation and no removal takes history back. The negative
 * expectations at the end are therefore narrow in the way this file's header describes: they say the endpoint
 * stops *following* the route, not that the ciphertext became safe.
 *
 * Every probe runs on a cold session, so what they show is that the key alone suffices, with no cached state.
 */
TEST_F(GroupAbuseTest, rotating_the_epoch_does_not_take_back_a_compromised_members_key) {
    std::string groupId;
    ASSERT_NO_THROW({ groupId = createTreeGroup({user(1), user(2), user(3)}); });
    group::Group atEpoch1;
    ASSERT_NO_THROW({ atEpoch1 = groupApi->getGroup(groupId); });
    ASSERT_EQ(atEpoch1.statusCode, 0);
    ASSERT_EQ(atEpoch1.keyVersion, 1);

    std::string threadId;
    ASSERT_NO_THROW({ threadId = createThreadGrantedTo(atEpoch1); });
    std::string beforeRotation;
    ASSERT_NO_THROW({
        beforeRotation = threadApi->sendMessage(
            threadId, core::Buffer::from("pre_public"), core::Buffer::from("pre_private"),
            core::Buffer::from("before_rotation_data")
        );
    });
    ASSERT_TRUE(canReadMessage(2, beforeRotation)) << "the member could not read before the rotation; " <<
        lastReadError;

    // The rotation: user_3 — somebody else entirely — is removed, which is the one call that mints a new epoch.
    ASSERT_NO_THROW({ groupApi->removeGroupMembers(groupId, {user(3).userId}); });
    group::Group atEpoch2;
    ASSERT_NO_THROW({ atEpoch2 = groupApi->getGroup(groupId); });
    ASSERT_EQ(atEpoch2.keyVersion, 2) << "nothing rotated, so this test would prove nothing";
    ASSERT_NO_THROW({ rekeyThreadForGroupEpoch(threadId, atEpoch2); });
    std::string afterRotation;
    ASSERT_NO_THROW({
        afterRotation = threadApi->sendMessage(
            threadId, core::Buffer::from("post_public"), core::Buffer::from("post_private"),
            core::Buffer::from("after_rotation_data")
        );
    });

    // The finding: user_2's leaf was never re-wrapped, so their key opens the epoch the rotation minted — and
    // with it content written afterwards, which needs that epoch's key and no earlier one.
    EXPECT_TRUE(canReadMessage(2, afterRotation)) <<
        "expected the compromised key to keep reading — a rotation is not post-compromise security; " <<
        lastReadError;

    // Nor is there another rotation to reach for: `updateGroup` edits metadata and nothing else, and the epoch
    // moves only where a member leaves. Which is the one thing that does end it — their path is refreshed and the
    // new grant key reaches their leaf through nothing, so the stolen key stops being served: the new epoch and,
    // through the endpoint, everything older with it. What removal does not do is take back what that key already
    // read, which the ladder makes permanent.
    ASSERT_NO_THROW({ groupApi->removeGroupMembers(groupId, {user(2).userId}); });
    group::Group atEpoch3;
    ASSERT_NO_THROW({ atEpoch3 = groupApi->getGroup(groupId); });
    ASSERT_EQ(atEpoch3.keyVersion, 3);
    ASSERT_NO_THROW({ rekeyThreadForGroupEpoch(threadId, atEpoch3); });
    std::string afterRemoval;
    ASSERT_NO_THROW({
        afterRemoval = threadApi->sendMessage(
            threadId, core::Buffer::from("out_public"), core::Buffer::from("out_private"),
            core::Buffer::from("after_removal_data")
        );
    });
    EXPECT_FALSE(canReadMessage(2, afterRemoval)) << "the removed member's key is still served new content";
    EXPECT_FALSE(canReadMessage(2, afterRotation)) << "the removed member's key is still served the group route";
}

TEST_F(GroupAbuseTest, changing_a_members_public_key_locks_them_out_without_re_wrapping_their_leaf) {
    if (!hasManagementApi()) {
        GTEST_SKIP() << MANAGEMENT_API_MISSING;
    }
    // `context/addUserToContext` is an upsert: called twice for one userId it *replaces* the public key
    // (`ContextUserRepository::insertOrUpdate`). That is the supported way to rotate a member's key — and
    // nothing in it touches the groups that member sits in. Their leaf edge stays wrapped to the key that was
    // current when they were seated, and no field anywhere records which key that was.
    const Identity firstKey = newIdentity("rotating_member");
    ASSERT_NO_FATAL_FAILURE(registerContextUser(firstKey.userId, firstKey.pubKey));

    std::string groupId;
    ASSERT_NO_THROW({ groupId = createTreeGroup({user(1), asMember(firstKey)}); });
    group::Group atEpoch1;
    ASSERT_NO_THROW({ atEpoch1 = groupApi->getGroup(groupId); });
    ASSERT_EQ(atEpoch1.statusCode, 0);
    ASSERT_EQ(atEpoch1.keyVersion, 1);

    std::string threadId;
    ASSERT_NO_THROW({ threadId = createThreadGrantedTo(atEpoch1); });
    std::string messageId;
    ASSERT_NO_THROW({
        messageId = threadApi->sendMessage(
            threadId, core::Buffer::from("rot_public"), core::Buffer::from("rot_private"),
            core::Buffer::from("rot_data")
        );
    });

    // Baseline: with the key they were seated with, the member reads the group and everything it was granted.
    ASSERT_TRUE(canReadGroupAs(firstKey, groupId)) << "the member could not read before the rotation; " <<
        lastReadError;
    ASSERT_TRUE(canReadMessageAs(firstKey, messageId)) << lastReadError;

    // The rotation: same userId, brand-new keypair. The Bridge takes it and serves the new key from now on.
    const Identity secondKey = newIdentity(firstKey.userId);
    ASSERT_NO_FATAL_FAILURE(registerContextUser(secondKey.userId, secondKey.pubKey));
    EXPECT_EQ(pubKeyOnBridge(firstKey.userId), secondKey.pubKey) <<
        "addUserToContext did not replace the member's public key, so this test proves nothing";

    // The member now holds a key their own leaf was never wrapped to, so the climb has nothing to start from:
    // they lose the group, and with it every container the group could read. Nobody removed them.
    EXPECT_FALSE(canReadGroupAs(secondKey, groupId)) << "the rotated-in key opened a leaf it was never wrapped to";
    EXPECT_FALSE(canReadMessageAs(secondKey, messageId)) << "the rotated-in key opened content it has no route to";

    // Meanwhile the roster still names them, so the Bridge's own answer to "who has access" is now wrong in
    // both directions: it lists somebody who cannot read, and the tree still holds a wrap for a key the Bridge
    // no longer recognises as anybody.
    group::Group afterRotation;
    ASSERT_NO_THROW({ afterRotation = groupApi->getGroup(groupId); });
    EXPECT_EQ(afterRotation.statusCode, 0);
    EXPECT_EQ(afterRotation.keyVersion, 1) << "a key rotation must not be mistaken for a membership change";
    EXPECT_TRUE(contains(afterRotation.users, firstKey.userId)) <<
        "the locked-out member is still on the roster — that is the mismatch this test is about";

    // The retired key gets no route either: it belongs to no context user any more, so the endpoint has nothing
    // to serve it. What it still holds is the *ciphertext* — the leaf edge is unchanged and no rotation of the
    // group's own epoch re-wraps it, which is the part this test cannot probe through the public API.
    EXPECT_FALSE(canReadGroupWithRetiredKey(firstKey, groupId)) <<
        "a key the Bridge no longer knows still got served the group";

    // Only re-seating repairs it, and it repairs it completely: the removal refreshes the leaf's path and mints
    // epoch 2, the addition wraps the new leaf to the new key, and the ladder hands back the epoch-1 history.
    ASSERT_NO_THROW({
        groupApi->removeGroupMembers(groupId, {firstKey.userId});
    });
    ASSERT_NO_THROW({
        groupApi->addGroupMembers(groupId, {group::GroupMemberToAdd{.user = asMember(secondKey), .role = "user"}});
    });
    group::Group afterReseat;
    ASSERT_NO_THROW({ afterReseat = groupApi->getGroup(groupId); });
    EXPECT_EQ(afterReseat.keyVersion, 2);
    EXPECT_TRUE(canReadGroupAs(secondKey, groupId)) << "re-seating did not restore access; " << lastReadError;
    EXPECT_TRUE(canReadMessageAs(secondKey, messageId)) <<
        "re-seating did not hand back the pre-rotation history; " << lastReadError;
}

// ─────────────────────────────────────────────────────────────────────────────
// churning one member's seat
// ─────────────────────────────────────────────────────────────────────────────

TEST_F(GroupAbuseTest, add_and_remove_the_same_member_repeatedly_keeps_the_tree_consistent) {
    // Three add/remove cycles on the same member. Each removal blanks their leaf, refreshes its path and mints
    // an epoch; each addition seats them again, reusing a blank, and must not advance the epoch. What this
    // hunts for is residue: a leaf that stays half-blank, a generation that stops matching, an archive rung
    // that leaves an earlier epoch unreachable — anything that would show up as a member losing access to a
    // group nobody removed them from.
    std::string groupId;
    ASSERT_NO_THROW({ groupId = createTreeGroup({user(1), user(2), user(3)}); });
    int64_t epoch = 1;
    ASSERT_EQ(groupApi->getGroup(groupId).keyVersion, epoch);

    for (int cycle = 1; cycle <= 3; ++cycle) {
        SCOPED_TRACE("cycle " + std::to_string(cycle));

        ASSERT_NO_THROW({
            groupApi->removeGroupMembers(groupId, {user(3).userId});
        });
        ++epoch;
        group::Group afterRemoval;
        ASSERT_NO_THROW({ afterRemoval = groupApi->getGroup(groupId); });
        EXPECT_EQ(afterRemoval.statusCode, 0) << "the group stopped verifying after a removal (851979 = 0xD000B, "
            "the G1 chain-link check)";
        EXPECT_EQ(afterRemoval.keyVersion, epoch) << "a removal must advance the epoch exactly once";
        EXPECT_FALSE(contains(afterRemoval.users, user(3).userId));
        EXPECT_FALSE(canReadGroup(3, groupId)) << "the removed member still reads the group";
        EXPECT_TRUE(canReadGroup(2, groupId)) << "a member nobody touched lost access to the group; " <<
            lastReadError;

        ASSERT_NO_THROW({
            groupApi->addGroupMembers(groupId, {group::GroupMemberToAdd{.user = user(3), .role = "user"}});
        });
        group::Group afterAddition;
        ASSERT_NO_THROW({ afterAddition = groupApi->getGroup(groupId); });
        EXPECT_EQ(afterAddition.statusCode, 0) << "the group stopped verifying after an addition (851979 = "
            "0xD000B, the G1 chain-link check)";
        EXPECT_EQ(afterAddition.keyVersion, epoch) << "an addition must not advance the epoch";
        EXPECT_TRUE(contains(afterAddition.users, user(3).userId));
        EXPECT_TRUE(canReadGroup(3, groupId)) << "the re-added member cannot read the group; " << lastReadError;
        EXPECT_TRUE(canReadGroup(2, groupId)) << "a member nobody touched lost access to the group; " <<
            lastReadError;
    }

    // Same roster as at the start, three epochs later, and every member still reads it from a cold client.
    group::Group finalState;
    ASSERT_NO_THROW({ finalState = groupApi->getGroup(groupId); });
    EXPECT_EQ(finalState.statusCode, 0);
    EXPECT_EQ(finalState.keyVersion, 4);
    EXPECT_EQ(finalState.users.size(), 3);

    // Reading again with nothing in between must give the same verified answer. The second call asks for history
    // above the head, so the Bridge re-serves the head entry and the client has to accept a window that overlaps
    // what it already verified instead of taking it for an unanchored one.
    group::Group reread;
    ASSERT_NO_THROW({ reread = groupApi->getGroup(groupId); });
    EXPECT_EQ(reread.statusCode, 0) << "re-reading an unchanged group broke its verification";
    EXPECT_EQ(reread.keyVersion, finalState.keyVersion);
    EXPECT_EQ(reread.version, finalState.version);
    EXPECT_EQ(reread.privateMeta.stdString(), finalState.privateMeta.stdString());
    for (int index = 1; index <= 3; ++index) {
        EXPECT_TRUE(canReadGroup(index, groupId)) << "user_" << index << " cannot read the group; " <<
            lastReadError;
    }
}

TEST_F(GroupAbuseTest, concurrent_add_and_remove_of_the_same_member_leaves_the_group_consistent) {
    // Two managers go for the same seat at the same time: user_1 removes user_3 while user_2 adds them. Any
    // serialisation of the two is acceptable — remove then add (both land), or add first and lose because
    // user_3 is still a member. What is not acceptable is both landing on the same base state: the roster and
    // the tree would then disagree, and somebody would be a member who cannot climb, or a non-member who can.
    //
    // The race needs two *different* logins because a websocket carries one session per user key, so a user
    // cannot hold two sessions at once — which also makes this the more realistic version of the scenario.
    const core::UserWithPubKey remover = user(1);
    const core::UserWithPubKey adder = user(2);
    const core::UserWithPubKey contested = user(3);
    const std::vector<core::UserWithPubKey> managers{remover, adder};
    const std::vector<core::UserWithPubKey> withContested{remover, adder, contested};

    std::string groupId;
    ASSERT_NO_THROW({ groupId = createTreeGroup(withContested, managers); });

    // The fixture's own session (user_1) removes; user_2 gets a session of their own to add from. Both are
    // warmed up before the race, so what overlaps is the mutating call and not two first reads.
    auto adderConnection = connect(2);
    auto adderGroups = group::GroupApi::create(*adderConnection);
    ASSERT_EQ(groupApi->getGroup(groupId).statusCode, 0);
    ASSERT_EQ(adderGroups.getGroup(groupId).statusCode, 0);
    auto& removerGroups = *groupApi;

    bool removed = false;
    bool added = false;
    std::string removeFailure;
    std::string addFailure;
    std::thread removingThread([&] {
        try {
            removerGroups.removeGroupMembers(groupId, {contested.userId});
            removed = true;
        } catch (const core::Exception& e) {
            removeFailure = e.getFull();
        } catch (const std::exception& e) {
            removeFailure = e.what();
        }
    });
    std::thread addingThread([&] {
        try {
            adderGroups.addGroupMembers(groupId, {group::GroupMemberToAdd{.user = contested, .role = "user"}});
            added = true;
        } catch (const core::Exception& e) {
            addFailure = e.getFull();
        } catch (const std::exception& e) {
            addFailure = e.what();
        }
    });
    removingThread.join();
    addingThread.join();
    // user_2's session has to be gone before any probe reconnects as user_2.
    adderConnection->disconnect();

    EXPECT_TRUE(removed || added) << "both calls were dropped; remove: " << removeFailure << " add: " << addFailure;

    group::Group afterRace;
    ASSERT_NO_THROW({ afterRace = groupApi->getGroup(groupId); });
    EXPECT_EQ(afterRace.statusCode, 0) << "the race left the group undecryptable to its manager";
    // Only a removal advances the epoch, and only one removal was asked for.
    EXPECT_EQ(afterRace.keyVersion, removed ? 2 : 1) << "remove: " << removeFailure << " add: " << addFailure;

    // The roster the Bridge serves and who can actually climb must agree — that is the corruption this race
    // could produce, and it is invisible without asking both questions.
    const bool onRoster = contains(afterRace.users, user(3).userId) || contains(afterRace.managers, user(3).userId);
    EXPECT_EQ(canReadGroup(3, groupId), onRoster) <<
        "user_3 is " << (onRoster ? "on the roster but cannot climb" : "off the roster but can still climb");
    EXPECT_TRUE(canReadGroup(2, groupId)) << "a bystanding member lost access to the group; " << lastReadError;
    EXPECT_TRUE(canReadGroup(1, groupId)) << "the manager lost access to their own group; " << lastReadError;
}

TEST_F(GroupAbuseTest, concurrent_update_and_removal_leaves_the_group_verifying) {
    // A metadata update and a removal computed against the same head. Whichever lands second was built against a
    // state that no longer exists, and its roster tag commits a version it will not land at — so the loser has to
    // lose *before* it writes. The version pin is what does that, which is why the update cannot skip it: this
    // test is the regression guard for removing that escape hatch.
    //
    // Any serialisation is acceptable. What is not is a group whose head stops verifying, or a call that reports
    // success without landing.
    const core::UserWithPubKey remover = user(1);
    const core::UserWithPubKey updater = user(2);
    const std::vector<core::UserWithPubKey> managers{remover, updater};

    std::string groupId;
    ASSERT_NO_THROW({ groupId = createTreeGroup({remover, updater, user(3)}, managers); });
    group::Group before;
    ASSERT_NO_THROW({ before = groupApi->getGroup(groupId); });
    ASSERT_EQ(before.statusCode, 0);

    // user_1 removes from the fixture's session; user_2 updates from one of their own. Both are warmed up first,
    // so what overlaps is the mutating call rather than two cold reads.
    auto updaterConnection = connect(2);
    auto updaterGroups = group::GroupApi::create(*updaterConnection);
    ASSERT_EQ(updaterGroups.getGroup(groupId).statusCode, 0);
    auto& removerGroups = *groupApi;

    bool removed = false;
    bool updated = false;
    std::string removeFailure;
    std::string updateFailure;
    std::thread removingThread([&] {
        try {
            removerGroups.removeGroupMembers(groupId, {user(3).userId});
            removed = true;
        } catch (const core::Exception& e) {
            removeFailure = e.getFull();
        } catch (const std::exception& e) {
            removeFailure = e.what();
        }
    });
    std::thread updatingThread([&] {
        try {
            updaterGroups.updateGroup(
                groupId, core::Buffer::from("raced_public"), core::Buffer::from("raced_private"), before.version
            );
            updated = true;
        } catch (const core::Exception& e) {
            updateFailure = e.getFull();
        } catch (const std::exception& e) {
            updateFailure = e.what();
        }
    });
    removingThread.join();
    updatingThread.join();
    // user_2's session has to be gone before any probe reconnects as user_2.
    updaterConnection->disconnect();

    EXPECT_TRUE(removed || updated) << "both calls were dropped; remove: " << removeFailure << " update: " <<
        updateFailure;

    group::Group after;
    ASSERT_NO_THROW({ after = groupApi->getGroup(groupId); });
    EXPECT_EQ(after.statusCode, 0) << "the race left the group's chain unverifiable; remove: " << removeFailure <<
        " update: " << updateFailure;
    // Only a removal moves the epoch; an update moves the version alone, and each call that reported success
    // must have moved it exactly once — a retry is one landing, not two.
    EXPECT_EQ(after.keyVersion, removed ? 2 : 1) << "remove: " << removeFailure << " update: " << updateFailure;
    EXPECT_EQ(after.version, before.version + (removed ? 1 : 0) + (updated ? 1 : 0)) << "remove: " <<
        removeFailure << " update: " << updateFailure;
    if (updated) {
        EXPECT_EQ(after.publicMeta.stdString(), "raced_public") << "the update reported success without landing";
    }
    EXPECT_EQ(contains(after.users, user(3).userId), !removed);
    EXPECT_TRUE(canReadGroup(2, groupId)) << "the manager who updated the group lost access to it; " <<
        lastReadError;
    EXPECT_TRUE(canReadGroup(1, groupId)) << "the manager who removed a member lost access to the group; " <<
        lastReadError;
}
