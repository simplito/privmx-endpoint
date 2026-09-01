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
 * roster, another group's tree. Two things have to hold no matter what is tried. Group membership may only ever
 * grant access through a *group grant*, so a key wrapped to a group's public key by any other route must open
 * for nobody; and no sequence of roster edits, however abusive or concurrent, may leave a group in a state the
 * Bridge accepts but its remaining members cannot climb.
 *
 * Tests named SECURITY assert that something *cannot* happen. They fail silently at runtime if the guard
 * regresses — nothing breaks, access simply persists where it should have ended — so they must not be deleted
 * or weakened into positive assertions.
 *
 * Where the fate of the abusive call itself is not part of the contract (the Bridge may refuse it outright, or
 * take it and leave the caller with a wrap nobody can use), the test records which way it went and asserts the
 * invariant that has to hold either way.
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

    std::shared_ptr<core::Connection> connect(int index) {
        return std::make_shared<core::Connection>(
            core::Connection::connect(
                reader->getString("Login.user_" + std::to_string(index) + "_privKey"),
                reader->getString("Login.solutionId"),
                getPlatformUrl(reader->getString("Login.instanceUrl"))
            )
        );
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
        auto freshConnection = connect(index);
        privmx::test::ScopeExit closeIt([&] { freshConnection->disconnect(); });
        auto groups = group::GroupApi::create(*freshConnection);
        auto threads = thread::ThreadApi::create(*freshConnection, groups);
        body(groups, threads);
    }

    /**
     * Whether a cold client for the given login can actually decrypt the group.
     *
     * A read the Bridge refuses outright counts as no access just as a non-zero status does — both mean the
     * caller sees no plaintext. `lastReadError` holds why, for the expectations that wanted a yes.
     */
    bool canReadGroup(int index, const std::string& groupId) {
        bool readable = false;
        lastReadError.clear();
        onFreshSession(index, [&](group::GroupApi& groups, thread::ThreadApi&) {
            try {
                readable = groups.getGroup(groupId).statusCode == 0;
            } catch (const core::Exception& e) {
                lastReadError = e.getFull();
            } catch (const std::exception& e) {
                lastReadError = e.what();
            }
        });
        return readable;
    }

    bool canReadThread(int index, const std::string& threadId) {
        bool readable = false;
        lastReadError.clear();
        onFreshSession(index, [&](group::GroupApi&, thread::ThreadApi& threads) {
            try {
                readable = threads.getThread(threadId).statusCode == 0;
            } catch (const core::Exception& e) {
                lastReadError = e.getFull();
            } catch (const std::exception& e) {
                lastReadError = e.what();
            }
        });
        return readable;
    }

    bool canReadMessage(int index, const std::string& messageId) {
        bool readable = false;
        lastReadError.clear();
        onFreshSession(index, [&](group::GroupApi&, thread::ThreadApi& threads) {
            try {
                readable = threads.getMessage(messageId).statusCode == 0;
            } catch (const core::Exception& e) {
                lastReadError = e.getFull();
            } catch (const std::exception& e) {
                lastReadError = e.what();
            }
        });
        return readable;
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

TEST_F(GroupAbuseTest, SECURITY_a_group_key_worn_as_a_user_key_opens_no_container) {
    if (!hasManagementApi()) {
        GTEST_SKIP() << MANAGEMENT_API_MISSING;
    }
    // G's members are user_1 and user_2, and its grant public key is then registered as a context user of its
    // own. From here on nothing in a roster distinguishes "the group G" from "a person".
    std::string groupId;
    ASSERT_NO_THROW({ groupId = createTreeGroup({user(1), user(2)}); });
    group::Group g;
    ASSERT_NO_THROW({ g = groupApi->getGroup(groupId); });
    ASSERT_EQ(g.statusCode, 0);
    ASSERT_FALSE(g.groupPubKey.empty());

    const std::string wornAsUser = "group_worn_as_user";
    ASSERT_NO_FATAL_FAILURE(registerContextUser(wornAsUser, g.groupPubKey));

    // T wraps its content key to that "user" — that is, to G's grant key — while G is not a grantee of T at
    // all. If the wrap were usable, every G member would read T through a route T does not know about, and no
    // removal from G would ever cause T to be re-keyed.
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

    // user_2 can climb G, so they can obtain G's grant private key. That must buy them nothing here.
    EXPECT_FALSE(canReadThread(2, threadId)) << "a member of G decrypted a thread G was never granted";
    EXPECT_FALSE(canReadMessage(2, messageId)) << "a member of G decrypted a message G was never granted";

    // And G itself is untouched by the impersonation: same epoch, still readable, still removable-from.
    group::Group afterAbuse;
    ASSERT_NO_THROW({ afterAbuse = groupApi->getGroup(groupId); });
    EXPECT_EQ(afterAbuse.statusCode, 0);
    EXPECT_EQ(afterAbuse.keyVersion, g.keyVersion);
    EXPECT_NO_THROW({
        groupApi->removeGroupMember(
            groupId, user(2).userId, std::vector<core::UserWithPubKey>{user(1)},
            std::vector<core::UserWithPubKey>{user(1)}, core::Buffer::from("abuse_public"),
            core::Buffer::from("abuse_private")
        );
    });
    group::Group afterRemoval;
    ASSERT_NO_THROW({ afterRemoval = groupApi->getGroup(groupId); });
    EXPECT_EQ(afterRemoval.statusCode, 0);
    EXPECT_EQ(afterRemoval.keyVersion, g.keyVersion + 1);
}

TEST_F(GroupAbuseTest, SECURITY_a_group_key_worn_as_a_user_key_opens_no_other_group) {
    if (!hasManagementApi()) {
        GTEST_SKIP() << MANAGEMENT_API_MISSING;
    }
    // A = user_1 + user_2, B = user_1 + user_3. A's grant key is registered as a context user and then seated
    // in B's tree: a group nested inside a group, smuggled in as a person.
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
        groupApi->addGroupMember(
            groupB, nestedGroup, false, std::vector<core::UserWithPubKey>{user(1), user(3), nestedGroup},
            std::vector<core::UserWithPubKey>{user(1)}, core::Buffer::from("abuse_public"),
            core::Buffer::from("abuse_private")
        );
    } catch (const core::Exception& e) {
        seated = false;
        refusal = e.getFull();
    }

    // user_2 is a member of A and holds no seat of their own in B. Whether or not the seat was allowed, being
    // able to climb A must not become a way into B.
    EXPECT_FALSE(canReadGroup(2, groupB)) << "a member of A read B through A's key (seat " <<
        (seated ? "was accepted)" : "was refused: " + refusal + ")");

    // B's own members are unaffected, and B's tree still takes a removal: a rogue leaf must not wedge it.
    EXPECT_TRUE(canReadGroup(3, groupB)) << "a real member of B lost access; " << lastReadError;
    std::vector<core::UserWithPubKey> remaining{user(1)};
    if (seated) {
        remaining.push_back(nestedGroup);
    }
    EXPECT_NO_THROW({
        groupApi->removeGroupMember(
            groupB, user(3).userId, remaining, std::vector<core::UserWithPubKey>{user(1)},
            core::Buffer::from("abuse_public"), core::Buffer::from("abuse_private")
        );
    });
    group::Group afterRemoval;
    ASSERT_NO_THROW({ afterRemoval = groupApi->getGroup(groupB); });
    EXPECT_EQ(afterRemoval.statusCode, 0);
    EXPECT_EQ(afterRemoval.keyVersion, b.keyVersion + 1);
    EXPECT_TRUE(canReadGroup(1, groupB)) << "B's manager lost access to their own group; " << lastReadError;
    EXPECT_FALSE(canReadGroup(2, groupB)) << "a member of A read B through A's key after B rotated";
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
            groupApi->addGroupMember(
                groupB, groupAsMember, false, std::vector<core::UserWithPubKey>{user(1), user(3), groupAsMember},
                std::vector<core::UserWithPubKey>{user(1)}, core::Buffer::from("abuse_public"),
                core::Buffer::from("abuse_private")
            );
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
            groupApi->removeGroupMember(
                groupId, user(3).userId, std::vector<core::UserWithPubKey>{user(1), user(2)},
                std::vector<core::UserWithPubKey>{user(1)}, core::Buffer::from("abuse_public"),
                core::Buffer::from("abuse_private")
            );
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
            groupApi->addGroupMember(
                groupId, user(3), false, std::vector<core::UserWithPubKey>{user(1), user(2), user(3)},
                std::vector<core::UserWithPubKey>{user(1)}, core::Buffer::from("abuse_public"),
                core::Buffer::from("abuse_private")
            );
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
    const std::vector<core::UserWithPubKey> withoutContested{remover, adder};
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
            removerGroups.removeGroupMember(
                groupId, contested.userId, withoutContested, managers, core::Buffer::from("abuse_public"),
                core::Buffer::from("abuse_private")
            );
            removed = true;
        } catch (const core::Exception& e) {
            removeFailure = e.getFull();
        } catch (const std::exception& e) {
            removeFailure = e.what();
        }
    });
    std::thread addingThread([&] {
        try {
            adderGroups.addGroupMember(
                groupId, contested, false, withContested, managers, core::Buffer::from("abuse_public"),
                core::Buffer::from("abuse_private")
            );
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

TEST_F(GroupAbuseTest, SECURITY_a_roster_lying_about_a_members_key_hands_nobody_that_seat) {
    // A removal re-wraps the surviving siblings' path keys to whatever public keys the caller claims those
    // members hold — a claim the Bridge cannot check. Naming another *group's* key there is the closest thing
    // to nesting a group in a tree the API allows: the target group would keep a leaf that says "user_3" while
    // the edge into it opens with group A's key instead.
    //
    // With three leaves (user_1, user_2, user_3 by id) removing user_2 refreshes the path [1, 3], and node 3
    // re-wraps to its other child — user_3's leaf. So the lie is used, not ignored.
    std::string borrowedFrom, target;
    ASSERT_NO_THROW({ borrowedFrom = createTreeGroup({user(1), user(2)}); });
    ASSERT_NO_THROW({ target = createTreeGroup({user(1), user(2), user(3)}); });
    group::Group a;
    ASSERT_NO_THROW({ a = groupApi->getGroup(borrowedFrom); });
    ASSERT_EQ(a.statusCode, 0);

    bool accepted = true;
    std::string refusal;
    try {
        groupApi->removeGroupMember(
            target, user(2).userId,
            std::vector<core::UserWithPubKey>{
                user(1), core::UserWithPubKey{.userId = user(3).userId, .pubKey = a.groupPubKey}
            },
            std::vector<core::UserWithPubKey>{user(1)}, core::Buffer::from("abuse_public"),
            core::Buffer::from("abuse_private")
        );
    } catch (const core::Exception& e) {
        accepted = false;
        refusal = e.getFull();
    }

    // Either way the group stays usable for the manager who owns it: a lie in a roster must not be a way to
    // make a group unreadable to everybody, including its author.
    EXPECT_TRUE(canReadGroup(1, target)) << "the group became unreadable to its manager (removal " <<
        (accepted ? "accepted)" : "refused: " + refusal + ")");

    if (accepted) {
        // The group whose key was borrowed gains nothing by it: user_2 belongs to it, and was just removed
        // from the target. This is the half that would be an escalation rather than a foot-gun.
        EXPECT_FALSE(canReadGroup(2, target)) << "a member of the group whose key was borrowed read the target";

        // user_3 is left on the roster of a tree whose edge into their leaf may no longer open with their own
        // key. Either way — locked out or untouched, depending on where their leaf sat relative to the removed
        // one — the group must stay repairable: a lie in a roster cannot produce a group nobody can fix.
        const bool lockedOut = !canReadGroup(3, target);
        EXPECT_NO_THROW({
            groupApi->removeGroupMember(
                target, user(3).userId, std::vector<core::UserWithPubKey>{user(1)},
                std::vector<core::UserWithPubKey>{user(1)}, core::Buffer::from("abuse_public"),
                core::Buffer::from("abuse_private")
            );
        }) << "the group could not be repaired after the roster lie (user_3 was " <<
            (lockedOut ? "locked out)" : "unaffected)");
        EXPECT_TRUE(canReadGroup(1, target)) << "the manager lost their own group while repairing it; " <<
            lastReadError;
    }
}
