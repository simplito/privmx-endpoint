#include <gtest/gtest.h>
#include "../../utils/BaseGroupTest.hpp"
#include <Poco/Util/IniFileConfiguration.h>
#include <chrono>
#include <privmx/endpoint/core/Connection.hpp>
#include <privmx/endpoint/core/CoreException.hpp>
#include <privmx/endpoint/core/EventQueue.hpp>
#include <privmx/endpoint/core/EventQueueImpl.hpp>
#include <privmx/endpoint/core/Exception.hpp>
#include <privmx/endpoint/core/VarSerializer.hpp>
#include <privmx/endpoint/group/Events.hpp>
#include <privmx/endpoint/group/GroupApi.hpp>
#include <privmx/endpoint/group/GroupException.hpp>
#include <privmx/endpoint/group/VarSerializer.hpp>
#include <thread>

using namespace privmx::endpoint;

/**
 * End-to-end tests for custom notifications sent within a Group.
 *
 * What makes these worth running against a real bridge rather than mocking: the payload never travels with a
 * key. The sender seals it with the Group's own key and the bridge relays the bytes; whether a recipient can
 * open it therefore depends on the Group's key tree agreeing with the sender's, across a rotation, across a
 * removal, across the bridge's own idea of who is a member. None of that is observable without both halves.
 *
 * Tests named SECURITY assert that somebody *cannot* read something. They fail silently if the guard regresses
 * — nothing breaks, the notification simply arrives where it should not have — so they must not be deleted or
 * weakened into positive assertions.
 */

class GroupCustomEventsTest : public privmx::test::BaseGroupTest {
protected:
    std::string createGroup(const std::vector<core::UserWithPubKey>& members) {
        return groupApi->createGroup(
            contextId(), members, std::vector<core::UserWithPubKey>{user(1)},
            core::Buffer::from("custom_events_public"), core::Buffer::from("custom_events_private")
        );
    }

    // Drains rather than taking the head: connecting emits `libConnected` and subscribing may emit more, so the
    // notification is never first in the queue.
    std::optional<group::GroupCustomEvent> awaitCustomEvent(int attempts = 20) {
        for (int i = 0; i < attempts; ++i) {
            auto holder = eventQueue.getEvent();
            if (!holder.has_value()) {
                std::this_thread::sleep_for(std::chrono::milliseconds(150));
                continue;
            }
            if (group::Events::isGroupCustomEvent(holder.value())) {
                return group::Events::extractGroupCustomEvent(holder.value());
            }
        }
        return std::nullopt;
    }

    core::EventQueue eventQueue = core::EventQueue::getInstance();
};

TEST_F(GroupCustomEventsTest, a_member_receives_the_notification_opened_and_attributed) {
    const std::string groupId = createGroup({user(1), user(2)});
    auto connection2 = connect(2);
    auto groupApi2 = group::GroupApi::create(*connection2);
    groupApi2.subscribeFor(
        {groupApi2.buildCustomEventSubscriptionQuery("typing", group::EventSelectorType::GROUP_ID, groupId)}
    );

    groupApi->sendCustomEvent(groupId, "typing", core::Buffer::from("user_1 is typing"));

    auto received = awaitCustomEvent();
    ASSERT_TRUE(received.has_value());
    EXPECT_EQ(received->data.statusCode, 0);
    EXPECT_EQ(received->data.payload.stdString(), "user_1 is typing");
    EXPECT_EQ(received->data.groupId, groupId);
    EXPECT_EQ(received->data.channelName, "typing");
    EXPECT_EQ(received->data.userId, userId(1));
    // The bridge's `userId` is a claim; this is the field a signature stands behind.
    EXPECT_EQ(received->data.authorPubKey, user(1).pubKey);
    EXPECT_EQ(received->channel, "group/" + groupId + "/typing");
    EXPECT_EQ(received->subscriptions.size(), 1);

    connection2->disconnect();
}

TEST_F(GroupCustomEventsTest, a_notification_still_opens_after_the_group_key_has_rotated) {
    // The envelope names the epoch it was sealed under, so a recipient who has moved on climbs to the older key
    // rather than failing. Otherwise every rotation would drop in-flight notifications, exactly when chattiest.
    const std::string groupId = createGroup({user(1), user(2), user(3)});
    auto connection2 = connect(2);
    auto groupApi2 = group::GroupApi::create(*connection2);
    groupApi2.subscribeFor(
        {groupApi2.buildCustomEventSubscriptionQuery("typing", group::EventSelectorType::GROUP_ID, groupId)}
    );

    const auto sealedUnderEpoch1 = groupApi->encrypt(groupId, core::Buffer::from("sealed before rotation"));
    // Removal, not addition: seating a member re-keys their path but keeps the epoch, so a removal is the only
    // public call that advances it.
    groupApi->removeGroupMembers(groupId, {userId(3)});
    ASSERT_GT(groupApi->getGroup(groupId).keyVersion, 1);

    groupApi->sendCustomEvent(groupId, "typing", core::Buffer::from("sent after rotation"));
    auto received = awaitCustomEvent();
    ASSERT_TRUE(received.has_value());
    EXPECT_EQ(received->data.statusCode, 0);
    EXPECT_EQ(received->data.payload.stdString(), "sent after rotation");
    // And the epoch-1 envelope is still readable — the same key path the notification travels.
    EXPECT_EQ(groupApi2.decrypt(sealedUnderEpoch1).data.stdString(), "sealed before rotation");

    connection2->disconnect();
}

TEST_F(GroupCustomEventsTest, a_notification_narrowed_to_one_member_reaches_only_them) {
    const std::string groupId = createGroup({user(1), user(2), user(3)});
    auto connection3 = connect(3);
    auto groupApi3 = group::GroupApi::create(*connection3);
    groupApi3.subscribeFor(
        {groupApi3.buildCustomEventSubscriptionQuery("typing", group::EventSelectorType::GROUP_ID, groupId)}
    );

    groupApi->sendCustomEvent(groupId, "typing", core::Buffer::from("for user_2 only"), {userId(2)});

    EXPECT_FALSE(awaitCustomEvent(6).has_value());

    connection3->disconnect();
}

TEST_F(GroupCustomEventsTest, subscribing_to_one_channel_does_not_deliver_another) {
    const std::string groupId = createGroup({user(1), user(2)});
    auto connection2 = connect(2);
    auto groupApi2 = group::GroupApi::create(*connection2);
    groupApi2.subscribeFor(
        {groupApi2.buildCustomEventSubscriptionQuery("typing", group::EventSelectorType::GROUP_ID, groupId)}
    );

    groupApi->sendCustomEvent(groupId, "cursor", core::Buffer::from("moved"));
    EXPECT_FALSE(awaitCustomEvent(6).has_value());

    // ...and the channel that *was* subscribed still works, so the negative above is about the channel and not
    // about a subscription that never took.
    groupApi->sendCustomEvent(groupId, "typing", core::Buffer::from("typing"));
    auto received = awaitCustomEvent();
    ASSERT_TRUE(received.has_value());
    EXPECT_EQ(received->data.channelName, "typing");

    connection2->disconnect();
}

TEST_F(GroupCustomEventsTest, SECURITY_a_removed_member_receives_nothing_sent_afterwards) {
    const std::string groupId = createGroup({user(1), user(2)});
    auto connection2 = connect(2);
    auto groupApi2 = group::GroupApi::create(*connection2);
    groupApi2.subscribeFor(
        {groupApi2.buildCustomEventSubscriptionQuery("typing", group::EventSelectorType::GROUP_ID, groupId)}
    );

    groupApi->removeGroupMembers(groupId, {userId(2)});
    groupApi->sendCustomEvent(groupId, "typing", core::Buffer::from("after the removal"));

    EXPECT_FALSE(awaitCustomEvent(6).has_value());

    connection2->disconnect();
}

TEST_F(GroupCustomEventsTest, SECURITY_a_context_user_outside_the_group_cannot_send) {
    // user_3 belongs to the Context and holds the same ACL, so the ACL alone would let this through. It is
    // membership that stops it, and it is stopped on the bridge — the client cannot even seal the payload.
    const std::string groupId = createGroup({user(1), user(2)});
    auto connection3 = connect(3);
    auto groupApi3 = group::GroupApi::create(*connection3);

    EXPECT_THROW(
        groupApi3.sendCustomEvent(groupId, "typing", core::Buffer::from("let me in")), core::Exception
    );

    connection3->disconnect();
}

TEST_F(GroupCustomEventsTest, a_notification_cannot_be_aimed_outside_the_group) {
    const std::string groupId = createGroup({user(1), user(2)});
    EXPECT_THROW(
        groupApi->sendCustomEvent(groupId, "typing", core::Buffer::from("hello"), {userId(3)}), core::Exception
    );
}

TEST_F(GroupCustomEventsTest, a_channel_name_carrying_a_query_separator_is_refused) {
    // The name becomes one element of a subscription query, and the query is parsed by splitting on these
    // characters. Letting one through would write extra path elements or selectors into the query.
    const std::string groupId = createGroup({user(1), user(2)});
    for (const std::string& bad : {"a/b", "a|b", "a,b", "a=b", ""}) {
        EXPECT_THROW(
            groupApi->buildCustomEventSubscriptionQuery(bad, group::EventSelectorType::GROUP_ID, groupId),
            core::Exception
        ) << "channel name '" << bad << "' should be refused";
    }
}

TEST_F(GroupCustomEventsTest, a_payload_over_the_ceiling_is_refused_before_it_reaches_the_bridge) {
    const std::string groupId = createGroup({user(1), user(2)});
    EXPECT_THROW(
        groupApi->sendCustomEvent(groupId, "typing", core::Buffer::from(std::string(16 * 1024, 'x'))),
        core::Exception
    );
}

TEST_F(GroupCustomEventsTest, the_subscription_query_is_the_channel_the_bridge_matches_on) {
    const std::string groupId = createGroup({user(1), user(2)});
    EXPECT_EQ(
        groupApi->buildCustomEventSubscriptionQuery("typing", group::EventSelectorType::GROUP_ID, groupId),
        "context/groups/custom/typing|containerId=" + groupId
    );
    EXPECT_EQ(
        groupApi->buildCustomEventSubscriptionQuery("typing", group::EventSelectorType::CONTEXT_ID, contextId()),
        "context/groups/custom/typing|contextId=" + contextId()
    );
}
