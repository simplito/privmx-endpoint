#include <gtest/gtest.h>
#include <privmx/endpoint/core/CoreException.hpp>
#include <privmx/endpoint/core/Subscriber.hpp>
#include <privmx/endpoint/group/GroupException.hpp>
#include <privmx/endpoint/group/SubscriberImpl.hpp>

using namespace privmx::endpoint;

/**
 * The subscription-query grammar for custom-event channels.
 *
 * A custom channel's name is the one part of a query the caller writes, and the query is parsed by splitting on
 * '/', '|', ',' and '='. A name carrying any of them would not round-trip — and worse, would let a caller append
 * path elements or selectors to a query the bridge then honours. The bridge's own channel-name pattern permits
 * those characters, so this is where they are refused.
 */

namespace {
constexpr char GROUP_ID[] = "664f1c8f5e2a4b0012345678";
constexpr char CONTEXT_ID[] = "664f1c8f5e2a4b0087654321";

/**
 * Reaches `assertQuery`, which is a private virtual invoked by `subscribeFor`.
 *
 * A rejected query throws before the gateway is touched, so the whole validation path runs with no connection.
 * A query that passes validation would then dereference the null gateway — which is why every case here is a
 * rejection, and why the accepting cases live in the e2e suite.
 */
class ProbeSubscriber : public group::SubscriberImpl {
public:
    ProbeSubscriber() : SubscriberImpl(nullptr) {}
};
} // namespace

TEST(GroupCustomChannelTest, SECURITY_a_query_shorter_than_the_path_it_claims_is_rejected_not_read_past) {
    // The path is split out of a caller-supplied string, so a one-element path is ordinary input. Validating
    // the elements before checking how many there are reads off the end of the vector.
    ProbeSubscriber subscriber;
    for (const std::string& tooShort :
         {"context|contextId=x", "context/groups|contextId=x", "x|contextId=y"}) {
        EXPECT_THROW(subscriber.subscribeFor({tooShort}), group::InvalidSubscriptionQueryException)
            << "query '" << tooShort << "' should be rejected";
    }
}

TEST(GroupCustomChannelTest, a_query_longer_than_a_custom_path_is_rejected) {
    ProbeSubscriber subscriber;
    EXPECT_THROW(
        subscriber.subscribeFor({"context/groups/custom/typing/extra|containerId=x"}),
        group::InvalidSubscriptionQueryException
    );
}

TEST(GroupCustomChannelTest, a_four_element_path_that_is_not_a_custom_channel_is_rejected) {
    // Four elements alone does not make it a notification channel — the third has to say so, or a subscription
    // to `context/groups/update/anything` would be taken for one.
    ProbeSubscriber subscriber;
    EXPECT_THROW(
        subscriber.subscribeFor({"context/groups/update/typing|containerId=x"}),
        group::InvalidSubscriptionQueryException
    );
}

TEST(GroupCustomChannelTest, SECURITY_a_custom_query_with_a_separator_in_its_name_is_rejected_on_the_way_in) {
    // Not only when built by `buildCustomEventQuery`: a query handed to `subscribeFor` as a raw string has to
    // face the same check, since that is the path a caller who assembles their own query takes.
    ProbeSubscriber subscriber;
    EXPECT_THROW(
        subscriber.subscribeFor({"context/groups/custom/a=b|containerId=x"}), core::InvalidParamsException
    );
}

TEST(GroupCustomChannelTest, a_query_names_the_channel_the_bridge_matches_on) {
    EXPECT_EQ(
        group::SubscriberImpl::buildCustomEventQuery("typing", group::EventSelectorType::GROUP_ID, GROUP_ID),
        std::string("context/groups/custom/typing|containerId=") + GROUP_ID
    );
    EXPECT_EQ(
        group::SubscriberImpl::buildCustomEventQuery("typing", group::EventSelectorType::CONTEXT_ID, CONTEXT_ID),
        std::string("context/groups/custom/typing|contextId=") + CONTEXT_ID
    );
}

TEST(GroupCustomChannelTest, the_channel_name_reads_back_out_of_its_own_query) {
    // This is how the receiving side learns which channel a notification arrived on: the notification does not
    // carry the name, the query that matched it does.
    for (const std::string& name : {"typing", "cursor.move", "call:started", "a-b_c9"}) {
        const auto query =
            group::SubscriberImpl::buildCustomEventQuery(name, group::EventSelectorType::GROUP_ID, GROUP_ID);
        EXPECT_EQ(group::SubscriberImpl::channelNameFromQuery(query), name);
    }
}

TEST(GroupCustomChannelTest, a_change_event_query_yields_no_channel_name) {
    // Three path elements is a create/update/delete subscription. Returning a name for one of those would have
    // the dispatcher treat a change event as a notification and try to open its payload.
    const auto changeQuery = group::SubscriberImpl::buildQuery(
        group::EventType::GROUP_UPDATE, group::EventSelectorType::GROUP_ID, GROUP_ID
    );
    EXPECT_EQ(group::SubscriberImpl::channelNameFromQuery(changeQuery), "");
}

TEST(GroupCustomChannelTest, SECURITY_a_channel_name_carrying_a_query_separator_is_refused) {
    for (const std::string& bad : {"a/b", "a|b", "a,b", "a=b", "typing|contextId=other", ""}) {
        EXPECT_THROW(
            group::SubscriberImpl::buildCustomEventQuery(bad, group::EventSelectorType::GROUP_ID, GROUP_ID),
            core::InvalidParamsException
        ) << "channel name '" << bad << "' should be refused";
    }
}

TEST(GroupCustomChannelTest, both_selector_types_are_available_to_a_custom_channel) {
    // Unlike GROUP_CREATE, which can only be scoped to a Context, a notification channel is meaningful at
    // either scope: every Group in a Context, or one Group.
    EXPECT_NO_THROW(
        group::SubscriberImpl::buildCustomEventQuery("typing", group::EventSelectorType::GROUP_ID, GROUP_ID)
    );
    EXPECT_NO_THROW(
        group::SubscriberImpl::buildCustomEventQuery("typing", group::EventSelectorType::CONTEXT_ID, CONTEXT_ID)
    );
}
