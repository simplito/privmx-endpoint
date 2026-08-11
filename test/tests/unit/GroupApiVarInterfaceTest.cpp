/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

/**
 * Unit tests for the group Var interface — the dispatch layer every language wrapper goes through.
 *
 * What can break here without any test noticing is dull and expensive: a method added to the `METHOD` enum but
 * forgotten in `methodMap` (the wrapper's call vanishes into `InvalidMethodException`), or a number reused after a
 * method was removed (the wrapper's call lands on a *different operation*). Both are wire-contract bugs, so they
 * are checked by number, not by name.
 *
 * No server is involved: every case either fails before touching the API, or fails inside the argument
 * deserialisation. That is enough — the point is which handler the number reaches.
 */

#include <gtest/gtest.h>

#include <Poco/JSON/Array.h>

#include <privmx/endpoint/core/CoreException.hpp>
#include <privmx/endpoint/group/varinterface/GroupApiVarInterface.hpp>

using namespace privmx::endpoint;
using namespace privmx::endpoint::group;

namespace {

GroupApiVarInterface makeInterface() {
    // An unconnected Connection is fine: nothing here reaches the network, and `create()` is never called.
    return GroupApiVarInterface(core::Connection(), core::VarSerializer({}));
}

/** Calls a method with an argument list of the wrong shape, and reports how it failed. */
enum class Outcome {
    ReachedHandler, ///< the number is mapped: it got as far as argument validation
    UnmappedMethod, ///< `methodMap` has no entry for this number
};

Outcome probe(GroupApiVarInterface::METHOD method) {
    auto args = Poco::JSON::Array::Ptr(new Poco::JSON::Array());
    args->add(std::string("deliberately-wrong-argument-list"));
    try {
        makeInterface().exec(method, args);
    } catch (const core::InvalidMethodException&) {
        return Outcome::UnmappedMethod;
    } catch (...) {
        // Anything else means the call was dispatched and the handler rejected the arguments.
        return Outcome::ReachedHandler;
    }
    return Outcome::ReachedHandler;
}

} // namespace

TEST(GroupVarInterface, EveryDeclaredMethodIsMapped) {
    // The list is written out rather than looped over a range, so that adding a METHOD value without adding it
    // here is a visible omission in this file instead of a silent gap in coverage.
    const std::vector<std::pair<GroupApiVarInterface::METHOD, const char*>> methods{
        {GroupApiVarInterface::Create, "Create"},
        {GroupApiVarInterface::CreateGroup, "CreateGroup"},
        {GroupApiVarInterface::UpdateGroup, "UpdateGroup"},
        {GroupApiVarInterface::DeleteGroup, "DeleteGroup"},
        {GroupApiVarInterface::GetGroup, "GetGroup"},
        {GroupApiVarInterface::ListGroups, "ListGroups"},
        {GroupApiVarInterface::GenerateNewGroupKey, "GenerateNewGroupKey"},
        {GroupApiVarInterface::SubscribeFor, "SubscribeFor"},
        {GroupApiVarInterface::UnsubscribeFrom, "UnsubscribeFrom"},
        {GroupApiVarInterface::BuildSubscriptionQuery, "BuildSubscriptionQuery"},
        {GroupApiVarInterface::CreateGroupWithKeyTree, "CreateGroupWithKeyTree"},
        {GroupApiVarInterface::AddGroupMember, "AddGroupMember"},
        {GroupApiVarInterface::RemoveGroupMember, "RemoveGroupMember"},
    };
    for (const auto& [method, name] : methods) {
        EXPECT_EQ(probe(method), Outcome::ReachedHandler)
            << name << " (" << static_cast<int>(method) << ") is declared but not in methodMap: every wrapper call "
            << "to it would fail as an unknown method";
    }
}

TEST(GroupVarInterface, TheMethodNumbersAreTheOnesWrappersSend) {
    // Frozen on purpose. A wrapper sends the number, so changing one silently redirects its calls; a removed
    // method must leave a gap rather than let the next one shift down.
    EXPECT_EQ(static_cast<int>(GroupApiVarInterface::Create), 0);
    EXPECT_EQ(static_cast<int>(GroupApiVarInterface::CreateGroup), 1);
    EXPECT_EQ(static_cast<int>(GroupApiVarInterface::UpdateGroup), 2);
    EXPECT_EQ(static_cast<int>(GroupApiVarInterface::DeleteGroup), 3);
    EXPECT_EQ(static_cast<int>(GroupApiVarInterface::GetGroup), 4);
    EXPECT_EQ(static_cast<int>(GroupApiVarInterface::ListGroups), 5);
    EXPECT_EQ(static_cast<int>(GroupApiVarInterface::GenerateNewGroupKey), 6);
    EXPECT_EQ(static_cast<int>(GroupApiVarInterface::SubscribeFor), 7);
    EXPECT_EQ(static_cast<int>(GroupApiVarInterface::UnsubscribeFrom), 8);
    EXPECT_EQ(static_cast<int>(GroupApiVarInterface::BuildSubscriptionQuery), 9);
    EXPECT_EQ(static_cast<int>(GroupApiVarInterface::CreateGroupWithKeyTree), 10);
    EXPECT_EQ(static_cast<int>(GroupApiVarInterface::AddGroupMember), 11);
    EXPECT_EQ(static_cast<int>(GroupApiVarInterface::RemoveGroupMember), 12);
}

TEST(GroupVarInterface, AnUnknownMethodNumberIsRejected) {
    EXPECT_EQ(probe(static_cast<GroupApiVarInterface::METHOD>(9999)), Outcome::UnmappedMethod);
}

TEST(GroupVarInterface, ArgumentCountIsEnforcedPerMethod) {
    // The count is part of the contract too: the handlers read arguments positionally, so a wrapper that sends the
    // wrong number of them must be told, not have the extras ignored.
    auto tooFew = Poco::JSON::Array::Ptr(new Poco::JSON::Array());
    tooFew->add(std::string("only-one-argument"));
    EXPECT_THROW(makeInterface().exec(GroupApiVarInterface::AddGroupMember, tooFew), core::Exception)
        << "addGroupMember takes seven arguments";
    EXPECT_THROW(makeInterface().exec(GroupApiVarInterface::RemoveGroupMember, tooFew), core::Exception)
        << "removeGroupMember takes six arguments";
    EXPECT_THROW(makeInterface().exec(GroupApiVarInterface::CreateGroupWithKeyTree, tooFew), core::Exception)
        << "createGroupWithKeyTree takes six arguments";
}

TEST(GroupVarInterface, EventEnumsDeserialiseAndRejectUnknownValues) {
    core::VarDeserializer deserializer;
    EXPECT_EQ(deserializer.deserialize<group::EventType>(0, "eventType"), group::EventType::GROUP_CREATE);
    EXPECT_EQ(deserializer.deserialize<group::EventType>(2, "eventType"), group::EventType::GROUP_DELETE);
    EXPECT_EQ(
        deserializer.deserialize<group::EventSelectorType>(1, "selectorType"), group::EventSelectorType::GROUP_ID
    );
    // A value this build does not know means the wrapper and the library disagree about the enum. Guessing would
    // subscribe the caller to the wrong events, so it is refused.
    EXPECT_THROW(deserializer.deserialize<group::EventType>(77, "eventType"), core::Exception);
    EXPECT_THROW(deserializer.deserialize<group::EventSelectorType>(77, "selectorType"), core::Exception);
}
