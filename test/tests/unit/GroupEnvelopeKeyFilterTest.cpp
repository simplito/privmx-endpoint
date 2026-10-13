/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

/**
 * Narrowing a group's published key routes down to the one an envelope names.
 *
 * This is what keeps opening an envelope at a constant cost. Handed the whole archive, the key provider
 * resolves a grant key — and the bridge answers for one — per key the group has ever held, on every single
 * envelope. So the filter has to be exact in both directions: drop everything unrelated, and keep *every*
 * route to the key that was asked for, since a group can publish more than one way into the same key and
 * only some of them may open for this caller.
 */

#include <gtest/gtest.h>

#include <string>
#include <utility>

#include <privmx/endpoint/group/GroupApiImpl.hpp>
#include <privmx/endpoint/group/GroupException.hpp>

using namespace privmx::endpoint;
using namespace privmx::endpoint::group;

namespace {

core::server::GroupKeyEntry key(const std::string& keyId, int64_t epoch) {
    core::server::GroupKeyEntry entry;
    entry.keyId = keyId;
    entry.groupEpoch = epoch;
    return entry;
}

core::server::GroupKeysEntry route(const std::string& group, std::vector<core::server::GroupKeyEntry> keys) {
    core::server::GroupKeysEntry entry;
    entry.group = group;
    entry.keys = std::move(keys);
    return entry;
}

std::size_t totalKeys(const std::vector<core::server::GroupKeysEntry>& entries) {
    std::size_t n = 0;
    for (const auto& e : entries) {
        n += e.keys.size();
    }
    return n;
}

} // namespace

TEST(GroupEnvelopeKeyFilter, KeepsOnlyTheKeyAskedFor) {
    // A group that has rotated three times publishes all three keys. Opening an envelope sealed under the
    // oldest must not drag the other two through key resolution.
    auto all = std::vector<core::server::GroupKeysEntry>{
        route("grp", {key("aaa", 1), key("bbb", 2), key("ccc", 3)})
    };
    auto filtered = GroupApiImpl::filterToKeyId(all, "grp", "bbb");

    ASSERT_EQ(filtered.size(), 1u);
    ASSERT_EQ(filtered[0].keys.size(), 1u);
    EXPECT_EQ(filtered[0].keys[0].keyId, "bbb");
    EXPECT_EQ(filtered[0].group, "grp");
    EXPECT_EQ(totalKeys(filtered), 1u);
}

TEST(GroupEnvelopeKeyFilter, KeepsEveryRouteToTheSameKey) {
    // Several entries can carry the same keyId by different routes. Keeping only the first would make a key
    // that is perfectly openable look unopenable whenever the route we kept is the one that fails.
    auto all = std::vector<core::server::GroupKeysEntry>{
        route("grp", {key("shared", 1), key("other", 1)}),
        route("grp", {key("shared", 2)}),
        route("grp", {key("unrelated", 2)}),
    };
    auto filtered = GroupApiImpl::filterToKeyId(all, "grp", "shared");

    EXPECT_EQ(filtered.size(), 2u);
    EXPECT_EQ(totalKeys(filtered), 2u);
    for (const auto& entry : filtered) {
        for (const auto& k : entry.keys) {
            EXPECT_EQ(k.keyId, "shared");
        }
    }
}

TEST(GroupEnvelopeKeyFilter, DropsEntriesLeftEmpty) {
    // An entry whose keys all filtered away must disappear, not survive as an empty shell — an empty entry
    // would be enqueued as a route that can never open.
    auto all = std::vector<core::server::GroupKeysEntry>{
        route("grp", {key("aaa", 1)}),
        route("grp", {key("bbb", 1)}),
    };
    auto filtered = GroupApiImpl::filterToKeyId(all, "grp", "aaa");

    ASSERT_EQ(filtered.size(), 1u);
    EXPECT_EQ(filtered[0].keys[0].keyId, "aaa");
}

TEST(GroupEnvelopeKeyFilter, SECURITY_KeepsOnlyTheGroupsOwnRoutes) {
    // T4-07: a group's key is wrapped to the group itself. A route through another group is a key somebody else
    // chose, served under the same keyId.
    auto all = std::vector<core::server::GroupKeysEntry>{route("grp", {key("k", 1)}), route("other", {key("k", 1)})};
    auto filtered = GroupApiImpl::filterToKeyId(all, "grp", "k");
    ASSERT_EQ(filtered.size(), 1u);
    EXPECT_EQ(filtered[0].group, "grp");
}

TEST(GroupEnvelopeKeyFilter, SECURITY_AnEarlierEpochsKeyCountsOnlyAsItsOpenerWrappedIt) {
    // T4-07: anybody in the context can wrap a key of their own to epoch 2's public grant key and seal a member
    // envelope under it. Only the member who opened epoch 2 wraps that epoch's content key.
    std::map<std::uint64_t, keytree::CommitStatement> openers;
    openers[1].committer = "alice";
    openers[2].committer = "bob";
    const auto routes = std::vector<core::server::GroupKeysEntry>{route("grp", {key("k2", 2)})};
    EXPECT_TRUE(GroupApiImpl::wrappedByEpochOpener(routes, "bob", openers));
    EXPECT_FALSE(GroupApiImpl::wrappedByEpochOpener(routes, "mallory", openers));
    EXPECT_FALSE(GroupApiImpl::wrappedByEpochOpener(routes, "alice", openers)) << "another epoch's opener";
}

TEST(GroupEnvelopeKeyFilter, UnknownKeyYieldsNothing) {
    // The caller reads this as "this group publishes no such key" and reports it, rather than fetching and
    // resolving its way through the whole archive to discover the same thing.
    auto all = std::vector<core::server::GroupKeysEntry>{route("grp", {key("aaa", 1), key("bbb", 2)})};
    EXPECT_TRUE(GroupApiImpl::filterToKeyId(all, "grp", "missing").empty());
    EXPECT_TRUE(GroupApiImpl::filterToKeyId({}, "grp", "aaa").empty());
}

TEST(GroupEnvelopeKeyFilter, SECURITY_AHeadKeyFromAnEarlierEpochIsRefused) {
    // T3-02: the bridge serves the verified current epoch over the head entry from before a removal. The
    // pre-removal key is the one the removed member still holds; nothing may be written or cached under it.
    group::server::GroupInfo group;
    group.id = "grp";
    group.keyVersion = 5;
    group.data.push_back(group::server::GroupDataEntry{});
    group.data.back().keyId = "k4";
    group.groupKeys = std::vector<core::server::GroupKeysEntry>{route("grp", {key("k4", 4), key("k5", 5)})};
    EXPECT_THROW(GroupApiImpl::assertHeadKeyAtEpoch(group), GroupDataIntegrityException);
    group.data.back().keyId = "k5";
    EXPECT_NO_THROW(GroupApiImpl::assertHeadKeyAtEpoch(group));
    group.groupKeys = std::vector<core::server::GroupKeysEntry>{route("other", {key("k5", 5)})};
    EXPECT_THROW(GroupApiImpl::assertHeadKeyAtEpoch(group), GroupDataIntegrityException) << "not the group's own route";
}

TEST(GroupEnvelopeKeyFilter, SECURITY_AGrantBehindThePinnedEpochIsStale) {
    // T3-05: the bridge reports no stale group, but the container's current key is still wrapped to the epoch a
    // removal ended. Only the route to the current key counts; older keys keep their old epochs by design.
    const auto pinned = [](const std::string& groupId) -> int64_t { return groupId == "grpA" ? 4 : 5; };
    const auto groupKeys = std::vector<core::server::GroupKeysEntry>{
        route("grpA", {key("old", 1), key("cur", 3)}),
        route("grpB", {key("old", 1), key("cur", 5)}),
    };
    EXPECT_EQ(core::ContainerBaseApi::groupsBehindPins(groupKeys, "cur", pinned), std::vector<std::string>{"grpA"});
    EXPECT_TRUE(core::ContainerBaseApi::groupsBehindPins(groupKeys, "cur", nullptr).empty()) << "no group module";
    EXPECT_TRUE(core::ContainerBaseApi::groupsBehindPins(groupKeys, "cur", [](const std::string&) -> int64_t {
        return 0;
    }).empty()) << "no pin, no verdict";
}
