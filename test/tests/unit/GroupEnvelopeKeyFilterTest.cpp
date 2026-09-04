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
#include <vector>

#include <privmx/endpoint/group/GroupApiImpl.hpp>

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
    auto filtered = GroupApiImpl::onlyKeyId(all, "bbb");

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
        route("grpA", {key("shared", 1), key("other", 1)}),
        route("grpB", {key("shared", 2)}),
        route("grpC", {key("unrelated", 2)}),
    };
    auto filtered = GroupApiImpl::onlyKeyId(all, "shared");

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
        route("grpA", {key("aaa", 1)}),
        route("grpB", {key("bbb", 1)}),
    };
    auto filtered = GroupApiImpl::onlyKeyId(all, "aaa");

    ASSERT_EQ(filtered.size(), 1u);
    EXPECT_EQ(filtered[0].group, "grpA");
}

TEST(GroupEnvelopeKeyFilter, UnknownKeyYieldsNothing) {
    // The caller reads this as "this group publishes no such key" and reports it, rather than fetching and
    // resolving its way through the whole archive to discover the same thing.
    auto all = std::vector<core::server::GroupKeysEntry>{route("grp", {key("aaa", 1), key("bbb", 2)})};
    EXPECT_TRUE(GroupApiImpl::onlyKeyId(all, "missing").empty());
    EXPECT_TRUE(GroupApiImpl::onlyKeyId({}, "aaa").empty());
}
