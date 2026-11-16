/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

/**
 * A container policy has to survive the trip through `Poco::Dynamic::Var` intact.
 *
 * That trip is not an implementation detail: it is how every wrapper language reaches the library.
 * Java, Swift and the JS bindings all hand their arguments over as a `Var`, so a field the
 * serializer writes and the deserializer does not read is a field that works in C++ and silently
 * does nothing everywhere else — and silently, because a dropped `std::optional` is indistinguishable
 * from one the caller never set. The container is created either way, just not as asked.
 *
 * `cryptoSuite` was exactly that: written by `VarSerializer`, read by the `ContainerPolicyWithoutItem`
 * deserializer, and dropped by the `ContainerPolicy` one, which listed its base's fields again
 * instead of delegating. `rotateKeys` and `forwardSecrecy` had been lost the same way before it. The
 * round trip below is deliberately field-by-field over a *fully populated* policy, so the next field
 * added to either struct is caught here rather than in a wrapper months later.
 */

#include <string>

#include <Poco/Dynamic/Var.h>
#include <Poco/JSON/Object.h>
#include <gtest/gtest.h>

#include <privmx/endpoint/core/Types.hpp>
#include <privmx/endpoint/core/VarDeserializer.hpp>
#include <privmx/endpoint/core/VarSerializer.hpp>

using namespace privmx::endpoint;

namespace {

/// Every field set, and each to a distinct value, so a mix-up between two of them is visible.
core::ContainerPolicy fullyPopulatedPolicy() {
    core::ItemPolicy item{};
    item.get = "item-get";
    item.listMy = "item-listMy";
    item.listAll = "item-listAll";
    item.create = "item-create";
    item.update = "item-update";
    item.delete_ = "item-delete";

    core::ContainerPolicy policy{};
    policy.get = "policy-get";
    policy.update = "policy-update";
    policy.delete_ = "policy-delete";
    policy.updatePolicy = "policy-updatePolicy";
    policy.updaterCanBeRemovedFromManagers = "policy-updaterCanBeRemoved";
    policy.ownerCanBeRemovedFromManagers = "policy-ownerCanBeRemoved";
    policy.rotateKeys = "policy-rotateKeys";
    policy.forwardSecrecy = "policy-forwardSecrecy";
    policy.cryptoSuite = "aes256gcm-sha512";
    policy.item = item;
    return policy;
}

core::ContainerPolicy roundTrip(const core::ContainerPolicy& policy) {
    core::VarSerializer serializer{core::VarSerializer::Options{}};
    core::VarDeserializer deserializer;
    return deserializer.deserialize<core::ContainerPolicy>(serializer.serialize(policy), "policy");
}

} // namespace

TEST(ContainerPolicyVar, EveryFieldSurvivesTheRoundTrip) {
    const core::ContainerPolicy original = fullyPopulatedPolicy();
    const core::ContainerPolicy result = roundTrip(original);

    EXPECT_EQ(original.get, result.get);
    EXPECT_EQ(original.update, result.update);
    EXPECT_EQ(original.delete_, result.delete_);
    EXPECT_EQ(original.updatePolicy, result.updatePolicy);
    EXPECT_EQ(original.updaterCanBeRemovedFromManagers, result.updaterCanBeRemovedFromManagers);
    EXPECT_EQ(original.ownerCanBeRemovedFromManagers, result.ownerCanBeRemovedFromManagers);
    EXPECT_EQ(original.rotateKeys, result.rotateKeys);
    EXPECT_EQ(original.forwardSecrecy, result.forwardSecrecy);
    EXPECT_EQ(original.cryptoSuite, result.cryptoSuite);

    ASSERT_TRUE(result.item.has_value());
    EXPECT_EQ(original.item->get, result.item->get);
    EXPECT_EQ(original.item->listMy, result.item->listMy);
    EXPECT_EQ(original.item->listAll, result.item->listAll);
    EXPECT_EQ(original.item->create, result.item->create);
    EXPECT_EQ(original.item->update, result.item->update);
    EXPECT_EQ(original.item->delete_, result.item->delete_);
}

/**
 * Called out on its own because of what it buys: `cryptoSuite` is level 2 of the format choice, the
 * only way a container can name algorithms other than the build's own. Dropped here, the whole
 * feature is reachable from C++ and from nothing else.
 */
TEST(ContainerPolicyVar, CryptoSuiteReachesTheContainerPolicy) {
    core::ContainerPolicy policy{};
    policy.cryptoSuite = "aes256gcm-sha512";

    const core::ContainerPolicy result = roundTrip(policy);

    ASSERT_TRUE(result.cryptoSuite.has_value());
    EXPECT_EQ("aes256gcm-sha512", *result.cryptoSuite);
}

/// The other direction: an unset field must stay unset rather than arrive as an empty string, or
/// "no policy" would become "a policy naming nothing" and override what the container already has.
TEST(ContainerPolicyVar, AnEmptyPolicyStaysEmpty) {
    const core::ContainerPolicy result = roundTrip(core::ContainerPolicy{});

    EXPECT_FALSE(result.get.has_value());
    EXPECT_FALSE(result.update.has_value());
    EXPECT_FALSE(result.delete_.has_value());
    EXPECT_FALSE(result.updatePolicy.has_value());
    EXPECT_FALSE(result.updaterCanBeRemovedFromManagers.has_value());
    EXPECT_FALSE(result.ownerCanBeRemovedFromManagers.has_value());
    EXPECT_FALSE(result.rotateKeys.has_value());
    EXPECT_FALSE(result.forwardSecrecy.has_value());
    EXPECT_FALSE(result.cryptoSuite.has_value());
    EXPECT_FALSE(result.item.has_value());
}

/// The base type reads the same fields when it is deserialized on its own — `updateThread` and the
/// rest take this one, and it is what `policyForUpdate` compares a container's current suite against.
TEST(ContainerPolicyVar, TheBaseTypeAgreesWithTheDerivedOne) {
    core::VarSerializer serializer{core::VarSerializer::Options{}};
    core::VarDeserializer deserializer;
    const core::ContainerPolicy original = fullyPopulatedPolicy();

    const Poco::Dynamic::Var serialized = serializer.serialize(original);
    const auto asBase = deserializer.deserialize<core::ContainerPolicyWithoutItem>(serialized, "policy");
    const auto asDerived = deserializer.deserialize<core::ContainerPolicy>(serialized, "policy");

    EXPECT_EQ(asBase.get, asDerived.get);
    EXPECT_EQ(asBase.update, asDerived.update);
    EXPECT_EQ(asBase.delete_, asDerived.delete_);
    EXPECT_EQ(asBase.updatePolicy, asDerived.updatePolicy);
    EXPECT_EQ(asBase.updaterCanBeRemovedFromManagers, asDerived.updaterCanBeRemovedFromManagers);
    EXPECT_EQ(asBase.ownerCanBeRemovedFromManagers, asDerived.ownerCanBeRemovedFromManagers);
    EXPECT_EQ(asBase.rotateKeys, asDerived.rotateKeys);
    EXPECT_EQ(asBase.forwardSecrecy, asDerived.forwardSecrecy);
    EXPECT_EQ(asBase.cryptoSuite, asDerived.cryptoSuite);
}
