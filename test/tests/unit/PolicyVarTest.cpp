/*
 * A container policy as a binding hands it over (the Var layer the web and other bindings call through). Every
 * field of the policy must survive it: a rule that is dropped on the way in is a rule the caller believes they set.
 * Found by the browser tests - a rule set on the way in came back missing.
 */

#include <gtest/gtest.h>

#include <privmx/endpoint/core/Types.hpp>
#include <privmx/endpoint/core/VarDeserializer.hpp>
#include <privmx/utils/Utils.hpp>

using namespace privmx::endpoint::core;

TEST(PolicyVar, EveryFieldOfAContainerPolicySurvivesTheBindingLayer) {
    const auto json = privmx::utils::Utils::parseJsonObject(R"({
        "get": "all", "update": "user", "delete_": "owner", "updatePolicy": "none",
        "updaterCanBeRemovedFromManagers": "no", "ownerCanBeRemovedFromManagers": "yes",
        "rotateKeys": "manager", "forwardSecrecy": "yes"
    })");
    VarDeserializer deserializer;
    for (const bool withItem : {true, false}) {
        const ContainerPolicyWithoutItem policy = withItem ?
            static_cast<ContainerPolicyWithoutItem>(deserializer.deserialize<ContainerPolicy>(json, "policy")) :
            deserializer.deserialize<ContainerPolicyWithoutItem>(json, "policy");
        EXPECT_EQ(policy.get, "all") << withItem;
        EXPECT_EQ(policy.update, "user") << withItem;
        EXPECT_EQ(policy.delete_, "owner") << withItem;
        EXPECT_EQ(policy.updatePolicy, "none") << withItem;
        EXPECT_EQ(policy.updaterCanBeRemovedFromManagers, "no") << withItem;
        EXPECT_EQ(policy.ownerCanBeRemovedFromManagers, "yes") << withItem;
        EXPECT_EQ(policy.rotateKeys, "manager") << withItem;
        EXPECT_EQ(policy.forwardSecrecy, "yes") << withItem;
    }
}
