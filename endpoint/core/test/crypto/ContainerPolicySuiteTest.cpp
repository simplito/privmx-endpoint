/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

/**
 * The container's algorithm suite versus the policy sent in an update.
 *
 * The contract: the suite is fixed when the container is **created** and does not change afterwards.
 * The bridge enforces that literally — an update carries the whole policy, so to it omitting
 * `cryptoSuite` is as much a change as swapping it, and ends in `INVALID_PARAMS`.
 *
 * Hence the two things these tests guard:
 *  - the policy going out in an update carries the container's suite, even when the caller did not
 *    repeat it;
 *  - an explicitly named, conflicting suite is reported **on our side**, not bounced off the server.
 */

#include <optional>
#include <string>

#include <gtest/gtest.h>

#include <Poco/Dynamic/Var.h>
#include <Poco/JSON/Object.h>

#include <privmx/endpoint/core/ContainerBaseApi.hpp>
#include <privmx/endpoint/core/CoreException.hpp>
#include <privmx/endpoint/core/Types.hpp>

using namespace privmx::endpoint::core;

namespace {

/// The minimum `policyForUpdate` requires: anything with a `policy` field.
struct FakeContainer {
    Poco::Dynamic::Var policy;
};

FakeContainer containerWithSuite(const std::optional<std::string>& suite) {
    Poco::JSON::Object::Ptr obj = new Poco::JSON::Object();
    if (suite.has_value()) {
        obj->set("cryptoSuite", suite.value());
    }
    return FakeContainer{.policy = obj};
}

/// `policyForUpdate` is `protected` and static — inheriting is the simplest way to reach it without
/// opening it up to the outside world just for a test.
struct Reach : ContainerBaseApi {
    using ContainerBaseApi::policyForUpdate;
};

ContainerPolicyWithoutItem policyNaming(const std::optional<std::string>& suite) {
    ContainerPolicyWithoutItem policy;
    policy.cryptoSuite = suite;
    return policy;
}

const std::string SUITE_A{"aes256gcm-sha256"};
const std::string SUITE_B{"aes256gcm-sha512"};

} // namespace

/// The commonest case: the caller changes permissions and has no reason to repeat the suite.
/// Without carrying it over, the bridge would reject such an update.
TEST(ContainerPolicySuite, OmittedSuiteIsCarriedOverFromTheContainer) {
    const auto result = Reach::policyForUpdate(containerWithSuite(SUITE_A), policyNaming(std::nullopt));

    ASSERT_TRUE(result.cryptoSuite.has_value());
    EXPECT_EQ(SUITE_A, result.cryptoSuite.value());
}

TEST(ContainerPolicySuite, RepeatingTheSameSuiteIsAccepted) {
    const auto result = Reach::policyForUpdate(containerWithSuite(SUITE_A), policyNaming(SUITE_A));

    ASSERT_TRUE(result.cryptoSuite.has_value());
    EXPECT_EQ(SUITE_A, result.cryptoSuite.value());
}

/// Reported under its own name rather than as the server's `INVALID_PARAMS` — the caller should
/// know they are trying to change something that is immutable by design.
TEST(ContainerPolicySuite, NamingADifferentSuiteIsRefused) {
    EXPECT_THROW(
        Reach::policyForUpdate(containerWithSuite(SUITE_A), policyNaming(SUITE_B)),
        CryptoSuiteIsFixedAtCreationException
    );
}

/// A container that never named a suite cannot acquire one later — the bridge will not accept it either.
TEST(ContainerPolicySuite, AContainerWithoutASuiteCannotAcquireOne) {
    EXPECT_THROW(
        Reach::policyForUpdate(containerWithSuite(std::nullopt), policyNaming(SUITE_A)),
        CryptoSuiteIsFixedAtCreationException
    );
}

TEST(ContainerPolicySuite, AContainerWithoutASuiteStaysWithoutOne) {
    const auto result = Reach::policyForUpdate(containerWithSuite(std::nullopt), policyNaming(std::nullopt));

    EXPECT_FALSE(result.cryptoSuite.has_value());
}

/// Only `cryptoSuite` is carried over — the rest of the policy is the caller's and passes through unchanged.
TEST(ContainerPolicySuite, TheRestOfThePolicyIsLeftAlone) {
    ContainerPolicyWithoutItem policy = policyNaming(std::nullopt);
    policy.update = std::string("manager");
    policy.get = std::string("all");

    const auto result = Reach::policyForUpdate(containerWithSuite(SUITE_A), policy);

    ASSERT_TRUE(result.update.has_value());
    EXPECT_EQ("manager", result.update.value());
    ASSERT_TRUE(result.get.has_value());
    EXPECT_EQ("all", result.get.value());
    EXPECT_EQ(SUITE_A, result.cryptoSuite.value());
}
