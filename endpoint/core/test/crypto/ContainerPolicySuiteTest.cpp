/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

/**
 * Zestaw algorytmow kontenera a polityka wysylana w aktualizacji.
 *
 * Kontrakt: zestaw jest ustalany przy **tworzeniu** kontenera i juz sie nie zmienia. Bridge egzekwuje
 * to doslownie - aktualizacja niesie cala polityke, wiec pominiecie `cryptoSuite` jest dla niego taka
 * sama zmiana jak podmiana, i konczy sie `INVALID_PARAMS`.
 *
 * Stad dwie rzeczy, ktorych pilnuja te testy:
 *  - polityka wychodzaca w aktualizacji ma zestaw kontenera, nawet gdy wolajacy go nie powtorzyl;
 *  - jawnie podany, sprzeczny zestaw jest zglaszany **po naszej stronie**, a nie odbijany z serwera.
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

/// Minimum, ktorego wymaga `policyForUpdate`: cokolwiek z polem `policy`.
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

/// `policyForUpdate` jest `protected` i statyczna - dziedziczenie jest tu najprostszym sposobem
/// dostania sie do niej bez otwierania jej na zewnatrz tylko dla testu.
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

/// Najczestszy przypadek: wolajacy zmienia uprawnienia i nie ma powodu powtarzac zestawu.
/// Bez przeniesienia Bridge odrzucilby taka aktualizacje.
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

/// Zglaszane pod wlasna nazwa, a nie jako `INVALID_PARAMS` z serwera - wolajacy ma wiedziec,
/// ze probuje zmienic cos, co jest z zalozenia niezmienne.
TEST(ContainerPolicySuite, NamingADifferentSuiteIsRefused) {
    EXPECT_THROW(
        Reach::policyForUpdate(containerWithSuite(SUITE_A), policyNaming(SUITE_B)),
        CryptoSuiteIsFixedAtCreationException
    );
}

/// Kontener, ktory nigdy nie nazwal zestawu, nie moze go nabyc pozniej - Bridge tez tego nie przyjmie.
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

/// Przenoszenie dotyczy wylacznie `cryptoSuite` - reszta polityki jest wolajacego i ma przejsc bez zmian.
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
