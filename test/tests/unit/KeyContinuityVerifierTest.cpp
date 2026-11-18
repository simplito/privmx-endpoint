/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

// The verifier a connection has by default: the first key a user is seen with is theirs, and another is refused
// until the application accepts the change.

#include <gtest/gtest.h>

#include <privmx/endpoint/core/KeyContinuityVerifier.hpp>

using namespace privmx::endpoint::core;

namespace {

const std::int64_t FAR_FUTURE = 4102444800000; // 2100-01-01

bool ask(KeyContinuityVerifier& verifier, const std::string& user, const std::string& key, std::int64_t date = 1) {
    return verifier.verify({VerificationRequest{
        .contextId = "ctx", .senderId = user, .senderPubKey = key, .date = date, .bridgeIdentity = std::nullopt
    }})[0];
}

} // namespace

TEST(KeyContinuityVerifier, SECURITY_TheFirstKeyIsKeptAndAnotherIsRefused) {
    KeyContinuityVerifier verifier;
    EXPECT_TRUE(ask(verifier, "bob", "K1"));
    EXPECT_TRUE(ask(verifier, "bob", "K1"));
    EXPECT_FALSE(ask(verifier, "bob", "K2")) << "a key swapped by the Bridge";
    EXPECT_TRUE(ask(verifier, "carol", "K2")) << "users are told apart";
    // The same user id in another Context is another user.
    EXPECT_TRUE(verifier.verify({VerificationRequest{
        .contextId = "other", .senderId = "bob", .senderPubKey = "K2", .date = 1, .bridgeIdentity = std::nullopt
    }})[0]);
}

TEST(KeyContinuityVerifier, AnAcceptedChangeMovesTheUserToTheNewKey) {
    KeyContinuityVerifier verifier;
    ASSERT_TRUE(ask(verifier, "bob", "K1"));
    verifier.accept("ctx", "bob", "K1", "K2");
    EXPECT_TRUE(ask(verifier, "bob", "K2"));
    EXPECT_TRUE(ask(verifier, "bob", "K2", FAR_FUTURE));
    // What the old key signed before stays the user's; nothing it signs from now on does.
    EXPECT_TRUE(ask(verifier, "bob", "K1", 1));
    EXPECT_FALSE(ask(verifier, "bob", "K1", FAR_FUTURE));
    EXPECT_FALSE(ask(verifier, "bob", "K3"));
}

TEST(KeyContinuityVerifier, SECURITY_AChangeIsAcceptedOnlyFromTheKeyTheUserIsKnownBy) {
    KeyContinuityVerifier verifier;
    ASSERT_TRUE(ask(verifier, "bob", "K1"));
    EXPECT_THROW(verifier.accept("ctx", "bob", "K9", "K2"), InvalidParamsException);
    EXPECT_THROW(verifier.accept("ctx", "bob", "K1", "K1"), InvalidParamsException);
    EXPECT_FALSE(ask(verifier, "bob", "K2")) << "a refused accept changes nothing";
    // A user not seen yet: both keys are the application's word.
    verifier.accept("ctx", "dave", "D1", "D2");
    EXPECT_TRUE(ask(verifier, "dave", "D2"));
    EXPECT_FALSE(ask(verifier, "dave", "D1", FAR_FUTURE));
}

TEST(KeyContinuityVerifier, TheConnectionsOwnKeysAreAcceptedForItsOwnUser) {
    KeyContinuityVerifier verifier([](const std::string&) { return std::string("me"); });
    ASSERT_TRUE(ask(verifier, "me", "OLD")); // a statement signed before the key change, seen first
    verifier.trustOwn("NEW", true);
    EXPECT_TRUE(ask(verifier, "me", "NEW")) << "the user's own current key, after a change";
    EXPECT_TRUE(ask(verifier, "me", "NEW", FAR_FUTURE));
    EXPECT_FALSE(ask(verifier, "me", "ELSE"));
}

TEST(KeyContinuityVerifier, SECURITY_AnOwnKeyVouchesForTheOwnUserOnly) {
    KeyContinuityVerifier verifier([](const std::string&) { return std::string("me"); });
    verifier.trustOwn("MINE", true);
    ASSERT_TRUE(ask(verifier, "bob", "BOBS"));
    EXPECT_FALSE(ask(verifier, "bob", "MINE")) << "the Bridge presenting this user's key as bob's";
    // Without knowing who this connection is, an own key is a key like any other.
    KeyContinuityVerifier anonymous;
    anonymous.trustOwn("MINE", true);
    ASSERT_TRUE(ask(anonymous, "bob", "BOBS"));
    EXPECT_FALSE(ask(anonymous, "bob", "MINE"));
}

TEST(KeyContinuityVerifier, SECURITY_APreviousOwnKeyIsGoodOnlyForWhatWasDatedBeforeItWasAdopted) {
    KeyContinuityVerifier verifier([](const std::string&) { return std::string("me"); });
    verifier.trustOwn("NEW", true);
    ASSERT_TRUE(ask(verifier, "me", "NEW"));
    verifier.trustOwn("OLD", false);
    EXPECT_TRUE(ask(verifier, "me", "OLD", 1));
    EXPECT_FALSE(ask(verifier, "me", "OLD", FAR_FUTURE)) << "whoever holds the old key signs nothing new";
}
