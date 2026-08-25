#include <gtest/gtest.h>

#include <map>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include <privmx/crypto/Crypto.hpp>
#include <privmx/crypto/ecc/PrivateKey.hpp>
#include <privmx/crypto/ecc/PublicKey.hpp>
#include <privmx/endpoint/core/CoreException.hpp>
#include <privmx/endpoint/core/CoreTypes.hpp>
#include <privmx/endpoint/core/KeyProvider.hpp>
#include <privmx/endpoint/core/ServerTypes.hpp>
#include <privmx/endpoint/core/UserVerifier.hpp>
#include <privmx/endpoint/core/encryptors/EncKey/EncKeyEncryptorV2.hpp>

using namespace privmx::endpoint;
using namespace privmx::endpoint::core;

// Several granted groups mean several routes to one container key, under one `keyId`. Two properties are
// pinned here, and they pull against each other: every route is kept and tried, yet any route that failed
// still marks the key — so one dead route among several denies the container, deliberately.
//
// Stubbing the resolver is the only way to make a route dead on demand and to assert one was not attempted.

namespace {

constexpr const char* CONTEXT_ID = "ctx_key_provider_group_keys";
constexpr const char* RESOURCE_ID = "res_key_provider_group_keys";
constexpr const char* KEY_ID = "key_shared_by_every_group";
constexpr const char* GROUP_A = "group_a";
constexpr const char* GROUP_B = "group_b";

class AcceptAllVerifier : public UserVerifierInterface {
public:
    std::vector<bool> verify(const std::vector<VerificationRequest>& request) override {
        return std::vector<bool>(request.size(), true);
    }
};

/** Records which groups the resolver was asked about, so a test can assert on attempts not made. */
struct ResolverLog {
    std::vector<std::string> attempted;
};

class KeyProviderGroupKeysTest : public ::testing::Test {
protected:
    void SetUp() override {
        // By pointer: `KeyProvider` has no default constructor, and this assumes nothing about copy/move.
        _keyProvider = std::make_unique<KeyProvider>(privmx::crypto::PrivateKey::generateRandom(), [] {
            return std::make_shared<UserVerifier>(std::make_shared<AcceptAllVerifier>());
        });
    }

    /** One group-addressed wrapping of the shared container key, shaped as `buildGroupKeyEntries` emits it. */
    server::GroupKeyEntry wrapFor(const privmx::crypto::PublicKey& groupPubKey, int64_t groupEpoch) {
        const std::string keySecret = "key-secret-at-epoch-" + std::to_string(groupEpoch);

        DataIntegrityObject dio;
        dio.creatorUserId = "user_1";
        dio.creatorPubKey = _author.getPublicKey().toBase58DER();
        dio.contextId = CONTEXT_ID;
        dio.resourceId = RESOURCE_ID;
        dio.timestamp = 1787061039429;
        // Distinct per entry: a shared (randomId, timestamp) is what `verifyForDuplication` fails on.
        dio.randomId = "random-id-" + std::to_string(groupEpoch);
        // Not optional in practice: `DIOEncryptorV1::decodeAndVerify` dereferences it without checking.
        dio.bridgeIdentity = BridgeIdentity{.url = "http://localhost/"};

        EncKeyV2ToEncrypt toEncrypt;
        toEncrypt.id = _containerKey.id;
        toEncrypt.key = _containerKey.key;
        toEncrypt.dio = dio;
        toEncrypt.location = _location;
        toEncrypt.keySecret = keySecret;
        toEncrypt.secretHash = privmx::crypto::Crypto::hmacSha256(
            _containerSecret, keySecret + std::string(CONTEXT_ID) + std::string(RESOURCE_ID)
        );

        EncKeyEncryptorV2 encryptor;
        auto encrypted = encryptor.encrypt(toEncrypt, groupPubKey, _author);
        return server::GroupKeyEntry{
            .keyId = _containerKey.id, .data = encrypted.toJSON(), .groupEpoch = groupEpoch
        };
    }

    /** Two granted groups covering one keyId, served in A-then-B order, as the bridge stores them. */
    std::vector<server::GroupKeysEntry> twoRoutes(
        const privmx::crypto::PrivateKey& groupA,
        const privmx::crypto::PrivateKey& groupB
    ) {
        return {
            {.group = GROUP_A, .keys = {wrapFor(groupA.getPublicKey(), 1)}},
            {.group = GROUP_B, .keys = {wrapFor(groupB.getPublicKey(), 2)}}
        };
    }

    /** Resolves only the listed groups; every call is recorded, in order. */
    static KeyProvider::GroupPrivKeyResolver resolverOver(
        const std::map<std::string, privmx::crypto::PrivateKey>& openable,
        ResolverLog& log
    ) {
        return [&openable, &log](const std::string& groupId, int64_t) {
            log.attempted.push_back(groupId);
            const auto found = openable.find(groupId);
            return found == openable.end() ? std::nullopt :
                                             std::optional<privmx::crypto::PrivateKey>(found->second);
        };
    }

    std::unique_ptr<KeyProvider> _keyProvider;
    privmx::crypto::PrivateKey _author = privmx::crypto::PrivateKey::generateRandom();
    EncKey _containerKey{.id = KEY_ID, .key = std::string(32, '\x2b')};
    EncKeyLocation _location{.contextId = CONTEXT_ID, .resourceId = RESOURCE_ID};
    std::string _containerSecret = "container-secret";
};

} // namespace

TEST_F(KeyProviderGroupKeysTest, dead_route_marks_the_key_even_though_a_later_route_opens_it) {
    // Fail closed: group_b yields the right key, but group_a's failure still marks it. The same shape covers
    // "this epoch is not mine to reach" and "the server served a DIO that does not verify".
    const auto groupA = privmx::crypto::PrivateKey::generateRandom();
    const auto groupB = privmx::crypto::PrivateKey::generateRandom();

    KeyDecryptionAndVerificationRequest request;
    request.addGroupKeys(twoRoutes(groupA, groupB), _location);

    ResolverLog log;
    const std::map<std::string, privmx::crypto::PrivateKey> openable{{GROUP_B, groupB}};
    const auto keys = _keyProvider->getKeysAndVerify(request, resolverOver(openable, log));

    const auto& key = keys.at(_location).at(KEY_ID);
    EXPECT_EQ(key.statusCode, UnknownEncryptionKeyVersionException().getCode());
    // `statusCode` withholds the key without erasing what was found.
    EXPECT_EQ(key.id, KEY_ID);
    EXPECT_EQ(key.key, _containerKey.key);
    // Both tried: nothing can tell a route is dead without attempting it.
    EXPECT_EQ(log.attempted, (std::vector<std::string>{GROUP_A, GROUP_B}));
}

TEST_F(KeyProviderGroupKeysTest, opening_on_the_first_route_leaves_no_mark) {
    // The case a single-entry map got wrong: it kept the *last* group, discarding the only openable route.
    //
    // Also the honest limit of the mark: the search stops on success, so a dead group_b is never attempted and
    // never reported. Detection stays order-dependent until the key-free DIO checks run over every route first.
    const auto groupA = privmx::crypto::PrivateKey::generateRandom();
    const auto groupB = privmx::crypto::PrivateKey::generateRandom();

    KeyDecryptionAndVerificationRequest request;
    request.addGroupKeys(twoRoutes(groupA, groupB), _location);

    ResolverLog log;
    const std::map<std::string, privmx::crypto::PrivateKey> openable{{GROUP_A, groupA}};
    const auto keys = _keyProvider->getKeysAndVerify(request, resolverOver(openable, log));

    const auto& key = keys.at(_location).at(KEY_ID);
    EXPECT_EQ(key.statusCode, 0);
    EXPECT_EQ(key.key, _containerKey.key);
    // Stopped on the first success: attempting group_b costs a `groupGet` and a climb for nothing.
    EXPECT_EQ(log.attempted, (std::vector<std::string>{GROUP_A}));
}

TEST_F(KeyProviderGroupKeysTest, unopenable_routes_leave_a_failed_entry_under_the_keyId) {
    // Every route dead still yields an entry: callers read `.at(keyId).statusCode`, so a gap throws instead.
    const auto groupA = privmx::crypto::PrivateKey::generateRandom();
    const auto groupB = privmx::crypto::PrivateKey::generateRandom();

    KeyDecryptionAndVerificationRequest request;
    request.addGroupKeys(twoRoutes(groupA, groupB), _location);

    ResolverLog log;
    const std::map<std::string, privmx::crypto::PrivateKey> openable{};
    const auto keys = _keyProvider->getKeysAndVerify(request, resolverOver(openable, log));

    const auto locationKeys = keys.at(_location);
    ASSERT_EQ(locationKeys.count(KEY_ID), 1u);
    EXPECT_EQ(locationKeys.at(KEY_ID).statusCode, UnknownEncryptionKeyVersionException().getCode());
    EXPECT_EQ(log.attempted, (std::vector<std::string>{GROUP_A, GROUP_B}));
}

TEST_F(KeyProviderGroupKeysTest, adding_the_same_location_twice_does_not_duplicate_routes) {
    // `DataSchemaMapperUtils` adds per item and two items can share a container, so a repeated add is ordinary.
    // `insert_or_assign` was idempotent for free; appending is not, and a dup route is a dup `groupGet`.
    const auto groupA = privmx::crypto::PrivateKey::generateRandom();
    const auto groupB = privmx::crypto::PrivateKey::generateRandom();
    const std::vector<server::GroupKeysEntry> served = twoRoutes(groupA, groupB);

    KeyDecryptionAndVerificationRequest request;
    request.addGroupKeys(served, _location);
    request.addGroupKeys(served, _location);

    EXPECT_EQ(request.groupRequestData.at(_location).at(KEY_ID).size(), 2u);
}
