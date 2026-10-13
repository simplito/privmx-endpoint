#include <gtest/gtest.h>

#include <map>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include <privmx/crypto/Crypto.hpp>
#include <privmx/crypto/EciesEncryptor.hpp>
#include <privmx/crypto/ecc/PrivateKey.hpp>
#include <privmx/crypto/ecc/PublicKey.hpp>
#include <privmx/endpoint/core/ContainerBaseApi.hpp>
#include <privmx/endpoint/core/CoreConstants.hpp>
#include <privmx/endpoint/core/CoreException.hpp>
#include <privmx/endpoint/core/CoreTypes.hpp>
#include <privmx/endpoint/core/KeyProvider.hpp>
#include <privmx/endpoint/core/ServerTypes.hpp>
#include <privmx/endpoint/core/UserVerifier.hpp>
#include <privmx/endpoint/core/encryptors/EncKey/EncKeyEncryptorV2.hpp>

#include "AcceptAllVerifier.hpp"

using namespace privmx::endpoint::core;

/**
 * Several granted groups mean several routes to one container key, under one `keyId`. Two properties are
 * pinned here, and they pull against each other: every route is kept and tried, yet any route that failed
 * still marks the key — so one dead route among several denies the container, deliberately.
 *
 * Stubbing the resolver is the only way to make a route dead on demand and to assert one was not attempted.
 */

namespace {

constexpr const char* CONTEXT_ID = "ctx_key_provider_group_keys";
constexpr const char* RESOURCE_ID = "res_key_provider_group_keys";
constexpr const char* KEY_ID = "key_shared_by_every_group";
constexpr const char* GROUP_A = "group_a";
constexpr const char* GROUP_B = "group_b";

// Records which groups the resolver was asked about, so a test can assert on attempts not made.
struct ResolverLog {
    std::vector<std::string> attempted;
};

class KeyProviderGroupKeysTest : public ::testing::Test {
protected:
    void SetUp() override {
        // By pointer: `KeyProvider` has no default constructor, and this assumes nothing about copy/move.
        _keyProvider = std::make_unique<KeyProvider>(_userKey, [] {
            return std::make_shared<UserVerifier>(std::make_shared<AcceptAllVerifier>());
        });
    }

    // One group-addressed wrapping of the shared container key, shaped as `buildGroupKeyEntries` emits it.
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

    // Two granted groups covering one keyId, served in A-then-B order, as the bridge stores them.
    std::vector<server::GroupKeysEntry> twoRoutes(
        const privmx::crypto::PrivateKey& groupA,
        const privmx::crypto::PrivateKey& groupB
    ) {
        return {
            {.group = GROUP_A, .keys = {wrapFor(groupA.getPublicKey(), 1)}},
            {.group = GROUP_B, .keys = {wrapFor(groupB.getPublicKey(), 2)}}
        };
    }

    // Resolves only the listed groups; every call is recorded, in order.
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

    // An unsigned V1 entry, as old clients wrote it and as anyone holding the recipient's public key can forge it.
    server::KeyEntry v1For(const privmx::crypto::PublicKey& recipient, const std::string& key) {
        return server::KeyEntry{
            .keyId = _containerKey.id,
            .data = privmx::crypto::EciesEncryptor::encryptToBase64(
                recipient, key, privmx::crypto::PrivateKey::generateRandom()
            )
        };
    }

    privmx::crypto::PrivateKey _userKey = privmx::crypto::PrivateKey::generateRandom();
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
    // The honest limit of the mark: the search stops on success, so a dead group_b is never attempted and never
    // reported. Detection stays order-dependent until the key-free DIO checks run over every route first.
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

namespace {

// Just enough of a module to call the `ModuleKeys` current-key read, the one Thread, Kvdb and most Store calls use.
class CurrentKeyReader : public ContainerBaseApi {
public:
    CurrentKeyReader(const std::shared_ptr<KeyProvider>& keyProvider, const KeyProvider::GroupPrivKeyResolver& resolver)
        : ContainerBaseApi(privmx::crypto::PrivateKey::generateRandom(), keyProvider, "", nullptr, Connection()) {
        initGroupPrivKeyResolver(resolver);
    }
    using ContainerBaseApi::getAndValidateModuleCurrentEncKey;
    using ContainerBaseApi::isRekeyNeeded;

private:
    std::pair<ModuleKeys, int64_t> getModuleKeysAndVersionFromServer(std::string) override { return {}; }
};

} // namespace

TEST_F(KeyProviderGroupKeysTest, reading_the_current_key_resolves_only_its_own_epoch) {
    // A container re-keyed with every group epoch carries a grant per old key too. Reading the current key must not
    // resolve the group key of each of them: at epoch 30 that was 30 `groupGet`s and climbs per read.
    const auto group = privmx::crypto::PrivateKey::generateRandom();
    server::GroupKeysEntry grants{.group = GROUP_A, .keys = {}};
    for (int64_t epoch = 1; epoch < 30; ++epoch) {
        auto old = wrapFor(group.getPublicKey(), epoch);
        old.keyId = "old-key-" + std::to_string(epoch);
        grants.keys.push_back(old);
    }
    grants.keys.push_back(wrapFor(group.getPublicKey(), 30));

    std::vector<int64_t> resolvedEpochs;
    CurrentKeyReader reader(
        std::shared_ptr<KeyProvider>(std::move(_keyProvider)),
        [&](const std::string&, int64_t epoch) -> std::optional<privmx::crypto::PrivateKey> {
            resolvedEpochs.push_back(epoch);
            return group;
        }
    );
    const auto key = reader.getAndValidateModuleCurrentEncKey(ModuleKeys{
        .keys = {}, .groupKeys = {grants}, .staleGroups = {}, .currentKeyId = KEY_ID, .moduleSchemaVersion = 0,
        .moduleResourceId = _location.resourceId, .contextId = _location.contextId
    });

    EXPECT_EQ(key.statusCode, 0);
    EXPECT_EQ(key.key, _containerKey.key);
    EXPECT_EQ(resolvedEpochs, (std::vector<int64_t>{30}));
}

TEST_F(KeyProviderGroupKeysTest, v1_entry_on_a_group_route_is_rejected) {
    // Grants are written as V2 only, so a V1 grant is the server's own key, sealed to the public group key.
    const auto group = privmx::crypto::PrivateKey::generateRandom();
    const std::string serverKey(32, '\x5a');
    auto forged = v1For(group.getPublicKey(), serverKey);
    std::vector<server::GroupKeysEntry> served{
        {.group = GROUP_A, .keys = {server::GroupKeyEntry{.keyId = forged.keyId, .data = forged.data, .groupEpoch = 1}}}
    };
    KeyDecryptionAndVerificationRequest request;
    request.addGroupKeys(served, _location);

    ResolverLog log;
    const std::map<std::string, privmx::crypto::PrivateKey> openable{{GROUP_A, group}};
    const auto key = _keyProvider->getKeysAndVerify(request, resolverOver(openable, log)).at(_location).at(KEY_ID);
    EXPECT_NE(key.statusCode, 0);
}

TEST_F(KeyProviderGroupKeysTest, v1_entry_stays_readable_but_is_refused_as_the_write_key) {
    const std::string serverKey(32, '\x5a');
    const auto forged = v1For(_userKey.getPublicKey(), serverKey);
    auto keyProvider = std::shared_ptr<KeyProvider>(std::move(_keyProvider));

    // Reading old data under a legacy V1 key keeps working.
    KeyDecryptionAndVerificationRequest request;
    request.addOne({forged}, KEY_ID, _location);
    const auto read = keyProvider->getKeysAndVerify(request).at(_location).at(KEY_ID);
    EXPECT_EQ(read.statusCode, 0);
    EXPECT_EQ(read.key, serverKey);

    // Encrypting under it does not: the key id and the entry are both the server's choice. It reads as a key to
    // re-key away, so a write that may re-key rotates it first and any other is told it has to be.
    CurrentKeyReader reader(keyProvider, nullptr);
    const ModuleKeys current{
        .keys = {forged}, .groupKeys = {}, .staleGroups = {}, .currentKeyId = KEY_ID, .moduleSchemaVersion = 0,
        .moduleResourceId = _location.resourceId, .contextId = _location.contextId
    };
    EXPECT_TRUE(reader.isRekeyNeeded(current));
    EXPECT_THROW(reader.getAndValidateModuleCurrentEncKey(current), StaleKeyRekeyRequiredException);
}

TEST_F(KeyProviderGroupKeysTest, malformed_v1_entry_fails_alone) {
    server::KeyEntry malformed{.keyId = "malformed", .data = std::string("not-ecies")};
    auto good = wrapFor(_userKey.getPublicKey(), 1);
    KeyDecryptionAndVerificationRequest request;
    request.addAll({malformed, server::KeyEntry{.keyId = good.keyId, .data = good.data}}, _location);

    const auto keys = _keyProvider->getKeysAndVerify(request).at(_location);
    EXPECT_NE(keys.at("malformed").statusCode, 0);
    EXPECT_EQ(keys.at(KEY_ID).statusCode, 0);
}

TEST_F(KeyProviderGroupKeysTest, v1_key_is_never_rewrapped_as_signed_v2) {
    // Re-wrapping would sign a key the server may have chosen, laundering it into a V2 entry a new member trusts.
    DecryptedEncKeyV2 v1;
    v1.id = KEY_ID;
    v1.key = std::string(32, '\x5a');
    v1.statusCode = 0;
    v1.dataStructureVersion = EncryptionKeyDataSchema::Version::VERSION_1;
    const UserWithPubKey newcomer{.userId = "user_2", .pubKey = _author.getPublicKey().toBase58DER()};
    const auto entries = _keyProvider->prepareMissingKeysForNewUsers(
        {{KEY_ID, v1}}, {newcomer}, DataIntegrityObject{}, _location, _containerSecret
    );
    EXPECT_TRUE(entries.empty());
}
