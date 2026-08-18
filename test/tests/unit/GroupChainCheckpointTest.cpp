/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

/** Unit tests for `GroupDataSchemaMapper::assertDataIntegrity`'s warm-read chain checkpoint and version/keyVersion trust-on-first-use pinning; no server is involved, each history entry is authored through the real `encrypt` path and assembled into a `server::GroupInfo` by hand, the way the bridge would serve it. */

#include <gtest/gtest.h>

#include <optional>
#include <set>
#include <string>
#include <vector>

#include <privmx/crypto/Crypto.hpp>
#include <privmx/crypto/ecc/PrivateKey.hpp>
#include <privmx/utils/Utils.hpp>

#include <privmx/endpoint/core/Connection.hpp>
#include <privmx/endpoint/group/GroupException.hpp>
#include <privmx/endpoint/group/checkpoint/ChainCheckpoint.hpp>
#include <privmx/endpoint/group/checkpoint/ChainCheckpointRegistry.hpp>
#include <privmx/endpoint/group/encryptors/group/GroupDataSchemaMapper.hpp>

using privmx::crypto::PrivateKey;
using namespace privmx::endpoint;
using namespace privmx::endpoint::group;

// assertDataIntegrity — warm-read checkpoint behaviour
class GroupChainCheckpoint : public testing::Test {
protected:
    struct ChainFixture {
        server::GroupInfo group;
        std::string e0Dio, e1Dio, e2Dio;
        PrivateKey alice = PrivateKey::generateRandom();
    };

    std::string hashOf(const std::string& dioStr) {
        return privmx::utils::Hex::from(privmx::crypto::Crypto::sha256(dioStr));
    }

    std::string appendNewHistoryEntry(
        server::GroupInfo& group,
        const PrivateKey& authorPriv,
        const std::string& authorUserId,
        const std::vector<std::string>& users,
        const std::vector<std::string>& managers,
        const std::string& groupPubKey,
        int64_t keyVersion,
        const std::optional<std::string>& prevEntryHash,
        int64_t timestamp
    ) {
        GroupDataSchemaMapper authorMapper(authorPriv, core::Connection());

        dynamic::MembershipBlock membership{
            .users = users,
            .managers = managers,
            .groupPubKey = groupPubKey,
            .keyId = "key1",
            .keyVersion = keyVersion,
            .prevEntryHash = prevEntryHash
        };

        core::DataIntegrityObject dio;
        dio.creatorUserId = authorUserId;
        dio.creatorPubKey = authorPriv.getPublicKey().toBase58DER();
        dio.contextId = group.contextId;
        dio.resourceId = group.resourceId.value_or("");
        dio.timestamp = timestamp;
        dio.randomId = "rnd-" + std::to_string(group.data.size());
        // A real Connection always stamps this, and DIOEncryptorV1::decodeAndVerify unconditionally dereferences it, so leaving it unset here would be undefined behavior, not a validated-away missing field.
        dio.bridgeIdentity = core::BridgeIdentity{.url = "https://bridge.test", .pubKey = std::nullopt, .instanceId = std::nullopt};

        GroupDataToEncryptV5 dataToEncrypt{
            .publicMeta = core::Buffer::from(std::string("pub-") + std::to_string(group.data.size())),
            .privateMeta = core::Buffer::from(std::string("priv")),
            .internalMeta = core::ModuleInternalMetaV5{
                .secret = "secret", .resourceId = dio.resourceId, .randomId = dio.randomId
            },
            .dio = dio,
            .groupPrivKey = "placeholder-group-priv-key",
            .membership = membership
        };

        // Never decrypted by these tests, but it still has to be a real AES-256 key or signAndEncryptAndEncode throws.
        Poco::Dynamic::Var blob = authorMapper.encrypt(dataToEncrypt, privmx::crypto::Crypto::randomBytes(32));

        server::GroupDataEntry entry;
        entry.keyId = "key1";
        entry.data = blob;
        group.data.push_back(entry);

        server::GroupHistoryEntryInfo hist;
        hist.keyId = "key1";
        hist.groupPubKey = groupPubKey;
        hist.users = users;
        hist.managers = managers;
        hist.created = timestamp;
        hist.author = authorUserId;
        group.history.push_back(hist);

        return dynamic::EncryptedGroupDataV5::fromJSON(blob).dio;
    }

    void populateHeadFromLastEntry(server::GroupInfo& group, int64_t keyVersion) {
        const auto& last = group.history.back();
        group.version = static_cast<int64_t>(group.data.size());
        group.users = last.users;
        group.managers = last.managers;
        group.groupPubKey = last.groupPubKey;
        group.keyVersion = keyVersion;
    }

    ChainFixture buildThreeEntryChain(const std::string& groupId) {
        ChainFixture fx;
        fx.group.id = groupId;
        fx.group.contextId = "ctx1";
        fx.group.resourceId = "res1";

        fx.e0Dio = appendNewHistoryEntry(fx.group, fx.alice, "alice", {"alice"}, {"alice"}, "pub0", 0, std::nullopt, 1000);
        fx.e1Dio = appendNewHistoryEntry(fx.group, fx.alice, "alice", {"alice"}, {"alice"}, "pub0", 0, hashOf(fx.e0Dio), 2000);
        fx.e2Dio = appendNewHistoryEntry(fx.group, fx.alice, "alice", {"alice"}, {"alice"}, "pub0", 0, hashOf(fx.e1Dio), 3000);
        populateHeadFromLastEntry(fx.group, 0);
        return fx;
    }
};

TEST_F(GroupChainCheckpoint, ColdThenWarmBaselineDeltaZero) {
    ChainFixture fx = buildThreeEntryChain("grp-baseline");
    GroupDataSchemaMapper verifier(PrivateKey::generateRandom(), core::Connection());

    ASSERT_NO_THROW(verifier.assertDataIntegrity(fx.group));
    auto checkpoint = verifier.peekChainCheckpoint(fx.group.id);
    ASSERT_TRUE(checkpoint.has_value());
    EXPECT_EQ(checkpoint->verifiedVersion, 3);
    EXPECT_EQ(checkpoint->lastEntryDioHashHex, hashOf(fx.e2Dio));

    // Second call, identical response: nothing new to verify (Δ=0), but it must still succeed and leave the checkpoint exactly where it was.
    ASSERT_NO_THROW(verifier.assertDataIntegrity(fx.group));
    auto checkpointAfter = verifier.peekChainCheckpoint(fx.group.id);
    ASSERT_TRUE(checkpointAfter.has_value());
    EXPECT_EQ(checkpointAfter->verifiedVersion, 3);
    EXPECT_EQ(checkpointAfter->lastEntryDioHashHex, hashOf(fx.e2Dio));
}

TEST_F(GroupChainCheckpoint, DeltaCorrectnessExtendsPastCheckpoint) {
    ChainFixture fx = buildThreeEntryChain("grp-delta");
    GroupDataSchemaMapper verifier(PrivateKey::generateRandom(), core::Connection());

    ASSERT_NO_THROW(verifier.assertDataIntegrity(fx.group));
    ASSERT_EQ(verifier.peekChainCheckpoint(fx.group.id)->verifiedVersion, 3);

    // Two more entries, still authored by alice (already an authorized manager per the checkpoint).
    std::string e3Dio = appendNewHistoryEntry(fx.group, fx.alice, "alice", {"alice"}, {"alice"}, "pub0", 0, hashOf(fx.e2Dio), 4000);
    appendNewHistoryEntry(fx.group, fx.alice, "alice", {"alice"}, {"alice"}, "pub0", 0, hashOf(e3Dio), 5000);
    populateHeadFromLastEntry(fx.group, 0);

    ASSERT_NO_THROW(verifier.assertDataIntegrity(fx.group));
    auto checkpoint = verifier.peekChainCheckpoint(fx.group.id);
    ASSERT_TRUE(checkpoint.has_value());
    EXPECT_EQ(checkpoint->verifiedVersion, 5) << "the resumed run must validate the new entries, not just no-op";
}

TEST_F(GroupChainCheckpoint, RewrittenPrefixIsRejected) {
    ChainFixture fx = buildThreeEntryChain("grp-rewrite");
    GroupDataSchemaMapper verifier(PrivateKey::generateRandom(), core::Connection());

    ASSERT_NO_THROW(verifier.assertDataIntegrity(fx.group));
    ASSERT_EQ(verifier.peekChainCheckpoint(fx.group.id)->verifiedVersion, 3);

    // A bridge that quietly swapped the already-verified slot 2 for a different, validly-signed entry that secretly promotes "mallory" to manager, then continues the chain from that alternate entry instead of the one this client actually verified.
    PrivateKey mallory = PrivateKey::generateRandom();
    server::GroupInfo alternate;
    alternate.id = fx.group.id;
    alternate.contextId = fx.group.contextId;
    alternate.resourceId = fx.group.resourceId;
    alternate.data = {fx.group.data[0], fx.group.data[1]};
    alternate.history = {fx.group.history[0], fx.group.history[1]};

    std::string e2AltDio = appendNewHistoryEntry(
        alternate, fx.alice, "alice", {"alice", "mallory"}, {"alice", "mallory"}, "pub0", 0, hashOf(fx.e1Dio), 3000
    );
    appendNewHistoryEntry(
        alternate, mallory, "mallory", {"alice", "mallory"}, {"alice", "mallory"}, "pub0", 0, hashOf(e2AltDio), 4000
    );
    populateHeadFromLastEntry(alternate, 0);

    EXPECT_THROW(verifier.assertDataIntegrity(alternate), GroupChainBrokenException)
        << "the new entry chains from the alternate slot-2, not from the checkpoint's remembered anchor";

    // The rejected attempt must not have disturbed the existing checkpoint.
    auto checkpoint = verifier.peekChainCheckpoint(fx.group.id);
    ASSERT_TRUE(checkpoint.has_value());
    EXPECT_EQ(checkpoint->verifiedVersion, 3);
    EXPECT_EQ(checkpoint->lastEntryDioHashHex, hashOf(fx.e2Dio));
}

TEST_F(GroupChainCheckpoint, VersionRegressionRejectedAsFork) {
    // A genuinely valid but stale shorter prefix of the same chain is indistinguishable from "fine" by chain-link/manager checks alone; once a longer state has been confirmed, a shorter one must be rejected outright, not silently re-verified and accepted.
    ChainFixture fx = buildThreeEntryChain("grp-regression");
    GroupDataSchemaMapper verifier(PrivateKey::generateRandom(), core::Connection());

    ASSERT_NO_THROW(verifier.assertDataIntegrity(fx.group));
    ASSERT_EQ(verifier.peekChainCheckpoint(fx.group.id)->verifiedVersion, 3);

    server::GroupInfo shorter;
    shorter.id = fx.group.id;
    shorter.contextId = fx.group.contextId;
    shorter.resourceId = fx.group.resourceId;
    shorter.data = {fx.group.data[0], fx.group.data[1]};
    shorter.history = {fx.group.history[0], fx.group.history[1]};
    populateHeadFromLastEntry(shorter, 0);

    EXPECT_THROW(verifier.assertDataIntegrity(shorter), GroupHistoryForkException)
        << "a shorter response than what's already confirmed must be reported as a fork, not silently accepted";

    // The rejected attempt must not have disturbed the existing checkpoint.
    auto checkpointAfterShorter = verifier.peekChainCheckpoint(fx.group.id);
    ASSERT_TRUE(checkpointAfterShorter.has_value());
    EXPECT_EQ(checkpointAfterShorter->verifiedVersion, 3);

    // The original, longer chain must still verify correctly afterward.
    ASSERT_NO_THROW(verifier.assertDataIntegrity(fx.group));
    EXPECT_EQ(verifier.peekChainCheckpoint(fx.group.id)->verifiedVersion, 3);
}

TEST_F(GroupChainCheckpoint, FirstSightingIsExemptFromPinning) {
    // Trust-on-first-use: with no checkpoint yet, there is nothing to regress behind, so any version verifies.
    ChainFixture fx = buildThreeEntryChain("grp-first-sighting");
    GroupDataSchemaMapper verifier(PrivateKey::generateRandom(), core::Connection());

    server::GroupInfo firstEntryOnly;
    firstEntryOnly.id = fx.group.id;
    firstEntryOnly.contextId = fx.group.contextId;
    firstEntryOnly.resourceId = fx.group.resourceId;
    firstEntryOnly.data = {fx.group.data[0]};
    firstEntryOnly.history = {fx.group.history[0]};
    populateHeadFromLastEntry(firstEntryOnly, 0);

    EXPECT_NO_THROW(verifier.assertDataIntegrity(firstEntryOnly));
    EXPECT_EQ(verifier.peekChainCheckpoint(fx.group.id)->verifiedVersion, 1);
}

TEST_F(GroupChainCheckpoint, DeltaZeroTamperedUsersEchoIsRejected) {
    // Regression test for the head-check anchoring fix: on a Δ=0 read, the head check must compare against the checkpoint-anchored `verifiedUsers`, not the bridge-supplied, unverified-this-round field.
    ChainFixture fx = buildThreeEntryChain("grp-tamper-users");
    GroupDataSchemaMapper verifier(PrivateKey::generateRandom(), core::Connection());
    ASSERT_NO_THROW(verifier.assertDataIntegrity(fx.group));

    server::GroupInfo tampered = fx.group; // same `data[]`, byte for byte — no re-signing needed
    tampered.history.back().users = {"alice", "mallory"};
    tampered.users = {"alice", "mallory"};

    EXPECT_THROW(verifier.assertDataIntegrity(tampered), GroupDataIntegrityException);
    EXPECT_EQ(verifier.peekChainCheckpoint(fx.group.id)->verifiedVersion, 3);
}

TEST_F(GroupChainCheckpoint, DeltaZeroTamperedGroupPubKeyEchoIsRejected) {
    ChainFixture fx = buildThreeEntryChain("grp-tamper-pubkey");
    GroupDataSchemaMapper verifier(PrivateKey::generateRandom(), core::Connection());
    ASSERT_NO_THROW(verifier.assertDataIntegrity(fx.group));

    server::GroupInfo tampered = fx.group;
    tampered.history.back().groupPubKey = "pub-fabricated";
    tampered.groupPubKey = "pub-fabricated";

    EXPECT_THROW(verifier.assertDataIntegrity(tampered), GroupDataIntegrityException);
    EXPECT_EQ(verifier.peekChainCheckpoint(fx.group.id)->verifiedVersion, 3);
}

// checkpoint::ChainCheckpoint / ChainCheckpointRegistry — no crypto involved
class ChainCheckpointCache : public testing::Test {};

TEST_F(ChainCheckpointCache, AdvanceIsMonotonic) {
    checkpoint::ChainCheckpoint cache;
    EXPECT_FALSE(cache.get().has_value());

    checkpoint::ChainCheckpoint::Snapshot low;
    low.verifiedVersion = 3;
    low.lastEntryDioHashHex = "hash-3";
    cache.advance(low);
    ASSERT_TRUE(cache.get().has_value());
    EXPECT_EQ(cache.get()->verifiedVersion, 3);

    checkpoint::ChainCheckpoint::Snapshot sameOrLower = low;
    sameOrLower.lastEntryDioHashHex = "hash-should-not-apply";
    cache.advance(sameOrLower);
    EXPECT_EQ(cache.get()->lastEntryDioHashHex, "hash-3") << "equal verifiedVersion must be a no-op";

    checkpoint::ChainCheckpoint::Snapshot higher;
    higher.verifiedVersion = 5;
    higher.lastEntryDioHashHex = "hash-5";
    cache.advance(higher);
    EXPECT_EQ(cache.get()->verifiedVersion, 5);
    EXPECT_EQ(cache.get()->lastEntryDioHashHex, "hash-5");
}

TEST_F(ChainCheckpointCache, RegistryGetOrCreateAndDrop) {
    checkpoint::ChainCheckpointRegistry registry;
    EXPECT_EQ(registry.groupCount(), 0u);
    EXPECT_EQ(registry.tryGet("grp1"), nullptr);

    auto store = registry.get("grp1");
    ASSERT_NE(store, nullptr);
    EXPECT_EQ(registry.groupCount(), 1u);
    EXPECT_EQ(registry.get("grp1"), store) << "must return the same store on a second lookup";

    registry.drop("grp1");
    EXPECT_EQ(registry.groupCount(), 0u);
    EXPECT_EQ(registry.tryGet("grp1"), nullptr);
    // The detached store handed out earlier stays valid for whoever still holds it.
    checkpoint::ChainCheckpoint::Snapshot snapshot;
    snapshot.verifiedVersion = 1;
    EXPECT_NO_THROW(store->advance(snapshot));

    registry.get("a");
    registry.get("b");
    EXPECT_EQ(registry.groupCount(), 2u);
    registry.dropAll();
    EXPECT_EQ(registry.groupCount(), 0u);
}
