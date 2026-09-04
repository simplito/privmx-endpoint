/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

/**
 * The roster attestation: `HMAC(metadata key, epoch | version | roster)` committed by whoever made the change.
 *
 * This replaced a signed chain walked back to genesis. What it keeps: a bridge cannot invent a member, because it
 * never holds the key. What it drops on purpose: who made the change, and whether they were a manager rather than
 * an ordinary member — holding the key is the authority now.
 *
 * These tests exist because the verification is one HMAC. Cheap is only good if it still refuses everything it
 * ought to, and each case below is a lie a malicious bridge would tell.
 */

#include <gtest/gtest.h>

#include <optional>
#include <string>
#include <vector>

#include <privmx/crypto/Crypto.hpp>
#include <privmx/crypto/ecc/PrivateKey.hpp>
#include <privmx/utils/Utils.hpp>

#include <privmx/endpoint/core/Connection.hpp>
#include <privmx/endpoint/group/GroupException.hpp>
#include <privmx/endpoint/group/encryptors/group/GroupDataSchemaMapper.hpp>

using privmx::crypto::PrivateKey;
using namespace privmx::endpoint;
using namespace privmx::endpoint::group;

class GroupRosterTag : public testing::Test {
protected:
    PrivateKey author = PrivateKey::generateRandom();
    std::string encKey = privmx::crypto::Crypto::randomBytes(32);

    core::DecryptedEncKey key(const std::string& material) {
        core::DecryptedEncKey k;
        k.key = material;
        k.statusCode = 0;
        return k;
    }

    /** A group as the bridge would serve it: one head entry, authored through the real encrypt path. */
    server::GroupInfo serve(
        const std::vector<std::string>& users,
        const std::vector<std::string>& managers,
        int64_t version,
        int64_t keyVersion,
        const std::string& tagKey
    ) {
        GroupDataSchemaMapper authorMapper(author, core::Connection());
        server::GroupInfo group;
        group.id = "grp";
        group.contextId = "ctx1";
        group.resourceId = "res1";
        group.groupPubKey = "pub0";
        group.users = users;
        group.managers = managers;
        group.version = version;
        group.keyVersion = keyVersion;

        dynamic::MembershipBlock membership{
            .rosterTag = GroupDataSchemaMapper::rosterTag(tagKey, keyVersion, version, users, managers),
            .groupPubKey = "pub0",
            .keyId = "key1",
            .keyVersion = keyVersion
        };
        core::DataIntegrityObject dio;
        dio.creatorUserId = "alice";
        dio.creatorPubKey = author.getPublicKey().toBase58DER();
        dio.contextId = group.contextId;
        dio.resourceId = group.resourceId.value_or("");
        dio.timestamp = 1000;
        dio.randomId = "rnd";
        dio.bridgeIdentity = core::BridgeIdentity{.url = "https://bridge.test", .pubKey = std::nullopt, .instanceId = std::nullopt};

        GroupDataToEncryptV5 toEncrypt{
            .publicMeta = core::Buffer::from(std::string("pub")),
            .privateMeta = core::Buffer::from(std::string("priv")),
            .internalMeta = core::ModuleInternalMetaV5{.secret = "s", .resourceId = dio.resourceId, .randomId = dio.randomId},
            .dio = dio,
            .groupPrivKey = "placeholder",
            .membership = membership
        };
        server::GroupDataEntry entry;
        entry.keyId = "key1";
        entry.data = authorMapper.encrypt(toEncrypt, privmx::crypto::Crypto::randomBytes(32));
        group.data.push_back(entry);

        server::GroupHistoryEntryInfo hist;
        hist.keyId = "key1";
        hist.groupPubKey = "pub0";
        hist.created = 1000;
        hist.author = "alice";
        group.history.push_back(hist);
        return group;
    }
};

TEST_F(GroupRosterTag, AnHonestRosterVerifies) {
    auto group = serve({"bob", "carol"}, {"alice"}, 4, 2, encKey);
    GroupDataSchemaMapper verifier(PrivateKey::generateRandom(), core::Connection());
    EXPECT_NO_THROW(verifier.assertDataIntegrity(group));
    EXPECT_NO_THROW(verifier.assertRosterIsAttested(group, key(encKey)));
}

TEST_F(GroupRosterTag, RosterOrderDoesNotMatter) {
    // The tag sorts before hashing, or two honest clients listing the same members differently would disagree.
    auto group = serve({"bob", "carol"}, {"alice"}, 4, 2, encKey);
    std::swap(group.users[0], group.users[1]);
    GroupDataSchemaMapper verifier(PrivateKey::generateRandom(), core::Connection());
    EXPECT_NO_THROW(verifier.assertRosterIsAttested(group, key(encKey)));
}

TEST_F(GroupRosterTag, SECURITY_AnInventedMemberIsRejected) {
    // The whole point: a bridge that adds a name nobody attested to.
    auto group = serve({"bob", "carol"}, {"alice"}, 4, 2, encKey);
    group.users.push_back("mallory");
    GroupDataSchemaMapper verifier(PrivateKey::generateRandom(), core::Connection());
    EXPECT_THROW(verifier.assertRosterIsAttested(group, key(encKey)), GroupMembershipMismatchException);
}

TEST_F(GroupRosterTag, SECURITY_APromotionToManagerIsRejected) {
    // Moving a name between the two lists changes the roster, so it changes the tag.
    auto group = serve({"bob", "carol"}, {"alice"}, 4, 2, encKey);
    group.users = {"carol"};
    group.managers = {"alice", "bob"};
    GroupDataSchemaMapper verifier(PrivateKey::generateRandom(), core::Connection());
    EXPECT_THROW(verifier.assertRosterIsAttested(group, key(encKey)), GroupMembershipMismatchException);
}

TEST_F(GroupRosterTag, SECURITY_ADroppedMemberIsRejected) {
    auto group = serve({"bob", "carol"}, {"alice"}, 4, 2, encKey);
    group.users = {"bob"};
    GroupDataSchemaMapper verifier(PrivateKey::generateRandom(), core::Connection());
    EXPECT_THROW(verifier.assertRosterIsAttested(group, key(encKey)), GroupMembershipMismatchException);
}

TEST_F(GroupRosterTag, SECURITY_ATagFromAnotherGroupIsRejected) {
    // No group id inside the payload — the key is what binds a tag to its group, so this is what proves it does.
    auto group = serve({"bob", "carol"}, {"alice"}, 4, 2, encKey);
    GroupDataSchemaMapper verifier(PrivateKey::generateRandom(), core::Connection());
    EXPECT_THROW(
        verifier.assertRosterIsAttested(group, key(privmx::crypto::Crypto::randomBytes(32))),
        GroupMembershipMismatchException
    );
}

TEST_F(GroupRosterTag, SECURITY_AVersionEchoedBackDifferentlyIsRejected) {
    // The version is inside the tag, so the bridge cannot relabel a roster as a different point in time.
    auto group = serve({"bob", "carol"}, {"alice"}, 4, 2, encKey);
    group.version = 5;
    GroupDataSchemaMapper verifier(PrivateKey::generateRandom(), core::Connection());
    EXPECT_THROW(verifier.assertRosterIsAttested(group, key(encKey)), GroupMembershipMismatchException);
}

TEST_F(GroupRosterTag, SECURITY_AnEpochEchoedBackDifferentlyIsRejected) {
    auto group = serve({"bob", "carol"}, {"alice"}, 4, 2, encKey);
    group.keyVersion = 3;
    GroupDataSchemaMapper verifier(PrivateKey::generateRandom(), core::Connection());
    EXPECT_THROW(verifier.assertRosterIsAttested(group, key(encKey)), GroupDataIntegrityException);
}

TEST_F(GroupRosterTag, SECURITY_AnOlderCorrectlyTaggedRosterIsRejected) {
    // A tag stays valid forever, so replaying a genuine past state is the one lie it cannot catch on its own.
    // The version pin is what refuses it.
    GroupDataSchemaMapper verifier(PrivateKey::generateRandom(), core::Connection());
    auto current = serve({"bob", "carol"}, {"alice"}, 4, 2, encKey);
    ASSERT_NO_THROW(verifier.assertDataIntegrity(current));

    auto rolledBack = serve({"bob", "carol", "mallory"}, {"alice"}, 3, 2, encKey);
    EXPECT_THROW(verifier.assertDataIntegrity(rolledBack), GroupHistoryForkException);
}

TEST_F(GroupRosterTag, ANonMemberCannotCheckTheTagAndIsNotToldOtherwise) {
    // No key recovered means the caller is not a member here. There is nothing to verify against, and pretending
    // otherwise would turn "I cannot check" into "I checked and it was fine".
    auto group = serve({"bob", "carol"}, {"alice"}, 4, 2, encKey);
    group.users.push_back("mallory");
    core::DecryptedEncKey noKey;
    noKey.statusCode = 1;
    GroupDataSchemaMapper verifier(PrivateKey::generateRandom(), core::Connection());
    EXPECT_NO_THROW(verifier.assertRosterIsAttested(group, noKey));
}
