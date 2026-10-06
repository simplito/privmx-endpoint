/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

/**
 * The three attestations a group carries, one per plane.
 *
 * `rosterTag` is `HMAC(content key of the epoch, epoch | roster)`, committed by whoever changed the membership.
 * `publicMetaTag` and `privateMetaTag` are `HMAC(content key of its epoch, "publicMeta" or "privateMeta" |
 * epoch | metaVersion)`, each committed by whoever last wrote that plane.
 *
 * The split is the point. The roster tag deliberately does **not** commit either metadata counter: those are
 * guarded by their own CAS on the bridge, not by anything a tree operation holds, so committing them left a
 * membership change stranded at a version it never landed at whenever an update interleaved. And the two
 * metadata planes do not commit each other's, which is what lets them be written independently. What each plane
 * commits is exactly what its own preconditions guard.
 *
 * The domain prefixes matter because both metadata planes carry the same block shape: without them an entry
 * could be served in the other plane's position at the same (epoch, version).
 *
 * What they give: a bridge cannot invent a member or forge metadata, because it never holds the key. What they
 * deliberately do not give: who made the change, or whether they were a manager rather than an ordinary member —
 * holding the key is the authority.
 *
 * These tests exist because each verification is one HMAC. Cheap is only good if it still refuses everything it
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

    // Each entry is its own signed object, so each carries its own `randomId` — sharing one would make a
    // reader's replay check see the group's two entries as one entry served twice.
    core::DataIntegrityObject dioFor(
        const server::GroupInfo& group,
        const std::string& authorId,
        const std::string& randomId
    ) {
        core::DataIntegrityObject dio;
        dio.creatorUserId = authorId;
        dio.creatorPubKey = author.getPublicKey().toBase58DER();
        dio.contextId = group.contextId;
        dio.resourceId = group.resourceId.value_or("");
        dio.timestamp = 1000;
        dio.randomId = randomId;
        dio.bridgeIdentity =
            core::BridgeIdentity{.url = "https://bridge.test", .pubKey = std::nullopt, .instanceId = std::nullopt};
        return dio;
    }

    // A group as the bridge would serve it, all three entries through the real encrypt path. Each plane's key
    // epoch defaults to the group's; a lower one is normal after a rotation no write to *that* plane followed.
    server::GroupInfo serve(
        const std::vector<std::string>& users,
        const std::vector<std::string>& managers,
        int64_t rosterVersion,
        int64_t keyVersion,
        const std::string& tagKey,
        int64_t publicMetaVersion = 1,
        std::optional<int64_t> publicMetaKeyVersion = std::nullopt,
        int64_t privateMetaVersion = 1,
        std::optional<int64_t> privateMetaKeyVersion = std::nullopt
    ) {
        GroupDataSchemaMapper authorMapper(author, core::Connection());
        server::GroupInfo group;
        group.id = "grp";
        group.contextId = "ctx1";
        group.resourceId = "res1";
        group.groupPubKey = "pub0";
        group.users = users;
        group.managers = managers;
        group.rosterVersion = rosterVersion;
        group.publicMetaVersion = publicMetaVersion;
        group.privateMetaVersion = privateMetaVersion;
        group.keyVersion = keyVersion;
        const int64_t publicMetaEpoch = publicMetaKeyVersion.value_or(keyVersion);
        const int64_t privateMetaEpoch = privateMetaKeyVersion.value_or(keyVersion);

        GroupRosterToEncryptV5 rosterToEncrypt{
            .internalMeta =
                core::ModuleInternalMetaV5{.secret = "s", .resourceId = "res1", .randomId = "rnd"},
            .dio = dioFor(group, "alice", "rnd"),
            .membership =
                dynamic::MembershipBlock{
                    .rosterTag =
                        GroupDataSchemaMapper::rosterTag(tagKey, keyVersion, rosterVersion, users, managers),
                    .groupPubKey = "pub0",
                    .keyId = "key1",
                    .keyVersion = keyVersion,
                    .rosterVersion = rosterVersion
                }
        };
        server::GroupDataEntry entry;
        entry.keyId = "key1";
        entry.data = authorMapper.encryptRoster(rosterToEncrypt, privmx::crypto::Crypto::randomBytes(32));
        group.data.push_back(entry);

        GroupPublicMetaToEncryptV5 publicMetaToEncrypt{
            .publicMeta = core::Buffer::from(std::string("pub")),
            .dio = dioFor(group, "alice", "rnd2"),
            .meta =
                dynamic::MetaBlock{
                    .metaTag = GroupDataSchemaMapper::publicMetaTag(tagKey, publicMetaEpoch, publicMetaVersion),
                    .keyId = "metaKey1",
                    .keyVersion = publicMetaEpoch,
                    .metaVersion = publicMetaVersion
                }
        };
        group.publicMeta = server::GroupMetaEntry{
            .version = publicMetaVersion,
            .keyId = "metaKey1",
            .keyVersion = publicMetaEpoch,
            .data = authorMapper.encryptPublicMeta(publicMetaToEncrypt),
            .created = 1000,
            .author = "alice"
        };

        GroupPrivateMetaToEncryptV5 privateMetaToEncrypt{
            .privateMeta = core::Buffer::from(std::string("priv")),
            .dio = dioFor(group, "alice", "rnd3"),
            .meta =
                dynamic::MetaBlock{
                    .metaTag = GroupDataSchemaMapper::privateMetaTag(tagKey, privateMetaEpoch, privateMetaVersion),
                    .keyId = "metaKey1",
                    .keyVersion = privateMetaEpoch,
                    .metaVersion = privateMetaVersion
                }
        };
        group.privateMeta = server::GroupMetaEntry{
            .version = privateMetaVersion,
            .keyId = "metaKey1",
            .keyVersion = privateMetaEpoch,
            .data = authorMapper.encryptPrivateMeta(privateMetaToEncrypt, privmx::crypto::Crypto::randomBytes(32)),
            .created = 1000,
            .author = "alice"
        };

        server::GroupHistoryEntryInfo hist;
        hist.keyId = "key1";
        hist.groupPubKey = "pub0";
        hist.created = 1000;
        hist.author = "alice";
        group.history.push_back(hist);
        return group;
    }
};

// -- the roster plane --

TEST_F(GroupRosterTag, AnHonestRosterVerifies) {
    auto group = serve({"bob", "carol"}, {"alice"}, 4, 2, encKey);
    GroupDataSchemaMapper verifier(PrivateKey::generateRandom(), core::Connection());
    EXPECT_NO_THROW(verifier.assertDataIntegrity(group));
    EXPECT_NO_THROW(verifier.assertRosterIsAttested(group, key(encKey)));
}

TEST_F(GroupRosterTag, ARosterServedUnderAnotherVersionIsRefused) {
    // Within an epoch the roster only grows, so every earlier roster still carries a valid tag. Pairing the
    // current `rosterVersion` with an earlier roster would hide whoever was added between, unseen by the pin.
    auto group = serve({"bob", "carol"}, {"alice"}, 4, 2, encKey);
    GroupDataSchemaMapper verifier(PrivateKey::generateRandom(), core::Connection());
    group.rosterVersion = 5;
    EXPECT_THROW(verifier.assertRosterIsAttested(group, key(encKey)), GroupMembershipMismatchException);
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

TEST_F(GroupRosterTag, SECURITY_AnEpochEchoedBackDifferentlyIsRejected) {
    // The epoch is what the roster tag commits now that the version is gone, so it carries the weight.
    auto group = serve({"bob", "carol"}, {"alice"}, 4, 2, encKey);
    group.keyVersion = 3;
    GroupDataSchemaMapper verifier(PrivateKey::generateRandom(), core::Connection());
    EXPECT_THROW(verifier.assertRosterIsAttested(group, key(encKey)), GroupDataIntegrityException);
}

TEST_F(GroupRosterTag, AMetadataVersionEchoedBackDifferentlyLeavesTheRosterTagAlone) {
    // The roster plane commits neither metadata counter, so moving them cannot invalidate a membership change —
    // which is what used to brick a group when a metadata write interleaved with a removal's read and write.
    auto group = serve({"bob", "carol"}, {"alice"}, 4, 2, encKey);
    group.publicMetaVersion = 99;
    group.privateMetaVersion = 99;
    GroupDataSchemaMapper verifier(PrivateKey::generateRandom(), core::Connection());
    EXPECT_NO_THROW(verifier.assertRosterIsAttested(group, key(encKey)));
}

TEST_F(GroupRosterTag, SECURITY_AnOlderCorrectlyTaggedRosterIsRejected) {
    // A tag stays valid forever, so replaying a genuine past state is the one lie it cannot catch on its own.
    // The roster version pin is what refuses it.
    GroupDataSchemaMapper verifier(PrivateKey::generateRandom(), core::Connection());
    auto current = serve({"bob", "carol"}, {"alice"}, 4, 2, encKey);
    ASSERT_NO_THROW(verifier.assertDataIntegrity(current));
    ASSERT_NO_THROW(verifier.assertRosterIsAttested(current, key(encKey)));

    auto rolledBack = serve({"bob", "carol", "mallory"}, {"alice"}, 3, 2, encKey);
    EXPECT_THROW(verifier.assertDataIntegrity(rolledBack), GroupHistoryForkException);
}

TEST_F(GroupRosterTag, SECURITY_AnOlderPublicMetaVersionIsRejectedIndependently) {
    // Three pins, because the counters move independently: neither an unmoved roster nor an unmoved private
    // plane may excuse a public-metadata entry that went backwards.
    GroupDataSchemaMapper verifier(PrivateKey::generateRandom(), core::Connection());
    auto current = serve({"bob", "carol"}, {"alice"}, 4, 2, encKey, 9, std::nullopt, 3);
    ASSERT_NO_THROW(verifier.assertDataIntegrity(current));
    ASSERT_NO_THROW(verifier.assertPublicMetaIsAttested(current, key(encKey)));

    auto rolledBack = serve({"bob", "carol"}, {"alice"}, 4, 2, encKey, 8, std::nullopt, 3);
    EXPECT_THROW(verifier.assertDataIntegrity(rolledBack), GroupHistoryForkException);
}

TEST_F(GroupRosterTag, SECURITY_AnOlderPrivateMetaVersionIsRejectedIndependently) {
    GroupDataSchemaMapper verifier(PrivateKey::generateRandom(), core::Connection());
    auto current = serve({"bob", "carol"}, {"alice"}, 4, 2, encKey, 3, std::nullopt, 9);
    ASSERT_NO_THROW(verifier.assertDataIntegrity(current));
    ASSERT_NO_THROW(verifier.assertPrivateMetaIsAttested(current, key(encKey)));

    auto rolledBack = serve({"bob", "carol"}, {"alice"}, 4, 2, encKey, 3, std::nullopt, 8);
    EXPECT_THROW(verifier.assertDataIntegrity(rolledBack), GroupHistoryForkException);
}

TEST_F(GroupRosterTag, AnUnattestedResponseRaisesNoPin) {
    // The invariant the fix rests on: an integrity pass proves no counter, so it pins none. Only the tag that
    // binds a counter to signed content may raise that counter's pin.
    GroupDataSchemaMapper verifier(PrivateKey::generateRandom(), core::Connection());
    ASSERT_NO_THROW(verifier.assertDataIntegrity(serve({"bob", "carol"}, {"alice"}, 9, 2, encKey)));
    EXPECT_NO_THROW(verifier.assertDataIntegrity(serve({"bob", "carol"}, {"alice"}, 4, 2, encKey)));
}

TEST_F(GroupRosterTag, SECURITY_AnInflatedRosterVersionLeavesThePinAlone) {
    // A keyless bridge raising only the served counter used to pin 5 before the tag check refused the answer,
    // and every honest version-4 answer afterwards read as a fork — the group bricked until reconnect.
    GroupDataSchemaMapper verifier(PrivateKey::generateRandom(), core::Connection());
    auto inflated = serve({"bob", "carol"}, {"alice"}, 4, 2, encKey);
    inflated.rosterVersion = 5;
    ASSERT_NO_THROW(verifier.assertDataIntegrity(inflated));
    EXPECT_THROW(verifier.assertRosterIsAttested(inflated, key(encKey)), GroupMembershipMismatchException);

    auto genuine = serve({"bob", "carol"}, {"alice"}, 4, 2, encKey);
    EXPECT_NO_THROW(verifier.assertDataIntegrity(genuine));
    EXPECT_NO_THROW(verifier.assertRosterIsAttested(genuine, key(encKey)));
}

TEST_F(GroupRosterTag, SECURITY_AnInflatedPublicMetaVersionLeavesThePinAlone) {
    // The same lie on the metadata plane, refused the same way: `publicMetaVersion` is the bridge's word until
    // `metaVersion` inside the signed entry agrees with it.
    GroupDataSchemaMapper verifier(PrivateKey::generateRandom(), core::Connection());
    auto inflated = serve({"bob", "carol"}, {"alice"}, 4, 2, encKey, 7);
    inflated.publicMetaVersion = 9;
    ASSERT_NO_THROW(verifier.assertDataIntegrity(inflated));
    EXPECT_THROW(verifier.assertPublicMetaIsAttested(inflated, key(encKey)), GroupMembershipMismatchException);

    auto genuine = serve({"bob", "carol"}, {"alice"}, 4, 2, encKey, 7);
    EXPECT_NO_THROW(verifier.assertDataIntegrity(genuine));
    EXPECT_NO_THROW(verifier.assertPublicMetaIsAttested(genuine, key(encKey)));
}

TEST_F(GroupRosterTag, SECURITY_AFailedMetadataPlaneDoesNotLoseTheRosterPin) {
    // The planes pin apart, so breaking a metadata entry cannot cost the roster its pin — otherwise a bridge
    // would buy itself free roster rollbacks by corrupting a plane it does not even need to read.
    GroupDataSchemaMapper verifier(PrivateKey::generateRandom(), core::Connection());
    auto group = serve({"bob", "carol"}, {"alice"}, 4, 2, encKey, 7, std::nullopt, 7);
    ASSERT_NO_THROW(verifier.assertRosterIsAttested(group, key(encKey)));
    group.publicMeta = group.privateMeta;
    EXPECT_THROW(verifier.assertPublicMetaIsAttested(group, key(encKey)), GroupMembershipMismatchException);

    auto rolledBack = serve({"bob", "carol", "mallory"}, {"alice"}, 3, 2, encKey, 7, std::nullopt, 7);
    EXPECT_THROW(verifier.assertDataIntegrity(rolledBack), GroupHistoryForkException);
}

TEST_F(GroupRosterTag, APinDoesNotMoveBackwards) {
    // Two reads in flight at once may attest out of order, and both are genuine. The later, older one must not
    // lower the pin, or the next sequential read reopens the window the pin exists to close.
    GroupDataSchemaMapper verifier(PrivateKey::generateRandom(), core::Connection());
    auto newer = serve({"bob", "carol"}, {"alice"}, 9, 2, encKey);
    auto older = serve({"bob"}, {"alice"}, 4, 2, encKey);
    ASSERT_NO_THROW(verifier.assertRosterIsAttested(newer, key(encKey)));
    ASSERT_NO_THROW(verifier.assertRosterIsAttested(older, key(encKey)));

    EXPECT_THROW(verifier.assertDataIntegrity(older), GroupHistoryForkException);
}

TEST_F(GroupRosterTag, DroppingAPinForgetsIt) {
    GroupDataSchemaMapper verifier(PrivateKey::generateRandom(), core::Connection());
    auto older = serve({"bob"}, {"alice"}, 4, 2, encKey);
    ASSERT_NO_THROW(verifier.assertRosterIsAttested(serve({"bob", "carol"}, {"alice"}, 9, 2, encKey), key(encKey)));
    ASSERT_THROW(verifier.assertDataIntegrity(older), GroupHistoryForkException);

    verifier.dropVersionPin("grp");
    EXPECT_NO_THROW(verifier.assertDataIntegrity(older));
}

TEST_F(GroupRosterTag, DroppingAllPinsForgetsThem) {
    GroupDataSchemaMapper verifier(PrivateKey::generateRandom(), core::Connection());
    auto older = serve({"bob"}, {"alice"}, 4, 2, encKey);
    ASSERT_NO_THROW(verifier.assertRosterIsAttested(serve({"bob", "carol"}, {"alice"}, 9, 2, encKey), key(encKey)));
    ASSERT_THROW(verifier.assertDataIntegrity(older), GroupHistoryForkException);

    verifier.dropAllVersionPins();
    EXPECT_NO_THROW(verifier.assertDataIntegrity(older));
}

TEST_F(GroupRosterTag, AMovedPrivateMetaVersionLeavesThePublicPlaneAlone) {
    // The metadata split, stated as a test: the two planes commit their own counters and nothing else, so a
    // write to one cannot invalidate the other's entry. This is what lets the two race and both win.
    auto group = serve({"bob", "carol"}, {"alice"}, 4, 2, encKey, 7, std::nullopt, 11);
    GroupDataSchemaMapper verifier(PrivateKey::generateRandom(), core::Connection());
    EXPECT_NO_THROW(verifier.assertPublicMetaIsAttested(group, key(encKey)));
    EXPECT_NO_THROW(verifier.assertPrivateMetaIsAttested(group, key(encKey)));
}

TEST_F(GroupRosterTag, SECURITY_AMissingRosterKeyIsAFailureNotAPass) {
    // It used to return quietly, reading a missing key as "not a member, nothing to check". Since the split that
    // is wrong: a member removed at epoch N still holds that epoch's metadata key but cannot reach the roster one.
    auto group = serve({"bob", "carol"}, {"alice"}, 4, 2, encKey);
    group.users.push_back("mallory");
    core::DecryptedEncKey noKey;
    noKey.statusCode = 1;
    GroupDataSchemaMapper verifier(PrivateKey::generateRandom(), core::Connection());
    EXPECT_THROW(verifier.assertRosterIsAttested(group, noKey), GroupMembershipMismatchException);
}

// -- the metadata plane --

TEST_F(GroupRosterTag, PublicAndPrivateMetaTagsAreDomainSeparated) {
    // Two lines, and the whole reason the prefixes exist: both planes carry the same `MetaBlock` shape, so at
    // the same (epoch, version) an undomained tag would verify in either position.
    EXPECT_NE(
        GroupDataSchemaMapper::publicMetaTag(encKey, 2, 7), GroupDataSchemaMapper::privateMetaTag(encKey, 2, 7)
    );
}

TEST_F(GroupRosterTag, AnHonestMetadataEntryVerifies) {
    auto group = serve({"bob", "carol"}, {"alice"}, 4, 2, encKey, 7, std::nullopt, 7);
    GroupDataSchemaMapper verifier(PrivateKey::generateRandom(), core::Connection());
    EXPECT_NO_THROW(verifier.assertPublicMetaIsAttested(group, key(encKey)));
    EXPECT_NO_THROW(verifier.assertPrivateMetaIsAttested(group, key(encKey)));
}

TEST_F(GroupRosterTag, AMetadataEntryAtAnOlderEpochVerifies) {
    // The normal state after a removal: the entry stays at the epoch it was written under, and the reader
    // descends the Epoch Ladder to its key rather than having every removal rewrite it.
    auto group = serve({"bob", "carol"}, {"alice"}, 4, 5, encKey, 7, 2, 7, 2);
    GroupDataSchemaMapper verifier(PrivateKey::generateRandom(), core::Connection());
    EXPECT_NO_THROW(verifier.assertPublicMetaIsAttested(group, key(encKey)));
    EXPECT_NO_THROW(verifier.assertPrivateMetaIsAttested(group, key(encKey)));
}

TEST_F(GroupRosterTag, PlanesAtDifferentEpochsBothVerify) {
    // Unreachable before the split, routine after: each plane stays at the epoch it was written under, and only
    // a write to that same plane brings it forward.
    auto group = serve({"bob", "carol"}, {"alice"}, 4, 3, encKey, 7, 1, 7, 3);
    GroupDataSchemaMapper verifier(PrivateKey::generateRandom(), core::Connection());
    EXPECT_NO_THROW(verifier.assertPublicMetaIsAttested(group, key(encKey)));
    EXPECT_NO_THROW(verifier.assertPrivateMetaIsAttested(group, key(encKey)));
}

TEST_F(GroupRosterTag, SECURITY_AMetadataEntryFromAnEpochThatDoesNotExistYetIsRejected) {
    // Lagging the group's epoch is legitimate; leading it names a key nobody could have held.
    auto group = serve({"bob", "carol"}, {"alice"}, 4, 2, encKey, 7, 9, 7, 9);
    GroupDataSchemaMapper verifier(PrivateKey::generateRandom(), core::Connection());
    EXPECT_THROW(verifier.assertPublicMetaIsAttested(group, key(encKey)), GroupMembershipMismatchException);
    EXPECT_THROW(verifier.assertPrivateMetaIsAttested(group, key(encKey)), GroupMembershipMismatchException);
}

TEST_F(GroupRosterTag, SECURITY_AMetaVersionEchoedBackDifferentlyIsRejected) {
    auto group = serve({"bob", "carol"}, {"alice"}, 4, 2, encKey, 7, std::nullopt, 7);
    group.publicMetaVersion = 8;
    group.publicMeta.version = 8;
    group.privateMetaVersion = 8;
    group.privateMeta.version = 8;
    GroupDataSchemaMapper verifier(PrivateKey::generateRandom(), core::Connection());
    EXPECT_THROW(verifier.assertPublicMetaIsAttested(group, key(encKey)), GroupMembershipMismatchException);
    EXPECT_THROW(verifier.assertPrivateMetaIsAttested(group, key(encKey)), GroupMembershipMismatchException);
}

TEST_F(GroupRosterTag, SECURITY_AStaleMetadataEntryUnderARisingCounterIsRejected) {
    // The attack the tag exists to stop: serve version 7's entry while claiming the plane is at version 9. A
    // monotone pin cannot see it — the counter it checks is going up — so the commitment has to be in the entry.
    auto group = serve({"bob", "carol"}, {"alice"}, 4, 2, encKey, 7, std::nullopt, 7);
    group.publicMetaVersion = 9;
    group.privateMetaVersion = 9;
    GroupDataSchemaMapper verifier(PrivateKey::generateRandom(), core::Connection());
    EXPECT_THROW(verifier.assertPublicMetaIsAttested(group, key(encKey)), GroupMembershipMismatchException);
    EXPECT_THROW(verifier.assertPrivateMetaIsAttested(group, key(encKey)), GroupMembershipMismatchException);
}

TEST_F(GroupRosterTag, SECURITY_AMetadataEntryNamingAnotherKeyIsRejected) {
    auto group = serve({"bob", "carol"}, {"alice"}, 4, 2, encKey, 7, std::nullopt, 7);
    group.publicMeta.keyId = "someoneElsesKey";
    group.privateMeta.keyId = "someoneElsesKey";
    GroupDataSchemaMapper verifier(PrivateKey::generateRandom(), core::Connection());
    EXPECT_THROW(verifier.assertPublicMetaIsAttested(group, key(encKey)), GroupMembershipMismatchException);
    EXPECT_THROW(verifier.assertPrivateMetaIsAttested(group, key(encKey)), GroupMembershipMismatchException);
}

TEST_F(GroupRosterTag, SECURITY_AReauthoredMetadataEnvelopeIsRejected) {
    // Why the tag is key-bound rather than merely signed: the public plane is not encrypted, so a bridge with
    // its own keypair could re-author the envelope, DIO included. Only the content key it never holds refuses.
    auto group = serve({"bob", "carol"}, {"alice"}, 4, 2, encKey, 7, std::nullopt, 7);
    const std::string bridgeKey = privmx::crypto::Crypto::randomBytes(32);
    auto forged = serve({"bob", "carol"}, {"alice"}, 4, 2, bridgeKey, 7, std::nullopt, 7);
    group.publicMeta = forged.publicMeta;
    group.privateMeta = forged.privateMeta;
    GroupDataSchemaMapper verifier(PrivateKey::generateRandom(), core::Connection());
    EXPECT_THROW(verifier.assertPublicMetaIsAttested(group, key(encKey)), GroupMembershipMismatchException);
    EXPECT_THROW(verifier.assertPrivateMetaIsAttested(group, key(encKey)), GroupMembershipMismatchException);
}

TEST_F(GroupRosterTag, SECURITY_APublicMetaEnvelopeServedAsThePrivateOneIsRejected) {
    // The substitution the domain prefixes exist to refuse, caught twice: deserialisation rejects it first, on
    // the missing `privateMeta` field, which is why the parse is wrapped — unwrapped it escapes as a JSON error.
    auto group = serve({"bob", "carol"}, {"alice"}, 4, 2, encKey, 7, std::nullopt, 7);
    group.privateMeta = group.publicMeta;
    GroupDataSchemaMapper verifier(PrivateKey::generateRandom(), core::Connection());
    EXPECT_THROW(verifier.assertPrivateMetaIsAttested(group, key(encKey)), GroupMembershipMismatchException);
}

TEST_F(GroupRosterTag, SECURITY_APrivateMetaEnvelopeServedAsThePublicOneIsRejected) {
    auto group = serve({"bob", "carol"}, {"alice"}, 4, 2, encKey, 7, std::nullopt, 7);
    group.publicMeta = group.privateMeta;
    GroupDataSchemaMapper verifier(PrivateKey::generateRandom(), core::Connection());
    EXPECT_THROW(verifier.assertPublicMetaIsAttested(group, key(encKey)), GroupMembershipMismatchException);
}

TEST_F(GroupRosterTag, SECURITY_AMissingMetadataKeyIsAFailureNotAPass) {
    auto group = serve({"bob", "carol"}, {"alice"}, 4, 2, encKey, 7, std::nullopt, 7);
    core::DecryptedEncKey noKey;
    noKey.statusCode = 1;
    GroupDataSchemaMapper verifier(PrivateKey::generateRandom(), core::Connection());
    EXPECT_THROW(verifier.assertPublicMetaIsAttested(group, noKey), GroupMembershipMismatchException);
    EXPECT_THROW(verifier.assertPrivateMetaIsAttested(group, noKey), GroupMembershipMismatchException);
}

TEST_F(GroupRosterTag, AMetadataEntryWrittenByASinceRemovedMemberStillVerifies) {
    // Pinned deliberately: it rules out the cheap fix for the forgery gap below. A former member is the *expected*
    // author of an entry written before they left — refusing off-roster authors would make the group unreadable.
    auto group = serve({"bob", "carol"}, {"alice"}, 4, 2, encKey, 7, std::nullopt, 7);
    group.publicMeta.author = "dave";  // wrote the metadata at epoch 2, removed since
    group.privateMeta.author = "dave";
    GroupDataSchemaMapper verifier(PrivateKey::generateRandom(), core::Connection());
    EXPECT_NO_THROW(verifier.assertPublicMetaIsAttested(group, key(encKey)));
    EXPECT_NO_THROW(verifier.assertPrivateMetaIsAttested(group, key(encKey)));
}

// -- key separation --

TEST_F(GroupRosterTag, SECURITY_EachTagPurposeGetsItsOwnKey) {
    // The content key is also the AES key for the metadata fields and the HMAC key behind three tags. Disjoint
    // preimages are a convention someone must keep re-deriving; the subkeys make the separation structural.
    const std::string k = privmx::crypto::Crypto::randomBytes(32);
    const std::string roster = GroupDataSchemaMapper::tagSubkey(k, "roster-tag");
    const std::string publicMeta = GroupDataSchemaMapper::tagSubkey(k, "publicMeta-tag");
    const std::string privateMeta = GroupDataSchemaMapper::tagSubkey(k, "privateMeta-tag");
    const std::string confirm = GroupDataSchemaMapper::tagSubkey(k, "confirm-tag");
    EXPECT_EQ(roster.size(), 32u);
    EXPECT_NE(roster, k);
    EXPECT_NE(publicMeta, k);
    EXPECT_NE(privateMeta, k);
    EXPECT_NE(confirm, k);
    EXPECT_NE(roster, publicMeta);
    EXPECT_NE(roster, privateMeta);
    EXPECT_NE(roster, confirm);
    EXPECT_NE(publicMeta, privateMeta);
    EXPECT_NE(publicMeta, confirm);
    EXPECT_NE(privateMeta, confirm);
}

TEST_F(GroupRosterTag, SECURITY_ARosterTagCannotBeReplayedAsAMetadataTag) {
    // Three tags over the same numbers under one content key. Even if a preimage change made the payloads
    // coincide, the subkeys keep them apart — the two metadata planes included, identical in shape otherwise.
    const std::string k = privmx::crypto::Crypto::randomBytes(32);
    EXPECT_NE(GroupDataSchemaMapper::rosterTag(k, 2, 7, {}, {}), GroupDataSchemaMapper::publicMetaTag(k, 2, 7));
    EXPECT_NE(GroupDataSchemaMapper::rosterTag(k, 2, 7, {}, {}), GroupDataSchemaMapper::privateMetaTag(k, 2, 7));
    EXPECT_NE(GroupDataSchemaMapper::publicMetaTag(k, 2, 7), GroupDataSchemaMapper::privateMetaTag(k, 2, 7));
}

TEST_F(GroupRosterTag, TheInternalMetaViewReadsTheRosterPlane) {
    // `prepareContainerUpdate` reads the container's `secret` from the roster head, now the only plane carrying
    // `internalMeta`. Reading it under the metadata shape threw, and the empty secret failed every roster write.
    GroupDataSchemaMapper mapper(author, core::Connection());
    server::GroupInfo group;
    group.contextId = "ctx1";
    group.resourceId = "res1";
    const core::ModuleInternalMetaV5 internalMeta{.secret = "s3cr3t", .resourceId = "res1", .randomId = "rnd"};

    const Poco::Dynamic::Var roster = mapper.encryptRoster(
        GroupRosterToEncryptV5{
            .internalMeta = internalMeta,
            .dio = dioFor(group, "alice", "rnd"),
            .membership =
                dynamic::MembershipBlock{
                    .rosterTag = "tag",
                    .groupPubKey = "pub0",
                    .keyId = "key1",
                    .keyVersion = 1,
                    .rosterVersion = 1
                }
        },
        encKey
    );
    EXPECT_EQ(mapper.decryptInternalMeta(roster, key(encKey)).secret, "s3cr3t");

    // And a metadata envelope yields nothing, because it carries no `internalMeta` to yield: the view's parse
    // finds the field absent rather than reading some other plane's identity.
    const Poco::Dynamic::Var publicMeta = mapper.encryptPublicMeta(
        GroupPublicMetaToEncryptV5{
            .publicMeta = core::Buffer::from(std::string("pub")),
            .dio = dioFor(group, "alice", "rnd2"),
            .meta = dynamic::MetaBlock{.metaTag = "tag", .keyId = "key1", .keyVersion = 1, .metaVersion = 1}
        }
    );
    EXPECT_EQ(mapper.decryptInternalMeta(publicMeta, key(encKey)).secret, "");
}
