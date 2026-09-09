/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

/**
 * The two attestations a group carries, one per plane.
 *
 * `rosterTag` is `HMAC(content key of the epoch, epoch | roster)`, committed by whoever changed the membership.
 * `metaTag` is `HMAC(content key of its epoch, "meta" | epoch | metaVersion)`, committed by whoever last called
 * `updateGroup`.
 *
 * The split is the point. The roster tag deliberately does **not** commit the metadata version: that counter is
 * guarded by `groupUpdate`'s CAS, not by anything a tree operation holds, so committing it left a membership
 * change stranded at a version it never landed at whenever an update interleaved. What each plane commits is
 * exactly what its own preconditions guard.
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

    /**
     * A group as the bridge would serve it: one roster head and one metadata entry, both through the real
     * encrypt path.
     *
     * `metaKeyVersion` defaults to the group's epoch. Passing a lower one is the normal case after a rotation
     * that no update followed — the metadata entry stays where it was written.
     */
    server::GroupInfo serve(
        const std::vector<std::string>& users,
        const std::vector<std::string>& managers,
        int64_t rosterVersion,
        int64_t keyVersion,
        const std::string& tagKey,
        int64_t metaVersion = 1,
        std::optional<int64_t> metaKeyVersion = std::nullopt
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
        group.version = metaVersion;
        group.keyVersion = keyVersion;
        const int64_t metaEpoch = metaKeyVersion.value_or(keyVersion);

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

        GroupMetaToEncryptV5 metaToEncrypt{
            .publicMeta = core::Buffer::from(std::string("pub")),
            .privateMeta = core::Buffer::from(std::string("priv")),
            .internalMeta = core::ModuleInternalMetaV5{.secret = "s", .resourceId = "res1", .randomId = "rnd2"},
            .dio = dioFor(group, "alice", "rnd2"),
            .meta =
                dynamic::MetaBlock{
                    .metaTag = GroupDataSchemaMapper::metaTag(tagKey, metaEpoch, metaVersion),
                    .keyId = "metaKey1",
                    .keyVersion = metaEpoch,
                    .metaVersion = metaVersion
                }
        };
        group.meta = server::GroupMetaEntry{
            .version = metaVersion,
            .keyId = "metaKey1",
            .keyVersion = metaEpoch,
            .data = authorMapper.encryptMeta(metaToEncrypt, privmx::crypto::Crypto::randomBytes(32)),
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

// ─────────────────────────────────────────────────────────────────────────────
// the roster plane
// ─────────────────────────────────────────────────────────────────────────────

TEST_F(GroupRosterTag, AnHonestRosterVerifies) {
    auto group = serve({"bob", "carol"}, {"alice"}, 4, 2, encKey);
    GroupDataSchemaMapper verifier(PrivateKey::generateRandom(), core::Connection());
    EXPECT_NO_THROW(verifier.assertDataIntegrity(group));
    EXPECT_NO_THROW(verifier.assertRosterIsAttested(group, key(encKey)));
}

TEST_F(GroupRosterTag, ARosterServedUnderAnotherVersionIsRefused) {
    // Within an epoch the roster only grows, so every earlier roster carries a genuine, still-valid tag. A
    // bridge pairing the current `rosterVersion` with one of them would conceal whoever was added in between,
    // and the monotone pin cannot see it — the counter it checks is not going down. Binding the counter into
    // the preimage is what makes the pair checkable.
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
    // This is the fix, stated as a test. The roster plane does not commit the metadata counter, so moving that
    // counter cannot invalidate a membership change — which is exactly what used to brick a group when an
    // `updateGroup` interleaved between a removal's read and its write.
    auto group = serve({"bob", "carol"}, {"alice"}, 4, 2, encKey);
    group.version = 99;
    GroupDataSchemaMapper verifier(PrivateKey::generateRandom(), core::Connection());
    EXPECT_NO_THROW(verifier.assertRosterIsAttested(group, key(encKey)));
}

TEST_F(GroupRosterTag, SECURITY_AnOlderCorrectlyTaggedRosterIsRejected) {
    // A tag stays valid forever, so replaying a genuine past state is the one lie it cannot catch on its own.
    // The roster version pin is what refuses it.
    GroupDataSchemaMapper verifier(PrivateKey::generateRandom(), core::Connection());
    auto current = serve({"bob", "carol"}, {"alice"}, 4, 2, encKey);
    ASSERT_NO_THROW(verifier.assertDataIntegrity(current));

    auto rolledBack = serve({"bob", "carol", "mallory"}, {"alice"}, 3, 2, encKey);
    EXPECT_THROW(verifier.assertDataIntegrity(rolledBack), GroupHistoryForkException);
}

TEST_F(GroupRosterTag, SECURITY_AnOlderMetadataVersionIsRejectedIndependently) {
    // Two pins, because the counters move independently: a roster that has not moved must not excuse a metadata
    // entry that went backwards.
    GroupDataSchemaMapper verifier(PrivateKey::generateRandom(), core::Connection());
    auto current = serve({"bob", "carol"}, {"alice"}, 4, 2, encKey, 9);
    ASSERT_NO_THROW(verifier.assertDataIntegrity(current));

    auto rolledBack = serve({"bob", "carol"}, {"alice"}, 4, 2, encKey, 8);
    EXPECT_THROW(verifier.assertDataIntegrity(rolledBack), GroupHistoryForkException);
}

TEST_F(GroupRosterTag, SECURITY_AMissingRosterKeyIsAFailureNotAPass) {
    // It used to return quietly: no key meant "not a member here, nothing to check against". Since the planes
    // split that inference is wrong — a member removed at epoch N may still hold the key to a metadata entry
    // written at epoch N while having no way to reach the current epoch's roster key. Passing would hand them a
    // group reported as verified.
    auto group = serve({"bob", "carol"}, {"alice"}, 4, 2, encKey);
    group.users.push_back("mallory");
    core::DecryptedEncKey noKey;
    noKey.statusCode = 1;
    GroupDataSchemaMapper verifier(PrivateKey::generateRandom(), core::Connection());
    EXPECT_THROW(verifier.assertRosterIsAttested(group, noKey), GroupMembershipMismatchException);
}

// ─────────────────────────────────────────────────────────────────────────────
// the metadata plane
// ─────────────────────────────────────────────────────────────────────────────

TEST_F(GroupRosterTag, AnHonestMetadataEntryVerifies) {
    auto group = serve({"bob", "carol"}, {"alice"}, 4, 2, encKey, 7);
    GroupDataSchemaMapper verifier(PrivateKey::generateRandom(), core::Connection());
    EXPECT_NO_THROW(verifier.assertMetaIsAttested(group, key(encKey)));
}

TEST_F(GroupRosterTag, AMetadataEntryAtAnOlderEpochVerifies) {
    // The normal state after a removal: the entry stays at the epoch it was written under, and the reader
    // descends the Epoch Ladder to its key rather than having every removal rewrite it.
    auto group = serve({"bob", "carol"}, {"alice"}, 4, 5, encKey, 7, 2);
    GroupDataSchemaMapper verifier(PrivateKey::generateRandom(), core::Connection());
    EXPECT_NO_THROW(verifier.assertMetaIsAttested(group, key(encKey)));
}

TEST_F(GroupRosterTag, SECURITY_AMetadataEntryFromAnEpochThatDoesNotExistYetIsRejected) {
    // Lagging the group's epoch is legitimate; leading it names a key nobody could have held.
    auto group = serve({"bob", "carol"}, {"alice"}, 4, 2, encKey, 7, 9);
    GroupDataSchemaMapper verifier(PrivateKey::generateRandom(), core::Connection());
    EXPECT_THROW(verifier.assertMetaIsAttested(group, key(encKey)), GroupMembershipMismatchException);
}

TEST_F(GroupRosterTag, SECURITY_AMetaVersionEchoedBackDifferentlyIsRejected) {
    auto group = serve({"bob", "carol"}, {"alice"}, 4, 2, encKey, 7);
    group.version = 8;
    group.meta.version = 8;
    GroupDataSchemaMapper verifier(PrivateKey::generateRandom(), core::Connection());
    EXPECT_THROW(verifier.assertMetaIsAttested(group, key(encKey)), GroupMembershipMismatchException);
}

TEST_F(GroupRosterTag, SECURITY_AStaleMetadataEntryUnderARisingCounterIsRejected) {
    // The attack the tag exists to stop: serve version 7's entry while claiming the group is at version 9. A
    // monotone pin cannot see it — the counter it checks is going up — so the commitment has to be in the entry.
    auto group = serve({"bob", "carol"}, {"alice"}, 4, 2, encKey, 7);
    group.version = 9;
    GroupDataSchemaMapper verifier(PrivateKey::generateRandom(), core::Connection());
    EXPECT_THROW(verifier.assertMetaIsAttested(group, key(encKey)), GroupMembershipMismatchException);
}

TEST_F(GroupRosterTag, SECURITY_AMetadataEntryNamingAnotherKeyIsRejected) {
    auto group = serve({"bob", "carol"}, {"alice"}, 4, 2, encKey, 7);
    group.meta.keyId = "someoneElsesKey";
    GroupDataSchemaMapper verifier(PrivateKey::generateRandom(), core::Connection());
    EXPECT_THROW(verifier.assertMetaIsAttested(group, key(encKey)), GroupMembershipMismatchException);
}

TEST_F(GroupRosterTag, SECURITY_AReauthoredMetadataEnvelopeIsRejected) {
    // Why the tag is key-bound rather than merely signed: `publicMeta` is signed but not encrypted, so a bridge
    // holding a keypair of its own could re-author the whole envelope — DIO included — and forge it. Only the
    // content key, which the bridge never holds, refuses that.
    auto group = serve({"bob", "carol"}, {"alice"}, 4, 2, encKey, 7);
    const std::string bridgeKey = privmx::crypto::Crypto::randomBytes(32);
    auto forged = serve({"bob", "carol"}, {"alice"}, 4, 2, bridgeKey, 7);
    group.meta = forged.meta;
    GroupDataSchemaMapper verifier(PrivateKey::generateRandom(), core::Connection());
    EXPECT_THROW(verifier.assertMetaIsAttested(group, key(encKey)), GroupMembershipMismatchException);
}

TEST_F(GroupRosterTag, SECURITY_AMissingMetadataKeyIsAFailureNotAPass) {
    auto group = serve({"bob", "carol"}, {"alice"}, 4, 2, encKey, 7);
    core::DecryptedEncKey noKey;
    noKey.statusCode = 1;
    GroupDataSchemaMapper verifier(PrivateKey::generateRandom(), core::Connection());
    EXPECT_THROW(verifier.assertMetaIsAttested(group, noKey), GroupMembershipMismatchException);
}

TEST_F(GroupRosterTag, AMetadataEntryWrittenByASinceRemovedMemberStillVerifies) {
    // Pinned deliberately, because it is what rules out the cheap fix for the forgery gap below. A former member
    // is the *expected* author of an entry written before they left — the metadata plane is not rewritten on
    // removal — so refusing an author who is off the current roster would make the group unreadable for everyone
    // the moment its metadata writer is removed. Same failure shape as `updateGroup_by_a_different_manager`.
    auto group = serve({"bob", "carol"}, {"alice"}, 4, 2, encKey, 7);
    group.meta.author = "dave"; // wrote the metadata at epoch 2, removed since
    GroupDataSchemaMapper verifier(PrivateKey::generateRandom(), core::Connection());
    EXPECT_NO_THROW(verifier.assertMetaIsAttested(group, key(encKey)));
}

// ─────────────────────────────────────────────────────────────────────────────
// key separation
// ─────────────────────────────────────────────────────────────────────────────

TEST_F(GroupRosterTag, SECURITY_EachTagPurposeGetsItsOwnKey) {
    // The content key is also the AES key for the metadata fields and the HMAC key behind three tags. The
    // preimages happen to be prefix-disjoint, but that is a convention someone has to keep re-deriving; the
    // subkeys make it structural. Nothing below may equal anything else below.
    const std::string k = privmx::crypto::Crypto::randomBytes(32);
    const std::string roster = GroupDataSchemaMapper::tagSubkey(k, "roster-tag");
    const std::string meta = GroupDataSchemaMapper::tagSubkey(k, "meta-tag");
    const std::string confirm = GroupDataSchemaMapper::tagSubkey(k, "confirm-tag");
    EXPECT_EQ(roster.size(), 32u);
    EXPECT_NE(roster, k);
    EXPECT_NE(meta, k);
    EXPECT_NE(confirm, k);
    EXPECT_NE(roster, meta);
    EXPECT_NE(roster, confirm);
    EXPECT_NE(meta, confirm);
}

TEST_F(GroupRosterTag, SECURITY_ARosterTagCannotBeReplayedAsAMetadataTag) {
    // Two tags over the same numbers under the same content key. Even if a future preimage change made the
    // payloads coincide, the subkeys keep the tags apart.
    const std::string k = privmx::crypto::Crypto::randomBytes(32);
    EXPECT_NE(GroupDataSchemaMapper::rosterTag(k, 2, 7, {}, {}), GroupDataSchemaMapper::metaTag(k, 2, 7));
}
