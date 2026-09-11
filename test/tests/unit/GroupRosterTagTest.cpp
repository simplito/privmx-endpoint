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

    /**
     * A group as the bridge would serve it: one roster head and one entry per metadata plane, all three through
     * the real encrypt path.
     *
     * Each plane's key epoch defaults to the group's. Passing a lower one is the normal case after a rotation
     * that no write to *that* plane followed — an entry stays where it was written. The two planes take their
     * epochs separately, because they may legitimately sit at different ones.
     */
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
    // This is the fix, stated as a test. The roster plane does not commit either metadata counter, so moving
    // them cannot invalidate a membership change — which is exactly what used to brick a group when a metadata
    // write interleaved between a removal's read and its write.
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

    auto rolledBack = serve({"bob", "carol", "mallory"}, {"alice"}, 3, 2, encKey);
    EXPECT_THROW(verifier.assertDataIntegrity(rolledBack), GroupHistoryForkException);
}

TEST_F(GroupRosterTag, SECURITY_AnOlderPublicMetaVersionIsRejectedIndependently) {
    // Three pins, because the counters move independently: neither an unmoved roster nor an unmoved private
    // plane may excuse a public-metadata entry that went backwards.
    GroupDataSchemaMapper verifier(PrivateKey::generateRandom(), core::Connection());
    auto current = serve({"bob", "carol"}, {"alice"}, 4, 2, encKey, 9, std::nullopt, 3);
    ASSERT_NO_THROW(verifier.assertDataIntegrity(current));

    auto rolledBack = serve({"bob", "carol"}, {"alice"}, 4, 2, encKey, 8, std::nullopt, 3);
    EXPECT_THROW(verifier.assertDataIntegrity(rolledBack), GroupHistoryForkException);
}

TEST_F(GroupRosterTag, SECURITY_AnOlderPrivateMetaVersionIsRejectedIndependently) {
    GroupDataSchemaMapper verifier(PrivateKey::generateRandom(), core::Connection());
    auto current = serve({"bob", "carol"}, {"alice"}, 4, 2, encKey, 3, std::nullopt, 9);
    ASSERT_NO_THROW(verifier.assertDataIntegrity(current));

    auto rolledBack = serve({"bob", "carol"}, {"alice"}, 4, 2, encKey, 3, std::nullopt, 8);
    EXPECT_THROW(verifier.assertDataIntegrity(rolledBack), GroupHistoryForkException);
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
    // Unreachable before the split, and routine after it: write the public plane, remove a member, write the
    // private plane. Each plane stays at the epoch it was written under, and only a write to that same plane
    // brings it forward.
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
    // Why the tag is key-bound rather than merely signed: the public plane is signed and not encrypted at all,
    // so a bridge holding a keypair of its own could re-author the whole envelope — DIO included — and forge it.
    // Only the content key, which the bridge never holds, refuses that.
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
    // The substitution the domain prefixes exist to refuse. It is caught twice over — the private plane's
    // envelope has no `privateMeta` field, so deserialisation refuses it before the tag is ever computed — and
    // that first refusal is why the parse is wrapped: unwrapped it escapes as a bare JSON error.
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
    // Pinned deliberately, because it is what rules out the cheap fix for the forgery gap below. A former member
    // is the *expected* author of an entry written before they left — a removal does not rewrite either metadata
    // plane, only the carry-up afterwards does, and that is best-effort — so refusing an author who is off the
    // current roster would make the group unreadable for everyone the moment its metadata writer is removed.
    // Same failure shape as `metadata_written_by_a_different_manager_keeps_the_group_readable`.
    auto group = serve({"bob", "carol"}, {"alice"}, 4, 2, encKey, 7, std::nullopt, 7);
    group.publicMeta.author = "dave";  // wrote the metadata at epoch 2, removed since
    group.privateMeta.author = "dave";
    GroupDataSchemaMapper verifier(PrivateKey::generateRandom(), core::Connection());
    EXPECT_NO_THROW(verifier.assertPublicMetaIsAttested(group, key(encKey)));
    EXPECT_NO_THROW(verifier.assertPrivateMetaIsAttested(group, key(encKey)));
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
    // Three tags over the same numbers under the same content key. Even if a future preimage change made the
    // payloads coincide, the subkeys keep the tags apart — including the two metadata planes from each other,
    // which carry the same `MetaBlock` shape and so would otherwise be interchangeable at equal (epoch, version).
    const std::string k = privmx::crypto::Crypto::randomBytes(32);
    EXPECT_NE(GroupDataSchemaMapper::rosterTag(k, 2, 7, {}, {}), GroupDataSchemaMapper::publicMetaTag(k, 2, 7));
    EXPECT_NE(GroupDataSchemaMapper::rosterTag(k, 2, 7, {}, {}), GroupDataSchemaMapper::privateMetaTag(k, 2, 7));
    EXPECT_NE(GroupDataSchemaMapper::publicMetaTag(k, 2, 7), GroupDataSchemaMapper::privateMetaTag(k, 2, 7));
}

TEST_F(GroupRosterTag, TheInternalMetaViewReadsTheRosterPlane) {
    // `prepareContainerUpdate` takes the container's `secret` from here and feeds it to `verifyKeysSecret`, and
    // the entry it hands over is the roster head — now the only plane that carries `internalMeta` at all, since
    // neither metadata envelope has a module identity of its own. Reading it under the metadata shape threw on
    // the fields a roster entry does not carry, and the empty secret that came back failed every roster write
    // with EncryptionKeyValidationException.
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
