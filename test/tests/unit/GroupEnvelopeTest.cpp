/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

/**
 * The group envelope wire format.
 *
 * Round-trips are the easy half and are covered first. The half that matters is everything below them: each
 * case is a specific lie — a bridge's, a fellow member's, or an outsider's — that the format has to refuse.
 * Two of them are the reason the format looks the way it does at all:
 *
 *   - `LadderRungIsNotAnEnvelope`, because epoch-ladder rungs are the same ECIES construction addressed to the
 *     same group key, and their plaintext is a *private key*;
 *   - `HeaderIsSigned*` / `TypeCannotBeRelabelled`, because a header outside the signature is a header anyone
 *     can rewrite.
 */

#include <gtest/gtest.h>

#include <string>

#include <privmx/crypto/Crypto.hpp>
#include <privmx/crypto/EciesEncryptor.hpp>
#include <privmx/crypto/ecc/PrivateKey.hpp>
#include <privmx/endpoint/core/Exception.hpp>

#include <privmx/endpoint/group/GroupException.hpp>
#include <privmx/endpoint/group/encryptors/envelope/EnvelopeWire.hpp>
#include <privmx/endpoint/group/encryptors/envelope/GroupEnvelopeEncryptor.hpp>

using privmx::crypto::PrivateKey;
using namespace privmx::endpoint;
using namespace privmx::endpoint::group;

class GroupEnvelope : public testing::Test {
protected:
    GroupEnvelopeEncryptor enc;
    PrivateKey author = PrivateKey::generateRandom();
    PrivateKey grantKey = PrivateKey::generateRandom();
    std::string groupKey = privmx::crypto::Crypto::randomBytes(32);
    std::string groupId = "grp1";
    std::string keyId = "0123456789abcdef0123456789abcdef";
    // Bound to nothing, said out loud: what every case here uses unless it is about the binding itself.
    EnvelopeBinding none{};
    EnvelopeSeal seal{.binding = none, .keyVersion = 7, .encryptedAt = 1700000000000, .authorUserId = "alice"};

    core::Buffer buf(const std::string& s) { return core::Buffer::from(s); }
};

// -- round trips ---------------------------------------------------------------------------------------

TEST_F(GroupEnvelope, GroupKeyRoundTrip) {
    core::Buffer env = enc.packMemberEnvelope(groupId, keyId, buf("hello group"), author, groupKey, seal);
    OpenedEnvelope out = enc.openMemberEnvelope(env, groupKey, none);

    EXPECT_EQ(out.data.stdString(), "hello group");
    EXPECT_EQ(out.groupId, groupId);
    EXPECT_EQ(out.authorPubKey, author.getPublicKey().toBase58DER());
    EXPECT_EQ(out.type, ENVELOPE_FROM_MEMBER);
}

TEST_F(GroupEnvelope, AnonymousRoundTripAndCarriesNoAuthor) {
    core::Buffer env = enc.packAnonymousEnvelope(groupId, grantKey.getPublicKey(), buf("from outside"), none);
    OpenedEnvelope out = enc.openAnonymousEnvelope(env, grantKey, none);

    EXPECT_EQ(out.data.stdString(), "from outside");
    EXPECT_EQ(out.groupId, groupId);
    EXPECT_EQ(out.type, ENVELOPE_ANONYMOUS);
    // A throwaway sender key attests to nothing, so nothing is reported.
    EXPECT_TRUE(out.authorPubKey.empty());
}

TEST_F(GroupEnvelope, AnonymousEnvelopesAreNotDeterministic) {
    // The ECIES layer derives its IV from the sender key, so a fixed sender would leak plaintext equality.
    // A fresh ephemeral key per call is what stops that.
    core::Buffer a = enc.packAnonymousEnvelope(groupId, grantKey.getPublicKey(), buf("same"), none);
    core::Buffer b = enc.packAnonymousEnvelope(groupId, grantKey.getPublicKey(), buf("same"), none);
    EXPECT_NE(a.stdString(), b.stdString());
}

TEST_F(GroupEnvelope, EmptyContentRoundTrips) {
    core::Buffer env = enc.packMemberEnvelope(groupId, keyId, buf(""), author, groupKey, seal);
    EXPECT_EQ(enc.openMemberEnvelope(env, groupKey, none).data.stdString(), "");
}

TEST_F(GroupEnvelope, PeekRoutesWithoutOpening) {
    auto r1 = enc.peek(enc.packMemberEnvelope(groupId, keyId, buf("x"), author, groupKey, seal));
    EXPECT_EQ(r1.type, ENVELOPE_FROM_MEMBER);
    EXPECT_EQ(r1.groupId, groupId);
    EXPECT_EQ(r1.keyId, keyId);

    auto r2 = enc.peek(enc.packAnonymousEnvelope(groupId, grantKey.getPublicKey(), buf("x"), none));
    EXPECT_EQ(r2.type, ENVELOPE_ANONYMOUS);
    EXPECT_EQ(r2.groupPubKey, grantKey.getPublicKey().toBase58DER());
}

// -- the ladder-rung oracle ----------------------------------------------------------------------------

TEST_F(GroupEnvelope, LadderRungIsNotAnEnvelope) {
    // Exactly what `TreeKeys::wrapKey` produces, byte-identical to a type 2 key wrap. If `openAnonymousEnvelope`
    // took it, it would return a past epoch's private key as content, past every era-floor and pruning check.
    PrivateKey pastEpochKey = PrivateKey::generateRandom();
    std::string rung = privmx::crypto::EciesEncryptor::encrypt(
        grantKey.getPublicKey(), pastEpochKey.toWIF(), PrivateKey::generateRandom()
    );

    std::string forged;
    forged.push_back(static_cast<char>(GroupEnvelopeEncryptor::VERSION));
    forged.push_back(2); // TYPE_ANONYMOUS
    forged.push_back(0); // flags: no location, a message
    forged.push_back(static_cast<char>(groupId.size()));
    forged.append(groupId);
    std::string pub = grantKey.getPublicKey().toBase58DER();
    forged.push_back(static_cast<char>(pub.size()));
    forged.append(pub);
    forged.push_back(static_cast<char>(rung.size()));
    forged.append(rung);
    forged.append(privmx::crypto::Crypto::randomBytes(64)); // payload never gets reached

    EXPECT_THROW(enc.openAnonymousEnvelope(buf(forged), grantKey, none), InvalidEnvelopeFormatException);
}

TEST_F(GroupEnvelope, AnonymousRejectsAMismatchedGroupKey) {
    // A hostile server steering us onto the wrong epoch's key must not leave ECIES's 4-byte checksum as the
    // only thing between us and a wrong answer.
    core::Buffer env = enc.packAnonymousEnvelope(groupId, grantKey.getPublicKey(), buf("x"), none);
    EXPECT_THROW(enc.openAnonymousEnvelope(env, PrivateKey::generateRandom(), none), InvalidEnvelopeFormatException);
}

// -- header authentication -----------------------------------------------------------------------------

TEST_F(GroupEnvelope, HeaderIsSignedSoAnEnvelopeCannotBeReplayedIntoAnotherGroup) {
    // A member of both groups re-seals Alice's *same signed inner blob* under group B's key. Her signature still
    // verifies, so only the header being inside that signature stops her "yes" in A becoming a "yes" in B.
    core::Buffer envA = enc.packMemberEnvelope("groupA", keyId, buf("approve"), author, groupKey, seal);

    std::string otherKey = privmx::crypto::Crypto::randomBytes(32);
    core::DataInnerEncryptorV4 raw;
    // ver | type | flags | groupId | keyId | authorDER | u64 keyVersion
    std::size_t headerLen = 3 + 1 + std::string("groupA").size() + 1 + keyId.size() + 1 + 5 + 1 + 33 + 8;
    core::Buffer sealed = raw.decrypt(buf(envA.stdString().substr(headerLen)), groupKey);

    std::string forgedHeader;
    forgedHeader.push_back(static_cast<char>(GroupEnvelopeEncryptor::VERSION));
    forgedHeader.push_back(1);
    forgedHeader.push_back(0); // flags: no location, as in the original
    std::string other = "groupB";
    forgedHeader.push_back(static_cast<char>(other.size()));
    forgedHeader.append(other);
    forgedHeader.push_back(static_cast<char>(keyId.size()));
    forgedHeader.append(keyId);
    forgedHeader.push_back(5);
    forgedHeader.append("alice");
    std::string der = author.getPublicKey().toDER();
    forgedHeader.push_back(static_cast<char>(der.size()));
    forgedHeader.append(der);
    forgedHeader.append(EnvelopeWriter::toBE(7, 8)); // the same key version the original carries

    core::Buffer forged = buf(forgedHeader + raw.encrypt(sealed, otherKey).stdString());
    EXPECT_THROW(enc.openMemberEnvelope(forged, otherKey, none), InvalidEnvelopeFormatException);
}

TEST_F(GroupEnvelope, TamperedHeaderFieldsAreRejected) {
    core::Buffer env = enc.packMemberEnvelope(groupId, keyId, buf("x"), author, groupKey, seal);
    for (std::size_t i = 2; i < 3 + 1 + groupId.size() + 1 + keyId.size(); ++i) {
        std::string tampered = env.stdString();
        tampered[i] = static_cast<char>(tampered[i] ^ 0x01);
        EXPECT_ANY_THROW(enc.openMemberEnvelope(buf(tampered), groupKey, none)) << "byte " << i;
    }
}

TEST_F(GroupEnvelope, AMalformedSignatureFrameThrowsAPrivmxException) {
    // A payload of `\x01\xff` claims a 255-byte signature and carries none. The frame parser once ran off the end
    // with std::out_of_range, crossing the public API and the language bindings as a bare standard-library error.
    core::DataInnerEncryptorV4 raw;
    std::string header;
    header.push_back(static_cast<char>(GroupEnvelopeEncryptor::VERSION));
    header.push_back(1); // TYPE_GROUP_KEY
    for (const std::string& field : {groupId, keyId, author.getPublicKey().toDER()}) {
        header.push_back(static_cast<char>(field.size()));
        header.append(field);
    }
    core::Buffer forged = buf(header + raw.encrypt(buf(std::string("\x01\xFF", 2)), groupKey).stdString());

    EXPECT_THROW(enc.openMemberEnvelope(forged, groupKey, none), core::Exception);
}

TEST_F(GroupEnvelope, WrongGroupKeyIsRejected) {
    core::Buffer env = enc.packMemberEnvelope(groupId, keyId, buf("x"), author, groupKey, seal);
    EXPECT_ANY_THROW(enc.openMemberEnvelope(env, privmx::crypto::Crypto::randomBytes(32), none));
}

TEST_F(GroupEnvelope, TamperedCiphertextIsRejected) {
    core::Buffer env = enc.packMemberEnvelope(groupId, keyId, buf("payload here"), author, groupKey, seal);
    std::string tampered = env.stdString();
    tampered[tampered.size() - 1] = static_cast<char>(tampered[tampered.size() - 1] ^ 0x01);
    EXPECT_ANY_THROW(enc.openMemberEnvelope(buf(tampered), groupKey, none));
}

// -- malformed input -----------------------------------------------------------------------------------

TEST_F(GroupEnvelope, TruncatedEnvelopesThrowRatherThanParseGarbage) {
    for (const std::string& junk : {std::string(""), std::string("\x01"), std::string("\x01\x01\x40")}) {
        EXPECT_THROW(enc.peek(buf(junk)), InvalidEnvelopeFormatException) << "len " << junk.size();
        EXPECT_THROW(enc.openMemberEnvelope(buf(junk), groupKey, none), InvalidEnvelopeFormatException);
    }
}

TEST_F(GroupEnvelope, UnsupportedVersionIsRejected) {
    core::Buffer env = enc.packMemberEnvelope(groupId, keyId, buf("x"), author, groupKey, seal);
    std::string bumped = env.stdString();
    bumped[0] = 99;
    EXPECT_THROW(enc.peek(buf(bumped)), InvalidEnvelopeFormatException);
}

TEST_F(GroupEnvelope, OversizedFieldThrowsInsteadOfTruncating) {
    // One length octet on the wire; a silent wrap would produce an envelope that parses into the wrong group.
    EXPECT_THROW(
        enc.packMemberEnvelope(std::string(256, 'a'), keyId, buf("x"), author, groupKey, seal),
        InvalidEnvelopeFormatException
    );
}

// -- files ---------------------------------------------------------------------------------------------

TEST_F(GroupEnvelope, ChunkRoundTripAndSizeIsPredictable) {
    std::string fileKey = privmx::crypto::Crypto::randomBytes(32);
    std::string plain(GroupEnvelopeEncryptor::CHUNK_SIZE, 'z');

    core::Buffer cipher = enc.encryptChunk(buf(plain), fileKey, 0);
    // The read side slices the stream by this constant, so it must hold exactly.
    EXPECT_EQ(cipher.size(), encryptedChunkSizeFor(GroupEnvelopeEncryptor::CHUNK_SIZE));
    EXPECT_EQ(enc.decryptChunk(cipher, fileKey, 0).stdString(), plain);
}

TEST_F(GroupEnvelope, ChunkCannotBeMovedReorderedOrSpliced) {
    std::string fileKey = privmx::crypto::Crypto::randomBytes(32);
    core::Buffer chunk0 = enc.encryptChunk(buf("first"), fileKey, 0);

    // Same file, different position: the index is bound into the chunk key.
    EXPECT_ANY_THROW(enc.decryptChunk(chunk0, fileKey, 1));
    // Different file: the per-file random key is bound in too.
    EXPECT_ANY_THROW(enc.decryptChunk(chunk0, privmx::crypto::Crypto::randomBytes(32), 0));
}

// -- anonymous files (type 4) --------------------------------------------------------------------------

// -- random access -------------------------------------------------------------------------------------

TEST_F(GroupEnvelope, ChunksOpenIndependentlyOfEachOther) {
    // Random access rests on a chunk needing nothing but the file key and its own index — no running state,
    // no prior chunk. Open them backwards to prove it.
    constexpr ByteCount C = GroupEnvelopeEncryptor::CHUNK_SIZE;
    std::string fileKey = privmx::crypto::Crypto::randomBytes(32);
    std::vector<core::Buffer> sealed;
    for (ChunkIndex i = 0; i < 4; ++i) {
        sealed.push_back(enc.encryptChunk(buf(std::string(C, 'a' + i)), fileKey, i));
    }
    for (int i = 3; i >= 0; --i) {
        EXPECT_EQ(enc.decryptChunk(sealed[i], fileKey, static_cast<ChunkIndex>(i)).stdString(), std::string(C, 'a' + i))
            << "chunk " << i;
    }
}

// -- what a finished read means ------------------------------------------------------------------------

// The truth table `finishFileDecryption` acts on, pinned here because the reader that owns the decision needs a
// live bridge to construct — which is how the seeked case below shipped broken.
using Outcome = GroupEnvelopeEncryptor::ReadOutcome;

TEST_F(GroupEnvelope, AStraightReadIsCompleteOnlyWhenEverythingArrived) {
    // all five chunks, nothing left over
    EXPECT_EQ(enc.classifyRead(false, 5, 5, true), Outcome::Complete);
}

TEST_F(GroupEnvelope, AStraightReadMissingChunksIsTruncated) {
    EXPECT_EQ(enc.classifyRead(false, 4, 5, true), Outcome::Truncated);
    EXPECT_EQ(enc.classifyRead(false, 0, 1, true), Outcome::Truncated);
    // Truncation outranks leftover bytes: a short read is the more useful thing to report.
    EXPECT_EQ(enc.classifyRead(false, 4, 5, false), Outcome::Truncated);
}

TEST_F(GroupEnvelope, AStraightReadWithBytesPastTheEndIsOverrun) {
    EXPECT_EQ(enc.classifyRead(false, 5, 5, false), Outcome::Overrun);
}

TEST_F(GroupEnvelope, ASeekedReadIsNeverAnError) {
    // The regression. A range reader stopping mid-chunk ends with fewer chunks opened than the file holds *and*
    // a partly-filled buffer — both look exactly like the two failure cases above, and neither is a failure.
    EXPECT_EQ(enc.classifyRead(true, 2, 5, false), Outcome::PartialRange);  // stopped mid-chunk
    EXPECT_EQ(enc.classifyRead(true, 2, 5, true), Outcome::PartialRange);   // stopped on a boundary
    EXPECT_EQ(enc.classifyRead(true, 5, 5, false), Outcome::PartialRange);  // read to the end, bytes spare
    EXPECT_EQ(enc.classifyRead(true, 0, 5, true), Outcome::PartialRange);   // read nothing at all
}

// ════════════════════════════════════════════════════════════════════════════════════════════════════
// Format 3: location binding, signed outsiders, further recipients
// ════════════════════════════════════════════════════════════════════════════════════════════════════

class GroupEnvelopeV3 : public GroupEnvelope {
protected:
    static PathSegment name(const std::string& text) { return {false, core::Buffer::from(text)}; }
    static PathSegment id(const std::string& bytes) { return {true, core::Buffer::from(bytes)}; }

    Path messageA = {name("chat"), id("c1"), name("message"), id("m1")};
    Path messageB = {name("chat"), id("c1"), name("message"), id("m2")};
    EnvelopeBinding atA = GroupEnvelopeEncryptor::bindLocation(messageA);
    EnvelopeBinding atB = GroupEnvelopeEncryptor::bindLocation(messageB);
    EnvelopeSeal sealA{.binding = atA, .keyVersion = 3, .encryptedAt = 1700000000123, .authorUserId = "alice"};

    PrivateKey outsider = PrivateKey::generateRandom();
    PrivateKey billingKey = PrivateKey::generateRandom(); // another group's identity key
    PrivateKey auditorKey = PrivateKey::generateRandom(); // a single user's key
    std::vector<WireRecipient> recipients = {
        {.isGroup = true, .id = "billing", .pubKey = billingKey.getPublicKey().toBase58DER(), .keyVersion = 4},
        {.isGroup = false, .id = "auditor", .pubKey = auditorKey.getPublicKey().toBase58DER(), .keyVersion = 0},
    };
};

// -- binding -------------------------------------------------------------------------------------------

TEST_F(GroupEnvelopeV3, OpensAtTheLocationItWasWrittenFor) {
    core::Buffer env = enc.packMemberEnvelope(groupId, keyId, buf("hello"), author, groupKey, sealA);
    OpenedEnvelope out = enc.openMemberEnvelope(env, groupKey, atA);
    EXPECT_EQ(out.data.stdString(), "hello");
    EXPECT_EQ(out.keyVersion, 3);
    EXPECT_EQ(out.encryptedAt, 1700000000123);
    EXPECT_EQ(out.authorUserId, "alice");
    EXPECT_TRUE(out.recipients.empty());
}

TEST_F(GroupEnvelopeV3, SECURITY_AMovedEnvelopeIsRefused) {
    // The server stores message m1's envelope in m2's row. Everything about it is authentic; it is just not here.
    core::Buffer env = enc.packMemberEnvelope(groupId, keyId, buf("pay 100"), author, groupKey, sealA);
    EXPECT_THROW(enc.openMemberEnvelope(env, groupKey, atB), EnvelopeWrongLocationException);
}

TEST_F(GroupEnvelopeV3, SECURITY_BoundAndUnboundNeverOpenAsEachOther) {
    core::Buffer bound = enc.packMemberEnvelope(groupId, keyId, buf("x"), author, groupKey, sealA);
    core::Buffer unbound = enc.packMemberEnvelope(groupId, keyId, buf("x"), author, groupKey, seal);
    EXPECT_THROW(enc.openMemberEnvelope(bound, groupKey, none), EnvelopeWrongLocationException);
    EXPECT_THROW(enc.openMemberEnvelope(unbound, groupKey, atA), EnvelopeWrongLocationException);
    EXPECT_NO_THROW(enc.openMemberEnvelope(unbound, groupKey, none));
}

TEST_F(GroupEnvelopeV3, SECURITY_TheLocationFlagIsSigned) {
    // Clearing the flag on the wire must not turn a bound envelope into an unbound one.
    std::string wire = enc.packMemberEnvelope(groupId, keyId, buf("x"), author, groupKey, sealA).stdString();
    wire[2] = 0;
    EXPECT_THROW(enc.openMemberEnvelope(buf(wire), groupKey, none), InvalidEnvelopeFormatException);
}

TEST_F(GroupEnvelopeV3, UnknownFlagsAreRefused) {
    std::string wire = enc.packMemberEnvelope(groupId, keyId, buf("x"), author, groupKey, sealA).stdString();
    wire[2] = static_cast<char>(wire[2] | 0x02);
    EXPECT_THROW(enc.peek(buf(wire)), InvalidEnvelopeFormatException);
}

TEST_F(GroupEnvelopeV3, DifferentPathsNeverBindAlike) {
    auto digest = [](const Path& path) { return GroupEnvelopeEncryptor::bindLocation(path).locationDigest; };
    // Segment boundaries count.
    EXPECT_NE(digest({name("ab")}), digest({name("a"), name("b")}));
    // A name is not an identifier with the same bytes.
    EXPECT_NE(digest({name("chat"), name("c1")}), digest({name("chat"), id("c1")}));
    // Order counts.
    EXPECT_NE(digest({name("a"), name("b")}), digest({name("b"), name("a")}));
    // A length cannot be smuggled in as content.
    EXPECT_NE(digest({name(std::string("a\0\0\0\0\1b", 7))}), digest({name("a"), name("b")}));
    EXPECT_EQ(digest(messageA), digest({name("chat"), id("c1"), name("message"), id("m1")}));
    EXPECT_EQ(digest(messageA).size(), 32u);
}

TEST_F(GroupEnvelopeV3, AnEmptyLocationIsRefused) {
    EXPECT_THROW(GroupEnvelopeEncryptor::bindLocation({}), InvalidEnvelopeFormatException);
}

TEST_F(GroupEnvelopeV3, AMalformedBindingIsRefusedOnWrite) {
    EnvelopeSeal bad{.binding = EnvelopeBinding{.hasLocation = true, .locationDigest = "short"}};
    EXPECT_THROW(
        enc.packMemberEnvelope(groupId, keyId, buf("x"), author, groupKey, bad), InvalidEnvelopeFormatException
    );
}

TEST_F(GroupEnvelopeV3, AnonymousAndFileEnvelopesAreBoundToo) {
    core::Buffer anon = enc.packAnonymousEnvelope(groupId, grantKey.getPublicKey(), buf("x"), atA);
    EXPECT_NO_THROW(enc.openAnonymousEnvelope(anon, grantKey, atA));
    EXPECT_THROW(enc.openAnonymousEnvelope(anon, grantKey, atB), EnvelopeWrongLocationException);
    EXPECT_THROW(enc.openAnonymousEnvelope(anon, grantKey, none), EnvelopeWrongLocationException);

}

// -- the plain header ----------------------------------------------------------------------------------

TEST_F(GroupEnvelopeV3, PeekReportsWhatAServerGateNeeds) {
    auto bound = GroupEnvelopeEncryptor::peekAny(
        enc.packMemberEnvelope(groupId, keyId, buf("x"), author, groupKey, sealA, recipients)
    );
    EXPECT_EQ(bound.type, ENVELOPE_FROM_MEMBER);
    EXPECT_EQ(bound.content, EnvelopeContent::Message);
    EXPECT_TRUE(bound.hasLocation);
    EXPECT_EQ(bound.keyVersion, 3);
    EXPECT_EQ(bound.authorPubKey, author.getPublicKey().toBase58DER());
    ASSERT_EQ(bound.recipients.size(), 2u);
    EXPECT_TRUE(bound.recipients[0].isGroup);
    EXPECT_EQ(bound.recipients[0].id, "billing");
    EXPECT_EQ(bound.recipients[0].keyVersion, 4);
    EXPECT_FALSE(bound.recipients[1].isGroup);
    EXPECT_EQ(bound.recipients[1].id, "auditor");

    auto unbound = GroupEnvelopeEncryptor::peekAny(
        enc.packMemberEnvelope(groupId, keyId, buf("x"), author, groupKey, seal)
    );
    EXPECT_FALSE(unbound.hasLocation);

    EnvelopeSeal fileSeal = sealA;
    fileSeal.binding.content = EnvelopeContent::File;
    auto file = GroupEnvelopeEncryptor::peekAny(
        enc.packMemberEnvelope(groupId, keyId, buf("manifest"), author, groupKey, fileSeal)
    );
    EXPECT_EQ(file.content, EnvelopeContent::File);
    EXPECT_EQ(file.keyVersion, 3);

    auto fromOutside = GroupEnvelopeEncryptor::peekAny(
        enc.packOutsiderEnvelope(groupId, grantKey.getPublicKey(), buf("x"), outsider, sealA)
    );
    EXPECT_EQ(fromOutside.type, ENVELOPE_FROM_OUTSIDER);
    EXPECT_EQ(fromOutside.authorPubKey, outsider.getPublicKey().toBase58DER());
}

// -- signed outsiders ----------------------------------------------------------------------------------

TEST_F(GroupEnvelopeV3, OutsiderRoundTripNamesTheSender) {
    core::Buffer env = enc.packOutsiderEnvelope(groupId, grantKey.getPublicKey(), buf("lab result"), outsider, sealA);
    OpenedEnvelope out = enc.openOutsiderEnvelope(env, grantKey, atA);
    EXPECT_EQ(out.data.stdString(), "lab result");
    EXPECT_EQ(out.type, ENVELOPE_FROM_OUTSIDER);
    EXPECT_EQ(out.authorPubKey, outsider.getPublicKey().toBase58DER());
    EXPECT_EQ(out.encryptedAt, 1700000000123);
}

TEST_F(GroupEnvelopeV3, SECURITY_EachOpenerReadsItsOwnKindOnly) {
    core::Buffer member = enc.packMemberEnvelope(groupId, keyId, buf("x"), author, groupKey, sealA);
    core::Buffer shared = enc.packMemberEnvelope(groupId, keyId, buf("x"), author, groupKey, sealA, recipients);
    core::Buffer fromOutside = enc.packOutsiderEnvelope(groupId, grantKey.getPublicKey(), buf("x"), outsider, sealA);
    core::Buffer anon = enc.packAnonymousEnvelope(groupId, grantKey.getPublicKey(), buf("x"), atA);

    // What a non-member wrote is never opened as a member's, and what nobody signed is never opened as signed.
    EXPECT_ANY_THROW(enc.openMemberEnvelope(fromOutside, groupKey, atA));
    EXPECT_ANY_THROW(enc.openMemberEnvelope(anon, groupKey, atA));
    EXPECT_ANY_THROW(enc.openOutsiderEnvelope(member, grantKey, atA));
    EXPECT_ANY_THROW(enc.openOutsiderEnvelope(shared, grantKey, atA));
    EXPECT_ANY_THROW(enc.openOutsiderEnvelope(anon, grantKey, atA));
    EXPECT_ANY_THROW(enc.openAnonymousEnvelope(member, grantKey, atA));
    EXPECT_ANY_THROW(enc.openAnonymousEnvelope(fromOutside, grantKey, atA));
    EXPECT_ANY_THROW(enc.openSharedEnvelope(member, 0, billingKey, atA));
    EXPECT_ANY_THROW(enc.openSharedEnvelope(anon, 0, billingKey, atA));

    EXPECT_NO_THROW(enc.openMemberEnvelope(member, groupKey, atA));
    EXPECT_NO_THROW(enc.openMemberEnvelope(shared, groupKey, atA));
    EXPECT_NO_THROW(enc.openOutsiderEnvelope(fromOutside, grantKey, atA));
    EXPECT_NO_THROW(enc.openAnonymousEnvelope(anon, grantKey, atA));
}

TEST_F(GroupEnvelopeV3, SECURITY_AnOutsiderEnvelopeCannotBeRelabelledAnonymousOrBack) {
    std::string fromOutside =
        enc.packOutsiderEnvelope(groupId, grantKey.getPublicKey(), buf("x"), outsider, sealA).stdString();
    fromOutside[1] = 2; // TYPE_OUTSIDER -> TYPE_ANONYMOUS
    EXPECT_ANY_THROW(enc.openAnonymousEnvelope(buf(fromOutside), grantKey, atA));

    std::string anon = enc.packAnonymousEnvelope(groupId, grantKey.getPublicKey(), buf("x"), atA).stdString();
    anon[1] = 5; // TYPE_ANONYMOUS -> TYPE_OUTSIDER
    EXPECT_ANY_THROW(enc.openOutsiderEnvelope(buf(anon), grantKey, atA));
}

TEST_F(GroupEnvelopeV3, SECURITY_AnotherSendersKeyInTheHeaderIsRefused) {
    // The server swaps the sender's public key for someone else's: the signature no longer verifies.
    PrivateKey mallory = PrivateKey::generateRandom();
    std::string wire =
        enc.packOutsiderEnvelope(groupId, grantKey.getPublicKey(), buf("x"), outsider, sealA).stdString();
    std::string from = outsider.getPublicKey().toDER();
    std::string to = mallory.getPublicKey().toDER();
    std::size_t at = wire.find(from);
    ASSERT_NE(at, std::string::npos);
    wire.replace(at, from.size(), to);
    EXPECT_ANY_THROW(enc.openOutsiderEnvelope(buf(wire), grantKey, atA));
}

// -- further recipients --------------------------------------------------------------------------------

TEST_F(GroupEnvelopeV3, EveryReaderOpensASharedEnvelope) {
    core::Buffer env = enc.packMemberEnvelope(groupId, keyId, buf("discharge"), author, groupKey, sealA, recipients);

    OpenedEnvelope home = enc.openMemberEnvelope(env, groupKey, atA);
    EXPECT_EQ(home.data.stdString(), "discharge");
    ASSERT_EQ(home.recipients.size(), 2u);
    EXPECT_EQ(home.recipients[0].id, "billing");

    OpenedEnvelope billing = enc.openSharedEnvelope(env, 0, billingKey, atA);
    EXPECT_EQ(billing.data.stdString(), "discharge");
    EXPECT_EQ(billing.groupId, groupId);
    EXPECT_EQ(billing.type, ENVELOPE_FROM_MEMBER);
    // ...which is only what the writer says: a recipient never held the home group's key.
    EXPECT_TRUE(billing.homeGroupUnverified);
    EXPECT_FALSE(home.homeGroupUnverified);
    EXPECT_EQ(billing.authorPubKey, author.getPublicKey().toBase58DER());
    EXPECT_EQ(billing.keyVersion, 3);

    OpenedEnvelope auditor = enc.openSharedEnvelope(env, 1, auditorKey, atA);
    EXPECT_EQ(auditor.data.stdString(), "discharge");
}

TEST_F(GroupEnvelopeV3, AnOutsidersEnvelopeCanBeSharedToo) {
    core::Buffer env =
        enc.packOutsiderEnvelope(groupId, grantKey.getPublicKey(), buf("result"), outsider, sealA, recipients);
    EXPECT_EQ(enc.openOutsiderEnvelope(env, grantKey, atA).data.stdString(), "result");
    OpenedEnvelope billing = enc.openSharedEnvelope(env, 0, billingKey, atA);
    EXPECT_EQ(billing.data.stdString(), "result");
    // Whoever reads it through `alsoFor` still learns it came from outside the home group.
    EXPECT_EQ(billing.type, ENVELOPE_FROM_OUTSIDER);
}

TEST_F(GroupEnvelopeV3, SECURITY_ARecipientOpensOnlyItsOwnWrap) {
    core::Buffer env = enc.packMemberEnvelope(groupId, keyId, buf("x"), author, groupKey, sealA, recipients);
    EXPECT_ANY_THROW(enc.openSharedEnvelope(env, 0, auditorKey, atA)); // the auditor's key on billing's slot
    EXPECT_ANY_THROW(enc.openSharedEnvelope(env, 1, billingKey, atA));
    EXPECT_ANY_THROW(enc.openSharedEnvelope(env, 0, PrivateKey::generateRandom(), atA));
    EXPECT_THROW(enc.openSharedEnvelope(env, 2, billingKey, atA), EnvelopeNotARecipientException);
}

TEST_F(GroupEnvelopeV3, SECURITY_SharedEnvelopesAreBoundToTheirLocationForEveryReader) {
    core::Buffer env = enc.packMemberEnvelope(groupId, keyId, buf("x"), author, groupKey, sealA, recipients);
    EXPECT_THROW(enc.openSharedEnvelope(env, 0, billingKey, atB), EnvelopeWrongLocationException);
    EXPECT_THROW(enc.openMemberEnvelope(env, groupKey, atB), EnvelopeWrongLocationException);
}

TEST_F(GroupEnvelopeV3, SECURITY_TheListOfReadersIsSigned) {
    // A server that renames a recipient - so that a reader shows "shared with billing" as something else -
    // breaks the signed header.
    std::string wire =
        enc.packMemberEnvelope(groupId, keyId, buf("x"), author, groupKey, sealA, recipients).stdString();
    std::size_t at = wire.find("billing");
    ASSERT_NE(at, std::string::npos);
    wire[at] = 'B';
    EXPECT_ANY_THROW(enc.openMemberEnvelope(buf(wire), groupKey, atA));
    EXPECT_ANY_THROW(enc.openSharedEnvelope(buf(wire), 0, billingKey, atA));
}

TEST_F(GroupEnvelopeV3, SECURITY_AWrappedContentKeyIsNotAMemberEnvelope) {
    // Type 6 seals the content key under the group key. That seal must never open as a type 1 payload, and a
    // type 1 payload must never be taken for a wrapped key.
    core::Buffer shared = enc.packMemberEnvelope(groupId, keyId, buf("x"), author, groupKey, sealA, recipients);
    std::string relabelled = shared.stdString();
    relabelled[1] = 1; // TYPE_MEMBER_SHARED -> TYPE_GROUP_KEY
    EXPECT_ANY_THROW(enc.openMemberEnvelope(buf(relabelled), groupKey, atA));

    core::Buffer plain = enc.packMemberEnvelope(groupId, keyId, buf("x"), author, groupKey, sealA);
    std::string up = plain.stdString();
    up[1] = 6; // TYPE_GROUP_KEY -> TYPE_MEMBER_SHARED
    EXPECT_ANY_THROW(enc.openMemberEnvelope(buf(up), groupKey, atA));
}

TEST_F(GroupEnvelopeV3, SECURITY_ALadderRungIsNotARecipientWrap) {
    // The same oracle as `LadderRungIsNotAnEnvelope`, through the recipient slot: a rung addressed to billing's
    // key, put where billing's wrap goes, must not come back as a content key.
    core::Buffer env = enc.packMemberEnvelope(groupId, keyId, buf("x"), author, groupKey, sealA, {recipients[0]});
    std::string wire = env.stdString();
    PrivateKey eph = PrivateKey::generateRandom();
    std::string rung = privmx::crypto::EciesEncryptor::encrypt(
        billingKey.getPublicKey(), PrivateKey::generateRandom().toWIF(), eph
    );
    // Locate billing's wrap: it is the second length-prefixed field after the header.
    auto routing = GroupEnvelopeEncryptor::peekAny(env);
    ASSERT_EQ(routing.recipients.size(), 1u);
    // header length = everything up to and including the recipients block
    std::size_t headerLen = 3 + 1 + groupId.size() + 1 + keyId.size() + 1 + 5 + 1 + 33 + 8 + 1 +
        (1 + 1 + recipients[0].id.size() + 1 + recipients[0].pubKey.size() + 8);
    std::size_t homeWrapLen = static_cast<std::uint8_t>(wire[headerLen]);
    std::size_t slot = headerLen + 1 + homeWrapLen;
    std::size_t oldLen = static_cast<std::uint8_t>(wire[slot]);
    std::string forged = wire.substr(0, slot);
    forged.push_back(static_cast<char>(rung.size()));
    forged.append(rung);
    forged.append(wire.substr(slot + 1 + oldLen));
    EXPECT_THROW(enc.openSharedEnvelope(buf(forged), 0, billingKey, atA), InvalidEnvelopeFormatException);
}

TEST_F(GroupEnvelopeV3, TooManyRecipientsAreRefused) {
    std::vector<WireRecipient> many(256, recipients[1]);
    EXPECT_THROW(
        enc.packMemberEnvelope(groupId, keyId, buf("x"), author, groupKey, sealA, many), InvalidEnvelopeFormatException
    );
}

TEST_F(GroupEnvelopeV3, TruncatedSharedEnvelopesThrowRatherThanParseGarbage) {
    std::string wire =
        enc.packMemberEnvelope(groupId, keyId, buf("x"), author, groupKey, sealA, recipients).stdString();
    for (std::size_t len = 0; len < wire.size(); len += 7) {
        EXPECT_ANY_THROW(enc.openSharedEnvelope(buf(wire.substr(0, len)), 0, billingKey, atA)) << "length " << len;
        EXPECT_ANY_THROW(enc.openMemberEnvelope(buf(wire.substr(0, len)), groupKey, atA)) << "length " << len;
    }
}

TEST_F(GroupEnvelopeV3, SECURITY_TheAuthorsUserIdIsSigned) {
    // The server relabels alice's envelope as bob's. The id is inside the signed header, so the open fails.
    std::string wire = enc.packMemberEnvelope(groupId, keyId, buf("x"), author, groupKey, sealA).stdString();
    std::size_t at = wire.find("alice");
    ASSERT_NE(at, std::string::npos);
    wire.replace(at, 5, "bobby");
    EXPECT_ANY_THROW(enc.openMemberEnvelope(buf(wire), groupKey, atA));

    EnvelopeSeal fromDevice = sealA;
    fromDevice.authorUserId = "analyzer";
    core::Buffer env = enc.packOutsiderEnvelope(groupId, grantKey.getPublicKey(), buf("x"), outsider, fromDevice);
    EXPECT_EQ(enc.openOutsiderEnvelope(env, grantKey, atA).authorUserId, "analyzer");
    EXPECT_EQ(GroupEnvelopeEncryptor::peekAny(env).authorUserId, "analyzer");
}

TEST_F(GroupEnvelopeV3, SECURITY_AMemberClaimIsNotProofForARecipient) {
    // Mallory is in no group. She writes "from a member of grp1" to billing, sealing the home wrap under a key she
    // made up. Billing cannot tell from the envelope: it opens, and it must come back marked as unverified.
    PrivateKey mallory = PrivateKey::generateRandom();
    std::string madeUpGroupKey = privmx::crypto::Crypto::randomBytes(32);
    EnvelopeSeal forgedSeal = sealA;
    forgedSeal.authorUserId = "mallory";
    core::Buffer forged = enc.packMemberEnvelope(
        groupId, keyId, buf("approved"), mallory, madeUpGroupKey, forgedSeal, {recipients[0]}
    );
    OpenedEnvelope billing = enc.openSharedEnvelope(forged, 0, billingKey, atA);
    EXPECT_EQ(billing.data.stdString(), "approved");
    EXPECT_TRUE(billing.homeGroupUnverified);
    // The home group itself refuses it: its real key does not open the made-up wrap.
    EXPECT_ANY_THROW(enc.openMemberEnvelope(forged, groupKey, atA));
}

// -- what an envelope carries: a message, a file's manifest, a sequence's key ------------------------------

class GroupEnvelopeContent : public GroupEnvelope {
protected:
    EnvelopeBinding as(EnvelopeContent content) { return EnvelopeBinding{.content = content}; }
    EnvelopeSeal sealOf(EnvelopeContent content) {
        EnvelopeSeal s = seal;
        s.binding.content = content;
        return s;
    }
    std::string flipped(const core::Buffer& b, std::size_t at) {
        std::string out = b.stdString();
        out[at] = static_cast<char>(out[at] ^ 0x01);
        return out;
    }
};

TEST_F(GroupEnvelopeContent, AFileEnvelopeIsNeverOpenedAsAMessage) {
    // Its content is the file key and the chunk list: handed back as message content it would give the key away
    // to whatever shows messages.
    const EnvelopeBinding file = as(EnvelopeContent::File);
    core::Buffer member = enc.packMemberEnvelope(groupId, keyId, buf("manifest"), author, groupKey, sealOf(EnvelopeContent::File));
    core::Buffer outsider =
        enc.packOutsiderEnvelope(groupId, grantKey.getPublicKey(), buf("manifest"), author, sealOf(EnvelopeContent::File));
    core::Buffer anonymous = enc.packAnonymousEnvelope(groupId, grantKey.getPublicKey(), buf("manifest"), file);

    for (const core::Buffer& envelope : {member, outsider, anonymous}) {
        EXPECT_THROW(enc.peek(envelope), InvalidEnvelopeFormatException);
        EXPECT_NO_THROW(enc.peek(envelope, EnvelopeContent::File));
        EXPECT_THROW(enc.peek(envelope, EnvelopeContent::Sequence), InvalidEnvelopeFormatException);
    }
    EXPECT_EQ(enc.openMemberEnvelope(member, groupKey, file).data.stdString(), "manifest");
    EXPECT_THROW(enc.openMemberEnvelope(member, groupKey, none), InvalidEnvelopeFormatException);
    EXPECT_EQ(enc.openOutsiderEnvelope(outsider, grantKey, file).data.stdString(), "manifest");
    EXPECT_THROW(enc.openOutsiderEnvelope(outsider, grantKey, none), InvalidEnvelopeFormatException);
    EXPECT_EQ(enc.openAnonymousEnvelope(anonymous, grantKey, file).data.stdString(), "manifest");
    EXPECT_THROW(enc.openAnonymousEnvelope(anonymous, grantKey, none), InvalidEnvelopeFormatException);
}

TEST_F(GroupEnvelopeContent, TheContentFlagCannotBeRewritten) {
    // Byte 2 is the flags octet. Cleared there, the envelope reads as a message - and the sealed header disagrees.
    core::Buffer member = enc.packMemberEnvelope(groupId, keyId, buf("manifest"), author, groupKey, sealOf(EnvelopeContent::File));
    std::string relabelled = member.stdString();
    relabelled[2] = 0;
    EXPECT_NO_THROW(enc.peek(buf(relabelled)));
    EXPECT_THROW(enc.openMemberEnvelope(buf(relabelled), groupKey, none), InvalidEnvelopeFormatException);

    core::Buffer anonymous =
        enc.packAnonymousEnvelope(groupId, grantKey.getPublicKey(), buf("manifest"), as(EnvelopeContent::File));
    relabelled = anonymous.stdString();
    relabelled[2] = 0;
    EXPECT_THROW(enc.openAnonymousEnvelope(buf(relabelled), grantKey, none), InvalidEnvelopeFormatException);

    std::string unknown = member.stdString();
    unknown[2] = 0x08; // a flag bit nobody defined
    EXPECT_THROW(GroupEnvelopeEncryptor::peekAny(buf(unknown)), InvalidEnvelopeFormatException);
}

TEST_F(GroupEnvelopeContent, FileManifestRoundTrip) {
    const std::string fileKey = privmx::crypto::Crypto::randomBytes(32);
    const std::vector<FileChunk> chunks{
        {.plainSize = 131072, .digest = privmx::crypto::Crypto::sha256("a")},
        {.plainSize = 1, .digest = privmx::crypto::Crypto::sha256("b")},
    };
    std::string readKey;
    const auto read = GroupEnvelopeEncryptor::readFileManifest(GroupEnvelopeEncryptor::packFileManifest(fileKey, chunks), readKey);
    EXPECT_EQ(readKey, fileKey);
    ASSERT_EQ(read.size(), 2u);
    EXPECT_EQ(read[0].plainSize, 131072u);
    EXPECT_EQ(read[1].digest, chunks[1].digest);

    // An empty file is a key and no chunks.
    EXPECT_TRUE(GroupEnvelopeEncryptor::readFileManifest(GroupEnvelopeEncryptor::packFileManifest(fileKey, {}), readKey).empty());
}

TEST_F(GroupEnvelopeContent, AMalformedFileManifestIsRefused) {
    const std::string fileKey = privmx::crypto::Crypto::randomBytes(32);
    const std::string digest = privmx::crypto::Crypto::sha256("a");
    std::string readKey;
    const std::string good = GroupEnvelopeEncryptor::packFileManifest(fileKey, {{.plainSize = 5, .digest = digest}}).stdString();

    EXPECT_THROW(GroupEnvelopeEncryptor::readFileManifest(buf(good.substr(0, 20)), readKey), InvalidEnvelopeFormatException);
    EXPECT_THROW(GroupEnvelopeEncryptor::readFileManifest(buf(good.substr(0, good.size() - 1)), readKey), InvalidEnvelopeFormatException);
    EXPECT_THROW(GroupEnvelopeEncryptor::readFileManifest(buf(good + "x"), readKey), InvalidEnvelopeFormatException);
    // A count that promises more than is there: nothing is allocated on its word.
    std::string lying = good;
    lying[32] = '\xff';
    EXPECT_THROW(GroupEnvelopeEncryptor::readFileManifest(buf(lying), readKey), InvalidEnvelopeFormatException);
    // A chunk no writer makes: empty, or above the chunk size.
    EXPECT_THROW(
        GroupEnvelopeEncryptor::readFileManifest(GroupEnvelopeEncryptor::packFileManifest(fileKey, {{.plainSize = 0, .digest = digest}}), readKey),
        InvalidEnvelopeFormatException
    );
    EXPECT_THROW(
        GroupEnvelopeEncryptor::readFileManifest(
            GroupEnvelopeEncryptor::packFileManifest(fileKey, {{.plainSize = 131073, .digest = digest}}), readKey
        ),
        InvalidEnvelopeFormatException
    );
}

// -- sequences -----------------------------------------------------------------------------------------

class GroupSequenceWire : public GroupEnvelopeContent {
protected:
    std::string key = privmx::crypto::Crypto::randomBytes(32);
    core::Buffer header = enc.packMemberEnvelope(groupId, keyId, buf(key), author, groupKey, sealOf(EnvelopeContent::Sequence));
    std::string id = GroupEnvelopeEncryptor::sequenceIdOf(header);
    std::string authorPub = author.getPublicKey().toBase58DER();
};

TEST_F(GroupSequenceWire, ItemRoundTripAndPlainHeader) {
    const core::Buffer item = enc.packSequenceItem(id, key, 5, buf("edit"));
    const auto wire = GroupEnvelopeEncryptor::parseSequenceWire(item);
    EXPECT_FALSE(wire.isMark);
    EXPECT_EQ(wire.sequenceId, id);
    EXPECT_EQ(wire.index, 5u);
    EXPECT_EQ(enc.openSequenceItem(wire, key).stdString(), "edit");
    // A message envelope is not an item, and the other way round.
    EXPECT_THROW(GroupEnvelopeEncryptor::parseSequenceWire(header), InvalidEnvelopeFormatException);
    EXPECT_THROW(GroupEnvelopeEncryptor::peekAny(item), InvalidEnvelopeFormatException);
    EXPECT_THROW(GroupEnvelopeEncryptor::parseSequenceWire(buf(item.stdString().substr(0, 10))), InvalidEnvelopeFormatException);
}

TEST_F(GroupSequenceWire, AnItemOpensOnlyAtItsPositionInItsSequence) {
    const core::Buffer item = enc.packSequenceItem(id, key, 5, buf("edit"));
    auto wire = GroupEnvelopeEncryptor::parseSequenceWire(item);
    wire.index = 6; // moved, or replayed as a later one
    EXPECT_ANY_THROW(enc.openSequenceItem(wire, key));
    wire.index = 5;
    EXPECT_ANY_THROW(enc.openSequenceItem(wire, privmx::crypto::Crypto::randomBytes(32))); // another sequence
    EXPECT_ANY_THROW(enc.openSequenceItem(GroupEnvelopeEncryptor::parseSequenceWire(buf(flipped(item, item.size() - 1))), key));
}

TEST_F(GroupSequenceWire, AMarkIsTheAuthorsAndCoversThisSequenceAndCount) {
    const GroupEnvelopeEncryptor::SequenceMark mark{.count = 3, .closed = true, .transcript = privmx::crypto::Crypto::sha256("t")};
    const core::Buffer packed = enc.packSequenceMark(id, key, mark, author);
    const auto wire = GroupEnvelopeEncryptor::parseSequenceWire(packed);
    EXPECT_TRUE(wire.isMark);
    EXPECT_EQ(wire.index, 3u);
    const auto opened = enc.openSequenceMark(wire, key, authorPub);
    EXPECT_EQ(opened.count, 3u);
    EXPECT_TRUE(opened.closed);
    EXPECT_EQ(opened.transcript, mark.transcript);

    // Every member holds `key`, so a member can seal a mark - but not sign it as the author.
    const core::Buffer forged = enc.packSequenceMark(id, key, mark, PrivateKey::generateRandom());
    EXPECT_ANY_THROW(enc.openSequenceMark(GroupEnvelopeEncryptor::parseSequenceWire(forged), key, authorPub));
    // The author's mark for one count, relabelled as another, or lifted into another sequence of theirs.
    auto relabelled = wire;
    relabelled.index = 4;
    EXPECT_THROW(enc.openSequenceMark(relabelled, key, authorPub), InvalidEnvelopeFormatException);
    relabelled = wire;
    relabelled.sequenceId = std::string(16, 'x');
    EXPECT_THROW(enc.openSequenceMark(relabelled, key, authorPub), InvalidEnvelopeFormatException);
}

TEST_F(GroupSequenceWire, TheIdAndTheTranscriptFollowFromTheBytes) {
    EXPECT_EQ(id.size(), GroupEnvelopeEncryptor::SEQUENCE_ID_SIZE);
    EXPECT_NE(id, GroupEnvelopeEncryptor::sequenceIdOf(buf(flipped(header, header.size() - 1))));
    const std::string start = GroupEnvelopeEncryptor::sequenceTranscriptStart(id);
    const core::Buffer a = enc.packSequenceItem(id, key, 0, buf("a"));
    const core::Buffer b = enc.packSequenceItem(id, key, 1, buf("b"));
    const auto next = GroupEnvelopeEncryptor::sequenceTranscriptNext;
    EXPECT_NE(next(next(start, a), b), next(next(start, b), a));
    EXPECT_NE(next(start, a), next(start, buf(flipped(a, a.size() - 1))));
}

// -- spaces --------------------------------------------------------------------------------------------

class GroupSpaceWire : public GroupEnvelopeContent {
protected:
    using Slot = GroupEnvelopeEncryptor::SpaceKeySlot;
    std::string spaceKey = privmx::crypto::Crypto::randomBytes(32);
    std::string spaceId = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    PrivateKey recipient = PrivateKey::generateRandom();
    Slot slot{.spaceId = spaceId, .keyVersion = 2, .isGroup = true, .recipientId = "sales", .groupKeyVersion = 5};
    GroupEnvelopeEncryptor::SpaceKeyWrap wrap =
        enc.wrapSpaceKey(spaceKey, slot, recipient.getPublicKey(), "alice", author);
};

TEST_F(GroupSpaceWire, EnvelopeRoundTripAndPlainHeader) {
    const core::Buffer env = enc.packSpaceEnvelope(spaceId, "sales", buf("note"), author, spaceKey, seal);
    const auto routing = GroupEnvelopeEncryptor::peekAny(env);
    EXPECT_EQ(routing.spaceId, spaceId);
    EXPECT_EQ(routing.groupId, "sales");
    EXPECT_EQ(routing.keyVersion, 7);
    EXPECT_EQ(routing.authorUserId, "alice");

    const OpenedEnvelope opened = enc.openSpaceEnvelope(env, spaceKey, none);
    EXPECT_EQ(opened.data.stdString(), "note");
    EXPECT_EQ(opened.groupId, "sales");
    EXPECT_EQ(opened.keyVersion, 7);
    EXPECT_EQ(opened.authorPubKey, author.getPublicKey().toBase58DER());
    EXPECT_EQ(opened.encryptedAt, 1700000000000);

    EXPECT_ANY_THROW(enc.openSpaceEnvelope(env, privmx::crypto::Crypto::randomBytes(32), none));
    EXPECT_THROW(
        enc.openSpaceEnvelope(env, spaceKey, GroupEnvelopeEncryptor::bindLocation({{false, buf("x")}})),
        EnvelopeWrongLocationException
    );
}

TEST_F(GroupSpaceWire, ASpaceEnvelopeAndAMembersNeverOpenAsEachOther) {
    // The same 32 bytes as both keys: only the type keeps them apart, and the type is in the signed header.
    const core::Buffer inSpace = enc.packSpaceEnvelope(spaceId, "", buf("note"), author, groupKey, seal);
    const core::Buffer inGroup = enc.packMemberEnvelope(groupId, keyId, buf("note"), author, groupKey, seal);
    EXPECT_THROW(enc.openMemberEnvelope(inSpace, groupKey, none), InvalidEnvelopeFormatException);
    EXPECT_THROW(enc.openSpaceEnvelope(inGroup, groupKey, none), InvalidEnvelopeFormatException);
    std::string relabelled = inSpace.stdString();
    relabelled[1] = 1; // TYPE_SPACE -> TYPE_GROUP_KEY
    EXPECT_ANY_THROW(enc.openMemberEnvelope(buf(relabelled), groupKey, none));
    // The Space, the group written through and the key version are signed.
    for (const std::size_t at : {std::size_t{4}, std::size_t{12}}) {
        EXPECT_ANY_THROW(enc.openSpaceEnvelope(buf(flipped(enc.packSpaceEnvelope(spaceId, "sales", buf("n"), author, spaceKey, seal), at)), spaceKey, none));
    }
    // A Space is named: an envelope cannot be in none.
    EXPECT_THROW(
        GroupEnvelopeEncryptor::peekAny(enc.packSpaceEnvelope("", "sales", buf("n"), author, spaceKey, seal)),
        InvalidEnvelopeFormatException
    );
}

TEST_F(GroupSpaceWire, AKeyWrapOpensForItsSpaceVersionAndRecipientOnly) {
    EXPECT_EQ(enc.unwrapSpaceKey(wrap, slot, recipient), spaceKey);
    const auto header = GroupEnvelopeEncryptor::peekSpaceKeyWrap(wrap.data);
    EXPECT_EQ(header.signerUserId, "alice");
    EXPECT_EQ(header.signerPubKey, author.getPublicKey().toBase58DER());
    EXPECT_EQ(header.recipientPubKey, recipient.getPublicKey().toBase58DER());

    // The Bridge files it under another Space, version, recipient or epoch: the signature says where it belongs.
    Slot other = slot;
    other.spaceId[0] = 'f';
    EXPECT_THROW(enc.unwrapSpaceKey(wrap, other, recipient), InvalidEnvelopeFormatException);
    other = slot;
    other.keyVersion = 3;
    EXPECT_THROW(enc.unwrapSpaceKey(wrap, other, recipient), InvalidEnvelopeFormatException);
    other = slot;
    other.recipientId = "support";
    EXPECT_THROW(enc.unwrapSpaceKey(wrap, other, recipient), InvalidEnvelopeFormatException);
    other = slot;
    other.isGroup = false;
    EXPECT_THROW(enc.unwrapSpaceKey(wrap, other, recipient), InvalidEnvelopeFormatException);
    other = slot;
    other.groupKeyVersion = 6;
    EXPECT_THROW(enc.unwrapSpaceKey(wrap, other, recipient), InvalidEnvelopeFormatException);
    // Not the key it is wrapped to.
    EXPECT_ANY_THROW(enc.unwrapSpaceKey(wrap, slot, PrivateKey::generateRandom()));
}

TEST_F(GroupSpaceWire, SECURITY_AKeyWrapNamesWhoMadeItAndTheSignatureHoldsThemToIt) {
    // The Bridge wraps a key it knows for the recipient. It can sign with a key of its own, and then the wrap names
    // that key: the caller's UserVerifier is asked about it, and says no.
    const PrivateKey bridge = PrivateKey::generateRandom();
    const std::string bridgeKey = privmx::crypto::Crypto::randomBytes(32);
    const auto planted = enc.wrapSpaceKey(bridgeKey, slot, recipient.getPublicKey(), "alice", bridge);
    EXPECT_EQ(GroupEnvelopeEncryptor::peekSpaceKeyWrap(planted.data).signerPubKey, bridge.getPublicKey().toBase58DER());
    // What it cannot do is keep alice's key in the header: her signature is not on its data.
    GroupEnvelopeEncryptor::SpaceKeyWrap spliced{.data = planted.data, .signature = wrap.signature};
    EXPECT_ANY_THROW(enc.unwrapSpaceKey(spliced, slot, recipient));
    spliced = {.data = wrap.data, .signature = planted.signature};
    EXPECT_ANY_THROW(enc.unwrapSpaceKey(spliced, slot, recipient));
    // Nor change a byte of a wrap alice made.
    spliced = {.data = wrap.data, .signature = wrap.signature};
    spliced.data[spliced.data.size() - 1] ^= 0x01;
    EXPECT_ANY_THROW(enc.unwrapSpaceKey(spliced, slot, recipient));
    spliced = {.data = wrap.data + "x", .signature = wrap.signature};
    EXPECT_ANY_THROW(enc.unwrapSpaceKey(spliced, slot, recipient));
}

TEST_F(GroupSpaceWire, SECURITY_AnEnvelopeKeyWrapIsNotASpaceKeyAndTheOtherWayRound) {
    // Both are ECIES to a group's identity key. An anonymous envelope's content key, lifted into a Space key wrap,
    // would make a key the sender of that envelope knows the Space's key.
    const core::Buffer anonymous = enc.packAnonymousEnvelope(groupId, recipient.getPublicKey(), buf("x"), none);
    EnvelopeReader cursor(anonymous.stdString());
    cursor.skip(3);
    cursor.readField();
    cursor.readField();
    const std::string contentKeyWrap = cursor.readField();

    std::string data(1, '\x01');
    EnvelopeWriter::putField(data, "alice");
    EnvelopeWriter::putField(data, author.getPublicKey().toDER());
    EnvelopeWriter::putField(data, recipient.getPublicKey().toBase58DER());
    EnvelopeWriter::putField(data, contentKeyWrap);
    // Signed properly by a member, so only the domain stands between the two.
    core::DataInnerEncryptorV4 raw;
    std::string preimage = "privmx/space/key";
    EnvelopeWriter::putField(preimage, slot.spaceId);
    preimage += EnvelopeWriter::toBE(2, 8);
    preimage.push_back('\x01');
    EnvelopeWriter::putField(preimage, slot.recipientId);
    preimage += EnvelopeWriter::toBE(5, 8);
    const GroupEnvelopeEncryptor::SpaceKeyWrap lifted{
        .data = data,
        .signature =
            raw.signAndPackDataWithSignature(buf(privmx::crypto::Crypto::sha256(preimage + data)), author).stdString(),
    };
    EXPECT_THROW(enc.unwrapSpaceKey(lifted, slot, recipient), InvalidEnvelopeFormatException);
    // The control: the same construction over a real Space key wrap opens.
    std::string good(1, '\x01');
    EnvelopeReader real(wrap.data);
    real.skip(1);
    EnvelopeWriter::putField(good, real.readField());
    EnvelopeWriter::putField(good, real.readField());
    EnvelopeWriter::putField(good, real.readField());
    EnvelopeWriter::putField(good, real.readField());
    EXPECT_EQ(good, wrap.data);
    const GroupEnvelopeEncryptor::SpaceKeyWrap resigned{
        .data = good,
        .signature =
            raw.signAndPackDataWithSignature(buf(privmx::crypto::Crypto::sha256(preimage + good)), author).stdString(),
    };
    EXPECT_EQ(enc.unwrapSpaceKey(resigned, slot, recipient), spaceKey);
}

TEST_F(GroupSpaceWire, SECURITY_AValueOfTheApplicationIsNeverTheSpacesMetadata) {
    // Every recipient can write a value at any location. The metadata is not at a location: it is a content kind
    // of its own, in the signed header, that no write of a value produces.
    const EnvelopeBinding meta{.hasLocation = false, .locationDigest = {}, .content = EnvelopeContent::SpaceMeta};
    EnvelopeSeal metaSeal = seal;
    metaSeal.binding = meta;
    const core::Buffer real = enc.packSpaceEnvelope(spaceId, "", buf("budget"), author, spaceKey, metaSeal);
    EXPECT_EQ(enc.openSpaceEnvelope(real, spaceKey, meta).data.stdString(), "budget");
    EXPECT_THROW(enc.peek(real), InvalidEnvelopeFormatException);

    const core::Buffer value = enc.packSpaceEnvelope(spaceId, "", buf("budget 0"), author, spaceKey, seal);
    EXPECT_THROW(enc.peek(value, EnvelopeContent::SpaceMeta), InvalidEnvelopeFormatException);
    EXPECT_THROW(enc.openSpaceEnvelope(value, spaceKey, meta), InvalidEnvelopeFormatException);
    std::string relabelled = value.stdString();
    relabelled[2] = 0x06; // the flags octet says "metadata"; the signed header still says "a message"
    EXPECT_THROW(enc.openSpaceEnvelope(buf(relabelled), spaceKey, meta), InvalidEnvelopeFormatException);
}
