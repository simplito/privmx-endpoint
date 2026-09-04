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

#include <privmx/endpoint/group/GroupException.hpp>
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

    core::Buffer buf(const std::string& s) { return core::Buffer::from(s); }
};

// -- round trips ---------------------------------------------------------------------------------------

TEST_F(GroupEnvelope, GroupKeyRoundTrip) {
    core::Buffer env = enc.packGroupKeyEnvelope(groupId, keyId, buf("hello group"), author, groupKey);
    DecryptedEnvelope out = enc.openGroupKeyEnvelope(env, groupKey);

    EXPECT_EQ(out.data.stdString(), "hello group");
    EXPECT_EQ(out.groupId, groupId);
    EXPECT_EQ(out.authorPubKey, author.getPublicKey().toBase58DER());
    EXPECT_EQ(out.type, ENVELOPE_FROM_MEMBER);
}

TEST_F(GroupEnvelope, AnonymousRoundTripAndCarriesNoAuthor) {
    core::Buffer env = enc.packAnonymousEnvelope(groupId, grantKey.getPublicKey(), buf("from outside"));
    DecryptedEnvelope out = enc.openAnonymousEnvelope(env, grantKey);

    EXPECT_EQ(out.data.stdString(), "from outside");
    EXPECT_EQ(out.groupId, groupId);
    EXPECT_EQ(out.type, ENVELOPE_ANONYMOUS);
    // A throwaway sender key attests to nothing, so nothing is reported.
    EXPECT_TRUE(out.authorPubKey.empty());
}

TEST_F(GroupEnvelope, AnonymousEnvelopesAreNotDeterministic) {
    // The ECIES layer derives its IV from the sender key, so a fixed sender would leak plaintext equality.
    // A fresh ephemeral key per call is what stops that.
    core::Buffer a = enc.packAnonymousEnvelope(groupId, grantKey.getPublicKey(), buf("same"));
    core::Buffer b = enc.packAnonymousEnvelope(groupId, grantKey.getPublicKey(), buf("same"));
    EXPECT_NE(a.stdString(), b.stdString());
}

TEST_F(GroupEnvelope, EmptyContentRoundTrips) {
    core::Buffer env = enc.packGroupKeyEnvelope(groupId, keyId, buf(""), author, groupKey);
    EXPECT_EQ(enc.openGroupKeyEnvelope(env, groupKey).data.stdString(), "");
}

TEST_F(GroupEnvelope, PeekRoutesWithoutOpening) {
    auto r1 = enc.peek(enc.packGroupKeyEnvelope(groupId, keyId, buf("x"), author, groupKey));
    EXPECT_EQ(r1.type, ENVELOPE_FROM_MEMBER);
    EXPECT_EQ(r1.groupId, groupId);
    EXPECT_EQ(r1.keyId, keyId);

    auto r2 = enc.peek(enc.packAnonymousEnvelope(groupId, grantKey.getPublicKey(), buf("x")));
    EXPECT_EQ(r2.type, ENVELOPE_ANONYMOUS);
    EXPECT_EQ(r2.groupPubKey, grantKey.getPublicKey().toBase58DER());
}

// -- the ladder-rung oracle ----------------------------------------------------------------------------

TEST_F(GroupEnvelope, LadderRungIsNotAnEnvelope) {
    // Exactly what `TreeKeys::wrapKey` produces: a past epoch's grant private key, ECIES-wrapped to the
    // group's grant public key. Byte-identical in construction to a type 2 key wrap, addressed to the same
    // key. If `openAnonymousEnvelope` accepted it, it would return that private key as message content and
    // walk past every era-floor and pruning check the ladder exists to enforce.
    PrivateKey pastEpochKey = PrivateKey::generateRandom();
    std::string rung = privmx::crypto::EciesEncryptor::encrypt(
        grantKey.getPublicKey(), pastEpochKey.toWIF(), PrivateKey::generateRandom()
    );

    std::string forged;
    forged.push_back(static_cast<char>(GroupEnvelopeEncryptor::VERSION));
    forged.push_back(2); // TYPE_ANONYMOUS
    forged.push_back(static_cast<char>(groupId.size()));
    forged.append(groupId);
    std::string pub = grantKey.getPublicKey().toBase58DER();
    forged.push_back(static_cast<char>(pub.size()));
    forged.append(pub);
    forged.push_back(static_cast<char>(rung.size()));
    forged.append(rung);
    forged.append(privmx::crypto::Crypto::randomBytes(64)); // payload never gets reached

    EXPECT_THROW(enc.openAnonymousEnvelope(buf(forged), grantKey), InvalidEnvelopeFormatException);
}

TEST_F(GroupEnvelope, AnonymousRejectsAMismatchedGroupKey) {
    // A hostile server steering us onto the wrong epoch's key must not leave ECIES's 4-byte checksum as the
    // only thing between us and a wrong answer.
    core::Buffer env = enc.packAnonymousEnvelope(groupId, grantKey.getPublicKey(), buf("x"));
    EXPECT_THROW(enc.openAnonymousEnvelope(env, PrivateKey::generateRandom()), InvalidEnvelopeFormatException);
}

// -- header authentication -----------------------------------------------------------------------------

TEST_F(GroupEnvelope, HeaderIsSignedSoAnEnvelopeCannotBeReplayedIntoAnotherGroup) {
    // A member of both groups holds both keys. They open Alice's envelope in group A and re-seal the *same
    // signed inner blob* under group B's key with a group B header. Alice's signature still verifies — so
    // only the header being inside that signature stops her "yes" in one group becoming a "yes" in another.
    core::Buffer envA = enc.packGroupKeyEnvelope("groupA", keyId, buf("approve"), author, groupKey);

    std::string otherKey = privmx::crypto::Crypto::randomBytes(32);
    core::DataInnerEncryptorV4 raw;
    std::size_t headerLen = 2 + 1 + std::string("groupA").size() + 1 + keyId.size() + 1 + 33;
    core::Buffer sealed = raw.decrypt(buf(envA.stdString().substr(headerLen)), groupKey);

    std::string forgedHeader;
    forgedHeader.push_back(static_cast<char>(GroupEnvelopeEncryptor::VERSION));
    forgedHeader.push_back(1);
    std::string other = "groupB";
    forgedHeader.push_back(static_cast<char>(other.size()));
    forgedHeader.append(other);
    forgedHeader.push_back(static_cast<char>(keyId.size()));
    forgedHeader.append(keyId);
    std::string der = author.getPublicKey().toDER();
    forgedHeader.push_back(static_cast<char>(der.size()));
    forgedHeader.append(der);

    core::Buffer forged = buf(forgedHeader + raw.encrypt(sealed, otherKey).stdString());
    EXPECT_THROW(enc.openGroupKeyEnvelope(forged, otherKey), InvalidEnvelopeFormatException);
}

TEST_F(GroupEnvelope, TypeCannotBeRelabelled) {
    // Relabelling a file envelope as a message would hand back the file key as content.
    std::string fileKey = privmx::crypto::Crypto::randomBytes(32);
    core::Buffer env = enc.packFileEnvelope(groupId, keyId, 10, fileKey, author, groupKey);

    std::string relabelled = env.stdString();
    relabelled[1] = 1; // TYPE_FILE -> TYPE_GROUP_KEY
    EXPECT_THROW(enc.openGroupKeyEnvelope(buf(relabelled), groupKey), InvalidEnvelopeFormatException);

    // And a file envelope must not route through the message dispatcher at all.
    EXPECT_THROW(enc.peek(env), InvalidEnvelopeFormatException);
}

TEST_F(GroupEnvelope, TamperedHeaderFieldsAreRejected) {
    core::Buffer env = enc.packGroupKeyEnvelope(groupId, keyId, buf("x"), author, groupKey);
    for (std::size_t i = 2; i < 2 + 1 + groupId.size() + 1 + keyId.size(); ++i) {
        std::string tampered = env.stdString();
        tampered[i] = static_cast<char>(tampered[i] ^ 0x01);
        EXPECT_ANY_THROW(enc.openGroupKeyEnvelope(buf(tampered), groupKey)) << "byte " << i;
    }
}

TEST_F(GroupEnvelope, WrongGroupKeyIsRejected) {
    core::Buffer env = enc.packGroupKeyEnvelope(groupId, keyId, buf("x"), author, groupKey);
    EXPECT_ANY_THROW(enc.openGroupKeyEnvelope(env, privmx::crypto::Crypto::randomBytes(32)));
}

TEST_F(GroupEnvelope, TamperedCiphertextIsRejected) {
    core::Buffer env = enc.packGroupKeyEnvelope(groupId, keyId, buf("payload here"), author, groupKey);
    std::string tampered = env.stdString();
    tampered[tampered.size() - 1] = static_cast<char>(tampered[tampered.size() - 1] ^ 0x01);
    EXPECT_ANY_THROW(enc.openGroupKeyEnvelope(buf(tampered), groupKey));
}

// -- malformed input -----------------------------------------------------------------------------------

TEST_F(GroupEnvelope, TruncatedEnvelopesThrowRatherThanParseGarbage) {
    for (const std::string& junk : {std::string(""), std::string("\x01"), std::string("\x01\x01\x40")}) {
        EXPECT_THROW(enc.peek(buf(junk)), InvalidEnvelopeFormatException) << "len " << junk.size();
        EXPECT_THROW(enc.openGroupKeyEnvelope(buf(junk), groupKey), InvalidEnvelopeFormatException);
    }
}

TEST_F(GroupEnvelope, UnsupportedVersionIsRejected) {
    core::Buffer env = enc.packGroupKeyEnvelope(groupId, keyId, buf("x"), author, groupKey);
    std::string bumped = env.stdString();
    bumped[0] = 99;
    EXPECT_THROW(enc.peek(buf(bumped)), InvalidEnvelopeFormatException);
}

TEST_F(GroupEnvelope, OversizedFieldThrowsInsteadOfTruncating) {
    // One length octet on the wire; a silent wrap would produce an envelope that parses into the wrong group.
    EXPECT_THROW(
        enc.packGroupKeyEnvelope(std::string(256, 'a'), keyId, buf("x"), author, groupKey),
        InvalidEnvelopeFormatException
    );
}

// -- files ---------------------------------------------------------------------------------------------

TEST_F(GroupEnvelope, FileEnvelopeRoundTrip) {
    std::string fileKey = privmx::crypto::Crypto::randomBytes(32);
    core::Buffer env = enc.packFileEnvelope(groupId, keyId, 4096, fileKey, author, groupKey);
    auto header = enc.unpackFileEnvelope(env, groupKey);

    EXPECT_EQ(header.groupId, groupId);
    EXPECT_EQ(header.keyId, keyId);
    EXPECT_EQ(header.authorPubKey, author.getPublicKey().toBase58DER());
    EXPECT_EQ(header.plainSize, 4096u);
    EXPECT_EQ(header.fileKey, fileKey);
}

TEST_F(GroupEnvelope, ChunkRoundTripAndSizeIsPredictable) {
    std::string fileKey = privmx::crypto::Crypto::randomBytes(32);
    std::string plain(GroupEnvelopeEncryptor::CHUNK_SIZE, 'z');

    core::Buffer cipher = enc.encryptChunk(buf(plain), fileKey, 0);
    // The read side slices the stream by this constant, so it must hold exactly.
    EXPECT_EQ(cipher.size(), GroupEnvelopeEncryptor::ENCRYPTED_CHUNK_SIZE);
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

TEST_F(GroupEnvelope, ChunkCountHasNoTrailingEmptyChunk) {
    constexpr ByteCount C = GroupEnvelopeEncryptor::CHUNK_SIZE;
    EXPECT_EQ(GroupEnvelopeEncryptor::chunkCount(0), 0u);
    EXPECT_EQ(GroupEnvelopeEncryptor::chunkCount(1), 1u);
    EXPECT_EQ(GroupEnvelopeEncryptor::chunkCount(C - 1), 1u);
    EXPECT_EQ(GroupEnvelopeEncryptor::chunkCount(C), 1u); // exact multiple: no extra empty chunk
    EXPECT_EQ(GroupEnvelopeEncryptor::chunkCount(C + 1), 2u);
    EXPECT_EQ(GroupEnvelopeEncryptor::chunkCount(2 * C), 2u);
}

TEST_F(GroupEnvelope, FileEnvelopeRejectsAnUnsignedSizeChange) {
    // `plainSize` is the only thing that makes a dropped trailing chunk detectable, so it has to be inside
    // the signature rather than alongside it.
    std::string fileKey = privmx::crypto::Crypto::randomBytes(32);
    core::Buffer env = enc.packFileEnvelope(groupId, keyId, 999999, fileKey, author, groupKey);
    std::string tampered = env.stdString();
    tampered[tampered.size() - 1] = static_cast<char>(tampered[tampered.size() - 1] ^ 0x01);
    EXPECT_ANY_THROW(enc.unpackFileEnvelope(buf(tampered), groupKey));
}

/**
 * The streaming boundary arithmetic, which `GroupApiImpl` drives but does not own.
 *
 * Both directions find chunk edges purely from the signed `plainSize` — no framing on the wire says where a
 * chunk ends. So the sizes have to agree exactly, at every awkward length, or a stream desynchronises and
 * every later chunk fails to open. That is what these exercise; the API-level plumbing is covered e2e.
 */
TEST_F(GroupEnvelope, StreamingRoundTripAtAwkwardSizes) {
    constexpr ByteCount C = GroupEnvelopeEncryptor::CHUNK_SIZE;
    const std::vector<ByteCount> sizes = {0, 1, 15, 16, 17, C - 1, C, C + 1, 2 * C, 2 * C + 3, 3 * C - 1};

    for (ByteCount size : sizes) {
        std::string fileKey = privmx::crypto::Crypto::randomBytes(32);
        std::string plain;
        plain.reserve(size);
        for (ByteCount i = 0; i < size; ++i) {
            plain.push_back(static_cast<char>('a' + (i % 26)));
        }

        // Seal, slicing exactly the way the write path does.
        std::string cipher;
        const ChunkCount chunks = GroupEnvelopeEncryptor::chunkCount(size);
        for (ChunkIndex i = 0; i < chunks; ++i) {
            const ByteCount len = GroupEnvelopeEncryptor::plainChunkSizeAt(size, i);
            cipher.append(enc.encryptChunk(buf(plain.substr(i * C, len)), fileKey, i).stdString());
        }

        // Open, taking each chunk's sealed length from the declared size alone — the read path's only clue.
        std::string recovered;
        std::size_t offset = 0;
        for (ChunkIndex i = 0; i < chunks; ++i) {
            const ByteCount need = GroupEnvelopeEncryptor::encryptedChunkSizeFor(
                GroupEnvelopeEncryptor::plainChunkSizeAt(size, i)
            );
            ASSERT_LE(offset + need, cipher.size()) << "size " << size << " chunk " << i;
            recovered.append(enc.decryptChunk(buf(cipher.substr(offset, need)), fileKey, i).stdString());
            offset += need;
        }
        // Nothing left over: the predicted lengths accounted for every byte produced.
        EXPECT_EQ(offset, cipher.size()) << "size " << size;
        EXPECT_EQ(recovered, plain) << "size " << size;
    }
}

TEST_F(GroupEnvelope, DroppedTrailingChunkIsOnlyCaughtByTheDeclaredSize) {
    // Two full chunks arrive intact and verify individually; the third never comes. Nothing in chunk 2 says a
    // chunk 3 was owed, so only the signed size in the envelope can notice.
    constexpr ByteCount C = GroupEnvelopeEncryptor::CHUNK_SIZE;
    const ByteCount size = 2 * C + 100;
    EXPECT_EQ(GroupEnvelopeEncryptor::chunkCount(size), 3u);

    std::string fileKey = privmx::crypto::Crypto::randomBytes(32);
    core::Buffer chunk0 = enc.encryptChunk(buf(std::string(C, 'a')), fileKey, 0);
    core::Buffer chunk1 = enc.encryptChunk(buf(std::string(C, 'b')), fileKey, 1);
    // Both open cleanly on their own — that is exactly why the count has to come from somewhere else.
    EXPECT_NO_THROW(enc.decryptChunk(chunk0, fileKey, 0));
    EXPECT_NO_THROW(enc.decryptChunk(chunk1, fileKey, 1));

    const std::size_t delivered = chunk0.size() + chunk1.size();
    std::size_t expected = 0;
    for (ChunkIndex i = 0; i < 3; ++i) {
        expected += GroupEnvelopeEncryptor::encryptedChunkSizeFor(
            GroupEnvelopeEncryptor::plainChunkSizeAt(size, i)
        );
    }
    EXPECT_LT(delivered, expected); // the shortfall the close-time check turns into a refusal
}

// -- anonymous files (type 4) --------------------------------------------------------------------------

TEST_F(GroupEnvelope, AnonymousFileEnvelopeRoundTrip) {
    std::string fileKey = privmx::crypto::Crypto::randomBytes(32);
    core::Buffer env = enc.packAnonymousFileEnvelope(groupId, grantKey.getPublicKey(), 4096, fileKey);
    auto header = enc.unpackAnonymousFileEnvelope(env, grantKey);

    EXPECT_EQ(header.type, ENVELOPE_ANONYMOUS);
    EXPECT_EQ(header.groupId, groupId);
    EXPECT_EQ(header.plainSize, 4096u);
    EXPECT_EQ(header.fileKey, fileKey);
    // Nothing to attribute: the sender sealed with a throwaway key.
    EXPECT_TRUE(header.authorPubKey.empty());
    EXPECT_TRUE(header.keyId.empty());
}

TEST_F(GroupEnvelope, AnonymousFileBodyIsIdenticalToAMemberFileBody) {
    // The two file types differ only in how the header wraps the file key. If the bodies ever diverged, the
    // shared chunk arithmetic and the shared streaming path would both be silently wrong for one of them.
    std::string fileKey = privmx::crypto::Crypto::randomBytes(32);
    core::Buffer memberEnv = enc.packFileEnvelope(groupId, keyId, 100, fileKey, author, groupKey);
    core::Buffer anonEnv = enc.packAnonymousFileEnvelope(groupId, grantKey.getPublicKey(), 100, fileKey);

    auto a = enc.unpackFileEnvelope(memberEnv, groupKey);
    auto b = enc.unpackAnonymousFileEnvelope(anonEnv, grantKey);
    EXPECT_EQ(a.fileKey, b.fileKey);
    EXPECT_EQ(a.plainSize, b.plainSize);
    EXPECT_EQ(a.type, ENVELOPE_FROM_MEMBER);
    EXPECT_EQ(b.type, ENVELOPE_ANONYMOUS);
}

TEST_F(GroupEnvelope, AnonymousFileIsNotALadderRungOracleEither) {
    // Type 4 unwraps an attacker-supplied ECIES blob with the group's grant key, exactly as type 2 does, so
    // it needs the same domain separation — otherwise closing the hole for messages just moved it to files.
    PrivateKey pastEpochKey = PrivateKey::generateRandom();
    std::string rung = privmx::crypto::EciesEncryptor::encrypt(
        grantKey.getPublicKey(), pastEpochKey.toWIF(), PrivateKey::generateRandom()
    );

    std::string forged;
    forged.push_back(static_cast<char>(GroupEnvelopeEncryptor::VERSION));
    forged.push_back(4); // TYPE_ANON_FILE
    forged.push_back(static_cast<char>(groupId.size()));
    forged.append(groupId);
    std::string pub = grantKey.getPublicKey().toBase58DER();
    forged.push_back(static_cast<char>(pub.size()));
    forged.append(pub);
    forged.push_back(static_cast<char>(rung.size()));
    forged.append(rung);
    forged.append(privmx::crypto::Crypto::randomBytes(64));

    EXPECT_THROW(enc.unpackAnonymousFileEnvelope(buf(forged), grantKey), InvalidEnvelopeFormatException);
}

TEST_F(GroupEnvelope, AnonymousFileRejectsAMismatchedGroupKey) {
    core::Buffer env = enc.packAnonymousFileEnvelope(groupId, grantKey.getPublicKey(), 10, groupKey);
    EXPECT_THROW(
        enc.unpackAnonymousFileEnvelope(env, PrivateKey::generateRandom()), InvalidEnvelopeFormatException
    );
}

TEST_F(GroupEnvelope, FileTypesCannotBeSwappedForEachOther) {
    std::string fileKey = privmx::crypto::Crypto::randomBytes(32);
    core::Buffer memberEnv = enc.packFileEnvelope(groupId, keyId, 10, fileKey, author, groupKey);
    core::Buffer anonEnv = enc.packAnonymousFileEnvelope(groupId, grantKey.getPublicKey(), 10, fileKey);

    EXPECT_THROW(enc.unpackAnonymousFileEnvelope(memberEnv, grantKey), InvalidEnvelopeFormatException);
    EXPECT_THROW(enc.unpackFileEnvelope(anonEnv, groupKey), InvalidEnvelopeFormatException);

    // Relabelling the type byte must not work either: the header is sealed inside the payload.
    std::string relabelled = anonEnv.stdString();
    relabelled[1] = 3;
    EXPECT_ANY_THROW(enc.unpackFileEnvelope(buf(relabelled), groupKey));
}

TEST_F(GroupEnvelope, PeekFileRoutesBothKindsAndRejectsMessages) {
    std::string fileKey = privmx::crypto::Crypto::randomBytes(32);
    auto member = enc.peekFile(enc.packFileEnvelope(groupId, keyId, 10, fileKey, author, groupKey));
    EXPECT_EQ(member.type, ENVELOPE_FROM_MEMBER);
    EXPECT_EQ(member.keyId, keyId);

    auto anon = enc.peekFile(enc.packAnonymousFileEnvelope(groupId, grantKey.getPublicKey(), 10, fileKey));
    EXPECT_EQ(anon.type, ENVELOPE_ANONYMOUS);
    EXPECT_EQ(anon.groupPubKey, grantKey.getPublicKey().toBase58DER());

    // A message envelope has no body to stream; routing it here would hand back a handle onto nothing.
    EXPECT_THROW(enc.peekFile(enc.packGroupKeyEnvelope(groupId, keyId, buf("x"), author, groupKey)),
                 InvalidEnvelopeFormatException);
    EXPECT_THROW(enc.peekFile(enc.packAnonymousEnvelope(groupId, grantKey.getPublicKey(), buf("x"))),
                 InvalidEnvelopeFormatException);
    // ...and conversely a file envelope must not route through the message dispatcher.
    EXPECT_THROW(enc.peek(enc.packAnonymousFileEnvelope(groupId, grantKey.getPublicKey(), 10, fileKey)),
                 InvalidEnvelopeFormatException);
}

// -- random access -------------------------------------------------------------------------------------

TEST_F(GroupEnvelope, CipherOffsetOfChunkMatchesAnActualStream) {
    // The seek is a multiplication, not a lookup, and that is only sound because every chunk but the last is
    // exactly ENCRYPTED_CHUNK_SIZE. If that ever stopped holding, seeking would land mid-chunk and every
    // subsequent chunk would fail to open — so pin it against a stream actually produced.
    constexpr ByteCount C = GroupEnvelopeEncryptor::CHUNK_SIZE;
    const ByteCount size = 4 * C + 77;
    std::string fileKey = privmx::crypto::Crypto::randomBytes(32);

    std::string cipher;
    std::vector<std::size_t> realOffsets;
    for (ChunkIndex i = 0; i < GroupEnvelopeEncryptor::chunkCount(size); ++i) {
        realOffsets.push_back(cipher.size());
        const ByteCount len = GroupEnvelopeEncryptor::plainChunkSizeAt(size, i);
        cipher.append(enc.encryptChunk(buf(std::string(len, 'k')), fileKey, i).stdString());
    }
    for (ChunkIndex i = 0; i < realOffsets.size(); ++i) {
        EXPECT_EQ(GroupEnvelopeEncryptor::cipherOffsetOfChunk(i), realOffsets[i]) << "chunk " << i;
    }
}

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
