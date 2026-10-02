#ifndef _PRIVMXLIB_ENDPOINT_GROUP_ENCRYPTORS_ENVELOPE_GROUPENVELOPEENCRYPTOR_HPP_
#define _PRIVMXLIB_ENDPOINT_GROUP_ENCRYPTORS_ENVELOPE_GROUPENVELOPEENCRYPTOR_HPP_

#include <cassert>
#include <cstddef>
#include <cstdint>
#include <string>
#include <utility>
#include <vector>

#include <privmx/crypto/ecc/PrivateKey.hpp>
#include <privmx/crypto/ecc/PublicKey.hpp>
#include <privmx/endpoint/core/Buffer.hpp>
#include <privmx/endpoint/core/encryptors/DataInnerEncryptorV4.hpp>

#include "privmx/endpoint/group/GroupTypes.hpp"
#include "privmx/endpoint/group/Types.hpp"

namespace privmx {
namespace endpoint {
namespace group {

// Sealed size of a chunk holding `plainLen` bytes: type byte, zero block, PKCS#7-padded ciphertext, tag.
// At namespace scope so `ENCRYPTED_CHUNK_SIZE` derives from it instead of restating the arithmetic.
constexpr ByteCount encryptedChunkSizeFor(ByteCount plainLen) {
    return 1 + 16 + (plainLen + 16 - (plainLen % 16)) + 16;
}

/**
 * The group envelope wire format, packing and parsing and the crypto, and nothing else. Every key it needs is
 * passed in, which is what lets the whole format — tamper and replay cases included — be exercised by a unit
 * test with no bridge.
 *
 * Every type is `header || payload`: plaintext routing, then a payload that re-seals the header bytes and
 * compares them on the way out, because a header outside the seal is one anyone can rewrite.
 *
 * ## Notation
 *
 *   u8 x            one octet
 *   u8len x         one length octet, then x; `EnvelopeWriter::putField` refuses anything above 255 bytes
 *   u32be / u64be   fixed-width big-endian integer
 *   encrypt(p, k)   `core::DataInnerEncryptorV4`, CipherType 4: `0x04 | cbc(zero16 || p) | hmac tag16`. The
 *                   IV is random but not transmitted — the cipher prepends a 16-byte zero block and decrypt
 *                   reuses that block's ciphertext as the CBC IV. 16 bytes of overhead either way, which is
 *                   the arithmetic `encryptedChunkSizeFor` depends on and a test pins.
 *   sign(p, priv)   `signAndPackDataWithSignature`; covers only the buffer handed to it, which is why every
 *                   type repeats its header inside the sealed payload.
 *
 * ## TYPE 1 — member -> group, symmetric
 *
 * Written by `packGroupKeyEnvelope`, opened by `openGroupKeyEnvelope`, routed by `peek`.
 *
 *   header  = u8 ver | u8 type=1 | u8len groupId | u8len keyId | u8len authorPubKeyDER
 *   payload = encrypt(sign(header || content, authorPriv), groupKey32)
 *
 * Re-sealing the header stops a member of two groups re-sealing another member's signed content into the
 * second group under their name, and stops a type 3 envelope being relabelled as a type 1 — which would hand
 * back the file key as if it were message content.
 *
 * ## TYPE 2 — outsider -> group, ECIES to the group identity key
 *
 * Written by `packAnonymousEnvelope`, opened by `openAnonymousEnvelope`, routed by `peek`. The key wrap is
 * built by `wrapContentKey` and undone by `unwrapContentKey`.
 *
 *   header  = u8 ver | u8 type=2 | u8len groupId | u8len groupPubKeyBase58DER
 *   payload = u8len ecies(ECIES_DOMAIN || contentKey32) || encrypt(header || content, contentKey32)
 *
 * No author signature: the sender is anonymous by construction, so one by their throwaway key would attest to
 * nothing. Header integrity rests on the payload's own encrypt-then-MAC instead.
 *
 * `ECIES_DOMAIN` is load-bearing. Epoch-ladder rungs wrap a past grant private key to this same key with the
 * same `EciesEncryptor`, so without the prefix a rung lifted off the wire could be presented here and opened
 * as message content. A rung's plaintext is a WIF and can never carry it.
 *
 * ## TYPE 3 — member -> group, file header
 *
 * Written by `packFileEnvelope`, read by `unpackFileEnvelope`, routed by `peekFile`. Only the header travels
 * as the envelope; the body is sealed and opened chunk by chunk by `encryptChunk`/`decryptChunk`, whose
 * offsets and sizes come from `cipherOffsetOfChunk`, `chunkCount` and `plainChunkSizeAt`, and is stored
 * separately by the caller.
 *
 *   header  = u8 ver | u8 type=3 | u8len groupId | u8len keyId | u8len authorPubKeyDER
 *   payload = encrypt(sign(header || u64be plainSize || fileKey32, authorPriv), groupKey32)
 *   body    = for each chunk i: encrypt(plain_i, hmac-sha256(fileKey, CHUNK_KEY_LABEL || u32be i))
 *
 * `plainSize` sits inside the signature because each chunk authenticates only itself — nothing about chunk N
 * says how many were supposed to follow, so a dropped trailing chunk is otherwise undetectable. Every chunk's
 * sealed length follows from its plaintext length, and that follows from `plainSize`, which is what lets the
 * read side slice a stream fed to it in arbitrary pieces and still recognise the short final chunk — which is
 * otherwise indistinguishable from one that has not finished arriving. `classifyRead` names the end states.
 *
 * ## TYPE 4 — outsider -> group, file header
 *
 * Written by `packAnonymousFileEnvelope`, read by `unpackAnonymousFileEnvelope`, routed by `peekFile`; body
 * exactly as type 3.
 *
 *   header  = u8 ver | u8 type=4 | u8len groupId | u8len groupPubKeyBase58DER
 *   payload = u8len ecies(ECIES_DOMAIN || contentKey32)
 *             || encrypt(header || u64be plainSize || fileKey32, contentKey32)
 *   body    = identical to type 3
 *
 * The body is byte-for-byte type 3's — only the header differs, in how it wraps the file key and the size —
 * so the chunk helpers and every size calculation are shared with the member case. No signature, for the same
 * reason as type 2; `plainSize` still sits inside the encrypt-then-MAC payload, so a dropped tail stays
 * detectable even though its author is not attested.
 */
class GroupEnvelopeEncryptor {
public:
    // 2 since the per-chunk key derivation moved from `sha256(fileKey || i)` to a keyed, labelled HMAC.
    // Headers parse identically across the two, so without the bump a v1 file fails late, at the first MAC.
    static constexpr std::uint8_t VERSION = 2;

    // Plaintext bytes per file chunk. Fixed rather than carried in the envelope, so a hostile header cannot
    // force a divide-by-zero or an allocation bomb. `VERSION` is the upgrade path if it ever has to change.
    static constexpr ByteCount CHUNK_SIZE = 128 * 1024;

    // Sealed size of a full chunk. Derived, so it cannot drift from `encryptedChunkSizeFor`.
    static constexpr ByteCount ENCRYPTED_CHUNK_SIZE = encryptedChunkSizeFor(CHUNK_SIZE);

    // Every chunk but the last is exactly `ENCRYPTED_CHUNK_SIZE`, so this is a multiplication rather than a
    // running sum — which is what makes random access possible without an index or a second pass.
    static ByteCount cipherOffsetOfChunk(ChunkIndex index) {
        return static_cast<ByteCount>(index) * ENCRYPTED_CHUNK_SIZE;
    }

    // An exact multiple of CHUNK_SIZE gets no trailing empty chunk and an empty file gets none at all;
    // the off-by-one lives nowhere but here.
    static constexpr ByteCount chunkCount(ByteCount plainSize) { return (plainSize + CHUNK_SIZE - 1) / CHUNK_SIZE; }

    // `index` must be below `chunkCount(plainSize)`.
    static ByteCount plainChunkSizeAt(ByteCount plainSize, ChunkIndex index) {
        // Past the end the subtraction below wraps and hands back a full chunk, which desynchronises the
        // stream several chunks later rather than here. Both callers loop under `chunkCount`; say so.
        assert(index < chunkCount(plainSize));
        ByteCount offset = static_cast<ByteCount>(index) * CHUNK_SIZE;
        return plainSize - offset < CHUNK_SIZE ? plainSize - offset : CHUNK_SIZE;
    }

    // After a seek a partly-filled buffer is the expected outcome, so leftover bytes are not an error there.
    enum class ReadOutcome {
        // Every chunk the signed size called for arrived, and nothing followed them.
        Complete,
        // Fewer chunks arrived than the signed size calls for. A dropped tail, or an unfinished write.
        Truncated,
        // Every chunk arrived, and then more bytes followed.
        Overrun,
        // A seeked reader stopped early. Not an error — and not a whole-file guarantee either.
        PartialRange,
    };

    // `chunksOpened` is how many chunks were actually opened, `chunksExpected` what the signed size calls for.
    static ReadOutcome classifyRead(bool seeked, ByteCount chunksOpened, ByteCount chunksExpected, bool bufferEmpty) {
        // A seeked reader chose what to read, so neither "did it all arrive" nor "was there anything left
        // over" is a question this handle can answer. Both checks below would misfire.
        if (seeked) {
            return ReadOutcome::PartialRange;
        }
        if (chunksOpened < chunksExpected) {
            return ReadOutcome::Truncated;
        }
        if (!bufferEmpty) {
            return ReadOutcome::Overrun;
        }
        return ReadOutcome::Complete;
    }

    core::Buffer packGroupKeyEnvelope(
        const std::string& groupId,
        const std::string& keyId,
        const core::Buffer& content,
        const privmx::crypto::PrivateKey& authorPrivKey,
        const std::string& groupKey
    );

    core::Buffer packAnonymousEnvelope(
        const std::string& groupId,
        const privmx::crypto::PublicKey& groupPubKey,
        const core::Buffer& content
    );

    core::Buffer packFileEnvelope(
        const std::string& groupId,
        const std::string& keyId,
        ByteCount plainSize,
        const std::string& fileKey,
        const privmx::crypto::PrivateKey& authorPrivKey,
        const std::string& groupKey
    );

    EnvelopeFileHeader unpackFileEnvelope(const core::Buffer& envelope, const std::string& groupKey);

    core::Buffer packAnonymousFileEnvelope(
        const std::string& groupId,
        const privmx::crypto::PublicKey& groupPubKey,
        ByteCount plainSize,
        const std::string& fileKey
    );

    EnvelopeFileHeader unpackAnonymousFileEnvelope(
        const core::Buffer& envelope,
        const privmx::crypto::PrivateKey& groupPrivKey
    );

    core::Buffer encryptChunk(const core::Buffer& plainChunk, const std::string& fileKey, ChunkIndex index);
    core::Buffer decryptChunk(const core::Buffer& cipherChunk, const std::string& fileKey, ChunkIndex index);

    // -- dispatch ----------------------------------------------------------------------------------------

    // Message envelopes (type 1 or 2) only. A file envelope is refused: letting one through would hand back
    // a file key as though it were message content.
    EnvelopeRouting peek(const core::Buffer& envelope) { return peekFamily(envelope, EnvelopeFamily::Message); }

    // File envelopes (type 3 or 4) only. A message envelope is refused: it has no body to stream, so the
    // caller would be left with a handle onto data that does not exist.
    EnvelopeRouting peekFile(const core::Buffer& envelope) { return peekFamily(envelope, EnvelopeFamily::File); }

    DecryptedEnvelope openGroupKeyEnvelope(const core::Buffer& envelope, const std::string& groupKey);
    DecryptedEnvelope openAnonymousEnvelope(
        const core::Buffer& envelope,
        const privmx::crypto::PrivateKey& groupPrivKey
    );

private:
    // The type octet of each envelope type, as the format notes above spell them out.
    static constexpr std::uint8_t TYPE_GROUP_KEY = 1;
    static constexpr std::uint8_t TYPE_ANONYMOUS = 2;
    static constexpr std::uint8_t TYPE_FILE = 3;
    static constexpr std::uint8_t TYPE_ANON_FILE = 4;

    static constexpr std::size_t CONTENT_KEY_SIZE = 32;

    // Domain separator on the ECIES plaintext. See the note in the .cpp — it is load-bearing, not decoration.
    static const std::string ECIES_DOMAIN;

    // Domain label on the per-chunk key derivation. See `chunkKey` in the .cpp.
    static const std::string CHUNK_KEY_LABEL;

    enum class EnvelopeFamily {
        Message,
        File
    };

    static EnvelopeRouting peekFamily(const core::Buffer& envelope, EnvelopeFamily family);

    static std::string writeHeader(std::uint8_t type, const std::vector<std::string>& fields);
    static std::string chunkKey(const std::string& fileKey, ChunkIndex index);

    // The sealed tail both file types carry: the echoed header, then `u64be plainSize || fileKey32`.
    // `plain` must already have been checked to begin with `header`. Returns `{plainSize, fileKey}`.
    static std::pair<ByteCount, std::string> readFileBody(const std::string& plain, const std::string& header);

    // ECIES key wrap shared by the two anonymous types. Returns `{wrap, contentKey}`.
    static std::pair<std::string, std::string> wrapContentKey(const privmx::crypto::PublicKey& groupPubKey);
    // Inverse, including the domain check that keeps epoch-ladder rungs out.
    static std::string unwrapContentKey(
        const privmx::crypto::PrivateKey& groupPrivKey,
        const std::string& groupPubKeyBase58,
        const std::string& wrap
    );

    core::DataInnerEncryptorV4 _dataEncryptor;
};

} // namespace group
} // namespace endpoint
} // namespace privmx

#endif // _PRIVMXLIB_ENDPOINT_GROUP_ENCRYPTORS_ENVELOPE_GROUPENVELOPEENCRYPTOR_HPP_
