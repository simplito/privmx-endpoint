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
#include "privmx/endpoint/group/encryptors/envelope/EnvelopeWire.hpp"

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
 * ## Header and binding (all types)
 *
 *   header  = u8 ver | u8 type | u8 flags | type-specific fields
 *   flags   = bit 0: the envelope is bound to a location
 *   binding = sha256(LOCATION_LABEL || canonical path) when bit 0 is set, empty otherwise
 *
 * `binding` is never transmitted. The writer puts it into the signed (or sealed) body right after the header;
 * the reader computes it from the location it is reading at and the two must agree, or the open fails with
 * `EnvelopeWrongLocationException`. "No location" is a value of its own (bit 0 clear), so an envelope written
 * without a location never opens with one and the other way round. `bindLocation` is the canonical path.
 *
 *   recipients = u8 count | count * (u8 kind | u8len id | u8len pubKeyBase58DER | u64be keyVersion)
 *
 * ## TYPE 1 - member -> group, symmetric
 *
 *   header  = ... | u8len groupId | u8len keyId | u8len authorUserId | u8len authorPubKeyDER | u64be keyVersion
 *   payload = encrypt(sign(header || binding || u64be encryptedAt || content, authorPriv), groupKey32)
 *
 * `authorUserId` is the writer's claim, as the public key beside it is: the caller has the UserVerifier confirm
 * that this user holds that key. It is in the header so that a reader can name the author without a directory
 * of every member's key.
 *
 * Re-sealing the header stops a member of two groups re-sealing another member's signed content into the
 * second group under their name, and stops a file envelope being relabelled as a message - which would hand
 * back the file key as if it were message content. `keyVersion` is the writer's claim, for a server that
 * refuses stale writes without holding keys; the caller checks it against the epoch of the key that opened it.
 *
 * ## TYPE 2 - anonymous -> group, ECIES to the group identity key
 *
 *   header  = ... | u8len groupId | u8len groupPubKeyBase58DER
 *   payload = u8len ecies(ECIES_DOMAIN || contentKey32) || encrypt(header || binding || content, contentKey32)
 *
 * No author signature: the sender is anonymous by construction, so one by their throwaway key would attest to
 * nothing. Header integrity rests on the payload's own encrypt-then-MAC instead.
 *
 * `ECIES_DOMAIN` is load-bearing. Epoch-ladder rungs wrap a past grant private key to this same key with the
 * same `EciesEncryptor`, so without the prefix a rung lifted off the wire could be presented here and opened
 * as message content. A rung's plaintext is a WIF and can never carry it.
 *
 * ## TYPE 5 - outsider -> group, signed
 *
 *   header  = ... | u8len groupId | u8len groupPubKeyBase58DER | u8len senderUserId | u8len senderPubKeyDER
 *             | recipients
 *   payload = u8len ecies(group) | count * u8len ecies(recipient)
 *             || encrypt(sign(header || binding || u64be encryptedAt || content, senderPriv), contentKey32)
 *
 * As type 2, but the writer signs: the group learns who wrote it. Never opened as a member's envelope.
 *
 * ## TYPE 6 - member -> group and further recipients
 *
 *   header  = ... | u8len groupId | u8len keyId | u8len authorUserId | u8len authorPubKeyDER | u64be keyVersion
 *             | recipients
 *   payload = u8len encrypt(KEY_WRAP_LABEL || contentKey32, groupKey32) | count * u8len ecies(recipient)
 *             || encrypt(sign(header || binding || u64be encryptedAt || content, authorPriv), contentKey32)
 *
 * The content key is wrapped once per reader; the list of readers is in the signed header, so a server cannot
 * add or drop one unnoticed. The home group opens it as a member's envelope (`openMemberEnvelope`), every
 * other reader with `openSharedEnvelope`, as do the further recipients of a type 5.
 *
 * ## TYPE 3 - member -> group, file header
 *
 *   header  = ... | u8len groupId | u8len keyId | u8len authorUserId | u8len authorPubKeyDER | u64be keyVersion
 *   payload = encrypt(sign(header || binding || u64be plainSize || fileKey32, authorPriv), groupKey32)
 *   body    = for each chunk i: encrypt(plain_i, hmac-sha256(fileKey, CHUNK_KEY_LABEL || u32be i))
 *
 * `plainSize` sits inside the signature because each chunk authenticates only itself - nothing about chunk N
 * says how many were supposed to follow, so a dropped trailing chunk is otherwise undetectable.
 *
 * ## TYPE 4 - anonymous -> group, file header
 *
 *   header  = ... | u8len groupId | u8len groupPubKeyBase58DER
 *   payload = u8len ecies(ECIES_DOMAIN || contentKey32)
 *             || encrypt(header || binding || u64be plainSize || fileKey32, contentKey32)
 *   body    = identical to type 3
 */
class GroupEnvelopeEncryptor {
public:
    // 2 since the per-chunk key derivation moved from `sha256(fileKey || i)` to a keyed, labelled HMAC.
    // Headers parse identically across the two, so without the bump a v1 file fails late, at the first MAC.
    // 3: every type gained the flags octet and the location binding; member types the key version.
    static constexpr std::uint8_t VERSION = 3;

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

    // The canonical form of a location, hashed. Two paths bind alike only if they have the same segments, each
    // of the same kind (name or identifier) and the same bytes. An empty path is refused: "no location" is
    // `EnvelopeBinding{}` and has to be asked for.
    static EnvelopeBinding bindLocation(const Path& location);

    // -- messages ----------------------------------------------------------------------------------------

    // Type 1, or type 6 when `recipients` is not empty.
    core::Buffer packMemberEnvelope(
        const std::string& groupId,
        const std::string& keyId,
        const core::Buffer& content,
        const privmx::crypto::PrivateKey& authorPrivKey,
        const std::string& groupKey,
        const EnvelopeSeal& seal,
        const std::vector<WireRecipient>& recipients = {}
    );

    // Type 5.
    core::Buffer packOutsiderEnvelope(
        const std::string& groupId,
        const privmx::crypto::PublicKey& groupPubKey,
        const core::Buffer& content,
        const privmx::crypto::PrivateKey& senderPrivKey,
        const EnvelopeSeal& seal,
        const std::vector<WireRecipient>& recipients = {}
    );

    // Type 2.
    core::Buffer packAnonymousEnvelope(
        const std::string& groupId,
        const privmx::crypto::PublicKey& groupPubKey,
        const core::Buffer& content,
        const EnvelopeBinding& binding
    );

    // Types 1 and 6, with the home group's key.
    OpenedEnvelope openMemberEnvelope(
        const core::Buffer& envelope,
        const std::string& groupKey,
        const EnvelopeBinding& binding
    );
    // Type 5, with the home group's private key.
    OpenedEnvelope openOutsiderEnvelope(
        const core::Buffer& envelope,
        const privmx::crypto::PrivateKey& groupPrivKey,
        const EnvelopeBinding& binding
    );
    // Type 2.
    OpenedEnvelope openAnonymousEnvelope(
        const core::Buffer& envelope,
        const privmx::crypto::PrivateKey& groupPrivKey,
        const EnvelopeBinding& binding
    );
    // Types 5 and 6, as the recipient at `recipientIndex` in the header's list, with that recipient's private
    // key. The signature and the binding are checked as everywhere. What is NOT established is the home group:
    // `type` (a member of it, or an outsider to it), `groupId` and `keyVersion` in the result are the writer's
    // signed claims - a recipient never held the home group's key to check them with. The result says so
    // (`homeGroupUnverified`), and the caller decides membership against the group's roster or reports it unknown.
    OpenedEnvelope openSharedEnvelope(
        const core::Buffer& envelope,
        std::size_t recipientIndex,
        const privmx::crypto::PrivateKey& recipientPrivKey,
        const EnvelopeBinding& binding
    );

    // -- files -------------------------------------------------------------------------------------------

    core::Buffer packFileEnvelope(
        const std::string& groupId,
        const std::string& keyId,
        ByteCount plainSize,
        const std::string& fileKey,
        const privmx::crypto::PrivateKey& authorPrivKey,
        const std::string& groupKey,
        const EnvelopeSeal& seal
    );

    EnvelopeFileHeader unpackFileEnvelope(
        const core::Buffer& envelope,
        const std::string& groupKey,
        const EnvelopeBinding& binding
    );

    core::Buffer packAnonymousFileEnvelope(
        const std::string& groupId,
        const privmx::crypto::PublicKey& groupPubKey,
        ByteCount plainSize,
        const std::string& fileKey,
        const EnvelopeBinding& binding
    );

    EnvelopeFileHeader unpackAnonymousFileEnvelope(
        const core::Buffer& envelope,
        const privmx::crypto::PrivateKey& groupPrivKey,
        const EnvelopeBinding& binding
    );

    core::Buffer encryptChunk(const core::Buffer& plainChunk, const std::string& fileKey, ChunkIndex index);
    core::Buffer decryptChunk(const core::Buffer& cipherChunk, const std::string& fileKey, ChunkIndex index);

    // -- dispatch ----------------------------------------------------------------------------------------

    // Message envelopes only. A file envelope is refused: letting one through would hand back a file key as
    // though it were message content.
    EnvelopeRouting peek(const core::Buffer& envelope) { return peekFamily(envelope, EnvelopeFamily::Message); }

    // File envelopes only. A message envelope is refused: it has no body to stream, so the caller would be
    // left with a handle onto data that does not exist.
    EnvelopeRouting peekFile(const core::Buffer& envelope) { return peekFamily(envelope, EnvelopeFamily::File); }

    // Either family; `isFile` in the result says which. For a caller that only inspects (a server's write gate).
    static EnvelopeRouting peekAny(const core::Buffer& envelope);

private:
    // The type octet of each envelope type, as the format notes above spell them out.
    static constexpr std::uint8_t TYPE_GROUP_KEY = 1;
    static constexpr std::uint8_t TYPE_ANONYMOUS = 2;
    static constexpr std::uint8_t TYPE_FILE = 3;
    static constexpr std::uint8_t TYPE_ANON_FILE = 4;
    static constexpr std::uint8_t TYPE_OUTSIDER = 5;
    static constexpr std::uint8_t TYPE_MEMBER_SHARED = 6;

    static constexpr std::uint8_t FLAG_HAS_LOCATION = 0x01;
    static constexpr std::uint8_t RECIPIENT_GROUP = 1;
    static constexpr std::uint8_t RECIPIENT_USER = 2;

    static constexpr std::size_t LOCATION_DIGEST_SIZE = 32;

    static constexpr std::size_t CONTENT_KEY_SIZE = 32;

    // Domain separator on the ECIES plaintext. See the note in the .cpp — it is load-bearing, not decoration.
    static const std::string ECIES_DOMAIN;

    // Domain label on the per-chunk key derivation. See `chunkKey` in the .cpp.
    static const std::string CHUNK_KEY_LABEL;
    // Domain label on the location digest, and on a content key wrapped under a group's symmetric key.
    static const std::string LOCATION_LABEL;
    static const std::string KEY_WRAP_LABEL;

    enum class EnvelopeFamily {
        Message,
        File
    };

    static EnvelopeRouting peekFamily(const core::Buffer& envelope, EnvelopeFamily family);

    // A header as read off the wire: its fields, and the exact bytes the writer signed or sealed.
    struct ParsedHeader {
        std::uint8_t wireType = 0;
        EnvelopeRouting routing{};
        std::string bytes{};
    };
    static ParsedHeader parseHeader(EnvelopeReader& cursor);

    static std::string writeHeader(
        std::uint8_t type,
        const EnvelopeBinding& binding,
        const std::vector<std::string>& fields
    );
    static void putRecipients(std::string& header, const std::vector<WireRecipient>& recipients);
    // The echoed header and the binding, checked; returns where the rest of `plain` starts.
    static std::size_t checkSealedPrefix(
        const std::string& plain,
        const ParsedHeader& header,
        const EnvelopeBinding& binding
    );
    // header || binding || u64be encryptedAt || content, signed; shared by every signed message type.
    core::Buffer signMessage(
        const std::string& header,
        const EnvelopeSeal& seal,
        const core::Buffer& content,
        const privmx::crypto::PrivateKey& signer
    );
    OpenedEnvelope openSignedMessage(
        const std::string& sealed,
        const std::string& contentKey,
        const ParsedHeader& header,
        const EnvelopeBinding& binding,
        EnvelopeType type
    );
    static std::string chunkKey(const std::string& fileKey, ChunkIndex index);

    // The sealed tail both file types carry after the echoed header and the binding:
    // `u64be plainSize || fileKey32`, starting at `offset`. Returns `{plainSize, fileKey}`.
    static std::pair<ByteCount, std::string> readFileBody(const std::string& plain, std::size_t offset);

    // ECIES key wrap of `contentKey` to `pubKey`, with a throwaway sender key.
    static std::string wrapContentKey(const privmx::crypto::PublicKey& pubKey, const std::string& contentKey);
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
