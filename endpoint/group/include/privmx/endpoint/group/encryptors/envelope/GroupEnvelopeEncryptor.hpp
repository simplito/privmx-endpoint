#ifndef _PRIVMXLIB_ENDPOINT_GROUP_ENCRYPTORS_ENVELOPE_GROUPENVELOPEENCRYPTOR_HPP_
#define _PRIVMXLIB_ENDPOINT_GROUP_ENCRYPTORS_ENVELOPE_GROUPENVELOPEENCRYPTOR_HPP_

#include <cstdint>
#include <string>

#include <Poco/Types.h>
#include <privmx/crypto/ecc/PrivateKey.hpp>
#include <privmx/crypto/ecc/PublicKey.hpp>
#include <privmx/endpoint/core/Buffer.hpp>
#include <privmx/endpoint/core/encryptors/DataInnerEncryptorV4.hpp>

#include "privmx/endpoint/group/Types.hpp"

namespace privmx {
namespace endpoint {
namespace group {

/**
 * Names for the quantities the chunk arithmetic juggles.
 *
 * Aliases, not distinct types — but three different unsigned meanings pass through the same functions here
 * (which chunk, how many chunks, how many bytes), and a signature that says which one it wants is the
 * cheapest guard available. `ChunkIndex` is deliberately 32-bit: the wire writes it as `u32be` into the chunk
 * key, so that width is a format constraint rather than a choice.
 */
using ChunkIndex = Poco::UInt32;
using ChunkCount = Poco::UInt64;
using ByteCount = Poco::UInt64;

/**
 * The group envelope wire format: packing, parsing and the crypto, and nothing else.
 *
 * Every key it needs is passed in. It never touches `ServerApi`, which is what lets the whole format —
 * including the tamper and replay cases that matter most — be exercised by a unit test with no bridge.
 * `GroupApiImpl` is the half that knows how to *find* the keys.
 *
 * ## Format
 *
 * All three types share the shape `header || payload`, where the header is plaintext routing information and
 * the payload is sealed. The header bytes are repeated *inside* the sealed payload and compared on the way
 * out. That repetition is the point: `signAndPackDataWithSignature` covers only the buffer handed to it, so a
 * header left outside the seal is a header anyone can rewrite. Without it, a member of two groups could
 * re-seal another member's signed content into the second group under their name, and relabelling a type 3
 * envelope as type 1 would hand back the file key as if it were a message.
 *
 *     TYPE 1 (member -> group, symmetric)
 *       header  = u8 ver | u8 type=1 | u8len groupId | u8len keyId | u8len authorPubKeyDER
 *       payload = encrypt(sign(header || content, authorPriv), groupKey32)
 *
 *     TYPE 2 (outsider -> group, ECIES to the group identity key)
 *       header  = u8 ver | u8 type=2 | u8len groupId | u8len groupPubKeyBase58DER
 *       payload = u8len ecies(ECIES_DOMAIN || contentKey32) || encrypt(header || content, contentKey32)
 *
 *     TYPE 3 (member -> group, file header; the body is stored separately by the caller)
 *       header  = u8 ver | u8 type=3 | u8len groupId | u8len keyId | u8len authorPubKeyDER
 *       payload = encrypt(sign(header || u64be plainSize || fileKey32, authorPriv), groupKey32)
 *       body    = for each chunk i: encrypt(plain_i, sha256(fileKey || u32be i))
 *
 * Type 2 carries no author signature. The sender is anonymous by construction, so a signature by their
 * throwaway key would attest to nothing; header integrity there rests on the payload's own encrypt-then-MAC.
 *
 * `encrypt`/`sign` are `core::DataInnerEncryptorV4`, i.e. CipherType 4 —
 * `0x04 | iv16 | aes-256-cbc | hmac-sha256 tag16`, random IV, encrypt-then-MAC, raw bytes with no base64.
 */
class GroupEnvelopeEncryptor {
public:
    static constexpr Poco::UInt8 VERSION = 1;

    /**
     * Plaintext bytes per file chunk. Fixed rather than carried in the envelope: it is a constant that has
     * never varied, and a caller-supplied one would need bounds checks to stop a hostile header causing a
     * divide-by-zero or an allocation bomb. `VERSION` is the upgrade path if it ever has to change.
     */
    static constexpr ByteCount CHUNK_SIZE = 128 * 1024;

    /**
     * Sealed size of a full chunk: `0x04 | iv16 | cbc(CHUNK_SIZE) | tag16`. PKCS#7 pads an exact multiple of
     * the block size out by a whole extra block, so this is CHUNK_SIZE + 16, not CHUNK_SIZE.
     */
    static constexpr ByteCount ENCRYPTED_CHUNK_SIZE = 1 + 16 + (CHUNK_SIZE + 16) + 16;

    /**
     * Sealed size of a chunk holding `plainLen` bytes.
     *
     * Every chunk's sealed length is a function of its plaintext length alone, and the plaintext length of
     * chunk `i` follows from the signed `plainSize`. That is what lets the read side slice a stream it is
     * being fed in arbitrary pieces — including the short final chunk, which is otherwise indistinguishable
     * from a chunk that simply has not finished arriving.
     */
    static ByteCount encryptedChunkSizeFor(ByteCount plainLen) {
        return 1 + 16 + (plainLen + 16 - (plainLen % 16)) + 16;
    }

    /**
     * Offset of chunk `index` in the ciphertext stream.
     *
     * Every chunk but the last is exactly `ENCRYPTED_CHUNK_SIZE`, so this is a multiplication rather than a
     * running sum — which is what makes random access possible without an index or a second pass.
     */
    static ByteCount cipherOffsetOfChunk(ChunkIndex index) {
        return static_cast<ByteCount>(index) * ENCRYPTED_CHUNK_SIZE;
    }

    /** Plaintext bytes in chunk `index` of a file of `plainSize` bytes. */
    static ByteCount plainChunkSizeAt(ByteCount plainSize, ChunkIndex index) {
        ByteCount offset = static_cast<ByteCount>(index) * CHUNK_SIZE;
        return plainSize - offset < CHUNK_SIZE ? plainSize - offset : CHUNK_SIZE;
    }

    struct FileHeader {
        EnvelopeType type;
        std::string groupId;
        std::string keyId;        //< set for ENVELOPE_FROM_MEMBER only
        std::string authorPubKey; //< base58-DER, signature verified; EMPTY for ENVELOPE_ANONYMOUS
        ByteCount plainSize;
        std::string fileKey; //< 32 raw bytes
    };

    // -- type 1 ------------------------------------------------------------------------------------------

    core::Buffer packGroupKeyEnvelope(
        const std::string& groupId,
        const std::string& keyId,
        const core::Buffer& content,
        const privmx::crypto::PrivateKey& authorPrivKey,
        const std::string& groupKey
    );

    // -- type 2 ------------------------------------------------------------------------------------------

    core::Buffer packAnonymousEnvelope(
        const std::string& groupId,
        const privmx::crypto::PublicKey& groupPubKey,
        const core::Buffer& content
    );

    // -- type 3 ------------------------------------------------------------------------------------------

    core::Buffer packFileEnvelope(
        const std::string& groupId,
        const std::string& keyId,
        ByteCount plainSize,
        const std::string& fileKey,
        const privmx::crypto::PrivateKey& authorPrivKey,
        const std::string& groupKey
    );

    FileHeader unpackFileEnvelope(const core::Buffer& envelope, const std::string& groupKey);

    // -- type 4 ------------------------------------------------------------------------------------------
    //
    // The file body is byte-for-byte the same as type 3's — only the header differs, in how it wraps the file
    // key and the size. That is the whole reason this variant is nearly free: `encryptChunk`/`decryptChunk`
    // and every size calculation are shared with the member case.

    core::Buffer packAnonymousFileEnvelope(
        const std::string& groupId,
        const privmx::crypto::PublicKey& groupPubKey,
        ByteCount plainSize,
        const std::string& fileKey
    );

    FileHeader unpackAnonymousFileEnvelope(
        const core::Buffer& envelope,
        const privmx::crypto::PrivateKey& groupPrivKey
    );

    core::Buffer encryptChunk(const core::Buffer& plainChunk, const std::string& fileKey, ChunkIndex index);
    core::Buffer decryptChunk(const core::Buffer& cipherChunk, const std::string& fileKey, ChunkIndex index);

    /**
     * Number of chunks a file of `plainSize` bytes occupies.
     *
     * An exact multiple of CHUNK_SIZE gets no trailing empty chunk, and an empty file gets none at all.
     * Stated here once so both sides agree; the off-by-one lives nowhere else.
     */
    static ChunkCount chunkCount(ByteCount plainSize) { return (plainSize + CHUNK_SIZE - 1) / CHUNK_SIZE; }

    // -- dispatch ----------------------------------------------------------------------------------------

    /** Reads the routing header without opening anything. Throws if the envelope is malformed. */
    struct Routing {
        EnvelopeType type;
        std::string groupId;
        std::string keyId;       //< set for ENVELOPE_FROM_MEMBER only
        std::string groupPubKey; //< base58-DER; set for ENVELOPE_ANONYMOUS only
    };
    Routing peek(const core::Buffer& envelope);

    /** Peeks a file envelope's routing, member or anonymous. Rejects anything that is not a file envelope. */
    Routing peekFile(const core::Buffer& envelope);

    DecryptedEnvelope openGroupKeyEnvelope(const core::Buffer& envelope, const std::string& groupKey);
    DecryptedEnvelope openAnonymousEnvelope(
        const core::Buffer& envelope,
        const privmx::crypto::PrivateKey& groupPrivKey
    );

private:
    /** Domain separator on the ECIES plaintext. See the note in the .cpp — it is load-bearing, not decoration. */
    static const std::string ECIES_DOMAIN;

    static std::string writeHeader(Poco::UInt8 type, const std::vector<std::string>& fields);
    static std::string chunkKey(const std::string& fileKey, ChunkIndex index);

    /** ECIES key wrap shared by the two anonymous types. Returns `{wrap, contentKey}`. */
    static std::pair<std::string, std::string> wrapContentKey(const privmx::crypto::PublicKey& groupPubKey);
    /** Inverse, including the domain check that keeps epoch-ladder rungs out. */
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
