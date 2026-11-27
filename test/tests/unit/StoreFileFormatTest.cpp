/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

/**
 * Characterization tests for the file-data format in `store`.
 *
 * They were written before that format was rebuilt, because `store` had no unit tests at all — only
 * e2e ones, which need a bridge and do not show what exactly goes to disk. Their job is not to
 * describe how the format ought to look, but to **pin down how it looks today**, so the refactor
 * could be called safe.
 *
 * That is why the assertions are deliberately literal: specific sizes, specific offsets, a specific
 * frame layout. If a format change is intended, these numbers should be changed deliberately — not
 * adjusted to whatever the new result happens to be.
 *
 * Chunk format AES_CBC_HMAC_SHA256 (cipherType = 4):
 *     [32 B HMAC-SHA256][16 B IV][AES-256-CBC + PKCS#7]
 *   chunkKey = hmacSha256(fileKey, "privmx/store/file-chunk" || BE32(index))
 *   the HMAC is computed with chunkKey over (IV || ciphertext)
 *
 * Chunk format AES_GCM (cipherType = 5):
 *     [12 B IV][AES-256-GCM || 16 B tag]
 *   no padding; the hash-table entry is the AEAD tag from the **end** of the frame
 *
 * Ids 1, 2 and 3 named these same frame layouts with a digest-derived chunk key and were retired at
 * 3.0.0; `RetiredTypesAreRejected` keeps them out of the registry.
 *
 * The write format is picked by `PRIVMX_DEFAULT_FILE_CIPHER` at configure time, so no test
 * describing a particular format may rely on `defaultForWrite()` — the format is named explicitly.
 * Tests that have to hold for every format loop over `FileCipher::known()`, so that the next format
 * added gets that coverage right away.
 */

#include <string>

#include <gtest/gtest.h>

#include <privmx/crypto/Crypto.hpp>
#include <privmx/endpoint/store/ChunkStreamer.hpp>
#include <privmx/endpoint/store/Mapper.hpp>
#include <privmx/endpoint/store/ServerTypes.hpp>
#include <privmx/endpoint/store/StoreException.hpp>
#include <privmx/endpoint/store/StoreTypes.hpp>
#include <privmx/endpoint/store/Types.hpp>
#include <privmx/endpoint/store/encryptors/fileData/ChunkEncryptor.hpp>
#include <privmx/endpoint/store/encryptors/fileData/FileCipher.hpp>
#include <privmx/endpoint/store/encryptors/fileData/HmacList.hpp>

using namespace privmx::endpoint;
using namespace privmx::endpoint::store;

namespace {

const std::string KEY(32, 'k');
constexpr size_t CHUNK = 128 * 1024;

std::string repeat(char c, size_t n) {
    return std::string(n, c);
}

/**
 * Format 1 named **explicitly**, not via `defaultForWrite()`.
 *
 * The tests below describe one particular format, not "whichever this build happens to write with"
 * — and the write format is chosen at configure time by `PRIVMX_DEFAULT_FILE_CIPHER`. Without this,
 * switching the default format broke these tests even though AES_CBC_HMAC_SHA256 had not changed.
 */
FileCipher cbc() {
    return FileCipher::forType(FileCipher::AES_CBC_HMAC_SHA256);
}

ChunkEncryptor cbcEncryptor(size_t chunkSize = CHUNK) {
    return ChunkEncryptor(KEY, chunkSize, cbc());
}

} // namespace

// ---------------------------------------------------------------------------------------------
// The chunk frame layout
// ---------------------------------------------------------------------------------------------

TEST(StoreFileFormat, ChunkLayoutIsHmacThenIvThenCipher) {
    ChunkEncryptor encryptor = cbcEncryptor();
    const std::string plain = repeat('a', 100);

    const auto chunk = encryptor.encrypt(0, plain);

    ASSERT_GE(chunk.data.size(), HMAC_SIZE + IV_SIZE);
    EXPECT_EQ(32u, HMAC_SIZE);
    EXPECT_EQ(16u, IV_SIZE);
    // The HMAC sits at the front and is the same thing returned alongside in `Chunk::hmac`.
    EXPECT_EQ(chunk.hmac, chunk.data.substr(0, HMAC_SIZE));
    EXPECT_EQ(HMAC_SIZE, chunk.hmac.size());
    // 100 bytes + PKCS#7 up to a multiple of 16 = 112.
    EXPECT_EQ(HMAC_SIZE + IV_SIZE + 112u, chunk.data.size());
}

/// The chunk key and the HMAC are deterministic — this test ties them to particular primitives, so
/// changing either stops being invisible.
TEST(StoreFileFormat, ChunkKeyAndHmacFollowTheDocumentedFormula) {
    ChunkEncryptor encryptor = cbcEncryptor();
    const uint64_t index = 7;

    const auto chunk = encryptor.encrypt(index, repeat('b', 64));

    const std::string indexBE("\x00\x00\x00\x07", 4);
    const std::string expectedChunkKey =
        privmx::crypto::Crypto::hmacSha256(KEY, std::string("privmx/store/file-chunk") + indexBE);
    const std::string ivWithCipher = chunk.data.substr(HMAC_SIZE);

    EXPECT_EQ(privmx::crypto::Crypto::hmacSha256(expectedChunkKey, ivWithCipher), chunk.hmac);
}

TEST(StoreFileFormat, RoundTripForEdgeSizes) {
    ChunkEncryptor encryptor = cbcEncryptor();

    for (const size_t size : {size_t{0}, size_t{1}, size_t{15}, size_t{16}, size_t{17}, size_t{4096}}) {
        const std::string plain = repeat('x', size);
        const auto chunk = encryptor.encrypt(3, plain);
        EXPECT_EQ(plain, encryptor.decrypt(3, chunk)) << "size " << size;
    }
}

/// The chunk index goes into the key, so a chunk read under a different index has to be rejected.
/// This is the only thing stopping chunks from being swapped around within a file.
TEST(StoreFileFormat, ChunkFromAnotherIndexIsRejected) {
    ChunkEncryptor encryptor = cbcEncryptor();
    const auto chunk = encryptor.encrypt(1, repeat('c', 64));

    EXPECT_THROW(encryptor.decrypt(2, chunk), FileChunkInvalidCipherChecksumException);
}

TEST(StoreFileFormat, TamperedCiphertextIsRejected) {
    ChunkEncryptor encryptor = cbcEncryptor();
    auto chunk = encryptor.encrypt(0, repeat('d', 64));

    chunk.data[chunk.data.size() - 1] ^= 0xFF;
    EXPECT_THROW(encryptor.decrypt(0, chunk), FileChunkInvalidCipherChecksumException);
}

TEST(StoreFileFormat, HmacNotMatchingTheListIsRejectedBeforeDecryption) {
    ChunkEncryptor encryptor = cbcEncryptor();
    auto chunk = encryptor.encrypt(0, repeat('e', 64));

    chunk.hmac[0] ^= 0xFF; // as if the hash list named a different hash than the frame carries
    EXPECT_THROW(encryptor.decrypt(0, chunk), FileChunkInvalidChecksumException);
}

TEST(StoreFileFormat, HasHashComparesThePrefix) {
    ChunkEncryptor encryptor = cbcEncryptor();
    const auto chunk = encryptor.encrypt(0, repeat('f', 64));

    EXPECT_TRUE(encryptor.hasHash(chunk.data, chunk.hmac));
    EXPECT_FALSE(encryptor.hasHash(chunk.data, std::string(HMAC_SIZE, '\0')));
    EXPECT_FALSE(encryptor.hasHash("too short", chunk.hmac));
}

// ---------------------------------------------------------------------------------------------
// Size arithmetic. These numbers address chunks within the file on the server, so any mistake here
// means reading the wrong fragment.
// ---------------------------------------------------------------------------------------------

TEST(StoreFileFormat, EncryptedChunkSizeIsPlainPlusPaddingPlusHmacAndIv) {
    // A chunkSize that is a multiple of 16 still gets a full block of PKCS#7 padding.
    EXPECT_EQ(CHUNK + 16 + HMAC_SIZE + IV_SIZE, cbcEncryptor().getEncryptedChunkSize());
    EXPECT_EQ(100u + 12 + HMAC_SIZE + IV_SIZE, cbcEncryptor(100).getEncryptedChunkSize());
}

TEST(StoreFileFormat, EncryptedFileSizeMatchesWhatTheChunksActuallyWeigh) {
    constexpr size_t smallChunk = 1024;
    ChunkEncryptor encryptor = cbcEncryptor(smallChunk);

    EXPECT_EQ(0u, encryptor.getEncryptedFileSize(0));

    // A single partial chunk.
    EXPECT_EQ(
        encryptor.encrypt(0, repeat('g', 100)).data.size(), encryptor.getEncryptedFileSize(100)
    );

    // Two chunks: one full + the remainder. We compute it as encryption actually turns out.
    const size_t full = encryptor.encrypt(0, repeat('g', smallChunk)).data.size();
    const size_t tail = encryptor.encrypt(1, repeat('g', 100)).data.size();
    EXPECT_EQ(full + tail, encryptor.getEncryptedFileSize(smallChunk + 100));

    // A size that is an exact multiple of the chunk — the last chunk is full, not empty.
    EXPECT_EQ(2 * full, encryptor.getEncryptedFileSize(2 * smallChunk));
}

// ---------------------------------------------------------------------------------------------
// The hash list. Here `HMAC_SIZE` is the **table stride**, not merely a hash length.
// ---------------------------------------------------------------------------------------------

TEST(StoreFileFormat, HashListStrideIsHmacSize) {
    const std::string topKey(32, 't');
    const std::string h0(HMAC_SIZE, '0');
    const std::string h1(HMAC_SIZE, '1');
    const std::string hashes = h0 + h1;

    HmacList list(topKey, privmx::crypto::Crypto::hmacSha256(topKey, hashes), hashes, cbc());

    EXPECT_EQ(HMAC_SIZE, list.getHashSize());
    EXPECT_EQ(h0, list.getHash(0));
    EXPECT_EQ(h1, list.getHash(1));
    EXPECT_TRUE(list.verifyHash(1, h1));
}

TEST(StoreFileFormat, HashListTopHashIsHmacOverTheWholeTable) {
    const std::string topKey(32, 't');
    const std::string hashes = std::string(HMAC_SIZE, '0') + std::string(HMAC_SIZE, '1');

    HmacList list(topKey, privmx::crypto::Crypto::hmacSha256(topKey, hashes), hashes, cbc());

    EXPECT_EQ(privmx::crypto::Crypto::hmacSha256(topKey, hashes), list.getTopHash());
    EXPECT_TRUE(list.verifyTopHash(privmx::crypto::Crypto::hmacSha256(topKey, hashes)));
}

TEST(StoreFileFormat, HashListRejectsTableThatIsNotAWholeNumberOfHashes) {
    const std::string topKey(32, 't');
    const std::string hashes(HMAC_SIZE + 1, '0');

    EXPECT_THROW(
        HmacList(topKey, privmx::crypto::Crypto::hmacSha256(topKey, hashes), hashes, cbc()),
        InvalidHashSizeException
    );
}

TEST(StoreFileFormat, HashListRejectsWrongTopHash) {
    const std::string topKey(32, 't');
    const std::string hashes(HMAC_SIZE, '0');

    EXPECT_THROW(
        HmacList(topKey, std::string(HMAC_SIZE, 'z'), hashes, cbc()), InvalidFileTopHashException
    );
}

TEST(StoreFileFormat, HashListAppendsAndTruncates) {
    const std::string topKey(32, 't');
    HmacList list(topKey, privmx::crypto::Crypto::hmacSha256(topKey, ""), "", cbc());

    list.set(0, std::string(HMAC_SIZE, '0'));
    list.set(1, std::string(HMAC_SIZE, '1'));
    EXPECT_EQ(2 * HMAC_SIZE, list.getAll().size());

    // A truncating write in the middle cuts the table down to that chunk inclusive.
    list.set(0, std::string(HMAC_SIZE, '2'), true);
    EXPECT_EQ(HMAC_SIZE, list.getAll().size());
    EXPECT_EQ(std::string(HMAC_SIZE, '2'), list.getHash(0));

    EXPECT_THROW(list.set(5, std::string(HMAC_SIZE, '3')), HashIndexOutOfBoundsException);
    EXPECT_THROW(list.set(1, std::string(HMAC_SIZE - 1, '4')), InvalidHashSizeException);
}

// ---------------------------------------------------------------------------------------------
// The `FileCipher` layer: picking a format by the `cipherType` marker.
// ---------------------------------------------------------------------------------------------

/// The write format is chosen by `PRIVMX_DEFAULT_FILE_CIPHER` at configure time, so this test
/// cannot pin a particular value. It pins what has to hold in **every** build: that the default
/// value is a format this build can read.
TEST(StoreFileCipher, DefaultForWriteIsAFormatThisBuildCanRead) {
    EXPECT_TRUE(FileCipher::isKnown(FileCipher::defaultForWrite().type()));
    // Once issued, a marker value must never be redefined.
    EXPECT_EQ(4, FileCipher::AES_CBC_HMAC_SHA256);
    EXPECT_EQ(5, FileCipher::AES_GCM);
    EXPECT_EQ(6, FileCipher::AES_GCM_SHA512);
}

/// Ids 1, 2 and 3 named these same frame layouts with a digest-derived chunk key, up to 3.0.0. They
/// are retired, not merely unused: reissuing one would make a pre-3.0.0 file look like a format this
/// build can read, and it would then fail on a chunk authenticator — the one failure shape that is
/// indistinguishable from storage corruption. Refused at the format gate instead, by name.
TEST(StoreFileCipher, RetiredTypesAreRejected) {
    for (const int64_t retired : {int64_t{1}, int64_t{2}, int64_t{3}}) {
        EXPECT_FALSE(FileCipher::isKnown(retired)) << "cipherType " << retired << " is retired";
        EXPECT_THROW(FileCipher::forType(retired), UnsupportedCipherTypeException);
    }
}

/// Checks that `PRIVMX_DEFAULT_FILE_CIPHER` actually **reached the compiled library**, rather than
/// merely being printed at configure time. Such a silent loss has happened once already: definitions
/// added by `target_compile_definitions` were wiped by a later
/// `set_target_properties(... COMPILE_DEFINITIONS ...)`, so the build announced one format and wrote
/// with another. The test compares the value the library sees with the one CMake gave this file.
TEST(StoreFileCipher, BuildOptionReachedTheLibrary) {
    EXPECT_EQ(
        static_cast<int64_t>(PRIVMX_DEFAULT_FILE_CIPHER_ID), FileCipher::defaultForWrite().type()
    ) << "PRIVMX_DEFAULT_FILE_CIPHER did not reach privmxendpointstore";
}

/// The format's parameters have to match the constants that described it before — otherwise the
/// refactor would have quietly changed the file layout.
TEST(StoreFileCipher, ParametersMatchTheConstantsTheyReplaced) {
    const FileCipher cipher = cbc();

    EXPECT_EQ(IV_SIZE, cipher.ivLength());
    EXPECT_EQ(HMAC_SIZE, cipher.hashLength());
    EXPECT_EQ(CHUNK_PADDING, cipher.paddingBlock());
}

TEST(StoreFileCipher, UnknownTypeIsRejected) {
    EXPECT_FALSE(FileCipher::isKnown(0));
    EXPECT_FALSE(FileCipher::isKnown(99));
    EXPECT_THROW(FileCipher::forType(99), UnsupportedCipherTypeException);

    for (const int64_t type : FileCipher::known()) {
        EXPECT_TRUE(FileCipher::isKnown(type));
        EXPECT_NO_THROW(FileCipher::forType(type));
    }
}

/// `ChunkStreamer` used to compute the file size with its own copy of the same formula as
/// `ChunkEncryptor`. Both now go through `FileCipher`, so agreement holds by construction — this
/// test pins it, because a drift between those two numbers means reading the wrong part of a file.
TEST(StoreFileCipher, SizeArithmeticHasOneSource) {
    constexpr size_t chunkSize = 1024;

    for (const int64_t type : FileCipher::known()) {
        const FileCipher cipher = FileCipher::forType(type);
        ChunkEncryptor encryptor(KEY, chunkSize, cipher);

        for (const uint64_t fileSize :
             {uint64_t{0}, uint64_t{1}, uint64_t{1023}, uint64_t{1024}, uint64_t{5000}}) {
            EXPECT_EQ(cipher.encryptedFileSize(fileSize, chunkSize), encryptor.getEncryptedFileSize(fileSize))
                << "format " << type << ", size " << fileSize;
        }
        EXPECT_EQ(cipher.encryptedChunkSize(chunkSize), encryptor.getEncryptedChunkSize())
            << "format " << type;
    }
}

// ---------------------------------------------------------------------------------------------
// What has to hold in **every** format. These tests exist so that the next format added does not
// slip through uncovered — the loop over `FileCipher::known()` picks it up on its own.
// ---------------------------------------------------------------------------------------------

TEST(StoreFileCipherAllFormats, RoundTripForEdgeSizes) {
    for (const int64_t type : FileCipher::known()) {
        ChunkEncryptor encryptor(KEY, CHUNK, FileCipher::forType(type));

        for (const size_t size : {size_t{0}, size_t{1}, size_t{15}, size_t{16}, size_t{17}, size_t{4096}}) {
            const std::string plain = repeat('x', size);
            const auto chunk = encryptor.encrypt(3, plain);
            EXPECT_EQ(plain, encryptor.decrypt(3, chunk)) << "format " << type << ", size " << size;
        }
    }
}

/// The hash returned alongside the frame and the hash the frame carries are the same thing —
/// wherever in the frame a format keeps it. The pre-decryption check rests on this.
TEST(StoreFileCipherAllFormats, ChunkHashIsTheOneCarriedInTheFrame) {
    for (const int64_t type : FileCipher::known()) {
        const FileCipher cipher = FileCipher::forType(type);
        ChunkEncryptor encryptor(KEY, CHUNK, cipher);

        const auto chunk = encryptor.encrypt(0, repeat('h', 64));

        EXPECT_EQ(cipher.hashLength(), chunk.hmac.size()) << "format " << type;
        EXPECT_TRUE(encryptor.hasHash(chunk.data, chunk.hmac)) << "format " << type;
        EXPECT_FALSE(encryptor.hasHash(chunk.data, std::string(cipher.hashLength(), '\0')))
            << "format " << type;
        EXPECT_FALSE(encryptor.hasHash("too short", chunk.hmac)) << "format " << type;
    }
}

TEST(StoreFileCipherAllFormats, TamperedCiphertextIsRejected) {
    for (const int64_t type : FileCipher::known()) {
        ChunkEncryptor encryptor(KEY, CHUNK, FileCipher::forType(type));
        auto chunk = encryptor.encrypt(0, repeat('d', 64));

        chunk.data[chunk.data.size() - 1] ^= 0xFF;
        EXPECT_ANY_THROW(encryptor.decrypt(0, chunk)) << "format " << type;
    }
}

/// The chunk index goes into the key in every format, so chunks are not interchangeable.
TEST(StoreFileCipherAllFormats, ChunkFromAnotherIndexIsRejected) {
    for (const int64_t type : FileCipher::known()) {
        ChunkEncryptor encryptor(KEY, CHUNK, FileCipher::forType(type));
        const auto chunk = encryptor.encrypt(1, repeat('c', 64));

        EXPECT_THROW(encryptor.decrypt(2, chunk), FileChunkInvalidCipherChecksumException)
            << "format " << type;
    }
}

TEST(StoreFileCipherAllFormats, HashListStrideFollowsTheFormat) {
    const std::string topKey(32, 't');

    for (const int64_t type : FileCipher::known()) {
        const FileCipher cipher = FileCipher::forType(type);
        const std::string h0(cipher.hashLength(), '0');
        const std::string h1(cipher.hashLength(), '1');

        HmacList list(topKey, cipher.topHash(topKey, h0 + h1), h0 + h1, cipher);

        EXPECT_EQ(cipher.hashLength(), list.getHashSize()) << "format " << type;
        EXPECT_EQ(h0, list.getHash(0)) << "format " << type;
        EXPECT_EQ(h1, list.getHash(1)) << "format " << type;
    }
}

// ---------------------------------------------------------------------------------------------
// AES_GCM (cipherType = 5): AES-256-GCM, frame `[12 B IV][ciphertext || 16 B tag]`.
// As literal as with AES_CBC_HMAC_SHA256 — these numbers address chunks within the file.
// ---------------------------------------------------------------------------------------------

namespace {

constexpr size_t GCM_IV = 12;
constexpr size_t GCM_TAG = 16;

FileCipher gcm() {
    return FileCipher::forType(FileCipher::AES_GCM);
}

} // namespace

TEST(StoreFileGcmFormat, Parameters) {
    const FileCipher cipher = gcm();

    EXPECT_EQ(GCM_IV, cipher.ivLength());
    EXPECT_EQ(GCM_TAG, cipher.hashLength());
    // AEAD is a stream cipher — it does not pad, so the file does not grow to a block multiple.
    EXPECT_EQ(0u, cipher.paddingBlock());
}

TEST(StoreFileGcmFormat, ChunkLayoutIsIvThenCipherWithTrailingTag) {
    ChunkEncryptor encryptor(KEY, CHUNK, gcm());
    const std::string plain = repeat('a', 100);

    const auto chunk = encryptor.encrypt(0, plain);

    // No padding: the length is exactly IV + plaintext + tag.
    EXPECT_EQ(GCM_IV + 100u + GCM_TAG, chunk.data.size());
    // The chunk hash is the AEAD tag, i.e. the **end** of the frame — unlike in AES_CBC_HMAC_SHA256.
    EXPECT_EQ(GCM_TAG, chunk.hmac.size());
    EXPECT_EQ(chunk.hmac, chunk.data.substr(chunk.data.size() - GCM_TAG));
}

TEST(StoreFileGcmFormat, EncryptedChunkSizeIsPlainPlusIvAndTag) {
    EXPECT_EQ(CHUNK + GCM_IV + GCM_TAG, ChunkEncryptor(KEY, CHUNK, gcm()).getEncryptedChunkSize());
    EXPECT_EQ(100u + GCM_IV + GCM_TAG, ChunkEncryptor(KEY, 100, gcm()).getEncryptedChunkSize());
}

TEST(StoreFileGcmFormat, EncryptedFileSizeMatchesWhatTheChunksActuallyWeigh) {
    constexpr size_t smallChunk = 1024;
    ChunkEncryptor encryptor(KEY, smallChunk, gcm());

    EXPECT_EQ(0u, encryptor.getEncryptedFileSize(0));
    EXPECT_EQ(
        encryptor.encrypt(0, repeat('g', 100)).data.size(), encryptor.getEncryptedFileSize(100)
    );

    const size_t full = encryptor.encrypt(0, repeat('g', smallChunk)).data.size();
    const size_t tail = encryptor.encrypt(1, repeat('g', 100)).data.size();
    EXPECT_EQ(full + tail, encryptor.getEncryptedFileSize(smallChunk + 100));
    EXPECT_EQ(2 * full, encryptor.getEncryptedFileSize(2 * smallChunk));
}

TEST(StoreFileGcmFormat, HashNotMatchingTheListIsRejectedBeforeDecryption) {
    ChunkEncryptor encryptor(KEY, CHUNK, gcm());
    auto chunk = encryptor.encrypt(0, repeat('e', 64));

    chunk.hmac[0] ^= 0xFF; // as if the hash list named a different hash than the frame carries
    EXPECT_THROW(encryptor.decrypt(0, chunk), FileChunkInvalidChecksumException);
}

/// Tampering with the ciphertext is caught by the AEAD authentication itself, not by a separate
/// HMAC in front of the frame.
TEST(StoreFileGcmFormat, TamperedCiphertextIsRejectedByTheAeadTag) {
    ChunkEncryptor encryptor(KEY, CHUNK, gcm());
    auto chunk = encryptor.encrypt(0, repeat('d', 64));

    chunk.data[GCM_IV] ^= 0xFF; // the first ciphertext byte, past the IV
    EXPECT_THROW(encryptor.decrypt(0, chunk), FileChunkInvalidCipherChecksumException);
}

// ---------------------------------------------------------------------------------------------
// AES_GCM_SHA512 (cipherType = 6): AES-256-GCM with SHA-512 hashes.
//
// The frame layout is **identical** to AES_GCM — an AEAD tag is 16 B whatever the hash function.
// They differ only in what the chunk key and the table's top hash are computed with. The format
// exists so that a container naming a SHA-512 suite gets its file data computed with the same hash.
// ---------------------------------------------------------------------------------------------

namespace {

FileCipher gcm512() {
    return FileCipher::forType(FileCipher::AES_GCM_SHA512);
}

} // namespace

/// If the layout differed, chunk addressing within a file would stop being shared by the two formats.
TEST(StoreFileSha512Format, LayoutIsIdenticalToFormatTwo) {
    EXPECT_EQ(gcm().ivLength(), gcm512().ivLength());
    EXPECT_EQ(gcm().hashLength(), gcm512().hashLength());
    EXPECT_EQ(gcm().paddingBlock(), gcm512().paddingBlock());
    EXPECT_EQ(gcm().encryptedChunkSize(1024), gcm512().encryptedChunkSize(1024));
}

/**
 * The chunk key is a **cipher** key, and all three formats cipher with AES-256 — 32 bytes, whatever
 * hash function computed it.
 *
 * Only the top hash is as long as its hash function; the chunk key has to be cut to the cipher's
 * size. Format 3 hashes with SHA-512, so it produces 64 bytes, and handing those over whole worked
 * only because the provider does not check key lengths and OpenSSL takes the first 32 in silence
 * (pmx-crypto passes `key.data()` straight through — `issue-pmx-crypto-key-iv-length`). The day that
 * check is added, every format-3 file would have become unreadable and unwritable at once, with the
 * round-trip test below still passing right up to it. Hence a test on the length itself.
 */
TEST(StoreFileCipher, ChunkKeyIsTheCiphersKeyLengthInEveryFormat) {
    for (const int64_t type : FileCipher::known()) {
        EXPECT_EQ(32u, FileCipher::forType(type).chunkKey(KEY, 0).size()) << "cipherType " << type;
    }
}

/**
 * The derivation is HMAC keyed by the file key — not the bare digest it was before 3.0.0.
 *
 * `ChunkKeyAndHmacFollowTheDocumentedFormula` pins this for AES_CBC_HMAC_SHA256 through the frame it produces;
 * this says it directly, for the GCM formats too, and names the construction that was replaced so a
 * revert to `H(fileKey || BE32(index))` fails here rather than merely changing what gets written.
 */
TEST(StoreFileCipher, ChunkKeyIsAKeyedPrfAndNotABareDigest) {
    const std::string indexBE("\x00\x00\x00\x07", 4);
    const std::string label("privmx/store/file-chunk");

    // Formats 1 and 2 hash with SHA-256, so the expected value is the same for both.
    const std::string expected = privmx::crypto::Crypto::hmacSha256(KEY, label + indexBE).substr(0, 32);
    EXPECT_EQ(expected, cbc().chunkKey(KEY, 7));
    EXPECT_EQ(expected, gcm().chunkKey(KEY, 7));

    EXPECT_NE(privmx::crypto::Crypto::sha256(KEY + indexBE), cbc().chunkKey(KEY, 7));
    // The label is load-bearing: without it this would be HMAC over the index alone.
    EXPECT_NE(privmx::crypto::Crypto::hmacSha256(KEY, indexBE).substr(0, 32), cbc().chunkKey(KEY, 7));
}

/// The point of this format: the same layout, a different hash. If the chunk key came out the same,
/// AES_GCM_SHA512 would be no more than another label on AES_GCM. With both keys now cut to 32 bytes this
/// also says the truncation did not collapse the two formats into one.
TEST(StoreFileSha512Format, ChunkKeyAndTopHashDifferFromFormatTwo) {
    EXPECT_NE(gcm().chunkKey(KEY, 0), gcm512().chunkKey(KEY, 0));

    const std::string topKey(32, 't');
    const std::string hashes(16, '0');
    EXPECT_NE(gcm().topHash(topKey, hashes), gcm512().topHash(topKey, hashes));
    // HMAC-SHA512 is 64 B, HMAC-SHA256 is 32 B.
    EXPECT_EQ(32u, gcm().topHash(topKey, hashes).size());
    EXPECT_EQ(64u, gcm512().topHash(topKey, hashes).size());
}

TEST(StoreFileSha512Format, RoundTrip) {
    ChunkEncryptor encryptor(KEY, CHUNK, gcm512());

    for (const size_t size : {size_t{0}, size_t{1}, size_t{4096}}) {
        const std::string plain = repeat('y', size);
        const auto chunk = encryptor.encrypt(2, plain);
        EXPECT_EQ(plain, encryptor.decrypt(2, chunk)) << "size " << size;
    }
}

// ---------------------------------------------------------------------------------------------
// Picking the format from the container's suite (level 2).
// ---------------------------------------------------------------------------------------------

/// A container naming a suite gets a file format computed with the same hash. Without this, the
/// suite choice would stop at the `store` boundary: files would use SHA-256 whatever the policy.
TEST(StoreFileCipherFromSuite, EachSuiteMapsToTheFormatWithItsOwnHash) {
    using core::CryptoSuite;
    using core::SuiteId;

    EXPECT_EQ(
        FileCipher::AES_GCM,
        FileCipher::forContainerSuite(CryptoSuite::forId(SuiteId::Aes256GcmSha256)).type()
    );
    EXPECT_EQ(
        FileCipher::AES_GCM_SHA512,
        FileCipher::forContainerSuite(CryptoSuite::forId(SuiteId::Aes256GcmSha512)).type()
    );
}

/// "No policy" is not the same as "a policy naming the default suite" — only the former should
/// follow the build setting.
TEST(StoreFileCipherFromSuite, NoSuiteFallsBackToTheBuildDefault) {
    EXPECT_EQ(
        FileCipher::defaultForWrite().type(), FileCipher::forContainerSuite(std::nullopt).type()
    );
}

/// Every suite in the registry has to have a counterpart among the file formats — otherwise a
/// container with such a policy could be created but not written to.
TEST(StoreFileCipherFromSuite, EverySuiteHasAFileFormat) {
    for (const core::SuiteId id : core::CryptoSuite::known()) {
        EXPECT_NO_THROW(FileCipher::forContainerSuite(core::CryptoSuite::forId(id)))
            << "suite " << static_cast<int>(id);
    }
}

/// The two formats give two different file layouts — if one computed the other's size, chunks would
/// be read from the wrong offsets. This test pins that they really are distinct.
TEST(StoreFileGcmFormat, LayoutDiffersFromFormatOne) {
    constexpr size_t chunkSize = 1024;

    EXPECT_NE(cbc().hashLength(), gcm().hashLength());
    EXPECT_NE(cbc().encryptedChunkSize(chunkSize), gcm().encryptedChunkSize(chunkSize));
    EXPECT_LT(gcm().encryptedChunkSize(chunkSize), cbc().encryptedChunkSize(chunkSize));
}

TEST(StoreFileCipher, ChunkEncryptorHonoursTheCipherItWasGiven) {
    const FileCipher cipher = FileCipher::forType(FileCipher::AES_CBC_HMAC_SHA256);
    ChunkEncryptor encryptor(KEY, CHUNK, cipher);

    const auto chunk = encryptor.encrypt(0, repeat('h', 64));

    EXPECT_EQ(cipher.hashLength(), chunk.hmac.size());
    EXPECT_EQ(repeat('h', 64), encryptor.decrypt(0, chunk));
}

TEST(StoreFileCipher, HashListHonoursTheCipherItWasGiven) {
    const FileCipher cipher = FileCipher::forType(FileCipher::AES_CBC_HMAC_SHA256);
    const std::string topKey(32, 't');
    const std::string hashes(cipher.hashLength(), '0');

    HmacList list(topKey, cipher.topHash(topKey, hashes), hashes, cipher);

    EXPECT_EQ(cipher.hashLength(), list.getHashSize());
}

/**
 * `storeFileUpdated` reports the changed range in **server** offsets, and the application is handed
 * plain ones. The conversion divides by the encrypted chunk size and multiplies by the plain one —
 * both of which belong to the file's own format, never to whatever this build writes with.
 *
 * Every format is checked, so a file written with any of them reports its own ranges correctly.
 */
TEST(StoreFileUpdatedMapping, ServerOffsetsConvertWithTheFilesOwnCipher) {
    constexpr size_t chunkSize = 1024;

    for (const int64_t type : FileCipher::known()) {
        const FileCipher cipher = FileCipher::forType(type);
        const int64_t encrypted = static_cast<int64_t>(cipher.encryptedChunkSize(chunkSize));

        FileDecryptionParams params{};
        params.key = KEY;
        params.chunkSize = chunkSize;
        params.cipherType = type;

        File file{};
        file.size = 4 * static_cast<int64_t>(chunkSize);

        server::StoreFileUpdatedEventData data{};
        data.changes = std::vector<server::StoreFileChange>{
            server::StoreFileChange{.type = "file", .pos = encrypted, .length = encrypted, .truncate = false}
        };

        const auto mapped = Mapper::mapToStoreFileUpdatedEventData(data, file, params);

        ASSERT_EQ(1u, mapped.changes.size()) << "cipherType " << type;
        // The second encrypted chunk is the second plain chunk, whatever the frame overhead is.
        EXPECT_EQ(static_cast<int64_t>(chunkSize), mapped.changes[0].pos) << "cipherType " << type;
        EXPECT_EQ(static_cast<int64_t>(chunkSize), mapped.changes[0].length) << "cipherType " << type;
    }
}

/**
 * `inbox` makes a file handle before it knows which Inbox the entry is for, so it learns the write
 * format only in `prepareEntry`. `setCipher` is what lets it apply it, and the size the server
 * request is made from has to follow — otherwise the request reserves one format's layout and the
 * chunks arrive in another's.
 */
TEST(ChunkStreamerCipher, SettingTheCipherChangesTheDeclaredSize) {
    constexpr size_t chunkSize = 1024;
    constexpr uint64_t fileSize = 4 * 1024;

    ChunkStreamer streamer(nullptr, chunkSize, fileSize, chunkSize, FileCipher::forType(FileCipher::AES_CBC_HMAC_SHA256));
    const auto asCbc = streamer.getFileSize();

    streamer.setCipher(FileCipher::forType(FileCipher::AES_GCM));
    const auto asGcm = streamer.getFileSize();

    EXPECT_NE(asCbc.size, asGcm.size);
    EXPECT_NE(asCbc.checksumSize, asGcm.checksumSize);
    EXPECT_EQ(gcm().encryptedFileSize(fileSize, chunkSize), asGcm.size);
}

/// Once the upload is tied to a server request the layout is fixed — the reserved size was computed
/// from the old format, so a later change would address the wrong offsets.
TEST(ChunkStreamerCipher, TheCipherCannotChangeOnceTheUploadIsTied) {
    ChunkStreamer streamer(nullptr, 1024, 4 * 1024, 1024);
    streamer.setRequestData("request-1", std::string(32, 'k'), 0);

    EXPECT_THROW(streamer.setCipher(FileCipher::forType(FileCipher::AES_GCM)), FileRandomWriteInternalException);
}

/// A change the server places past the end of the file used to come out as a negative length, which
/// the application would read as a range running backwards.
TEST(StoreFileUpdatedMapping, AChangePastTheEndIsClampedNotNegative) {
    constexpr size_t chunkSize = 1024;
    const FileCipher cipher = FileCipher::forType(FileCipher::AES_CBC_HMAC_SHA256);
    const int64_t encrypted = static_cast<int64_t>(cipher.encryptedChunkSize(chunkSize));

    FileDecryptionParams params{};
    params.key = KEY;
    params.chunkSize = chunkSize;
    params.cipherType = FileCipher::AES_CBC_HMAC_SHA256;

    File file{};
    file.size = static_cast<int64_t>(chunkSize); // one plain chunk

    server::StoreFileUpdatedEventData data{};
    data.changes = std::vector<server::StoreFileChange>{
        server::StoreFileChange{.type = "file", .pos = 5 * encrypted, .length = encrypted, .truncate = false}
    };

    const auto mapped = Mapper::mapToStoreFileUpdatedEventData(data, file, params);

    ASSERT_EQ(1u, mapped.changes.size());
    EXPECT_GE(mapped.changes[0].length, 0);
    EXPECT_LE(mapped.changes[0].pos + mapped.changes[0].length, file.size);
}
