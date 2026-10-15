/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include <array>

#include <Poco/ByteOrder.h>

#include <privmx/cryptoservice/base/CoreTypes.hpp>
#include <privmx/endpoint/core/crypto/CryptoSuite.hpp>
#include <privmx/endpoint/core/crypto/ProviderAccess.hpp>
#include <privmx/endpoint/store/StoreException.hpp>
#include <privmx/endpoint/store/StoreTypes.hpp>
#include <privmx/endpoint/store/encryptors/fileData/FileCipher.hpp>

using namespace privmx::endpoint;
using namespace privmx::endpoint::store;

namespace {

/**
 * The cipher mode: the frame layout and how it is authenticated.
 *
 * Separate from `type`, because several formats can share a frame layout and differ only in the
 * hash. Branching on `type` would mean adding every new format to every `if`, and missing one
 * would not be a compile error — just a file written in the wrong layout.
 */
enum class Mode {
    /// `[HMAC][IV][ciphertext]`, authenticated by a separate HMAC in front of the frame.
    CbcHmac,
    /// `[IV][ciphertext || tag]`, authenticated by the AEAD mode itself.
    Gcm,
};

struct CipherSpec {
    int64_t type;
    Mode mode;
    std::size_t ivLength;
    std::size_t hashLength;
    /// 0 means the format does not pad to a block boundary.
    std::size_t paddingBlock;
    /**
     * Bytes the frame adds to the plaintext **beyond** padding.
     *
     * Stated explicitly rather than derived from `ivLength + hashLength`, because those two add up
     * to the overhead only by coincidence: in format 1 the hash is prepended to the frame, in
     * format 2 the tag is part of the cipher's output. A format whose hash length differed from
     * the frame's authenticator would break that formula silently.
     */
    std::size_t fixedOverhead;
    /**
     * The suite this format takes its **hash function** from — the chunk key and the table's top
     * hash. Only the hash part is used; the cipher is described by this entry's other fields,
     * because the mode and frame layout belong to the file format, not to the container's suite.
     */
    core::SuiteId hashSuite;
};

/**
 * The registry of file data formats.
 *
 * Format 1's constants come from `StoreTypes.hpp`, because those described this format before it
 * had a name. A `cipherType` value that has been issued must never be redefined.
 */
constexpr std::size_t GCM_IV_LENGTH = 12;
constexpr std::size_t GCM_TAG_LENGTH = 16;

constexpr std::array<CipherSpec, 3> CIPHERS{{
    {FileCipher::AES_CBC_HMAC_SHA256, Mode::CbcHmac, IV_SIZE, HMAC_SIZE, CHUNK_PADDING,
     HMAC_SIZE + IV_SIZE, core::SuiteId::Aes256GcmSha256},
    {FileCipher::AES_GCM, Mode::Gcm, GCM_IV_LENGTH, GCM_TAG_LENGTH, 0,
     GCM_IV_LENGTH + GCM_TAG_LENGTH, core::SuiteId::Aes256GcmSha256},
    // Frame identical to format 2 — an AEAD tag is 16 B whatever the hash function, so the
    // hash-table stride and chunk addressing do not change. Only the hash differs.
    {FileCipher::AES_GCM_SHA512, Mode::Gcm, GCM_IV_LENGTH, GCM_TAG_LENGTH, 0,
     GCM_IV_LENGTH + GCM_TAG_LENGTH, core::SuiteId::Aes256GcmSha512},
}};

/// The file format matching a container suite. The mode is always AEAD — container suites are
/// AEAD, and format 1 (CBC+HMAC) exists only as the legacy layout of files already written.
constexpr int64_t cipherForHashSuite(core::SuiteId suite) {
    for (const auto& spec : CIPHERS) {
        if (spec.mode == Mode::Gcm && spec.hashSuite == suite) {
            return spec.type;
        }
    }
    return 0;
}

/**
 * The format used for writing new files; set at build configuration through
 * `PRIVMX_DEFAULT_FILE_CIPHER`. It affects **writing only** — `CIPHERS` stays complete whatever
 * this value is, because every file's `cipherType` sits in its own internal meta.
 */
#ifndef PRIVMX_DEFAULT_FILE_CIPHER_ID
#define PRIVMX_DEFAULT_FILE_CIPHER_ID 1
#endif
constexpr int64_t DEFAULT_WRITE_CIPHER = PRIVMX_DEFAULT_FILE_CIPHER_ID;

/// A build error rather than an exception on the first write, should an unknown id be configured.
constexpr bool defaultWriteCipherIsKnown() {
    for (const auto& spec : CIPHERS) {
        if (spec.type == DEFAULT_WRITE_CIPHER) {
            return true;
        }
    }
    return false;
}
static_assert(defaultWriteCipherIsKnown(), "PRIVMX_DEFAULT_FILE_CIPHER_ID matches no known format");

const CipherSpec* findSpec(int64_t type) {
    for (const auto& spec : CIPHERS) {
        if (spec.type == type) {
            return &spec;
        }
    }
    return nullptr;
}

const CipherSpec& requireSpec(int64_t type) {
    const CipherSpec* spec = findSpec(type);
    if (spec == nullptr) {
        throw UnsupportedCipherTypeException("cipherType: " + std::to_string(type));
    }
    return *spec;
}

namespace cs = privmx::cryptoservice;

cs::BytesView view(const std::string& data) {
    return cs::BytesView(reinterpret_cast<const std::uint8_t*>(data.data()), data.size());
}

std::string str(const cs::Bytes& data) {
    return std::string(reinterpret_cast<const char*>(data.data()), data.size());
}

/**
 * The format's cipher, called **straight from the provider** rather than through `CryptoSuite`.
 *
 * `CryptoSuite::encrypt` wraps its output in a frame of its own carrying a suite tag; here the
 * frame belongs to the file format (`cipherType`) and must not be duplicated. So `store` reaches
 * for the raw cipher exactly as `CryptoSuite` itself does.
 *
 * Byte equivalence with the previous implementation (`privmx::crypto::Crypto`) was measured for
 * both modes across the edge lengths, zero included, before the swap.
 */
std::string symEncrypt(cs::SymAlg alg, const std::string& key, const std::string& iv, const std::string& plain) {
    cs::SymParams params{.cipher = alg, .key = view(key), .iv = view(iv), .aad = {}, .taglen = GCM_TAG_LENGTH};
    return str(core::cryptoProvider().encrypt(params, view(plain)));
}

std::string symDecrypt(cs::SymAlg alg, const std::string& key, const std::string& iv, const std::string& cipher) {
    cs::SymParams params{.cipher = alg, .key = view(key), .iv = view(iv), .aad = {}, .taglen = GCM_TAG_LENGTH};
    return str(core::cryptoProvider().decrypt(params, view(cipher)));
}

std::string indexToBE(std::uint64_t index) {
    std::uint32_t indexBE = Poco::ByteOrder::toBigEndian(static_cast<std::uint32_t>(index));
    return std::string(reinterpret_cast<char*>(&indexBE), 4);
}

} // namespace

FileCipher FileCipher::forType(int64_t cipherType) {
    requireSpec(cipherType);
    return FileCipher(cipherType);
}

FileCipher FileCipher::defaultForWrite() {
    return FileCipher(DEFAULT_WRITE_CIPHER);
}

FileCipher FileCipher::forContainerSuite(const std::optional<core::CryptoSuite>& suite) {
    if (!suite.has_value()) {
        return defaultForWrite();
    }
    const int64_t type = cipherForHashSuite(suite->id());
    if (type == 0) {
        // A suite with no corresponding file format. We do not quietly fall back to the default:
        // the container asked for specific algorithms, so writing its files with different ones
        // would be an unnoticeable divergence between the policy and what is actually on disk.
        throw UnsupportedCipherTypeException("no file format for crypto suite: " + suite->policyValue());
    }
    return FileCipher(type);
}

bool FileCipher::isKnown(int64_t cipherType) {
    return findSpec(cipherType) != nullptr;
}

std::vector<int64_t> FileCipher::known() {
    std::vector<int64_t> result;
    result.reserve(CIPHERS.size());
    for (const auto& spec : CIPHERS) {
        result.push_back(spec.type);
    }
    return result;
}

std::size_t FileCipher::ivLength() const {
    return requireSpec(_type).ivLength;
}

std::size_t FileCipher::hashLength() const {
    return requireSpec(_type).hashLength;
}

std::size_t FileCipher::paddingBlock() const {
    return requireSpec(_type).paddingBlock;
}

std::string FileCipher::chunkKey(const std::string& fileKey, std::uint64_t index) const {
    // The hash comes from the format's suite, not from a constant. For formats 1 and 2 that is
    // SHA-256 — exactly what `Crypto::sha256` computed here before, so files written earlier read
    // unchanged. Format 3 computes the same thing with SHA-512, which is why it has its own
    // `cipherType`.
    return core::CryptoSuite::forId(requireSpec(_type).hashSuite).hash(fileKey + indexToBE(index));
}

IChunkEncryptor::Chunk FileCipher::encryptChunk(const std::string& chunkKey, const std::string& plain) const {
    const CipherSpec& spec = requireSpec(_type);
    const std::string iv = core::CryptoSuite::randomBytes(spec.ivLength);

    if (spec.mode == Mode::Gcm) {
        // `[IV][ciphertext || tag]`. The tag is the tail of the cipher's output and it is what goes
        // into the hash table — there is no separate authenticator prepended to the frame.
        const std::string cipherWithTag = symEncrypt(cs::SymAlg::Aes256Gcm, chunkKey, iv, plain);
        return {
            .data = iv + cipherWithTag,
            .hmac = cipherWithTag.substr(cipherWithTag.size() - spec.hashLength)
        };
    }

    const std::string cipher = symEncrypt(cs::SymAlg::Aes256Cbc, chunkKey, iv, plain);
    const std::string ivWithCipher = iv + cipher;
    const std::string hmac = core::CryptoSuite::forId(spec.hashSuite).mac(chunkKey, ivWithCipher);
    return {.data = hmac + ivWithCipher, .hmac = hmac};
}

std::string FileCipher::decryptChunk(const std::string& chunkKey, const IChunkEncryptor::Chunk& chunk) const {
    const CipherSpec& spec = requireSpec(_type);

    if (spec.mode == Mode::Gcm) {
        if (chunk.data.size() < spec.fixedOverhead) {
            throw FileChunkInvalidCipherChecksumException();
        }
        const std::string iv = chunk.data.substr(0, spec.ivLength);
        // The AEAD mode authenticates on its own: a bad tag surfaces from the cipher rather than
        // from a separate comparison. We translate it to the same exception format 1 raises, so the
        // caller does not have to tell the formats apart.
        try {
            return symDecrypt(cs::SymAlg::Aes256Gcm, chunkKey, iv, chunk.data.substr(spec.ivLength));
        } catch (...) {
            throw FileChunkInvalidCipherChecksumException();
        }
    }

    const std::string ivWithCipher = chunk.data.substr(spec.hashLength);
    if (core::CryptoSuite::forId(spec.hashSuite).mac(chunkKey, ivWithCipher) !=
        chunk.data.substr(0, spec.hashLength)) {
        throw FileChunkInvalidCipherChecksumException();
    }
    const std::string iv = ivWithCipher.substr(0, spec.ivLength);
    return symDecrypt(cs::SymAlg::Aes256Cbc, chunkKey, iv, ivWithCipher.substr(spec.ivLength));
}

bool FileCipher::frameCarriesHash(const std::string& chunkData, const std::string& hash) const {
    const CipherSpec& spec = requireSpec(_type);
    if (chunkData.size() < spec.fixedOverhead || hash.size() != spec.hashLength) {
        return false;
    }
    if (spec.mode == Mode::Gcm) {
        return chunkData.compare(chunkData.size() - spec.hashLength, spec.hashLength, hash) == 0;
    }
    return chunkData.compare(0, spec.hashLength, hash) == 0;
}

std::string FileCipher::topHash(const std::string& topHashKey, const std::string& hashes) const {
    // As with `chunkKey`: the hash comes from the format's suite. For formats 1 and 2 that is
    // HMAC-SHA256, the same as before.
    return core::CryptoSuite::forId(requireSpec(_type).hashSuite).mac(topHashKey, hashes);
}

std::size_t FileCipher::encryptedChunkSize(std::size_t plainChunkSize) const {
    const CipherSpec& spec = requireSpec(_type);
    // PKCS#7 appends a full block even when the data is already a multiple of the block size.
    // A format that does not pad has `paddingBlock == 0`, and then we must not divide.
    const std::size_t padding =
        spec.paddingBlock == 0 ? 0 : spec.paddingBlock - (plainChunkSize % spec.paddingBlock);
    return plainChunkSize + padding + spec.fixedOverhead;
}

std::uint64_t FileCipher::encryptedFileSize(std::uint64_t fileSize, std::size_t plainChunkSize) const {
    if (fileSize == 0) {
        return 0;
    }
    const std::uint64_t parts = (fileSize + plainChunkSize - 1) / plainChunkSize;
    std::uint64_t lastChunkSize = fileSize % plainChunkSize;
    if (lastChunkSize == 0) {
        lastChunkSize = plainChunkSize;
    }
    return (parts - 1) * encryptedChunkSize(plainChunkSize) + encryptedChunkSize(lastChunkSize);
}
