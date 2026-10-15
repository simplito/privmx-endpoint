/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_ENDPOINT_STORE_FILECIPHER_HPP_
#define _PRIVMXLIB_ENDPOINT_STORE_FILECIPHER_HPP_

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include <privmx/endpoint/core/crypto/CryptoSuite.hpp>

#include "privmx/endpoint/store/interfaces/IChunkEncryptor.hpp"

namespace privmx {
namespace endpoint {
namespace store {

/**
 * @brief A file data format: one set of parameters and operations, selected by `cipherType`.
 *
 * **Why this is not `core::CryptoSuite`.** In a container, the algorithm suite changes only the
 * frame's *contents* — the tag sits in every frame separately, and frames are not addressed by
 * offset. A file is different: the hash length is the **hash-table stride**
 * (`chunkIndex * hashLength()`), and the sealed chunk size addresses chunks within the file on the
 * server (`index * encryptedChunkSize()`). Changing the algorithm therefore moves the whole file
 * layout, not just its contents — which is why it gets its own, coarser marker.
 *
 * **Where the marker lives.** `cipherType` in the file's internal meta. The field existed before:
 * it was written as `1` and checked on read. It is now a first-class format choice.
 *
 * Adding a format means an entry in the table in `FileCipher.cpp` plus its own `encryptChunk` and
 * `decryptChunk`. A `cipherType` value that has been issued must never be redefined — files written
 * with the old value are still on disk.
 */
class FileCipher {
public:
    /**
     * AES-256-CBC + PKCS#7, HMAC-SHA256 over `IV || ciphertext`.
     * Frame: `[32 B HMAC][16 B IV][ciphertext]`; the hash-table entry is the HMAC at the front.
     */
    static constexpr int64_t AES_CBC_HMAC_SHA256 = 1;

    /**
     * AES-256-GCM, SHA-256 hashes.
     * Frame: `[12 B IV][ciphertext || 16 B tag]`; the hash-table entry is the tag at the **end**.
     *
     * Against format 1: no block padding and half the hash-table stride (16 instead of 32 B), so
     * both the file on the server and its hash table are smaller. Authentication is the AEAD mode's
     * own, instead of a separate HMAC prepended to the frame.
     */
    static constexpr int64_t AES_GCM = 2;

    /**
     * AES-256-GCM, SHA-512 hashes.
     *
     * The frame is **identical** to format 2 — an AEAD tag is 16 B whatever the hash function, so
     * the hash-table stride and chunk addressing do not change. What differs is what the chunk key
     * and the table's top hash are computed with.
     *
     * It exists so that a container naming a SHA-512 suite gets its file data computed with the same
     * hash. Without this format a file in such a container would still use SHA-256 — the suite
     * choice would stop at the `store` boundary.
     */
    static constexpr int64_t AES_GCM_SHA512 = 3;

    /**
     * @brief The format with the given marker.
     * @throws UnsupportedCipherTypeException when this build does not know the format
     */
    static FileCipher forType(int64_t cipherType);

    /// @brief The format used for writing new files when nothing names one (level 1).
    static FileCipher defaultForWrite();

    /**
     * @brief The format matching the container's algorithm suite (level 2).
     *
     * File data is container data, so it should use the same algorithm and the same hash as the rest
     * of the container's contents. A container that named no suite gets `defaultForWrite()` — hence
     * the optional parameter: "no policy" is not the same as "a policy naming the default suite",
     * and only the former should follow the build setting.
     *
     * @throws UnsupportedCipherTypeException when no file format corresponds to the suite
     */
    static FileCipher forContainerSuite(const std::optional<core::CryptoSuite>& suite);

    static bool isKnown(int64_t cipherType);

    /// @brief Every known format. The read registry is complete in every build.
    static std::vector<int64_t> known();

    int64_t type() const { return _type; }

    std::size_t ivLength() const;

    /// @brief The chunk hash length. This is the **hash-table stride**, not just an output size.
    std::size_t hashLength() const;

    /// @brief The padding block size; 0 when the format does not pad.
    std::size_t paddingBlock() const;

    /**
     * @brief Whether the frame carries the given chunk hash.
     *
     * Checked before anything is decrypted: it catches the case where the server serves a chunk
     * from a different part of the file. Where the hash sits in the frame depends on the format —
     * format 1 puts it at the front, format 2 uses the AEAD tag at the end — which is why
     * `FileCipher` knows this and the caller does not.
     */
    bool frameCarriesHash(const std::string& chunkData, const std::string& hash) const;

    /// @brief The key for the chunk at this index. The index goes into the key, so chunks are not
    /// interchangeable.
    std::string chunkKey(const std::string& fileKey, std::uint64_t index) const;

    IChunkEncryptor::Chunk encryptChunk(const std::string& chunkKey, const std::string& plain) const;

    /**
     * @throws FileChunkInvalidCipherChecksumException when the frame's hash does not match
     */
    std::string decryptChunk(const std::string& chunkKey, const IChunkEncryptor::Chunk& chunk) const;

    /// @brief The hash binding the whole chunk hash table.
    std::string topHash(const std::string& topHashKey, const std::string& hashes) const;

    std::size_t encryptedChunkSize(std::size_t plainChunkSize) const;

    std::uint64_t encryptedFileSize(std::uint64_t fileSize, std::size_t plainChunkSize) const;

private:
    explicit FileCipher(int64_t type) : _type(type) {}

    int64_t _type;
};

} // namespace store
} // namespace endpoint
} // namespace privmx

#endif // _PRIVMXLIB_ENDPOINT_STORE_FILECIPHER_HPP_
