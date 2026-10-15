/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_ENDPOINT_CORE_CRYPTOSUITE_HPP_
#define _PRIVMXLIB_ENDPOINT_CORE_CRYPTOSUITE_HPP_

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace privmx {
namespace endpoint {
namespace core {

// Deliberately not in a `crypto` sub-namespace. The tree already has `privmx::crypto` and
// `privmx::endpoint::crypto`; a third would shadow them for code inside `core`, where the short
// form `crypto::PrivateKey` is in common use.

/**
 * @brief Identifier of an algorithm suite, written into the frame of encrypted data.
 *
 * The values are part of the data format — once used, a value must never change meaning.
 * A retired suite's number stays reserved and is not reused.
 */
enum class SuiteId : std::uint8_t {
    Unknown = 0x00,
    /// AES-256-GCM + SHA-256 + KDF. The default suite for writing.
    Aes256GcmSha256 = 0x01,
    /// AES-256-GCM + SHA-512 + KDF.
    Aes256GcmSha512 = 0x02,
};

/**
 * @brief The algorithm-selection layer.
 *
 * Endpoint modules call it by intent ("hash this", "encrypt with this key") and **do not name
 * algorithms**. The concrete algorithms follow from the suite, and the suite is recorded in the
 * data frame — which is what makes a read work regardless of what the author wrote with.
 *
 * Writing: the suite chosen for the operation (`defaultForWrite()` when nothing says otherwise).
 * Reading: always the tag read from the data.
 *
 * **Scope.** This layer covers data encrypted with the container's key. It does **not** cover the
 * integrity layer — DIO field checksums and `EncKeyV2.secretHash` stay on fixed SHA-256, versioned
 * by those structures' `structureVersion`. The reason: a reader has to know up front what to verify
 * with, and a DIO carries no suite tag; it is also part of the envelope rather than of what happens
 * inside the container. Do not move them onto this layer without changing the DIO format.
 *
 * Frame produced by `encrypt()`:
 * @code
 *   [1B SuiteId][IV][ciphertext || AEAD tag]
 * @endcode
 * The `SuiteId` byte is passed as AAD, so it is **authenticated** — rewriting the tag to name a
 * weaker suite invalidates the AEAD tag and decryption fails.
 */
class CryptoSuite {
public:
    /**
     * @brief The suite used for writing when nothing names one explicitly.
     *
     * Comes from a build-time constant (level 1 of the write-format choice).
     */
    static CryptoSuite defaultForWrite();

    /**
     * @brief The suite with the given identifier.
     * @throws UnknownCryptoSuiteException when this build does not know the identifier
     */
    static CryptoSuite forId(SuiteId id);

    /// @brief Whether this build can handle the given suite.
    static bool isKnown(SuiteId id);

    /**
     * @brief Every known suite.
     *
     * The read registry is **complete in every build** — the build configuration picks only the
     * default write suite, never the read range. Otherwise clients built differently could not
     * read each other's data.
     */
    static std::vector<SuiteId> known();

    /**
     * @brief The suite named by a container policy value (level 2 of the write-format choice).
     * @throws UnknownCryptoSuiteException when this build does not know the value
     */
    static CryptoSuite forPolicyValue(const std::string& value);

    /// @brief Whether a policy value names a suite this build knows.
    static bool isKnownPolicyValue(const std::string& value);

    SuiteId id() const { return _id; }

    /**
     * @brief How many bytes the frame adds to the plaintext: `[1B SuiteId][IV][AEAD tag]`.
     *
     * **This** suite's figure, not a global constant. `group` derives the sealed chunk size from it
     * and addresses chunks as `index * encryptedChunkSize(suite)`, so a differently-framed suite
     * moves every offset — which is why it has to be known before anything is read. A file envelope
     * carries it in its header.
     *
     * This used to be a `DEFAULT_FRAME_OVERHEAD` constant computed for the build's default suite.
     * It worked, because every suite in the registry has the same overhead — but it tied addressing
     * to a build setting rather than to the data.
     */
    std::size_t frameOverhead() const;

    /// @brief The suite's name as used in `ContainerPolicy::cryptoSuite`.
    std::string policyValue() const;

    /// @brief The symmetric key length this suite requires, in bytes.
    std::size_t keyLength() const;

    /**
     * @brief Random bytes.
     *
     * Static, because randomness does not depend on the suite — no part of it changes what "32
     * random bytes" means. Callers that need only entropy (generating keys, IVs, identifiers) do
     * not have to obtain a suite from anywhere.
     */
    static std::string randomBytes(std::size_t length);

    std::string hash(const std::string& data) const;
    std::string mac(const std::string& key, const std::string& data) const;
    std::string deriveKey(const std::string& secret, const std::string& label, std::size_t length) const;

    /**
     * @brief Encrypts and wraps the result in a frame carrying an authenticated suite tag.
     *
     * @throws crypto::EncryptInvalidKeyLengthException when the key length differs from `keyLength()`
     */
    std::string encrypt(const std::string& key, const std::string& plaintext) const;

    /**
     * @brief Decrypts a frame, picking the suite from its own tag.
     *
     * Static by design: a read does not need — and does not accept — an algorithm to be named.
     *
     * @throws MalformedCryptoFrameException when the frame is too short
     * @throws UnknownCryptoSuiteException when this build does not know the tag
     * @throws crypto::DecryptInvalidKeyLengthException when the key length differs from `keyLength()`
     */
    static std::string decrypt(const std::string& key, const std::string& framed);

    /// @brief Reads just the suite tag, without decrypting.
    static SuiteId readSuiteId(const std::string& framed);

private:
    explicit CryptoSuite(SuiteId id) : _id(id) {}

    SuiteId _id;
};

} // namespace core
} // namespace endpoint
} // namespace privmx

#endif // _PRIVMXLIB_ENDPOINT_CORE_CRYPTOSUITE_HPP_
