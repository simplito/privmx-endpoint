/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include <array>

#include <privmx/cryptoservice/base/CoreTypes.hpp>

#include <privmx/endpoint/core/ConvertedExceptions.hpp>
#include <privmx/endpoint/core/CoreException.hpp>
#include <privmx/endpoint/core/crypto/CryptoErrors.hpp>
#include <privmx/endpoint/core/crypto/CryptoSuite.hpp>
#include <privmx/endpoint/core/crypto/ProviderAccess.hpp>

using namespace privmx::endpoint::core;

namespace cs = privmx::cryptoservice;

namespace {

/// The parameters of a single algorithm suite.
struct SuiteSpec {
    SuiteId id;
    cs::SymAlg sym;
    cs::Hash hash;
    cs::Kdf kdf;
    std::size_t keyLength;
    std::size_t ivLength;
    /// The name used in `ContainerPolicy::cryptoSuite`. A policy value is capped at 32 characters.
    const char* policyName;
};

/**
 * The suite registry.
 *
 * Complete in every build — see CryptoSuite::known().
 * Both entries are AEAD modes, because only those let the suite tag be authenticated through AAD.
 * AES-256-CBC + HMAC cannot do that (the provider API has no AAD), so the tag would sit outside the
 * MAC's reach — exactly the weakness the old format's CipherType byte has today.
 */
constexpr std::array<SuiteSpec, 2> SUITES{{
    {SuiteId::Aes256GcmSha256, cs::SymAlg::Aes256Gcm, cs::Hash::Sha256, cs::Kdf::Kdf, 32, 12, "aes256gcm-sha256"},
    {SuiteId::Aes256GcmSha512, cs::SymAlg::Aes256Gcm, cs::Hash::Sha512, cs::Kdf::Kdf, 32, 12, "aes256gcm-sha512"},
}};

/**
 * The suite used for writing when nothing names another one (level 1 of the format choice).
 *
 * Set at build configuration time through `PRIVMX_DEFAULT_CRYPTO_SUITE`. It affects **writing only**
 * — `SUITES` above stays complete whatever this value is, because every frame carries its own tag.
 * A client built with one value reads data written with any other.
 */
#ifndef PRIVMX_DEFAULT_CRYPTO_SUITE_ID
#define PRIVMX_DEFAULT_CRYPTO_SUITE_ID 1
#endif
constexpr SuiteId DEFAULT_WRITE_SUITE = static_cast<SuiteId>(PRIVMX_DEFAULT_CRYPTO_SUITE_ID);

/// A build error instead of an exception on the first write, should someone pass an unknown id.
constexpr bool defaultWriteSuiteIsKnown() {
    for (const auto& spec : SUITES) {
        if (spec.id == DEFAULT_WRITE_SUITE) {
            return true;
        }
    }
    return false;
}
static_assert(defaultWriteSuiteIsKnown(), "PRIVMX_DEFAULT_CRYPTO_SUITE_ID matches no known suite");

/// The length of the AEAD tag the provider appends to the ciphertext.
constexpr std::size_t AEAD_TAG_LENGTH = 16;

const SuiteSpec* findSpec(SuiteId id) {
    for (const auto& spec : SUITES) {
        if (spec.id == id) {
            return &spec;
        }
    }
    return nullptr;
}

const SuiteSpec& requireSpec(SuiteId id) {
    const SuiteSpec* spec = findSpec(id);
    if (spec == nullptr) {
        throw UnknownCryptoSuiteException("suite id: " + std::to_string(static_cast<unsigned>(id)));
    }
    return *spec;
}

cs::BytesView view(const std::string& data) {
    return cs::BytesView(reinterpret_cast<const std::uint8_t*>(data.data()), data.size());
}

std::string str(const cs::Bytes& data) {
    return std::string(reinterpret_cast<const char*>(data.data()), data.size());
}

/**
 * Checks the key length before handing it to the provider.
 *
 * This is not a courtesy to the caller but a memory-safety condition: `CryptoProvider` passes
 * `key.data()` to `EVP_EncryptInit_ex` **without looking at `key.size()`**, and OpenSSL reads as
 * many bytes as the cipher requires. A shorter key means a read past the end of the buffer. The old
 * `CryptoPrivmx` had the same check ("required: 32, received: N") and it must not be lost in the
 * migration.
 */
void requireKeyLength(const SuiteSpec& spec, const std::string& key, bool forEncryption) {
    if (key.size() == spec.keyLength) {
        return;
    }
    const std::string detail =
        "required: " + std::to_string(spec.keyLength) + ", received: " + std::to_string(key.size());
    if (forEncryption) {
        throw privmx::endpoint::crypto::EncryptInvalidKeyLengthException(detail);
    }
    throw privmx::endpoint::crypto::DecryptInvalidKeyLengthException(detail);
}

} // namespace

CryptoSuite CryptoSuite::defaultForWrite() {
    return CryptoSuite(DEFAULT_WRITE_SUITE);
}

CryptoSuite CryptoSuite::forId(SuiteId id) {
    requireSpec(id);
    return CryptoSuite(id);
}

bool CryptoSuite::isKnown(SuiteId id) {
    return findSpec(id) != nullptr;
}

CryptoSuite CryptoSuite::forPolicyValue(const std::string& value) {
    for (const auto& spec : SUITES) {
        if (value == spec.policyName) {
            return CryptoSuite(spec.id);
        }
    }
    throw UnknownCryptoSuiteException("policy value: '" + value + "'");
}

bool CryptoSuite::isKnownPolicyValue(const std::string& value) {
    for (const auto& spec : SUITES) {
        if (value == spec.policyName) {
            return true;
        }
    }
    return false;
}

std::string CryptoSuite::policyValue() const {
    return requireSpec(_id).policyName;
}

std::size_t CryptoSuite::keyLength() const {
    return requireSpec(_id).keyLength;
}

std::size_t CryptoSuite::frameOverhead() const {
    // `[1B SuiteId][IV][ciphertext || tag]`. The ciphertext is as long as the plaintext — an AEAD
    // mode does not pad — so the overhead is constant per suite and does not depend on data length.
    return 1 + requireSpec(_id).ivLength + AEAD_TAG_LENGTH;
}

std::vector<SuiteId> CryptoSuite::known() {
    std::vector<SuiteId> result;
    result.reserve(SUITES.size());
    for (const auto& spec : SUITES) {
        result.push_back(spec.id);
    }
    return result;
}

std::string CryptoSuite::randomBytes(std::size_t length) {
    return mapCryptoErrors("CryptoSuite::randomBytes", [&] { return str(cryptoProvider().randomBytes(length)); });
}

std::string CryptoSuite::hash(const std::string& data) const {
    return mapCryptoErrors("CryptoSuite::hash", [&] {
        return str(cryptoProvider().digest(requireSpec(_id).hash, view(data)));
    });
}

std::string CryptoSuite::mac(const std::string& key, const std::string& data) const {
    return mapCryptoErrors("CryptoSuite::mac", [&] {
        return str(cryptoProvider().hmac(requireSpec(_id).hash, view(key), view(data)));
    });
}

std::string CryptoSuite::deriveKey(const std::string& secret, const std::string& label, std::size_t length) const {
    return mapCryptoErrors("CryptoSuite::deriveKey", [&] {
        const SuiteSpec& spec = requireSpec(_id);
        cs::KdfParams params{
            .kdf = spec.kdf, .length = length, .hash = spec.hash, .rounds = 0, .salt = {}, .label = label
        };
        return str(cryptoProvider().derive(params, view(secret)));
    });
}

std::string CryptoSuite::encrypt(const std::string& key, const std::string& plaintext) const {
    return mapCryptoErrors("CryptoSuite::encrypt", [&] {
        const SuiteSpec& spec = requireSpec(_id);
        requireKeyLength(spec, key, true);
        const std::string iv = randomBytes(spec.ivLength);
        // The suite tag is both the frame's first byte and the AAD, so swapping it invalidates the
        // AEAD tag.
        const std::string tag(1, static_cast<char>(spec.id));
        cs::SymParams params{
            .cipher = spec.sym, .key = view(key), .iv = view(iv), .aad = view(tag), .taglen = AEAD_TAG_LENGTH
        };
        return tag + iv + str(cryptoProvider().encrypt(params, view(plaintext)));
    });
}

SuiteId CryptoSuite::readSuiteId(const std::string& framed) {
    if (framed.empty()) {
        throw MalformedCryptoFrameException("empty frame");
    }
    return static_cast<SuiteId>(static_cast<std::uint8_t>(framed[0]));
}

std::string CryptoSuite::decrypt(const std::string& key, const std::string& framed) {
    return mapCryptoErrors("CryptoSuite::decrypt", [&] {
        const SuiteSpec& spec = requireSpec(readSuiteId(framed));
        requireKeyLength(spec, key, false);
        const std::size_t headerLength = 1 + spec.ivLength;
        // Equality is valid: a frame of exactly `header + tag` is an encrypted **empty** plaintext.
        // Rejecting it made an empty field unreadable, even though writing one went through fine.
        if (framed.size() < headerLength + AEAD_TAG_LENGTH) {
            throw MalformedCryptoFrameException("frame shorter than its header, iv and tag");
        }
        const std::string tag = framed.substr(0, 1);
        const std::string iv = framed.substr(1, spec.ivLength);
        const std::string ciphertext = framed.substr(headerLength);
        cs::SymParams params{
            .cipher = spec.sym, .key = view(key), .iv = view(iv), .aad = view(tag), .taglen = AEAD_TAG_LENGTH
        };
        return str(cryptoProvider().decrypt(params, view(ciphertext)));
    });
}
