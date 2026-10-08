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

#include <privmx/crypto/Crypto.hpp>
#include <privmx/endpoint/core/crypto/CryptoSuite.hpp>
#include <privmx/endpoint/store/StoreException.hpp>
#include <privmx/endpoint/store/StoreTypes.hpp>
#include <privmx/endpoint/store/encryptors/fileData/FileCipher.hpp>

using namespace privmx::endpoint;
using namespace privmx::endpoint::store;

namespace {

struct CipherSpec {
    int64_t type;
    std::size_t ivLength;
    std::size_t hashLength;
    /// 0 oznacza format bez dopelnienia blokowego.
    std::size_t paddingBlock;
    /**
     * Bajty, ktore ramka dokłada do jawnego tekstu **poza** dopelnieniem.
     *
     * Podane wprost, a nie liczone z `ivLength + hashLength`, bo te dwie wartosci skladaja sie na
     * narzut tylko przypadkiem: w formacie 1 skrot jest doklejany przed ramke, w formacie 2 tag
     * jest czescia wyjscia szyfru. Format, w ktorym skrot ma inna dlugosc niz uwierzytelniacz
     * w ramce, rozjechalby taki wzor po cichu.
     */
    std::size_t fixedOverhead;
};

/**
 * Rejestr formatow danych pliku.
 *
 * Stale formatu 1 pochodza z `StoreTypes.hpp`, bo to one opisywaly ten format, zanim dostal nazwe.
 * Raz wydanej wartosci `cipherType` nie wolno przedefiniowac.
 */
constexpr std::size_t GCM_IV_LENGTH = 12;
constexpr std::size_t GCM_TAG_LENGTH = 16;

constexpr std::array<CipherSpec, 2> CIPHERS{{
    {FileCipher::AES_CBC_HMAC_SHA256, IV_SIZE, HMAC_SIZE, CHUNK_PADDING, HMAC_SIZE + IV_SIZE},
    {FileCipher::AES_GCM, GCM_IV_LENGTH, GCM_TAG_LENGTH, 0, GCM_IV_LENGTH + GCM_TAG_LENGTH},
}};

/**
 * Format uzywany do zapisu nowych plikow; ustawiany przy konfiguracji buildu przez
 * `PRIVMX_DEFAULT_FILE_CIPHER`. Dotyczy **wylacznie zapisu** - `CIPHERS` pozostaje kompletne
 * niezaleznie od tej wartosci, bo `cipherType` kazdego pliku siedzi w jego wewnetrznym meta.
 */
#ifndef PRIVMX_DEFAULT_FILE_CIPHER_ID
#define PRIVMX_DEFAULT_FILE_CIPHER_ID 1
#endif
constexpr int64_t DEFAULT_WRITE_CIPHER = PRIVMX_DEFAULT_FILE_CIPHER_ID;

/// Blad budowania zamiast wyjatku przy pierwszym zapisie, gdyby podano nieznany identyfikator.
constexpr bool defaultWriteCipherIsKnown() {
    for (const auto& spec : CIPHERS) {
        if (spec.type == DEFAULT_WRITE_CIPHER) {
            return true;
        }
    }
    return false;
}
static_assert(defaultWriteCipherIsKnown(), "PRIVMX_DEFAULT_FILE_CIPHER_ID nie odpowiada zadnemu formatowi");

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
    requireSpec(_type);
    return privmx::crypto::Crypto::sha256(fileKey + indexToBE(index));
}

IChunkEncryptor::Chunk FileCipher::encryptChunk(const std::string& chunkKey, const std::string& plain) const {
    const CipherSpec& spec = requireSpec(_type);
    const std::string iv = core::CryptoSuite::randomBytes(spec.ivLength);

    if (spec.type == FileCipher::AES_GCM) {
        // `[IV][szyfrogram || tag]`. Tag jest koncowka wyjscia szyfru i to on trafia do tablicy
        // skrotow - nie ma tu osobnego uwierzytelniacza doklejanego przed ramke.
        const std::string cipherWithTag = privmx::crypto::Crypto::aes256GcmEncrypt(plain, chunkKey, iv);
        return {
            .data = iv + cipherWithTag,
            .hmac = cipherWithTag.substr(cipherWithTag.size() - spec.hashLength)
        };
    }

    const std::string cipher = privmx::crypto::Crypto::aes256CbcPkcs7Encrypt(plain, chunkKey, iv);
    const std::string ivWithCipher = iv + cipher;
    const std::string hmac = privmx::crypto::Crypto::hmacSha256(chunkKey, ivWithCipher);
    return {.data = hmac + ivWithCipher, .hmac = hmac};
}

std::string FileCipher::decryptChunk(const std::string& chunkKey, const IChunkEncryptor::Chunk& chunk) const {
    const CipherSpec& spec = requireSpec(_type);

    if (spec.type == FileCipher::AES_GCM) {
        if (chunk.data.size() < spec.fixedOverhead) {
            throw FileChunkInvalidCipherChecksumException();
        }
        const std::string iv = chunk.data.substr(0, spec.ivLength);
        // Uwierzytelnienie robi sam tryb AEAD: blad tagu wychodzi z `aes256GcmDecrypt`, a nie
        // z osobnego porownania. Tlumaczymy go na ten sam wyjatek co w formacie 1, zeby wolajacy
        // nie musial rozrozniac formatow.
        try {
            return privmx::crypto::Crypto::aes256GcmDecrypt(chunk.data.substr(spec.ivLength), chunkKey, iv);
        } catch (...) {
            throw FileChunkInvalidCipherChecksumException();
        }
    }

    const std::string ivWithCipher = chunk.data.substr(spec.hashLength);
    if (privmx::crypto::Crypto::hmacSha256(chunkKey, ivWithCipher) != chunk.data.substr(0, spec.hashLength)) {
        throw FileChunkInvalidCipherChecksumException();
    }
    const std::string iv = ivWithCipher.substr(0, spec.ivLength);
    return privmx::crypto::Crypto::aes256CbcPkcs7Decrypt(ivWithCipher.substr(spec.ivLength), chunkKey, iv);
}

bool FileCipher::frameCarriesHash(const std::string& chunkData, const std::string& hash) const {
    const CipherSpec& spec = requireSpec(_type);
    if (chunkData.size() < spec.fixedOverhead || hash.size() != spec.hashLength) {
        return false;
    }
    if (spec.type == FileCipher::AES_GCM) {
        return chunkData.compare(chunkData.size() - spec.hashLength, spec.hashLength, hash) == 0;
    }
    return chunkData.compare(0, spec.hashLength, hash) == 0;
}

std::string FileCipher::topHash(const std::string& topHashKey, const std::string& hashes) const {
    requireSpec(_type);
    return privmx::crypto::Crypto::hmacSha256(topHashKey, hashes);
}

std::size_t FileCipher::encryptedChunkSize(std::size_t plainChunkSize) const {
    const CipherSpec& spec = requireSpec(_type);
    // Dopelnienie PKCS#7 dokleja pelny blok takze wtedy, gdy dane sa juz wielokrotnoscia bloku.
    // Format bez dopelnienia ma `paddingBlock == 0` - wtedy nie wolno dzielic.
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
