/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

/**
 * Testy charakteryzujace format danych pliku w `store`.
 *
 * Powstaly przed przebudowa tego formatu, bo `store` nie mial zadnych testow jednostkowych -
 * tylko e2e, ktore wymagaja Bridge'a i nie pokazuja, co dokladnie leci na dysk. Ich zadaniem nie
 * jest opisanie, jak format powinien wygladac, tylko **przybicie tego, jak wyglada dzis**, zeby
 * refaktor dalo sie uznac za bezpieczny.
 *
 * Dlatego asercje sa celowo doslowne: konkretne rozmiary, konkretne przesuniecia, konkretny uklad
 * ramki. Jesli zmiana formatu jest zamierzona, te liczby nalezy zmienic swiadomie - a nie
 * dopasowac je do nowego wyniku.
 *
 * Dzisiejszy format chunku (cipherType = 1):
 *     [32 B HMAC-SHA256][16 B IV][AES-256-CBC + PKCS#7]
 *   chunkKey = sha256(fileKey || BE32(index))
 *   HMAC liczony z chunkKey nad (IV || szyfrogram)
 */

#include <string>

#include <gtest/gtest.h>

#include <privmx/crypto/Crypto.hpp>
#include <privmx/endpoint/store/StoreException.hpp>
#include <privmx/endpoint/store/StoreTypes.hpp>
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

} // namespace

// ---------------------------------------------------------------------------------------------
// Uklad ramki chunku
// ---------------------------------------------------------------------------------------------

TEST(StoreFileFormat, ChunkLayoutIsHmacThenIvThenCipher) {
    ChunkEncryptor encryptor(KEY, CHUNK);
    const std::string plain = repeat('a', 100);

    const auto chunk = encryptor.encrypt(0, plain);

    ASSERT_GE(chunk.data.size(), HMAC_SIZE + IV_SIZE);
    EXPECT_EQ(32u, HMAC_SIZE);
    EXPECT_EQ(16u, IV_SIZE);
    // HMAC stoi na poczatku i jest tym samym, co oddane obok w `Chunk::hmac`.
    EXPECT_EQ(chunk.hmac, chunk.data.substr(0, HMAC_SIZE));
    EXPECT_EQ(HMAC_SIZE, chunk.hmac.size());
    // 100 bajtow + PKCS#7 do wielokrotnosci 16 = 112.
    EXPECT_EQ(HMAC_SIZE + IV_SIZE + 112u, chunk.data.size());
}

/// Klucz chunku i HMAC sa deterministyczne - ten test wiaze je z konkretnymi prymitywami,
/// wiec zmiana ktoregokolwiek z nich przestanie byc niezauwazalna.
TEST(StoreFileFormat, ChunkKeyAndHmacFollowTheDocumentedFormula) {
    ChunkEncryptor encryptor(KEY, CHUNK);
    const uint64_t index = 7;

    const auto chunk = encryptor.encrypt(index, repeat('b', 64));

    const std::string indexBE("\x00\x00\x00\x07", 4);
    const std::string expectedChunkKey = privmx::crypto::Crypto::sha256(KEY + indexBE);
    const std::string ivWithCipher = chunk.data.substr(HMAC_SIZE);

    EXPECT_EQ(privmx::crypto::Crypto::hmacSha256(expectedChunkKey, ivWithCipher), chunk.hmac);
}

TEST(StoreFileFormat, RoundTripForEdgeSizes) {
    ChunkEncryptor encryptor(KEY, CHUNK);

    for (const size_t size : {size_t{0}, size_t{1}, size_t{15}, size_t{16}, size_t{17}, size_t{4096}}) {
        const std::string plain = repeat('x', size);
        const auto chunk = encryptor.encrypt(3, plain);
        EXPECT_EQ(plain, encryptor.decrypt(3, chunk)) << "rozmiar " << size;
    }
}

/// Indeks chunku wchodzi do klucza, wiec chunk odczytany pod innym indeksem musi zostac odrzucony.
/// To jest jedyne, co powstrzymuje zamiane chunkow miejscami w obrebie pliku.
TEST(StoreFileFormat, ChunkFromAnotherIndexIsRejected) {
    ChunkEncryptor encryptor(KEY, CHUNK);
    const auto chunk = encryptor.encrypt(1, repeat('c', 64));

    EXPECT_THROW(encryptor.decrypt(2, chunk), FileChunkInvalidCipherChecksumException);
}

TEST(StoreFileFormat, TamperedCiphertextIsRejected) {
    ChunkEncryptor encryptor(KEY, CHUNK);
    auto chunk = encryptor.encrypt(0, repeat('d', 64));

    chunk.data[chunk.data.size() - 1] ^= 0xFF;
    EXPECT_THROW(encryptor.decrypt(0, chunk), FileChunkInvalidCipherChecksumException);
}

TEST(StoreFileFormat, HmacNotMatchingTheListIsRejectedBeforeDecryption) {
    ChunkEncryptor encryptor(KEY, CHUNK);
    auto chunk = encryptor.encrypt(0, repeat('e', 64));

    chunk.hmac[0] ^= 0xFF; // tak, jakby lista skrotow podawala inny hash niz ramka
    EXPECT_THROW(encryptor.decrypt(0, chunk), FileChunkInvalidChecksumException);
}

TEST(StoreFileFormat, HasHashComparesThePrefix) {
    ChunkEncryptor encryptor(KEY, CHUNK);
    const auto chunk = encryptor.encrypt(0, repeat('f', 64));

    EXPECT_TRUE(encryptor.hasHash(chunk.data, chunk.hmac));
    EXPECT_FALSE(encryptor.hasHash(chunk.data, std::string(HMAC_SIZE, '\0')));
    EXPECT_FALSE(encryptor.hasHash("za krotkie", chunk.hmac));
}

// ---------------------------------------------------------------------------------------------
// Arytmetyka rozmiarow. Te liczby adresuja chunki w pliku na serwerze, wiec kazda pomylka tutaj
// to czytanie nie tego fragmentu.
// ---------------------------------------------------------------------------------------------

TEST(StoreFileFormat, EncryptedChunkSizeIsPlainPlusPaddingPlusHmacAndIv) {
    // chunkSize bedacy wielokrotnoscia 16 i tak dostaje pelny blok dopelnienia PKCS#7.
    EXPECT_EQ(CHUNK + 16 + HMAC_SIZE + IV_SIZE, ChunkEncryptor(KEY, CHUNK).getEncryptedChunkSize());
    EXPECT_EQ(100u + 12 + HMAC_SIZE + IV_SIZE, ChunkEncryptor(KEY, 100).getEncryptedChunkSize());
}

TEST(StoreFileFormat, EncryptedFileSizeMatchesWhatTheChunksActuallyWeigh) {
    constexpr size_t smallChunk = 1024;
    ChunkEncryptor encryptor(KEY, smallChunk);

    EXPECT_EQ(0u, encryptor.getEncryptedFileSize(0));

    // Jeden niepelny chunk.
    EXPECT_EQ(
        encryptor.encrypt(0, repeat('g', 100)).data.size(), encryptor.getEncryptedFileSize(100)
    );

    // Dwa chunki: jeden pelny + reszta. Liczymy to tak, jak faktycznie wyjdzie z szyfrowania.
    const size_t full = encryptor.encrypt(0, repeat('g', smallChunk)).data.size();
    const size_t tail = encryptor.encrypt(1, repeat('g', 100)).data.size();
    EXPECT_EQ(full + tail, encryptor.getEncryptedFileSize(smallChunk + 100));

    // Rozmiar bedacy dokladna wielokrotnoscia chunku - ostatni chunk jest pelny, nie pusty.
    EXPECT_EQ(2 * full, encryptor.getEncryptedFileSize(2 * smallChunk));
}

// ---------------------------------------------------------------------------------------------
// Lista skrotow. `HMAC_SIZE` jest tu **krokiem tablicy**, nie tylko dlugoscia skrotu.
// ---------------------------------------------------------------------------------------------

TEST(StoreFileFormat, HashListStrideIsHmacSize) {
    const std::string topKey(32, 't');
    const std::string h0(HMAC_SIZE, '0');
    const std::string h1(HMAC_SIZE, '1');
    const std::string hashes = h0 + h1;

    HmacList list(topKey, privmx::crypto::Crypto::hmacSha256(topKey, hashes), hashes);

    EXPECT_EQ(HMAC_SIZE, list.getHashSize());
    EXPECT_EQ(h0, list.getHash(0));
    EXPECT_EQ(h1, list.getHash(1));
    EXPECT_TRUE(list.verifyHash(1, h1));
}

TEST(StoreFileFormat, HashListTopHashIsHmacOverTheWholeTable) {
    const std::string topKey(32, 't');
    const std::string hashes = std::string(HMAC_SIZE, '0') + std::string(HMAC_SIZE, '1');

    HmacList list(topKey, privmx::crypto::Crypto::hmacSha256(topKey, hashes), hashes);

    EXPECT_EQ(privmx::crypto::Crypto::hmacSha256(topKey, hashes), list.getTopHash());
    EXPECT_TRUE(list.verifyTopHash(privmx::crypto::Crypto::hmacSha256(topKey, hashes)));
}

TEST(StoreFileFormat, HashListRejectsTableThatIsNotAWholeNumberOfHashes) {
    const std::string topKey(32, 't');
    const std::string hashes(HMAC_SIZE + 1, '0');

    EXPECT_THROW(
        HmacList(topKey, privmx::crypto::Crypto::hmacSha256(topKey, hashes), hashes), InvalidHashSizeException
    );
}

TEST(StoreFileFormat, HashListRejectsWrongTopHash) {
    const std::string topKey(32, 't');
    const std::string hashes(HMAC_SIZE, '0');

    EXPECT_THROW(HmacList(topKey, std::string(HMAC_SIZE, 'z'), hashes), InvalidFileTopHashException);
}

TEST(StoreFileFormat, HashListAppendsAndTruncates) {
    const std::string topKey(32, 't');
    HmacList list(topKey, privmx::crypto::Crypto::hmacSha256(topKey, ""), "");

    list.set(0, std::string(HMAC_SIZE, '0'));
    list.set(1, std::string(HMAC_SIZE, '1'));
    EXPECT_EQ(2 * HMAC_SIZE, list.getAll().size());

    // Zapis w srodku z obcieciem przycina tablice do tego chunku wlacznie.
    list.set(0, std::string(HMAC_SIZE, '2'), true);
    EXPECT_EQ(HMAC_SIZE, list.getAll().size());
    EXPECT_EQ(std::string(HMAC_SIZE, '2'), list.getHash(0));

    EXPECT_THROW(list.set(5, std::string(HMAC_SIZE, '3')), HashIndexOutOfBoundsException);
    EXPECT_THROW(list.set(1, std::string(HMAC_SIZE - 1, '4')), InvalidHashSizeException);
}

// ---------------------------------------------------------------------------------------------
// Warstwa `FileCipher`: wybor formatu po znaczniku `cipherType`.
// ---------------------------------------------------------------------------------------------

TEST(StoreFileCipher, DefaultForWriteIsTheFormatIssuedSoFar) {
    EXPECT_EQ(FileCipher::AES_CBC_HMAC_SHA256, FileCipher::defaultForWrite().type());
    EXPECT_EQ(1, FileCipher::AES_CBC_HMAC_SHA256);
}

/// Parametry formatu musza zgadzac sie ze stalymi, ktore opisywaly go wczesniej - inaczej
// refaktor po cichu zmienilby uklad pliku.
TEST(StoreFileCipher, ParametersMatchTheConstantsTheyReplaced) {
    const FileCipher cipher = FileCipher::defaultForWrite();

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

/// `ChunkStreamer` liczyl rozmiar pliku wlasna kopia tego samego wzoru co `ChunkEncryptor`.
/// Teraz oba ida przez `FileCipher`, wiec zgodnosc jest z konstrukcji - ten test to przybija,
/// bo rozjazd tych dwoch liczb oznacza czytanie nie tego fragmentu pliku.
TEST(StoreFileCipher, SizeArithmeticHasOneSource) {
    const FileCipher cipher = FileCipher::defaultForWrite();
    constexpr size_t chunkSize = 1024;
    ChunkEncryptor encryptor(KEY, chunkSize);

    for (const uint64_t fileSize : {uint64_t{0}, uint64_t{1}, uint64_t{1023}, uint64_t{1024}, uint64_t{5000}}) {
        EXPECT_EQ(cipher.encryptedFileSize(fileSize, chunkSize), encryptor.getEncryptedFileSize(fileSize))
            << "rozmiar " << fileSize;
    }
    EXPECT_EQ(cipher.encryptedChunkSize(chunkSize), encryptor.getEncryptedChunkSize());
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
