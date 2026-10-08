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
 * Format chunku 1 (cipherType = 1):
 *     [32 B HMAC-SHA256][16 B IV][AES-256-CBC + PKCS#7]
 *   chunkKey = sha256(fileKey || BE32(index))
 *   HMAC liczony z chunkKey nad (IV || szyfrogram)
 *
 * Format chunku 2 (cipherType = 2):
 *     [12 B IV][AES-256-GCM || 16 B tag]
 *   bez dopelnienia; wpisem tablicy skrotow jest tag AEAD z **konca** ramki
 *
 * Format zapisu wybiera `PRIVMX_DEFAULT_FILE_CIPHER` przy konfiguracji, wiec zaden z testow
 * opisujacych konkretny format nie moze opierac sie na `defaultForWrite()` - format podaje sie
 * jawnie. Testy, ktore maja zachodzic w kazdym formacie, chodza petla po `FileCipher::known()`,
 * dzieki czemu kolejny dopisany format od razu dostaje to pokrycie.
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

/**
 * Format 1 podawany **jawnie**, a nie przez `defaultForWrite()`.
 *
 * Ponizsze testy opisuja konkretny format, nie "ten, ktorym akurat zapisuje ten build" - a format
 * zapisu jest wybierany przy konfiguracji przez `PRIVMX_DEFAULT_FILE_CIPHER`. Bez tego przelaczenie
 * domyslnego formatu wywracalo te testy, chociaz format 1 nie ulegal zmianie.
 */
FileCipher cbc() {
    return FileCipher::forType(FileCipher::AES_CBC_HMAC_SHA256);
}

ChunkEncryptor cbcEncryptor(size_t chunkSize = CHUNK) {
    return ChunkEncryptor(KEY, chunkSize, cbc());
}

} // namespace

// ---------------------------------------------------------------------------------------------
// Uklad ramki chunku
// ---------------------------------------------------------------------------------------------

TEST(StoreFileFormat, ChunkLayoutIsHmacThenIvThenCipher) {
    ChunkEncryptor encryptor = cbcEncryptor();
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
    ChunkEncryptor encryptor = cbcEncryptor();
    const uint64_t index = 7;

    const auto chunk = encryptor.encrypt(index, repeat('b', 64));

    const std::string indexBE("\x00\x00\x00\x07", 4);
    const std::string expectedChunkKey = privmx::crypto::Crypto::sha256(KEY + indexBE);
    const std::string ivWithCipher = chunk.data.substr(HMAC_SIZE);

    EXPECT_EQ(privmx::crypto::Crypto::hmacSha256(expectedChunkKey, ivWithCipher), chunk.hmac);
}

TEST(StoreFileFormat, RoundTripForEdgeSizes) {
    ChunkEncryptor encryptor = cbcEncryptor();

    for (const size_t size : {size_t{0}, size_t{1}, size_t{15}, size_t{16}, size_t{17}, size_t{4096}}) {
        const std::string plain = repeat('x', size);
        const auto chunk = encryptor.encrypt(3, plain);
        EXPECT_EQ(plain, encryptor.decrypt(3, chunk)) << "rozmiar " << size;
    }
}

/// Indeks chunku wchodzi do klucza, wiec chunk odczytany pod innym indeksem musi zostac odrzucony.
/// To jest jedyne, co powstrzymuje zamiane chunkow miejscami w obrebie pliku.
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

    chunk.hmac[0] ^= 0xFF; // tak, jakby lista skrotow podawala inny hash niz ramka
    EXPECT_THROW(encryptor.decrypt(0, chunk), FileChunkInvalidChecksumException);
}

TEST(StoreFileFormat, HasHashComparesThePrefix) {
    ChunkEncryptor encryptor = cbcEncryptor();
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
    EXPECT_EQ(CHUNK + 16 + HMAC_SIZE + IV_SIZE, cbcEncryptor().getEncryptedChunkSize());
    EXPECT_EQ(100u + 12 + HMAC_SIZE + IV_SIZE, cbcEncryptor(100).getEncryptedChunkSize());
}

TEST(StoreFileFormat, EncryptedFileSizeMatchesWhatTheChunksActuallyWeigh) {
    constexpr size_t smallChunk = 1024;
    ChunkEncryptor encryptor = cbcEncryptor(smallChunk);

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

/// Format zapisu wybiera `PRIVMX_DEFAULT_FILE_CIPHER` przy konfiguracji, wiec test nie moze
/// przybijac konkretnej wartosci. Przybija to, co musi byc prawda w **kazdym** buildzie: ze
/// domyslna wartosc jest formatem, ktory ten build potrafi odczytac.
TEST(StoreFileCipher, DefaultForWriteIsAFormatThisBuildCanRead) {
    EXPECT_TRUE(FileCipher::isKnown(FileCipher::defaultForWrite().type()));
    // Raz wydanych znacznikow nie wolno przedefiniowac.
    EXPECT_EQ(1, FileCipher::AES_CBC_HMAC_SHA256);
    EXPECT_EQ(2, FileCipher::AES_GCM);
}

/// Sprawdza, ze `PRIVMX_DEFAULT_FILE_CIPHER` faktycznie **doszlo do kompilacji biblioteki**, a nie
/// tylko wypisalo sie przy konfiguracji. Taka cicha strata zdarzyla sie juz raz: definicje dodane
/// przez `target_compile_definitions` kasowal pozniejszy `set_target_properties(... COMPILE_DEFINITIONS ...)`,
/// wiec build deklarowal jeden format, a zapisywal innym. Test porownuje wartosc widziana przez
/// biblioteke z ta, ktora CMake podal temu plikowi.
TEST(StoreFileCipher, BuildOptionReachedTheLibrary) {
    EXPECT_EQ(
        static_cast<int64_t>(PRIVMX_DEFAULT_FILE_CIPHER_ID), FileCipher::defaultForWrite().type()
    ) << "PRIVMX_DEFAULT_FILE_CIPHER nie dotarlo do privmxendpointstore";
}

/// Parametry formatu musza zgadzac sie ze stalymi, ktore opisywaly go wczesniej - inaczej
// refaktor po cichu zmienilby uklad pliku.
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

/// `ChunkStreamer` liczyl rozmiar pliku wlasna kopia tego samego wzoru co `ChunkEncryptor`.
/// Teraz oba ida przez `FileCipher`, wiec zgodnosc jest z konstrukcji - ten test to przybija,
/// bo rozjazd tych dwoch liczb oznacza czytanie nie tego fragmentu pliku.
TEST(StoreFileCipher, SizeArithmeticHasOneSource) {
    constexpr size_t chunkSize = 1024;

    for (const int64_t type : FileCipher::known()) {
        const FileCipher cipher = FileCipher::forType(type);
        ChunkEncryptor encryptor(KEY, chunkSize, cipher);

        for (const uint64_t fileSize :
             {uint64_t{0}, uint64_t{1}, uint64_t{1023}, uint64_t{1024}, uint64_t{5000}}) {
            EXPECT_EQ(cipher.encryptedFileSize(fileSize, chunkSize), encryptor.getEncryptedFileSize(fileSize))
                << "format " << type << ", rozmiar " << fileSize;
        }
        EXPECT_EQ(cipher.encryptedChunkSize(chunkSize), encryptor.getEncryptedChunkSize())
            << "format " << type;
    }
}

// ---------------------------------------------------------------------------------------------
// To, co musi zachodzic w **kazdym** formacie. Te testy sa po to, zeby kolejny dopisany format
// nie przeszedl bez pokrycia - petla po `FileCipher::known()` obejmie go sama.
// ---------------------------------------------------------------------------------------------

TEST(StoreFileCipherAllFormats, RoundTripForEdgeSizes) {
    for (const int64_t type : FileCipher::known()) {
        ChunkEncryptor encryptor(KEY, CHUNK, FileCipher::forType(type));

        for (const size_t size : {size_t{0}, size_t{1}, size_t{15}, size_t{16}, size_t{17}, size_t{4096}}) {
            const std::string plain = repeat('x', size);
            const auto chunk = encryptor.encrypt(3, plain);
            EXPECT_EQ(plain, encryptor.decrypt(3, chunk)) << "format " << type << ", rozmiar " << size;
        }
    }
}

/// Skrot oddany obok ramki i skrot niesiony w ramce to ta sama rzecz - niezaleznie od tego,
/// gdzie w ramce format go trzyma. Na tym stoi sprawdzenie przed odszyfrowaniem.
TEST(StoreFileCipherAllFormats, ChunkHashIsTheOneCarriedInTheFrame) {
    for (const int64_t type : FileCipher::known()) {
        const FileCipher cipher = FileCipher::forType(type);
        ChunkEncryptor encryptor(KEY, CHUNK, cipher);

        const auto chunk = encryptor.encrypt(0, repeat('h', 64));

        EXPECT_EQ(cipher.hashLength(), chunk.hmac.size()) << "format " << type;
        EXPECT_TRUE(encryptor.hasHash(chunk.data, chunk.hmac)) << "format " << type;
        EXPECT_FALSE(encryptor.hasHash(chunk.data, std::string(cipher.hashLength(), '\0')))
            << "format " << type;
        EXPECT_FALSE(encryptor.hasHash("za krotkie", chunk.hmac)) << "format " << type;
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

/// Indeks chunku wchodzi do klucza w kazdym formacie, wiec chunki nie sa zamienne miejscami.
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
// Format 2 (cipherType = 2): AES-256-GCM, ramka `[12 B IV][szyfrogram || 16 B tag]`.
// Tak samo doslownie jak przy formacie 1 - te liczby adresuja chunki w pliku.
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
    // AEAD jest szyfrem strumieniowym - nie dopelnia, wiec plik nie rosnie do wielokrotnosci bloku.
    EXPECT_EQ(0u, cipher.paddingBlock());
}

TEST(StoreFileGcmFormat, ChunkLayoutIsIvThenCipherWithTrailingTag) {
    ChunkEncryptor encryptor(KEY, CHUNK, gcm());
    const std::string plain = repeat('a', 100);

    const auto chunk = encryptor.encrypt(0, plain);

    // Brak dopelnienia: dlugosc to dokladnie IV + tekst jawny + tag.
    EXPECT_EQ(GCM_IV + 100u + GCM_TAG, chunk.data.size());
    // Skrotem chunku jest tag AEAD, czyli **koncowka** ramki - inaczej niz w formacie 1.
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

    chunk.hmac[0] ^= 0xFF; // tak, jakby lista skrotow podawala inny hash niz ramka
    EXPECT_THROW(encryptor.decrypt(0, chunk), FileChunkInvalidChecksumException);
}

/// Naruszenie szyfrogramu lapie samo uwierzytelnienie AEAD, a nie osobny HMAC przed ramka.
TEST(StoreFileGcmFormat, TamperedCiphertextIsRejectedByTheAeadTag) {
    ChunkEncryptor encryptor(KEY, CHUNK, gcm());
    auto chunk = encryptor.encrypt(0, repeat('d', 64));

    chunk.data[GCM_IV] ^= 0xFF; // pierwszy bajt szyfrogramu, za IV
    EXPECT_THROW(encryptor.decrypt(0, chunk), FileChunkInvalidCipherChecksumException);
}

/// Dwa formaty daja dwa rozne uklady pliku - gdyby ktorys policzyl rozmiar drugiego, chunki
/// czytalyby sie spod zlych przesuniec. Ten test przybija, ze sa faktycznie rozlaczne.
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
