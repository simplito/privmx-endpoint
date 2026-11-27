/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

/**
 * The file format an Inbox's attachments are written with, carried in its **public** data.
 *
 * An Inbox takes entries from clients that are nobody: they can read neither the Inbox policy nor
 * the inner Store's, so the only place they can learn the format from is the public view. If the
 * field does not survive the round trip, every attachment silently falls back to the sender's build
 * default — readable, because `cipherType` travels in each file's own meta, and so invisible until
 * someone checks what algorithm an Inbox created with a named suite is actually using.
 *
 * `ChunkStreamerCipher.*` in StoreFileFormatTest covers the other half: applying the format to a
 * handle that already exists.
 */

#include <optional>
#include <string>

#include <gtest/gtest.h>

#include <privmx/endpoint/core/Buffer.hpp>
#include <privmx/endpoint/core/CoreTypes.hpp>
#include <privmx/endpoint/core/crypto/CryptoSuite.hpp>
#include <privmx/endpoint/core/crypto/PrivateKey.hpp>
#include <privmx/endpoint/inbox/InboxTypes.hpp>
#include <privmx/endpoint/inbox/encryptors/inbox/InboxDataProcessorV5.hpp>
#include <privmx/endpoint/store/encryptors/fileData/FileCipher.hpp>

using namespace privmx::endpoint;

namespace {

/// Everything `packForServer` needs; only `publicData.fileCipherType` is under test.
inbox::InboxDataProcessorModelV5 modelNaming(
    const core::PrivateKey& author,
    const std::optional<int64_t>& fileCipherType
) {
    // The private DIO is signed by the author and refuses to name anybody else.
    core::DataIntegrityObject dio{};
    dio.creatorUserId = "user-1";
    dio.creatorPubKey = author.getPublicKey().toBase58DER();
    dio.contextId = "ctx-1";
    dio.resourceId = "res-1";
    dio.timestamp = 0;
    dio.randomId = "rand-1";

    return inbox::InboxDataProcessorModelV5{
        .storeId = "store-1",
        .threadId = "thread-1",
        .filesConfig = {.minCount = 0, .maxCount = 10, .maxFileSize = 1024, .maxWholeUploadSize = 10240},
        .privateData =
            {.privateMeta = core::Buffer::from("private"),
             .internalMeta =
                 inbox::InboxInternalMetaV5{.secret = "secret", .resourceId = "res-1", .randomId = "rand-1"},
             .dio = dio},
        .publicData =
            {.publicMeta = core::Buffer::from("{}"),
             .inboxEntriesPubKeyBase58DER = core::PrivateKey::generateRandom().getPublicKey().toBase58DER(),
             .inboxEntriesKeyId = "key-1",
             .fileCipherType = fileCipherType}
    };
}

core::EncKey anyKey() {
    core::EncKey key;
    key.id = "key-1";
    key.key = core::CryptoSuite::randomBytes(32);
    return key;
}

} // namespace

TEST(InboxPublicCipher, EveryFormatSurvivesTheRoundTrip) {
    const core::PrivateKey author = core::PrivateKey::generateRandom();

    for (const int64_t type : store::FileCipher::known()) {
        inbox::InboxDataProcessorV5 processor;
        const auto packed = processor.packForServer(modelNaming(author, type), author, anyKey());

        // `unpackPublicOnly` is the sender's path: no container key, only what the bridge serves publicly.
        const auto unpacked = processor.unpackPublicOnly(packed.publicData);

        ASSERT_EQ(0, unpacked.statusCode()) << "cipherType " << type;
        ASSERT_TRUE(unpacked.fileCipherType.has_value()) << "cipherType " << type;
        EXPECT_EQ(type, unpacked.fileCipherType.value());
    }
}

/// An Inbox written before the field existed names no format, and must read as naming none rather
/// than as naming format 0 — the sender falls back to its own default, as it did for all of them.
TEST(InboxPublicCipher, AnInboxFromBeforeTheFieldNamesNoFormat) {
    const core::PrivateKey author = core::PrivateKey::generateRandom();
    inbox::InboxDataProcessorV5 processor;

    const auto packed = processor.packForServer(modelNaming(author, std::nullopt), author, anyKey());
    const auto unpacked = processor.unpackPublicOnly(packed.publicData);

    ASSERT_EQ(0, unpacked.statusCode());
    EXPECT_FALSE(unpacked.fileCipherType.has_value());
}
