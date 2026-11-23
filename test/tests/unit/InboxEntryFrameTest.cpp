/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

/**
 * The two framings of an Inbox entry, and telling them apart.
 *
 * Two length prefixes in this frame widened from one octet to two when a post-quantum public key
 * stopped fitting in 255 bytes. The frame carried no version marker, so the widened reader took
 * every entry written before it as corrupt — the kind of break that shows up only once there is
 * data old enough to hit it.
 *
 * The new frame now opens with `0x00` and a version octet, which the old one can never produce: its
 * first byte is the length of a public block that always holds at least a sender key. These tests
 * pin both directions of that dispatch, and the long-entry case that rules out guessing by shape.
 */

#include <string>

#include <gtest/gtest.h>

#include <privmx/endpoint/inbox/encryptors/entry/InboxEntryDataEncryptorV1.hpp>
#include <privmx/utils/BinaryBufferBE.hpp>
#include <privmx/utils/Utils.hpp>

using namespace privmx::endpoint;
namespace utils = privmx::utils;

namespace {

const std::string SECP_PUB_KEY(33, 'p');
const std::string KEY_ID = "inbox-key-1";

/// A frame exactly as a pre-widening client wrote it: one octet for both lengths.
std::string legacyFrame(const std::string& userPubKey, bool keyPreset, const std::string& keyId,
                        const std::string& eciesWrap) {
    utils::BinaryBufferBE publicBlock;
    publicBlock.writeOneOctetLengthBuffer(userPubKey);
    publicBlock.writeBool(keyPreset);
    publicBlock.writeOneOctetLengthBuffer(keyId);

    utils::BinaryBufferBE whole;
    whole.writeOneOctetLengthBuffer(publicBlock.str());
    whole.writeRaw(eciesWrap);
    return utils::Base64::from(whole.str());
}

} // namespace

TEST(InboxEntryFrame, ALegacyEntryStillReads) {
    std::string frame = legacyFrame(SECP_PUB_KEY, true, KEY_ID, std::string(64, 'c'));

    inbox::InboxEntryDataEncryptorV1 encryptor;
    const auto result = encryptor.decryptPublicOnly(frame);

    ASSERT_EQ(0, result.statusCode);
    EXPECT_EQ(SECP_PUB_KEY, result.userPubKey);
    EXPECT_TRUE(result.keyPreset);
    EXPECT_EQ(KEY_ID, result.usedInboxKeyId);
}

/**
 * The case that rules out guessing the framing from shape.
 *
 * Reading a legacy one-octet length as two octets overruns the buffer only while what follows is
 * short. An entry's text has no bound, so past a certain size the bogus length fits inside the
 * frame and the misread succeeds — quietly, on the entries least likely to be spot-checked. The
 * marker is what makes this one read correctly.
 */
TEST(InboxEntryFrame, ALegacyEntryWithALongBodyStillReads) {
    std::string frame = legacyFrame(SECP_PUB_KEY, false, KEY_ID, std::string(64 * 1024, 'c'));

    inbox::InboxEntryDataEncryptorV1 encryptor;
    const auto result = encryptor.decryptPublicOnly(frame);

    ASSERT_EQ(0, result.statusCode);
    EXPECT_EQ(SECP_PUB_KEY, result.userPubKey);
    EXPECT_FALSE(result.keyPreset);
    EXPECT_EQ(KEY_ID, result.usedInboxKeyId);
}

/// The marker is a byte the old framing cannot produce, so dispatch is exact rather than guessed.
TEST(InboxEntryFrame, ALegacyFrameNeverOpensWithTheMarker) {
    const std::string raw = utils::Base64::toString(legacyFrame(SECP_PUB_KEY, true, KEY_ID, std::string(8, 'c')));

    ASSERT_FALSE(raw.empty());
    // Byte 0 is the length of the public block, which always carries at least a sender key.
    EXPECT_NE(0x00, static_cast<unsigned char>(raw[0]));
}
