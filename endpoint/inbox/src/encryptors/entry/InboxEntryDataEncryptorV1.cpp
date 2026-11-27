/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include <privmx/endpoint/core/Exception.hpp>
#include <privmx/endpoint/core/crypto/Ecies.hpp>
#include <privmx/endpoint/core/crypto/PrivateKey.hpp>
#include <privmx/endpoint/core/crypto/PublicKey.hpp>
#include <privmx/utils/BinaryBufferBE.hpp>

#include "privmx/endpoint/inbox/InboxException.hpp"
#include "privmx/endpoint/inbox/encryptors/entry/InboxEntryDataEncryptorV1.hpp"

using namespace privmx;
using namespace privmx::endpoint;
using namespace privmx::endpoint::inbox;

namespace {

/**
 * Telling the two framings of this entry apart.
 *
 * Two length prefixes here widened from one octet to two when a post-quantum public key stopped
 * fitting in 255 bytes: the public block's own length, and the sender key's inside it. The frame
 * carried no version marker, so the widened reader had no way to know it was looking at an older
 * entry and rejected every one of them as corrupt.
 *
 * Shape alone cannot settle it. Reading an old frame's one-octet length as two octets usually
 * overruns the buffer, but not always: the overrun is only certain while the ECIES wrap is short,
 * and an entry's text has no bound. A long enough entry makes the two framings genuinely
 * indistinguishable, so guessing would fail on exactly the entries hardest to notice.
 *
 * So the new frame says what it is. An old frame opens with the one-octet length of its public
 * block, and that is never zero — the block always carries at least a sender key — which leaves
 * `0x00` free as a marker, followed by a version octet. Dispatch is then exact.
 */
constexpr unsigned char VERSIONED_FRAME_MARKER = 0x00;
constexpr unsigned char FRAME_VERSION_WIDE_LENGTHS = 0x02;

struct EntryFrame {
    InboxEntryPublicData publicData;
    std::string eciesWrap;
};

EntryFrame readFrame(const std::string& raw) {
    if (raw.empty()) {
        throw InvalidEncryptedInboxDataVersionException("inbox entry frame is empty");
    }
    const bool versioned = static_cast<unsigned char>(raw[0]) == VERSIONED_FRAME_MARKER;

    utils::BinaryBufferBE wholeBuffer(versioned ? raw.substr(2) : raw);
    if (versioned) {
        if (raw.size() < 2 || static_cast<unsigned char>(raw[1]) != FRAME_VERSION_WIDE_LENGTHS) {
            throw InvalidEncryptedInboxDataVersionException(
                "inbox entry frame version: " + std::to_string(raw.size() < 2 ? -1 : int(raw[1]))
            );
        }
    }

    EntryFrame frame;
    std::string publicDataStr;
    if (versioned) {
        wholeBuffer.readTwoOctetLengthBuffer(publicDataStr);
    } else {
        wholeBuffer.readOneOctetLengthBuffer(publicDataStr);
    }

    utils::BinaryBufferBE publicDataBuffer(publicDataStr);
    if (versioned) {
        publicDataBuffer.readTwoOctetLengthBuffer(frame.publicData.userPubKey);
    } else {
        publicDataBuffer.readOneOctetLengthBuffer(frame.publicData.userPubKey);
    }
    publicDataBuffer.readBool(frame.publicData.keyPreset);
    // Short by construction in both framings, so it never widened.
    publicDataBuffer.readOneOctetLengthBuffer(frame.publicData.usedInboxKeyId);

    wholeBuffer.readRawUntilEnd(frame.eciesWrap);
    return frame;
}

} // namespace

std::string InboxEntryDataEncryptorV1::encrypt(
    InboxEntrySendModel data,
    core::PrivateKey& userPriv,
    core::PublicKey& inboxPub
) {
    // Two-octet lengths on the fields that carry a key, and on the public block that holds one. A
    // sender's public key was 33 bytes when this format was written; a post-quantum identity is 1248,
    // about 1.7 kB in base58, so one octet no longer spans it. The key id and the files-meta key are
    // short by construction and keep theirs.
    utils::BinaryBufferBE sendDataBuffer;
    sendDataBuffer.writeTwoOctetLengthBuffer(data.publicData.userPubKey);
    sendDataBuffer.writeBool(data.publicData.keyPreset);
    sendDataBuffer.writeOneOctetLengthBuffer(data.publicData.usedInboxKeyId);

    utils::BinaryBufferBE dataSecuredBuffer;
    auto filesMetaKeyBase64{utils::Base64::from(data.privateData.filesMetaKey)};
    dataSecuredBuffer.writeOneOctetLengthBuffer(filesMetaKeyBase64);
    dataSecuredBuffer.writeRaw(data.privateData.text);

    // The same frame as the one previously assembled by hand: the ECIES wrap, which for a
    // post-quantum recipient also carries its ML-KEM ciphertext.
    auto cipherWithKey = core::Ecies::encrypt(inboxPub, dataSecuredBuffer.str(), userPriv);

    utils::BinaryBufferBE concatBuffer;
    // The marker and version that let a reader tell this framing from the one-octet one it replaced.
    concatBuffer.writeRaw(std::string(1, static_cast<char>(VERSIONED_FRAME_MARKER)));
    concatBuffer.writeRaw(std::string(1, static_cast<char>(FRAME_VERSION_WIDE_LENGTHS)));
    concatBuffer.writeTwoOctetLengthBuffer(sendDataBuffer.str());
    concatBuffer.writeRaw(cipherWithKey);
    return utils::Base64::from(concatBuffer.str());
}

InboxEntryDataResult InboxEntryDataEncryptorV1::decrypt(std::string& serializedBase64, core::PrivateKey& inboxPriv) {
    InboxEntryDataResult result;
    try {
        // `readFrame` does the buffer walk that used to be spelled out here, and `core::Ecies`
        // replaces `crypto::EciesEncryptor` — the ECIES wrap moved with the rest of the key types.
        const EntryFrame frame = readFrame(utils::Base64::toString(serializedBase64));
        InboxEntryPublicData publicData = frame.publicData;
        auto decrypted = core::Ecies::decrypt(inboxPriv, frame.eciesWrap);

        InboxEntryPrivateData privateData;
        utils::BinaryBufferBE securedBuffer(decrypted);
        std::string filesMetaKeyBase64;
        securedBuffer.readOneOctetLengthBuffer(filesMetaKeyBase64);
        securedBuffer.readRawUntilEnd(privateData.text);
        privateData.filesMetaKey = utils::Base64::toString(filesMetaKeyBase64);

        result.privateData = privateData;
        result.publicData = publicData;
    } catch (const privmx::endpoint::core::Exception& e) { result.error = core::asError(e); } catch (...) {
        result.error = core::unknownError("unpacking the inbox entry");
    }
    return result;
}

InboxEntryPublicDataResult InboxEntryDataEncryptorV1::decryptPublicOnly(std::string& serializedBase64) {
    InboxEntryPublicDataResult result;
    try {
        const EntryFrame frame = readFrame(utils::Base64::toString(serializedBase64));
        result.userPubKey = frame.publicData.userPubKey;
        result.keyPreset = frame.publicData.keyPreset;
        result.usedInboxKeyId = frame.publicData.usedInboxKeyId;
        // The PrivmxException branch is gone with ExceptionConverter: everything that reaches here
        // is already a core::Exception, and anything else is reported as an unknown error.
    } catch (const privmx::endpoint::core::Exception& e) { result.error = core::asError(e); } catch (...) {
        result.error = core::unknownError("unpacking the inbox entry");
    }
    return result;
}
