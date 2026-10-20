/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include <privmx/endpoint/core/crypto/Ecies.hpp>
#include <privmx/endpoint/core/crypto/PrivateKey.hpp>
#include <privmx/endpoint/core/crypto/PublicKey.hpp>
#include <privmx/endpoint/core/Exception.hpp>
#include <privmx/endpoint/core/ExceptionConverter.hpp>
#include <privmx/utils/BinaryBufferBE.hpp>

#include "privmx/endpoint/inbox/encryptors/entry/InboxEntryDataEncryptorV1.hpp"

using namespace privmx;
using namespace privmx::endpoint;
using namespace privmx::endpoint::inbox;

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
    concatBuffer.writeTwoOctetLengthBuffer(sendDataBuffer.str());
    concatBuffer.writeRaw(cipherWithKey);
    return utils::Base64::from(concatBuffer.str());
}

InboxEntryDataResult InboxEntryDataEncryptorV1::decrypt(
    std::string& serializedBase64,
    core::PrivateKey& inboxPriv
) {
    InboxEntryDataResult result;
    try {
        result.statusCode = 0;
        utils::BinaryBufferBE wholeBuffer(utils::Base64::toString(serializedBase64));
        std::string publicDataStr;
        wholeBuffer.readTwoOctetLengthBuffer(publicDataStr);
        InboxEntryPublicData publicData;

        utils::BinaryBufferBE sendDataBuffer(publicDataStr);
        sendDataBuffer.readTwoOctetLengthBuffer(publicData.userPubKey);
        sendDataBuffer.readBool(publicData.keyPreset);
        sendDataBuffer.readOneOctetLengthBuffer(publicData.usedInboxKeyId);

        std::string privateDataStr;
        wholeBuffer.readRawUntilEnd(privateDataStr);
        auto decrypted = core::Ecies::decrypt(inboxPriv, privateDataStr);

        InboxEntryPrivateData privateData;
        utils::BinaryBufferBE securedBuffer(decrypted);
        std::string filesMetaKeyBase64;
        securedBuffer.readOneOctetLengthBuffer(filesMetaKeyBase64);
        securedBuffer.readRawUntilEnd(privateData.text);
        privateData.filesMetaKey = utils::Base64::toString(filesMetaKeyBase64);

        result.privateData = privateData;
        result.publicData = publicData;
    } catch (const privmx::endpoint::core::Exception& e) {
        result.statusCode = e.getCode();
    } catch (const privmx::utils::PrivmxException& e) {
        result.statusCode = core::ExceptionConverter::convert(e).getCode();
    } catch (...) { result.statusCode = ENDPOINT_CORE_EXCEPTION_CODE; }
    return result;
}

InboxEntryPublicDataResult InboxEntryDataEncryptorV1::decryptPublicOnly(std::string& serializedBase64) {
    InboxEntryPublicDataResult result;
    try {
        result.statusCode = 0;
        utils::BinaryBufferBE wholeBuffer(utils::Base64::toString(serializedBase64));
        std::string publicDataStr;
        wholeBuffer.readTwoOctetLengthBuffer(publicDataStr);

        utils::BinaryBufferBE publicDataBuffer(publicDataStr);
        publicDataBuffer.readTwoOctetLengthBuffer(result.userPubKey);
        publicDataBuffer.readBool(result.keyPreset);
        publicDataBuffer.readOneOctetLengthBuffer(result.usedInboxKeyId);

    } catch (const privmx::endpoint::core::Exception& e) {
        result.statusCode = e.getCode();
    } catch (const privmx::utils::PrivmxException& e) {
        result.statusCode = core::ExceptionConverter::convert(e).getCode();
    } catch (...) { result.statusCode = ENDPOINT_CORE_EXCEPTION_CODE; }
    return result;
}
