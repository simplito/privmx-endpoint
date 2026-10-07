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
    utils::BinaryBufferBE sendDataBuffer;
    sendDataBuffer.writeOneOctetLengthBuffer(data.publicData.userPubKey);
    sendDataBuffer.writeBool(data.publicData.keyPreset);
    sendDataBuffer.writeOneOctetLengthBuffer(data.publicData.usedInboxKeyId);

    utils::BinaryBufferBE dataSecuredBuffer;
    auto filesMetaKeyBase64{utils::Base64::from(data.privateData.filesMetaKey)};
    dataSecuredBuffer.writeOneOctetLengthBuffer(filesMetaKeyBase64);
    dataSecuredBuffer.writeRaw(data.privateData.text);

    // Ta sama ramka co dotychczas skladana recznie: 'e' || pub33(nadawca) || pub33(odbiorca) || ecies.
    auto cipherWithKey = core::Ecies::encrypt(inboxPub, dataSecuredBuffer.str(), userPriv);

    utils::BinaryBufferBE concatBuffer;
    concatBuffer.writeOneOctetLengthBuffer(sendDataBuffer.str());
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
        wholeBuffer.readOneOctetLengthBuffer(publicDataStr);
        InboxEntryPublicData publicData;

        utils::BinaryBufferBE sendDataBuffer(publicDataStr);
        sendDataBuffer.readOneOctetLengthBuffer(publicData.userPubKey);
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
        wholeBuffer.readOneOctetLengthBuffer(publicDataStr);

        utils::BinaryBufferBE publicDataBuffer(publicDataStr);
        publicDataBuffer.readOneOctetLengthBuffer(result.userPubKey);
        publicDataBuffer.readBool(result.keyPreset);
        publicDataBuffer.readOneOctetLengthBuffer(result.usedInboxKeyId);

    } catch (const privmx::endpoint::core::Exception& e) {
        result.statusCode = e.getCode();
    } catch (const privmx::utils::PrivmxException& e) {
        result.statusCode = core::ExceptionConverter::convert(e).getCode();
    } catch (...) { result.statusCode = ENDPOINT_CORE_EXCEPTION_CODE; }
    return result;
}
