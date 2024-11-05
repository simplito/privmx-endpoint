/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include <string>

#include <privmx/crypto/ecc/PublicKey.hpp>
#include <privmx/crypto/ecc/PrivateKey.hpp>
#include <privmx/crypto/EciesEncryptor.hpp>
#include <privmx/endpoint/inbox/InboxEntriesDataEncryptorSerializer.hpp>
#include <privmx/crypto/CryptoPrivmx.hpp>
#include <privmx/utils/BinaryBufferBE.hpp>
#include <privmx/crypto/ecc/ECIES.hpp>
#include <privmx/crypto/EciesEncryptor.hpp>
#include <privmx/endpoint/core/Exception.hpp>
#include <privmx/endpoint/core/ExceptionConverter.hpp>

using namespace privmx;
using namespace privmx::endpoint;
using namespace privmx::endpoint::inbox;
inbox::InboxEntriesDataEncryptorSerializer::InboxEntriesDataEncryptorSerializer() {}

std::string InboxEntriesDataEncryptorSerializer::packMessage(InboxEntrySendModel data, privmx::crypto::PrivateKey &userPriv, privmx::crypto::PublicKey &inboxPub) {
    utils::BinaryBufferBE sendDataBuffer;
    sendDataBuffer.writeOneOctetLengthBuffer(data.publicData.userPubKey);
    sendDataBuffer.writeBool(data.publicData.keyPreset);
    sendDataBuffer.writeOneOctetLengthBuffer(data.publicData.usedInboxKeyId);

    utils::BinaryBufferBE dataSecuredBuffer;
    auto filesMetaKeyBase64 {utils::Base64::from(data.privateData.filesMetaKey)};
    dataSecuredBuffer.writeOneOctetLengthBuffer(filesMetaKeyBase64);
    dataSecuredBuffer.writeRaw(data.privateData.text);

    // encrypt secured part with ecies
    privmx::crypto::ECIES ecies(userPriv, inboxPub);
    auto cipher = ecies.encrypt(dataSecuredBuffer.str());
    auto cipherWithKey = std::string("e")
            .append(userPriv.getPublicKey().toDER())
            .append(inboxPub.toDER())
            .append(cipher);

    utils::BinaryBufferBE concatBuffer;
    concatBuffer.writeOneOctetLengthBuffer(sendDataBuffer.str());
    concatBuffer.writeRaw(cipherWithKey);
    return utils::Base64::from(concatBuffer.str());
}

InboxEntryDataResult InboxEntriesDataEncryptorSerializer::unpackMessage(std::string &serializedBase64, privmx::crypto::PrivateKey &inboxPriv) {
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
        auto decrypted = crypto::EciesEncryptor::decrypt(inboxPriv, privateDataStr);

        InboxEntryPrivateData privateData;
        utils::BinaryBufferBE securedBuffer(decrypted);
        std::string filesMetaKeyBase64;
        securedBuffer.readOneOctetLengthBuffer(filesMetaKeyBase64);
        securedBuffer.readRawUntilEnd(privateData.text);
        privateData.filesMetaKey = utils::Base64::toString(filesMetaKeyBase64);

        result.privateData = privateData;
        result.publicData = publicData;
    }  catch (const privmx::endpoint::core::Exception& e) {
        result.statusCode = e.getCode();
    } catch (const privmx::utils::PrivmxException& e) {
        result.statusCode = core::ExceptionConverter::convert(e).getCode();
    } catch (...) {
        result.statusCode = ENDPOINT_CORE_EXCEPTION_CODE;
    }
    return result;   
}

InboxEntryPublicDataResult InboxEntriesDataEncryptorSerializer::unpackMessagePublicOnly(std::string &serializedBase64) {
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

    }  catch (const privmx::endpoint::core::Exception& e) {
        result.statusCode = e.getCode();
    } catch (const privmx::utils::PrivmxException& e) {
        result.statusCode = core::ExceptionConverter::convert(e).getCode();
    } catch (...) {
        result.statusCode = ENDPOINT_CORE_EXCEPTION_CODE;
    }
    return result;   
}