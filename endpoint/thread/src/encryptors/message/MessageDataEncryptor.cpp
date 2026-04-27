/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include <Poco/JSON/Parser.h>

#include <privmx/crypto/CryptoPrivmx.hpp>
#include <privmx/utils/Utils.hpp>
#include <privmx/utils/Debug.hpp>

#include <privmx/endpoint/thread/ThreadException.hpp>
#include <privmx/endpoint/core/ExceptionConverter.hpp>
#include "privmx/endpoint/thread/encryptors/message/MessageDataEncryptor.hpp"

using namespace privmx::endpoint::thread;

std::string MessageDataV2Encryptor::signAndEncrypt(const dynamic::MessageDataV2_c_struct& data, const privmx::crypto::PrivateKey& priv, const core::EncKey& encKey) {
    return _dataEncryptor.signAndEncrypt(data, priv, encKey);
}

dynamic::MessageDataV2Signed_c_struct  MessageDataV2Encryptor::decryptAndGetSign(const std::string& data, const core::EncKey& key) {
    dynamic::MessageDataV2Signed_c_struct result;
    auto decrypted = _dataEncryptor.decryptAndGetSign(data, key);
    result.dataSignature = std::get<0>(decrypted);
    result.data = std::get<1>(decrypted);
    result.data.statusCode = 0;
    result.dataBuf = std::get<2>(decrypted);
    return result;
}

std::string MessageDataV3Encryptor::signAndEncrypt(const dynamic::MessageDataV3_c_struct& data, const privmx::crypto::PrivateKey& priv, const core::EncKey& encKey) {
    dynamic::MessageDataV3_c_struct messageDataV3Encrypted;
    messageDataV3Encrypted.publicMeta = utils::Base64::from(data.publicMeta); // for extra save 
    messageDataV3Encrypted.privateMeta =_dataEncryptorBinaryString.encrypt(data.privateMeta, encKey);
    messageDataV3Encrypted.data =_dataEncryptorBinaryString.encrypt(data.data, encKey);
    return utils::Base64::from(_dataEncryptorMessageDataV3.sign(messageDataV3Encrypted, priv));
}

dynamic::MessageDataV3Signed_c_struct  MessageDataV3Encryptor::decryptAndGetSign(const std::string& data, const core::EncKey& key) {
    dynamic::MessageDataV3Signed_c_struct result;
    Pson::BinaryString dataBuf, dataSignature;
    std::tie(dataSignature, dataBuf) = _dataEncryptorMessageDataV3.extractSignAndDataBuff(utils::Base64::toString(data));
    dynamic::MessageDataV3_c_struct messageDataV3Encrypted = dynamic::MessageDataV3_c_struct::formJSON(privmx::utils::Utils::parseJsonObject(dataBuf));
    dynamic::MessageDataV3_c_struct messageDataV3;
    messageDataV3.publicMeta = utils::Base64::toString(messageDataV3Encrypted.publicMeta);
    try {
        messageDataV3.privateMeta = _dataEncryptorBinaryString.decrypt(messageDataV3Encrypted.privateMeta, key);
        messageDataV3.data = _dataEncryptorBinaryString.decrypt(messageDataV3Encrypted.data, key);
        messageDataV3.statusCode = 0;
    } catch (const privmx::endpoint::core::Exception& e) {
        messageDataV3.statusCode = e.getCode();
    } catch (const privmx::utils::PrivmxException& e) {
        messageDataV3.statusCode = core::ExceptionConverter::convert(e).getCode();
    } catch (...) {
        messageDataV3.statusCode = ENDPOINT_CORE_EXCEPTION_CODE;
    }
    result.data = messageDataV3;
    result.dataSignature = dataSignature;
    result.dataBuf =dataBuf;
    return result;
}