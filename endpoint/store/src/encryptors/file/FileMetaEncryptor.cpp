/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include <privmx/crypto/CryptoPrivmx.hpp>
#include <privmx/crypto/ecc/PrivateKey.hpp>
#include <Poco/JSON/Parser.h>
#include <privmx/utils/Utils.hpp>

#include "privmx/endpoint/store/encryptors/file/FileMetaEncryptor.hpp"

using namespace privmx::endpoint::store;

std::string FileMetaEncryptor::signAndEncrypt(const dynamic::compat_v1::StoreFileMeta& data, const privmx::crypto::PrivateKey& priv, const std::string& key) {
    auto buffer {utils::Utils::stringify(data)};
    auto signature = priv.signToCompactSignatureWithHash(buffer);
    std::string plain;
    plain.push_back(1);
    plain.push_back(signature.length());
    plain.append(signature).append(buffer);
    auto cipher = crypto::CryptoPrivmx::privmxEncrypt(crypto::CryptoPrivmx::privmxOptAesWithSignature(), plain, key);
    return utils::Base64::from(cipher);
}

FileMetaSigned FileMetaEncryptor::decrypt(const std::string& data, const std::string& key) {
    FileMetaSigned metaSigned;
    auto plain = crypto::CryptoPrivmx::privmxDecrypt(true, utils::Base64::toString(data), key);
    Poco::JSON::Parser parser;
    
    if (plain[0] == 1) {
        size_t sigLen = reinterpret_cast<Poco::UInt8&>(plain[1]);
        auto signature = plain.substr(2, sigLen);
        auto metaBuf = plain.substr(2 + sigLen);
        auto meta = utils::TypedObjectFactory::createObjectFromVar<dynamic::compat_v1::StoreFileMeta>(parser.parse(metaBuf));
        metaSigned.signature = signature;
        metaSigned.metaBuf = metaBuf;
        metaSigned.meta = meta;
    } 
    else if (plain[0] == 123) {
        auto meta = utils::TypedObjectFactory::createObjectFromVar<dynamic::compat_v1::StoreFileMeta>(parser.parse(plain));
        metaSigned.signature = Pson::BinaryString();
        metaSigned.metaBuf = Pson::BinaryString();
        metaSigned.meta = meta;
    }
    return metaSigned;
}
