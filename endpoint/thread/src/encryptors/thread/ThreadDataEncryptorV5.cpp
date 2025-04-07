/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include "privmx/endpoint/thread/encryptors/thread/ThreadDataEncryptorV5.hpp"

#include "privmx/endpoint/core/ExceptionConverter.hpp"
#include "privmx/endpoint/thread/ThreadException.hpp"
#include <privmx/crypto/Crypto.hpp>

using namespace privmx::endpoint;
using namespace privmx::endpoint::thread;

server::EncryptedThreadDataV5 ThreadDataEncryptorV5::encrypt(const ThreadDataToEncryptV5& threadData,
                                                                     const crypto::PrivateKey& authorPrivateKey,
                                                                     const std::string& encryptionKey) {
    auto result = utils::TypedObjectFactory::createNewObject<server::EncryptedThreadDataV5>();
    result.version(5);
    std::unordered_map<std::string, std::string> fieldChecksums;
    result.publicMeta(_dataEncryptor.signAndEncode(threadData.publicMeta, authorPrivateKey));
    fieldChecksums.insert(std::make_pair("publicMeta",privmx::crypto::Crypto::sha256(result.publicMeta())));
    try {
        result.publicMetaObject(utils::Utils::parseJsonObject(threadData.publicMeta.stdString()));
    } catch (...) {
        result.publicMetaObjectClear();
    }
    result.privateMeta(_dataEncryptor.signAndEncryptAndEncode(threadData.privateMeta, authorPrivateKey, encryptionKey));
    fieldChecksums.insert(std::make_pair("privateMeta",privmx::crypto::Crypto::sha256(result.privateMeta())));
    result.internalMeta(_dataEncryptor.signAndEncryptAndEncode(threadData.internalMeta, authorPrivateKey, encryptionKey));
    fieldChecksums.insert(std::make_pair("internalMeta",privmx::crypto::Crypto::sha256(result.internalMeta())));
    result.authorPubKey(authorPrivateKey.getPublicKey().toBase58DER());
    core::ExpandedDataIntegrityObject expandedDio = {threadData.dio, .structureVersion=5, .fieldChecksums=fieldChecksums};
    result.dio(_DIOEncryptor.signAndEncode(expandedDio, authorPrivateKey));
    return result;
}

DecryptedThreadDataV5 ThreadDataEncryptorV5::decrypt(const server::EncryptedThreadDataV5& encryptedThreadData, const std::string& encryptionKey) {
    DecryptedThreadDataV5 result;
    result.statusCode = 0;
    result.dataStructureVersion = 5;
    try {  
        result.dio = getDIOAndAssertIntegrity(encryptedThreadData);
        auto authorPublicKey = crypto::PublicKey::fromBase58DER(encryptedThreadData.authorPubKey());
        result.publicMeta = _dataEncryptor.decodeAndVerify(encryptedThreadData.publicMeta(), authorPublicKey);
        if(!encryptedThreadData.publicMetaObjectEmpty()) {
            auto tmp_1 = utils::Utils::stringify(utils::Utils::parseJsonObject(result.publicMeta.stdString()));
            auto tmp_2 = utils::Utils::stringify(encryptedThreadData.publicMetaObject());
            if(tmp_1 != tmp_2) {
                auto e = ThreadPublicDataMismatchException();
                result.statusCode = e.getCode();
            }
        }
        result.privateMeta = _dataEncryptor.decodeAndDecryptAndVerify(encryptedThreadData.privateMeta(), authorPublicKey, encryptionKey);
        result.internalMeta = _dataEncryptor.decodeAndDecryptAndVerify(encryptedThreadData.internalMeta(), authorPublicKey, encryptionKey);
        result.authorPubKey = encryptedThreadData.authorPubKey();   
    }  catch (const privmx::endpoint::core::Exception& e) {
        result.statusCode = e.getCode();
    } catch (const privmx::utils::PrivmxException& e) {
        result.statusCode = core::ExceptionConverter::convert(e).getCode();
    } catch (...) {
        result.statusCode = ENDPOINT_CORE_EXCEPTION_CODE;
    }
    return result;
}


DecryptedThreadDataV5 ThreadDataEncryptorV5::extractPublic(const server::EncryptedThreadDataV5& encryptedThreadData) {
    DecryptedThreadDataV5 result;
    result.statusCode = 0;
    result.dataStructureVersion = 5;
    try {  
        result.dio = getDIOAndAssertIntegrity(encryptedThreadData);
        auto authorPublicKey = crypto::PublicKey::fromBase58DER(encryptedThreadData.authorPubKey());
        result.publicMeta = _dataEncryptor.decodeAndVerify(encryptedThreadData.publicMeta(), authorPublicKey);
        if(!encryptedThreadData.publicMetaObjectEmpty()) {
            auto tmp_1 = utils::Utils::stringify(utils::Utils::parseJsonObject(result.publicMeta.stdString()));
            auto tmp_2 = utils::Utils::stringify(encryptedThreadData.publicMetaObject());
            if(tmp_1 != tmp_2) {
                auto e = ThreadPublicDataMismatchException();
                result.statusCode = e.getCode();
            }
        }
        result.authorPubKey = encryptedThreadData.authorPubKey();   
    }  catch (const privmx::endpoint::core::Exception& e) {
        result.statusCode = e.getCode();
    } catch (const privmx::utils::PrivmxException& e) {
        result.statusCode = core::ExceptionConverter::convert(e).getCode();
    } catch (...) {
        result.statusCode = ENDPOINT_CORE_EXCEPTION_CODE;
    }
    return result;
}

core::DataIntegrityObject ThreadDataEncryptorV5::getDIOAndAssertIntegrity(const server::EncryptedThreadDataV5& encryptedThreadData) {
    assertDataFormat(encryptedThreadData);
    auto encryptedDIO = encryptedThreadData.dio();
    auto dio = _DIOEncryptor.decodeAndVerify(encryptedDIO);
    if (
        dio.structureVersion != 5 ||
        dio.creatorPubKey != encryptedThreadData.authorPubKey() ||
        dio.fieldChecksums.at("publicMeta") != privmx::crypto::Crypto::sha256(encryptedThreadData.publicMeta()) ||
        dio.fieldChecksums.at("privateMeta") != privmx::crypto::Crypto::sha256(encryptedThreadData.privateMeta()) ||
        dio.fieldChecksums.at("internalMeta") != privmx::crypto::Crypto::sha256(encryptedThreadData.internalMeta())     
    ) {
        throw core::InvalidDataIntegrityObjectChecksumException();
    }
    return dio;
}

void ThreadDataEncryptorV5::assertDataFormat(const server::EncryptedThreadDataV5& encryptedThreadData) {
    if (encryptedThreadData.versionEmpty() ||
        encryptedThreadData.version() != 5 ||
        encryptedThreadData.publicMetaEmpty() ||
        encryptedThreadData.privateMetaEmpty() ||
        encryptedThreadData.internalMetaEmpty() ||
        encryptedThreadData.authorPubKeyEmpty() ||
        encryptedThreadData.dioEmpty()
    ) {
        throw InvalidEncryptedThreadDataVersionException(std::to_string(encryptedThreadData.version()) + " expected version: 5");
    }
}
