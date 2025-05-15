/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include "privmx/endpoint/core/encryptors/EncKey/EncKeyEncryptorV2.hpp"
#include "privmx/endpoint/core/ServerTypes.hpp"
#include "privmx/endpoint/core/CoreException.hpp"
#include "privmx/endpoint/core/ExceptionConverter.hpp"
#include "privmx/endpoint/core/DynamicTypes.hpp"
#include "privmx/endpoint/core/CoreConstants.hpp"
#include <privmx/crypto/EciesEncryptor.hpp>
#include <privmx/utils/Utils.hpp>
#include <privmx/crypto/Crypto.hpp>
using namespace privmx::endpoint::core;


server::EncryptedKeyEntryDataV2 EncKeyEncryptorV2::encrypt(const EncKeyV2ToEncrypt& key, 
        const privmx::crypto::PublicKey& encryptionKey, const crypto::PrivateKey& authorPrivateKey
) {
    auto result = privmx::utils::TypedObjectFactory::createNewObject<server::EncryptedKeyEntryDataV2>();
    result.version(EncryptionKeyDataSchema::Version::VERSION_2);
    auto keyToEncrypt = privmx::utils::TypedObjectFactory::createNewObject<dynamic::EncryptionKey>();
    keyToEncrypt.id(key.id);
    keyToEncrypt.key(utils::Base64::from(key.key));
    keyToEncrypt.keySecret(utils::Base64::from(key.keySecret));
    result.encryptedKey(crypto::EciesEncryptor::encryptObjectToBase64(encryptionKey, keyToEncrypt, authorPrivateKey));
    std::unordered_map<std::string, std::string> fieldChecksums;
    fieldChecksums.insert(std::make_pair("encryptedKey",privmx::crypto::Crypto::sha256(result.encryptedKey())));
    fieldChecksums.insert(std::make_pair("secretHash",key.secretHash));
    ExpandedDataIntegrityObject expandedDio = ExpandedDataIntegrityObject{
        key.dio, 
        .structureVersion=EncryptionKeyDataSchema::Version::VERSION_2, 
        .fieldChecksums=fieldChecksums
    };
    result.dio(_DIOEncryptor.signAndEncode(expandedDio, authorPrivateKey));
    return result;
}

DecryptedEncKeyV2 EncKeyEncryptorV2::decrypt(const server::EncryptedKeyEntryDataV2& encryptedEncKey, const privmx::crypto::PrivateKey& decryptionKey) {
    DecryptedEncKeyV2 result;
    result.statusCode = 0;
    result.dataStructureVersion = EncryptionKeyDataSchema::Version::VERSION_2;
    try {
        assertDataFormat(encryptedEncKey);
        ExpandedDataIntegrityObject expandedDio = _DIOEncryptor.decodeAndVerify(encryptedEncKey.dio());
        result.dio = expandedDio;
        if(
            expandedDio.fieldChecksums.at("encryptedKey") != privmx::crypto::Crypto::sha256(encryptedEncKey.encryptedKey())
        ) {
            throw InvalidDataIntegrityObjectChecksumException();
        }
        auto decryptedKey = privmx::utils::TypedObjectFactory::createObjectFromVar<dynamic::EncryptionKey>(
            crypto::EciesEncryptor::decryptObjectFromBase64(decryptionKey, encryptedEncKey.encryptedKey(), privmx::crypto::PublicKey::fromBase58DER(result.dio.creatorPubKey))
        );
        if(decryptedKey.idEmpty() || decryptedKey.keyEmpty()) {
            throw MalformedEncryptionKeyException();
        }
        result.id = decryptedKey.id();
        result.key = utils::Base64::toString(decryptedKey.key());
        result.secretHash = expandedDio.fieldChecksums.at("secretHash");
        result.keySecret = utils::Base64::toString(decryptedKey.keySecret());
    }  catch (const privmx::endpoint::core::Exception& e) {
        result.statusCode = e.getCode();
    } catch (const privmx::utils::PrivmxException& e) {
        result.statusCode = core::ExceptionConverter::convert(e).getCode();
    } catch (...) {
        result.statusCode = ENDPOINT_CORE_EXCEPTION_CODE;
    }
    return result;
}

void EncKeyEncryptorV2::assertDataFormat(const server::EncryptedKeyEntryDataV2& encryptedEncKey) {
    if (encryptedEncKey.versionEmpty()                                          || 
        encryptedEncKey.version() != EncryptionKeyDataSchema::Version::VERSION_2  || 
        encryptedEncKey.encryptedKeyEmpty()                                     ||
        encryptedEncKey.dioEmpty()
    ) {
        throw MalformedEncryptionKeyException();
    }
}
