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
#include "privmx/endpoint/core/DynamicTypes.hpp"
#include "privmx/endpoint/core/CoreException.hpp"
#include "privmx/endpoint/core/ExceptionConverter.hpp"
#include <privmx/crypto/EciesEncryptor.hpp>
#include <privmx/utils/Utils.hpp>
#include <privmx/crypto/Crypto.hpp>
using namespace privmx::endpoint::core;


server::EncryptedKeyEntryDataV2 EncKeyEncryptorV2::encrypt(const EncKeyV2ToEncrypt& key, 
        const privmx::crypto::PublicKey& encryptionKey, const crypto::PrivateKey& authorPrivateKey
) {
    auto result = privmx::utils::TypedObjectFactory::createNewObject<server::EncryptedKeyEntryDataV2>();
    result.version(2);
    auto keyToEncrypt = privmx::utils::TypedObjectFactory::createNewObject<server::EncryptionKey>();
    keyToEncrypt.id(key.id);
    keyToEncrypt.key(key.key);
    keyToEncrypt.containerControlNumber(key.containerControlNumber);
    result.encryptedKey(crypto::EciesEncryptor::encryptObjectToBase64(encryptionKey, keyToEncrypt, authorPrivateKey));
    std::unordered_map<std::string, std::string> mapOfDataSha256;
    mapOfDataSha256.insert(std::make_pair("encryptedKey",privmx::crypto::Crypto::sha256(result.encryptedKey())));
    ExpandedDataIntegrityObject expandedDio = ExpandedDataIntegrityObject{key.dio, .objectFormat=2, .mapOfDataSha256=mapOfDataSha256};
    result.dio(_DIOEncryptor.signAndEncode(expandedDio, authorPrivateKey));
    return result;
}

DecryptedEncKeyV2 EncKeyEncryptorV2::decrypt(const server::EncryptedKeyEntryDataV2& encryptedEncKey, const privmx::crypto::PrivateKey& decryptionKey) {
    DecryptedEncKeyV2 result;
    result.dataStructureVersion = 2;
    try {
        assertDataFormat(encryptedEncKey);
        ExpandedDataIntegrityObject expandedDio = _DIOEncryptor.decodeAndVerify(encryptedEncKey.dio());
        result.dio = expandedDio;
        if(
            expandedDio.mapOfDataSha256.at("encryptedKey") != privmx::crypto::Crypto::sha256(encryptedEncKey.encryptedKey()) ||
            expandedDio.objectFormat == 2
        ) {
            throw DataIntegrityObjectInvalidSHA256Exception();
        }
        auto decryptedKey = privmx::utils::TypedObjectFactory::createObjectFromVar<server::EncryptionKey>(
            crypto::EciesEncryptor::decryptObjectFromBase64(decryptionKey, encryptedEncKey.encryptedKey(), privmx::crypto::PublicKey::fromBase58DER(result.dio.creatorPubKey))
        );
        if(decryptedKey.idEmpty() || decryptedKey.keyEmpty()) {
            throw EncryptionKeyMalformedDataException();
        }
        result.id = decryptedKey.id();
        result.key = decryptedKey.key();
        result.containerControlNumber = decryptedKey.containerControlNumber();
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
    if (encryptedEncKey.versionEmpty() || 
        encryptedEncKey.version() != 2 || 
        encryptedEncKey.encryptedKeyEmpty() ||
        encryptedEncKey.dioEmpty()
    ) {
        throw EncryptionKeyMalformedDataException();
    }
}
