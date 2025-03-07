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

using namespace privmx::endpoint::core;


server::EncryptedKeyEntryDataV2 EncKeyEncryptorV2::encrypt(const DataIntegrityObject& dio, 
    const privmx::endpoint::core::EncKey& key, const privmx::crypto::PublicKey& encryptionKey, 
    const privmx::crypto::PrivateKey& authorPrivateKey
) {
    auto result = privmx::utils::TypedObjectFactory::createNewObject<server::EncryptedKeyEntryDataV2>();
    result.version(2);
    auto keyToEncrypt = privmx::utils::TypedObjectFactory::createNewObject<dynamic::EncryptionKey>();
    keyToEncrypt.id(key.id);
    keyToEncrypt.key(key.key);
    result.encryptedKey(crypto::EciesEncryptor::encryptObjectToBase64(encryptionKey, keyToEncrypt, authorPrivateKey));
    result.dio(_DIOEncryptor.signAndEncode(dio, authorPrivateKey));
    return result;
}

EncKeyV2 EncKeyEncryptorV2::decrypt(const server::EncryptedKeyEntryDataV2& encryptedEncKey, const privmx::crypto::PrivateKey& decryptionKey) {
    EncKeyV2 result;
    try {
        assertDataFormat(encryptedEncKey);
        result.dio = _DIOEncryptor.decodeAndValidate(encryptedEncKey.dio());
        auto decryptedKey = privmx::utils::TypedObjectFactory::createObjectFromVar<dynamic::EncryptionKey>(
            crypto::EciesEncryptor::decryptObjectFromBase64(decryptionKey, encryptedEncKey.encryptedKey(), privmx::crypto::PublicKey::fromBase58DER(result.dio.creatorPubKey))
        );
        if(decryptedKey.idEmpty() || decryptedKey.keyEmpty()) {
            throw EncryptionKeyMalformedDataException();
        }
        result.id = decryptedKey.id();
        result.key = decryptedKey.key();
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
    if(encryptedEncKey.versionEmpty() || encryptedEncKey.version() != 2) {
        throw EncryptionKeyMalformedDataException();
    }
}
