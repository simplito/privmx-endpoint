/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include "privmx/endpoint/event/encryptors/event/EventDataEncryptorV5.hpp"
#include "privmx/utils/Utils.hpp"
#include "privmx/utils/Debug.hpp"
#include "privmx/endpoint/core/ExceptionConverter.hpp"
#include "privmx/endpoint/event/EventException.hpp"
#include "privmx/endpoint/event/Constants.hpp"
#include <privmx/crypto/Crypto.hpp>

using namespace privmx::endpoint;
using namespace privmx::endpoint::event;

server::EncryptedContextEventDataV5 EventDataEncryptorV5::encrypt(
    const ContextEventDataToEncryptV5& eventData,
    const privmx::crypto::PrivateKey& authorPrivateKey,
    const std::string& encryptionKey
) {
    auto result = utils::TypedObjectFactory::createNewObject<server::EncryptedContextEventDataV5>();
    result.version(EventDataSchema::Version::VERSION_5);
    std::unordered_map<std::string, std::string> fieldChecksums;
    result.encryptedData(_dataEncryptor.signAndEncryptAndEncode(eventData.data, authorPrivateKey, encryptionKey));
    fieldChecksums.insert(std::make_pair("encryptedData",privmx::crypto::Crypto::sha256(result.encryptedData())));
    if (eventData.type.has_value()) {
        result.type(eventData.type.value());
        fieldChecksums.insert(std::make_pair("type",result.type()));
    }
    core::ExpandedDataIntegrityObject expandedDio = {eventData.dio, .structureVersion=5, .fieldChecksums=fieldChecksums};
    result.dio(_DIOEncryptor.signAndEncode(expandedDio, authorPrivateKey));
    return result; 
}

DecryptedEventDataV5 EventDataEncryptorV5::decrypt(
    const server::EncryptedContextEventDataV5& encryptedEventData, 
    const privmx::crypto::PublicKey& authorPublicKey, 
    const std::string& encryptionKey
) {
    DecryptedEventDataV5 result;
    result.statusCode = 0;
    result.dataStructureVersion = EventDataSchema::Version::VERSION_5;
    try {
        result.dio = getDIOAndAssertIntegrity(encryptedEventData, authorPublicKey);
        result.data = _dataEncryptor.decodeAndDecryptAndVerify(encryptedEventData.encryptedData(), authorPublicKey, encryptionKey);
        result.type = encryptedEventData.typeOptional();
    }  catch (const privmx::endpoint::core::Exception& e) {
        result.statusCode = e.getCode();
    } catch (const privmx::utils::PrivmxException& e) {
        result.statusCode = core::ExceptionConverter::convert(e).getCode();
    } catch (...) {
        result.statusCode = ENDPOINT_CORE_EXCEPTION_CODE;
    }
    return result;
}

core::DataIntegrityObject EventDataEncryptorV5::getDIOAndAssertIntegrity(
    const server::EncryptedContextEventDataV5& encryptedEventData, 
    const privmx::crypto::PublicKey& authorPublicKey
) {
    assertDataFormat(encryptedEventData);
    auto dio = _DIOEncryptor.decodeAndVerify(encryptedEventData.dio());
    if (
        dio.structureVersion != EventDataSchema::Version::VERSION_5 ||
        dio.creatorPubKey != authorPublicKey.toBase58DER() ||
        dio.fieldChecksums.at("encryptedData") != privmx::crypto::Crypto::sha256(encryptedEventData.encryptedData()) || (
            !encryptedEventData.typeEmpty() &&
            dio.fieldChecksums.at("type") != encryptedEventData.type()
        )
    ) {
        throw core::InvalidDataIntegrityObjectChecksumException();
    }
    return dio;
}

void EventDataEncryptorV5::assertDataFormat(const server::EncryptedContextEventDataV5& encryptedEventData) {
    if (encryptedEventData.versionEmpty() ||
        encryptedEventData.version() != EventDataSchema::Version::VERSION_5 ||
        encryptedEventData.encryptedDataEmpty() ||
        encryptedEventData.dioEmpty()
    ) {
        throw InvalidEncryptedEventDataVersionException(std::to_string(encryptedEventData.version()) + " expected version: " + std::to_string(EventDataSchema::Version::VERSION_5));
    }
}
