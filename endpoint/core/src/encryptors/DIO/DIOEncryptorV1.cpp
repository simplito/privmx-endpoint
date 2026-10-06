
/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include "privmx/endpoint/core/encryptors/DIO/DIOEncryptorV1.hpp"
#include "privmx/endpoint/core/CoreConstants.hpp"
#include "privmx/endpoint/core/CoreException.hpp"
#include "privmx/endpoint/core/ServerTypes.hpp"
#include <privmx/crypto/ecc/PublicKeyCache.hpp>
#include <privmx/utils/Utils.hpp>

using namespace privmx::endpoint::core;

std::string DIOEncryptorV1::signAndEncode(
    const ExpandedDataIntegrityObject& dio,
    const privmx::crypto::PrivateKey& authorKey
) {
    if (dio.creatorPubKey != authorKey.getPublicKey().toBase58DER()) {
        throw DataIntegrityObjectMismatchEncKeyException();
    }
    // Pola przypisywane po konstrukcji, a nie lista inicjalizujaca: C++20 nie pozwala mieszac
    // klauzul desygnowanych i pozycyjnych, a klasy bazowej (nosnika `version`) nie da sie
    // desygnowac. Sama lista desygnowana dawalaby z kolei -Wmissing-field-initializers,
    // co pod -Werror (PRIVMX_CI_WERROR) lamie build.
    dynamic::DataIntegrityObject dioJSON{};
    dioJSON.version = DataIntegrityObjectDataSchema::Version::VERSION_1;
    dioJSON.creatorUserId = dio.creatorUserId;
    dioJSON.creatorPublicKey = dio.creatorPubKey;
    dioJSON.contextId = dio.contextId;
    dioJSON.resourceId = dio.resourceId;
    dioJSON.timestamp = dio.timestamp;
    dioJSON.randomId = dio.randomId;
    dioJSON.containerId = dio.containerId;
    dioJSON.containerResourceId = dio.containerResourceId;
    dioJSON.fieldChecksums = std::unordered_map<std::string, std::string>();
    dioJSON.structureVersion = dio.structureVersion;
    dioJSON.bridgeIdentity = std::nullopt;
    for (const auto& checksum : dio.fieldChecksums) {
        dioJSON.fieldChecksums.insert_or_assign(checksum.first, privmx::utils::Base64::from(checksum.second));
    }
    if (dio.bridgeIdentity.has_value()) {
        dioJSON.bridgeIdentity = {
            .url = dio.bridgeIdentity->url,
            .pubKey = dio.bridgeIdentity->pubKey,
            .instanceId = dio.bridgeIdentity->instanceId
        };
    } else {
        dioJSON.bridgeIdentity = std::nullopt;
    }
    return _dataEncryptor.encode(
        _dataEncryptor.signAndPackDataWithSignature(core::Buffer::from(dioJSON.serialize()), authorKey)
    );
}

ExpandedDataIntegrityObject DIOEncryptorV1::decodeAndVerify(const std::string& signedDio) {
    auto dioAndSignature = _dataEncryptor.extractDataWithSignature(_dataEncryptor.decode(signedDio));
    dynamic::DataIntegrityObject dioJSON = dynamic::DataIntegrityObject::fromJSON(
        privmx::utils::Utils::parseJsonObject(dioAndSignature.data.stdString())
    );
    assertDataFormat(dioJSON);
    std::unordered_map<std::string, std::string> fieldChecksums;
    for (const auto& checksumBase64 : dioJSON.fieldChecksums) {
        fieldChecksums.insert_or_assign(checksumBase64.first, privmx::utils::Base64::toString(checksumBase64.second));
    }
    auto signatureStatus = _dataEncryptor.verifySignature(
        dioAndSignature, privmx::crypto::PublicKeyCache::getInstance()->fromBase58DER(dioJSON.creatorPublicKey)
    );
    if (!signatureStatus) {
        throw DataIntegrityObjectInvalidSignatureException();
    }

    return ExpandedDataIntegrityObject{
        DataIntegrityObject{
            .creatorUserId = dioJSON.creatorUserId,
            .creatorPubKey = dioJSON.creatorPublicKey,
            .contextId = dioJSON.contextId,
            .resourceId = dioJSON.resourceId,
            .timestamp = dioJSON.timestamp,
            .randomId = dioJSON.randomId,
            .containerId = dioJSON.containerId,
            .containerResourceId = dioJSON.containerResourceId,
            .bridgeIdentity =
                BridgeIdentity{
                    .url = dioJSON.bridgeIdentity->url,
                    .pubKey = dioJSON.bridgeIdentity->pubKey,
                    .instanceId = dioJSON.bridgeIdentity->instanceId
                }
        },
        dioJSON.structureVersion, fieldChecksums
    };
}

void DIOEncryptorV1::assertDataFormat(const dynamic::DataIntegrityObject& dioJSON) {
    if (dioJSON.version != DataIntegrityObjectDataSchema::Version::VERSION_1 ||
        dioJSON.creatorUserId.empty() ||
        dioJSON.creatorPublicKey.empty() ||
        dioJSON.contextId.empty() ||
        dioJSON.randomId.empty()) {
        throw MalformedDataIntegrityObjectException();
    }
}