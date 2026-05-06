
/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include "privmx/endpoint/core/encryptors/DIO/DIOEncryptorV1.hpp"
#include "privmx/endpoint/core/ServerTypes.hpp"
#include "privmx/endpoint/core/CoreException.hpp"
#include "privmx/endpoint/core/CoreConstants.hpp"
#include <privmx/utils/Utils.hpp>


using namespace privmx::endpoint::core;

std::string DIOEncryptorV1::signAndEncode(const ExpandedDataIntegrityObject& dio, const privmx::crypto::PrivateKey& authorKey) {
    if(dio.creatorPubKey != authorKey.getPublicKey().toBase58DER()) {
        throw DataIntegrityObjectMismatchEncKeyException();
    }
    dynamic::DataIntegrityObject dioJSON{
        {.version = DataIntegrityObjectDataSchema::Version::VERSION_1},
        .creatorUserId = dio.creatorUserId,
        .creatorPublicKey = dio.creatorPubKey,
        .contextId = dio.contextId,
        .resourceId = dio.resourceId,
        .timestamp = dio.timestamp,
        .randomId = dio.randomId,
        .containerId = dio.containerId,
        .containerResourceId = dio.containerResourceId,
        .fieldChecksums = std::unordered_map<std::string, std::string>(),
        .structureVersion = dio.structureVersion,
        .bridgeIdentity = std::nullopt
    };
    for(const auto& checksum : dio.fieldChecksums) {
        dioJSON.fieldChecksums.insert_or_assign(checksum.first, privmx::utils::Base64::from(checksum.second));
    }
    if(dio.bridgeIdentity.has_value()) {
        dioJSON.bridgeIdentity = {.url=dio.bridgeIdentity->url, .pubKey=dio.bridgeIdentity->pubKey, .instanceId=dio.bridgeIdentity->instanceId};
    } else {
        throw MissingBridgeIdentityException();
    }
    return _dataEncryptor.encode(_dataEncryptor.signAndPackDataWithSignature(core::Buffer::from(privmx::utils::Utils::stringify(dioJSON.toJSON())), authorKey));
}

ExpandedDataIntegrityObject DIOEncryptorV1::decodeAndVerify(const std::string& signedDio) {
    auto dioAndSignature = _dataEncryptor.extractDataWithSignature(_dataEncryptor.decode(signedDio));
    dynamic::DataIntegrityObject dioJSON = dynamic::DataIntegrityObject::fromJSON(
       privmx::utils::Utils::parseJsonObject(dioAndSignature.data.stdString())
    );
    assertDataFormat(dioJSON);
    std::unordered_map<std::string, std::string> fieldChecksums;
    for(const auto& checksumBase64 : dioJSON.fieldChecksums) {
        fieldChecksums.insert_or_assign(checksumBase64.first, privmx::utils::Base64::toString(checksumBase64.second));
    }
    auto signatureStatus = _dataEncryptor.verifySignature(dioAndSignature, privmx::crypto::PublicKey::fromBase58DER(dioJSON.creatorPublicKey));
    if(!signatureStatus) {
        throw DataIntegrityObjectInvalidSignatureException();
    }

    return ExpandedDataIntegrityObject{
        DataIntegrityObject{
            .creatorUserId=dioJSON.creatorUserId,
            .creatorPubKey=dioJSON.creatorPublicKey,
            .contextId=dioJSON.contextId,
            .resourceId=dioJSON.resourceId,
            .timestamp=dioJSON.timestamp,
            .randomId=dioJSON.randomId,
            .containerId=dioJSON.containerId,
            .containerResourceId=dioJSON.containerResourceId,
            .bridgeIdentity= BridgeIdentity{
                .url=dioJSON.bridgeIdentity->url,
                .pubKey=dioJSON.bridgeIdentity->pubKey,
                .instanceId=dioJSON.bridgeIdentity->instanceId
            }
        },
        .structureVersion=dioJSON.structureVersion,
        .fieldChecksums=fieldChecksums
    };
}

void DIOEncryptorV1::assertDataFormat(const dynamic::DataIntegrityObject& dioJSON) {
    if (
        dioJSON.version != DataIntegrityObjectDataSchema::Version::VERSION_1   ||
        dioJSON.creatorUserId.empty()                                          ||
        dioJSON.creatorPublicKey.empty()                                       ||
        dioJSON.contextId.empty()                                              ||
        // dioJSON.resourceId.empty()                                             || TO fix
        dioJSON.randomId.empty() 
    ) {
        throw MalformedDataIntegrityObjectException();
    }
}