
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

using namespace privmx::endpoint::core;

std::string DIOEncryptorV1::signAndEncode(const ExpandedDataIntegrityObject& dio, const privmx::crypto::PrivateKey& authorKey) {
    if(dio.creatorPubKey != authorKey.getPublicKey().toBase58DER()) {
        throw DataIntegrityObjectMismatchEncKeyException();
    }
    auto dioJSON = privmx::utils::TypedObjectFactory::createNewObject<dynamic::DataIntegrityObject>();
    dioJSON.version(1);
    dioJSON.creatorUserId(dio.creatorUserId);
    dioJSON.creatorPublicKey(dio.creatorPubKey);
    dioJSON.contextId(dio.contextId);
    dioJSON.resourceId(dio.resourceId);
    if (dio.containerId.has_value()) {
        dioJSON.itemId(dio.containerId.value());
    }
    if (dio.containerResourceId.has_value()) {
        dioJSON.itemId(dio.containerResourceId.value());
    }
    dioJSON.timestamp(dio.timestamp);
    dioJSON.randomId(dio.randomId);
    auto dioJSONfieldChecksums = privmx::utils::TypedObjectFactory::createNewMap<std::string>();
    for(auto  a: dio.fieldChecksums) {
        dioJSONfieldChecksums.add(a.first, utils::Base64::from(a.second));
    }
    dioJSON.fieldChecksums(dioJSONfieldChecksums);
    dioJSON.structureVersion(dio.structureVersion);
    return _dataEncryptor.encode(_dataEncryptor.signAndPackDataWithSignature(core::Buffer::from(privmx::utils::Utils::stringify(dioJSON)), authorKey));
}
ExpandedDataIntegrityObject DIOEncryptorV1::decodeAndVerify(const std::string& signedDio) {
    auto dioAndSignature = _dataEncryptor.extractDataWithSignature(_dataEncryptor.decode(signedDio));
    dynamic::DataIntegrityObject dioJSON = privmx::utils::TypedObjectFactory::createObjectFromVar<dynamic::DataIntegrityObject>(
       privmx::utils::Utils::parseJsonObject(dioAndSignature.data.stdString())
    );
    assertDataFormat(dioJSON);
    auto signatureStatus = _dataEncryptor.verifySignature(dioAndSignature, privmx::crypto::PublicKey::fromBase58DER(dioJSON.creatorPublicKey()));
    if(!signatureStatus) {
        throw DataIntegrityObjectInvalidSignatureException();
    }
    std::unordered_map<std::string, std::string> fieldChecksums;
    for(auto  a: dioJSON.fieldChecksums()) {
        fieldChecksums.insert(std::make_pair(a.first, utils::Base64::toString(a.second)));
    }
    std::optional<std::string> containerId = std::nullopt;
    if(!dioJSON.containerIdEmpty()) {
        containerId =  dioJSON.containerId();
    }
    std::optional<std::string> containerResourceId = std::nullopt;
    if(!dioJSON.containerResourceIdEmpty()) {
        containerResourceId = dioJSON.containerResourceId();
    }

    return ExpandedDataIntegrityObject{
        DataIntegrityObject{
            .creatorUserId=dioJSON.creatorUserId(),
            .creatorPubKey=dioJSON.creatorPublicKey(),
            .contextId=dioJSON.contextId(),
            .resourceId=dioJSON.resourceId(),
            .timestamp=dioJSON.timestamp(),
            .randomId=dioJSON.randomId(),
            .containerId=containerId,
            .containerResourceId=containerResourceId
        },
        .structureVersion=dioJSON.structureVersion(),
        .fieldChecksums=fieldChecksums
    };
}

void DIOEncryptorV1::assertDataFormat(const dynamic::DataIntegrityObject& dioJSON) {
    if (dioJSON.versionEmpty()          ||
        dioJSON.version() != 1          ||
        dioJSON.creatorUserIdEmpty()    ||
        dioJSON.creatorPublicKeyEmpty() ||
        dioJSON.contextIdEmpty()        ||
        dioJSON.resourceIdEmpty()       ||
        dioJSON.randomIdEmpty()         ||
        dioJSON.timestampEmpty()        ||
        dioJSON.fieldChecksumsEmpty()
    ) {
        throw MalformedDataIntegrityObjectException();
    }
}