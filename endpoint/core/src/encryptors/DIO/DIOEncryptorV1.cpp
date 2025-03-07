
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

std::string DIOEncryptorV1::signAndEncode(const ExpandedDataIntegrityObject& dio, const privmx::crypto::PrivateKey& autorKey) {
    auto dioJSON = privmx::utils::TypedObjectFactory::createNewObject<server::DataIntegrityObject>();
    dioJSON.version(1);
    dioJSON.creatorUserId(dio.creatorUserId);
    dioJSON.contextId(dio.contextId);
    dioJSON.containerId(dio.containerId);
    dioJSON.timestamp(dio.timestamp);
    dioJSON.nonce(dio.nonce);
    auto dioJSONmapOfDataSha256 = privmx::utils::TypedObjectFactory::createNewMap<std::string>();
    for(auto  a: dio.mapOfDataSha256) {
        dioJSONmapOfDataSha256.add(a.first, a.second);
    }
    dioJSON.mapOfDataSha256(dioJSONmapOfDataSha256);
    dioJSON.objectFormat(dio.objectFormat);
    return _dataEncryptor.encode(_dataEncryptor.signAndPackDataWithSignature(core::Buffer::from(privmx::utils::Utils::stringify(dioJSON)), autorKey));
}
ExpandedDataIntegrityObject DIOEncryptorV1::decodeAndVerify(const std::string& signedDio) {
    auto dioAndSignature = _dataEncryptor.extractDataWithSignature(_dataEncryptor.decode(signedDio));
    server::DataIntegrityObject dioJSON = privmx::utils::TypedObjectFactory::createObjectFromVar<server::DataIntegrityObject>(
       privmx::utils::Utils::parseJsonObject(dioAndSignature.data.stdString())
    );
    assertDataFormat(dioJSON);
    _dataEncryptor.verifySignature(dioAndSignature, privmx::crypto::PublicKey::fromBase58DER(dioJSON.creatorPublicKey()));
    std::unordered_map<std::string, std::string> mapOfDataSha256;
    for(auto  a: dioJSON.mapOfDataSha256()) {
        mapOfDataSha256.insert(a);
    }

    return ExpandedDataIntegrityObject{
        DataIntegrityObject{
            .creatorUserId=dioJSON.creatorUserId(),
            .creatorPubKey=dioJSON.creatorPublicKey(),
            .contextId=dioJSON.contextId(),
            .containerId=dioJSON.containerId(),
            .timestamp=dioJSON.timestamp(),
            .nonce=dioJSON.nonce()
        },
        .objectFormat=dioJSON.objectFormat(),
        .mapOfDataSha256=mapOfDataSha256
    };
}

void DIOEncryptorV1::assertDataFormat(const server::DataIntegrityObject& dioJSON) {
    if (dioJSON.versionEmpty() ||
        dioJSON.version() != 1 ||
        dioJSON.creatorUserIdEmpty() ||
        dioJSON.creatorPublicKeyEmpty() ||
        dioJSON.contextIdEmpty() ||
        dioJSON.containerIdEmpty() ||
        dioJSON.nonceEmpty() ||
        dioJSON.timestampEmpty() ||
        dioJSON.mapOfDataSha256Empty()
    ) {
        throw DataIntegrityObjectMalformedDataException();
    }
}