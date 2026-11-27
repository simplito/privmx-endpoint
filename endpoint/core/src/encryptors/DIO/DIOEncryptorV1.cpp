
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
#include <privmx/endpoint/core/crypto/PublicKeyCache.hpp>
#include <privmx/utils/Utils.hpp>

#include <cstdint>
#include <limits>

using namespace privmx::endpoint::core;

std::string DIOEncryptorV1::signAndEncode(const ExpandedDataIntegrityObject& dio, const core::PrivateKey& authorKey) {
    if (dio.creatorPubKey != authorKey.getPublicKey().toBase58DER()) {
        throw DataIntegrityObjectMismatchEncKeyException();
    }
    // Fields assigned after construction rather than through an initialiser list: C++20 does not
    // allow mixing designated and positional clauses, and the base class (which carries `version`)
    // cannot be designated. A purely designated list would in turn give
    // -Wmissing-field-initializers, which breaks the build under -Werror (PRIVMX_CI_WERROR).
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
    // Recorded so the checksums can be verified without the reader knowing the container's suite.
    // Inside the signed bytes, so naming a weaker suite breaks the signature.
    dioJSON.cryptoSuite = static_cast<int64_t>(dio.suite.id());
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
        dioAndSignature, core::PublicKeyCache::getInstance()->fromBase58DER(dioJSON.creatorPublicKey)
    );
    if (!signatureStatus) {
        throw DataIntegrityObjectInvalidSignatureException();
    }
    std::optional<BridgeIdentity> bridgeIdentity;
    if (dioJSON.bridgeIdentity.has_value()) {
        bridgeIdentity = BridgeIdentity{
            .url = dioJSON.bridgeIdentity->url,
            .pubKey = dioJSON.bridgeIdentity->pubKey,
            .instanceId = dioJSON.bridgeIdentity->instanceId
        };
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
            .bridgeIdentity = bridgeIdentity
        },
        dioJSON.structureVersion, fieldChecksums, suiteOf(dioJSON)
    };
}

CryptoSuite DIOEncryptorV1::suiteOf(const dynamic::DataIntegrityObject& dioJSON) {
    // A DIO from before the format carried a suite names none, and those checksums are SHA-256.
    if (!dioJSON.cryptoSuite.has_value()) {
        return CryptoSuite::forId(SuiteId::Aes256GcmSha256);
    }
    const auto id = dioJSON.cryptoSuite.value();
    // Checked here rather than let through to `forId`, so a value outside the enum's range — which
    // the cast below would otherwise turn into an arbitrary `SuiteId` — fails as what it is.
    if (id < 0 || id > static_cast<int64_t>(std::numeric_limits<std::uint8_t>::max())) {
        throw UnknownCryptoSuiteException(std::to_string(id));
    }
    return CryptoSuite::forId(static_cast<SuiteId>(static_cast<std::uint8_t>(id)));
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