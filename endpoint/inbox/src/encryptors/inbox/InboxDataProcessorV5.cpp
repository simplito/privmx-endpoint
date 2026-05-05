/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include "privmx/endpoint/inbox/encryptors/inbox/InboxDataProcessorV5.hpp"

#include "privmx/endpoint/inbox/InboxException.hpp"
#include "privmx/endpoint/inbox/DynamicTypes.hpp"
#include "privmx/endpoint/inbox/Constants.hpp"

using namespace privmx::endpoint;
using namespace privmx::endpoint::inbox;

server::InboxData InboxDataProcessorV5::packForServer(const InboxDataProcessorModelV5& plainData,
                                                               const crypto::PrivateKey& authorPrivateKey,
                                                               const std::string& inboxKey) {
    server::PublicDataV5 serverPublicData;
    serverPublicData.version = InboxDataSchema::Version::VERSION_5;
    serverPublicData.publicMeta = _dataEncryptor.signAndEncode(plainData.publicData.publicMeta, authorPrivateKey);
    try {
        serverPublicData.publicMetaObject = utils::Utils::parseJsonObject(plainData.publicData.publicMeta.stdString());
    } catch (...) {
        serverPublicData.publicMetaObject = Poco::Dynamic::Var();
    }
    auto authorPubKeyECC {authorPrivateKey.getPublicKey().toBase58DER()};
    serverPublicData.authorPubKey = authorPubKeyECC;
    serverPublicData.inboxPubKey = plainData.publicData.inboxEntriesPubKeyBase58DER;
    serverPublicData.inboxKeyId = plainData.publicData.inboxEntriesKeyId;

    std::unordered_map<std::string, std::string> privateDataMapOfDataSha256;
    server::PrivateDataV5 serverPrivateData;
    serverPrivateData.version = InboxDataSchema::Version::VERSION_5;
    serverPrivateData.privateMeta = _dataEncryptor.signAndEncryptAndEncode(plainData.privateData.privateMeta, authorPrivateKey, inboxKey);
    privateDataMapOfDataSha256.insert(std::make_pair("privateMeta", privmx::crypto::Crypto::sha256(serverPrivateData.privateMeta)));

    dynamic::InboxInternalMetaV5 internalMetaObj;
    internalMetaObj.secret = plainData.privateData.internalMeta.secret;
    internalMetaObj.resourceId = plainData.privateData.internalMeta.resourceId;
    internalMetaObj.randomId = plainData.privateData.internalMeta.randomId;
    serverPrivateData.internalMeta = _dataEncryptor.signAndEncryptAndEncode(core::Buffer::from(utils::Utils::stringifyVar(internalMetaObj.toJSON())), authorPrivateKey, inboxKey);
    privateDataMapOfDataSha256.insert(std::make_pair("internalMeta", privmx::crypto::Crypto::sha256(serverPrivateData.internalMeta)));
    serverPrivateData.authorPubKey = authorPubKeyECC;
    core::ExpandedDataIntegrityObject privateDataExpandedDio = {plainData.privateData.dio, .structureVersion=InboxDataSchema::Version::VERSION_5, .fieldChecksums=privateDataMapOfDataSha256};
    serverPrivateData.dio = _DIOEncryptor.signAndEncode(privateDataExpandedDio, authorPrivateKey);

    server::InboxData serverInboxData;
    serverInboxData.storeId = plainData.storeId;
    serverInboxData.threadId = plainData.threadId;
    serverInboxData.fileConfig = InboxDataHelper::fileConfigToTypedObject(plainData.filesConfig);
    serverInboxData.publicData = serverPublicData.toJSON();
    serverInboxData.meta = serverPrivateData.toJSON();
    return serverInboxData;
}

InboxDataResultV5 InboxDataProcessorV5::unpackAll(const server::InboxData& encryptedData, const std::string& inboxKey) {
    InboxDataResultV5 result;
    result.storeId = encryptedData.storeId;
    result.threadId = encryptedData.threadId;
    result.filesConfig = InboxDataHelper::fileConfigFromTypedObject(encryptedData.fileConfig);
    result.publicData = unpackPublic(encryptedData.publicData);
    result.statusCode = result.publicData.statusCode;
    if (result.statusCode != 0) {
        return result;
    }

    result.privateData = unpackPrivate(encryptedData, inboxKey);
    result.statusCode = result.privateData.statusCode;
    return result;
}

InboxPublicDataV5AsResult InboxDataProcessorV5::unpackPublicOnly(const Poco::Dynamic::Var& publicData) {
    return unpackPublic(publicData);
}

/// PRIVATE METHODS
InboxPublicDataV5AsResult InboxDataProcessorV5::unpackPublic(const Poco::Dynamic::Var& publicData) {
    InboxPublicDataV5AsResult result;
    result.dataStructureVersion = InboxDataSchema::Version::VERSION_5;
    result.statusCode = 0;
    try {
        auto publicDataV5 = server::PublicDataV5::fromJSON(publicData);
        assertDataFormat(publicDataV5);
        auto authorPublicKeyECC = crypto::PublicKey::fromBase58DER(publicDataV5.authorPubKey);

        result.publicMeta = _dataEncryptor.decodeAndVerify(publicDataV5.publicMeta, authorPublicKeyECC);
        if (!publicDataV5.publicMetaObject.isEmpty()) {
            auto tmp_1 = utils::Utils::stringifyVar(utils::Utils::parseJsonObject(result.publicMeta.stdString()));
            auto tmp_2 = utils::Utils::stringifyVar(publicDataV5.publicMetaObject);
            if (tmp_1 != tmp_2) {
                auto e = InboxPublicDataMismatchException();
                result.statusCode = e.getCode();
            }
        }
        result.inboxEntriesPubKeyBase58DER = publicDataV5.inboxPubKey;
        result.inboxEntriesKeyId = publicDataV5.inboxKeyId;
        result.authorPubKey = publicDataV5.authorPubKey;

    } catch (const privmx::endpoint::core::Exception& e) {
        result.statusCode = e.getCode();
    } catch (const privmx::utils::PrivmxException& e) {
        result.statusCode = core::ExceptionConverter::convert(e).getCode();
    } catch (...) {
        result.statusCode = ENDPOINT_CORE_EXCEPTION_CODE;
    }
    return result;
}

InboxPrivateDataV5AsResult InboxDataProcessorV5::unpackPrivate(
    const server::InboxData& encryptedData, const std::string& inboxKey) {
    InboxPrivateDataV5AsResult result;
    result.dataStructureVersion = InboxDataSchema::Version::VERSION_5;
    result.statusCode = 0;
    try {
        auto privateDataV5 = server::PrivateDataV5::fromJSON(encryptedData.meta);
        result.dio = getDIOAndAssertIntegrity(privateDataV5);
        auto authorPublicKeyECC = crypto::PublicKey::fromBase58DER(privateDataV5.authorPubKey);

        result.privateMeta = _dataEncryptor.decodeAndDecryptAndVerify(privateDataV5.privateMeta, authorPublicKeyECC, inboxKey);
        auto internalMetaStr = _dataEncryptor.decodeAndDecryptAndVerify(privateDataV5.internalMeta, authorPublicKeyECC, inboxKey).stdString();
        auto internalMetaJSON = dynamic::InboxInternalMetaV5::fromJSON(utils::Utils::parseJsonObject(internalMetaStr));
        result.internalMeta = InboxInternalMetaV5{.secret=internalMetaJSON.secret, .resourceId=internalMetaJSON.resourceId, .randomId=internalMetaJSON.randomId};
        result.authorPubKey = privateDataV5.authorPubKey;

    } catch (const privmx::endpoint::core::Exception& e) {
        result.statusCode = e.getCode();
    } catch (const privmx::utils::PrivmxException& e) {
        result.statusCode = core::ExceptionConverter::convert(e).getCode();
    } catch (...) {
        result.statusCode = ENDPOINT_CORE_EXCEPTION_CODE;
    }
    return result;
}

void InboxDataProcessorV5::validateVersion(const Poco::Dynamic::Var& data) {
    Poco::JSON::Object::Ptr obj = data.extract<Poco::JSON::Object::Ptr>();
    if (obj->get("version").convert<Poco::Int64>() != InboxDataSchema::Version::VERSION_5) {
        throw InvalidEncryptedInboxDataVersionException();
    }
}

core::DataIntegrityObject InboxDataProcessorV5::getDIOAndAssertIntegrity(const server::PrivateDataV5& encryptedPrivateData) {
    assertDataFormat(encryptedPrivateData);
    auto dio = _DIOEncryptor.decodeAndVerify(encryptedPrivateData.dio);
    if (
        dio.structureVersion != InboxDataSchema::Version::VERSION_5 ||
        dio.creatorPubKey != encryptedPrivateData.authorPubKey ||
        dio.fieldChecksums.at("privateMeta") != privmx::crypto::Crypto::sha256(encryptedPrivateData.privateMeta) ||
        dio.fieldChecksums.at("internalMeta") != privmx::crypto::Crypto::sha256(encryptedPrivateData.internalMeta)
    ) {
        throw core::InvalidDataIntegrityObjectChecksumException();
    }
    return dio;
}

void InboxDataProcessorV5::assertDataFormat(const server::PrivateDataV5& encryptedPrivateData) {
    if (
        encryptedPrivateData.version != InboxDataSchema::Version::VERSION_5 ||
        encryptedPrivateData.privateMeta.empty() ||
        encryptedPrivateData.authorPubKey.empty() ||
        encryptedPrivateData.dio.empty()
    ) {
        throw InvalidEncryptedInboxDataVersionException();
    }
}

void InboxDataProcessorV5::assertDataFormat(const server::PublicDataV5& encryptedPublicData) {
    if (
        encryptedPublicData.version != InboxDataSchema::Version::VERSION_5 ||
        encryptedPublicData.publicMeta.empty() ||
        encryptedPublicData.authorPubKey.empty() ||
        encryptedPublicData.inboxPubKey.empty() ||
        encryptedPublicData.inboxKeyId.empty()
    ) {
        throw InvalidEncryptedInboxDataVersionException();
    }
}

core::DataIntegrityObject InboxDataProcessorV5::getDIOAndAssertIntegrity(const server::InboxData& data) {
    auto privateDataV5 = server::PrivateDataV5::fromJSON(data.meta);
    return getDIOAndAssertIntegrity(privateDataV5);
}
