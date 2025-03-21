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

using namespace privmx::endpoint;
using namespace privmx::endpoint::inbox;

server::InboxData InboxDataProcessorV5::packForServer(const InboxDataProcessorModelV5& plainData,
                                                                     const crypto::PrivateKey& authorPrivateKey,
                                                                     const std::string& inboxKey) {
    
    auto serverPublicData = utils::TypedObjectFactory::createNewObject<server::PublicDataV5>();
    serverPublicData.version(5);
    serverPublicData.publicMeta(_dataEncryptor.signAndEncode(plainData.publicData.publicMeta, authorPrivateKey));
    try {
        serverPublicData.publicMetaObject(utils::Utils::parseJsonObject(plainData.publicData.publicMeta.stdString()));
    } catch (...) {
        serverPublicData.publicMetaObjectClear();
    }
    auto authorPubKeyECC {authorPrivateKey.getPublicKey().toBase58DER()};
    serverPublicData.authorPubKey(authorPubKeyECC);
    serverPublicData.inboxPubKey(plainData.publicData.inboxEntriesPubKeyBase58DER);
    serverPublicData.inboxKeyId(plainData.publicData.inboxEntriesKeyId);
    std::unordered_map<std::string, std::string> privateDataMapOfDataSha256;
    auto serverPrivateData = utils::TypedObjectFactory::createNewObject<server::PrivateDataV5>();
    serverPrivateData.version(5);
    serverPrivateData.privateMeta(_dataEncryptor.signAndEncryptAndEncode(plainData.privateData.privateMeta, authorPrivateKey, inboxKey));
    privateDataMapOfDataSha256.insert(std::make_pair("privateMeta",privmx::crypto::Crypto::sha256(serverPrivateData.privateMeta())));
    if (plainData.privateData.internalMeta.has_value()) {
        serverPrivateData.internalMeta(_dataEncryptor.signAndEncryptAndEncode(plainData.privateData.internalMeta.value(), authorPrivateKey, inboxKey));
        privateDataMapOfDataSha256.insert(std::make_pair("internalMeta",privmx::crypto::Crypto::sha256(serverPrivateData.internalMeta())));
    }
    serverPrivateData.authorPubKey(authorPubKeyECC);
    core::ExpandedDataIntegrityObject privateDataExpandedDio = {plainData.privateData.dio, .objectFormat=5, .mapOfDataSha256=privateDataMapOfDataSha256};
    serverPrivateData.dio(_DIOEncryptor.signAndEncode(privateDataExpandedDio, authorPrivateKey));

    auto serverInboxData = utils::TypedObjectFactory::createNewObject<server::InboxData>();

    std::unordered_map<std::string, std::string> mapOfDataSha256;
    serverInboxData.storeId(plainData.storeId);
    serverInboxData.threadId(plainData.threadId);
    serverInboxData.fileConfig(InboxDataHelper::fileConfigToTypedObject(plainData.filesConfig));
    serverInboxData.publicData(serverPublicData.asVar());
    serverInboxData.meta(serverPrivateData.asVar());
    return serverInboxData;
}

InboxDataResultV5 InboxDataProcessorV5::unpackAll(const server::InboxData& encryptedData, const std::string& inboxKey) {
    InboxDataResultV5 result;
    result.storeId = encryptedData.storeId();
    result.threadId = encryptedData.threadId();
    result.filesConfig = InboxDataHelper::fileConfigFromTypedObject(encryptedData.fileConfig());
    result.publicData = unpackPublic(encryptedData.publicData());
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
    result.dataStructureVersion = 5;
    result.statusCode = 0;
    try {
        auto publicDataV5 = utils::TypedObjectFactory::createObjectFromVar<server::PublicDataV5>(publicData);
        assertDataFormat(publicDataV5);
        auto authorPublicKeyECC = crypto::PublicKey::fromBase58DER(publicDataV5.authorPubKey());

        result.publicMeta = _dataEncryptor.decodeAndVerify(publicDataV5.publicMeta(), authorPublicKeyECC);
        if(!publicDataV5.publicMetaObjectEmpty()) {
            auto tmp_1 = utils::Utils::stringify(utils::Utils::parseJsonObject(result.publicMeta.stdString()));
            auto tmp_2 = utils::Utils::stringify(publicDataV5.publicMetaObject());
            if(tmp_1 != tmp_2) {
                auto e = InboxPublicDataMismatchException();
                result.statusCode = e.getCode();
            }
        }
        result.inboxEntriesPubKeyBase58DER = publicDataV5.inboxPubKey();
        result.inboxEntriesKeyId = publicDataV5.inboxKeyId();
        result.authorPubKey = publicDataV5.authorPubKey();
   
    }  catch (const privmx::endpoint::core::Exception& e) {
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
    result.dataStructureVersion = 5;
    result.statusCode = 0;
    try {
        auto privateDataV5 = utils::TypedObjectFactory::createObjectFromVar<server::PrivateDataV5>(encryptedData.meta());
        result.dio = getDIOAndAssertIntegrity(privateDataV5);
        auto authorPublicKeyECC = crypto::PublicKey::fromBase58DER(privateDataV5.authorPubKey());

        result.privateMeta = _dataEncryptor.decodeAndDecryptAndVerify(privateDataV5.privateMeta(), authorPublicKeyECC, inboxKey);
        result.internalMeta = privateDataV5.internalMetaEmpty() ? 
            std::nullopt : 
            std::make_optional(_dataEncryptor.decodeAndDecryptAndVerify(privateDataV5.internalMeta(), authorPublicKeyECC, inboxKey));
        result.authorPubKey = privateDataV5.authorPubKey();

    }  catch (const privmx::endpoint::core::Exception& e) {
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
    if (obj->get("version") != 5) {
        throw InvalidEncryptedInboxDataVersionException();
    }
}


core::DataIntegrityObject InboxDataProcessorV5::getDIOAndAssertIntegrity(const server::PrivateDataV5& encryptedPrivateData) {
    assertDataFormat(encryptedPrivateData);
    auto dio = _DIOEncryptor.decodeAndVerify(encryptedPrivateData.dio());
    if (
        dio.objectFormat != 5 ||
        dio.creatorPubKey != encryptedPrivateData.authorPubKey() ||
        dio.mapOfDataSha256.at("privateMeta") != privmx::crypto::Crypto::sha256(encryptedPrivateData.privateMeta()) || (
            !encryptedPrivateData.internalMetaEmpty() &&
            dio.mapOfDataSha256.at("internalMeta") != privmx::crypto::Crypto::sha256(encryptedPrivateData.internalMeta())
        )
    ) {
        throw core::DataIntegrityObjectInvalidSHA256Exception();
    }
    return dio;
}

void InboxDataProcessorV5::assertDataFormat(const server::PrivateDataV5& encryptedPrivateData) {
    if (encryptedPrivateData.versionEmpty() ||
        encryptedPrivateData.version() != 5 ||
        encryptedPrivateData.privateMetaEmpty() ||
        encryptedPrivateData.authorPubKeyEmpty() ||
        encryptedPrivateData.dioEmpty()
    ) {
        throw InvalidEncryptedInboxDataVersionException();
    }
}

void InboxDataProcessorV5::assertDataFormat(const server::PublicDataV5& encryptedPublicData) {
    if (encryptedPublicData.versionEmpty() ||
        encryptedPublicData.version() != 5 ||
        encryptedPublicData.publicMetaEmpty() ||
        encryptedPublicData.authorPubKeyEmpty() ||
        encryptedPublicData.inboxPubKeyEmpty() ||
        encryptedPublicData.inboxKeyIdEmpty()
    ) {
        throw InvalidEncryptedInboxDataVersionException();
    }
}