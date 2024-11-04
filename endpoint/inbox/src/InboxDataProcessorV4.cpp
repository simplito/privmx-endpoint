/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include "privmx/endpoint/inbox/InboxDataProcessorV4.hpp"

#include "privmx/endpoint/inbox/InboxException.hpp"

using namespace privmx::endpoint;
using namespace privmx::endpoint::inbox;

server::InboxData InboxDataProcessorV4::packForServer(const InboxDataProcessorModel& plainData,
                                                                     const crypto::PrivateKey& authorPrivateKey,
                                                                     const std::string& inboxKey) {
    
    auto serverPublicData = utils::TypedObjectFactory::createNewObject<PublicDataV4>();
    serverPublicData.version(4);
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

    auto serverPrivateData = utils::TypedObjectFactory::createNewObject<PrivateDataV4>();
    serverPrivateData.version(4);
    serverPrivateData.privateMeta(
        _dataEncryptor.signAndEncryptAndEncode(plainData.privateData.privateMeta, authorPrivateKey, inboxKey));
    if (plainData.privateData.internalMeta.has_value()) {
        serverPrivateData.internalMeta(
            _dataEncryptor.signAndEncryptAndEncode(plainData.privateData.internalMeta.value(), authorPrivateKey, inboxKey));
    }
    serverPrivateData.authorPubKey(authorPubKeyECC);

    auto serverInboxData = utils::TypedObjectFactory::createNewObject<server::InboxData>();
    serverInboxData.storeId(plainData.storeId);
    serverInboxData.threadId(plainData.threadId);
    serverInboxData.fileConfig(InboxDataHelper::fileConfigToTypedObject(plainData.filesConfig));

    serverInboxData.publicData(serverPublicData.asVar());
    serverInboxData.meta(serverPrivateData.asVar());
    return serverInboxData;
}

InboxDataResult InboxDataProcessorV4::unpackAll(const server::InboxData& encryptedData, const std::string& inboxKey) {
    InboxDataResult result;
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

InboxPublicDataAsResult InboxDataProcessorV4::unpackPublicOnly(const Poco::Dynamic::Var& publicData) {
    return unpackPublic(publicData);
}

/// PRIVATE METHODS
InboxPublicDataAsResult InboxDataProcessorV4::unpackPublic(const Poco::Dynamic::Var& publicData) {

    InboxPublicDataAsResult result;
    result.statusCode = 0;
    try {
        validateVersion(publicData);
        auto publicDataV4 = utils::TypedObjectFactory::createObjectFromVar<PublicDataV4>(publicData);
        auto authorPublicKeyECC = crypto::PublicKey::fromBase58DER(publicDataV4.authorPubKey());

        result.publicMeta = _dataEncryptor.decodeAndVerify(publicDataV4.publicMeta(), authorPublicKeyECC);
        if(!publicDataV4.publicMetaObjectEmpty()) {
            auto tmp_1 = utils::Utils::stringify(utils::Utils::parseJsonObject(result.publicMeta.stdString()));
            auto tmp_2 = utils::Utils::stringify(publicDataV4.publicMetaObject());
            if(tmp_1 != tmp_2) {
                auto e = InboxPublicDataMismatchException();
                result.statusCode = e.getCode();
            }
        }
        result.inboxEntriesPubKeyBase58DER = publicDataV4.inboxPubKey();
        result.inboxEntriesKeyId = publicDataV4.inboxKeyId();
        result.authorPubKey = publicDataV4.authorPubKey();
   
    }  catch (const privmx::endpoint::core::Exception& e) {
        result.statusCode = e.getCode();
    } catch (const privmx::utils::PrivmxException& e) {
        result.statusCode = core::ExceptionConverter::convert(e).getCode();
    } catch (...) {
        result.statusCode = ENDPOINT_CORE_EXCEPTION_CODE;
    }
    return result;
}

InboxPrivateDataAsResult InboxDataProcessorV4::unpackPrivate(
    const server::InboxData& encryptedData, const std::string& inboxKey) {

    InboxPrivateDataAsResult result;
    result.statusCode = 0;
    try {
        validateVersion(encryptedData.meta());
        auto privateDataV4 = utils::TypedObjectFactory::createObjectFromVar<PrivateDataV4>(encryptedData.meta());
        auto authorPublicKeyECC = crypto::PublicKey::fromBase58DER(privateDataV4.authorPubKey());

        result.privateMeta = _dataEncryptor.decodeAndDecryptAndVerify(privateDataV4.privateMeta(), authorPublicKeyECC, inboxKey);
        result.internalMeta = privateDataV4.internalMetaEmpty() ? 
            std::nullopt : 
            std::make_optional(_dataEncryptor.decodeAndDecryptAndVerify(privateDataV4.internalMeta(), authorPublicKeyECC, inboxKey));
        result.authorPubKey = privateDataV4.authorPubKey();

    }  catch (const privmx::endpoint::core::Exception& e) {
        result.statusCode = e.getCode();
    } catch (const privmx::utils::PrivmxException& e) {
        result.statusCode = core::ExceptionConverter::convert(e).getCode();
    } catch (...) {
        result.statusCode = ENDPOINT_CORE_EXCEPTION_CODE;
    }
    return result;
}

void InboxDataProcessorV4::validateVersion(const Poco::Dynamic::Var& data) {
    Poco::JSON::Object::Ptr obj = data.extract<Poco::JSON::Object::Ptr>();
    if (obj->get("version") != 4) {
        throw InvalidEncryptedInboxDataVersionException();
    }
}
