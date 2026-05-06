/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include "privmx/endpoint/inbox/encryptors/inbox/InboxDataProcessorV4.hpp"

#include "privmx/endpoint/inbox/InboxException.hpp"
#include "privmx/endpoint/inbox/Constants.hpp"

using namespace privmx::endpoint;
using namespace privmx::endpoint::inbox;

server::InboxData InboxDataProcessorV4::packForServer(const InboxDataProcessorModelV4& plainData,
                                                               const crypto::PrivateKey& authorPrivateKey,
                                                               const std::string& inboxKey) {
    server::PublicDataV4 serverPublicData;
    serverPublicData.version = InboxDataSchema::Version::VERSION_4;
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

    server::PrivateDataV4 serverPrivateData;
    serverPrivateData.version = InboxDataSchema::Version::VERSION_4;
    serverPrivateData.privateMeta = _dataEncryptor.signAndEncryptAndEncode(plainData.privateData.privateMeta, authorPrivateKey, inboxKey);
    if (plainData.privateData.internalMeta.has_value()) {
        serverPrivateData.internalMeta = _dataEncryptor.signAndEncryptAndEncode(plainData.privateData.internalMeta.value(), authorPrivateKey, inboxKey);
    }
    serverPrivateData.authorPubKey = authorPubKeyECC;

    return server::InboxData{
        .threadId = plainData.threadId,
        .storeId = plainData.storeId,
        .fileConfig = InboxDataHelper::fileConfigToTypedObject(plainData.filesConfig),
        .meta = serverPrivateData.toJSON(),
        .publicData = serverPublicData.toJSON(),
    };
}

InboxDataResultV4 InboxDataProcessorV4::unpackAll(const server::InboxData& encryptedData, const std::string& inboxKey) {
    InboxDataResultV4 result;
    result.dataStructureVersion = InboxDataSchema::Version::VERSION_4;
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

InboxPublicDataV4AsResult InboxDataProcessorV4::unpackPublicOnly(const Poco::Dynamic::Var& publicData) {
    return unpackPublic(publicData);
}

/// PRIVATE METHODS
InboxPublicDataV4AsResult InboxDataProcessorV4::unpackPublic(const Poco::Dynamic::Var& publicData) {
    InboxPublicDataV4AsResult result;
    result.dataStructureVersion = InboxDataSchema::Version::VERSION_4;
    result.statusCode = 0;
    try {
        validateVersion(publicData);
        auto publicDataV4 = server::PublicDataV4::fromJSON(publicData);
        auto authorPublicKeyECC = crypto::PublicKey::fromBase58DER(publicDataV4.authorPubKey);

        result.publicMeta = _dataEncryptor.decodeAndVerify(publicDataV4.publicMeta, authorPublicKeyECC);
        if (!publicDataV4.publicMetaObject.isEmpty()) {
            auto tmp_1 = utils::Utils::stringifyVar(utils::Utils::parseJsonObject(result.publicMeta.stdString()));
            auto tmp_2 = utils::Utils::stringifyVar(publicDataV4.publicMetaObject);
            if (tmp_1 != tmp_2) {
                auto e = InboxPublicDataMismatchException();
                result.statusCode = e.getCode();
            }
        }
        result.inboxEntriesPubKeyBase58DER = publicDataV4.inboxPubKey;
        result.inboxEntriesKeyId = publicDataV4.inboxKeyId;
        result.authorPubKey = publicDataV4.authorPubKey;

    } catch (const privmx::endpoint::core::Exception& e) {
        result.statusCode = e.getCode();
    } catch (const privmx::utils::PrivmxException& e) {
        result.statusCode = core::ExceptionConverter::convert(e).getCode();
    } catch (...) {
        result.statusCode = ENDPOINT_CORE_EXCEPTION_CODE;
    }
    return result;
}

InboxPrivateDataV4AsResult InboxDataProcessorV4::unpackPrivate(
    const server::InboxData& encryptedData, const std::string& inboxKey) {

    InboxPrivateDataV4AsResult result;
    result.dataStructureVersion = InboxDataSchema::Version::VERSION_4;
    result.statusCode = 0;
    try {
        validateVersion(encryptedData.meta);
        auto privateDataV4 = server::PrivateDataV4::fromJSON(encryptedData.meta);
        auto authorPublicKeyECC = crypto::PublicKey::fromBase58DER(privateDataV4.authorPubKey);

        result.privateMeta = _dataEncryptor.decodeAndDecryptAndVerify(privateDataV4.privateMeta, authorPublicKeyECC, inboxKey);
        result.internalMeta = !privateDataV4.internalMeta.has_value() ?
            std::nullopt :
            std::make_optional(_dataEncryptor.decodeAndDecryptAndVerify(privateDataV4.internalMeta.value(), authorPublicKeyECC, inboxKey));
        result.authorPubKey = privateDataV4.authorPubKey;

    } catch (const privmx::endpoint::core::Exception& e) {
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
    if (obj->get("version").convert<Poco::Int64>() != InboxDataSchema::Version::VERSION_4) {
        throw InvalidEncryptedInboxDataVersionException();
    }
}
