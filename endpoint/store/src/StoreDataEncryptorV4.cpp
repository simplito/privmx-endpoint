#include "privmx/endpoint/store/StoreDataEncryptorV4.hpp"

#include "privmx/endpoint/core/ExceptionConverter.hpp"
#include "privmx/endpoint/store/StoreException.hpp"

using namespace privmx::endpoint;
using namespace privmx::endpoint::store;

server::EncryptedStoreDataV4 StoreDataEncryptorV4::encrypt(const StoreDataToEncrypt& plainData,
                                                                     const crypto::PrivateKey& authorPrivateKey,
                                                                     const std::string& encryptionKey) {
    auto result = utils::TypedObjectFactory::createNewObject<server::EncryptedStoreDataV4>();
    result.version(4);
    result.publicMeta(_dataEncryptor.signAndEncode(plainData.publicMeta, authorPrivateKey));
    try {
        result.publicMetaObject(utils::Utils::parseJsonObject(plainData.publicMeta.stdString()));
    } catch (...) {
        result.publicMetaObjectClear();
    }
    result.privateMeta(
        _dataEncryptor.signAndEncryptAndEncode(plainData.privateMeta, authorPrivateKey, encryptionKey));
    if (plainData.internalMeta.has_value()) {
        result.internalMeta(
            _dataEncryptor.signAndEncryptAndEncode(plainData.internalMeta.value(), authorPrivateKey, encryptionKey));
    }
    result.authorPubKey(authorPrivateKey.getPublicKey().toBase58DER());
    return result;
}

DecryptedStoreData StoreDataEncryptorV4::decrypt(
    const server::EncryptedStoreDataV4& encryptedData, const std::string& encryptionKey) {
    DecryptedStoreData result;
    result.statusCode = 0;
    try {
        auto authorPublicKey = crypto::PublicKey::fromBase58DER(encryptedData.authorPubKey());
        result.publicMeta = _dataEncryptor.decodeAndVerify(encryptedData.publicMeta(), authorPublicKey);
        if(!encryptedData.publicMetaObjectEmpty()) {
            auto tmp_1 = utils::Utils::stringify(utils::Utils::parseJsonObject(result.publicMeta.stdString()));
            auto tmp_2 = utils::Utils::stringify(encryptedData.publicMetaObject());
            if(tmp_1 != tmp_2) {
                auto e = StorePublicDataMismatchException();
                result.statusCode = e.getCode();
            }
        }
        result.privateMeta = _dataEncryptor.decodeAndDecryptAndVerify(encryptedData.privateMeta(), authorPublicKey, encryptionKey);
        result.internalMeta = encryptedData.internalMetaEmpty() ? 
            std::nullopt : 
            std::make_optional(_dataEncryptor.decodeAndDecryptAndVerify(encryptedData.internalMeta(), authorPublicKey, encryptionKey));
        result.authorPubKey = encryptedData.authorPubKey();   
    }  catch (const privmx::endpoint::core::Exception& e) {
        result.statusCode = e.getCode();
    } catch (const privmx::utils::PrivmxException& e) {
        result.statusCode = core::ExceptionConverter::convert(e).getCode();
    } catch (...) {
        result.statusCode = ENDPOINT_CORE_EXCEPTION_CODE;
    }
    return result;
}

void StoreDataEncryptorV4::validateVersion(const server::EncryptedStoreDataV4& encryptedData) {
    if (encryptedData.version() != 4) {
        throw InvalidEncryptedStoreDataVersionException();
    }
}
