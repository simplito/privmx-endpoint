/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include "privmx/endpoint/store/encryptors/file/FileMetaEncryptor.hpp"
#include <privmx/endpoint/core/ConnectionImpl.hpp>

#include "privmx/endpoint/core/ExceptionConverter.hpp"
#include "privmx/endpoint/core/CoreException.hpp"
#include "privmx/endpoint/store/StoreException.hpp"
#include "privmx/endpoint/store/Constants.hpp"

using namespace privmx::endpoint;
using namespace privmx::endpoint::store;

FileMetaEncryptor::FileMetaEncryptor(const privmx::crypto::PrivateKey& userPrivKey,const core::Connection& connection) 
    : _userPrivKey(userPrivKey), _connection(connection) {}

Poco::Dynamic::Var FileMetaEncryptor::encrypt(const FileInfo& fileInfo, const FileMeta& fileMeta, core::EncKey encKey, int64_t keyVersion) {
    switch (keyVersion) {
        case core::EncryptionKeyDataSchema::Version::VERSION_1:
            return FileMetaEncryptorV4().encrypt(
                store::FileMetaToEncryptV4{
                    .publicMeta = fileMeta.publicMeta,
                    .privateMeta = fileMeta.privateMeta,
                    .fileSize = fileMeta.internalFileMeta.size(),
                    .internalMeta = core::Buffer::from(utils::Utils::stringifyVar(fileMeta.internalFileMeta.asVar()))
                },
                _userPrivKey,
                encKey.key
            ).asVar();
        case core::EncryptionKeyDataSchema::Version::VERSION_2:
            return FileMetaEncryptorV5().encrypt(
                store::FileMetaToEncryptV5{
                    .publicMeta = fileMeta.publicMeta,
                    .privateMeta = fileMeta.privateMeta,
                    .internalMeta = core::Buffer::from(utils::Utils::stringifyVar(fileMeta.internalFileMeta.asVar())),
                    .dio = createDIO(fileInfo)
                },
                _userPrivKey,
                encKey.key
            ).asVar();
        default:
            throw core::UnknownEncryptionKeyVersionException();
    }
}

FileMetaEncryptor::DecryptedFileMeta FileMetaEncryptor::decrypt(Poco::Dynamic::Var encryptedFileMeta, core::EncKey encKey) {
    switch (getFileDataStructureVersion(encryptedFileMeta)) {
        case FileDataSchema::Version::UNKNOWN: 
            return FileMetaEncryptor::DecryptedFileMeta();
        case FileDataSchema::Version::VERSION_1: {
            // this can throw TODO
            auto encryptedFileMetaV1 = encryptedFileMeta.convert<std::string>();
            return FileMetaEncryptor::DecryptedFileMeta(_fileMetaEncryptorV1.decrypt(encryptedFileMetaV1, encKey.key));
        }
        case FileDataSchema::Version::VERSION_4: {
            auto encryptedFileMetaV4 = utils::TypedObjectFactory::createObjectFromVar<server::EncryptedFileMetaV4>(encryptedFileMeta);
            return FileMetaEncryptor::DecryptedFileMeta(_fileMetaEncryptorV4.decrypt(encryptedFileMetaV4, encKey.key));
        }
        case FileDataSchema::Version::VERSION_5: {
            auto encryptedFileMetaV5 = utils::TypedObjectFactory::createObjectFromVar<server::EncryptedFileMetaV5>(encryptedFileMeta);
            return FileMetaEncryptor::DecryptedFileMeta(_fileMetaEncryptorV5.decrypt(encryptedFileMetaV5, encKey.key));
        }
    }
    return FileMetaEncryptor::DecryptedFileMeta();
}

FileMetaEncryptor::DecryptedFileMeta FileMetaEncryptor::extractPublic(Poco::Dynamic::Var encryptedFileMeta) {
    switch (getFileDataStructureVersion(encryptedFileMeta)) {
        case FileDataSchema::Version::UNKNOWN: 
            return FileMetaEncryptor::DecryptedFileMeta();
        case FileDataSchema::Version::VERSION_1: {
            // this can throw TODO
            auto encryptedFileMetaV1 = encryptedFileMeta.convert<std::string>();
            return FileMetaEncryptor::DecryptedFileMeta(_fileMetaEncryptorV1.decrypt(encryptedFileMetaV1, ""));
        }
        case FileDataSchema::Version::VERSION_4: {
            auto encryptedFileMetaV4 = utils::TypedObjectFactory::createObjectFromVar<server::EncryptedFileMetaV4>(encryptedFileMeta);
            return FileMetaEncryptor::DecryptedFileMeta(_fileMetaEncryptorV4.decrypt(encryptedFileMetaV4, ""));
        }
        case FileDataSchema::Version::VERSION_5: {
            auto encryptedFileMetaV5 = utils::TypedObjectFactory::createObjectFromVar<server::EncryptedFileMetaV5>(encryptedFileMeta);
            return FileMetaEncryptor::DecryptedFileMeta(_fileMetaEncryptorV5.extractPublic(encryptedFileMetaV5));
        }
    }
    return FileMetaEncryptor::DecryptedFileMeta();
}

FileDataSchema::Version FileMetaEncryptor::getFileDataStructureVersion(Poco::Dynamic::Var encryptedFileMeta) {
    if (encryptedFileMeta.type() == typeid(Poco::JSON::Object::Ptr)) {
        auto versioned = utils::TypedObjectFactory::createObjectFromVar<core::dynamic::VersionedData>(encryptedFileMeta);
        auto version = versioned.versionOpt(FileDataSchema::Version::UNKNOWN);
        switch (version) {
            case FileDataSchema::Version::VERSION_4:
                return FileDataSchema::Version::VERSION_4;
            case FileDataSchema::Version::VERSION_5:
                return FileDataSchema::Version::VERSION_5;
            default:
                return FileDataSchema::Version::UNKNOWN;
        }
    } else if (encryptedFileMeta.isString()) {
        return FileDataSchema::Version::VERSION_1;
    }
    return FileDataSchema::Version::UNKNOWN;
}

privmx::endpoint::core::DataIntegrityObject FileMetaEncryptor::createDIO(const FileInfo& fileInfo) {
    privmx::endpoint::core::DataIntegrityObject fileDIO = _connection.getImpl()->createDIO(
        fileInfo.contextId,
        fileInfo.resourceId,
        fileInfo.storeId,
        fileInfo.storeResourceId
    );
    return fileDIO;
}