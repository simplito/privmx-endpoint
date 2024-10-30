#ifndef _PRIVMXLIB_ENDPOINT_STORE_DYNAMICTYPES_HPP_
#define _PRIVMXLIB_ENDPOINT_STORE_DYNAMICTYPES_HPP_

#include <string>

#include <privmx/endpoint/core/TypesMacros.hpp>

namespace privmx {
namespace endpoint {
namespace store {
namespace dynamic {
//V4

ENDPOINT_CLIENT_TYPE(VersionedData)
    INT64_FIELD(version)
TYPE_END

ENDPOINT_CLIENT_TYPE(InternalStoreFileMeta)
    INT64_FIELD(version)
    INT64_FIELD(size)
    INT64_FIELD(cipherType)
    INT64_FIELD(chunkSize)
    STRING_FIELD(key)
    STRING_FIELD(hmac)
TYPE_END

ENDPOINT_CLIENT_TYPE(StoreFileMetaV4)
    INT64_FIELD(version)
    STRING_FIELD(publicMeta)
    STRING_FIELD(privateMeta)
    STRING_FIELD(encryptedFileSize)
    STRING_FIELD(internalMeta)
    STRING_FIELD(authorPubKey)
TYPE_END


class BlobPropertyBag : public utils::TypedObject
{
public:
    ENDPOINT_TYPE_CONSTRUCTOR(BlobPropertyBag);
    void initialize() override {}
    STRING_FIELD(type);
};

class Blob : public utils::TypedObject
{
public:
    ENDPOINT_TYPE_CONSTRUCTOR(Blob);
    void initialize() override {}
    BINARYSTRING_FIELD(data)
    OBJECT_FIELD(options, BlobPropertyBag)
};

class File : public Blob
{
public:
    ENDPOINT_TYPE_CONSTRUCTOR_INHERIT(File, Blob)
    void initialize() override {}
    INT64_FIELD(lastModified)
    STRING_FIELD(name)
    STRING_FIELD(webkitRelativePath)
};

ENDPOINT_CLIENT_TYPE(SendFileResult)
    OBJECT_FIELD(file, File)
    INT64_FIELD(cipherType)
    STRING_FIELD(key)
    STRING_FIELD(hmac)
    INT64_FIELD(chunkSize)
TYPE_END

namespace compat_v1 {
    ENDPOINT_CLIENT_TYPE(StoreData)
        STRING_FIELD(name)
        INT64_FIELD(statusCode)
    TYPE_END

    ENDPOINT_CLIENT_TYPE(StoreFileMetaAuthor)
        STRING_FIELD(pubKey)
    TYPE_END

    ENDPOINT_CLIENT_TYPE(StoreFileMetaDestination)
        STRING_FIELD(server)
        STRING_FIELD(contextId)
        STRING_FIELD(storeId)
        STRING_FIELD(store) // deprecated, backward compatibility
    TYPE_END

    ENDPOINT_CLIENT_TYPE(StoreMeta)
        STRING_FIELD(mimetype)  // mimetype: string;
        INT64_FIELD(size)         // size: number;
        INT64_FIELD(cipherType)
        INT64_FIELD(chunkSize)
        STRING_FIELD(key)
        STRING_FIELD(hmac)
        INT64_FIELD(statusCode)
    TYPE_END

    ENDPOINT_CLIENT_TYPE_INHERIT(StoreThumbMeta, StoreMeta)
    TYPE_END

    ENDPOINT_CLIENT_TYPE_INHERIT(StoreFileMeta, StoreMeta)
        INT64_FIELD(ver)
        STRING_FIELD(name)
        OBJECT_FIELD(author, StoreFileMetaAuthor)
        OBJECT_FIELD(destination, StoreFileMetaDestination)
        OBJECT_FIELD(thumb, StoreThumbMeta)  // thumb?: {size: number; mimetype: string;}
    TYPE_END
}

} // dynamic
} // store
} // endpoint
} // privmx

#endif // _PRIVMXLIB_ENDPOINT_STORE_DYNAMICTYPES_HPP_
