/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_ENDPOINT_STORE_SERVERTYPES_HPP_
#define _PRIVMXLIB_ENDPOINT_STORE_SERVERTYPES_HPP_

#include <string>

#include <privmx/endpoint/core/ServerTypes.hpp>
#include <privmx/endpoint/core/TypesMacros.hpp>
#include <privmx/endpoint/core/ServerTypes.hpp>

namespace privmx {
namespace endpoint {
namespace store {
namespace server {

// BEGIN BUF
class BufferReadRange : public utils::TypedObject
{
public:
    ENDPOINT_TYPE_CONSTRUCTOR(BufferReadRange)
    void initialize() override {
        type(std::string("all"));
    }
    STRING_FIELD(type)
};
class BufferReadRangeSlice : public BufferReadRange
{
public:
    ENDPOINT_TYPE_CONSTRUCTOR_INHERIT(BufferReadRangeSlice, BufferReadRange)
    void initialize() override {
        type(std::string("slice"));
    }
    INT64_FIELD(from)
    INT64_FIELD(to)
};

class BufferReadRangeChecksum : public BufferReadRange
{
public:
    ENDPOINT_TYPE_CONSTRUCTOR_INHERIT(BufferReadRangeChecksum, BufferReadRange)
    void initialize() override {
        type(std::string("checksum"));
    }
};
// END BUF
ENDPOINT_SERVER_TYPE(StoreDataEntry)
    STRING_FIELD(keyId)
    VAR_FIELD(data)
TYPE_END

ENDPOINT_SERVER_TYPE(Store)
    STRING_FIELD(id)
    STRING_FIELD(contextId)
    INT64_FIELD(createDate)
    STRING_FIELD(creator)
    INT64_FIELD(lastModificationDate)
    STRING_FIELD(lastModifier)
    LIST_FIELD(data, StoreDataEntry)
    STRING_FIELD(keyId)
    LIST_FIELD(users, std::string)
    LIST_FIELD(managers, std::string)
    LIST_FIELD(keys, core::server::KeyEntry)
    INT64_FIELD(version)
    INT64_FIELD(lastFileDate)
    INT64_FIELD(files)
    STRING_FIELD(type)
TYPE_END

ENDPOINT_SERVER_TYPE(StoreCreateModel)
    STRING_FIELD(contextId)
    LIST_FIELD(users, std::string)
    LIST_FIELD(managers, std::string)
    VAR_FIELD(data)
    STRING_FIELD(keyId)
    LIST_FIELD(keys, core::server::KeyEntrySet)
    STRING_FIELD(type)
TYPE_END

ENDPOINT_SERVER_TYPE(StoreUpdateModel)
    STRING_FIELD(id)
    LIST_FIELD(users, std::string)
    LIST_FIELD(managers, std::string)
    VAR_FIELD(data)
    STRING_FIELD(keyId)
    LIST_FIELD(keys, core::server::KeyEntrySet)
    INT64_FIELD(version)
    BOOL_FIELD(force)
TYPE_END

//-----------------------------------------------------

// File/sMetaGet

ENDPOINT_SERVER_TYPE(FileThumb)
    INT64_FIELD(size)
TYPE_END

ENDPOINT_SERVER_TYPE(File)
    STRING_FIELD(id)
    INT64_FIELD(version)
    STRING_FIELD(contextId)
    STRING_FIELD(storeId)
    INT64_FIELD(created)
    STRING_FIELD(creator)
    INT64_FIELD(lastModificationDate)
    STRING_FIELD(lastModifier)
    VAR_FIELD(meta)  // meta: unknown
    INT64_FIELD(size)
    STRING_FIELD(keyId)
    OBJECT_FIELD(thumb, FileThumb)
TYPE_END

ENDPOINT_SERVER_TYPE(FileError)
    INT64_FIELD(code)
    STRING_FIELD(message)
TYPE_END

ENDPOINT_SERVER_TYPE_INHERIT(FileListElement, File)
    STRING_FIELD(id)
    OBJECT_FIELD(error, FileError)
TYPE_END

ENDPOINT_SERVER_TYPE(StoreFileGetModel)
    STRING_FIELD(fileId)
TYPE_END

ENDPOINT_SERVER_TYPE(StoreFileGetManyModel)
    STRING_FIELD(storeId)
    LIST_FIELD(fileIds, std::string)
    BOOL_FIELD(failOnError)
TYPE_END

ENDPOINT_SERVER_TYPE(StoreFileGetResult)
    OBJECT_FIELD(store, Store)
    OBJECT_FIELD(file, File)
TYPE_END

ENDPOINT_SERVER_TYPE(StoreFileGetManyResult)
    OBJECT_FIELD(store, Store)
    LIST_FIELD(files, FileListElement)
TYPE_END

ENDPOINT_SERVER_TYPE(StoreFileListModel)
    STRING_FIELD(storeId)
    INT64_FIELD(skip)
    INT64_FIELD(limit)
    STRING_FIELD(sortOrder)
    STRING_FIELD(lastId)
TYPE_END

ENDPOINT_SERVER_TYPE(StoreFileListResult)
    OBJECT_FIELD(store, Store)
    LIST_FIELD(files, File)
    INT64_FIELD(count)
TYPE_END

ENDPOINT_CLIENT_TYPE(EncryptedFileMetaV4)
    INT64_FIELD(version)
    STRING_FIELD(publicMeta)
    OBJECT_PTR_FIELD(publicMetaObject)
    STRING_FIELD(privateMeta)
    STRING_FIELD(fileSize)
    STRING_FIELD(internalMeta)
    STRING_FIELD(authorPubKey)
TYPE_END

ENDPOINT_CLIENT_TYPE(EncryptedStoreDataV4)
    INT64_FIELD(version)
    STRING_FIELD(publicMeta)
    OBJECT_PTR_FIELD(publicMetaObject)
    STRING_FIELD(privateMeta)
    STRING_FIELD(internalMeta)
    STRING_FIELD(authorPubKey)
TYPE_END

//-----------------------------------------------------




ENDPOINT_SERVER_TYPE(StoreCreateResult)
    STRING_FIELD(storeId)
TYPE_END

ENDPOINT_SERVER_TYPE(StoreDeleteModel)
    STRING_FIELD(storeId)
TYPE_END

ENDPOINT_SERVER_TYPE(StoreGetModel)
    STRING_FIELD(storeId)
    STRING_FIELD(type)
TYPE_END

ENDPOINT_SERVER_TYPE(StoreGetResult)
    OBJECT_FIELD(store, Store)
TYPE_END

ENDPOINT_SERVER_TYPE(StoreListModel)
    STRING_FIELD(contextId)
    INT64_FIELD(skip)
    INT64_FIELD(limit)
    STRING_FIELD(sortOrder)
    STRING_FIELD(lastId)
    STRING_FIELD(type)
TYPE_END

ENDPOINT_SERVER_TYPE(StoreListResult)
    LIST_FIELD(stores, Store)
    INT64_FIELD(count)
TYPE_END

ENDPOINT_SERVER_TYPE(StoreMetaThumb)
    INT64_FIELD(size)         // size: number;
TYPE_END


ENDPOINT_SERVER_TYPE(StoreFileCreateModel)
    STRING_FIELD(storeId)     
    STRING_FIELD(requestId)        // request.RequestId
    INT64_FIELD(fileIndex)
    VAR_FIELD(meta)        // meta: unknown
    STRING_FIELD(keyId)
    INT64_FIELD(thumbIndex)
TYPE_END

ENDPOINT_SERVER_TYPE(StoreFileCreateResult)
    STRING_FIELD(fileId)
TYPE_END

ENDPOINT_SERVER_TYPE(StoreFileReadModel)
    STRING_FIELD(fileId)
    OBJECT_FIELD(range, BufferReadRange)
    INT64_FIELD(version)
    BOOL_FIELD(thumb)
TYPE_END

ENDPOINT_SERVER_TYPE(StoreFileReadResult)
    BINARYSTRING_FIELD(data)
TYPE_END

ENDPOINT_SERVER_TYPE(StoreFileWriteModel)
    STRING_FIELD(fileId)     
    STRING_FIELD(requestId)
    INT64_FIELD(fileIndex)
    VAR_FIELD(meta) // meta: unknown
    STRING_FIELD(keyId)
    INT64_FIELD(thumbIndex)
TYPE_END

ENDPOINT_SERVER_TYPE(StoreFileUpdateModel)
    STRING_FIELD(fileId)     
    VAR_FIELD(meta) // meta: unknown
    STRING_FIELD(keyId)
TYPE_END

ENDPOINT_SERVER_TYPE(StoreFileDeleteModel)
    STRING_FIELD(fileId)
TYPE_END

ENDPOINT_SERVER_TYPE(FileDefinition)
    INT64_FIELD(size)
    INT64_FIELD(checksumSize)
TYPE_END

ENDPOINT_SERVER_TYPE(CreateRequestModel)
    LIST_FIELD(files, FileDefinition)
TYPE_END

ENDPOINT_SERVER_TYPE(CreateRequestResult)
    STRING_FIELD(id)
TYPE_END

ENDPOINT_SERVER_TYPE(ChunkModel)
    STRING_FIELD(requestId)
    INT64_FIELD(fileIndex)
    INT64_FIELD(seq)
    BINARYSTRING_FIELD(data)
TYPE_END

ENDPOINT_SERVER_TYPE(CommitFileModel)
    STRING_FIELD(requestId)
    INT64_FIELD(fileIndex)
    INT64_FIELD(seq)
    BINARYSTRING_FIELD(checksum)
TYPE_END

ENDPOINT_SERVER_TYPE(FileSizeResult)
    INT64_FIELD(size)
    INT64_FIELD(checksumSize)
TYPE_END

ENDPOINT_SERVER_TYPE(PrepareChunkRespond)
    STRING_FIELD(hmac)
    STRING_FIELD(cipher)
TYPE_END

ENDPOINT_SERVER_TYPE(StoreDeletedEventData)
    STRING_FIELD(storeId)
    STRING_FIELD(type)
TYPE_END

ENDPOINT_SERVER_TYPE(StoreStatsChangedEventData)
    STRING_FIELD(id)
    STRING_FIELD(contextId)
    INT64_FIELD(lastFileDate)
    INT64_FIELD(files)
    STRING_FIELD(type)
TYPE_END

ENDPOINT_SERVER_TYPE(StoreFileDeletedEventData)
    STRING_FIELD(id)
    STRING_FIELD(contextId)
    STRING_FIELD(storeId)
TYPE_END

} // server
} // store
} // endpoint
} // privmx

#endif // _PRIVMXLIB_ENDPOINT_STORE_SERVERTYPES_HPP_
