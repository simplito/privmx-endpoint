#ifndef _PRIVMXLIB_ENDPOINT_STORE_EXT_EXCEPTION_HPP_
#define _PRIVMXLIB_ENDPOINT_STORE_EXT_EXCEPTION_HPP_

#include "privmx/endpoint/core/Exception.hpp"

#define DECLARE_SCOPE_ENDPOINT_EXCEPTION(NAME, MSG, SCOPE, CODE, ...)                                            \
    class NAME : public privmx::endpoint::core::Exception {                                                      \
    public:                                                                                                      \
        NAME() : privmx::endpoint::core::Exception(MSG, #NAME, SCOPE, (CODE << 16)) {}                           \
        NAME(const std::string& msg, const std::string& name, unsigned int code)                                 \
            : privmx::endpoint::core::Exception(msg, name, SCOPE, (CODE << 16) | code, std::string()) {}         \
        NAME(const std::string& msg, const std::string& name, unsigned int code, const std::string& description) \
            : privmx::endpoint::core::Exception(msg, name, SCOPE, (CODE << 16) | code, description) {}           \
        void rethrow() const override;                                                                           \
    };                                                                                                           \
    inline void NAME::rethrow() const {                                                                          \
        throw *this;                                                                                             \
    };

#define DECLARE_ENDPOINT_EXCEPTION(BASE_SCOPED, NAME, MSG, CODE, ...)                                            \
    class NAME : public BASE_SCOPED {                                                                            \
    public:                                                                                                      \
        NAME() : BASE_SCOPED(MSG, #NAME, CODE) {}                                                                \
        NAME(const std::string& new_of_description) : BASE_SCOPED(MSG, #NAME, CODE, new_of_description) {}       \
        void rethrow() const override;                                                                           \
    };                                                                                                           \
    inline void NAME::rethrow() const {                                                                          \
        throw *this;                                                                                             \
    };

namespace privmx {
namespace endpoint {
namespace store {

#define ENDPOINT_STORE_EXCEPTION_CODE 0x00040000

DECLARE_SCOPE_ENDPOINT_EXCEPTION(EndpointStoreException, "Unknown endpoint store exception", "Store", 0x0004)
DECLARE_ENDPOINT_EXCEPTION(EndpointStoreException, NotInitializedException, "Endpoint not initialized", 0x0001)
DECLARE_ENDPOINT_EXCEPTION(EndpointStoreException, CannotExtractStoreCreatedEventException, "Cannot extract StoreCreatedEvent", 0x0002)
DECLARE_ENDPOINT_EXCEPTION(EndpointStoreException, CannotExtractStoreUpdatedEventException, "Cannot extract StoreUpdatedEvent", 0x0003)
DECLARE_ENDPOINT_EXCEPTION(EndpointStoreException, CannotExtractStoreStatsChangedEventException, "Cannot extract StoreStatsChangedEvent", 0x0004)
DECLARE_ENDPOINT_EXCEPTION(EndpointStoreException, CannotExtractStoreFileCreatedEventException, "Cannot extract StoreFileCreatedEvent", 0x0005)
DECLARE_ENDPOINT_EXCEPTION(EndpointStoreException, CannotExtractStoreFileUpdatedEventException, "Cannot extract StoreFileUpdatedEvent", 0x0006)
DECLARE_ENDPOINT_EXCEPTION(EndpointStoreException, CannotExtractStoreFileDeletedEventException, "Cannot extract StoreFileDeletedEvent", 0x0007)
DECLARE_ENDPOINT_EXCEPTION(EndpointStoreException, CannotExtractStoreDeletedEventException, "Cannot extract StoreDeletedEvent", 0x000D)

DECLARE_ENDPOINT_EXCEPTION(EndpointStoreException, UnsupportedCipherTypeException, "Unsupported cipher type", 0x0009)
DECLARE_ENDPOINT_EXCEPTION(EndpointStoreException, FileInvalidChecksumException, "File invalid checksum", 0x000A)
DECLARE_ENDPOINT_EXCEPTION(EndpointStoreException, FileChunkInvalidChecksumException, "File chunk invalid checksum", 0x000B)
DECLARE_ENDPOINT_EXCEPTION(EndpointStoreException, FileChunkInvalidCipherChecksumException, "File chunk invalid cipher checksum", 0x000C)
DECLARE_ENDPOINT_EXCEPTION(EndpointStoreException, InvalidFileChunkSizeException, "Invalid file chunk size", 0x000E)
DECLARE_ENDPOINT_EXCEPTION(EndpointStoreException, InvalidFileReadHandleException, "Invalid file handle: handle is not FILE_READ_HANDLE", 0x000F)
DECLARE_ENDPOINT_EXCEPTION(EndpointStoreException, InvalidFileWriteHandleException, "Invalid file handle: handle is not FILE_WRITE_HANDLE", 0x0010)
DECLARE_ENDPOINT_EXCEPTION(EndpointStoreException, InvalidFileHandleException, "Invalid file handle: handle does not exist", 0x0011)
DECLARE_ENDPOINT_EXCEPTION(EndpointStoreException, IncorrectKeyIdFormatException, "Incorrect key id format", 0x0012)
DECLARE_ENDPOINT_EXCEPTION(EndpointStoreException, FileVersionMismatchHandleClosedException, "File version mismatch, handle closed", 0x0013)
DECLARE_ENDPOINT_EXCEPTION(EndpointStoreException, PosOutOfBoundsException, "Pos out of bounds", 0x0014)
DECLARE_ENDPOINT_EXCEPTION(EndpointStoreException, FileCorruptedException, "File corrupted", 0x0015)
DECLARE_ENDPOINT_EXCEPTION(EndpointStoreException, NumberToBigForCPUArchitectureException, "Number is to big for this CPU Architecture", 0x0016)
DECLARE_ENDPOINT_EXCEPTION(EndpointStoreException, AlreadySubscribedException, "Already subscribed", 0x0017)
DECLARE_ENDPOINT_EXCEPTION(EndpointStoreException, NotSubscribedException, "Cannot unsubscribe if not subscribed", 0x0018)
DECLARE_ENDPOINT_EXCEPTION(EndpointStoreException, InvalidEncryptedStoreFileMetaVersionException, "Invalid version of encrypted file meta", 0x0019)
DECLARE_ENDPOINT_EXCEPTION(EndpointStoreException, InvalidEncryptedStoreDataVersionException, "Invalid version of encrypted store data", 0x001A)
DECLARE_ENDPOINT_EXCEPTION(EndpointStoreException, NotImplementedException, "Not Implemented", 0x001B)
DECLARE_ENDPOINT_EXCEPTION(EndpointStoreException, UnknowStoreFormatException, "Unknown Store format", 0x001C)
DECLARE_ENDPOINT_EXCEPTION(EndpointStoreException, UnknowFileFormatException, "Unknown File format", 0x001D)
DECLARE_ENDPOINT_EXCEPTION(EndpointStoreException, FileFetchFailedException, "File fetch failed", 0x001E)
DECLARE_ENDPOINT_EXCEPTION(EndpointStoreException, FileVersionMismatchException, "File version mismatch", 0x001F)
DECLARE_ENDPOINT_EXCEPTION(EndpointStoreException, StorePublicDataMismatchException, "Store public data mismatch", 0x0020)
DECLARE_ENDPOINT_EXCEPTION(EndpointStoreException, FilePublicDataMismatchException, "File public data mismatch", 0x0021)
DECLARE_ENDPOINT_EXCEPTION(EndpointStoreException, WritingToFileInteruptedWrittenDataSmallerThenDeclaredException, "Writing to file interupted. Written data smaller then declared", 0x0022)
DECLARE_ENDPOINT_EXCEPTION(EndpointStoreException, FileDecryptionFailedException, "FileDecryptionFailed", 0x0023)
DECLARE_ENDPOINT_EXCEPTION(EndpointStoreException, StoreEncryptionKeyValidationException, "Failed Store encryption key validation", 0x0026)
DECLARE_ENDPOINT_EXCEPTION(EndpointStoreException, StoreDataIntegrityException, "Failed Store data integrity check", 0x0027)
DECLARE_ENDPOINT_EXCEPTION(EndpointStoreException, FileDataIntegrityException, "Failed file data integrity check", 0x0028)
// ------------------------------ Random/Write ------------------------------
DECLARE_ENDPOINT_EXCEPTION(EndpointStoreException, InvalidHashSizeException, "InvalidHashSize", 0x0029)
DECLARE_ENDPOINT_EXCEPTION(EndpointStoreException, HashIndexOutOfBoundsException, "Hash index out of bounds", 0x0029)
DECLARE_ENDPOINT_EXCEPTION(EndpointStoreException, FileRandomWriteInternalException, "File random write internal Exception ", 0x00FF)


} // store
} // endpoint
} // privmx

#undef DECLARE_SCOPE_ENDPOINT_EXCEPTION
#undef DECLARE_ENDPOINT_EXCEPTION

#endif // _PRIVMXLIB_ENDPOINT_STORE_EXT_EXCEPTION_HPP_