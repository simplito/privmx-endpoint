#ifndef _PRIVMXLIB_ENDPOINT_STORE_EXT_EXCEPTION_HPP_
#define _PRIVMXLIB_ENDPOINT_STORE_EXT_EXCEPTION_HPP_

#include "privmx/endpoint/core/Exception.hpp"

#define DECLARE_SCOPE_ENDPOINT_EXCEPTION(NAME, MSG, SCOPE, CODE, ...)                                                  \
    class NAME : public privmx::endpoint::core::Exception {                                                            \
    public:                                                                                                            \
        static constexpr unsigned int SCOPE_CODE = (CODE);                                                             \
        NAME() : privmx::endpoint::core::Exception(MSG, #NAME, SCOPE, (CODE << 16)) {}                                 \
        NAME(const std::string& msg, const std::string& name, unsigned int code)                                       \
            : privmx::endpoint::core::Exception(msg, name, SCOPE, (CODE << 16) | code, std::string()) {}               \
        NAME(const std::string& msg, const std::string& name, unsigned int code, const std::string& description)       \
            : privmx::endpoint::core::Exception(msg, name, SCOPE, (CODE << 16) | code, description) {}                 \
        void rethrow() const override;                                                                                 \
    };                                                                                                                 \
    inline void NAME::rethrow() const {                                                                                \
        throw *this;                                                                                                   \
    };

#define DECLARE_ENDPOINT_EXCEPTION(BASE_SCOPED, NAME, MSG, CODE, ...)                                                  \
    class NAME : public BASE_SCOPED {                                                                                  \
    public:                                                                                                            \
        static constexpr unsigned int FULL_CODE = (BASE_SCOPED::SCOPE_CODE << 16) | (CODE);                            \
        NAME() : BASE_SCOPED(MSG, #NAME, CODE) {}                                                                      \
        NAME(const std::string& new_of_description) : BASE_SCOPED(MSG, #NAME, CODE, new_of_description) {}             \
        void rethrow() const override;                                                                                 \
    };                                                                                                                 \
    inline void NAME::rethrow() const {                                                                                \
        throw *this;                                                                                                   \
    };

namespace privmx {
namespace endpoint {
namespace store {
// clang-format off
#define ENDPOINT_STORE_EXCEPTION_CODE 0x00040000

DECLARE_SCOPE_ENDPOINT_EXCEPTION(EndpointStoreException, "Unknown endpoint store exception", "Store", 0x0004)

#define STORE_EXCEPTIONS(X)                                                                                           \
    X(CannotExtractStoreCreatedEventException, "Cannot extract StoreCreatedEvent", 0x0002)                            \
    X(CannotExtractStoreUpdatedEventException, "Cannot extract StoreUpdatedEvent", 0x0003)                            \
    X(CannotExtractStoreStatsChangedEventException, "Cannot extract StoreStatsChangedEvent", 0x0004)                  \
    X(CannotExtractStoreFileCreatedEventException, "Cannot extract StoreFileCreatedEvent", 0x0005)                    \
    X(CannotExtractStoreFileUpdatedEventException, "Cannot extract StoreFileUpdatedEvent", 0x0006)                    \
    X(CannotExtractStoreFileDeletedEventException, "Cannot extract StoreFileDeletedEvent", 0x0007)                    \
    X(CannotExtractStoreDeletedEventException, "Cannot extract StoreDeletedEvent", 0x000D)                            \
    X(UnsupportedCipherTypeException, "Unsupported cipher type", 0x0009)                                              \
    X(FileChunkInvalidChecksumException, "File chunk invalid checksum", 0x000B)                                       \
    X(FileChunkInvalidCipherChecksumException, "File chunk invalid cipher checksum", 0x000C)                          \
    X(InvalidFileChunkSizeException, "Invalid file chunk size", 0x000E)                                               \
    X(InvalidFileReadHandleException, "Invalid file handle: handle is not FILE_READ_HANDLE", 0x000F)                  \
    X(InvalidFileWriteHandleException, "Invalid file handle: handle is not FILE_WRITE_HANDLE", 0x0010)                \
    X(InvalidFileHandleException, "Invalid file handle: handle does not exist", 0x0011)                               \
    X(FileVersionMismatchHandleClosedException, "File version mismatch, handle closed", 0x0013)                       \
    X(PosOutOfBoundsException, "Pos out of bounds", 0x0014)                                                           \
    X(FileCorruptedException, "File corrupted", 0x0015)                                                               \
    X(NumberToBigForCPUArchitectureException, "Number is to big for this CPU Architecture", 0x0016)                   \
    X(InvalidEncryptedStoreFileMetaVersionException, "Invalid version of encrypted file meta", 0x0019)                \
    X(UnknowStoreFormatException, "Unknown Store format", 0x001C)                                                     \
    X(UnknowFileFormatException, "Unknown File format", 0x001D)                                                       \
    X(FileFetchFailedException, "File fetch failed", 0x001E)                                                          \
    X(FileVersionMismatchException, "File version mismatch", 0x001F)                                                  \
    X(FilePublicDataMismatchException, "File public data mismatch", 0x0021)                                           \
    X(WritingToFileInteruptedWrittenDataSmallerThenDeclaredException, "Writing to file interupted. Written data smaller then declared", 0x0022) \
    X(StoreDataIntegrityException, "Failed Store data integrity check", 0x0027)                                       \
    X(FileDataIntegrityException, "Failed file data integrity check", 0x0028)                                         \
    X(InvalidHashSizeException, "Invalid hash size", 0x0029)                                                          \
    X(HashIndexOutOfBoundsException, "Hash index out of bounds", 0x002A)                                              \
    X(InvalidFileTopHashException, "Invalid file top hash", 0x002B)                                                   \
    X(FileSyncFailedHandleCloseException, "File sync failed, handle closed", 0x002C)                                  \
    X(FileRandomWriteInternalException, "File random write internal Exception ", 0x002D)

#define PRIVMX_STORE_DECLARE(NAME, MSG, CODE) DECLARE_ENDPOINT_EXCEPTION(EndpointStoreException, NAME, MSG, CODE)
STORE_EXCEPTIONS(PRIVMX_STORE_DECLARE)
#undef PRIVMX_STORE_DECLARE

// compile-time guard: codes are collected from the list above, never retyped
#define PRIVMX_STORE_CODE(NAME, MSG, CODE) NAME::FULL_CODE,
static_assert(
    privmx::endpoint::core::exceptionCodesUnique({STORE_EXCEPTIONS(PRIVMX_STORE_CODE)}),
    "Duplicate exception code in store scope"
);
#undef PRIVMX_STORE_CODE
#undef STORE_EXCEPTIONS
// clang-format on

} // namespace store
} // namespace endpoint
} // namespace privmx

#undef DECLARE_SCOPE_ENDPOINT_EXCEPTION
#undef DECLARE_ENDPOINT_EXCEPTION

#endif // _PRIVMXLIB_ENDPOINT_STORE_EXT_EXCEPTION_HPP_
