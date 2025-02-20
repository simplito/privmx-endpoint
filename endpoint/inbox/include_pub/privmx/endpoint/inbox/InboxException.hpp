#ifndef _PRIVMXLIB_ENDPOINT_INBOX_EXT_EXCEPTION_HPP_
#define _PRIVMXLIB_ENDPOINT_INBOX_EXT_EXCEPTION_HPP_

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
namespace inbox {

#define ENDPOINT_INBOX_EXCEPTION_CODE 0x00070000

DECLARE_SCOPE_ENDPOINT_EXCEPTION(EndpointInboxException, "Unknown endpoint inbox exception", "Inbox", 0x0007)
DECLARE_ENDPOINT_EXCEPTION(EndpointInboxException, NotInitializedException, "Endpoint not initialized", 0x0001)
DECLARE_ENDPOINT_EXCEPTION(EndpointInboxException, UnknownInboxHandleException, "Unknown inbox handle Id", 0x0002)
DECLARE_ENDPOINT_EXCEPTION(EndpointInboxException, InboxHandleIsNotTiedToInboxFileHandleException, "inboxHandle is not tied to inboxFileHandle", 0x0003)
DECLARE_ENDPOINT_EXCEPTION(EndpointInboxException, CannotExtractInboxCreatedEventException, "Cannot extract InboxCreatedEvent", 0x0004)
DECLARE_ENDPOINT_EXCEPTION(EndpointInboxException, CannotExtractInboxUpdatedEventException, "Cannot extract InboxUpdatedEvent", 0x0005)
DECLARE_ENDPOINT_EXCEPTION(EndpointInboxException, CannotExtractInboxDeletedEventException, "Cannot extract InboxDeletedEvent", 0x0006)
DECLARE_ENDPOINT_EXCEPTION(EndpointInboxException, IncorrectKeyIdFormatException, "Incorrect key id format", 0x0007)
DECLARE_ENDPOINT_EXCEPTION(EndpointInboxException, FailedToDecryptFileMetaException, "Failed to decrypt file meta", 0x0008)
DECLARE_ENDPOINT_EXCEPTION(EndpointInboxException, FailedToExtractMessagePublicMetaException, "Failed to extract message public meta", 0x0009)
DECLARE_ENDPOINT_EXCEPTION(EndpointInboxException, FileVersionMismatchHandleClosedException, "File version mismatch, handle closed", 0x000A)
DECLARE_ENDPOINT_EXCEPTION(EndpointInboxException, PosOutOfBoundsException, "Pos out of bounds", 0x000B)
DECLARE_ENDPOINT_EXCEPTION(EndpointInboxException, NumberToBigForCPUArchitectureException, "ChunkSize bigger then size_t", 0x000C)
DECLARE_ENDPOINT_EXCEPTION(EndpointInboxException, AlreadySubscribedException, "Already subscribed", 0x000D)
DECLARE_ENDPOINT_EXCEPTION(EndpointInboxException, NotSubscribedException, "Cannot unsubscribe if not subscribed", 0x000E)
DECLARE_ENDPOINT_EXCEPTION(EndpointInboxException, InvalidEncryptedInboxDataVersionException, "Invalid version of encrypted Inbox data", 0x000F)
DECLARE_ENDPOINT_EXCEPTION(EndpointInboxException, CannotExtractInboxEntryCreatedEventException, "Cannot extract InboxEntryCreatedEvent", 0x0010)
DECLARE_ENDPOINT_EXCEPTION(EndpointInboxException, CannotExtractInboxEntryDeletedException, "Cannot extract InboxEntryDeleted", 0x0011)
DECLARE_ENDPOINT_EXCEPTION(EndpointInboxException, FileFetchFailedException, "File fetch failed", 0x0012)
DECLARE_ENDPOINT_EXCEPTION(EndpointInboxException, InboxPublicDataMismatchException, "Inbox public data mismatch", 0x0013)
DECLARE_ENDPOINT_EXCEPTION(EndpointInboxException, WritingToEntryInteruptedWrittenDataSmallerThenDeclaredException, "Writing to entry interupted. Written data smaller then declared", 0x0014)
DECLARE_ENDPOINT_EXCEPTION(EndpointInboxException, HandleIsUsedInInboxHandleException, "Handle is used in inbox handle", 0x0015)
DECLARE_ENDPOINT_EXCEPTION(EndpointInboxException, InvalidFileReadHandleException, "Invalid file handle: handle is not FILE_READ_HANDLE", 0x0016)
DECLARE_ENDPOINT_EXCEPTION(EndpointInboxException, InvalidFileWriteHandleException, "Invalid file handle: handle is not FILE_WRITE_HANDLE", 0x0017)
DECLARE_ENDPOINT_EXCEPTION(EndpointInboxException, CannotExtractInboxCustomEventException, "Cannot extract InboxCustomEvent", 0x0018)
DECLARE_ENDPOINT_EXCEPTION(EndpointInboxException, ForbiddenChannelNameException, "Forbidden channel name", 0x0019)
DECLARE_ENDPOINT_EXCEPTION(EndpointInboxException, InboxModuleDoesNotSupportQueriesYetException, "Inbox module does not support queries yet.", 0x0099)


} // store
} // endpoint
} // privmx

#undef DECLARE_SCOPE_ENDPOINT_EXCEPTION
#undef DECLARE_ENDPOINT_EXCEPTION

#endif // _PRIVMXLIB_ENDPOINT_INBOX_EXT_EXCEPTION_HPP_