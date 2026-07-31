#ifndef _PRIVMXLIB_ENDPOINT_INBOX_EXT_EXCEPTION_HPP_
#define _PRIVMXLIB_ENDPOINT_INBOX_EXT_EXCEPTION_HPP_

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
namespace inbox {
// clang-format off
#define ENDPOINT_INBOX_EXCEPTION_CODE 0x00070000

DECLARE_SCOPE_ENDPOINT_EXCEPTION(EndpointInboxException, "Unknown endpoint inbox exception", "Inbox", 0x0007)

#define INBOX_EXCEPTIONS(X)                                                                                           \
    X(UnknownInboxHandleException, "Unknown inbox handle Id", 0x0002)                                                 \
    X(InboxHandleIsNotTiedToInboxFileHandleException, "inboxHandle is not tied to inboxFileHandle", 0x0003)           \
    X(CannotExtractInboxCreatedEventException, "Cannot extract InboxCreatedEvent", 0x0004)                            \
    X(CannotExtractInboxUpdatedEventException, "Cannot extract InboxUpdatedEvent", 0x0005)                            \
    X(CannotExtractInboxDeletedEventException, "Cannot extract InboxDeletedEvent", 0x0006)                            \
    X(FailedToExtractMessagePublicMetaException, "Failed to extract message public meta", 0x0009)                     \
    X(InvalidEncryptedInboxDataVersionException, "Invalid version of encrypted Inbox data", 0x000F)                   \
    X(CannotExtractInboxEntryCreatedEventException, "Cannot extract InboxEntryCreatedEvent", 0x0010)                  \
    X(CannotExtractInboxEntryDeletedException, "Cannot extract InboxEntryDeleted", 0x0011)                            \
    X(InboxPublicDataMismatchException, "Inbox public data mismatch", 0x0013)                                         \
    X(WritingToEntryInteruptedWrittenDataSmallerThenDeclaredException, "Writing to entry interupted. Written data smaller then declared", 0x0014) \
    X(HandleIsUsedInInboxHandleException, "Handle is used in inbox handle", 0x0015)                                   \
    X(UnknownInboxFormatException, "Unknown Inbox format", 0x0020)                                                    \
    X(InboxDataIntegrityException, "Failed inbox data integrity check", 0x0021)                                       \
    X(InboxModuleDoesNotSupportQueriesYetException, "Inbox module does not support queries yet.", 0x0099)

#define PRIVMX_INBOX_DECLARE(NAME, MSG, CODE) DECLARE_ENDPOINT_EXCEPTION(EndpointInboxException, NAME, MSG, CODE)
INBOX_EXCEPTIONS(PRIVMX_INBOX_DECLARE)
#undef PRIVMX_INBOX_DECLARE

// compile-time guard: codes are collected from the list above, never retyped
#define PRIVMX_INBOX_CODE(NAME, MSG, CODE) NAME::FULL_CODE,
static_assert(
    privmx::endpoint::core::exceptionCodesUnique({INBOX_EXCEPTIONS(PRIVMX_INBOX_CODE)}),
    "Duplicate exception code in inbox scope"
);
#undef PRIVMX_INBOX_CODE
#undef INBOX_EXCEPTIONS
// clang-format on
} // namespace inbox
} // namespace endpoint
} // namespace privmx

#undef DECLARE_SCOPE_ENDPOINT_EXCEPTION
#undef DECLARE_ENDPOINT_EXCEPTION

#endif // _PRIVMXLIB_ENDPOINT_INBOX_EXT_EXCEPTION_HPP_
