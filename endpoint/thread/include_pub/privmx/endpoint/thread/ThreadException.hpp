#ifndef _PRIVMXLIB_ENDPOINT_THREAD_EXT_EXCEPTION_HPP_
#define _PRIVMXLIB_ENDPOINT_THREAD_EXT_EXCEPTION_HPP_

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
namespace thread {
// clang-format off
#define ENDPOINT_THREAD_EXCEPTION_CODE 0x00030000

DECLARE_SCOPE_ENDPOINT_EXCEPTION(EndpointThreadException, "Unknown endpoint thread exception", "Thread", 0x0003)

#define THREAD_EXCEPTIONS(X)                                                                                           \
    X(CannotExtractThreadCreatedEventException, "Cannot extract ThreadCreatedEvent", 0x0002)                           \
    X(CannotExtractThreadUpdatedEventException, "Cannot extract ThreadUpdatedEvent", 0x0003)                           \
    X(CannotExtractThreadNewMessageEventException, "Cannot extract ThreadNewMessageEvent", 0x0004)                     \
    X(CannotExtractThreadDeletedEventException, "Cannot extract ThreadDeletedEvent", 0x0005)                           \
    X(CannotExtractThreadDeletedMessageEventException, "Cannot extract ThreadDeletedMessageEvent", 0x0006)             \
    X(CannotExtractThreadStatsEventException, "Cannot extract ThreadStatsEvent", 0x0008)                               \
    X(InvalidEncryptedMessageDataVersionException, "Invalid version of encrypted message data", 0x000C)                \
    X(UnknowThreadFormatException, "Unknown Thread format", 0x000D)                                                    \
    X(UnknowMessageFormatException, "Unknown Message format", 0x000E)                                                  \
    X(CannotExtractThreadMessageUpdatedEventException, "Cannot extract ThreadMessageUpdatedEvent", 0x000F)             \
    X(MessagePublicDataMismatchException, "Message public data mismatch", 0x0011)                                      \
    X(ThreadDataIntegrityException, "Failed thread data integrity check", 0x0014)                                      \
    X(MessageDataIntegrityException, "Failed message data integrity check", 0x0015)                                     \
    X(UnresolvedGroupGranteeException, "Cannot resolve current key of a Thread's grantee group", 0x0016)

#define PRIVMX_THREAD_DECLARE(NAME, MSG, CODE) DECLARE_ENDPOINT_EXCEPTION(EndpointThreadException, NAME, MSG, CODE)
THREAD_EXCEPTIONS(PRIVMX_THREAD_DECLARE)
#undef PRIVMX_THREAD_DECLARE

// compile-time guard: codes are collected from the list above, never retyped
#define PRIVMX_THREAD_CODE(NAME, MSG, CODE) NAME::FULL_CODE,
static_assert(
    privmx::endpoint::core::exceptionCodesUnique({THREAD_EXCEPTIONS(PRIVMX_THREAD_CODE)}),
    "Duplicate exception code in thread scope"
);
#undef PRIVMX_THREAD_CODE
#undef THREAD_EXCEPTIONS
// clang-format on

} // namespace thread
} // namespace endpoint
} // namespace privmx

#undef DECLARE_SCOPE_ENDPOINT_EXCEPTION
#undef DECLARE_ENDPOINT_EXCEPTION

#endif // _PRIVMXLIB_ENDPOINT_THREAD_EXT_EXCEPTION_HPP_