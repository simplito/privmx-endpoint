#ifndef _PRIVMXLIB_ENDPOINT_THREAD_EXT_EXCEPTION_HPP_
#define _PRIVMXLIB_ENDPOINT_THREAD_EXT_EXCEPTION_HPP_


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
namespace thread {

#define ENDPOINT_THREAD_EXCEPTION_CODE 0x00030000

DECLARE_SCOPE_ENDPOINT_EXCEPTION(EndpointThreadException, "Unknown endpoint thread exception", "Thread", 0x0003)
DECLARE_ENDPOINT_EXCEPTION(EndpointThreadException, NotInitializedException, "Endpoint not initialized", 0x0001)
DECLARE_ENDPOINT_EXCEPTION(EndpointThreadException, CannotExtractThreadCreatedEventException, "Cannot extract ThreadCreatedEvent", 0x0002)
DECLARE_ENDPOINT_EXCEPTION(EndpointThreadException, CannotExtractThreadUpdatedEventException, "Cannot extract ThreadUpdatedEvent", 0x0003)
DECLARE_ENDPOINT_EXCEPTION(EndpointThreadException, CannotExtractThreadNewMessageEventException, "Cannot extract ThreadNewMessageEvent", 0x0004)
DECLARE_ENDPOINT_EXCEPTION(EndpointThreadException, CannotExtractThreadDeletedEventException, "Cannot extract ThreadDeletedEvent", 0x0005)
DECLARE_ENDPOINT_EXCEPTION(EndpointThreadException, CannotExtractThreadDeletedMessageEventException, "Cannot extract ThreadDeletedMessageEvent", 0x0006)
DECLARE_ENDPOINT_EXCEPTION(EndpointThreadException, IncorrectKeyIdFormatException, "Incorrect key id format", 0x0007)
DECLARE_ENDPOINT_EXCEPTION(EndpointThreadException, CannotExtractThreadStatsEventException, "Cannot extract ThreadStatsEvent", 0x0008)
DECLARE_ENDPOINT_EXCEPTION(EndpointThreadException, AlreadySubscribedException, "Already subscribed", 0x0009)
DECLARE_ENDPOINT_EXCEPTION(EndpointThreadException, NotSubscribedException, "Cannot unsubscribe if not subscribed", 0x000A)
DECLARE_ENDPOINT_EXCEPTION(EndpointThreadException, InvalidEncryptedThreadDataVersionException, "Invalid version of encrypted thread data", 0x000B)
DECLARE_ENDPOINT_EXCEPTION(EndpointThreadException, InvalidEncryptedMessageDataVersionException, "Invalid version of encrypted message data", 0x000C)
DECLARE_ENDPOINT_EXCEPTION(EndpointThreadException, UnknowThreadFormatException, "Unknown Thread format", 0x000D)
DECLARE_ENDPOINT_EXCEPTION(EndpointThreadException, UnknowMessageFormatException, "Unknown Message format", 0x000E)
DECLARE_ENDPOINT_EXCEPTION(EndpointThreadException, CannotExtractThreadMessageUpdatedEventException, "Cannot extract ThreadMessageUpdatedEvent", 0x000F)
DECLARE_ENDPOINT_EXCEPTION(EndpointThreadException, ThreadPublicDataMismatchException, "Thread public data mismatch", 0x0010)
DECLARE_ENDPOINT_EXCEPTION(EndpointThreadException, MessagePublicDataMismatchException, "Message public data mismatch", 0x0011)
DECLARE_ENDPOINT_EXCEPTION(EndpointThreadException, CannotExtractThreadCustomEventException, "Cannot extract ThreadCustomEvent", 0x0013)
DECLARE_ENDPOINT_EXCEPTION(EndpointThreadException, ForbiddenChannelNameException, "Forbidden channel name", 0x0014)
DECLARE_ENDPOINT_EXCEPTION(EndpointThreadException, ThreadDataIntegrityException, "Failed thread data integrity check", 0x0015)

} // thread
} // endpoint
} // privmx

#undef DECLARE_SCOPE_ENDPOINT_EXCEPTION
#undef DECLARE_ENDPOINT_EXCEPTION

#endif // _PRIVMXLIB_ENDPOINT_THREAD_EXT_EXCEPTION_HPP_