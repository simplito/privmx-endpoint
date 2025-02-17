#ifndef _PRIVMXLIB_ENDPOINT_EVENT_EXT_EXCEPTION_HPP_
#define _PRIVMXLIB_ENDPOINT_EVENT_EXT_EXCEPTION_HPP_


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
namespace event {

#define ENDPOINT_THREAD_EXCEPTION_CODE 0x00090000

DECLARE_SCOPE_ENDPOINT_EXCEPTION(EndpointEventException, "Unknown endpoint event exception", "Event", 0x0009)
DECLARE_ENDPOINT_EXCEPTION(EndpointEventException, NotInitializedException, "Endpoint not initialized", 0x0001)
DECLARE_ENDPOINT_EXCEPTION(EndpointEventException, UnallowedChannelNameException, "Unallowed channel name", 0x0002)
DECLARE_ENDPOINT_EXCEPTION(EndpointEventException, CannotExtractContextCustomEvent, "Cannot extract ContextCustomEvent", 0x0003)
DECLARE_ENDPOINT_EXCEPTION(EndpointEventException, NotSubscribedException, "Not subscribed", 0x0004)
DECLARE_ENDPOINT_EXCEPTION(EndpointEventException, AlreadySubscribedException, "Already subscribed", 0x0005)

} // event
} // endpoint
} // privmx

#undef DECLARE_SCOPE_ENDPOINT_EXCEPTION
#undef DECLARE_ENDPOINT_EXCEPTION

#endif // _PRIVMXLIB_ENDPOINT_THREAD_EXT_EXCEPTION_HPP_