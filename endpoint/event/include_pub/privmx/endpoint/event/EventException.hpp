#ifndef _PRIVMXLIB_ENDPOINT_EVENT_EXT_EXCEPTION_HPP_
#define _PRIVMXLIB_ENDPOINT_EVENT_EXT_EXCEPTION_HPP_

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
namespace event {
// clang-format off
#define ENDPOINT_EVENT_EXCEPTION_CODE 0x00090000

DECLARE_SCOPE_ENDPOINT_EXCEPTION(EndpointEventException, "Unknown endpoint event exception", "Event", 0x0009)

#define EVENT_EXCEPTIONS(X)                                                                                            \
    X(ForbiddenChannelNameException, "Forbidden channel name", 0x0002)                                                 \
    X(CannotExtractContextCustomEvent, "Cannot extract ContextCustomEvent", 0x0003)                                    \
    X(InvalidEncryptedEventDataVersionException, "Invalid version of encrypted event data", 0x0005)

#define PRIVMX_EVENT_DECLARE(NAME, MSG, CODE) DECLARE_ENDPOINT_EXCEPTION(EndpointEventException, NAME, MSG, CODE)
EVENT_EXCEPTIONS(PRIVMX_EVENT_DECLARE)
#undef PRIVMX_EVENT_DECLARE

// compile-time guard: codes are collected from the list above, never retyped
#define PRIVMX_EVENT_CODE(NAME, MSG, CODE) NAME::FULL_CODE,
static_assert(
    privmx::endpoint::core::exceptionCodesUnique({EVENT_EXCEPTIONS(PRIVMX_EVENT_CODE)}),
    "Duplicate exception code in event scope"
);
#undef PRIVMX_EVENT_CODE
#undef EVENT_EXCEPTIONS
// clang-format on
} // namespace event
} // namespace endpoint
} // namespace privmx

#undef DECLARE_SCOPE_ENDPOINT_EXCEPTION
#undef DECLARE_ENDPOINT_EXCEPTION

#endif // _PRIVMXLIB_ENDPOINT_EVENT_EXT_EXCEPTION_HPP_
