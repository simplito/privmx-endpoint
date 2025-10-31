#ifndef _PRIVMXLIB_ENDPOINT_SEARCH_EXT_EXCEPTION_HPP_
#define _PRIVMXLIB_ENDPOINT_SEARCH_EXT_EXCEPTION_HPP_


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
namespace search {

#define ENDPOINT_SEARCH_EXCEPTION_CODE 0x000B0000

DECLARE_SCOPE_ENDPOINT_EXCEPTION(EndpointSearchException, "Unknown endpoint search exception", "Search", 0x0003)
DECLARE_ENDPOINT_EXCEPTION(EndpointSearchException, NotInitializedException, "Endpoint not initialized", 0x0001)

} // search
} // endpoint
} // privmx

#undef DECLARE_SCOPE_ENDPOINT_EXCEPTION
#undef DECLARE_ENDPOINT_EXCEPTION

#endif // _PRIVMXLIB_ENDPOINT_SEARCH_EXT_EXCEPTION_HPP_
