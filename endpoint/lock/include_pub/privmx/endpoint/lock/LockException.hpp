/*
PrivMX Endpoint.
Copyright © 2026 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_ENDPOINT_LOCK_EXT_EXCEPTION_HPP_
#define _PRIVMXLIB_ENDPOINT_LOCK_EXT_EXCEPTION_HPP_

#include "privmx/endpoint/core/Exception.hpp"

#define DECLARE_SCOPE_ENDPOINT_EXCEPTION(NAME, MSG, SCOPE, CODE, ...)                                                  \
    class NAME : public privmx::endpoint::core::Exception {                                                            \
    public:                                                                                                            \
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
        NAME() : BASE_SCOPED(MSG, #NAME, CODE) {}                                                                      \
        NAME(const std::string& new_of_description) : BASE_SCOPED(MSG, #NAME, CODE, new_of_description) {}             \
        void rethrow() const override;                                                                                 \
    };                                                                                                                 \
    inline void NAME::rethrow() const {                                                                                \
        throw *this;                                                                                                   \
    };

namespace privmx {
namespace endpoint {
namespace lock {
// clang-format off
#define ENDPOINT_LOCK_EXCEPTION_CODE 0x000A0000

DECLARE_SCOPE_ENDPOINT_EXCEPTION(EndpointLockException, "Unknown endpoint lock exception", "Lock", 0x000A)
DECLARE_ENDPOINT_EXCEPTION(EndpointLockException, NotInitializedException, "Endpoint not initialized", 0x0001)
DECLARE_ENDPOINT_EXCEPTION(EndpointLockException, InvalidLockLevelException, "Invalid lock level value", 0x0002)
// clang-format on
} // namespace lock
} // namespace endpoint
} // namespace privmx

#undef DECLARE_SCOPE_ENDPOINT_EXCEPTION
#undef DECLARE_ENDPOINT_EXCEPTION

#endif // _PRIVMXLIB_ENDPOINT_LOCK_EXT_EXCEPTION_HPP_
