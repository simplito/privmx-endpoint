/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_ENDPOINT_INTERFACE_EXCEPTION_HPP_
#define _PRIVMXLIB_ENDPOINT_INTERFACE_EXCEPTION_HPP_

#include "privmx/endpoint/core/Exception.hpp"

#define DECLARE_SCOPE_ENDPOINT_EXCEPTION(NAME, MSG, SCOPE, CODE, ...)                                                  \
    class NAME : public privmx::endpoint::core::Exception {                                                            \
    public:                                                                                                            \
        static constexpr unsigned int SCOPE_CODE = (CODE);                                                             \
        NAME() : privmx::endpoint::core::Exception(MSG, #NAME, SCOPE, (CODE << 16)) {}                                 \
        NAME(std::string description)                                                                                  \
            : privmx::endpoint::core::Exception(MSG, #NAME, SCOPE, (CODE << 16), std::move(description)) {}            \
        NAME(const Exception& cause)                                                                                   \
            : privmx::endpoint::core::Exception(MSG, #NAME, SCOPE, (CODE << 16), std::string(), cause) {}              \
        NAME(std::string description, const Exception& cause)                                                          \
            : privmx::endpoint::core::Exception(MSG, #NAME, SCOPE, (CODE << 16), std::move(description), cause) {}     \
        NAME(std::string msg, std::string_view name, unsigned int code)                                                \
            : privmx::endpoint::core::Exception(std::move(msg), name, SCOPE, (CODE << 16) | code, std::string()) {}    \
        NAME(std::string msg, std::string_view name, unsigned int code, std::string description)                       \
            : privmx::endpoint::core::Exception(                                                                       \
                  std::move(msg),                                                                                      \
                  name,                                                                                                \
                  SCOPE,                                                                                               \
                  (CODE << 16) | code,                                                                                 \
                  std::move(description)                                                                               \
              ) {}                                                                                                     \
        NAME(std::string msg, std::string_view name, unsigned int code, const Exception& cause)                        \
            : privmx::endpoint::core::Exception(                                                                       \
                  std::move(msg),                                                                                      \
                  name,                                                                                                \
                  SCOPE,                                                                                               \
                  (CODE << 16) | code,                                                                                 \
                  std::string(),                                                                                       \
                  cause                                                                                                \
              ) {}                                                                                                     \
        NAME(                                                                                                          \
            std::string msg,                                                                                           \
            std::string_view name,                                                                                     \
            unsigned int code,                                                                                         \
            std::string description,                                                                                   \
            const Exception& cause                                                                                     \
        )                                                                                                              \
            : privmx::endpoint::core::Exception(                                                                       \
                  std::move(msg),                                                                                      \
                  name,                                                                                                \
                  SCOPE,                                                                                               \
                  (CODE << 16) | code,                                                                                 \
                  std::move(description),                                                                              \
                  cause                                                                                                \
              ) {}                                                                                                     \
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
        NAME(std::string new_of_description) : BASE_SCOPED(MSG, #NAME, CODE, std::move(new_of_description)) {}         \
        NAME(const Exception& cause)                                                                                   \
            : BASE_SCOPED(MSG, #NAME, CODE, std::string(), cause) {}                                                   \
        NAME(std::string new_of_description, const Exception& cause)                                                   \
            : BASE_SCOPED(MSG, #NAME, CODE, std::move(new_of_description), cause) {}                                   \
        void rethrow() const override;                                                                                 \
    };                                                                                                                 \
    inline void NAME::rethrow() const {                                                                                \
        throw *this;                                                                                                   \
    };
namespace privmx {
namespace endpoint {
namespace cinterface { // confliceted name interface in Windows

#define ENDPOINT_INTERFACE_EXCEPTION_CODE 0x00050000

DECLARE_SCOPE_ENDPOINT_EXCEPTION(
    EndpointInterfaceException,
    "Unknown endpoint interface exception",
    "Interface",
    0x0005
)
DECLARE_ENDPOINT_EXCEPTION(EndpointInterfaceException, UncaughtException, "Uncaught exception in C interface", 0x0002)

static_assert(
    ::privmx::endpoint::core::exceptionCodesUnique({
        UncaughtException::FULL_CODE,
    }),
    "Duplicate exception code in cinterface scope"
);
} // namespace cinterface
} // namespace endpoint
} // namespace privmx

#undef DECLARE_SCOPE_ENDPOINT_EXCEPTION
#undef DECLARE_ENDPOINT_EXCEPTION

#endif // _PRIVMXLIB_ENDPOINT_INTERFACE_EXCEPTION_HPP_
