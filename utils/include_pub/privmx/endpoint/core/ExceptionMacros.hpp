/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

// Deliberately has no include guard: every header that declares exceptions includes it, declares its
// classes, then undefines both macros so they never leak. Re-including must redefine them.

#include "privmx/endpoint/core/Exception.hpp"

#define DECLARE_SCOPE_ENDPOINT_EXCEPTION(NAME, MSG, SCOPE, CODE, ...)                                                  \
    class NAME : public privmx::endpoint::core::Exception {                                                            \
    public:                                                                                                            \
        static constexpr unsigned int SCOPE_CODE = (CODE);                                                             \
        NAME() : privmx::endpoint::core::Exception(MSG, #NAME, SCOPE, (CODE << 16)) {}                                 \
        NAME(std::string description)                                                                                  \
            : privmx::endpoint::core::Exception(MSG, #NAME, SCOPE, (CODE << 16), std::move(description)) {}            \
        NAME(std::string description, unsigned int code)                                                               \
            : privmx::endpoint::core::Exception(MSG, #NAME, SCOPE, (CODE << 16) | code, std::move(description)) {}     \
        NAME(const privmx::endpoint::core::Exception& cause)                                                           \
            : privmx::endpoint::core::Exception(MSG, #NAME, SCOPE, (CODE << 16), std::string(), cause) {}              \
        NAME(std::string description, const privmx::endpoint::core::Exception& cause)                                  \
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
        NAME(std::string msg, std::string_view name, unsigned int code, const privmx::endpoint::core::Exception& cause)\
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
            const privmx::endpoint::core::Exception& cause                                                             \
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
        NAME(const privmx::endpoint::core::Exception& cause)                                                           \
            : BASE_SCOPED(MSG, #NAME, CODE, std::string(), cause) {}                                                   \
        NAME(std::string new_of_description, const privmx::endpoint::core::Exception& cause)                           \
            : BASE_SCOPED(MSG, #NAME, CODE, std::move(new_of_description), cause) {}                                   \
        void rethrow() const override;                                                                                 \
    };                                                                                                                 \
    inline void NAME::rethrow() const {                                                                                \
        throw *this;                                                                                                   \
    };
