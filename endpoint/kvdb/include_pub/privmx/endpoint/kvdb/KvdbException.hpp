#ifndef _PRIVMXLIB_ENDPOINT_KVDB_EXT_EXCEPTION_HPP_
#define _PRIVMXLIB_ENDPOINT_KVDB_EXT_EXCEPTION_HPP_

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
namespace kvdb {
// clang-format off
#define ENDPOINT_KVDB_EXCEPTION_CODE 0x000A0000

DECLARE_SCOPE_ENDPOINT_EXCEPTION(EndpointKvdbException, "Unknown endpoint kvdb exception", "Kvdb", 0x000A)

#define KVDB_EXCEPTIONS(X)                                                                                           \
    X(CannotExtractKvdbCreatedEventException, "Cannot extract KvdbCreatedEvent", 0x0002)                             \
    X(CannotExtractKvdbUpdatedEventException, "Cannot extract KvdbUpdatedEvent", 0x0003)                             \
    X(CannotExtractKvdbDeletedEventException, "Cannot extract KvdbDeletedEvent", 0x0004)                             \
    X(CannotExtractKvdbStatsEventException, "Cannot extract KvdbStatsEvent", 0x0005)                                 \
    X(CannotExtractKvdbNewEntryEventException, "Cannot extract KvdbNewEntryEvent", 0x0006)                           \
    X(CannotExtractKvdbDeletedEntryEventException, "Cannot extract KvdbDeletedEntryEvent", 0x0007)                   \
    X(CannotExtractKvdbEntryUpdatedEventException, "Cannot extract KvdbKvdbEntryUpdatedEvent", 0x0008)               \
    X(KvdbEntryPublicDataMismatchException, "Kvdb entry public data mismatch", 0x000A)                               \
    X(InvalidEncryptedKvdbEntryDataVersionException, "Invalid version of encrypted kvdb entry data", 0x000B)         \
    X(UnknownKvdbFormatException, "Unknown kvdb format", 0x000F)                                                     \
    X(UnknownKvdbEntryFormatException, "Unknown item format", 0x0010)                                                \
    X(KvdbDataIntegrityException, "Failed kvdb data integrity check", 0x0011)                                        \
    X(KvdbEntryDataIntegrityException, "Failed kvdb entry data integrity check", 0x0012)

#define PRIVMX_KVDB_DECLARE(NAME, MSG, CODE) DECLARE_ENDPOINT_EXCEPTION(EndpointKvdbException, NAME, MSG, CODE)
KVDB_EXCEPTIONS(PRIVMX_KVDB_DECLARE)
#undef PRIVMX_KVDB_DECLARE

// compile-time guard: codes are collected from the list above, never retyped
#define PRIVMX_KVDB_CODE(NAME, MSG, CODE) NAME::FULL_CODE,
static_assert(
    privmx::endpoint::core::exceptionCodesUnique({KVDB_EXCEPTIONS(PRIVMX_KVDB_CODE)}),
    "Duplicate exception code in kvdb scope"
);
#undef PRIVMX_KVDB_CODE
#undef KVDB_EXCEPTIONS
// clang-format on
} // namespace kvdb
} // namespace endpoint
} // namespace privmx

#undef DECLARE_SCOPE_ENDPOINT_EXCEPTION
#undef DECLARE_ENDPOINT_EXCEPTION

#endif // _PRIVMXLIB_ENDPOINT_KVDB_EXT_EXCEPTION_HPP_
