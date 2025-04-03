#ifndef _PRIVMXLIB_ENDPOINT_KVDB_EXT_EXCEPTION_HPP_
#define _PRIVMXLIB_ENDPOINT_KVDB_EXT_EXCEPTION_HPP_


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
namespace kvdb {

#define ENDPOINT_KVDB_EXCEPTION_CODE 0x00090000

DECLARE_SCOPE_ENDPOINT_EXCEPTION(EndpointKvdbException, "Unknown endpoint kvdb exception", "Kvdb", 0x0009)
DECLARE_ENDPOINT_EXCEPTION(EndpointKvdbException, NotInitializedException, "Endpoint not initialized", 0x0001)
DECLARE_ENDPOINT_EXCEPTION(EndpointKvdbException, CannotExtractKvdbCreatedEventException, "Cannot extract KvdbCreatedEvent", 0x0002)
DECLARE_ENDPOINT_EXCEPTION(EndpointKvdbException, CannotExtractKvdbUpdatedEventException, "Cannot extract KvdbUpdatedEvent", 0x0003)
DECLARE_ENDPOINT_EXCEPTION(EndpointKvdbException, CannotExtractKvdbDeletedEventException, "Cannot extract KvdbDeletedEvent", 0x0004)
DECLARE_ENDPOINT_EXCEPTION(EndpointKvdbException, CannotExtractKvdbStatsEventException, "Cannot extract KvdbStatsEvent", 0x0005)
DECLARE_ENDPOINT_EXCEPTION(EndpointKvdbException, CannotExtractKvdbNewItemEventException, "Cannot extract KvdbNewItemEvent", 0x0006)
DECLARE_ENDPOINT_EXCEPTION(EndpointKvdbException, CannotExtractKvdbItemUpdatedEventException, "Cannot extract KvdbKvdbItemUpdatedEvent", 0x0006)
DECLARE_ENDPOINT_EXCEPTION(EndpointKvdbException, CannotExtractKvdbDeletedItemEventException, "Cannot extract KvdbDeletedItemEvent", 0x0007)

} // kvdb
} // endpoint
} // privmx

#undef DECLARE_SCOPE_ENDPOINT_EXCEPTION
#undef DECLARE_ENDPOINT_EXCEPTION

#endif // _PRIVMXLIB_ENDPOINT_KVDB_EXT_EXCEPTION_HPP_