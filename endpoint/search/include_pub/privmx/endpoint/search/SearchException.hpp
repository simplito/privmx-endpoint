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
DECLARE_ENDPOINT_EXCEPTION(EndpointSearchException, InvalidIndexHandleException, "Invalid Index handle", 0x0002)
DECLARE_ENDPOINT_EXCEPTION(EndpointSearchException, InvalidDocumentIdException, "Invalid document ID", 0x0003)
DECLARE_ENDPOINT_EXCEPTION(EndpointSearchException, MalformedInternalFileIdException, "Malformed internal file Id", 0x0004)
DECLARE_ENDPOINT_EXCEPTION(EndpointSearchException, MalformedInternalFileException, "Malformed internal file", 0x0005)
DECLARE_ENDPOINT_EXCEPTION(EndpointSearchException, MalformedFileLockException, "Malformed file lock", 0x0006)

DECLARE_ENDPOINT_EXCEPTION(EndpointSearchException, DatabaseVFSRegisterException, "Can't register VFS", 0x0101)
DECLARE_ENDPOINT_EXCEPTION(EndpointSearchException, DatabaseOpenException, "Can't open database", 0x0102)
DECLARE_ENDPOINT_EXCEPTION(EndpointSearchException, DatabaseAttachException, "ATTACH failed", 0x0103)

DECLARE_ENDPOINT_EXCEPTION(EndpointSearchException, InsertPrepareException, "Error preparing INSERT", 0x0201)
DECLARE_ENDPOINT_EXCEPTION(EndpointSearchException, InsertExecuteException, "Error executing INSERT", 0x0202)
DECLARE_ENDPOINT_EXCEPTION(EndpointSearchException, UpdatePrepareException, "Error preparing UPDATE", 0x0203)
DECLARE_ENDPOINT_EXCEPTION(EndpointSearchException, UpdateExecuteException, "Error executing UPDATE", 0x0204)
DECLARE_ENDPOINT_EXCEPTION(EndpointSearchException, DeletePrepareException, "Error preparing DELETE", 0x0205)
DECLARE_ENDPOINT_EXCEPTION(EndpointSearchException, DeleteExecuteException, "Error executing DELETE", 0x0206)
DECLARE_ENDPOINT_EXCEPTION(EndpointSearchException, SelectPrepareException, "Error preparing SELECT", 0x0207)
DECLARE_ENDPOINT_EXCEPTION(EndpointSearchException, QueryPrepareException, "Error preparing query", 0x0208)
DECLARE_ENDPOINT_EXCEPTION(EndpointSearchException, TableCreationException, "Error creating table", 0x0209)

} // search
} // endpoint
} // privmx

#undef DECLARE_SCOPE_ENDPOINT_EXCEPTION
#undef DECLARE_ENDPOINT_EXCEPTION

#endif // _PRIVMXLIB_ENDPOINT_SEARCH_EXT_EXCEPTION_HPP_
