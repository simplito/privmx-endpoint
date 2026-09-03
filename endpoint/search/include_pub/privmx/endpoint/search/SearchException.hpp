#ifndef _PRIVMXLIB_ENDPOINT_SEARCH_EXT_EXCEPTION_HPP_
#define _PRIVMXLIB_ENDPOINT_SEARCH_EXT_EXCEPTION_HPP_

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
namespace search {
// clang-format off
#define ENDPOINT_SEARCH_EXCEPTION_CODE 0x000B0000

DECLARE_SCOPE_ENDPOINT_EXCEPTION(EndpointSearchException, "Unknown endpoint search exception", "Search", 0x000B)

#define SEARCH_EXCEPTIONS(X)                                                                                           \
    X(NotInitializedException, "Endpoint not initialized", 0x0001)                                                     \
    X(InvalidIndexHandleException, "Invalid Index handle", 0x0002)                                                     \
    X(InvalidDocumentIdException, "Invalid document ID", 0x0003)                                                       \
    X(MalformedInternalFileIdException, "Malformed internal file Id", 0x0004)                                          \
    X(MalformedInternalFileException, "Malformed internal file", 0x0005)                                               \
    X(MalformedFileLockException, "Malformed file lock", 0x0006)                                                       \
    X(DatabaseVFSRegisterException, "Can't register VFS", 0x0101)                                                      \
    X(DatabaseOpenException, "Can't open database", 0x0102)                                                            \
    X(DatabaseAttachException, "ATTACH failed", 0x0103)                                                                \
    X(InsertPrepareException, "Error preparing INSERT", 0x0201)                                                        \
    X(InsertExecuteException, "Error executing INSERT", 0x0202)                                                        \
    X(UpdatePrepareException, "Error preparing UPDATE", 0x0203)                                                        \
    X(UpdateExecuteException, "Error executing UPDATE", 0x0204)                                                        \
    X(DeletePrepareException, "Error preparing DELETE", 0x0205)                                                        \
    X(DeleteExecuteException, "Error executing DELETE", 0x0206)                                                        \
    X(SelectPrepareException, "Error preparing SELECT", 0x0207)                                                        \
    X(SelectExecuteException, "Error executing SELECT", 0x020A)                                                        \
    X(QueryPrepareException, "Error preparing query", 0x0208)                                                          \
    X(TableCreationException, "Error creating table", 0x0209)                                                          \
    X(TransactionBeginException, "Error beginning transaction", 0x0301)                                                \
    X(TransactionCommitException, "Error committing transaction", 0x0302)                                              \
    X(TransactionRollbackException, "Error rolling back transaction", 0x0303)

#define PRIVMX_SEARCH_DECLARE(NAME, MSG, CODE) DECLARE_ENDPOINT_EXCEPTION(EndpointSearchException, NAME, MSG, CODE)
SEARCH_EXCEPTIONS(PRIVMX_SEARCH_DECLARE)
#undef PRIVMX_SEARCH_DECLARE

// compile-time guard: codes are collected from the list above, never retyped
#define PRIVMX_SEARCH_CODE(NAME, MSG, CODE) NAME::FULL_CODE,
static_assert(
    privmx::endpoint::core::exceptionCodesUnique({SEARCH_EXCEPTIONS(PRIVMX_SEARCH_CODE)}),
    "Duplicate exception code in search scope"
);
#undef PRIVMX_SEARCH_CODE
#undef SEARCH_EXCEPTIONS
// clang-format on
} // namespace search
} // namespace endpoint
} // namespace privmx

#undef DECLARE_SCOPE_ENDPOINT_EXCEPTION
#undef DECLARE_ENDPOINT_EXCEPTION

#endif // _PRIVMXLIB_ENDPOINT_SEARCH_EXT_EXCEPTION_HPP_
