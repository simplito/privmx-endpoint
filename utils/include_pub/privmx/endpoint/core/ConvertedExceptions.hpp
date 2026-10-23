#ifndef _PRIVMXLIB_ENDPOINT_CONVERTED_EXT_EXCEPTION_HPP_
#define _PRIVMXLIB_ENDPOINT_CONVERTED_EXT_EXCEPTION_HPP_

// Errors reported by the Bridge. The exceptions each library layer raises itself are declared by that
// layer instead, in its own PrivmxExtExceptions / CryptoException / RpcException / PrivFsException header.

#include "privmx/endpoint/core/ExceptionMacros.hpp"

namespace privmx {
namespace endpoint {
// clang-format off
namespace server {

DECLARE_SCOPE_ENDPOINT_EXCEPTION(EndpointServerRequestException, "Invalid request exception", "Server request", 0xFFFF)

#define SERVER_REQUEST_EXCEPTIONS(X)                                                                                  \
    X(ParseErrorException, "Parse error", 0x8043)                                                                     \
    X(InvalidRequestAException, "Invalid request", 0x80A8)                                                            \
    X(MethodNotFoundException, "Method not found", 0x80A7)                                                            \
    X(InvalidParamsException, "Invalid params", 0x80A6)                                                               \
    X(InternalErrorException, "Internal error", 0x80A5)                                                               \
    X(InvalidRequestBException, "Invalid request", 0x80A4)                                                            \
    X(InvalidRequestCException, "Invalid request", 0x80A3)

#define PRIVMX_SERVER_REQUEST_DECLARE(NAME, MSG, CODE) DECLARE_ENDPOINT_EXCEPTION(EndpointServerRequestException, NAME, MSG, CODE)
SERVER_REQUEST_EXCEPTIONS(PRIVMX_SERVER_REQUEST_DECLARE)
#undef PRIVMX_SERVER_REQUEST_DECLARE

DECLARE_SCOPE_ENDPOINT_EXCEPTION(EndpointServerException, "Unknown server exception", "Server", 0xF000)

#define SERVER_EXCEPTIONS(X)                                                                                          \
    X(UserDoesNotExistException, "User doesn't exist", 0x0009)                                                        \
    X(AccessDeniedException, "Access denied", 0x0030)                                                                 \
    X(InvalidKeyException, "Invalid key", 0x0070)                                                                     \
    X(ThreadDoesNotExistException, "Thread does not exist", 0x6001)                                                   \
    X(InvalidThreadKeyException, "Invalid thread key", 0x6002)                                                        \
    X(ThreadMessageDoesNotExistException, "Thread message does not exist", 0x600D)                                    \
    X(ContainerGroupEpochOutdatedException, "Container group epoch outdated", 0x600E)                                   \
    X(ContainerRotatedAlreadyException, "Container keys were already rotated by a concurrent request", 0x600F)        \
    X(GroupRotatedAlreadyException, "Group key was already rotated by a concurrent request", 0x621C)                 \
    X(InvalidKeyIdException, "Invalid key id", 0x6015)                                                              \
    X(ContextDoesNotExistException, "Context does not exist", 0x6116)                                                 \
    X(StoreDoesNotExistException, "Store does not exist", 0x6117)                                                     \
    X(StoreFileDoesNotExistException, "Store file does not exist", 0x6118)                                            \
    X(StoreFileVersionMismatchException, "Store file version mismatch", 0x6128)                                       \
    X(InboxDoesNotExistException, "Inbox does not exist", 0x611E)                                                     \
    X(KvdbDoesNotExistException, "Kvdb does not exist", 0x613C)                                                       \
    X(KvdbEntryDoesNotExistException, "Kvdb entry does not exist", 0x613D)

#define PRIVMX_SERVER_DECLARE(NAME, MSG, CODE) DECLARE_ENDPOINT_EXCEPTION(EndpointServerException, NAME, MSG, CODE)
SERVER_EXCEPTIONS(PRIVMX_SERVER_DECLARE)
#undef PRIVMX_SERVER_DECLARE

// compile-time guard: codes are collected from the lists above, never retyped
#define PRIVMX_CODE(NAME, MSG, CODE) NAME::FULL_CODE,
static_assert(::privmx::endpoint::core::exceptionCodesUnique({
    SERVER_REQUEST_EXCEPTIONS(PRIVMX_CODE)
    SERVER_EXCEPTIONS(PRIVMX_CODE)
}), "Duplicate exception code in server scope");
#undef PRIVMX_CODE
#undef SERVER_REQUEST_EXCEPTIONS
#undef SERVER_EXCEPTIONS
}
// clang-format on
} // namespace endpoint
} // namespace privmx

#undef DECLARE_SCOPE_ENDPOINT_EXCEPTION
#undef DECLARE_ENDPOINT_EXCEPTION

#endif // _PRIVMXLIB_ENDPOINT_CONVERTED_EXT_EXCEPTION_HPP_
