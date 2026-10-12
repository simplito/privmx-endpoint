/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_UTILS_PRIVMXEXTEXCEPTIONS_HPP_
#define _PRIVMXLIB_UTILS_PRIVMXEXTEXCEPTIONS_HPP_

#include <privmx/endpoint/core/CoreException.hpp>
#include <privmx/endpoint/core/ExceptionMacros.hpp>
#include <privmx/utils/PrivmxException.hpp>

namespace privmx {
namespace utils {
// clang-format off

// the one base class every privmx exception derives from
using BaseException = privmx::endpoint::core::Exception;

// a lost connection reaches callers as core::NotConnectedException, so it is not redeclared here
using NotConnectedException = privmx::endpoint::core::NotConnectedException;

DECLARE_SCOPE_ENDPOINT_EXCEPTION(NetConnectionException, "Unknown Network Exception", "NetConnection", 0xE001)

#define NET_EXCEPTIONS(X)                                                                                             \
    X(WebsocketDisconnectedException, "Websocket disconnected", 0x0002)                                               \
    X(NoMessageReceivedException, "No message received, http session lost", 0x0003)

#define PRIVMX_NET_DECLARE(NAME, MSG, CODE) DECLARE_ENDPOINT_EXCEPTION(NetConnectionException, NAME, MSG, CODE)
NET_EXCEPTIONS(PRIVMX_NET_DECLARE)
#undef PRIVMX_NET_DECLARE

DECLARE_SCOPE_ENDPOINT_EXCEPTION(ServerException, "Unknown Server Exception", "Server", 0xE002)

#define NET_SERVER_EXCEPTIONS(X)                                                                                      \
    X(InvalidHttpStatusException, "Unexpected server data", 0x0001)                                                   \
    X(UnexpectedServerDataException, "Unknown Server Exception", 0x0002)

#define PRIVMX_NET_SERVER_DECLARE(NAME, MSG, CODE) DECLARE_ENDPOINT_EXCEPTION(ServerException, NAME, MSG, CODE)
NET_SERVER_EXCEPTIONS(PRIVMX_NET_SERVER_DECLARE)
#undef PRIVMX_NET_SERVER_DECLARE

DECLARE_SCOPE_ENDPOINT_EXCEPTION(LibException, "Unknown Lib exception", "Lib", 0xE003)

#define LIB_EXCEPTIONS(X)                                                                                             \
    X(CannotStringifyVarException, "Cannot stringify var", 0x0001)                                                    \
    X(KeyNotExistException, "Key not exist", 0x0002)                                                                  \
    X(VarIsNotObjectException, "Var is not object", 0x0003)                                                           \
    X(VarIsNotArrayException, "Var is not array", 0x0004)                                                             \
    X(OperationCancelledException, "Operation canceled", 0x0005)                                                      \
    X(NotImplementedException, "Not implemented", 0x0006)                                                             \
    X(InvalidVersionFormatException, "Invalid version format", 0x0007)                                                \
    X(JSONParseException, "Cannot parse JSON", 0x0008)                                                                \
    X(BinaryBufferTruncatedException, "Binary buffer ended mid-field", 0x0009)                                        \
    X(BinaryBufferFieldTooLongException, "Binary buffer field exceeds 255 bytes", 0x000A)                             \
    X(TypedObjectException, "TypedObject error", 0x000B)

#define PRIVMX_LIB_DECLARE(NAME, MSG, CODE) DECLARE_ENDPOINT_EXCEPTION(LibException, NAME, MSG, CODE)
LIB_EXCEPTIONS(PRIVMX_LIB_DECLARE)
#undef PRIVMX_LIB_DECLARE

// old spelling, kept so the existing throw sites still compile
using CannotStringifyVar = CannotStringifyVarException;

// compile-time guard: codes are collected from the lists above, never retyped
#define PRIVMX_CODE(NAME, MSG, CODE) NAME::FULL_CODE,
static_assert(::privmx::endpoint::core::exceptionCodesUnique({
    NET_EXCEPTIONS(PRIVMX_CODE)
    NET_SERVER_EXCEPTIONS(PRIVMX_CODE)
    LIB_EXCEPTIONS(PRIVMX_CODE)
}), "Duplicate exception code in utils scope");
#undef PRIVMX_CODE
#undef NET_EXCEPTIONS
#undef NET_SERVER_EXCEPTIONS
#undef LIB_EXCEPTIONS
// clang-format on
} // utils
} // privmx

#undef DECLARE_SCOPE_ENDPOINT_EXCEPTION
#undef DECLARE_ENDPOINT_EXCEPTION

#endif // _PRIVMXLIB_UTILS_PRIVMXEXTEXCEPTIONS_HPP_
