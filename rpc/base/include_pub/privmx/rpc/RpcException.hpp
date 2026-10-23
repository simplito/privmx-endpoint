/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_RPC_RPCEXCEPTION_HPP_
#define _PRIVMXLIB_RPC_RPCEXCEPTION_HPP_

#include <privmx/endpoint/core/CoreException.hpp>
#include <privmx/utils/PrivmxExtExceptions.hpp>
// must come last: the headers above undefine the declaration macros when they are done with them
#include <privmx/endpoint/core/ExceptionMacros.hpp>

namespace privmx {
namespace rpc {
// clang-format off

DECLARE_SCOPE_ENDPOINT_EXCEPTION(RpcException, "Unknown Rpc exception", "Rpc", 0xE0A4)

#define RPC_EXCEPTIONS(X)                                                                                             \
    X(WsConnectException, "wsConnect", 0x0002)                                                                        \
    X(WsSend1Exception, "WsSend1", 0x0003)                                                                            \
    X(WebSocketInvalidPayloadLengthException, "Invalid payload length", 0x0004)                                       \
    X(InvalidWebSocketRequestIdException, "Invalid WebSocket request id", 0x0005)                                     \
    X(HttpConnectException, "httpConnect", 0x0006)                                                                    \
    X(HttpRequestException, "httpRequest", 0x0007)                                                                    \
    X(WebSocketPingLoopStoppedException, "Ping loop stopped", 0x0008)                                                 \
    X(WebSocketPingTimeoutException, "Ping timeout", 0x0009)                                                          \
    X(InvalidHandshakeStateException, "Invalid handshake state", 0x000A)                                              \
    X(IncorrectHashmailException, "Incorrect hashmail", 0x000B)                                                       \
    X(UnexpectedEcdhePacketFromServerException, "Unexpected ecdhe packet from server", 0x000C)                        \
    X(UnexpectedEcdhexPacketFromServerException, "Unexpected ecdhex packet from server", 0x000D)                      \
    X(InvalidWsChannelIdException, "Invalid wsChannelId", 0x000E)                                                     \
    X(ErrorDuringGettingHTTPChannelException, "Error during getting HTTP channel", 0x000F)                            \
    X(ConnectionDestroyedException, "Connection destroyed", 0x0010)                                                   \
    X(SessionLostException, "Session lost", 0x0011)                                                                   \
    X(ProbeFailException, "Probe fail", 0x0012)                                                                       \
    X(InvalidHostException, "Invalid host", 0x0013)                                                                   \
    X(WebsocketCannotBeMainChannelWhenItIsDisabledException, "Websocket cannot be main channel when it is disabled", 0x0014) \
    X(RejectedException, "Rejected", 0x0015)                                                                          \
    X(FrameHeaderTagsAreNotEqualException, "Frame header tags are not equal", 0x0016)                                 \
    X(UnsupportedFrameVersionException, "Unsupported frame version", 0x0017)                                          \
    X(FrameMacsAreNotEqualException, "Frame macs are not equal", 0x0018)                                              \
    X(InvalidNextReadStateException, "Invalid next read state", 0x0019)                                               \
    X(WriteStateIsNotInitializedException, "Write state is not initialized", 0x001A)                                  \
    X(TicketHandshakeErrorException, "Ticket handshake error", 0x001B)                                                \
    X(TimeDifferenceBetweenServerAndClientBiggerThanAllowedException, "Time difference between server and client bigger than allowed", 0x001C) \
    X(ServerChallengeFailedException, "Server key challenge failed", 0x001D)                                          \
    X(ServerChallengeMissingSignatureException, "Server key challenge failed, missing signature", 0x001E)             \
    X(ServerAlertException, "Server sent an alert frame", 0x001F)

#define PRIVMX_RPC_DECLARE(NAME, MSG, CODE) DECLARE_ENDPOINT_EXCEPTION(RpcException, NAME, MSG, CODE)
RPC_EXCEPTIONS(PRIVMX_RPC_DECLARE)
#undef PRIVMX_RPC_DECLARE

// not an RpcException: an exhausted ticket pool has always reached callers as NotConnected,
// and only the ticket loop needs to tell it apart from any other lost connection
class TicketsCountIsEqualZeroException : public privmx::endpoint::core::NotConnectedException {
public:
    using privmx::endpoint::core::NotConnectedException::NotConnectedException;
    void rethrow() const override;
};

inline void TicketsCountIsEqualZeroException::rethrow() const {
    throw *this;
}

// compile-time guard: codes are collected from the list above, never retyped
#define PRIVMX_CODE(NAME, MSG, CODE) NAME::FULL_CODE,
static_assert(::privmx::endpoint::core::exceptionCodesUnique({
    RPC_EXCEPTIONS(PRIVMX_CODE)
}), "Duplicate exception code in rpc scope");
#undef PRIVMX_CODE
#undef RPC_EXCEPTIONS
// clang-format on
} // rpc
} // privmx

#undef DECLARE_SCOPE_ENDPOINT_EXCEPTION
#undef DECLARE_ENDPOINT_EXCEPTION

#endif // _PRIVMXLIB_RPC_RPCEXCEPTION_HPP_
