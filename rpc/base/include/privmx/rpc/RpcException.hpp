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

#include <privmx/utils/PrivmxExtExceptions.hpp>

namespace privmx {
namespace rpc {

DECLARE_PRIVMX_EXCEPTION(RpcException, utils::BaseException, "Rpc error", 0x00A4)
DECLARE_PRIVMX_EXCEPTION_CHILD(TicketsCountIsEqualZeroException, RpcException, "Tickets count is equal 0", 0x0001)
DECLARE_PRIVMX_EXCEPTION_CHILD(WsConnectException, RpcException, "wsConnect", 0x0002)
DECLARE_PRIVMX_EXCEPTION_CHILD(WsSend1Exception, RpcException, "wsSend1", 0x0003)
DECLARE_PRIVMX_EXCEPTION_CHILD(WebSocketInvalidPayloadLengthException, RpcException, "Web socket invalid payload Length", 0x0004)
DECLARE_PRIVMX_EXCEPTION_CHILD(InvalidWebSocketRequestIdException, RpcException, "Invalid WebSocket request id", 0x0005)
DECLARE_PRIVMX_EXCEPTION_CHILD(HttpConnectException, RpcException, "httpConnect", 0x0006)
DECLARE_PRIVMX_EXCEPTION_CHILD(HttpRequestException, RpcException, "httpRequest", 0x0007)
DECLARE_PRIVMX_EXCEPTION_CHILD(WebSocketPingLoopStoppedException, RpcException, "Ping loop stopped", 0x0008)
DECLARE_PRIVMX_EXCEPTION_CHILD(WebSocketPingTimeoutException, RpcException, "Ping timeout", 0x0009)
DECLARE_PRIVMX_EXCEPTION_CHILD(InvalidHandshakeStateException, RpcException, "Invalid handshake state", 0x000A)
DECLARE_PRIVMX_EXCEPTION_CHILD(IncorrectHashmailException, RpcException, "Incorrect hashmail", 0x000B)
DECLARE_PRIVMX_EXCEPTION_CHILD(UnexpectedEcdhePacketFromServerException, RpcException, "Unexpected ecdhe packet from server", 0x000C)
DECLARE_PRIVMX_EXCEPTION_CHILD(UnexpectedEcdhexPacketFromServerException, RpcException, "Unexpected ecdhex packet from server", 0x000D)

DECLARE_PRIVMX_EXCEPTION_CHILD(InvalidWsChannelIdException, RpcException, "Invalid wsChannelId", 0x000E)
DECLARE_PRIVMX_EXCEPTION_CHILD(ErrorDuringGettingHTTPChannelException, RpcException, "Error during getting HTTP channel", 0x000F)
DECLARE_PRIVMX_EXCEPTION_CHILD(ConnectionDestroyedException, RpcException, "Connection destroyed", 0x0010)
DECLARE_PRIVMX_EXCEPTION_CHILD(SessionLostException, RpcException, "Session lost", 0x0011)
DECLARE_PRIVMX_EXCEPTION_CHILD(ProbeFailException, RpcException, "Probe fail", 0x0012)
DECLARE_PRIVMX_EXCEPTION_CHILD(InvalidHostException, RpcException, "Invalid host", 0x0013)
DECLARE_PRIVMX_EXCEPTION_CHILD(WebsocketCannotBeMainChannelWhenItIsDisabledException, RpcException, "Websocket cannot be main channel when it is disabled", 0x0014)
DECLARE_PRIVMX_EXCEPTION_CHILD(RejectedException, RpcException, "Rejected", 0x0015)
DECLARE_PRIVMX_EXCEPTION_CHILD(FrameHeaderTagsAreNotEqualException, RpcException, "Frame header tags are not equal", 0x0016)
DECLARE_PRIVMX_EXCEPTION_CHILD(UnsupportedFrameVersionException, RpcException, "Unsupported frame version", 0x0017)
DECLARE_PRIVMX_EXCEPTION_CHILD(FrameMacsAreNotEqualException, RpcException, "Frame macs are not equal", 0x0018)
DECLARE_PRIVMX_EXCEPTION_CHILD(InvalidNextReadStateException, RpcException, "Invalid next read state", 0x0019)
DECLARE_PRIVMX_EXCEPTION_CHILD(WriteStateIsNotInitializedException, RpcException, "Write state is not initialized", 0x001A)
DECLARE_PRIVMX_EXCEPTION_CHILD(TicketHandshakeErrorException, RpcException, "Ticket handshake error", 0x001B)

DECLARE_PRIVMX_EXCEPTION_CHILD(TimeDifferenceBetweenServerAndClientBiggerThanAllowedException, RpcException, "Time difference between server and client bigger than allowed", 0x001C)
DECLARE_PRIVMX_EXCEPTION_CHILD(ServerChallengeFailedException, RpcException, "Server key challenge failed", 0x001D)
DECLARE_PRIVMX_EXCEPTION_CHILD(ServerChallengeMissingSignatureException, RpcException, "Server key challenge failed, missing signature", 0x001E)
} // rpc
} // privmx

#endif // _PRIVMXLIB_RPC_RPCEXCEPTION_HPP_
