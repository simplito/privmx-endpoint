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

#include <privmx/utils/PrivmxException.hpp>

namespace privmx {
namespace utils {

class BaseException : public PrivmxException
{
public:
    BaseException(const std::string& msg, int code) : PrivmxException(msg, LIBRARY, code) {}
    BaseException(const std::string& msg, const std::string& extra_msg, int code)
            : PrivmxException(msg + ": " + extra_msg, LIBRARY, code) {}
    void rethrow() const override;
};

inline void BaseException::rethrow() const {
    throw *this;
}

#define DECLARE_PRIVMX_EXCEPTION(NAME, BASE, MSG, CODE)                                                 \
class NAME : public BASE                                                                                \
{                                                                                                       \
public:                                                                                                 \
    NAME() : BASE(MSG, CODE) {}                                                                         \
    NAME(const std::string& msg) : BASE(MSG, msg, CODE << 16) {}                                        \
    NAME(const std::string& msg, int code) : BASE(MSG, msg, (CODE << 16) | code) {}                     \
    NAME(const std::string& msg, const std::string& extra_msg, int code)                                \
            : BASE(MSG, msg + ": " + extra_msg, (CODE << 16) | code) {}                                 \
    void rethrow() const override;                                                                      \
};                                                                                                      \
                                                                                                        \
inline void NAME::rethrow() const {                                                                     \
    throw *this;                                                                                        \
}

#define DECLARE_PRIVMX_EXCEPTION_CHILD(NAME, BASE, MSG, CODE)                                           \
class NAME : public BASE                                                                                \
{                                                                                                       \
public:                                                                                                 \
    NAME() : BASE(MSG, CODE) {}                                                                         \
    NAME(const std::string& msg) : BASE(MSG, msg, CODE) {}                                              \
    void rethrow() const override;                                                                      \
};                                                                                                      \
                                                                                                        \
inline void NAME::rethrow() const {                                                                     \
    throw *this;                                                                                        \
}
// do no use first 4 bits
DECLARE_PRIVMX_EXCEPTION(NetConnectionException, BaseException, "Network connection error", 0x0001);
DECLARE_PRIVMX_EXCEPTION_CHILD(NotConnectedException, NetConnectionException, "RpcGateway is not connected", 0x0001);
DECLARE_PRIVMX_EXCEPTION_CHILD(WebsocketDisconnectedException, NetConnectionException, "Websocket disconnected", 0x0002);
DECLARE_PRIVMX_EXCEPTION_CHILD(NoMessageReceivedException, NetConnectionException, "No message received, http session lost", 0x0003);

DECLARE_PRIVMX_EXCEPTION(ServerException, BaseException, "Server error", 0x0002);
DECLARE_PRIVMX_EXCEPTION_CHILD(InvalidHttpStatusException, ServerException, "Invalid server HTTP status", 0x0001);
DECLARE_PRIVMX_EXCEPTION_CHILD(UnexpectedServerDataException, ServerException, "Unexpected data from server", 0x0002);

DECLARE_PRIVMX_EXCEPTION(LibException, BaseException, "Lib internal error", 0x0003);
DECLARE_PRIVMX_EXCEPTION_CHILD(CannotStringifyVar, LibException, "Cannot stringify var", 0x0001);
DECLARE_PRIVMX_EXCEPTION_CHILD(KeyNotExistException, LibException, "Key not exist", 0x0002);
DECLARE_PRIVMX_EXCEPTION_CHILD(VarIsNotObjectException, LibException, "Var is not object", 0x0003);
DECLARE_PRIVMX_EXCEPTION_CHILD(VarIsNotArrayException, LibException, "Var is not array", 0x0004);


DECLARE_PRIVMX_EXCEPTION(OperationCancelledException, BaseException, "Operation canceled", 0x000C);

DECLARE_PRIVMX_EXCEPTION(NotImplementedException, BaseException, "Not implemented", 0x000D);


DECLARE_PRIVMX_EXCEPTION(TypedObjectException, BaseException, "TypedObject error", 0x000E);







} // utils
} // privmx

#endif // _PRIVMXLIB_UTILS_PRIVMXEXTEXCEPTIONS_HPP_
