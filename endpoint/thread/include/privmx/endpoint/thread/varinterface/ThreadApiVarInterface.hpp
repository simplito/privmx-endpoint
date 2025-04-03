/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_ENDPOINT_THREAD_THREADAPIVARINTERFACE_HPP_
#define _PRIVMXLIB_ENDPOINT_THREAD_THREADAPIVARINTERFACE_HPP_

#include <Poco/Dynamic/Var.h>

#include "privmx/endpoint/thread/ThreadApi.hpp"
#include "privmx/endpoint/thread/ThreadVarDeserializer.hpp"
#include "privmx/endpoint/thread/ThreadVarSerializer.hpp"
#include "privmx/endpoint/thread/c_api.h"

namespace privmx {
namespace endpoint {
namespace thread {

class ThreadApiVarInterface {
public:
    ThreadApiVarInterface(core::Connection connection, const core::VarSerializer& serializer)
        : _connection(std::move(connection)), _serializer(serializer) {}

    Poco::Dynamic::Var create(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var createThread(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var updateThread(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var deleteThread(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var getThread(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var listThreads(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var getMessage(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var listMessages(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var sendMessage(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var deleteMessage(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var updateMessage(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var subscribeForThreadEvents(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var unsubscribeFromThreadEvents(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var subscribeForMessageEvents(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var unsubscribeFromMessageEvents(const Poco::Dynamic::Var& args);

    Poco::Dynamic::Var exec(privmx_ThreadApi_Method method, const Poco::Dynamic::Var& args);

    ThreadApi getApi() const { return _threadApi; }

private:
    static std::map<privmx_ThreadApi_Method, Poco::Dynamic::Var (ThreadApiVarInterface::*)(const Poco::Dynamic::Var&)> methodMap;

    core::Connection _connection;
    ThreadApi _threadApi;
    core::VarDeserializer _deserializer;
    core::VarSerializer _serializer;
};

}  // namespace thread
}  // namespace endpoint
}  // namespace privmx

#endif  // _PRIVMXLIB_ENDPOINT_THREAD_THREADAPIVARINTERFACE_HPP_
