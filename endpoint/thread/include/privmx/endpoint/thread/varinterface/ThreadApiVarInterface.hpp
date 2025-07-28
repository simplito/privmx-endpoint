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
#include "privmx/endpoint/thread/VarDeserializer.hpp"
#include "privmx/endpoint/thread/VarSerializer.hpp"

namespace privmx {
namespace endpoint {
namespace thread {

class ThreadApiVarInterface {
public:
    enum METHOD {
        Create = 0,
        CreateThread = 1,
        UpdateThread = 2,
        DeleteThread = 3,
        GetThread = 4,
        ListThreads = 5,
        GetMessage = 6,
        ListMessages = 7,
        SendMessage = 8,
        DeleteMessage = 9,
        UpdateMessage = 10,
        Deleted_Function_0 = 11,
        Deleted_Function_1 = 12,
        Deleted_Function_2 = 13,
        Deleted_Function_3 = 14,
        SubscribeFor = 15,
        UnsubscribeFrom = 16,
        BuildSubscriptionQuery = 17,
    };

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
    Poco::Dynamic::Var subscribeFor(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var unsubscribeFrom(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var buildSubscriptionQuery(const Poco::Dynamic::Var& args);


    Poco::Dynamic::Var exec(METHOD method, const Poco::Dynamic::Var& args);

    ThreadApi getApi() const { return _threadApi; }

private:
    static std::map<METHOD, Poco::Dynamic::Var (ThreadApiVarInterface::*)(const Poco::Dynamic::Var&)> methodMap;

    core::Connection _connection;
    ThreadApi _threadApi;
    core::VarDeserializer _deserializer;
    core::VarSerializer _serializer;
};

}  // namespace thread
}  // namespace endpoint
}  // namespace privmx

#endif  // _PRIVMXLIB_ENDPOINT_THREAD_THREADAPIVARINTERFACE_HPP_
