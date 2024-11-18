/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include "privmx/endpoint/thread/varinterface/ThreadApiVarInterface.hpp"

#include "privmx/endpoint/core/CoreException.hpp"
#include "privmx/endpoint/core/varinterface/VarInterfaceUtil.hpp"

using namespace privmx::endpoint;
using namespace privmx::endpoint::thread;

std::map<ThreadApiVarInterface::METHOD, Poco::Dynamic::Var (ThreadApiVarInterface::*)(const Poco::Dynamic::Var&)>
    ThreadApiVarInterface::methodMap = {{Create, &ThreadApiVarInterface::create},
                                        {CreateThread, &ThreadApiVarInterface::createThread},
                                        {UpdateThread, &ThreadApiVarInterface::updateThread},
                                        {DeleteThread, &ThreadApiVarInterface::deleteThread},
                                        {GetThread, &ThreadApiVarInterface::getThread},
                                        {ListThreads, &ThreadApiVarInterface::listThreads},
                                        {GetMessage, &ThreadApiVarInterface::getMessage},
                                        {ListMessages, &ThreadApiVarInterface::listMessages},
                                        {SendMessage, &ThreadApiVarInterface::sendMessage},
                                        {DeleteMessage, &ThreadApiVarInterface::deleteMessage},
                                        {UpdateMessage, &ThreadApiVarInterface::updateMessage},
                                        {SubscribeForThreadEvents, &ThreadApiVarInterface::subscribeForThreadEvents},
                                        {UnsubscribeFromThreadEvents, &ThreadApiVarInterface::unsubscribeFromThreadEvents},
                                        {SubscribeForMessageEvents, &ThreadApiVarInterface::subscribeForMessageEvents},
                                        {UnsubscribeFromMessageEvents, &ThreadApiVarInterface::unsubscribeFromMessageEvents}};

Poco::Dynamic::Var ThreadApiVarInterface::create(const Poco::Dynamic::Var& args) {
    core::VarInterfaceUtil::validateAndExtractArray(args, 0);
    _threadApi = ThreadApi::create(_connection);
    return {};
}

Poco::Dynamic::Var ThreadApiVarInterface::createThread(const Poco::Dynamic::Var& args) {
    auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 5);
    auto contextId = _deserializer.deserialize<std::string>(argsArr->get(0), "contextId");
    auto users = _deserializer.deserializeVector<core::UserWithPubKey>(argsArr->get(1), "users");
    auto managers = _deserializer.deserializeVector<core::UserWithPubKey>(argsArr->get(2), "managers");
    auto publicMeta = _deserializer.deserialize<core::Buffer>(argsArr->get(3), "publicMeta");
    auto privateMeta = _deserializer.deserialize<core::Buffer>(argsArr->get(4), "privateMeta");
    auto policies = _deserializer.deserializeOptional<core::ContainerPolicy>(argsArr.get(5), "policies");
    auto result = _threadApi.createThread(contextId, users, managers, publicMeta, privateMeta, policies);
    return _serializer.serialize(result);
}

Poco::Dynamic::Var ThreadApiVarInterface::updateThread(const Poco::Dynamic::Var& args) {
    auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 8);
    auto threadId = _deserializer.deserialize<std::string>(argsArr->get(0), "threadId");
    auto users = _deserializer.deserializeVector<core::UserWithPubKey>(argsArr->get(1), "users");
    auto managers = _deserializer.deserializeVector<core::UserWithPubKey>(argsArr->get(2), "managers");
    auto publicMeta = _deserializer.deserialize<core::Buffer>(argsArr->get(3), "publicMeta");
    auto privateMeta = _deserializer.deserialize<core::Buffer>(argsArr->get(4), "privateMeta");
    auto version = _deserializer.deserialize<int64_t>(argsArr->get(5), "version");
    auto force = _deserializer.deserialize<bool>(argsArr->get(6), "force");
    auto forceGenerateNewKey = _deserializer.deserialize<bool>(argsArr->get(7), "forceGenerateNewKey");
    auto policies = _deserializer.deserializeOptional<core::ContainerPolicy>(argsArr.get(8), "policies");
    _threadApi.updateThread(threadId, users, managers, publicMeta, privateMeta, version, force, forceGenerateNewKey, policies);
    return {};
}

Poco::Dynamic::Var ThreadApiVarInterface::deleteThread(const Poco::Dynamic::Var& args) {
    auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 1);
    auto threadId = _deserializer.deserialize<std::string>(argsArr->get(0), "threadId");
    _threadApi.deleteThread(threadId);
    return {};
}

Poco::Dynamic::Var ThreadApiVarInterface::getThread(const Poco::Dynamic::Var& args) {
    auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 1);
    auto threadId = _deserializer.deserialize<std::string>(argsArr->get(0), "threadId");
    auto result = _threadApi.getThread(threadId);
    return _serializer.serialize(result);
}

Poco::Dynamic::Var ThreadApiVarInterface::listThreads(const Poco::Dynamic::Var& args) {
    auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 2);
    auto contextId = _deserializer.deserialize<std::string>(argsArr->get(0), "contextId");
    auto pagingQuery = _deserializer.deserialize<core::PagingQuery>(argsArr->get(1), "pagingQuery");
    auto result = _threadApi.listThreads(contextId, pagingQuery);
    return _serializer.serialize(result);
}

Poco::Dynamic::Var ThreadApiVarInterface::getMessage(const Poco::Dynamic::Var& args) {
    auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 1);
    auto messageId = _deserializer.deserialize<std::string>(argsArr->get(0), "messageId");
    auto result = _threadApi.getMessage(messageId);
    return _serializer.serialize(result);
}

Poco::Dynamic::Var ThreadApiVarInterface::listMessages(const Poco::Dynamic::Var& args) {
    auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 2);
    auto threadId = _deserializer.deserialize<std::string>(argsArr->get(0), "threadId");
    auto pagingQuery = _deserializer.deserialize<core::PagingQuery>(argsArr->get(1), "pagingQuery");
    auto result = _threadApi.listMessages(threadId, pagingQuery);
    return _serializer.serialize(result);
}

Poco::Dynamic::Var ThreadApiVarInterface::sendMessage(const Poco::Dynamic::Var& args) {
    auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 4);
    auto threadId = _deserializer.deserialize<std::string>(argsArr->get(0), "threadId");
    auto publicMeta = _deserializer.deserialize<core::Buffer>(argsArr->get(1), "publicMeta");
    auto privateMeta = _deserializer.deserialize<core::Buffer>(argsArr->get(2), "privateMeta");
    auto data = _deserializer.deserialize<core::Buffer>(argsArr->get(3), "data");
    auto result = _threadApi.sendMessage(threadId, publicMeta, privateMeta, data);
    return _serializer.serialize(result);
}

Poco::Dynamic::Var ThreadApiVarInterface::updateMessage(const Poco::Dynamic::Var& args) {
    auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 4);
    auto messageId = _deserializer.deserialize<std::string>(argsArr->get(0), "messageId");
    auto publicMeta = _deserializer.deserialize<core::Buffer>(argsArr->get(1), "publicMeta");
    auto privateMeta = _deserializer.deserialize<core::Buffer>(argsArr->get(2), "privateMeta");
    auto data = _deserializer.deserialize<core::Buffer>(argsArr->get(3), "data");
    _threadApi.updateMessage(messageId, publicMeta, privateMeta, data);
    return {};
}

Poco::Dynamic::Var ThreadApiVarInterface::deleteMessage(const Poco::Dynamic::Var& args) {
    auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 1);
    auto messageId = _deserializer.deserialize<std::string>(argsArr->get(0), "messageId");
    _threadApi.deleteMessage(messageId);
    return {};
}

Poco::Dynamic::Var ThreadApiVarInterface::subscribeForThreadEvents(const Poco::Dynamic::Var& args) {
    core::VarInterfaceUtil::validateAndExtractArray(args, 0);
    _threadApi.subscribeForThreadEvents();
    return {};
}

Poco::Dynamic::Var ThreadApiVarInterface::unsubscribeFromThreadEvents(const Poco::Dynamic::Var& args) {
    core::VarInterfaceUtil::validateAndExtractArray(args, 0);
    _threadApi.unsubscribeFromThreadEvents();
    return {};
}

Poco::Dynamic::Var ThreadApiVarInterface::subscribeForMessageEvents(const Poco::Dynamic::Var& args) {
    auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 1);
    auto threadId = _deserializer.deserialize<std::string>(argsArr->get(0), "threadId");
    _threadApi.subscribeForMessageEvents(threadId);
    return {};
}

Poco::Dynamic::Var ThreadApiVarInterface::unsubscribeFromMessageEvents(const Poco::Dynamic::Var& args) {
    auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 1);
    auto threadId = _deserializer.deserialize<std::string>(argsArr->get(0), "threadId");
    _threadApi.unsubscribeFromMessageEvents(threadId);
    return {};
}

Poco::Dynamic::Var ThreadApiVarInterface::exec(METHOD method, const Poco::Dynamic::Var& args) {
    auto it = methodMap.find(method);
    if (it == methodMap.end()) {
        throw core::InvalidMethodException();
    }
    return (*this.*(it->second))(args);
}
