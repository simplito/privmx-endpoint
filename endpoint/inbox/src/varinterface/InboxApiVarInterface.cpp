/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include "privmx/endpoint/inbox/varinterface/InboxApiVarInterface.hpp"

#include "privmx/endpoint/core/CoreException.hpp"
#include "privmx/endpoint/core/varinterface/VarInterfaceUtil.hpp"

using namespace privmx::endpoint;
using namespace privmx::endpoint::inbox;

std::map<privmx_InboxApi_Method, Poco::Dynamic::Var (InboxApiVarInterface::*)(const Poco::Dynamic::Var&)>
    InboxApiVarInterface::methodMap = {{privmx_InboxApi_Create, &InboxApiVarInterface::create},
                                       {privmx_InboxApi_CreateInbox, &InboxApiVarInterface::createInbox},
                                       {privmx_InboxApi_UpdateInbox, &InboxApiVarInterface::updateInbox},
                                       {privmx_InboxApi_GetInbox, &InboxApiVarInterface::getInbox},
                                       {privmx_InboxApi_ListInboxes, &InboxApiVarInterface::listInboxes},
                                       {privmx_InboxApi_GetInboxPublicView, &InboxApiVarInterface::getInboxPublicView},
                                       {privmx_InboxApi_DeleteInbox, &InboxApiVarInterface::deleteInbox},
                                       {privmx_InboxApi_PrepareEntry, &InboxApiVarInterface::prepareEntry},
                                       {privmx_InboxApi_SendEntry, &InboxApiVarInterface::sendEntry},
                                       {privmx_InboxApi_ReadEntry, &InboxApiVarInterface::readEntry},
                                       {privmx_InboxApi_ListEntries, &InboxApiVarInterface::listEntries},
                                       {privmx_InboxApi_DeleteEntry, &InboxApiVarInterface::deleteEntry},
                                       {privmx_InboxApi_CreateFileHandle, &InboxApiVarInterface::createFileHandle},
                                       {privmx_InboxApi_WriteToFile, &InboxApiVarInterface::writeToFile},
                                       {privmx_InboxApi_OpenFile, &InboxApiVarInterface::openFile},
                                       {privmx_InboxApi_ReadFromFile, &InboxApiVarInterface::readFromFile},
                                       {privmx_InboxApi_SeekInFile, &InboxApiVarInterface::seekInFile},
                                       {privmx_InboxApi_CloseFile, &InboxApiVarInterface::closeFile},
                                       {privmx_InboxApi_SubscribeForInboxEvents, &InboxApiVarInterface::subscribeForInboxEvents},
                                       {privmx_InboxApi_UnsubscribeFromInboxEvents, &InboxApiVarInterface::unsubscribeFromInboxEvents},
                                       {privmx_InboxApi_SubscribeForEntryEvents, &InboxApiVarInterface::subscribeForEntryEvents},
                                       {privmx_InboxApi_UnsubscribeFromEntryEvents, &InboxApiVarInterface::unsubscribeFromEntryEvents}};

Poco::Dynamic::Var InboxApiVarInterface::create(const Poco::Dynamic::Var& args) {
    core::VarInterfaceUtil::validateAndExtractArray(args, 0);
    _inboxApi = InboxApi::create(_connection, _threadApi, _storeApi);
    return {};
}

Poco::Dynamic::Var InboxApiVarInterface::createInbox(const Poco::Dynamic::Var& args) {
    auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 7);
    auto contextId = _deserializer.deserialize<std::string>(argsArr->get(0), "contextId");
    auto users = _deserializer.deserializeVector<core::UserWithPubKey>(argsArr->get(1), "users");
    auto managers = _deserializer.deserializeVector<core::UserWithPubKey>(argsArr->get(2), "managers");
    auto publicMeta = _deserializer.deserialize<core::Buffer>(argsArr->get(3), "publicMeta");
    auto privateMeta = _deserializer.deserialize<core::Buffer>(argsArr->get(4), "privateMeta");
    auto filesConfig = _deserializer.deserializeOptional<inbox::FilesConfig>(argsArr->get(5), "filesConfig");
    auto policies = _deserializer.deserializeOptional<core::ContainerPolicyWithoutItem>(argsArr->get(6), "policies");
    auto result = _inboxApi.createInbox(contextId, users, managers, publicMeta, privateMeta, filesConfig, policies);
    return _serializer.serialize(result);
}

Poco::Dynamic::Var InboxApiVarInterface::updateInbox(const Poco::Dynamic::Var& args) {
    auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 10);
    auto inboxId = _deserializer.deserialize<std::string>(argsArr->get(0), "inboxId");
    auto users = _deserializer.deserializeVector<core::UserWithPubKey>(argsArr->get(1), "users");
    auto managers = _deserializer.deserializeVector<core::UserWithPubKey>(argsArr->get(2), "managers");
    auto publicMeta = _deserializer.deserialize<core::Buffer>(argsArr->get(3), "publicMeta");
    auto privateMeta = _deserializer.deserialize<core::Buffer>(argsArr->get(4), "privateMeta");
    auto filesConfig = _deserializer.deserializeOptional<inbox::FilesConfig>(argsArr->get(5), "filesConfig");
    auto version = _deserializer.deserialize<int64_t>(argsArr->get(6), "version");
    auto force = _deserializer.deserialize<bool>(argsArr->get(7), "force");
    auto forceGenerateNewKey = _deserializer.deserialize<bool>(argsArr->get(8), "forceGenerateNewKey");
    auto policies = _deserializer.deserializeOptional<core::ContainerPolicyWithoutItem>(argsArr->get(9), "policies");
    _inboxApi.updateInbox(inboxId, users, managers, publicMeta, privateMeta, filesConfig, version, force,
                          forceGenerateNewKey, policies);
    return {};
}

Poco::Dynamic::Var InboxApiVarInterface::getInbox(const Poco::Dynamic::Var& args) {
    auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 1);
    auto inboxId = _deserializer.deserialize<std::string>(argsArr->get(0), "inboxId");
    auto result = _inboxApi.getInbox(inboxId);
    return _serializer.serialize(result);
}

Poco::Dynamic::Var InboxApiVarInterface::listInboxes(const Poco::Dynamic::Var& args) {
    auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 2);
    auto contextId = _deserializer.deserialize<std::string>(argsArr->get(0), "contextId");
    auto pagingQuery = _deserializer.deserialize<core::PagingQuery>(argsArr->get(1), "pagingQuery");
    auto result = _inboxApi.listInboxes(contextId, pagingQuery);
    return _serializer.serialize(result);
}

Poco::Dynamic::Var InboxApiVarInterface::getInboxPublicView(const Poco::Dynamic::Var& args) {
    auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 1);
    auto inboxId = _deserializer.deserialize<std::string>(argsArr->get(0), "inboxId");
    auto result = _inboxApi.getInboxPublicView(inboxId);
    return _serializer.serialize(result);
}

Poco::Dynamic::Var InboxApiVarInterface::deleteInbox(const Poco::Dynamic::Var& args) {
    auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 1);
    auto inboxId = _deserializer.deserialize<std::string>(argsArr->get(0), "inboxId");
    _inboxApi.deleteInbox(inboxId);
    return {};
}

Poco::Dynamic::Var InboxApiVarInterface::prepareEntry(const Poco::Dynamic::Var& args) {
    auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 4);
    auto inboxId = _deserializer.deserialize<std::string>(argsArr->get(0), "inboxId");
    auto data = _deserializer.deserialize<core::Buffer>(argsArr->get(1), "data");
    auto inboxFileHandles = _deserializer.deserializeVector<int64_t>(argsArr->get(2), "inboxFileHandles");
    auto userPrivKey = _deserializer.deserializeOptional<std::string>(argsArr->get(3), "userPrivKey");
    auto result = _inboxApi.prepareEntry(inboxId, data, inboxFileHandles, userPrivKey);
    return _serializer.serialize(result);
}

Poco::Dynamic::Var InboxApiVarInterface::sendEntry(const Poco::Dynamic::Var& args) {
    auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 1);
    auto inboxHandle = _deserializer.deserialize<int64_t>(argsArr->get(0), "inboxHandle");
    _inboxApi.sendEntry(inboxHandle);
    return {};
}

Poco::Dynamic::Var InboxApiVarInterface::readEntry(const Poco::Dynamic::Var& args) {
    auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 1);
    auto messageId = _deserializer.deserialize<std::string>(argsArr->get(0), "messageId");
    auto result = _inboxApi.readEntry(messageId);
    return _serializer.serialize(result);
}

Poco::Dynamic::Var InboxApiVarInterface::listEntries(const Poco::Dynamic::Var& args) {
    auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 2);
    auto threadId = _deserializer.deserialize<std::string>(argsArr->get(0), "threadId");
    auto pagingQuery = _deserializer.deserialize<core::PagingQuery>(argsArr->get(1), "pagingQuery");
    auto result = _inboxApi.listEntries(threadId, pagingQuery);
    return _serializer.serialize(result);
}

Poco::Dynamic::Var InboxApiVarInterface::deleteEntry(const Poco::Dynamic::Var& args) {
    auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 1);
    auto entryId = _deserializer.deserialize<std::string>(argsArr->get(0), "entryId");
    _inboxApi.deleteEntry(entryId);
    return {};
}

Poco::Dynamic::Var InboxApiVarInterface::createFileHandle(const Poco::Dynamic::Var& args) {
    auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 3);
    auto publicMeta = _deserializer.deserialize<core::Buffer>(argsArr->get(0), "publicMeta");
    auto privateMeta = _deserializer.deserialize<core::Buffer>(argsArr->get(1), "privateMeta");
    auto size = _deserializer.deserialize<int64_t>(argsArr->get(2), "size");
    auto result = _inboxApi.createFileHandle(publicMeta, privateMeta, size);
    return _serializer.serialize(result);
}

Poco::Dynamic::Var InboxApiVarInterface::writeToFile(const Poco::Dynamic::Var& args) {
    auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 3);
    auto inboxHandle = _deserializer.deserialize<int64_t>(argsArr->get(0), "inboxHandle");
    auto inboxFileHandle = _deserializer.deserialize<int64_t>(argsArr->get(1), "inboxFileHandle");
    auto dataChunk = _deserializer.deserialize<core::Buffer>(argsArr->get(2), "dataChunk");
    _inboxApi.writeToFile(inboxHandle, inboxFileHandle, dataChunk);
    return {};
}

Poco::Dynamic::Var InboxApiVarInterface::openFile(const Poco::Dynamic::Var& args) {
    auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 1);
    auto fileId = _deserializer.deserialize<std::string>(argsArr->get(0), "fileId");
    auto result = _inboxApi.openFile(fileId);
    return _serializer.serialize(result);
}

Poco::Dynamic::Var InboxApiVarInterface::readFromFile(const Poco::Dynamic::Var& args) {
    auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 2);
    auto handle = _deserializer.deserialize<int64_t>(argsArr->get(0), "handle");
    auto length = _deserializer.deserialize<int64_t>(argsArr->get(1), "length");
    auto result = _inboxApi.readFromFile(handle, length);
    return _serializer.serialize(result);
}

Poco::Dynamic::Var InboxApiVarInterface::seekInFile(const Poco::Dynamic::Var& args) {
    auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 2);
    auto handle = _deserializer.deserialize<int64_t>(argsArr->get(0), "handle");
    auto position = _deserializer.deserialize<int64_t>(argsArr->get(1), "position");
    _inboxApi.seekInFile(handle, position);
    return {};
}

Poco::Dynamic::Var InboxApiVarInterface::closeFile(const Poco::Dynamic::Var& args) {
    auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 1);
    auto handle = _deserializer.deserialize<int64_t>(argsArr->get(0), "handle");
    auto result = _inboxApi.closeFile(handle);
    return _serializer.serialize(result);
}

Poco::Dynamic::Var InboxApiVarInterface::subscribeForInboxEvents(const Poco::Dynamic::Var& args) {
    core::VarInterfaceUtil::validateAndExtractArray(args, 0);
    _inboxApi.subscribeForInboxEvents();
    return {};
}

Poco::Dynamic::Var InboxApiVarInterface::unsubscribeFromInboxEvents(const Poco::Dynamic::Var& args) {
    core::VarInterfaceUtil::validateAndExtractArray(args, 0);
    _inboxApi.unsubscribeFromInboxEvents();
    return {};
}

Poco::Dynamic::Var InboxApiVarInterface::subscribeForEntryEvents(const Poco::Dynamic::Var& args) {
    auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 1);
    auto inboxId = _deserializer.deserialize<std::string>(argsArr->get(0), "inboxId");
    _inboxApi.subscribeForEntryEvents(inboxId);
    return {};
}

Poco::Dynamic::Var InboxApiVarInterface::unsubscribeFromEntryEvents(const Poco::Dynamic::Var& args) {
    auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 1);
    auto inboxId = _deserializer.deserialize<std::string>(argsArr->get(0), "inboxId");
    _inboxApi.unsubscribeFromEntryEvents(inboxId);
    return {};
}

Poco::Dynamic::Var InboxApiVarInterface::exec(privmx_InboxApi_Method method, const Poco::Dynamic::Var& args) {
    auto it = methodMap.find(method);
    if (it == methodMap.end()) {
        throw core::InvalidMethodException();
    }
    return (*this.*(it->second))(args);
}
