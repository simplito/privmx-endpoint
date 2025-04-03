/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include "privmx/endpoint/store/varinterface/StoreApiVarInterface.hpp"

#include "privmx/endpoint/core/CoreException.hpp"
#include "privmx/endpoint/core/varinterface/VarInterfaceUtil.hpp"

using namespace privmx::endpoint;
using namespace privmx::endpoint::store;

std::map<privmx_StoreApi_Method, Poco::Dynamic::Var (StoreApiVarInterface::*)(const Poco::Dynamic::Var&)>
    StoreApiVarInterface::methodMap = {{privmx_StoreApi_Create, &StoreApiVarInterface::create},
                                       {privmx_StoreApi_CreateStore, &StoreApiVarInterface::createStore},
                                       {privmx_StoreApi_UpdateStore, &StoreApiVarInterface::updateStore},
                                       {privmx_StoreApi_DeleteStore, &StoreApiVarInterface::deleteStore},
                                       {privmx_StoreApi_GetStore, &StoreApiVarInterface::getStore},
                                       {privmx_StoreApi_ListStores, &StoreApiVarInterface::listStores},
                                       {privmx_StoreApi_CreateFile, &StoreApiVarInterface::createFile},
                                       {privmx_StoreApi_UpdateFile, &StoreApiVarInterface::updateFile},
                                       {privmx_StoreApi_UpdateFileMeta, &StoreApiVarInterface::updateFileMeta},
                                       {privmx_StoreApi_WriteToFile, &StoreApiVarInterface::writeToFile},
                                       {privmx_StoreApi_DeleteFile, &StoreApiVarInterface::deleteFile},
                                       {privmx_StoreApi_GetFile, &StoreApiVarInterface::getFile},
                                       {privmx_StoreApi_ListFiles, &StoreApiVarInterface::listFiles},
                                       {privmx_StoreApi_OpenFile, &StoreApiVarInterface::openFile},
                                       {privmx_StoreApi_ReadFromFile, &StoreApiVarInterface::readFromFile},
                                       {privmx_StoreApi_SeekInFile, &StoreApiVarInterface::seekInFile},
                                       {privmx_StoreApi_CloseFile, &StoreApiVarInterface::closeFile},
                                       {privmx_StoreApi_SubscribeForStoreEvents, &StoreApiVarInterface::subscribeForStoreEvents},
                                       {privmx_StoreApi_UnsubscribeFromStoreEvents, &StoreApiVarInterface::unsubscribeFromStoreEvents},
                                       {privmx_StoreApi_SubscribeForFileEvents, &StoreApiVarInterface::subscribeForFileEvents},
                                       {privmx_StoreApi_UnsubscribeFromFileEvents, &StoreApiVarInterface::unsubscribeFromFileEvents}};


Poco::Dynamic::Var StoreApiVarInterface::create(const Poco::Dynamic::Var& args) {
    core::VarInterfaceUtil::validateAndExtractArray(args, 0);
    _storeApi = StoreApi::create(_connection);
    return {};
}

Poco::Dynamic::Var StoreApiVarInterface::createStore(const Poco::Dynamic::Var& args) {
    auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 6);
    auto contextId = _deserializer.deserialize<std::string>(argsArr->get(0), "contextId");
    auto users = _deserializer.deserializeVector<core::UserWithPubKey>(argsArr->get(1), "users");
    auto managers = _deserializer.deserializeVector<core::UserWithPubKey>(argsArr->get(2), "managers");
    auto publicMeta = _deserializer.deserialize<core::Buffer>(argsArr->get(3), "publicMeta");
    auto privateMeta = _deserializer.deserialize<core::Buffer>(argsArr->get(4), "privateMeta");
    auto policies = _deserializer.deserializeOptional<core::ContainerPolicy>(argsArr->get(5), "policies");
    auto result = _storeApi.createStore(contextId, users, managers, publicMeta, privateMeta, policies);
    return _serializer.serialize(result);
}

Poco::Dynamic::Var StoreApiVarInterface::updateStore(const Poco::Dynamic::Var& args) {
    auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 9);
    auto storeId = _deserializer.deserialize<std::string>(argsArr->get(0), "storeId");
    auto users = _deserializer.deserializeVector<core::UserWithPubKey>(argsArr->get(1), "users");
    auto managers = _deserializer.deserializeVector<core::UserWithPubKey>(argsArr->get(2), "managers");
    auto publicMeta = _deserializer.deserialize<core::Buffer>(argsArr->get(3), "publicMeta");
    auto privateMeta = _deserializer.deserialize<core::Buffer>(argsArr->get(4), "privateMeta");
    auto version = _deserializer.deserialize<int64_t>(argsArr->get(5), "version");
    auto force = _deserializer.deserialize<bool>(argsArr->get(6), "force");
    auto forceGenerateNewKey = _deserializer.deserialize<bool>(argsArr->get(7), "forceGenerateNewKey");
    auto policies = _deserializer.deserializeOptional<core::ContainerPolicy>(argsArr->get(8), "policies");
    _storeApi.updateStore(storeId, users, managers, publicMeta, privateMeta, version, force, forceGenerateNewKey, policies);
    return {};
}

Poco::Dynamic::Var StoreApiVarInterface::deleteStore(const Poco::Dynamic::Var& args) {
    auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 1);
    auto storeId = _deserializer.deserialize<std::string>(argsArr->get(0), "storeId");
    _storeApi.deleteStore(storeId);
    return {};
}

Poco::Dynamic::Var StoreApiVarInterface::getStore(const Poco::Dynamic::Var& args) {
    auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 1);
    auto storeId = _deserializer.deserialize<std::string>(argsArr->get(0), "storeId");
    auto result = _storeApi.getStore(storeId);
    return _serializer.serialize(result);
}

Poco::Dynamic::Var StoreApiVarInterface::listStores(const Poco::Dynamic::Var& args) {
    auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 2);
    auto contextId = _deserializer.deserialize<std::string>(argsArr->get(0), "contextId");
    auto pagingQuery = _deserializer.deserialize<core::PagingQuery>(argsArr->get(1), "pagingQuery");
    auto result = _storeApi.listStores(contextId, pagingQuery);
    return _serializer.serialize(result);
}

Poco::Dynamic::Var StoreApiVarInterface::deleteFile(const Poco::Dynamic::Var& args) {
    auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 1);
    auto fileId = _deserializer.deserialize<std::string>(argsArr->get(0), "fileId");
    _storeApi.deleteFile(fileId);
    return {};
}

Poco::Dynamic::Var StoreApiVarInterface::createFile(const Poco::Dynamic::Var& args) {
    auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 4);
    auto storeId = _deserializer.deserialize<std::string>(argsArr->get(0), "storeId");
    auto publicMeta = _deserializer.deserialize<core::Buffer>(argsArr->get(1), "publicMeta");
    auto privateMeta = _deserializer.deserialize<core::Buffer>(argsArr->get(2), "privateMeta");
    auto size = _deserializer.deserialize<int64_t>(argsArr->get(3), "size");
    auto result = _storeApi.createFile(storeId, publicMeta, privateMeta, size);
    return _serializer.serialize(result);
}

Poco::Dynamic::Var StoreApiVarInterface::updateFile(const Poco::Dynamic::Var& args) {
    auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 4);
    auto storeId = _deserializer.deserialize<std::string>(argsArr->get(0), "storeId");
    auto publicMeta = _deserializer.deserialize<core::Buffer>(argsArr->get(1), "publicMeta");
    auto privateMeta = _deserializer.deserialize<core::Buffer>(argsArr->get(2), "privateMeta");
    auto size = _deserializer.deserialize<int64_t>(argsArr->get(3), "size");
    auto result = _storeApi.updateFile(storeId, publicMeta, privateMeta, size);
    return _serializer.serialize(result);
}

Poco::Dynamic::Var StoreApiVarInterface::writeToFile(const Poco::Dynamic::Var& args) {
    auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 2);
    auto fileHandle = _deserializer.deserialize<int64_t>(argsArr->get(0), "fileHandle");
    auto dataChunk = _deserializer.deserialize<core::Buffer>(argsArr->get(1), "dataChunk");
    _storeApi.writeToFile(fileHandle, dataChunk);
    return {};
}

Poco::Dynamic::Var StoreApiVarInterface::getFile(const Poco::Dynamic::Var& args) {
    auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 1);
    auto fileId = _deserializer.deserialize<std::string>(argsArr->get(0), "fileId");
    auto result = _storeApi.getFile(fileId);
    return _serializer.serialize(result);
}

Poco::Dynamic::Var StoreApiVarInterface::listFiles(const Poco::Dynamic::Var& args) {
    auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 2);
    auto storeId = _deserializer.deserialize<std::string>(argsArr->get(0), "storeId");
    auto pagingQuery = _deserializer.deserialize<core::PagingQuery>(argsArr->get(1), "pagingQuery");
    auto result = _storeApi.listFiles(storeId, pagingQuery);
    return _serializer.serialize(result);
}

Poco::Dynamic::Var StoreApiVarInterface::openFile(const Poco::Dynamic::Var& args) {
    auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 1);
    auto fileId = _deserializer.deserialize<std::string>(argsArr->get(0), "fileId");
    auto result = _storeApi.openFile(fileId);
    return _serializer.serialize(result);
}

Poco::Dynamic::Var StoreApiVarInterface::readFromFile(const Poco::Dynamic::Var& args) {
    auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 2);
    auto fileHandle = _deserializer.deserialize<int64_t>(argsArr->get(0), "fileHandle");
    auto length = _deserializer.deserialize<int64_t>(argsArr->get(1), "length");
    auto result = _storeApi.readFromFile(fileHandle, length);
    return _serializer.serialize(result);
}

Poco::Dynamic::Var StoreApiVarInterface::seekInFile(const Poco::Dynamic::Var& args) {
    auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 2);
    auto fileHandle = _deserializer.deserialize<int64_t>(argsArr->get(0), "fileHandle");
    auto position = _deserializer.deserialize<int64_t>(argsArr->get(1), "position");
    _storeApi.seekInFile(fileHandle, position);
    return {};
}

Poco::Dynamic::Var StoreApiVarInterface::closeFile(const Poco::Dynamic::Var& args) {
    auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 1);
    auto fileHandle = _deserializer.deserialize<int64_t>(argsArr->get(0), "fileHandle");
    auto result = _storeApi.closeFile(fileHandle);
    return _serializer.serialize(result);
}

Poco::Dynamic::Var StoreApiVarInterface::subscribeForStoreEvents(const Poco::Dynamic::Var& args) {
    core::VarInterfaceUtil::validateAndExtractArray(args, 0);
    _storeApi.subscribeForStoreEvents();
    return {};
}

Poco::Dynamic::Var StoreApiVarInterface::unsubscribeFromStoreEvents(const Poco::Dynamic::Var& args) {
    core::VarInterfaceUtil::validateAndExtractArray(args, 0);
    _storeApi.unsubscribeFromStoreEvents();
    return {};
}

Poco::Dynamic::Var StoreApiVarInterface::subscribeForFileEvents(const Poco::Dynamic::Var& args) {
    auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 1);
    auto storeId = _deserializer.deserialize<std::string>(argsArr->get(0), "storeId");
    _storeApi.subscribeForFileEvents(storeId);
    return {};
}

Poco::Dynamic::Var StoreApiVarInterface::unsubscribeFromFileEvents(const Poco::Dynamic::Var& args) {
    auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 1);
    auto storeId = _deserializer.deserialize<std::string>(argsArr->get(0), "storeId");
    _storeApi.unsubscribeFromFileEvents(storeId);
    return {};
}

Poco::Dynamic::Var StoreApiVarInterface::updateFileMeta(const Poco::Dynamic::Var& args) {
    auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 3);
    auto fileId = _deserializer.deserialize<std::string>(argsArr->get(0), "fileId");
    auto publicMeta = _deserializer.deserialize<core::Buffer>(argsArr->get(1), "publicMeta");
    auto privateMeta = _deserializer.deserialize<core::Buffer>(argsArr->get(2), "privateMeta");
    _storeApi.updateFileMeta(fileId, publicMeta, privateMeta);
    return {};
}

Poco::Dynamic::Var StoreApiVarInterface::exec(privmx_StoreApi_Method method, const Poco::Dynamic::Var& args) {
    auto it = methodMap.find(method);
    if (it == methodMap.end()) {
        throw core::InvalidMethodException();
    }
    return (*this.*(it->second))(args);
}
