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

std::map<StoreApiVarInterface::METHOD, Poco::Dynamic::Var (StoreApiVarInterface::*)(const Poco::Dynamic::Var&)>
    StoreApiVarInterface::methodMap = {{Create, &StoreApiVarInterface::create},
                                       {CreateStore, &StoreApiVarInterface::createStore},
                                       {UpdateStore, &StoreApiVarInterface::updateStore},
                                       {DeleteStore, &StoreApiVarInterface::deleteStore},
                                       {GetStore, &StoreApiVarInterface::getStore},
                                       {ListStores, &StoreApiVarInterface::listStores},
                                       {CreateFile, &StoreApiVarInterface::createFile},
                                       {UpdateFile, &StoreApiVarInterface::updateFile},
                                       {UpdateFileMeta, &StoreApiVarInterface::updateFileMeta},
                                       {WriteToFile, &StoreApiVarInterface::writeToFile},
                                       {DeleteFile, &StoreApiVarInterface::deleteFile},
                                       {GetFile, &StoreApiVarInterface::getFile},
                                       {ListFiles, &StoreApiVarInterface::listFiles},
                                       {OpenFile, &StoreApiVarInterface::openFile},
                                       {ReadFromFile, &StoreApiVarInterface::readFromFile},
                                       {SeekInFile, &StoreApiVarInterface::seekInFile},
                                       {CloseFile, &StoreApiVarInterface::closeFile},
                                       {SubscribeFor, &StoreApiVarInterface::subscribeFor},
                                       {UnsubscribeFrom, &StoreApiVarInterface::unsubscribeFrom},
                                       {BuildSubscriptionQuery, &StoreApiVarInterface::buildSubscriptionQuery}};


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

Poco::Dynamic::Var StoreApiVarInterface::updateFileMeta(const Poco::Dynamic::Var& args) {
    auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 3);
    auto fileId = _deserializer.deserialize<std::string>(argsArr->get(0), "fileId");
    auto publicMeta = _deserializer.deserialize<core::Buffer>(argsArr->get(1), "publicMeta");
    auto privateMeta = _deserializer.deserialize<core::Buffer>(argsArr->get(2), "privateMeta");
    _storeApi.updateFileMeta(fileId, publicMeta, privateMeta);
    return {};
}

Poco::Dynamic::Var StoreApiVarInterface::subscribeFor(const Poco::Dynamic::Var& args) {
    auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 1);
    auto subscriptionQueries = _deserializer.deserializeVector<std::string>(argsArr->get(0), "subscriptionQueries");
    auto result = _storeApi.subscribeFor(subscriptionQueries);
    return _serializer.serialize(result);
}

Poco::Dynamic::Var StoreApiVarInterface::unsubscribeFrom(const Poco::Dynamic::Var& args) {
    auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 1);
    auto subscriptionIds = _deserializer.deserializeVector<std::string>(argsArr->get(0), "subscriptionIds");
    _storeApi.unsubscribeFrom(subscriptionIds);
    return {};
}

Poco::Dynamic::Var StoreApiVarInterface::buildSubscriptionQuery(const Poco::Dynamic::Var& args) {
    auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 3);
    auto eventType = _deserializer.deserialize<store::EventType>(argsArr->get(0), "eventType");
    auto selectorType = _deserializer.deserialize<store::EventSelectorType>(argsArr->get(1), "selectorType");
    auto selectorId = _deserializer.deserialize<std::string>(argsArr->get(2), "selectorId");
    auto result = _storeApi.buildSubscriptionQuery(eventType, selectorType, selectorId);
    return _serializer.serialize(result);
}

Poco::Dynamic::Var StoreApiVarInterface::exec(METHOD method, const Poco::Dynamic::Var& args) {
    auto it = methodMap.find(method);
    if (it == methodMap.end()) {
        throw core::InvalidMethodException();
    }
    return (*this.*(it->second))(args);
}
