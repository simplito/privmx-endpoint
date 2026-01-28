/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include "privmx/endpoint/search/varinterface/SearchApiVarInterface.hpp"

#include "privmx/endpoint/core/CoreException.hpp"
#include "privmx/endpoint/search/VarDeserializer.hpp"
#include "privmx/endpoint/core/varinterface/VarInterfaceUtil.hpp"
#include "privmx/endpoint/search/VarSerializer.hpp"

using namespace privmx::endpoint;
using namespace privmx::endpoint::search;

std::map<SearchApiVarInterface::METHOD, Poco::Dynamic::Var (SearchApiVarInterface::*)(const Poco::Dynamic::Var&)>
    SearchApiVarInterface::methodMap = {{Create, &SearchApiVarInterface::create},
                                        {CreateSearchIndex, &SearchApiVarInterface::createSearchIndex},
                                        {UpdateSearchIndex, &SearchApiVarInterface::updateSearchIndex},
                                        {DeleteSearchIndex, &SearchApiVarInterface::deleteSearchIndex},
                                        {GetSearchIndex, &SearchApiVarInterface::getSearchIndex},
                                        {ListSearchIndexes, &SearchApiVarInterface::listSearchIndexes},
                                        {OpenSearchIndex, &SearchApiVarInterface::openSearchIndex},
                                        {CloseSearchIndex, &SearchApiVarInterface::closeSearchIndex},
                                        {AddDocument, &SearchApiVarInterface::addDocument},
                                        {UpdateDocument, &SearchApiVarInterface::updateDocument},
                                        {DeleteDocument, &SearchApiVarInterface::deleteDocument},
                                        {GetDocument, &SearchApiVarInterface::getDocument},
                                        {ListDocuments, &SearchApiVarInterface::listDocuments},
                                        {SearchDocuments, &SearchApiVarInterface::searchDocuments}};

Poco::Dynamic::Var SearchApiVarInterface::create(const Poco::Dynamic::Var& args) {
    core::VarInterfaceUtil::validateAndExtractArray(args, 0);
    _searchApi = SearchApi::create(_connection, _storeApi, _kvdbApi);
    return {};
}

Poco::Dynamic::Var SearchApiVarInterface::createSearchIndex(const Poco::Dynamic::Var& args) {
    auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 7);
    auto contextId = _deserializer.deserialize<std::string>(argsArr->get(0), "contextId");
    auto users = _deserializer.deserializeVector<core::UserWithPubKey>(argsArr->get(1), "users");
    auto managers = _deserializer.deserializeVector<core::UserWithPubKey>(argsArr->get(2), "managers");
    auto publicMeta = _deserializer.deserialize<core::Buffer>(argsArr->get(3), "publicMeta");
    auto privateMeta = _deserializer.deserialize<core::Buffer>(argsArr->get(4), "privateMeta");
    auto mode = _deserializer.deserialize<search::IndexMode>(argsArr->get(5), "mode");
    auto policies = _deserializer.deserializeOptional<core::ContainerPolicy>(argsArr->get(6), "policies");
    auto result = _searchApi.createSearchIndex(contextId, users, managers, publicMeta, privateMeta, mode, policies);
    return _serializer.serialize(result);
}

Poco::Dynamic::Var SearchApiVarInterface::updateSearchIndex(const Poco::Dynamic::Var& args) {
    auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 9);
    auto indexId = _deserializer.deserialize<std::string>(argsArr->get(0), "indexId");
    auto users = _deserializer.deserializeVector<core::UserWithPubKey>(argsArr->get(1), "users");
    auto managers = _deserializer.deserializeVector<core::UserWithPubKey>(argsArr->get(2), "managers");
    auto publicMeta = _deserializer.deserialize<core::Buffer>(argsArr->get(3), "publicMeta");
    auto privateMeta = _deserializer.deserialize<core::Buffer>(argsArr->get(4), "privateMeta");
    auto version = _deserializer.deserialize<int64_t>(argsArr->get(5), "version");
    auto force = _deserializer.deserialize<bool>(argsArr->get(6), "force");
    auto forceGenerateNewKey = _deserializer.deserialize<bool>(argsArr->get(7), "forceGenerateNewKey");
    auto policies = _deserializer.deserializeOptional<core::ContainerPolicy>(argsArr->get(8), "policies");
    _searchApi.updateSearchIndex(indexId, users, managers, publicMeta, privateMeta, version, force, forceGenerateNewKey, policies);
    return {};
}

Poco::Dynamic::Var SearchApiVarInterface::deleteSearchIndex(const Poco::Dynamic::Var& args) {
    auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 1);
    auto indexId = _deserializer.deserialize<std::string>(argsArr->get(0), "indexId");
    _searchApi.deleteSearchIndex(indexId);
    return {};
}

Poco::Dynamic::Var SearchApiVarInterface::getSearchIndex(const Poco::Dynamic::Var& args) {
    auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 1);
    auto indexId = _deserializer.deserialize<std::string>(argsArr->get(0), "indexId");
    auto result = _searchApi.getSearchIndex(indexId);
    return _serializer.serialize(result);
}

Poco::Dynamic::Var SearchApiVarInterface::listSearchIndexes(const Poco::Dynamic::Var& args) {
    auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 2);
    auto contextId = _deserializer.deserialize<std::string>(argsArr->get(0), "contextId");
    auto pagingQuery = _deserializer.deserialize<core::PagingQuery>(argsArr->get(1), "pagingQuery");
    auto result = _searchApi.listSearchIndexes(contextId, pagingQuery);
    return _serializer.serialize(result);
}

Poco::Dynamic::Var SearchApiVarInterface::openSearchIndex(const Poco::Dynamic::Var& args) {
    auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 1);
    auto indexId = _deserializer.deserialize<std::string>(argsArr->get(0), "indexId");
    auto result = _searchApi.openSearchIndex(indexId);
    return _serializer.serialize(result);
}

Poco::Dynamic::Var SearchApiVarInterface::closeSearchIndex(const Poco::Dynamic::Var& args) {
    auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 1);
    auto indexHandle = _deserializer.deserialize<int64_t>(argsArr->get(0), "indexHandle");
    _searchApi.closeSearchIndex(indexHandle);
    return {};
}

Poco::Dynamic::Var SearchApiVarInterface::addDocument(const Poco::Dynamic::Var& args) {
    auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 3);
    auto indexHandle = _deserializer.deserialize<int64_t>(argsArr->get(0), "indexHandle");
    auto name = _deserializer.deserialize<std::string>(argsArr->get(1), "name");
    auto content = _deserializer.deserialize<std::string>(argsArr->get(2), "content");
    auto result = _searchApi.addDocument(indexHandle, name, content);
    return _serializer.serialize(result);
}

Poco::Dynamic::Var SearchApiVarInterface::updateDocument(const Poco::Dynamic::Var& args) {
    auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 2);
    auto indexHandle = _deserializer.deserialize<int64_t>(argsArr->get(0), "indexHandle");
    auto document = _deserializer.deserialize<search::Document>(argsArr->get(1), "document");
    _searchApi.updateDocument(indexHandle, document);
    return {};
}

Poco::Dynamic::Var SearchApiVarInterface::deleteDocument(const Poco::Dynamic::Var& args) {
    auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 2);
    auto indexHandle = _deserializer.deserialize<int64_t>(argsArr->get(0), "indexHandle");
    auto documentId = _deserializer.deserialize<int64_t>(argsArr->get(1), "documentId");
    _searchApi.deleteDocument(indexHandle, documentId);
    return {};
}

Poco::Dynamic::Var SearchApiVarInterface::getDocument(const Poco::Dynamic::Var& args) {
    auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 2);
    auto indexHandle = _deserializer.deserialize<int64_t>(argsArr->get(0), "indexHandle");
    auto documentId = _deserializer.deserialize<int64_t>(argsArr->get(1), "documentId");
    auto result = _searchApi.getDocument(indexHandle, documentId);
    return _serializer.serialize(result);
}

Poco::Dynamic::Var SearchApiVarInterface::listDocuments(const Poco::Dynamic::Var& args) {
    auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 2);
    auto indexHandle = _deserializer.deserialize<int64_t>(argsArr->get(0), "indexHandle");
    auto pagingQuery = _deserializer.deserialize<core::PagingQuery>(argsArr->get(1), "pagingQuery");
    auto result = _searchApi.listDocuments(indexHandle, pagingQuery);
    return _serializer.serialize(result);
}

Poco::Dynamic::Var SearchApiVarInterface::searchDocuments(const Poco::Dynamic::Var& args) {
    auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 3);
    auto indexHandle = _deserializer.deserialize<int64_t>(argsArr->get(0), "indexHandle");
    auto searchQuery = _deserializer.deserialize<std::string>(argsArr->get(1), "searchQuery");
    auto pagingQuery = _deserializer.deserialize<core::PagingQuery>(argsArr->get(2), "pagingQuery");
    auto result = _searchApi.searchDocuments(indexHandle, searchQuery, pagingQuery);
    return _serializer.serialize(result);
}

Poco::Dynamic::Var SearchApiVarInterface::exec(METHOD method, const Poco::Dynamic::Var& args) {
    auto it = methodMap.find(method);
    if (it == methodMap.end()) {
        throw core::InvalidMethodException();
    }
    return (*this.*(it->second))(args);
}
