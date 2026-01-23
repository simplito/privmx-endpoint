/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_ENDPOINT_SEARCH_SEARCHAPIVARINTERFACE_HPP_
#define _PRIVMXLIB_ENDPOINT_SEARCH_SEARCHAPIVARINTERFACE_HPP_

#include <Poco/Dynamic/Var.h>

#include "privmx/endpoint/core/VarDeserializer.hpp"
#include "privmx/endpoint/search/SearchApi.hpp"
#include "privmx/endpoint/search/VarSerializer.hpp"

namespace privmx {
namespace endpoint {
namespace search {

class SearchApiVarInterface {
public:
    enum METHOD {
        Create = 0,
        CreateSearchIndex = 1,
        UpdateSearchIndex = 2,
        DeleteSearchIndex = 3,
        GetSearchIndex = 4,
        ListSearchIndexes = 5,
        OpenSearchIndex = 6,
        CloseSearchIndex = 7,
        AddDocument = 8,
        UpdateDocument = 9,
        DeleteDocument = 10,
        GetDocument = 11,
        ListDocuments = 12,
        SearchDocuments = 13,
    };

    SearchApiVarInterface(core::Connection connection, store::StoreApi storeApi, kvdb::KvdbApi kvdbApi, const core::VarSerializer& serializer)
        : _connection(std::move(connection)), _storeApi(std::move(storeApi)), _kvdbApi(std::move(kvdbApi)), _serializer(serializer) {}

    Poco::Dynamic::Var create(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var createSearchIndex(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var updateSearchIndex(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var deleteSearchIndex(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var getSearchIndex(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var listSearchIndexes(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var openSearchIndex(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var closeSearchIndex(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var addDocument(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var updateDocument(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var deleteDocument(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var getDocument(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var listDocuments(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var searchDocuments(const Poco::Dynamic::Var& args);


    Poco::Dynamic::Var exec(METHOD method, const Poco::Dynamic::Var& args);

    SearchApi getApi() const { return _searchApi; }

private:
    static std::map<METHOD, Poco::Dynamic::Var (SearchApiVarInterface::*)(const Poco::Dynamic::Var&)> methodMap;

    core::Connection _connection;
    store::StoreApi _storeApi;
    kvdb::KvdbApi _kvdbApi;
    SearchApi _searchApi;
    core::VarDeserializer _deserializer;
    core::VarSerializer _serializer;
};

}  // namespace search
}  // namespace endpoint
}  // namespace privmx

#endif  // _PRIVMXLIB_ENDPOINT_SEARCH_SEARCHAPIVARINTERFACE_HPP_
