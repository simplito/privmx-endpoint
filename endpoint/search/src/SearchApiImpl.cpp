/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include "privmx/endpoint/search/SearchApiImpl.hpp"
#include "privmx/endpoint/search/PrivmxFS.hpp"
#include "privmx/utils/ThreadSaveMap.hpp"
#include "privmx/endpoint/search/SearchException.hpp"

#include "privmx/endpoint/search/DynamicTypes.hpp"
#include "privmx/utils/Utils.hpp"
#include "privmx/utils/TypedObject.hpp"

using namespace privmx::endpoint;
using namespace privmx::endpoint::search;

// struct IndexData
// {
//     IndexMode mode;
//     std::string storeId;
// };

core::Buffer serializeIndexData(const dynamic::IndexData& indexData) {
    return core::Buffer::from(privmx::utils::Utils::stringifyVar(indexData));
}

dynamic::IndexData deserializeIndexData(const core::Buffer& buf) {
    auto json = privmx::utils::Utils::parseJson(buf.stdString());
    return privmx::utils::TypedObjectFactory::createObjectFromVar<dynamic::IndexData>(json);
}

SearchApiImpl::SearchApiImpl(
        const core::Connection& connection,
        const store::StoreApi& storeApi,
        const kvdb::KvdbApi& kvdbApi
) {
    // _session = SessionManager::get()->addSession(connection, storeApi, kvdbApi);
    _connection = connection;
    _storeApi = storeApi;
    _kvdbApi = kvdbApi;
}

std::string SearchApiImpl::createSearchIndex(
    const std::string& contextId,
    const std::vector<core::UserWithPubKey>& users,
    const std::vector<core::UserWithPubKey>& managers,
    const core::Buffer& publicMeta,
    const core::Buffer& privateMeta,
    const IndexMode mode,
    const std::optional<core::ContainerPolicy>& policies
) {
    std::string indexId = _kvdbApi.createKvdb(contextId, users, managers, publicMeta, privateMeta, policies);
    std::string storeId = _storeApi.createStore(contextId, users, managers, {}, {}, policies);
    setIndexData(indexId, storeId, mode);
    l("Created KVDB", indexId);
    return indexId;
}

void SearchApiImpl::updateSearchIndex(
    const std::string& indexId,
    const std::vector<core::UserWithPubKey>& users,
    const std::vector<core::UserWithPubKey>& managers,
    const core::Buffer& publicMeta,
    const core::Buffer& privateMeta,
    const int64_t version,
    const bool force,
    const bool forceGenerateNewKey,
    const std::optional<core::ContainerPolicy>& policies
) {
    auto data = getIndexData(indexId);
    _kvdbApi.updateKvdb(indexId, users, managers, publicMeta, privateMeta, version, force, forceGenerateNewKey, policies);
    _storeApi.updateStore(data.storeId(), users, managers, {}, {}, version, force, forceGenerateNewKey, policies);
}

void SearchApiImpl::deleteSearchIndex(const std::string& indexId) {
    auto data = getIndexData(indexId);
    _kvdbApi.deleteKvdb(indexId);
    _storeApi.deleteStore(data.storeId());
}

int64_t SearchApiImpl::openSearchIndex(const std::string& indexId) {
    auto data = getIndexData(indexId);
    auto session = SessionManager::get()->addSession(_connection, _storeApi, _kvdbApi, indexId, data.storeId());
    std::string filename = "/pmx/" + session->id + "/index.db";
    std::cerr << filename << std::endl;
    auto fts = FullTextSearch::openDb(filename);
    fts->ensureTableCreated();
    return _fts.add(fts);
}

void SearchApiImpl::closeSearchIndex(const int64_t indexHandle) {
    l("open", indexHandle);
    auto fts = _fts.get(indexHandle);
    fts->close();
    _fts.remove(indexHandle);
}

int64_t SearchApiImpl::addDocument(const int64_t indexHandle, const std::string& name, const std::string& content) {
    auto fts = _fts.get(indexHandle);
    fts->addDocument(name, content);
    return 1;
}

void SearchApiImpl::updateDocument(const int64_t indexHandle, const Document& document) {
    auto fts = _fts.get(indexHandle);
    // fts->updateDocument(document);
}

void SearchApiImpl::deleteDocument(const int64_t indexHandle, int64_t documentId) {
    auto fts = _fts.get(indexHandle);
    // fts->deleteDocument(documentId);
}

core::PagingList<Document> SearchApiImpl::searchDocuments(const int64_t indexHandle, const std::string& searchQuery, const core::PagingQuery& pagingQuery) {
    auto fts = _fts.get(indexHandle);
    core::PagingList<Document> result;
    auto list = fts->search(searchQuery);
    for (auto& id : list) {
        result.readItems.push_back(id);
    }
    return result;
}

dynamic::IndexData SearchApiImpl::getIndexData(const std::string& indexId) {
    auto data = _kvdbApi.getEntry(indexId, "data");
    return deserializeIndexData(data.data);
}

void SearchApiImpl::setIndexData(const std::string& indexId, const std::string& storeId, const IndexMode mode) {
    auto indexData = privmx::utils::TypedObjectFactory::createNewObject<dynamic::IndexData>();
    indexData.storeId(storeId);
    indexData.mode(mode);
    _kvdbApi.setEntry(indexId, "data", {}, {}, serializeIndexData(indexData));
}
