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

#include "privmx/endpoint/store/StoreApiImpl.hpp"
#include "privmx/endpoint/kvdb/KvdbApiImpl.hpp"

using namespace privmx::endpoint;
using namespace privmx::endpoint::search;

const std::string SearchApiImpl::SEARCH_TYPE_FILTER_FLAG = "search";

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
    _connection = connection;
    _storeApi = storeApi;
    _kvdbApi = kvdbApi;
}

SearchApiImpl::~SearchApiImpl() { }

std::string SearchApiImpl::createSearchIndex(
    const std::string& contextId,
    const std::vector<core::UserWithPubKey>& users,
    const std::vector<core::UserWithPubKey>& managers,
    const core::Buffer& publicMeta,
    const core::Buffer& privateMeta,
    const IndexMode mode,
    const std::optional<core::ContainerPolicy>& policies
) {
    std::string indexId = _kvdbApi.getImpl()->createKvdbEx(contextId, users, managers, publicMeta, privateMeta, SEARCH_TYPE_FILTER_FLAG, policies);
    std::string storeId = _storeApi.getImpl()->createStoreEx(contextId, users, managers, {}, {}, SEARCH_TYPE_FILTER_FLAG, policies);
    setIndexData(indexId, storeId, mode);
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
    _kvdbApi.getImpl()->updateKvdb(indexId, users, managers, publicMeta, privateMeta, version, force, forceGenerateNewKey, policies);
    _storeApi.getImpl()->updateStore(data.storeId(), users, managers, {}, {}, version, force, forceGenerateNewKey, policies);
}

void SearchApiImpl::deleteSearchIndex(const std::string& indexId) {
    auto data = getIndexData(indexId);
    _kvdbApi.getImpl()->deleteKvdb(indexId);
    _storeApi.getImpl()->deleteStore(data.storeId());
}

SearchIndex SearchApiImpl::getSearchIndex(const std::string& indexId) {
    auto kvdb = _kvdbApi.getImpl()->getKvdbEx(indexId, SEARCH_TYPE_FILTER_FLAG);
    return mapSearchIndex(kvdb);
}

core::PagingList<SearchIndex> SearchApiImpl::listSearchIndexes(const std::string& contextId, const core::PagingQuery& pagingQuery) {
    auto kvdbs = _kvdbApi.getImpl()->listKvdbsEx(contextId, pagingQuery, SEARCH_TYPE_FILTER_FLAG);
    return { .totalAvailable = kvdbs.totalAvailable, mapSearchIndexes(kvdbs.readItems) };
}

int64_t SearchApiImpl::openSearchIndex(const std::string& indexId) {
    auto data = getIndexData(indexId);
    auto session = SessionManager::get()->addSession(_connection, _storeApi, _kvdbApi, indexId, data.storeId());
    std::string filename = "/pmx/" + session->id + "/index.db";
    auto fts = FullTextSearch::openDb(filename, (IndexMode)data.mode());
    fts->ensureTableCreated();
    return _fts.add(fts);
}

void SearchApiImpl::closeSearchIndex(const int64_t indexHandle) {
    auto fts = _fts.get(indexHandle);
    fts->close();
    _fts.remove(indexHandle);
}

int64_t SearchApiImpl::addDocument(const int64_t indexHandle, const std::string& name, const std::string& content) {
    auto fts = _fts.get(indexHandle);
    return fts->addDocument(name, content);
}

void SearchApiImpl::updateDocument(const int64_t indexHandle, const Document& document) {
    auto fts = _fts.get(indexHandle);
    fts->updateDocument(document);
}

void SearchApiImpl::deleteDocument(const int64_t indexHandle, int64_t documentId) {
    auto fts = _fts.get(indexHandle);
    fts->deleteDocument(documentId);
}

Document SearchApiImpl::getDocument(const int64_t indexHandle, const int64_t documentId) {
    auto fts = _fts.get(indexHandle);
    return fts->getDocument(documentId);
}

core::PagingList<Document> SearchApiImpl::listDocuments(const int64_t indexHandle, const core::PagingQuery& pagingQuery) {
    auto fts = _fts.get(indexHandle);
    return fts->listDocuments(pagingQuery);
}

core::PagingList<Document> SearchApiImpl::searchDocuments(const int64_t indexHandle, const std::string& searchQuery, const core::PagingQuery& pagingQuery) {
    auto fts = _fts.get(indexHandle);
    core::PagingList<Document> result;
    return fts->search(searchQuery, pagingQuery);
}

dynamic::IndexData SearchApiImpl::getIndexData(const std::string& indexId) {
    auto data = _kvdbApi.getImpl()->getEntry(indexId, "data");
    return deserializeIndexData(data.data);
}

void SearchApiImpl::setIndexData(const std::string& indexId, const std::string& storeId, const IndexMode mode) {
    auto indexData = privmx::utils::TypedObjectFactory::createNewObject<dynamic::IndexData>();
    indexData.storeId(storeId);
    indexData.mode(mode);
    _kvdbApi.getImpl()->setEntry(indexId, "data", {}, {}, serializeIndexData(indexData), 0);
}

SearchIndex SearchApiImpl::mapSearchIndex(const kvdb::Kvdb& kvdb) {
    return SearchIndex {
        .contextId = kvdb.contextId,
        .indexId = kvdb.kvdbId,
        .createDate = kvdb.createDate,
        .creator = kvdb.creator,
        .lastModificationDate = kvdb.lastModificationDate,
        .lastModifier = kvdb.lastModifier,
        .users = kvdb.users,
        .managers = kvdb.managers,
        .version = kvdb.version,
        .publicMeta = kvdb.publicMeta,
        .privateMeta = kvdb.privateMeta,
        .policy = kvdb.policy,
        .mode = (IndexMode)getIndexData(kvdb.kvdbId).mode(),
        .statusCode = kvdb.statusCode
    };
}

std::vector<SearchIndex> SearchApiImpl::mapSearchIndexes(const std::vector<kvdb::Kvdb>& kvdbs) {
    std::vector<SearchIndex> results;
    results.resize(kvdbs.size());
    for (std::size_t i = 0; i < kvdbs.size(); ++i) {
        results[i] = mapSearchIndex(kvdbs[i]);
    }
    return results;
}
