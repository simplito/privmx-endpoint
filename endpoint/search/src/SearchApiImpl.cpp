/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include "privmx/endpoint/search/SearchApiImpl.hpp"

using namespace privmx::endpoint;
using namespace privmx::endpoint::search;

SearchApiImpl::SearchApiImpl(
        // const core::Connection& connection,
        // const store::StoreApi& storeApi,
        // const kvdb::KvdbApi& kvdbApi
) {

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
    return "X";
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

}

void SearchApiImpl::deleteSearchIndex(const std::string& indexId) {

}

int64_t SearchApiImpl::openSearchIndex(const std::string& indexId) {
    _fts = FullTextSearch::openDb("x");
    _fts->ensureTableCreated();
    return 1; // TODO
}

void SearchApiImpl::closeSearchIndex(const int64_t indexHandle) {
}

int64_t SearchApiImpl::addDocument(const int64_t indexHandle, const std::string& name, const std::string& content) {
    _fts->addDocument(name, content);
    return 1;
}

void SearchApiImpl::updateDocument(const int64_t indexHandle, const Document& document) {

}

void SearchApiImpl::deleteDocument(const int64_t indexHandle, int64_t documentId) {

}

core::PagingList<Document> SearchApiImpl::searchDocuments(const int64_t indexHandle, const std::string& searchQuery, const core::PagingQuery& pagingQuery) {
    core::PagingList<Document> result;
    auto list = _fts->search(searchQuery);
    for (auto& id : list) {
        result.readItems.push_back(id);
    }
    return result;
}
