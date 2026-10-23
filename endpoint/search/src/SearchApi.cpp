/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/
#include <privmx/endpoint/core/Exception.hpp>
#include <privmx/endpoint/core/JsonSerializer.hpp>

#include "privmx/endpoint/core/Validator.hpp"
#include "privmx/endpoint/search/SearchApi.hpp"
#include "privmx/endpoint/search/SearchApiImpl.hpp"
#include "privmx/endpoint/search/SearchException.hpp"

using namespace privmx::endpoint;
using namespace privmx::endpoint::search;

SearchApi::SearchApi() {};
SearchApi::SearchApi(const SearchApi& obj) : BaseApiClass(obj) {};
SearchApi& SearchApi::operator=(const SearchApi& obj) {
    this->BaseApiClass::operator=(obj);
    return *this;
};
SearchApi::SearchApi(SearchApi&& obj) : BaseApiClass(std::move(obj)) {};
SearchApi::~SearchApi() {}

SearchApi SearchApi::create(
    core::Connection& connection,
    store::StoreApi& storeApi,
    kvdb::KvdbApi& kvdbApi,
    lock::LockApi& lockApi
) {
    std::shared_ptr<SearchApiImpl> impl = std::make_shared<SearchApiImpl>(connection, storeApi, kvdbApi, lockApi);
    return SearchApi(impl);
}

SearchApi::SearchApi(const std::shared_ptr<SearchApiImpl>& impl) : BaseApiClass(impl) {}

std::string SearchApi::createSearchIndex(
    const std::string& contextId,
    const std::vector<core::UserWithPubKey>& users,
    const std::vector<core::UserWithPubKey>& managers,
    const core::Buffer& publicMeta,
    const core::Buffer& privateMeta,
    const IndexMode mode,
    const std::optional<core::ContainerPolicy>& policies,
    const std::vector<core::GroupGrantWithKey>& groups
) {
    auto impl = getImpl();
    core::Validator::validateId(contextId, "field:contextId ");
    core::Validator::validateClass<std::vector<core::UserWithPubKey>>(users, "field:users ");
    core::Validator::validateClass<std::vector<core::UserWithPubKey>>(managers, "field:managers ");
    core::Validator::validateEnum<IndexMode>(mode, {IndexMode::WITH_CONTENT, IndexMode::WITHOUT_CONTENT}, "field:mode");
    core::Validator::validateClass<std::vector<core::GroupGrantWithKey>>(groups, "field:groups ");
    return impl->createSearchIndex(contextId, users, managers, publicMeta, privateMeta, mode, policies, groups);
}

void SearchApi::updateSearchIndex(
    const std::string& indexId,
    const std::vector<core::UserWithPubKey>& users,
    const std::vector<core::UserWithPubKey>& managers,
    const core::Buffer& publicMeta,
    const core::Buffer& privateMeta,
    const int64_t version,
    const bool force,
    const bool forceGenerateNewKey,
    const std::optional<core::ContainerPolicy>& policies,
    const std::vector<core::GroupGrantWithKey>& groups
) {
    auto impl = getImpl();
    core::Validator::validateId(indexId, "field:indexId ");
    core::Validator::validateClass<std::vector<core::UserWithPubKey>>(users, "field:users ");
    core::Validator::validateClass<std::vector<core::UserWithPubKey>>(managers, "field:managers ");
    core::Validator::validateClass<std::vector<core::GroupGrantWithKey>>(groups, "field:groups ");
    impl->updateSearchIndex(
        indexId, users, managers, publicMeta, privateMeta, version, force, forceGenerateNewKey, policies, groups
    );
}

void SearchApi::rotateSearchIndexKeys(
    const std::string& indexId,
    const std::vector<core::UserWithPubKey>& users,
    const std::vector<core::UserWithPubKey>& managers,
    const int64_t version,
    const bool force,
    const std::vector<core::GroupGrantWithKey>& groups
) {
    auto impl = getImpl();
    core::Validator::validateId(indexId, "field:indexId ");
    core::Validator::validateClass<std::vector<core::UserWithPubKey>>(users, "field:users ");
    core::Validator::validateClass<std::vector<core::UserWithPubKey>>(managers, "field:managers ");
    core::Validator::validateClass<std::vector<core::GroupGrantWithKey>>(groups, "field:groups ");
    impl->rotateSearchIndexKeys(indexId, users, managers, version, force, groups);
}

void SearchApi::deleteSearchIndex(const std::string& indexId) {
    auto impl = getImpl();
    core::Validator::validateId(indexId, "field:indexId ");
    return impl->deleteSearchIndex(indexId);
}

SearchIndex SearchApi::getSearchIndex(const std::string& indexId) {
    auto impl = getImpl();
    core::Validator::validateId(indexId, "field:indexId ");
    return impl->getSearchIndex(indexId);
}

core::PagingList<SearchIndex> SearchApi::listSearchIndexes(
    const std::string& contextId,
    const core::PagingQuery& pagingQuery
) {
    auto impl = getImpl();
    core::Validator::validateId(contextId, "field:contextId ");
    core::Validator::validatePagingQuery(pagingQuery, {}, "field:pagingQuery ");
    return impl->listSearchIndexes(contextId, pagingQuery);
}

int64_t SearchApi::openSearchIndex(const std::string& indexId) {
    auto impl = getImpl();
    core::Validator::validateId(indexId, "field:indexId ");
    return impl->openSearchIndex(indexId);
}

void SearchApi::closeSearchIndex(const int64_t indexHandle) {
    auto impl = getImpl();
    return impl->closeSearchIndex(indexHandle);
}

void SearchApi::beginTransaction(const int64_t indexHandle) {
    auto impl = getImpl();
    impl->beginTransaction(indexHandle);
}

void SearchApi::commit(const int64_t indexHandle) {
    auto impl = getImpl();
    impl->commit(indexHandle);
}

void SearchApi::rollback(const int64_t indexHandle) {
    auto impl = getImpl();
    impl->rollback(indexHandle);
}

int64_t SearchApi::addDocument(const int64_t indexHandle, const std::string& name, const std::string& content) {
    auto impl = getImpl();
    return impl->addDocument(indexHandle, name, content);
}

void SearchApi::updateDocument(const int64_t indexHandle, const Document& document) {
    auto impl = getImpl();
    return impl->updateDocument(indexHandle, document);
}

void SearchApi::deleteDocument(const int64_t indexHandle, int64_t documentId) {
    auto impl = getImpl();
    return impl->deleteDocument(indexHandle, documentId);
}

Document SearchApi::getDocument(const int64_t indexHandle, const int64_t documentId) {
    auto impl = getImpl();
    return impl->getDocument(indexHandle, documentId);
}

core::PagingList<Document> SearchApi::listDocuments(const int64_t indexHandle, const core::PagingQuery& pagingQuery) {
    auto impl = getImpl();
    core::Validator::validatePagingQuery(pagingQuery, {}, "field:pagingQuery ");
    return impl->listDocuments(indexHandle, pagingQuery);
}

core::PagingList<Document> SearchApi::searchDocuments(
    const int64_t indexHandle,
    const std::string& searchQuery,
    const core::PagingQuery& pagingQuery
) {
    auto impl = getImpl();
    core::Validator::validatePagingQuery(pagingQuery, {}, "field:pagingQuery ");
    return impl->searchDocuments(indexHandle, searchQuery, pagingQuery);
}
