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
#include <privmx/endpoint/core/ExceptionConverter.hpp>

#include "privmx/endpoint/search/SearchApi.hpp"
#include "privmx/endpoint/search/SearchApiImpl.hpp"
#include "privmx/endpoint/search/SearchException.hpp"
#include "privmx/endpoint/core/Validator.hpp"

using namespace privmx::endpoint;
using namespace privmx::endpoint::search;

SearchApi::SearchApi() {};
SearchApi::SearchApi(const SearchApi& obj): ExtendedPointer(obj) {};
SearchApi& SearchApi::operator=(const SearchApi& obj) {
    this->ExtendedPointer::operator=(obj);
    return *this;
};
SearchApi::SearchApi(SearchApi&& obj): ExtendedPointer(std::move(obj)) {};
SearchApi::~SearchApi() {}

SearchApi SearchApi::create(core::Connection& connection, store::StoreApi& storeApi, kvdb::KvdbApi& kvdbApi) {
    try {
        std::shared_ptr<SearchApiImpl> impl = std::make_shared<SearchApiImpl>(
            connection,
            storeApi,
            kvdbApi
        );
        impl->attach(impl);
        return SearchApi(impl);
    }  catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

SearchApi::SearchApi(const std::shared_ptr<SearchApiImpl>& impl) : ExtendedPointer(impl) {}

std::string SearchApi::createSearchIndex(
    const std::string& contextId,
    const std::vector<core::UserWithPubKey>& users,
    const std::vector<core::UserWithPubKey>& managers,
    const core::Buffer& publicMeta,
    const core::Buffer& privateMeta,
    const IndexMode mode,
    const std::optional<core::ContainerPolicy>& policies
) {
    auto impl = getImpl();
    core::Validator::validateId(contextId, "field:contextId ");
    core::Validator::validateClass<std::vector<core::UserWithPubKey>>(users, "field:users ");
    core::Validator::validateClass<std::vector<core::UserWithPubKey>>(managers, "field:managers ");
    core::Validator::validateEnum<IndexMode>(mode, {IndexMode::WITH_CONTENT, IndexMode::WITHOUT_CONTENT}, "field:mode");
    try {
        return impl->createSearchIndex(contextId, users, managers, publicMeta, privateMeta, mode, policies);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
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
    const std::optional<core::ContainerPolicy>& policies
) {
    auto impl = getImpl();
    core::Validator::validateId(indexId, "field:indexId ");
    core::Validator::validateClass<std::vector<core::UserWithPubKey>>(users, "field:users ");
    core::Validator::validateClass<std::vector<core::UserWithPubKey>>(managers, "field:managers ");
    try {
        impl->updateSearchIndex(indexId, users, managers, publicMeta, privateMeta, version, force, forceGenerateNewKey, policies);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

void SearchApi::deleteSearchIndex(const std::string& indexId) {
    auto impl = getImpl();
    core::Validator::validateId(indexId, "field:indexId ");
    try {
        return impl->deleteSearchIndex(indexId);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

SearchIndex SearchApi::getSearchIndex(const std::string& indexId) {
    auto impl = getImpl();
    core::Validator::validateId(indexId, "field:indexId ");
    try {
        return impl->getSearchIndex(indexId);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

core::PagingList<SearchIndex> SearchApi::listSearchIndexes(const std::string& contextId, const core::PagingQuery& pagingQuery) {
    auto impl = getImpl();
    core::Validator::validateId(contextId, "field:contextId ");
    core::Validator::validatePagingQuery(pagingQuery, {}, "field:pagingQuery ");
    try {
        return impl->listSearchIndexes(contextId, pagingQuery);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

int64_t SearchApi::openSearchIndex(const std::string& indexId) {
    auto impl = getImpl();
    core::Validator::validateId(indexId, "field:indexId ");
    try {
        return impl->openSearchIndex(indexId);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

void SearchApi::closeSearchIndex(const int64_t indexHandle) {
    auto impl = getImpl();
    try {
        return impl->closeSearchIndex(indexHandle);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

int64_t SearchApi::addDocument(const int64_t indexHandle, const std::string& name, const std::string& content) {
    auto impl = getImpl();
    try {
        return impl->addDocument(indexHandle, name, content);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

std::vector<int64_t> SearchApi::addDocuments(const int64_t indexHandle, const std::vector<NewDocument>& documents) {
    auto impl = getImpl();
    try {
        return impl->addDocuments(indexHandle, documents);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

void SearchApi::updateDocument(const int64_t indexHandle, const Document& document) {
    auto impl = getImpl();
    try {
        return impl->updateDocument(indexHandle, document);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

void SearchApi::deleteDocument(const int64_t indexHandle, int64_t documentId) {
    auto impl = getImpl();
    try {
        return impl->deleteDocument(indexHandle, documentId);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

Document SearchApi::getDocument(const int64_t indexHandle, const int64_t documentId) {
    auto impl = getImpl();
    try {
        return impl->getDocument(indexHandle, documentId);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

core::PagingList<Document> SearchApi::listDocuments(const int64_t indexHandle, const core::PagingQuery& pagingQuery) {
    auto impl = getImpl();
    core::Validator::validatePagingQuery(pagingQuery, {}, "field:pagingQuery ");
    try {
        return impl->listDocuments(indexHandle, pagingQuery);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

core::PagingList<Document> SearchApi::searchDocuments(const int64_t indexHandle, const std::string& searchQuery, const core::PagingQuery& pagingQuery) {
    auto impl = getImpl();
    core::Validator::validatePagingQuery(pagingQuery, {}, "field:pagingQuery ");
    try {
        return impl->searchDocuments(indexHandle, searchQuery, pagingQuery);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}
