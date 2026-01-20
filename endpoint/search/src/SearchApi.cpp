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

SearchApi SearchApi::create(core::Connection& connection, store::StoreApi& storeApi, kvdb::KvdbApi& kvdbApi) {
    try {
        std::shared_ptr<SearchApiImpl> impl = std::make_shared<SearchApiImpl>(
            connection,
            storeApi,
            kvdbApi
        );
        return SearchApi(impl);
    }  catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

SearchApi::SearchApi(const std::shared_ptr<SearchApiImpl>& impl) : _impl(impl) {}

std::string SearchApi::createSearchIndex(
    const std::string& contextId,
    const std::vector<core::UserWithPubKey>& users,
    const std::vector<core::UserWithPubKey>& managers,
    const core::Buffer& publicMeta,
    const core::Buffer& privateMeta,
    const IndexMode mode,
    const std::optional<core::ContainerPolicy>& policies
) {
    validateEndpoint();
    core::Validator::validateId(contextId, "field:contextId ");
    core::Validator::validateClass<std::vector<core::UserWithPubKey>>(users, "field:users ");
    core::Validator::validateClass<std::vector<core::UserWithPubKey>>(managers, "field:managers ");
    try {
        return _impl->createSearchIndex(contextId, users, managers, publicMeta, privateMeta, mode, policies);
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
    validateEndpoint();
    core::Validator::validateId(indexId, "field:indexId ");
    core::Validator::validateClass<std::vector<core::UserWithPubKey>>(users, "field:users ");
    core::Validator::validateClass<std::vector<core::UserWithPubKey>>(managers, "field:managers ");
    try {
        _impl->updateSearchIndex(indexId, users, managers, publicMeta, privateMeta, version, force, forceGenerateNewKey, policies);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

void SearchApi::deleteSearchIndex(const std::string& indexId) {
    validateEndpoint();
    core::Validator::validateId(indexId, "field:indexId ");
    try {
        return _impl->deleteSearchIndex(indexId);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

SearchIndex SearchApi::getSearchIndex(const std::string& indexId) {
    validateEndpoint();
    core::Validator::validateId(indexId, "field:indexId ");
    try {
        return _impl->getSearchIndex(indexId);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

core::PagingList<SearchIndex> SearchApi::listSearchIndexes(const std::string& contextId, const core::PagingQuery& pagingQuery) {
    validateEndpoint();
    core::Validator::validateId(contextId, "field:contextId ");
    core::Validator::validatePagingQuery(pagingQuery, {}, "field:pagingQuery ");
    try {
        return _impl->listSearchIndexes(contextId, pagingQuery);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

int64_t SearchApi::openSearchIndex(const std::string& indexId) {
    validateEndpoint();
    core::Validator::validateId(indexId, "field:indexId ");
    try {
        return _impl->openSearchIndex(indexId);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

void SearchApi::closeSearchIndex(const int64_t indexHandle) {
    validateEndpoint();
    try {
        return _impl->closeSearchIndex(indexHandle);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

int64_t SearchApi::addDocument(const int64_t indexHandle, const std::string& name, const std::string& content) {
    validateEndpoint();
    try {
        return _impl->addDocument(indexHandle, name, content);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

void SearchApi::updateDocument(const int64_t indexHandle, const Document& document) {
    validateEndpoint();
    try {
        return _impl->updateDocument(indexHandle, document);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

void SearchApi::deleteDocument(const int64_t indexHandle, int64_t documentId) {
    validateEndpoint();
    try {
        return _impl->deleteDocument(indexHandle, documentId);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

Document SearchApi::getDocument(const int64_t indexHandle, const int64_t documentId) {
    validateEndpoint();
    try {
        return _impl->getDocument(indexHandle, documentId);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

core::PagingList<Document> SearchApi::listDocuments(const int64_t indexHandle, const core::PagingQuery& pagingQuery) {
    validateEndpoint();
    core::Validator::validatePagingQuery(pagingQuery, {}, "field:pagingQuery ");
    try {
        return _impl->listDocuments(indexHandle, pagingQuery);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

core::PagingList<Document> SearchApi::searchDocuments(const int64_t indexHandle, const std::string& searchQuery, const core::PagingQuery& pagingQuery) {
    validateEndpoint();
    core::Validator::validatePagingQuery(pagingQuery, {}, "field:pagingQuery ");
    try {
        return _impl->searchDocuments(indexHandle, searchQuery, pagingQuery);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

void SearchApi::validateEndpoint() {
    if (!_impl) throw NotInitializedException();
}
