/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/
#ifndef _PRIVMXLIB_ENDPOINT_SEARCH_SEARCHAPIIMPL_HPP_
#define _PRIVMXLIB_ENDPOINT_SEARCH_SEARCHAPIIMPL_HPP_

#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "privmx/endpoint/core/Connection.hpp"
#include "privmx/endpoint/store/StoreApi.hpp"
#include "privmx/endpoint/kvdb/KvdbApi.hpp"
#include "privmx/endpoint/core/Types.hpp"
#include "privmx/endpoint/search/Types.hpp"

#include "privmx/endpoint/search/FullTextSearch.hpp"

#include "privmx/utils/ThreadSaveMap.hpp"
#include "privmx/endpoint/search/SearchException.hpp"
#include "privmx/endpoint/search/DynamicTypes.hpp"
#include "privmx/endpoint/search/SearchTypes.hpp"

namespace privmx {
namespace endpoint {
namespace search {

class FtsContainer
{
    public:
    int64_t add(std::shared_ptr<FullTextSearch> fts) {
        int64_t handle = index++;
        _ftsMap.set(handle, fts);
        return handle;
    }

    void remove(int64_t handle) {
        _ftsMap.erase(handle);
    }

    std::shared_ptr<FullTextSearch> get(int64_t handle) {
        auto val = _ftsMap.get(handle);
        if (val.has_value()) {
            return val.value();
        }
        throw InvalidIndexHandleException();
    }

private:
    std::atomic<int64_t> index = 1;
    privmx::utils::ThreadSaveMap<int64_t, std::shared_ptr<FullTextSearch>> _ftsMap;
};

class SearchApiImpl
{
public:
    SearchApiImpl(
        const core::Connection& connection,
        const store::StoreApi& storeApi,
        const kvdb::KvdbApi& kvdbApi
    );

    std::string createSearchIndex(const std::string& contextId, const std::vector<core::UserWithPubKey>& users,
                                  const std::vector<core::UserWithPubKey>& managers, const core::Buffer& publicMeta,
                                  const core::Buffer& privateMeta, const IndexMode mode, const std::optional<core::ContainerPolicy>& policies = std::nullopt);

    void updateSearchIndex(const std::string& indexId, const std::vector<core::UserWithPubKey>& users,
                           const std::vector<core::UserWithPubKey>& managers, const core::Buffer& publicMeta, const core::Buffer& privateMeta,
                           const int64_t version, const bool force, const bool forceGenerateNewKey, const std::optional<core::ContainerPolicy>& policies = std::nullopt);

    void deleteSearchIndex(const std::string& indexId);

    SearchIndex getSearchIndex(const std::string& indexId);

    core::PagingList<SearchIndex> listSearchIndexes(const std::string& contextId, const core::PagingQuery& pagingQuery);

    int64_t openSearchIndex(const std::string& indexId);

    void closeSearchIndex(const int64_t indexHandle);

    int64_t addDocument(const int64_t indexHandle, const std::string& name, const std::string& content);

    void updateDocument(const int64_t indexHandle, const Document& document);

    void deleteDocument(const int64_t indexHandle, int64_t documentId);

    Document getDocument(const int64_t indexHandle, const int64_t documentId);

    core::PagingList<Document> listDocuments(const std::string& indexId, const core::PagingQuery& pagingQuery);

    core::PagingList<Document> searchDocuments(const int64_t indexHandle, const std::string& searchQuery, const core::PagingQuery& pagingQuery);

private:
    dynamic::IndexData getIndexData(const std::string& indexId);
    void setIndexData(const std::string& indexId, const std::string& storeId, const IndexMode mode);

    std::shared_ptr<PrivmxSession> _session;
    core::Connection _connection;
    store::StoreApi _storeApi;
    kvdb::KvdbApi _kvdbApi;
    FtsContainer _fts;
    
};

}  // namespace search
}  // namespace endpoint
}  // namespace privmx

#endif  // _PRIVMXLIB_ENDPOINT_SEARCH_SEARCHAPIIMPL_HPP_
