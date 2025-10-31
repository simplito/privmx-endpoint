/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/
#ifndef _PRIVMXLIB_ENDPOINT_SEARCH_SEARCHAPI_HPP_
#define _PRIVMXLIB_ENDPOINT_SEARCH_SEARCHAPI_HPP_

#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "privmx/endpoint/core/Connection.hpp"
#include "privmx/endpoint/store/StoreApi.hpp"
#include "privmx/endpoint/kvdb/KvdbApi.hpp"
#include "privmx/endpoint/core/Types.hpp"
#include "privmx/endpoint/search/Types.hpp"

namespace privmx {
namespace endpoint {
namespace search {

class SearchApiImpl;

/**
 * 'SearchApi' is a class representing Endpoint's API for Search Indexes and their Documents.
 */
class SearchApi
{
public:
    /**
     * Creates an instance of 'SearchApi'.
     *
     * @param connection instance of 'Connection'
     *
     * @return SearchApi object
     */
    static SearchApi create(core::Connection& connetion, store::StoreApi& storeApi, kvdb::KvdbApi& kvdbApi);

    /**
     * //doc-gen:ignore
     */
    SearchApi() = default;

    /**
     * Creates a new Search Index in a given Context.
     *
     * @param contextId ID of the Context to create the Index in
     * @param users vector of UserWithPubKey structs which indicates who will have access to the created Index
     * @param managers vector of UserWithPubKey structs which indicates who will have access (and management rights) to
     * the created Index
     * @param publicMeta public (unencrypted) metadata
     * @param privateMeta private (encrypted) metadata
     * @param policies Index's policies
     * @return ID of the created Search Index
     */
    std::string createSearchIndex(const std::string& contextId, const std::vector<core::UserWithPubKey>& users,
                                  const std::vector<core::UserWithPubKey>& managers, const core::Buffer& publicMeta,
                                  const core::Buffer& privateMeta, const IndexMode mode, const std::optional<core::ContainerPolicy>& policies = std::nullopt);

    /**
     * Updates an existing Search Index.
     *
     * @param indexId ID of the Index to update
     * @param users vector of UserWithPubKey structs which indicates who will have access to the Index
     * @param managers vector of UserWithPubKey structs which indicates who will have access (and management rights) to
     * the Index
     * @param publicMeta public (unencrypted) metadata
     * @param privateMeta private (encrypted) metadata
     * @param version current version of the updated Index
     * @param force force update (without checking version)
     * @param forceGenerateNewKey force to regenerate a key for the Index
     * @param policies Index's policies
     */
    void updateSearchIndex(const std::string& indexId, const std::vector<core::UserWithPubKey>& users,
                           const std::vector<core::UserWithPubKey>& managers, const core::Buffer& publicMeta, const core::Buffer& privateMeta,
                           const int64_t version, const bool force, const bool forceGenerateNewKey, const std::optional<core::ContainerPolicy>& policies = std::nullopt);

    /**
     * Deletes a Search Index by given Index ID.
     *
     * @param indexId ID of the Index to delete
     */
    void deleteSearchIndex(const std::string& indexId);

    /**
     * Opens a Search Index for use and returns a handle.
     *
     * @param indexId ID of the Index to open
     * @return Handle to the opened Search Index
     */
    int64_t openSearchIndex(const std::string& indexId);

    /**
     * Closes the Search Index associated with the given handle.
     *
     * @param indexHandle Handle of the Search Index to close
     */
    void closeSearchIndex(const int64_t indexHandle);

    /**
     * Adds a new document to the Search Index.
     *
     * @param indexHandle Handle of the Index to add the document to
     * @param name name of the document
     * @param content content of the document
     * @return ID of the newly added document
     */
    int64_t addDocument(const int64_t indexHandle, const std::string& name, const std::string& content);

    /**
     * Updates an existing document in the Search Index.
     *
     * @param indexHandle Handle of the Index containing the document
     * @param document Document struct with data for update
     */
    void updateDocument(const int64_t indexHandle, const Document& document);

    /**
     * Deletes a document by given document ID from the Search Index.
     *
     * @param indexHandle Handle of the Index to delete the document from
     * @param documentId ID of the document to delete
     */
    void deleteDocument(const int64_t indexHandle, int64_t documentId);

    /**
     * Searches for documents in the Index.
     *
     * @param indexHandle Handle of the Index to search
     * @param searchQuery Search query
     * @param pagingQuery struct with list query parameters (e.g., search query, pagination)
     * @return struct containing a list of matching Documents
     */
    core::PagingList<Document> searchDocuments(const int64_t indexHandle, const std::string& searchQuery, const core::PagingQuery& pagingQuery);

    std::shared_ptr<SearchApiImpl> getImpl() const { return _impl; }

private:
    void validateEndpoint();
    SearchApi(const std::shared_ptr<SearchApiImpl>& impl);
    std::shared_ptr<SearchApiImpl> _impl;
};

}  // namespace search
}  // namespace endpoint
}  // namespace privmx

#endif  // _PRIVMXLIB_ENDPOINT_SEARCH_SEARCHAPI_HPP_
