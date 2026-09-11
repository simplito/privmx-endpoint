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
#include "privmx/endpoint/core/ExtendedPointer.hpp"
#include "privmx/endpoint/core/Types.hpp"
#include "privmx/endpoint/kvdb/KvdbApi.hpp"
#include "privmx/endpoint/lock/LockApi.hpp"
#include "privmx/endpoint/search/Types.hpp"
#include "privmx/endpoint/store/StoreApi.hpp"

namespace privmx {
namespace endpoint {
namespace search {

class SearchApiImpl;

/**
 * 'SearchApi' is a class representing Endpoint's API for Search Indexes and their Documents.
 */
class SearchApi : public privmx::endpoint::core::ExtendedPointer<SearchApiImpl> {
public:
    /**
     * Creates an instance of 'SearchApi'.
     *
     * A Search Index is a KVDB and a Store, so group support comes from the APIs given here: to read and write
     * Indexes granted to groups, create `storeApi` and `kvdbApi` with a GroupApi of their own.
     *
     * @param connection instance of 'Connection'
     * @param storeApi instance of 'StoreApi', holds the Index's documents
     * @param kvdbApi instance of 'KvdbApi', holds the Index's metadata
     * @param lockApi instance of 'LockApi', serializes concurrent writes to the Index
     *
     * @return SearchApi object
     */
    static SearchApi create(
        core::Connection& connection,
        store::StoreApi& storeApi,
        kvdb::KvdbApi& kvdbApi,
        lock::LockApi& lockApi
    );

    /**
     * //doc-gen:ignore
     */
    SearchApi();
    SearchApi(const SearchApi& obj);
    SearchApi& operator=(const SearchApi& obj);
    SearchApi(SearchApi&& obj);
    ~SearchApi();

    /**
     * Creates a new Search Index in a given Context.
     *
     * @param contextId ID of the Context to create the Index in
     * @param users vector of UserWithPubKey structs which indicates who will have access to the created Index
     * @param managers vector of UserWithPubKey structs which indicates who will have access (and management rights) to
     * the created Index
     * @param publicMeta public (unencrypted) metadata
     * @param privateMeta private (encrypted) metadata
     * @param mode mode the operational mode of the Serach Index
     * @param policies Index's policies
     * @param groups groups granted access to the Index, with their verified epoch public keys; the same grants
     * are applied to both containers backing the Index
     * @return ID of the created Search Index
     */
    std::string createSearchIndex(
        const std::string& contextId,
        const std::vector<core::UserWithPubKey>& users,
        const std::vector<core::UserWithPubKey>& managers,
        const core::Buffer& publicMeta,
        const core::Buffer& privateMeta,
        const IndexMode mode,
        const std::optional<core::ContainerPolicy>& policies = std::nullopt,
        const std::vector<core::GroupGrantWithKey>& groups = {}
    );

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
     * @param groups groups granted access to the Index, with their verified epoch public keys; the list is
     * authoritative — an empty list revokes every group grant the Index had
     */
    void updateSearchIndex(
        const std::string& indexId,
        const std::vector<core::UserWithPubKey>& users,
        const std::vector<core::UserWithPubKey>& managers,
        const core::Buffer& publicMeta,
        const core::Buffer& privateMeta,
        const int64_t version,
        const bool force,
        const bool forceGenerateNewKey,
        const std::optional<core::ContainerPolicy>& policies = std::nullopt,
        const std::vector<core::GroupGrantWithKey>& groups = {}
    );

    /**
     * Re-encrypts the Search Index keys for all current members without changing data, membership, or policy.
     * Unlike updateSearchIndex, this can be called by any Index member (not just managers) when the default
     * rotateKeys policy of "user" is in effect.
     *
     * Both containers backing the Index are re-keyed, each against its own current version, so a half that was
     * already re-keyed on its own (see `SearchIndex::staleGroups`) does not fail the call.
     *
     * The keys are re-wrapped to every one of the Index's grantee groups at that group's current epoch, whether
     * or not it names the group in `groups`: the grantee list comes from the Index itself, and any epoch public
     * key missing from `groups` is read from the Bridge. A caller who belongs to none of the Index's grantee
     * groups, and cannot supply their epoch keys in `groups` either, gets `UnresolvedGroupGranteeException`
     * naming the group it could not resolve.
     *
     * @param indexId ID of the Index to re-key
     * @param users current Index users with their public keys
     * @param managers current Index managers with their public keys
     * @param version current Index version (optimistic lock guard)
     * @param force skip the version check when true
     * @param groups epoch public keys of grantee groups the caller has verified itself; optional, and groups the
     * Index does not grant are ignored — a re-key changes no grants
     */
    void rotateSearchIndexKeys(
        const std::string& indexId,
        const std::vector<core::UserWithPubKey>& users,
        const std::vector<core::UserWithPubKey>& managers,
        const int64_t version,
        const bool force,
        const std::vector<core::GroupGrantWithKey>& groups = {}
    );

    /**
     * Deletes a Search Index by given Index ID.
     *
     * @param indexId ID of the Index to delete
     */
    void deleteSearchIndex(const std::string& indexId);

    /**
     * Gets a Search Index by given Index ID.
     *
     * @param indexId ID of the Index to get
     * @return SearchIndex struct containing info about the Index
     */
    SearchIndex getSearchIndex(const std::string& indexId);

    /**
     * Gets a list of Search Indexes in given Context.
     *
     * @param contextId ID of the Context to get the Indexes from
     * @param pagingQuery struct with list query parameters
     * @return struct containing a list of Search Indexes
     */
    core::PagingList<SearchIndex> listSearchIndexes(const std::string& contextId, const core::PagingQuery& pagingQuery);

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
     * Begins a SQLite transaction on the Search Index.
     *
     * @param indexHandle Handle of the Index to begin the transaction on
     */
    void beginTransaction(const int64_t indexHandle);

    /**
     * Commits the active transaction on the Search Index.
     *
     * @param indexHandle Handle of the Index to commit the transaction on
     */
    void commit(const int64_t indexHandle);

    /**
     * Rolls back the active transaction on the Search Index.
     *
     * @param indexHandle Handle of the Index to roll back the transaction on
     */
    void rollback(const int64_t indexHandle);

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
     * Gets a document by given document ID from the Search Index.
     *
     * @param indexHandle Handle of the Index containing the document
     * @param documentId ID of the document to get
     * @return Document struct containing the document data
     */
    Document getDocument(const int64_t indexHandle, const int64_t documentId);

    /**
     * Gets a list of documents (e.g., messages, threads, or custom documents) from a Search Index.
     *
     * @param indexId Handle of the Index containing documents
     * @param pagingQuery struct with list query parameters (can include search terms)
     * @return struct containing a list of documents
     */
    core::PagingList<Document> listDocuments(const int64_t indexHandle, const core::PagingQuery& pagingQuery);

    /**
     * Searches for documents in the Index.
     *
     * @param indexHandle Handle of the Index to search
     * @param searchQuery Search query
     * @param pagingQuery struct with list query parameters (e.g., search query, pagination)
     * @return struct containing a list of matching Documents
     */
    core::PagingList<Document> searchDocuments(
        const int64_t indexHandle,
        const std::string& searchQuery,
        const core::PagingQuery& pagingQuery
    );

private:
    SearchApi(const std::shared_ptr<SearchApiImpl>& impl);
};

} // namespace search
} // namespace endpoint
} // namespace privmx

#endif // _PRIVMXLIB_ENDPOINT_SEARCH_SEARCHAPI_HPP_
