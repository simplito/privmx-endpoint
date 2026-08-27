#ifndef _PRIVMXLIB_ENDPOINT_STORE_STOREAPI_HPP_
#define _PRIVMXLIB_ENDPOINT_STORE_STOREAPI_HPP_

#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "privmx/endpoint/core/Connection.hpp"
#include "privmx/endpoint/store/Types.hpp"
#include <privmx/endpoint/core/ExtendedPointer.hpp>
#include <privmx/endpoint/group/GroupApi.hpp>

namespace privmx {
namespace endpoint {
namespace store {

class StoreApiImpl;

/**
 * 'StoreApi' is a class representing Endpoint's API for Stores and their files.
 */
class StoreApi : public privmx::endpoint::core::ExtendedPointer<StoreApiImpl> {
public:
    /**
     * Creates an instance of 'StoreApi'.
     *
     * @param connection instance of 'Connection'
     * @param groupApi instance of 'GroupApi', required to read and write Stores granted to groups
     *
     * @return StoreApi object
     */
    static StoreApi create(core::Connection& connection, const std::optional<group::GroupApi>& groupApi = std::nullopt);

    /**
     * //doc-gen:ignore
     */
    StoreApi();
    StoreApi(const StoreApi& obj);
    StoreApi& operator=(const StoreApi& obj);
    StoreApi(StoreApi&& obj);
    ~StoreApi();

    /**
     * Creates a new Store in given Context.
     *
     * @param contextId ID of the Context to create the Store in
     * @param users vector of UserWithPubKey structs which indicates who will have access to the created Store
     * @param managers vector of UserWithPubKey structs which indicates who will have access (and management rights) to the
     * created Store
     * @param publicMeta public (unencrypted) metadata
     * @param privateMeta private (encrypted) metadata
     * @param policies Store's policies
     * @param groups groups granted access to the Store, with their verified epoch public keys
     * @return created Store ID
     */
    std::string createStore(
        const std::string& contextId,
        const std::vector<core::UserWithPubKey>& users,
        const std::vector<core::UserWithPubKey>& managers,
        const core::Buffer& publicMeta,
        const core::Buffer& privateMeta,
        const std::optional<core::ContainerPolicy>& policies = std::nullopt,
        const std::vector<core::GroupGrantWithKey>& groups = {}
    );

    /**
     * Updates an existing Store.
     *
     * @param storeId ID of the Store to update
     * @param users vector of UserWithPubKey structs which indicates who will have access to the created Store
     * @param managers vector of UserWithPubKey structs which indicates who will have access (and management rights) to the
     * created Store
     * @param publicMeta public (unencrypted) metadata
     * @param privateMeta private (encrypted) metadata
     * @param version current version of the updated Store
     * @param force force update (without checking version)
     * @param forceGenerateNewKey force to regenerate a key for the Store
     * @param policies Store's policies
     * @param groups groups granted access to the Store, with their verified epoch public keys; the list is
     * authoritative — an empty list revokes every group grant the Store had
    */
    void updateStore(
        const std::string& storeId,
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
     * Re-encrypts the Store key for all current members without changing data, membership, or policy.
     * Unlike updateStore, this can be called by any Store member (not just managers) when the
     * default rotateKeys policy of "user" is in effect.
     *
     * The Store's key is re-wrapped to every one of its grantee groups at that group's current epoch, whether or
     * not it names the group in `groups`: the grantee list comes from the Store itself, and any epoch public key
     * missing from `groups` is read from the Bridge.
     *
     * That read is what bounds who may re-key: a group's epoch and public key are readable only by its members
     * under the default group policy (`get: "user"`, `listAll: "none"`). A caller who belongs to none of the
     * Store's grantee groups, and cannot supply their epoch keys in `groups` either, gets
     * `UnresolvedGroupGranteeException` naming the group it could not resolve.
     *
     * @param storeId ID of the Store to re-key
     * @param users current Store users with their public keys
     * @param managers current Store managers with their public keys
     * @param version current Store version (optimistic lock guard)
     * @param force skip the version check when true
     * @param groups epoch public keys of grantee groups the caller has verified itself; optional, and groups the
     * Store does not grant are ignored — a re-key changes no grants
     */
    void rotateStoreKeys(
        const std::string& storeId,
        const std::vector<core::UserWithPubKey>& users,
        const std::vector<core::UserWithPubKey>& managers,
        const int64_t version,
        const bool force,
        const std::vector<core::GroupGrantWithKey>& groups = {}
    );

    /**
     * Deletes a Store by given Store ID.
     *
     * @param storeId ID of the Store to delete
     */
    void deleteStore(const std::string& storeId);

    /**
     * Gets a single Store by given Store ID.
     *
     * @param storeId ID of the Store to get
     * @return struct containing information about the Store
    */
    Store getStore(const std::string& storeId);

    /**
     * Gets a list of Stores in given Context.
     *
     * @param contextId ID of the Context to get the Stores from
     * @param pagingQuery struct with list query parameters
     * @return struct containing list of Stores
    */
    core::PagingList<Store> listStores(const std::string& contextId, const core::PagingQuery& pagingQuery);

    /**
     * Creates a new file in a Store.
     *
     * @param storeId ID of the Store to create the file in
     * @param publicMeta public file metadata
     * @param privateMeta private file metadata
     * @param size size of the file
     * @param randomWriteSupport enable random write support for file
     * @return handle to write data
     */
    int64_t createFile(
        const std::string& storeId,
        const core::Buffer& publicMeta,
        const core::Buffer& privateMeta,
        const int64_t size,
        bool randomWriteSupport = false
    );

    /**
     * Update an existing file in a Store.
     *
     * @param fileId ID of the file to update
     * @param publicMeta public file metadata
     * @param privateMeta private file metadata
     * @param size size of the file
     * @return handle to write file data
     */
    int64_t updateFile(
        const std::string& fileId,
        const core::Buffer& publicMeta,
        const core::Buffer& privateMeta,
        const int64_t size
    );

    /**
     * Update metadata of an existing file in a Store.
     *
     * @param fileId ID of the file to update
     * @param publicMeta public file metadata
     * @param privateMeta private file metadata
     */
    void updateFileMeta(const std::string& fileId, const core::Buffer& publicMeta, const core::Buffer& privateMeta);

    /**
     * Writes a file data.
     *
     * @param handle handle to write file data
     * @param dataChunk file data chunk
     * @param truncate truncate the file from: current pos + dataChunk size
     */
    void writeToFile(const int64_t fileHandle, const core::Buffer& dataChunk, bool truncate = false);

    /**
     * Deletes a file by given ID.
     *
     * @param fileId ID of the file to delete
     */
    void deleteFile(const std::string& fileId);

    /**
     * Gets a single file by the given file ID.
     *
     * @param fileId ID of the file to get
     * @return struct containing information about the file
     */
    File getFile(const std::string& fileId);

    /**
     * Gets a list of files in given Store.
     *
     * @param store ID of the Store to get files from
     * @param pagingQuery struct with list query parameters
     * @return struct containing list of files
     */
    core::PagingList<File> listFiles(const std::string& storeId, const core::PagingQuery& pagingQuery);

    /**
     * Opens a file to read.
     *
     * @param fileId ID of the file to read
     * @return handle to read file data
     */
    int64_t openFile(const std::string& fileId);

    /**
     * Reads file data.
     * Single read call moves the files's cursor position by declared length or set it at the end of the file.
     *
     * @param handle handle to write file data
     * @param length size of data to read
     * @return buffer with file data chunk
     */
    core::Buffer readFromFile(const int64_t fileHandle, const int64_t length);

    /**
     * Moves read cursor.
     *
     * @param handle handle to write file data
     * @param position new cursor position
     */
    void seekInFile(const int64_t fileHandle, const int64_t position);

    /**
     * Closes the file handle.
     *
     * @param handle handle to read/write file data
     * @return ID of closed file
     */
    std::string closeFile(const int64_t fileHandle);

    /**
     * Subscribe for the Store events on the given subscription query.
     * 
     * @param subscriptionQueries list of queries
     * @return list of subscriptionIds in maching order to subscriptionQueries
     */
    std::vector<std::string> subscribeFor(const std::vector<std::string>& subscriptionQueries);

    /**
     * Unsubscribe from events for the given subscriptionId.
     * @param subscriptionIds list of subscriptionId
     */
    void unsubscribeFrom(const std::vector<std::string>& subscriptionIds);

    /**
     * Generate subscription Query for the Store events.
     * @param eventType type of event which you listen for
     * @param selectorType scope on which you listen for events  
     * @param selectorId ID of the selector
     */
    std::string buildSubscriptionQuery(
        EventType eventType,
        EventSelectorType selectorType,
        const std::string& selectorId
    );

    /**
     * Synchronize file handle data with newest data on server
     * @param fileHandle handle to read/write file data
     */
    void syncFile(const int64_t fileHandle);

private:
    StoreApi(const std::shared_ptr<StoreApiImpl>& impl);
};

} // namespace store
} // namespace endpoint
} // namespace privmx

#endif // _PRIVMXLIB_ENDPOINT_STORE_STOREAPI_HPP_
