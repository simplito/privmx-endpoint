#ifndef _PRIVMXLIB_ENDPOINT_STORE_STOREAPI_HPP_
#define _PRIVMXLIB_ENDPOINT_STORE_STOREAPI_HPP_

#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "privmx/endpoint/core/Connection.hpp"
#include "privmx/endpoint/store/Types.hpp"

namespace privmx {
namespace endpoint {
namespace store {


class StoreApiImpl;

/**
 * 'StoreApi' is a class representing Endpoint's API for Stores and their files.
 */
class StoreApi {
public:
    /**
     * Creates an instance of 'StoreApi'.
     * 
     * @param connection instance of 'Connection'
     * 
     * @return StoreApi object
     */
    static StoreApi create(core::Connection& connection);

    /**
     * //doc-gen:ignore
     */
    StoreApi() = default;

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
     * @return created Store ID
     */
    std::string createStore(const std::string& contextId, const std::vector<core::UserWithPubKey>& users,
                            const std::vector<core::UserWithPubKey>& managers, const core::Buffer& publicMeta, const core::Buffer& privateMeta,
                            const std::optional<core::ContainerPolicy>& policies = std::nullopt);

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
    */
    void updateStore(const std::string& storeId, const std::vector<core::UserWithPubKey>& users,
                     const std::vector<core::UserWithPubKey>& managers, const core::Buffer& publicMeta, const core::Buffer& privateMeta, const int64_t version,
                     const bool force, const bool forceGenerateNewKey,
                     const std::optional<core::ContainerPolicy>& policies = std::nullopt);

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
     * @return handle to write data
     */
    int64_t createFile(const std::string& storeId, const core::Buffer& publicMeta, const core::Buffer& privateMeta,
                            const int64_t size);

    /**
     * Update an existing file in a Store.
     *
     * @param fileId ID of the file to update
     * @param publicMeta public file metadata
     * @param privateMeta private file metadata
     * @param size size of the file
     * @return handle to write file data
     */
    int64_t updateFile(const std::string& fileId, const core::Buffer& publicMeta, const core::Buffer& privateMeta,
                            const int64_t size);

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
     */
    void writeToFile(const int64_t fileHandle, const core::Buffer& dataChunk);

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
     * Single read call moves the files's cursor position by decleared length or set it at the end of the file.
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
     * Subscribes for the Store module main events.
     */
    void subscribeForStoreEvents();

    /**
     * Unsubscribes from the Store module main events.
     */
    void unsubscribeFromStoreEvents();
    
    /**
     * Subscribes for events in given Store.
     * @param store ID of the Store to subscribe
     */
    void subscribeForFileEvents(const std::string& storeId);

    /**
     * Unsubscribes from events in given Store.
     * @param store ID of the Store to unsubscribe
     */    
    void unsubscribeFromFileEvents(const std::string& storeId);

    std::shared_ptr<StoreApiImpl> getImpl() const { return _impl; }
private:
    void validateEndpoint();
    StoreApi(const std::shared_ptr<StoreApiImpl>& impl);
    std::shared_ptr<StoreApiImpl> _impl;
};

}  // namespace store
}  // namespace endpoint
}  // namespace privmx

#endif  // _PRIVMXLIB_ENDPOINT_STORE_STOREAPI_HPP_
