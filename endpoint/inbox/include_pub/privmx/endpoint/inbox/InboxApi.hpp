#ifndef _PRIVMXLIB_ENDPOINT_INBOX_INBOXAPI_HPP_
#define _PRIVMXLIB_ENDPOINT_INBOX_INBOXAPI_HPP_

#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "privmx/endpoint/core/Connection.hpp"
#include "privmx/endpoint/core/Types.hpp"

#include "privmx/endpoint/store/StoreApi.hpp"
#include "privmx/endpoint/thread/ThreadApi.hpp"
#include "privmx/endpoint/inbox/Types.hpp"

namespace privmx {
namespace endpoint {
namespace inbox {



class InboxApiImpl;

/**
 * 'InboxApi' is a class representing Endpoint's API for Inboxes and their entries.
 */
class InboxApi {
public:
    /**
     * Creates an instance of 'InboxApi'.
     * 
     * @param connection instance of 'Connection'
     * @param threadApi instance of 'ThreadApi'
     * @param storeApi instance of 'StoreApi'
     * 
     * @return InboxApi object
     */
    static InboxApi create(core::Connection& connection, thread::ThreadApi& threadApi, store::StoreApi& storeApi);

    /**
     * //doc-gen:ignore
     */
    InboxApi() = default;

    /**
     * Creates a new Inbox.
     *
     * @param contextId ID of the Context of the new Inbox
     * @param users vector of UserWithPubKey structs which indicates who will have access to the created Inbox
     * @param managers vector of UserWithPubKey structs which indicates who will have access (and management rights) to
     * the created Inbox
     * @param publicMeta public (unencrypted) metadata
     * @param privateMeta private (encrypted) metadata
     * @param filesConfig struct to override default file configuration
     * @param policies Inbox policies
     * @return ID of the created Inbox
     */
    std::string createInbox(const std::string& contextId, const std::vector<core::UserWithPubKey>& users,
                            const std::vector<core::UserWithPubKey>& managers, const core::Buffer& publicMeta, const core::Buffer& privateMeta,
                            const std::optional<inbox::FilesConfig>& filesConfig,
                            const std::optional<core::ContainerPolicyWithoutItem>& policies = std::nullopt);

    
    /**
     * Updates an existing Inbox.
     *
     * @param inboxId ID of the Inbox to update
     * @param users vector of UserWithPubKey structs which indicates who will have access to the created Inbox
     * @param managers vector of UserWithPubKey structs which indicates who will have access (and management rights) to
     * the created Inbox
     * @param publicMeta public (unencrypted) metadata
     * @param privateMeta private (encrypted) metadata
     * @param filesConfig struct to override default files configuration
     * @param version current version of the updated Inbox
     * @param force force update (without checking version)
     * @param forceGenerateNewKey force to regenerate a key for the Inbox
     * @param policies Inbox policies
     */
    void updateInbox(const std::string& inboxId, const std::vector<core::UserWithPubKey>& users,
                     const std::vector<core::UserWithPubKey>& managers,
                     const core::Buffer& publicMeta, const core::Buffer& privateMeta,
                     const std::optional<inbox::FilesConfig>& filesConfig, const int64_t version, const bool force,
                     const bool forceGenerateNewKey,
                     const std::optional<core::ContainerPolicyWithoutItem>& policies = std::nullopt);

    /**
     * Gets a single Inbox by given Inbox ID.
     *
     * @param inboxId ID of the Inbox to get
     * @return struct containing information about the Inbox
     */
    Inbox getInbox(const std::string& inboxId);

    /**
     * Gets s list of Inboxes in given Context.
     *
     * @param contextId ID of the Context to get Inboxes from
     * @param pagingQuery struct with list query parameters
     * @return struct containing list of Inboxes
     */    
    core::PagingList<inbox::Inbox> listInboxes(const std::string& contextId, const core::PagingQuery& pagingQuery);


    /**
     * Gets public data of given Inbox.
     * You do not have to be logged in to call this function.
     *
     * @param inboxId ID of the Inbox to get
     * @return struct containing public accessible information about the Inbox
     */    
    inbox::InboxPublicView getInboxPublicView(const std::string& inboxId);

    /**
     * Deletes an Inbox by given Inbox ID.
     *
     * @param inboxId ID of the Inbox to delete
     */    
    void deleteInbox(const std::string& inboxId);

    /**
     * Prepares a request to send data to an Inbox.
     * You do not have to be logged in to call this function.
     *
     * @param inboxId ID of the Inbox to which the request applies
     * @param data entry data to send
     * @param inboxFileHandles optional list of file handles that will be sent with the request
     * @param userPrivKey optional sender's private key which can be used later to encrypt data for that sender
     * @return handle
     */
    int64_t /*inboxHandle*/ prepareEntry(const std::string& inboxId, const core::Buffer& data,
                                             const std::vector<int64_t>& inboxFileHandles = std::vector<int64_t>(),
                                             const std::optional<std::string>& userPrivKey = std::nullopt);

    /**
     * Sends data to an Inbox.
     * You do not have to be logged in to call this function.
     *
     * @param inboxHandle ID of the Inbox to which the request applies
     */
    void sendEntry(const int64_t inboxHandle);

    /**
     * Gets an entry from an Inbox.
     *
     * @param inboxEntryId ID of an entry to read from the Inbox
     * @return struct containing data of the selected entry stored in the Inbox
     */
    inbox::InboxEntry readEntry(const std::string& inboxEntryId);

    /**
     * Gets list of entries in given Inbox.
     *
     * @param inboxId ID of the Inbox
     * @param pagingQuery struct with list query parameters
     * @return struct containing list of entries
     */
    core::PagingList<inbox::InboxEntry> listEntries(const std::string& inboxId, const core::PagingQuery& pagingQuery);

    /**
     * Delete an entry from an Inbox.
     *
     * @param ID of an entry to delete
     */
    void deleteEntry(const std::string& inboxEntryId);

    /**
     * Creates a file handle to send a file to an Inbox.
     * You do not have to be logged in to call this function.
     *
     * @param publicMeta file's public metadata
     * @param privateMeta file's private metadata
     * @param fileSize size of the file to send
     * @return file handle
     */
    int64_t /*inboxFileHandle*/ createFileHandle(const core::Buffer& publicMeta, const core::Buffer& privateMeta, const int64_t& fileSize);

    /**
     * Sends file's data chunk to an Inbox.
     * (note: To send the entire file - divide it into pieces of the desired size and call the function for each fragment.)
     * You do not have to be logged in to call this function.
     *
     * @param inboxHandle ID of the Inbox to which the request applies
     * @param inboxFileHandle handle to the file where the uploaded chunk belongs
     * @param Buffer dataChunk - file chunk to send
     */    
    void writeToFile(const int64_t inboxHandle, const int64_t inboxFileHandle,
                                const core::Buffer& dataChunk);


    /**
     * Opens a file to read.
     *
     * @param fileId ID of the file to read
     * @return handle to read file data
     */
    int64_t openFile(const std::string& fileId);

    /**
     * Reads file data.
     *
     * @param fileHandle handle to the file
     * @param length size of data to read
     * @return buffer with file data chunk
     */
    core::Buffer readFromFile(const int64_t fileHandle, const int64_t length);

    /**
     * Moves file's read cursor.
     *
     * @param fileHandle handle to the file
     * @param position sets new cursor position
     */    
    void seekInFile(const int64_t fileHandle, const int64_t position);

    /**
     * Closes a file by given handle.
     *
     * @param fileHandle handle to the file
     * @return ID of closed file
     */
    std::string closeFile(const int64_t fileHandle);

    /**
     * Subscribes for the Inbox module main events.
     */
    void subscribeForInboxEvents();

    /**
     * Unsubscribes from the Inbox module main events.
     */
    void unsubscribeFromInboxEvents();

    /**
     * Subscribes for events in given Inbox.
     * @param inbox ID of the Inbox to subscribe
     */
    void subscribeForEntryEvents(const std::string& inboxId);

    /**
     * Unsubscribes from events in given Inbox.
     * @param inbox ID of the Inbox to unsubscribe
     */
    void unsubscribeFromEntryEvents(const std::string& inboxId);

private:
    void validateEndpoint();
    InboxApi(const std::shared_ptr<InboxApiImpl>& impl);
    std::shared_ptr<InboxApiImpl> _impl;
};

}  // namespace inbox
}  // namespace endpoint
}  // namespace privmx

#endif  // _PRIVMXLIB_ENDPOINT_INBOX_INBOXAPI_HPP_
