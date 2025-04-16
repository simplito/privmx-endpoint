#ifndef _PRIVMXLIB_ENDPOINT_INBOX_INBOXAPI_TYPES_HPP_
#define _PRIVMXLIB_ENDPOINT_INBOX_INBOXAPI_TYPES_HPP_

#include "privmx/endpoint/core/Types.hpp"
#include "privmx/endpoint/store/Types.hpp"


namespace privmx {
namespace endpoint {
namespace inbox {

/**
 * Holds Inbox file configuration.
 */
struct FilesConfig {
    /**
     * minimum numer of files required when sending inbox entry
     */
    int64_t minCount;

    /**
     * maximum numer of files allowed when sending inbox entry
     */
    int64_t maxCount;

    /**
     * maximum file size allowed when sending inbox entry
     */
    int64_t maxFileSize;

    /**
     * maximum size of all files in total allowed when sending inbox entry
     */
    int64_t maxWholeUploadSize;
};

/**
 * Holds public information of an Inbox. 
 */
struct InboxPublicView {
    /**
     * ID of the Inbox
     */
    std::string inboxId;

    /**
     * version of the Inbox
     */
    int64_t version;

    /**
     * Inbox public metadata
     */
    core::Buffer publicMeta;
};

/**
 * Holds all available information about an Inbox.
 */
struct Inbox {
    /**
     * ID ot the Inbox
     */
    std::string inboxId;

    /**
     * ID of the Context
     */
    std::string contextId;

    /**
     * Inbox creation timestamp
     */
    int64_t createDate;

    /**
     * ID of user who created the Inbox
     */
    std::string creator;

    /**
     * Inbox last modification timestamp
     */
    int64_t lastModificationDate;

    /**
     * ID of the user who last modified the Inbox
     */
    std::string lastModifier;

    /**
     * list of users (their IDs) with access to the Inbox
     */
    std::vector<std::string> users;

    /**
     * list of users (their IDs) with management rights
     */
    std::vector<std::string> managers;

    /**
     * version number (changes on updates)
     */
    int64_t version;

    /**
     * Inbox public metadata
     */
    core::Buffer publicMeta;

    /**
     * Inbox private metadata
     */
    core::Buffer privateMeta;

    /**
     * Inbox files configuration
     */
    std::optional<FilesConfig> filesConfig;

    /**
     * Inbox policies
     */
    core::ContainerPolicyWithoutItem policy;

    /**
     * status code of retrieval and decryption of the Inbox
     */
    int64_t statusCode;

    /**
     * encrypted dataStructure version of Inbox
     */
    int64_t dataStructureVersion;
};

/**
 * Holds information about Inbox entry
 */
struct InboxEntry {
    /**
     * ID of the entry
     */
    std::string entryId;

    /**
     * ID of the Inbox
     */
    std::string inboxId;

    /**
     * entry data
     */
    core::Buffer data;

    /**
     * list of files attached to the entry
     */
    std::vector<store::File> files;

    /**
     * public key of the author of the entry
     */
    std::string authorPubKey;

    /**
     * Inbox entry creation timestamp
     */
    int64_t createDate;

    /**
     * status code of retrieval and decryption of the Inbox entry
     */
    int64_t statusCode;

    /**
     * encrypted dataStructure version of Entry
     */
    int64_t dataStructureVersion;
};

}  // namespace inbox
}  // namespace endpoint
}  // namespace privmx

#endif  // _PRIVMXLIB_ENDPOINT_INBOX_INBOXAPI_TYPES_HPP_
