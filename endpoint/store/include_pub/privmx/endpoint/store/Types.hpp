#ifndef _PRIVMXLIB_ENDPOINT_STORE_STOREAPI_TYPES_HPP_
#define _PRIVMXLIB_ENDPOINT_STORE_STOREAPI_TYPES_HPP_

#include "privmx/endpoint/core/Buffer.hpp"
#include "privmx/endpoint/core/Types.hpp"

namespace privmx {
namespace endpoint {
namespace store {

/**
 * Holds file's information created by server
 */
struct ServerFileInfo {
    /**
     * ID of the Store
     */
    std::string storeId;

    /**
     * ID of the file
     */
    std::string fileId;

    /**
     * file's creation timestamp
     */
    int64_t createDate;

    /**
     * ID of the user who created the file
     */
    std::string author;
};

/**
 * Holds information about the file.
 * 
 */
struct File {

    /**
     * file's information created by server
     */
    ServerFileInfo info;

    /**
     * file's public metadata
     */
    core::Buffer publicMeta;

    /**
     * file's private metadata
     */
    core::Buffer privateMeta;

    /**
     * file's size
     */
    int64_t size;

    /**
     * public key of the author of the file
     */
    std::string authorPubKey;

    /**
     * status code of retrieval and decryption of the file
     */
    int64_t statusCode;

    /**
     * Version of the file data structure and how it is encoded/encrypted
     */
    int64_t schemaVersion;

    /**
     * have random write feature enabled 
     */
    bool randomWrite;
};


/**
 * Holds all available information about a Store.
 */
struct Store {

    /**
     * ID ot the Store
     */
    std::string storeId;

    /**
     * ID of the Context
     */
    std::string contextId;

    /**
     * Store creation timestamp
     */
    int64_t createDate;

    /**
     * ID of user who created the Store
     */
    std::string creator;

    /**
     * Store last modification timestamp
     */
    int64_t lastModificationDate;

    /**
     * timestamp of last created file
     */
    int64_t lastFileDate;

    /**
     * ID of the user who last modified the Store
     */
    std::string lastModifier;

    /**
     * list of users (their IDs) with access to the Store
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
     * Store's public metadata
     */
    core::Buffer publicMeta;

    /**
     * Store's private metadata
     */
    core::Buffer privateMeta;

    /**
     * Store's policies
     */
    core::ContainerPolicy policy;

    /**
     * total number of files in the Store
     */
    int64_t filesCount;

    /**
     * status code of retrieval and decryption of the Store
     */
    int64_t statusCode;

    /**
     * Version of the Store data structure and how it is encoded/encrypted
     */
    int64_t schemaVersion;
};


}  // namespace store
}  // namespace endpoint
}  // namespace privmx

#endif  // _PRIVMXLIB_ENDPOINT_STORE_STOREAPI_HPP_
