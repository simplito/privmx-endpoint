#ifndef _PRIVMXLIB_ENDPOINT_KVDB_KVDBAPI_TYPES_HPP_
#define _PRIVMXLIB_ENDPOINT_KVDB_KVDBAPI_TYPES_HPP_

#include "privmx/endpoint/core/Buffer.hpp"
#include "privmx/endpoint/core/Types.hpp"


namespace privmx {
namespace endpoint {
namespace kvdb {

/**
 * Holds all available information about a Kvdb.
 */
struct Kvdb {

    /**
     * ID of the Context
     */
    std::string contextId;

    /**
     * ID of the Kvdb
     */
    std::string kvdbId;

    /**
     * Kvdb creation timestamp
     */
    int64_t createDate;

    /**
     * ID of user who created the Kvdb
     */
    std::string creator;

    /**
     * Kvdb last modification timestamp
     */
    int64_t lastModificationDate;

    /**
     * ID of the user who last modified the Kvdb
     */
    std::string lastModifier;

    /**
     * list of users (their IDs) with access to the Kvdb
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
     * Kvdb's public metadata
     */
    core::Buffer publicMeta;

    /**
     * Kvdb's private metadata
     */
    core::Buffer privateMeta;

    /**
     * total number of entries in the Kvdb
     */
    int64_t entries;

    /**
     * Timestamp of the last added entry
     */
    int64_t lastEntryDate;

    /**
     * Kvdb's policies
     */
    core::ContainerPolicy policy;

    /**
     * Retrieval and decryption status code
     */
    int64_t statusCode;

    /**
     * Version of the Kvdb data structure and how it is encoded/encrypted
     */
    int64_t schemaVersion;
};


/**
 * Holds Kvdb entry's information created by the server
 */
struct ServerKvdbEntryInfo {
    /**
     * ID of the Kvdb
     */
    std::string kvdbId;

    /**
     * Kvdb entry's key
     */
    std::string key;

    /**
     * Entry's creation timestamp
     */
    int64_t createDate;

    /**
     * ID of the user who created the entry
     */
    std::string author;
};

/**
 * Holds all available information about a Entry.
 */
struct KvdbEntry {

    /**
     * Entry information created by server
     */
    ServerKvdbEntryInfo info;

    /**
     * Entry public metadata
     */
    core::Buffer publicMeta;

    /**
     * Entry private metadata
     */
    core::Buffer privateMeta;

    /**
     * Entry data
     */
    core::Buffer data;

    /**
     * public key of an author of the entry
     */
    std::string authorPubKey;

    /**
     * version number (changes on every on existing item)
     */
    int64_t version;

    /**
     * Retrieval and decryption status code
     */
    int64_t statusCode;

    /**
     * Version of the Entry data structure and how it is encoded/encrypted
     */
    int64_t schemaVersion;
};

struct KvdbKeysPagingQuery {
    /**
     * number of elements to skip from result
     */
    int64_t skip;

    /**
     * limit of elements to return for query
     */
    int64_t limit;

    /**
     * order of elements in result ("asc" for ascending, "desc" for descending)
     */
    std::string sortOrder;

    /**
     * order of elements are sorted in result ("createDate" for createDate, "itemKey" for itemKey, "lastModificationDate" for itemKey)
     */
    std::optional<std::string> sortBy;

    /**
     * Key of the element from which query results should start
     */
    std::optional<std::string> lastKey;

    /**
     * prefix of the element from which query results should have
     */
    std::optional<std::string> prefix;
};

struct KvdbEntryPagingQuery {
    /**
     * number of elements to skip from result
     */
    int64_t skip;

    /**
     * limit of elements to return for query
     */
    int64_t limit;

    /**
     * order of elements in result ("asc" for ascending, "desc" for descending)
     */
    std::string sortOrder;

    /**
     * order of elements are sorted in result ("createDate" for createDate, "itemKey" for itemKey, "lastModificationDate" for itemKey)
     */
    std::optional<std::string> sortBy;

    /**
     * Key of the element from which query results should start
     */
    std::optional<std::string> lastKey;

    /**
     * prefix of the element from which query results should have
     */
    std::optional<std::string> prefix;

    /**
     * extra query parameters in serialized JSON  
     */
    std::optional<std::string> queryAsJson;
};

}  // namespace kvdb
}  // namespace endpoint
}  // namespace privmx

#endif  // _PRIVMXLIB_ENDPOINT_KVDB_KVDBAPI_TYPES_HPP_
