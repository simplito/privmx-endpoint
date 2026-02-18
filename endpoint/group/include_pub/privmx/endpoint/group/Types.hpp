#ifndef _PRIVMXLIB_ENDPOINT_GROUP_GROUPAPI_TYPES_HPP_
#define _PRIVMXLIB_ENDPOINT_GROUP_GROUPAPI_TYPES_HPP_

#include "privmx/endpoint/core/Buffer.hpp"
#include "privmx/endpoint/core/Types.hpp"


namespace privmx {
namespace endpoint {
namespace group {


/**
 * Holds all available information about a group.
 */
struct Group {

    /**
     * ID of the Context
     */
    std::string contextId;

    /**
     * ID of the group
     */
    std::string groupId;

    /**
     * group public key
     */
    std::string pubKey;

    /**
     * group creation timestamp
     */
    int64_t createDate;

    /**
     * ID of user who created the group
     */
    std::string creator;

    /**
     * group last modification timestamp
     */
    int64_t lastModificationDate;

    /**
     * ID of the user who last modified the group
     */
    std::string lastModifier;

    /**
     * list of users (their IDs) with access to the group and its resources
     */
    std::vector<std::string> users;

    /**
     * list of users (their IDs) with management rights and its resources
     */
    std::vector<std::string> managers;

    /**
     * version number (changes on updates)
     */
    int64_t version;

    /**
     * group public metadata
     */
    core::Buffer publicMeta;

    /**
     * group private metadata
     */
    core::Buffer privateMeta;

    /**
     * status code of retrieval and decryption of the group
     */
    int64_t statusCode;

    /**
     * Version of the group data structure and how it is encoded/encrypted
     */
    int64_t schemaVersion;
};

}  // namespace group
}  // namespace endpoint
}  // namespace privmx

#endif  // _PRIVMXLIB_ENDPOINT_GROUP_GROUPAPI_TYPES_HPP_
