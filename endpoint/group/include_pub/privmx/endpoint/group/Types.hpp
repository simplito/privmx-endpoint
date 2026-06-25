#ifndef _PRIVMXLIB_ENDPOINT_GROUP_TYPES_HPP_
#define _PRIVMXLIB_ENDPOINT_GROUP_TYPES_HPP_

#include <optional>
#include <string>
#include <vector>

#include "privmx/endpoint/core/Buffer.hpp"
#include "privmx/endpoint/core/Types.hpp"

namespace privmx {
namespace endpoint {
namespace group {

/**
 * Holds all available information about a Group.
 */
struct Group {
    /**
     * ID of the Context
     */
    std::string contextId;

    /**
     * ID of the Group
     */
    std::string groupId;

    /**
     * Group identity public key (base58-DER encoded)
     */
    std::string groupPubKey;

    /**
     * Group creation timestamp
     */
    int64_t createDate;

    /**
     * ID of user who created the Group
     */
    std::string creator;

    /**
     * Group last modification timestamp
     */
    int64_t lastModificationDate;

    /**
     * ID of the user who last modified the Group
     */
    std::string lastModifier;

    /**
     * list of users (their IDs) with access to the Group
     */
    std::vector<std::string> users;

    /**
     * list of users (their IDs) with management rights
     */
    std::vector<std::string> managers;

    /**
     * version number (= number of history entries; changes on updates)
     */
    int64_t version;

    /**
     * Group's public metadata
     */
    core::Buffer publicMeta;

    /**
     * Group's private metadata
     */
    core::Buffer privateMeta;

    /**
     * Group's policies
     */
    core::ContainerPolicy policy;

    /**
     * status code of retrieval and verification of the Group (0 = success)
     */
    int64_t statusCode;

    /**
     * Version of the Group data structure and how it is encoded/encrypted
     */
    int64_t schemaVersion;

    /**
     * Optional type tag
     */
    std::optional<std::string> type;
};

enum EventType : int64_t {
    GROUP_CREATE = 0,
    GROUP_UPDATE = 1,
    GROUP_DELETE = 2,
};

enum EventSelectorType : int64_t {
    CONTEXT_ID = 0,
    GROUP_ID   = 1,
};

} // namespace group
} // namespace endpoint
} // namespace privmx

#endif // _PRIVMXLIB_ENDPOINT_GROUP_TYPES_HPP_
